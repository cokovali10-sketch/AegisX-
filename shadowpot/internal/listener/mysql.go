package listener

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"net"
	"time"

	"aegisx.local/shadowpot/internal/config"
	"aegisx.local/shadowpot/internal/event"
	"aegisx.local/shadowpot/internal/pcap"
)

// MySQL protocol capability flags we advertise (client echoes a subset).
const (
	capProto41       = 0x00000200
	capPluginAuth    = 0x00080000
	capSecureConn    = 0x00008000
	capConnectWithDB = 0x00000008
	advCapabilities  = capProto41 | capSecureConn | capPluginAuth | capConnectWithDB
)

const fakeAuthPlugin = "mysql_native_password"

// MySQLListener is a handshake-level MySQL decoy. It speaks enough of the
// MySQL wire protocol (protocol v10) to force a real client — or credential
// brute-forcer — to transmit its username and password hash, which we extract
// and capture before rejecting the authentication attempt.
type MySQLListener struct {
	addr     string
	version  string
	bus      *event.Bus
	timeout  time.Duration
	rec      *pcap.Recorder
	srv      *net.TCPListener
	serverID uint32
}

func NewMySQL(cfg config.Config, bus *event.Bus, rec *pcap.Recorder) *MySQLListener {
	return &MySQLListener{
		addr:     cfg.MySQLAddr,
		version:  cfg.FakeMySQLVer,
		bus:      bus,
		timeout:  cfg.ReadTimeout,
		rec:      rec,
		serverID: uint32(time.Now().UnixNano() & 0x7fffffff),
	}
}

func (l *MySQLListener) Start(ctx context.Context) error {
	ln, err := net.Listen("tcp", l.addr)
	if err != nil {
		return fmt.Errorf("mysql decoy listen %s: %w", l.addr, err)
	}
	l.srv = ln.(*net.TCPListener)
	slog.Info("mysql decoy listening", "addr", l.addr)

	go func() {
		<-ctx.Done()
		_ = l.srv.Close()
	}()

	for {
		conn, err := l.srv.AcceptTCP()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			slog.Warn("mysql accept failed", "err", err)
			continue
		}
		go l.handle(conn)
	}
}

func (l *MySQLListener) handle(conn *net.TCPConn) {
	start := time.Now()
	remote, ok := conn.RemoteAddr().(*net.TCPAddr)
	if !ok {
		_ = conn.Close()
		return
	}
	_ = conn.SetDeadline(time.Now().Add(l.timeout))

	evID := newEventID()
	flow := pcap.NewFlow(l.rec, evID, remote.IP.String(), remote.Port, portOf(l.srv.Addr()))
	defer func() {
		_ = flow.Flush()
		_ = conn.Close()
	}()

	// 1) Send HandshakeV10 greeting.
	greeting, _ := l.buildGreeting()
	if _, err := conn.Write(greeting); err != nil {
		return
	}

	// 2) Read HandshakeResponse41 (contains username + scrambled password).
	resp := make([]byte, 4096)
	n, err := io.TeeReader(conn, flow).Read(resp)
	if err != nil || n < 4 {
		return
	}
	payload := resp[4:n] // strip 3-byte length + 1-byte sequence

	username, passwordHash, db, plugin := parseHandshakeResponse(payload)

	// 3) Reject auth with a generic access-denied error packet.
	authError := buildErrorPacket(1045, "28000", "Access denied for user '"+username+"'@'"+remote.IP.String()+"' (using password: "+passwordState(passwordHash)+")")
	_, _ = conn.Write(authError)

	meta := map[string]string{
		"auth_plugin":   plugin,
		"database":      db,
		"password_hash": passwordHash,
		"server_id":     fmt.Sprintf("%d", l.serverID),
	}

	l.bus.Publish(&event.Event{
		ID:                 evID,
		Timestamp:          time.Now(),
		SourceIP:           remote.IP.String(),
		SourcePort:         uint32(remote.Port),
		Protocol:           "mysql",
		TargetPort:         uint32(portOf(l.srv.Addr())),
		Username:           username,
		Password:           passwordHash,
		Method:             "auth",
		ConnectionDuration: time.Since(start),
		Metadata:           meta,
	})
}

// buildGreeting assembles the MySQL HandshakeV10 packet and a random salt.
func (l *MySQLListener) buildGreeting() (packet []byte, salt []byte) {
	pluginData := make([]byte, 20)
	_, _ = rand.Read(pluginData)

	buf := make([]byte, 0, 128)
	buf = append(buf, 0x0a) // protocol version 10
	buf = append(buf, l.version...)
	buf = append(buf, 0x00)
	buf = binary.LittleEndian.AppendUint32(buf, l.serverID)
	buf = append(buf, pluginData[:8]...) // auth-plugin-data-part-1
	buf = append(buf, 0x00)              // filler
	buf = binary.LittleEndian.AppendUint16(buf, uint16(advCapabilities&0xFFFF))
	buf = append(buf, 45)                               // character_set: utf8mb4_general_ci
	buf = binary.LittleEndian.AppendUint16(buf, 0x0002) // status: SERVER_STATUS_AUTOCOMMIT
	buf = binary.LittleEndian.AppendUint16(buf, uint16(advCapabilities>>16))
	buf = append(buf, byte(len(pluginData))) // auth plugin data length
	buf = append(buf, make([]byte, 10)...)   // reserved (10 zero bytes)
	buf = append(buf, pluginData[8:]...)     // auth-plugin-data-part-2
	buf = append(buf, 0x00)
	buf = append(buf, []byte(fakeAuthPlugin)...) // auth plugin name
	buf = append(buf, 0x00)

	return wrapPacket(buf, 0), pluginData
}

// parseHandshakeResponse decodes the client's handshake response 41 payload.
func parseHandshakeResponse(p []byte) (username, passwordHash, database, plugin string) {
	if len(p) < 32 {
		return "", "", "", ""
	}
	pos := 4 + 4 + 1 + 23 // client_flags(4) + max_packet(4) + charset(1) + 23 reserved
	// username is NULL-terminated
	end := indexByte(p[pos:], 0x00)
	if end < 0 {
		return "", "", "", ""
	}
	username = string(p[pos : pos+end])
	pos += end + 1

	if pos >= len(p) {
		return username, "", "", ""
	}

	// auth-response: length-encoded (we advertise PLUGIN_AUTH).
	switch {
	case pos+1 <= len(p) && p[pos] < 0xfb:
		authLen := int(p[pos])
		pos++
		if pos+authLen <= len(p) {
			passwordHash = fmt.Sprintf("%x", p[pos:pos+authLen])
			pos += authLen
		}
	default:
		return username, "", "", ""
	}

	// optional database (CLIENT_CONNECT_WITH_DB)
	if pos < len(p) {
		if dbEnd := indexByte(p[pos:], 0x00); dbEnd >= 0 {
			database = string(p[pos : pos+dbEnd])
			pos += dbEnd + 1
		}
	}

	// optional auth plugin name (CLIENT_PLUGIN_AUTH)
	if pos < len(p) {
		if plEnd := indexByte(p[pos:], 0x00); plEnd >= 0 {
			plugin = string(p[pos : pos+plEnd])
		}
	}
	return username, passwordHash, database, plugin
}

func buildErrorPacket(code uint16, sqlState, message string) []byte {
	buf := make([]byte, 0, 32+len(message))
	buf = append(buf, 0xff)                           // ERR header
	buf = binary.LittleEndian.AppendUint16(buf, code) // error code
	buf = append(buf, '#')                            // marker
	buf = append(buf, sqlState...)                    // 5-byte sqlstate
	buf = append(buf, message...)                     // message
	buf = append(buf, 0x00)
	return wrapPacket(buf, 1)
}

// wrapPacket prefixes the MySQL packet header: 3-byte little-endian length
// followed by a 1-byte sequence id.
func wrapPacket(payload []byte, seq byte) []byte {
	hdr := make([]byte, 4)
	hdr[0] = byte(len(payload))
	hdr[1] = byte(len(payload) >> 8)
	hdr[2] = byte(len(payload) >> 16)
	hdr[3] = seq
	return append(hdr, payload...)
}

func indexByte(b []byte, c byte) int {
	for i, x := range b {
		if x == c {
			return i
		}
	}
	return -1
}

func passwordState(hash string) string {
	if hash == "" {
		return "NO"
	}
	return "YES"
}
