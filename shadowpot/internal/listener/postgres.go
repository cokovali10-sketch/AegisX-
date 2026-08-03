package listener

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strconv"
	"time"

	"aegisx.local/shadowpot/internal/config"
	"aegisx.local/shadowpot/internal/event"
	"aegisx.local/shadowpot/internal/pcap"
)

const (
	// pgProtocolVersion is the PostgreSQL 3.0 startup protocol identifier.
	pgProtocolVersion = 196608
	// pgSSLRequest is the startup message protocol code requesting TLS first.
	pgSSLRequest = 80877103
	// pgGSSEncRequest requests GSSAPI encryption before the real startup.
	pgGSSEncRequest = 80877104
	// pgMaxStartup caps the startup packet size we will accept.
	pgMaxStartup = 64 * 1024
)

// PostgresListener impersonates a PostgreSQL server at the startup handshake
// level. It parses the client's startup message (length + protocol + key/value
// pairs), extracts the attempted user/database credentials, and rejects
// authentication with a FATAL error — capturing the probe in the process.
type PostgresListener struct {
	addr    string
	version string
	bus     *event.Bus
	timeout time.Duration
	rec     *pcap.Recorder
	srv     *net.TCPListener
}

// NewPostgres builds a Postgres decoy bound to cfg.PostgresAddr with the given
// version, recording raw traffic to rec.
func NewPostgres(cfg config.Config, bus *event.Bus, rec *pcap.Recorder) *PostgresListener {
	return &PostgresListener{
		addr:    cfg.PostgresAddr,
		version: cfg.FakePostgresVer,
		bus:     bus,
		timeout: cfg.ReadTimeout,
		rec:     rec,
	}
}

// Start accepts TCP connections until ctx is cancelled.
func (l *PostgresListener) Start(ctx context.Context) error {
	ln, err := net.Listen("tcp", l.addr)
	if err != nil {
		return fmt.Errorf("postgres decoy listen %s: %w", l.addr, err)
	}
	l.srv = ln.(*net.TCPListener)
	slog.Info("postgres decoy listening", "addr", l.addr)

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
			slog.Warn("postgres accept failed", "err", err)
			continue
		}
		go l.handle(conn)
	}
}

func (l *PostgresListener) handle(conn *net.TCPConn) {
	start := time.Now()
	remote, ok := conn.RemoteAddr().(*net.TCPAddr)
	if !ok {
		_ = conn.Close()
		return
	}
	_ = conn.SetDeadline(time.Now().Add(l.timeout))

	evID := newEventID()
	flow := pcap.NewFlow(l.rec, evID, remote.IP.String(), remote.Port, portOf(l.srv.Addr()))
	rd := bufio.NewReader(io.TeeReader(conn, flow))
	defer func() {
		_ = flow.Flush()
		_ = conn.Close()
	}()

	params := map[string]string{}
	var rawStartup []byte
	var proto uint32

	// Some clients first issue an SSLRequest/GSSENCRequest; answer 'N' to
	// decline encryption, then wait for the real startup message.
	for {
		protocol, kv, raw, err := readStartupMessage(rd)
		if err != nil {
			return
		}
		if protocol == pgSSLRequest || protocol == pgGSSEncRequest {
			if _, err := conn.Write([]byte{'N'}); err != nil {
				return
			}
			continue
		}
		params = kv
		rawStartup = raw
		proto = protocol
		break
	}

	user := params["user"]
	database := params["database"]
	if database == "" {
		database = user
	}

	// Reject authentication with a FATAL password-authentication failure.
	_, _ = conn.Write(pgErrorResponse(user))

	meta := map[string]string{
		"pg_version":  l.version,
		"db":          database,
		"param_count": strconv.Itoa(len(params)),
		"protocol":    strconv.FormatUint(uint64(proto), 10),
	}
	if app := params["application_name"]; app != "" {
		meta["application_name"] = app
	}

	l.bus.Publish(&event.Event{
		ID:                 evID,
		Timestamp:          time.Now(),
		SourceIP:           remote.IP.String(),
		SourcePort:         uint32(remote.Port),
		Protocol:           "postgres",
		TargetPort:         uint32(portOf(l.srv.Addr())),
		Username:           user,
		Password:           params["password"],
		Payload:            sanitizePayload(rawStartup),
		Method:             "auth",
		ConnectionDuration: time.Since(start),
		Metadata:           meta,
	})
}

// readStartupMessage reads one backend message fronted by a 4-byte big-endian
// length. The length counts the 4-byte protocol number and parameters but not
// the length field itself. It returns the protocol code, the decoded key/value
// parameter map and the raw message bytes (payload = full startup packet).
func readStartupMessage(rd *bufio.Reader) (uint32, map[string]string, []byte, error) {
	lenBuf := make([]byte, 4)
	if _, err := io.ReadFull(rd, lenBuf); err != nil {
		return 0, nil, nil, err
	}
	length := binary.BigEndian.Uint32(lenBuf)
	if length < 4 || length > pgMaxStartup {
		return 0, nil, nil, errors.New("postgres startup packet too large")
	}
	body := make([]byte, length-4)
	if _, err := io.ReadFull(rd, body); err != nil {
		return 0, nil, nil, err
	}
	raw := make([]byte, 0, 4+len(body))
	raw = append(raw, lenBuf...)
	raw = append(raw, body...)

	protocol := binary.BigEndian.Uint32(body[:4])
	params := make(map[string]string)
	rest := body[4:]
	for len(rest) > 0 {
		idx := indexByte(rest, 0)
		if idx < 0 {
			break
		}
		key := string(rest[:idx])
		rest = rest[idx+1:]
		if key == "" {
			break
		}
		idx = indexByte(rest, 0)
		if idx < 0 {
			params[key] = string(rest)
			break
		}
		params[key] = string(rest[:idx])
		rest = rest[idx+1:]
	}
	return protocol, params, raw, nil
}

// pgErrorResponse builds a backend ErrorResponse ('E') reporting a FATAL
// password-authentication failure (SQLSTATE 28P01) for the given user.
func pgErrorResponse(user string) []byte {
	msg := "password authentication failed for user \"" + user + "\""
	body := []byte{'S', 'F', 'A', 'T', 'A', 'L', 0, 'C', '2', '8', 'P', '0', '1', 0, 'M'}
	body = append(body, msg...)
	body = append(body, 0, 0)

	out := make([]byte, 0, 1+4+len(body))
	out = append(out, 'E')
	out = binary.BigEndian.AppendUint32(out, uint32(len(body)))
	out = append(out, body...)
	return out
}
