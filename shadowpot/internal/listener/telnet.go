package listener

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"time"

	"aegisx.local/shadowpot/internal/config"
	"aegisx.local/shadowpot/internal/event"
	"aegisx.local/shadowpot/internal/pcap"
)

const (
	// maxTelnetLines caps the number of shell commands captured per session.
	maxTelnetLines = 20
)

// TelnetListener impersonates a Unix telnet login. It negotiates echo off,
// prompts for credentials, and then runs a fake shell that quietly collects a
// handful of attacker commands before hanging up.
type TelnetListener struct {
	addr    string
	bus     *event.Bus
	timeout time.Duration
	rec     *pcap.Recorder
	srv     *net.TCPListener
}

// NewTelnet builds a Telnet decoy bound to cfg.TelnetAddr, recording raw
// traffic to rec.
func NewTelnet(cfg config.Config, bus *event.Bus, rec *pcap.Recorder) *TelnetListener {
	return &TelnetListener{addr: cfg.TelnetAddr, bus: bus, timeout: cfg.ReadTimeout, rec: rec}
}

// Start accepts TCP connections until ctx is cancelled.
func (l *TelnetListener) Start(ctx context.Context) error {
	ln, err := net.Listen("tcp", l.addr)
	if err != nil {
		return fmt.Errorf("telnet decoy listen %s: %w", l.addr, err)
	}
	l.srv = ln.(*net.TCPListener)
	slog.Info("telnet decoy listening", "addr", l.addr)

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
			slog.Warn("telnet accept failed", "err", err)
			continue
		}
		go l.handle(conn)
	}
}

func (l *TelnetListener) handle(conn *net.TCPConn) {
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

	// Minimal Telnet negotiation: server WILL echo + WILL suppress go-ahead.
	_, _ = conn.Write([]byte{0xff, 0xfb, 0x01, 0xff, 0xfb, 0x03, '\r', '\n'})
	_, _ = conn.Write([]byte("Ubuntu 22.04.3 LTS\r\n\r\nlogin: "))

	userLine, err := rd.ReadString('\n')
	if err != nil {
		return
	}
	username := strings.TrimSpace(string(stripTelnetIAC([]byte(userLine))))

	// Disable echo while the password is typed.
	_, _ = conn.Write([]byte{0xff, 0xfc, 0x01})
	_, _ = conn.Write([]byte("Password: "))
	passLine, err := rd.ReadString('\n')
	if err != nil {
		return
	}
	password := strings.TrimSpace(string(stripTelnetIAC([]byte(passLine))))

	// Fake shell: collect a handful of commands, then close.
	var shell []string
	for len(shell) < maxTelnetLines {
		_, _ = conn.Write([]byte("$ "))
		cmd, err := rd.ReadString('\n')
		if err != nil {
			break
		}
		cmd = strings.TrimSpace(string(stripTelnetIAC([]byte(cmd))))
		if cmd == "" {
			continue
		}
		shell = append(shell, cmd)
	}

	meta := map[string]string{
		"shell_lines": strconv.Itoa(len(shell)),
	}

	l.bus.Publish(&event.Event{
		ID:                 evID,
		Timestamp:          time.Now(),
		SourceIP:           remote.IP.String(),
		SourcePort:         uint32(remote.Port),
		Protocol:           "telnet",
		TargetPort:         uint32(portOf(l.srv.Addr())),
		Username:           username,
		Password:           password,
		Payload:            sanitizePayload([]byte(strings.Join(shell, "\n"))),
		Method:             "login",
		ConnectionDuration: time.Since(start),
		Metadata:           meta,
	})
}

// stripTelnetIAC removes Telnet IAC negotiation sequences (and any embedded
// sub-negotiation payloads) from a raw input line.
func stripTelnetIAC(b []byte) []byte {
	out := make([]byte, 0, len(b))
	for i := 0; i < len(b); i++ {
		if b[i] != 0xff {
			out = append(out, b[i])
			continue
		}
		i++
		if i >= len(b) {
			break
		}
		switch b[i] {
		case 0xfb, 0xfc, 0xfd, 0xfe: // WILL/WONT/DO/DONT + option byte
			i++
		case 0xfa: // subnegotiation: consume until IAC SE
			for i+1 < len(b) {
				i++
				if b[i] == 0xff && i+1 < len(b) && b[i+1] == 0xf0 {
					i++
					break
				}
			}
		}
	}
	return out
}
