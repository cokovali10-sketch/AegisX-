package listener

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"time"

	"aegisx.local/shadowpot/internal/config"
	"aegisx.local/shadowpot/internal/event"
	"aegisx.local/shadowpot/internal/pcap"
)

// SSHListener is a protocol-level SSH decoy. It cannot complete a key exchange
// (that would require real key material), but it captures the client's version
// banner, its initial KEXINIT packet, and any early auth bytes — precisely the
// reconnaissance fingerprint real scanners leak.
type SSHListener struct {
	addr    string
	banner  string
	bus     *event.Bus
	timeout time.Duration
	rec     *pcap.Recorder
	srv     *net.TCPListener
}

func NewSSH(cfg config.Config, bus *event.Bus, rec *pcap.Recorder) *SSHListener {
	return &SSHListener{
		addr:    cfg.SSHAddr,
		banner:  cfg.FakeSSHBanner,
		bus:     bus,
		timeout: cfg.ReadTimeout,
		rec:     rec,
	}
}

func (l *SSHListener) Start(ctx context.Context) error {
	ln, err := net.Listen("tcp", l.addr)
	if err != nil {
		return fmt.Errorf("ssh decoy listen %s: %w", l.addr, err)
	}
	tcpLn := ln.(*net.TCPListener)
	l.srv = tcpLn
	slog.Info("ssh decoy listening", "addr", l.addr)

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
			slog.Warn("ssh accept failed", "err", err)
			continue
		}
		go l.handle(conn)
	}
}

func (l *SSHListener) handle(conn *net.TCPConn) {
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

	// SSH servers speak first with their version banner.
	if _, err := conn.Write([]byte(l.banner + "\r\n")); err != nil {
		return
	}

	rd := bufio.NewReader(io.TeeReader(conn, flow))
	clientBanner, _ := rd.ReadString('\n')
	clientBanner = strings.TrimSpace(clientBanner)

	// Capture the binary KEXINIT that follows; cap the footprint.
	raw, _ := io.ReadAll(io.LimitReader(rd, 2048))

	meta := map[string]string{
		"client_banner": clientBanner,
		"bytes_read":    fmt.Sprintf("%d", len(raw)),
	}

	l.bus.Publish(&event.Event{
		ID:                 evID,
		Timestamp:          time.Now(),
		SourceIP:           remote.IP.String(),
		SourcePort:         uint32(remote.Port),
		Protocol:           "ssh",
		TargetPort:         uint32(portOf(l.srv.Addr())),
		Payload:            sanitizePayload(raw),
		Method:             "kexinit",
		ConnectionDuration: time.Since(start),
		Metadata:           meta,
	})
}

// newEventID returns a short random identifier for correlation across the
// gRPC boundary (event_id in ScoringResult).
func newEventID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return "ev-" + hex.EncodeToString(b)
}

// sanitizePayload renders raw capture bytes as a printable ASCII projection.
func sanitizePayload(b []byte) string {
	out := make([]rune, 0, len(b))
	for _, c := range b {
		if c < 0x20 || c > 0x7e {
			out = append(out, '.')
		} else {
			out = append(out, rune(c))
		}
	}
	s := string(out)
	if len(s) > 2048 {
		s = s[:2048]
	}
	return s
}
