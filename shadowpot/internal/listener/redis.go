package listener

import (
	"bufio"
	"context"
	"errors"
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
	// maxRedisCommands caps the RESP commands processed per connection so a
	// long-lived attacker cannot keep the decoy busy forever.
	maxRedisCommands = 64
	// maxRedisArgLen caps a single RESP bulk-string length we will accept.
	maxRedisArgLen = 4096
)

// RedisListener impersonates a Redis server. It accepts RESP arrays and inline
// commands, answers with plausible Redis replies, and captures any credentials
// sent via AUTH before the connection is torn down.
type RedisListener struct {
	addr    string
	version string
	bus     *event.Bus
	timeout time.Duration
	rec     *pcap.Recorder
	srv     *net.TCPListener
}

// NewRedis builds a Redis decoy bound to cfg.RedisAddr with the given version
// banner, recording raw traffic to rec.
func NewRedis(cfg config.Config, bus *event.Bus, rec *pcap.Recorder) *RedisListener {
	return &RedisListener{
		addr:    cfg.RedisAddr,
		version: cfg.FakeRedisVer,
		bus:     bus,
		timeout: cfg.ReadTimeout,
		rec:     rec,
	}
}

// Start accepts TCP connections until ctx is cancelled, mirroring the other
// protocol decoys.
func (l *RedisListener) Start(ctx context.Context) error {
	ln, err := net.Listen("tcp", l.addr)
	if err != nil {
		return fmt.Errorf("redis decoy listen %s: %w", l.addr, err)
	}
	l.srv = ln.(*net.TCPListener)
	slog.Info("redis decoy listening", "addr", l.addr)

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
			slog.Warn("redis accept failed", "err", err)
			continue
		}
		go l.handle(conn)
	}
}

func (l *RedisListener) handle(conn *net.TCPConn) {
	start := time.Now()
	remote, ok := conn.RemoteAddr().(*net.TCPAddr)
	if !ok {
		_ = conn.Close()
		return
	}
	_ = conn.SetDeadline(time.Now().Add(l.timeout))

	// Redis serves a banner-less protocol; send a benign OK so banner grabbing
	// registers the port as live without revealing anything.
	if _, err := conn.Write([]byte("+OK\r\n")); err != nil {
		_ = conn.Close()
		return
	}

	evID := newEventID()
	flow := pcap.NewFlow(l.rec, evID, remote.IP.String(), remote.Port, portOf(l.srv.Addr()))
	rd := bufio.NewReader(io.TeeReader(conn, flow))
	defer func() {
		_ = flow.Flush()
		_ = conn.Close()
	}()

	var (
		commands []string
		lines    []string
		username string
		password string
	)
	for len(commands) < maxRedisCommands {
		toks, err := readRESPCommand(rd)
		if err != nil {
			break
		}
		if len(toks) == 0 {
			continue
		}
		verb := strings.ToUpper(toks[0])
		commands = append(commands, verb)
		lines = append(lines, strings.Join(toks, " "))

		switch verb {
		case "AUTH":
			switch len(toks) {
			case 2:
				password = toks[1]
			case 3:
				username, password = toks[1], toks[2]
			}
			_, _ = conn.Write([]byte("+OK\r\n"))
		case "PING":
			_, _ = conn.Write([]byte("+PONG\r\n"))
		case "INFO":
			_, _ = conn.Write(bulkString(redisInfo(l.version)))
		case "CONFIG":
			if len(toks) >= 2 && strings.EqualFold(toks[1], "GET") {
				_, _ = conn.Write(redisConfigGet(toks[2:]))
			} else {
				_, _ = conn.Write([]byte("+OK\r\n"))
			}
		case "COMMAND":
			_, _ = conn.Write([]byte("*-1\r\n"))
		case "GET":
			_, _ = conn.Write([]byte("$-1\r\n"))
		case "SET":
			_, _ = conn.Write([]byte("+OK\r\n"))
		case "EVAL":
			_, _ = conn.Write([]byte("$-1\r\n"))
		default:
			_, _ = conn.Write([]byte("-ERR unknown command '" + verb + "'\r\n"))
		}
	}

	method := "connect"
	if len(commands) > 0 {
		method = commands[0]
	}
	meta := map[string]string{
		"redis_version":  l.version,
		"redis_commands": strings.Join(commands, " "),
		"command_count":  strconv.Itoa(len(commands)),
	}

	l.bus.Publish(&event.Event{
		ID:                 evID,
		Timestamp:          time.Now(),
		SourceIP:           remote.IP.String(),
		SourcePort:         uint32(remote.Port),
		Protocol:           "redis",
		TargetPort:         uint32(portOf(l.srv.Addr())),
		Username:           username,
		Password:           password,
		Payload:            sanitizePayload([]byte(strings.Join(lines, "\n"))),
		Method:             method,
		ConnectionDuration: time.Since(start),
		Metadata:           meta,
	})
}

// info renders a plausible INFO reply using the configured redis version.
func redisInfo(version string) string {
	return fmt.Sprintf(
		"# Server\r\nredis_version:%s\r\nredis_mode:standalone\r\nos:Linux 5.15.0-91-generic x86_64\r\narch_bits:64\r\nprocess_id:1371\r\nrun_id:3f8c9d5a4b2e6f1a7c9d0e1f2a3b4c5d6e7f8a9b\r\n# Clients\r\nconnected_clients:1\r\n# Memory\r\nused_memory:1048576\r\nmaxmemory:0\r\n",
		version)
}

// redisConfigGet answers CONFIG GET with a small set of plausible values, or a
// nil array for unknown keys.
func redisConfigGet(keys []string) []byte {
	if len(keys) == 0 || keys[0] == "" || strings.EqualFold(keys[0], "ALL") {
		return []byte("*-1\r\n")
	}
	vals := map[string]string{
		"dir":            "/var/lib/redis",
		"save":           "3600 1 300 100 60 10000",
		"appendonly":     "no",
		"maxmemory":      "0",
		"bind":           "0.0.0.0",
		"protected-mode": "yes",
	}
	key := strings.ToLower(keys[0])
	if v, ok := vals[key]; ok {
		return append([]byte("*2\r\n"), append(bulkString(key), bulkString(v)...)...)
	}
	return []byte("*-1\r\n")
}

// bulkString encodes a RESP bulk string reply.
func bulkString(s string) []byte {
	return []byte("$" + strconv.Itoa(len(s)) + "\r\n" + s + "\r\n")
}

// readRESPCommand reads the next RESP command as an array (or inline) and
// returns its tokens. It walks $m bulk arguments safely and rejects oversized
// or malformed input.
func readRESPCommand(rd *bufio.Reader) ([]string, error) {
	line, err := rd.ReadString('\n')
	if err != nil {
		return nil, err
	}
	line = strings.TrimRight(line, "\r\n")
	if line == "" {
		return readRESPCommand(rd)
	}
	if line[0] == '*' {
		n, err := strconv.Atoi(line[1:])
		if err != nil || n < 0 || n > maxRedisCommands {
			return nil, errors.New("invalid RESP array length")
		}
		toks := make([]string, 0, n)
		for i := 0; i < n; i++ {
			hdr, err := rd.ReadString('\n')
			if err != nil {
				return nil, err
			}
			hdr = strings.TrimRight(hdr, "\r\n")
			if hdr == "" || hdr[0] != '$' {
				return nil, errors.New("expected RESP bulk string")
			}
			blen, err := strconv.Atoi(hdr[1:])
			if err != nil || blen < 0 || blen > maxRedisArgLen {
				return nil, errors.New("invalid RESP bulk length")
			}
			buf := make([]byte, blen+2)
			if _, err := io.ReadFull(rd, buf); err != nil {
				return nil, err
			}
			toks = append(toks, string(buf[:blen]))
		}
		return toks, nil
	}
	return strings.Fields(line), nil
}
