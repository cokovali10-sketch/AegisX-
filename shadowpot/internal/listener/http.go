package listener

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"time"

	"aegisx.local/shadowpot/internal/config"
	"aegisx.local/shadowpot/internal/event"
)

// HTTPListener impersonates a vulnerable web control panel. Every request is
// fully recorded (verb, path, headers, body) and answered with a credible
// non-revealing response so the attacker keeps interacting.
type HTTPListener struct {
	addr    string
	bus     *event.Bus
	srv     *http.Server
	timeout time.Duration
}

func NewHTTP(cfg config.Config, bus *event.Bus) *HTTPListener {
	return &HTTPListener{addr: cfg.HTTPAddr, bus: bus, timeout: cfg.ReadTimeout}
}

func (l *HTTPListener) Start(ctx context.Context) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/", l.handleRequest)

	l.srv = &http.Server{
		Addr:              l.addr,
		Handler:           mux,
		ReadTimeout:       10 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       30 * time.Second,
	}

	ln, err := net.Listen("tcp", l.addr)
	if err != nil {
		return fmt.Errorf("http decoy listen %s: %w", l.addr, err)
	}
	slog.Info("http decoy listening", "addr", l.addr)

	go func() {
		<-ctx.Done()
		_ = l.srv.Shutdown(context.Background())
	}()

	if err := l.srv.Serve(ln); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

func (l *HTTPListener) handleRequest(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	body, _ := io.ReadAll(io.LimitReader(r.Body, 64*1024))

	meta := map[string]string{
		"host":         r.Host,
		"http_version": r.Proto,
		"content_type": r.Header.Get("Content-Type"),
		"x_forwarded":  r.Header.Get("X-Forwarded-For"),
		"cookies":      r.Header.Get("Cookie"),
	}

	// Surface authentication probes as credentials.
	username, password := extractCreds(r)

	l.bus.Publish(&event.Event{
		ID:                 newEventID(),
		Timestamp:          time.Now(),
		SourceIP:           clientIP(r),
		Protocol:           "http",
		TargetPort:         uint32(localPort(r)),
		Username:           username,
		Password:           password,
		UserAgent:          r.UserAgent(),
		Payload:            string(body),
		Method:             r.Method,
		Path:               r.URL.RequestURI(),
		ConnectionDuration: time.Since(start),
		Metadata:           meta,
	})

	// Plausible decoy reply. This looks like a small CMS admin login.
	w.Header().Set("Server", "nginx/1.18.0")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`<!doctype html><html><head><title>Admin</title></head>
<body><form method="POST"><label>Username</label><input name="username">
<label>Password</label><input type="password" name="password">
<button type="submit">Sign in</button></form></body></html>`))
}

// localPort resolves the bound target port from the connection context.
func localPort(r *http.Request) int {
	if v := r.Context().Value(http.LocalAddrContextKey); v != nil {
		if tcp, ok := v.(*net.TCPAddr); ok {
			return tcp.Port
		}
	}
	return 0
}

// clientIP resolves the real source address, honoring the proxy chain the
// attacker passes (metadata only — we never trust it for enforcement).
func clientIP(r *http.Request) string {
	if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
		return firstCSV(fwd)
	}
	if rip := r.RemoteAddr; rip != "" {
		if h, _, err := net.SplitHostPort(rip); err == nil {
			return h
		}
		return rip
	}
	return "0.0.0.0"
}

func firstCSV(s string) string {
	for _, f := range splitCSV(s) {
		if f != "" {
			return f
		}
	}
	return ""
}

func splitCSV(s string) []string {
	out := []string{}
	cur := ""
	for _, c := range s {
		if c == ',' {
			out = append(out, trimSpace(cur))
			cur = ""
			continue
		}
		cur += string(c)
	}
	if cur != "" {
		out = append(out, trimSpace(cur))
	}
	return out
}

func trimSpace(s string) string {
	for len(s) > 0 && (s[0] == ' ') {
		s = s[1:]
	}
	for len(s) > 0 && (s[len(s)-1] == ' ') {
		s = s[:len(s)-1]
	}
	return s
}

// extractCreds pulls username/password from common auth surfaces.
func extractCreds(r *http.Request) (user, pass string) {
	_ = r.ParseForm()
	if u := r.FormValue("username"); u != "" {
		user = u
	} else if u := r.FormValue("user"); u != "" {
		user = u
	}
	if p := r.FormValue("password"); p != "" {
		pass = p
	} else if p := r.FormValue("pass"); p != "" {
		pass = p
	}
	if user != "" || pass != "" {
		return user, pass
	}
	if u, p, ok := r.BasicAuth(); ok {
		return u, p
	}
	return "", ""
}
