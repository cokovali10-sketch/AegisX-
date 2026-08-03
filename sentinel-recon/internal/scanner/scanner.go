package scanner

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"sync"
	"time"
)

// Result is the normalized output of probing a single port.
type Result struct {
	Host     string
	Port     int
	Protocol string // "tcp" | "udp"
	State    string // "open" | "filtered" | "closed"
	Service  string
	Banner   string
	RTTMs    int64
	Err      error
}

// Config defines a scan job.
type Config struct {
	Target        string
	StartPort     int
	EndPort       int
	Concurrency   int
	Timeout       time.Duration
	GrabBanners   bool
	ScanUDP       bool
	TryProbe      bool
	RandomShuffle bool
	ScanMode      string // "connect" | "syn"
	MaxPPS        int
	Adaptive      bool
}

// Scanner owns a bounded worker pool over the port range.
type Scanner struct {
	cfg      Config
	pacer    *Pacer
	syn      *synScanner
	resolved string
	dst      net.IP
	wg       sync.WaitGroup
}

func New(cfg Config) *Scanner {
	conc := cfg.Concurrency
	if conc <= 0 {
		conc = 256 // deterministic default; on typical hosts ~ NumCPU*4
	}
	if cfg.ScanMode == "" {
		cfg.ScanMode = "connect"
	}
	return &Scanner{
		cfg:   cfg,
		pacer: NewPacer(cfg.MaxPPS, conc, cfg.Adaptive),
	}
}

// Scan resolves the host once, then fans the port range across the worker pool.
// The first returned channel streams Results; the second is closed when all
// workers have finished (error aggregation can be read from Result.Err).
func (s *Scanner) Scan(ctx context.Context) (<-chan Result, <-chan struct{}) {
	results := make(chan Result, 4096)
	done := make(chan struct{})

	go func() {
		defer close(results)
		defer close(done)
		defer s.wg.Wait()

		ip, err := resolve(ctx, s.cfg.Target)
		if err != nil {
			results <- Result{State: "error", Err: fmt.Errorf("resolve %q: %w", s.cfg.Target, err)}
			return
		}
		s.dst = ip
		s.resolved = ip.String()

		if s.cfg.ScanMode == "syn" {
			syn, err := openSynScanner(ctx, ip, uint32(rand.Uint32()))
			if err != nil {
				results <- Result{State: "warn", Host: s.resolved, Port: 0, Protocol: "tcp",
					Err: fmt.Errorf("raw syn unavailable, falling back to connect scan: %w", err)}
			} else {
				s.syn = syn
				defer syn.close()
			}
		}

		ports := s.portRange()
		if s.cfg.RandomShuffle {
			rand.Shuffle(len(ports), func(i, j int) { ports[i], ports[j] = ports[j], ports[i] })
		}

		ctx, cancel := context.WithCancel(ctx)
		defer cancel()

		for _, port := range ports {
			select {
			case <-ctx.Done():
				return
			case s.pacer.Slots() <- struct{}{}:
			}
			s.pacer.Delay()
			s.wg.Add(1)
			go func(p int) {
				defer s.wg.Done()
				defer func() { <-s.pacer.Slots() }()
				start := time.Now()
				res := s.probe(ctx, p)
				s.pacer.Observe(time.Since(start), res.State == "filtered")
				results <- res
				if s.cfg.ScanUDP {
					results <- s.probeUDP(ctx, p)
				}
			}(port)
		}
	}()

	return results, done
}

func (s *Scanner) portRange() []int {
	n := s.cfg.EndPort - s.cfg.StartPort + 1
	ports := make([]int, n)
	for i := range ports {
		ports[i] = s.cfg.StartPort + i
	}
	return ports
}

func resolve(ctx context.Context, host string) (net.IP, error) {
	if ip := net.ParseIP(host); ip != nil {
		return ip, nil
	}
	r := &net.Resolver{PreferGo: true, StrictErrors: false}
	addrs, err := r.LookupIP(ctx, "ip4", host)
	if err != nil {
		return nil, err
	}
	if len(addrs) == 0 {
		return nil, fmt.Errorf("no A records for %q", host)
	}
	return addrs[0], nil
}

func (s *Scanner) probeTCP(ctx context.Context, port int) Result {
	res := Result{Host: s.resolved, Port: port, Protocol: "tcp", State: "closed"}

	d := net.Dialer{Timeout: s.cfg.Timeout}
	start := time.Now()
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(s.resolved, itoa(port)))
	rtt := time.Since(start).Milliseconds()
	res.RTTMs = rtt

	if err != nil {
		if ne, ok := err.(net.Error); ok && ne.Timeout() {
			res.State = "filtered"
		}
		return res
	}
	defer conn.Close()

	res.State = "open"

	if s.cfg.GrabBanners {
		svc, banner := GrabBanner(conn, s.cfg.Timeout, s.cfg.TryProbe)
		res.Service = svc
		res.Banner = banner
	}
	return res
}

// probe dispatches the active scan mode; it falls back to a connect probe when
// the raw SYN scanner failed to initialize.
func (s *Scanner) probe(ctx context.Context, port int) Result {
	if s.syn != nil {
		return s.probeSYN(ctx, port, s.dst)
	}
	return s.probeTCP(ctx, port)
}

// probeSYN runs a raw SYN probe against dst and, on success, performs a
// follow-up connect only to capture a service banner.
func (s *Scanner) probeSYN(ctx context.Context, port int, dst net.IP) Result {
	res := s.syn.probe(ctx, port, s.cfg.Timeout)
	if res.State == "open" && s.cfg.GrabBanners {
		res.Service, res.Banner = s.grabSynBanner(port)
	}
	return res
}

// grabSynBanner re-connects to a SYN-confirmed open port for banner capture.
func (s *Scanner) grabSynBanner(port int) (service, banner string) {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(s.resolved, itoa(port)), s.cfg.Timeout)
	if err != nil {
		return "", ""
	}
	defer conn.Close()
	return GrabBanner(conn, s.cfg.Timeout, s.cfg.TryProbe)
}

func (s *Scanner) probeUDP(ctx context.Context, port int) Result {
	res := Result{Host: s.resolved, Port: port, Protocol: "udp", State: "filtered"}

	// A UDP "open" can only be inferred from an application response; ICMP
	// port-unreachable is how we close the loop on closed ports. This uses a
	// shared ICMP socket so we do not open a raw socket per probe.
	sock, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: net.ParseIP(s.resolved), Port: port})
	if err != nil {
		return res
	}
	defer sock.Close()

	_ = sock.SetDeadline(time.Now().Add(s.cfg.Timeout))
	// Generic application probe: a 4-byte NTP-style request triggers responses
	// from NTP/echo services and is silently dropped elsewhere.
	if _, err := sock.Write([]byte{0xe3, 0x00, 0x00, 0x00}); err != nil {
		return res
	}

	buf := make([]byte, 512)
	for {
		select {
		case <-ctx.Done():
			return res
		default:
		}
		n, err := sock.Read(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				break // nothing answered; treat as filtered/open-filtered
			}
			return res
		}
		if n > 0 {
			res.State = "open"
			if s.cfg.GrabBanners {
				svc, banner := sniffService(string(buf[:min(n, 256)]))
				res.Service = svc
				res.Banner = banner
			}
			return res
		}
	}
	return res
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [6]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
