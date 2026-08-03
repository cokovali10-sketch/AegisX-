package config

import (
	"flag"
	"log/slog"
	"time"
)

// Config carries every tunable for a scan run. Values are deliberately
// conservative for unattended operation (default concurrency == NumCPU*4).
type Config struct {
	Target         string
	StartPort      int
	EndPort        int
	Concurrency    int
	Timeout        time.Duration
	GrabBanners    bool
	ScanUDP        bool
	TryProbe       bool
	RandomShuffle  bool
	ScanMode       string
	MaxPPS         int
	Adaptive       bool
	OutputFormat   string
	OutputFile     string
	StreamEndpoint string
	LogLevel       slog.Level
}

func FromFlags() Config {
	var (
		target         = flag.String("target", "127.0.0.1", "scan target host (hostname or IP)")
		startPort      = flag.Int("start", 1, "start port (inclusive)")
		endPort        = flag.Int("end", 65535, "end port (inclusive)")
		concurrency    = flag.Int("concurrency", 0, "dial concurrency (default CPU*4)")
		timeoutMs      = flag.Int("timeout", 1200, "per-connection timeout in ms")
		grabBanners    = flag.Bool("banners", true, "grab banners on open TCP ports")
		scanUDP        = flag.Bool("udp", false, "best-effort UDP sweep (slow)")
		tryProbe       = flag.Bool("probe", true, "send protocol probes to elicit a server banner")
		shuffle        = flag.Bool("shuffle", true, "randomize probe order to evade naive IDS")
		mode           = flag.String("mode", "connect", "scan mode: connect | syn")
		maxpps         = flag.Int("maxpps", 1000, "max packets per second budget")
		noAdaptive     = flag.Bool("no-adaptive", false, "disable adaptive rate limiting")
		format         = flag.String("format", "both", "export format: json | protobuf | both")
		outputFile     = flag.String("out", "scan-result", "output file base path")
		streamEndpoint = flag.String("stream", "", "gRPC endpoint for live telemetry (host:port)")
		verbose        = flag.Bool("v", false, "debug logging")
	)
	flag.Parse()

	if *concurrency <= 0 {
		*concurrency = 0
		// resolved by scanner.New below the flag layer to avoid flag==0 semantics
	}
	if *startPort < 1 || *endPort > 65535 || *startPort > *endPort {
		panic("invalid port range: start must be >=1 and end <=65535 and start<=end")
	}

	level := slog.LevelInfo
	if *verbose {
		level = slog.LevelDebug
	}

	return Config{
		Target:         *target,
		StartPort:      *startPort,
		EndPort:        *endPort,
		Concurrency:    *concurrency,
		Timeout:        time.Duration(*timeoutMs) * time.Millisecond,
		GrabBanners:    *grabBanners,
		ScanUDP:        *scanUDP,
		TryProbe:       *tryProbe,
		RandomShuffle:  *shuffle,
		ScanMode:       *mode,
		MaxPPS:         *maxpps,
		Adaptive:       !*noAdaptive,
		OutputFormat:   *format,
		OutputFile:     *outputFile,
		StreamEndpoint: *streamEndpoint,
		LogLevel:       level,
	}
}
