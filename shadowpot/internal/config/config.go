package config

import (
	"os"
	"strconv"
	"time"
)

// Config holds the decoy topology and the upstream AI gateway endpoint.
// Every value is overridable via environment variables so the same binary
// can be parameterized by docker-compose.
type Config struct {
	HTTPAddr        string
	SSHAddr         string
	MySQLAddr       string
	RedisAddr       string
	PostgresAddr    string
	TelnetAddr      string
	GRPCUpstream    string // phishguard gRPC endpoint
	GRPCListen      string // local gRPC command plane (SOAR mitigation)
	GRPCCommandToken string // bearer token required on the command plane (empty = open in dev)
	ConnectTimeout  time.Duration
	ReadTimeout     time.Duration
	FakeSSHBanner   string
	FakeMySQLVer    string
	FakeRedisVer    string
	FakePostgresVer string
	PcapDir         string
	PcapEnabled     bool
	BanThreshold    int
	BanWindow       time.Duration
	BanDuration     time.Duration
	BanEnabled      bool
	BanBackend      string
	TelemetryNode   string
}

func FromEnv() Config {
	return Config{
		HTTPAddr:        envStr("SHADOWPOT_HTTP_ADDR", ":8080"),
		SSHAddr:         envStr("SHADOWPOT_SSH_ADDR", ":2222"),
		MySQLAddr:       envStr("SHADOWPOT_MYSQL_ADDR", ":3306"),
		RedisAddr:       envStr("SHADOWPOT_REDIS_ADDR", ":6379"),
		PostgresAddr:    envStr("SHADOWPOT_POSTGRES_ADDR", ":5432"),
		TelnetAddr:      envStr("SHADOWPOT_TELNET_ADDR", ":23"),
		GRPCUpstream:    envStr("SHADOWPOT_GRPC_UPSTREAM", "phishguard:50051"),
		GRPCListen:      envStr("SHADOWPOT_GRPC_LISTEN", ":50053"),
		GRPCCommandToken: envStr("SHADOWPOT_GRPC_TOKEN", ""),
		ConnectTimeout:  time.Duration(envInt("SHADOWPOT_CONNECT_TIMEOUT_MS", 5000)) * time.Millisecond,
		ReadTimeout:     time.Duration(envInt("SHADOWPOT_READ_TIMEOUT_MS", 10000)) * time.Millisecond,
		FakeSSHBanner:   envStr("SHADOWPOT_SSH_BANNER", "SSH-2.0-OpenSSH_7.9p1 Debian-10+deb10u2"),
		FakeMySQLVer:    envStr("SHADOWPOT_MYSQL_VERSION", "5.7.38-log"),
		FakeRedisVer:    envStr("SHADOWPOT_REDIS_VERSION", "7.2.4"),
		FakePostgresVer: envStr("SHADOWPOT_POSTGRES_VERSION", "16.3"),
		PcapDir:         envStr("SHADOWPOT_PCAP_DIR", "captures"),
		PcapEnabled:     envBool("SHADOWPOT_PCAP_ENABLED", true),
		BanThreshold:    envInt("SHADOWPOT_BAN_THRESHOLD", 3),
		BanWindow:       time.Duration(envInt("SHADOWPOT_BAN_WINDOW_SECONDS", 300)) * time.Second,
		BanDuration:     time.Duration(envInt("SHADOWPOT_BAN_DURATION_SECONDS", 3600)) * time.Second,
		BanEnabled:      envBool("SHADOWPOT_BAN_ENABLED", true),
		BanBackend:      envStr("SHADOWPOT_BAN_BACKEND", "auto"),
		TelemetryNode:   "shadowpot",
	}
}

func envStr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

func envBool(key string, def bool) bool {
	if v := os.Getenv(key); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			return b
		}
	}
	return def
}
