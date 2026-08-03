package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"aegisx.local/shadowpot/internal/blocker"
	"aegisx.local/shadowpot/internal/cmdserver"
	"aegisx.local/shadowpot/internal/config"
	"aegisx.local/shadowpot/internal/event"
	"aegisx.local/shadowpot/internal/listener"
	"aegisx.local/shadowpot/internal/pcap"
	"aegisx.local/shadowpot/internal/streamer"
	"aegisx/proto/gen/go"
)

var version = "0.1.0"

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	cfg := config.FromEnv()
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	bus := event.NewBus()
	defer bus.Close()

	var wg sync.WaitGroup

	// Raw traffic recorder for the PCAP captures directory.
	pcapRec, err := pcap.New(cfg.PcapDir, cfg.PcapEnabled)
	if err != nil {
		slog.Warn("pcap capture disabled", "dir", cfg.PcapDir, "err", err)
	}

	// Automated IP-banning engine + janitor.
	banBlocker := blocker.New(cfg)
	wg.Add(1)
	go func() {
		defer wg.Done()
		banBlocker.Run(ctx)
	}()

	// SOAR command plane: PhishGuard playbooks push mitigation commands here.
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := cmdserver.Serve(ctx, cfg.GRPCListen, banBlocker, cfg.GRPCCommandToken); err != nil {
			slog.Warn("command server stopped", "addr", cfg.GRPCListen, "err", err)
		}
	}()

	// Small id -> *event index so the onScored callback can map a ScoringResult
	// back to the raw event (and thus the source IP) it refers to.
	var idMu sync.RWMutex
	idIndex := make(map[string]*event.Event)

	// Attach a local audit logger + blocker feed for every captured interaction.
	auditCh := bus.Subscribe()
	wg.Add(1)
	go func() {
		defer wg.Done()
		for e := range auditCh {
			idMu.Lock()
			idIndex[e.ID] = e
			idMu.Unlock()

			banBlocker.RecordEvent(e)

			slog.Info("decoy interaction captured",
				"protocol", e.Protocol,
				"src", e.SourceIP,
				"src_port", e.SourcePort,
				"target_port", e.TargetPort,
				"username", e.Username,
				"user_agent", e.UserAgent,
				"path", e.Path,
			)
		}
	}()

	// Stream everything to the PhishGuard AI gateway for scoring.
	streamerSvc := streamer.New(ctx, cfg.GRPCUpstream, bus, func(res *aegisxpb.ScoringResult) {
		slog.Info("scored decoy event",
			"event_id", res.EventId,
			"score", res.ThreatScore,
			"severity", res.Severity.String(),
			"verdict", res.Verdict.String(),
			"summary", res.Summary,
		)
		// High-confidence malicious verdicts feed the automated ban engine too.
		if res.Verdict == aegisxpb.Verdict_VERDICT_MALICIOUS && res.ThreatScore >= 60 {
			idMu.RLock()
			e := idIndex[res.EventId]
			idMu.RUnlock()
			if e != nil {
				if banned := banBlocker.RecordEvent(e); banned {
					slog.Warn("source ip auto-banned",
						"ip", e.SourceIP,
						"event_id", e.ID,
						"threat_score", res.ThreatScore,
					)
				}
			}
		}
	})
	wg.Add(1)
	go func() {
		defer wg.Done()
		streamerSvc.Run()
	}()

	// Decoy listeners.
	httpLn := listener.NewHTTP(cfg, bus)
	sshLn := listener.NewSSH(cfg, bus, pcapRec)
	mysqlLn := listener.NewMySQL(cfg, bus, pcapRec)
	redisLn := listener.NewRedis(cfg, bus, pcapRec)
	postgresLn := listener.NewPostgres(cfg, bus, pcapRec)
	telnetLn := listener.NewTelnet(cfg, bus, pcapRec)

	var listeners []func(context.Context) error = []func(context.Context) error{
		httpLn.Start,
		sshLn.Start,
		mysqlLn.Start,
		redisLn.Start,
		postgresLn.Start,
		telnetLn.Start,
	}

	lnErr := make(chan error, len(listeners))
	for _, start := range listeners {
		start := start
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := start(ctx); err != nil {
				slog.Error("decoy listener failed", "err", err)
				lnErr <- err
			}
		}()
	}

	slog.Info("shadowpot decoy grid online",
		"http", cfg.HTTPAddr,
		"ssh", cfg.SSHAddr,
		"mysql", cfg.MySQLAddr,
		"redis", cfg.RedisAddr,
		"postgres", cfg.PostgresAddr,
		"telnet", cfg.TelnetAddr,
		"upstream", cfg.GRPCUpstream,
		"version", version,
	)

	select {
	case err := <-lnErr:
		slog.Error("fatal listener error, shutting down", "err", err)
		stop()
	case <-ctx.Done():
		slog.Info("shutdown signal received")
	}

	wg.Wait()
	slog.Info("shadowpot stopped cleanly")
}
