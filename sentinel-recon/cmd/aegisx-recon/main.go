package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"

	"aegisx.local/sentinel-recon/internal/config"
	"aegisx.local/sentinel-recon/internal/export"
	"aegisx.local/sentinel-recon/internal/scanner"
	"aegisx.local/sentinel-recon/internal/streamer"
)

var version = "0.1.0"

func main() {
	cfg := config.FromFlags()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: cfg.LogLevel,
	}))
	slog.SetDefault(logger)

	if err := run(cfg); err != nil {
		slog.Error("sentinel-recon terminated with error", "err", err)
		os.Exit(1)
	}
}

func run(cfg config.Config) error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	slog.Info("sentinel-recon starting",
		"version", version,
		"target", cfg.Target,
		"ports", fmt.Sprintf("%d-%d", cfg.StartPort, cfg.EndPort),
		"concurrency", cfg.Concurrency,
		"grab_banners", cfg.GrabBanners,
	)

	scanCfg := scanner.Config{
		Target:        cfg.Target,
		StartPort:     cfg.StartPort,
		EndPort:       cfg.EndPort,
		Concurrency:   cfg.Concurrency,
		Timeout:       cfg.Timeout,
		GrabBanners:   cfg.GrabBanners,
		ScanUDP:       cfg.ScanUDP,
		TryProbe:      cfg.TryProbe,
		RandomShuffle: cfg.RandomShuffle,
		ScanMode:      cfg.ScanMode,
		MaxPPS:        cfg.MaxPPS,
		Adaptive:      cfg.Adaptive,
	}

	s := scanner.New(scanCfg)
	results, done := s.Scan(ctx)

	// Optional live streaming of open ports to the PhishGuard gateway.
	var streamerSvc *streamer.Streamer
	if cfg.StreamEndpoint != "" {
		sc, err := streamer.New(ctx, cfg.StreamEndpoint)
		if err != nil {
			slog.Warn("telemetry stream unavailable, continuing local scan", "err", err)
		} else {
			go sc.Run()
			streamerSvc = sc
		}
	}

	var (
		openPorts  []scanner.Result
		udpOpens   []scanner.Result
		filtered   uint64
		scanErrors []scanner.Result
	)

	consume := func(r scanner.Result) {
		switch r.State {
		case "open":
			openPorts = append(openPorts, r)
			if r.Protocol == "udp" {
				udpOpens = append(udpOpens, r)
			}
			if streamerSvc != nil {
				streamerSvc.Publish(r)
			}
		case "filtered":
			filtered++
		default:
			if r.Err != nil {
				scanErrors = append(scanErrors, r)
			}
		}
	}

	// Single drain loop: collect locally AND forward open ports upstream.
	for r := range results {
		consume(r)
	}
	<-done // all workers finished

	if streamerSvc != nil {
		streamerSvc.Close()
	}

	report := export.BuildReport(scanCfg, openPorts, udpOpens, filtered, scanErrors)

	switch strings.ToLower(cfg.OutputFormat) {
	case "json":
		if err := export.WriteJSON(cfg.OutputFile, report); err != nil {
			return fmt.Errorf("write json: %w", err)
		}
	case "protobuf":
		if err := export.WriteProto(cfg.OutputFile, report); err != nil {
			return fmt.Errorf("write protobuf: %w", err)
		}
	case "both":
		if err := export.WriteJSON(cfg.OutputFile+".json", report); err != nil {
			return err
		}
		if err := export.WriteProto(cfg.OutputFile+".pb", report); err != nil {
			return err
		}
	}

	slog.Info("scan complete",
		"open_tcp", len(openPorts),
		"open_udp", len(udpOpens),
		"filtered", filtered,
		"duration_ms", report.DurationMs,
		"goroutines_active", runtime.NumGoroutine(),
	)
	return nil
}
