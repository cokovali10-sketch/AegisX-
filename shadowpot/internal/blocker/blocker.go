// Package blocker implements the automated IP-banning engine for ShadowPot.
// It maintains an in-memory offender table and enforces bans through whatever
// firewall backend is available (nftables or iptables), degrading gracefully
// to a journal-only (in-memory) dry-run when no backend binary exists.
package blocker

import (
	"context"
	"log/slog"
	"os/exec"
	"strings"
	"sync"
	"time"

	"aegisx.local/shadowpot/internal/config"
	"aegisx.local/shadowpot/internal/event"
)

// Backend identifies the firewall enforcement mechanism.
type Backend string

const (
	// BackendAuto probes nft then iptables on the PATH.
	BackendAuto Backend = "auto"
	// BackendNftables uses nftables for both IPv4 and IPv6.
	BackendNftables Backend = "nftables"
	// BackendIptables uses iptables/ip6tables.
	BackendIptables Backend = "iptables"
	// BackendJournal keeps blocks in memory only (dry-run, no firewall rule).
	BackendJournal Backend = "journal"
)

// firewallCommandTimeout bounds each firewall syscall. Never hang a decoy loop.
const firewallCommandTimeout = 10 * time.Second

// offender tracks a source IP's offense count and ban state within a window.
type offender struct {
	count     int
	firstSeen time.Time
	lastSeen  time.Time
	banned    bool
	bannedAt  time.Time
}

// Blocker maintains the in-memory offender table and, when a firewall backend
// is available, pushes/removes drop rules for banned IPs.
type Blocker struct {
	enabled     bool
	threshold   int
	window      time.Duration
	banDuration time.Duration
	backend     Backend
	v4Bin       string
	v6Bin       string

	mu        sync.Mutex
	offenders map[string]*offender
	counted   map[string]time.Time
}

// New creates a Blocker from config, probing for the active firewall backend.
func New(cfg config.Config) *Blocker {
	backend, v4, v6 := resolveBackend(Backend(cfg.BanBackend))
	return &Blocker{
		enabled:     cfg.BanEnabled,
		threshold:   cfg.BanThreshold,
		window:      cfg.BanWindow,
		banDuration: cfg.BanDuration,
		backend:     backend,
		v4Bin:       v4,
		v6Bin:       v6,
		offenders:   make(map[string]*offender),
		counted:     make(map[string]time.Time),
	}
}

// resolveBackend picks the firewall binary set. It degrades to the journal
// backend (dry-run) whenever the configured backend is unavailable, so a
// missing nft/iptables never prevents the daemon from running.
func resolveBackend(configured Backend) (backend Backend, v4Bin, v6Bin string) {
	switch configured {
	case BackendNftables:
		if bin, err := exec.LookPath("nft"); err == nil {
			return BackendNftables, bin, bin
		}
		slog.Warn("nftables backend requested but nft not found; using journal (in-memory dry-run)")
		return BackendJournal, "", ""
	case BackendIptables:
		v4, _ := exec.LookPath("iptables")
		v6, _ := exec.LookPath("ip6tables")
		if v4 == "" && v6 == "" {
			slog.Warn("iptables backend requested but no iptables binary found; using journal (in-memory dry-run)")
			return BackendJournal, "", ""
		}
		return BackendIptables, v4, v6
	case BackendJournal:
		return BackendJournal, "", ""
	default: // BackendAuto
		if bin, err := exec.LookPath("nft"); err == nil {
			return BackendNftables, bin, bin
		}
		if v4, err := exec.LookPath("iptables"); err == nil {
			v6, _ := exec.LookPath("ip6tables")
			return BackendIptables, v4, v6
		}
		slog.Warn("no nft or iptables on PATH; firewall enforcement disabled (in-memory dry-run)")
		return BackendJournal, "", ""
	}
}

// RecordEvent counts an offense for the event's source IP. Every decoy
// interaction is treated as malicious intent, and repeated hits within the
// ban window push the IP over the threshold and trigger a ban. Events are
// deduplicated by ID so a single event counted through both the bus feed and
// the onScored path is never double-counted. It returns true when a ban was
// issued.
func (b *Blocker) RecordEvent(e *event.Event) (banned bool) {
	if b == nil || !b.enabled || e == nil || e.SourceIP == "" {
		return false
	}
	now := time.Now()

	b.mu.Lock()
	if _, seen := b.counted[e.ID]; seen {
		b.mu.Unlock()
		return false
	}
	b.counted[e.ID] = now

	off := b.offenders[e.SourceIP]
	if off == nil {
		off = &offender{}
		b.offenders[e.SourceIP] = off
	}
	if off.firstSeen.IsZero() || now.Sub(off.firstSeen) > b.window {
		off.firstSeen = now
		off.count = 0
	}
	off.count++
	off.lastSeen = now

	var ip string
	if off.count >= b.threshold && !off.banned {
		off.banned = true
		off.bannedAt = now
		ip = e.SourceIP
	}
	b.mu.Unlock()

	if ip != "" {
		b.ban(ip)
		return true
	}
	return false
}

// Banned reports whether the given IP is currently banned.
func (b *Blocker) Banned(ip string) bool {
	if b == nil {
		return false
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	off, ok := b.offenders[ip]
	return ok && off.banned
}

// Block immediately bans an IP, bypassing the threshold counter. It is the
// entry point for SOAR playbook-driven enforcement (PhishGuard Command RPC).
func (b *Blocker) Block(ip string) {
	if b == nil || !b.enabled || ip == "" {
		return
	}
	b.mu.Lock()
	off := b.offenders[ip]
	if off == nil {
		off = &offender{}
		b.offenders[ip] = off
	}
	off.banned = true
	off.bannedAt = time.Now()
	b.mu.Unlock()
	b.ban(ip)
}

// Unblock releases an immediate ban and removes any installed firewall rule.
func (b *Blocker) Unblock(ip string) {
	if b == nil || ip == "" {
		return
	}
	b.mu.Lock()
	if off, ok := b.offenders[ip]; ok {
		off.banned = false
		delete(b.offenders, ip)
	}
	b.mu.Unlock()
	b.unban(ip)
}

// ban installs a firewall drop rule for ip, or logs an in-memory-only block.
func (b *Blocker) ban(ip string) {
	switch b.backend {
	case BackendJournal:
		slog.Info("ip banned (journal backend, no firewall binary)",
			"ip", ip, "duration", b.banDuration.String())
		return
	case BackendNftables, BackendIptables:
		bin, args := b.banCommand(ip)
		if bin == "" {
			slog.Warn("ip banned in-memory only (no matching firewall binary)", "ip", ip)
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), firewallCommandTimeout)
		defer cancel()
		out, err := exec.CommandContext(ctx, bin, args...).CombinedOutput()
		if err != nil {
			slog.Warn("firewall ban failed; block kept in-memory",
				"ip", ip, "backend", b.backend,
				"err", err, "output", strings.TrimSpace(string(out)))
			return
		}
		slog.Info("ip banned at firewall",
			"ip", ip, "backend", b.backend,
			"command", bin+" "+strings.Join(args, " "))
	}
}

// banCommand returns the (binary, args) needed to drop the IP.
func (b *Blocker) banCommand(ip string) (bin string, args []string) {
	if strings.Contains(ip, ":") { // IPv6
		if b.backend == BackendNftables {
			return b.v6Bin, []string{"add", "rule", "inet", "filter", "input", "ip6", "saddr", ip, "drop"}
		}
		return b.v6Bin, []string{"-A", "INPUT", "-s", ip, "-j", "DROP"}
	}
	if b.backend == BackendNftables {
		return b.v4Bin, []string{"add", "rule", "inet", "filter", "input", "ip", "saddr", ip, "drop"}
	}
	return b.v4Bin, []string{"-A", "INPUT", "-s", ip, "-j", "DROP"}
}

// unban removes an installed drop rule for the IP, best-effort.
func (b *Blocker) unban(ip string) {
	switch b.backend {
	case BackendJournal:
		slog.Info("block released (in-memory)", "ip", ip)
		return
	case BackendNftables, BackendIptables:
		bin, args := b.unbanCommand(ip)
		if bin == "" {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), firewallCommandTimeout)
		defer cancel()
		out, err := exec.CommandContext(ctx, bin, args...).CombinedOutput()
		if err != nil {
			slog.Warn("firewall unban failed", "ip", ip, "err", err,
				"output", strings.TrimSpace(string(out)))
			return
		}
		slog.Info("ip unbanned at firewall", "ip", ip, "backend", b.backend)
	}
}

// unbanCommand returns the (binary, args) needed to remove the drop rule.
func (b *Blocker) unbanCommand(ip string) (string, []string) {
	if strings.Contains(ip, ":") {
		if b.backend == BackendNftables {
			return b.v6Bin, []string{"delete", "rule", "inet", "filter", "input", "ip6", "saddr", ip, "drop"}
		}
		return b.v6Bin, []string{"-D", "INPUT", "-s", ip, "-j", "DROP"}
	}
	if b.backend == BackendNftables {
		return b.v4Bin, []string{"delete", "rule", "inet", "filter", "input", "ip", "saddr", ip, "drop"}
	}
	return b.v4Bin, []string{"-D", "INPUT", "-s", ip, "-j", "DROP"}
}

// Run starts the janitor that periodically expires bans and prunes the
// offender and dedup tables. It blocks until ctx is cancelled.
func (b *Blocker) Run(ctx context.Context) {
	if b == nil {
		return
	}
	slog.Info("ip ban janitor started",
		"enabled", b.enabled,
		"backend", b.backend,
		"threshold", b.threshold,
		"window", b.window.String(),
		"ban_duration", b.banDuration.String())
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			b.sweep()
		}
	}
}

// sweep expires finished bans and prunes aged bookkeeping entries.
func (b *Blocker) sweep() {
	now := time.Now()
	var toUnban []string

	b.mu.Lock()
	for ip, off := range b.offenders {
		switch {
		case off.banned && now.Sub(off.bannedAt) >= b.banDuration:
			delete(b.offenders, ip)
			toUnban = append(toUnban, ip)
		case !off.banned && now.Sub(off.lastSeen) > 2*b.window:
			delete(b.offenders, ip)
		}
	}
	for id, seen := range b.counted {
		if now.Sub(seen) > b.window {
			delete(b.counted, id)
		}
	}
	b.mu.Unlock()

	for _, ip := range toUnban {
		b.unban(ip)
	}
}
