package blocker

import (
	"testing"
	"time"

	"aegisx.local/shadowpot/internal/config"
	"aegisx.local/shadowpot/internal/event"
)

func journalBlocker(t *testing.T, threshold int, banDuration time.Duration) *Blocker {
	t.Helper()
	cfg := config.Config{
		BanEnabled:   true,
		BanBackend:   "journal", // never touches a real firewall
		BanThreshold: threshold,
		BanWindow:    time.Minute,
		BanDuration:  banDuration,
	}
	return New(cfg)
}

func ev(ip string, id string) *event.Event {
	return &event.Event{ID: id, SourceIP: ip, Protocol: "ssh"}
}

func TestBansAfterThreshold(t *testing.T) {
	b := journalBlocker(t, 3, time.Hour)
	for i := 0; i < 2; i++ {
		if b.RecordEvent(ev("1.2.3.4", string(rune('a'+i)))) {
			t.Fatalf("ban fired before threshold")
		}
	}
	if b.Banned("1.2.3.4") {
		t.Fatal("IP should not be banned below threshold")
	}
	if !b.RecordEvent(ev("1.2.3.4", "ev-3")) {
		t.Fatal("third event should trigger a ban")
	}
	if !b.Banned("1.2.3.4") {
		t.Fatal("IP should be banned after threshold")
	}
}

func TestEventDedupByID(t *testing.T) {
	b := journalBlocker(t, 1, time.Hour)
	// Same event routed twice (bus feed + scored path) must count once.
	if !b.RecordEvent(ev("5.6.7.8", "dup-1")) {
		t.Fatal("first sighting should ban at threshold 1")
	}
	if b.RecordEvent(ev("5.6.7.8", "dup-1")) {
		t.Fatal("deduplicated event double-counted / re-banned")
	}
}

func TestIndependentOffenders(t *testing.T) {
	b := journalBlocker(t, 2, time.Hour)
	b.RecordEvent(ev("1.1.1.1", "a"))
	b.RecordEvent(ev("2.2.2.2", "b"))
	if b.Banned("1.1.1.1") || b.Banned("2.2.2.2") {
		t.Fatal("offenders must be tracked per-IP")
	}
	b.RecordEvent(ev("1.1.1.1", "c"))
	if !b.Banned("1.1.1.1") {
		t.Fatal("1.1.1.1 reached threshold and must be banned")
	}
	if b.Banned("2.2.2.2") {
		t.Fatal("2.2.2.2 must not be affected by another IP")
	}
}

func TestBlockBypassesThreshold(t *testing.T) {
	b := journalBlocker(t, 99, time.Hour)
	b.Block("9.9.9.9")
	if !b.Banned("9.9.9.9") {
		t.Fatal("Block must bypass the threshold counter")
	}
}

func TestUnblockReleases(t *testing.T) {
	b := journalBlocker(t, 1, time.Hour)
	b.RecordEvent(ev("7.7.7.7", "u"))
	if !b.Banned("7.7.7.7") {
		t.Fatal("precondition: banned")
	}
	b.Unblock("7.7.7.7")
	if b.Banned("7.7.7.7") {
		t.Fatal("Unblock must release the ban")
	}
}

func TestSweepExpiresBans(t *testing.T) {
	b := journalBlocker(t, 1, 30*time.Millisecond)
	b.RecordEvent(ev("8.8.8.8", "s"))
	if !b.Banned("8.8.8.8") {
		t.Fatal("precondition: banned")
	}
	time.Sleep(50 * time.Millisecond)
	b.sweep()
	if b.Banned("8.8.8.8") {
		t.Fatal("expired ban must be swept")
	}
}

func TestDisabledBlockerIsNoop(t *testing.T) {
	cfg := config.Config{BanEnabled: false, BanBackend: "journal"}
	b := New(cfg)
	if b.RecordEvent(ev("3.3.3.3", "n")) {
		t.Fatal("disabled blocker must not ban")
	}
	if b.Banned("3.3.3.3") {
		t.Fatal("disabled blocker reports no bans")
	}
}

func TestBanCommandV4(t *testing.T) {
	b := &Blocker{backend: BackendNftables, v4Bin: "/usr/sbin/nft"}
	bin, args := b.banCommand("1.2.3.4")
	if bin != "/usr/sbin/nft" || len(args) != 9 {
		t.Fatalf("nft v4 command = %s %v", bin, args)
	}
	if args[0] != "add" || args[7] != "1.2.3.4" || args[8] != "drop" {
		t.Fatalf("nft v4 args malformed: %v", args)
	}
}

func TestBanCommandV6RoutesByColon(t *testing.T) {
	b := &Blocker{backend: BackendIptables, v4Bin: "iptables", v6Bin: "ip6tables"}
	bin, args := b.banCommand("2001:db8::1")
	if bin != "ip6tables" || args[1] != "INPUT" {
		t.Fatalf("v6 should use ip6tables -A INPUT: %s %v", bin, args)
	}
}