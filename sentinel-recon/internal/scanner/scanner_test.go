package scanner

import (
	"encoding/binary"
	"net"
	"sync"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Pacer
// ---------------------------------------------------------------------------

func TestPacerDefaultsAndSlots(t *testing.T) {
	p := NewPacer(0, 0, false)
	if p.base != defaultMinDelay {
		t.Fatalf("maxPPS 0 should clamp base to %v, got %v", defaultMinDelay, p.base)
	}
	if cap(p.slots) != 256 {
		t.Fatalf("concurrency 0 should default to 256 slots, got %d", cap(p.slots))
	}
}

func TestPacerBaseIntervalFollowsMaxPPS(t *testing.T) {
	p := NewPacer(100, 8, false) // 100pps -> 10ms (no clamp)
	if want := time.Second / 100; p.base != want {
		t.Fatalf("base = %v, want %v", p.base, want)
	}
}

func TestPacerAdaptiveLoss(t *testing.T) {
	p := NewPacer(1000, 8, true)
	base := p.base
	// force loss above 5%
	for i := 0; i < 3; i++ {
		p.Observe(30*time.Millisecond, true)
	}
	iv := p.currentInterval()
	if iv < base {
		t.Fatalf("loss must increase interval, got %v < base %v", iv, base)
	}
	if p.loss <= 0.05 {
		t.Fatalf("loss should be > 0.05 after timeouts, got %v", p.loss)
	}
}

func TestPacerAdaptiveOnRTT(t *testing.T) {
	p := NewPacer(1000, 8, true)
	p.Observe(3*time.Second, false) // ewma RTT > critical watermark
	iv := p.currentInterval()
	if want := p.base * 3; iv != want {
		t.Fatalf("rtt surcharge: interval = %v, want %v", iv, want)
	}
}

func TestPacerAdaptiveCapsInterval(t *testing.T) {
	p := NewPacer(1000, 8, true)
	p.maxDelay = 3 * time.Millisecond
	p.Observe(5*time.Second, true)
	p.Observe(0, true)
	p.Observe(0, true)
	if iv := p.currentInterval(); iv != 3*time.Millisecond {
		t.Fatalf("interval should clamp to maxDelay 3ms, got %v", iv)
	}
}

func TestPacerDisabledIsStable(t *testing.T) {
	p := NewPacer(1000, 8, false)
	p.Observe(3*time.Second, true)
	if iv := p.currentInterval(); iv != p.base {
		t.Fatalf("non-adaptive pacer must ignore network signals, got %v", iv)
	}
}

func TestPacerEWMAAverages(t *testing.T) {
	p := NewPacer(1000, 8, true)
	p.Observe(100*time.Millisecond, false) // first sample seeds the EWMA
	p.Observe(100*time.Millisecond, false)
	p.Observe(100*time.Millisecond, false)
	p.Observe(100*time.Millisecond, false)
	// EWMA = (3*(prev)+next)/4 starting from 100ms -> stays 100ms for constant input.
	if p.ewmaRTT != 100*time.Millisecond {
		t.Fatalf("ewmaRTT = %v, want 100ms", p.ewmaRTT)
	}
}

// ---------------------------------------------------------------------------
// SYN correlation + checksum
// ---------------------------------------------------------------------------

func TestOnesComplementChecksumEmptyIsFFFF(t *testing.T) {
	if got := onesComplementChecksum([]byte{}); got != 0xffff {
		t.Fatalf("checksum of empty input = %#x, want 0xffff", got)
	}
}

func verifyV4Checksum(t *testing.T, src, dst net.IP, seg []byte) {
	t.Helper()
	pseudo := make([]byte, 12+len(seg))
	copy(pseudo[0:4], src.To4())
	copy(pseudo[4:8], dst.To4())
	pseudo[9] = 6
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(len(seg)))
	copy(pseudo[12:], seg)
	if got := onesComplementChecksum(pseudo); got != 0 {
		t.Fatalf("IPv4 TCP checksum invalid (sum=0x%04x)", got)
	}
}

func TestTCPSegmentV4ChecksumValid(t *testing.T) {
	src := net.ParseIP("10.0.0.1")
	dst := net.ParseIP("10.0.0.2")
	seg := tcpSegmentV4(src, dst, 12345, 80, 0xDEADBEEF, 0, tcpSYN)
	if seg[13] != tcpSYN {
		t.Fatalf("flags = %#x, want SYN", seg[13])
	}
	if binary.BigEndian.Uint16(seg[0:2]) != 12345 {
		t.Fatalf("src port mismatch")
	}
	if binary.BigEndian.Uint16(seg[2:4]) != 80 {
		t.Fatalf("dst port mismatch")
	}
	if binary.BigEndian.Uint32(seg[4:8]) != 0xDEADBEEF {
		t.Fatalf("seq mismatch")
	}
	verifyV4Checksum(t, src, dst, seg)
}

func TestTCPSegmentV6ChecksumValid(t *testing.T) {
	src := net.ParseIP("2001:db8::1")
	dst := net.ParseIP("2001:db8::2")
	seg := tcpSegmentV6(src, dst, 5000, 443, 7, 0, tcpSYN|tcpACK)
	pseudo := make([]byte, 40+len(seg))
	copy(pseudo[0:16], src.To16())
	copy(pseudo[16:32], dst.To16())
	binary.BigEndian.PutUint32(pseudo[32:36], uint32(len(seg)))
	pseudo[39] = 6
	copy(pseudo[40:], seg)
	if got := onesComplementChecksum(pseudo); got != 0 {
		t.Fatalf("IPv6 TCP checksum = 0x%x, want 0", got)
	}
}

// openSynScanner requires raw sockets; construct a scanner directly (same
// package) to exercise the SYN-ACK/RST correlation logic.
func TestHandleTCPCorrelatesByAckMinusOne(t *testing.T) {
	s := &synScanner{
		dst:    net.ParseIP("127.0.0.1"),
		srcIP:  net.ParseIP("127.0.0.1"),
		srcPort: 40000,
		probes: sync.Map{},
	}
	// non-nil v6 so the follow-up RST write succeeds harmlessly.
	var err error
	s.v6, err = net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Skipf("cannot bind loopback udp for RST sink: %v", err)
	}
	defer s.v6.Close()

	probe := &synProbe{seq: 1000, port: 80, res: make(chan synState, 1)}
	s.probes.Store(uint32(1000), probe)

	seg := make([]byte, 20)
	binary.BigEndian.PutUint16(seg[0:2], 80)    // source = target's 80
	binary.BigEndian.PutUint16(seg[2:4], 40000) // dst = our claimed port
	binary.BigEndian.PutUint32(seg[4:8], 55)    // target ISN
	binary.BigEndian.PutUint32(seg[8:12], 1001) // ack = sent seq + 1
	seg[13] = tcpSYN | tcpACK

	s.handleTCP(seg)
	select {
	case st := <-probe.res:
		if st != synOpen {
			t.Fatalf("state = %v, want open", st)
		}
	default:
		t.Fatal("SYN-ACK not correlated to in-flight probe")
	}
}

func TestHandleTCPRSTMarksClosed(t *testing.T) {
	s := &synScanner{dst: net.ParseIP("127.0.0.1"), srcPort: 41000, probes: sync.Map{}}
	probe := &synProbe{seq: 7, port: 81, res: make(chan synState, 1)}
	s.probes.Store(uint32(7), probe)

	seg := make([]byte, 20)
	binary.BigEndian.PutUint16(seg[0:2], 81)
	binary.BigEndian.PutUint16(seg[2:4], 41000)
	binary.BigEndian.PutUint32(seg[4:8], 9)
	binary.BigEndian.PutUint32(seg[8:12], 8) // ack = seq+1
	seg[13] = tcpRST

	s.handleTCP(seg)
	select {
	case st := <-probe.res:
		if st != synClosed {
			t.Fatalf("state = %v, want closed", st)
		}
	default:
		t.Fatal("RST not correlated to in-flight probe")
	}
}

func TestHandleTCPIgnoresForeignPackets(t *testing.T) {
	s := &synScanner{srcPort: 42000, probes: sync.Map{}}
	probe := &synProbe{seq: 5, port: 82, res: make(chan synState, 1)}
	s.probes.Store(uint32(5), probe)

	// Wrong source port (not 82) -> no resolution.
	seg := make([]byte, 20)
	binary.BigEndian.PutUint16(seg[0:2], 9000)
	binary.BigEndian.PutUint16(seg[2:4], 42000)
	binary.BigEndian.PutUint32(seg[8:12], 6)
	seg[13] = tcpRST
	s.handleTCP(seg)
	select {
	case <-probe.res:
		t.Fatal("foreign packet incorrectly matched a probe")
	default:
	}
}

func TestV6TCPPayloadParses(t *testing.T) {
	// Build a minimal IPv6 packet with a TCP next-header at the base offset.
	b := make([]byte, 52)
	b[0] = 0x60                       // version 6
	b[6] = 6                          // next header: TCP
	b[7] = 1                          // hop limit
	binary.BigEndian.PutUint16(b[40:42], 443)
	if p := v6TCPPayload(b); p == nil || len(p) != 12 {
		t.Fatalf("expected cut-through TCP payload, got %v (len %d)", p, len(p))
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func TestPortRange(t *testing.T) {
	s := &Scanner{cfg: Config{StartPort: 10, EndPort: 12}}
	if got := s.portRange(); len(got) != 3 || got[0] != 10 || got[2] != 12 {
		t.Fatalf("portRange = %v", got)
	}
}

func TestItoa(t *testing.T) {
	for _, c := range [][2]interface{}{{22, "22"}, {443, "443"}, {0, "0"}, {65535, "65535"}} {
		if got := itoa(c[0].(int)); got != c[1].(string) {
			t.Fatalf("itoa(%d) = %q, want %q", c[0].(int), got, c[1].(string))
		}
	}
}

func TestMin(t *testing.T) {
	if min(3, 9) != 3 || min(9, 3) != 3 || min(3, 3) != 3 {
		t.Fatal("min failed")
	}
}