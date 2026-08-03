package listener

import (
	"net"
	"strings"
	"testing"
)

func TestSanitizePayloadProjectsNonPrintable(t *testing.T) {
	raw := []byte("root\x00\x01\xffp\x00ass\x0aword")
	got := sanitizePayload(raw)
	if strings.ContainsRune(got, '\x00') || strings.ContainsRune(got, '\xff') {
		t.Fatalf("sanitized payload still contains raw control bytes: %q", got)
	}
	for _, c := range got {
		if c != '.' && (c < 0x20 || c > 0x7e) {
			t.Fatalf("non-printable char %q leaked into projection", c)
		}
	}
}

func TestSanitizePayloadCapsAt2048(t *testing.T) {
	big := make([]byte, 8192)
	for i := range big {
		big[i] = 'A'
	}
	if got := sanitizePayload(big); len(got) != 2048 {
		t.Fatalf("payload should be capped at 2048, got %d", len(got))
	}
}

func TestSanitizePayloadPassesASCII(t *testing.T) {
	in := "GET /admin HTTP/1.1"
	if got := sanitizePayload([]byte(in)); got != in {
		t.Fatalf("printable payload altered: %q", got)
	}
}

func TestPortOfFromTCPAddr(t *testing.T) {
	addr := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 2222}
	if got := portOf(addr); got != 2222 {
		t.Fatalf("portOf = %d, want 2222", got)
	}
}

func TestPortOfFromString(t *testing.T) {
	// A non-TCPAddr Addr implementation still resolves through SplitHostPort.
	addr := testAddr("10.0.0.1:443")
	if got := portOf(addr); got != 443 {
		t.Fatalf("portOf = %d, want 443", got)
	}
}

func TestPortOfBadAddr(t *testing.T) {
	if got := portOf(testAddr("not-an-address")); got != 0 {
		t.Fatalf("portOf(bad) = %d, want 0", got)
	}
}

func TestNewEventIDUniqueAndPrefixed(t *testing.T) {
	a := newEventID()
	b := newEventID()
	if !strings.HasPrefix(a, "ev-") || len(a) != 3+16 {
		t.Fatalf("bad event id shape: %q", a)
	}
	if a == b {
		t.Fatal("two event ids collided")
	}
}

type testAddr string

func (t testAddr) Network() string { return "test" }
func (t testAddr) String() string  { return string(t) }