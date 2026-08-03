package cmdserver

import (
	"context"
	"testing"
	"time"

	"aegisx.local/shadowpot/internal/blocker"
	"aegisx.local/shadowpot/internal/config"
	"aegisx/proto/gen/go"
	"google.golang.org/grpc/metadata"
)

func testBlocker(t *testing.T) *blocker.Blocker {
	t.Helper()
	cfg := config.Config{
		BanEnabled:   true,
		BanBackend:   "journal", // never shells out to a real firewall in tests
		BanThreshold: 3,
		BanWindow:    time.Minute,
		BanDuration:  time.Hour,
	}
	return blocker.New(cfg)
}

func TestCommandMitigateBansIP(t *testing.T) {
	s := New(testBlocker(t))
	ack, err := s.Command(context.Background(), &aegisxpb.CommandFrame{
		Id: "c1", Command: "mitigate_ban_ip", Target: "198.51.100.9",
	})
	if err != nil {
		t.Fatalf("Command error: %v", err)
	}
	if !ack.Accepted {
		t.Fatalf("ban not accepted: %s", ack.Detail)
	}
	if !s.blocker.Banned("198.51.100.9") {
		t.Fatal("SOAR ban did not reach the blocker")
	}
}

func TestCommandMitigateRequiresTarget(t *testing.T) {
	s := New(testBlocker(t))
	ack, _ := s.Command(context.Background(), &aegisxpb.CommandFrame{
		Id: "c2", Command: "mitigate_ban_ip",
	})
	if ack.Accepted {
		t.Fatal("ban without target must be rejected")
	}
}

func TestCommandUnbanReleases(t *testing.T) {
	s := New(testBlocker(t))
	s.blocker.Block("203.0.113.7")
	if !s.blocker.Banned("203.0.113.7") {
		t.Fatal("precondition: banned")
	}
	ack, _ := s.Command(context.Background(), &aegisxpb.CommandFrame{
		Id: "c3", Command: "unban_ip", Target: "203.0.113.7",
	})
	if !ack.Accepted {
		t.Fatalf("unban rejected: %s", ack.Detail)
	}
	if s.blocker.Banned("203.0.113.7") {
		t.Fatal("unban did not release the IP")
	}
}

func TestCommandUnknownIsAcknowledged(t *testing.T) {
	s := New(testBlocker(t))
	ack, _ := s.Command(context.Background(), &aegisxpb.CommandFrame{Id: "c4", Command: "self-destruct"})
	if !ack.Accepted {
		t.Fatal("unknown commands should be acknowledged, not error")
	}
}

func TestCommandStatus(t *testing.T) {
	s := New(testBlocker(t))
	ack, _ := s.Command(context.Background(), &aegisxpb.CommandFrame{Id: "c5", Command: "status"})
	if !ack.Accepted {
		t.Fatal("status command must be accepted")
	}
}

func TestAuthInterceptorNoTokenAllowsAll(t *testing.T) {
	interceptor := authInterceptor("")
	_, err := interceptor(context.Background(), nil, nil, func(context.Context, any) (any, error) {
		return "ok", nil
	})
	if err != nil {
		t.Fatalf("open plane must allow the call: %v", err)
	}
}

func TestAuthInterceptorRejectsWithoutCredentials(t *testing.T) {
	interceptor := authInterceptor("sekret")
	_, err := interceptor(context.Background(), nil, nil, func(context.Context, any) (any, error) {
		return "ok", nil
	})
	if err == nil {
		t.Fatal("missing metadata must be rejected")
	}
}

func TestAuthInterceptorRejectsWrongToken(t *testing.T) {
	interceptor := authInterceptor("sekret")
	md := metadata.New(map[string]string{"authorization": "Bearer nope"})
	ctx := metadata.NewIncomingContext(context.Background(), md)
	_, err := interceptor(ctx, nil, nil, func(context.Context, any) (any, error) {
		return "ok", nil
	})
	if err == nil {
		t.Fatal("wrong token must be rejected")
	}
}

func TestAuthInterceptorAcceptsValidToken(t *testing.T) {
	interceptor := authInterceptor("sekret")
	md := metadata.New(map[string]string{"authorization": "Bearer sekret"})
	ctx := metadata.NewIncomingContext(context.Background(), md)
	out, err := interceptor(ctx, nil, nil, func(context.Context, any) (any, error) {
		return "ok", nil
	})
	if err != nil {
		t.Fatalf("valid token must pass: %v", err)
	}
	if out != "ok" {
		t.Fatal("handler result must be forwarded")
	}
}