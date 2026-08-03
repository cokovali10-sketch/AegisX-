package streamer

import (
	"context"
	"log/slog"
	"time"

	"aegisx.local/shadowpot/internal/event"
	"aegisx/proto/gen/go"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
)

// Streamer owns the bidirectional gRPC connection to the PhishGuard AI
// gateway. It pumps decoy events upstream and pipes scored results back to
// any consumer that needs them (local alerting, Control Center fan-out).
type Streamer struct {
	ctx       context.Context
	endpoint  string
	conn      *grpc.ClientConn
	client    aegisxpb.AegisXClient
	events    *event.Bus
	onScored  func(*aegisxpb.ScoringResult)
	connected bool
}

func New(ctx context.Context, endpoint string, events *event.Bus,
	onScored func(*aegisxpb.ScoringResult)) *Streamer {
	return &Streamer{ctx: ctx, endpoint: endpoint, events: events, onScored: onScored}
}

// Run blocks while streaming; it reconnects with exponential backoff on
// failure so a transient PhishGuard restart does not kill the decoys.
func (s *Streamer) Run() {
	backoff := 500 * time.Millisecond
	for {
		if !s.runOnce(&backoff) {
			return // ctx cancelled
		}
		select {
		case <-s.ctx.Done():
			return
		case <-time.After(backoff):
		}
		if backoff < 30*time.Second {
			backoff *= 2
		}
	}
}

// runOnce attempts a single streaming session. Returns false when the context
// is cancelled (permanent stop), true when a reconnect should be attempted.
func (s *Streamer) runOnce(backoff *time.Duration) bool {
	select {
	case <-s.ctx.Done():
		return false
	default:
	}

	conn, err := grpc.NewClient(s.endpoint,
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		slog.Warn("dial upstream failed", "err", err)
		return true
	}

	client := aegisxpb.NewAegisXClient(conn)
	stream, err := client.StreamHoneypotEvents(s.ctx)
	if err != nil {
		_ = conn.Close()
		slog.Warn("open honeypot stream failed", "err", err)
		return true
	}

	s.conn = conn
	s.client = client
	s.connected = true
	*backoff = 500 * time.Millisecond
	slog.Info("connected to PhishGuard AI gateway", "endpoint", s.endpoint)

	// Score fan-in: results come back on the same stream.
	go func() {
		for {
			res, rerr := stream.Recv()
			if rerr != nil {
				return
			}
			if s.onScored != nil {
				s.onScored(res)
			}
		}
	}()

	s.drain(stream)

	s.connected = false
	if s.conn != nil {
		_ = s.conn.Close()
		s.conn = nil
	}
	return true
}

func (s *Streamer) drain(stream aegisxpb.AegisX_StreamHoneypotEventsClient) {
	sub := s.events.Subscribe()
	defer s.events.Unsubscribe(sub)
	for {
		select {
		case <-s.ctx.Done():
			return
		case e, ok := <-sub:
			if !ok {
				return
			}
			if err := stream.Send(e.ToProto()); err != nil {
				if status.Code(err) == codes.Unavailable {
					slog.Warn("upstream unavailable, queueing locally", "err", err)
				}
				return
			}
		}
	}
}

// Healthy reports whether the upstream gRPC channel is live.
func (s *Streamer) Healthy() bool {
	return s.connected
}
