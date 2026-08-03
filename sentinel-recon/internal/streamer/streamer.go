package streamer

import (
	"context"
	"log/slog"
	"sync"

	"aegisx.local/sentinel-recon/internal/scanner"
	"aegisx/proto/gen/go"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// Streamer forwards discovered open ports to the PhishGuard gateway so the
// Control Center can render live recon on the network map. It uses the
// client-streaming SubmitScan RPC: open ports are pushed up and the server
// replies once with a consolidated summary.
type Streamer struct {
	ctx     context.Context
	conn    *grpc.ClientConn
	client  aegisxpb.AegisXClient
	mu      sync.Mutex
	stream  aegisxpb.AegisX_SubmitScanClient
	pending chan *aegisxpb.OpenPort
	once    sync.Once
}

func New(ctx context.Context, endpoint string) (*Streamer, error) {
	conn, err := grpc.NewClient(endpoint,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(4<<20)))
	if err != nil {
		return nil, err
	}
	return &Streamer{
		ctx:     ctx,
		conn:    conn,
		client:  aegisxpb.NewAegisXClient(conn),
		pending: make(chan *aegisxpb.OpenPort, 512),
	}, nil
}

// Run establishes the client-streaming submission and drains the publish
// queue; it reopens the stream if it breaks during a long scan.
func (s *Streamer) Run() {
	for {
		stream, err := s.client.SubmitScan(s.ctx)
		if err != nil {
			slog.Warn("failed to open scan stream", "err", err)
			return
		}
		s.mu.Lock()
		s.stream = stream
		s.mu.Unlock()

		sendErr := s.drain()
		// Send a terminal empty flow only if we didn't error mid-way.
		_ = sendErr
		return
	}
}

func (s *Streamer) drain() error {
	for {
		select {
		case <-s.ctx.Done():
			return s.ctx.Err()
		case p, ok := <-s.pending:
			if !ok {
				_, err := s.stream.CloseAndRecv()
				return err
			}
			if err := s.stream.Send(p); err != nil {
				slog.Warn("scan stream send failed", "err", err)
				return err
			}
		}
	}
}

func (s *Streamer) Publish(r scanner.Result) {
	select {
	case s.pending <- &aegisxpb.OpenPort{
		Host:     r.Host,
		Port:     int32(r.Port),
		Protocol: r.Protocol,
		State:    r.State,
		Service:  r.Service,
		Banner:   r.Banner,
		RttMs:    r.RTTMs,
	}:
	default:
		slog.Warn("publish queue full; dropping port event")
	}
}

func (s *Streamer) Close() error {
	var err error
	s.once.Do(func() {
		close(s.pending)
		err = s.conn.Close()
	})
	return err
}
