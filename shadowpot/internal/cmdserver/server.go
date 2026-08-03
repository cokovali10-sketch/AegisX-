// Package cmdserver exposes ShadowPot's gRPC command plane.
//
// ShadowPot is primarily a gRPC *client* to the PhishGuard AI gateway, but it
// also listens for unary commands so SOAR playbooks (executed by PhishGuard)
// can trigger immediate, threshold-bypassing mitigations — most notably the
// "mitigate_ban_ip" firewall block — over the same AegisX contract. The
// bidi honeypot/telemetry streams remain client-side on the streamer.
package cmdserver

import (
	"context"
	"crypto/subtle"
	"fmt"
	"log/slog"
	"net"
	"strings"

	"aegisx.local/shadowpot/internal/blocker"
	"aegisx/proto/gen/go"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// Server implements the unary command surface of the AegisX service. Streaming
// methods are left unimplemented (the agent is a client for those).
type Server struct {
	aegisxpb.UnimplementedAegisXServer
	blocker *blocker.Blocker
}

// New builds a command server wired to the shared IP-banning engine.
func New(blocker *blocker.Blocker) *Server {
	return &Server{blocker: blocker}
}

// Command dispatches a control-plane mitigation from PhishGuard/SOAR.
func (s *Server) Command(ctx context.Context, req *aegisxpb.CommandFrame) (*aegisxpb.CommandAck, error) {
	switch req.Command {
	case "mitigate_ban_ip":
		if req.Target == "" {
			return ack(req.Id, false, "ban requires an ip target"), nil
		}
		s.blocker.Block(req.Target)
		return ack(req.Id, true, fmt.Sprintf("ban issued for %s via SOAR", req.Target)), nil
	case "unban_ip":
		if req.Target == "" {
			return ack(req.Id, false, "ban requires an ip target"), nil
		}
		s.blocker.Unblock(req.Target)
		return ack(req.Id, true, fmt.Sprintf("ban released for %s", req.Target)), nil
	case "status":
		return ack(req.Id, true, fmt.Sprintf("shadowpot command plane up; target=%s", req.Target)), nil
	default:
		return ack(req.Id, true, "command acknowledged (no-op)"), nil
	}
}

func ack(id string, accepted bool, detail string) *aegisxpb.CommandAck {
	return &aegisxpb.CommandAck{
		Id:       id,
		Accepted: accepted,
		Detail:   detail,
	}
}

// Serve runs the unary gRPC command server until ctx is cancelled. When
// `token` is non-empty every command must present a matching `Authorization:
// Bearer <token>` metadata entry; an empty token leaves the plane open (dev).
func Serve(ctx context.Context, addr string, blk *blocker.Blocker, token string) error {
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("command server listen %s: %w", addr, err)
	}
	srv := grpc.NewServer(grpc.UnaryInterceptor(authInterceptor(token)))
	aegisxpb.RegisterAegisXServer(srv, New(blk))
	go func() {
		<-ctx.Done()
		srv.GracefulStop()
	}()
	if token == "" {
		slog.Warn("command plane is UNAUTHENTICATED (set SHADOWPOT_GRPC_TOKEN to secure it)")
	} else {
		slog.Info("command plane requires bearer token auth")
	}
	slog.Info("shadowpot command server listening", "addr", addr)
	if err := srv.Serve(lis); err != nil {
		return err
	}
	return nil
}

// authInterceptor enforces a bearer token on every unary command, applying a
// constant-time comparison so the token is not leaked through timing.
func authInterceptor(token string) grpc.UnaryServerInterceptor {
	if token == "" {
		return func(ctx context.Context, req any, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
			return handler(ctx, req)
		}
	}
	want := []byte("Bearer " + token)
	return func(ctx context.Context, req any, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		md, ok := metadata.FromIncomingContext(ctx)
		if !ok {
			return nil, status.Error(codes.Unauthenticated, "missing authorization metadata")
		}
		for _, v := range md.Get("authorization") {
			got := []byte(strings.TrimSpace(v))
			if subtle.ConstantTimeCompare(got, want) == 1 {
				return handler(ctx, req)
			}
		}
		return nil, status.Error(codes.Unauthenticated, "invalid bearer token")
	}
}
