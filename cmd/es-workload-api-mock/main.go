package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"flag"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	workloadpb "github.com/spiffe/go-spiffe/v2/proto/spiffe/workload"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type server struct {
	workloadpb.UnimplementedSpiffeWorkloadAPIServer

	signer  jose.Signer
	subject string
	ttl     time.Duration
}

func (s *server) FetchJWTSVID(ctx context.Context, request *workloadpb.JWTSVIDRequest) (*workloadpb.JWTSVIDResponse, error) {
	if len(request.Audience) == 0 {
		return nil, status.Error(codes.InvalidArgument, "audience is required")
	}
	if strings.TrimSpace(request.SpiffeId) != "" && strings.TrimSpace(request.SpiffeId) != s.subject {
		return nil, status.Error(codes.NotFound, "unknown spiffe id")
	}

	now := time.Now().UTC()
	token, err := jwt.Signed(s.signer).Claims(jwt.Claims{
		Subject:  s.subject,
		Audience: jwt.Audience(request.Audience),
		IssuedAt: jwt.NewNumericDate(now),
		Expiry:   jwt.NewNumericDate(now.Add(s.ttl)),
	}).Serialize()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "mint jwt-svid: %v", err)
	}

	return &workloadpb.JWTSVIDResponse{
		Svids: []*workloadpb.JWTSVID{
			{
				SpiffeId: s.subject,
				Svid:     token,
				Hint:     "default",
			},
		},
	}, nil
}

func main() {
	var (
		socketPath = flag.String("socket", "", "absolute Unix socket path to serve on")
		subject    = flag.String("subject", "spiffe://execution.internal/workload", "SPIFFE subject for minted JWT-SVIDs")
		ttl        = flag.Duration("ttl", 20*time.Second, "JWT-SVID TTL")
	)
	flag.Parse()

	if strings.TrimSpace(*socketPath) == "" {
		log.Fatal("-socket is required")
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("generate signing key: %v", err)
	}
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: privateKey},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", "mock-workload-api"),
	)
	if err != nil {
		log.Fatalf("build signer: %v", err)
	}

	_ = os.Remove(*socketPath)
	listener, err := net.Listen("unix", *socketPath)
	if err != nil {
		log.Fatalf("listen on unix socket: %v", err)
	}
	if err := os.Chmod(*socketPath, 0o777); err != nil {
		log.Fatalf("chmod socket: %v", err)
	}

	grpcServer := grpc.NewServer()
	workloadpb.RegisterSpiffeWorkloadAPIServer(grpcServer, &server{
		signer:  signer,
		subject: strings.TrimSpace(*subject),
		ttl:     *ttl,
	})

	signalCh := make(chan os.Signal, 1)
	signal.Notify(signalCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-signalCh
		grpcServer.GracefulStop()
		_ = listener.Close()
		_ = os.Remove(*socketPath)
	}()

	log.Printf("serving mock SPIFFE Workload API on %s for subject %s", *socketPath, *subject)
	if err := grpcServer.Serve(listener); err != nil {
		log.Fatalf("serve workload api: %v", err)
	}
}
