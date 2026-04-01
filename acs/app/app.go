package app

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"sync"

	"execution-platform/acs/api"
	"execution-platform/acs/audit"
	"execution-platform/acs/catalog"
	"execution-platform/acs/config"
)

type App struct {
	cfg        config.Config
	store      *catalog.MemoryStore
	auditSink  audit.Sink
	httpServer *http.Server

	mu       sync.RWMutex
	started  bool
	listener net.Listener
}

func New(cfg config.Config) (*App, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	store, err := catalog.NewMemoryStore(cfg.Catalog.SeedArtifactDigests)
	if err != nil {
		return nil, err
	}

	auditSink := audit.NewNoopSink()
	app := &App{
		cfg:       cfg,
		store:     store,
		auditSink: auditSink,
	}

	server := api.NewServer(store, auditSink, cfg.Authorization.AllowedSPIFFEPathPrefixes, app.Started)
	app.httpServer = &http.Server{
		Addr:         net.JoinHostPort(cfg.HTTP.BindAddress, strconv.Itoa(cfg.HTTP.Port)),
		Handler:      server.Handler(),
		ReadTimeout:  cfg.ReadTimeout(),
		WriteTimeout: cfg.WriteTimeout(),
		ErrorLog:     log.New(os.Stderr, "acs-http: ", log.LstdFlags),
	}

	return app, nil
}

func (a *App) Started() bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.started
}

func (a *App) Addr() string {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.listener == nil {
		return ""
	}
	return a.listener.Addr().String()
}

func (a *App) Start(ctx context.Context) (string, error) {
	if err := a.auditSink.Start(ctx); err != nil {
		return "", fmt.Errorf("start audit sink: %w", err)
	}

	tlsConfig, err := a.loadTLSConfig()
	if err != nil {
		_ = a.auditSink.Close(ctx)
		return "", err
	}

	listener, err := net.Listen("tcp", a.httpServer.Addr)
	if err != nil {
		_ = a.auditSink.Close(ctx)
		return "", fmt.Errorf("listen: %w", err)
	}

	tlsListener := tls.NewListener(listener, tlsConfig)

	a.mu.Lock()
	a.listener = listener
	a.started = true
	a.mu.Unlock()

	if err := a.auditSink.Emit(ctx, "catalog_snapshot_loaded", map[string]any{
		"cache_entries":           a.store.EntryCount(),
		"catalog_seed_digest":     a.store.SeedDigest(),
		"catalog_snapshot_digest": a.store.SnapshotDigest(),
	}); err != nil {
		listener.Close()
		a.mu.Lock()
		a.listener = nil
		a.started = false
		a.mu.Unlock()
		_ = a.auditSink.Close(ctx)
		return "", fmt.Errorf("emit startup audit event: %w", err)
	}

	go func() {
		err := a.httpServer.Serve(tlsListener)
		if err != nil && err != http.ErrServerClosed {
			log.Printf("acs serve error: %v", err)
		}
	}()

	return listener.Addr().String(), nil
}

func (a *App) Shutdown(ctx context.Context) error {
	a.mu.Lock()
	a.started = false
	a.mu.Unlock()

	serverErr := a.httpServer.Shutdown(ctx)
	auditErr := a.auditSink.Close(ctx)

	if serverErr != nil {
		return serverErr
	}
	if auditErr != nil {
		return auditErr
	}
	return nil
}

func (a *App) SeedDigest() string {
	return a.store.SeedDigest()
}

func (a *App) SnapshotDigest() string {
	return a.store.SnapshotDigest()
}

func (a *App) loadTLSConfig() (*tls.Config, error) {
	certificate, err := tls.LoadX509KeyPair(a.cfg.TLS.CertFile, a.cfg.TLS.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("load tls key pair: %w", err)
	}

	caPEM, err := os.ReadFile(a.cfg.TLS.ClientCAFile)
	if err != nil {
		return nil, fmt.Errorf("read client ca file: %w", err)
	}

	clientCAs := x509.NewCertPool()
	if !clientCAs.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("append client ca file: no valid certificates found")
	}

	return &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{certificate},
		ClientCAs:    clientCAs,
		ClientAuth:   tls.VerifyClientCertIfGiven,
	}, nil
}
