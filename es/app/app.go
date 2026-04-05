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

	"execution-substrate/es/admission"
	"execution-substrate/es/api"
	"execution-substrate/es/config"
)

type App struct {
	cfg        config.Config
	service    *admission.Service
	httpServer *http.Server

	mu       sync.RWMutex
	started  bool
	listener net.Listener
}

func New(cfg config.Config) (*App, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	service, err := admission.NewService(cfg)
	if err != nil {
		return nil, err
	}

	app := &App{
		cfg:     cfg,
		service: service,
	}

	server := api.NewServer(service, cfg.Security.BootstrapIssuerCommonName, app.Started)
	app.httpServer = &http.Server{
		Addr:         net.JoinHostPort(cfg.HTTP.BindAddress, strconv.Itoa(cfg.HTTP.Port)),
		Handler:      server.Handler(),
		ReadTimeout:  cfg.ReadTimeout(),
		WriteTimeout: cfg.WriteTimeout(),
		ErrorLog:     log.New(os.Stderr, "es-http: ", log.LstdFlags),
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
	if err := a.service.Initialize(ctx); err != nil {
		return "", err
	}

	tlsConfig, err := a.loadTLSConfig()
	if err != nil {
		return "", err
	}

	listener, err := net.Listen("tcp", a.httpServer.Addr)
	if err != nil {
		return "", fmt.Errorf("listen: %w", err)
	}

	tlsListener := tls.NewListener(listener, tlsConfig)

	a.mu.Lock()
	a.listener = listener
	a.started = true
	a.mu.Unlock()

	go func() {
		err := a.httpServer.Serve(tlsListener)
		if err != nil && err != http.ErrServerClosed {
			log.Printf("es serve error: %v", err)
		}
	}()

	return listener.Addr().String(), nil
}

func (a *App) Shutdown(ctx context.Context) error {
	a.mu.Lock()
	a.started = false
	a.mu.Unlock()
	return a.httpServer.Shutdown(ctx)
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
		ClientAuth:   tls.RequireAndVerifyClientCert,
	}, nil
}
