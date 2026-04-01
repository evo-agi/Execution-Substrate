package app

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"sync"

	"execution-platform/cgs/api"
	"execution-platform/cgs/config"
	"execution-platform/cgs/policy"
	"execution-platform/cgs/proof"
)

type Dependencies struct {
	ProofMinter proof.Minter
}

type App struct {
	cfg          config.Config
	httpServer   *http.Server
	listener     net.Listener
	mu           sync.RWMutex
	policyDigest string
	vaultDigest  string
}

func New(cfg config.Config) (*App, error) {
	return NewWithDependencies(cfg, Dependencies{})
}

func NewWithDependencies(cfg config.Config, deps Dependencies) (*App, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	policies, err := policy.Load(cfg.Policy.IDConfPath)
	if err != nil {
		return nil, err
	}

	if err := validateVaultRuntime(cfg.VaultRuntime); err != nil {
		return nil, err
	}

	proofMinter := deps.ProofMinter
	if proofMinter == nil {
		proofMinter, err = proof.NewHMACMinter(cfg.ActionProof.SecretKey, cfg.ActionProof.HashFunction)
		if err != nil {
			return nil, err
		}
	}

	app := &App{
		cfg:          cfg,
		policyDigest: policies.PolicyDigest(),
		vaultDigest:  digestVaultRuntime(cfg.VaultRuntime),
	}

	server := api.NewServer(
		policies,
		cfg.VaultRuntime,
		cfg.Security.BootstrapIssuerCommonName,
		proofMinter,
		app.policyDigest,
		app.vaultDigest,
		"startup",
	)
	app.httpServer = &http.Server{
		Addr:         net.JoinHostPort(cfg.HTTP.BindAddress, strconv.Itoa(cfg.HTTP.Port)),
		Handler:      server.Handler(),
		ReadTimeout:  cfg.ReadTimeout(),
		WriteTimeout: cfg.WriteTimeout(),
		ErrorLog:     log.New(os.Stderr, "cgs-http: ", log.LstdFlags),
	}

	return app, nil
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
	_ = ctx

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
	a.mu.Unlock()

	go func() {
		err := a.httpServer.Serve(tlsListener)
		if err != nil && err != http.ErrServerClosed {
			log.Printf("cgs serve error: %v", err)
		}
	}()

	return listener.Addr().String(), nil
}

func (a *App) Shutdown(ctx context.Context) error {
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
		ClientAuth:   tls.VerifyClientCertIfGiven,
	}, nil
}

func validateVaultRuntime(v config.VaultRuntimeConfig) error {
	if _, err := tls.LoadX509KeyPair(v.ClientCertFile, v.ClientKeyFile); err != nil {
		return fmt.Errorf("load vault_runtime client key pair: %w", err)
	}

	caPEM, err := os.ReadFile(v.ClientCAFile)
	if err != nil {
		return fmt.Errorf("read vault_runtime client ca file: %w", err)
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return fmt.Errorf("append vault_runtime client ca file: no valid certificates found")
	}

	return nil
}

func digestVaultRuntime(v config.VaultRuntimeConfig) string {
	payload := map[string]any{
		"address":            v.Address,
		"auth_mount":         v.AuthMount,
		"auth_role":          v.AuthRole,
		"jwt_audience":       v.JWTAudience,
		"expected_spiffe_id": v.ExpectedSPIFFEID,
	}
	canonical, _ := json.Marshal(payload)
	sum := sha256.Sum256(canonical)
	return "sha256:" + hex.EncodeToString(sum[:])
}
