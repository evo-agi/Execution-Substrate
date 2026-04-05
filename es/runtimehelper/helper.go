package runtimehelper

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

const (
	workloadVaultAuthMode       = "vault_identity_jwt"
	helperRefreshLeadTime       = 2 * time.Second
	helperRefreshRetryInterval  = 1 * time.Second
	helperInitialFetchTimeout   = 5 * time.Second
	helperPerRequestReadTimeout = 5 * time.Second
)

type cachedToken struct {
	jwt    string
	expiry time.Time
}

type helperServer struct {
	client   *workloadapi.Client
	paths    runtimePaths
	audience string

	mu    sync.RWMutex
	token cachedToken
}

func runHelper(args []string) error {
	if len(args) != 0 {
		return fmt.Errorf("helper does not accept positional arguments")
	}
	if os.Geteuid() != 0 || os.Getegid() != 0 {
		return fmt.Errorf("runtime helper must start as 0:0")
	}

	authMode, err := requireEnv(workloadVaultModeEnvKey)
	if err != nil {
		return err
	}
	if authMode != workloadVaultAuthMode {
		return fmt.Errorf("unsupported %s value: %s", workloadVaultModeEnvKey, authMode)
	}
	audience, err := requireEnv(workloadVaultAudienceEnvKey)
	if err != nil {
		return err
	}
	paths, err := runtimePathsFromEnvironment()
	if err != nil {
		return err
	}
	if err := ensureHelperFilesystemBoundary(paths); err != nil {
		return err
	}

	signalCtx, stopSignals := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stopSignals()

	client, err := workloadapi.New(signalCtx, workloadapi.WithAddr("unix://"+paths.spireSocket))
	if err != nil {
		return fmt.Errorf("connect spire workload api: %w", err)
	}
	defer client.Close()

	server := &helperServer{
		client:   client,
		paths:    paths,
		audience: audience,
	}

	readyCtx, cancelReady := context.WithTimeout(signalCtx, helperInitialFetchTimeout)
	defer cancelReady()
	if err := server.refreshToken(readyCtx); err != nil {
		return fmt.Errorf("initial jwt-svid fetch failed: %w", err)
	}

	if err := os.Remove(paths.endpointPath); err != nil && !isNotExist(err) {
		return fmt.Errorf("remove stale endpoint socket: %w", err)
	}
	listener, err := net.Listen("unix", paths.endpointPath)
	if err != nil {
		return fmt.Errorf("bind runtime identity endpoint: %w", err)
	}
	defer listener.Close()

	if err := os.Chown(paths.endpointPath, workloadUID, workloadGID); err != nil {
		return fmt.Errorf("chown runtime identity endpoint: %w", err)
	}
	if err := os.Chmod(paths.endpointPath, 0o600); err != nil {
		return fmt.Errorf("chmod runtime identity endpoint: %w", err)
	}

	snapshot, err := dropHelperSteadyStatePrivileges()
	if err != nil {
		return fmt.Errorf("drop helper steady-state privileges: %w", err)
	}
	fmt.Printf("%s cap_eff=%s cap_prm=%s cap_amb=%s cap_bnd=%s no_new_privs=%t\n",
		helperCapsLogPrefix, snapshot.CapEff, snapshot.CapPrm, snapshot.CapAmb, snapshot.CapBnd, snapshot.NoNewPrivs)
	fmt.Printf("%s endpoint=%s target=%s\n", helperReadyLogMarker, paths.endpointPath, endpointRequestTargetWorkload)

	serveErrCh := make(chan error, 1)
	refreshErrCh := make(chan error, 1)
	go func() {
		serveErrCh <- server.serve(signalCtx, listener)
	}()
	go func() {
		refreshErrCh <- server.refreshLoop(signalCtx, listener)
	}()

	select {
		case <-signalCtx.Done():
			_ = listener.Close()
			return nil
		case err := <-refreshErrCh:
			_ = listener.Close()
			if signalCtx.Err() != nil {
				return nil
			}
			return err
		case err := <-serveErrCh:
			if signalCtx.Err() != nil {
				return nil
			}
			return err
	}
}

func ensureHelperFilesystemBoundary(paths runtimePaths) error {
	if err := os.Chown(paths.workspaceRoot, 0, 0); err != nil {
		return fmt.Errorf("chown runtime identity workspace root: %w", err)
	}
	if err := os.Chmod(paths.workspaceRoot, 0o711); err != nil {
		return fmt.Errorf("chmod runtime identity workspace root: %w", err)
	}
	if err := os.Chown(paths.workspaceDir, 0, 0); err != nil {
		return fmt.Errorf("chown runtime identity workspace: %w", err)
	}
	if err := os.Chmod(paths.workspaceDir, 0o711); err != nil {
		return fmt.Errorf("chmod runtime identity workspace: %w", err)
	}
	if err := os.MkdirAll(paths.internalDir, 0o700); err != nil {
		return fmt.Errorf("create internal runtime identity dir: %w", err)
	}
	if err := os.Chown(paths.internalDir, 0, 0); err != nil {
		return fmt.Errorf("chown internal runtime identity dir: %w", err)
	}
	if err := os.Chmod(paths.internalDir, 0o700); err != nil {
		return fmt.Errorf("chmod internal runtime identity dir: %w", err)
	}

	info, err := os.Stat(paths.spireSocket)
	if err != nil {
		return fmt.Errorf("validate spire workload api socket: %w", err)
	}
	if info.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("validate spire workload api socket: helper-private path is not a unix socket")
	}
	return nil
}

func (s *helperServer) serve(ctx context.Context, listener net.Listener) error {
	for {
		connection, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("accept runtime identity endpoint: %w", err)
		}

		go s.handleConnection(connection)
	}
}

func (s *helperServer) handleConnection(connection net.Conn) {
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(helperPerRequestReadTimeout))

	reader := bufio.NewReader(connection)
	line, err := reader.ReadString('\n')
	if err != nil {
		_, _ = connection.Write(appendJSONLine(endpointResponse{Error: "read_failed"}))
		return
	}

	var request endpointRequest
	if err := json.Unmarshal([]byte(strings.TrimSpace(line)), &request); err != nil {
		_, _ = connection.Write(appendJSONLine(endpointResponse{Error: "invalid_json"}))
		return
	}
	if request.Kind != endpointRequestKindJWTSVID || request.Target != endpointRequestTargetWorkload {
		_, _ = connection.Write(appendJSONLine(endpointResponse{Error: "unsupported_request"}))
		return
	}

	token, err := s.currentToken()
	if err != nil {
		_, _ = connection.Write(appendJSONLine(endpointResponse{Error: "identity_unavailable"}))
		return
	}
	_, _ = connection.Write(appendJSONLine(endpointResponse{
		JWT:       token.jwt,
		ExpiresAt: token.expiry.UTC().Format(time.RFC3339),
	}))
}

func (s *helperServer) refreshLoop(ctx context.Context, listener net.Listener) error {
	for {
		token, err := s.currentToken()
		if err != nil {
			if refreshErr := s.refreshToken(ctx); refreshErr != nil {
				_ = listener.Close()
				return fmt.Errorf("runtime identity token expired and refresh failed: %w", refreshErr)
			}
			continue
		}

		refreshAt := token.expiry.Add(-helperRefreshLeadTime)
		if refreshAt.Before(time.Now()) {
			refreshAt = time.Now().Add(helperRefreshRetryInterval)
		}

		timer := time.NewTimer(time.Until(refreshAt))
		select {
			case <-ctx.Done():
				timer.Stop()
				return nil
			case <-timer.C:
		}

		if err := s.refreshToken(ctx); err != nil {
			token, tokenErr := s.currentToken()
			if tokenErr == nil && time.Now().Before(token.expiry) {
				time.Sleep(helperRefreshRetryInterval)
				continue
			}
			_ = listener.Close()
			return fmt.Errorf("refresh jwt-svid: %w", err)
		}
	}
}

func (s *helperServer) refreshToken(ctx context.Context) error {
	refreshCtx, cancel := context.WithTimeout(ctx, helperInitialFetchTimeout)
	defer cancel()

	svid, err := s.client.FetchJWTSVID(refreshCtx, jwtsvid.Params{
		Audience: s.audience,
	})
	if err != nil {
		return err
	}

	s.mu.Lock()
	s.token = cachedToken{
		jwt:    svid.Marshal(),
		expiry: svid.Expiry.UTC(),
	}
	s.mu.Unlock()
	return nil
}

func (s *helperServer) currentToken() (cachedToken, error) {
	s.mu.RLock()
	token := s.token
	s.mu.RUnlock()
	if strings.TrimSpace(token.jwt) == "" {
		return cachedToken{}, fmt.Errorf("token not initialized")
	}
	if !time.Now().Before(token.expiry) {
		return cachedToken{}, fmt.Errorf("token expired")
	}
	return token, nil
}

func appendJSONLine(payload endpointResponse) []byte {
	body, _ := json.Marshal(payload)
	return append(body, '\n')
}
