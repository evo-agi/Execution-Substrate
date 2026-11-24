package app_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	agsapp "execution-substrate/ags/app"
	agsconfig "execution-substrate/ags/config"
	arsapp "execution-substrate/ars/app"
	arsconfig "execution-substrate/ars/config"
	egsapp "execution-substrate/egs/app"
	egsconfig "execution-substrate/egs/config"
	egsmodel "execution-substrate/egs/model"
	esapp "execution-substrate/es/app"
	esconfig "execution-substrate/es/config"
	runtimeconfigv1 "execution-substrate/internal/contracts/runtimeconfig/v1"
)

func TestResolvedPlanCustodyHermeticAmbiguousRegistrationRetainsStage(t *testing.T) {
	var registrations atomic.Int32
	stack := startResolvedPlanCustodyHermeticStack(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/jobs" {
			t.Errorf("unexpected fake Nomad request %s %q", r.Method, r.URL.Path)
			return
		}
		registrations.Add(1)
		panic(http.ErrAbortHandler)
	}))
	response := submitExecutionRequest(t, stack, buildSubmitRequestBody(t, stack))
	defer response.Body.Close()
	body := string(mustReadBody(t, response.Body))
	if response.StatusCode != http.StatusServiceUnavailable || !strings.Contains(body, `"code":"submission_failed"`) {
		t.Fatalf("ambiguous registration response: status=%d body=%s", response.StatusCode, body)
	}
	if registrations.Load() != 1 {
		t.Fatalf("registrations = %d, want 1", registrations.Load())
	}
	entries, err := os.ReadDir(filepath.Join(stack.rootDir, "es-stage"))
	if err != nil {
		t.Fatalf("claimed stage root was not retained: entries=%v err=%v", entries, err)
	}
	var runName string
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), "run-") {
			if runName != "" || !entry.IsDir() {
				t.Fatalf("ambiguous registration retained unexpected run roots: entries=%v", entries)
			}
			runName = entry.Name()
		}
	}
	if runName == "" {
		t.Fatalf("ambiguous registration retained no run root: entries=%v", entries)
	}
	if _, err := os.Lstat(filepath.Join(stack.rootDir, "es-stage", runName, "payload")); err != nil {
		t.Fatalf("retained stage material is absent: %v", err)
	}
}

func TestResolvedPlanCustodyHermeticTerminalSuccessRetainsStage(t *testing.T) {
	var registrations atomic.Int32
	stack := startResolvedPlanCustodyHermeticStack(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/jobs":
			registrations.Add(1)
			_, _ = w.Write([]byte(`{"EvalID":"eval-hermetic"}`))
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v1/job/") && strings.HasSuffix(r.URL.Path, "/allocations"):
			_, _ = w.Write([]byte(`[{"ID":"alloc-success","ModifyIndex":20}]`))
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v1/job/"):
			jobID := strings.TrimPrefix(r.URL.Path, "/v1/job/")
			_, _ = w.Write([]byte(fmt.Sprintf(`{"ID":%q,"Status":"dead","ModifyIndex":10}`, jobID)))
		case r.Method == http.MethodGet && r.URL.Path == "/v1/allocation/alloc-success":
			_, _ = w.Write([]byte(`{"ID":"alloc-success","ClientStatus":"complete","ModifyIndex":25,"TaskStates":{"task":{"State":"dead","Events":[{"Type":"Terminated","ExitCode":0}]}}}`))
		default:
			t.Errorf("unexpected fake Nomad request %s %q", r.Method, r.URL.Path)
		}
	}))
	response := submitExecutionRequest(t, stack, buildSubmitRequestBody(t, stack))
	defer response.Body.Close()
	if response.StatusCode != http.StatusAccepted {
		t.Fatalf("submit status=%d body=%s", response.StatusCode, mustReadBody(t, response.Body))
	}
	var submitted struct {
		RunID string `json:"run_id"`
	}
	if err := json.NewDecoder(response.Body).Decode(&submitted); err != nil || submitted.RunID == "" {
		t.Fatalf("decode accepted receipt: run=%q err=%v", submitted.RunID, err)
	}
	stagePath := filepath.Join(stack.rootDir, "es-stage", submitted.RunID)
	if _, err := os.Lstat(stagePath); err != nil {
		t.Fatalf("stage root missing before terminal observation: %v", err)
	}
	status := fetchExecutionStatus(t, stack, submitted.RunID)
	if !status.Terminal || status.Status != "terminal" || status.ExitCode == nil || *status.ExitCode != 0 {
		t.Fatalf("unexpected terminal status: %+v", status)
	}
	if registrations.Load() != 1 {
		t.Fatalf("registrations = %d, want 1", registrations.Load())
	}
	if _, err := os.Lstat(stagePath); err != nil {
		t.Fatalf("terminal observation removed claimed stage root: %v", err)
	}
}

func TestResolvedPlanCustodyHermeticRepeatedResultReadIsNonMutating(t *testing.T) {
	stack, runID, expected, nomadCalls := startHermeticCommittedResult(t)
	runPath := filepath.Join(stack.rootDir, "es-results", runID)
	before, err := os.Lstat(runPath)
	if err != nil {
		t.Fatal(err)
	}
	beforeChange := hermeticResultChangeTime(t, before)
	previousCalls := nomadCalls.Load()
	for attempt := 0; attempt < 2; attempt++ {
		response := executionResultRequestWithCaller(t, stack, runID, "operator/local")
		body := mustReadBody(t, response.Body)
		_ = response.Body.Close()
		if response.StatusCode != http.StatusOK || !bytes.Equal(body, expected) {
			t.Fatalf("result read %d: status=%d body=%q", attempt+1, response.StatusCode, body)
		}
	}
	if nomadCalls.Load() != previousCalls {
		t.Fatalf("retained fast reads made %d Nomad calls", nomadCalls.Load()-previousCalls)
	}
	after, err := os.Lstat(runPath)
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(before, after) || before.Mode() != after.Mode() || hermeticResultChangeTime(t, after) != beforeChange {
		t.Fatal("repeat public result reads mutated existing directory metadata")
	}
}

type hermeticRetainedObject struct {
	mode   os.FileMode
	size   int64
	device uint64
	inode  uint64
	digest [sha256.Size]byte
}

func hermeticRetainedInventory(t *testing.T, runPath string) map[string]hermeticRetainedObject {
	t.Helper()
	entries, err := os.ReadDir(runPath)
	if err != nil {
		t.Fatal(err)
	}
	inventory := make(map[string]hermeticRetainedObject, len(entries))
	for _, entry := range entries {
		path := filepath.Join(runPath, entry.Name())
		info, err := os.Lstat(path)
		if err != nil {
			t.Fatal(err)
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || !info.Mode().IsRegular() {
			t.Fatalf("retained result entry has unexpected type: %s", entry.Name())
		}
		payload, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		inventory[entry.Name()] = hermeticRetainedObject{info.Mode(), info.Size(), uint64(stat.Dev), uint64(stat.Ino), sha256.Sum256(payload)}
	}
	return inventory
}

func TestRetainedResultReviewHermeticTerminalObservationIdempotence(t *testing.T) {
	stack, runID, committed, _ := startHermeticCommittedResult(t)
	runPath := filepath.Join(stack.rootDir, "es-results", runID)
	baseline := hermeticRetainedInventory(t, runPath)
	if len(baseline) < 2 {
		t.Fatalf("incomplete retained inventory: %v", baseline)
	}
	stagePath := filepath.Join(stack.rootDir, "es-stage", runID)
	if err := os.WriteFile(filepath.Join(stagePath, "run", "result", "summary.txt"), []byte("changed"), 0o640); err != nil {
		t.Fatal(err)
	}
	for phase := 0; phase < 2; phase++ {
		if phase == 1 {
			if err := os.Rename(stagePath, filepath.Join(stack.rootDir, "moved-stage-run")); err != nil {
				t.Fatal(err)
			}
		}
		for attempt := 0; attempt < 2; attempt++ {
			status := executionStatusRequestWithCaller(t, stack, runID, "operator/local")
			statusBody := mustReadBody(t, status.Body)
			_ = status.Body.Close()
			if status.StatusCode != http.StatusOK || !bytes.Contains(statusBody, []byte("terminal")) {
				t.Fatalf("terminal status %d: status=%d body=%q", attempt, status.StatusCode, statusBody)
			}
			logs := executionLogsRequestWithCaller(t, stack, runID, "operator/local")
			logsBody := mustReadBody(t, logs.Body)
			_ = logs.Body.Close()
			if logs.StatusCode != http.StatusOK || !bytes.Contains(logsBody, []byte("synthetic logs")) {
				t.Fatalf("terminal logs %d: status=%d body=%q", attempt, logs.StatusCode, logsBody)
			}
			result := executionResultRequestWithCaller(t, stack, runID, "operator/local")
			resultBody := mustReadBody(t, result.Body)
			_ = result.Body.Close()
			if result.StatusCode != http.StatusOK || !bytes.Equal(resultBody, committed) {
				t.Fatalf("retained result %d changed: status=%d", attempt, result.StatusCode)
			}
			if got := hermeticRetainedInventory(t, runPath); !reflect.DeepEqual(got, baseline) {
				t.Fatalf("terminal observation changed retained inventory: got=%v want=%v", got, baseline)
			}
		}
	}
}

func TestResolvedPlanCustodyHermeticAuthenticatedResultHTTPReaderRejectsMutation(t *testing.T) {
	stack, runID, _, nomadCalls := startHermeticCommittedResult(t)
	finalPath := filepath.Join(stack.rootDir, "es-results", runID, "result.tar.gz")
	payload, err := os.ReadFile(finalPath)
	if err != nil {
		t.Fatal(err)
	}
	payload[len(payload)-1] ^= 1
	if err := os.WriteFile(finalPath, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	previousCalls := nomadCalls.Load()
	response := executionResultRequestWithCaller(t, stack, runID, "operator/local")
	body := mustReadBody(t, response.Body)
	_ = response.Body.Close()
	if response.StatusCode != http.StatusConflict || !bytes.Contains(body, []byte(`"code":"result_unavailable"`)) || bytes.Equal(body, payload) {
		t.Fatalf("HTTP reader served altered final: status=%d body=%q", response.StatusCode, body)
	}
	if nomadCalls.Load() != previousCalls {
		t.Fatal("invalid retained pair fell through to Nomad")
	}
}

func TestResolvedPlanCustodyHermeticAuthenticatedResultHTTPReaderRejectsUnmarkedFinal(t *testing.T) {
	stack, runID, committed, nomadCalls := startHermeticCommittedResult(t)
	recordPath := filepath.Join(stack.rootDir, "es-results", runID, "result.commit.v1")
	if err := os.Remove(recordPath); err != nil {
		t.Fatal(err)
	}
	previousCalls := nomadCalls.Load()
	response := executionResultRequestWithCaller(t, stack, runID, "operator/local")
	body := mustReadBody(t, response.Body)
	_ = response.Body.Close()
	if response.StatusCode != http.StatusConflict || !bytes.Contains(body, []byte(`"code":"result_unavailable"`)) ||
		bytes.Equal(body, committed) || response.Header.Get("Content-Type") == "application/gzip" ||
		bytes.Contains(body, []byte(filepath.Join(stack.rootDir, "es-auth", "key"))) {
		t.Fatalf("HTTP reader served unmarked final: status=%d body=%q", response.StatusCode, body)
	}
	if nomadCalls.Load() != previousCalls {
		t.Fatal("unmarked final fell through to Nomad")
	}
}

func startHermeticCommittedResult(t *testing.T) (*submitStack, string, []byte, *atomic.Int32) {
	t.Helper()
	var nomadCalls atomic.Int32
	var stack *submitStack
	stack = startResolvedPlanCustodyHermeticStack(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/jobs":
			body, err := io.ReadAll(r.Body)
			if err != nil {
				t.Errorf("read fake Nomad request: %v", err)
			}
			if bytes.Contains(body, []byte(filepath.Join(stack.rootDir, "es-auth", "key"))) || bytes.Contains(body, bytes.Repeat([]byte{0x53}, 32)) {
				t.Error("retained-result authentication material entered Nomad registration")
			}
			_, _ = w.Write([]byte(`{"EvalID":"eval-hermetic"}`))
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v1/job/") && strings.HasSuffix(r.URL.Path, "/allocations"):
			nomadCalls.Add(1)
			_, _ = w.Write([]byte(`[{"ID":"alloc-success","ModifyIndex":20}]`))
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v1/job/"):
			nomadCalls.Add(1)
			jobID := strings.TrimPrefix(r.URL.Path, "/v1/job/")
			_, _ = w.Write([]byte(fmt.Sprintf(`{"ID":%q,"Status":"dead","ModifyIndex":10}`, jobID)))
		case r.Method == http.MethodGet && r.URL.Path == "/v1/allocation/alloc-success":
			nomadCalls.Add(1)
			_, _ = w.Write([]byte(`{"ID":"alloc-success","ClientStatus":"complete","ModifyIndex":25,"TaskStates":{"task":{"State":"dead","Events":[{"Type":"Terminated","ExitCode":0}]}}}`))
		case r.Method == http.MethodGet && r.URL.Path == "/v1/client/fs/logs/alloc-success":
			nomadCalls.Add(1)
			_, _ = w.Write([]byte("synthetic logs\n"))
		default:
			t.Errorf("unexpected fake Nomad request %s %q", r.Method, r.URL.Path)
		}
	}))
	response := submitExecutionRequest(t, stack, buildSubmitRequestBody(t, stack))
	defer response.Body.Close()
	if response.StatusCode != http.StatusAccepted {
		t.Fatalf("submit status=%d body=%s", response.StatusCode, mustReadBody(t, response.Body))
	}
	var submitted struct {
		RunID string `json:"run_id"`
	}
	if err := json.NewDecoder(response.Body).Decode(&submitted); err != nil || submitted.RunID == "" {
		t.Fatalf("decode receipt: run=%q err=%v", submitted.RunID, err)
	}
	resultPath := filepath.Join(stack.rootDir, "es-stage", submitted.RunID, "run", "result", "summary.txt")
	if err := os.WriteFile(resultPath, []byte("synthetic result\n"), 0o640); err != nil {
		t.Fatalf("write synthetic staged result: %v", err)
	}
	first := executionResultRequestWithCaller(t, stack, submitted.RunID, "operator/local")
	resultBytes := mustReadBody(t, first.Body)
	_ = first.Body.Close()
	if first.StatusCode != http.StatusOK || first.Header.Get("Content-Type") != "application/gzip" || len(resultBytes) == 0 {
		t.Fatalf("first committed result: status=%d body=%q", first.StatusCode, resultBytes)
	}
	return stack, submitted.RunID, resultBytes, &nomadCalls
}

func hermeticResultChangeTime(t *testing.T, info os.FileInfo) string {
	t.Helper()
	stat := reflect.ValueOf(info.Sys())
	if stat.Kind() != reflect.Ptr || stat.IsNil() {
		t.Fatal("result fixture has no stat metadata")
	}
	stat = stat.Elem()
	change := stat.FieldByName("Ctimespec")
	if !change.IsValid() {
		change = stat.FieldByName("Ctim")
	}
	if !change.IsValid() {
		t.Fatal("result fixture has no metadata change timestamp")
	}
	return fmt.Sprint(change.Interface())
}

// This fixture has only loopback services and a private testing root.
// Its runtime-support build uses the same local Go toolchain as the test.
func startResolvedPlanCustodyHermeticStack(t *testing.T, handler http.Handler) *submitStack {
	t.Helper()
	if handler == nil {
		t.Fatal("hermetic Nomad handler is required")
	}
	opts := submitStackOptions{nomadHandler: handler}
	rootDir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil || !filepath.IsAbs(rootDir) {
		t.Fatalf("resolve private fixture root: path=%q err=%v", rootDir, err)
	}
	stagingRoot, resultsRoot := prepareSubmitStackExecutionRoots(t, rootDir)
	resultAuth := newSubmitStackSyntheticRetainedResultAuth(t, rootDir)
	fixture := newTLSFixture(t)
	var nomad *nomadHarness
	nomadServer := httptest.NewServer(lockedFakeNomadHandler(handler))
	nomadBaseURL := nomadServer.URL
	nomadTokenFile := writeFakeNomadTokenFile(t, rootDir)
	runtimeSupportBinary := buildResolvedPlanCustodyHermeticRuntimeSupport(t, rootDir)
	mockSPIRE := startMockWorkloadAPIServer(t, rootDir, mockWorkloadAPIServerOptions{
		jwtTTL:    firstNonZeroDuration(opts.mockSPIREJWTTTL, 20*time.Second),
		failFetch: opts.mockSPIREFetchError,
	})

	arsRootDir := filepath.Join(rootDir, "ars-storage")
	if err := os.MkdirAll(arsRootDir, 0o755); err != nil {
		t.Fatalf("mkdir ars storage root: %v", err)
	}
	indexPath := filepath.Join(rootDir, "artifact-index.json")
	if err := os.WriteFile(indexPath, []byte("{}\n"), 0o600); err != nil {
		t.Fatalf("write empty artifact index: %v", err)
	}

	vaultConfig := map[string]any{
		"address":      firstNonEmpty(opts.workloadVaultAddress, "https://vault.internal:8200"),
		"auth_mount":   "jwt",
		"auth_role":    "service_execution",
		"jwt_audience": "vault",
	}
	if strings.TrimSpace(opts.workloadVaultCABundlePEM) != "" {
		vaultConfig["ca_bundle_pem"] = opts.workloadVaultCABundlePEM
	}
	workloadZoneVaultBytes := mustMarshalJSON(t, map[string]any{
		"vault_config": vaultConfig,
	})
	workloadZoneVaultDigest := writeBlobBytes(t, arsRootDir, workloadZoneVaultBytes)

	allowedAGSCallerPrefixes := []string{"operator/local"}
	if len(opts.allowedAGSCallerPrefixes) > 0 {
		allowedAGSCallerPrefixes = append([]string(nil), opts.allowedAGSCallerPrefixes...)
	}
	allowedExecutionCallerPrefixes := []string{"operator/local"}
	if len(opts.allowedExecutionCallerPrefixes) > 0 {
		allowedExecutionCallerPrefixes = append([]string(nil), opts.allowedExecutionCallerPrefixes...)
	}
	publishCallerPath := firstNonEmpty(opts.publishCallerPath, "operator/local")
	executionCallerPath := firstNonEmpty(opts.executionCallerPath, "operator/local")

	stack := &submitStack{
		fixture:                 fixture,
		rootDir:                 rootDir,
		arsRootDir:              arsRootDir,
		indexPath:               indexPath,
		publishCallerPath:       publishCallerPath,
		executionCallerPath:     executionCallerPath,
		nomad:                   nomad,
		nomadServer:             nomadServer,
		mockSPIRE:               mockSPIRE,
		intentDigest:            labeledDigest("aa"),
		derivationSpecDigest:    labeledDigest("bb"),
		outputID:                "runtime",
		workloadZoneVaultDigest: workloadZoneVaultDigest,
	}

	arsCfg := arsconfig.Config{
		HTTP: arsconfig.HTTPConfig{
			BindAddress:            "127.0.0.1",
			Port:                   0,
			ReadTimeoutSeconds:     5,
			WriteTimeoutSeconds:    5,
			ShutdownTimeoutSeconds: 5,
		},
		TLS: arsconfig.TLSConfig{
			CertFile:     fixture.arsServerCertPath,
			KeyFile:      fixture.arsServerKeyPath,
			ClientCAFile: fixture.clientCAPath,
		},
		Security: arsconfig.SecurityConfig{
			BootstrapIssuerCommonName: fixture.bootstrapCACN,
		},
		Authorization: arsconfig.AuthorizationConfig{
			AllowedSPIFFEPathPrefixes: []string{"service/execution"},
		},
		Storage: arsconfig.StorageConfig{
			RootDir:   arsRootDir,
			IndexFile: indexPath,
		},
	}
	arsService, err := arsapp.New(arsCfg)
	if err != nil {
		t.Fatalf("build ars app: %v", err)
	}
	stack.ars = arsService
	startService(t, arsService.Start, arsService.Addr, fixture.clientTLSConfigForServer(t, fixture.arsServerName, "service/execution", false))
	stack.arsRunning = true

	egsCfg := egsconfig.Config{
		HTTP: egsconfig.HTTPConfig{
			BindAddress:            "127.0.0.1",
			Port:                   0,
			ReadTimeoutSeconds:     5,
			WriteTimeoutSeconds:    5,
			ShutdownTimeoutSeconds: 5,
		},
		TLS: egsconfig.TLSConfig{
			CertFile:     fixture.egsServerCertPath,
			KeyFile:      fixture.egsServerKeyPath,
			ClientCAFile: fixture.clientCAPath,
		},
		Security: egsconfig.SecurityConfig{
			BootstrapIssuerCommonName: fixture.bootstrapCACN,
		},
		Signer: egsconfig.SignerConfig{
			Algorithm:     "ed25519",
			KeyID:         fixture.egsKeyID,
			PrivateKeyHex: fixture.egsPrivateKeyHex,
			PublicKeyHex:  fixture.egsPublicKeyHex,
		},
		RuntimeTrust: egsmodel.RuntimeTrustPolicy{
			SignerPolicy: egsmodel.SignerPolicy{
				AllowedSigners: []string{fixture.agsKeyID},
				RevokedSigners: []string{},
			},
			ArtifactPolicy: egsmodel.ArtifactPolicy{
				RevokedArtifacts: []string{},
			},
		},
		Publication: egsmodel.PublicationMetadata{
			UpdateRevision: 7,
			Version:        "1.0.0",
		},
	}
	egsService, err := egsapp.New(egsCfg)
	if err != nil {
		t.Fatalf("build egs app: %v", err)
	}
	stack.egs = egsService
	startService(t, egsService.Start, egsService.Addr, fixture.clientTLSConfigForServer(t, fixture.egsServerName, "service/execution", false))
	stack.egsRunning = true

	agsCfg := agsconfig.Config{
		HTTP: agsconfig.HTTPConfig{
			BindAddress:            "127.0.0.1",
			Port:                   0,
			ReadTimeoutSeconds:     5,
			WriteTimeoutSeconds:    5,
			ShutdownTimeoutSeconds: 5,
		},
		TLS: agsconfig.TLSConfig{
			CertFile:     fixture.agsServerCertPath,
			KeyFile:      fixture.agsServerKeyPath,
			ClientCAFile: fixture.clientCAPath,
		},
		Security: agsconfig.SecurityConfig{
			BootstrapIssuerCommonName: fixture.bootstrapCACN,
		},
		Authorization: agsconfig.AuthorizationConfig{
			AllowedSPIFFEPathPrefixes: allowedAGSCallerPrefixes,
		},
		Dependencies: agsconfig.DependenciesConfig{
			ArtifactRegistry: agsconfig.DependencyConfig{
				BaseURL:        "https://" + stack.ars.Addr(),
				ServerName:     fixture.arsServerName,
				ClientCertFile: fixture.agsClientCertPath,
				ClientKeyFile:  fixture.agsClientKeyPath,
				RootCAFile:     fixture.runtimeCAPath,
				TimeoutSeconds: 5,
			},
		},
		Signer: agsconfig.SignerConfig{
			Algorithm:     "ed25519",
			KeyID:         fixture.agsKeyID,
			PrivateKeyHex: fixture.agsPrivateKeyHex,
			PublicKeyHex:  fixture.agsPublicKeyHex,
		},
	}
	agsService, err := agsapp.New(agsCfg)
	if err != nil {
		t.Fatalf("build ags app: %v", err)
	}
	stack.ags = agsService
	startService(t, agsService.Start, agsService.Addr, fixture.clientTLSConfigForServer(t, fixture.agsServerName, "operator/local", false))
	stack.agsRunning = true

	esCfg := esconfig.Config{
		HTTP: esconfig.HTTPConfig{
			BindAddress:            "127.0.0.1",
			Port:                   0,
			ReadTimeoutSeconds:     5,
			WriteTimeoutSeconds:    5,
			ShutdownTimeoutSeconds: 5,
		},
		TLS: esconfig.TLSConfig{
			CertFile:     fixture.esServerCertPath,
			KeyFile:      fixture.esServerKeyPath,
			ClientCAFile: fixture.clientCAPath,
		},
		Security: esconfig.SecurityConfig{
			BootstrapIssuerCommonName: fixture.bootstrapCACN,
		},
		Authorization: esconfig.AuthorizationConfig{
			AllowedSPIFFEPathPrefixes: allowedExecutionCallerPrefixes,
		},
		Dependencies: esconfig.DependenciesConfig{
			ArtifactRegistry: esconfig.DependencyConfig{
				BaseURL:        "https://" + stack.ars.Addr(),
				ServerName:     fixture.arsServerName,
				ClientCertFile: fixture.executionClientCertPath,
				ClientKeyFile:  fixture.executionClientKeyPath,
				RootCAFile:     fixture.runtimeCAPath,
				TimeoutSeconds: 5,
			},
			ExecutionGovernance: esconfig.DependencyConfig{
				BaseURL:        "https://" + stack.egs.Addr(),
				ServerName:     fixture.egsServerName,
				ClientCertFile: fixture.executionClientCertPath,
				ClientKeyFile:  fixture.executionClientKeyPath,
				RootCAFile:     fixture.runtimeCAPath,
				TimeoutSeconds: 5,
			},
		},
		RuntimeConfig: esconfig.RuntimeConfigConfig{
			WorkloadZoneVaultConfigRef: runtimeconfigv1.WorkloadZoneVaultConfigRef{
				Digest: workloadZoneVaultDigest,
			},
		},
		Verification: esconfig.VerificationConfig{
			TrustModel: esconfig.SignerVerifierConfig{
				Algorithm:    "ed25519",
				KeyID:        fixture.egsKeyID,
				PublicKeyHex: fixture.egsPublicKeyHex,
			},
			Provenance: esconfig.SignerVerifierConfig{
				Algorithm:    "ed25519",
				KeyID:        fixture.agsKeyID,
				PublicKeyHex: fixture.agsPublicKeyHex,
			},
			DerivationAttestation: esconfig.SignerVerifierConfig{
				Algorithm:    "ed25519",
				KeyID:        fixture.agsKeyID,
				PublicKeyHex: fixture.agsPublicKeyHex,
			},
			WorkloadIdentityBinding: esconfig.SignerVerifierConfig{
				Algorithm:    "ed25519",
				KeyID:        fixture.agsKeyID,
				PublicKeyHex: fixture.agsPublicKeyHex,
			},
		},
		WorkloadVaultAuth: esconfig.WorkloadVaultAuthConfig{
			DefaultMode: esconfig.WorkloadVaultAuthModeVaultIdentityJWT,
		},
		Nomad: esconfig.NomadConfig{
			BaseURL:        nomadBaseURL,
			Datacenter:     "dc1",
			TimeoutSeconds: 5,
			TokenFile:      nomadTokenFile,
		},
		Execution: esconfig.ExecutionConfig{
			StagingRootDir:             stagingRoot,
			ResultsRootDir:             resultsRoot,
			RetainedResultAuth:         resultAuth,
			BaseImage:                  firstNonEmpty(opts.baseImage, "alpine:3.20"),
			RuntimeIdentityTmpfsSize:   opts.runtimeIdentityTmpfsSize,
			RuntimeSupportBinary:       runtimeSupportBinary,
			SPIREWorkloadAPISocketPath: mockSPIRE.socketPath,
		},
	}
	esService, err := esapp.New(esCfg)
	if err != nil {
		t.Fatalf("build es app: %v", err)
	}
	stack.es = esService
	startService(t, esService.Start, esService.Addr, fixture.clientTLSConfigForServer(t, fixture.esServerName, "operator/local", false))
	stack.esRunning = true

	publishSubmitArtifact(t, stack, opts.networkAccess)

	t.Cleanup(func() { stack.shutdownAll(t) })
	return stack
}

func buildResolvedPlanCustodyHermeticRuntimeSupport(t *testing.T, rootDir string) string {
	t.Helper()
	if runtime.Version() != "go1.26.5" {
		t.Fatalf("hermetic fixture requires go1.26.5, got %q", runtime.Version())
	}
	outputPath := filepath.Join(rootDir, "es-runtime-support")
	goBinary := filepath.Join(runtime.GOROOT(), "bin", "go")
	command := exec.Command(goBinary, "build", "-mod=readonly", "-o", outputPath, "./cmd/es-runtime-support")
	command.Dir = repoRootFromTestFile(t)
	command.Env = append(os.Environ(), "GOOS=linux", "GOARCH="+runtime.GOARCH, "CGO_ENABLED=0")
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("build private runtime support: %v output=%s", err, strings.TrimSpace(string(output)))
	}
	return outputPath
}
