package admission

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	egsmodel "execution-substrate/egs/model"
	esconfig "execution-substrate/es/config"
	runtimeconfigv1 "execution-substrate/internal/contracts/runtimeconfig/v1"
)

func TestNewServiceRejectsDualMissingExecutionRootsBeforeMutation(t *testing.T) {
	workspace := physicalTestTempDir(t)
	stagingRoot := filepath.Join(workspace, "es-stage")
	resultsRoot := filepath.Join(workspace, "es-results")

	service, err := NewService(newExecutionRootStartupTestConfig(t, stagingRoot, resultsRoot))
	if err == nil {
		_ = service
		t.Fatal("dual-missing execution roots in one lookup context were accepted")
	}
	if !strings.Contains(err.Error(), "dual-missing execution roots share one unobserved lookup context") {
		t.Fatalf("unexpected dual-missing startup error: %v", err)
	}
	for _, root := range []string{stagingRoot, resultsRoot} {
		if _, statErr := os.Stat(root); !os.IsNotExist(statErr) {
			t.Fatalf("startup refusal mutated %s: %v", root, statErr)
		}
	}
	entries, readErr := os.ReadDir(workspace)
	if readErr != nil {
		t.Fatalf("read unchanged workspace: %v", readErr)
	}
	if len(entries) != 0 {
		t.Fatalf("startup refusal left workspace effects: %v", entries)
	}
}

func TestNewServiceRejectsResultsRootUnderStagingBeforeMutation(t *testing.T) {
	workspace := physicalTestTempDir(t)
	stagingRoot := filepath.Join(workspace, "es-stage")
	if err := os.Mkdir(stagingRoot, 0o755); err != nil {
		t.Fatalf("create staging root: %v", err)
	}
	marker := filepath.Join(stagingRoot, "sentinel")
	if err := os.WriteFile(marker, []byte("unchanged"), 0o600); err != nil {
		t.Fatalf("write staging sentinel: %v", err)
	}
	resultsRoot := filepath.Join(stagingRoot, "missing", "es-results")

	service, err := NewService(newExecutionRootStartupTestConfig(t, stagingRoot, resultsRoot))
	if err == nil {
		_ = service
		t.Fatal("results root beneath staging was accepted")
	}
	if !strings.Contains(err.Error(), "results_root_dir must be separate from execution.staging_root_dir") {
		t.Fatalf("unexpected nested-results startup error: %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(stagingRoot, "missing")); !os.IsNotExist(statErr) {
		t.Fatalf("startup refusal created a result component under staging: %v", statErr)
	}
	payload, readErr := os.ReadFile(marker)
	if readErr != nil || string(payload) != "unchanged" {
		t.Fatalf("startup refusal changed staging sentinel: payload=%q err=%v", payload, readErr)
	}
}

func TestRetainedResultAuthRequiredStartupFailsWithoutKeyAndPrepareOnlySkipsIt(t *testing.T) {
	workspace := physicalTestTempDir(t)
	stage := filepath.Join(workspace, "stage")
	results := filepath.Join(workspace, "results")
	// The staging root exists and the results root does not, so a configured
	// startup that gets past the key starts and provisions the results root.
	// The absent key is the only refusal this fixture can reach; the control
	// below proves it.
	if err := os.Mkdir(stage, 0o755); err != nil {
		t.Fatal(err)
	}
	cfg := newExecutionRootStartupTestConfig(t, stage, results)
	keyPath := cfg.Execution.RetainedResultAuth.KeyFile
	keyBytes, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(keyPath); err != nil {
		t.Fatal(err)
	}
	if service, err := NewService(cfg); err == nil || service != nil ||
		!strings.Contains(err.Error(), "retained result authentication key is unavailable") ||
		strings.Contains(err.Error(), keyPath) {
		t.Fatalf("configured Submit did not fail safely for absent key: service=%v err=%v", service != nil, err)
	}
	if _, err := os.Lstat(results); !os.IsNotExist(err) {
		t.Fatalf("key prerequisite failure provisioned %s: %v", results, err)
	}
	if entries, err := os.ReadDir(stage); err != nil || len(entries) != 0 {
		t.Fatalf("key prerequisite failure left staging effects: entries=%v err=%v", entries, err)
	}

	// Control: the same configuration with the same key bytes back in place
	// starts and provisions the results root.
	if err := os.WriteFile(keyPath, keyBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	if service, err := NewService(cfg); err != nil || service == nil || service.resultAuth == nil {
		t.Fatalf("configured Submit with its key did not start: service=%v err=%v", service != nil, err)
	}
	if info, err := os.Lstat(results); err != nil || !info.IsDir() {
		t.Fatalf("configured Submit with its key did not provision %s: %v", results, err)
	}

	if err := os.Remove(keyPath); err != nil {
		t.Fatal(err)
	}
	cfg.Nomad = esconfig.NomadConfig{}
	cfg.Execution = esconfig.ExecutionConfig{}
	service, err := NewService(cfg)
	if err != nil || service == nil || service.resultAuth != nil {
		t.Fatalf("prepare-only startup required retained-result key: service=%v err=%v", service != nil, err)
	}
}

func TestRetainedResultAuditF3StartupRejectsRootParentBeforeEffects(t *testing.T) {
	workspace := physicalTestTempDir(t)
	stage := filepath.Join(workspace, "uncreated-stage")
	results := filepath.Join(workspace, "uncreated-results")
	cfg := newExecutionRootStartupTestConfig(t, stage, results)
	cfg.Execution.RetainedResultAuth.KeyFile = "/key"
	if service, err := NewService(cfg); err == nil || service != nil ||
		!strings.Contains(err.Error(), "execution.retained_result_auth.key_file") ||
		!strings.Contains(err.Error(), "non-root parent") || strings.Contains(err.Error(), "/key") {
		t.Fatalf("root-parent key was not refused before service effects: service=%v err=%v", service != nil, err)
	}
	for _, path := range []string{stage, results} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatalf("rejected startup created execution root: %v", err)
		}
	}
	cfg.Nomad = esconfig.NomadConfig{}
	cfg.Execution = esconfig.ExecutionConfig{}
	service, err := NewService(cfg)
	if err != nil || service == nil || service.resultAuth != nil {
		t.Fatalf("prepare-only service required retained-result key: service=%v err=%v", service != nil, err)
	}
}

func TestRetainedResultAuditF1RenderedConfigConstructsConfiguredService(t *testing.T) {
	workspace := physicalTestTempDir(t)
	proofDir := filepath.Join(workspace, "proof")
	stage := filepath.Join(proofDir, "es-staging")
	results := filepath.Join(proofDir, "es-results")
	fixture := newExecutionRootStartupTestConfig(t, stage, results)
	keyParent := filepath.Join(workspace, "external auth ", "keys")
	if err := os.MkdirAll(keyParent, 0o700); err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(keyParent, "key")
	keyBytes := bytes.Repeat([]byte{0xa5}, 32)
	if err := os.WriteFile(keyPath, keyBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	// The renderer names <acl dir>/es-token as nomad.token_file; setup's
	// provisioning step (not run here) keeps or issues that token.
	nomadACLDir := filepath.Join(workspace, "nomad-acl")
	if err := os.Mkdir(nomadACLDir, 0o700); err != nil {
		t.Fatal(err)
	}
	nomadTokenPath := filepath.Join(nomadACLDir, "es-token")
	if err := os.WriteFile(nomadTokenPath, []byte(testNomadToken+"\n"), 0o400); err != nil {
		t.Fatal(err)
	}
	vaultCAPath := filepath.Join(proofDir, "tls", "vault-dev", "vault-ca.pem")
	if err := os.MkdirAll(filepath.Dir(vaultCAPath), 0o700); err != nil {
		t.Fatal(err)
	}
	certificate, err := os.ReadFile(fixture.TLS.CertFile)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(vaultCAPath, certificate, 0o600); err != nil {
		t.Fatal(err)
	}
	// The renderer only serializes these test-owned roots. Canonical setup is
	// responsible for fresh service-owned provisioning in the supported-local
	// profile; this unprivileged service fixture uses its own local identity.
	for _, root := range []string{stage, results} {
		if err := os.Mkdir(root, 0o755); err != nil {
			t.Fatalf("prepare renderer fixture root: %v", err)
		}
		if err := os.Chmod(root, 0o755); err != nil {
			t.Fatalf("set renderer fixture root mode: %v", err)
		}
	}
	script := filepath.Join("..", "..", "scripts", "72_supported_local_setup.sh")
	command := exec.Command("/bin/bash", "-c", `source "$1"
preflight_supported_local_setup_retained_result_auth
write_runtime_blob_and_configs "$SUPPORTED_LOCAL_PROOF_DIR" "https://127.0.0.1:18460" "jwt" "service_execution" "vault" "execution-substrate/control-plane-normal-shell:supported-local" "/usr/local/bin/codex" "proof-secrets/data/codex-runtime-profile" "api_key"
write_env_file "$SUPPORTED_LOCAL_PROOF_DIR/env.sh"`, "bash", script)
	command.Env = append(os.Environ(),
		"SUPPORTED_LOCAL_PROOF_DIR="+proofDir,
		"SUPPORTED_LOCAL_RUNTIME_SUPPORT_BINARY="+fixture.Execution.RuntimeSupportBinary,
		"SUPPORTED_LOCAL_RETAINED_RESULT_AUTH_STORE_ID=stable_store",
		"SUPPORTED_LOCAL_RETAINED_RESULT_AUTH_KEY_ID=stable_key",
		"SUPPORTED_LOCAL_RETAINED_RESULT_AUTH_KEY_FILE="+keyPath,
		"SUPPORTED_LOCAL_NOMAD_ACL_DIR="+nomadACLDir,
	)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("production setup renderer failed: %v output=%s", err, output)
	}
	data, err := os.ReadFile(filepath.Join(proofDir, "es.json"))
	if err != nil {
		t.Fatal(err)
	}
	var rendered esconfig.Config
	if err := json.Unmarshal(data, &rendered); err != nil {
		t.Fatalf("decode rendered ES config: %v", err)
	}
	if rendered.Execution.StagingRootDir != stage || rendered.Execution.ResultsRootDir != results {
		t.Fatal("renderer root paths do not match the prepared fixture roots")
	}
	envBytes, err := os.ReadFile(filepath.Join(proofDir, "env.sh"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(envBytes, []byte("export SUPPORTED_LOCAL_ES_ROOTS_PROFILE=\"service-root-v1\"")) ||
		!bytes.Contains(envBytes, []byte("export ES_CONFIG=\""+filepath.Join(proofDir, "es.json")+"\"")) {
		t.Fatal("renderer env does not select the same supported-local config and profile")
	}
	if rendered.Nomad.TokenFile != nomadTokenPath ||
		!bytes.Contains(envBytes, []byte("export NOMAD_TOKEN_FILE=\""+filepath.Join(nomadACLDir, "observer-token")+"\"")) {
		t.Fatal("renderer does not name ES's Nomad token and the observer token from the selected ACL directory")
	}
	for _, root := range []string{stage, results} {
		info, err := os.Lstat(root)
		if err != nil || !info.IsDir() || info.Mode().Perm() != 0o755 {
			t.Fatalf("renderer altered its prepared fixture root: root=%s info=%v err=%v", root, info, err)
		}
	}
	auth := rendered.Execution.RetainedResultAuth
	if auth.StoreID != "stable_store" || auth.KeyID != "stable_key" || auth.KeyFile != keyPath {
		t.Fatal("renderer changed selected retained-result metadata")
	}
	if err := rendered.Validate(); err != nil {
		t.Fatalf("full rendered ES config rejected: %v", err)
	}
	// The renderer owns auth metadata. Only dependency/TLS test fixtures replace
	// unrelated external files before real service construction.
	rendered.TLS = fixture.TLS
	rendered.Dependencies = fixture.Dependencies
	service, err := NewService(rendered)
	if err != nil || service == nil || service.resultAuth == nil ||
		service.resultAuth.storeID != auth.StoreID || service.resultAuth.keyID != auth.KeyID ||
		!bytes.Equal(service.resultAuth.key[:], keyBytes) {
		t.Fatalf("rendered configuration did not construct authenticated service: service=%v err=%v", service != nil, err)
	}
	if info, err := os.Lstat(keyPath); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("external synthetic key metadata changed: info=%v err=%v", info, err)
	}
	if after, err := os.ReadFile(keyPath); err != nil || !bytes.Equal(after, keyBytes) {
		t.Fatalf("external synthetic key bytes changed: err=%v", err)
	}
	if err := filepath.WalkDir(proofDir, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return nil
		}
		payload, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if bytes.Contains(payload, keyBytes) {
			return fmt.Errorf("generated proof asset contains synthetic raw key bytes")
		}
		if bytes.Contains(payload, []byte(testNomadToken)) {
			return fmt.Errorf("generated proof asset contains the Nomad token")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestRetainedResultReviewStartupNaturalDirectoryMask(t *testing.T) {
	mask := os.Getenv("ES_REVIEW_RESULT_DIR_MASK")
	if mask == "" {
		for _, value := range []string{"0000", "0027", "0077"} {
			t.Run(value, func(t *testing.T) {
				command := exec.Command(os.Args[0], "-test.run=^TestRetainedResultReviewStartupNaturalDirectoryMask$")
				command.Env = append(os.Environ(), "ES_REVIEW_RESULT_DIR_MASK="+value)
				output, err := command.CombinedOutput()
				if err != nil {
					t.Fatalf("isolated process mask %s: %v output=%s", value, err, output)
				}
			})
		}
		return
	}
	workspace := physicalTestTempDir(t)
	stage := filepath.Join(workspace, "stage")
	results := filepath.Join(workspace, "results")
	for _, path := range []string{stage, results} {
		if err := os.Mkdir(path, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	cfg := newExecutionRootStartupTestConfig(t, stage, results)
	switch mask {
	case "0000":
		syscall.Umask(0)
	case "0027":
		syscall.Umask(0o027)
	case "0077":
		syscall.Umask(0o077)
	default:
		t.Fatalf("unexpected child mask %q", mask)
	}
	service, err := NewService(cfg)
	if mask == "0077" {
		if err == nil || service != nil || !strings.Contains(err.Error(), "natural retained result directory creation is unavailable") {
			t.Fatalf("restrictive mask did not refuse startup at natural directory probe: service=%v err=%v", service != nil, err)
		}
		entries, readErr := os.ReadDir(results)
		if readErr != nil {
			t.Fatal(readErr)
		}
		found := false
		for _, entry := range entries {
			if strings.HasPrefix(entry.Name(), ".execution-substrate-result-dir-probe-") {
				info, statErr := os.Lstat(filepath.Join(results, entry.Name()))
				if statErr != nil || !info.IsDir() || info.Mode().Perm() != 0o700 {
					t.Fatalf("failed natural probe fixture was repaired or removed: info=%v err=%v", info, statErr)
				}
				found = true
			}
		}
		if !found {
			t.Fatal("restrictive startup left no retained natural-directory probe")
		}
		return
	}
	if err != nil || service == nil {
		t.Fatalf("qualified mask %s refused startup: %v", mask, err)
	}
	locator := newExecutionLocatorFromRunID("run-0123456789abcdef")
	custody, _ := claimTestStagingCustody(t, stage, locator.RunID)
	if err := custody.writeFile("run/result/summary.txt", []byte("qualified"), stableStageFileMode); err != nil {
		t.Fatal(err)
	}
	if err := custody.close(); err != nil {
		t.Fatal(err)
	}
	if retained, err := service.retainTerminalResult(locator); err != nil || !retained {
		t.Fatalf("qualified startup could not create retained result: retained=%t err=%v", retained, err)
	}
	info, err := os.Lstat(service.retainedResultRunDir(locator))
	if err != nil || info.Mode().Perm() != retainedResultRunDirMode {
		t.Fatalf("qualified result directory has wrong natural mode: info=%v err=%v", info, err)
	}
}

func TestRetainedResultReviewStartupUsesExactKeyParentWithPaddedRoots(t *testing.T) {
	workspace := physicalTestTempDir(t)
	stage := filepath.Join(workspace, "stage")
	results := filepath.Join(workspace, "results")
	exactParent := filepath.Join(workspace, "auth ")
	trimmedParent := filepath.Join(workspace, "auth")
	for _, path := range []string{stage, results, exactParent, trimmedParent} {
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	cfg := newExecutionRootStartupTestConfig(t, stage, results)
	cfg.Execution.StagingRootDir = " " + stage + " "
	cfg.Execution.ResultsRootDir = results + " "
	exactPath := filepath.Join(exactParent, "key")
	trimmedPath := filepath.Join(trimmedParent, "key")
	exactKey := bytes.Repeat([]byte{0x53}, 32)
	trimmedKey := bytes.Repeat([]byte{0x67}, 32)
	if err := os.WriteFile(trimmedPath, trimmedKey, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg.Execution.RetainedResultAuth.KeyFile = exactPath
	if service, err := NewService(cfg); err == nil || service != nil || strings.Contains(err.Error(), exactPath) {
		t.Fatalf("startup substituted trimmed key parent: service=%v err=%v", service != nil, err)
	}
	if err := os.WriteFile(exactPath, exactKey, 0o600); err != nil {
		t.Fatal(err)
	}
	service, err := NewService(cfg)
	if err != nil || service == nil || !bytes.Equal(service.resultAuth.key[:], exactKey) || bytes.Equal(service.resultAuth.key[:], trimmedKey) {
		t.Fatalf("startup did not load exact key parent: service=%v err=%v", service != nil, err)
	}
	for _, rootPath := range []string{stage, results} {
		cfg.Execution.RetainedResultAuth.KeyFile = filepath.Join(rootPath, "key")
		if service, err := NewService(cfg); err == nil || service != nil || strings.Contains(err.Error(), cfg.Execution.RetainedResultAuth.KeyFile) {
			t.Fatalf("startup accepted key inside effective root: service=%v err=%v", service != nil, err)
		}
	}
}

func TestRetainedResultReviewStartupPreservesSpaceBearingKeyAncestor(t *testing.T) {
	workspace := physicalTestTempDir(t)
	stage := filepath.Join(workspace, "stage")
	results := filepath.Join(workspace, "results")
	exactAncestor := filepath.Join(workspace, "auth ")
	otherAncestor := filepath.Join(workspace, "auth")
	for _, path := range []string{stage, results, otherAncestor, filepath.Join(otherAncestor, "keys")} {
		if err := os.Mkdir(path, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	cfg := newExecutionRootStartupTestConfig(t, stage, results)
	cfg.Execution.StagingRootDir = " " + stage + " "
	cfg.Execution.ResultsRootDir = results + " "
	exactPath := filepath.Join(exactAncestor, "keys", "key")
	otherPath := filepath.Join(otherAncestor, "keys", "key")
	firstKey := bytes.Repeat([]byte{0x53}, 32)
	secondKey := bytes.Repeat([]byte{0x59}, 32)
	otherKey := bytes.Repeat([]byte{0x67}, 32)
	if err := os.WriteFile(otherPath, otherKey, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg.Execution.RetainedResultAuth.KeyFile = exactPath
	if service, err := NewService(cfg); err == nil || service != nil ||
		strings.Contains(err.Error(), exactPath) || strings.Contains(err.Error(), otherPath) {
		t.Fatalf("startup accepted missing exact hierarchy or disclosed key path: service=%v err=%v", service != nil, err)
	}
	for _, path := range []string{exactAncestor, filepath.Join(exactAncestor, "keys")} {
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(exactPath, firstKey, 0o600); err != nil {
		t.Fatal(err)
	}
	first, err := NewService(cfg)
	if err != nil || first == nil || first.resultAuth == nil ||
		!bytes.Equal(first.resultAuth.key[:], firstKey) || bytes.Equal(first.resultAuth.key[:], otherKey) {
		t.Fatalf("startup did not load exact nested key: service=%v err=%v", first != nil, err)
	}
	if err := os.WriteFile(exactPath, secondKey, 0o600); err != nil {
		t.Fatal(err)
	}
	second, err := NewService(cfg)
	if err != nil || second == nil || second.resultAuth == nil ||
		!bytes.Equal(second.resultAuth.key[:], secondKey) || !bytes.Equal(first.resultAuth.key[:], firstKey) {
		t.Fatalf("fresh service did not reload exact nested key: service=%v err=%v", second != nil, err)
	}
	for _, rootPath := range []string{stage, results} {
		cfg.Execution.RetainedResultAuth.KeyFile = filepath.Join(rootPath, "key")
		if service, err := NewService(cfg); err == nil || service != nil ||
			strings.Contains(err.Error(), cfg.Execution.RetainedResultAuth.KeyFile) {
			t.Fatalf("startup accepted key inside padded effective root: service=%v err=%v", service != nil, err)
		}
	}
}

func TestRetainedResultReviewFreshServiceReopensPersistedResultWithReloadedKey(t *testing.T) {
	workspace := physicalTestTempDir(t)
	stage := filepath.Join(workspace, "stage")
	results := filepath.Join(workspace, "results")
	for _, path := range []string{stage, results} {
		if err := os.Mkdir(path, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	cfg := newExecutionRootStartupTestConfig(t, stage, results)
	first, err := NewService(cfg)
	if err != nil {
		t.Fatalf("first service startup: %v", err)
	}
	locator := newExecutionLocatorFromRunID("run-0123456789abcdef")
	custody, _ := claimTestStagingCustody(t, stage, locator.RunID)
	if err := custody.writeFile("run/result/summary.txt", []byte("persisted"), stableStageFileMode); err != nil {
		t.Fatal(err)
	}
	if err := custody.close(); err != nil {
		t.Fatal(err)
	}
	if retained, err := first.retainTerminalResult(locator); err != nil || !retained {
		t.Fatalf("first service retention: retained=%t err=%v", retained, err)
	}
	committed, err := os.ReadFile(first.retainedResultBundlePath(locator))
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewService(cfg)
	if err != nil || second == nil {
		t.Fatalf("fresh same-key service startup: %v", err)
	}
	bundle, resultErr := second.Result(context.Background(), locator.RunID)
	if resultErr != nil || !bytes.Equal(bundle.Payload, committed) {
		t.Fatalf("fresh same-key service could not read persisted bytes: err=%+v", resultErr)
	}
	keyPath := cfg.Execution.RetainedResultAuth.KeyFile
	if err := os.Remove(keyPath); err != nil {
		t.Fatal(err)
	}
	if missing, err := NewService(cfg); err == nil || missing != nil || strings.Contains(err.Error(), keyPath) {
		t.Fatalf("fresh startup accepted absent key: service=%v err=%v", missing != nil, err)
	}
	if err := os.WriteFile(keyPath, bytes.Repeat([]byte{0x67}, 32), 0o600); err != nil {
		t.Fatal(err)
	}
	third, err := NewService(cfg)
	if err != nil || third == nil {
		t.Fatalf("fresh different-key service startup: %v", err)
	}
	bundle, resultErr = third.Result(context.Background(), locator.RunID)
	if resultErr == nil || resultErr.Status != http.StatusConflict || resultErr.Code != codeResultUnavailable || len(bundle.Payload) != 0 {
		t.Fatalf("fresh different-key service authenticated old bytes: err=%+v", resultErr)
	}
}

func newExecutionRootStartupTestConfig(t *testing.T, stagingRoot string, resultsRoot string) esconfig.Config {
	t.Helper()

	server := httptest.NewTLSServer(http.NotFoundHandler())
	t.Cleanup(server.Close)
	certificate := server.TLS.Certificates[0]
	certificatePEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Certificate[0]})
	privateKeyDER, err := x509.MarshalPKCS8PrivateKey(certificate.PrivateKey)
	if err != nil {
		t.Fatalf("marshal test client key: %v", err)
	}
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateKeyDER})
	configDir := t.TempDir()
	certificatePath := filepath.Join(configDir, "client.pem")
	privateKeyPath := filepath.Join(configDir, "client-key.pem")
	for path, payload := range map[string][]byte{
		certificatePath: certificatePEM,
		privateKeyPath:  privateKeyPEM,
	} {
		if err := os.WriteFile(path, payload, 0o600); err != nil {
			t.Fatalf("write TLS fixture %s: %v", path, err)
		}
	}
	runtimeSupportPath := filepath.Join(configDir, "es-runtime-support")
	if err := os.WriteFile(runtimeSupportPath, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatalf("write runtime support fixture: %v", err)
	}
	resultKeyPath := filepath.Join(configDir, "synthetic-result-key")
	if err := os.WriteFile(resultKeyPath, bytes.Repeat([]byte{0x53}, 32), 0o600); err != nil {
		t.Fatalf("write synthetic result auth fixture: %v", err)
	}
	nomadTokenPath := filepath.Join(configDir, "nomad-token")
	if err := os.WriteFile(nomadTokenPath, []byte(testNomadToken+"\n"), 0o400); err != nil {
		t.Fatalf("write synthetic nomad token fixture: %v", err)
	}
	publicKey, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate verifier key: %v", err)
	}
	verifier := esconfig.SignerVerifierConfig{
		Algorithm:    "ed25519",
		KeyID:        "test-signer",
		PublicKeyHex: hex.EncodeToString(publicKey),
	}
	dependency := esconfig.DependencyConfig{
		BaseURL:        server.URL,
		ServerName:     "example.com",
		ClientCertFile: certificatePath,
		ClientKeyFile:  privateKeyPath,
		RootCAFile:     certificatePath,
		TimeoutSeconds: 1,
	}

	return esconfig.Config{
		HTTP: esconfig.HTTPConfig{
			BindAddress:            "127.0.0.1",
			ReadTimeoutSeconds:     1,
			WriteTimeoutSeconds:    1,
			ShutdownTimeoutSeconds: 1,
		},
		TLS: esconfig.TLSConfig{
			CertFile:     certificatePath,
			KeyFile:      privateKeyPath,
			ClientCAFile: certificatePath,
		},
		Security: esconfig.SecurityConfig{BootstrapIssuerCommonName: "test-bootstrap"},
		Authorization: esconfig.AuthorizationConfig{
			AllowedSPIFFEPathPrefixes: []string{"operator/test"},
		},
		Dependencies: esconfig.DependenciesConfig{
			ArtifactRegistry:    dependency,
			ExecutionGovernance: dependency,
		},
		RuntimeConfig: esconfig.RuntimeConfigConfig{
			WorkloadZoneVaultConfigRef: runtimeconfigv1.WorkloadZoneVaultConfigRef{Digest: testWorkloadZoneVaultConfigDigest},
		},
		Verification: esconfig.VerificationConfig{
			TrustModel:              verifier,
			Provenance:              verifier,
			DerivationAttestation:   verifier,
			WorkloadIdentityBinding: verifier,
		},
		WorkloadVaultAuth: esconfig.WorkloadVaultAuthConfig{DefaultMode: esconfig.WorkloadVaultAuthModeVaultIdentityJWT},
		Nomad: esconfig.NomadConfig{
			BaseURL:        "http://127.0.0.1:4646",
			Datacenter:     "dc1",
			TimeoutSeconds: 1,
			TokenFile:      nomadTokenPath,
		},
		Execution: esconfig.ExecutionConfig{
			StagingRootDir:             stagingRoot,
			ResultsRootDir:             resultsRoot,
			RetainedResultAuth:         esconfig.RetainedResultAuthConfig{StoreID: "test_store", KeyID: "test_key", KeyFile: resultKeyPath},
			BaseImage:                  "alpine:3.20",
			RuntimeSupportBinary:       runtimeSupportPath,
			SPIREWorkloadAPISocketPath: filepath.Join(configDir, "spire-agent.sock"),
		},
	}
}

func TestTrancheB2PreparedAdmissionOrdinaryFormattingAndJSONPrivacy(t *testing.T) {
	prepared := preparedAdmission{
		admittedRequest:             PrepareRequest{SchemaVersion: "private-schema"},
		result:                      PrepareResult{Success: true},
		artifact:                    preparedArtifact{payloadDigest: "private-payload"},
		workloadVaultPlan:           esconfig.ResolvedWorkloadVaultAuthPlan{Address: "https://private-vault.invalid"},
		workloadZoneVaultConfigRef:  runtimeconfigv1.WorkloadZoneVaultConfigRef{Digest: labeledDigest("91")},
		trustModel:                  egsmodel.RuntimeTrustPolicy{SignerPolicy: egsmodel.SignerPolicy{AllowedSigners: []string{"private-signer"}}},
		policyPayloadBytes:          []byte("private-bytes"),
		policyPayloadBytesAvailable: true,
	}

	values := []any{prepared, &prepared, any(prepared), any(&prepared)}
	formats := []string{"%v", "%+v", "%#v", "%s", "%q", "%20v", "%-20v", "%.3v", "%20.3v"}
	for _, value := range values {
		for _, format := range formats {
			if got := fmt.Sprintf(format, value); got != privateExecutionValueRedaction {
				t.Fatalf("format %q emitted %q", format, got)
			}
			var formatted bytes.Buffer
			if _, err := fmt.Fprintf(&formatted, format, value); err != nil {
				t.Fatalf("Fprintf %q: %v", format, err)
			}
			if got := formatted.String(); got != privateExecutionValueRedaction {
				t.Fatalf("Fprintf %q emitted %q", format, got)
			}
		}
	}

	for _, value := range values {
		var captured bytes.Buffer
		log.New(&captured, "", 0).Printf("%v", value)
		if got := captured.String(); got != privateExecutionValueRedaction+"\n" {
			t.Fatalf("formatted log emitted %q", got)
		}
		encoded, err := json.Marshal(value)
		if err != nil {
			t.Fatalf("marshal prepared admission: %v", err)
		}
		if string(encoded) != "{}" {
			t.Fatalf("ordinary JSON emitted %q", encoded)
		}
	}
}

func TestValidateExecutionRuntimeInputsAcceptsRegularBinaryWithoutLiveSPIRESocketAccess(t *testing.T) {
	rootDir := physicalTestTempDir(t)

	binaryPath := filepath.Join(rootDir, "es-runtime-support")
	if err := os.WriteFile(binaryPath, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatalf("write runtime support binary: %v", err)
	}

	err := validateExecutionRuntimeInputs(esconfig.ExecutionConfig{
		RuntimeSupportBinary:       binaryPath,
		SPIREWorkloadAPISocketPath: filepath.Join(rootDir, "missing-spire.sock"),
	})
	if err != nil {
		t.Fatalf("expected runtime inputs to validate, got %v", err)
	}
}

func TestValidateExecutionRuntimeInputsRejectsNonRegularBinary(t *testing.T) {
	rootDir := physicalTestTempDir(t)

	binaryPath := filepath.Join(rootDir, "runtime-support-dir")
	if err := os.MkdirAll(binaryPath, 0o755); err != nil {
		t.Fatalf("mkdir runtime support dir: %v", err)
	}

	err := validateExecutionRuntimeInputs(esconfig.ExecutionConfig{
		RuntimeSupportBinary:       binaryPath,
		SPIREWorkloadAPISocketPath: filepath.Join(rootDir, "ignored-spire.sock"),
	})
	if err == nil || !strings.Contains(err.Error(), "regular file") {
		t.Fatalf("expected regular file validation error, got %v", err)
	}
}

func TestValidateExecutionRuntimeInputsRejectsNonAbsoluteSPIRESocketPath(t *testing.T) {
	rootDir := physicalTestTempDir(t)

	binaryPath := filepath.Join(rootDir, "es-runtime-support")
	if err := os.WriteFile(binaryPath, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatalf("write runtime support binary: %v", err)
	}

	err := validateExecutionRuntimeInputs(esconfig.ExecutionConfig{
		RuntimeSupportBinary:       binaryPath,
		SPIREWorkloadAPISocketPath: "relative/spire.sock",
	})
	if err == nil || !strings.Contains(err.Error(), "spire_workload_api_socket_path") {
		t.Fatalf("expected SPIRE path shape validation error, got %v", err)
	}
}

func TestValidatePrepareRequestDefaultsVersionsAndRejectsInvalidInputs(t *testing.T) {
	req := PrepareRequest{
		Invocation: ArtifactInvocation{
			ArtifactDigest:       "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			DerivationSpecDigest: "sha256:abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd",
			OutputID:             "result",
		},
	}
	if err := validatePrepareRequest(&req); err != nil {
		t.Fatalf("expected prepare request to validate, got %v", err)
	}
	if req.SchemaVersion != "v1" || req.Invocation.SchemaVersion != "v1" {
		t.Fatalf("expected schema versions to default to v1, got %+v", req)
	}

	invalid := req
	invalid.Mode = "unsupported"
	err := validatePrepareRequest(&invalid)
	if err == nil || err.Code != codeInvalidRequest || !strings.Contains(err.Message, "mode must be sync or async") {
		t.Fatalf("expected mode validation error, got %+v", err)
	}
}

func TestValidateInvocationAgainstManifestRejectsReservedAndUndeclaredEnv(t *testing.T) {
	manifest := Manifest{
		ArtifactDigest: "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		RuntimeInterface: RuntimeInterface{
			EnvironmentVariables: []string{"ALLOWED_ENV"},
		},
	}

	err := validateInvocationAgainstManifest(ArtifactInvocation{
		ArtifactDigest: manifest.ArtifactDigest,
		Env: map[string]string{
			runtimeIdentityEndpointEnvKey: "unix:///tmp/socket",
		},
	}, manifest)
	if err == nil || !strings.Contains(err.Message, "reserved") {
		t.Fatalf("expected reserved env rejection, got %+v", err)
	}

	err = validateInvocationAgainstManifest(ArtifactInvocation{
		ArtifactDigest: manifest.ArtifactDigest,
		Env: map[string]string{
			"NOT_ALLOWED": "1",
		},
	}, manifest)
	if err == nil || !strings.Contains(err.Message, "not allowed by the runtime interface") {
		t.Fatalf("expected undeclared env rejection, got %+v", err)
	}
}

func TestVerifyTrustModelEnvelopeAcceptsSignedCanonicalAndIgnoresPublication(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate ed25519 keypair: %v", err)
	}
	model := egsmodel.RuntimeTrustPolicy{
		SignerPolicy: egsmodel.SignerPolicy{
			AllowedSigners: []string{"ags-signer"},
		},
	}
	canonical, err := model.CanonicalBytes()
	if err != nil {
		t.Fatalf("canonical bytes: %v", err)
	}

	service := Service{
		trustModelVerifier: &ed25519Verifier{
			algorithm: "ed25519",
			keyID:     "egs-signer",
			publicKey: publicKey,
		},
	}
	payload := signedRuntimeTrustResponse{
		RuntimeTrust:  model,
		Algorithm:     "ed25519",
		KeyID:         "egs-signer",
		PayloadDigest: digestBytes(canonical),
		Signature:     base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, canonical)),
		Publication:   json.RawMessage(`{"version":"ignored","update_revision":7}`),
	}

	if err := service.verifyTrustModelEnvelope(payload, canonical); err != nil {
		t.Fatalf("expected trust model envelope verification to succeed, got %v", err)
	}

	payload.PayloadDigest = "sha256:deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
	if err := service.verifyTrustModelEnvelope(payload, canonical); err == nil || !strings.Contains(err.Error(), "payload digest mismatch") {
		t.Fatalf("expected payload digest mismatch, got %v", err)
	}
}

func TestEnforceTrustModelRejectsDisallowedRevokedAndRevokedArtifact(t *testing.T) {
	err := enforceTrustModel(egsmodel.RuntimeTrustPolicy{
		SignerPolicy: egsmodel.SignerPolicy{
			AllowedSigners: []string{"allowed"},
		},
	}, "other", "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	if err == nil || err.Code != codeSignerNotAllowed {
		t.Fatalf("expected signer-not-allowed error, got %+v", err)
	}

	err = enforceTrustModel(egsmodel.RuntimeTrustPolicy{
		SignerPolicy: egsmodel.SignerPolicy{
			AllowedSigners: []string{"allowed"},
			RevokedSigners: []string{"allowed"},
		},
	}, "allowed", "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	if err == nil || err.Code != codeSignerRevoked {
		t.Fatalf("expected signer-revoked error, got %+v", err)
	}

	err = enforceTrustModel(egsmodel.RuntimeTrustPolicy{
		SignerPolicy: egsmodel.SignerPolicy{
			AllowedSigners: []string{"allowed"},
		},
		ArtifactPolicy: egsmodel.ArtifactPolicy{
			RevokedArtifacts: []string{"sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"},
		},
	}, "allowed", "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	if err == nil || err.Code != codeArtifactRevoked {
		t.Fatalf("expected artifact-revoked error, got %+v", err)
	}
}

func TestHealthReflectsArtifactRegistryReadinessAndLoadedTrustModel(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/health" {
			t.Fatalf("unexpected path %q", r.URL.Path)
		}
		_, _ = w.Write([]byte(`{"status":"healthy","ready":true}`))
	}))
	defer server.Close()

	baseURL := mustParseURL(t, server.URL)
	service := Service{
		arsClient: &dependencyClient{
			dependencyName: "artifact-registry",
			baseURL:        baseURL,
			client: &http.Client{
				Timeout:   time.Second,
				Transport: server.Client().Transport,
			},
		},
		trustModel: &egsmodel.RuntimeTrustPolicy{},
	}

	health := service.Health(context.Background())
	if !health.ArtifactRegistryHealthy || !health.TrustModelLoaded {
		t.Fatalf("expected health to reflect ready ARS and loaded trust model, got %+v", health)
	}
}

func TestFetchWorkloadZoneVaultConfigDecodesValidBlobAndRejectsInvalidBlob(t *testing.T) {
	var payload string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/v1/blobs/sha256:") || !strings.HasSuffix(r.URL.Path, ":json") {
			t.Fatalf("unexpected path %q", r.URL.Path)
		}
		_, _ = w.Write([]byte(payload))
	}))
	defer server.Close()

	service := Service{
		arsClient: &dependencyClient{
			dependencyName: "artifact-registry",
			baseURL:        mustParseURL(t, server.URL),
			client: &http.Client{
				Timeout:   time.Second,
				Transport: server.Client().Transport,
			},
		},
	}
	ref := runtimeconfigv1.WorkloadZoneVaultConfigRef{
		Digest: "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
	}

	payload = `{"vault_config":{"address":"https://vault.internal:8200","auth_mount":"jwt","auth_role":"execution","jwt_audience":"vault"}}`
	config, err := service.fetchWorkloadZoneVaultConfig(context.Background(), ref)
	if err != nil {
		t.Fatalf("expected workload-zone vault config fetch to succeed, got %+v", err)
	}
	if config.Address != "https://vault.internal:8200" || config.AuthRole != "execution" {
		t.Fatalf("unexpected workload-zone vault config %+v", config)
	}

	payload = `{"vault_config":{"address":"http://bad","auth_mount":"","auth_role":"","jwt_audience":""}}`
	_, err = service.fetchWorkloadZoneVaultConfig(context.Background(), ref)
	if err == nil || err.Code != codeWorkloadZoneVaultUnavailable {
		t.Fatalf("expected invalid workload-zone vault blob to map to unavailable, got %+v", err)
	}
}

func TestSubmitFailsAtAdmissionWhenWorkloadZoneVaultBlobIsUnavailable(t *testing.T) {
	fixture := newPreparedArtifactFixture(t)
	service, stagingRoot, resultsRoot := newWorkstreamCTestService(t, fixture)
	request := fixture.prepareRequest()
	request.Mode = ExecutionModeAsync

	arsCalls := map[string]int{}
	service.arsClient = newArtifactRegistryTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		arsCalls[r.URL.Path]++
		switch r.URL.Path {
		case "/v1/artifacts/" + fixture.discovery.Artifact.ArtifactDigest + "/discovery":
			writeJSONResponse(t, w, http.StatusOK, fixture.discovery)
		case "/v1/blobs/" + fixture.discovery.Evidence.Digest + ":json":
			writeJSONResponse(t, w, http.StatusOK, fixture.evidence)
		case "/v1/blobs/" + testWorkloadZoneVaultConfigDigest + ":json":
			writeJSONResponse(t, w, http.StatusNotFound, artifactRegistryErrorResponse{Error: "blob not found"})
		default:
			t.Fatalf("submit reached unexpected ARS path before runtime-config failure: %q", r.URL.Path)
		}
	}))
	service.nomadClient = newTestNomadClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("submit must not call nomad when runtime-config admission fails, got %s %q", r.Method, r.URL.Path)
	}))

	_, err := service.Submit(context.Background(), request)
	assertAdmissionError(t, err, http.StatusServiceUnavailable, codeWorkloadZoneVaultUnavailable)
	assertExactCallCount(t, arsCalls, "/v1/artifacts/"+fixture.discovery.Artifact.ArtifactDigest+"/discovery", 1)
	assertExactCallCount(t, arsCalls, "/v1/blobs/"+fixture.discovery.Evidence.Digest+":json", 1)
	assertExactCallCount(t, arsCalls, "/v1/blobs/"+testWorkloadZoneVaultConfigDigest+":json", 1)
	if len(arsCalls) != 3 {
		t.Fatalf("expected submit admission to stop after runtime-config read failure, got %v", arsCalls)
	}
	assertDirectoryEmpty(t, stagingRoot)
	assertDirectoryEmpty(t, resultsRoot)
}

func mustParseURL(t *testing.T, raw string) *url.URL {
	t.Helper()

	parsed, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse url %q: %v", raw, err)
	}
	return parsed
}
