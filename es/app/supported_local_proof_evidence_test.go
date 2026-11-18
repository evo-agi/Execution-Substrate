package app_test

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

const (
	proofRootTokenCanary = "TEST_ONLY_PROOF_ROOT_TOKEN_CANARY_91"
	proofSecretCanary    = "TEST_ONLY_PROOF_SECRET_VALUE_CANARY_92"
	proofAPIKeyCanary    = "TEST_ONLY_PROOF_API_KEY_CANARY_93"
)

type proofEvidenceManifest struct {
	Schema string `json:"schema"`
	Files  []struct {
		Path           string `json:"path"`
		Classification string `json:"classification"`
		FileType       string `json:"file_type"`
		Mode           string `json:"mode"`
		Size           int    `json:"size"`
		SHA256         string `json:"sha256"`
	} `json:"files"`
}

func proofEvidenceHelper(t *testing.T) string {
	t.Helper()
	return filepath.Join(executionPlatformRepoRoot(t), "scripts", "internal", "supported_local_proof_evidence.sh")
}

func writeProofEvidenceFile(t *testing.T, root, name string, contents []byte) {
	t.Helper()
	path := filepath.Join(root, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("mkdir proof fixture parent: %v", err)
	}
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		t.Fatalf("write proof fixture: %v", err)
	}
}

func prepareProofStagingObservationRoot(t *testing.T, proof string) {
	t.Helper()
	if err := os.Mkdir(filepath.Join(proof, "staging"), 0o755); err != nil {
		t.Fatalf("prepare explicit staging observation fixture: %v", err)
	}
}

// Match the field names and success/result semantics written by 60_execute_loop.sh.
func proofExecutionLoopSummary(t *testing.T, workdir, runID string, result []byte) []byte {
	t.Helper()
	value := map[string]any{
		"ok": true, "failed_phase": "", "failure_category": "",
		"message": "execution completed successfully", "error_code": "",
		"http_status": 200, "next_step": "none", "spec_path": filepath.Join(workdir, "input.json"),
		"workdir": workdir, "artifact_digest": strings.Repeat("a", 64),
		"intent_digest": strings.Repeat("b", 64), "derivation_spec_digest": strings.Repeat("c", 64),
		"build_log_digest": strings.Repeat("d", 64), "run_id": runID,
		"state": "terminal", "terminal": true, "exit_code": 0,
		"logs_path": filepath.Join(workdir, "logs.txt"), "logs_available": true,
		"result_path":      filepath.Join(workdir, "result.tar.gz"),
		"result_available": result != nil, "result_bytes": len(result),
	}
	return append(proofJSON(t, value), '\n')
}

func proofPhysicalTempDir(t *testing.T) string {
	t.Helper()
	path, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return path
}

func writeCapturedProofResultFixture(t *testing.T, guest string, bundle []byte) string {
	t.Helper()
	const runID = "run-fedcba9876543210"
	workdir := filepath.Join(guest, "workdirs", "normal")
	summary := proofExecutionLoopSummary(t, workdir, runID, bundle)
	writeProofEvidenceFile(t, guest, "workdirs/normal/summary.json", summary)
	writeProofEvidenceFile(t, guest, "workdirs/normal/result.tar.gz", bundle)
	writeProofEvidenceFile(t, guest, "control-plane-normal-shell-summary.json", summary)
	writeProofEvidenceFile(t, guest, "control-plane-normal-shell-nomad-execution-safe.json", append(proofJSON(t, map[string]any{
		"schema": "supported-local-nomad-execution-safe-v1", "run_id": runID,
		"job_id": "exec-" + runID, "allocation_id": "fedcba98-7654-3210-fedc-ba9876543210",
		"job_observed": true, "allocation_observed": true,
	}), '\n'))
	return workdir
}

func rewriteProofJSON(t *testing.T, path string, mutate func(map[string]any)) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var value map[string]any
	if err := json.Unmarshal(data, &value); err != nil {
		t.Fatal(err)
	}
	mutate(value)
	if err := os.WriteFile(path, append(proofJSON(t, value), '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
}

func rewriteBothProofSummaries(t *testing.T, guest, workdir string, mutate func(map[string]any)) {
	t.Helper()
	for _, path := range []string{
		filepath.Join(guest, "control-plane-normal-shell-summary.json"), filepath.Join(workdir, "summary.json"),
	} {
		rewriteProofJSON(t, path, mutate)
	}
}

func runProofEvidenceCollector(t *testing.T, root string) ([]byte, string, error) {
	t.Helper()
	command := exec.Command("bash", proofEvidenceHelper(t), "collect-safe", root)
	command.Dir = executionPlatformRepoRoot(t)
	command.Env = append(os.Environ(), "PYTHONDONTWRITEBYTECODE=1")
	var stdout, stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	err := command.Run()
	return stdout.Bytes(), stderr.String(), err
}

func readProofEvidenceArchive(t *testing.T, payload []byte) (map[string][]byte, proofEvidenceManifest) {
	t.Helper()
	reader := tar.NewReader(bytes.NewReader(payload))
	files := map[string][]byte{}
	var names []string
	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("read safe evidence archive: %v", err)
		}
		if header.Typeflag != tar.TypeReg && header.Typeflag != tar.TypeRegA {
			t.Fatalf("nonregular safe evidence archive member %q", header.Name)
		}
		if header.Mode != 0o600 || header.Uid != 0 || header.Gid != 0 || header.ModTime.Unix() != 0 {
			t.Fatalf("nondeterministic archive metadata for %q: %+v", header.Name, header)
		}
		if strings.Contains(header.Name, "/") || strings.Contains(header.Name, "..") || header.Name == "" {
			t.Fatalf("unclean archive member name %q", header.Name)
		}
		if _, exists := files[header.Name]; exists {
			t.Fatalf("duplicate archive member %q", header.Name)
		}
		body, err := io.ReadAll(reader)
		if err != nil {
			t.Fatalf("read archive body: %v", err)
		}
		files[header.Name] = body
		names = append(names, header.Name)
	}
	if !sort.StringsAreSorted(names) {
		t.Fatalf("archive members not in deterministic path order: %v", names)
	}
	manifestBytes, ok := files["safe-evidence-manifest.json"]
	if !ok {
		t.Fatal("safe evidence manifest missing")
	}
	var manifest proofEvidenceManifest
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		t.Fatalf("decode safe evidence manifest: %v", err)
	}
	if manifest.Schema != "supported-local-proof-safe-evidence-v1" {
		t.Fatalf("unexpected manifest schema %q", manifest.Schema)
	}
	manifestNames := make([]string, 0, len(manifest.Files))
	for _, entry := range manifest.Files {
		body, ok := files[entry.Path]
		if !ok || entry.Path == "safe-evidence-manifest.json" {
			t.Fatalf("manifest names absent or self-referential member %q", entry.Path)
		}
		if entry.Classification == "" || entry.FileType != "regular" || entry.Mode != "0600" || entry.Size != len(body) {
			t.Fatalf("invalid manifest metadata for %q: %+v", entry.Path, entry)
		}
		hash := sha256.Sum256(body)
		if entry.SHA256 != hex.EncodeToString(hash[:]) {
			t.Fatalf("manifest digest mismatch for %q", entry.Path)
		}
		manifestNames = append(manifestNames, entry.Path)
	}
	if !sort.StringsAreSorted(manifestNames) || len(files) != len(manifest.Files)+1 {
		t.Fatalf("manifest path set/order mismatch: paths=%v archive_count=%d", manifestNames, len(files))
	}
	return files, manifest
}

func TestSupportedLocalProofSafeEvidenceCollector(t *testing.T) {
	t.Run("allowlist, canaries, manifest, determinism", func(t *testing.T) {
		root := t.TempDir()
		for name, contents := range map[string][]byte{
			"guest-repo-snapshot.sha256":                     []byte(strings.Repeat("a", 64) + "\n"),
			"repo-snapshot-match.txt":                        []byte(strings.Repeat("a", 64) + "\n"),
			"execution-roots-setup-safe.json":                []byte(`{"schema":"supported-local-execution-roots-setup-safe-v1","profile":"service-root-v1","configured_root_uid":0,"configured_root_gid":0,"configured_root_mode":"0755","static_root_owner_mode_checked":true,"operator_write_access_required":false,"container_identity_or_behavioral_capability_proved":false}`),
			"nomad-service-safe.json":                        []byte(`{"schema":"supported-local-nomad-service-safe-v1","loaded":true,"active":true,"running":true,"enabled":true,"main_pid_positive":true,"exec_main_status_zero":true}`),
			"nomad-agent-safe.json":                          []byte(`{"schema":"supported-local-nomad-agent-safe-v1","version":"1.9.0","region_present":true,"datacenter_present":true,"node_name_present":true,"dev_mode":false,"client_enabled":true,"server_enabled":true}`),
			"summary.json":                                   []byte(`{"ok":true,"message":"execution completed successfully","spec_path":"` + proofAPIKeyCanary + `","run_id":"run-0123456789abcdef"}`),
			"runtime-identity-vault-summary.json":            []byte(`{"ok":true,"message":"execution completed successfully","run_id":"run-0123456789abcdef"}`),
			"runtime-identity-vault-status-safe.json":        []byte(`{"schema":"supported-local-execution-status-safe-v1","terminal":true,"state":"complete","exit_code":0}`),
			"runtime-identity-vault-run-id.txt":              []byte("run-proof-1\n"),
			"runtime-identity-vault-log-assertions.json":     []byte(`{"schema":"supported-local-proof-log-assertions-v1","secret_read_success":true}`),
			"control-plane-normal-shell-log-assertions.json": []byte(`{"schema":"supported-local-proof-log-assertions-v1","runtime_contract_proved":true}`),
			"control-plane-normal-shell-summary.json":        []byte(`{"ok":false,"message":"` + proofSecretCanary + `"}`),
			"managed-secrets.conf":                           []byte(proofRootTokenCanary + "\n" + proofSecretCanary + "\n" + proofAPIKeyCanary),
			"env.sh":                                         []byte(proofAPIKeyCanary),
			"vault-dev-cluster.json":                         []byte(proofRootTokenCanary),
			"vault-dev.log":                                  []byte(proofSecretCanary),
			"spire-agent.log":                                []byte(proofAPIKeyCanary),
			"tls/client-key.pem":                             []byte(proofAPIKeyCanary),
			"spire-data/server/private.key":                  []byte(proofRootTokenCanary),
			"ars-storage/secret":                             []byte(proofSecretCanary),
			"es-staging/run/file":                            []byte(proofSecretCanary),
			"es-results/run/file":                            []byte(proofSecretCanary),
			"workdirs/latest/logs.txt":                       []byte(proofSecretCanary),
			"bringup-state/state.db":                         []byte(proofRootTokenCanary),
			"payload/artifact.tar.gz":                        []byte(proofAPIKeyCanary),
			"bin/tool":                                       []byte(proofAPIKeyCanary),
			"logs.txt":                                       []byte("SECRET-READ-SUCCESS:" + proofSecretCanary),
			"runtime-identity-vault-logs.txt":                []byte("SECRET-READ-SUCCESS:" + proofSecretCanary),
			"systemctl-status-nomad.txt":                     []byte(proofSecretCanary),
			"nomad-agent-self.json":                          []byte(proofRootTokenCanary),
			"docker-info.txt":                                []byte(proofAPIKeyCanary),
			"result.tar.gz":                                  []byte(proofAPIKeyCanary),
			"control-plane-normal-shell-result.tar.gz":       []byte(proofSecretCanary),
		} {
			writeProofEvidenceFile(t, root, name, contents)
		}
		outside := filepath.Join(t.TempDir(), "outside-secret")
		if err := os.WriteFile(outside, []byte(proofRootTokenCanary), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(outside, filepath.Join(root, "unclassified-link")); err != nil {
			t.Fatal(err)
		}
		if err := syscall.Mkfifo(filepath.Join(root, "unclassified-fifo"), 0o600); err != nil {
			t.Logf("FIFO fixture unavailable on this platform: %v", err)
		}

		first, stderr, err := runProofEvidenceCollector(t, root)
		if err != nil {
			t.Fatalf("first safe collection: %v stderr=%s", err, stderr)
		}
		second, stderr, err := runProofEvidenceCollector(t, root)
		if err != nil {
			t.Fatalf("second safe collection: %v stderr=%s", err, stderr)
		}
		if !bytes.Equal(first, second) {
			t.Fatal("safe archive and manifest changed across identical runs")
		}
		files, _ := readProofEvidenceArchive(t, first)
		for _, name := range []string{
			"guest-repo-snapshot.sha256", "repo-snapshot-match.txt", "execution-roots-setup-safe.json", "nomad-service-safe.json", "nomad-agent-safe.json", "summary.json",
			"runtime-identity-vault-summary.json", "runtime-identity-vault-status-safe.json",
			"runtime-identity-vault-log-assertions.json",
			"control-plane-normal-shell-log-assertions.json", "safe-evidence-manifest.json",
		} {
			if _, ok := files[name]; !ok {
				t.Fatalf("expected safe evidence %q missing", name)
			}
		}
		var rootsSetup map[string]any
		if err := json.Unmarshal(files["execution-roots-setup-safe.json"], &rootsSetup); err != nil ||
			len(rootsSetup) != 8 || rootsSetup["profile"] != "service-root-v1" ||
			rootsSetup["static_root_owner_mode_checked"] != true ||
			rootsSetup["container_identity_or_behavioral_capability_proved"] != false {
			t.Fatalf("fixed setup projection changed: fields=%v err=%v", rootsSetup, err)
		}
		if _, ok := files["control-plane-normal-shell-summary.json"]; ok {
			t.Fatal("failed execution summary with untrusted message entered evidence archive")
		}
		for _, canary := range []string{proofRootTokenCanary, proofSecretCanary, proofAPIKeyCanary} {
			if bytes.Contains(first, []byte(canary)) {
				t.Fatal("secret canary entered safe archive or manifest")
			}
		}
		for _, forbidden := range []string{"managed-secrets.conf", "env.sh", "vault-dev", "spire-data", "tls", "es-staging", "es-results", "workdirs", "payload", "bin", "logs.txt", "run-id.txt", "result.tar.gz", "nomad-agent-self.json", "systemctl-status-nomad.txt", "docker-info.txt"} {
			for name := range files {
				if name == forbidden || strings.Contains(name, forbidden) {
					t.Fatalf("forbidden path %q entered safe archive", name)
				}
			}
		}
	})

	for _, tc := range []struct {
		name  string
		setup func(*testing.T, string)
	}{
		{"selected symlink", func(t *testing.T, root string) {
			target := filepath.Join(t.TempDir(), "target")
			writeProofEvidenceFile(t, filepath.Dir(target), filepath.Base(target), []byte("safe"))
			if err := os.Symlink(target, filepath.Join(root, "status-safe.json")); err != nil {
				t.Fatal(err)
			}
		}},
		{"selected hard link", func(t *testing.T, root string) {
			writeProofEvidenceFile(t, root, "source", []byte("safe"))
			if err := os.Link(filepath.Join(root, "source"), filepath.Join(root, "status-safe.json")); err != nil {
				t.Fatal(err)
			}
		}},
		{"selected FIFO", func(t *testing.T, root string) {
			if err := syscall.Mkfifo(filepath.Join(root, "status-safe.json"), 0o600); err != nil {
				t.Skipf("FIFO unavailable: %v", err)
			}
		}},
		{"oversized selected file", func(t *testing.T, root string) {
			path := filepath.Join(root, "status-safe.json")
			writeProofEvidenceFile(t, root, "status-safe.json", nil)
			if err := os.Truncate(path, (32<<20)+1); err != nil {
				t.Fatal(err)
			}
		}},
		{"invalid roots setup projection", func(t *testing.T, root string) {
			writeProofEvidenceFile(t, root, "execution-roots-setup-safe.json", []byte(`{"schema":"supported-local-execution-roots-setup-safe-v1","profile":"service-root-v1","configured_root_uid":0,"configured_root_gid":0,"configured_root_mode":"0755","static_root_owner_mode_checked":true,"operator_write_access_required":false,"container_identity_or_behavioral_capability_proved":false,"unknown":"`+proofSecretCanary+`"}`))
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			tc.setup(t, root)
			stdout, stderr, err := runProofEvidenceCollector(t, root)
			if err == nil || len(stdout) != 0 || strings.Contains(stderr, proofRootTokenCanary) {
				t.Fatalf("unsafe selected file did not fail closed: err=%v stdout_bytes=%d stderr=%q", err, len(stdout), stderr)
			}
		})
	}
	t.Run("traversal root argument", func(t *testing.T) {
		root := t.TempDir()
		stdout, _, err := runProofEvidenceCollector(t, root+"/../"+filepath.Base(root))
		if err == nil || len(stdout) != 0 {
			t.Fatalf("traversal path accepted: err=%v stdout_bytes=%d", err, len(stdout))
		}
	})
}

func TestSupportedLocalProofLogAssertionProjection(t *testing.T) {
	guest := t.TempDir()
	fakeCommands := t.TempDir()
	writeProofEvidenceFile(t, guest, "env.sh", nil)
	writeProofEvidenceFile(t, guest, "es.json", []byte(`{"execution":{"staging_root_dir":"`+guest+`/staging"}}`))
	prepareProofStagingObservationRoot(t, guest)
	writeProofEvidenceFile(t, guest, "workdirs/run-1/summary.json", []byte(`{"ok":true,"message":"execution completed successfully","run_id":"run-0123456789abcdef"}`))
	writeProofEvidenceFile(t, guest, "workdirs/run-1/status.json", []byte(`{"terminal":true}`))
	writeProofEvidenceFile(t, guest, "workdirs/run-1/logs.txt", []byte("PLATFORM-ENDPOINT-USED\nIDENTITY-JWT-RECEIVED\nVAULT-LOGIN-SUCCESS\nSECRET-READ-SUCCESS:"+proofSecretCanary+"\n"))
	nomad := `#!/usr/bin/env bash
set -euo pipefail
if [[ "$1" == job && "$2" == allocs ]]; then
  printf '[{"ID":"01234567-89ab-cdef-0123-456789abcdef"}]\n'
else
  printf 'proof status\n'
fi
`
	if err := os.WriteFile(filepath.Join(fakeCommands, "nomad"), []byte(nomad), 0o755); err != nil {
		t.Fatal(err)
	}
	command := exec.Command("bash", "-c", `source "$PROOF_SCRIPT"; run_guest_stdin() { bash -seuo pipefail; }; capture_execution_evidence runtime-identity-vault`)
	command.Dir = executionPlatformRepoRoot(t)
	command.Env = append(os.Environ(),
		"PROOF_SCRIPT="+filepath.Join(executionPlatformRepoRoot(t), "scripts", "73_supported_local_proof.sh"),
		"GUEST_REPO_ROOT="+executionPlatformRepoRoot(t), "GUEST_PROOF_DIR="+guest,
		"PATH="+fakeCommands+string(os.PathListSeparator)+os.Getenv("PATH"),
	)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("local proof evidence projection failed: %v output=%q", err, output)
	}
	assertions, err := os.ReadFile(filepath.Join(guest, "runtime-identity-vault-log-assertions.json"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(assertions, []byte(proofSecretCanary)) {
		t.Fatal("secret canary entered log assertion projection")
	}
	var projected map[string]any
	if err := json.Unmarshal(assertions, &projected); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"identity_endpoint_used", "identity_jwt_received", "vault_login_success", "secret_read_success"} {
		if projected[key] != true {
			t.Fatalf("missing fixed log assertion %q", key)
		}
	}
	for _, name := range []string{"logs.txt", "runtime-identity-vault-logs.txt"} {
		if _, err := os.Lstat(filepath.Join(guest, name)); !os.IsNotExist(err) {
			t.Fatalf("raw log copied into top-level guest evidence: %q err=%v", name, err)
		}
	}
}

func TestSupportedLocalProofSequentialCapturesAndLineage(t *testing.T) {
	const firstRun = "run-0123456789abcdef"
	const secondRun = "run-fedcba9876543210"
	const firstAllocation = "01234567-89ab-cdef-0123-456789abcdef"
	const secondAllocation = "fedcba98-7654-3210-fedc-ba9876543210"
	guest := proofPhysicalTempDir(t)
	fakeCommands := t.TempDir()
	writeProofEvidenceFile(t, guest, "env.sh", nil)
	writeProofEvidenceFile(t, guest, "es.json", []byte(`{"execution":{"staging_root_dir":"`+guest+`/staging"}}`))
	prepareProofStagingObservationRoot(t, guest)
	writeProofEvidenceFile(t, guest, "workdirs/first/summary.json", proofExecutionLoopSummary(t, filepath.Join(guest, "workdirs", "first"), firstRun, nil))
	writeProofEvidenceFile(t, guest, "workdirs/first/status.json", []byte(`{"state":"complete","terminal":true,"exit_code":0}`))
	writeProofEvidenceFile(t, guest, "workdirs/first/logs.txt", []byte("PLATFORM-ENDPOINT-USED\nIDENTITY-JWT-RECEIVED\nVAULT-LOGIN-SUCCESS\nSECRET-READ-SUCCESS:"+proofSecretCanary+"\n"))
	resultBundle := proofResultFixture(t, "")
	writeProofEvidenceFile(t, guest, "workdirs/second/summary.json", proofExecutionLoopSummary(t, filepath.Join(guest, "workdirs", "second"), secondRun, resultBundle))
	writeProofEvidenceFile(t, guest, "workdirs/second/status.json", []byte(`{"state":"terminal","terminal":true,"exit_code":0}`))
	writeProofEvidenceFile(t, guest, "workdirs/second/logs.txt", []byte("CP-NORMAL-SHELL-RUNTIME-CONTRACT-PROVED\n"+proofAPIKeyCanary+"\n"))
	writeProofEvidenceFile(t, guest, "workdirs/second/result.tar.gz", resultBundle)
	if err := os.Chtimes(filepath.Join(guest, "workdirs", "second"), time.Unix(0, 0), time.Unix(0, 0)); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(filepath.Join(guest, "workdirs", "first"), time.Unix(1, 0), time.Unix(1, 0)); err != nil {
		t.Fatal(err)
	}
	nomad := `#!/usr/bin/env bash
set -euo pipefail
if [[ "$1" == job && "$2" == status ]]; then
  [[ "$3" == exec-run-0123456789abcdef || "$3" == exec-run-fedcba9876543210 ]]
  exit
fi
if [[ "$1" == job && "$2" == allocs && "$3" == -json ]]; then
  case "$4" in
    exec-run-0123456789abcdef) printf '[{"ID":"01234567-89ab-cdef-0123-456789abcdef"}]\n' ;;
    exec-run-fedcba9876543210) printf '[{"ID":"fedcba98-7654-3210-fedc-ba9876543210"}]\n' ;;
    *) exit 91 ;;
  esac
  exit
fi
if [[ "$1" == alloc && "$2" == status ]]; then
  [[ "$3" == 01234567-89ab-cdef-0123-456789abcdef || "$3" == fedcba98-7654-3210-fedc-ba9876543210 ]]
  exit
fi
exit 92
`
	if err := os.WriteFile(filepath.Join(fakeCommands, "nomad"), []byte(nomad), 0o755); err != nil {
		t.Fatal(err)
	}
	shell := `source "$PROOF_SCRIPT"
run_guest_stdin() { bash -seuo pipefail; }
capture_execution_evidence runtime-identity-vault
touch "$GUEST_PROOF_DIR/workdirs/second"
capture_execution_evidence control-plane-normal-shell
validate_control_plane_normal_shell_result_bundle`
	command := exec.Command("bash", "-c", shell)
	command.Dir = executionPlatformRepoRoot(t)
	command.Env = append(os.Environ(), "PROOF_SCRIPT="+filepath.Join(executionPlatformRepoRoot(t), "scripts", "73_supported_local_proof.sh"),
		"GUEST_REPO_ROOT="+executionPlatformRepoRoot(t), "GUEST_PROOF_DIR="+guest,
		"PATH="+fakeCommands+string(os.PathListSeparator)+os.Getenv("PATH"))
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("canonical sequential captures failed: %v output=%q", err, output)
	}
	if _, err := os.Lstat(filepath.Join(guest, "status-safe.json")); !os.IsNotExist(err) {
		t.Fatal("labeled capture created conflicting base status projection")
	}
	for _, name := range []string{"summary.json", "nomad-execution-safe.json"} {
		if _, err := os.Lstat(filepath.Join(guest, name)); !os.IsNotExist(err) {
			t.Fatalf("labeled capture created ambiguous base lineage %s", name)
		}
	}
	for _, item := range []struct {
		label, runID, allocationID, state string
	}{
		{"runtime-identity-vault", firstRun, firstAllocation, "complete"},
		{"control-plane-normal-shell", secondRun, secondAllocation, "terminal"},
	} {
		summary, err := os.ReadFile(filepath.Join(guest, item.label+"-summary.json"))
		if err != nil || !bytes.Contains(summary, []byte(`"run_id":"`+item.runID+`"`)) {
			t.Fatalf("labeled raw summary lost run lineage: %s err=%v", item.label, err)
		}
		status, err := os.ReadFile(filepath.Join(guest, item.label+"-status-safe.json"))
		if err != nil || !bytes.Contains(status, []byte(`"state":"`+item.state+`"`)) {
			t.Fatalf("labeled status did not follow its workdir: %s err=%v", item.label, err)
		}
		execution, err := os.ReadFile(filepath.Join(guest, item.label+"-nomad-execution-safe.json"))
		if err != nil {
			t.Fatal(err)
		}
		var lineage map[string]any
		if err := json.Unmarshal(execution, &lineage); err != nil || lineage["run_id"] != item.runID ||
			lineage["job_id"] != "exec-"+item.runID || lineage["allocation_id"] != item.allocationID {
			t.Fatalf("labeled Nomad lineage mismatch: %s err=%v", item.label, err)
		}
	}
	if _, err := os.Lstat(filepath.Join(guest, "control-plane-normal-shell-result.tar.gz")); !os.IsNotExist(err) {
		t.Fatal("obsolete proof-root result alias exists; Review-16 consumer would be masked")
	}
	resultEvidence, err := os.ReadFile(filepath.Join(guest, "control-plane-normal-shell-result-evidence.json"))
	if err != nil {
		t.Fatal("result validation was not reachable after second capture")
	}
	var result map[string]any
	if err := json.Unmarshal(resultEvidence, &result); err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(resultBundle)
	if result["bundle_sha256"] != hex.EncodeToString(hash[:]) || result["bundle_size"] != float64(len(resultBundle)) {
		t.Fatalf("result projection did not describe bound workdir bundle: %v", result)
	}
	archive, stderr, err := runProofEvidenceCollector(t, guest)
	if err != nil {
		t.Fatalf("collect sequential projections: %v stderr=%q", err, stderr)
	}
	requireNoProofCanary(t, archive)
	if bytes.Contains(archive, resultBundle) || bytes.Contains(archive, []byte(guest)) {
		t.Fatal("raw bundle or private workdir path entered collected evidence")
	}
	files, _ := readProofEvidenceArchive(t, archive)
	for _, item := range []struct{ label, runID string }{{"runtime-identity-vault", firstRun}, {"control-plane-normal-shell", secondRun}} {
		var projected map[string]any
		if err := json.Unmarshal(files[item.label+"-summary.json"], &projected); err != nil || projected["run_id"] != item.runID {
			t.Fatalf("retained labeled summary lost run ID: %s err=%v", item.label, err)
		}
		if _, present := files[item.label+"-nomad-execution-safe.json"]; !present {
			t.Fatalf("retained labeled execution projection missing: %s", item.label)
		}
	}
	for _, forbidden := range []string{"summary.json", "status-safe.json", "nomad-execution-safe.json", "logs.txt", "control-plane-normal-shell-result.tar.gz"} {
		if _, present := files[forbidden]; present {
			t.Fatalf("unclassified base/raw file retained: %s", forbidden)
		}
	}
}

func TestSupportedLocalProofCaptureRejectsResultPathMismatch(t *testing.T) {
	guest := proofPhysicalTempDir(t)
	workdir := filepath.Join(guest, "workdirs", "normal")
	writeProofEvidenceFile(t, guest, "env.sh", nil)
	summary := proofExecutionLoopSummary(t, workdir, "run-fedcba9876543210", proofResultFixture(t, ""))
	var value map[string]any
	if err := json.Unmarshal(summary, &value); err != nil {
		t.Fatal(err)
	}
	value["result_path"] = filepath.Join(workdir, "wrong-result.tar.gz")
	writeProofEvidenceFile(t, guest, "workdirs/normal/summary.json", append(proofJSON(t, value), '\n'))
	fakeCommands := t.TempDir()
	if err := os.WriteFile(filepath.Join(fakeCommands, "nomad"), []byte("#!/bin/sh\nexit 97\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	command := exec.Command("bash", "-c", `source "$PROOF_SCRIPT"
run_guest_stdin() { bash -seuo pipefail; }
capture_execution_evidence control-plane-normal-shell`)
	command.Dir = executionPlatformRepoRoot(t)
	command.Env = append(os.Environ(),
		"PROOF_SCRIPT="+filepath.Join(executionPlatformRepoRoot(t), "scripts", "73_supported_local_proof.sh"),
		"GUEST_REPO_ROOT="+executionPlatformRepoRoot(t), "GUEST_PROOF_DIR="+guest,
		"PATH="+fakeCommands+string(os.PathListSeparator)+os.Getenv("PATH"))
	output, err := command.CombinedOutput()
	if err == nil || string(output) != "normal-shell proof result binding invalid\n" {
		t.Fatalf("capture accepted mismatched producer result path: err=%v output=%q", err, output)
	}
	if _, err := os.Lstat(filepath.Join(guest, "control-plane-normal-shell-nomad-execution-safe.json")); !os.IsNotExist(err) {
		t.Fatalf("mismatched capture published Nomad lineage: %v", err)
	}
}

func TestSupportedLocalProofCapturedResultBinding(t *testing.T) {
	type fixture struct {
		guest, workdir, inputProof string
		bundle                     []byte
	}
	const resultName = "control-plane-normal-shell-result-evidence.json"
	const alternateRun = "run-0123456789abcdef"
	cases := []struct {
		name   string
		accept bool
		mutate func(*testing.T, *fixture)
	}{
		{"bound result", true, nil},
		{"status state not required", true, func(t *testing.T, f *fixture) {
			rewriteBothProofSummaries(t, f.guest, f.workdir, func(v map[string]any) { v["state"] = nil })
		}},
		{"newer unrelated workdir", true, func(t *testing.T, f *fixture) {
			writeProofEvidenceFile(t, f.guest, "workdirs/newer/result.tar.gz", proofResultFixture(t, "wrong status"))
			writeProofEvidenceFile(t, f.guest, "workdirs/newer/summary.json",
				proofExecutionLoopSummary(t, filepath.Join(f.guest, "workdirs", "newer"), alternateRun, f.bundle))
		}},
		{"missing bound with legacy alias and another bundle", false, func(t *testing.T, f *fixture) {
			if err := os.Remove(filepath.Join(f.workdir, "result.tar.gz")); err != nil {
				t.Fatal(err)
			}
			writeProofEvidenceFile(t, f.guest, "control-plane-normal-shell-result.tar.gz", f.bundle)
			writeProofEvidenceFile(t, f.guest, "workdirs/other/result.tar.gz", f.bundle)
		}},
		{"source summary changed", false, func(t *testing.T, f *fixture) {
			rewriteProofJSON(t, filepath.Join(f.workdir, "summary.json"), func(v map[string]any) { v["result_bytes"] = len(f.bundle) + 1 })
		}},
		{"captured run changed", false, func(t *testing.T, f *fixture) {
			rewriteProofJSON(t, filepath.Join(f.guest, "control-plane-normal-shell-summary.json"), func(v map[string]any) { v["run_id"] = alternateRun })
		}},
		{"nomad run changed", false, func(t *testing.T, f *fixture) {
			rewriteProofJSON(t, filepath.Join(f.guest, "control-plane-normal-shell-nomad-execution-safe.json"), func(v map[string]any) {
				v["run_id"] = alternateRun
				v["job_id"] = "exec-" + alternateRun
			})
		}},
		{"nomad job changed", false, func(t *testing.T, f *fixture) {
			rewriteProofJSON(t, filepath.Join(f.guest, "control-plane-normal-shell-nomad-execution-safe.json"), func(v map[string]any) { v["job_id"] = "exec-" + alternateRun })
		}},
		{"invalid allocation", false, func(t *testing.T, f *fixture) {
			rewriteProofJSON(t, filepath.Join(f.guest, "control-plane-normal-shell-nomad-execution-safe.json"), func(v map[string]any) { v["allocation_id"] = "invalid" })
		}},
		{"unobserved allocation", false, func(t *testing.T, f *fixture) {
			rewriteProofJSON(t, filepath.Join(f.guest, "control-plane-normal-shell-nomad-execution-safe.json"), func(v map[string]any) { v["allocation_observed"] = false })
		}},
		{"result unavailable", false, func(t *testing.T, f *fixture) {
			rewriteBothProofSummaries(t, f.guest, f.workdir, func(v map[string]any) { v["result_available"] = false })
		}},
		{"execution failed", false, func(t *testing.T, f *fixture) {
			rewriteBothProofSummaries(t, f.guest, f.workdir, func(v map[string]any) { v["ok"] = false })
		}},
		{"execution not terminal", false, func(t *testing.T, f *fixture) {
			rewriteBothProofSummaries(t, f.guest, f.workdir, func(v map[string]any) { v["terminal"] = false })
		}},
		{"execution nonzero", false, func(t *testing.T, f *fixture) {
			rewriteBothProofSummaries(t, f.guest, f.workdir, func(v map[string]any) { v["exit_code"] = 1 })
		}},
		{"invalid run id", false, func(t *testing.T, f *fixture) {
			rewriteBothProofSummaries(t, f.guest, f.workdir, func(v map[string]any) { v["run_id"] = "invalid" })
		}},
		{"wrong result byte count", false, func(t *testing.T, f *fixture) {
			rewriteBothProofSummaries(t, f.guest, f.workdir, func(v map[string]any) { v["result_bytes"] = len(f.bundle) + 1 })
		}},
		{"boolean result byte count", false, func(t *testing.T, f *fixture) {
			rewriteBothProofSummaries(t, f.guest, f.workdir, func(v map[string]any) { v["result_bytes"] = true })
		}},
		{"zero result byte count", false, func(t *testing.T, f *fixture) {
			rewriteBothProofSummaries(t, f.guest, f.workdir, func(v map[string]any) { v["result_bytes"] = 0 })
		}},
		{"wrong result path", false, func(t *testing.T, f *fixture) {
			rewriteBothProofSummaries(t, f.guest, f.workdir, func(v map[string]any) { v["result_path"] = filepath.Join(f.workdir, "other.tar.gz") })
		}},
		{"nonstandard summary JSON", false, func(t *testing.T, f *fixture) {
			path := filepath.Join(f.guest, "control-plane-normal-shell-summary.json")
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			data = bytes.Replace(data, []byte(`"ok":true`), []byte(`"extra":NaN,"ok":true`), 1)
			if err := os.WriteFile(path, data, 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{"workdir outside proof", false, func(t *testing.T, f *fixture) {
			outside := filepath.Join(filepath.Dir(f.guest), "outside-workdir")
			rewriteBothProofSummaries(t, f.guest, f.workdir, func(v map[string]any) {
				v["workdir"] = outside
				v["result_path"] = filepath.Join(outside, "result.tar.gz")
			})
		}},
		{"relative workdir", false, func(t *testing.T, f *fixture) {
			rewriteBothProofSummaries(t, f.guest, f.workdir, func(v map[string]any) {
				v["workdir"] = "workdirs/normal"
				v["result_path"] = "workdirs/normal/result.tar.gz"
			})
		}},
		{"unclean workdir", false, func(t *testing.T, f *fixture) {
			unclean := filepath.Join(f.guest, "workdirs") + "/../workdirs/normal"
			rewriteBothProofSummaries(t, f.guest, f.workdir, func(v map[string]any) {
				v["workdir"] = unclean
				v["result_path"] = unclean + "/result.tar.gz"
			})
		}},
		{"symlinked proof root", false, func(t *testing.T, f *fixture) {
			aliasDir := proofPhysicalTempDir(t)
			alias := filepath.Join(aliasDir, "proof-alias")
			if err := os.Symlink(f.guest, alias); err != nil {
				t.Fatal(err)
			}
			f.inputProof = alias
		}},
		{"symlinked workdir", false, func(t *testing.T, f *fixture) {
			held := filepath.Join(f.guest, "held-workdir")
			if err := os.Rename(f.workdir, held); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(held, f.workdir); err != nil {
				t.Fatal(err)
			}
		}},
		{"symlinked workdirs parent", false, func(t *testing.T, f *fixture) {
			original := filepath.Join(f.guest, "workdirs")
			held := filepath.Join(f.guest, "held-workdirs")
			if err := os.Rename(original, held); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(held, original); err != nil {
				t.Fatal(err)
			}
		}},
		{"symlinked result", false, func(t *testing.T, f *fixture) {
			result := filepath.Join(f.workdir, "result.tar.gz")
			held := filepath.Join(f.workdir, "held-result.tar.gz")
			if err := os.Rename(result, held); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(held, result); err != nil {
				t.Fatal(err)
			}
		}},
		{"hard linked result", false, func(t *testing.T, f *fixture) {
			if err := os.Link(filepath.Join(f.workdir, "result.tar.gz"), filepath.Join(f.workdir, "other-link")); err != nil {
				t.Fatal(err)
			}
		}},
		{"nonregular result", false, func(t *testing.T, f *fixture) {
			result := filepath.Join(f.workdir, "result.tar.gz")
			if err := os.Remove(result); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(result, 0o700); err != nil {
				t.Fatal(err)
			}
		}},
		{"oversized declared and stored result", false, func(t *testing.T, f *fixture) {
			const oversized = (16 << 20) + 1
			if err := os.Truncate(filepath.Join(f.workdir, "result.tar.gz"), oversized); err != nil {
				t.Fatal(err)
			}
			rewriteBothProofSummaries(t, f.guest, f.workdir, func(v map[string]any) { v["result_bytes"] = oversized })
		}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			f := fixture{guest: proofPhysicalTempDir(t), bundle: proofResultFixture(t, "")}
			f.workdir = writeCapturedProofResultFixture(t, f.guest, f.bundle)
			f.inputProof = f.guest
			if test.mutate != nil {
				test.mutate(t, &f)
			}
			output, err := runProofPython(t, "supported_local_proof_projection.py", nil,
				"captured-result", f.inputProof, filepath.Join(f.inputProof, resultName))
			projectionPath := filepath.Join(f.guest, resultName)
			if test.accept {
				if err != nil {
					t.Fatalf("bound result refused: %v output=%q", err, output)
				}
				projection, readErr := os.ReadFile(projectionPath)
				if readErr != nil {
					t.Fatal(readErr)
				}
				var value map[string]any
				if err := json.Unmarshal(projection, &value); err != nil {
					t.Fatal(err)
				}
				hash := sha256.Sum256(f.bundle)
				if value["bundle_size"] != float64(len(f.bundle)) || value["bundle_sha256"] != hex.EncodeToString(hash[:]) {
					t.Fatalf("bound bundle size/digest mismatch: %v", value)
				}
			} else {
				if err == nil || string(output) != "supported-local safe proof projection failed\n" {
					t.Fatalf("rejected binding accepted or leaked diagnostic: err=%v output=%q", err, output)
				}
				if _, statErr := os.Lstat(projectionPath); !os.IsNotExist(statErr) {
					t.Fatalf("rejected result left success projection: %v", statErr)
				}
			}
			archive, stderr, err := runProofEvidenceCollector(t, f.guest)
			if err != nil {
				if len(archive) != 0 || strings.Contains(stderr, f.guest) {
					t.Fatalf("collector failure exposed private input: err=%v stderr=%q", err, stderr)
				}
				return
			}
			if bytes.Contains(archive, f.bundle) || bytes.Contains(archive, []byte(f.guest)) {
				t.Fatal("raw bundle or private workdir path entered safe collection")
			}
			files, _ := readProofEvidenceArchive(t, archive)
			_, hasResult := files[resultName]
			if hasResult != test.accept {
				t.Fatalf("result projection publication mismatch: got=%v want=%v", hasResult, test.accept)
			}
		})
	}
}

func TestSupportedLocalProofResultValidationFinalizerContinuation(t *testing.T) {
	const firstRun = "run-0123456789abcdef"
	const secondRun = "run-fedcba9876543210"
	for _, variant := range []string{"success", "missing", "invalid schema"} {
		t.Run(variant, func(t *testing.T) {
			guest := proofPhysicalTempDir(t)
			host := filepath.Join(proofPhysicalTempDir(t), "host-proof")
			fakeCommands := t.TempDir()
			writeFakeProofLimactl(t, fakeCommands)
			writeProofEvidenceFile(t, guest, "env.sh", nil)
			writeProofEvidenceFile(t, guest, "es.json", []byte(`{"execution":{"staging_root_dir":"`+guest+`/staging"}}`))
			prepareProofStagingObservationRoot(t, guest)
			writeProofEvidenceFile(t, guest, "workdirs/first/summary.json",
				proofExecutionLoopSummary(t, filepath.Join(guest, "workdirs", "first"), firstRun, nil))
			writeProofEvidenceFile(t, guest, "workdirs/first/status.json", []byte(`{"state":"complete","terminal":true,"exit_code":0}`))
			writeProofEvidenceFile(t, guest, "workdirs/first/logs.txt", []byte("PLATFORM-ENDPOINT-USED\nIDENTITY-JWT-RECEIVED\nVAULT-LOGIN-SUCCESS\nSECRET-READ-SUCCESS:"+proofSecretCanary+"\n"))
			bundle := proofResultFixture(t, "")
			if variant == "invalid schema" {
				bundle = proofResultFixture(t, "wrong status")
			}
			writeProofEvidenceFile(t, guest, "workdirs/second/summary.json",
				proofExecutionLoopSummary(t, filepath.Join(guest, "workdirs", "second"), secondRun, bundle))
			writeProofEvidenceFile(t, guest, "workdirs/second/status.json", []byte(`{"state":"terminal","terminal":true,"exit_code":0}`))
			writeProofEvidenceFile(t, guest, "workdirs/second/logs.txt", []byte("CP-NORMAL-SHELL-RUNTIME-CONTRACT-PROVED\n"+proofAPIKeyCanary+"\n"))
			writeProofEvidenceFile(t, guest, "workdirs/second/result.tar.gz", bundle)
			if variant == "missing" {
				if err := os.Remove(filepath.Join(guest, "workdirs", "second", "result.tar.gz")); err != nil {
					t.Fatal(err)
				}
				writeProofEvidenceFile(t, guest, "control-plane-normal-shell-result.tar.gz", proofResultFixture(t, ""))
			}
			if err := os.Chtimes(filepath.Join(guest, "workdirs", "second"), time.Unix(0, 0), time.Unix(0, 0)); err != nil {
				t.Fatal(err)
			}
			if err := os.Chtimes(filepath.Join(guest, "workdirs", "first"), time.Unix(1, 0), time.Unix(1, 0)); err != nil {
				t.Fatal(err)
			}
			nomad := `#!/usr/bin/env bash
set -euo pipefail
case "$1 $2" in
  "job status") [[ "$3" == exec-run-0123456789abcdef || "$3" == exec-run-fedcba9876543210 ]] ;;
  "job allocs")
    [[ "$3" == -json ]]
    case "$4" in
      exec-run-0123456789abcdef) printf '[{"ID":"01234567-89ab-cdef-0123-456789abcdef"}]\n' ;;
      exec-run-fedcba9876543210) printf '[{"ID":"fedcba98-7654-3210-fedc-ba9876543210"}]\n' ;;
      *) exit 91 ;;
    esac ;;
  "alloc status") [[ "$3" == 01234567-89ab-cdef-0123-456789abcdef || "$3" == fedcba98-7654-3210-fedc-ba9876543210 ]] ;;
  *) exit 92 ;;
esac
`
			if err := os.WriteFile(filepath.Join(fakeCommands, "nomad"), []byte(nomad), 0o755); err != nil {
				t.Fatal(err)
			}
			for _, name := range []string{"docker", "sudo", "vault", "spire-server", "spire-agent", "curl"} {
				if err := os.WriteFile(filepath.Join(fakeCommands, name), []byte("#!/bin/sh\nexit 97\n"), 0o755); err != nil {
					t.Fatal(err)
				}
			}
			limactlLog := filepath.Join(fakeCommands, "limactl.log")
			shell := `source "$PROOF_SCRIPT"
run_guest_stdin() { bash -seuo pipefail; }
cleanup_control_plane() { CONTROL_PLANE_STARTED=false; }
cleanup_host_bootstrap_scratch() { return 0; }
remove_current_guest_scratch() { :; }
create_private_host_proof_dir
GUEST_COLLECTION_READY=true
trap finalize EXIT
run_phase runtime-identity-capture capture_execution_evidence runtime-identity-vault
touch "$GUEST_PROOF_DIR/workdirs/second"
run_phase normal-shell-capture capture_execution_evidence control-plane-normal-shell
run_phase result-validation validate_control_plane_normal_shell_result_bundle
collect_guest_workspace final`
			command := exec.Command("bash", "-c", shell)
			command.Dir = executionPlatformRepoRoot(t)
			command.Env = append(os.Environ(),
				"PROOF_SCRIPT="+filepath.Join(executionPlatformRepoRoot(t), "scripts", "73_supported_local_proof.sh"),
				"GUEST_REPO_ROOT="+executionPlatformRepoRoot(t), "GUEST_PROOF_DIR="+guest,
				"GUEST_BOOTSTRAP_DIR="+filepath.Join(t.TempDir(), "guest-bootstrap"),
				"SUPPORTED_LOCAL_PROOF_ID=result-handoff-"+strconv.FormatInt(time.Now().UnixNano(), 10),
				"SUPPORTED_LOCAL_HOST_PROOF_DIR="+host, "SUPPORTED_LOCAL_INSTANCE=fake-proof-guest",
				"SUPPORTED_LOCAL_GUEST_PROOF_DIR="+guest, "FAKE_GUEST_PROOF_DIR="+guest,
				"FAKE_LIMACTL_LOG="+limactlLog,
				"PATH="+fakeCommands+string(os.PathListSeparator)+os.Getenv("PATH"))
			output, err := command.CombinedOutput()
			wantSuccess := variant == "success"
			if wantSuccess && err != nil {
				t.Fatalf("safe continuation failed: %v output=%q", err, output)
			}
			if !wantSuccess {
				var exitErr *exec.ExitError
				if !errors.As(err, &exitErr) || exitErr.ExitCode() != 1 {
					t.Fatalf("failed result changed primary status: err=%v output=%q", err, output)
				}
			}
			generation := "failure"
			if wantSuccess {
				generation = "final"
			}
			for _, name := range []string{"runtime-identity-vault-nomad-execution-safe.json",
				"control-plane-normal-shell-summary.json", "control-plane-normal-shell-nomad-execution-safe.json",
				"safe-evidence-manifest.json"} {
				if _, err := os.ReadFile(filepath.Join(host, "guest-evidence", generation, name)); err != nil {
					t.Fatalf("honest %s evidence missing %s: %v", generation, name, err)
				}
			}
			resultPath := filepath.Join(host, "guest-evidence", generation, "control-plane-normal-shell-result-evidence.json")
			if wantSuccess {
				data, err := os.ReadFile(resultPath)
				if err != nil {
					t.Fatal(err)
				}
				var projected map[string]any
				if err := json.Unmarshal(data, &projected); err != nil {
					t.Fatal(err)
				}
				hash := sha256.Sum256(bundle)
				if projected["bundle_sha256"] != hex.EncodeToString(hash[:]) || projected["bundle_size"] != float64(len(bundle)) {
					t.Fatalf("final result projection lost workdir bytes: %v", projected)
				}
			} else if _, err := os.Lstat(resultPath); !os.IsNotExist(err) {
				t.Fatalf("failure published result success projection: %v", err)
			}
			otherGeneration := "final"
			if wantSuccess {
				otherGeneration = "failure"
			}
			if _, err := os.Lstat(filepath.Join(host, "guest-evidence", otherGeneration)); !os.IsNotExist(err) {
				t.Fatalf("wrong evidence generation exists: %v", err)
			}
			phase, err := os.ReadFile(filepath.Join(host, "phase-result-validation.json"))
			if err != nil {
				t.Fatal(err)
			}
			var phaseValue map[string]any
			if err := json.Unmarshal(phase, &phaseValue); err != nil || phaseValue["success"] != wantSuccess {
				t.Fatalf("result phase status mismatch: %v err=%v", phaseValue, err)
			}
			closeout, err := os.ReadFile(filepath.Join(host, "proof-closeout.json"))
			if err != nil {
				t.Fatal(err)
			}
			var closeoutValue map[string]any
			if err := json.Unmarshal(closeout, &closeoutValue); err != nil || closeoutValue["primary_exit_code"] != map[bool]float64{true: 0, false: 1}[wantSuccess] {
				t.Fatalf("closeout status mismatch: %v err=%v", closeoutValue, err)
			}
			manifest, err := os.ReadFile(filepath.Join(host, "host-evidence-manifest.json"))
			if err != nil {
				t.Fatal(err)
			}
			if wantSuccess && !bytes.Contains(manifest, []byte("guest-evidence/final/control-plane-normal-shell-result-evidence.json")) {
				t.Fatal("host manifest omitted final result projection")
			}
			if err := filepath.WalkDir(host, func(path string, entry os.DirEntry, walkErr error) error {
				if walkErr != nil || entry.IsDir() {
					return walkErr
				}
				data, err := os.ReadFile(path)
				if err != nil {
					return err
				}
				if bytes.Contains(data, bundle) || bytes.Contains(data, []byte(guest)) ||
					bytes.Contains(data, []byte(proofSecretCanary)) || bytes.Contains(data, []byte(proofAPIKeyCanary)) {
					t.Fatalf("raw result, path, or canary entered host evidence: %s", path)
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(output), guest) || strings.Contains(string(output), proofSecretCanary) || strings.Contains(string(output), proofAPIKeyCanary) {
				t.Fatalf("failure diagnostic leaked private input: %q", output)
			}
		})
	}
}

func TestSupportedLocalProofAllocationExactCount(t *testing.T) {
	const runID = "run-0123456789abcdef"
	const allocationID = "01234567-89ab-cdef-0123-456789abcdef"
	const otherAllocationID = "fedcba98-7654-3210-fedc-ba9876543210"
	for _, tc := range []struct {
		name, response, wantError string
	}{
		{"exact_one", `[{"ID":"` + allocationID + `","Meta":"` + proofSecretCanary + `"}]`, ""},
		{"exact_one_unknown_strict_json", `[{"ID":"` + allocationID + `","Meta":{"weight":1.5,"enabled":true},"Extra":[1,false,null]}]`, ""},
		{"zero", `[]`, "proof allocation count must be exactly one"},
		{"multiple_stale_first", `[{"ID":"` + allocationID + `"},{"ID":"` + otherAllocationID + `"}]`, "proof allocation count must be exactly one"},
		{"multiple_intended_first", `[{"ID":"` + otherAllocationID + `"},{"ID":"` + allocationID + `"}]`, "proof allocation count must be exactly one"},
		{"duplicate_entries", `[{"ID":"` + allocationID + `"},{"ID":"` + allocationID + `"}]`, "proof allocation count must be exactly one"},
		{"non_list", `{"ID":"` + allocationID + `"}`, "proof allocation list invalid"},
		{"non_object_entry", `[7]`, "proof allocation entry invalid"},
		{"missing_id", `[{}]`, "proof allocation id invalid"},
		{"invalid_id", `[{"ID":"ALLOC-NOT-UUID"}]`, "proof allocation id invalid"},
		{"malformed_json", `[`, "proof allocation list invalid"},
		{"nonstandard_nan_unknown_field", `[{"ID":"` + allocationID + `","Meta":NaN}]`, "proof allocation list invalid"},
		{"nonstandard_infinity_unknown_field", `[{"ID":"` + allocationID + `","Meta":Infinity}]`, "proof allocation list invalid"},
		{"nonstandard_negative_infinity_unknown_field", `[{"ID":"` + allocationID + `","Meta":-Infinity}]`, "proof allocation list invalid"},
		{"nonstandard_nested_nan", `[{"ID":"` + allocationID + `","Meta":{"weight":NaN}}]`, "proof allocation list invalid"},
		{"nonstandard_unknown_list_infinity", `[{"ID":"` + allocationID + `","Meta":[1,Infinity]}]`, "proof allocation list invalid"},
		{"nonstandard_other_entry", `[{"ID":"` + allocationID + `"},NaN]`, "proof allocation list invalid"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			guest := t.TempDir()
			fakeCommands := t.TempDir()
			responsePath := filepath.Join(fakeCommands, "alloc-response.json")
			logPath := filepath.Join(fakeCommands, "nomad.log")
			resultMarker := filepath.Join(fakeCommands, "result-validation-reached")
			writeProofEvidenceFile(t, guest, "env.sh", nil)
			writeProofEvidenceFile(t, guest, "es.json", []byte(`{"execution":{"staging_root_dir":"`+guest+`/staging"}}`))
			prepareProofStagingObservationRoot(t, guest)
			writeProofEvidenceFile(t, guest, "workdirs/only/summary.json", []byte(`{"ok":true,"message":"execution completed successfully","run_id":"`+runID+`","Meta":"`+proofAPIKeyCanary+`"}`))
			writeProofEvidenceFile(t, guest, "workdirs/only/status.json", []byte(`{"state":"complete","terminal":true,"exit_code":0}`))
			writeProofEvidenceFile(t, guest, "workdirs/only/logs.txt", []byte("SECRET-READ-SUCCESS:"+proofSecretCanary+"\n"))
			if err := os.WriteFile(responsePath, []byte(tc.response), 0o600); err != nil {
				t.Fatal(err)
			}
			nomad := `#!/usr/bin/env bash
set -euo pipefail
if [[ "$1" == job && "$2" == status ]]; then
  printf 'job-status:%s\n' "$3" >> "$FAKE_NOMAD_LOG"
  exit 0
fi
if [[ "$1" == job && "$2" == allocs && "$3" == -json ]]; then
  printf 'job-allocs:%s\n' "$4" >> "$FAKE_NOMAD_LOG"
  cat "$FAKE_ALLOC_RESPONSE"
  exit 0
fi
if [[ "$1" == alloc && "$2" == status ]]; then
  printf 'alloc-status:%s\n' "$3" >> "$FAKE_NOMAD_LOG"
  exit 0
fi
exit 92
`
			if err := os.WriteFile(filepath.Join(fakeCommands, "nomad"), []byte(nomad), 0o755); err != nil {
				t.Fatal(err)
			}
			command := exec.Command("bash", "-c", `source "$PROOF_SCRIPT"; run_guest_stdin() { bash -seuo pipefail; }; capture_execution_evidence runtime-identity-vault; printf 'reached\n' > "$RESULT_VALIDATION_MARKER"`)
			command.Dir = executionPlatformRepoRoot(t)
			command.Env = append(os.Environ(), "PROOF_SCRIPT="+filepath.Join(executionPlatformRepoRoot(t), "scripts", "73_supported_local_proof.sh"),
				"GUEST_REPO_ROOT="+executionPlatformRepoRoot(t), "GUEST_PROOF_DIR="+guest,
				"FAKE_ALLOC_RESPONSE="+responsePath, "FAKE_NOMAD_LOG="+logPath,
				"RESULT_VALIDATION_MARKER="+resultMarker,
				"PATH="+fakeCommands+string(os.PathListSeparator)+os.Getenv("PATH"))
			output, err := command.CombinedOutput()
			calls, readErr := os.ReadFile(logPath)
			if readErr != nil {
				t.Fatal(readErr)
			}
			wantCalls := "job-status:exec-" + runID + "\njob-allocs:exec-" + runID + "\n"
			projectionPath := filepath.Join(guest, "runtime-identity-vault-nomad-execution-safe.json")
			if tc.wantError != "" {
				if err == nil || string(output) != tc.wantError+"\n" || string(calls) != wantCalls {
					t.Fatalf("allocation refusal mismatch: err=%v output=%q calls=%q", err, output, calls)
				}
				if _, statErr := os.Lstat(projectionPath); !os.IsNotExist(statErr) {
					t.Fatalf("failed selection wrote Nomad lineage: %v", statErr)
				}
				for _, name := range []string{"staging-check.txt", "runtime-identity-vault-staging-check.txt"} {
					if _, statErr := os.Lstat(filepath.Join(guest, name)); !os.IsNotExist(statErr) {
						t.Fatalf("failed selection wrote staging check %s: %v", name, statErr)
					}
				}
				if _, statErr := os.Lstat(resultMarker); !os.IsNotExist(statErr) {
					t.Fatalf("failed selection reached later result validation: %v", statErr)
				}
			} else {
				if err != nil || len(output) != 0 || string(calls) != wantCalls+"alloc-status:"+allocationID+"\n" {
					t.Fatalf("exact-one capture mismatch: err=%v output=%q calls=%q", err, output, calls)
				}
				if _, statErr := os.Lstat(resultMarker); statErr != nil {
					t.Fatalf("exact-one capture did not reach later result validation: %v", statErr)
				}
				projection, readErr := os.ReadFile(projectionPath)
				if readErr != nil {
					t.Fatal(readErr)
				}
				var value map[string]any
				if err := json.Unmarshal(projection, &value); err != nil || len(value) != 6 ||
					value["run_id"] != runID || value["job_id"] != "exec-"+runID ||
					value["allocation_id"] != allocationID || value["job_observed"] != true ||
					value["allocation_observed"] != true || value["schema"] != "supported-local-nomad-execution-safe-v1" {
					t.Fatalf("exact-one retained lineage mismatch: %v err=%v", value, err)
				}
				if bytes.Contains(projection, []byte("Meta")) || bytes.Contains(projection, []byte("Extra")) {
					t.Fatalf("unknown allocation fields entered lineage: %q", projection)
				}
			}
			archive, stderr, collectErr := runProofEvidenceCollector(t, guest)
			if collectErr != nil {
				t.Fatalf("safe partial collection failed: %v stderr=%q", collectErr, stderr)
			}
			requireNoProofCanary(t, archive)
			if tc.wantError == "proof allocation list invalid" {
				for _, forbidden := range []string{"NaN", "Infinity", "Meta", "weight"} {
					if bytes.Contains(archive, []byte(forbidden)) {
						t.Fatalf("malformed allocation response entered safe evidence: %s", forbidden)
					}
				}
			}
			files, _ := readProofEvidenceArchive(t, archive)
			if _, ok := files["runtime-identity-vault-summary.json"]; !ok {
				t.Fatal("honest summary was not retained")
			}
			if _, ok := files["runtime-identity-vault-status-safe.json"]; !ok {
				t.Fatal("honest status was not retained")
			}
			_, hasExecution := files["runtime-identity-vault-nomad-execution-safe.json"]
			if hasExecution != (tc.wantError == "") {
				t.Fatalf("unsafe or missing retained lineage: hasExecution=%v", hasExecution)
			}
		})
	}
}

func TestSupportedLocalProofSequentialAllocationFailureFinalizer(t *testing.T) {
	const firstRun = "run-0123456789abcdef"
	const secondRun = "run-fedcba9876543210"
	const firstAllocation = "01234567-89ab-cdef-0123-456789abcdef"
	const secondAllocation = "fedcba98-7654-3210-fedc-ba9876543210"
	guest := t.TempDir()
	host := filepath.Join(t.TempDir(), "host-proof")
	fakeCommands := t.TempDir()
	resultMarker := filepath.Join(t.TempDir(), "result-validation-reached")
	writeProofEvidenceFile(t, guest, "env.sh", nil)
	writeProofEvidenceFile(t, guest, "es.json", []byte(`{"execution":{"staging_root_dir":"`+guest+`/staging"}}`))
	prepareProofStagingObservationRoot(t, guest)
	writeProofEvidenceFile(t, guest, "workdirs/first/summary.json", proofExecutionLoopSummary(t, filepath.Join(guest, "workdirs", "first"), firstRun, nil))
	writeProofEvidenceFile(t, guest, "workdirs/first/status.json", []byte(`{"state":"complete","terminal":true,"exit_code":0}`))
	writeProofEvidenceFile(t, guest, "workdirs/first/logs.txt", []byte("SECRET-READ-SUCCESS:"+proofSecretCanary+"\n"))
	resultBundle := proofResultFixture(t, "")
	writeProofEvidenceFile(t, guest, "workdirs/second/summary.json", proofExecutionLoopSummary(t, filepath.Join(guest, "workdirs", "second"), secondRun, resultBundle))
	writeProofEvidenceFile(t, guest, "workdirs/second/status.json", []byte(`{"state":"complete","terminal":true,"exit_code":0}`))
	writeProofEvidenceFile(t, guest, "workdirs/second/logs.txt", []byte("CP-NORMAL-SHELL-RUNTIME-CONTRACT-PROVED\n"+proofAPIKeyCanary+"\n"))
	writeProofEvidenceFile(t, guest, "workdirs/second/result.tar.gz", resultBundle)
	if err := os.Chtimes(filepath.Join(guest, "workdirs", "second"), time.Unix(0, 0), time.Unix(0, 0)); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(filepath.Join(guest, "workdirs", "first"), time.Unix(1, 0), time.Unix(1, 0)); err != nil {
		t.Fatal(err)
	}
	nomad := `#!/usr/bin/env bash
set -euo pipefail
if [[ "$1" == job && "$2" == status ]]; then
  printf 'job-status:%s\n' "$3" >> "$FAKE_NOMAD_LOG"
  exit 0
fi
if [[ "$1" == job && "$2" == allocs && "$3" == -json ]]; then
  printf 'job-allocs:%s\n' "$4" >> "$FAKE_NOMAD_LOG"
  case "$4" in
    exec-run-0123456789abcdef) printf '[{"ID":"01234567-89ab-cdef-0123-456789abcdef"}]\n' ;;
    exec-run-fedcba9876543210) printf '[{"ID":"01234567-89ab-cdef-0123-456789abcdef"},{"ID":"fedcba98-7654-3210-fedc-ba9876543210"}]\n' ;;
    *) exit 91 ;;
  esac
  exit 0
fi
if [[ "$1" == alloc && "$2" == status ]]; then
  printf 'alloc-status:%s\n' "$3" >> "$FAKE_NOMAD_LOG"
  [[ "$3" == 01234567-89ab-cdef-0123-456789abcdef ]]
  exit
fi
exit 92
`
	if err := os.WriteFile(filepath.Join(fakeCommands, "nomad"), []byte(nomad), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFakeProofLimactl(t, fakeCommands)
	nomadLog := filepath.Join(fakeCommands, "nomad.log")
	limactlLog := filepath.Join(fakeCommands, "limactl.log")
	shell := `source "$PROOF_SCRIPT"
run_guest_stdin() { bash -seuo pipefail; }
create_private_host_proof_dir
GUEST_COLLECTION_READY=true
trap finalize EXIT
run_phase runtime-identity-capture capture_execution_evidence runtime-identity-vault
touch "$GUEST_PROOF_DIR/workdirs/second"
run_phase normal-shell-capture capture_execution_evidence control-plane-normal-shell
printf 'unexpected\n' > "$RESULT_VALIDATION_MARKER"
run_phase result-validation validate_control_plane_normal_shell_result_bundle`
	command := exec.Command("bash", "-c", shell)
	command.Dir = executionPlatformRepoRoot(t)
	command.Env = append(os.Environ(),
		"PROOF_SCRIPT="+filepath.Join(executionPlatformRepoRoot(t), "scripts", "73_supported_local_proof.sh"),
		"GUEST_REPO_ROOT="+executionPlatformRepoRoot(t), "GUEST_PROOF_DIR="+guest,
		"GUEST_BOOTSTRAP_DIR="+filepath.Join(t.TempDir(), "guest-bootstrap"),
		"SUPPORTED_LOCAL_PROOF_ID=review12-test-"+strconv.FormatInt(time.Now().UnixNano(), 10),
		"SUPPORTED_LOCAL_HOST_PROOF_DIR="+host, "SUPPORTED_LOCAL_INSTANCE=fake-proof-guest",
		"SUPPORTED_LOCAL_GUEST_PROOF_DIR="+guest, "FAKE_GUEST_PROOF_DIR="+guest,
		"FAKE_NOMAD_LOG="+nomadLog, "FAKE_LIMACTL_LOG="+limactlLog,
		"RESULT_VALIDATION_MARKER="+resultMarker,
		"PATH="+fakeCommands+string(os.PathListSeparator)+os.Getenv("PATH"))
	output, err := command.CombinedOutput()
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() != 1 {
		t.Fatalf("ambiguous second capture did not fail: err=%v output=%q", err, output)
	}
	if _, statErr := os.Lstat(resultMarker); !os.IsNotExist(statErr) {
		t.Fatalf("result validation was reached after ambiguity: %v", statErr)
	}
	if _, statErr := os.Lstat(filepath.Join(guest, "control-plane-normal-shell-nomad-execution-safe.json")); !os.IsNotExist(statErr) {
		t.Fatalf("ambiguous capture wrote lineage: %v", statErr)
	}
	calls, err := os.ReadFile(nomadLog)
	if err != nil {
		t.Fatal(err)
	}
	wantCalls := "job-status:exec-" + firstRun + "\njob-allocs:exec-" + firstRun + "\nalloc-status:" + firstAllocation +
		"\njob-status:exec-" + secondRun + "\njob-allocs:exec-" + secondRun + "\n"
	if string(calls) != wantCalls {
		t.Fatalf("ambiguous capture observed an allocation: %q", calls)
	}
	firstBytes, err := os.ReadFile(filepath.Join(guest, "runtime-identity-vault-nomad-execution-safe.json"))
	if err != nil {
		t.Fatal(err)
	}
	var first map[string]any
	if err := json.Unmarshal(firstBytes, &first); err != nil || first["run_id"] != firstRun ||
		first["job_id"] != "exec-"+firstRun || first["allocation_id"] != firstAllocation {
		t.Fatalf("first labeled lineage changed: %v err=%v", first, err)
	}
	closeoutBytes, err := os.ReadFile(filepath.Join(host, "proof-closeout.json"))
	if err != nil {
		t.Fatal(err)
	}
	var closeout map[string]any
	if err := json.Unmarshal(closeoutBytes, &closeout); err != nil || closeout["primary_exit_code"] != float64(1) ||
		closeout["failure_collection_succeeded"] != true {
		t.Fatalf("failure closeout did not preserve primary status: %v err=%v", closeout, err)
	}
	for _, name := range []string{
		"runtime-identity-vault-nomad-execution-safe.json",
		"control-plane-normal-shell-summary.json", "control-plane-normal-shell-status-safe.json",
		"control-plane-normal-shell-log-assertions.json", "safe-evidence-manifest.json",
	} {
		if _, err := os.ReadFile(filepath.Join(host, "guest-evidence", "failure", name)); err != nil {
			t.Fatalf("honest partial failure evidence missing %s: %v", name, err)
		}
	}
	for _, name := range []string{
		"guest-evidence/final", "guest-evidence/failure/control-plane-normal-shell-nomad-execution-safe.json",
		"guest-evidence/failure/control-plane-normal-shell-result-evidence.json", "phase-result-validation.json",
	} {
		if _, err := os.Lstat(filepath.Join(host, name)); !os.IsNotExist(err) {
			t.Fatalf("failed proof published success evidence %s: %v", name, err)
		}
	}
	phaseBytes, err := os.ReadFile(filepath.Join(host, "phase-normal-shell-capture.json"))
	if err != nil {
		t.Fatal(err)
	}
	var phase map[string]any
	if err := json.Unmarshal(phaseBytes, &phase); err != nil || phase["success"] != false {
		t.Fatalf("ambiguous capture phase was not recorded as failed: %v err=%v", phase, err)
	}
	if err := filepath.WalkDir(host, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil || entry.IsDir() {
			return walkErr
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if bytes.Contains(data, []byte(proofSecretCanary)) || bytes.Contains(data, []byte(proofAPIKeyCanary)) {
			t.Fatalf("secret canary entered failure evidence: %s", path)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(output), proofSecretCanary) || strings.Contains(string(output), proofAPIKeyCanary) ||
		strings.Contains(string(output), secondAllocation) {
		t.Fatalf("failure diagnostic leaked raw allocation or secret: %q", output)
	}
}

func writeFakeProofLimactl(t *testing.T, dir string) string {
	t.Helper()
	path := filepath.Join(dir, "limactl")
	script := `#!/usr/bin/env bash
set -euo pipefail
[[ "$#" -ge 4 && "$1" == shell && "$2" == fake-proof-guest && "$3" == -- ]] || exit 91
shift 3
if [[ "$#" -eq 5 && "$1" == bash && "$2" == -s && "$3" == -- && "$4" == collect-safe && "$5" == "$FAKE_GUEST_PROOF_DIR" ]]; then
  printf 'collect-safe\n' >> "$FAKE_LIMACTL_LOG"
  exec bash -s -- collect-safe "$5"
fi
if [[ "$1" == env ]]; then
  printf 'cleanup\n' >> "$FAKE_LIMACTL_LOG"
  cat >/dev/null
  exit 0
fi
printf 'unexpected-transport\n' >> "$FAKE_LIMACTL_LOG"
exit 92
`
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

func runProofWrapperFunctions(t *testing.T, guest, host, shell string) (string, error, string) {
	t.Helper()
	fakeDir := t.TempDir()
	writeFakeProofLimactl(t, fakeDir)
	logPath := filepath.Join(fakeDir, "limactl.log")
	command := exec.Command("bash", "-c", shell)
	command.Dir = executionPlatformRepoRoot(t)
	command.Env = append(os.Environ(),
		"PROOF_SCRIPT="+filepath.Join(executionPlatformRepoRoot(t), "scripts", "73_supported_local_proof.sh"),
		"SUPPORTED_LOCAL_INSTANCE=fake-proof-guest",
		"SUPPORTED_LOCAL_GUEST_PROOF_DIR="+guest,
		"SUPPORTED_LOCAL_HOST_PROOF_DIR="+host,
		"FAKE_GUEST_PROOF_DIR="+guest,
		"FAKE_LIMACTL_LOG="+logPath,
		"PATH="+fakeDir+string(os.PathListSeparator)+os.Getenv("PATH"),
	)
	output, err := command.CombinedOutput()
	log, readErr := os.ReadFile(logPath)
	if readErr != nil && !os.IsNotExist(readErr) {
		t.Fatal(readErr)
	}
	return string(output), err, string(log)
}

func TestSupportedLocalProofWrapperSafeCollection(t *testing.T) {
	guest := t.TempDir()
	host := filepath.Join(t.TempDir(), "host-proof")
	writeProofEvidenceFile(t, guest, "guest-repo-snapshot.sha256", []byte(strings.Repeat("b", 64)+"\n"))
	writeProofEvidenceFile(t, guest, "managed-secrets.conf", []byte(proofRootTokenCanary+proofSecretCanary+proofAPIKeyCanary))
	writeProofEvidenceFile(t, guest, "runtime-identity-vault-logs.txt", []byte(proofSecretCanary))
	output, err, log := runProofWrapperFunctions(t, guest, host, `source "$PROOF_SCRIPT"; create_private_host_proof_dir; collect_guest_workspace setup`)
	if err != nil {
		t.Fatalf("wrapper safe collection: %v output=%s log=%s", err, output, log)
	}
	info, err := os.Lstat(host)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0o700 {
		t.Fatalf("host proof directory not real private 0700: info=%v err=%v", info, err)
	}
	for _, name := range []string{"guest-repo-snapshot.sha256", "safe-evidence-manifest.json"} {
		path := filepath.Join(host, "guest-evidence", "setup", name)
		fileInfo, err := os.Lstat(path)
		if err != nil || !fileInfo.Mode().IsRegular() || fileInfo.Mode().Perm() != 0o600 {
			t.Fatalf("collected file not private regular: %s info=%v err=%v", name, fileInfo, err)
		}
	}
	for _, name := range []string{"managed-secrets.conf", "runtime-identity-vault-logs.txt"} {
		if _, err := os.Lstat(filepath.Join(host, name)); !os.IsNotExist(err) {
			t.Fatalf("sensitive host artifact exists: %s err=%v", name, err)
		}
	}
	if log != "collect-safe\n" || strings.Contains(log, "tar -C") || strings.Contains(output, proofSecretCanary) {
		t.Fatalf("wrapper did not use bounded collector: log=%q output=%q", log, output)
	}

	t.Run("preexisting symlink refused", func(t *testing.T) {
		outside := t.TempDir()
		link := filepath.Join(t.TempDir(), "host-proof")
		if err := os.Symlink(outside, link); err != nil {
			t.Fatal(err)
		}
		_, err, _ := runProofWrapperFunctions(t, guest, link, `source "$PROOF_SCRIPT"; create_private_host_proof_dir`)
		if err == nil {
			t.Fatal("preexisting host proof symlink was accepted")
		}
		entries, err := os.ReadDir(outside)
		if err != nil || len(entries) != 0 {
			t.Fatalf("outside path changed: entries=%v err=%v", entries, err)
		}
	})
}

func TestSupportedLocalProofFailureFinalizerPreservesStatus(t *testing.T) {
	for _, tc := range []struct {
		name           string
		unsafeSelected bool
	}{
		{name: "partial safe evidence"},
		{name: "selected symlink collection failure", unsafeSelected: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			guest := t.TempDir()
			host := filepath.Join(t.TempDir(), "host-proof")
			writeProofEvidenceFile(t, guest, "guest-repo-snapshot.sha256", []byte(strings.Repeat("c", 64)+"\n"))
			writeProofEvidenceFile(t, guest, "managed-secrets.conf", []byte(proofRootTokenCanary+proofSecretCanary+proofAPIKeyCanary))
			writeProofEvidenceFile(t, guest, "logs.txt", []byte("SECRET-READ-SUCCESS:"+proofSecretCanary))
			if tc.unsafeSelected {
				target := filepath.Join(t.TempDir(), "outside")
				writeProofEvidenceFile(t, filepath.Dir(target), filepath.Base(target), []byte(proofAPIKeyCanary))
				if err := os.Symlink(target, filepath.Join(guest, "status-safe.json")); err != nil {
					t.Fatal(err)
				}
			}
			output, err, log := runProofWrapperFunctions(t, guest, host, `source "$PROOF_SCRIPT"; create_private_host_proof_dir; GUEST_COLLECTION_READY=true; trap finalize EXIT; exit 37`)
			var exitErr *exec.ExitError
			if !errors.As(err, &exitErr) || exitErr.ExitCode() != 37 {
				t.Fatalf("primary proof status changed: err=%v output=%q log=%q", err, output, log)
			}
			if !strings.Contains(log, "collect-safe\n") || strings.Contains(log, "tar -C") {
				t.Fatalf("finalizer missed bounded collector: log=%q", log)
			}
			if strings.Contains(output, proofRootTokenCanary) || strings.Contains(output, proofSecretCanary) || strings.Contains(output, proofAPIKeyCanary) {
				t.Fatal("secret canary appeared in finalizer diagnostic")
			}
			if _, err := os.Lstat(filepath.Join(host, "managed-secrets.conf")); !os.IsNotExist(err) {
				t.Fatalf("sensitive host file exists: %v", err)
			}
			if !tc.unsafeSelected {
				if _, err := os.Lstat(filepath.Join(host, "guest-evidence", "failure", "guest-repo-snapshot.sha256")); err != nil {
					t.Fatalf("safe partial evidence missing: %v", err)
				}
			} else if !strings.Contains(output, "supported-local safe evidence collection failed") {
				t.Fatalf("collection failure not reported safely: %q", output)
			}
		})
	}
}
