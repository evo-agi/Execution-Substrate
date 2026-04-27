package executionsubstrate_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const remoteAlphaESWritableStateOwnershipStageDefaultSummaryPath = "/var/tmp/execution-substrate-remote-alpha/es-writable-state-ownership-summary.json"
const remoteAlphaESWritableStateOwnershipStageDefaultStagingRoot = "/var/tmp/execution-substrate-remote-alpha/helper-staging"
const remoteAlphaESWritableStateOwnershipStageCheckOnlyArtifactName = "es-writable-state-ownership-check-only.json"
const remoteAlphaESWritableStateOwnershipStageApplySummaryArtifactName = "es-writable-state-ownership-apply-summary.json"
const remoteAlphaESWritableStateOwnershipStageHelperStagingRecordName = "es-writable-state-ownership-helper-staging-record.json"

func runSourcedESWritableStateOwnershipHelper(t *testing.T, env []string, shellBody string) ([]byte, error) {
	t.Helper()
	helperPath := filepath.Join(executionSubstrateRepoRoot, "scripts", "internal", "remote_alpha_prepare_es_writable_state_ownership.sh")
	script := fmt.Sprintf("set -euo pipefail\nsource %q\n%s\n", helperPath, shellBody)
	cmd := exec.Command("/bin/bash", "-c", script)
	cmd.Dir = executionSubstrateRepoRoot
	cmd.Env = env
	return cmd.CombinedOutput()
}

func esWritableStateOwnershipExpectedSliceShell(f esServiceUserMigrationFixture) string {
	return fmt.Sprintf(`
remote_alpha_prepare_es_writable_state_ownership_expected_config_path=%q
remote_alpha_prepare_es_writable_state_ownership_expected_healthcheck_env_path=%q
remote_alpha_prepare_es_writable_state_ownership_expected_service_unit_path=%q
`, f.ConfigPath, f.HealthEnvPath, f.ServiceUnitPath)
}

func parseWritableStateOwnershipOutput(t *testing.T, output []byte) map[string]any {
	t.Helper()
	var payload map[string]any
	if err := json.Unmarshal(output, &payload); err != nil {
		t.Fatalf("decode writable-state ownership helper output: %v\noutput=%s", err, string(output))
	}
	return payload
}

func writeLegacyESWritableStateRun(t *testing.T, fixture esServiceUserMigrationFixture, runID string) {
	t.Helper()

	for _, dir := range []string{
		filepath.Join(fixture.StagingRoot, runID, "run", "platform"),
		filepath.Join(fixture.StagingRoot, runID, "run", "work"),
		filepath.Join(fixture.StagingRoot, runID, "run", "result"),
	} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatalf("mkdir %s: %v", dir, err)
		}
	}
}

func findObservedWritableStateRun(t *testing.T, payload map[string]any, runID string) map[string]any {
	t.Helper()

	validation := nestedMap(t, payload, "validation")
	activeRun := nestedMap(t, validation, "active_run_or_drain")
	observed, ok := activeRun["observed_runs"].([]any)
	if !ok {
		t.Fatalf("expected observed_runs array, got %+v", activeRun["observed_runs"])
	}
	for _, raw := range observed {
		item := jsonMap(t, raw)
		if fmt.Sprint(item["run_id"]) == runID {
			return item
		}
	}
	t.Fatalf("missing observed run %q in %+v", runID, observed)
	return nil
}

func preserveNormalizationEvidenceForRun(t *testing.T, fixture esServiceUserMigrationFixture, runID string) {
	t.Helper()

	stageMarkerPath := filepath.Join(fixture.StagingRoot, runID, "run", "platform", "ownership-normalization.json")
	payload := []byte(mustRead(t, stageMarkerPath))
	resultsRunDir := filepath.Join(fixture.ResultsRoot, runID)
	if err := os.MkdirAll(resultsRunDir, 0o700); err != nil {
		t.Fatalf("mkdir results run dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(resultsRunDir, "ownership-normalization.json"), payload, 0o600); err != nil {
		t.Fatalf("write preserved normalization evidence: %v", err)
	}
}

func findArtifactReconciliationRetainedCandidate(t *testing.T, payload map[string]any, runID string) map[string]any {
	t.Helper()

	artifact := nestedMap(t, nestedMap(t, payload, "validation"), "artifact_reconciliation")
	retained := nestedMap(t, artifact, "retained_results")
	candidates, ok := retained["retained_run_candidates"].([]any)
	if !ok {
		t.Fatalf("expected retained_run_candidates array, got %+v", retained["retained_run_candidates"])
	}
	for _, raw := range candidates {
		item := jsonMap(t, raw)
		if fmt.Sprint(item["run_id"]) == runID {
			return item
		}
	}
	t.Fatalf("missing retained artifact candidate %q in %+v", runID, candidates)
	return nil
}

func findArtifactReconciliationStageCandidate(t *testing.T, payload map[string]any, runID string) map[string]any {
	t.Helper()

	artifact := nestedMap(t, nestedMap(t, payload, "validation"), "artifact_reconciliation")
	stage := nestedMap(t, artifact, "stage_roots")
	candidates, ok := stage["stage_root_candidates"].([]any)
	if !ok {
		t.Fatalf("expected stage_root_candidates array, got %+v", stage["stage_root_candidates"])
	}
	for _, raw := range candidates {
		item := jsonMap(t, raw)
		if fmt.Sprint(item["run_id"]) == runID {
			return item
		}
	}
	t.Fatalf("missing stage artifact candidate %q in %+v", runID, candidates)
	return nil
}

func goodESWritableStateOwnershipStageCheckOnlyReport() map[string]any {
	return map[string]any{
		"schema_version": "execution-substrate.remote-alpha.es-writable-state-ownership-summary.v1",
		"mode": map[string]any{
			"name":         "check_only",
			"non_mutating": true,
		},
		"proof": map[string]any{
			"host_mutation_performed": false,
		},
		"plan": map[string]any{
			"apply_ready":                true,
			"roots_nonempty_block_apply": false,
		},
		"warnings":               []any{},
		"blockers":               []any{},
		"overall_classification": "pass",
	}
}

func writeESWritableStateOwnershipStageCheckOnlyReport(t *testing.T, path string, payload map[string]any) {
	t.Helper()
	writeJSONFile(t, path, payload)
}

func writeESWritableStateOwnershipStageApplySummary(t *testing.T, path string) {
	t.Helper()
	writeJSONFile(t, path, map[string]any{
		"schema_version": "execution-substrate.remote-alpha.es-writable-state-ownership-summary.v1",
		"result": map[string]any{
			"ok": true,
		},
	})
}

func setupFakeRemoteESWritableStateOwnershipStageHarness(t *testing.T, checkOnlyReportPath, applySummaryPath string) *fakeRemoteStageHarness {
	t.Helper()

	tmpDir := t.TempDir()
	localBin := filepath.Join(tmpDir, "local-bin")
	remoteBin := filepath.Join(tmpDir, "remote-bin")
	remoteRoot := filepath.Join(tmpDir, "remote-root")
	if err := os.MkdirAll(localBin, 0o755); err != nil {
		t.Fatalf("mkdir local bin: %v", err)
	}
	if err := os.MkdirAll(remoteBin, 0o755); err != nil {
		t.Fatalf("mkdir remote bin: %v", err)
	}
	if err := os.MkdirAll(remoteRoot, 0o755); err != nil {
		t.Fatalf("mkdir remote root: %v", err)
	}

	h := &fakeRemoteStageHarness{
		localBin:       localBin,
		remoteBin:      remoteBin,
		remoteRoot:     remoteRoot,
		sshLogPath:     filepath.Join(tmpDir, "ssh.log"),
		scpLogPath:     filepath.Join(tmpDir, "scp.log"),
		uploadLogPath:  filepath.Join(tmpDir, "uploaded-paths.log"),
		sudoLogPath:    filepath.Join(tmpDir, "sudo.log"),
		installLogPath: filepath.Join(tmpDir, "install.log"),
		helperLogPath:  filepath.Join(tmpDir, "helper.log"),
		metadataPath:   filepath.Join(tmpDir, "remote-metadata.json"),
	}

	writeExecutable(t, localBin, "ssh", fmt.Sprintf(`#!/usr/bin/env bash
set -euo pipefail
target="$1"
shift
printf 'target=%%s args=%%s\n' "$target" "$*" >> %q
export PATH="${FAKE_REMOTE_BIN}:${PATH}"
if [[ "${1:-}" != "/bin/bash" || "${2:-}" != "-s" ]]; then
  echo "unexpected ssh invocation: $*" >&2
  exit 64
fi
shift 2
if [[ "${1:-}" == "--" ]]; then
  shift
fi
mapped_args=()
for arg in "$@"; do
  if [[ "$arg" == /* ]]; then
    mapped_args+=("${FAKE_REMOTE_ROOT}${arg}")
  else
    mapped_args+=("$arg")
  fi
done
script_path="$(mktemp)"
cat >"${script_path}"
stdout_path="$(mktemp)"
stderr_path="$(mktemp)"
if ((${#mapped_args[@]} > 0)); then
  /bin/bash "${script_path}" "${mapped_args[@]}" >"${stdout_path}" 2>"${stderr_path}"
else
  /bin/bash "${script_path}" >"${stdout_path}" 2>"${stderr_path}"
fi
status=$?
sed "s#${FAKE_REMOTE_ROOT}##g" "${stdout_path}"
sed "s#${FAKE_REMOTE_ROOT}##g" "${stderr_path}" >&2
rm -f "${script_path}" "${stdout_path}" "${stderr_path}"
exit "${status}"
`, h.sshLogPath))

	writeExecutable(t, localBin, "scp", fmt.Sprintf(`#!/usr/bin/env bash
set -euo pipefail
recursive=false
args=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    -r)
      recursive=true
      shift
      ;;
    *)
      args+=("$1")
      shift
      ;;
  esac
done
if [[ "${#args[@]}" -ne 2 ]]; then
  echo "unexpected scp args: ${args[*]}" >&2
  exit 64
fi
src="${args[0]}"
dest="${args[1]}"
printf '%%s\t%%s\n' "$src" "$dest" >> %q
if [[ "$src" == *:* && "$dest" != *:* ]]; then
  remote_path="${src#*:}"
  mapped_src="${FAKE_REMOTE_ROOT}${remote_path}"
  mkdir -p "$(dirname "$dest")"
  cp "$mapped_src" "$dest"
  exit 0
fi
if [[ "$src" != *:* && "$dest" == *:* ]]; then
  remote_path="${dest#*:}"
  mapped_dest="${FAKE_REMOTE_ROOT}${remote_path}"
  if [[ "$recursive" == "true" ]]; then
    src_trimmed="${src%%/}"
    base="$(basename "$src_trimmed")"
    mkdir -p "$mapped_dest"
    target="${mapped_dest}/${base}"
    cp -R "$src_trimmed" "$target"
    while IFS= read -r uploaded; do
      printf '%%s\n' "${uploaded#"${FAKE_REMOTE_ROOT}"}" >> %q
    done < <(find "$target" -type f | sort)
    exit 0
  fi
  mkdir -p "$(dirname "$mapped_dest")"
  cp "$src" "$mapped_dest"
  printf '%%s\n' "${remote_path}" >> %q
  exit 0
fi
echo "unsupported scp direction: $src -> $dest" >&2
exit 64
`, h.scpLogPath, h.uploadLogPath, h.uploadLogPath))

	writeExecutable(t, remoteBin, "install", fmt.Sprintf(`#!/usr/bin/env bash
set -euo pipefail
directory=false
mode="0755"
owner="root"
group="root"
args=()

set_meta() {
  python3 - %q "$1" "$2" "$3" "$4" <<'PY'
import json
import pathlib
import sys

meta_path = pathlib.Path(sys.argv[1])
target = sys.argv[2]
owner = sys.argv[3]
group = sys.argv[4]
mode = sys.argv[5]
payload = {}
if meta_path.exists():
    payload = json.loads(meta_path.read_text(encoding="utf-8"))
payload[target] = {
    "owner": owner,
    "group": group,
    "mode": mode,
}
meta_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
}

unmap_path() {
  local path=$1
  printf '%%s' "${path#"${FAKE_REMOTE_ROOT}"}"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -d)
      directory=true
      shift
      ;;
    -m)
      mode="$2"
      shift 2
      ;;
    -o)
      owner="$2"
      shift 2
      ;;
    -g)
      group="$2"
      shift 2
      ;;
    *)
      args+=("$1")
      shift
      ;;
  esac
done

if [[ "$directory" == "true" ]]; then
  for dest in "${args[@]}"; do
    mkdir -p "$dest"
    chmod "$mode" "$dest"
    printf 'dir\t%%s\t%%s:%%s\t%%s\n' "$(unmap_path "$dest")" "$owner" "$group" "$mode" >> %q
    set_meta "$dest" "$owner" "$group" "$mode"
  done
  exit 0
fi

if [[ "${#args[@]}" -ne 2 ]]; then
  echo "unexpected install args: ${args[*]}" >&2
  exit 64
fi
src="${args[0]}"
dest="${args[1]}"
unmapped_src="$(unmap_path "$src")"
if [[ -n "${FAKE_REMOTE_INSTALL_FAIL_ON:-}" && "$unmapped_src" == *"${FAKE_REMOTE_INSTALL_FAIL_ON}" ]]; then
  echo "simulated install failure for ${unmapped_src}" >&2
  exit 88
fi
mkdir -p "$(dirname "$dest")"
cp "$src" "$dest"
chmod "$mode" "$dest"
printf 'file\t%%s\t%%s\t%%s:%%s\t%%s\n' "$unmapped_src" "$(unmap_path "$dest")" "$owner" "$group" "$mode" >> %q
set_meta "$dest" "$owner" "$group" "$mode"
`, h.metadataPath, h.installLogPath, h.installLogPath))

	writeExecutable(t, remoteBin, "stat", fmt.Sprintf(`#!/usr/bin/env bash
set -euo pipefail
if [[ "${1:-}" != "-c" ]]; then
  echo "unexpected stat args: $*" >&2
  exit 64
fi
format="$2"
shift 2
python3 - "$format" %q "$@" <<'PY'
import json
import os
import pathlib
import sys

format_text = bytes(sys.argv[1], "utf-8").decode("unicode_escape")
meta_path = pathlib.Path(sys.argv[2])
payload = {}
if meta_path.exists():
    payload = json.loads(meta_path.read_text(encoding="utf-8"))

for raw_path in sys.argv[3:]:
    item = payload.get(raw_path)
    if item is None:
        raise SystemExit(f"missing fake stat metadata for {raw_path}")
    display_path = raw_path
    fake_root = os.environ.get("FAKE_REMOTE_ROOT", "")
    if fake_root and display_path.startswith(fake_root):
        display_path = display_path[len(fake_root):]
    line = format_text
    line = line.replace("%%U", item["owner"])
    line = line.replace("%%G", item["group"])
    line = line.replace("%%a", item["mode"])
    line = line.replace("%%n", display_path)
    print(line)
PY
`, h.metadataPath))

	writeExecutable(t, remoteBin, "sudo", fmt.Sprintf(`#!/usr/bin/env bash
set -euo pipefail
printf '%%s\n' "$*" >> %q

if [[ "${1:-}" == "-n" ]]; then
  shift
fi

if [[ "${1:-}" == "-v" ]]; then
  exit "${FAKE_REMOTE_SUDO_PREFLIGHT_EXIT:-0}"
fi

if [[ "${1:-}" == "true" ]]; then
  exit "${FAKE_REMOTE_SUDO_PREFLIGHT_EXIT:-0}"
fi

if [[ "${1:-}" == */scripts/remote_alpha_prepare_es_writable_state_ownership.sh ]]; then
  summary_path=""
  check_only=false
  args=("$@")
  for ((i=0; i<${#args[@]}; i++)); do
    case "${args[$i]}" in
      --check-only|--dry-run)
        check_only=true
        ;;
      --summary-path)
        if (( i + 1 < ${#args[@]} )); then
          summary_path="${args[$((i + 1))]}"
        fi
        ;;
    esac
  done

  if [[ "$check_only" == "true" ]]; then
    printf 'check_only\t%%s\n' "${summary_path}" >> %q
    cat %q
    exit "${FAKE_REMOTE_CHECK_ONLY_EXIT:-0}"
  fi

  printf 'apply\t%%s\n' "${summary_path}" >> %q
  if [[ -n "${summary_path}" && -f %q ]]; then
    mkdir -p "$(dirname "${summary_path}")"
    cp %q "${summary_path}"
  fi
  exit "${FAKE_REMOTE_APPLY_EXIT:-0}"
fi

exec "$@"
`, h.sudoLogPath, h.helperLogPath, checkOnlyReportPath, h.helperLogPath, applySummaryPath, applySummaryPath))

	return h
}

func runRemoteAlphaESWritableStateOwnershipStageWrapper(t *testing.T, env []string, args ...string) ([]byte, error) {
	t.Helper()
	scriptPath := filepath.Join(executionSubstrateRepoRoot, "scripts", "remote_alpha_prepare_es_writable_state_ownership.sh")
	cmd := exec.Command("/bin/bash", append([]string{scriptPath}, args...)...)
	cmd.Dir = executionSubstrateRepoRoot
	cmd.Env = env
	return cmd.CombinedOutput()
}

func TestRemoteAlphaESWritableStateOwnershipCheckOnlyIsDefaultAndNonMutating(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	fakeBin := filepath.Join(tmpDir, "bin")
	if err := os.MkdirAll(fakeBin, 0o755); err != nil {
		t.Fatalf("mkdir fake bin: %v", err)
	}

	fixture := setupESServiceUserMigrationFixture(t, tmpDir)
	if err := os.Chmod(fixture.StagingRoot, 0o700); err != nil {
		t.Fatalf("chmod staging root: %v", err)
	}
	if err := os.Chmod(fixture.ResultsRoot, 0o700); err != nil {
		t.Fatalf("chmod results root: %v", err)
	}

	mutationLogPath := filepath.Join(tmpDir, "mutations.log")
	setupFakeESServiceUserMigrationCommands(t, fakeBin, fakeESServiceUserAccount{
		Present:   true,
		UID:       os.Getuid(),
		GID:       os.Getgid(),
		GroupName: "es",
	}, fixture, mutationLogPath)

	shellBody := esWritableStateOwnershipExpectedSliceShell(fixture) + `
remote_alpha_prepare_es_writable_state_ownership_main
`
	output, err := runSourcedESWritableStateOwnershipHelper(t, envWithPath(fakeBin), shellBody)
	if err != nil {
		t.Fatalf("helper failed: %v\noutput=%s", err, string(output))
	}

	payload := parseWritableStateOwnershipOutput(t, output)
	mode := nestedMap(t, payload, "mode")
	proof := nestedMap(t, payload, "proof")
	plan := nestedMap(t, payload, "plan")
	validation := nestedMap(t, payload, "validation")
	roots := nestedMap(t, payload, "roots")

	if mode["name"] != "check_only" || mode["non_mutating"] != true {
		t.Fatalf("unexpected mode payload: %+v", mode)
	}
	if proof["host_mutation_performed"] != false {
		t.Fatalf("expected host_mutation_performed=false, got %+v", proof)
	}
	if plan["apply_ready"] != true {
		t.Fatalf("expected apply_ready=true, got %v", plan["apply_ready"])
	}
	if plan["roots_need_change"] != true {
		t.Fatalf("expected roots_need_change=true, got %v", plan["roots_need_change"])
	}
	if plan["changing_only_root_directories_would_make_es_manageable"] != true {
		t.Fatalf("expected changing_only_root_directories_would_make_es_manageable=true, got %v", plan["changing_only_root_directories_would_make_es_manageable"])
	}
	if payload["overall_classification"] != "warning" {
		t.Fatalf("expected warning classification, got %v", payload["overall_classification"])
	}
	if nestedMap(t, validation, "active_run_or_drain")["classification"] != "pass" {
		t.Fatalf("expected active_run_or_drain pass, got %+v", nestedMap(t, validation, "active_run_or_drain"))
	}
	if nestedMap(t, roots, "staging")["classification"] != "warning" {
		t.Fatalf("expected staging warning, got %+v", nestedMap(t, roots, "staging"))
	}
	if nestedMap(t, roots, "results")["classification"] != "warning" {
		t.Fatalf("expected results warning, got %+v", nestedMap(t, roots, "results"))
	}
	if got := nestedMap(t, payload, "not_claimed")["service_user_change"]; got != true {
		t.Fatalf("expected not_claimed.service_user_change=true, got %v", got)
	}

	if info, err := os.Stat(fixture.StagingRoot); err != nil {
		t.Fatalf("stat staging root: %v", err)
	} else if info.Mode().Perm() != 0o700 {
		t.Fatalf("expected staging root mode to remain 0700, got %o", info.Mode().Perm())
	}
	if info, err := os.Stat(fixture.ResultsRoot); err != nil {
		t.Fatalf("stat results root: %v", err)
	} else if info.Mode().Perm() != 0o700 {
		t.Fatalf("expected results root mode to remain 0700, got %o", info.Mode().Perm())
	}
	if _, err := os.Stat(mutationLogPath); !os.IsNotExist(err) {
		t.Fatalf("mutation log should not exist in check-only mode")
	}
}

func TestRemoteAlphaESWritableStateOwnershipBlocksWhenServiceAccountMissing(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	fakeBin := filepath.Join(tmpDir, "bin")
	if err := os.MkdirAll(fakeBin, 0o755); err != nil {
		t.Fatalf("mkdir fake bin: %v", err)
	}

	fixture := setupESServiceUserMigrationFixture(t, tmpDir)
	setupFakeESServiceUserMigrationCommands(t, fakeBin, fakeESServiceUserAccount{
		Present: false,
	}, fixture, filepath.Join(tmpDir, "mutations.log"))

	shellBody := esWritableStateOwnershipExpectedSliceShell(fixture) + `
remote_alpha_prepare_es_writable_state_ownership_main
`
	output, err := runSourcedESWritableStateOwnershipHelper(t, envWithPath(fakeBin), shellBody)
	if err == nil {
		t.Fatalf("expected blocker when es:es account is missing\noutput=%s", string(output))
	}

	payload := parseWritableStateOwnershipOutput(t, output)
	if payload["overall_classification"] != "blocker" {
		t.Fatalf("expected blocker classification, got %v", payload["overall_classification"])
	}
	status := nestedMap(t, nestedMap(t, payload, "validation"), "service_account_narrowness")
	if status["classification"] != "blocker" {
		t.Fatalf("expected service account blocker, got %+v", status)
	}
	if nestedMap(t, payload, "plan")["apply_ready"] != false {
		t.Fatalf("expected apply_ready=false, got %v", nestedMap(t, payload, "plan")["apply_ready"])
	}
}

func TestRemoteAlphaESWritableStateOwnershipBlocksWhenRootsContainEntries(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	fakeBin := filepath.Join(tmpDir, "bin")
	if err := os.MkdirAll(fakeBin, 0o755); err != nil {
		t.Fatalf("mkdir fake bin: %v", err)
	}

	fixture := setupESServiceUserMigrationFixture(t, tmpDir)
	if err := os.Mkdir(filepath.Join(fixture.StagingRoot, "run-0001"), 0o700); err != nil {
		t.Fatalf("mkdir retained staging child: %v", err)
	}
	if err := os.Mkdir(filepath.Join(fixture.ResultsRoot, "run-0001"), 0o700); err != nil {
		t.Fatalf("mkdir retained results child: %v", err)
	}

	setupFakeESServiceUserMigrationCommands(t, fakeBin, fakeESServiceUserAccount{
		Present:   true,
		UID:       os.Getuid(),
		GID:       os.Getgid(),
		GroupName: "es",
	}, fixture, filepath.Join(tmpDir, "mutations.log"))

	shellBody := esWritableStateOwnershipExpectedSliceShell(fixture) + `
remote_alpha_prepare_es_writable_state_ownership_main
`
	output, err := runSourcedESWritableStateOwnershipHelper(t, envWithPath(fakeBin), shellBody)
	if err == nil {
		t.Fatalf("expected blocker for non-empty roots\noutput=%s", string(output))
	}

	payload := parseWritableStateOwnershipOutput(t, output)
	if payload["overall_classification"] != "blocker" {
		t.Fatalf("expected blocker classification, got %v", payload["overall_classification"])
	}
	plan := nestedMap(t, payload, "plan")
	if plan["roots_nonempty_block_apply"] != true {
		t.Fatalf("expected roots_nonempty_block_apply=true, got %v", plan["roots_nonempty_block_apply"])
	}
	staging := nestedMap(t, nestedMap(t, payload, "roots"), "staging")
	if staging["classification"] != "blocker" {
		t.Fatalf("expected staging blocker, got %+v", staging)
	}
}

func TestRemoteAlphaESWritableStateOwnershipBlocksWhenChangingOnlyRootsIsInsufficient(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	fakeBin := filepath.Join(tmpDir, "bin")
	if err := os.MkdirAll(fakeBin, 0o755); err != nil {
		t.Fatalf("mkdir fake bin: %v", err)
	}

	fixture := setupESServiceUserMigrationFixture(t, tmpDir)
	stateBase := filepath.Dir(fixture.StagingRoot)
	if err := os.Chmod(stateBase, 0o700); err != nil {
		t.Fatalf("chmod state base: %v", err)
	}

	setupFakeESServiceUserMigrationCommands(t, fakeBin, fakeESServiceUserAccount{
		Present:   true,
		UID:       42424,
		GID:       42424,
		GroupName: "es",
	}, fixture, filepath.Join(tmpDir, "mutations.log"))

	shellBody := esWritableStateOwnershipExpectedSliceShell(fixture) + `
remote_alpha_prepare_es_writable_state_ownership_main
`
	output, err := runSourcedESWritableStateOwnershipHelper(t, envWithPath(fakeBin), shellBody)
	if err == nil {
		t.Fatalf("expected blocker when parent traversal remains blocked\noutput=%s", string(output))
	}

	payload := parseWritableStateOwnershipOutput(t, output)
	if payload["overall_classification"] != "blocker" {
		t.Fatalf("expected blocker classification, got %v", payload["overall_classification"])
	}
	plan := nestedMap(t, payload, "plan")
	if plan["changing_only_root_directories_would_make_es_manageable"] != false {
		t.Fatalf("expected changing_only_root_directories_would_make_es_manageable=false, got %v", plan["changing_only_root_directories_would_make_es_manageable"])
	}
	staging := nestedMap(t, nestedMap(t, payload, "roots"), "staging")
	if staging["classification"] != "blocker" {
		t.Fatalf("expected staging blocker, got %+v", staging)
	}
}

func TestRemoteAlphaESWritableStateOwnershipParentTraversalFixIsAdvertisedAndNonMutating(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	fakeBin := filepath.Join(tmpDir, "bin")
	if err := os.MkdirAll(fakeBin, 0o755); err != nil {
		t.Fatalf("mkdir fake bin: %v", err)
	}

	fixture := setupESServiceUserMigrationFixture(t, tmpDir)
	stateBase := filepath.Dir(fixture.StagingRoot)
	if err := os.Chmod(stateBase, 0o700); err != nil {
		t.Fatalf("chmod state base: %v", err)
	}
	for _, path := range []string{fixture.StagingRoot, fixture.ResultsRoot} {
		if err := os.Chmod(path, 0o750); err != nil {
			t.Fatalf("chmod %s: %v", path, err)
		}
	}

	mutationLogPath := filepath.Join(tmpDir, "mutations.log")
	setupFakeESServiceUserMigrationCommands(t, fakeBin, fakeESServiceUserAccount{
		Present:   true,
		UID:       os.Getuid(),
		GID:       os.Getgid(),
		GroupName: "es",
	}, fixture, mutationLogPath)

	shellBody := esWritableStateOwnershipExpectedSliceShell(fixture) + `
remote_alpha_prepare_es_writable_state_ownership_main
`
	output, err := runSourcedESWritableStateOwnershipHelper(t, envWithPath(fakeBin), shellBody)
	if err != nil {
		t.Fatalf("expected parent traversal check-only planning warning, got %v\noutput=%s", err, string(output))
	}

	payload := parseWritableStateOwnershipOutput(t, output)
	if payload["overall_classification"] != "warning" {
		t.Fatalf("expected warning classification, got %v", payload["overall_classification"])
	}

	validation := nestedMap(t, payload, "validation")
	parentTraversal := nestedMap(t, validation, "parent_traversal")
	if parentTraversal["classification"] != "warning" {
		t.Fatalf("expected parent traversal warning, got %+v", parentTraversal)
	}
	if parentTraversal["owner_strategy"] != "preserve_existing_owner" {
		t.Fatalf("expected preserve_existing_owner strategy, got %+v", parentTraversal)
	}

	plan := nestedMap(t, payload, "plan")
	if plan["parent_traversal_apply_ready"] != true {
		t.Fatalf("expected parent_traversal_apply_ready=true, got %+v", plan)
	}
	if plan["parent_traversal_flag"] != "--fix-parent-chain" {
		t.Fatalf("expected --fix-parent-chain advertisement, got %+v", plan)
	}
	if plan["rotation_apply_ready"] != false {
		t.Fatalf("expected rotation_apply_ready=false, got %+v", plan)
	}

	changedPaths, ok := plan["parent_traversal_changed_paths"].([]any)
	if !ok || len(changedPaths) != 1 || changedPaths[0] != stateBase {
		t.Fatalf("expected parent-only changed path %q, got %+v", stateBase, plan["parent_traversal_changed_paths"])
	}
	if nestedMap(t, validation, "active_run_or_drain")["classification"] != "pass" {
		t.Fatalf("expected active_run_or_drain pass, got %+v", nestedMap(t, validation, "active_run_or_drain"))
	}
	if nestedMap(t, nestedMap(t, payload, "roots"), "staging")["classification"] != "pass" {
		t.Fatalf("expected staging pass when only the parent traversal path needs preparation, got %+v", nestedMap(t, nestedMap(t, payload, "roots"), "staging"))
	}
	if _, err := os.Stat(mutationLogPath); !os.IsNotExist(err) {
		t.Fatalf("check-only mode should not have mutated service state: %v", err)
	}
}

func TestRemoteAlphaESWritableStateOwnershipParentTraversalFlagRequiresApply(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	fakeBin := filepath.Join(tmpDir, "bin")
	if err := os.MkdirAll(fakeBin, 0o755); err != nil {
		t.Fatalf("mkdir fake bin: %v", err)
	}

	fixture := setupESServiceUserMigrationFixture(t, tmpDir)
	setupFakeESServiceUserMigrationCommands(t, fakeBin, fakeESServiceUserAccount{
		Present:   true,
		UID:       os.Getuid(),
		GID:       os.Getgid(),
		GroupName: "es",
	}, fixture, filepath.Join(tmpDir, "mutations.log"))

	shellBody := esWritableStateOwnershipExpectedSliceShell(fixture) + `
remote_alpha_prepare_es_writable_state_ownership_main --fix-parent-chain
`
	output, err := runSourcedESWritableStateOwnershipHelper(t, envWithPath(fakeBin), shellBody)
	if err == nil {
		t.Fatalf("expected flag validation failure without --apply\noutput=%s", string(output))
	}
	if !strings.Contains(string(output), "requires --apply with --fix-parent-chain") {
		t.Fatalf("expected explicit --fix-parent-chain guidance, got %q", string(output))
	}
}

func TestRemoteAlphaESWritableStateOwnershipParentTraversalApplyChangesOnlyParentPath(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	fakeBin := filepath.Join(tmpDir, "bin")
	if err := os.MkdirAll(fakeBin, 0o755); err != nil {
		t.Fatalf("mkdir fake bin: %v", err)
	}

	fixture := setupESServiceUserMigrationFixture(t, tmpDir)
	stateBase := filepath.Dir(fixture.StagingRoot)
	if err := os.Chmod(stateBase, 0o700); err != nil {
		t.Fatalf("chmod state base: %v", err)
	}
	for _, path := range []string{fixture.StagingRoot, fixture.ResultsRoot} {
		if err := os.Chmod(path, 0o750); err != nil {
			t.Fatalf("chmod %s: %v", path, err)
		}
	}

	stagingQuarantine := filepath.Join(stateBase, "staging.pre-es-writable-state-ownership-20260427T012922Z")
	resultsQuarantine := filepath.Join(stateBase, "results.pre-es-writable-state-ownership-20260427T012922Z")
	for _, dir := range []string{filepath.Join(stagingQuarantine, "run-0001"), filepath.Join(resultsQuarantine, "run-0001")} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatalf("mkdir %s: %v", dir, err)
		}
	}
	if err := os.WriteFile(filepath.Join(stagingQuarantine, "run-0001", "staging.txt"), []byte("legacy staging\n"), 0o600); err != nil {
		t.Fatalf("write staging quarantine evidence: %v", err)
	}
	if err := os.WriteFile(filepath.Join(resultsQuarantine, "run-0001", "result.tar.gz"), []byte("legacy result\n"), 0o600); err != nil {
		t.Fatalf("write results quarantine evidence: %v", err)
	}

	originalServiceUnit := mustRead(t, fixture.ServiceUnitPath)
	mutationLogPath := filepath.Join(tmpDir, "mutations.log")
	setupFakeESServiceUserMigrationCommands(t, fakeBin, fakeESServiceUserAccount{
		Present:   true,
		UID:       os.Getuid(),
		GID:       os.Getgid(),
		GroupName: "es",
	}, fixture, mutationLogPath)

	summaryPath := filepath.Join(tmpDir, "apply-summary.json")
	shellBody := esWritableStateOwnershipExpectedSliceShell(fixture) + fmt.Sprintf(`
remote_alpha_prepare_es_writable_state_ownership_main --apply --fix-parent-chain --summary-path %q
`, summaryPath)
	output, err := runSourcedESWritableStateOwnershipHelper(t, envWithPath(fakeBin), shellBody)
	if err != nil {
		t.Fatalf("parent traversal apply failed: %v\noutput=%s\nsummary=%s", err, string(output), readIfExists(summaryPath))
	}

	summary := readJSONFile(t, summaryPath)
	if summary["overall_classification"] != "pass" {
		t.Fatalf("expected pass summary, got %+v", summary)
	}

	changedPaths, ok := summary["changed_paths"].([]any)
	if !ok || len(changedPaths) != 1 || changedPaths[0] != stateBase {
		t.Fatalf("expected only the bounded parent path to change, got %+v", summary["changed_paths"])
	}

	backup := nestedMap(t, summary, "backup")
	if fmt.Sprint(backup["path"]) == "" || fmt.Sprint(backup["snapshot_manifest_path"]) == "" {
		t.Fatalf("expected backup metadata, got %+v", backup)
	}
	if _, err := os.Stat(fmt.Sprint(backup["path"])); err != nil {
		t.Fatalf("backup path missing: %v", err)
	}
	rollbackNotes, ok := backup["rollback_notes"].([]any)
	if !ok || len(rollbackNotes) == 0 {
		t.Fatalf("expected rollback notes, got %+v", backup)
	}

	postValidation := nestedMap(t, summary, "post_apply_validation")
	if postValidation["classification"] != "pass" {
		t.Fatalf("expected post-apply validation pass, got %+v", postValidation)
	}
	if postValidation["service_stop_performed"] != false || postValidation["service_start_performed"] != false || postValidation["service_restart_performed"] != false {
		t.Fatalf("expected no service restart activity, got %+v", postValidation)
	}
	posture := nestedMap(t, postValidation, "es_service_posture")
	if posture["effective_user"] != "root(default)" || posture["effective_group"] != "root(default)" {
		t.Fatalf("expected service posture to remain root(default), got %+v", posture)
	}
	if nestedMap(t, postValidation, "parent_traversal")["classification"] != "pass" {
		t.Fatalf("expected post-apply parent traversal pass, got %+v", nestedMap(t, postValidation, "parent_traversal"))
	}
	if nestedMap(t, postValidation, "health")["classification"] != "not_observed" {
		t.Fatalf("expected health to remain not_observed for parent-only apply, got %+v", nestedMap(t, postValidation, "health"))
	}
	if nestedMap(t, postValidation, "contract")["classification"] != "not_observed" {
		t.Fatalf("expected contract to remain not_observed for parent-only apply, got %+v", nestedMap(t, postValidation, "contract"))
	}

	if info, err := os.Stat(stateBase); err != nil {
		t.Fatalf("stat state base: %v", err)
	} else if info.Mode().Perm() != 0o750 {
		t.Fatalf("expected bounded parent path mode 0750 after apply, got %o", info.Mode().Perm())
	}
	for _, path := range []string{fixture.StagingRoot, fixture.ResultsRoot} {
		if info, err := os.Stat(path); err != nil {
			t.Fatalf("stat %s: %v", path, err)
		} else if info.Mode().Perm() != 0o750 {
			t.Fatalf("expected %s to remain 0750, got %o", path, info.Mode().Perm())
		}
	}
	if got := mustRead(t, fixture.ServiceUnitPath); got != originalServiceUnit {
		t.Fatalf("service unit should remain unchanged")
	}

	quarantinedRoots, ok := summary["quarantined_roots"].([]any)
	if !ok || len(quarantinedRoots) != 2 {
		t.Fatalf("expected two observed quarantined roots, got %+v", summary["quarantined_roots"])
	}
	for _, raw := range quarantinedRoots {
		item := jsonMap(t, raw)
		if item["classification"] != "pass" || item["unchanged"] != true {
			t.Fatalf("expected unchanged quarantined root evidence, got %+v", item)
		}
	}
	if _, err := os.Stat(filepath.Join(stagingQuarantine, "run-0001", "staging.txt")); err != nil {
		t.Fatalf("expected staging quarantine evidence to remain untouched: %v", err)
	}
	if _, err := os.Stat(filepath.Join(resultsQuarantine, "run-0001", "result.tar.gz")); err != nil {
		t.Fatalf("expected results quarantine evidence to remain untouched: %v", err)
	}
	if _, err := os.Stat(mutationLogPath); !os.IsNotExist(err) {
		t.Fatalf("parent-only apply should not stop/start services: %v", err)
	}
}

func TestRemoteAlphaESWritableStateOwnershipApplyChangesOnlyStableRootsAndWritesBackup(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	fakeBin := filepath.Join(tmpDir, "bin")
	if err := os.MkdirAll(fakeBin, 0o755); err != nil {
		t.Fatalf("mkdir fake bin: %v", err)
	}

	fixture := setupESServiceUserMigrationFixture(t, tmpDir)
	if err := os.Chmod(fixture.StagingRoot, 0o700); err != nil {
		t.Fatalf("chmod staging root: %v", err)
	}
	if err := os.Chmod(fixture.ResultsRoot, 0o700); err != nil {
		t.Fatalf("chmod results root: %v", err)
	}
	originalServiceUnit := mustRead(t, fixture.ServiceUnitPath)
	mutationLogPath := filepath.Join(tmpDir, "mutations.log")

	setupFakeESServiceUserMigrationCommands(t, fakeBin, fakeESServiceUserAccount{
		Present:   true,
		UID:       os.Getuid(),
		GID:       os.Getgid(),
		GroupName: "es",
	}, fixture, mutationLogPath)

	summaryPath := filepath.Join(tmpDir, "apply-summary.json")
	shellBody := esWritableStateOwnershipExpectedSliceShell(fixture) + fmt.Sprintf(`
remote_alpha_prepare_es_writable_state_ownership_main --apply --summary-path %q
`, summaryPath)
	output, err := runSourcedESWritableStateOwnershipHelper(t, envWithPath(fakeBin), shellBody)
	if err != nil {
		t.Fatalf("apply helper failed: %v\noutput=%s\nsummary=%s", err, string(output), readIfExists(summaryPath))
	}

	summary := readJSONFile(t, summaryPath)
	if summary["overall_classification"] != "pass" {
		t.Fatalf("expected pass classification, got %+v", summary)
	}
	proof := nestedMap(t, summary, "proof")
	if proof["host_mutation_performed"] != true {
		t.Fatalf("expected host_mutation_performed=true, got %+v", proof)
	}
	backup := nestedMap(t, summary, "backup")
	backupPath, ok := backup["path"].(string)
	if !ok || backupPath == "" {
		t.Fatalf("expected backup path, got %+v", backup)
	}
	if _, err := os.Stat(backupPath); err != nil {
		t.Fatalf("backup path missing: %v", err)
	}
	snapshot := readJSONFile(t, nestedMap(t, summary, "backup")["snapshot_manifest_path"].(string))
	backupRoots := jsonMap(t, snapshot["roots"])
	if got := jsonMap(t, backupRoots["staging"])["mode"]; got != "0700" {
		t.Fatalf("expected snapshot to capture pre-apply staging mode 0700, got %v", got)
	}
	if got := jsonMap(t, backupRoots["results"])["mode"]; got != "0700" {
		t.Fatalf("expected snapshot to capture pre-apply results mode 0700, got %v", got)
	}

	changedPaths, ok := summary["changed_paths"].([]any)
	if !ok || len(changedPaths) != 2 {
		t.Fatalf("expected exactly two changed paths, got %+v", summary["changed_paths"])
	}
	if changedPaths[0] != fixture.StagingRoot || changedPaths[1] != fixture.ResultsRoot {
		t.Fatalf("unexpected changed paths %+v", changedPaths)
	}
	postValidation := nestedMap(t, summary, "post_apply_validation")
	if postValidation["service_restart_performed"] != false {
		t.Fatalf("expected no service restart, got %+v", postValidation)
	}
	posture := nestedMap(t, postValidation, "es_service_posture")
	if posture["effective_user"] != "root(default)" || posture["effective_group"] != "root(default)" {
		t.Fatalf("expected service posture to remain root(default), got %+v", posture)
	}

	if info, err := os.Stat(fixture.StagingRoot); err != nil {
		t.Fatalf("stat staging root: %v", err)
	} else if info.Mode().Perm() != 0o750 {
		t.Fatalf("expected staging root mode 0750 after apply, got %o", info.Mode().Perm())
	}
	if info, err := os.Stat(fixture.ResultsRoot); err != nil {
		t.Fatalf("stat results root: %v", err)
	} else if info.Mode().Perm() != 0o750 {
		t.Fatalf("expected results root mode 0750 after apply, got %o", info.Mode().Perm())
	}
	if got := mustRead(t, fixture.ServiceUnitPath); got != originalServiceUnit {
		t.Fatalf("service unit should remain unchanged")
	}
	if _, err := os.Stat(mutationLogPath); !os.IsNotExist(err) {
		t.Fatalf("helper should not restart services or mutate systemctl state: %v", err)
	}
	rollbackNotes, ok := backup["rollback_notes"].([]any)
	if !ok || len(rollbackNotes) == 0 {
		t.Fatalf("expected rollback notes in backup metadata, got %+v", backup)
	}
}

func TestRemoteAlphaESWritableStateOwnershipNonEmptyRootsStillBlockButAdvertiseRotation(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	fakeBin := filepath.Join(tmpDir, "bin")
	if err := os.MkdirAll(fakeBin, 0o755); err != nil {
		t.Fatalf("mkdir fake bin: %v", err)
	}

	fixture := setupESServiceUserMigrationFixture(t, tmpDir)
	writeNormalizedESServiceUserRun(t, fixture, os.Getuid(), os.Getgid())

	setupFakeESServiceUserMigrationCommands(t, fakeBin, fakeESServiceUserAccount{
		Present:   true,
		UID:       os.Getuid(),
		GID:       os.Getgid(),
		GroupName: "es",
	}, fixture, filepath.Join(tmpDir, "mutations.log"))

	shellBody := esWritableStateOwnershipExpectedSliceShell(fixture) + `
remote_alpha_prepare_es_writable_state_ownership_main
`
	output, err := runSourcedESWritableStateOwnershipHelper(t, envWithPath(fakeBin), shellBody)
	if err == nil {
		t.Fatalf("expected default blocker for non-empty roots even when drained evidence exists\noutput=%s", string(output))
	}

	payload := parseWritableStateOwnershipOutput(t, output)
	if payload["overall_classification"] != "blocker" {
		t.Fatalf("expected blocker classification, got %v", payload["overall_classification"])
	}
	plan := nestedMap(t, payload, "plan")
	if plan["roots_nonempty_block_apply"] != true {
		t.Fatalf("expected roots_nonempty_block_apply=true, got %v", plan["roots_nonempty_block_apply"])
	}
	if plan["rotation_apply_ready"] != true {
		t.Fatalf("expected rotation_apply_ready=true, got %v", plan["rotation_apply_ready"])
	}
	if plan["rotation_requires_explicit_flag"] != true {
		t.Fatalf("expected rotation_requires_explicit_flag=true, got %v", plan["rotation_requires_explicit_flag"])
	}
	if plan["rotation_flag"] != "--rotate-nonempty-roots" {
		t.Fatalf("expected rotation flag advertisement, got %v", plan["rotation_flag"])
	}
	if nestedMap(t, nestedMap(t, payload, "validation"), "active_run_or_drain")["classification"] != "pass" {
		t.Fatalf("expected active_run_or_drain pass, got %+v", nestedMap(t, nestedMap(t, payload, "validation"), "active_run_or_drain"))
	}
	if nestedMap(t, payload, "rotation")["supported"] != true {
		t.Fatalf("expected rotation.supported=true, got %+v", nestedMap(t, payload, "rotation"))
	}
}

func TestRemoteAlphaESWritableStateOwnershipRotateFlagRequiresApply(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	fakeBin := filepath.Join(tmpDir, "bin")
	if err := os.MkdirAll(fakeBin, 0o755); err != nil {
		t.Fatalf("mkdir fake bin: %v", err)
	}

	fixture := setupESServiceUserMigrationFixture(t, tmpDir)
	setupFakeESServiceUserMigrationCommands(t, fakeBin, fakeESServiceUserAccount{
		Present:   true,
		UID:       os.Getuid(),
		GID:       os.Getgid(),
		GroupName: "es",
	}, fixture, filepath.Join(tmpDir, "mutations.log"))

	shellBody := esWritableStateOwnershipExpectedSliceShell(fixture) + `
remote_alpha_prepare_es_writable_state_ownership_main --rotate-nonempty-roots
`
	output, err := runSourcedESWritableStateOwnershipHelper(t, envWithPath(fakeBin), shellBody)
	if err == nil {
		t.Fatalf("expected flag validation failure without --apply\noutput=%s", string(output))
	}
	if !strings.Contains(string(output), "requires --apply with --rotate-nonempty-roots") {
		t.Fatalf("expected explicit rotate flag guidance, got %q", string(output))
	}
}

func TestRemoteAlphaESWritableStateOwnershipApplyWithoutRotateFlagStillBlocksOnNonEmptyRoots(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	fakeBin := filepath.Join(tmpDir, "bin")
	if err := os.MkdirAll(fakeBin, 0o755); err != nil {
		t.Fatalf("mkdir fake bin: %v", err)
	}

	fixture := setupESServiceUserMigrationFixture(t, tmpDir)
	writeNormalizedESServiceUserRun(t, fixture, os.Getuid(), os.Getgid())

	summaryPath := filepath.Join(tmpDir, "apply-summary.json")
	mutationLogPath := filepath.Join(tmpDir, "mutations.log")
	setupFakeESServiceUserMigrationCommands(t, fakeBin, fakeESServiceUserAccount{
		Present:   true,
		UID:       os.Getuid(),
		GID:       os.Getgid(),
		GroupName: "es",
	}, fixture, mutationLogPath)

	shellBody := esWritableStateOwnershipExpectedSliceShell(fixture) + fmt.Sprintf(`
remote_alpha_prepare_es_writable_state_ownership_main --apply --summary-path %q
`, summaryPath)
	output, err := runSourcedESWritableStateOwnershipHelper(t, envWithPath(fakeBin), shellBody)
	if err == nil {
		t.Fatalf("expected apply blocker without explicit rotate flag\noutput=%s", string(output))
	}

	summary := readJSONFile(t, summaryPath)
	if summary["overall_classification"] != "blocker" {
		t.Fatalf("expected blocker summary, got %+v", summary)
	}
	if nestedMap(t, summary, "post_apply_validation")["classification"] != "blocker" {
		t.Fatalf("expected post_apply_validation blocker, got %+v", nestedMap(t, summary, "post_apply_validation"))
	}
	if !strings.Contains(fmt.Sprint(nestedMap(t, summary, "post_apply_validation")["summary"]), "default apply is blocked") {
		t.Fatalf("expected default apply blocker summary, got %+v", nestedMap(t, summary, "post_apply_validation"))
	}
	if _, err := os.Stat(mutationLogPath); !os.IsNotExist(err) {
		t.Fatalf("mutation log should not exist when apply is blocked")
	}
}

func TestRemoteAlphaESWritableStateOwnershipRotationBlocksWhenActiveRunsCannotBeRuledOut(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	fakeBin := filepath.Join(tmpDir, "bin")
	if err := os.MkdirAll(fakeBin, 0o755); err != nil {
		t.Fatalf("mkdir fake bin: %v", err)
	}

	fixture := setupESServiceUserMigrationFixture(t, tmpDir)
	if err := os.Mkdir(filepath.Join(fixture.StagingRoot, "run-0001"), 0o700); err != nil {
		t.Fatalf("mkdir staging run: %v", err)
	}
	if err := os.Mkdir(filepath.Join(fixture.ResultsRoot, "run-0001"), 0o700); err != nil {
		t.Fatalf("mkdir results run: %v", err)
	}

	summaryPath := filepath.Join(tmpDir, "apply-summary.json")
	mutationLogPath := filepath.Join(tmpDir, "mutations.log")
	setupFakeESServiceUserMigrationCommands(t, fakeBin, fakeESServiceUserAccount{
		Present:   true,
		UID:       os.Getuid(),
		GID:       os.Getgid(),
		GroupName: "es",
	}, fixture, mutationLogPath)

	shellBody := esWritableStateOwnershipExpectedSliceShell(fixture) + fmt.Sprintf(`
remote_alpha_prepare_es_writable_state_ownership_main --apply --rotate-nonempty-roots --summary-path %q
`, summaryPath)
	output, err := runSourcedESWritableStateOwnershipHelper(t, envWithPath(fakeBin), shellBody)
	if err == nil {
		t.Fatalf("expected rotation blocker when active-run state is unknown\noutput=%s", string(output))
	}

	summary := readJSONFile(t, summaryPath)
	if summary["overall_classification"] != "blocker" {
		t.Fatalf("expected blocker summary, got %+v", summary)
	}
	if nestedMap(t, nestedMap(t, summary, "validation"), "active_run_or_drain")["classification"] != "blocker" {
		t.Fatalf("expected active_run_or_drain blocker, got %+v", nestedMap(t, nestedMap(t, summary, "validation"), "active_run_or_drain"))
	}
	if _, err := os.Stat(mutationLogPath); !os.IsNotExist(err) {
		t.Fatalf("rotation should not stop/start the service when active-run gating blocks apply")
	}
}

func TestRemoteAlphaESWritableStateOwnershipNomadActiveRunBlocksRotation(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	fakeBin := filepath.Join(tmpDir, "bin")
	if err := os.MkdirAll(fakeBin, 0o755); err != nil {
		t.Fatalf("mkdir fake bin: %v", err)
	}

	const runID = "run-legacy-active"
	fixture := setupESServiceUserMigrationFixture(t, tmpDir)
	writeLegacyESWritableStateRun(t, fixture, runID)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/job/exec-" + runID:
			_, _ = w.Write([]byte(`{"ID":"exec-run-legacy-active","Status":"running","ModifyIndex":11}`))
		case "/v1/job/exec-" + runID + "/allocations":
			_, _ = w.Write([]byte(`[{"ID":"alloc-active","ModifyIndex":12}]`))
		case "/v1/allocation/alloc-active":
			_, _ = w.Write([]byte(`{"ID":"alloc-active","ClientStatus":"running","ModifyIndex":12,"TaskStates":{"task":{"State":"running"}}}`))
		default:
			t.Fatalf("unexpected nomad path %q", r.URL.Path)
		}
	}))
	defer server.Close()
	updateESServiceUserFixtureNomadConfig(t, fixture, server.URL, "dc1", 5)

	setupFakeESServiceUserMigrationCommands(t, fakeBin, fakeESServiceUserAccount{
		Present:   true,
		UID:       os.Getuid(),
		GID:       os.Getgid(),
		GroupName: "es",
	}, fixture, filepath.Join(tmpDir, "mutations.log"))

	shellBody := esWritableStateOwnershipExpectedSliceShell(fixture) + `
remote_alpha_prepare_es_writable_state_ownership_main
`
	output, err := runSourcedESWritableStateOwnershipHelper(t, envWithPath(fakeBin), shellBody)
	if err == nil {
		t.Fatalf("expected blocker when Nomad still reports an active run\noutput=%s", string(output))
	}

	summary := parseWritableStateOwnershipOutput(t, output)
	if nestedMap(t, nestedMap(t, summary, "validation"), "active_run_or_drain")["classification"] != "blocker" {
		t.Fatalf("expected active_run_or_drain blocker, got %+v", nestedMap(t, nestedMap(t, summary, "validation"), "active_run_or_drain"))
	}
	observedRun := findObservedWritableStateRun(t, summary, runID)
	if observedRun["classification"] != "active" {
		t.Fatalf("expected active classification, got %+v", observedRun)
	}
	if observedRun["scheduler_state"] != "active" {
		t.Fatalf("expected scheduler_state=active, got %+v", observedRun)
	}
	if nestedMap(t, summary, "plan")["rotation_apply_ready"] != false {
		t.Fatalf("expected rotation_apply_ready=false, got %+v", nestedMap(t, summary, "plan"))
	}
}

func TestRemoteAlphaESWritableStateOwnershipNomadUnknownStateBlocksRotation(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	fakeBin := filepath.Join(tmpDir, "bin")
	if err := os.MkdirAll(fakeBin, 0o755); err != nil {
		t.Fatalf("mkdir fake bin: %v", err)
	}

	const runID = "run-legacy-unknown"
	fixture := setupESServiceUserMigrationFixture(t, tmpDir)
	writeLegacyESWritableStateRun(t, fixture, runID)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/job/exec-" + runID:
			_, _ = w.Write([]byte(`{"ID":"exec-run-legacy-unknown","Status":"running","ModifyIndex":11}`))
		case "/v1/job/exec-" + runID + "/allocations":
			_, _ = w.Write([]byte(`not-json`))
		default:
			t.Fatalf("unexpected nomad path %q", r.URL.Path)
		}
	}))
	defer server.Close()
	updateESServiceUserFixtureNomadConfig(t, fixture, server.URL, "dc1", 5)

	setupFakeESServiceUserMigrationCommands(t, fakeBin, fakeESServiceUserAccount{
		Present:   true,
		UID:       os.Getuid(),
		GID:       os.Getgid(),
		GroupName: "es",
	}, fixture, filepath.Join(tmpDir, "mutations.log"))

	shellBody := esWritableStateOwnershipExpectedSliceShell(fixture) + `
remote_alpha_prepare_es_writable_state_ownership_main
`
	output, err := runSourcedESWritableStateOwnershipHelper(t, envWithPath(fakeBin), shellBody)
	if err == nil {
		t.Fatalf("expected blocker when Nomad allocation state is invalid\noutput=%s", string(output))
	}

	summary := parseWritableStateOwnershipOutput(t, output)
	observedRun := findObservedWritableStateRun(t, summary, runID)
	if observedRun["classification"] != "unknown" {
		t.Fatalf("expected unknown classification, got %+v", observedRun)
	}
	if nestedMap(t, nestedMap(t, summary, "validation"), "active_run_or_drain")["classification"] != "blocker" {
		t.Fatalf("expected active_run_or_drain blocker, got %+v", nestedMap(t, nestedMap(t, summary, "validation"), "active_run_or_drain"))
	}
}

func TestRemoteAlphaESWritableStateOwnershipNomadUnavailableBlocksRotation(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	fakeBin := filepath.Join(tmpDir, "bin")
	if err := os.MkdirAll(fakeBin, 0o755); err != nil {
		t.Fatalf("mkdir fake bin: %v", err)
	}

	const runID = "run-legacy-unavailable"
	fixture := setupESServiceUserMigrationFixture(t, tmpDir)
	writeLegacyESWritableStateRun(t, fixture, runID)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nomad unavailable", http.StatusServiceUnavailable)
	}))
	defer server.Close()
	updateESServiceUserFixtureNomadConfig(t, fixture, server.URL, "dc1", 5)

	setupFakeESServiceUserMigrationCommands(t, fakeBin, fakeESServiceUserAccount{
		Present:   true,
		UID:       os.Getuid(),
		GID:       os.Getgid(),
		GroupName: "es",
	}, fixture, filepath.Join(tmpDir, "mutations.log"))

	shellBody := esWritableStateOwnershipExpectedSliceShell(fixture) + `
remote_alpha_prepare_es_writable_state_ownership_main
`
	output, err := runSourcedESWritableStateOwnershipHelper(t, envWithPath(fakeBin), shellBody)
	if err == nil {
		t.Fatalf("expected blocker when Nomad is unavailable\noutput=%s", string(output))
	}

	summary := parseWritableStateOwnershipOutput(t, output)
	observedRun := findObservedWritableStateRun(t, summary, runID)
	if observedRun["classification"] != "unknown" {
		t.Fatalf("expected unknown classification, got %+v", observedRun)
	}
	if !strings.Contains(fmt.Sprint(observedRun["summary"]), "Nomad") {
		t.Fatalf("expected Nomad-backed summary, got %+v", observedRun)
	}
}

func TestRemoteAlphaESWritableStateOwnershipAbsentNomadJobBecomesStaleOrphanCandidate(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	fakeBin := filepath.Join(tmpDir, "bin")
	if err := os.MkdirAll(fakeBin, 0o755); err != nil {
		t.Fatalf("mkdir fake bin: %v", err)
	}

	const runID = "run-legacy-orphan"
	fixture := setupESServiceUserMigrationFixture(t, tmpDir)
	writeLegacyESWritableStateRun(t, fixture, runID)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer server.Close()
	updateESServiceUserFixtureNomadConfig(t, fixture, server.URL, "dc1", 5)

	setupFakeESServiceUserMigrationCommands(t, fakeBin, fakeESServiceUserAccount{
		Present:   true,
		UID:       os.Getuid(),
		GID:       os.Getgid(),
		GroupName: "es",
	}, fixture, filepath.Join(tmpDir, "mutations.log"))

	shellBody := esWritableStateOwnershipExpectedSliceShell(fixture) + `
remote_alpha_prepare_es_writable_state_ownership_main
`
	output, err := runSourcedESWritableStateOwnershipHelper(t, envWithPath(fakeBin), shellBody)
	if err == nil {
		t.Fatalf("expected blocker because non-empty roots still block default apply\noutput=%s", string(output))
	}

	summary := parseWritableStateOwnershipOutput(t, output)
	activeRun := nestedMap(t, nestedMap(t, summary, "validation"), "active_run_or_drain")
	if activeRun["classification"] != "pass" {
		t.Fatalf("expected active_run_or_drain pass, got %+v", activeRun)
	}
	observedRun := findObservedWritableStateRun(t, summary, runID)
	if observedRun["classification"] != "stale_orphan_candidate" {
		t.Fatalf("expected stale_orphan_candidate classification, got %+v", observedRun)
	}
	if observedRun["scheduler_state"] != "absent_in_scheduler" {
		t.Fatalf("expected scheduler_state=absent_in_scheduler, got %+v", observedRun)
	}
	plan := nestedMap(t, summary, "plan")
	if plan["rotation_apply_ready"] != true {
		t.Fatalf("expected rotation_apply_ready=true, got %+v", plan)
	}
	if plan["legacy_orphan_acceptance_required"] != true {
		t.Fatalf("expected legacy_orphan_acceptance_required=true, got %+v", plan)
	}
	if plan["legacy_orphan_acceptance_flag"] != "--accept-stale-orphaned-runs" {
		t.Fatalf("expected acceptance flag advertisement, got %+v", plan)
	}
	if !strings.Contains(fmt.Sprint(plan["rotation_explicit_flags_required"]), "--accept-stale-orphaned-runs") {
		t.Fatalf("expected explicit flags to include stale/orphan acceptance, got %+v", plan)
	}
}

func TestRemoteAlphaESWritableStateOwnershipTerminalNomadRunIsNotActive(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	fakeBin := filepath.Join(tmpDir, "bin")
	if err := os.MkdirAll(fakeBin, 0o755); err != nil {
		t.Fatalf("mkdir fake bin: %v", err)
	}

	const runID = "run-legacy-terminal"
	fixture := setupESServiceUserMigrationFixture(t, tmpDir)
	writeLegacyESWritableStateRun(t, fixture, runID)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/job/exec-" + runID:
			_, _ = w.Write([]byte(`{"ID":"exec-run-legacy-terminal","Status":"dead","ModifyIndex":11}`))
		case "/v1/job/exec-" + runID + "/allocations":
			_, _ = w.Write([]byte(`[{"ID":"alloc-terminal","ModifyIndex":12}]`))
		case "/v1/allocation/alloc-terminal":
			_, _ = w.Write([]byte(`{"ID":"alloc-terminal","ClientStatus":"complete","ModifyIndex":12,"TaskStates":{"task":{"State":"dead","Events":[{"Type":"Terminated","ExitCode":0}]}}}`))
		default:
			t.Fatalf("unexpected nomad path %q", r.URL.Path)
		}
	}))
	defer server.Close()
	updateESServiceUserFixtureNomadConfig(t, fixture, server.URL, "dc1", 5)

	setupFakeESServiceUserMigrationCommands(t, fakeBin, fakeESServiceUserAccount{
		Present:   true,
		UID:       os.Getuid(),
		GID:       os.Getgid(),
		GroupName: "es",
	}, fixture, filepath.Join(tmpDir, "mutations.log"))

	shellBody := esWritableStateOwnershipExpectedSliceShell(fixture) + `
remote_alpha_prepare_es_writable_state_ownership_main
`
	output, err := runSourcedESWritableStateOwnershipHelper(t, envWithPath(fakeBin), shellBody)
	if err == nil {
		t.Fatalf("expected blocker because non-empty roots still block default apply\noutput=%s", string(output))
	}

	summary := parseWritableStateOwnershipOutput(t, output)
	activeRun := nestedMap(t, nestedMap(t, summary, "validation"), "active_run_or_drain")
	if activeRun["classification"] != "pass" {
		t.Fatalf("expected active_run_or_drain pass, got %+v", activeRun)
	}
	observedRun := findObservedWritableStateRun(t, summary, runID)
	if observedRun["classification"] != "terminal" {
		t.Fatalf("expected terminal classification, got %+v", observedRun)
	}
	if observedRun["scheduler_state"] != "terminal" {
		t.Fatalf("expected scheduler_state=terminal, got %+v", observedRun)
	}
}

func TestRemoteAlphaESWritableStateOwnershipStaleOrphanRotationRequiresExplicitAcceptanceFlag(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	fakeBin := filepath.Join(tmpDir, "bin")
	if err := os.MkdirAll(fakeBin, 0o755); err != nil {
		t.Fatalf("mkdir fake bin: %v", err)
	}

	const runID = "run-legacy-apply-gated"
	fixture := setupESServiceUserMigrationFixture(t, tmpDir)
	writeLegacyESWritableStateRun(t, fixture, runID)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer server.Close()
	updateESServiceUserFixtureNomadConfig(t, fixture, server.URL, "dc1", 5)

	summaryPath := filepath.Join(tmpDir, "apply-summary.json")
	mutationLogPath := filepath.Join(tmpDir, "mutations.log")
	setupFakeESServiceUserMigrationCommands(t, fakeBin, fakeESServiceUserAccount{
		Present:   true,
		UID:       os.Getuid(),
		GID:       os.Getgid(),
		GroupName: "es",
	}, fixture, mutationLogPath)

	shellBody := esWritableStateOwnershipExpectedSliceShell(fixture) + fmt.Sprintf(`
remote_alpha_prepare_es_writable_state_ownership_main --apply --rotate-nonempty-roots --summary-path %q
`, summaryPath)
	output, err := runSourcedESWritableStateOwnershipHelper(t, envWithPath(fakeBin), shellBody)
	if err == nil {
		t.Fatalf("expected apply blocker without stale/orphan acceptance flag\noutput=%s", string(output))
	}

	summary := readJSONFile(t, summaryPath)
	if summary["overall_classification"] != "blocker" {
		t.Fatalf("expected blocker summary, got %+v", summary)
	}
	postValidation := nestedMap(t, summary, "post_apply_validation")
	if postValidation["classification"] != "blocker" {
		t.Fatalf("expected post_apply_validation blocker, got %+v", postValidation)
	}
	if !strings.Contains(fmt.Sprint(postValidation["summary"]), "acceptance flag") {
		t.Fatalf("expected stale/orphan acceptance flag guidance, got %+v", postValidation)
	}
	if _, err := os.Stat(mutationLogPath); !os.IsNotExist(err) {
		t.Fatalf("mutation log should not exist when stale/orphan acceptance is missing")
	}
}

func TestRemoteAlphaESWritableStateOwnershipStaleOrphanRotationApplyPassesWithExplicitAcceptanceFlag(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	fakeBin := filepath.Join(tmpDir, "bin")
	if err := os.MkdirAll(fakeBin, 0o755); err != nil {
		t.Fatalf("mkdir fake bin: %v", err)
	}

	const runID = "run-legacy-apply-ok"
	fixture := setupESServiceUserMigrationFixture(t, tmpDir)
	writeLegacyESWritableStateRun(t, fixture, runID)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer server.Close()
	updateESServiceUserFixtureNomadConfig(t, fixture, server.URL, "dc1", 5)
	if err := os.Chmod(fixture.StagingRoot, 0o700); err != nil {
		t.Fatalf("chmod staging root: %v", err)
	}
	if err := os.Chmod(fixture.ResultsRoot, 0o700); err != nil {
		t.Fatalf("chmod results root: %v", err)
	}

	summaryPath := filepath.Join(tmpDir, "apply-summary.json")
	mutationLogPath := filepath.Join(tmpDir, "mutations.log")
	backupSentinelPath := filepath.Join(tmpDir, "backup.sentinel")
	setupFakeESServiceUserMigrationCommands(t, fakeBin, fakeESServiceUserAccount{
		Present:   true,
		UID:       os.Getuid(),
		GID:       os.Getgid(),
		GroupName: "es",
	}, fixture, mutationLogPath)

	shellBody := esWritableStateOwnershipExpectedSliceShell(fixture) + fmt.Sprintf(`
remote_alpha_prepare_es_writable_state_ownership_main --apply --rotate-nonempty-roots --accept-stale-orphaned-runs --summary-path %q
`, summaryPath)
	output, err := runSourcedESWritableStateOwnershipHelper(t, envWithPath(fakeBin,
		"REMOTE_ALPHA_TEST_MUTATION_LOG_PATH="+mutationLogPath,
		"REMOTE_ALPHA_TEST_BACKUP_SENTINEL_PATH="+backupSentinelPath,
	), shellBody)
	if err != nil {
		t.Fatalf("rotation apply failed: %v\noutput=%s\nsummary=%s", err, string(output), readIfExists(summaryPath))
	}

	summary := readJSONFile(t, summaryPath)
	if summary["overall_classification"] != "pass" {
		t.Fatalf("expected pass summary, got %+v", summary)
	}
	if nestedMap(t, nestedMap(t, summary, "post_apply_validation"), "health")["classification"] != "pass" {
		t.Fatalf("expected health pass, got %+v", nestedMap(t, nestedMap(t, summary, "post_apply_validation"), "health"))
	}
	if !strings.Contains(strings.TrimSpace(mustRead(t, mutationLogPath)), "systemctl stop") {
		t.Fatalf("expected bounded stop/start log, got %q", readIfExists(mutationLogPath))
	}
}

func TestRemoteAlphaESWritableStateOwnershipRotationApplyMovesOldRootsAndRestartsService(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	fakeBin := filepath.Join(tmpDir, "bin")
	if err := os.MkdirAll(fakeBin, 0o755); err != nil {
		t.Fatalf("mkdir fake bin: %v", err)
	}

	fixture := setupESServiceUserMigrationFixture(t, tmpDir)
	writeNormalizedESServiceUserRun(t, fixture, os.Getuid(), os.Getgid())
	if err := os.Chmod(fixture.StagingRoot, 0o700); err != nil {
		t.Fatalf("chmod staging root: %v", err)
	}
	if err := os.Chmod(fixture.ResultsRoot, 0o700); err != nil {
		t.Fatalf("chmod results root: %v", err)
	}

	originalServiceUnit := mustRead(t, fixture.ServiceUnitPath)
	summaryPath := filepath.Join(tmpDir, "apply-summary.json")
	mutationLogPath := filepath.Join(tmpDir, "mutations.log")
	backupSentinelPath := filepath.Join(tmpDir, "backup.sentinel")
	backupPathFile := filepath.Join(tmpDir, "backup-path.txt")
	setupFakeESServiceUserMigrationCommands(t, fakeBin, fakeESServiceUserAccount{
		Present:   true,
		UID:       os.Getuid(),
		GID:       os.Getgid(),
		GroupName: "es",
	}, fixture, mutationLogPath)

	shellBody := esWritableStateOwnershipExpectedSliceShell(fixture) + fmt.Sprintf(`
remote_alpha_prepare_es_writable_state_ownership_main --apply --rotate-nonempty-roots --summary-path %q
`, summaryPath)
	output, err := runSourcedESWritableStateOwnershipHelper(t, envWithPath(fakeBin,
		"REMOTE_ALPHA_TEST_MUTATION_LOG_PATH="+mutationLogPath,
		"REMOTE_ALPHA_TEST_BACKUP_SENTINEL_PATH="+backupSentinelPath,
		"REMOTE_ALPHA_TEST_BACKUP_PATH_FILE="+backupPathFile,
	), shellBody)
	if err != nil {
		t.Fatalf("rotation apply failed: %v\noutput=%s\nsummary=%s", err, string(output), readIfExists(summaryPath))
	}

	summary := readJSONFile(t, summaryPath)
	if summary["overall_classification"] != "pass" {
		t.Fatalf("expected pass summary, got %+v", summary)
	}
	changedPaths, ok := summary["changed_paths"].([]any)
	if !ok || len(changedPaths) != 2 || changedPaths[0] != fixture.StagingRoot || changedPaths[1] != fixture.ResultsRoot {
		t.Fatalf("unexpected changed_paths %+v", summary["changed_paths"])
	}
	postValidation := nestedMap(t, summary, "post_apply_validation")
	if postValidation["classification"] != "pass" {
		t.Fatalf("expected post-apply validation pass, got %+v", postValidation)
	}
	if postValidation["service_stop_performed"] != true || postValidation["service_start_performed"] != true {
		t.Fatalf("expected bounded stop/start, got %+v", postValidation)
	}
	if postValidation["service_restart_performed"] != false {
		t.Fatalf("expected no restart, got %+v", postValidation)
	}
	if nestedMap(t, postValidation, "health")["classification"] != "pass" {
		t.Fatalf("expected health pass, got %+v", nestedMap(t, postValidation, "health"))
	}
	if nestedMap(t, postValidation, "contract")["classification"] != "pass" {
		t.Fatalf("expected contract pass, got %+v", nestedMap(t, postValidation, "contract"))
	}
	posture := nestedMap(t, postValidation, "es_service_posture")
	if posture["effective_user"] != "root(default)" || posture["effective_group"] != "root(default)" {
		t.Fatalf("expected service to remain root(default), got %+v", posture)
	}

	quarantinePaths := nestedMap(t, summary, "quarantine_paths")
	stagingQuarantine := fmt.Sprint(quarantinePaths["staging"])
	resultsQuarantine := fmt.Sprint(quarantinePaths["results"])
	if stagingQuarantine == "" || resultsQuarantine == "" {
		t.Fatalf("expected quarantine paths, got %+v", quarantinePaths)
	}
	if _, err := os.Stat(stagingQuarantine); err != nil {
		t.Fatalf("missing preserved staging root: %v", err)
	}
	if _, err := os.Stat(resultsQuarantine); err != nil {
		t.Fatalf("missing preserved results root: %v", err)
	}
	if _, err := os.Stat(filepath.Join(stagingQuarantine, "run-0001")); err != nil {
		t.Fatalf("expected preserved staging run evidence: %v", err)
	}
	if _, err := os.Stat(filepath.Join(resultsQuarantine, "run-0001", "result.tar.gz")); err != nil {
		t.Fatalf("expected preserved retained result evidence: %v", err)
	}
	if entries, err := os.ReadDir(fixture.StagingRoot); err != nil {
		t.Fatalf("read live staging root: %v", err)
	} else if len(entries) != 0 {
		t.Fatalf("expected fresh empty live staging root, got %d entries", len(entries))
	}
	if entries, err := os.ReadDir(fixture.ResultsRoot); err != nil {
		t.Fatalf("read live results root: %v", err)
	} else if len(entries) != 0 {
		t.Fatalf("expected fresh empty live results root, got %d entries", len(entries))
	}
	if info, err := os.Stat(fixture.StagingRoot); err != nil {
		t.Fatalf("stat fresh staging root: %v", err)
	} else if info.Mode().Perm() != 0o750 {
		t.Fatalf("expected fresh staging root mode 0750, got %o", info.Mode().Perm())
	}
	if info, err := os.Stat(fixture.ResultsRoot); err != nil {
		t.Fatalf("stat fresh results root: %v", err)
	} else if info.Mode().Perm() != 0o750 {
		t.Fatalf("expected fresh results root mode 0750, got %o", info.Mode().Perm())
	}
	if got := mustRead(t, fixture.ServiceUnitPath); got != originalServiceUnit {
		t.Fatalf("service unit should remain unchanged")
	}

	logLines := strings.Split(strings.TrimSpace(mustRead(t, mutationLogPath)), "\n")
	stopCount := 0
	startCount := 0
	for _, line := range logLines {
		if line == "systemctl stop" {
			stopCount++
		}
		if line == "systemctl start" {
			startCount++
		}
		if line == "systemctl restart" {
			t.Fatalf("unexpected restart in bounded maintenance window: %q", logLines)
		}
	}
	if stopCount != 1 || startCount != 1 {
		t.Fatalf("expected exactly one stop and one start, got %q", logLines)
	}
	if strings.Index(strings.Join(logLines, "\n"), "systemctl stop") > strings.Index(strings.Join(logLines, "\n"), "systemctl start") {
		t.Fatalf("expected stop before start, got %q", logLines)
	}

	backup := nestedMap(t, summary, "backup")
	if fmt.Sprint(backup["path"]) == "" || fmt.Sprint(backup["snapshot_manifest_path"]) == "" {
		t.Fatalf("expected backup metadata, got %+v", backup)
	}
	if _, err := os.Stat(fmt.Sprint(backup["path"])); err != nil {
		t.Fatalf("backup path missing: %v", err)
	}
	if got := strings.TrimSpace(mustRead(t, backupPathFile)); got != fmt.Sprint(backup["path"]) {
		t.Fatalf("expected backup path file to match summary path, got %q want %q", got, backup["path"])
	}
	rollbackNotes, ok := backup["rollback_notes"].([]any)
	if !ok || len(rollbackNotes) == 0 {
		t.Fatalf("expected rollback notes, got %+v", backup)
	}
	if nestedMap(t, summary, "rotation")["applied"] != true {
		t.Fatalf("expected rotation.applied=true, got %+v", nestedMap(t, summary, "rotation"))
	}
}

func TestRemoteAlphaESWritableStateOwnershipFreshNonemptyRootsAdvertiseArtifactReconciliation(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	fakeBin := filepath.Join(tmpDir, "bin")
	if err := os.MkdirAll(fakeBin, 0o755); err != nil {
		t.Fatalf("mkdir fake bin: %v", err)
	}

	fixture := setupESServiceUserMigrationFixture(t, tmpDir)
	writeNormalizedESServiceUserRun(t, fixture, os.Getuid(), os.Getgid())
	preserveNormalizationEvidenceForRun(t, fixture, "run-0001")
	if err := os.Chmod(fixture.StagingRoot, 0o750); err != nil {
		t.Fatalf("chmod staging root: %v", err)
	}
	if err := os.Chmod(fixture.ResultsRoot, 0o750); err != nil {
		t.Fatalf("chmod results root: %v", err)
	}
	if err := os.Chmod(filepath.Join(fixture.StagingRoot, "run-0001"), 0o700); err != nil {
		t.Fatalf("chmod run stage root: %v", err)
	}
	if err := os.Chmod(filepath.Join(fixture.ResultsRoot, "run-0001"), 0o700); err != nil {
		t.Fatalf("chmod retained run dir: %v", err)
	}
	if err := os.Chmod(filepath.Join(fixture.ResultsRoot, "run-0001", "result.tar.gz"), 0o644); err != nil {
		t.Fatalf("chmod retained bundle: %v", err)
	}

	setupFakeESServiceUserMigrationCommands(t, fakeBin, fakeESServiceUserAccount{
		Present:   true,
		UID:       os.Getuid(),
		GID:       os.Getgid(),
		GroupName: "es",
	}, fixture, filepath.Join(tmpDir, "mutations.log"))

	shellBody := esWritableStateOwnershipExpectedSliceShell(fixture) + `
remote_alpha_prepare_es_writable_state_ownership_main
`
	output, err := runSourcedESWritableStateOwnershipHelper(t, envWithPath(fakeBin), shellBody)
	if err != nil {
		t.Fatalf("expected warning-only reconciliation plan, got %v\noutput=%s", err, string(output))
	}

	summary := parseWritableStateOwnershipOutput(t, output)
	if summary["overall_classification"] != "warning" {
		t.Fatalf("expected warning classification, got %+v", summary)
	}
	plan := nestedMap(t, summary, "plan")
	if plan["roots_nonempty_block_apply"] != false {
		t.Fatalf("expected roots_nonempty_block_apply=false, got %+v", plan)
	}
	if plan["rotation_apply_ready"] != false {
		t.Fatalf("expected rotation_apply_ready=false, got %+v", plan)
	}
	if plan["artifact_reconciliation_apply_ready"] != true {
		t.Fatalf("expected artifact_reconciliation_apply_ready=true, got %+v", plan)
	}
	if plan["artifact_reconciliation_flag"] != "--reconcile-artifacts" {
		t.Fatalf("expected reconcile flag advertisement, got %+v", plan)
	}
	artifact := nestedMap(t, nestedMap(t, summary, "validation"), "artifact_reconciliation")
	if artifact["classification"] != "warning" {
		t.Fatalf("expected artifact reconciliation warning, got %+v", artifact)
	}
	retainedCandidate := findArtifactReconciliationRetainedCandidate(t, summary, "run-0001")
	if retainedCandidate["planned_action"] != "repair_retained_artifacts_in_place" {
		t.Fatalf("expected retained repair plan, got %+v", retainedCandidate)
	}
	stageCandidate := findArtifactReconciliationStageCandidate(t, summary, "run-0001")
	if stageCandidate["planned_action"] != "quarantine_stage_root" {
		t.Fatalf("expected stage-root quarantine plan, got %+v", stageCandidate)
	}
}

func TestRemoteAlphaESWritableStateOwnershipReconcileFlagRequiresApply(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	fakeBin := filepath.Join(tmpDir, "bin")
	if err := os.MkdirAll(fakeBin, 0o755); err != nil {
		t.Fatalf("mkdir fake bin: %v", err)
	}

	fixture := setupESServiceUserMigrationFixture(t, tmpDir)
	setupFakeESServiceUserMigrationCommands(t, fakeBin, fakeESServiceUserAccount{
		Present:   true,
		UID:       os.Getuid(),
		GID:       os.Getgid(),
		GroupName: "es",
	}, fixture, filepath.Join(tmpDir, "mutations.log"))

	shellBody := esWritableStateOwnershipExpectedSliceShell(fixture) + `
remote_alpha_prepare_es_writable_state_ownership_main --reconcile-artifacts
`
	output, err := runSourcedESWritableStateOwnershipHelper(t, envWithPath(fakeBin), shellBody)
	if err == nil {
		t.Fatalf("expected reconcile flag validation failure without --apply\noutput=%s", string(output))
	}
	if !strings.Contains(string(output), "requires --apply with --reconcile-artifacts") {
		t.Fatalf("expected explicit reconcile flag guidance, got %q", string(output))
	}
}

func TestRemoteAlphaESWritableStateOwnershipActiveRunBlocksArtifactReconciliation(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	fakeBin := filepath.Join(tmpDir, "bin")
	if err := os.MkdirAll(fakeBin, 0o755); err != nil {
		t.Fatalf("mkdir fake bin: %v", err)
	}

	const runID = "run-reconcile-active"
	fixture := setupESServiceUserMigrationFixture(t, tmpDir)
	writeLegacyESWritableStateRun(t, fixture, runID)
	if err := os.Chmod(fixture.StagingRoot, 0o750); err != nil {
		t.Fatalf("chmod staging root: %v", err)
	}
	if err := os.Chmod(fixture.ResultsRoot, 0o750); err != nil {
		t.Fatalf("chmod results root: %v", err)
	}
	if err := os.Chmod(filepath.Join(fixture.StagingRoot, runID), 0o700); err != nil {
		t.Fatalf("chmod run stage root: %v", err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/job/exec-" + runID:
			_, _ = w.Write([]byte(`{"ID":"exec-run-reconcile-active","Status":"running","ModifyIndex":11}`))
		case "/v1/job/exec-" + runID + "/allocations":
			_, _ = w.Write([]byte(`[{"ID":"alloc-active","ModifyIndex":12}]`))
		case "/v1/allocation/alloc-active":
			_, _ = w.Write([]byte(`{"ID":"alloc-active","ClientStatus":"running","ModifyIndex":12,"TaskStates":{"task":{"State":"running"}}}`))
		default:
			t.Fatalf("unexpected nomad path %q", r.URL.Path)
		}
	}))
	defer server.Close()
	updateESServiceUserFixtureNomadConfig(t, fixture, server.URL, "dc1", 5)

	setupFakeESServiceUserMigrationCommands(t, fakeBin, fakeESServiceUserAccount{
		Present:   true,
		UID:       os.Getuid(),
		GID:       os.Getgid(),
		GroupName: "es",
	}, fixture, filepath.Join(tmpDir, "mutations.log"))

	shellBody := esWritableStateOwnershipExpectedSliceShell(fixture) + `
remote_alpha_prepare_es_writable_state_ownership_main
`
	output, err := runSourcedESWritableStateOwnershipHelper(t, envWithPath(fakeBin), shellBody)
	if err == nil {
		t.Fatalf("expected blocker while an active run prevents reconciliation\noutput=%s", string(output))
	}

	summary := parseWritableStateOwnershipOutput(t, output)
	artifact := nestedMap(t, nestedMap(t, summary, "validation"), "artifact_reconciliation")
	if artifact["classification"] != "blocker" {
		t.Fatalf("expected artifact reconciliation blocker, got %+v", artifact)
	}
	plan := nestedMap(t, summary, "plan")
	if plan["artifact_reconciliation_apply_ready"] != false {
		t.Fatalf("expected artifact_reconciliation_apply_ready=false, got %+v", plan)
	}
	stageCandidate := findArtifactReconciliationStageCandidate(t, summary, runID)
	if stageCandidate["planned_action"] != "block" {
		t.Fatalf("expected blocked stage-root plan, got %+v", stageCandidate)
	}
}

func TestRemoteAlphaESWritableStateOwnershipReconcileApplyRepairsAndQuarantinesWithoutRestart(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	fakeBin := filepath.Join(tmpDir, "bin")
	if err := os.MkdirAll(fakeBin, 0o755); err != nil {
		t.Fatalf("mkdir fake bin: %v", err)
	}

	fixture := setupESServiceUserMigrationFixture(t, tmpDir)
	writeNormalizedESServiceUserRun(t, fixture, os.Getuid(), os.Getgid())
	preserveNormalizationEvidenceForRun(t, fixture, "run-0001")
	if err := os.Chmod(fixture.StagingRoot, 0o750); err != nil {
		t.Fatalf("chmod staging root: %v", err)
	}
	if err := os.Chmod(fixture.ResultsRoot, 0o750); err != nil {
		t.Fatalf("chmod results root: %v", err)
	}
	if err := os.Chmod(filepath.Join(fixture.StagingRoot, "run-0001"), 0o700); err != nil {
		t.Fatalf("chmod run stage root: %v", err)
	}
	if err := os.Chmod(filepath.Join(fixture.ResultsRoot, "run-0001"), 0o700); err != nil {
		t.Fatalf("chmod retained run dir: %v", err)
	}
	if err := os.Chmod(filepath.Join(fixture.ResultsRoot, "run-0001", "result.tar.gz"), 0o644); err != nil {
		t.Fatalf("chmod retained bundle: %v", err)
	}
	if err := os.Chmod(filepath.Join(fixture.ResultsRoot, "run-0001", "ownership-normalization.json"), 0o600); err != nil {
		t.Fatalf("chmod retained sidecar: %v", err)
	}

	legacyRetainedRunID := "run-retained-legacy"
	legacyRetainedDir := filepath.Join(fixture.ResultsRoot, legacyRetainedRunID)
	if err := os.MkdirAll(legacyRetainedDir, 0o700); err != nil {
		t.Fatalf("mkdir legacy retained dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(legacyRetainedDir, "result.tar.gz"), []byte("legacy bundle\n"), 0o600); err != nil {
		t.Fatalf("write legacy retained bundle: %v", err)
	}

	summaryPath := filepath.Join(tmpDir, "apply-summary.json")
	mutationLogPath := filepath.Join(tmpDir, "mutations.log")
	setupFakeESServiceUserMigrationCommands(t, fakeBin, fakeESServiceUserAccount{
		Present:   true,
		UID:       os.Getuid(),
		GID:       os.Getgid(),
		GroupName: "es",
	}, fixture, mutationLogPath)

	shellBody := esWritableStateOwnershipExpectedSliceShell(fixture) + fmt.Sprintf(`
remote_alpha_prepare_es_writable_state_ownership_main --apply --reconcile-artifacts --summary-path %q
`, summaryPath)
	output, err := runSourcedESWritableStateOwnershipHelper(t, envWithPath(fakeBin,
		"REMOTE_ALPHA_TEST_MUTATION_LOG_PATH="+mutationLogPath,
	), shellBody)
	if err != nil {
		t.Fatalf("artifact reconciliation apply failed: %v\noutput=%s\nsummary=%s", err, string(output), readIfExists(summaryPath))
	}

	summary := readJSONFile(t, summaryPath)
	if summary["overall_classification"] != "pass" {
		t.Fatalf("expected pass summary, got %+v", summary)
	}
	changes := nestedMap(t, summary, "changes")
	if changes["mode"] != "artifact_reconciliation" {
		t.Fatalf("expected artifact_reconciliation mode, got %+v", changes)
	}
	postValidation := nestedMap(t, summary, "post_apply_validation")
	if postValidation["classification"] != "pass" {
		t.Fatalf("expected post-apply validation pass, got %+v", postValidation)
	}
	if postValidation["service_stop_performed"] != false || postValidation["service_start_performed"] != false || postValidation["service_restart_performed"] != false {
		t.Fatalf("expected no service restart activity, got %+v", postValidation)
	}
	posture := nestedMap(t, postValidation, "es_service_posture")
	if posture["effective_user"] != "root(default)" || posture["effective_group"] != "root(default)" {
		t.Fatalf("expected service to remain root(default), got %+v", posture)
	}
	artifactPost := nestedMap(t, nestedMap(t, summary, "artifact_reconciliation"), "post_apply")
	if artifactPost["classification"] != "pass" {
		t.Fatalf("expected post-apply artifact reconciliation pass, got %+v", artifactPost)
	}
	if strings.Contains(readIfExists(mutationLogPath), "systemctl stop") || strings.Contains(readIfExists(mutationLogPath), "systemctl start") {
		t.Fatalf("expected no stop/start during artifact reconciliation, got %q", readIfExists(mutationLogPath))
	}

	if info, err := os.Stat(filepath.Join(fixture.ResultsRoot, "run-0001")); err != nil {
		t.Fatalf("stat repaired retained run dir: %v", err)
	} else if info.Mode().Perm() != 0o750 {
		t.Fatalf("expected repaired retained run dir mode 0750, got %o", info.Mode().Perm())
	}
	if info, err := os.Stat(filepath.Join(fixture.ResultsRoot, "run-0001", "result.tar.gz")); err != nil {
		t.Fatalf("stat repaired retained bundle: %v", err)
	} else if info.Mode().Perm() != 0o600 {
		t.Fatalf("expected repaired retained bundle mode 0600, got %o", info.Mode().Perm())
	}
	if info, err := os.Stat(filepath.Join(fixture.ResultsRoot, "run-0001", "ownership-normalization.json")); err != nil {
		t.Fatalf("stat repaired retained sidecar: %v", err)
	} else if info.Mode().Perm() != 0o640 {
		t.Fatalf("expected repaired retained sidecar mode 0640, got %o", info.Mode().Perm())
	}
	if _, err := os.Stat(filepath.Join(fixture.StagingRoot, "run-0001")); !os.IsNotExist(err) {
		t.Fatalf("expected incompatible stage root to be quarantined, got %v", err)
	}
	if _, err := os.Stat(filepath.Join(fixture.ResultsRoot, legacyRetainedRunID)); !os.IsNotExist(err) {
		t.Fatalf("expected legacy retained run dir to be quarantined, got %v", err)
	}

	quarantinePaths := nestedMap(t, summary, "quarantine_paths")
	resultsQuarantine := fmt.Sprint(quarantinePaths["results"])
	stagingQuarantine := fmt.Sprint(quarantinePaths["staging"])
	if resultsQuarantine == "" || stagingQuarantine == "" {
		t.Fatalf("expected quarantine roots, got %+v", quarantinePaths)
	}
	if _, err := os.Stat(filepath.Join(resultsQuarantine, legacyRetainedRunID, "result.tar.gz")); err != nil {
		t.Fatalf("expected legacy retained bundle in results quarantine root: %v", err)
	}
	if _, err := os.Stat(filepath.Join(stagingQuarantine, "run-0001", "run", "platform", "ownership-normalization.json")); err != nil {
		t.Fatalf("expected stage root preserved in staging quarantine root: %v", err)
	}
}

func TestRemoteAlphaESWritableStateOwnershipRotationApplyRequiresPostApplyHealthAndContract(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	fakeBin := filepath.Join(tmpDir, "bin")
	if err := os.MkdirAll(fakeBin, 0o755); err != nil {
		t.Fatalf("mkdir fake bin: %v", err)
	}

	fixture := setupESServiceUserMigrationFixture(t, tmpDir)
	writeNormalizedESServiceUserRun(t, fixture, os.Getuid(), os.Getgid())

	summaryPath := filepath.Join(tmpDir, "apply-summary.json")
	mutationLogPath := filepath.Join(tmpDir, "mutations.log")
	backupSentinelPath := filepath.Join(tmpDir, "backup.sentinel")
	setupFakeESServiceUserMigrationCommands(t, fakeBin, fakeESServiceUserAccount{
		Present:   true,
		UID:       os.Getuid(),
		GID:       os.Getgid(),
		GroupName: "es",
	}, fixture, mutationLogPath)

	shellBody := esWritableStateOwnershipExpectedSliceShell(fixture) + fmt.Sprintf(`
remote_alpha_prepare_es_writable_state_ownership_main --apply --rotate-nonempty-roots --summary-path %q
`, summaryPath)
	output, err := runSourcedESWritableStateOwnershipHelper(t, envWithPath(fakeBin,
		"REMOTE_ALPHA_TEST_MUTATION_LOG_PATH="+mutationLogPath,
		"REMOTE_ALPHA_TEST_BACKUP_SENTINEL_PATH="+backupSentinelPath,
		"REMOTE_ALPHA_TEST_CURL_FAIL_HEALTH=true",
	), shellBody)
	if err == nil {
		t.Fatalf("expected post-apply validation failure when /health fails\noutput=%s", string(output))
	}

	summary := readJSONFile(t, summaryPath)
	if summary["overall_classification"] != "blocker" {
		t.Fatalf("expected blocker summary, got %+v", summary)
	}
	postValidation := nestedMap(t, summary, "post_apply_validation")
	if postValidation["service_stop_performed"] != true || postValidation["service_start_performed"] != true {
		t.Fatalf("expected bounded stop/start even on validation failure, got %+v", postValidation)
	}
	if nestedMap(t, postValidation, "health")["classification"] != "blocker" {
		t.Fatalf("expected health blocker, got %+v", nestedMap(t, postValidation, "health"))
	}
	if nestedMap(t, postValidation, "contract")["classification"] != "pass" {
		t.Fatalf("expected contract validation to still run, got %+v", nestedMap(t, postValidation, "contract"))
	}
}

func TestRemoteAlphaStageESWritableStateOwnershipUploadsExactHelperPaths(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	checkOnlyReportPath := filepath.Join(tmpDir, "check-only-report.json")
	applySummaryPath := filepath.Join(tmpDir, "apply-summary-template.json")
	writeESWritableStateOwnershipStageCheckOnlyReport(t, checkOnlyReportPath, goodESWritableStateOwnershipStageCheckOnlyReport())
	writeESWritableStateOwnershipStageApplySummary(t, applySummaryPath)

	h := setupFakeRemoteESWritableStateOwnershipStageHarness(t, checkOnlyReportPath, applySummaryPath)
	outputDir := filepath.Join(tmpDir, "output")

	if output, err := runRemoteAlphaESWritableStateOwnershipStageWrapper(t, h.env(), "--ssh-target", "ds@m75q-test", "--run-id", "exact-upload", "--output-dir", outputDir); err != nil {
		t.Fatalf("wrapper failed: %v\noutput=%s\nscp=%q\ninstall=%q\nuploaded=%q", err, output, readIfExists(h.scpLogPath), readIfExists(h.installLogPath), readIfExists(h.uploadLogPath))
	}

	if _, err := os.Stat(filepath.Join(outputDir, remoteAlphaESWritableStateOwnershipStageCheckOnlyArtifactName)); err != nil {
		t.Fatalf("missing check-only output: %v", err)
	}

	uploadedLines := strings.Fields(strings.TrimSpace(readIfExists(h.uploadLogPath)))
	uploaded := make(map[string]bool, len(uploadedLines))
	for _, line := range uploadedLines {
		uploaded[line] = true
	}
	for _, required := range []string{
		"/tmp/execution-substrate-es-writable-state-ownership-upload-exact-upload/scripts/remote_alpha_prepare_es_writable_state_ownership.sh",
		"/tmp/execution-substrate-es-writable-state-ownership-upload-exact-upload/scripts/internal/remote_alpha_prepare_es_writable_state_ownership.sh",
	} {
		if !uploaded[required] {
			t.Fatalf("missing uploaded path %q in %q", required, uploadedLines)
		}
	}

	fileInstalls := make([]string, 0)
	for _, line := range strings.Split(strings.TrimSpace(readIfExists(h.installLogPath)), "\n") {
		if strings.HasPrefix(line, "file\t") {
			fileInstalls = append(fileInstalls, line)
			parts := strings.Split(line, "\t")
			if len(parts) < 3 {
				t.Fatalf("unexpected install log line %q", line)
			}
			if !uploaded[parts[1]] {
				t.Fatalf("install referenced %q before it was uploaded; uploaded=%q", parts[1], uploadedLines)
			}
		}
	}
	if len(fileInstalls) != 2 {
		t.Fatalf("expected exactly two staged helper files, got %q", fileInstalls)
	}

	provenance := readJSONFile(t, filepath.Join(outputDir, remoteAlphaESWritableStateOwnershipStageHelperStagingRecordName))
	if got := provenance["staging_occurred"]; got != true {
		t.Fatalf("expected staging_occurred=true, got %v", got)
	}
	if got := provenance["checker_ran"]; got != true {
		t.Fatalf("expected checker_ran=true, got %v", got)
	}
	if got := provenance["apply_ran"]; got != false {
		t.Fatalf("expected apply_ran=false, got %v", got)
	}
}

func TestRemoteAlphaStageESWritableStateOwnershipApplyPassesRotateFlag(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	checkOnlyReportPath := filepath.Join(tmpDir, "check-only-report.json")
	applySummaryPath := filepath.Join(tmpDir, "apply-summary-template.json")
	writeESWritableStateOwnershipStageCheckOnlyReport(t, checkOnlyReportPath, goodESWritableStateOwnershipStageCheckOnlyReport())
	writeESWritableStateOwnershipStageApplySummary(t, applySummaryPath)

	h := setupFakeRemoteESWritableStateOwnershipStageHarness(t, checkOnlyReportPath, applySummaryPath)
	outputDir := filepath.Join(tmpDir, "output")

	if output, err := runRemoteAlphaESWritableStateOwnershipStageWrapper(t, h.env(), "--ssh-target", "ds@m75q-test", "--run-id", "rotate-flag", "--output-dir", outputDir, "--apply", "--rotate-nonempty-roots"); err != nil {
		t.Fatalf("wrapper failed: %v\noutput=%s\nhelper=%q\nsudo=%q", err, output, readIfExists(h.helperLogPath), readIfExists(h.sudoLogPath))
	}

	if !strings.Contains(readIfExists(h.sudoLogPath), "--rotate-nonempty-roots") {
		t.Fatalf("expected sudo invocation to include --rotate-nonempty-roots, got %q", readIfExists(h.sudoLogPath))
	}
}

func TestRemoteAlphaStageESWritableStateOwnershipApplyPassesParentTraversalFlag(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	checkOnlyReportPath := filepath.Join(tmpDir, "check-only-report.json")
	applySummaryPath := filepath.Join(tmpDir, "apply-summary-template.json")
	writeESWritableStateOwnershipStageCheckOnlyReport(t, checkOnlyReportPath, map[string]any{
		"schema_version": "execution-substrate.remote-alpha.es-writable-state-ownership-summary.v1",
		"mode": map[string]any{
			"name":         "check_only",
			"non_mutating": true,
		},
		"proof": map[string]any{
			"host_mutation_performed": false,
		},
		"plan": map[string]any{
			"apply_ready":                  false,
			"roots_nonempty_block_apply":   false,
			"rotation_apply_ready":         false,
			"parent_traversal_apply_ready": true,
		},
		"warnings": []any{
			map[string]any{"scope": "parent_traversal", "summary": "bounded parent traversal preparation is available"},
		},
		"blockers": []any{
			map[string]any{"scope": "staging_root", "summary": "parent traversal remains blocked"},
			map[string]any{"scope": "results_root", "summary": "parent traversal remains blocked"},
		},
		"overall_classification": "blocker",
	})
	writeESWritableStateOwnershipStageApplySummary(t, applySummaryPath)

	h := setupFakeRemoteESWritableStateOwnershipStageHarness(t, checkOnlyReportPath, applySummaryPath)
	outputDir := filepath.Join(tmpDir, "output")

	if output, err := runRemoteAlphaESWritableStateOwnershipStageWrapper(t, h.env(), "--ssh-target", "ds@m75q-test", "--run-id", "parent-traversal-flag", "--output-dir", outputDir, "--apply", "--fix-parent-chain"); err != nil {
		t.Fatalf("wrapper failed: %v\noutput=%s\nhelper=%q\nsudo=%q", err, output, readIfExists(h.helperLogPath), readIfExists(h.sudoLogPath))
	}

	if !strings.Contains(readIfExists(h.sudoLogPath), "--fix-parent-chain") {
		t.Fatalf("expected sudo invocation to include --fix-parent-chain, got %q", readIfExists(h.sudoLogPath))
	}
	if _, err := os.Stat(filepath.Join(outputDir, remoteAlphaESWritableStateOwnershipStageApplySummaryArtifactName)); err != nil {
		t.Fatalf("missing apply summary output: %v", err)
	}
}

func TestRemoteAlphaStageESWritableStateOwnershipApplyPassesLegacyAcceptanceFlag(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	checkOnlyReportPath := filepath.Join(tmpDir, "check-only-report.json")
	applySummaryPath := filepath.Join(tmpDir, "apply-summary-template.json")
	writeESWritableStateOwnershipStageCheckOnlyReport(t, checkOnlyReportPath, map[string]any{
		"schema_version": "execution-substrate.remote-alpha.es-writable-state-ownership-summary.v1",
		"mode": map[string]any{
			"name":         "check_only",
			"non_mutating": true,
		},
		"proof": map[string]any{
			"host_mutation_performed": false,
		},
		"plan": map[string]any{
			"apply_ready":                       false,
			"roots_nonempty_block_apply":        true,
			"rotation_apply_ready":              true,
			"legacy_orphan_acceptance_required": true,
		},
		"warnings":               []any{},
		"blockers":               []any{map[string]any{"scope": "staging_root", "summary": "non-empty root requires rotation"}},
		"overall_classification": "blocker",
	})
	writeESWritableStateOwnershipStageApplySummary(t, applySummaryPath)

	h := setupFakeRemoteESWritableStateOwnershipStageHarness(t, checkOnlyReportPath, applySummaryPath)
	outputDir := filepath.Join(tmpDir, "output")

	if output, err := runRemoteAlphaESWritableStateOwnershipStageWrapper(t, h.env(), "--ssh-target", "ds@m75q-test", "--run-id", "legacy-acceptance-flag", "--output-dir", outputDir, "--apply", "--rotate-nonempty-roots", "--accept-stale-orphaned-runs"); err != nil {
		t.Fatalf("wrapper failed: %v\noutput=%s\nhelper=%q\nsudo=%q", err, output, readIfExists(h.helperLogPath), readIfExists(h.sudoLogPath))
	}

	if !strings.Contains(readIfExists(h.sudoLogPath), "--accept-stale-orphaned-runs") {
		t.Fatalf("expected sudo invocation to include --accept-stale-orphaned-runs, got %q", readIfExists(h.sudoLogPath))
	}
	if _, err := os.Stat(filepath.Join(outputDir, remoteAlphaESWritableStateOwnershipStageApplySummaryArtifactName)); err != nil {
		t.Fatalf("missing apply summary output: %v", err)
	}
}

func TestRemoteAlphaStageESWritableStateOwnershipApplyPassesReconcileArtifactsFlag(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	checkOnlyReportPath := filepath.Join(tmpDir, "check-only-report.json")
	applySummaryPath := filepath.Join(tmpDir, "apply-summary-template.json")
	writeESWritableStateOwnershipStageCheckOnlyReport(t, checkOnlyReportPath, map[string]any{
		"schema_version": "execution-substrate.remote-alpha.es-writable-state-ownership-summary.v1",
		"mode": map[string]any{
			"name":         "check_only",
			"non_mutating": true,
		},
		"proof": map[string]any{
			"host_mutation_performed": false,
		},
		"plan": map[string]any{
			"apply_ready":                         false,
			"roots_nonempty_block_apply":          false,
			"rotation_apply_ready":                false,
			"parent_traversal_apply_ready":        false,
			"artifact_reconciliation_apply_ready": true,
		},
		"warnings":               []any{map[string]any{"scope": "artifact_reconciliation", "summary": "bounded incompatible live artifact reconciliation is available"}},
		"blockers":               []any{},
		"overall_classification": "warning",
	})
	writeESWritableStateOwnershipStageApplySummary(t, applySummaryPath)

	h := setupFakeRemoteESWritableStateOwnershipStageHarness(t, checkOnlyReportPath, applySummaryPath)
	outputDir := filepath.Join(tmpDir, "output")

	if output, err := runRemoteAlphaESWritableStateOwnershipStageWrapper(t, h.env(), "--ssh-target", "ds@m75q-test", "--run-id", "reconcile-flag", "--output-dir", outputDir, "--apply", "--reconcile-artifacts"); err != nil {
		t.Fatalf("wrapper failed: %v\noutput=%s\nhelper=%q\nsudo=%q", err, output, readIfExists(h.helperLogPath), readIfExists(h.sudoLogPath))
	}

	if !strings.Contains(readIfExists(h.sudoLogPath), "--reconcile-artifacts") {
		t.Fatalf("expected sudo invocation to include --reconcile-artifacts, got %q", readIfExists(h.sudoLogPath))
	}
	if _, err := os.Stat(filepath.Join(outputDir, remoteAlphaESWritableStateOwnershipStageApplySummaryArtifactName)); err != nil {
		t.Fatalf("missing apply summary output: %v", err)
	}
}

func TestRemoteAlphaStageESWritableStateOwnershipSudoUnavailableIsStructured(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	checkOnlyReportPath := filepath.Join(tmpDir, "check-only-report.json")
	applySummaryPath := filepath.Join(tmpDir, "apply-summary-template.json")
	writeESWritableStateOwnershipStageCheckOnlyReport(t, checkOnlyReportPath, goodESWritableStateOwnershipStageCheckOnlyReport())
	writeESWritableStateOwnershipStageApplySummary(t, applySummaryPath)

	h := setupFakeRemoteESWritableStateOwnershipStageHarness(t, checkOnlyReportPath, applySummaryPath)
	outputDir := filepath.Join(tmpDir, "output")

	output, err := runRemoteAlphaESWritableStateOwnershipStageWrapper(t, h.env(
		"FAKE_REMOTE_SUDO_PREFLIGHT_EXIT=1",
	), "--ssh-target", "ds@m75q-test", "--run-id", "sudo-unavailable", "--output-dir", outputDir)
	if err == nil {
		t.Fatalf("expected noninteractive sudo preflight failure\noutput=%q", output)
	}

	if _, err := os.Stat(h.scpLogPath); !os.IsNotExist(err) {
		t.Fatalf("scp should not run when sudo preflight fails: %v", err)
	}
	if _, err := os.Stat(h.installLogPath); !os.IsNotExist(err) {
		t.Fatalf("remote install should not run when sudo preflight fails: %v", err)
	}

	provenance := readJSONFile(t, filepath.Join(outputDir, remoteAlphaESWritableStateOwnershipStageHelperStagingRecordName))
	if got := provenance["staging_occurred"]; got != false {
		t.Fatalf("expected staging_occurred=false, got %v", got)
	}
	if got := provenance["checker_ran"]; got != false {
		t.Fatalf("expected checker_ran=false, got %v", got)
	}
	if got := provenance["sudo_unavailable"]; got != true {
		t.Fatalf("expected sudo_unavailable=true, got %v", got)
	}
	if got := provenance["wrapper_tooling_error"]; got != false {
		t.Fatalf("expected wrapper_tooling_error=false, got %v", got)
	}
	if got := provenance["failure_classification"]; got != "sudo_unavailable" {
		t.Fatalf("expected failure_classification=sudo_unavailable, got %v", got)
	}
}

func TestRemoteAlphaStageESWritableStateOwnershipMissingUploadSourceIsStructured(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	fakeBin := filepath.Join(tmpDir, "bin")
	if err := os.MkdirAll(fakeBin, 0o755); err != nil {
		t.Fatalf("mkdir fake bin: %v", err)
	}
	sshLogPath := filepath.Join(tmpDir, "ssh.log")
	scpLogPath := filepath.Join(tmpDir, "scp.log")
	writeExecutable(t, fakeBin, "ssh", fmt.Sprintf("#!/bin/sh\nprintf '%%s\\n' \"$*\" >> %q\nexit 0\n", sshLogPath))
	writeExecutable(t, fakeBin, "scp", fmt.Sprintf("#!/bin/sh\nprintf '%%s\\n' \"$*\" >> %q\nexit 0\n", scpLogPath))

	outputDir := filepath.Join(tmpDir, "output")
	shellBody := fmt.Sprintf(`
remote_alpha_prepare_es_writable_state_ownership_stage_make_local_upload_tree() {
  local upload_dir=$1
  mkdir -p "$upload_dir/scripts/internal"
  cp "${REPO_ROOT}/scripts/internal/remote_alpha_prepare_es_writable_state_ownership.sh" "$upload_dir/scripts/internal/remote_alpha_prepare_es_writable_state_ownership.sh"
}
remote_alpha_prepare_es_writable_state_ownership_stage_main --ssh-target fake-target --run-id missing-upload-source --output-dir %q
`, outputDir)
	output, err := runSourcedESWritableStateOwnershipHelper(t, envWithPath(fakeBin), shellBody)
	if err == nil {
		t.Fatalf("expected missing upload source failure\noutput=%q", output)
	}
	if strings.Contains(string(output), "cannot stat") {
		t.Fatalf("expected structured wrapper error, got raw install failure: %q", output)
	}
	if _, err := os.Stat(sshLogPath); !os.IsNotExist(err) {
		t.Fatalf("ssh should not run when the local upload tree is invalid: %v", err)
	}
	if _, err := os.Stat(scpLogPath); !os.IsNotExist(err) {
		t.Fatalf("scp should not run when the local upload tree is invalid: %v", err)
	}

	provenance := readJSONFile(t, filepath.Join(outputDir, remoteAlphaESWritableStateOwnershipStageHelperStagingRecordName))
	if got := provenance["wrapper_tooling_error"]; got != true {
		t.Fatalf("expected wrapper_tooling_error=true, got %v", got)
	}
	if got := provenance["failure_classification"]; got != "wrapper_tooling_error" {
		t.Fatalf("expected failure_classification=wrapper_tooling_error, got %v", got)
	}
	if got := provenance["staging_occurred"]; got != false {
		t.Fatalf("expected staging_occurred=false, got %v", got)
	}
	if got := provenance["checker_ran"]; got != false {
		t.Fatalf("expected checker_ran=false, got %v", got)
	}
	if got := provenance["apply_ran"]; got != false {
		t.Fatalf("expected apply_ran=false, got %v", got)
	}
}

func TestRemoteAlphaStageESWritableStateOwnershipInstallFailureRecordsCleanupAndSkipsApply(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	checkOnlyReportPath := filepath.Join(tmpDir, "check-only-report.json")
	applySummaryPath := filepath.Join(tmpDir, "apply-summary-template.json")
	writeESWritableStateOwnershipStageCheckOnlyReport(t, checkOnlyReportPath, goodESWritableStateOwnershipStageCheckOnlyReport())
	writeESWritableStateOwnershipStageApplySummary(t, applySummaryPath)

	h := setupFakeRemoteESWritableStateOwnershipStageHarness(t, checkOnlyReportPath, applySummaryPath)
	outputDir := filepath.Join(tmpDir, "output")

	output, err := runRemoteAlphaESWritableStateOwnershipStageWrapper(t, h.env(
		"FAKE_REMOTE_INSTALL_FAIL_ON=/scripts/remote_alpha_prepare_es_writable_state_ownership.sh",
	), "--ssh-target", "ds@m75q-test", "--run-id", "install-failure", "--output-dir", outputDir)
	if err == nil {
		t.Fatalf("expected staged install failure\noutput=%q", output)
	}

	provenance := readJSONFile(t, filepath.Join(outputDir, remoteAlphaESWritableStateOwnershipStageHelperStagingRecordName))
	if got := provenance["wrapper_tooling_error"]; got != true {
		t.Fatalf("expected wrapper_tooling_error=true, got %v", got)
	}
	if got := provenance["failure_classification"]; got != "wrapper_tooling_error" {
		t.Fatalf("expected failure_classification=wrapper_tooling_error, got %v", got)
	}
	if got := provenance["remote_cleanup_completed"]; got != true {
		t.Fatalf("expected remote_cleanup_completed=true, got %v", got)
	}
	if got := provenance["transient_staging_removed"]; got != true {
		t.Fatalf("expected transient_staging_removed=true, got %v", got)
	}
	if got := provenance["apply_ran"]; got != false {
		t.Fatalf("expected apply_ran=false, got %v", got)
	}
	if got := provenance["checker_ran"]; got != false {
		t.Fatalf("expected checker_ran=false, got %v", got)
	}

	if helperLog := strings.TrimSpace(readIfExists(h.helperLogPath)); helperLog != "<missing>" && helperLog != "" {
		t.Fatalf("helper should not run after staged install failure, got %q", helperLog)
	}

	remoteUploadRoot := fakeRemotePath(h.remoteRoot, "/tmp/execution-substrate-es-writable-state-ownership-upload-install-failure")
	if _, err := os.Stat(remoteUploadRoot); !os.IsNotExist(err) {
		t.Fatalf("upload root should be removed after install failure cleanup: %v", err)
	}
	remoteStageRoot := fakeRemotePath(h.remoteRoot, remoteAlphaESWritableStateOwnershipStageDefaultStagingRoot+"/install-failure")
	if _, err := os.Stat(remoteStageRoot); !os.IsNotExist(err) {
		t.Fatalf("staging root should be removed after install failure cleanup: %v", err)
	}
}
