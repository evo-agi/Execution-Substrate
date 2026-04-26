package executionsubstrate_test

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const remoteAlphaStageWritableStateDefaultStagingRoot = "/var/tmp/execution-substrate-remote-alpha/helper-staging"
const remoteAlphaStageWritableStateArtifactName = "es-writable-state-readiness.json"
const remoteAlphaStageWritableStateHelperStagingRecordName = "es-writable-state-readiness-helper-staging-record.json"

type fakeRemoteWritableStateStageHarness struct {
	localBin         string
	remoteBin        string
	remoteRoot       string
	sshLogPath       string
	scpLogPath       string
	sudoLogPath      string
	installLogPath   string
	helperLogPath    string
	statVerifiedPath string
	metadataPath     string
}

func goodWritableStateStageReport(mode, overall string) map[string]any {
	future := mode == "future-non-root-required"
	blockers := make([]any, 0)
	warnings := make([]any, 0)
	targetOwnerStatus := "unverified"
	runtimeClassification := "pass"
	runtimeSummary := "normalization evidence is structurally valid"

	switch overall {
	case "blocker":
		blockers = append(blockers, map[string]any{
			"scope":   "runtime_normalization_contract_status",
			"summary": "future non-root-required readiness blockers remain",
		})
		targetOwnerStatus = "mismatch"
		runtimeClassification = "blocker"
		runtimeSummary = "future non-root-required readiness remains blocked"
	case "warning":
		warnings = append(warnings, map[string]any{
			"scope":   "runtime_normalization_contract_status",
			"summary": "alpha-compatible marker evidence remains unverified",
		})
		runtimeClassification = "warning"
		runtimeSummary = "alpha-compatible evidence is present but not future-ready proof"
	case "pass":
		if future {
			targetOwnerStatus = "verified"
		}
	default:
		runtimeClassification = "not_observed"
		runtimeSummary = "no normalization evidence was observed"
	}

	return map[string]any{
		"schema_version":           "execution-substrate.remote-alpha.es-writable-state-readiness.v1",
		"checked_at":               "2026-04-25T14:00:00Z",
		"operation_mode":           "check_only",
		"non_mutating":             true,
		"checker_mode":             mode,
		"future_non_root_required": future,
		"future_non_root_ready":    future && overall == "pass",
		"marker_presence_policy": map[string]any{
			"mode": strings.ReplaceAll(mode, "-", "_"),
			"missing_marker_classification": func() string {
				if future {
					return "blocker"
				}
				return "warning"
			}(),
			"present_invalid_classification": "blocker",
			"expected_owner_required":        future,
			"summary":                        "repo-local test report",
		},
		"target_owner_verification": map[string]any{
			"status":                         targetOwnerStatus,
			"summary":                        "repo-local test target-owner status",
			"checked_against_expected_owner": future,
		},
		"blockers":               blockers,
		"warnings":               warnings,
		"config_path":            "/etc/execution-substrate/es.json",
		"overall_classification": overall,
		"config_status": map[string]any{
			"classification": "pass",
			"summary":        "config was readable",
		},
		"es_account_status": map[string]any{
			"classification": "pass",
			"summary":        "es account metadata was observed",
			"present":        true,
		},
		"staging_root_status": map[string]any{
			"classification": "pass",
			"summary":        "staging root is readable",
		},
		"results_root_status": map[string]any{
			"classification": "pass",
			"summary":        "results root is readable",
		},
		"retained_result_readiness_status": map[string]any{
			"classification": "pass",
			"summary":        "retained result packaging is readable",
		},
		"cleanup_readiness_status": map[string]any{
			"classification": func() string {
				if overall == "blocker" {
					return "warning"
				}
				return "pass"
			}(),
			"summary": func() string {
				if overall == "blocker" {
					return "cleanup remains blocked by future readiness findings"
				}
				return "cleanup readiness is available"
			}(),
		},
		"runtime_normalization_contract_status": map[string]any{
			"classification": runtimeClassification,
			"summary":        runtimeSummary,
		},
		"bounded_compatibility_edges": []any{
			map[string]any{
				"name":           "root_start_runtime_helper",
				"classification": "warning",
				"summary":        "compatibility edge remains explicit",
			},
		},
	}
}

func writeWritableStateStageReport(t *testing.T, path string, payload map[string]any) {
	t.Helper()
	writeJSONFile(t, path, payload)
}

func setupFakeRemoteWritableStateStageHarness(t *testing.T, checkerReportPath string) *fakeRemoteWritableStateStageHarness {
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

	h := &fakeRemoteWritableStateStageHarness{
		localBin:         localBin,
		remoteBin:        remoteBin,
		remoteRoot:       remoteRoot,
		sshLogPath:       filepath.Join(tmpDir, "ssh.log"),
		scpLogPath:       filepath.Join(tmpDir, "scp.log"),
		sudoLogPath:      filepath.Join(tmpDir, "sudo.log"),
		installLogPath:   filepath.Join(tmpDir, "install.log"),
		helperLogPath:    filepath.Join(tmpDir, "helper.log"),
		statVerifiedPath: filepath.Join(tmpDir, "stat-verified"),
		metadataPath:     filepath.Join(tmpDir, "remote-metadata.json"),
	}

	writeExecutable(t, localBin, "ssh", fmt.Sprintf(`#!/usr/bin/env bash
set -euo pipefail
while [[ "${1:-}" == "-t" || "${1:-}" == "-tt" ]]; do
  printf 'tty=%%s\n' "$1" >> %q
  shift
done
target="$1"
shift
printf 'target=%%s args=%%s\n' "$target" "$*" >> %q
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
PATH="${FAKE_REMOTE_BIN}:${PATH}" /bin/bash "${script_path}" "${mapped_args[@]}"
status=$?
rm -f "${script_path}"
exit "${status}"
`, h.sshLogPath, h.sshLogPath))

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
  mkdir -p "$mapped_dest"
  if [[ "$recursive" == "true" ]]; then
    cp -R "$src" "$mapped_dest"/
  else
    cp "$src" "$mapped_dest"
  fi
  exit 0
fi
echo "unsupported scp direction: $src -> $dest" >&2
exit 64
`, h.scpLogPath))

	writeExecutable(t, remoteBin, "install", fmt.Sprintf(`#!/usr/bin/env bash
set -euo pipefail
directory=false
mode="0755"
owner="root"
group="root"
args=()

set_meta() {
  python3 - "$1" "$2" "$3" "$4" %q <<'PY'
import json
import pathlib
import sys

path, owner, group, mode, meta_path = sys.argv[1:]
meta_file = pathlib.Path(meta_path)
payload = {}
if meta_file.exists():
    payload = json.loads(meta_file.read_text(encoding="utf-8"))
payload[path] = {
    "owner": owner,
    "group": group,
    "mode": mode.zfill(4),
}
meta_file.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
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
    --)
      shift
      break
      ;;
    *)
      args+=("$1")
      shift
      ;;
  esac
done

owner="${FAKE_REMOTE_STAGE_OWNER:-$owner}"
group="${FAKE_REMOTE_STAGE_GROUP:-$group}"
mode="${FAKE_REMOTE_STAGE_MODE:-$mode}"

if [[ "$directory" == "true" ]]; then
  for dest in "${args[@]}"; do
    mkdir -p "$dest"
    chmod "$mode" "$dest"
    printf 'dir\t%%s\t%%s:%%s\t%%s\n' "$dest" "$owner" "$group" "$mode" >> %q
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
mkdir -p "$(dirname "$dest")"
cp "$src" "$dest"
chmod "$mode" "$dest"
printf 'file\t%%s\t%%s\t%%s:%%s\t%%s\n' "$src" "$dest" "$owner" "$group" "$mode" >> %q
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
    if raw_path not in payload:
        raise SystemExit(f"missing fake stat metadata for {raw_path}")
    item = payload[raw_path]
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
if [[ "$#" -eq 5 ]]; then
  : > %q
fi
`, h.metadataPath, h.statVerifiedPath))

	writeExecutable(t, remoteBin, "sudo", fmt.Sprintf(`#!/usr/bin/env bash
set -euo pipefail
printf '%%s\n' "$*" >> %q

unmap_path() {
  local path=$1
  printf '%%s' "${path#"${FAKE_REMOTE_ROOT}"}"
}

if [[ "${1:-}" == */scripts/remote_alpha_check_es_writable_state_readiness.sh ]]; then
  if [[ ! -f %q ]]; then
    echo "checker execution started before root-owned staging verification" >&2
    exit 97
  fi

  checker_mode="alpha-compat"
  config_path=""
  args=("$@")
  for ((i=0; i<${#args[@]}; i++)); do
    case "${args[$i]}" in
      --mode)
        if (( i + 1 < ${#args[@]} )); then
          checker_mode="${args[$((i + 1))]}"
        fi
        ;;
      --config-path)
        if (( i + 1 < ${#args[@]} )); then
          config_path="${args[$((i + 1))]}"
        fi
        ;;
    esac
  done

  printf 'checker\t%%s\t%%s\n' "$checker_mode" "$(unmap_path "${config_path}")" >> %q
  cat "${FAKE_REMOTE_CHECKER_REPORT}"
  exit "${FAKE_REMOTE_CHECKER_EXIT:-0}"
fi

exec "$@"
`, h.sudoLogPath, h.statVerifiedPath, h.helperLogPath))

	return h
}

func (h *fakeRemoteWritableStateStageHarness) env(extra ...string) []string {
	base := []string{
		"FAKE_REMOTE_BIN=" + h.remoteBin,
		"FAKE_REMOTE_ROOT=" + h.remoteRoot,
		"FAKE_REMOTE_CHECKER_EXIT=0",
	}
	return envWithPath(h.localBin, append(base, extra...)...)
}

func runRemoteAlphaWritableStateStageWrapper(t *testing.T, env []string, args ...string) ([]byte, error) {
	t.Helper()
	scriptPath := filepath.Join(executionSubstrateRepoRoot, "scripts", "remote_alpha_stage_es_writable_state_readiness_check.sh")
	cmd := exec.Command("/bin/bash", append([]string{scriptPath}, args...)...)
	cmd.Dir = executionSubstrateRepoRoot
	cmd.Env = env
	return cmd.CombinedOutput()
}

func TestRemoteAlphaStageESWritableStateReadinessDefaultModeIsAlphaCompat(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	reportPath := filepath.Join(tmpDir, "checker-report.json")
	writeWritableStateStageReport(t, reportPath, goodWritableStateStageReport("alpha-compat", "warning"))

	h := setupFakeRemoteWritableStateStageHarness(t, reportPath)
	outputDir := filepath.Join(tmpDir, "output")

	output, err := runRemoteAlphaWritableStateStageWrapper(t, h.env("FAKE_REMOTE_CHECKER_REPORT="+reportPath), "--ssh-target", "ds@m75q-test", "--run-id", "default-mode", "--output-dir", outputDir)
	if err != nil {
		t.Fatalf("wrapper failed: %v\noutput=%q\nrecord=%q\nssh=%q\nscp=%q\nsudo=%q\ninstall=%q\nhelper=%q", err, output, readIfExists(filepath.Join(outputDir, remoteAlphaStageWritableStateHelperStagingRecordName)), readIfExists(h.sshLogPath), readIfExists(h.scpLogPath), readIfExists(h.sudoLogPath), readIfExists(h.installLogPath), readIfExists(h.helperLogPath))
	}

	readinessOutputPath := filepath.Join(outputDir, remoteAlphaStageWritableStateArtifactName)
	if got := strings.TrimSpace(string(output)); got != readinessOutputPath {
		t.Fatalf("unexpected wrapper output %q", got)
	}
	report := readJSONFile(t, readinessOutputPath)
	if got := report["checker_mode"]; got != "alpha-compat" {
		t.Fatalf("unexpected checker mode %v", got)
	}

	helperLog := mustRead(t, h.helperLogPath)
	if !strings.Contains(helperLog, "checker\talpha-compat\t/etc/execution-substrate/es.json") {
		t.Fatalf("expected alpha-compat checker invocation, got %q", helperLog)
	}

	provenance := readJSONFile(t, filepath.Join(outputDir, remoteAlphaStageWritableStateHelperStagingRecordName))
	if got := provenance["requested_checker_mode"]; got != "alpha-compat" {
		t.Fatalf("unexpected requested checker mode %v", got)
	}
	checker := jsonMap(t, provenance["checker"])
	if got := checker["checker_mode"]; got != "alpha-compat" {
		t.Fatalf("unexpected checker summary mode %v", got)
	}
}

func TestRemoteAlphaStageESWritableStateReadinessFutureModeIsPassedThrough(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	reportPath := filepath.Join(tmpDir, "checker-report.json")
	writeWritableStateStageReport(t, reportPath, goodWritableStateStageReport("future-non-root-required", "warning"))

	h := setupFakeRemoteWritableStateStageHarness(t, reportPath)
	outputDir := filepath.Join(tmpDir, "output")

	output, err := runRemoteAlphaWritableStateStageWrapper(t, h.env("FAKE_REMOTE_CHECKER_REPORT="+reportPath), "--ssh-target", "ds@m75q-test", "--run-id", "future-mode", "--output-dir", outputDir, "--mode", "future-non-root-required")
	if err != nil {
		t.Fatalf("wrapper failed: %v\noutput=%q", err, output)
	}

	readinessOutputPath := filepath.Join(outputDir, remoteAlphaStageWritableStateArtifactName)
	if got := strings.TrimSpace(string(output)); got != readinessOutputPath {
		t.Fatalf("unexpected wrapper output %q", got)
	}
	report := readJSONFile(t, readinessOutputPath)
	if got := report["checker_mode"]; got != "future-non-root-required" {
		t.Fatalf("unexpected checker mode %v", got)
	}
	if got := report["future_non_root_required"]; got != true {
		t.Fatalf("expected future_non_root_required=true, got %v", got)
	}

	helperLog := mustRead(t, h.helperLogPath)
	if !strings.Contains(helperLog, "checker\tfuture-non-root-required\t/etc/execution-substrate/es.json") {
		t.Fatalf("expected future-mode checker invocation, got %q", helperLog)
	}
}

func TestRemoteAlphaStageESWritableStateReadinessStagesOnlyMinimalHelperFiles(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	reportPath := filepath.Join(tmpDir, "checker-report.json")
	writeWritableStateStageReport(t, reportPath, goodWritableStateStageReport("alpha-compat", "pass"))

	h := setupFakeRemoteWritableStateStageHarness(t, reportPath)
	outputDir := filepath.Join(tmpDir, "output")

	if output, err := runRemoteAlphaWritableStateStageWrapper(t, h.env("FAKE_REMOTE_CHECKER_REPORT="+reportPath), "--ssh-target", "ds@m75q-test", "--run-id", "minimal-files", "--output-dir", outputDir); err != nil {
		t.Fatalf("wrapper failed: %v\n%s", err, output)
	}

	lines := strings.Split(strings.TrimSpace(mustRead(t, h.installLogPath)), "\n")
	fileInstalls := make([]string, 0)
	for _, line := range lines {
		if strings.HasPrefix(line, "file\t") {
			fileInstalls = append(fileInstalls, line)
		}
	}
	if len(fileInstalls) != 2 {
		t.Fatalf("expected exactly two staged helper files, got %q", fileInstalls)
	}
	if !strings.Contains(strings.Join(fileInstalls, "\n"), "scripts/remote_alpha_check_es_writable_state_readiness.sh") {
		t.Fatalf("staged files did not include the public checker wrapper: %q", fileInstalls)
	}
	if !strings.Contains(strings.Join(fileInstalls, "\n"), "scripts/internal/remote_alpha_check_es_writable_state_readiness.sh") {
		t.Fatalf("staged files did not include the sourced internal helper: %q", fileInstalls)
	}
	if strings.Contains(strings.Join(fileInstalls, "\n"), "remote_alpha_stage_es_writable_state_readiness_check.sh") {
		t.Fatalf("repo-side operator wrapper should not be copied to the remote host: %q", fileInstalls)
	}
}

func TestRemoteAlphaStageESWritableStateReadinessWritesIMCompatibleOutputsAndProvenance(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	reportPath := filepath.Join(tmpDir, "checker-report.json")
	writeWritableStateStageReport(t, reportPath, goodWritableStateStageReport("alpha-compat", "pass"))

	h := setupFakeRemoteWritableStateStageHarness(t, reportPath)
	outputDir := filepath.Join(tmpDir, "output")

	if output, err := runRemoteAlphaWritableStateStageWrapper(t, h.env("FAKE_REMOTE_CHECKER_REPORT="+reportPath), "--ssh-target", "ds@m75q-test", "--run-id", "provenance", "--output-dir", outputDir); err != nil {
		t.Fatalf("wrapper failed: %v\n%s", err, output)
	}

	readinessOutputPath := filepath.Join(outputDir, remoteAlphaStageWritableStateArtifactName)
	provenancePath := filepath.Join(outputDir, remoteAlphaStageWritableStateHelperStagingRecordName)
	if _, err := os.Stat(readinessOutputPath); err != nil {
		t.Fatalf("missing readiness output: %v", err)
	}
	if _, err := os.Stat(provenancePath); err != nil {
		t.Fatalf("missing helper staging record: %v", err)
	}

	provenance := readJSONFile(t, provenancePath)
	if got := provenance["schema_version"]; got != "execution-substrate.remote-alpha.es-writable-state-readiness-stage-provenance.v1" {
		t.Fatalf("unexpected schema version %v", got)
	}
	if got := provenance["git_commit"]; got == "" {
		t.Fatalf("expected git commit provenance, got %v", got)
	}
	if got := provenance["local_git_commit"]; got != provenance["git_commit"] {
		t.Fatalf("expected local_git_commit to mirror git_commit, got %v vs %v", got, provenance["git_commit"])
	}
	if got := provenance["remote_staged_path"]; got != remoteAlphaStageWritableStateDefaultStagingRoot+"/provenance" {
		t.Fatalf("unexpected remote staged path %v", got)
	}
	if got := provenance["staging_occurred"]; got != true {
		t.Fatalf("expected staging_occurred=true, got %v", got)
	}
	if got := provenance["checker_ran"]; got != true {
		t.Fatalf("expected checker_ran=true, got %v", got)
	}
	if got := provenance["transient_staging_removed"]; got != true {
		t.Fatalf("expected transient_staging_removed=true, got %v", got)
	}
	if got := provenance["staging_retained_for_diagnostics"]; got != false {
		t.Fatalf("expected staging_retained_for_diagnostics=false, got %v", got)
	}

	localOutputs := jsonMap(t, provenance["local_outputs"])
	if got := localOutputs["readiness_output_path"]; got != readinessOutputPath {
		t.Fatalf("unexpected readiness output path %v", got)
	}
	if got := localOutputs["helper_staging_record_output_path"]; got != provenancePath {
		t.Fatalf("unexpected helper staging record output path %v", got)
	}

	localFiles, ok := provenance["local_files"].([]any)
	if !ok || len(localFiles) != 2 {
		t.Fatalf("expected two local file provenance entries, got %v", provenance["local_files"])
	}
	expectedDigests := map[string]string{
		filepath.Join(executionSubstrateRepoRoot, "scripts", "remote_alpha_check_es_writable_state_readiness.sh"):             sha256File(t, filepath.Join(executionSubstrateRepoRoot, "scripts", "remote_alpha_check_es_writable_state_readiness.sh")),
		filepath.Join(executionSubstrateRepoRoot, "scripts", "internal", "remote_alpha_check_es_writable_state_readiness.sh"): sha256File(t, filepath.Join(executionSubstrateRepoRoot, "scripts", "internal", "remote_alpha_check_es_writable_state_readiness.sh")),
	}
	for _, item := range localFiles {
		entry := jsonMap(t, item)
		path, _ := entry["path"].(string)
		sha, _ := entry["sha256"].(string)
		if sha != expectedDigests[path] {
			t.Fatalf("unexpected digest for %s: %s", path, sha)
		}
	}

	stagedFiles, ok := provenance["staged_files"].([]any)
	if !ok || len(stagedFiles) != 2 {
		t.Fatalf("expected two staged helper entries, got %v", provenance["staged_files"])
	}
	expectedStagedFiles := map[string]string{
		"scripts/remote_alpha_check_es_writable_state_readiness.sh":          sha256File(t, filepath.Join(executionSubstrateRepoRoot, "scripts", "remote_alpha_check_es_writable_state_readiness.sh")),
		"scripts/internal/remote_alpha_check_es_writable_state_readiness.sh": sha256File(t, filepath.Join(executionSubstrateRepoRoot, "scripts", "internal", "remote_alpha_check_es_writable_state_readiness.sh")),
	}
	for _, item := range stagedFiles {
		entry := jsonMap(t, item)
		localPath, _ := entry["local_path"].(string)
		sha, _ := entry["sha256"].(string)
		remotePath, _ := entry["remote_path"].(string)
		if sha != expectedStagedFiles[localPath] {
			t.Fatalf("unexpected staged helper digest for %s: %s", localPath, sha)
		}
		if remotePath != remoteAlphaStageWritableStateDefaultStagingRoot+"/provenance/"+localPath {
			t.Fatalf("unexpected staged helper remote path for %s: %s", localPath, remotePath)
		}
	}

	remoteStaging := jsonMap(t, provenance["remote_staging"])
	if got := remoteStaging["root_owned_before_execution"]; got != true {
		t.Fatalf("expected root-owned staging proof, got %v", got)
	}
	items, ok := remoteStaging["items"].([]any)
	if !ok || len(items) != 5 {
		t.Fatalf("expected five remote staged items, got %v", remoteStaging["items"])
	}
	for _, raw := range items {
		item := jsonMap(t, raw)
		if item["owner"] != "root" {
			t.Fatalf("expected root ownership, got %v", item)
		}
	}

	checker := jsonMap(t, provenance["checker"])
	if got := checker["accepted_evidence"]; got != true {
		t.Fatalf("expected accepted_evidence=true, got %v", got)
	}
	if got := checker["checker_mode_matches_requested"]; got != true {
		t.Fatalf("expected checker_mode_matches_requested=true, got %v", got)
	}
	if got := checker["blocker_count"]; got != float64(0) {
		t.Fatalf("unexpected blocker count %v", got)
	}
}

func TestRemoteAlphaStageESWritableStateReadinessPreservesBlockerEvidence(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	reportPath := filepath.Join(tmpDir, "checker-report.json")
	writeWritableStateStageReport(t, reportPath, goodWritableStateStageReport("future-non-root-required", "blocker"))

	h := setupFakeRemoteWritableStateStageHarness(t, reportPath)
	outputDir := filepath.Join(tmpDir, "output")

	output, err := runRemoteAlphaWritableStateStageWrapper(t, h.env(
		"FAKE_REMOTE_CHECKER_REPORT="+reportPath,
		"FAKE_REMOTE_CHECKER_EXIT=1",
	), "--ssh-target", "ds@m75q-test", "--run-id", "blocker-evidence", "--output-dir", outputDir, "--mode", "future-non-root-required")
	if err != nil {
		t.Fatalf("wrapper should preserve blocker evidence as success: %v\noutput=%q\nrecord=%q", err, output, readIfExists(filepath.Join(outputDir, remoteAlphaStageWritableStateHelperStagingRecordName)))
	}

	readinessOutputPath := filepath.Join(outputDir, remoteAlphaStageWritableStateArtifactName)
	report := readJSONFile(t, readinessOutputPath)
	if got := report["overall_classification"]; got != "blocker" {
		t.Fatalf("expected blocker classification, got %v", got)
	}

	provenance := readJSONFile(t, filepath.Join(outputDir, remoteAlphaStageWritableStateHelperStagingRecordName))
	if got := provenance["checker_exit_code"]; got != float64(1) {
		t.Fatalf("expected checker_exit_code=1, got %v", got)
	}
	if got := provenance["wrapper_exit_code"]; got != float64(0) {
		t.Fatalf("expected wrapper_exit_code=0, got %v", got)
	}
	checker := jsonMap(t, provenance["checker"])
	if got := checker["overall_classification"]; got != "blocker" {
		t.Fatalf("expected blocker evidence in checker summary, got %v", got)
	}
	if got := checker["blocker_count"]; got != float64(1) {
		t.Fatalf("expected blocker_count=1, got %v", got)
	}
}

func TestRemoteAlphaStageESWritableStateReadinessMalformedJSONFailsClosed(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	reportPath := filepath.Join(tmpDir, "checker-report.json")
	if err := os.WriteFile(reportPath, []byte("{not-json\n"), 0o644); err != nil {
		t.Fatalf("write malformed report: %v", err)
	}

	h := setupFakeRemoteWritableStateStageHarness(t, reportPath)
	outputDir := filepath.Join(tmpDir, "output")

	output, err := runRemoteAlphaWritableStateStageWrapper(t, h.env("FAKE_REMOTE_CHECKER_REPORT="+reportPath), "--ssh-target", "ds@m75q-test", "--run-id", "malformed-json", "--output-dir", outputDir)
	if err == nil {
		t.Fatalf("expected wrapper failure for malformed JSON\noutput=%q", output)
	}
	if !strings.Contains(string(output), "malformed checker JSON") {
		t.Fatalf("expected malformed JSON error, got %q", output)
	}

	provenance := readJSONFile(t, filepath.Join(outputDir, remoteAlphaStageWritableStateHelperStagingRecordName))
	checker := jsonMap(t, provenance["checker"])
	if got := checker["valid_json"]; got != false {
		t.Fatalf("expected valid_json=false, got %v", got)
	}
	if got := provenance["wrapper_exit_code"]; got != float64(1) {
		t.Fatalf("expected wrapper_exit_code=1, got %v", got)
	}
}

func TestRemoteAlphaStageESWritableStateReadinessNonMutatingFalseFailsClosed(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	reportPath := filepath.Join(tmpDir, "checker-report.json")
	report := goodWritableStateStageReport("alpha-compat", "pass")
	report["non_mutating"] = false
	writeWritableStateStageReport(t, reportPath, report)

	h := setupFakeRemoteWritableStateStageHarness(t, reportPath)
	outputDir := filepath.Join(tmpDir, "output")

	output, err := runRemoteAlphaWritableStateStageWrapper(t, h.env("FAKE_REMOTE_CHECKER_REPORT="+reportPath), "--ssh-target", "ds@m75q-test", "--run-id", "mutating-claim", "--output-dir", outputDir)
	if err == nil {
		t.Fatalf("expected wrapper failure when checker claims mutation\noutput=%q", output)
	}
	if !strings.Contains(string(output), "non_mutating=true") {
		t.Fatalf("expected non_mutating gate failure, got %q", output)
	}

	provenance := readJSONFile(t, filepath.Join(outputDir, remoteAlphaStageWritableStateHelperStagingRecordName))
	checker := jsonMap(t, provenance["checker"])
	if got := checker["non_mutating"]; got != false {
		t.Fatalf("expected checker summary to record non_mutating=false, got %v", got)
	}
	if got := checker["accepted_evidence"]; got != false {
		t.Fatalf("expected accepted_evidence=false, got %v", got)
	}
}

func TestRemoteAlphaStageESWritableStateReadinessStageOwnershipFailureFails(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	reportPath := filepath.Join(tmpDir, "checker-report.json")
	writeWritableStateStageReport(t, reportPath, goodWritableStateStageReport("alpha-compat", "pass"))

	h := setupFakeRemoteWritableStateStageHarness(t, reportPath)
	outputDir := filepath.Join(tmpDir, "output")

	output, err := runRemoteAlphaWritableStateStageWrapper(t, h.env(
		"FAKE_REMOTE_CHECKER_REPORT="+reportPath,
		"FAKE_REMOTE_STAGE_MODE=0777",
	), "--ssh-target", "ds@m75q-test", "--run-id", "bad-stage-mode", "--output-dir", outputDir)
	if err == nil {
		t.Fatalf("expected stage ownership or mode validation failure\noutput=%q", output)
	}
	if !strings.Contains(string(output), "staged checker helper tree failed root-owned or non-writable validation") {
		t.Fatalf("expected staging validation failure, got %q", output)
	}
	if _, err := os.Stat(h.helperLogPath); !os.IsNotExist(err) {
		t.Fatalf("checker should not run when stage ownership validation fails: %v", err)
	}

	provenance := readJSONFile(t, filepath.Join(outputDir, remoteAlphaStageWritableStateHelperStagingRecordName))
	if got := provenance["checker_ran"]; got != false {
		t.Fatalf("expected checker_ran=false, got %v", got)
	}
	if got := provenance["sudo_or_preflight_blocker"]; got == "" {
		t.Fatalf("expected sudo_or_preflight_blocker to be recorded, got %v", got)
	}
	remoteStaging := jsonMap(t, provenance["remote_staging"])
	if got := remoteStaging["root_owned_before_execution"]; got != false {
		t.Fatalf("expected root_owned_before_execution=false, got %v", got)
	}
}

func TestRemoteAlphaStageESWritableStateReadinessCleanupBehaviorIsRecorded(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	reportPath := filepath.Join(tmpDir, "checker-report.json")
	if err := os.WriteFile(reportPath, []byte("{not-json\n"), 0o644); err != nil {
		t.Fatalf("write malformed report: %v", err)
	}

	h := setupFakeRemoteWritableStateStageHarness(t, reportPath)
	outputDir := filepath.Join(tmpDir, "output")

	output, err := runRemoteAlphaWritableStateStageWrapper(t, h.env("FAKE_REMOTE_CHECKER_REPORT="+reportPath), "--ssh-target", "ds@m75q-test", "--run-id", "keep-staging", "--output-dir", outputDir, "--keep-staging-on-failure")
	if err == nil {
		t.Fatalf("expected wrapper failure for malformed JSON\noutput=%q", output)
	}

	remoteStagePath := fakeRemotePath(h.remoteRoot, remoteAlphaStageWritableStateDefaultStagingRoot+"/keep-staging")
	if _, err := os.Stat(remoteStagePath); err != nil {
		t.Fatalf("expected remote staged helper tree to be retained for diagnostics: %v", err)
	}

	provenance := readJSONFile(t, filepath.Join(outputDir, remoteAlphaStageWritableStateHelperStagingRecordName))
	if got := provenance["transient_staging_removed"]; got != false {
		t.Fatalf("expected transient_staging_removed=false, got %v", got)
	}
	if got := provenance["staging_retained_for_diagnostics"]; got != true {
		t.Fatalf("expected staging_retained_for_diagnostics=true, got %v", got)
	}
}

func TestRemoteAlphaStageESWritableStateReadinessDoesNotRunGovernedProof(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	reportPath := filepath.Join(tmpDir, "checker-report.json")
	writeWritableStateStageReport(t, reportPath, goodWritableStateStageReport("alpha-compat", "pass"))

	h := setupFakeRemoteWritableStateStageHarness(t, reportPath)
	outputDir := filepath.Join(tmpDir, "output")

	if output, err := runRemoteAlphaWritableStateStageWrapper(t, h.env("FAKE_REMOTE_CHECKER_REPORT="+reportPath), "--ssh-target", "ds@m75q-test", "--run-id", "no-proof", "--output-dir", outputDir); err != nil {
		t.Fatalf("wrapper failed: %v\n%s", err, output)
	}

	combinedLogs := strings.Join([]string{
		mustRead(t, h.sshLogPath),
		mustRead(t, h.scpLogPath),
		mustRead(t, h.sudoLogPath),
		mustRead(t, h.helperLogPath),
	}, "\n")
	for _, forbidden := range []string{
		"73_supported_local_proof.sh",
		"scripts/73_supported_local_proof.sh",
		"governed proof",
		"/v1/executions:submit",
	} {
		if strings.Contains(combinedLogs, forbidden) {
			t.Fatalf("wrapper should not run governed proof, found %q in logs %q", forbidden, combinedLogs)
		}
	}
}
