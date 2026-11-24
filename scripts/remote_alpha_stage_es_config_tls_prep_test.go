package scripts_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const remoteAlphaStageDefaultSummaryPath = "/var/tmp/execution-substrate-remote-alpha/es-config-tls-prep-summary.json"
const remoteAlphaStageDefaultStagingRoot = "/var/tmp/execution-substrate-remote-alpha/helper-staging"
const remoteAlphaStageCheckOnlyArtifactName = "es-config-tls-check-only.json"
const remoteAlphaStageApplySummaryArtifactName = "es-config-tls-apply-summary.json"
const remoteAlphaStageApplyStdoutArtifactName = "es-config-tls-apply-stdout.txt"
const remoteAlphaStageHelperStagingRecordName = "es-config-tls-helper-staging-record.json"

type fakeRemoteStageHarness struct {
	localBin         string
	remoteBin        string
	remoteRoot       string
	sshLogPath       string
	scpLogPath       string
	uploadLogPath    string
	sudoLogPath      string
	installLogPath   string
	helperLogPath    string
	statVerifiedPath string
	metadataPath     string
}

func fakeRemotePath(root, remotePath string) string {
	return filepath.Join(root, strings.TrimPrefix(remotePath, "/"))
}

func sha256File(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func readIfExists(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return "<missing>"
	}
	return string(data)
}

func writeJSONFile(t *testing.T, path string, payload any) {
	t.Helper()
	data, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		t.Fatalf("marshal %s: %v", path, err)
	}
	if err := os.WriteFile(path, append(data, '\n'), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func remoteAlphaStageAllowedPaths(summaryPath string) []string {
	return []string{
		"/etc/execution-substrate/es.json",
		"/etc/execution-substrate/es-tls",
		"/etc/execution-substrate/es-tls/es-server-cert.pem",
		"/etc/execution-substrate/es-tls/es-server-key.pem",
		summaryPath,
	}
}

func writeStageCheckOnlyReport(t *testing.T, path string, payload map[string]any) {
	t.Helper()
	writeJSONFile(t, path, payload)
}

func goodStageCheckOnlyReport(summaryPath string) map[string]any {
	return map[string]any{
		"plan": map[string]any{
			"blockers":      []string{},
			"paths_written": remoteAlphaStageAllowedPaths(summaryPath),
			"service_identity_would_remain_root_default": true,
		},
		"validation": map[string]any{
			"config_rewrite_scope": map[string]any{
				"status": "pass",
			},
		},
		"result": map[string]any{
			"ok":           true,
			"non_mutating": true,
		},
	}
}

func writeStageApplySummary(t *testing.T, path string) {
	t.Helper()
	writeJSONFile(t, path, map[string]any{
		"schema_version": "execution-substrate.remote-alpha.es-config-tls-prep-summary.v1",
		"result": map[string]any{
			"ok": true,
		},
	})
}

func setupFakeRemoteStageHarness(t *testing.T, checkOnlyReportPath, applySummaryPath string) *fakeRemoteStageHarness {
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
	if err := os.MkdirAll(filepath.Join(remoteRoot, "tmp"), 0o755); err != nil {
		t.Fatalf("mkdir remote root: %v", err)
	}

	h := &fakeRemoteStageHarness{
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

if [[ "${1:-}" == */scripts/remote_alpha_prepare_es_config_tls.sh ]]; then
  if [[ ! -f %q ]]; then
    echo "helper execution started before root-owned staging verification" >&2
    exit 97
  fi

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
    printf 'check_only\t%%s\n' "$(unmap_path "${summary_path}")" >> %q
    cat %q
    exit "${FAKE_REMOTE_CHECK_ONLY_EXIT:-0}"
  fi

  printf 'apply\t%%s\n' "$(unmap_path "${summary_path}")" >> %q
  if [[ -n "${summary_path}" && -f %q ]]; then
    mkdir -p "$(dirname "${summary_path}")"
    cp %q "${summary_path}"
  fi
  printf '%%s\n' "$(unmap_path "${summary_path}")"
  exit "${FAKE_REMOTE_APPLY_EXIT:-0}"
fi

exec "$@"
`, h.sudoLogPath, h.statVerifiedPath, h.helperLogPath, checkOnlyReportPath, h.helperLogPath, applySummaryPath, applySummaryPath))

	return h
}

func (h *fakeRemoteStageHarness) env(extra ...string) []string {
	base := []string{
		"FAKE_REMOTE_BIN=" + h.remoteBin,
		"FAKE_REMOTE_ROOT=" + h.remoteRoot,
		"FAKE_REMOTE_CHECK_ONLY_EXIT=0",
		"FAKE_REMOTE_APPLY_EXIT=0",
	}
	return envWithPath(h.localBin, append(base, extra...)...)
}

func runRemoteAlphaStageWrapper(t *testing.T, env []string, args ...string) ([]byte, error) {
	t.Helper()
	scriptPath := filepath.Join(executionSubstrateRepoRoot, "scripts", "remote_alpha_stage_es_config_tls_prep.sh")
	cmd := exec.Command("/bin/bash", append([]string{scriptPath}, args...)...)
	cmd.Dir = executionSubstrateRepoRoot
	cmd.Env = env
	return cmd.CombinedOutput()
}

func TestRemoteAlphaStageESConfigTLSPrepCheckOnlyIsDefault(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	checkOnlyReportPath := filepath.Join(tmpDir, "check-only-report.json")
	applySummaryPath := filepath.Join(tmpDir, "apply-summary-template.json")
	writeStageCheckOnlyReport(t, checkOnlyReportPath, goodStageCheckOnlyReport(remoteAlphaStageDefaultSummaryPath))
	writeStageApplySummary(t, applySummaryPath)

	h := setupFakeRemoteStageHarness(t, checkOnlyReportPath, applySummaryPath)
	outputDir := filepath.Join(tmpDir, "output")

	output, err := runRemoteAlphaStageWrapper(t, h.env(), "--ssh-target", "ds@m75q-test", "--run-id", "check-default", "--output-dir", outputDir)
	if err != nil {
		t.Fatalf("wrapper failed: %v\noutput=%q\nhelper_record=%q\nssh=%q\nscp=%q\nsudo=%q\ninstall=%q\nhelper=%q", err, output, readIfExists(filepath.Join(outputDir, remoteAlphaStageHelperStagingRecordName)), readIfExists(h.sshLogPath), readIfExists(h.scpLogPath), readIfExists(h.sudoLogPath), readIfExists(h.installLogPath), readIfExists(h.helperLogPath))
	}

	checkOutputPath := filepath.Join(outputDir, remoteAlphaStageCheckOnlyArtifactName)
	if got := strings.TrimSpace(string(output)); got != checkOutputPath {
		t.Fatalf("unexpected wrapper output %q", got)
	}
	if _, err := os.Stat(checkOutputPath); err != nil {
		t.Fatalf("missing check-only output: %v", err)
	}
	if _, err := os.Stat(filepath.Join(outputDir, remoteAlphaStageHelperStagingRecordName)); err != nil {
		t.Fatalf("missing helper staging record output: %v", err)
	}

	helperLog := mustRead(t, h.helperLogPath)
	if !strings.Contains(helperLog, "check_only\t"+remoteAlphaStageDefaultSummaryPath) {
		t.Fatalf("expected check-only invocation, got %q", helperLog)
	}
	if strings.Contains(helperLog, "apply\t") {
		t.Fatalf("did not expect apply invocation, got %q", helperLog)
	}

	provenance := readJSONFile(t, filepath.Join(outputDir, remoteAlphaStageHelperStagingRecordName))
	if got := provenance["command_mode"]; got != "check_only" {
		t.Fatalf("unexpected command mode %v", got)
	}

	if _, err := os.Stat(filepath.Join(outputDir, remoteAlphaStageApplySummaryArtifactName)); !os.IsNotExist(err) {
		t.Fatalf("apply summary should not exist in default check-only mode: %v", err)
	}
	if _, err := os.Stat(filepath.Join(outputDir, remoteAlphaStageApplyStdoutArtifactName)); !os.IsNotExist(err) {
		t.Fatalf("apply stdout should not exist in default check-only mode: %v", err)
	}

	remoteStagePath := fakeRemotePath(h.remoteRoot, remoteAlphaStageDefaultStagingRoot+"/check-default")
	if _, err := os.Stat(remoteStagePath); !os.IsNotExist(err) {
		t.Fatalf("staging root should be removed after successful check-only run: %v", err)
	}
}

func TestRemoteAlphaStageESConfigTLSPrepApplyRunsOnlyWithExplicitFlag(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	checkOnlyReportPath := filepath.Join(tmpDir, "check-only-report.json")
	applySummaryPath := filepath.Join(tmpDir, "apply-summary-template.json")
	writeStageCheckOnlyReport(t, checkOnlyReportPath, goodStageCheckOnlyReport(remoteAlphaStageDefaultSummaryPath))
	writeStageApplySummary(t, applySummaryPath)

	h := setupFakeRemoteStageHarness(t, checkOnlyReportPath, applySummaryPath)
	outputDir := filepath.Join(tmpDir, "output")

	output, err := runRemoteAlphaStageWrapper(t, h.env(), "--ssh-target", "ds@m75q-test", "--run-id", "apply-explicit", "--output-dir", outputDir, "--apply")
	if err != nil {
		t.Fatalf("wrapper failed: %v\n%s", err, output)
	}

	applySummaryOutputPath := filepath.Join(outputDir, remoteAlphaStageApplySummaryArtifactName)
	if got := strings.TrimSpace(string(output)); got != applySummaryOutputPath {
		t.Fatalf("unexpected wrapper output %q", got)
	}
	if _, err := os.Stat(applySummaryOutputPath); err != nil {
		t.Fatalf("missing apply summary output: %v", err)
	}
	if _, err := os.Stat(filepath.Join(outputDir, remoteAlphaStageApplyStdoutArtifactName)); err != nil {
		t.Fatalf("missing apply stdout output: %v", err)
	}
	if _, err := os.Stat(filepath.Join(outputDir, remoteAlphaStageCheckOnlyArtifactName)); err != nil {
		t.Fatalf("missing saved check-only output during apply: %v", err)
	}
	if _, err := os.Stat(filepath.Join(outputDir, remoteAlphaStageHelperStagingRecordName)); err != nil {
		t.Fatalf("missing helper staging record output: %v", err)
	}

	helperLogLines := strings.Split(strings.TrimSpace(mustRead(t, h.helperLogPath)), "\n")
	if len(helperLogLines) != 2 {
		t.Fatalf("expected check-only then apply, got %q", helperLogLines)
	}
	if !strings.HasPrefix(helperLogLines[0], "check_only\t") {
		t.Fatalf("expected first helper invocation to be check-only, got %q", helperLogLines[0])
	}
	if !strings.HasPrefix(helperLogLines[1], "apply\t") {
		t.Fatalf("expected second helper invocation to be apply, got %q", helperLogLines[1])
	}
}

func TestRemoteAlphaStageESConfigTLSPrepStagesOnlyMinimalHelperFiles(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	checkOnlyReportPath := filepath.Join(tmpDir, "check-only-report.json")
	applySummaryPath := filepath.Join(tmpDir, "apply-summary-template.json")
	writeStageCheckOnlyReport(t, checkOnlyReportPath, goodStageCheckOnlyReport(remoteAlphaStageDefaultSummaryPath))
	writeStageApplySummary(t, applySummaryPath)

	h := setupFakeRemoteStageHarness(t, checkOnlyReportPath, applySummaryPath)
	outputDir := filepath.Join(tmpDir, "output")

	if output, err := runRemoteAlphaStageWrapper(t, h.env(), "--ssh-target", "ds@m75q-test", "--run-id", "minimal-files", "--output-dir", outputDir); err != nil {
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
	if !strings.Contains(fileInstalls[0], "remote_alpha_prepare_es_config_tls.sh") && !strings.Contains(fileInstalls[1], "remote_alpha_prepare_es_config_tls.sh") {
		t.Fatalf("staged files did not include the wrapper helper: %q", fileInstalls)
	}
	if !strings.Contains(strings.Join(fileInstalls, "\n"), "scripts/internal/remote_alpha_prepare_es_config_tls.sh") {
		t.Fatalf("staged files did not include the sourced internal helper: %q", fileInstalls)
	}
	if strings.Contains(strings.Join(fileInstalls, "\n"), "remote_alpha_stage_es_config_tls_prep.sh") {
		t.Fatalf("repo-side operator wrapper should not be copied to the remote host: %q", fileInstalls)
	}
}

func TestRemoteAlphaStageESConfigTLSPrepWritesHelperStagingRecord(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	checkOnlyReportPath := filepath.Join(tmpDir, "check-only-report.json")
	applySummaryPath := filepath.Join(tmpDir, "apply-summary-template.json")
	writeStageCheckOnlyReport(t, checkOnlyReportPath, goodStageCheckOnlyReport(remoteAlphaStageDefaultSummaryPath))
	writeStageApplySummary(t, applySummaryPath)

	h := setupFakeRemoteStageHarness(t, checkOnlyReportPath, applySummaryPath)
	outputDir := filepath.Join(tmpDir, "output")

	if output, err := runRemoteAlphaStageWrapper(t, h.env(), "--ssh-target", "ds@m75q-test", "--run-id", "provenance", "--output-dir", outputDir); err != nil {
		t.Fatalf("wrapper failed: %v\n%s", err, output)
	}

	provenancePath := filepath.Join(outputDir, remoteAlphaStageHelperStagingRecordName)
	provenance := readJSONFile(t, provenancePath)

	if got := provenance["schema_version"]; got != "execution-substrate.remote-alpha.es-config-tls-prep-stage-provenance.v1" {
		t.Fatalf("unexpected schema version %v", got)
	}
	if got := provenance["command_mode"]; got != "check_only" {
		t.Fatalf("unexpected command mode %v", got)
	}
	if got := provenance["ssh_target"]; got != "ds@m75q-test" {
		t.Fatalf("unexpected ssh target %v", got)
	}
	if got := provenance["git_commit"]; got == "" {
		t.Fatalf("expected git commit provenance, got %v", got)
	}
	if got := provenance["local_git_commit"]; got != provenance["git_commit"] {
		t.Fatalf("expected local_git_commit to mirror git_commit, got %v vs %v", got, provenance["git_commit"])
	}

	localFiles, ok := provenance["local_files"].([]any)
	if !ok {
		t.Fatalf("expected local_files array, got %T", provenance["local_files"])
	}
	if len(localFiles) != 2 {
		t.Fatalf("expected two local file provenance entries, got %d", len(localFiles))
	}

	expectedDigests := map[string]string{
		filepath.Join(executionSubstrateRepoRoot, "scripts", "remote_alpha_prepare_es_config_tls.sh"):             sha256File(t, filepath.Join(executionSubstrateRepoRoot, "scripts", "remote_alpha_prepare_es_config_tls.sh")),
		filepath.Join(executionSubstrateRepoRoot, "scripts", "internal", "remote_alpha_prepare_es_config_tls.sh"): sha256File(t, filepath.Join(executionSubstrateRepoRoot, "scripts", "internal", "remote_alpha_prepare_es_config_tls.sh")),
	}

	for _, item := range localFiles {
		entry := jsonMap(t, item)
		path, _ := entry["path"].(string)
		sha, _ := entry["sha256"].(string)
		if sha != expectedDigests[path] {
			t.Fatalf("unexpected digest for %s: %s", path, sha)
		}
	}

	if got := provenance["remote_staged_path"]; got != remoteAlphaStageDefaultStagingRoot+"/provenance" {
		t.Fatalf("unexpected remote staged path %v", got)
	}
	stagedFiles, ok := provenance["staged_files"].([]any)
	if !ok {
		t.Fatalf("expected staged_files array, got %T", provenance["staged_files"])
	}
	if len(stagedFiles) != 2 {
		t.Fatalf("expected two staged helper entries, got %d", len(stagedFiles))
	}
	expectedStagedFiles := map[string]string{
		"scripts/remote_alpha_prepare_es_config_tls.sh":          sha256File(t, filepath.Join(executionSubstrateRepoRoot, "scripts", "remote_alpha_prepare_es_config_tls.sh")),
		"scripts/internal/remote_alpha_prepare_es_config_tls.sh": sha256File(t, filepath.Join(executionSubstrateRepoRoot, "scripts", "internal", "remote_alpha_prepare_es_config_tls.sh")),
	}
	for _, item := range stagedFiles {
		entry := jsonMap(t, item)
		localPath, _ := entry["local_path"].(string)
		sha, _ := entry["sha256"].(string)
		remotePath, _ := entry["remote_path"].(string)
		if sha != expectedStagedFiles[localPath] {
			t.Fatalf("unexpected staged helper digest for %s: %s", localPath, sha)
		}
		if remotePath != remoteAlphaStageDefaultStagingRoot+"/provenance/"+localPath {
			t.Fatalf("unexpected staged helper remote path for %s: %s", localPath, remotePath)
		}
	}

	remoteStaging := jsonMap(t, provenance["remote_staging"])
	if got := remoteStaging["staged_root"]; got != remoteAlphaStageDefaultStagingRoot+"/provenance" {
		t.Fatalf("unexpected staged root %v", got)
	}
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
}

func TestRemoteAlphaStageESConfigTLSPrepBlocksApplyWhenCheckOnlyGatesFail(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	checkOnlyReportPath := filepath.Join(tmpDir, "check-only-report.json")
	applySummaryPath := filepath.Join(tmpDir, "apply-summary-template.json")
	report := goodStageCheckOnlyReport(remoteAlphaStageDefaultSummaryPath)
	report["plan"] = map[string]any{
		"blockers":      []string{},
		"paths_written": []string{"/etc/execution-substrate/es.json", "/etc/passwd", remoteAlphaStageDefaultSummaryPath},
		"service_identity_would_remain_root_default": true,
	}
	writeStageCheckOnlyReport(t, checkOnlyReportPath, report)
	writeStageApplySummary(t, applySummaryPath)

	h := setupFakeRemoteStageHarness(t, checkOnlyReportPath, applySummaryPath)
	outputDir := filepath.Join(tmpDir, "output")

	output, err := runRemoteAlphaStageWrapper(t, h.env(), "--ssh-target", "ds@m75q-test", "--run-id", "blocked-apply", "--output-dir", outputDir, "--apply")
	if err == nil {
		t.Fatalf("expected apply to fail when check-only gates fail\n%s", output)
	}
	if !strings.Contains(string(output), "planned writes are broader than the allowed ES config/TLS prep paths") {
		t.Fatalf("expected gate failure output, got %q", output)
	}

	helperLog := mustRead(t, h.helperLogPath)
	if !strings.Contains(helperLog, "check_only\t") {
		t.Fatalf("expected check-only invocation, got %q", helperLog)
	}
	if strings.Contains(helperLog, "apply\t") {
		t.Fatalf("apply should be blocked before helper apply invocation, got %q", helperLog)
	}
	if _, err := os.Stat(filepath.Join(outputDir, remoteAlphaStageCheckOnlyArtifactName)); err != nil {
		t.Fatalf("expected saved check-only JSON even on apply gate failure: %v", err)
	}
	if _, err := os.Stat(filepath.Join(outputDir, remoteAlphaStageApplySummaryArtifactName)); !os.IsNotExist(err) {
		t.Fatalf("apply summary should not exist when apply is blocked: %v", err)
	}
}

func TestRemoteAlphaStageESConfigTLSPrepVerifiesRootOwnedStagingBeforeHelperExecution(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	checkOnlyReportPath := filepath.Join(tmpDir, "check-only-report.json")
	applySummaryPath := filepath.Join(tmpDir, "apply-summary-template.json")
	writeStageCheckOnlyReport(t, checkOnlyReportPath, goodStageCheckOnlyReport(remoteAlphaStageDefaultSummaryPath))
	writeStageApplySummary(t, applySummaryPath)

	h := setupFakeRemoteStageHarness(t, checkOnlyReportPath, applySummaryPath)
	outputDir := filepath.Join(tmpDir, "output")

	if output, err := runRemoteAlphaStageWrapper(t, h.env(), "--ssh-target", "ds@m75q-test", "--run-id", "root-owned", "--output-dir", outputDir); err != nil {
		t.Fatalf("wrapper failed: %v\n%s", err, output)
	}

	if _, err := os.Stat(h.statVerifiedPath); err != nil {
		t.Fatalf("expected staged ownership verification before helper execution: %v", err)
	}
	provenance := readJSONFile(t, filepath.Join(outputDir, remoteAlphaStageHelperStagingRecordName))
	remoteStaging := jsonMap(t, provenance["remote_staging"])
	if got := remoteStaging["root_owned_before_execution"]; got != true {
		t.Fatalf("expected root-owned staging proof, got %v", got)
	}
}

func TestRemoteAlphaStageESConfigTLSPrepDoesNotRunGovernedProof(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	checkOnlyReportPath := filepath.Join(tmpDir, "check-only-report.json")
	applySummaryPath := filepath.Join(tmpDir, "apply-summary-template.json")
	writeStageCheckOnlyReport(t, checkOnlyReportPath, goodStageCheckOnlyReport(remoteAlphaStageDefaultSummaryPath))
	writeStageApplySummary(t, applySummaryPath)

	h := setupFakeRemoteStageHarness(t, checkOnlyReportPath, applySummaryPath)
	outputDir := filepath.Join(tmpDir, "output")

	if output, err := runRemoteAlphaStageWrapper(t, h.env(), "--ssh-target", "ds@m75q-test", "--run-id", "no-proof", "--output-dir", outputDir, "--apply"); err != nil {
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
