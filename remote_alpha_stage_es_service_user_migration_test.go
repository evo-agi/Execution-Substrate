package executionsubstrate_test

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const remoteAlphaESServiceUserStageDefaultSummaryPath = "/var/tmp/execution-substrate-remote-alpha/es-service-user-migration-summary.json"
const remoteAlphaESServiceUserStageDefaultStagingRoot = "/var/tmp/execution-substrate-remote-alpha/helper-staging"
const remoteAlphaESServiceUserStageCheckOnlyArtifactName = "es-service-user-migration-check-only.json"
const remoteAlphaESServiceUserStageApplySummaryArtifactName = "es-service-user-migration-apply-summary.json"
const remoteAlphaESServiceUserStageApplyStdoutArtifactName = "es-service-user-migration-apply-stdout.txt"
const remoteAlphaESServiceUserStageHelperStagingRecordName = "es-service-user-migration-helper-staging-record.json"

func goodESServiceUserStageCheckOnlyReport() map[string]any {
	return map[string]any{
		"schema_version": "execution-substrate.remote-alpha.es-service-user-migration-summary.v1",
		"mode": map[string]any{
			"name":                    "check_only",
			"non_mutating":            true,
			"explicit_apply_required": true,
		},
		"proof": map[string]any{
			"check_only_is_not_proof": true,
			"host_mutation_performed": false,
		},
		"plan": map[string]any{
			"apply_ready":                 true,
			"planned_service_dropin_path": "/etc/systemd/system/es.service.d/10-account.conf",
			"mutation_scope":              []any{"systemd_dropin_only"},
		},
		"blockers": []any{},
		"warnings": []any{},
		"bounded_compatibility_edges": []any{
			map[string]any{
				"name":              "root_start_runtime_helper",
				"planned_unchanged": true,
			},
		},
		"not_claimed": map[string]any{
			"full_es_runtime_deroot": true,
		},
		"overall_classification": "pass",
	}
}

func writeESServiceUserStageCheckOnlyReport(t *testing.T, path string, payload map[string]any) {
	t.Helper()
	writeJSONFile(t, path, payload)
}

func writeESServiceUserStageApplySummary(t *testing.T, path string) {
	t.Helper()
	writeJSONFile(t, path, map[string]any{
		"schema_version": "execution-substrate.remote-alpha.es-service-user-migration-summary.v1",
		"result": map[string]any{
			"ok": true,
		},
	})
}

func runSourcedESServiceUserStageHelper(t *testing.T, env []string, shellBody string) ([]byte, error) {
	t.Helper()
	helperPath := filepath.Join(executionSubstrateRepoRoot, "scripts", "internal", "remote_alpha_migrate_es_service_user.sh")
	script := fmt.Sprintf("set -euo pipefail\nsource %q\n%s\n", helperPath, shellBody)
	cmd := exec.Command("/bin/bash", "-c", script)
	cmd.Dir = executionSubstrateRepoRoot
	cmd.Env = env
	return cmd.CombinedOutput()
}

func setupFakeRemoteESServiceUserStageHarness(t *testing.T, checkOnlyReportPath, applySummaryPath string) *fakeRemoteStageHarness {
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
		localBin:         localBin,
		remoteBin:        remoteBin,
		remoteRoot:       remoteRoot,
		sshLogPath:       filepath.Join(tmpDir, "ssh.log"),
		scpLogPath:       filepath.Join(tmpDir, "scp.log"),
		uploadLogPath:    filepath.Join(tmpDir, "uploaded-paths.log"),
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
export PATH="${FAKE_REMOTE_BIN}:${PATH}"
if [[ "${1:-}" == "/bin/bash" && "${2:-}" == "-s" ]]; then
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
  if ((${#mapped_args[@]} > 0)); then
    /bin/bash "${script_path}" "${mapped_args[@]}"
  else
    /bin/bash "${script_path}"
  fi
  status=$?
  rm -f "${script_path}"
  exit "${status}"
fi
if [[ "$#" -eq 1 ]]; then
  mapped_command="$(python3 - "$1" <<'PY'
import os
import shlex
import sys

command = sys.argv[1]
parts = shlex.split(command)
if len(parts) >= 4 and parts[0] == "/bin/bash" and parts[1] == "-c":
    fake_root = os.environ.get("FAKE_REMOTE_ROOT", "")
    mapped = parts[:4]
    for arg in parts[4:]:
        if arg.startswith("/"):
            mapped.append(fake_root + arg)
        else:
            mapped.append(arg)
    print(" ".join(shlex.quote(part) for part in mapped))
else:
    print(command)
PY
)"
  eval "$mapped_command"
  if [[ "${FAKE_SSH_EMIT_CONNECTION_CLOSED:-0}" == "1" ]]; then
    printf 'Connection to 192.0.2.10 closed.\n'
  fi
  exit $?
fi
echo "unexpected ssh invocation: $*" >&2
exit 64
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
if [[ "$#" -eq 7 ]]; then
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

if [[ "${1:-}" == "-n" ]]; then
  shift
fi

if [[ "${1:-}" == "-v" ]]; then
  exit "${FAKE_REMOTE_SUDO_PREFLIGHT_EXIT:-0}"
fi

if [[ "${1:-}" == "true" ]]; then
  exit "${FAKE_REMOTE_SUDO_PREFLIGHT_EXIT:-0}"
fi

if [[ "${1:-}" == */scripts/remote_alpha_migrate_es_service_user.sh ]]; then
  if [[ ! -f %q ]] && ! compgen -G "${FAKE_REMOTE_ROOT}/tmp/execution-substrate-es-service-user-artifacts-*/stage-stat.txt" >/dev/null; then
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
    printf 'check_only\t%%s\n' "${summary_path}" >> %q
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

func (h *fakeRemoteStageHarness) esServiceUserEnv(extra ...string) []string {
	base := []string{
		"FAKE_REMOTE_BIN=" + h.remoteBin,
		"FAKE_REMOTE_ROOT=" + h.remoteRoot,
		"FAKE_REMOTE_CHECK_ONLY_EXIT=0",
		"FAKE_REMOTE_APPLY_EXIT=0",
	}
	return envWithPath(h.localBin, append(base, extra...)...)
}

func runRemoteAlphaESServiceUserStageWrapper(t *testing.T, env []string, args ...string) ([]byte, error) {
	t.Helper()
	scriptPath := filepath.Join(executionSubstrateRepoRoot, "scripts", "remote_alpha_migrate_es_service_user.sh")
	cmd := exec.Command("/bin/bash", append([]string{scriptPath}, args...)...)
	cmd.Dir = executionSubstrateRepoRoot
	cmd.Env = env
	return cmd.CombinedOutput()
}

func TestRemoteAlphaStageESServiceUserMigrationCheckOnlyIsDefault(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	checkOnlyReportPath := filepath.Join(tmpDir, "check-only-report.json")
	applySummaryPath := filepath.Join(tmpDir, "apply-summary-template.json")
	writeESServiceUserStageCheckOnlyReport(t, checkOnlyReportPath, goodESServiceUserStageCheckOnlyReport())
	writeESServiceUserStageApplySummary(t, applySummaryPath)

	h := setupFakeRemoteESServiceUserStageHarness(t, checkOnlyReportPath, applySummaryPath)
	outputDir := filepath.Join(tmpDir, "output")

	output, err := runRemoteAlphaESServiceUserStageWrapper(t, h.esServiceUserEnv(), "--ssh-target", "ds@m75q-test", "--run-id", "check-default", "--output-dir", outputDir)
	if err != nil {
		t.Fatalf("wrapper failed: %v\noutput=%q\nhelper_record=%q\nssh=%q\nscp=%q\nsudo=%q\ninstall=%q\nhelper=%q", err, output, readIfExists(filepath.Join(outputDir, remoteAlphaESServiceUserStageHelperStagingRecordName)), readIfExists(h.sshLogPath), readIfExists(h.scpLogPath), readIfExists(h.sudoLogPath), readIfExists(h.installLogPath), readIfExists(h.helperLogPath))
	}

	checkOutputPath := filepath.Join(outputDir, remoteAlphaESServiceUserStageCheckOnlyArtifactName)
	if strings.TrimSpace(string(output)) != checkOutputPath {
		t.Fatalf("unexpected wrapper output %q", output)
	}
	if _, err := os.Stat(checkOutputPath); err != nil {
		t.Fatalf("missing check-only output: %v", err)
	}
	if _, err := os.Stat(filepath.Join(outputDir, remoteAlphaESServiceUserStageHelperStagingRecordName)); err != nil {
		t.Fatalf("missing helper staging record output: %v", err)
	}
	helperLog := mustRead(t, h.helperLogPath)
	if !strings.Contains(helperLog, "check_only\t") {
		t.Fatalf("expected check-only invocation, got %q", helperLog)
	}
	if strings.Contains(helperLog, "apply\t") {
		t.Fatalf("did not expect apply invocation, got %q", helperLog)
	}
	if _, err := os.Stat(filepath.Join(outputDir, remoteAlphaESServiceUserStageApplySummaryArtifactName)); !os.IsNotExist(err) {
		t.Fatalf("apply summary should not exist in default check-only mode: %v", err)
	}
	if _, err := os.Stat(filepath.Join(outputDir, remoteAlphaESServiceUserStageApplyStdoutArtifactName)); !os.IsNotExist(err) {
		t.Fatalf("apply stdout should not exist in default check-only mode: %v", err)
	}

	remoteStagePath := fakeRemotePath(h.remoteRoot, remoteAlphaESServiceUserStageDefaultStagingRoot+"/check-default")
	if _, err := os.Stat(remoteStagePath); !os.IsNotExist(err) {
		t.Fatalf("staging root should be removed after successful check-only run: %v", err)
	}
}

func TestRemoteAlphaStageESServiceUserMigrationDefaultBatchPathDoesNotForceTTY(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	checkOnlyReportPath := filepath.Join(tmpDir, "check-only-report.json")
	applySummaryPath := filepath.Join(tmpDir, "apply-summary-template.json")
	writeESServiceUserStageCheckOnlyReport(t, checkOnlyReportPath, goodESServiceUserStageCheckOnlyReport())
	writeESServiceUserStageApplySummary(t, applySummaryPath)

	h := setupFakeRemoteESServiceUserStageHarness(t, checkOnlyReportPath, applySummaryPath)
	outputDir := filepath.Join(tmpDir, "output")

	if output, err := runRemoteAlphaESServiceUserStageWrapper(t, h.esServiceUserEnv(), "--ssh-target", "ds@m75q-test", "--run-id", "no-tty", "--output-dir", outputDir); err != nil {
		t.Fatalf("wrapper failed: %v\n%s", err, output)
	}

	sshLog := mustRead(t, h.sshLogPath)
	if strings.Contains(sshLog, "tty=") {
		t.Fatalf("default batch path should not force a tty, got %q", sshLog)
	}
}

func TestRemoteAlphaStageESServiceUserMigrationInteractiveSudoFetchesRemoteArtifacts(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	checkOnlyReportPath := filepath.Join(tmpDir, "check-only-report.json")
	applySummaryPath := filepath.Join(tmpDir, "apply-summary-template.json")
	writeESServiceUserStageCheckOnlyReport(t, checkOnlyReportPath, goodESServiceUserStageCheckOnlyReport())
	writeESServiceUserStageApplySummary(t, applySummaryPath)

	h := setupFakeRemoteESServiceUserStageHarness(t, checkOnlyReportPath, applySummaryPath)
	outputDir := filepath.Join(tmpDir, "output")

	if output, err := runRemoteAlphaESServiceUserStageWrapper(t, h.esServiceUserEnv(
		"FAKE_SSH_EMIT_CONNECTION_CLOSED=1",
	), "--ssh-target", "ds@m75q-test", "--run-id", "interactive-artifacts", "--output-dir", outputDir, "--interactive-sudo"); err != nil {
		t.Fatalf("interactive wrapper failed: %v\n%s", err, output)
	}

	checkOnly := readJSONFile(t, filepath.Join(outputDir, remoteAlphaESServiceUserStageCheckOnlyArtifactName))
	if got := jsonMap(t, checkOnly["mode"])["name"]; got != "check_only" {
		t.Fatalf("expected check_only mode output, got %v", got)
	}

	sshLog := mustRead(t, h.sshLogPath)
	if got := strings.Count(sshLog, "tty="); got != 1 {
		t.Fatalf("expected exactly one tty-backed interactive ssh leg, got %d log=%q", got, sshLog)
	}

	provenance := readJSONFile(t, filepath.Join(outputDir, remoteAlphaESServiceUserStageHelperStagingRecordName))
	if got := provenance["sudo_mode"]; got != "interactive" {
		t.Fatalf("expected sudo_mode=interactive, got %v", got)
	}
	if got := provenance["staging_occurred"]; got != true {
		t.Fatalf("expected staging_occurred=true, got %v", got)
	}
	if got := provenance["transient_staging_removed"]; got != true {
		t.Fatalf("expected transient_staging_removed=true, got %v", got)
	}
}

func TestRemoteAlphaStageESServiceUserMigrationApplyRunsOnlyWithExplicitFlag(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	checkOnlyReportPath := filepath.Join(tmpDir, "check-only-report.json")
	applySummaryPath := filepath.Join(tmpDir, "apply-summary-template.json")
	writeESServiceUserStageCheckOnlyReport(t, checkOnlyReportPath, goodESServiceUserStageCheckOnlyReport())
	writeESServiceUserStageApplySummary(t, applySummaryPath)

	h := setupFakeRemoteESServiceUserStageHarness(t, checkOnlyReportPath, applySummaryPath)
	outputDir := filepath.Join(tmpDir, "output")

	output, err := runRemoteAlphaESServiceUserStageWrapper(t, h.esServiceUserEnv(), "--ssh-target", "ds@m75q-test", "--run-id", "apply-explicit", "--output-dir", outputDir, "--apply")
	if err != nil {
		t.Fatalf("wrapper failed: %v\noutput=%s", err, output)
	}

	applySummaryOutputPath := filepath.Join(outputDir, remoteAlphaESServiceUserStageApplySummaryArtifactName)
	if strings.TrimSpace(string(output)) != applySummaryOutputPath {
		t.Fatalf("unexpected wrapper output %q", output)
	}
	if _, err := os.Stat(applySummaryOutputPath); err != nil {
		t.Fatalf("missing apply summary output: %v", err)
	}
	if _, err := os.Stat(filepath.Join(outputDir, remoteAlphaESServiceUserStageApplyStdoutArtifactName)); err != nil {
		t.Fatalf("missing apply stdout output: %v", err)
	}
	if _, err := os.Stat(filepath.Join(outputDir, remoteAlphaESServiceUserStageCheckOnlyArtifactName)); err != nil {
		t.Fatalf("missing saved check-only output during apply: %v", err)
	}

	helperLogLines := strings.Split(strings.TrimSpace(mustRead(t, h.helperLogPath)), "\n")
	if len(helperLogLines) != 2 {
		t.Fatalf("expected check-only then apply, got %q", helperLogLines)
	}
	if !strings.HasPrefix(helperLogLines[0], "check_only\t") {
		t.Fatalf("expected first helper invocation to be check-only, got %q", helperLogLines[0])
	}
	if !strings.HasPrefix(helperLogLines[1], "apply\t"+remoteAlphaESServiceUserStageDefaultSummaryPath) {
		t.Fatalf("expected second helper invocation to be apply with remote summary path, got %q", helperLogLines[1])
	}
}

func TestRemoteAlphaStageESServiceUserMigrationUploadsExactHelperPaths(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	checkOnlyReportPath := filepath.Join(tmpDir, "check-only-report.json")
	applySummaryPath := filepath.Join(tmpDir, "apply-summary-template.json")
	writeESServiceUserStageCheckOnlyReport(t, checkOnlyReportPath, goodESServiceUserStageCheckOnlyReport())
	writeESServiceUserStageApplySummary(t, applySummaryPath)

	h := setupFakeRemoteESServiceUserStageHarness(t, checkOnlyReportPath, applySummaryPath)
	outputDir := filepath.Join(tmpDir, "output")

	if output, err := runRemoteAlphaESServiceUserStageWrapper(t, h.esServiceUserEnv(), "--ssh-target", "ds@m75q-test", "--run-id", "exact-upload", "--output-dir", outputDir); err != nil {
		t.Fatalf("wrapper failed: %v\noutput=%s\nscp=%q\ninstall=%q\nuploaded=%q", err, output, readIfExists(h.scpLogPath), readIfExists(h.installLogPath), readIfExists(h.uploadLogPath))
	}

	uploadedLines := strings.Fields(strings.TrimSpace(readIfExists(h.uploadLogPath)))
	uploaded := make(map[string]bool, len(uploadedLines))
	for _, line := range uploadedLines {
		uploaded[line] = true
	}
	for _, required := range []string{
		"/tmp/execution-substrate-es-service-user-upload-exact-upload/scripts/remote_alpha_migrate_es_service_user.sh",
		"/tmp/execution-substrate-es-service-user-upload-exact-upload/scripts/internal/remote_alpha_migrate_es_service_user.sh",
		"/tmp/execution-substrate-es-service-user-upload-exact-upload/scripts/remote_alpha_check_es_writable_state_readiness.sh",
		"/tmp/execution-substrate-es-service-user-upload-exact-upload/scripts/internal/remote_alpha_check_es_writable_state_readiness.sh",
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
	if len(fileInstalls) != 4 {
		t.Fatalf("expected exactly four staged helper files, got %q", fileInstalls)
	}
}

func TestRemoteAlphaStageESServiceUserMigrationStagesOnlyMinimalHelperFiles(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	checkOnlyReportPath := filepath.Join(tmpDir, "check-only-report.json")
	applySummaryPath := filepath.Join(tmpDir, "apply-summary-template.json")
	writeESServiceUserStageCheckOnlyReport(t, checkOnlyReportPath, goodESServiceUserStageCheckOnlyReport())
	writeESServiceUserStageApplySummary(t, applySummaryPath)

	h := setupFakeRemoteESServiceUserStageHarness(t, checkOnlyReportPath, applySummaryPath)
	outputDir := filepath.Join(tmpDir, "output")

	if output, err := runRemoteAlphaESServiceUserStageWrapper(t, h.esServiceUserEnv(), "--ssh-target", "ds@m75q-test", "--run-id", "minimal-files", "--output-dir", outputDir); err != nil {
		t.Fatalf("wrapper failed: %v\n%s", err, output)
	}

	lines := strings.Split(strings.TrimSpace(mustRead(t, h.installLogPath)), "\n")
	fileInstalls := make([]string, 0)
	for _, line := range lines {
		if strings.HasPrefix(line, "file\t") {
			fileInstalls = append(fileInstalls, line)
		}
	}
	if len(fileInstalls) != 4 {
		t.Fatalf("expected exactly four staged helper files, got %q", fileInstalls)
	}
	joined := strings.Join(fileInstalls, "\n")
	for _, required := range []string{
		"scripts/remote_alpha_migrate_es_service_user.sh",
		"scripts/internal/remote_alpha_migrate_es_service_user.sh",
		"scripts/remote_alpha_check_es_writable_state_readiness.sh",
		"scripts/internal/remote_alpha_check_es_writable_state_readiness.sh",
	} {
		if !strings.Contains(joined, required) {
			t.Fatalf("missing staged helper file %q in %q", required, fileInstalls)
		}
	}
	if strings.Contains(joined, "remote_alpha_stage_") {
		t.Fatalf("repo-side staging wrapper should not be copied to the remote host: %q", fileInstalls)
	}
}

func TestRemoteAlphaStageESServiceUserMigrationWritesHelperStagingRecord(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	checkOnlyReportPath := filepath.Join(tmpDir, "check-only-report.json")
	applySummaryPath := filepath.Join(tmpDir, "apply-summary-template.json")
	writeESServiceUserStageCheckOnlyReport(t, checkOnlyReportPath, goodESServiceUserStageCheckOnlyReport())
	writeESServiceUserStageApplySummary(t, applySummaryPath)

	h := setupFakeRemoteESServiceUserStageHarness(t, checkOnlyReportPath, applySummaryPath)
	outputDir := filepath.Join(tmpDir, "output")

	if output, err := runRemoteAlphaESServiceUserStageWrapper(t, h.esServiceUserEnv(), "--ssh-target", "ds@m75q-test", "--run-id", "provenance", "--output-dir", outputDir); err != nil {
		t.Fatalf("wrapper failed: %v\n%s", err, output)
	}

	provenancePath := filepath.Join(outputDir, remoteAlphaESServiceUserStageHelperStagingRecordName)
	provenance := readJSONFile(t, provenancePath)
	if got := provenance["schema_version"]; got != "execution-substrate.remote-alpha.es-service-user-migration-stage-provenance.v1" {
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

	localFiles, ok := provenance["local_files"].([]any)
	if !ok {
		t.Fatalf("expected local_files array, got %T", provenance["local_files"])
	}
	if len(localFiles) != 4 {
		t.Fatalf("expected four local file entries, got %d", len(localFiles))
	}

	expectedDigests := map[string]string{
		filepath.Join(executionSubstrateRepoRoot, "scripts", "remote_alpha_migrate_es_service_user.sh"):                       sha256File(t, filepath.Join(executionSubstrateRepoRoot, "scripts", "remote_alpha_migrate_es_service_user.sh")),
		filepath.Join(executionSubstrateRepoRoot, "scripts", "internal", "remote_alpha_migrate_es_service_user.sh"):           sha256File(t, filepath.Join(executionSubstrateRepoRoot, "scripts", "internal", "remote_alpha_migrate_es_service_user.sh")),
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

	if got := provenance["remote_staged_path"]; got != remoteAlphaESServiceUserStageDefaultStagingRoot+"/provenance" {
		t.Fatalf("unexpected remote staged path %v", got)
	}
	stagedFiles, ok := provenance["staged_files"].([]any)
	if !ok {
		t.Fatalf("expected staged_files array, got %T", provenance["staged_files"])
	}
	if len(stagedFiles) != 4 {
		t.Fatalf("expected four staged helper entries, got %d", len(stagedFiles))
	}
	stageStat := jsonMap(t, provenance["remote_stage_stat"])
	items, ok := stageStat["items"].([]any)
	if !ok || len(items) != 7 {
		t.Fatalf("expected seven root-owned staged paths, got %+v", stageStat)
	}
}

func TestRemoteAlphaStageESServiceUserMigrationSudoUnavailableIsStructured(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	checkOnlyReportPath := filepath.Join(tmpDir, "check-only-report.json")
	applySummaryPath := filepath.Join(tmpDir, "apply-summary-template.json")
	writeESServiceUserStageCheckOnlyReport(t, checkOnlyReportPath, goodESServiceUserStageCheckOnlyReport())
	writeESServiceUserStageApplySummary(t, applySummaryPath)

	h := setupFakeRemoteESServiceUserStageHarness(t, checkOnlyReportPath, applySummaryPath)
	outputDir := filepath.Join(tmpDir, "output")

	output, err := runRemoteAlphaESServiceUserStageWrapper(t, h.esServiceUserEnv(
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

	provenance := readJSONFile(t, filepath.Join(outputDir, remoteAlphaESServiceUserStageHelperStagingRecordName))
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

func TestRemoteAlphaStageESServiceUserMigrationMissingUploadSourceIsStructured(t *testing.T) {
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
remote_alpha_migrate_es_service_user_stage_make_local_upload_tree() {
  local upload_dir=$1
  mkdir -p "$upload_dir/scripts/internal"
  cp "${REPO_ROOT}/scripts/internal/remote_alpha_migrate_es_service_user.sh" "$upload_dir/scripts/internal/remote_alpha_migrate_es_service_user.sh"
  cp "${REPO_ROOT}/scripts/remote_alpha_check_es_writable_state_readiness.sh" "$upload_dir/scripts/remote_alpha_check_es_writable_state_readiness.sh"
  cp "${REPO_ROOT}/scripts/internal/remote_alpha_check_es_writable_state_readiness.sh" "$upload_dir/scripts/internal/remote_alpha_check_es_writable_state_readiness.sh"
}
remote_alpha_migrate_es_service_user_stage_main --ssh-target fake-target --run-id missing-upload-source --output-dir %q
`, outputDir)
	output, err := runSourcedESServiceUserStageHelper(t, envWithPath(fakeBin), shellBody)
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

	provenance := readJSONFile(t, filepath.Join(outputDir, remoteAlphaESServiceUserStageHelperStagingRecordName))
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

func TestRemoteAlphaStageESServiceUserMigrationCheckOnlyBlockerIsNotToolingError(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	checkOnlyReportPath := filepath.Join(tmpDir, "check-only-report.json")
	applySummaryPath := filepath.Join(tmpDir, "apply-summary-template.json")
	report := goodESServiceUserStageCheckOnlyReport()
	report["overall_classification"] = "blocker"
	report["plan"] = map[string]any{
		"apply_ready": false,
	}
	report["blockers"] = []any{map[string]any{"summary": "future readiness evidence blocked apply"}}
	writeESServiceUserStageCheckOnlyReport(t, checkOnlyReportPath, report)
	writeESServiceUserStageApplySummary(t, applySummaryPath)

	h := setupFakeRemoteESServiceUserStageHarness(t, checkOnlyReportPath, applySummaryPath)
	outputDir := filepath.Join(tmpDir, "output")

	output, err := runRemoteAlphaESServiceUserStageWrapper(t, h.esServiceUserEnv(
		"FAKE_REMOTE_CHECK_ONLY_EXIT=1",
	), "--ssh-target", "ds@m75q-test", "--run-id", "check-blocker", "--output-dir", outputDir)
	if err == nil {
		t.Fatalf("expected check-only blocker exit\noutput=%q", output)
	}

	provenance := readJSONFile(t, filepath.Join(outputDir, remoteAlphaESServiceUserStageHelperStagingRecordName))
	if got := provenance["sudo_unavailable"]; got != false {
		t.Fatalf("expected sudo_unavailable=false, got %v", got)
	}
	if got := provenance["wrapper_tooling_error"]; got != false {
		t.Fatalf("expected wrapper_tooling_error=false, got %v", got)
	}
	checkOutput := readJSONFile(t, filepath.Join(outputDir, remoteAlphaESServiceUserStageCheckOnlyArtifactName))
	if got := checkOutput["overall_classification"]; got != "blocker" {
		t.Fatalf("expected saved check-only blocker evidence, got %v", got)
	}
}

func TestRemoteAlphaStageESServiceUserMigrationInstallFailureRecordsCleanupAndSkipsApply(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	checkOnlyReportPath := filepath.Join(tmpDir, "check-only-report.json")
	applySummaryPath := filepath.Join(tmpDir, "apply-summary-template.json")
	writeESServiceUserStageCheckOnlyReport(t, checkOnlyReportPath, goodESServiceUserStageCheckOnlyReport())
	writeESServiceUserStageApplySummary(t, applySummaryPath)

	h := setupFakeRemoteESServiceUserStageHarness(t, checkOnlyReportPath, applySummaryPath)
	outputDir := filepath.Join(tmpDir, "output")

	output, err := runRemoteAlphaESServiceUserStageWrapper(t, h.esServiceUserEnv(
		"FAKE_REMOTE_INSTALL_FAIL_ON=/scripts/remote_alpha_migrate_es_service_user.sh",
	), "--ssh-target", "ds@m75q-test", "--run-id", "install-failure", "--output-dir", outputDir)
	if err == nil {
		t.Fatalf("expected staged install failure\noutput=%q", output)
	}

	provenance := readJSONFile(t, filepath.Join(outputDir, remoteAlphaESServiceUserStageHelperStagingRecordName))
	if got := provenance["wrapper_tooling_error"]; got != true {
		t.Fatalf("expected wrapper_tooling_error=true, got %v", got)
	}
	if got := provenance["failure_classification"]; got != "wrapper_tooling_error" {
		t.Fatalf("expected failure_classification=wrapper_tooling_error, got %v", got)
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

	remoteUploadRoot := fakeRemotePath(h.remoteRoot, "/tmp/execution-substrate-es-service-user-upload-install-failure")
	if _, err := os.Stat(remoteUploadRoot); !os.IsNotExist(err) {
		t.Fatalf("upload root should be removed after install failure cleanup: %v", err)
	}
	remoteStageRoot := fakeRemotePath(h.remoteRoot, remoteAlphaESServiceUserStageDefaultStagingRoot+"/install-failure")
	if _, err := os.Stat(remoteStageRoot); !os.IsNotExist(err) {
		t.Fatalf("staging root should be removed after install failure cleanup: %v", err)
	}
}
