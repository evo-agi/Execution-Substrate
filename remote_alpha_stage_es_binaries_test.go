package executionsubstrate_test

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const remoteAlphaESBinaryDeploymentStageDefaultSummaryPath = "/var/tmp/execution-substrate-remote-alpha/es-binary-deployment-summary.json"
const remoteAlphaESBinaryDeploymentStageDefaultStagingRoot = "/var/tmp/execution-substrate-remote-alpha/helper-staging"
const remoteAlphaESBinaryDeploymentStageCheckOnlyArtifactName = "es-binary-deployment-check-only.json"
const remoteAlphaESBinaryDeploymentStageApplySummaryArtifactName = "es-binary-deployment-apply-summary.json"
const remoteAlphaESBinaryDeploymentStageHelperStagingRecordName = "es-binary-deployment-helper-staging-record.json"

type fakeRemoteESBinaryDeploymentStageHarness struct {
	*fakeRemoteStageHarness
	uploadLogPath string
}

func goodESBinaryDeploymentStageCheckOnlyReport() map[string]any {
	return map[string]any{
		"schema_version": "execution-substrate.remote-alpha.es-binary-deployment-summary.v1",
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
			"deployment_needed": true,
			"apply_ready":       true,
		},
		"warnings": []any{
			map[string]any{
				"summary": "repo-built binaries differ from the live host payloads",
			},
		},
		"blockers":               []any{},
		"overall_classification": "warning",
		"not_claimed": map[string]any{
			"service_user_change": true,
		},
	}
}

func writeESBinaryDeploymentStageCheckOnlyReport(t *testing.T, path string, payload map[string]any) {
	t.Helper()
	writeJSONFile(t, path, payload)
}

func writeESBinaryDeploymentStageApplySummary(t *testing.T, path string) {
	t.Helper()
	writeJSONFile(t, path, map[string]any{
		"schema_version": "execution-substrate.remote-alpha.es-binary-deployment-summary.v1",
		"result": map[string]any{
			"ok": true,
		},
	})
}

func setupFakeRemoteESBinaryDeploymentStageHarness(t *testing.T, checkOnlyReportPath, applySummaryPath string) *fakeRemoteESBinaryDeploymentStageHarness {
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

	h := &fakeRemoteESBinaryDeploymentStageHarness{
		fakeRemoteStageHarness: &fakeRemoteStageHarness{
			localBin:       localBin,
			remoteBin:      remoteBin,
			remoteRoot:     remoteRoot,
			sshLogPath:     filepath.Join(tmpDir, "ssh.log"),
			scpLogPath:     filepath.Join(tmpDir, "scp.log"),
			sudoLogPath:    filepath.Join(tmpDir, "sudo.log"),
			installLogPath: filepath.Join(tmpDir, "install.log"),
			helperLogPath:  filepath.Join(tmpDir, "helper.log"),
			metadataPath:   filepath.Join(tmpDir, "remote-metadata.json"),
		},
		uploadLogPath: filepath.Join(tmpDir, "uploaded-paths.log"),
	}

	writeExecutable(t, localBin, "go", "#!/bin/sh\nexit 0\n")
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
rm -f "${script_path}"
rm -f "${stdout_path}" "${stderr_path}"
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
    fake_root = pathlib.Path().joinpath("").as_posix()
    fake_root = __import__("os").environ.get("FAKE_REMOTE_ROOT", "")
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

if [[ "${1:-}" == */scripts/remote_alpha_deploy_es_binaries.sh ]]; then
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
  exit "${FAKE_REMOTE_APPLY_EXIT:-0}"
fi

exec "$@"
`, h.sudoLogPath, h.helperLogPath, checkOnlyReportPath, h.helperLogPath, applySummaryPath, applySummaryPath))

	return h
}

func (h *fakeRemoteESBinaryDeploymentStageHarness) env(extra ...string) []string {
	base := []string{
		"FAKE_REMOTE_BIN=" + h.remoteBin,
		"FAKE_REMOTE_ROOT=" + h.remoteRoot,
		"FAKE_REMOTE_CHECK_ONLY_EXIT=0",
		"FAKE_REMOTE_APPLY_EXIT=0",
	}
	return envWithPath(h.localBin, append(base, extra...)...)
}

func TestRemoteAlphaESBinaryDeploymentStageUploadsExactMinimalHelperTree(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	checkOnlyReportPath := filepath.Join(tmpDir, "check-only-report.json")
	applySummaryPath := filepath.Join(tmpDir, "apply-summary-template.json")
	writeESBinaryDeploymentStageCheckOnlyReport(t, checkOnlyReportPath, goodESBinaryDeploymentStageCheckOnlyReport())
	writeESBinaryDeploymentStageApplySummary(t, applySummaryPath)

	h := setupFakeRemoteESBinaryDeploymentStageHarness(t, checkOnlyReportPath, applySummaryPath)
	outputDir := filepath.Join(tmpDir, "output")

	shellBody := fmt.Sprintf(`
remote_alpha_deploy_es_binaries_stage_make_local_payload_tree() {
  local payload_dir=$1
  mkdir -p "$payload_dir"
  printf 'es\n' > "$payload_dir/es"
  chmod 0755 "$payload_dir/es"
  printf 'runtime\n' > "$payload_dir/es-runtime-support"
  chmod 0755 "$payload_dir/es-runtime-support"
  printf '{}\n' > "$payload_dir/build-provenance.json"
}
remote_alpha_deploy_es_binaries_stage_main --ssh-target ds@m75q-test --run-id exact-upload --output-dir %q
`, outputDir)
	output, err := runSourcedESBinaryDeploymentHelper(t, h.env(), shellBody)
	if err != nil {
		t.Fatalf("wrapper failed: %v\noutput=%s\nscp=%q\nsudo=%q\ninstall=%q\nuploaded=%q\nhelper=%q\ncheck_only=%q\nprovenance=%q", err, output, readIfExists(h.scpLogPath), readIfExists(h.sudoLogPath), readIfExists(h.installLogPath), readIfExists(h.uploadLogPath), readIfExists(h.helperLogPath), readIfExists(filepath.Join(outputDir, remoteAlphaESBinaryDeploymentStageCheckOnlyArtifactName)), readIfExists(filepath.Join(outputDir, remoteAlphaESBinaryDeploymentStageHelperStagingRecordName)))
	}

	if _, err := os.Stat(filepath.Join(outputDir, remoteAlphaESBinaryDeploymentStageCheckOnlyArtifactName)); err != nil {
		t.Fatalf("missing check-only output: %v", err)
	}

	uploadedLines := strings.Fields(strings.TrimSpace(readIfExists(h.uploadLogPath)))
	uploaded := make(map[string]bool, len(uploadedLines))
	for _, line := range uploadedLines {
		uploaded[line] = true
	}
	requiredUploadedPaths := []string{
		"/tmp/execution-substrate-es-binary-deployment-upload-exact-upload/scripts/remote_alpha_deploy_es_binaries.sh",
		"/tmp/execution-substrate-es-binary-deployment-upload-exact-upload/scripts/internal/remote_alpha_deploy_es_binaries.sh",
	}
	for _, required := range requiredUploadedPaths {
		if !uploaded[required] {
			t.Fatalf("missing uploaded path %q in %q", required, uploadedLines)
		}
	}

	installLog := strings.TrimSpace(readIfExists(h.installLogPath))
	fileInstalls := make([]string, 0)
	for _, line := range strings.Split(installLog, "\n") {
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
	if len(fileInstalls) != 5 {
		t.Fatalf("expected exactly five staged files, got %q", fileInstalls)
	}

	helperLog := readIfExists(h.helperLogPath)
	if !strings.Contains(helperLog, "check_only\t") {
		t.Fatalf("expected check-only invocation, got %q", helperLog)
	}
	if strings.Contains(helperLog, "apply\t") {
		t.Fatalf("did not expect apply invocation, got %q", helperLog)
	}

	provenance := readJSONFile(t, filepath.Join(outputDir, remoteAlphaESBinaryDeploymentStageHelperStagingRecordName))
	if got := provenance["wrapper_tooling_error"]; got != false {
		t.Fatalf("expected wrapper_tooling_error=false, got %v", got)
	}
	if got := provenance["staging_occurred"]; got != true {
		t.Fatalf("expected staging_occurred=true, got %v", got)
	}
	if got := provenance["checker_ran"]; got != true {
		t.Fatalf("expected checker_ran=true, got %v", got)
	}
	if got := provenance["apply_ran"]; got != false {
		t.Fatalf("expected apply_ran=false, got %v", got)
	}

	remoteUploadRoot := fakeRemotePath(h.remoteRoot, "/tmp/execution-substrate-es-binary-deployment-upload-exact-upload")
	if _, err := os.Stat(remoteUploadRoot); !os.IsNotExist(err) {
		t.Fatalf("upload root should be removed after successful check-only run: %v", err)
	}
	remoteStageRoot := fakeRemotePath(h.remoteRoot, remoteAlphaESBinaryDeploymentStageDefaultStagingRoot+"/exact-upload")
	if _, err := os.Stat(remoteStageRoot); !os.IsNotExist(err) {
		t.Fatalf("staging root should be removed after successful check-only run: %v", err)
	}
}

func TestRemoteAlphaESBinaryDeploymentStageMissingUploadSourceIsStructured(t *testing.T) {
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
	writeExecutable(t, fakeBin, "go", "#!/bin/sh\nexit 0\n")

	outputDir := filepath.Join(tmpDir, "output")
	shellBody := fmt.Sprintf(`
remote_alpha_deploy_es_binaries_stage_make_local_upload_tree() {
  local upload_dir=$1
  mkdir -p "$upload_dir/scripts/internal" "$upload_dir/payload"
  cp "${REPO_ROOT}/scripts/internal/remote_alpha_deploy_es_binaries.sh" "$upload_dir/scripts/internal/remote_alpha_deploy_es_binaries.sh"
  printf 'es\n' > "$upload_dir/payload/es"
  chmod 0755 "$upload_dir/payload/es"
  printf 'runtime\n' > "$upload_dir/payload/es-runtime-support"
  chmod 0755 "$upload_dir/payload/es-runtime-support"
  printf '{}\n' > "$upload_dir/payload/build-provenance.json"
}
remote_alpha_deploy_es_binaries_stage_main --ssh-target fake-target --run-id missing-upload-source --output-dir %q
`, outputDir)
	output, err := runSourcedESBinaryDeploymentHelper(t, envWithPath(fakeBin), shellBody)
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

	provenance := readJSONFile(t, filepath.Join(outputDir, remoteAlphaESBinaryDeploymentStageHelperStagingRecordName))
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

func TestRemoteAlphaESBinaryDeploymentStageInstallFailureRecordsCleanupAndSkipsApply(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	checkOnlyReportPath := filepath.Join(tmpDir, "check-only-report.json")
	applySummaryPath := filepath.Join(tmpDir, "apply-summary-template.json")
	writeESBinaryDeploymentStageCheckOnlyReport(t, checkOnlyReportPath, goodESBinaryDeploymentStageCheckOnlyReport())
	writeESBinaryDeploymentStageApplySummary(t, applySummaryPath)

	h := setupFakeRemoteESBinaryDeploymentStageHarness(t, checkOnlyReportPath, applySummaryPath)
	outputDir := filepath.Join(tmpDir, "output")

	shellBody := fmt.Sprintf(`
remote_alpha_deploy_es_binaries_stage_make_local_payload_tree() {
  local payload_dir=$1
  mkdir -p "$payload_dir"
  printf 'es\n' > "$payload_dir/es"
  chmod 0755 "$payload_dir/es"
  printf 'runtime\n' > "$payload_dir/es-runtime-support"
  chmod 0755 "$payload_dir/es-runtime-support"
  printf '{}\n' > "$payload_dir/build-provenance.json"
}
remote_alpha_deploy_es_binaries_stage_main --ssh-target ds@m75q-test --run-id install-failure --output-dir %q
`, outputDir)
	output, err := runSourcedESBinaryDeploymentHelper(t, h.env(
		"FAKE_REMOTE_INSTALL_FAIL_ON=/scripts/remote_alpha_deploy_es_binaries.sh",
	), shellBody)
	if err == nil {
		t.Fatalf("expected staged install failure\noutput=%q", output)
	}

	provenance := readJSONFile(t, filepath.Join(outputDir, remoteAlphaESBinaryDeploymentStageHelperStagingRecordName))
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

	remoteUploadRoot := fakeRemotePath(h.remoteRoot, "/tmp/execution-substrate-es-binary-deployment-upload-install-failure")
	if _, err := os.Stat(remoteUploadRoot); !os.IsNotExist(err) {
		t.Fatalf("upload root should be removed after install failure cleanup: %v", err)
	}
	remoteStageRoot := fakeRemotePath(h.remoteRoot, remoteAlphaESBinaryDeploymentStageDefaultStagingRoot+"/install-failure")
	if _, err := os.Stat(remoteStageRoot); !os.IsNotExist(err) {
		t.Fatalf("staging root should be removed after install failure cleanup: %v", err)
	}
}
