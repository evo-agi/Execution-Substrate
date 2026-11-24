package scripts_test

// Additions from audit 10 of PR #50 (N-1 artifact folder check): tests that
// catch mutants of the check and of its call sites which the PR's own tests
// let through.

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

// TestRemoteAlphaOutputDirRefusesGroupWritableFolders shows that write access
// for the group alone is enough to refuse a folder, below the artifact folder
// and as the artifact folder itself, as for a ds:ds folder someone made 0770
// (audit 10 of PR #50).
func TestRemoteAlphaOutputDirRefusesGroupWritableFolders(t *testing.T) {
	base := remoteAlphaOutputDirTempDir(t)
	for _, mode := range []os.FileMode{0o770, 0o775} {
		dir := filepath.Join(base, "group-"+strconv.FormatUint(uint64(mode), 8))
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.Chmod(dir, mode); err != nil {
			t.Fatalf("chmod: %v", err)
		}
		output, err := runRemoteAlphaOutputDir(t, dir)
		requireRemoteAlphaOutputDirRefusal(t, output, err, dir, "can be written by its group or others")
		output, err = runRemoteAlphaOutputDir(t, filepath.Join(dir, "below"))
		requireRemoteAlphaOutputDirRefusal(t, output, err, dir, "can be written by its group or others")
		requireEmptyDir(t, dir)
	}
}

// TestRemoteAlphaOutputDirRefusesASharedStickyFolderAsTheArtifactFolder shows
// that a folder like /tmp or /var/tmp, which may sit above the artifact folder,
// is never accepted as the artifact folder itself, so a summary path such as
// /tmp/summary.json is refused (audit 10 of PR #50).
func TestRemoteAlphaOutputDirRefusesASharedStickyFolderAsTheArtifactFolder(t *testing.T) {
	checked := 0
	for _, dir := range []string{"/tmp", "/var/tmp"} {
		info, err := os.Lstat(dir)
		if err != nil || info.Sys().(*syscall.Stat_t).Uid != 0 || info.Mode()&(os.ModeSticky|os.ModeSymlink) != os.ModeSticky || info.Mode().Perm() != 0o777 {
			continue
		}
		checked++
		output, err := runRemoteAlphaOutputDir(t, dir)
		requireRemoteAlphaOutputDirRefusal(t, output, err, dir, "can be written by its group or others")
	}
	if checked == 0 {
		t.Fatalf("neither /tmp nor /var/tmp is a root-owned 1777 folder on this host")
	}
}

// TestRemoteAlphaOutputDirCallsCheckTheFoldersTheyWrite pins the folder each
// call of the check names, per script (audit 10 of PR #50). The copies test
// proves only that every copy is called somewhere; this test fails when a call
// checks some other folder than the summary, preflight, backup or staging
// folder the script writes, or when a script gains a call nobody pinned.
func TestRemoteAlphaOutputDirCallsCheckTheFoldersTheyWrite(t *testing.T) {
	const (
		summary = `remote_alpha_prepare_output_dir "$(dirname "${REMOTE_ALPHA_SUMMARY_PATH}")"`
		backup  = `remote_alpha_prepare_output_dir "${REMOTE_ALPHA_BACKUP_ROOT}"`
	)
	type call struct {
		text  string
		count int
	}
	want := map[string][]call{
		"scripts/internal/remote_alpha_deploy_es_binaries.sh": {
			{summary, 1},
			{`remote_alpha_prepare_output_dir "${remote_alpha_deploy_es_binaries_backup_root_dir}"`, 1},
			{`remote_alpha_prepare_output_dir_as_root "\$(dirname "\${staging_root}")"`, 4},
		},
		"scripts/internal/remote_alpha_es_service_tls_renew.sh":             {{summary, 1}, {backup, 2}},
		"scripts/internal/remote_alpha_operator_healthcheck_tls_renew.sh":   {{summary, 1}, {backup, 2}},
		"scripts/internal/remote_alpha_harden_ags_service.sh":               {{summary, 2}},
		"scripts/internal/remote_alpha_harden_ars_service.sh":               {{summary, 2}},
		"scripts/internal/remote_alpha_harden_egs_service.sh":               {{summary, 2}},
		"scripts/internal/remote_alpha_normal_shell_runtime_image_check.sh": {{summary, 2}},
		"scripts/internal/remote_alpha_vault_workload_auth_check.sh":        {{summary, 2}},
		"scripts/internal/remote_alpha_migrate_vault_service_user.sh": {
			{summary, 2},
			{`remote_alpha_prepare_output_dir "$(dirname "${REMOTE_ALPHA_PRECHECK_PATH}")"`, 1},
			{`remote_alpha_prepare_output_dir "${REMOTE_ALPHA_BACKUP_ROOT_DIR}"`, 1},
		},
		"scripts/internal/remote_alpha_prepare_es_config_tls.sh": {
			{summary, 1},
			{`remote_alpha_prepare_output_dir "${remote_alpha_es_config_tls_prep_backup_root_dir}"`, 1},
		},
		"scripts/internal/remote_alpha_vault_workload_auth_bootstrap.sh": {
			{`remote_alpha_prepare_output_dir "$(dirname "${REMOTE_ALPHA_BOOTSTRAP_SUMMARY_PATH}")"`, 1},
		},
		"scripts/remote_alpha_reset_disposable_vault.sh": {
			{`remote_alpha_prepare_output_dir "$(dirname "${VAULT_WORKLOAD_AUTH_SUMMARY_PATH}")"`, 1},
		},
		"scripts/remote_alpha_runtime_identity_helper_summary.sh": {
			{`remote_alpha_prepare_output_dir "$(dirname "${output_path}")"`, 1},
		},
		"scripts/internal/remote_alpha_stage_es_config_tls_prep.sh": {
			{`remote_alpha_prepare_output_dir_as_root "$(dirname "${staging_root}")"`, 2},
		},
		"scripts/remote_alpha_operator.sh": {
			{`remote_alpha_prepare_output_dir "${summary_dir}"`, 1},
		},
	}
	pinned := map[string]bool{}
	for path, calls := range want {
		pinned[path] = true
		text := mustRead(t, path)
		total := 0
		for _, c := range calls {
			total += c.count
			if got := strings.Count(text, c.text); got != c.count {
				t.Errorf("%s: %d calls of %s, want %d", path, got, c.text, c.count)
			}
		}
		if got := strings.Count(text, `remote_alpha_prepare_output_dir "`) + strings.Count(text, `remote_alpha_prepare_output_dir_as_root "`); got != total {
			t.Errorf("%s: %d calls of the check, want the %d pinned here", path, got, total)
		}
	}
	for _, path := range remoteAlphaOutputDirCopies {
		if !pinned[path] {
			t.Errorf("%s carries a copy of the check but its calls are not pinned here", path)
		}
	}
	for path := range remoteAlphaOutputDirSenders {
		if !pinned[path] {
			t.Errorf("%s sends the check but its calls are not pinned here", path)
		}
	}
}

// TestRemoteAlphaESBinaryDeploymentStageRefusesPlantedArtifactFolder runs the
// Mac-side staging of the ES binary deployment helper against a fake host whose
// artifact folder is a planted link, and shows that root installs nothing and
// removes nothing through it (audit 10 of PR #50).
func TestRemoteAlphaESBinaryDeploymentStageRefusesPlantedArtifactFolder(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	checkOnlyReportPath := filepath.Join(tmpDir, "check-only-report.json")
	applySummaryPath := filepath.Join(tmpDir, "apply-summary-template.json")
	writeESBinaryDeploymentStageCheckOnlyReport(t, checkOnlyReportPath, goodESBinaryDeploymentStageCheckOnlyReport())
	writeESBinaryDeploymentStageApplySummary(t, applySummaryPath)
	h := setupFakeRemoteESBinaryDeploymentStageHarness(t, checkOnlyReportPath, applySummaryPath)

	victim := filepath.Join(h.remoteRoot, "victim")
	if err := os.MkdirAll(filepath.Join(victim, "planted"), 0o755); err != nil {
		t.Fatalf("mkdir victim: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(h.remoteRoot, "var", "tmp"), 0o755); err != nil {
		t.Fatalf("mkdir var/tmp: %v", err)
	}
	if err := os.Symlink(victim, filepath.Join(h.remoteRoot, "var", "tmp", "execution-substrate-remote-alpha")); err != nil {
		t.Fatalf("plant link: %v", err)
	}

	output, err := runSourcedESBinaryDeploymentHelper(t, h.env(), fmt.Sprintf(`
remote_alpha_deploy_es_binaries_stage_make_local_payload_tree() {
  local payload_dir=$1
  mkdir -p "$payload_dir"
  printf 'es\n' > "$payload_dir/es"
  printf 'runtime\n' > "$payload_dir/es-runtime-support"
  printf '{}\n' > "$payload_dir/build-provenance.json"
}
remote_alpha_deploy_es_binaries_stage_main --ssh-target ds@m75q-test --run-id planted --output-dir %q
`, filepath.Join(tmpDir, "output")))
	if err == nil {
		t.Fatalf("staging went ahead through a planted artifact folder:\n%s", output)
	}
	record := readJSONFile(t, filepath.Join(tmpDir, "output", remoteAlphaESBinaryDeploymentStageHelperStagingRecordName))
	if record["failure_classification"] != "wrapper_tooling_error" || record["checker_ran"] != false || record["apply_ran"] != false {
		t.Fatalf("staging record does not show a refusal before the checker ran: %v", record)
	}
	if installLog := readIfExists(h.installLogPath); installLog != "<missing>" {
		t.Fatalf("root installed staged helpers through a planted artifact folder: %q", installLog)
	}
	if helperLog := readIfExists(h.helperLogPath); helperLog != "<missing>" {
		t.Fatalf("staged helper ran through a planted artifact folder: %q", helperLog)
	}
	assertContainsNone(t, "sudo log after refusal", readIfExists(h.sudoLogPath), "rm -rf", "install ")
	entries, err := os.ReadDir(victim)
	if err != nil || len(entries) != 1 || entries[0].Name() != "planted" {
		t.Fatalf("the folder behind the planted link changed: %v %v", entries, err)
	}
}

// TestRemoteAlphaOperatorPrepareSummaryPathRefusesASummaryLink runs the
// operator's summary-path preparation against a fake host whose summary file
// is a link to a file the helper user cannot write, and shows that sudo never
// hands anything over (audit 10 of PR #50).
func TestRemoteAlphaOperatorPrepareSummaryPathRefusesASummaryLink(t *testing.T) {
	h := setupFakeRemoteAlphaWorkloadAuthBootstrapHarness(t)

	folder := filepath.Join(h.remoteRoot, "var", "tmp", "execution-substrate-remote-alpha")
	if err := os.MkdirAll(folder, 0o700); err != nil {
		t.Fatalf("mkdir artifact folder: %v", err)
	}
	victim := filepath.Join(h.remoteRoot, "victim.json")
	if err := os.WriteFile(victim, []byte("victim\n"), 0o444); err != nil {
		t.Fatalf("write victim: %v", err)
	}
	if err := os.Symlink(victim, filepath.Join(folder, "vault-workload-auth-bootstrap-summary.json")); err != nil {
		t.Fatalf("plant link: %v", err)
	}

	output, err := runRemoteAlphaOperatorWithPTY(t, h.env(),
		"recovery-session", "vault-workload-auth-bootstrap",
		"--ssh-target", "ds@m75q-test",
		"--prepare-summary-path",
		"--interactive-tty",
	)
	if err == nil {
		t.Fatalf("summary-path preparation accepted a summary path that is a link:\n%s", output)
	}
	assertContainsAll(t, "summary-path preparation refusal", output,
		"summary_path_prepare_status=fail",
		"error_classification=summary_path_symlink",
	)
	assertContainsNone(t, "sudo log after refusal", readIfExists(h.sudoLogPath), "chown", "chmod")
	info, err := os.Stat(victim)
	if err != nil {
		t.Fatalf("stat victim: %v", err)
	}
	if info.Mode().Perm() != 0o444 || readIfExists(victim) != "victim\n" {
		t.Fatalf("the file behind the link changed: mode %v, bytes %q", info.Mode().Perm(), readIfExists(victim))
	}
}
