package scripts_test

// Tests for remote_alpha_prepare_output_dir, the check that root helpers run
// before they write summaries, preflights, backups or staged helpers into the
// shared Remote Alpha artifact folder /var/tmp/execution-substrate-remote-alpha
// (whole-trunk red-team follow-up N-1, 2026-11-24). /var/tmp is writable by
// every account, so another account could create that folder first and plant
// links in it. The tests below show the check refusing such a folder, the
// copies of the check staying identical, and three routes refusing a planted
// folder before root acts: a root helper on the host, the Mac-side staging of
// the ES config/TLS helper and the operator's summary-path preparation.
//
// The tests that need a folder owned by another account change ownership with
// root or passwordless sudo, like the tests in es/admission that need it, and
// skip without either. The CI runner has passwordless sudo.

import (
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

const remoteAlphaOutputDirDefinitionPath = "scripts/internal/remote_alpha_output_dir.sh"

// remoteAlphaOutputDirCopies are the scripts that carry a copy of
// remote_alpha_prepare_output_dir because they are staged to the host without
// the rest of the repository.
var remoteAlphaOutputDirCopies = []string{
	"scripts/internal/remote_alpha_deploy_es_binaries.sh",
	"scripts/internal/remote_alpha_es_service_tls_renew.sh",
	"scripts/internal/remote_alpha_harden_ags_service.sh",
	"scripts/internal/remote_alpha_harden_ars_service.sh",
	"scripts/internal/remote_alpha_harden_egs_service.sh",
	"scripts/internal/remote_alpha_migrate_vault_service_user.sh",
	"scripts/internal/remote_alpha_normal_shell_runtime_image_check.sh",
	"scripts/internal/remote_alpha_operator_healthcheck_tls_renew.sh",
	"scripts/internal/remote_alpha_prepare_es_config_tls.sh",
	"scripts/internal/remote_alpha_vault_workload_auth_bootstrap.sh",
	"scripts/internal/remote_alpha_vault_workload_auth_check.sh",
	"scripts/remote_alpha_reset_disposable_vault.sh",
	"scripts/remote_alpha_runtime_identity_helper_summary.sh",
}

// remoteAlphaOutputDirSenders are the Mac-side scripts that send the whole
// definition file to the host at the front of a remote batch.
var remoteAlphaOutputDirSenders = map[string]string{
	"scripts/internal/remote_alpha_deploy_es_binaries.sh":       `cat -- "${REPO_ROOT}/scripts/internal/remote_alpha_output_dir.sh"`,
	"scripts/internal/remote_alpha_stage_es_config_tls_prep.sh": `cat -- "${REPO_ROOT}/scripts/internal/remote_alpha_output_dir.sh"`,
	"scripts/remote_alpha_operator.sh":                          `REMOTE_ALPHA_OUTPUT_DIR_DEFINITION="${SCRIPT_DIR}/internal/remote_alpha_output_dir.sh"`,
}

func remoteAlphaOutputDirFunction(t *testing.T, text, label string) string {
	t.Helper()
	start := strings.Index(text, "\nremote_alpha_prepare_output_dir() {\n")
	if start < 0 {
		t.Fatalf("%s has no remote_alpha_prepare_output_dir() definition", label)
	}
	start++
	end := strings.Index(text[start:], "\nREMOTE_ALPHA_OUTPUT_DIR_PY\n}\n")
	if end < 0 {
		t.Fatalf("%s: remote_alpha_prepare_output_dir() does not end with its here-document and a closing brace", label)
	}
	return text[start : start+end+len("\nREMOTE_ALPHA_OUTPUT_DIR_PY\n}\n")]
}

// TestRemoteAlphaOutputDirCopiesMatch keeps every copy of the check identical
// to the definition, makes every copy-holding script call it, and makes every
// script that names the artifact folder either hold a copy or send the
// definition file, so a new writer cannot name the folder without the check.
func TestRemoteAlphaOutputDirCopiesMatch(t *testing.T) {
	definition := remoteAlphaOutputDirFunction(t, mustRead(t, remoteAlphaOutputDirDefinitionPath), remoteAlphaOutputDirDefinitionPath)
	for _, required := range []string{"os.O_NOFOLLOW", "dir_fd=fd", "SUDO_UID", "stat.S_ISVTX", "os.mkdir(parts[index], 0o755, dir_fd=fd)"} {
		if !strings.Contains(definition, required) {
			t.Fatalf("definition lost %q:\n%s", required, definition)
		}
	}

	copies := map[string]bool{}
	for _, path := range remoteAlphaOutputDirCopies {
		copies[path] = true
		text := mustRead(t, path)
		if got := remoteAlphaOutputDirFunction(t, text, path); got != definition {
			t.Errorf("%s holds a copy of remote_alpha_prepare_output_dir that differs from %s; change the definition there and copy it here", path, remoteAlphaOutputDirDefinitionPath)
		}
		if strings.Count(text, "\nremote_alpha_prepare_output_dir() {\n") != 1 {
			t.Errorf("%s defines remote_alpha_prepare_output_dir more than once", path)
		}
		if !strings.Contains(text, `remote_alpha_prepare_output_dir "`) {
			t.Errorf("%s holds a copy of remote_alpha_prepare_output_dir but never calls it", path)
		}
	}
	for path, marker := range remoteAlphaOutputDirSenders {
		text := mustRead(t, path)
		if !strings.Contains(text, marker) {
			t.Errorf("%s no longer sends %s to the host (missing %q)", path, remoteAlphaOutputDirDefinitionPath, marker)
		}
		if !strings.Contains(text, "remote_alpha_prepare_output_dir") {
			t.Errorf("%s sends the definition but never calls the check", path)
		}
	}

	var unchecked []string
	err := filepath.WalkDir(repoPath("scripts"), func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() || !(strings.HasSuffix(path, ".sh") || strings.HasSuffix(path, ".py")) {
			return nil
		}
		rel, err := filepath.Rel(executionSubstrateRepoRoot, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		text := mustRead(t, rel)
		if strings.Contains(text, "\nremote_alpha_prepare_output_dir() {\n") && !copies[rel] && rel != remoteAlphaOutputDirDefinitionPath {
			t.Errorf("%s holds a copy of remote_alpha_prepare_output_dir that is not listed in remoteAlphaOutputDirCopies", rel)
		}
		if !strings.Contains(text, "/var/tmp/execution-substrate-remote-alpha") || rel == remoteAlphaOutputDirDefinitionPath {
			return nil
		}
		if _, sends := remoteAlphaOutputDirSenders[rel]; !copies[rel] && !sends {
			unchecked = append(unchecked, rel)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk scripts: %v", err)
	}
	sort.Strings(unchecked)
	if len(unchecked) > 0 {
		t.Fatalf("these scripts name /var/tmp/execution-substrate-remote-alpha but neither hold a copy of remote_alpha_prepare_output_dir nor send %s: %v", remoteAlphaOutputDirDefinitionPath, unchecked)
	}
}

// remoteAlphaOutputDirEnv is the test environment without SUDO_UID, plus the
// given entries.
func remoteAlphaOutputDirEnv(extra ...string) []string {
	var env []string
	for _, entry := range os.Environ() {
		if !strings.HasPrefix(entry, "SUDO_UID=") {
			env = append(env, entry)
		}
	}
	return append(env, extra...)
}

func runRemoteAlphaOutputDir(t *testing.T, dir string, extraEnv ...string) (string, error) {
	t.Helper()
	cmd := exec.Command("/bin/bash", "-c", `source "$1" && remote_alpha_prepare_output_dir "$2"`, "remote-alpha-output-dir-test",
		repoPath(remoteAlphaOutputDirDefinitionPath), dir)
	cmd.Dir = executionSubstrateRepoRoot
	cmd.Env = remoteAlphaOutputDirEnv(extraEnv...)
	output, err := cmd.CombinedOutput()
	return string(output), err
}

// remoteAlphaOutputDirTempDir is a temporary directory whose path has no
// symbolic link in it, so that the check judges only what a test sets up.
func remoteAlphaOutputDirTempDir(t *testing.T) string {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("resolve temp dir: %v", err)
	}
	return dir
}

func requireRemoteAlphaOutputDirRefusal(t *testing.T, output string, err error, wants ...string) {
	t.Helper()
	if err == nil {
		t.Fatalf("remote_alpha_prepare_output_dir accepted the folder:\n%s", output)
	}
	assertContainsAll(t, "remote_alpha_prepare_output_dir refusal", output, append([]string{"remote alpha output folder: "}, wants...)...)
}

func requireEmptyDir(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read %s: %v", dir, err)
	}
	if len(entries) != 0 {
		t.Fatalf("%s should be untouched and empty, holds %v", dir, entries)
	}
}

func TestRemoteAlphaOutputDirCreatesMissingFolders(t *testing.T) {
	base := remoteAlphaOutputDirTempDir(t)
	target := filepath.Join(base, "var", "tmp", "execution-substrate-remote-alpha")

	for round := 1; round <= 2; round++ {
		if output, err := runRemoteAlphaOutputDir(t, target); err != nil {
			t.Fatalf("round %d: check refused a fresh private folder: %v\n%s", round, err, output)
		}
	}
	for _, dir := range []string{filepath.Join(base, "var"), filepath.Join(base, "var", "tmp"), target} {
		info, err := os.Lstat(dir)
		if err != nil {
			t.Fatalf("lstat %s: %v", dir, err)
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			t.Fatalf("%s is not a plain directory: %v", dir, info.Mode())
		}
		if info.Mode().Perm()&0o022 != 0 {
			t.Fatalf("%s was created writable by group or others: %v", dir, info.Mode())
		}
		if owner := info.Sys().(*syscall.Stat_t).Uid; int(owner) != os.Geteuid() {
			t.Fatalf("%s belongs to uid %d, want the running user %d", dir, owner, os.Geteuid())
		}
	}

	output, err := runRemoteAlphaOutputDir(t, "")
	requireRemoteAlphaOutputDirRefusal(t, output, err, "no folder given")
}

func TestRemoteAlphaOutputDirRefusesPlantedLinks(t *testing.T) {
	base := remoteAlphaOutputDirTempDir(t)
	victim := filepath.Join(base, "victim")
	if err := os.Mkdir(victim, 0o755); err != nil {
		t.Fatalf("mkdir victim: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(base, "var", "tmp"), 0o755); err != nil {
		t.Fatalf("mkdir var/tmp: %v", err)
	}

	// The artifact folder itself is a planted link.
	planted := filepath.Join(base, "var", "tmp", "execution-substrate-remote-alpha")
	if err := os.Symlink(victim, planted); err != nil {
		t.Fatalf("plant link: %v", err)
	}
	output, err := runRemoteAlphaOutputDir(t, planted)
	requireRemoteAlphaOutputDirRefusal(t, output, err, planted, "is not a directory or is a symbolic link")
	output, err = runRemoteAlphaOutputDir(t, filepath.Join(planted, "helper-staging"))
	requireRemoteAlphaOutputDirRefusal(t, output, err, planted, "is not a directory or is a symbolic link")
	requireEmptyDir(t, victim)

	// A link higher up the path.
	linkedVar := filepath.Join(base, "linked-var")
	if err := os.Symlink(filepath.Join(base, "var"), linkedVar); err != nil {
		t.Fatalf("plant upper link: %v", err)
	}
	output, err = runRemoteAlphaOutputDir(t, filepath.Join(linkedVar, "tmp", "fresh"))
	requireRemoteAlphaOutputDirRefusal(t, output, err, linkedVar, "is not a directory or is a symbolic link")
	if _, err := os.Lstat(filepath.Join(base, "var", "tmp", "fresh")); !os.IsNotExist(err) {
		t.Fatalf("check created a folder through a link: %v", err)
	}

	// A file where a folder belongs.
	file := filepath.Join(base, "file")
	if err := os.WriteFile(file, []byte("x"), 0o644); err != nil {
		t.Fatalf("write file: %v", err)
	}
	output, err = runRemoteAlphaOutputDir(t, filepath.Join(file, "below"))
	requireRemoteAlphaOutputDirRefusal(t, output, err, file, "is not a directory or is a symbolic link")
}

func TestRemoteAlphaOutputDirRefusesFoldersOthersCanWrite(t *testing.T) {
	base := remoteAlphaOutputDirTempDir(t)

	open := filepath.Join(base, "open")
	if err := os.Mkdir(open, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.Chmod(open, 0o777); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	output, err := runRemoteAlphaOutputDir(t, open)
	requireRemoteAlphaOutputDirRefusal(t, output, err, open, "can be written by its group or others")
	output, err = runRemoteAlphaOutputDir(t, filepath.Join(open, "below"))
	requireRemoteAlphaOutputDirRefusal(t, output, err, open, "can be written by its group or others")
	requireEmptyDir(t, open)

	// Sticky is not enough unless root owns the folder.
	sticky := filepath.Join(base, "sticky")
	if err := os.Mkdir(sticky, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.Chmod(sticky, 0o777|os.ModeSticky); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	if os.Geteuid() != 0 {
		output, err = runRemoteAlphaOutputDir(t, filepath.Join(sticky, "below"))
		requireRemoteAlphaOutputDirRefusal(t, output, err, sticky, "can be written by its group or others")
		requireEmptyDir(t, sticky)
	}
	// The folder itself is never accepted writable by others, sticky or not.
	output, err = runRemoteAlphaOutputDir(t, sticky)
	requireRemoteAlphaOutputDirRefusal(t, output, err, sticky, "can be written by its group or others")
}

// remoteAlphaOutputDirPrivileged runs a command as root, through sudo -n when
// the test does not run as root, and skips the test when it can do neither.
func remoteAlphaOutputDirPrivileged(t *testing.T, args ...string) {
	t.Helper()
	cmd := exec.Command(args[0], args[1:]...)
	if os.Geteuid() != 0 {
		probe := exec.Command("sudo", "-n", "true")
		probe.Dir = executionSubstrateRepoRoot
		if output, err := probe.CombinedOutput(); err != nil {
			t.Skipf("needs root or passwordless sudo to give a folder to another account: %v: %s", err, strings.TrimSpace(string(output)))
		}
		cmd = exec.Command("sudo", append([]string{"-n"}, args...)...)
	}
	cmd.Dir = executionSubstrateRepoRoot
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("%s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(string(output)))
	}
}

// remoteAlphaOutputDirGive gives dir to uid:gid and gives it back to the
// running user when the test ends, before the temporary directory goes.
func remoteAlphaOutputDirGive(t *testing.T, dir string, uid int, mode string) {
	t.Helper()
	remoteAlphaOutputDirPrivileged(t, "chown", strconv.Itoa(uid)+":"+strconv.Itoa(uid), dir)
	remoteAlphaOutputDirPrivileged(t, "chmod", mode, dir)
	self := strconv.Itoa(os.Geteuid()) + ":" + strconv.Itoa(os.Getegid())
	t.Cleanup(func() {
		remoteAlphaOutputDirPrivileged(t, "chown", "-R", self, dir)
		remoteAlphaOutputDirPrivileged(t, "chmod", "0700", dir)
	})
}

const remoteAlphaOutputDirOtherAccount = 65534

func TestRemoteAlphaOutputDirRefusesFolderOwnedByAnotherAccount(t *testing.T) {
	base := remoteAlphaOutputDirTempDir(t)

	// Another account created the artifact folder first.
	foreign := filepath.Join(base, "execution-substrate-remote-alpha")
	if err := os.Mkdir(foreign, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	remoteAlphaOutputDirGive(t, foreign, remoteAlphaOutputDirOtherAccount, "0755")
	output, err := runRemoteAlphaOutputDir(t, foreign)
	requireRemoteAlphaOutputDirRefusal(t, output, err, foreign, "belongs to uid 65534", "refusing to write under it")
	output, err = runRemoteAlphaOutputDir(t, filepath.Join(foreign, "helper-staging"))
	requireRemoteAlphaOutputDirRefusal(t, output, err, foreign, "belongs to uid 65534")
	requireEmptyDir(t, foreign)

	// The user who ran sudo is trusted, and only through SUDO_UID.
	if output, err := runRemoteAlphaOutputDir(t, foreign, "SUDO_UID="+strconv.Itoa(remoteAlphaOutputDirOtherAccount)); err != nil {
		t.Fatalf("check refused a folder owned by the user named in SUDO_UID: %v\n%s", err, output)
	}
	output, err = runRemoteAlphaOutputDir(t, foreign, "SUDO_UID=not-a-number")
	requireRemoteAlphaOutputDirRefusal(t, output, err, "belongs to uid 65534")

	// A sticky folder that everyone can write counts only when root owns it,
	// the way /var/tmp does.
	rootSticky := filepath.Join(base, "root-sticky")
	if err := os.Mkdir(rootSticky, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	remoteAlphaOutputDirGive(t, rootSticky, 0, "1777")
	if output, err := runRemoteAlphaOutputDir(t, filepath.Join(rootSticky, "execution-substrate-remote-alpha")); err != nil {
		t.Fatalf("check refused a private folder below a root-owned sticky folder: %v\n%s", err, output)
	}
	otherSticky := filepath.Join(base, "other-sticky")
	if err := os.Mkdir(otherSticky, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	remoteAlphaOutputDirGive(t, otherSticky, remoteAlphaOutputDirOtherAccount, "1777")
	output, err = runRemoteAlphaOutputDir(t, filepath.Join(otherSticky, "execution-substrate-remote-alpha"))
	requireRemoteAlphaOutputDirRefusal(t, output, err, otherSticky, "belongs to uid 65534")
	requireEmptyDir(t, otherSticky)
	rootOpen := filepath.Join(base, "root-open")
	if err := os.Mkdir(rootOpen, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	remoteAlphaOutputDirGive(t, rootOpen, 0, "0777")
	output, err = runRemoteAlphaOutputDir(t, filepath.Join(rootOpen, "execution-substrate-remote-alpha"))
	requireRemoteAlphaOutputDirRefusal(t, output, err, rootOpen, "can be written by its group or others")
	requireEmptyDir(t, rootOpen)
}

// TestRemoteAlphaRootHelperRefusesPlantedArtifactFolder runs a root helper of
// the host, the runtime identity summary, with its output in an artifact
// folder that another account planted, and shows it stops before it writes.
func TestRemoteAlphaRootHelperRefusesPlantedArtifactFolder(t *testing.T) {
	base := remoteAlphaOutputDirTempDir(t)
	victim := filepath.Join(base, "victim")
	if err := os.Mkdir(victim, 0o755); err != nil {
		t.Fatalf("mkdir victim: %v", err)
	}
	planted := filepath.Join(base, "execution-substrate-remote-alpha")
	if err := os.Symlink(victim, planted); err != nil {
		t.Fatalf("plant link: %v", err)
	}

	run := func(outputPath string) (string, error) {
		cmd := exec.Command("/bin/bash", repoPath("scripts/remote_alpha_runtime_identity_helper_summary.sh"),
			"--output", outputPath,
			"--runtime-support-path", filepath.Join(base, "missing-runtime-support"),
			"--spire-agent-socket-path", filepath.Join(base, "agent.sock"),
			"--spire-server-socket-path", filepath.Join(base, "server.sock"),
		)
		cmd.Dir = executionSubstrateRepoRoot
		cmd.Env = remoteAlphaOutputDirEnv()
		output, err := cmd.CombinedOutput()
		return string(output), err
	}

	output, err := run(filepath.Join(planted, "runtime-identity-helper-summary.json"))
	requireRemoteAlphaOutputDirRefusal(t, output, err, planted, "is not a directory or is a symbolic link")
	requireEmptyDir(t, victim)

	foreign := filepath.Join(base, "foreign")
	if err := os.Mkdir(foreign, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	remoteAlphaOutputDirGive(t, foreign, remoteAlphaOutputDirOtherAccount, "0777")
	output, err = run(filepath.Join(foreign, "runtime-identity-helper-summary.json"))
	requireRemoteAlphaOutputDirRefusal(t, output, err, foreign, "belongs to uid 65534")
	requireEmptyDir(t, foreign)
}

// TestRemoteAlphaStageESConfigTLSPrepRefusesPlantedArtifactFolder runs the
// Mac-side staging of the ES config/TLS helper against a fake host whose
// artifact folder is a planted link, and shows that root installs nothing.
func TestRemoteAlphaStageESConfigTLSPrepRefusesPlantedArtifactFolder(t *testing.T) {
	tmpDir := t.TempDir()
	checkOnlyReportPath := filepath.Join(tmpDir, "check-only-report.json")
	applySummaryPath := filepath.Join(tmpDir, "apply-summary-template.json")
	writeStageCheckOnlyReport(t, checkOnlyReportPath, goodStageCheckOnlyReport(remoteAlphaStageDefaultSummaryPath))
	writeStageApplySummary(t, applySummaryPath)
	h := setupFakeRemoteStageHarness(t, checkOnlyReportPath, applySummaryPath)

	victim := filepath.Join(h.remoteRoot, "victim")
	if err := os.MkdirAll(victim, 0o755); err != nil {
		t.Fatalf("mkdir victim: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(h.remoteRoot, "var", "tmp"), 0o755); err != nil {
		t.Fatalf("mkdir var/tmp: %v", err)
	}
	if err := os.Symlink(victim, filepath.Join(h.remoteRoot, "var", "tmp", "execution-substrate-remote-alpha")); err != nil {
		t.Fatalf("plant link: %v", err)
	}

	output, err := runRemoteAlphaStageWrapper(t, h.env(), "--ssh-target", "ds@m75q-test", "--run-id", "planted", "--output-dir", filepath.Join(tmpDir, "output"), "--apply")
	if err == nil {
		t.Fatalf("staging went ahead through a planted artifact folder:\n%s", output)
	}
	assertContainsAll(t, "staging refusal", string(output), "remote alpha output folder: ", "execution-substrate-remote-alpha is not a directory or is a symbolic link")
	if installLog := readIfExists(h.installLogPath); installLog != "<missing>" {
		t.Fatalf("root installed staged helpers through a planted artifact folder: %q", installLog)
	}
	if helperLog := readIfExists(h.helperLogPath); helperLog != "<missing>" {
		t.Fatalf("staged helper ran through a planted artifact folder: %q", helperLog)
	}
	assertContainsNone(t, "sudo log after refusal", readIfExists(h.sudoLogPath), "rm -rf", "install ")
	requireEmptyDir(t, victim)
}

// TestRemoteAlphaOperatorPrepareSummaryPathRefusesPlantedArtifactFolder runs
// the operator's summary-path preparation against a fake host whose artifact
// folder is a planted link to a folder the helper user cannot write, the case
// in which the route used to hand that folder to the helper user with sudo.
func TestRemoteAlphaOperatorPrepareSummaryPathRefusesPlantedArtifactFolder(t *testing.T) {
	h := setupFakeRemoteAlphaWorkloadAuthBootstrapHarness(t)

	victim := filepath.Join(h.remoteRoot, "victim")
	if err := os.MkdirAll(victim, 0o755); err != nil {
		t.Fatalf("mkdir victim: %v", err)
	}
	if err := os.Chmod(victim, 0o555); err != nil {
		t.Fatalf("chmod victim: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(victim, 0o755) })
	if err := os.MkdirAll(filepath.Join(h.remoteRoot, "var", "tmp"), 0o755); err != nil {
		t.Fatalf("mkdir var/tmp: %v", err)
	}
	if err := os.Symlink(victim, filepath.Join(h.remoteRoot, "var", "tmp", "execution-substrate-remote-alpha")); err != nil {
		t.Fatalf("plant link: %v", err)
	}

	output, err := runRemoteAlphaOperatorWithPTY(t, h.env(),
		"recovery-session", "vault-workload-auth-bootstrap",
		"--ssh-target", "ds@m75q-test",
		"--prepare-summary-path",
		"--interactive-tty",
	)
	if err == nil {
		t.Fatalf("summary-path preparation accepted a planted artifact folder:\n%s", output)
	}
	assertContainsAll(t, "summary-path preparation refusal", output,
		"remote alpha output folder: ",
		"is not a directory or is a symbolic link",
		"summary_path_prepare_status=fail",
		"error_classification=summary_parent_unsafe",
	)
	assertContainsNone(t, "summary-path preparation refusal", output, "summary_path_prepare_status=pass")
	assertContainsNone(t, "sudo log after refusal", readIfExists(h.sudoLogPath), "chown", "chmod", "install")
	info, err := os.Stat(victim)
	if err != nil {
		t.Fatalf("stat victim: %v", err)
	}
	if info.Mode().Perm() != 0o555 {
		t.Fatalf("victim folder mode changed to %v", info.Mode().Perm())
	}
	requireEmptyDir(t, victim)
}
