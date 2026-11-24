package scripts_test

// Red-team re-check 14 of PR #50, O14-1: the operator's Vault and
// healthcheck routes staged helpers under fixed /tmp parents made with
// mkdir -p, which another account could create first and own. The stage
// folders now sit directly under /tmp and are made with mkdir and no -p, and
// cleanup removes only a real folder the SSH user owns. A failed staging step
// stops the route (the staging functions run where Bash ignores set -e), and
// the run step runs a helper only from a private folder of the SSH user.

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

type remoteAlphaOperatorStageRoute struct {
	root    string // the *_STAGE_ROOT variable
	prepare string // heredoc tag of the staging step
	cleanup string // heredoc tag of the cleanup step
	subdirs bool   // stages scripts/ and scripts/internal/ as well
}

var remoteAlphaOperatorStageRoutes = []remoteAlphaOperatorStageRoute{
	{"REMOTE_ALPHA_VAULT_UNSEAL_STAGE_ROOT", "REMOTE_ALPHA_VAULT_UNSEAL_PREPARE", "REMOTE_ALPHA_VAULT_UNSEAL_CLEANUP", false},
	{"REMOTE_ALPHA_VAULT_RESET_DRY_RUN_STAGE_ROOT", "REMOTE_ALPHA_VAULT_RESET_DRY_RUN_PREPARE", "REMOTE_ALPHA_VAULT_RESET_DRY_RUN_CLEANUP", false},
	{"REMOTE_ALPHA_VAULT_RESET_EXECUTE_STAGE_ROOT", "REMOTE_ALPHA_VAULT_RESET_DRY_RUN_PREPARE", "REMOTE_ALPHA_VAULT_RESET_DRY_RUN_CLEANUP", false},
	{"REMOTE_ALPHA_VAULT_WORKLOAD_AUTH_BOOTSTRAP_STAGE_ROOT", "REMOTE_ALPHA_VAULT_WORKLOAD_AUTH_BOOTSTRAP_PREPARE", "REMOTE_ALPHA_VAULT_WORKLOAD_AUTH_BOOTSTRAP_CLEANUP", true},
	{"REMOTE_ALPHA_OPERATOR_HEALTHCHECK_TLS_RENEW_STAGE_ROOT", "REMOTE_ALPHA_OPERATOR_HEALTHCHECK_TLS_PREPARE", "REMOTE_ALPHA_ES_SERVICE_TLS_CLEANUP", true},
}

func remoteAlphaOperatorHeredoc(t *testing.T, operator, tag string) string {
	t.Helper()
	start := "<<'" + tag + "'"
	i := strings.Index(operator, start)
	if i < 0 {
		t.Fatalf("operator has no heredoc %s", tag)
	}
	body := operator[i+len(start):]
	nl := strings.Index(body, "\n")
	if nl < 0 {
		t.Fatalf("heredoc %s has no body", tag)
	}
	body = body[nl+1:]
	j := strings.Index(body, "\n"+tag+"\n")
	if j < 0 {
		t.Fatalf("heredoc %s has no end", tag)
	}
	return body[:j+1]
}

func runRemoteAlphaOperatorHeredoc(t *testing.T, script, arg string) (string, error) {
	t.Helper()
	cmd := exec.Command("/bin/bash", "-s", "--", arg)
	cmd.Dir = t.TempDir()
	cmd.Stdin = strings.NewReader(script)
	output, err := cmd.CombinedOutput()
	return string(output), err
}

// Every stage folder is one name directly under /tmp, so no parent another
// account could own sits between /tmp and the staged helpers.
func TestRemoteAlphaOperatorStageFoldersSitDirectlyUnderTmp(t *testing.T) {
	t.Parallel()
	operator := mustRead(t, filepath.Join(remoteAlphaOperatorRepoRoot(), "scripts", "remote_alpha_operator.sh"))
	for _, route := range remoteAlphaOperatorStageRoutes {
		value := regexp.MustCompile(`(?m)^` + route.root + `="([^"]*)"$`).FindStringSubmatch(operator)
		if value == nil || !regexp.MustCompile(`^/tmp/execution-substrate-remote-alpha-[a-z-]+$`).MatchString(value[1]) {
			t.Errorf("%s is %q, want one name directly under /tmp", route.root, value)
		}
		use := `remote_stage_dir="${` + route.root + `}-${run_id}"`
		if strings.Count(operator, use) != 1 {
			t.Errorf("the stage folder for %s is not %s", route.root, use)
		}
		if strings.Contains(operator, "${"+route.root+"}/") {
			t.Errorf("%s is still used as a parent folder", route.root)
		}
		prepare := remoteAlphaOperatorHeredoc(t, operator, route.prepare)
		assertContainsAll(t, route.prepare, prepare, `mkdir -m 0700 -- "${stage_dir}"`)
		assertContainsNone(t, route.prepare, prepare, "mkdir -p", "rm -rf", "chmod")
	}
}

// A folder or link planted at the stage name makes staging fail and stays as
// it was; a free name gets a new 0700 folder.
func TestRemoteAlphaOperatorStagingRefusesAPlantedStageFolder(t *testing.T) {
	t.Parallel()
	operator := mustRead(t, filepath.Join(remoteAlphaOperatorRepoRoot(), "scripts", "remote_alpha_operator.sh"))
	for _, route := range remoteAlphaOperatorStageRoutes {
		prepare := remoteAlphaOperatorHeredoc(t, operator, route.prepare)
		base := t.TempDir()
		victim := filepath.Join(base, "victim")
		if err := os.Mkdir(victim, 0o755); err != nil {
			t.Fatal(err)
		}

		link := filepath.Join(base, "planted-link")
		if err := os.Symlink(victim, link); err != nil {
			t.Fatal(err)
		}
		if output, err := runRemoteAlphaOperatorHeredoc(t, prepare, link); err == nil {
			t.Errorf("%s staged through a planted link:\n%s", route.prepare, output)
		}
		planted := filepath.Join(base, "planted-folder")
		if err := os.Mkdir(planted, 0o777); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(planted, 0o777); err != nil {
			t.Fatal(err)
		}
		if output, err := runRemoteAlphaOperatorHeredoc(t, prepare, planted); err == nil {
			t.Errorf("%s staged into a folder that was already there:\n%s", route.prepare, output)
		}
		for _, dir := range []string{victim, planted} {
			if entries, err := os.ReadDir(dir); err != nil || len(entries) != 0 {
				t.Errorf("%s changed %s: %v %v", route.prepare, dir, entries, err)
			}
		}
		if info, err := os.Stat(planted); err != nil || info.Mode().Perm() != 0o777 {
			t.Errorf("%s changed the planted folder's mode: %v %v", route.prepare, info, err)
		}

		fresh := filepath.Join(base, "fresh")
		if output, err := runRemoteAlphaOperatorHeredoc(t, prepare, fresh); err != nil {
			t.Errorf("%s failed on a free name: %v\n%s", route.prepare, err, output)
			continue
		}
		want := []string{fresh}
		if route.subdirs {
			want = append(want, filepath.Join(fresh, "scripts"), filepath.Join(fresh, "scripts", "internal"))
		}
		for _, dir := range want {
			info, err := os.Lstat(dir)
			if err != nil || !info.IsDir() || info.Mode().Perm() != 0o700 {
				t.Errorf("%s made %s as %v (%v), want a 0700 folder", route.prepare, dir, info, err)
			}
		}
	}
}

// Cleanup removes the user's own stage folder, and leaves a link, whatever
// it points to, and a folder another account owns.
func TestRemoteAlphaOperatorStageCleanupRemovesOnlyItsOwnFolder(t *testing.T) {
	t.Parallel()
	operator := mustRead(t, filepath.Join(remoteAlphaOperatorRepoRoot(), "scripts", "remote_alpha_operator.sh"))
	for _, tag := range []string{"REMOTE_ALPHA_VAULT_UNSEAL_CLEANUP", "REMOTE_ALPHA_VAULT_RESET_DRY_RUN_CLEANUP", "REMOTE_ALPHA_VAULT_WORKLOAD_AUTH_BOOTSTRAP_CLEANUP", "REMOTE_ALPHA_ES_SERVICE_TLS_CLEANUP"} {
		cleanup := remoteAlphaOperatorHeredoc(t, operator, tag)
		base := t.TempDir()

		own := filepath.Join(base, "own")
		if err := os.MkdirAll(filepath.Join(own, "scripts", "internal"), 0o700); err != nil {
			t.Fatal(err)
		}
		if output, err := runRemoteAlphaOperatorHeredoc(t, cleanup, own); err != nil {
			t.Errorf("%s failed: %v\n%s", tag, err, output)
		}
		if _, err := os.Lstat(own); !os.IsNotExist(err) {
			t.Errorf("%s left the user's own stage folder: %v", tag, err)
		}

		victim := filepath.Join(base, "victim")
		if err := os.MkdirAll(filepath.Join(victim, "keep"), 0o755); err != nil {
			t.Fatal(err)
		}
		link := filepath.Join(base, "planted-link")
		if err := os.Symlink(victim, link); err != nil {
			t.Fatal(err)
		}
		if output, err := runRemoteAlphaOperatorHeredoc(t, cleanup, link); err != nil {
			t.Errorf("%s failed on a link: %v\n%s", tag, err, output)
		}
		if target, err := os.Readlink(link); err != nil || target != victim {
			t.Errorf("%s removed or changed a planted link: %q %v", tag, target, err)
		}
		if _, err := os.Stat(filepath.Join(victim, "keep")); err != nil {
			t.Errorf("%s removed something behind a planted link: %v", tag, err)
		}

		if os.Geteuid() == 0 {
			foreign := filepath.Join(base, "foreign")
			if err := os.MkdirAll(filepath.Join(foreign, "keep"), 0o755); err != nil {
				t.Fatal(err)
			}
			for _, path := range []string{foreign, filepath.Join(foreign, "keep")} {
				if err := os.Chown(path, 65534, 65534); err != nil {
					t.Fatal(err)
				}
			}
			if output, err := runRemoteAlphaOperatorHeredoc(t, cleanup, foreign); err != nil {
				t.Errorf("%s failed on a foreign folder: %v\n%s", tag, err, output)
			}
			info, err := os.Lstat(filepath.Join(foreign, "keep"))
			if err != nil || info.Sys().(*syscall.Stat_t).Uid != 65534 {
				t.Errorf("%s removed a folder another account owns: %v", tag, err)
			}
		}
	}
}

// assertRemoteAlphaOperatorStageFoldersGone checks that no stage folder of a
// route (named <name>-<run id> directly under /tmp) is left on the fake host.
func assertRemoteAlphaOperatorStageFoldersGone(t *testing.T, remoteRoot, name string) {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(remoteRoot, "tmp", name+"*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) > 0 {
		t.Fatalf("expected the remote stage folder to be cleaned, found %q", matches)
	}
}

// mkdirFakeRemoteAlphaHostTmp gives a fake host the /tmp a real host has. The
// staging step makes its folder there with mkdir and no -p, so a fake host
// without one would fail staging.
func mkdirFakeRemoteAlphaHostTmp(t *testing.T, remoteRoot string) {
	t.Helper()
	dir := filepath.Join(remoteRoot, "tmp")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir fake host /tmp: %v", err)
	}
	if err := os.Chmod(dir, os.ModeSticky|0o777); err != nil {
		t.Fatalf("chmod fake host /tmp: %v", err)
	}
}

// remoteAlphaOperatorStageGuard is the check each run step makes before it
// sets its cleanup trap or touches the staged helpers.
const remoteAlphaOperatorStageGuard = `[[ -d "${stage_dir}" && ! -L "${stage_dir}" && -O "${stage_dir}" && -n "$(find "${stage_dir}" -maxdepth 0 -perm 0700 -print)" ]] || { printf "%%s\n" "the staged helper folder is not a private folder of this user; not running it" >&2; exit 1; }; cleanup() {`

func remoteAlphaOperatorShellFunction(t *testing.T, operator, name string) string {
	t.Helper()
	start := "\n" + name + "() {\n"
	i := strings.Index(operator, start)
	if i < 0 {
		t.Fatalf("operator has no function %s", name)
	}
	body := operator[i+len(start):]
	j := strings.Index(body, "\n}\n")
	if j < 0 {
		t.Fatalf("function %s has no end", name)
	}
	return body[:j+1]
}

// The staging functions run inside `if ! ...`, where Bash ignores set -e, so
// each SSH and copy step returns on failure itself. Each run step checks the
// stage folder is still a private folder of the SSH user before it runs
// anything from it.
func TestRemoteAlphaOperatorStagingStopsAtTheFirstFailedStep(t *testing.T) {
	t.Parallel()
	operator := mustRead(t, filepath.Join(remoteAlphaOperatorRepoRoot(), "scripts", "remote_alpha_operator.sh"))
	stages := map[string]int{
		"recovery_session_vault_workload_auth_bootstrap_stage_remote": 2,
		"recovery_session_vault_unseal_existing_stage_remote":         1,
		"recovery_session_vault_reset_disposable_stage_remote":        1,
		"recovery_session_operator_healthcheck_tls_stage_remote":      2,
	}
	for name, copies := range stages {
		body := remoteAlphaOperatorShellFunction(t, operator, name)
		if !strings.Contains(operator, "if ! "+name+" ") {
			t.Errorf("%s is not called as `if ! %s`", name, name)
		}
		sshSteps, scpSteps := 0, 0
		for _, line := range strings.Split(body, "\n") {
			trimmed := strings.TrimSpace(line)
			switch {
			case strings.HasPrefix(trimmed, "ssh "):
				sshSteps++
			case strings.HasPrefix(trimmed, "scp "):
				scpSteps++
			default:
				continue
			}
			if !strings.HasSuffix(trimmed, " || return 1") {
				t.Errorf("%s does not return when this step fails: %s", name, trimmed)
			}
		}
		if sshSteps != 1 || scpSteps != copies {
			t.Errorf("%s has %d SSH and %d copy steps, want 1 and %d", name, sshSteps, scpSteps, copies)
		}
	}

	runs := map[string]int{
		"recovery_session_vault_workload_auth_bootstrap_run_remote": 1,
		"recovery_session_vault_unseal_existing_run_remote":         1,
		"recovery_session_vault_reset_disposable_run_remote":        2,
		"recovery_session_operator_healthcheck_tls_run_remote":      1,
	}
	guarded := 0
	for name, want := range runs {
		body := remoteAlphaOperatorShellFunction(t, operator, name)
		commands := 0
		for _, line := range strings.Split(body, "\n") {
			if !strings.Contains(line, "printf -v remote_command ") {
				continue
			}
			commands++
			guard := strings.Index(line, remoteAlphaOperatorStageGuard)
			if guard < 0 || strings.Index(line, "trap cleanup EXIT") < guard || strings.Index(line, `"${helper_path}"`) < guard {
				t.Errorf("%s runs a staged helper without first checking its folder: %s", name, line)
				continue
			}
			guarded++
		}
		if commands != want {
			t.Errorf("%s builds %d run commands, want %d", name, commands, want)
		}
	}
	if guarded != 5 {
		t.Errorf("%d run commands check their stage folder, want 5", guarded)
	}
}

// remoteAlphaOperatorFakeStageRoute is one staging route wired to its fake host.
type remoteAlphaOperatorFakeStageRoute struct {
	localBin   string
	remoteRoot string
	sshLog     string
	scpLog     string
	helperLog  string
	run        func(t *testing.T) (string, error)
}

var remoteAlphaOperatorFakeStageRoutes = []struct {
	name  string
	setup func(t *testing.T) remoteAlphaOperatorFakeStageRoute
}{
	{"vault-unseal-existing", func(t *testing.T) remoteAlphaOperatorFakeStageRoute {
		h := setupFakeRemoteAlphaUnsealHarness(t)
		return remoteAlphaOperatorFakeStageRoute{h.localBin, h.remoteRoot, h.sshLogPath, h.scpLogPath, h.helperLog, func(t *testing.T) (string, error) {
			return runRemoteAlphaOperatorWithPTY(t, h.env(), "recovery-session", "vault-unseal-existing", "--ssh-target", "ds@m75q-test", "--interactive-tty")
		}}
	}},
	{"vault-reset-disposable-dry-run", func(t *testing.T) remoteAlphaOperatorFakeStageRoute {
		h := setupFakeRemoteAlphaResetDryRunHarness(t)
		return remoteAlphaOperatorFakeStageRoute{h.localBin, h.remoteRoot, h.sshLogPath, h.scpLogPath, h.helperLog, func(t *testing.T) (string, error) {
			return runRemoteAlphaOperatorWithEnv(h.env(), "recovery-session", "vault-reset-disposable", "--ssh-target", "ds@m75q-test", "--dry-run")
		}}
	}},
	{"vault-reset-disposable-execute", func(t *testing.T) remoteAlphaOperatorFakeStageRoute {
		h := setupFakeRemoteAlphaResetDryRunHarness(t)
		return remoteAlphaOperatorFakeStageRoute{h.localBin, h.remoteRoot, h.sshLogPath, h.scpLogPath, h.helperLog, func(t *testing.T) (string, error) {
			return runRemoteAlphaOperatorWithPTY(t, h.env(), "recovery-session", "vault-reset-disposable", "--ssh-target", "ds@m75q-test", "--execute-reset", "--interactive-tty")
		}}
	}},
	{"vault-workload-auth-bootstrap", func(t *testing.T) remoteAlphaOperatorFakeStageRoute {
		h := setupFakeRemoteAlphaWorkloadAuthBootstrapHarness(t)
		return remoteAlphaOperatorFakeStageRoute{h.localBin, h.remoteRoot, h.sshLogPath, h.scpLogPath, h.helperLog, func(t *testing.T) (string, error) {
			return runRemoteAlphaOperatorWithPTY(t, h.env(), "recovery-session", "vault-workload-auth-bootstrap", "--ssh-target", "ds@m75q-test", "--execute-bootstrap", "--interactive-tty")
		}}
	}},
	{"operator-healthcheck-tls-status", func(t *testing.T) remoteAlphaOperatorFakeStageRoute {
		h := setupFakeRemoteAlphaESServiceTLSHarness(t)
		return remoteAlphaOperatorFakeStageRoute{h.localBin, h.remoteRoot, h.sshLogPath, h.scpLogPath, h.helperLog, func(t *testing.T) (string, error) {
			return runRemoteAlphaOperatorWithPTY(t, h.env(), "recovery-session", "operator-healthcheck-tls-status", "--ssh-target", "ds@m75q-test", "--interactive-tty")
		}}
	}},
	{"operator-healthcheck-tls-renew", func(t *testing.T) remoteAlphaOperatorFakeStageRoute {
		h := setupFakeRemoteAlphaESServiceTLSHarness(t)
		return remoteAlphaOperatorFakeStageRoute{h.localBin, h.remoteRoot, h.sshLogPath, h.scpLogPath, h.helperLog, func(t *testing.T) (string, error) {
			return runRemoteAlphaOperatorWithPTY(t, h.env(), "recovery-session", "operator-healthcheck-tls-renew", "--ssh-target", "ds@m75q-test", "--interactive-tty", "--execute-renew")
		}}
	}},
}

// wrapFakeRemoteAlphaCommand puts a wrapper in front of a fake host command;
// the wrapper reaches the original as ${fake}.
func wrapFakeRemoteAlphaCommand(t *testing.T, localBin, name, body string) {
	t.Helper()
	fake := filepath.Join(localBin, name+"-fake")
	if err := os.Rename(filepath.Join(localBin, name), fake); err != nil {
		t.Fatal(err)
	}
	writeExecutable(t, localBin, name, "#!/usr/bin/env bash\nset -euo pipefail\nfake="+strconv.Quote(fake)+"\n"+body)
}

// Another account takes the stage name before the staging step runs. Staging
// fails, and the route copies nothing there and runs nothing from it.
func TestRemoteAlphaOperatorRoutesStopWhenTheStageNameIsTaken(t *testing.T) {
	for _, route := range remoteAlphaOperatorFakeStageRoutes {
		t.Run(route.name, func(t *testing.T) {
			r := route.setup(t)
			wrapFakeRemoteAlphaCommand(t, r.localBin, "ssh", `
if [[ "${1:-}" != "-tt" && "${2:-}" == "/bin/bash" && "${3:-}" == "-s" && "${4:-}" == "--" && "${5:-}" == /tmp/execution-substrate-remote-alpha-* && ! -e "${FAKE_REMOTE_ROOT}${5}" ]]; then
  mkdir -m 0777 -- "${FAKE_REMOTE_ROOT}${5}"
fi
exec "${fake}" "$@"
`)
			output, err := r.run(t)
			if err == nil {
				t.Fatalf("route succeeded with its stage name taken:\n%s", output)
			}
			if _, err := os.Stat(r.scpLog); !os.IsNotExist(err) {
				t.Errorf("route copied helpers after staging failed: %s", readIfExists(r.scpLog))
			}
			if _, err := os.Stat(r.helperLog); !os.IsNotExist(err) {
				t.Errorf("route ran a helper after staging failed: %s", readIfExists(r.helperLog))
			}
			if sshLog := readIfExists(r.sshLog); strings.Contains(sshLog, "args=exec /bin/bash -c") {
				t.Errorf("route ran its run step after staging failed:\n%s", sshLog)
			}
		})
	}
}

// The stage folder stops being a private folder of the SSH user between the
// copy and the run step: the run step refuses to run anything from it.
func TestRemoteAlphaOperatorRoutesRefuseAStageFolderThatIsNoLongerPrivate(t *testing.T) {
	changes := map[string]string{
		"open":   `chmod 0755 -- "${stage}"`,
		"linked": `if [[ ! -L "${stage}" ]]; then mv -- "${stage}" "${stage}.moved"; ln -s -- "${stage}.moved" "${stage}"; fi`,
	}
	for change, script := range changes {
		for _, route := range remoteAlphaOperatorFakeStageRoutes {
			t.Run(change+"/"+route.name, func(t *testing.T) {
				r := route.setup(t)
				wrapFakeRemoteAlphaCommand(t, r.localBin, "scp", `
"${fake}" "$@"
remote_path="${2#*:}"
name="${remote_path#/tmp/}"
stage="${FAKE_REMOTE_ROOT}/tmp/${name%%/*}"
`+script+"\n")
				output, err := r.run(t)
				if err == nil {
					t.Fatalf("route succeeded with a stage folder that is not private:\n%s", output)
				}
				if _, err := os.Stat(r.scpLog); err != nil {
					t.Fatalf("route did not reach the copy step: %v\n%s", err, output)
				}
				if _, err := os.Stat(r.helperLog); !os.IsNotExist(err) {
					t.Errorf("route ran a helper from a stage folder that is not private: %s", readIfExists(r.helperLog))
				}
				assertContainsAll(t, route.name, output, "the staged helper folder is not a private folder of this user; not running it")
			})
		}
	}
}
