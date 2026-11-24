package scripts_test

// Red-team re-check 14 of PR #50, O14-1: the operator's Vault and
// healthcheck routes staged helpers under fixed /tmp parents made with
// mkdir -p, which another account could create first and own. The stage
// folders now sit directly under /tmp and are made with mkdir and no -p, and
// cleanup removes only a real folder the SSH user owns.

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
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
	start := "<<'" + tag + "'\n"
	i := strings.Index(operator, start)
	if i < 0 {
		t.Fatalf("operator has no heredoc %s", tag)
	}
	body := operator[i+len(start):]
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
