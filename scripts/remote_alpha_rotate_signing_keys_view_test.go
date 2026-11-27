package scripts_test

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Tests of what the rotation asks of the running services and of systemd:
// that each service sees the host's own config and index files (red-team
// RT10-4), that a starting ARS is not taken for a stopped one, that a
// --host-root bind of / is the host (red-team re-check 19, RT19-2), and
// that a rollback that cannot keep the index it replaces leaves it alone.

var rotationServiceFiles = []string{
	"etc/execution-substrate/ags.json", "etc/execution-substrate/egs.json", "etc/execution-substrate/es.json",
	"etc/execution-substrate/ars.json", rotationIndex,
}

// otherRoot makes a folder a unit can be shown as its root folder, holding
// a copy of each config and of the index at the paths the unit reads: the
// files a unit with a RootDirectory= or BindPaths= of its own would read.
func (h *rotationHost) otherRoot() string {
	h.t.Helper()
	real, err := filepath.EvalSymlinks(h.root)
	if err != nil {
		h.t.Fatal(err)
	}
	other := filepath.Join(h.t.TempDir(), "other")
	for _, rel := range rotationServiceFiles {
		path := filepath.Join(other, real, rel)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			h.t.Fatal(err)
		}
		if err := os.WriteFile(path, h.read(rel), 0o644); err != nil {
			h.t.Fatal(err)
		}
	}
	return other
}

// showRoot makes the unit's stand-in process see root as its root folder.
func (h *rotationHost) showRoot(unit, root string) {
	h.t.Helper()
	pid := map[string]string{"ars": "4101", "egs": "4102", "ags": "4103", "es": "4104"}[unit]
	link := filepath.Join(h.state, "proc", pid, "root")
	if err := os.Remove(link); err != nil {
		h.t.Fatal(err)
	}
	if err := os.Symlink(root, link); err != nil {
		h.t.Fatal(err)
	}
}

// The ExecStart rule pins the command line only. A unit's own root folder
// or mounts can show its service other files under the config's name, and
// the service would then keep the retired key while apply said rotated.
// check and apply compare each config (and ARS's index) with the file the
// unit's main process sees there, and refuse before anything changes.
func TestSigningKeyRotationRefusesAServiceThatSeesOtherFiles(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(h *rotationHost)
		want  string
	}{
		{"AGS has a root folder of its own", func(h *rotationHost) { h.showRoot("ags", h.otherRoot()) },
			"ags sees another file at /etc/execution-substrate/ags.json than the host has there"},
		{"ES sees a symbolic link where its config is", func(h *rotationHost) {
			other := h.otherRoot()
			real, err := filepath.EvalSymlinks(h.root)
			if err != nil {
				t.Fatal(err)
			}
			link := filepath.Join(other, real, "etc/execution-substrate/es.json")
			if err := os.Remove(link); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(h.path("etc/execution-substrate/es.json"), link); err != nil {
				t.Fatal(err)
			}
			h.showRoot("es", other)
		}, "/etc/execution-substrate/es.json is a symbolic link there"},
		{"AGS has no main process", func(h *rotationHost) { h.markWith("mainpid-ags", "0") },
			"ags.service has no main process, so the files it reads cannot be compared"},
		{"ARS's main process is gone", func(h *rotationHost) { h.markWith("mainpid-ars", "4999") },
			"cannot see /etc/execution-substrate/ars.json as ars sees it"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newRotationHost(t)
			tc.setup(h)
			before := h.snapshot()
			stdout, stderr, code := h.run("check")
			if r := h.report(stdout, stderr, code); code != 1 || !strings.Contains(rotationProblems(r), tc.want) {
				t.Fatalf("check: exit %d problems %v, want %q", code, r["problems"], tc.want)
			}
			stdout, stderr, code = h.run("apply")
			if code != 1 || !strings.Contains(stdout, tc.want) || !strings.Contains(stderr, "nothing was changed") {
				t.Fatalf("apply: exit %d\nstdout %s\nstderr %s", code, stdout, stderr)
			}
			if !reflect.DeepEqual(h.snapshot(), before) || len(h.backupDirs()) != 0 {
				t.Fatalf("a refused apply changed the host: backups %v", h.backupDirs())
			}
		})
	}
}

// After the restarts, apply asks again: a unit restarted into a root
// folder of its own, or a config a command at the unit's start rewrote, is
// a failure, and apply rolls back. A unit that keeps its own root folder
// when the rollback restarts it still sees other files, so the rollback
// ends rollback_failed, and a second one settles it once the unit sees the
// host's files.
func TestSigningKeyRotationRollsBackWhenARestartedServiceSeesOtherFiles(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(h *rotationHost)
		want  string
		// unit still sees its own root folder when the rollback restarts it,
		// so the rollback ends rollback_failed until it sees the host's
		// files again; "" when nothing is left for the rollback to find.
		unit string
	}{
		{"EGS restarted with a root folder of its own", func(h *rotationHost) {
			h.markWith("proc-root-once-at-restart-egs", h.otherRoot())
		}, "egs sees another file at /etc/execution-substrate/egs.json than the host has there", "egs"},
		{"ARS restarted with a root folder of its own", func(h *rotationHost) {
			h.markWith("proc-root-once-at-restart-ars", h.otherRoot())
		}, "ars sees another file at /etc/execution-substrate/ars.json than the host has there", "ars"},
		{"AGS's config written again when it starts", func(h *rotationHost) {
			h.markWith("write-config-once-at-restart-ags", string(h.read(rotationConfigPaths["ags"])))
		}, "/etc/execution-substrate/ags.json no longer holds what the rotation wrote after ags restarted", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newRotationHost(t)
			before := h.snapshot()
			tc.setup(h)
			stdout, stderr, code := h.run("apply")
			report := h.report(stdout, stderr, code)
			want := "rolled_back"
			if tc.unit != "" {
				want = "rollback_failed"
			}
			if code != 1 || report["result"] != want || !strings.Contains(fmt.Sprint(report["failure"]), tc.want) {
				t.Fatalf("apply: exit %d result %v failure %v, want %s and %q\n%s", code, report["result"], report["failure"], want, tc.want, stderr)
			}
			if !reflect.DeepEqual(h.snapshot(), before) {
				t.Fatal("the rollback did not put the configs and the index back")
			}
			if tc.unit != "" {
				if failure := fmt.Sprint(report["rollback_failure"]); !strings.Contains(failure, tc.want) {
					t.Fatalf("the rollback's failure %q does not name %q", failure, tc.want)
				}
				h.showRoot(tc.unit, "/")
				stdout, stderr, code = h.run("check")
				if r := h.report(stdout, stderr, code); code != 1 || !strings.Contains(rotationProblems(r), "could not put everything back (rollback_failed)") {
					t.Fatalf("check after the failed rollback: exit %d problems %v", code, r["problems"])
				}
				stdout, stderr, code = h.run("rollback", "--backup-dir", report["backup_dir"].(string))
				if r := h.report(stdout, stderr, code); code != 0 || r["result"] != "rolled_back" || !reflect.DeepEqual(h.snapshot(), before) {
					t.Fatalf("the second rollback: exit %d result %v failure %v\n%s", code, r["result"], r["rollback_failure"], stderr)
				}
			}
			h.requireReady()
		})
	}
}

// A rollback compares what it put back the way apply compares what it
// wrote: once the services have restarted, each unit that runs must see
// the host's config (and ARS its index), and each config must still hold
// the copy put back, since a command a unit runs when it starts could
// write it again. Otherwise the rollback ends rollback_failed, check names
// the backup, and a second rollback settles it (Codex review of ES PR #76
// at afb5bac). A unit that does not run after the rollback, or whose
// process is gone on every read, is the health check's to judge:
// TestSigningKeyRotationRollbackTriesEveryStep ends rolled_back_unhealthy.
func TestSigningKeyRotationRollbackComparesWhatItPutBackAfterTheRestarts(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(h *rotationHost)
		fix   func(h *rotationHost)
		want  string
	}{
		{"a config written again when its unit starts", func(h *rotationHost) {
			// What a unit that renders its config when it starts writes:
			// the rotated config the rollback replaced.
			h.markWith("write-config-once-at-restart-ags", string(h.read(rotationConfigPaths["ags"])))
		}, func(*rotationHost) {}, "/etc/execution-substrate/ags.json no longer holds what the rollback put back after ags restarted"},
		{"AGS restarted with a root folder of its own", func(h *rotationHost) {
			h.markWith("proc-root-once-at-restart-ags", h.otherRoot())
		}, func(h *rotationHost) { h.showRoot("ags", "/") },
			"ags sees another file at /etc/execution-substrate/ags.json than the host has there"},
		{"ARS restarted with a root folder of its own", func(h *rotationHost) {
			h.markWith("proc-root-once-at-restart-ars", h.otherRoot())
		}, func(h *rotationHost) { h.showRoot("ars", "/") },
			"ars sees another file at /var/lib/ars/index.json than the host has there"},
		// AGS's process sees another file on the first read and is gone on
		// the next two: what was seen is still named, not cleared by a
		// process that is gone (as one systemd restarts would be).
		{"AGS seen with a root folder of its own, then gone", func(h *rotationHost) {
			seen := filepath.Join(h.state, "proc", "4199")
			if err := os.MkdirAll(seen, 0o755); err != nil {
				h.t.Fatal(err)
			}
			if err := os.Symlink(h.otherRoot(), filepath.Join(seen, "root")); err != nil {
				h.t.Fatal(err)
			}
			h.markWith("mainpid-seq-ags", "4199\n4198\n4198\n")
		}, func(*rotationHost) {}, "ags sees another file at /etc/execution-substrate/ags.json than the host has there"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newRotationHost(t)
			before := h.snapshot()
			backup := h.apply()["backup_dir"].(string)
			tc.setup(h)
			stdout, stderr, code := h.run("rollback", "--backup-dir", backup)
			report := h.report(stdout, stderr, code)
			if failure := fmt.Sprint(report["rollback_failure"]); code != 1 || report["result"] != "rollback_failed" || !strings.Contains(failure, tc.want) {
				t.Fatalf("rollback: exit %d result %v failure %s, want %q\n%s", code, report["result"], failure, tc.want, stderr)
			}
			stdout, stderr, code = h.run("check")
			if r := h.report(stdout, stderr, code); code != 1 || !strings.Contains(rotationProblems(r), "could not put everything back (rollback_failed)") {
				t.Fatalf("check after the failed rollback: exit %d problems %v", code, r["problems"])
			}
			tc.fix(h)
			stdout, stderr, code = h.run("rollback", "--backup-dir", backup)
			if r := h.report(stdout, stderr, code); code != 0 || r["result"] != "rolled_back" {
				t.Fatalf("the second rollback: exit %d result %v failure %v\n%s", code, r["result"], r["rollback_failure"], stderr)
			}
			if !reflect.DeepEqual(h.snapshot(), before) {
				t.Fatal("the second rollback did not put the configs and the index back")
			}
			h.requireReady()
		})
	}

	// apply's own rollback: ES does not answer after the restarts, and AGS
	// writes the rotated config again when the rollback restarts it (the
	// rollback puts EGS's config back first, so AGS's still holds the
	// rotated one when the rollback has just put EGS's back).
	t.Run("apply's own rollback", func(t *testing.T) {
		h := newRotationHost(t)
		before := h.snapshot()
		h.mark("unhealthy-after-es-start-1")
		stdout, stderr, code := h.runPausedAt("restored-egs.json", func() {
			h.markWith("write-config-once-at-restart-ags", string(h.read(rotationConfigPaths["ags"])))
		}, "apply")
		report := h.report(stdout, stderr, code)
		want := "/etc/execution-substrate/ags.json no longer holds what the rollback put back after ags restarted"
		if failure := fmt.Sprint(report["rollback_failure"]); code != 1 || report["result"] != "rollback_failed" || !strings.Contains(failure, want) {
			t.Fatalf("apply: exit %d result %v failure %s, want %q\n%s", code, report["result"], failure, want, stderr)
		}
		backup := report["backup_dir"].(string)
		if summary, err := os.ReadFile(filepath.Join(backup, "summary.json")); err != nil || !strings.Contains(string(summary), `"result": "rollback_failed"`) {
			t.Fatalf("summary.json does not record rollback_failed: %v\n%s", err, summary)
		}
		stdout, stderr, code = h.run("rollback", "--backup-dir", backup)
		if r := h.report(stdout, stderr, code); code != 0 || r["result"] != "rolled_back" || !reflect.DeepEqual(h.snapshot(), before) {
			t.Fatalf("the second rollback: exit %d result %v failure %v\n%s", code, r["result"], r["rollback_failure"], stderr)
		}
		h.requireReady()
	})
}

// startSeenBy starts a process that stands in for the unit's main process,
// in a mount namespace of its own when mounts is not empty (each pair binds
// its first file over its second), and names it in the fake systemctl's
// MainPID. It returns once the process sleeps, its mounts made.
func (h *rotationHost) startSeenBy(unit string, mounts [][2]string) {
	h.t.Helper()
	script := ""
	for _, m := range mounts {
		script += fmt.Sprintf("mount --bind %q %q && ", m[0], m[1])
	}
	argv := []string{"unshare", "-m", "sh", "-c", script + "exec sleep 600"}
	if len(mounts) == 0 {
		argv = []string{"sleep", "600"}
	}
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Dir = h.state
	if err := cmd.Start(); err != nil {
		h.t.Fatal(err)
	}
	h.t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	})
	deadline := time.Now().Add(10 * time.Second)
	for {
		comm, _ := os.ReadFile(fmt.Sprintf("/proc/%d/comm", cmd.Process.Pid))
		if strings.TrimSpace(string(comm)) == "sleep" {
			break
		}
		if time.Now().After(deadline) {
			h.t.Fatalf("the stand-in of %s did not start: %q", unit, comm)
		}
		time.Sleep(20 * time.Millisecond)
	}
	h.markWith("mainpid-"+unit, strconv.Itoa(cmd.Process.Pid))
}

// rotationMountNamespaceProbe asks the kernel for a mount namespace.
func rotationMountNamespaceProbe(t *testing.T) error {
	probe := exec.Command("unshare", "-m", "true")
	probe.Dir = t.TempDir()
	return probe.Run()
}

// The same with the kernel's own view: real processes, the real /proc, and
// a mount namespace in which a file is bound over a config or the index,
// as systemd makes one for a unit with BindPaths= or RootDirectory=. Needs
// root to make the mounts; the CI job runs it as root.
func TestSigningKeyRotationSeesTheFilesEachServiceSeesAsRoot(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to make mount namespaces and mounts")
	}
	if err := rotationMountNamespaceProbe(t); err != nil {
		t.Skipf("no mount namespaces here: %v", err)
	}
	for _, tc := range []struct {
		name, unit, rel, want string
	}{
		{"none", "", "", ""},
		{"a file bound over AGS's config", "ags", rotationConfigPaths["ags"],
			"ags sees another file at /etc/execution-substrate/ags.json than the host has there"},
		{"a file bound over ARS's index", "ars", rotationIndex,
			"ars sees another file at /var/lib/ars/index.json than the host has there"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newRotationHost(t)
			h.env = []string{"SIGNING_KEY_ROTATION_TEST_PROC=/proc"}
			for _, unit := range []string{"ars", "egs", "ags", "es"} {
				var mounts [][2]string
				if unit == tc.unit {
					copyPath := filepath.Join(t.TempDir(), "copy")
					if err := os.WriteFile(copyPath, h.read(tc.rel), 0o644); err != nil {
						t.Fatal(err)
					}
					mounts = [][2]string{{copyPath, h.path(tc.rel)}}
				}
				h.startSeenBy(unit, mounts)
			}
			stdout, stderr, code := h.run("check")
			r := h.report(stdout, stderr, code)
			if tc.want == "" {
				if code != 0 || r["result"] != "ready" {
					t.Fatalf("check with every service seeing the host's files: exit %d problems %v\n%s", code, r["problems"], stderr)
				}
				return
			}
			if code != 1 || !strings.Contains(rotationProblems(r), tc.want) {
				t.Fatalf("check: exit %d problems %v, want %q", code, r["problems"], tc.want)
			}
		})
	}
}

// A --host-root that is a bind mount of / is the host itself (Sonnet O-S3):
// it never turns the test hooks on over the host's files. Red-team re-check
// 19 found that no test pinned it (mutant M25). Needs root to make the
// mount; the CI job runs it as root.
func TestSigningKeyRotationHostRootBoundToSlashIsTheHostAsRoot(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to make a mount namespace and a bind mount")
	}
	if err := rotationMountNamespaceProbe(t); err != nil {
		t.Skipf("no mount namespaces here: %v", err)
	}
	bind := filepath.Join(t.TempDir(), "slash")
	if err := os.Mkdir(bind, 0o755); err != nil {
		t.Fatal(err)
	}
	hook := "/nonexistent/rotation-test-hook-systemctl"
	script := fmt.Sprintf("mount --bind / %q && exec python3 -I -B %q --host-root %q check", bind, repoPath(rotateSigningKeysPython), bind)
	cmd := exec.Command("unshare", "-m", "sh", "-c", script)
	cmd.Dir = t.TempDir()
	// The hook would turn on under a test host root; the clone check of the
	// host runs, and refuses a clone root does not own, as the CI's is.
	cmd.Env = append(os.Environ(), "SIGNING_KEY_ROTATION_TEST_SYSTEMCTL="+hook)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	_ = cmd.Run()
	out := stdout.String() + stderr.String()
	if strings.Contains(out, hook) || strings.Contains(out, fmt.Sprintf(`"host_root": %q`, bind)) {
		t.Fatalf("a --host-root bound to / turned the test hooks on:\n%s", out)
	}
	if !strings.Contains(out, `"host_root": "/"`) && !strings.Contains(out, "can change the code") {
		t.Fatalf("a --host-root bound to / did not run as the host:\n%s", out)
	}
}

// An ARS that systemd reports as activating right after the rotation
// stopped it (something else is starting it) is not stopped: apply must
// not replace the index under it (red-team re-check 19, mutant M34).
func TestSigningKeyRotationRefusesAnARSThatIsStartingAfterTheStop(t *testing.T) {
	h := newRotationHost(t)
	before := h.snapshot()
	h.markWith("stopped-state-ars", "activating")
	stdout, stderr, code := h.run("apply")
	report := h.report(stdout, stderr, code)
	if code != 1 || report["result"] != "rolled_back" || !strings.Contains(fmt.Sprint(report["failure"]), "ars is activating after systemctl stop ars") {
		t.Fatalf("apply with ARS activating after the stop: exit %d result %v failure %v\n%s", code, report["result"], report["failure"], stderr)
	}
	if !reflect.DeepEqual(h.snapshot(), before) {
		t.Fatal("the rollback did not put the configs and the index back")
	}
}

// rotationFullDiskAtKeep runs the helper with every creation of a kept
// copy of the index failing as a full disk would.
const rotationFullDiskAtKeep = `import errno, os, runpy, sys
real = os.open
def fake_open(path, flags, *args, **kwargs):
    if os.path.basename(str(path)).startswith("ars-index.replaced-"):
        raise OSError(errno.ENOSPC, "No space left on device")
    return real(path, flags, *args, **kwargs)
os.open = fake_open
helper = sys.argv[1]
sys.argv = [helper] + sys.argv[2:]
runpy.run_path(helper, run_name="__main__")
`

// A rollback that cannot keep the index it would replace (a full disk)
// leaves the index in place, ends rollback_failed and is named by check
// until a rollback settles it (red-team re-check 19, mutant M06).
func TestSigningKeyRotationRollbackThatCannotKeepTheIndexLeavesItInPlace(t *testing.T) {
	h := newRotationHost(t)
	before := h.snapshot()
	backup := h.apply()["backup_dir"].(string)
	h.writeJSON(rotationIndex, map[string]any{"d": 4}, 0o600)
	withD := h.read(rotationIndex)
	wrapper := filepath.Join(h.bin, "full_disk_at_keep.py")
	if err := os.WriteFile(wrapper, []byte(rotationFullDiskAtKeep), 0o644); err != nil {
		t.Fatal(err)
	}
	cmd := h.command("rollback", "--backup-dir", backup)
	cmd.Args = append([]string{"python3", "-I", "-B", wrapper}, cmd.Args[3:]...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	code := 0
	if err := cmd.Run(); err != nil {
		exitErr, ok := err.(*exec.ExitError)
		if !ok {
			t.Fatal(err)
		}
		code = exitErr.ExitCode()
	}
	report := h.report(stdout.String(), stderr.String(), code)
	if code != 1 || report["result"] != "rollback_failed" || !bytes.Equal(h.read(rotationIndex), withD) {
		t.Fatalf("rollback that cannot keep the index: exit %d result %v steps %v\n%s", code, report["result"], report["rollback_steps"], stderr.String())
	}
	stdout2, stderr2, code := h.run("check")
	if r := h.report(stdout2, stderr2, code); code != 1 || !strings.Contains(rotationProblems(r), "could not put everything back (rollback_failed)") {
		t.Fatalf("check after the failed rollback: exit %d problems %v", code, r["problems"])
	}
	stdout2, stderr2, code = h.run("rollback", "--backup-dir", backup)
	report = h.report(stdout2, stderr2, code)
	if code != 0 || report["result"] != "rolled_back" || !reflect.DeepEqual(h.snapshot(), before) {
		t.Fatalf("the second rollback: exit %d result %v\n%s", code, report["result"], stderr2)
	}
	if data, err := os.ReadFile(fmt.Sprint(report["replaced_index_kept"])); err != nil || !bytes.Equal(data, withD) {
		t.Fatalf("the second rollback kept %q (%v), want the index with record d", data, err)
	}
}
