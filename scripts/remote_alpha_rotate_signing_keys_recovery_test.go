package scripts_test

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// Tests of the rotation's rollback, signal and read-back paths that the
// audits of ES PR #76 found no test for (S76-3 of the Sonnet shadow audit,
// F3 and F5 of the Opus re-audit). Each names the change it pins.

// runPausedAt runs the rotation with args until it reaches the test point
// named point, calls during while it waits there, and lets it go on.
func (h *rotationHost) runPausedAt(point string, during func(), args ...string) (string, string, int) {
	h.t.Helper()
	marker := filepath.Join(h.state, "paused")
	saved := h.env
	h.env = append(append([]string{}, h.env...), "SIGNING_KEY_ROTATION_TEST_PAUSE_AT="+point,
		"SIGNING_KEY_ROTATION_TEST_PAUSE_MARKER="+marker)
	cmd := h.command(args...)
	h.env = saved
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Start(); err != nil {
		h.t.Fatal(err)
	}
	h.t.Cleanup(func() { _ = cmd.Process.Kill() })
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()
	deadline := time.Now().Add(60 * time.Second)
	for {
		if _, err := os.Lstat(marker); err == nil {
			break
		}
		select {
		case err := <-exited:
			h.t.Fatalf("%v ended (%v) before it reached %s\nstdout %s\nstderr %s", args, err, point, stdout.String(), stderr.String())
		default:
		}
		if time.Now().After(deadline) {
			h.t.Fatalf("%v did not reach %s", args, point)
		}
		time.Sleep(20 * time.Millisecond)
	}
	during()
	if err := os.Remove(marker); err != nil {
		h.t.Fatal(err)
	}
	code := 0
	if err := <-exited; err != nil {
		exitErr, ok := err.(*exec.ExitError)
		if !ok {
			h.t.Fatal(err)
		}
		code = exitErr.ExitCode()
	}
	return stdout.String(), stderr.String(), code
}

func rotationProblems(report map[string]any) string { return fmt.Sprint(report["problems"]) }

// A rollback that a SIGKILL stops is named by check and apply, with the
// backup that finishes it; rolling that backup back again settles the
// host (Opus re-audit F3).
func TestSigningKeyRotationNamesARollbackThatDidNotFinish(t *testing.T) {
	for _, step := range []string{"stop-ars", "start-ars", "start-es"} {
		t.Run(step, func(t *testing.T) {
			h := newRotationHost(t)
			before := h.snapshot()
			backup := h.apply()["backup_dir"].(string)
			shown := "/" + rotationBackupRoot + "/" + filepath.Base(backup)
			h.mark("signal-KILL-at-" + step)
			if _, stderr, code := h.run("rollback", "--backup-dir", backup); code != -1 && code != 137 {
				t.Fatalf("rollback was not killed at %s: exit %d\n%s", step, code, stderr)
			}
			for _, mode := range []string{"check", "apply"} {
				stdout, stderr, code := h.run(mode)
				report := h.report(stdout, stderr, code)
				if code != 1 || !strings.Contains(rotationProblems(report), "a rollback of "+shown+" did not finish") {
					t.Fatalf("%s after a rollback killed at %s: exit %d problems %v", mode, step, code, report["problems"])
				}
			}
			stdout, stderr, code := h.run("rollback", "--backup-dir", backup)
			if report := h.report(stdout, stderr, code); code != 0 || report["result"] != "rolled_back" {
				t.Fatalf("second rollback: exit %d result %v steps %v\n%s", code, report["result"], report["rollback_steps"], stderr)
			}
			if !reflect.DeepEqual(h.snapshot(), before) {
				t.Fatal("the second rollback did not put the configs and the index back")
			}
			h.requireReady()
		})
	}
}

// A rollback that finds ARS still running after a stop that answered
// success must not put the index back under it, must say rollback_failed,
// and check must name it until a second rollback settles it (Sonnet N02,
// Opus A18 and A52, Opus re-audit F3).
func TestSigningKeyRotationRollbackSaysWhenItCouldNotPutEverythingBack(t *testing.T) {
	h := newRotationHost(t)
	before := h.snapshot()
	backup := h.apply()["backup_dir"].(string)
	afterApply := h.snapshot()
	h.mark("stop-leaves-running-ars-once")
	stdout, stderr, code := h.run("rollback", "--backup-dir", backup)
	report := h.report(stdout, stderr, code)
	if code != 1 || report["result"] != "rollback_failed" {
		t.Fatalf("rollback with ARS still running: exit %d result %v steps %v\n%s", code, report["result"], report["rollback_steps"], stderr)
	}
	if !bytes.Equal(h.snapshot()["index"], afterApply["index"]) {
		t.Fatal("the index was put back while ARS was running")
	}
	stdout, stderr, code = h.run("check")
	if r := h.report(stdout, stderr, code); code != 1 || !strings.Contains(rotationProblems(r), "could not put everything back (rollback_failed)") {
		t.Fatalf("check after a failed rollback: exit %d problems %v", code, r["problems"])
	}
	stdout, stderr, code = h.run("rollback", "--backup-dir", backup)
	if r := h.report(stdout, stderr, code); code != 0 || r["result"] != "rolled_back" {
		t.Fatalf("second rollback: exit %d result %v\n%s", code, r["result"], stderr)
	}
	if !reflect.DeepEqual(h.snapshot(), before) {
		t.Fatal("the second rollback did not put the configs and the index back")
	}
	h.requireReady()
}

// A backup that was rolled back already is not put back again: its index
// copy would drop the records ARS took since (Sonnet shadow audit O-S1).
func TestSigningKeyRotationDoesNotRollBackTwice(t *testing.T) {
	t.Run("after apply rolled itself back", func(t *testing.T) {
		h := newRotationHost(t)
		h.mark("unhealthy-after-es-start-1")
		stdout, stderr, code := h.run("apply")
		report := h.report(stdout, stderr, code)
		if code != 1 || report["result"] != "rolled_back" {
			t.Fatalf("apply: exit %d result %v", code, report["result"])
		}
		h.writeJSON(rotationIndex, map[string]any{"a": 1, "b": 2, "c": 3, "taken-after-the-rollback": 4}, 0o600)
		withNew := h.snapshot()
		stdout, stderr, code = h.run("rollback", "--backup-dir", report["backup_dir"].(string))
		if code != 1 || !strings.Contains(stderr, "was rolled back already (result rolled_back):") {
			t.Fatalf("a second rollback: exit %d\nstdout %s\nstderr %s", code, stdout, stderr)
		}
		if !reflect.DeepEqual(h.snapshot(), withNew) {
			t.Fatal("a refused rollback changed a config or the index")
		}
		h.requireReady()
	})
	t.Run("after the rollback command", func(t *testing.T) {
		h := newRotationHost(t)
		backup := h.apply()["backup_dir"].(string)
		stdout, stderr, code := h.run("rollback", "--backup-dir", backup)
		if r := h.report(stdout, stderr, code); code != 0 || r["result"] != "rolled_back" {
			t.Fatalf("rollback: exit %d result %v", code, r["result"])
		}
		before := h.snapshot()
		if _, stderr, code := h.run("rollback", "--backup-dir", backup); code != 1 || !strings.Contains(stderr, "was rolled back already") {
			t.Fatalf("a second rollback: exit %d\n%s", code, stderr)
		}
		if !reflect.DeepEqual(h.snapshot(), before) {
			t.Fatal("a refused rollback changed a config or the index")
		}
	})
	t.Run("after a rollback whose services did not all answer", func(t *testing.T) {
		h := newRotationHost(t)
		backup := h.apply()["backup_dir"].(string)
		h.mark("fail-stop-es-once")
		stdout, stderr, code := h.run("rollback", "--backup-dir", backup)
		if r := h.report(stdout, stderr, code); code != 1 || r["result"] != "rolled_back_unhealthy" {
			t.Fatalf("rollback: exit %d result %v", code, r["result"])
		}
		before := h.snapshot()
		_, stderr, code = h.run("rollback", "--backup-dir", backup)
		if code != 1 || !strings.Contains(stderr, "was rolled back already (result rolled_back_unhealthy): its files are back") ||
			!strings.Contains(stderr, "start the ones that do not run") {
			t.Fatalf("a second rollback: exit %d\n%s", code, stderr)
		}
		if !reflect.DeepEqual(h.snapshot(), before) {
			t.Fatal("a refused rollback changed a config or the index")
		}
	})
}

// The rollback command records TERM, HUP, INT and QUIT and does not stop
// for them (Sonnet N01, Opus A64).
func TestSigningKeyRotationRollbackCommandHoldsSignals(t *testing.T) {
	for sig, step := range map[string]string{"TERM": "stop-ars", "HUP": "start-ars", "INT": "restart-egs", "QUIT": "start-es"} {
		t.Run(sig, func(t *testing.T) {
			h := newRotationHost(t)
			before := h.snapshot()
			backup := h.apply()["backup_dir"].(string)
			h.mark("signal-" + sig + "-at-" + step)
			stdout, stderr, code := h.run("rollback", "--backup-dir", backup)
			report := h.report(stdout, stderr, code)
			if code != 0 || report["result"] != "rolled_back" || fmt.Sprint(report["signals_received"]) != "[SIG"+sig+"]" {
				t.Fatalf("rollback with SIG%s at %s: exit %d result %v signals %v\n%s", sig, step, code, report["result"], report["signals_received"], stderr)
			}
			if !reflect.DeepEqual(h.snapshot(), before) {
				t.Fatal("the rollback did not put the configs and the index back")
			}
		})
	}
}

// A signal during apply turns into a rollback at the next step: after a
// TERM at the stop of AGS, apply stops nothing more before it rolls back
// (Sonnet N07).
func TestSigningKeyRotationRollsBackAtTheStepAfterASignal(t *testing.T) {
	h := newRotationHost(t)
	before := h.snapshot()
	h.mark("signal-TERM-at-stop-ags")
	stdout, stderr, code := h.run("apply")
	report := h.report(stdout, stderr, code)
	if code != 1 || report["result"] != "rolled_back" {
		t.Fatalf("exit %d result %v failure %v\n%s", code, report["result"], report["failure"], stderr)
	}
	want := []string{"systemctl stop es", "systemctl stop ags", "systemctl stop es", "systemctl stop ags", "systemctl stop ars"}
	if calls := h.serviceCalls(); len(calls) < len(want) || !reflect.DeepEqual(calls[:len(want)], want) {
		t.Fatalf("the forward run went on after the signal: %v", calls)
	}
	if !reflect.DeepEqual(h.snapshot(), before) {
		t.Fatal("not restored")
	}
}

// ARS must accept connections before EGS restarts: apply stops there and
// rolls back (Sonnet N16; the EGS wait has its own test).
func TestSigningKeyRotationWaitsForARSBeforeEGS(t *testing.T) {
	h := newRotationHost(t)
	h.mark("no-listen-once-ars")
	stdout, stderr, code := h.run("apply")
	report := h.report(stdout, stderr, code)
	if code != 1 || report["result"] != "rolled_back" || !strings.Contains(fmt.Sprint(report["failure"]), "ARS does not accept connections") {
		t.Fatalf("exit %d result %v failure %v\n%s", code, report["result"], report["failure"], stderr)
	}
	// The rollback stops ES again and then restarts EGS itself; the forward
	// run must not have restarted EGS before that.
	calls := h.serviceCalls()
	lastStopES, firstRestartEGS := -1, -1
	for i, call := range calls {
		if call == "systemctl stop es" {
			lastStopES = i
		}
		if call == "systemctl restart egs" && firstRestartEGS < 0 {
			firstRestartEGS = i
		}
	}
	if lastStopES <= 0 || firstRestartEGS < lastStopES {
		t.Fatalf("EGS was restarted though ARS did not accept connections: %v", calls)
	}
}

// The backup gets its name only if every config still holds what check
// read: a config changed while the copies were written stops apply before
// anything changes, with no backup left (Sonnet N09: this test point is new).
func TestSigningKeyRotationRechecksTheConfigsBeforeTheBackupIsNamed(t *testing.T) {
	h := newRotationHost(t)
	var edited []byte
	stdout, stderr, code := h.runPausedAt("backup-copied", func() {
		edited = append(h.read(rotationConfigPaths["es"]), '\n')
		h.write(rotationConfigPaths["es"], edited, 0o640)
	}, "apply")
	if code != 1 || stdout != "" || !strings.Contains(stderr, "/etc/execution-substrate/es.json changed while apply ran; nothing was changed") {
		t.Fatalf("apply with es.json changed while the backup was written: exit %d\nstdout %s\nstderr %s", code, stdout, stderr)
	}
	if dirs := h.backupDirs(); len(dirs) != 0 {
		t.Fatalf("a backup was left: %v", dirs)
	}
	if !bytes.Equal(h.read(rotationConfigPaths["es"]), edited) || len(h.serviceCalls()) != 0 {
		t.Fatal("apply changed something")
	}
}

// Each config and the index are read back after the restore puts them
// back; a file that does not hold its backup then makes the result
// rollback_failed (Sonnet N36, Opus A19; these test points are new).
func TestSigningKeyRotationRollbackReadsEachRestoredFileBack(t *testing.T) {
	for point, rel := range map[string]string{"restored-ags.json": rotationConfigPaths["ags"], "restored-index": rotationIndex} {
		t.Run(point, func(t *testing.T) {
			h := newRotationHost(t)
			backup := h.apply()["backup_dir"].(string)
			stdout, stderr, code := h.runPausedAt(point, func() {
				h.write(rel, append(h.read(rel), '\n'), 0o600)
			}, "rollback", "--backup-dir", backup)
			report := h.report(stdout, stderr, code)
			if code != 1 || report["result"] != "rollback_failed" || !strings.Contains(fmt.Sprint(report["rollback_steps"]), "does not match its backup after the restore") {
				t.Fatalf("rollback with %s changed after its restore: exit %d result %v steps %v\n%s", rel, code, report["result"], report["rollback_steps"], stderr)
			}
		})
	}
}

// Each config is read back after apply writes it: one that another writer
// changed between the temporary file and the rename makes apply roll back
// (Opus A12).
func TestSigningKeyRotationReadsEachWrittenConfigBack(t *testing.T) {
	h := newRotationHost(t)
	original := h.read(rotationConfigPaths["ags"])
	h.env = []string{"SIGNING_KEY_ROTATION_TEST_TEMP_SUFFIX=fixed"}
	stdout, stderr, code := h.runPausedAt("config-temp-written:ags", func() {
		if err := os.WriteFile(h.path("etc/execution-substrate/.ags.json.signing-key-rotation.fixed"), original, 0o640); err != nil {
			t.Fatal(err)
		}
	}, "apply")
	report := h.report(stdout, stderr, code)
	if code != 1 || report["result"] != "rolled_back" || !strings.Contains(fmt.Sprint(report["failure"]), "does not hold the rotated config after the write") {
		t.Fatalf("exit %d result %v failure %v\n%s", code, report["result"], report["failure"], stderr)
	}
}

// rollback puts back only a folder directly under the backup root, even an
// exact copy of a real backup (Sonnet N34, Opus A25).
func TestSigningKeyRotationRollbackRefusesABackupOutsideTheRoot(t *testing.T) {
	h := newRotationHost(t)
	backup := h.apply()["backup_dir"].(string)
	elsewhere := h.path("var/tmp/" + filepath.Base(backup))
	if err := os.MkdirAll(elsewhere, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(elsewhere, 0o700); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(backup)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		data, err := os.ReadFile(filepath.Join(backup, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		h.write(strings.TrimPrefix(filepath.Join(elsewhere, entry.Name()), h.root+"/"), data, 0o600)
	}
	before, calls := h.snapshot(), len(h.serviceCalls())
	stdout, stderr, code := h.run("rollback", "--backup-dir", elsewhere)
	if code != 1 || !strings.Contains(stderr, "is not a folder directly under /var/backups/execution-substrate-signing-keys") {
		t.Fatalf("rollback of a copy outside the backup root: exit %d\nstdout %s\nstderr %s", code, stdout, stderr)
	}
	if !reflect.DeepEqual(h.snapshot(), before) || len(h.serviceCalls()) != calls {
		t.Fatal("a refused rollback changed something")
	}
}

// rollback removes an unfinished backup folder only when root owns it
// (Sonnet N33, Opus A24).
func TestSigningKeyRotationRollbackKeepsAnUnfinishedBackupOfAnotherOwner(t *testing.T) {
	h := newRotationHost(t)
	folder := h.path(rotationBackupRoot + "/.incomplete-20261127T000000Z-ags-0000000000000000")
	if err := os.MkdirAll(folder, 0o700); err != nil {
		t.Fatal(err)
	}
	h.env = []string{fmt.Sprintf("SIGNING_KEY_ROTATION_TEST_ROOT_UID=%d", os.Getuid()+1)}
	_, stderr, code := h.run("rollback", "--backup-dir", folder)
	if _, err := os.Lstat(folder); err != nil || code != 1 || !strings.Contains(stderr, "is not a folder root owns") {
		t.Fatalf("rollback of an unfinished folder another uid owns: exit %d, kept %v\n%s", code, err == nil, stderr)
	}
}

// A command that outlives its time limit is ended with every process it
// started: the rotation starts each in a process group of its own and kills
// the group (Sonnet N19, Opus A50).
func TestSigningKeyRotationTimeoutEndsTheWholeProcessGroup(t *testing.T) {
	dir := t.TempDir()
	beat := filepath.Join(dir, "beat")
	script := fmt.Sprintf(`
import importlib.util, os, sys, time
spec = importlib.util.spec_from_file_location("rotation", sys.argv[1])
rotation = importlib.util.module_from_spec(spec)
spec.loader.exec_module(rotation)
try:
    rotation.run(["/bin/sh", "-c", "(while :; do echo x >> %s; sleep 0.05; done) & sleep 300"], timeout=1)
except rotation.Refusal as exc:
    print("refused:", exc)
time.sleep(0.3)
first = os.path.getsize(%q)
time.sleep(0.6)
print("grows:", os.path.getsize(%q) > first)
`, beat, beat, beat)
	cmd := exec.Command("python3", "-I", "-B", "-c", script, repoPath(rotateSigningKeysPython))
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if !strings.Contains(string(out), "did not finish within 1 s") || !strings.Contains(string(out), "grows: False") {
		t.Fatalf("a timed-out command's child kept running:\n%s", out)
	}
}

// The health calls go over HTTPS only, with the CA and the operator
// certificate and key that healthcheck.env names, and ~/.curlrc unread
// (Sonnet N20, N21, N22).
func TestSigningKeyRotationHealthCallsUseTheOperatorCertificate(t *testing.T) {
	h := newRotationHost(t)
	script := fmt.Sprintf("#!/usr/bin/env bash\necho \"curl-args $*\" >> %q\nprintf 200\n", filepath.Join(h.state, "calls.log"))
	if err := os.WriteFile(filepath.Join(h.bin, "curl"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	h.requireReady()
	lines := h.calls("curl-args")
	if len(lines) != 3 {
		t.Fatalf("health calls: %v", lines)
	}
	for _, line := range lines {
		if !strings.HasPrefix(line, "curl-args -q ") {
			t.Fatalf("a health call does not start with -q: %s", line)
		}
		for _, want := range []string{"--proto =https", "--cacert /etc/execution-substrate/tls/ca.pem", "--cert /etc/x/op.pem",
			"--key /etc/x/op-key.pem", " https://127.0.0.1:"} {
			if !strings.Contains(line, want) {
				t.Fatalf("a health call lacks %q: %s", want, line)
			}
		}
	}
}
