package scripts_test

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Re-check 52 of ES PR #83, A52-2: HashiCorp's nomad package makes
// /opt/nomad/data and gives it to the nomad account on each install or
// upgrade, and while that account owns it, it can rename root's entries
// there; with Nomad's server folder renamed, Nomad starts a new cluster and
// hands out a new ACL bootstrap token. apply moves Nomad's state to
// /opt/nomad/es-data, which the package never touches, with the setup's
// nomad_data_move, and a rollback moves it back.

// A host whose state moved is held to where apply left it. Anything else at
// either folder is refused, with nothing changed. A dpkg run that makes the
// package's folder again, empty, is accepted: the take-back program makes
// it root's.
func TestRemoteAlphaUpgradeESRefusesANomadDataFolderItCannotTellApart(t *testing.T) {
	helper := buildESConfigCheck(t)
	cutOff := "; an apply cut off while it moved Nomad's state is undone by rolling back its backup"
	notAlone := "Nomad's data folder: nomad.hcl names /opt/nomad/es-data, but Nomad's state is not there alone, with /opt/nomad/data missing or empty "
	for _, tc := range []struct {
		name, scope, says string
		break_            func(h *upgradeHost)
	}{
		{"the package's data folder holds entries again", "shape", "Nomad's data folder: unknown (nomad data: Nomad's state cannot be told apart: ",
			func(h *upgradeHost) {
				h.write(hostPackageData+"/server/raft/raft.db", "a new cluster\n", 0o600)
				_ = os.Chmod(h.path(hostPackageData), 0o700)
			}},
		{"a file of root's that is not the stand-in at the package's data folder", "shape",
			"Nomad's data folder: unknown (nomad data: Nomad's state cannot be told apart: ",
			func(h *upgradeHost) { h.write(hostPackageData, "not the stand-in\n", 0o600) }},
		{"the stand-in still at the package's data folder: an apply cut off before it removed it", "shape",
			notAlone + "(nomad_data_move plan: keep)" + cutOff,
			func(h *upgradeHost) { writeNomadStandIn(h, hostPackageData) }},
		{"the folder Nomad's state moved to is empty", "shape", notAlone + "(nomad_data_move plan: keep)" + cutOff,
			func(h *upgradeHost) {
				_ = os.RemoveAll(h.path(hostMovedData))
				h.mkdir(hostMovedData, 0o700)
			}},
		{"the folder Nomad's state moved to is missing", "shape", notAlone + "(nomad_data_move plan: new)" + cutOff,
			func(h *upgradeHost) { _ = os.RemoveAll(h.path(hostMovedData)) }},
		{"the folder Nomad's state moved to is a link", "shape", "Nomad's data folder: unknown (nomad data: Nomad's state cannot be told apart: ",
			func(h *upgradeHost) {
				if err := os.Rename(h.path(hostMovedData), h.path("var/backups/es-data")); err != nil {
					h.t.Fatal(err)
				}
				if err := os.Symlink(h.path("var/backups/es-data"), h.path(hostMovedData)); err != nil {
					h.t.Fatal(err)
				}
			}},
		{"the folder Nomad's state moved to is group-readable", "nomad_dirs", "/opt/nomad/es-data is not a root:root 0700 directory",
			func(h *upgradeHost) { _ = os.Chmod(h.path(hostMovedData), 0o750) }},
		{"the package's data folder, made again, is group-readable", "nomad_dirs", "/opt/nomad/data is not a root:root 0700 directory",
			func(h *upgradeHost) { h.mkdir(hostPackageData, 0o750) }},
		{"no keyring where Nomad's state moved", "shape",
			"Nomad's data folder: moved (in /opt/nomad/es-data, which the nomad package never touches); Nomad's gossip keyring: absent",
			func(h *upgradeHost) { _ = os.Remove(h.path(hostMovedGossipKeyring)) }},
		{"nomad.hcl names the package's data folder again", "shape",
			"Nomad's data folder: nomad.hcl names /opt/nomad/data, but Nomad's state is not there alone (nomad_data_move plan: keep)" + cutOff,
			func(h *upgradeHost) { h.write("etc/nomad.d/nomad.hcl", boxNomadHCLHTTPS, 0o640) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newUpgradeHost(t, helper)
			h.toHTTPSMoved(previousESCommit)
			tc.break_(h)
			before := h.snapshot()
			report, stderr, code := h.check()
			found := false
			for _, b := range report["blockers"].([]any) {
				blocker := b.(map[string]any)
				if blocker["scope"] == tc.scope && strings.Contains(blocker["summary"].(string), tc.says) {
					found = true
				}
			}
			if code != 1 || !found {
				t.Fatalf("check: exit %d, no %s blocker saying %q in %v; %s", code, tc.scope, tc.says, report["blockers"], stderr)
			}
			if _, stderr, code := h.apply(); code != 1 || !strings.Contains(stderr, "nothing was changed") {
				t.Fatalf("apply: exit %d: %s", code, stderr)
			}
			onlyReads(t, h, "a refused check and apply")
			if dirs := backupDirs(t, h); len(dirs) != 0 {
				t.Fatalf("the refused apply wrote %v", dirs)
			}
			assertRestored(t, before, h.snapshot())
		})
	}

	// A dpkg run makes the package's data folder again, and the take-back
	// program makes it root's 0700: check finds the host where apply left
	// it, and apply changes nothing.
	t.Run("the package's data folder made again, empty, by dpkg", func(t *testing.T) {
		h := newUpgradeHost(t, helper)
		if stdout, stderr, code := h.apply(); code != 0 {
			t.Fatalf("apply exited %d\nstdout %s\nstderr %s", code, stdout, stderr)
		}
		h.mkdir(hostPackageData, 0o700)
		before := h.snapshot()
		h.clearCalls()
		report, stderr, code := h.check()
		if code != 0 || report["shape"] != "https-gossip" || report["result"] != "nothing to do" {
			t.Fatalf("check: exit %d, shape %v, result %v, blockers %v, %s", code, report["shape"], report["result"], report["blockers"], stderr)
		}
		if part := fmt.Sprint(report["parts"].(map[string]any)["Nomad's data folder"]); part != "moved (in /opt/nomad/es-data, which the nomad package never touches)" {
			t.Fatalf("data folder part %q", part)
		}
		if stdout, stderr, code := h.apply(); code != 0 || !strings.Contains(stdout, `"result": "nothing to do"`) {
			t.Fatalf("apply: exit %d\nstdout %s\nstderr %s", code, stdout, stderr)
		}
		onlyReads(t, h, "a check and an apply of a host whose package's data folder dpkg made again")
		assertRestored(t, before, h.snapshot())
	})
}

// cutAfterSwap patches apply so that it stops right after nomad_data_move
// has swapped Nomad's state out of the package's data folder, before
// nomad.hcl names the new folder: first it starts Nomad, as a dpkg run's
// postrm or a reboot would in that moment, then it fails (raise) or the
// process dies with no rollback (kill).
const cutAfterSwap = `import os, signal
_move = m.move_nomad_data
def _cut(src, dst, log):
    _move(src, dst, log)
    if src == m.NOMAD_PACKAGE_DATA_DIR:
        m.run(["systemctl", "start", "nomad"], timeout=60)
        if os.environ.get("CUT") == "kill":
            os.kill(os.getpid(), signal.SIGKILL)
        raise OSError(5, "Input/output error")
m.move_nomad_data = _cut`

// Between the swap and the new nomad.hcl, a Nomad that starts finds the
// stand-in where its old nomad.hcl keeps its state and does not start,
// rather than starting a new cluster in an empty folder. A failure there
// rolls the host back; a run that dies there leaves a host that check
// refuses, until the backup's rollback moves Nomad's state back.
func TestRemoteAlphaUpgradeESRollsBackAnApplyCutOffAfterItsSwap(t *testing.T) {
	helper := buildESConfigCheck(t)
	for _, start := range []string{"locked-http", "https"} {
		for _, cut := range []string{"raise", "kill"} {
			t.Run(start+" "+cut, func(t *testing.T) {
				h := newUpgradeHost(t, helper)
				if start == "https" {
					h.toHTTPSWithoutKeyring(previousESCommit)
				}
				before := h.snapshot()
				h.env["CUT"] = cut
				_, stderr, code := runWithPatchedUpgrade(h, cutAfterSwap, "apply", "--payload", h.payload, "--commit", upgradeTestCommit)
				delete(h.env, "CUT")
				log := mustRead(t, filepath.Join(h.state, "calls.log"))
				if !strings.Contains(log, "start nomad: data_dir "+h.path(hostPackageData)+" is not a folder") {
					t.Fatalf("Nomad started while its state was moving:\n%s", log)
				}
				if fresh, err := os.ReadFile(filepath.Join(h.state, "fresh-nomad-state")); err == nil {
					t.Fatalf("Nomad started in a new, empty data folder: %s", fresh)
				}
				if cut == "raise" {
					if code != 1 || !strings.Contains(stderr, "apply failed; result rolled_back;") {
						t.Fatalf("apply exited %d: %s", code, stderr)
					}
					_, summary := readSummary(t, h)
					if rollback := summary["rollback"].(map[string]any); rollback["moved_back"] != true {
						t.Fatalf("the rollback did not move Nomad's state back: %v", rollback)
					}
					assertRestored(t, before, h.snapshot())
					return
				}
				if code != -1 && code != 137 {
					t.Fatalf("the killed apply exited %d: %s", code, stderr)
				}
				// Nomad's state is in /opt/nomad/es-data, the stand-in in
				// /opt/nomad/data, and nomad.hcl names the stand-in.
				if mustRead(t, h.path(hostPackageData)) != nomadStandIn || modeOf(t, h.path(hostMovedData)) != 0o700 ||
					mustRead(t, h.path(hostMovedData+"/server/raft/raft.db")) != "raft state\n" {
					t.Fatal("the killed apply did not leave Nomad's state moved and the stand-in in its place")
				}
				report, _, code := h.check()
				if code != 1 || !strings.Contains(fmt.Sprint(report["blockers"]),
					"Nomad's data folder: nomad.hcl names /opt/nomad/data, but Nomad's state is not there alone (nomad_data_move plan: keep); "+
						"an apply cut off while it moved Nomad's state is undone by rolling back its backup") {
					t.Fatalf("check of the cut-off host: exit %d, blockers %v", code, report["blockers"])
				}
				dirs := backupDirs(t, h)
				if len(dirs) != 1 {
					t.Fatalf("backups %v", dirs)
				}
				stdout, stderr, code := h.run("rollback", "--backup-dir", dirs[0])
				if code != 0 || !strings.Contains(stdout, `"moved_back": true`) {
					t.Fatalf("rollback exited %d\nstdout %s\nstderr %s", code, stdout, stderr)
				}
				if fresh, err := os.ReadFile(filepath.Join(h.state, "fresh-nomad-state")); err == nil {
					t.Fatalf("Nomad started in a new, empty data folder: %s", fresh)
				}
				assertRestored(t, before, h.snapshot())
				if report, stderr, code := h.check(); code != 0 || report["shape"] != start {
					t.Fatalf("check after the rollback: exit %d, shape %v, blockers %v, %s", code, report["shape"], report["blockers"], stderr)
				}
			})
		}
	}
}

// A rollback moves Nomad's state back only from where apply put it, and
// only to where the backup's nomad.hcl names it. A host where it cannot be
// told apart is refused before a service is touched.
func TestRemoteAlphaUpgradeESRefusesARollbackThatCannotPutNomadsStateBack(t *testing.T) {
	helper := buildESConfigCheck(t)
	for _, tc := range []struct {
		name, says string
		break_     func(h *upgradeHost)
	}{
		{"the package's data folder holds entries again", "nomad data: Nomad's state cannot be told apart: ", func(h *upgradeHost) {
			h.write(hostPackageData+"/server/raft/raft.db", "a new cluster\n", 0o600)
			_ = os.Chmod(h.path(hostPackageData), 0o700)
		}},
		{"the folder Nomad's state moved to is gone", "the backup's /etc/nomad.d/nomad.hcl names /opt/nomad/data as Nomad's data folder, " +
			"but Nomad's state is not there to put back (nomad_data_move plan: new); nothing was changed", func(h *upgradeHost) {
			if err := os.Rename(h.path(hostMovedData), h.path("var/backups/es-data")); err != nil {
				h.t.Fatal(err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newUpgradeHost(t, helper)
			if stdout, stderr, code := h.apply(); code != 0 {
				t.Fatalf("apply exited %d\nstdout %s\nstderr %s", code, stdout, stderr)
			}
			backupDir, _ := readSummary(t, h)
			tc.break_(h)
			before, files := h.snapshot(), backupFiles(t, h)
			h.clearCalls()
			_, stderr, code := h.run("rollback", "--backup-dir", backupDir)
			if code != 1 || !strings.Contains(stderr, tc.says) || !strings.Contains(stderr, "nothing was changed") {
				t.Fatalf("rollback exited %d, want %q: %s", code, tc.says, stderr)
			}
			onlyReads(t, h, "a refused rollback")
			assertRestored(t, before, h.snapshot())
			if after := backupFiles(t, h); fmt.Sprint(after) != fmt.Sprint(files) {
				t.Fatalf("a refused rollback changed the backups: %q -> %q", files, after)
			}
		})
	}
}
