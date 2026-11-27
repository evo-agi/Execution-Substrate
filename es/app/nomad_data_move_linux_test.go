package app_test

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"testing"
	"time"
)

// Nomad keeps its state out of the folder the nomad package gives to the
// nomad account (re-check 52 of #83, A52-2): the setup's nomad_data_move
// region and install_nomad_data_folder. Linux only: the move is renameat2's
// RENAME_EXCHANGE.

// nomadDataStandIn is the text of the stand-in nomad_data_move leaves where
// Nomad's state was.
const nomadDataStandIn = "Execution Substrate: Nomad's state is moving to the folder beside this file. Nomad cannot\n" +
	"keep its state in a file, so it does not start with a nomad.hcl that names this path.\n" +
	"scripts/70_linux_setup.sh, or the box upgrade, removes this file once the move is done.\n"

// runNomadDataMove runs the setup's nomad_data_move with args, as the test
// user, whose uid stands for root's.
func runNomadDataMove(t *testing.T, args ...string) (string, string, error) {
	t.Helper()
	script := "set -euo pipefail\n" + linuxSetupRegion(t, "nomad_data_move") + "nomad_data_move \"$@\"\n"
	command := exec.Command("bash", append([]string{"-c", script, "nomad-data-move"}, args...)...)
	command.Env = []string{"PATH=" + os.Getenv("PATH")}
	var stdout, stderr strings.Builder
	command.Stdout, command.Stderr = &stdout, &stderr
	err := command.Run()
	return stdout.String(), stderr.String(), err
}

// nomadDataFolders makes a folder like /opt/nomad (0755) under a new
// temporary folder and returns it with the paths of the package's data
// folder and Nomad's own in it, neither made yet.
func nomadDataFolders(t *testing.T) (opt, pkg, data string) {
	t.Helper()
	opt = filepath.Join(t.TempDir(), "opt")
	if err := os.Mkdir(opt, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(opt, 0o755); err != nil {
		t.Fatal(err)
	}
	return opt, filepath.Join(opt, "data"), filepath.Join(opt, "es-data")
}

// nomadState makes folder hold a stand-in for Nomad's state (0700, a raft
// file in its server folder) and returns the folder's inode.
func nomadState(t *testing.T, folder string) uint64 {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(folder, "server", "raft"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(folder, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(folder, "server", "raft", "raft.db"), []byte("raft state\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return inode(t, folder)
}

// writeStandIn puts the stand-in at path, as nomad_data_move writes it.
func writeStandIn(t *testing.T, path string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(nomadDataStandIn), 0o600); err != nil {
		t.Fatal(err)
	}
}

// requireNomadState fails unless folder is the folder nomadState made, at
// the same inode, mode 0700.
func requireNomadState(t *testing.T, folder string, was uint64) {
	t.Helper()
	requireFolder(t, folder, os.Getuid(), os.Getgid(), 0o700)
	if inode(t, folder) != was {
		t.Fatalf("%s is not the folder that held Nomad's state", folder)
	}
	if got, err := os.ReadFile(filepath.Join(folder, "server", "raft", "raft.db")); err != nil || string(got) != "raft state\n" {
		t.Fatalf("Nomad's state in %s holds %q (%v)", folder, got, err)
	}
}

// listing is every path under root with its kind and mode, for a check that
// nothing changed.
func listing(t *testing.T, root string) string {
	t.Helper()
	var lines []string
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		lines = append(lines, fmt.Sprintf("%s %v %d", path, info.Mode(), info.Sys().(*syscall.Stat_t).Ino))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return strings.Join(lines, "\n")
}

// plan says what the setup has to do from what is in the two folders, and
// refuses what it cannot tell apart.
func TestNomadDataMovePlansFromWhatIsThere(t *testing.T) {
	type place func(t *testing.T, path string)
	absent := func(*testing.T, string) {}
	empty := func(t *testing.T, path string) {
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	state := func(t *testing.T, path string) { nomadState(t, path) }
	standIn := writeStandIn
	otherFile := func(t *testing.T, path string) {
		if err := os.WriteFile(path, []byte("not the stand-in\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	link := func(t *testing.T, path string) {
		target := filepath.Join(t.TempDir(), "elsewhere")
		nomadState(t, target)
		if err := os.Symlink(target, path); err != nil {
			t.Fatal(err)
		}
	}
	for _, test := range []struct {
		name      string
		pkg, data place
		want      string
	}{
		{"a host set up before: Nomad's state in the package's folder", state, absent, "move"},
		{"a swap cut off before its one step", state, standIn, "move"},
		{"a run cut off after it made Nomad's folder, before it wrote nomad.hcl", state, empty, "move"},
		{"moved, the package's folder gone", absent, state, "keep"},
		{"moved, the package's folder made again by dpkg", empty, state, "keep"},
		{"moved, the stand-in still there", standIn, state, "keep"},
		{"a new host", absent, absent, "new"},
		{"a new host the package was installed on", empty, absent, "new"},
		{"state in both", state, state, "is a folder that holds entries; look at both"},
		{"another file where Nomad's state goes", state, otherFile, "is a file of uid"},
		{"a link where Nomad's state goes", state, link, "is a link"},
		{"a link where Nomad's state was", link, absent, "is a link"},
		{"the stand-in alone", standIn, absent, "is missing, and"},
		{"the stand-in where Nomad's state goes, and nothing to move", empty, standIn, "is the stand-in, and"},
	} {
		t.Run(test.name, func(t *testing.T) {
			opt, pkg, data := nomadDataFolders(t)
			test.pkg(t, pkg)
			test.data(t, data)
			before := listing(t, opt)
			stdout, stderr, err := runNomadDataMove(t, "plan", pkg, data)
			if test.want == "move" || test.want == "keep" || test.want == "new" {
				if err != nil || stdout != test.want+"\n" {
					t.Fatalf("plan: %v %q %q, want %s", err, stdout, stderr, test.want)
				}
			} else if err == nil || stdout != "" || !strings.Contains(stderr, "nomad data: Nomad's state cannot be told apart: ") ||
				!strings.Contains(stderr, test.want) {
				t.Fatalf("plan: %v %q %q, want a refusal saying %q", err, stdout, stderr, test.want)
			}
			if after := listing(t, opt); after != before {
				t.Fatalf("plan changed something:\n%s\nwas\n%s", after, before)
			}
		})
	}
}

// swap moves the folder in one step and leaves the stand-in where it was;
// finish removes the stand-in and nothing else. The rollback's swap the
// other way finds the package's folder missing, made again by dpkg, or the
// stand-in of an apply cut off after its swap.
func TestNomadDataMoveSwapsInOneStepAndLeavesAStandIn(t *testing.T) {
	opt, pkg, data := nomadDataFolders(t)
	was := nomadState(t, pkg)
	stdout, stderr, err := runNomadDataMove(t, "swap", pkg, data)
	if err != nil || stdout != "nomad data: moved Nomad's state from "+pkg+" to "+data+"; "+pkg+" holds a stand-in until nomad.hcl names "+data+"\n" {
		t.Fatalf("swap: %v %q %q", err, stdout, stderr)
	}
	requireNomadState(t, data, was)
	requireRegularFile(t, pkg, nomadDataStandIn, 0o600)
	// finish leaves anything but the stand-in as it is.
	if _, stderr, err := runNomadDataMove(t, "finish", data); err != nil {
		t.Fatalf("finish on Nomad's state: %v %s", err, stderr)
	}
	requireNomadState(t, data, was)
	if _, stderr, err := runNomadDataMove(t, "finish", pkg); err != nil {
		t.Fatalf("finish: %v %s", err, stderr)
	}
	if _, err := os.Lstat(pkg); !os.IsNotExist(err) {
		t.Fatalf("the stand-in is still at %s: %v", pkg, err)
	}
	if _, stderr, err := runNomadDataMove(t, "finish", pkg); err != nil {
		t.Fatalf("finish with nothing there: %v %s", err, stderr)
	}

	for _, test := range []struct {
		name string
		at   func(t *testing.T, path string)
	}{
		{"missing", func(*testing.T, string) {}},
		{"an empty folder", func(t *testing.T, path string) {
			if err := os.Mkdir(path, 0o700); err != nil {
				t.Fatal(err)
			}
		}},
		{"the stand-in", writeStandIn},
	} {
		t.Run("back, with the package's folder "+test.name, func(t *testing.T) {
			test.at(t, pkg)
			if _, stderr, err := runNomadDataMove(t, "can-swap", data, pkg); err != nil {
				t.Fatalf("can-swap: %v %s", err, stderr)
			}
			if _, stderr, err := runNomadDataMove(t, "swap", data, pkg); err != nil {
				t.Fatalf("swap back: %v %s", err, stderr)
			}
			requireNomadState(t, pkg, was)
			requireRegularFile(t, data, nomadDataStandIn, 0o600)
			if _, stderr, err := runNomadDataMove(t, "finish", data); err != nil {
				t.Fatalf("finish: %v %s", err, stderr)
			}
			// And forward again, for the next case.
			if _, stderr, err := runNomadDataMove(t, "swap", pkg, data); err != nil {
				t.Fatalf("swap: %v %s", err, stderr)
			}
			if _, stderr, err := runNomadDataMove(t, "finish", pkg); err != nil {
				t.Fatalf("finish: %v %s", err, stderr)
			}
			requireNomadState(t, data, was)
		})
	}
	requireFolder(t, opt, os.Getuid(), os.Getgid(), 0o755)
}

// swap and can-swap refuse, changing nothing, what is not Nomad's state to
// move, what stands where it goes, and folders that are not side by side
// in a folder only root can change.
func TestNomadDataMoveRefusesWhatItCannotSwap(t *testing.T) {
	for _, test := range []struct {
		name  string
		setup func(t *testing.T, opt, pkg, data string) (string, string)
		says  string
	}{
		{"nothing to move", func(t *testing.T, opt, pkg, data string) (string, string) {
			return pkg, data
		}, ", where Nomad's state should be, is missing; nothing was moved"},
		{"the stand-in to move", func(t *testing.T, opt, pkg, data string) (string, string) {
			writeStandIn(t, pkg)
			return pkg, data
		}, ", where Nomad's state should be, is the stand-in; nothing was moved"},
		{"a link to move", func(t *testing.T, opt, pkg, data string) (string, string) {
			target := filepath.Join(t.TempDir(), "elsewhere")
			nomadState(t, target)
			if err := os.Symlink(target, pkg); err != nil {
				t.Fatal(err)
			}
			return pkg, data
		}, ", where Nomad's state should be, is a link; nothing was moved"},
		{"a folder that holds entries where it goes", func(t *testing.T, opt, pkg, data string) (string, string) {
			nomadState(t, pkg)
			nomadState(t, data)
			return pkg, data
		}, ", where Nomad's state goes, is a folder that holds entries; nothing was moved"},
		{"another file where it goes", func(t *testing.T, opt, pkg, data string) (string, string) {
			nomadState(t, pkg)
			if err := os.WriteFile(data, []byte(nomadDataStandIn+"x"), 0o600); err != nil {
				t.Fatal(err)
			}
			return pkg, data
		}, ", where Nomad's state goes, is a file of uid"},
		{"a link where it goes", func(t *testing.T, opt, pkg, data string) (string, string) {
			nomadState(t, pkg)
			if err := os.Symlink(t.TempDir(), data); err != nil {
				t.Fatal(err)
			}
			return pkg, data
		}, ", where Nomad's state goes, is a link; nothing was moved"},
		{"a folder others can change above them", func(t *testing.T, opt, pkg, data string) (string, string) {
			nomadState(t, pkg)
			if err := os.Chmod(opt, 0o775); err != nil {
				t.Fatal(err)
			}
			return pkg, data
		}, " is not a folder of uid "},
		{"folders that are not side by side", func(t *testing.T, opt, pkg, data string) (string, string) {
			nomadState(t, pkg)
			if err := os.Mkdir(filepath.Join(opt, "sub"), 0o755); err != nil {
				t.Fatal(err)
			}
			return pkg, filepath.Join(opt, "sub", "es-data")
		}, " are not two folders side by side"},
	} {
		for _, command := range []string{"can-swap", "swap"} {
			t.Run(test.name+", "+command, func(t *testing.T) {
				opt, pkg, data := nomadDataFolders(t)
				src, dst := test.setup(t, opt, pkg, data)
				before := listing(t, filepath.Dir(opt))
				stdout, stderr, err := runNomadDataMove(t, command, src, dst)
				if err == nil || stdout != "" || !strings.HasPrefix(stderr, "nomad data: ") || !strings.Contains(stderr, test.says) {
					t.Fatalf("%s: %v %q %q, want a refusal saying %q", command, err, stdout, stderr, test.says)
				}
				if after := listing(t, filepath.Dir(opt)); after != before {
					t.Fatalf("%s changed something:\n%s\nwas\n%s", command, after, before)
				}
			})
		}
	}
}

// What the stand-in is for: a real Nomad whose data_dir is a file does not
// start, where with nothing at its data_dir it makes the folder and starts
// a new cluster (with a fresh ACL bootstrap).
func TestRealNomadDoesNotStartWithItsDataDirAFile(t *testing.T) {
	requireNomadBinary(t)
	dir := t.TempDir()
	standIn := filepath.Join(dir, "data")
	writeStandIn(t, standIn)
	ports := make([]int, 3)
	for i := range ports {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		ports[i] = listener.Addr().(*net.TCPAddr).Port
		defer listener.Close()
	}
	config := filepath.Join(dir, "nomad.hcl")
	text := fmt.Sprintf(`data_dir = %q
bind_addr = "127.0.0.1"
server {
  enabled          = true
  bootstrap_expect = 1
}
acl {
  enabled = true
}
ports {
  http = %[2]d
  rpc  = %[3]d
  serf = %[4]d
}
advertise {
  http = "127.0.0.1:%[2]d"
  rpc  = "127.0.0.1:%[3]d"
  serf = "127.0.0.1:%[4]d"
}
`, standIn, ports[0], ports[1], ports[2])
	if err := os.WriteFile(config, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, "nomad", "agent", "-config", config).CombinedOutput()
	if ctx.Err() != nil || err == nil || !strings.Contains(string(output), standIn+": not a directory") {
		t.Fatalf("nomad agent with its data_dir a file: %v (%v)\n%s", err, ctx.Err(), output)
	}
	requireRegularFile(t, standIn, nomadDataStandIn, 0o600)
}

// linuxSetupDataFolderHarness defines install_nomad_data_folder with what
// it calls, under "$1": /opt/nomad at "$1/opt", the package's data folder
// at "$1/opt/data" and Nomad's at "$1/opt/es-data". sudo stands in for
// itself, install for install -d, and systemctl logs each call to
// "$1/systemctl.log" and fails while "$1/systemctl-fails" exists.
func linuxSetupDataFolderHarness(t *testing.T) string {
	t.Helper()
	text := linuxSetupText(t)
	harness := "set -euo pipefail\nROOT=\"$1\"\nsudo() { \"$@\"; }\n" +
		"systemctl() { echo \"systemctl $*\" >>\"${ROOT}/systemctl.log\"; [[ ! -e \"${ROOT}/systemctl-fails\" ]]; }\n" +
		linuxSetupInstallStandIn + linuxSetupRegion(t, "nomad_data_move")
	for _, name := range []string{"nomad_folder_take_back", "nomad_needs_restart", "install_nomad_data_folder"} {
		harness += linuxSetupFunction(t, text, name)
	}
	return harness + "NOMAD_OPT_DIR=\"$1/opt\"\nNOMAD_PACKAGE_DATA_DIR=\"$1/opt/data\"\nNOMAD_DATA_DIR=\"$1/opt/es-data\"\n" +
		"NOMAD_RESTART_PENDING=\"${NOMAD_DATA_DIR}/execution-substrate-restart-pending\"\nNOMAD_CONFIG_CHANGED=0\n"
}

// runInstallNomadDataFolder runs install_nomad_data_folder, then finish
// when finish (as install_nomad_service_config does once nomad.hcl names
// Nomad's folder), under root, and returns its output and
// NOMAD_CONFIG_CHANGED.
func runInstallNomadDataFolder(t *testing.T, root string, finish bool) (string, string, string, error) {
	t.Helper()
	steps := "install_nomad_data_folder\n"
	if finish {
		steps += "nomad_data_move_as_root finish \"${NOMAD_PACKAGE_DATA_DIR}\"\n"
	}
	steps += "echo \"changed=${NOMAD_CONFIG_CHANGED}\" >&2\n"
	command := exec.Command("bash", "-c", linuxSetupDataFolderHarness(t)+steps, "bash", root)
	command.Env = []string{"PATH=" + os.Getenv("PATH")}
	var stdout, stderr strings.Builder
	command.Stdout, command.Stderr = &stdout, &stderr
	err := command.Run()
	errText := stderr.String()
	changed := ""
	if i := strings.LastIndex(errText, "changed="); i >= 0 {
		changed = strings.TrimSpace(errText[i+len("changed="):])
	}
	return stdout.String(), errText, changed, err
}

// A host set up before keeps Nomad's state in the package's data folder:
// the setup stops Nomad, moves the state to its own folder, records the
// restart, and leaves the stand-in until nomad.hcl names the new folder. A
// run cut off after the move goes on from there. A new host gets its folder
// made, and Nomad is not stopped.
func TestLinuxSetupMovesNomadsStateOutOfThePackagesFolder(t *testing.T) {
	t.Run("a host set up before", func(t *testing.T) {
		root := t.TempDir()
		opt, pkg, data := filepath.Join(root, "opt"), filepath.Join(root, "opt", "data"), filepath.Join(root, "opt", "es-data")
		if err := os.Mkdir(opt, 0o775); err != nil {
			t.Fatal(err)
		}
		was := nomadState(t, pkg)
		stdout, stderr, changed, err := runInstallNomadDataFolder(t, root, false)
		if err != nil || changed != "1" || !strings.Contains(stdout, "==> Moving Nomad's state from "+pkg+", which the nomad package gives to the nomad account, to "+data+"\n") {
			t.Fatalf("install_nomad_data_folder: %v changed=%q %q %q", err, changed, stdout, stderr)
		}
		requireFolder(t, opt, os.Getuid(), os.Getgid(), 0o755)
		requireNomadState(t, data, was)
		requireRegularFile(t, pkg, nomadDataStandIn, 0o600)
		requireRegularFile(t, filepath.Join(data, "execution-substrate-restart-pending"), "", 0o600)
		requireRegularFile(t, filepath.Join(root, "systemctl.log"), "systemctl stop nomad\n", 0o644)

		// Cut off before nomad.hcl named the new folder: the rerun keeps
		// Nomad's state where it is, does not stop Nomad again, and removes
		// the stand-in once nomad.hcl is written.
		stdout, stderr, _, err = runInstallNomadDataFolder(t, root, true)
		if err != nil || strings.Contains(stdout, "Moving") {
			t.Fatalf("the rerun: %v %q %q", err, stdout, stderr)
		}
		requireNomadState(t, data, was)
		if _, err := os.Lstat(pkg); !os.IsNotExist(err) {
			t.Fatalf("the stand-in is still at %s: %v", pkg, err)
		}
		requireRegularFile(t, filepath.Join(root, "systemctl.log"), "systemctl stop nomad\n", 0o644)
	})
	t.Run("a new host", func(t *testing.T) {
		root := t.TempDir()
		pkg, data := filepath.Join(root, "opt", "data"), filepath.Join(root, "opt", "es-data")
		if err := os.MkdirAll(pkg, 0o755); err != nil {
			t.Fatal(err)
		}
		stdout, stderr, changed, err := runInstallNomadDataFolder(t, root, true)
		if err != nil || changed != "0" || strings.Contains(stdout, "Moving") {
			t.Fatalf("install_nomad_data_folder: %v changed=%q %q %q", err, changed, stdout, stderr)
		}
		requireFolder(t, data, os.Getuid(), os.Getgid(), 0o700)
		requireFolder(t, pkg, os.Getuid(), os.Getgid(), 0o755)
		if _, err := os.Lstat(filepath.Join(root, "systemctl.log")); !os.IsNotExist(err) {
			t.Fatalf("Nomad was stopped on a new host: %v", err)
		}
	})
	t.Run("Nomad does not stop", func(t *testing.T) {
		root := t.TempDir()
		pkg, data := filepath.Join(root, "opt", "data"), filepath.Join(root, "opt", "es-data")
		was := nomadState(t, pkg)
		if err := os.WriteFile(filepath.Join(root, "systemctl-fails"), nil, 0o644); err != nil {
			t.Fatal(err)
		}
		_, stderr, _, err := runInstallNomadDataFolder(t, root, false)
		if err == nil || !strings.Contains(stderr, "nomad: could not stop nomad.service to move its state; nothing was moved\n") {
			t.Fatalf("install_nomad_data_folder: %v %q", err, stderr)
		}
		requireNomadState(t, pkg, was)
		if _, err := os.Lstat(data); !os.IsNotExist(err) {
			t.Fatalf("%s was made: %v", data, err)
		}
	})
	t.Run("state in both", func(t *testing.T) {
		root := t.TempDir()
		pkg, data := filepath.Join(root, "opt", "data"), filepath.Join(root, "opt", "es-data")
		was, wasData := nomadState(t, pkg), nomadState(t, data)
		_, stderr, _, err := runInstallNomadDataFolder(t, root, true)
		if err == nil || !strings.Contains(stderr, "nomad data: Nomad's state cannot be told apart: "+data+" is a folder that holds entries, and "+pkg+" is a folder that holds entries; ") {
			t.Fatalf("install_nomad_data_folder: %v %q", err, stderr)
		}
		requireNomadState(t, pkg, was)
		requireNomadState(t, data, wasData)
		if _, err := os.Lstat(filepath.Join(root, "systemctl.log")); !os.IsNotExist(err) {
			t.Fatalf("Nomad was stopped: %v", err)
		}
	})
}

// The take-back program, run by the setup first and by dpkg after each of
// its runs, passes over the stand-in at the package's data folder (a file
// of root's, where Nomad cannot keep its state), so neither a setup run cut
// off after the move nor a dpkg run in between fails on it. It still takes
// the config folder back.
func TestNomadTakeBackProgramPassesOverTheStandInAtTheDataFolder(t *testing.T) {
	program := nomadTakeBackProgram(t)
	root := t.TempDir()
	config, data := filepath.Join(root, "etc"), filepath.Join(root, "data")
	for _, folder := range []string{config, filepath.Join(config, "tls")} {
		if err := os.MkdirAll(folder, 0o775); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(folder, 0o775); err != nil {
			t.Fatal(err)
		}
	}
	writeStandIn(t, data)
	stdout, stderr, err := runTakeBack(t, program, false, config, data)
	if err != nil || stderr != "" {
		t.Fatalf("the program: %v %q %q", err, stdout, stderr)
	}
	requireLines(t, stdout, []string{
		`execution-substrate: took ` + regexp.QuoteMeta(config) + ` back \(it was uid [0-9]+, gid [0-9]+, 0775\)`,
		`execution-substrate: took ` + regexp.QuoteMeta(filepath.Join(config, "tls")) + ` back \(it was uid [0-9]+, gid [0-9]+, 0775\)`,
		regexp.QuoteMeta("execution-substrate: passed over " + data + ": a file of root's, where Nomad cannot keep its state (the setup and the box upgrade leave one there while they move Nomad's state out of it)"),
	})
	requireRegularFile(t, data, nomadDataStandIn, 0o600)
}

// The package's postinst runs `mkdir -p /opt/nomad/data` (which fails on
// the stand-in) and then `chown nomad:nomad /opt/nomad/data`, which gives
// the stand-in to the nomad account. The program, run by dpkg right after,
// makes it root's again in place (0600, no ACL) rather than refusing the
// data folder as not a folder, which would fail every dpkg run until the
// move was finished. It reads nothing from it, so a file of any size is
// handled the same way, and nomad_data_move takes it for its stand-in again
// only while its bytes are the stand-in's.
func TestNomadTakeBackProgramTakesBackTheStandInThePostinstGaveAway(t *testing.T) {
	program := nomadTakeBackProgram(t)
	for _, c := range []struct {
		name, content string
		standIn       bool
	}{
		{"the stand-in", nomadDataStandIn, true},
		{"the stand-in the account wrote past 1 MiB", nomadDataStandIn + strings.Repeat("x", 2<<20), false},
	} {
		t.Run(c.name, func(t *testing.T) {
			root := rootTempDir(t)
			opt := filepath.Join(root, "opt")
			config, data := filepath.Join(root, "etc"), filepath.Join(opt, "data")
			for _, folder := range []string{config, filepath.Join(config, "tls"), opt} {
				if err := os.MkdirAll(folder, 0o755); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.WriteFile(data, []byte(c.content), 0o644); err != nil {
				t.Fatal(err)
			}
			if err := syscall.Setxattr(data, "system.posix_acl_access", grantingACL(), 0); err != nil {
				t.Fatal(err)
			}
			was := inode(t, data)
			runTestSudo(t, "chown", "0:0", "--", config, filepath.Join(config, "tls"), opt)
			runTestSudo(t, "chown", "65534:65534", "--", data)
			stdout, stderr, err := runTakeBack(t, program, true, config, data)
			if err != nil || stderr != "" {
				t.Fatalf("the program: %v %q %q", err, stdout, stderr)
			}
			requireLines(t, stdout, []string{
				regexp.QuoteMeta("execution-substrate: took " + data + " back (it was uid 65534, gid 65534, 0775, with an ACL), a file where Nomad cannot keep its state (the setup and the box upgrade leave one there while they move Nomad's state out of it)"),
			})
			if got := sudoStat(t, data); got != "0:0 600 regular file" {
				t.Fatalf("the file at the data folder is %s, not root's 0600", got)
			}
			if inode(t, data) != was || sudoRead(t, data) != c.content {
				t.Fatal("the file at the data folder was replaced or changed, not taken back in place")
			}
			if hasACL(t, data, "system.posix_acl_access") {
				t.Fatal("the file at the data folder still has an ACL")
			}
			requireNothingSetAside(t, data)
			// nomad_data_move, as root, takes it for the stand-in only while
			// its bytes are the stand-in's.
			script := "set -euo pipefail\n" + linuxSetupRegion(t, "nomad_data_move") + "nomad_data_move \"$@\"\n"
			if err := os.MkdirAll(filepath.Join(root, "es-data-src", "server"), 0o700); err != nil {
				t.Fatal(err)
			}
			runTestSudo(t, "mv", "-T", "--", filepath.Join(root, "es-data-src"), filepath.Join(opt, "es-data"))
			runTestSudo(t, "chown", "-R", "0:0", "--", filepath.Join(opt, "es-data"))
			out, err := exec.Command("sudo", "-n", "bash", "-c", script, "nomad-data-move", "plan", data, filepath.Join(opt, "es-data")).CombinedOutput()
			if c.standIn && (err != nil || string(out) != "keep\n") {
				t.Fatalf("plan with the stand-in taken back: %v %q", err, out)
			}
			if !c.standIn && (err == nil || !strings.Contains(string(out), "is a file of uid 0, not the stand-in")) {
				t.Fatalf("plan with another file at the package's data folder: %v %q", err, out)
			}
		})
	}
}

// install_nomad_service_config removes the stand-in once nomad.hcl is
// written, after a run cut off between the move and nomad.hcl: the
// program's first run passes over it.
func TestLinuxSetupRemovesTheStandInOnceNomadHCLIsWritten(t *testing.T) {
	dataDir := t.TempDir()
	steps := "NOMAD_PACKAGE_DATA_DIR=\"$1/package\"\n" +
		"mkdir -m 0700 \"$1/package\" && : >\"$1/package/raft\"\n" +
		"nomad_data_move swap \"$1/package\" \"$1/moved\" >/dev/null\n" +
		"install_nomad_service_config\n"
	stdout, stderr, err := runLinuxSetupServiceHarness(t, dataDir, steps)
	if err != nil || !strings.Contains(stdout, "execution-substrate: passed over "+filepath.Join(dataDir, "package")+": a file of root's") {
		t.Fatalf("install_nomad_service_config: %v %q %q", err, stdout, stderr)
	}
	if _, err := os.Lstat(filepath.Join(dataDir, "package")); !os.IsNotExist(err) {
		t.Fatalf("the stand-in is still there: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(dataDir, "etc", "nomad.hcl")); err != nil {
		t.Fatalf("nomad.hcl was not written: %v", err)
	}
}
