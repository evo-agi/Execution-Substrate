package admission

// Stress test from the red-team of pull request #20 at eb6eea9 (report
// 14-red-team-pr20.md, finding RT-3), written by the red-team and adopted
// with the repair. It shows the race that
// TestExecutionRootProbeHandsNoDirectoryToAnotherUser pins without a race. It
// is opt-in, because a race is not a gate: it runs only as root and only when
// ES_PROBE_SWAP_STRESS_ROUNDS is set. On eb6eea9 it failed in most runs of
// 1000 rounds, not in all.
//
// Setup: this process is root, as an ES started as root would be. Both roots
// belong to an unprivileged user, the attacker. A second unprivileged user,
// the victim, owns a world-writable sticky directory inside a directory of
// the attacker's, so the attacker may rename it but may not change its owner
// or its mode. The attacker watches the staging root and swaps the victim's
// directory in between the probe's creation of a directory and its open. A
// hit means root gave the victim's directory to the attacker.
//
// Since the repair, the probe refuses roots that belong to another user at
// its first directory, before any owner or mode change. The "probe" target
// still races that directory. The "nested" target is no longer reached, so it
// passes without exercising the race (audit 16 of the pull request, A16-7).

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

const (
	probeSwapStressRoundsEnv   = "ES_PROBE_SWAP_STRESS_ROUNDS"
	probeSwapStressAttackerEnv = "ES_PROBE_SWAP_STRESS_ATTACKER"
	probeSwapStressAttackerUID = 54331
	probeSwapStressAttackerGID = 54332
	probeSwapStressVictimUID   = 54341
	probeSwapStressVictimGID   = 54342
)

func TestExecutionRootProbeDirectorySwapStress(t *testing.T) {
	rounds, err := strconv.Atoi(os.Getenv(probeSwapStressRoundsEnv))
	if err != nil || rounds < 1 {
		t.Skipf("opt-in: set %s to a number of rounds and run as root", probeSwapStressRoundsEnv)
	}
	if os.Geteuid() != 0 {
		t.Skip("the race needs a root process on roots that belong to another user")
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{"probe", "nested"} {
		t.Run(target, func(t *testing.T) {
			base, err := os.MkdirTemp("", "es-probe-swap-")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.RemoveAll(base) })
			if base, err = filepath.EvalSymlinks(base); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(base, 0o755); err != nil {
				t.Fatal(err)
			}
			staging := filepath.Join(base, "staging")
			results := filepath.Join(base, "results")
			victims := filepath.Join(base, "attacker-owned")
			for _, dir := range []string{staging, results, victims} {
				if err := os.Mkdir(dir, 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.Chown(dir, probeSwapStressAttackerUID, probeSwapStressAttackerGID); err != nil {
					t.Fatal(err)
				}
			}
			hits := 0
			for round := 0; round < rounds; round++ {
				victim := filepath.Join(victims, fmt.Sprintf("victim-%05d", round))
				if err := os.Mkdir(victim, 0o777); err != nil {
					t.Fatal(err)
				}
				if err := os.Chown(victim, probeSwapStressVictimUID, probeSwapStressVictimGID); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(victim, 0o777|os.ModeSticky); err != nil {
					t.Fatal(err)
				}
				var before syscall.Stat_t
				if err := syscall.Stat(victim, &before); err != nil {
					t.Fatal(err)
				}
				attacker := exec.Command(self, "-test.run", "^TestExecutionRootProbeDirectorySwapStressAttacker$", "-test.v")
				attacker.Env = append(os.Environ(), probeSwapStressAttackerEnv+"="+target+":"+staging+":"+victim)
				attacker.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: probeSwapStressAttackerUID, Gid: probeSwapStressAttackerGID, Groups: []uint32{probeSwapStressAttackerGID}}}
				stdout, err := attacker.StdoutPipe()
				if err != nil {
					t.Fatal(err)
				}
				if err := attacker.Start(); err != nil {
					t.Fatal(err)
				}
				reader := bufio.NewReader(stdout)
				for {
					line, err := reader.ReadString('\n')
					if strings.HasPrefix(line, "ATTACKER-READY") {
						break
					}
					if err != nil || strings.HasPrefix(line, "ATTACKER-ERROR") {
						_ = attacker.Process.Kill()
						_ = attacker.Wait()
						t.Fatalf("attacker did not start: %q %v", line, err)
					}
				}
				if roots, err := provisionExecutionRoots(staging, results, nil); err == nil {
					if owner, err := roots.owner(); err == nil {
						_ = roots.probeCapabilities(owner)
					}
					_ = roots.close()
				}
				_ = attacker.Process.Kill()
				_ = attacker.Wait()
				after, found := findTestDirectoryByInode(base, before.Ino)
				if found && (after.Uid != before.Uid || after.Gid != before.Gid || after.Mode != before.Mode) {
					hits++
					t.Logf("round %d: the victim's directory went from %d:%d mode %04o to %d:%d mode %04o", round, before.Uid, before.Gid, before.Mode&0o7777, after.Uid, after.Gid, after.Mode&0o7777)
				}
			}
			if hits > 0 {
				t.Fatalf("root gave another user's directory to the roots' owner in %d of %d starts", hits, rounds)
			}
		})
	}
}

// TestExecutionRootProbeDirectorySwapStressAttacker is the attacker of the
// stress test. It runs in its own process as the unprivileged owner of the
// roots and does nothing unless the stress test started it.
func TestExecutionRootProbeDirectorySwapStressAttacker(t *testing.T) {
	parts := strings.SplitN(os.Getenv(probeSwapStressAttackerEnv), ":", 3)
	if len(parts) != 3 {
		t.Skip("started only by TestExecutionRootProbeDirectorySwapStress")
	}
	target, staging, victim := parts[0], parts[1], parts[2]
	runtime.LockOSThread()
	watch, err := unix.InotifyInit1(unix.IN_CLOEXEC)
	if err != nil {
		fmt.Println("ATTACKER-ERROR", err)
		return
	}
	if _, err := unix.InotifyAddWatch(watch, staging, unix.IN_CREATE); err != nil {
		fmt.Println("ATTACKER-ERROR", err)
		return
	}
	fmt.Println("ATTACKER-READY")
	buffer := make([]byte, 4096)
	for {
		n, err := unix.Read(watch, buffer)
		if err != nil || n < unix.SizeofInotifyEvent {
			continue
		}
		for offset := 0; offset+unix.SizeofInotifyEvent <= n; {
			nameLength := int(uint32(buffer[offset+12]) | uint32(buffer[offset+13])<<8 | uint32(buffer[offset+14])<<16 | uint32(buffer[offset+15])<<24)
			name := strings.TrimRight(string(buffer[offset+unix.SizeofInotifyEvent:offset+unix.SizeofInotifyEvent+nameLength]), "\x00")
			offset += unix.SizeofInotifyEvent + nameLength
			if !strings.HasPrefix(name, ".execution-substrate-staging-probe-") || strings.HasSuffix(name, "-symlink") {
				continue
			}
			probe := filepath.Join(staging, name)
			if target == "probe" {
				// The probe directory itself: created by name, opened by name.
				if unix.Rename(probe, probe+".moved") == nil {
					_ = unix.Rename(victim, probe)
				}
				return
			}
			// The nested directory: its name is fixed, so try until it exists.
			nested := filepath.Join(probe, nestedStagingProbeName)
			deadline := time.Now().Add(5 * time.Second)
			for spins := 0; unix.Rename(nested, probe+"/moved") != nil; spins++ {
				if spins&0xfff == 0 && time.Now().After(deadline) {
					return
				}
			}
			_ = unix.Rename(victim, nested)
			return
		}
	}
}

func findTestDirectoryByInode(root string, inode uint64) (syscall.Stat_t, bool) {
	var found syscall.Stat_t
	ok := false
	_ = filepath.WalkDir(root, func(path string, _ os.DirEntry, err error) error {
		if err != nil || ok {
			return nil
		}
		var stat syscall.Stat_t
		if syscall.Lstat(path, &stat) == nil && stat.Ino == inode && stat.Mode&syscall.S_IFMT == syscall.S_IFDIR {
			found, ok = stat, true
		}
		return nil
	})
	return found, ok
}
