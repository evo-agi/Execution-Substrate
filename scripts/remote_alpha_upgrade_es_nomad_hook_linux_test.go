package scripts_test

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// Red-team 45's O45-1 on the box, which does not run the setup: HashiCorp's
// nomad package gives /etc/nomad.d, everything in it and the data folder to
// the nomad account each time it is installed or upgraded. nomad-hook
// installs the setup's program that takes them back and the dpkg
// configuration that runs it after each dpkg run, and runs the program once;
// check and apply refuse a box without them.

// nomad-hook takes a box as the package leaves it (nomad.env the package
// account's to write, here: writable by others) and without the hook, which
// check refuses, to one check takes; a rerun changes nothing.
func TestRemoteAlphaUpgradeESNomadHookInstallsTheSetupsHookAndTakesNomadsFilesBack(t *testing.T) {
	h := newUpgradeHost(t, buildESConfigCheck(t))
	for _, rel := range []string{nomadTakeBackProgramRel, nomadDpkgHookRel} {
		if err := os.Remove(h.path(rel)); err != nil {
			t.Fatal(err)
		}
	}
	env := h.path("etc/nomad.d/nomad.env")
	if err := os.Chmod(env, 0o666); err != nil {
		t.Fatal(err)
	}
	report, _, code := h.check()
	scopes := map[string]int{}
	for _, blocker := range report["blockers"].([]any) {
		scopes[blocker.(map[string]any)["scope"].(string)]++
	}
	if code == 0 || scopes["nomad_env"] != 1 || scopes["nomad_package_hook"] != 2 || len(scopes) != 2 {
		t.Fatalf("check of a box without the hook: exit %d, blockers %v", code, report["blockers"])
	}
	before := h.snapshot()

	stdout, stderr, code := h.run("nomad-hook")
	if code != 0 {
		t.Fatalf("nomad-hook: exit %d\n%s\n%s", code, stdout, stderr)
	}
	program, hook := nomadPackageHookTexts(t, h.root)
	for rel, want := range map[string]string{nomadTakeBackProgramRel: program, nomadDpkgHookRel: hook} {
		data, err := os.ReadFile(h.path(rel))
		if err != nil || string(data) != want {
			t.Fatalf("nomad-hook wrote %s as %q (%v), want the setup's text", rel, data, err)
		}
	}
	if modeOf(t, h.path(nomadTakeBackProgramRel)) != 0o755 || modeOf(t, h.path(nomadDpkgHookRel)) != 0o644 {
		t.Fatal("nomad-hook did not write the program 0755 and the dpkg configuration 0644")
	}
	if !strings.Contains(stdout, "execution-substrate: took "+env+" back (it was ") || modeOf(t, env) != 0o644 {
		t.Fatalf("nomad-hook's program did not take nomad.env back: %s", stdout)
	}
	// Nothing else on the host changed.
	after := h.snapshot()
	for path, value := range before {
		if path != "etc/nomad.d/nomad.env" && after[path] != value {
			t.Fatalf("nomad-hook changed %s", path)
		}
	}
	for path := range after {
		if _, ok := before[path]; !ok && path != nomadTakeBackProgramRel && path != nomadDpkgHookRel {
			t.Fatalf("nomad-hook created %s", path)
		}
	}
	report, stderr, code = h.check()
	if code != 0 || report["result"] != "ready" {
		t.Fatalf("check after nomad-hook: exit %d, result %v, blockers %v, %s", code, report["result"], report["blockers"], stderr)
	}

	// A rerun writes the same files and takes nothing back.
	stdout, stderr, code = h.run("nomad-hook")
	if code != 0 || strings.Contains(stdout, "execution-substrate: took ") {
		t.Fatalf("nomad-hook, again: exit %d\n%s\n%s", code, stdout, stderr)
	}

	// What the program sets aside fails nomad-hook, with the program's
	// words, and check, until the operator removes it (audit 51 of #83,
	// A51-4).
	link := h.path("etc/nomad.d/extra.hcl")
	if err := os.Symlink(h.path("etc/execution-substrate/ags.json"), link); err != nil {
		t.Fatal(err)
	}
	aside := h.path("etc/nomad.d.execution-substrate-set-aside")
	_, stderr, code = h.run("nomad-hook")
	if code == 0 || !strings.Contains(stderr, "execution-substrate: set aside "+link+" (a link, not a regular file): it is "+aside+"/") ||
		!strings.Contains(stderr, "nomad: "+aside+" holds what was set aside from Nomad's folders") {
		t.Fatalf("nomad-hook went on past a link: exit %d\n%s", code, stderr)
	}
	if _, err := os.Lstat(link); !os.IsNotExist(err) {
		t.Fatalf("the link is still where Nomad reads it: %v", err)
	}
	report, _, code = h.check()
	if code == 0 || !strings.Contains(fmt.Sprint(report["blockers"]), "nomad_set_aside") {
		t.Fatalf("check went on past what was set aside: exit %d, blockers %v", code, report["blockers"])
	}
	if err := os.RemoveAll(aside); err != nil {
		t.Fatal(err)
	}
	if _, stderr, code = h.run("nomad-hook"); code != 0 {
		t.Fatalf("nomad-hook with nothing set aside: exit %d\n%s", code, stderr)
	}
	if report, stderr, code = h.check(); code != 0 || report["result"] != "ready" {
		t.Fatalf("check with nothing set aside: exit %d, blockers %v, %s", code, report["blockers"], stderr)
	}
}

// A setup function that does not finish within NOMAD_HOOK_TIMEOUT seconds
// is ended, with what it started, and refused by name, not by the script's
// text: nomad-hook's install, and check's reading of the program's text
// (audit 53 of #83, A83-4). Here the timeout is 2 s and each function
// sleeps a minute in a child, whose number it writes down.
func TestRemoteAlphaUpgradeESNomadHookEndsASetupFunctionThatDoesNotFinish(t *testing.T) {
	h := newUpgradeHost(t, buildESConfigCheck(t))
	for _, tc := range []struct{ function, want string }{
		{"install_nomad_package_hook", "scripts/70_linux_setup.sh's install_nomad_package_hook did not finish within 2 s"},
		{"nomad_take_back_program", "the setup's nomad_package_hook functions cannot be read: scripts/70_linux_setup.sh's nomad_take_back_program did not finish within 2 s"},
	} {
		t.Run(tc.function, func(t *testing.T) {
			pidFile := filepath.Join(t.TempDir(), "sleep.pid")
			slow := fmt.Sprintf("%s() { sleep 60 & echo $! > '%s'; wait; }\n", tc.function, pidFile)
			patch := fmt.Sprintf("m.NOMAD_HOOK_TIMEOUT = 2\nsetup_functions = m.setup_functions\n"+
				"m.setup_functions = lambda region: setup_functions(region) + (%q if region == \"nomad_package_hook\" else \"\")", slow)
			before := h.snapshot()
			started := time.Now()
			var stdout, stderr string
			var code int
			if tc.function == "install_nomad_package_hook" {
				stdout, stderr, code = runWithPatchedUpgrade(h, patch, "nomad-hook")
			} else {
				stdout, stderr, code = runWithPatchedUpgrade(h, patch, "check", "--payload", h.payload, "--commit", h.commit)
			}
			took := time.Since(started)
			if code == 0 || !strings.Contains(stdout+stderr, tc.want) || strings.Contains(stdout+stderr, "set -euo pipefail") {
				t.Fatalf("exit %d, want a refusal with %q and without the script's text\n%s\n%s", code, tc.want, stdout, stderr)
			}
			if took > 30*time.Second {
				t.Fatalf("took %v: the function was not ended at its timeout", took)
			}
			pid, err := os.ReadFile(pidFile)
			if err != nil {
				t.Fatalf("the slow function did not run: %v", err)
			}
			if cmdline, err := os.ReadFile("/proc/" + strings.TrimSpace(string(pid)) + "/cmdline"); err == nil && bytes.HasPrefix(cmdline, []byte("sleep\x00")) {
				t.Fatalf("the function's child, process %s, is still running", strings.TrimSpace(string(pid)))
			}
			after := h.snapshot()
			for path, value := range before {
				if after[path] != value {
					t.Fatalf("changed %s", path)
				}
			}
			if len(after) != len(before) {
				t.Fatal("created or removed a path")
			}
		})
	}
}

// The upgrade's paths for the program and the dpkg configuration are the
// setup's.
func TestRemoteAlphaUpgradeESNomadHookPathsAreTheSetups(t *testing.T) {
	setup, err := os.ReadFile(repoPath("scripts/70_linux_setup.sh"))
	if err != nil {
		t.Fatal(err)
	}
	upgrade, err := os.ReadFile(repoPath(upgradeESPython))
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"NOMAD_TAKE_BACK_PROGRAM", "NOMAD_DPKG_HOOK"} {
		inSetup := regexp.MustCompile(`(?m)^` + name + `="([^"]+)"$`).FindSubmatch(setup)
		inUpgrade := regexp.MustCompile(`(?m)^` + name + ` = "([^"]+)"$`).FindSubmatch(upgrade)
		if inSetup == nil || inUpgrade == nil || string(inSetup[1]) != string(inUpgrade[1]) {
			t.Fatalf("%s: the setup has %q, the upgrade %q", name, inSetup, inUpgrade)
		}
		rel := map[string]string{"NOMAD_TAKE_BACK_PROGRAM": nomadTakeBackProgramRel, "NOMAD_DPKG_HOOK": nomadDpkgHookRel}[name]
		if "/"+filepath.ToSlash(rel) != string(inSetup[1]) {
			t.Fatalf("the tests place %s at %s, the setup at %s", name, rel, inSetup[1])
		}
	}
}

// On a host (no --host-root), nomad-hook refuses to run without root before
// it writes anything, as check and apply do. The clone is root's, in a
// folder of root's below /tmp, so that the checkout guard lets it through
// and the refusal seen is the one for root.
func TestRemoteAlphaUpgradeESNomadHookRefusesToRunWithoutRootOnAHost(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("runs as root: a run without root cannot be seen")
	}
	probe := exec.Command("sudo", "-n", "true")
	probe.Dir = t.TempDir()
	if probe.Run() != nil {
		t.Skip("needs passwordless sudo to give a clone to root")
	}
	work := t.TempDir()
	sudo := func(args ...string) string {
		t.Helper()
		run := exec.Command("sudo", append([]string{"-n"}, args...)...)
		run.Dir = work
		output, err := run.CombinedOutput()
		if err != nil {
			t.Fatalf("sudo %v: %v: %s", args, err, output)
		}
		return strings.TrimSpace(string(output))
	}
	base := sudo("mktemp", "-d", "/tmp/es-upgrade-nomad-hook-XXXXXXXX")
	if !strings.HasPrefix(base, "/tmp/es-upgrade-nomad-hook-") || strings.Contains(base, "..") {
		t.Fatalf("mktemp named %q", base)
	}
	t.Cleanup(func() { sudo("rm", "-rf", "--", base) })
	sudo("chmod", "0755", base)
	clone := filepath.Join(base, "clone")
	sudo("install", "-d", "-o", "root", "-g", "root", "-m", "0755", clone, filepath.Join(clone, "scripts"), filepath.Join(clone, "scripts", "internal"))
	for rel, mode := range map[string]string{"scripts/remote_alpha_upgrade_es.sh": "0755", upgradeESPython: "0644"} {
		sudo("install", "-o", "root", "-g", "root", "-m", mode, repoPath(rel), filepath.Join(clone, filepath.FromSlash(rel)))
	}
	cmd := exec.Command("python3", "-I", filepath.Join(clone, filepath.FromSlash(upgradeESPython)), "nomad-hook")
	cmd.Dir = t.TempDir()
	for _, entry := range os.Environ() {
		if !strings.HasPrefix(entry, "ES_UPGRADE_TEST_") {
			cmd.Env = append(cmd.Env, entry)
		}
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	if exitErr, ok := err.(*exec.ExitError); !ok || exitErr.ExitCode() != 1 ||
		strings.TrimSpace(stderr.String()) != "remote alpha ES upgrade refused: run as root (sudo -n)" || stdout.Len() != 0 {
		t.Fatalf("nomad-hook without root on a host: %v\nstdout %s\nstderr %s", err, stdout.String(), stderr.String())
	}
}
