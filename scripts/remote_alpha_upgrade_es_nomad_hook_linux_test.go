package scripts_test

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
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

	// What the program refuses fails nomad-hook, with the program's words.
	link := h.path("etc/nomad.d/extra.hcl")
	if err := os.Symlink(h.path("etc/execution-substrate/ags.json"), link); err != nil {
		t.Fatal(err)
	}
	_, stderr, code = h.run("nomad-hook")
	if code == 0 || !strings.Contains(stderr, link+" is a link, not a regular file, and Nomad's unit reads it as root") {
		t.Fatalf("nomad-hook went on past a link: exit %d\n%s", code, stderr)
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
