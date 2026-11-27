package app_test

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"testing"
	"time"
)

// Audit 46 of ES PR #66. HashiCorp's Nomad package gives Nomad's data
// directory, and /etc/nomad.d with everything in it, to the nomad account on
// every install or upgrade. Whatever that account left at a name the setup
// writes there as root must be replaced, not followed: the restart record
// (A46-1), nomad.hcl, its backup and the TLS folder and files (P46-1). And
// the steps that decide on a restart and on the closing summary's claim are
// run, not only read (A46-2).

// linuxSetupText is the setup script's text.
func linuxSetupText(t *testing.T) string {
	t.Helper()
	body, err := os.ReadFile(filepath.Join(executionPlatformRepoRoot(t), "scripts", "70_linux_setup.sh"))
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

// linuxSetupDefinitions returns the script's own top-level definitions of
// the named variables, one line each.
func linuxSetupDefinitions(t *testing.T, text string, names ...string) string {
	t.Helper()
	var lines []string
	for _, name := range names {
		line := regexp.MustCompile(`(?m)^` + name + `=.*$`).FindString(text)
		if line == "" {
			t.Fatalf("70_linux_setup.sh does not define %s", name)
		}
		lines = append(lines, line)
	}
	return strings.Join(lines, "\n") + "\n"
}

// linuxSetupServiceHarness is linuxSetupGossipHarness with
// nomad_folder_take_back, nomad_config_write, install_nomad_service_config
// and the nomad_package_hook region added, and Nomad's config folder at
// "$1/etc" (nomad.hcl, its backup name and the TLS folder defined from it as
// the script does). The take-back program and its dpkg configuration go to
// "$1/sbin" and "$1/dpkg.cfg.d", which the harness makes. install stands in
// for itself as install -d: it makes the folder, following a link there as
// the real one does, and applies -m. date prints a fixed time, and the TLS
// and keyring steps do nothing.
func linuxSetupServiceHarness(t *testing.T) string {
	t.Helper()
	text := linuxSetupText(t)
	harness := linuxSetupGossipHarness(t) + nomadPackageHookRegion(t)
	for _, name := range []string{"nomad_folder_take_back", "nomad_config_write", "install_nomad_service_config"} {
		harness += linuxSetupFunction(t, text, name)
	}
	return harness + "NOMAD_CONFIG_DIR=\"$1/etc\"\n" +
		"NOMAD_TAKE_BACK_PROGRAM=\"$1/sbin/execution-substrate-nomad-take-back\"\n" +
		"NOMAD_DPKG_HOOK=\"$1/dpkg.cfg.d/execution-substrate-nomad\"\n" +
		"mkdir -p -m 0755 \"$1/sbin\" \"$1/dpkg.cfg.d\"\n" +
		linuxSetupDefinitions(t, text, "NOMAD_CONFIG_PATH", "NOMAD_CONFIG_BACKUP_PATH", "NOMAD_TLS_DIR", "NOMAD_MANAGED_MARKER") + `
install() {
  local mode=""
  while [[ $# -gt 1 ]]; do
    case "$1" in
      -m) mode=$2; shift 2 ;;
      -o|-g) shift 2 ;;
      -d) shift ;;
      *) echo "install stand-in: unexpected $1" >&2; return 1 ;;
    esac
  done
  mkdir -p -- "$1"
  [[ -z "${mode}" ]] || chmod "${mode}" -- "$1"
}
date() { echo 20261127000000; }
install_nomad_tls_material() { :; }
install_nomad_gossip_keyring() { :; }
`
}

// runLinuxSetupServiceHarness runs steps after linuxSetupServiceHarness for
// the data directory dataDir.
func runLinuxSetupServiceHarness(t *testing.T, dataDir, steps string) (string, string, error) {
	t.Helper()
	command := exec.Command("bash", "-c", linuxSetupServiceHarness(t)+steps, "bash", dataDir)
	command.Env = []string{"PATH=" + os.Getenv("PATH")}
	var stdout, stderr strings.Builder
	command.Stdout, command.Stderr = &stdout, &stderr
	err := command.Run()
	return stdout.String(), stderr.String(), err
}

// renderedNomadConfig renders install_nomad_service_config's nomad.hcl
// template for dataDir and configDir, independently of the shell.
func renderedNomadConfig(t *testing.T, dataDir, configDir string) string {
	t.Helper()
	text := linuxSetupText(t)
	service := linuxSetupFunction(t, text, "install_nomad_service_config")
	const open, closing = "  config=\"$(cat <<EOF\n", "\nEOF\n)\"\n"
	start := strings.Index(service, open)
	end := strings.Index(service, closing)
	if start < 0 || end < start {
		t.Fatal("install_nomad_service_config has no nomad.hcl template")
	}
	marker := regexp.MustCompile(`(?m)^NOMAD_MANAGED_MARKER="([^"]*)"$`).FindStringSubmatch(text)
	if marker == nil {
		t.Fatal("70_linux_setup.sh does not define NOMAD_MANAGED_MARKER")
	}
	values := map[string]string{
		"NOMAD_MANAGED_MARKER": marker[1],
		"NOMAD_DATA_DIR":       dataDir,
		"NOMAD_GOSSIP_KEYRING": filepath.Join(dataDir, "server", "serf.keyring"),
		"NOMAD_TLS_DIR":        filepath.Join(configDir, "tls"),
	}
	return os.Expand(service[start+len(open):end], func(name string) string {
		value, ok := values[name]
		if !ok {
			t.Fatalf("the nomad.hcl template names %s, which this test does not set", name)
		}
		return value
	})
}

// requireRegularFile fails unless path is a regular file (not a link) with
// the given content and mode.
func requireRegularFile(t *testing.T, path, content string, mode os.FileMode) {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != mode {
		t.Fatalf("%s is %v, want a regular file with mode %04o", path, info.Mode(), mode)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != content {
		t.Fatalf("%s holds %q, want %q", path, data, content)
	}
}

// A46-1: the restart record was written with `: >` as root, which follows a
// link the data folder's former owner left at its name. It is now removed
// first and created exclusively.
func TestLinuxSetupWritesTheRestartRecordWithoutFollowingALink(t *testing.T) {
	for _, test := range []struct {
		name  string
		place func(t *testing.T, pending, outside string)
	}{
		{"a link to a file outside", func(t *testing.T, pending, outside string) {
			if err := os.WriteFile(outside, []byte("victim\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(outside, pending); err != nil {
				t.Fatal(err)
			}
		}},
		{"a dangling link", func(t *testing.T, pending, outside string) {
			if err := os.Symlink(outside, pending); err != nil {
				t.Fatal(err)
			}
		}},
		{"a file others can read", func(t *testing.T, pending, outside string) {
			if err := os.WriteFile(pending, []byte("left\n"), 0o644); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			dataDir := t.TempDir()
			pending := filepath.Join(dataDir, "execution-substrate-restart-pending")
			outside := filepath.Join(t.TempDir(), "victim")
			test.place(t, pending, outside)
			before, beforeErr := os.ReadFile(outside)

			if _, stderr, err := runLinuxSetupGossipHarness(t, dataDir, "nomad_needs_restart\n[[ ${NOMAD_CONFIG_CHANGED} == 1 ]]\n"); err != nil {
				t.Fatalf("nomad_needs_restart: %v %s", err, stderr)
			}
			requireRegularFile(t, pending, "", 0o600)
			after, afterErr := os.ReadFile(outside)
			if string(after) != string(before) || (beforeErr == nil) != (afterErr == nil) {
				t.Fatalf("the record was written through the link: outside held %q (%v), now %q (%v)", before, beforeErr, after, afterErr)
			}
			if beforeErr == nil {
				requireFileMode(t, outside, 0o644)
			}
		})
	}
}

// Once only root can change Nomad's folders, nothing can put a link at a
// name between the setup's removal of it and the creation that follows.
// set -C still makes each creation exclusive, so a link that appears there
// anyway is refused, not followed. A stand-in rm plays the account that wins
// that race: right after it removes RACE_NAME, a link to RACE_TARGET appears
// there (once).
func TestLinuxSetupRefusesALinkThatAppearsAfterItClearsAName(t *testing.T) {
	realRm, err := exec.LookPath("rm")
	if err != nil {
		t.Fatal(err)
	}
	bin := t.TempDir()
	racer := "#!/bin/sh\n" + realRm + ` "$@" || exit
for last; do :; done
if [ "$last" = "$RACE_NAME" ] && [ ! -e "$RACE_ONCE" ]; then
  : >"$RACE_ONCE"
  ln -s -- "$RACE_TARGET" "$last"
fi
`
	if err := os.WriteFile(filepath.Join(bin, "rm"), []byte(racer), 0o755); err != nil {
		t.Fatal(err)
	}
	race := func(t *testing.T, harness, dataDir, name, steps string) (string, string, error) {
		t.Helper()
		victim := filepath.Join(t.TempDir(), "victim")
		if err := os.WriteFile(victim, []byte("victim\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		command := exec.Command("bash", "-c", harness+steps, "bash", dataDir)
		command.Env = []string{"PATH=" + bin + string(os.PathListSeparator) + os.Getenv("PATH"),
			"RACE_NAME=" + name, "RACE_TARGET=" + victim, "RACE_ONCE=" + filepath.Join(t.TempDir(), "once")}
		output, err := command.CombinedOutput()
		requireRegularFile(t, victim, "victim\n", 0o644)
		return string(output), victim, err
	}

	t.Run("the restart record", func(t *testing.T) {
		dataDir := t.TempDir()
		pending := filepath.Join(dataDir, "execution-substrate-restart-pending")
		if output, _, err := race(t, linuxSetupGossipHarness(t), dataDir, pending, "nomad_needs_restart\n"); err == nil {
			t.Fatalf("the record was written through a link that appeared at its name: %s", output)
		}
	})
	t.Run("nomad.hcl's temporary name", func(t *testing.T) {
		dataDir := t.TempDir()
		config := filepath.Join(dataDir, "etc")
		if err := os.Mkdir(config, 0o755); err != nil {
			t.Fatal(err)
		}
		nomadHCL := filepath.Join(config, "nomad.hcl")
		output, _, err := race(t, linuxSetupServiceHarness(t), dataDir, nomadHCL+".execution-substrate-new", "install_nomad_service_config\n")
		if err == nil {
			t.Fatalf("nomad.hcl was written through a link that appeared at its temporary name: %s", output)
		}
		for _, path := range []string{nomadHCL, nomadHCL + ".execution-substrate-new"} {
			if _, err := os.Lstat(path); !os.IsNotExist(err) {
				t.Fatalf("%s is left after the refusal: %v", path, err)
			}
		}
	})
}

// A46-2 (1) and P46-1: install_nomad_service_config records a restart
// exactly when nomad.hcl's text changes, before the new text is written; it
// writes the rendered text plus one newline as a new file, root's 0640 (the
// caller's here), renamed into place; and it follows no link at nomad.hcl,
// at the backup's name, at the temporary name or at the TLS folder.
func TestLinuxSetupWritesNomadConfigAsANewFileAndRecordsOnlyAChange(t *testing.T) {
	// The record must be written before nomad.hcl holds the new text; "$2"
	// names a file holding that text. The function's messages go to
	// standard error, NOMAD_CONFIG_CHANGED to standard output.
	const steps = `NEW_CONFIG="$2"
eval "setup_$(declare -f nomad_needs_restart)"
nomad_needs_restart() {
  if cmp -s -- "${NOMAD_CONFIG_PATH}" "${NEW_CONFIG}"; then
    echo "nomad.hcl was written before the restart record" >&2
    return 1
  fi
  setup_nomad_needs_restart
}
install_nomad_service_config >&2
printf '%s' "${NOMAD_CONFIG_CHANGED}"
`
	type paths struct {
		data, config, nomadHCL, pending, outside string
	}
	setup := func(t *testing.T) paths {
		t.Helper()
		data := t.TempDir()
		config := filepath.Join(data, "etc")
		if err := os.Mkdir(config, 0o755); err != nil {
			t.Fatal(err)
		}
		return paths{data, config, filepath.Join(config, "nomad.hcl"),
			filepath.Join(data, "execution-substrate-restart-pending"), t.TempDir()}
	}
	// guards runs the setup without its take-back program, which sets aside
	// a link where Nomad reads and stops the setup (nomad_take_back_program),
	// so that the setup's own guards behind it are tested too.
	const guards = "nomad_package_hook_as_root() { :; }\n"
	runSteps := func(t *testing.T, p paths, steps string) (string, string) {
		t.Helper()
		newConfig := filepath.Join(p.outside, "new-config")
		if err := os.WriteFile(newConfig, []byte(renderedNomadConfig(t, p.data, p.config)+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		command := exec.Command("bash", "-c", linuxSetupServiceHarness(t)+steps, "bash", p.data, newConfig)
		command.Env = []string{"PATH=" + os.Getenv("PATH")}
		var stdout, stderr strings.Builder
		command.Stdout, command.Stderr = &stdout, &stderr
		if err := command.Run(); err != nil {
			t.Fatalf("install_nomad_service_config: %v %s", err, stderr.String())
		}
		return stdout.String(), stderr.String()
	}
	run := func(t *testing.T, p paths) (string, string) {
		t.Helper()
		return runSteps(t, p, steps)
	}
	written := func(t *testing.T, p paths) string {
		t.Helper()
		want := renderedNomadConfig(t, p.data, p.config) + "\n"
		if strings.HasSuffix(want, "\n\n") || !strings.HasPrefix(want, "# Managed by Execution Substrate") {
			t.Fatalf("the rendered template is not one block ending in one newline: %q", want)
		}
		requireRegularFile(t, p.nomadHCL, want, 0o640)
		if _, err := os.Lstat(p.nomadHCL + ".execution-substrate-new"); !os.IsNotExist(err) {
			t.Fatalf("the temporary name is left: %v", err)
		}
		return want
	}
	recorded := func(t *testing.T, p paths, changed, want string) {
		t.Helper()
		if changed != want {
			t.Fatalf("NOMAD_CONFIG_CHANGED=%s, want %s", changed, want)
		}
		_, err := os.Lstat(p.pending)
		if (err == nil) != (want == "1") {
			t.Fatalf("restart record present=%v, want %v (%v)", err == nil, want == "1", err)
		}
	}

	t.Run("no nomad.hcl, then the same text, then other text", func(t *testing.T) {
		p := setup(t)
		changed, _ := run(t, p)
		recorded(t, p, changed, "1")
		want := written(t, p)

		// The same text: no record, no restart; the file is still written
		// anew.
		if err := os.Remove(p.pending); err != nil {
			t.Fatal(err)
		}
		changed, _ = run(t, p)
		recorded(t, p, changed, "0")
		written(t, p)

		// Other text in a managed file: the record comes first, and the old
		// file (a hard link keeps it, as a handle someone kept open would)
		// is not written: the new text is a new file.
		old := strings.Replace(want, "bind_addr = \"127.0.0.1\"", "bind_addr = \"0.0.0.0\"", 1)
		if old == want {
			t.Fatal("the template has no bind_addr line to change")
		}
		if err := os.WriteFile(p.nomadHCL, []byte(old), 0o640); err != nil {
			t.Fatal(err)
		}
		kept := filepath.Join(p.config, "kept")
		if err := os.Link(p.nomadHCL, kept); err != nil {
			t.Fatal(err)
		}
		changed, _ = run(t, p)
		recorded(t, p, changed, "1")
		written(t, p)
		requireRegularFile(t, kept, old, 0o640)
		if _, err := os.Lstat(p.nomadHCL + ".execution-substrate.bak.20261127000000"); !os.IsNotExist(err) {
			t.Fatalf("a managed nomad.hcl was backed up: %v", err)
		}
	})

	t.Run("a hand edit of the managed file is a change", func(t *testing.T) {
		p := setup(t)
		want := renderedNomadConfig(t, p.data, p.config)
		if err := os.WriteFile(p.nomadHCL, []byte(want+"\n# hand edit\n"), 0o640); err != nil {
			t.Fatal(err)
		}
		changed, _ := run(t, p)
		recorded(t, p, changed, "1")
		written(t, p)
	})

	t.Run("an unmanaged nomad.hcl is backed up, not through a link at the backup's name", func(t *testing.T) {
		p := setup(t)
		const operator = "# the operator's own config\n"
		if err := os.WriteFile(p.nomadHCL, []byte(operator), 0o644); err != nil {
			t.Fatal(err)
		}
		victim := filepath.Join(p.outside, "victim")
		if err := os.WriteFile(victim, []byte("victim\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		backup := p.nomadHCL + ".execution-substrate.bak.20261127000000"
		if err := os.Symlink(victim, backup); err != nil {
			t.Fatal(err)
		}
		changed, _ := run(t, p)
		recorded(t, p, changed, "1")
		written(t, p)
		requireRegularFile(t, victim, "victim\n", 0o644)
		info, err := os.Lstat(backup)
		if err != nil || !info.Mode().IsRegular() {
			t.Fatalf("the backup is not a regular file: %v %v", info, err)
		}
		if data, err := os.ReadFile(backup); err != nil || string(data) != operator {
			t.Fatalf("the backup holds %q (%v), want the operator's config", data, err)
		}
	})

	// R48-2 of re-check 48: with two names and no -T, cp copies into the
	// folder a link at the backup's name points to, and --remove-destination
	// then applies to the name inside it.
	t.Run("an unmanaged nomad.hcl is backed up onto its own name, not into a folder a link there points to", func(t *testing.T) {
		p := setup(t)
		const operator = "# the operator's own config\n"
		if err := os.WriteFile(p.nomadHCL, []byte(operator), 0o644); err != nil {
			t.Fatal(err)
		}
		folder := filepath.Join(p.outside, "folder")
		if err := os.Mkdir(folder, 0o700); err != nil {
			t.Fatal(err)
		}
		backup := p.nomadHCL + ".execution-substrate.bak.20261127000000"
		if err := os.Symlink(folder, backup); err != nil {
			t.Fatal(err)
		}
		changed, _ := run(t, p)
		recorded(t, p, changed, "1")
		written(t, p)
		if entries, err := os.ReadDir(folder); err != nil || len(entries) != 0 {
			t.Fatalf("the backup was copied into the linked folder: %v %v", entries, err)
		}
		requireFileMode(t, folder, 0o700)
		info, err := os.Lstat(backup)
		if err != nil || !info.Mode().IsRegular() {
			t.Fatalf("the backup is not a regular file: %v %v", info, err)
		}
		if data, err := os.ReadFile(backup); err != nil || string(data) != operator {
			t.Fatalf("the backup holds %q (%v), want the operator's config", data, err)
		}
	})

	// Re-check 49 (O49-1): by then the folders are root's again; nomad.hcl
	// and the restart record are not touched, and the message says what to do.
	t.Run("a folder at the backup's name stops the setup before it changes nomad.hcl", func(t *testing.T) {
		p := setup(t)
		const operator = "# the operator's own config\n"
		if err := os.WriteFile(p.nomadHCL, []byte(operator), 0o644); err != nil {
			t.Fatal(err)
		}
		backup := p.nomadHCL + ".execution-substrate.bak.20261127000000"
		if err := os.Mkdir(backup, 0o755); err != nil {
			t.Fatal(err)
		}
		_, stderr, err := runLinuxSetupServiceHarness(t, p.data, "install_nomad_service_config\n")
		if err == nil {
			t.Fatalf("install_nomad_service_config went on past a folder at the backup's name: %s", stderr)
		}
		if want := "nomad: could not back up " + p.nomadHCL + " to " + backup + "; remove what is at that name and rerun"; !strings.Contains(stderr, want) {
			t.Fatalf("the refusal does not say %q: %s", want, stderr)
		}
		if entries, err := os.ReadDir(backup); err != nil || len(entries) != 0 {
			t.Fatalf("the folder at the backup's name holds %v (%v)", entries, err)
		}
		requireRegularFile(t, p.nomadHCL, operator, 0o644)
		if _, err := os.Lstat(p.pending); !os.IsNotExist(err) {
			t.Fatalf("a restart was recorded: %v", err)
		}
	})

	for _, test := range []struct {
		name  string
		place func(t *testing.T, at, outside string) func(t *testing.T)
	}{
		{"a link to a file outside", func(t *testing.T, at, outside string) func(t *testing.T) {
			victim := filepath.Join(outside, "victim")
			if err := os.WriteFile(victim, []byte("victim\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(victim, at); err != nil {
				t.Fatal(err)
			}
			return func(t *testing.T) { requireRegularFile(t, victim, "victim\n", 0o644) }
		}},
		{"a link to a folder outside", func(t *testing.T, at, outside string) func(t *testing.T) {
			folder := filepath.Join(outside, "folder")
			if err := os.Mkdir(folder, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(folder, at); err != nil {
				t.Fatal(err)
			}
			return func(t *testing.T) {
				entries, err := os.ReadDir(folder)
				if err != nil || len(entries) != 0 {
					t.Fatalf("the config was written into the linked folder: %v %v", entries, err)
				}
				requireFileMode(t, folder, 0o700)
			}
		}},
		{"a dangling link", func(t *testing.T, at, outside string) func(t *testing.T) {
			missing := filepath.Join(outside, "missing")
			if err := os.Symlink(missing, at); err != nil {
				t.Fatal(err)
			}
			return func(t *testing.T) {
				if _, err := os.Lstat(missing); !os.IsNotExist(err) {
					t.Fatalf("the config was written through the dangling link: %v", err)
				}
			}
		}},
	} {
		t.Run("nomad.hcl is "+test.name+", without the take-back program", func(t *testing.T) {
			p := setup(t)
			untouched := test.place(t, p.nomadHCL, p.outside)
			changed, messages := runSteps(t, p, guards+steps)
			if !strings.Contains(messages, p.nomadHCL+" is a link; replacing it") {
				t.Errorf("the run did not say it replaced the link: %s", messages)
			}
			recorded(t, p, changed, "1")
			written(t, p)
			untouched(t)
			if matches, _ := filepath.Glob(p.nomadHCL + ".execution-substrate.bak.*"); len(matches) != 0 {
				t.Fatalf("a link was backed up through: %v", matches)
			}
		})
		t.Run("the temporary name is "+test.name, func(t *testing.T) {
			p := setup(t)
			untouched := test.place(t, p.nomadHCL+".execution-substrate-new", p.outside)
			changed, _ := run(t, p)
			recorded(t, p, changed, "1")
			written(t, p)
			untouched(t)
		})
	}

	t.Run("the TLS folder is a link to a folder outside, without the take-back program", func(t *testing.T) {
		p := setup(t)
		folder := filepath.Join(p.outside, "folder")
		if err := os.Mkdir(folder, 0o700); err != nil {
			t.Fatal(err)
		}
		tlsDir := filepath.Join(p.config, "tls")
		if err := os.Symlink(folder, tlsDir); err != nil {
			t.Fatal(err)
		}
		_, messages := runSteps(t, p, guards+steps)
		if !strings.Contains(messages, tlsDir+" is a link; replacing it with a folder") {
			t.Errorf("the run did not say it replaced the link: %s", messages)
		}
		info, err := os.Lstat(tlsDir)
		if err != nil || !info.IsDir() || info.Mode().Perm() != 0o755 {
			t.Fatalf("the TLS folder is %v (%v), want a folder with mode 0755", info, err)
		}
		requireFileMode(t, folder, 0o700)
	})
}

// P46-1: nomad_tls_issue writes Nomad's key and certificates as root. It
// refuses a TLS folder that is a link, and a link at one of its file names
// is replaced by the new file, not followed.
func TestNomadTLSIssueFollowsNoLink(t *testing.T) {
	t.Run("the folder is a link", func(t *testing.T) {
		folder := t.TempDir()
		if err := os.Chmod(folder, 0o700); err != nil {
			t.Fatal(err)
		}
		dir := filepath.Join(t.TempDir(), "tls")
		if err := os.Symlink(folder, dir); err != nil {
			t.Fatal(err)
		}
		output, err := nomadTLSSetupFunctions(`nomad_tls_issue "$1"`, nil, dir)
		if err == nil || !strings.Contains(output, dir+" is a link; refusing") {
			t.Fatalf("nomad_tls_issue wrote through a linked folder: %v %s", err, output)
		}
		if entries, err := os.ReadDir(folder); err != nil || len(entries) != 0 {
			t.Fatalf("the linked folder holds %v (%v)", entries, err)
		}
		// The refusal comes before the issuer makes or re-modes the folder
		// (N48-2 of re-check 48): the link's target keeps its mode.
		requireFileMode(t, folder, 0o700)
	})
	// Each kind of link at all three names: mv without -T would move a file
	// into a linked folder.
	for _, kind := range []string{"file", "folder", "missing"} {
		t.Run("links to a "+kind+" at the file names", func(t *testing.T) {
			dir, outside := t.TempDir(), t.TempDir()
			names := []string{"server-key.pem", "server.pem", "ca.pem"}
			for _, name := range names {
				target := filepath.Join(outside, name)
				switch kind {
				case "file":
					if err := os.WriteFile(target, []byte("victim\n"), 0o644); err != nil {
						t.Fatal(err)
					}
				case "folder":
					if err := os.Mkdir(target, 0o700); err != nil {
						t.Fatal(err)
					}
				}
				if err := os.Symlink(target, filepath.Join(dir, name)); err != nil {
					t.Fatal(err)
				}
			}
			if output, err := nomadTLSSetupFunctions(`nomad_tls_issue "$1" && nomad_tls_material_ok "$1"`, nil, dir); err != nil {
				t.Fatalf("nomad_tls_issue: %v %s", err, output)
			}
			for _, name := range names {
				info, err := os.Lstat(filepath.Join(dir, name))
				if err != nil || !info.Mode().IsRegular() {
					t.Fatalf("%s is %v (%v), want a regular file", name, info, err)
				}
				target := filepath.Join(outside, name)
				switch kind {
				case "file":
					requireRegularFile(t, target, "victim\n", 0o644)
				case "folder":
					if entries, err := os.ReadDir(target); err != nil || len(entries) != 0 {
						t.Fatalf("%s was moved into the linked folder: %v (%v)", name, entries, err)
					}
				default:
					if _, err := os.Lstat(target); !os.IsNotExist(err) {
						t.Fatalf("%s was written through the dangling link: %v", name, err)
					}
				}
			}
		})
	}
}

// A46-2 (2): the closing summary says Nomad encrypts its gossip only when
// qualification passed, which requires the agent to report
// stats.serf.encrypted as "true"; otherwise it makes no such claim.
func TestLinuxSetupSummaryClaimsGossipEncryptionOnlyAfterQualification(t *testing.T) {
	text := linuxSetupText(t)
	const claim = "Nomad encrypts its gossip with the key in"
	if n := strings.Count(text, claim); n != 1 {
		t.Fatalf("70_linux_setup.sh makes the gossip claim %d times, want once", n)
	}
	lines := strings.Split(text, "\n")
	at := -1
	for i, line := range lines {
		if strings.Contains(line, claim) {
			at = i
		}
	}
	start, end := at, at
	for start >= 0 && !strings.HasPrefix(lines[start], "if ") {
		start--
	}
	for end < len(lines) && lines[end] != "fi" {
		end++
	}
	if start < 0 || end == len(lines) {
		t.Fatal("the gossip claim is not inside a top-level if block")
	}
	block := strings.Join(lines[start:end+1], "\n") + "\n"
	for _, test := range []struct {
		ready, want, not string
	}{
		{"1", claim, "makes no claim"},
		{"0", "but this run did not qualify Nomad, so it makes no claim that Nomad encrypts its gossip", claim},
	} {
		command := exec.Command("bash", "-c", "set -euo pipefail\n"+block, "bash")
		command.Env = []string{"PATH=" + os.Getenv("PATH"), "SUPPORTED_SUBSTRATE_READY=" + test.ready, "NOMAD_GOSSIP_KEYRING=/k"}
		output, err := command.CombinedOutput()
		if err != nil || !strings.Contains(string(output), test.want) || strings.Contains(string(output), test.not) {
			t.Errorf("summary with SUPPORTED_SUBSTRATE_READY=%s: %v %q", test.ready, err, output)
		}
	}

	// Qualification is the only place that sets it, after its check of the
	// agent's gossip.
	if n := strings.Count(text, "SUPPORTED_SUBSTRATE_READY=1"); n != 1 {
		t.Fatalf("SUPPORTED_SUBSTRATE_READY=1 appears %d times", n)
	}
	qualify := linuxSetupFunction(t, text, "qualify_supported_substrate")
	check := strings.Index(qualify, `if serf.get("encrypted") != "true":`)
	ready := strings.Index(qualify, "\n  SUPPORTED_SUBSTRATE_READY=1\n")
	if check < 0 || ready < check {
		t.Fatalf("qualify_supported_substrate must check the agent's gossip before it sets SUPPORTED_SUBSTRATE_READY=1 (offsets %d %d)", check, ready)
	}
}

// S48-1 of re-check 48 (the test it proposed). configuration.md says the
// setup reads and backs up the old nomad.hcl only when it is a regular file.
// A FIFO at nomad.hcl, which the package's former owner can plant, must not
// make the setup block on reading it; a folder there is refused, and no
// temporary name is left behind. The take-back program, which the setup runs
// first, sets a FIFO aside without opening it, and the setup stops; without
// the program, the setup's own step replaces it.
func TestLinuxSetupReadsNomadConfigOnlyWhenItIsARegularFile(t *testing.T) {
	runSteps := func(t *testing.T, dataDir, steps string) (string, error) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		command := exec.CommandContext(ctx, "bash", "-c", linuxSetupServiceHarness(t)+steps+"install_nomad_service_config\n", "bash", dataDir)
		command.Env = []string{"PATH=" + os.Getenv("PATH")}
		command.WaitDelay = time.Second
		output, err := command.CombinedOutput()
		if ctx.Err() != nil {
			t.Fatalf("install_nomad_service_config did not finish: it blocked on what is at nomad.hcl: %s", output)
		}
		return string(output), err
	}
	run := func(t *testing.T, dataDir string) (string, error) {
		t.Helper()
		return runSteps(t, dataDir, "")
	}
	setup := func(t *testing.T) (data, config, hcl string) {
		t.Helper()
		data = t.TempDir()
		config = filepath.Join(data, "etc")
		if err := os.Mkdir(config, 0o755); err != nil {
			t.Fatal(err)
		}
		return data, config, filepath.Join(config, "nomad.hcl")
	}

	t.Run("a FIFO is set aside, not read, and the setup stops", func(t *testing.T) {
		data, config, hcl := setup(t)
		if err := syscall.Mkfifo(hcl, 0o644); err != nil {
			t.Fatal(err)
		}
		output, err := run(t, data)
		if err == nil || !strings.Contains(output, "execution-substrate: set aside "+hcl+" (a FIFO, not a regular file): it is "+config+".execution-substrate-set-aside/") {
			t.Fatalf("install_nomad_service_config went on past a FIFO at nomad.hcl: %v %s", err, output)
		}
		if _, err := os.Lstat(hcl); !os.IsNotExist(err) {
			t.Fatalf("the FIFO is still at nomad.hcl: %v", err)
		}
	})

	t.Run("a FIFO is replaced, not read, without the take-back program", func(t *testing.T) {
		data, config, hcl := setup(t)
		if err := syscall.Mkfifo(hcl, 0o644); err != nil {
			t.Fatal(err)
		}
		if output, err := runSteps(t, data, "nomad_package_hook_as_root() { :; }\n"); err != nil {
			t.Fatalf("install_nomad_service_config: %v %s", err, output)
		}
		requireRegularFile(t, hcl, renderedNomadConfig(t, data, config)+"\n", 0o640)
		if matches, _ := filepath.Glob(hcl + ".execution-substrate.bak.*"); len(matches) != 0 {
			t.Fatalf("a FIFO was backed up: %v", matches)
		}
	})

	t.Run("a folder is refused and left as it is", func(t *testing.T) {
		data, _, hcl := setup(t)
		if err := os.Mkdir(hcl, 0o755); err != nil {
			t.Fatal(err)
		}
		output, err := run(t, data)
		if err == nil {
			t.Fatalf("install_nomad_service_config replaced a folder at nomad.hcl: %s", output)
		}
		if info, statErr := os.Lstat(hcl); statErr != nil || !info.IsDir() {
			t.Fatalf("the folder at nomad.hcl is %v (%v)", info, statErr)
		}
		if _, statErr := os.Lstat(hcl + ".execution-substrate-new"); !os.IsNotExist(statErr) {
			t.Fatalf("the temporary name is left after the refusal: %v", statErr)
		}
		if !strings.Contains(output, "nomad: could not write "+hcl) {
			t.Fatalf("the refusal does not name nomad.hcl: %s", output)
		}
	})
}

// A folder at the restart record's name (R6 of re-check 48): the record is
// written only as a new file, so the setup refuses and leaves the folder, with
// whatever the former owner put in it, as it is.
func TestLinuxSetupRefusesAFolderAtTheRestartRecord(t *testing.T) {
	dataDir := t.TempDir()
	pending := filepath.Join(dataDir, "execution-substrate-restart-pending")
	if err := os.MkdirAll(filepath.Join(pending, "inside"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, stderr, err := runLinuxSetupGossipHarness(t, dataDir, "nomad_needs_restart\n"); err == nil {
		t.Fatalf("nomad_needs_restart replaced a folder at the record's name: %s", stderr)
	}
	if info, err := os.Lstat(filepath.Join(pending, "inside")); err != nil || !info.IsDir() {
		t.Fatalf("what was in the folder at the record's name is gone: %v %v", info, err)
	}
}
