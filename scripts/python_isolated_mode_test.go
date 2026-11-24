package scripts_test

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Every Python run in scripts/ starts in isolated mode (-I). Without it,
// Python puts the current folder (or the script's folder) first on sys.path
// and reads PYTHONPATH, PYTHONSTARTUP and the user's site-packages. A root
// run started from a folder another account can write would then import that
// account's base64.py or json.py instead of the standard module. -I turns all
// of that off. (Audit 16 of PR #51, O16-2.)
//
// The check is on the text: every word python, python3 or python3.N in a file
// under scripts/, other than a Go test file, is followed by " -I" (a shell
// run, "#!/usr/bin/env -S python3 -I") or by `", "-I"` (a Python or Go list).
// The exceptions are mentions that run nothing: an argument to `command -v`
// or to a *require_command(s) function, and the exact lines listed in
// pythonMentionsThatRunNothing, each with its reason.

// pythonMentionsThatRunNothing lists, by file, exact lines (without leading
// and trailing space) that name Python but do not start it. Every entry must
// still be found, so the list cannot keep a line that has gone.
var pythonMentionsThatRunNothing = map[string][]string{
	// A package name in the apt-get install list, and the label printed
	// before the version (the run after the label has -I).
	"scripts/70_linux_setup.sh": {
		`python3 \`,
		`printf 'python3: '; python3 -I --version`,
	},
	// A container image name.
	"scripts/72_supported_local_setup.sh": {
		`"base_image": "python:3.13-alpine",`,
	},
	// A field name of the runtime image summary.
	"scripts/internal/supported_local_proof_projection.py": {
		`require(set(summary) == {"status", "profile", "python", "git", "shell", "codex_cli",`,
		`require(isinstance(summary["python"], str) and re.fullmatch(r"Python [0-9.]{3,32}", summary["python"]))`,
	},
	// Commands printed for the operator to run on the Mac, in the
	// Infrastructure Manager checkout. They need PYTHONPATH=src, which -I
	// would ignore, and run that repository's own code, not these scripts.
	"scripts/remote_alpha_operator.sh": {
		`printf 'PYTHONPATH=src python3 -m infra_manager.cli remote-alpha-live-refresh \\\n'`,
		`printf 'PYTHONPATH=src python3 -m infra_manager.cli remote-alpha-live-support-bundle \\\n'`,
	},
	"scripts/remote_alpha_reset_disposable_vault.sh": {
		`PYTHONPATH=src python3 -m infra_manager.cli remote-alpha-live-refresh \`,
	},
	// The interpreter path for the remote command, which is always
	// REMOTE_PYTHON + " -I -S -B - ..." (pinned by
	// TestRemoteAlphaOperatorHealthcheckTLSStatusNoninteractive tests).
	"scripts/remote_alpha_operator_healthcheck_tls_status_noninteractive.py": {
		`REMOTE_PYTHON = "/usr/bin/python3"`,
	},
	// An error message.
	"scripts/remote_alpha_runtime_identity_helper_summary.sh": {
		`echo "python3 is required" >&2`,
	},
}

var pythonRequireCommandArgument = regexp.MustCompile(`(?:^|[^A-Za-z0-9_])[A-Za-z0-9_]*require_commands?((?: +[A-Za-z0-9_.-]+)*) +$`)

func pythonWordByte(b byte) bool {
	return b == '_' || b == '.' || b == '-' || (b >= '0' && b <= '9') || (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
}

// pythonWords returns the [start, end) offsets of every word python, python3
// or python3.N in line.
func pythonWords(line string) [][2]int {
	var words [][2]int
	for i := 0; ; {
		j := strings.Index(line[i:], "python")
		if j < 0 {
			return words
		}
		start := i + j
		end := start + len("python")
		if end < len(line) && line[end] == '3' {
			end++
			if end+1 < len(line) && line[end] == '.' && line[end+1] >= '0' && line[end+1] <= '9' {
				end += 2
				for end < len(line) && line[end] >= '0' && line[end] <= '9' {
					end++
				}
			}
		}
		if (start == 0 || !pythonWordByte(line[start-1])) && (end == len(line) || !pythonWordByte(line[end])) {
			words = append(words, [2]int{start, end})
		}
		i = start + len("python")
	}
}

// pythonRunIsIsolated reports whether the word that ends at end is followed
// by -I as its first option.
func pythonRunIsIsolated(line string, end int) bool {
	rest := line[end:]
	if strings.HasPrefix(rest, " -I") {
		return len(rest) == 3 || strings.ContainsRune(" \t\"'\\", rune(rest[3]))
	}
	return strings.HasPrefix(rest, `", "-I"`) || strings.HasPrefix(rest, `', '-I'`)
}

// pythonMentionRunsNothing reports whether the word at [start, end) is an
// argument to command -v or to a *require_command(s) function.
func pythonMentionRunsNothing(line string, start int) bool {
	before := line[:start]
	return strings.HasSuffix(before, "command -v ") || pythonRequireCommandArgument.MatchString(before)
}

// nonIsolatedPythonRuns returns the lines of text that name Python without
// -I, other than the exceptions above and the exact lines in allowed.
func nonIsolatedPythonRuns(text string, allowed map[string]bool) (lines []int, isolated int) {
	for number, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(raw)
		words := pythonWords(line)
		if len(words) == 0 {
			continue
		}
		if allowed[line] {
			continue
		}
		for _, word := range words {
			if pythonRunIsIsolated(line, word[1]) {
				isolated++
				continue
			}
			if pythonMentionRunsNothing(line, word[0]) {
				continue
			}
			lines = append(lines, number+1)
			break
		}
	}
	return lines, isolated
}

func TestScriptsStartPythonInIsolatedMode(t *testing.T) {
	root := filepath.Join(executionSubstrateRepoRoot, "scripts")
	used := map[string]map[string]bool{}
	isolatedRuns := 0
	files := 0
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() || strings.HasSuffix(entry.Name(), "_test.go") || !entry.Type().IsRegular() {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(executionSubstrateRepoRoot, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		files++
		allowed := map[string]bool{}
		for _, line := range pythonMentionsThatRunNothing[rel] {
			allowed[line] = true
		}
		text := string(data)
		bad, isolated := nonIsolatedPythonRuns(text, allowed)
		isolatedRuns += isolated
		lines := strings.Split(text, "\n")
		for _, number := range bad {
			t.Errorf("%s:%d names Python without -I as its first option; start it as python3 -I (or list it in pythonMentionsThatRunNothing with the reason if it runs nothing):\n  %s", rel, number, strings.TrimSpace(lines[number-1]))
		}
		for _, line := range lines {
			if allowed[strings.TrimSpace(line)] {
				if used[rel] == nil {
					used[rel] = map[string]bool{}
				}
				used[rel][strings.TrimSpace(line)] = true
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}
	for rel, entries := range pythonMentionsThatRunNothing {
		for _, line := range entries {
			if !used[rel][line] {
				t.Errorf("pythonMentionsThatRunNothing lists a line that %s no longer has; delete the entry:\n  %s", rel, line)
			}
		}
	}
	// The walk must have seen the scripts and their runs, so that a walk that
	// finds nothing cannot pass.
	if files < 50 || isolatedRuns < 200 {
		t.Fatalf("the walk saw %d files and %d isolated Python runs under %s; expected at least 50 and 200", files, isolatedRuns, root)
	}
}

// TestScriptsPythonIsolatedModeDocs pins the rule in the Remote Alpha docs,
// which cover the supported-local scripts too.
func TestScriptsPythonIsolatedModeDocs(t *testing.T) {
	section := compactDocSection(t, mustRead(t, ".docs/system_overview/remote_supported_host_alpha.md"), "## Python In The Scripts", "## Non-Goals")
	assertContainsAll(t, "Python In The Scripts docs", section,
		"Every Python run that a script under `scripts/` starts, the remote alpha scripts and the supported-local ones alike, starts in isolated mode: `python3 -I`, and `#!/usr/bin/env -S python3 -I` as the first line of a Python file.",
		"A root run started from a folder that another account can write would then import that account's module in place of a standard one.",
		"`TestScriptsStartPythonInIsolatedMode` fails on every mention of Python under `scripts/` that is not followed by `-I`.",
		"The test lists each one with its reason.",
	)
}

// TestScriptsPythonIsolatedModeCheckFindsEachForm runs the check above on
// lines written for it, so that a check that misses a form fails here.
func TestScriptsPythonIsolatedModeCheckFindsEachForm(t *testing.T) {
	flagged := []string{
		`python3 - "${path}" <<'PY'`,
		`  value="$(python3 -c 'import json; print(1)')"`,
		`sudo -n python3 "${HELPER}" provision`,
		`printf '%s' "${output}" | python3 /dev/fd/3 3<<'PY'`,
		`STATUS_JSON="${raw}" python3 <<'PY'`,
		`python3 -B -I - <<'PY'`,
		`python3 -m json.tool "${path}"`,
		`exec /usr/bin/python3 "${SCRIPT_DIR}/internal/x.py" "$@"`,
		`python3.12 - <<'PY'`,
		`python - <<'PY'`,
		`#!/usr/bin/env python3`,
		`subprocess.run(["python3", projector, "status"], check=True)`,
		`cmd := exec.Command("python3", "-c", script)`,
		`python3 -Im json.tool`,
		`require_command python3 && python3 - <<'PY'`,
	}
	for _, line := range flagged {
		if bad, _ := nonIsolatedPythonRuns(line, nil); len(bad) != 1 {
			t.Errorf("the check must flag %q", line)
		}
	}
	accepted := []string{
		`python3 -I - "${path}" <<'PY'`,
		`  value="$(python3 -I -c 'import json; print(1)')"`,
		`sudo -n python3 -I "${HELPER}" provision`,
		`printf '%s' "${output}" | python3 -I /dev/fd/3 3<<'PY'`,
		`STATUS_JSON="${raw}" python3 -I <<'PY'`,
		`python3 -I -B - <<'PY'`,
		`python3 -I \`,
		`exec /usr/bin/python3 -I -B "${SCRIPT_DIR}/internal/x.py" "$@"`,
		`#!/usr/bin/env -S python3 -I`,
		`subprocess.run(["python3", "-I", projector, "status"], check=True)`,
		`-lc 'python3 -I --version 2>&1'`,
		`remote_alpha_x_require_command python3 || return 1`,
		`remote_alpha_host_firewall_require_commands nft ip ss systemctl python3 sha256sum sshd || return 1`,
		`resolved=$(command -v python3 2>/dev/null || true)`,
		`PYTHONPATH=src`,
		`import pythonic`,
		`# typed by a person: see mypython3 and python3x`,
	}
	for _, line := range accepted {
		if bad, _ := nonIsolatedPythonRuns(line, nil); len(bad) != 0 {
			t.Errorf("the check must accept %q", line)
		}
	}
}
