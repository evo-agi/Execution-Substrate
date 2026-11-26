package scripts_test

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The upgrade moves the box's ES only forward along the clone's history: to
// a commit the installed build is an ancestor of. Any other move, to an
// older commit, to one on another line of history, or to one whose order
// the clone cannot show, runs only when root names that one move on the
// command line as --allow-downgrade <installed commit>..<named commit>.

// moveRun runs check or apply on h with one --allow-downgrade per value of
// allow. The commit goes in as --commit=<commit>, so that one that starts
// with "-" reaches the upgrade.
func moveRun(h *upgradeHost, command string, allow ...string) (string, string, int) {
	h.t.Helper()
	args := []string{command, "--payload", h.payload, "--commit=" + h.commit}
	for _, value := range allow {
		args = append(args, "--allow-downgrade", value)
	}
	return h.run(args...)
}

// moveCheck is check with allow, and its report.
func moveCheck(h *upgradeHost, allow ...string) (map[string]any, string, int) {
	h.t.Helper()
	stdout, stderr, code := moveRun(h, "check", allow...)
	var report map[string]any
	if err := json.Unmarshal([]byte(stdout), &report); err != nil {
		h.t.Fatalf("check printed no JSON report (exit %d): %v\nstdout %s\nstderr %s", code, err, stdout, stderr)
	}
	return report, stderr, code
}

// moveBlockers is what the report's blockers of the scope "move" say.
func moveBlockers(report map[string]any) []string {
	var found []string
	blockers, _ := report["blockers"].([]any)
	for _, b := range blockers {
		if blocker := b.(map[string]any); blocker["scope"] == "move" {
			found = append(found, blocker["summary"].(string))
		}
	}
	return found
}

// requireMoveRefused fails unless check refuses h with allow, with a move
// blocker that says says, and apply then refuses it too, with nothing
// changed, no backup written and no service touched.
func requireMoveRefused(t *testing.T, h *upgradeHost, says string, allow ...string) map[string]any {
	t.Helper()
	before := h.snapshot()
	h.clearCalls()
	report, stderr, code := moveCheck(h, allow...)
	if code != 1 || !strings.Contains(stderr, "blocker(s); nothing was changed") {
		t.Fatalf("check exited %d: %s\nblockers %v", code, stderr, report["blockers"])
	}
	blockers := moveBlockers(report)
	if len(blockers) != 1 || !strings.Contains(blockers[0], says) {
		t.Fatalf("move blockers %q, want one that says %q (all blockers %v)", blockers, says, report["blockers"])
	}
	assertRestored(t, before, h.snapshot())
	onlyReads(t, h, "a refused check")
	h.clearCalls()
	_, stderr, code = moveRun(h, "apply", allow...)
	if code != 1 || !strings.Contains(stderr, "nothing was changed") {
		t.Fatalf("apply exited %d: %s", code, stderr)
	}
	assertRestored(t, before, h.snapshot())
	if dirs := backupDirs(t, h); len(dirs) != 0 {
		t.Fatalf("a refused apply wrote a backup: %v", dirs)
	}
	onlyReads(t, h, "a refused apply")
	return report
}

// requireMove fails unless report's move is from installed to the named
// commit, with order, and authorized by --allow-downgrade (with sudoUser)
// exactly when authorized.
func requireMove(t *testing.T, report map[string]any, installed, order string, authorized bool, sudoUser any) {
	t.Helper()
	move, ok := report["move"].(map[string]any)
	if !ok {
		t.Fatalf("no move in the report: %v", report["move"])
	}
	want := map[string]any{"from": installed, "to": upgradeTestCommit, "order": order, "why": move["why"]}
	if authorized {
		want["authorized"] = "--allow-downgrade " + installed + ".." + upgradeTestCommit
		want["sudo_user"] = sudoUser
	}
	if why, _ := move["why"].(string); why == "" || fmt.Sprint(move) != fmt.Sprint(want) {
		t.Fatalf("move %v, want %v", move, want)
	}
}

// moveHost is a host and what check finds as the move from its ES build to
// upgradeTestCommit.
type moveHost struct {
	name      string
	setup     func(h *upgradeHost)
	installed string
	order     string
	why       string
}

// httpsHostRunning puts h on HTTPS without a gossip keyring, its ES a clean
// build of installed.
func httpsHostRunning(installed string) func(h *upgradeHost) {
	return func(h *upgradeHost) { h.toHTTPSWithoutKeyring(installed) }
}

// notForwardHosts are hosts whose move to upgradeTestCommit is not forward.
var notForwardHosts = []moveHost{
	{"an older commit than the installed build", httpsHostRunning(newerESCommit), newerESCommit, "backward",
		"backward: " + upgradeTestCommit + " is an ancestor of " + newerESCommit + ", so older"},
	{"a commit beside the installed build", httpsHostRunning(sideESCommit), sideESCommit, "sideways",
		"sideways: neither of " + sideESCommit + " and " + upgradeTestCommit + " is an ancestor of the other"},
	{"an installed build the clone does not hold", httpsHostRunning(strings.Repeat("ab", 20)), strings.Repeat("ab", 20), "unknown",
		"unknown: the clone %s does not hold the commit " + strings.Repeat("ab", 20)},
	{"a shallow clone", func(h *upgradeHost) {
		h.toHTTPSWithoutKeyring(previousESCommit)
		// git takes the commits .git/shallow names to have no parents.
		path := filepath.Join(h.modules, ".git", "shallow")
		if err := os.WriteFile(path, []byte(upgradeTestCommit+"\n"), 0o644); err != nil {
			h.t.Fatal(err)
		}
		denyGroupOtherWrite(h.t, h.modules)
	}, previousESCommit, "unknown", "unknown: the clone %s is shallow, so its history may stop short of " + previousESCommit},
	{"the box's own first build, which a clone of the fixture does not hold", func(h *upgradeHost) {
		// Without the test's stand-in, BOX_ES_COMMIT itself is the build
		// of a locked-http host.
		h.env["ES_UPGRADE_TEST_BOX_ES_COMMIT"] = ""
		h.installBuilds(realBoxESCommit)
	}, realBoxESCommit, "unknown", "unknown: the clone %s does not hold the commit " + realBoxESCommit},
}

func TestRemoteAlphaUpgradeESReportsAForwardMove(t *testing.T) {
	helper := buildESConfigCheck(t)
	for _, tc := range []moveHost{
		{"the box's first build, on a locked-http host", func(*upgradeHost) {}, boxESCommit, "forward",
			boxESCommit + " is an ancestor of " + upgradeTestCommit},
		{"the build the box runs, on an https host", httpsHostRunning(previousESCommit), previousESCommit, "forward",
			previousESCommit + " is an ancestor of " + upgradeTestCommit},
		{"the payload's own builds, on an https host without a keyring", httpsHostRunning(upgradeTestCommit), upgradeTestCommit, "same",
			"the installed ES binaries are builds of " + upgradeTestCommit + " already"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newUpgradeHost(t, helper)
			tc.setup(h)
			report, stderr, code := moveCheck(h)
			if code != 0 || report["result"] != "ready" {
				t.Fatalf("check exited %d, result %v: %s\nblockers %v", code, report["result"], stderr, report["blockers"])
			}
			requireMove(t, report, tc.installed, tc.order, false, nil)
			if why := report["move"].(map[string]any)["why"]; why != tc.why {
				t.Fatalf("why %q, want %q", why, tc.why)
			}
			stdout, stderr, code := moveRun(h, "apply")
			if code != 0 {
				t.Fatalf("apply exited %d\nstdout %s\nstderr %s", code, stdout, stderr)
			}
			backupDir, summary := readSummary(t, h)
			requireMove(t, summary, tc.installed, tc.order, false, nil)
			var record map[string]any
			if err := json.Unmarshal([]byte(mustRead(t, filepath.Join(backupDir, "move.json"))), &record); err != nil {
				t.Fatal(err)
			}
			if fmt.Sprint(record) != fmt.Sprint(summary["move"]) {
				t.Fatalf("move.json %v, the summary's move %v", record, summary["move"])
			}
			if strings.Contains(stdout, "which is not forward") {
				t.Fatalf("apply logged a forward move as authorized:\n%s", stdout)
			}
		})
	}
}

func TestRemoteAlphaUpgradeESRefusesAMoveThatIsNotForward(t *testing.T) {
	helper := buildESConfigCheck(t)
	for _, tc := range notForwardHosts {
		t.Run(tc.name, func(t *testing.T) {
			h := newUpgradeHost(t, helper)
			tc.setup(h)
			why := tc.why
			if strings.Contains(why, "%s") {
				why = fmt.Sprintf(why, h.modules)
			}
			report := requireMoveRefused(t, h, "moving ES from "+tc.installed+" to "+upgradeTestCommit+" is not forward ("+why+
				"); it runs only when root names this move on the command line as --allow-downgrade <installed commit>..<named commit>")
			requireMove(t, report, tc.installed, tc.order, false, nil)

			// No variable stands in for the command line.
			for _, name := range []string{"ALLOW_DOWNGRADE", "ES_ALLOW_DOWNGRADE", "ES_UPGRADE_ALLOW_DOWNGRADE", "ES_UPGRADE_TEST_ALLOW_DOWNGRADE"} {
				h.env[name] = tc.installed + ".." + upgradeTestCommit
			}
			requireMoveRefused(t, h, "is not forward ("+why+")")
		})
	}
}

func TestRemoteAlphaUpgradeESMakesAMoveThatIsNotForwardOnlyWhenRootNamesIt(t *testing.T) {
	helper := buildESConfigCheck(t)
	for i, tc := range notForwardHosts {
		t.Run(tc.name, func(t *testing.T) {
			h := newUpgradeHost(t, helper)
			tc.setup(h)
			// sudo names the user who started the run, when sudo started it.
			var sudoUser any
			if i%2 == 0 {
				h.env["SUDO_USER"] = "operator"
				sudoUser = "operator"
			} else {
				h.env["SUDO_USER"] = ""
			}
			allow := tc.installed + ".." + upgradeTestCommit
			before := h.snapshot()
			h.clearCalls()
			report, stderr, code := moveCheck(h, allow)
			if code != 0 || report["result"] != "ready" {
				t.Fatalf("check exited %d, result %v: %s\nblockers %v", code, report["result"], stderr, report["blockers"])
			}
			requireMove(t, report, tc.installed, tc.order, true, sudoUser)
			assertRestored(t, before, h.snapshot())
			onlyReads(t, h, "check")

			stdout, stderr, code := moveRun(h, "apply", allow)
			if code != 0 {
				t.Fatalf("apply exited %d\nstdout %s\nstderr %s", code, stdout, stderr)
			}
			if mustRead(t, h.path("usr/local/lib/execution-substrate/bin/es")) != string(newESBuild) ||
				mustRead(t, h.path("usr/local/bin/es-runtime-support")) != string(newRuntimeSupportBuild) {
				t.Fatal("the binaries are not the payload's")
			}
			backupDir, summary := readSummary(t, h)
			if summary["result"] != "applied" {
				t.Fatalf("summary result %v", summary["result"])
			}
			requireMove(t, summary, tc.installed, tc.order, true, sudoUser)
			// The record in the backup is written before anything changes.
			var record map[string]any
			if err := json.Unmarshal([]byte(mustRead(t, filepath.Join(backupDir, "move.json"))), &record); err != nil {
				t.Fatal(err)
			}
			if fmt.Sprint(record) != fmt.Sprint(summary["move"]) {
				t.Fatalf("move.json %v, the summary's move %v", record, summary["move"])
			}
			by := "no sudo user named"
			if sudoUser != nil {
				by = "sudo user operator"
			}
			said := fmt.Sprintf("moving ES from %s to %s, which is not forward (%s), as root named it: --allow-downgrade %s (%s)",
				tc.installed, upgradeTestCommit, tc.order, allow, by)
			if !strings.Contains(fmt.Sprint(summary["events"]), said) || !strings.Contains(stdout, said) {
				t.Fatalf("apply did not say %q:\n%s", said, stdout)
			}
			log := mustRead(t, filepath.Join(h.state, "calls.log"))
			if first, stop := strings.Index(stdout, said), strings.Index(stdout, "es stopped"); first < 0 || stop < first {
				t.Fatalf("apply stopped ES before it recorded the move:\n%s", stdout)
			}
			if !strings.Contains(log, "systemctl stop es") {
				t.Fatalf("apply did not run:\n%s", log)
			}
		})
	}
}

func TestRemoteAlphaUpgradeESRefusesAnAllowDowngradeThatDoesNotNameTheMove(t *testing.T) {
	helper := buildESConfigCheck(t)
	older := httpsHostRunning(newerESCommit)
	malformed := " does not name a move as <installed commit>..<named commit>, each a full lower-case 40-character SHA-1"
	cases := []struct {
		name  string
		setup func(h *upgradeHost)
		allow []string
		says  string
	}{
		{"the two commits the other way round", older, []string{upgradeTestCommit + ".." + newerESCommit},
			"--allow-downgrade names the move " + upgradeTestCommit + ".." + newerESCommit + ", but this one is " + newerESCommit + ".." + upgradeTestCommit},
		{"another installed commit", older, []string{previousESCommit + ".." + upgradeTestCommit},
			"--allow-downgrade names the move " + previousESCommit + ".." + upgradeTestCommit + ", but this one is " + newerESCommit + ".." + upgradeTestCommit},
		{"another named commit", older, []string{newerESCommit + ".." + previousESCommit},
			"--allow-downgrade names the move " + newerESCommit + ".." + previousESCommit + ", but this one is " + newerESCommit + ".." + upgradeTestCommit},
		{"the move named twice", older, []string{newerESCommit + ".." + upgradeTestCommit, newerESCommit + ".." + upgradeTestCommit},
			"--allow-downgrade is given more than once; name the one move once"},
		{"the right move, then another", older, []string{newerESCommit + ".." + upgradeTestCommit, previousESCommit + ".." + upgradeTestCommit},
			"--allow-downgrade is given more than once"},
		{"one commit", older, []string{newerESCommit}, "--allow-downgrade '" + newerESCommit + "'" + malformed},
		{"three dots", older, []string{newerESCommit + "..." + upgradeTestCommit}, malformed},
		{"three commits", older, []string{newerESCommit + ".." + upgradeTestCommit + ".." + upgradeTestCommit}, malformed},
		{"short commits", older, []string{newerESCommit[:12] + ".." + upgradeTestCommit[:12]}, malformed},
		{"upper-case commits", older, []string{strings.ToUpper(newerESCommit) + ".." + upgradeTestCommit}, malformed},
		{"a trailing newline", older, []string{newerESCommit + ".." + upgradeTestCommit + "\n"}, malformed},
		{"a leading space", older, []string{" " + newerESCommit + ".." + upgradeTestCommit}, malformed},
		{"empty", older, []string{""}, "--allow-downgrade ''" + malformed},
		{"a forward move, on an https host", httpsHostRunning(previousESCommit), []string{previousESCommit + ".." + upgradeTestCommit},
			"--allow-downgrade is only for a move that is not forward, and this one is forward (" + previousESCommit + " is an ancestor of " + upgradeTestCommit + "); leave it out"},
		{"a forward move, on a locked-http host", func(*upgradeHost) {}, []string{boxESCommit + ".." + upgradeTestCommit},
			"--allow-downgrade is only for a move that is not forward, and this one is forward"},
		{"no move, the payload's builds being installed", httpsHostRunning(upgradeTestCommit), []string{upgradeTestCommit + ".." + upgradeTestCommit},
			"--allow-downgrade is only for a move that is not forward, and this one is same (the installed ES binaries are builds of " + upgradeTestCommit + " already)"},
		{"installed binaries of two commits", func(h *upgradeHost) {
			h.toHTTPSWithoutKeyring(newerESCommit)
			h.write("usr/local/bin/es-runtime-support", string(stampedBinary("es-runtime-support", "go1.26.5", previousESCommit, "false")), 0o755)
		}, []string{newerESCommit + ".." + upgradeTestCommit},
			"--allow-downgrade names a move, but the installed ES binaries are not clean builds of one commit"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newUpgradeHost(t, helper)
			tc.setup(h)
			requireMoveRefused(t, h, tc.says, tc.allow...)
		})
	}
}

func TestRemoteAlphaUpgradeESRefusesAHistoryOnlyRootCannotVouchFor(t *testing.T) {
	// Refused whether or not --allow-downgrade names the move: the order
	// cannot be read at all.
	helper := buildESConfigCheck(t)
	cases := []struct {
		name  string
		setup func(h *upgradeHost) string
		says  string
	}{
		{"another account can change the clone's git objects", func(h *upgradeHost) string {
			h.toHTTPSWithoutKeyring(newerESCommit)
			_ = os.Chmod(filepath.Join(h.modules, ".git", "objects"), 0o777)
			return newerESCommit
		}, "the history of the installed and named commits is not in git objects that only uid %d can change: "},
		{"the installed build's parent is missing from the clone", func(h *upgradeHost) string {
			tree := fixtureGit(h.t, h.modules, "rev-parse", upgradeTestCommit+"^{tree}")
			object := filepath.Join(h.t.TempDir(), "commit")
			body := "tree " + tree + "\nparent " + strings.Repeat("cd", 20) +
				"\nauthor fixture <fixture@example.invalid> 1700000000 +0000\ncommitter fixture <fixture@example.invalid> 1700000000 +0000\n\na build whose parent the clone lacks\n"
			if err := os.WriteFile(object, []byte(body), 0o644); err != nil {
				h.t.Fatal(err)
			}
			broken := fixtureGit(h.t, h.modules, "hash-object", "-t", "commit", "-w", object)
			denyGroupOtherWrite(h.t, h.modules)
			h.toHTTPSWithoutKeyring(broken)
			return broken
		}, "git cannot read the history of %s and " + upgradeTestCommit + " in the clone %s: exit "}, // 1 on git 2.43, 128 on git 2.56
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newUpgradeHost(t, helper)
			installed := tc.setup(h)
			says := tc.says
			if strings.HasPrefix(says, "the history") {
				says = fmt.Sprintf(says, os.Getuid())
			} else {
				says = fmt.Sprintf(says, installed, h.modules)
			}
			report := requireMoveRefused(t, h, says)
			if _, ok := report["move"]; ok {
				t.Fatalf("check reported a move it could not read: %v", report["move"])
			}
			want := "Could not read " + strings.Repeat("cd", 20)
			if strings.HasPrefix(says, "the history") {
				want = filepath.Join(h.modules, ".git", "objects") + " is writable by its group or others (0777)"
			}
			if blockers := moveBlockers(report); !strings.Contains(blockers[0], want) {
				t.Fatalf("the move blocker %q does not say %q", blockers[0], want)
			}
			requireMoveRefused(t, h, says, installed+".."+upgradeTestCommit)
		})
	}
}

// TestRemoteAlphaUpgradeESTakesTheBoxBuildFromATestOnlyUnderATestRoot keeps
// BOX_ES_COMMIT the box's real first build, and the tests' stand-in for it
// (ES_UPGRADE_TEST_BOX_ES_COMMIT) out of reach on a host.
func TestRemoteAlphaUpgradeESTakesTheBoxBuildFromATestOnlyUnderATestRoot(t *testing.T) {
	code := `import importlib.util, json, sys
spec = importlib.util.spec_from_file_location("upgrade", sys.argv[1])
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
found = {"constant": m.BOX_ES_COMMIT}
for root in ("/", sys.argv[2]):
    m.HOST_ROOT = root
    found[root] = m.box_es_commit()
print(json.dumps(found))`
	testRoot := t.TempDir()
	cmd := exec.Command("python3", "-I", "-c", code, repoPath(upgradeESPython), testRoot)
	cmd.Dir = t.TempDir()
	cmd.Env = append(os.Environ(), "ES_UPGRADE_TEST_BOX_ES_COMMIT="+boxESCommit)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("box_es_commit: %v", err)
	}
	var found map[string]string
	if err := json.Unmarshal(out, &found); err != nil {
		t.Fatal(err)
	}
	if found["constant"] != realBoxESCommit || found["/"] != realBoxESCommit || found[testRoot] != boxESCommit {
		t.Fatalf("BOX_ES_COMMIT %s, on a host %s, under a test root %s", found["constant"], found["/"], found[testRoot])
	}
}

func TestRemoteAlphaUpgradeESLooksUpOnlyAFullCommitInTheHistory(t *testing.T) {
	helper := buildESConfigCheck(t)
	for _, named := range []string{"HEAD", upgradeTestCommit[:12], "--git-dir=" + upgradeTestCommit} {
		t.Run(named, func(t *testing.T) {
			h := newUpgradeHost(t, helper)
			h.commit = named
			report, stderr, code := moveCheck(h)
			if code != 1 || !strings.Contains(fmt.Sprint(report["blockers"]), "the commit must be a full lower-case 40-character SHA-1") {
				t.Fatalf("check exited %d: %s\nblockers %v", code, stderr, report["blockers"])
			}
			if blockers := moveBlockers(report); len(blockers) != 0 || report["move"] != nil {
				t.Fatalf("check read a move to %q: %v, blockers %q", named, report["move"], blockers)
			}
		})
	}
}
