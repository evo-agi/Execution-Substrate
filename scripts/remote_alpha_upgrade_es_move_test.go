package scripts_test

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"
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
// commit, with order, and authorized by --allow-downgrade exactly when who
// (who ran it: its sudo_user, uid and login_user) is not nil.
func requireMove(t *testing.T, report map[string]any, installed, order string, who map[string]any) {
	t.Helper()
	move, ok := report["move"].(map[string]any)
	if !ok {
		t.Fatalf("no move in the report: %v", report["move"])
	}
	want := map[string]any{"from": installed, "to": upgradeTestCommit, "order": order, "why": move["why"]}
	if who != nil {
		want["authorized"] = "--allow-downgrade " + installed + ".." + upgradeTestCommit
		for key, value := range who {
			want[key] = value
		}
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
	{"a commit beside the installed build, which refs/replace puts after it", func(h *upgradeHost) {
		h.toHTTPSWithoutKeyring(sideESCommit)
		// A replacement for the named commit whose parent is the installed
		// one: a git that honoured refs/replace would read the move as
		// forward.
		tree := fixtureGit(h.t, h.modules, "rev-parse", upgradeTestCommit+"^{tree}")
		replacement := fixtureGit(h.t, h.modules, "commit-tree", tree, "-p", sideESCommit, "-m", "the named commit, after the side one")
		fixtureGit(h.t, h.modules, "replace", upgradeTestCommit, replacement)
		denyGroupOtherWrite(h.t, h.modules)
	}, sideESCommit, "sideways",
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
			requireMove(t, report, tc.installed, tc.order, nil)
			if why := report["move"].(map[string]any)["why"]; why != tc.why {
				t.Fatalf("why %q, want %q", why, tc.why)
			}
			stdout, stderr, code := moveRun(h, "apply")
			if code != 0 {
				t.Fatalf("apply exited %d\nstdout %s\nstderr %s", code, stdout, stderr)
			}
			backupDir, summary := readSummary(t, h)
			requireMove(t, summary, tc.installed, tc.order, nil)
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
			requireMove(t, report, tc.installed, tc.order, nil)

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
			// sudo names the user who started the run, when sudo started it;
			// the audit login uid names the user who logged in, unless no
			// login started the run, as under systemd-run.
			who := map[string]any{"sudo_user": "operator", "uid": os.Getuid(), "login_user": nil}
			by := fmt.Sprintf("sudo user operator, uid %d, login user not set", os.Getuid())
			if i%2 == 0 {
				h.env["SUDO_USER"] = "operator"
			} else {
				h.env["SUDO_USER"] = ""
				h.mark("loginuid", "0\n")
				who["sudo_user"], who["login_user"] = nil, "root"
				by = fmt.Sprintf("sudo user not named, uid %d, login user root", os.Getuid())
			}
			allow := tc.installed + ".." + upgradeTestCommit
			before := h.snapshot()
			h.clearCalls()
			report, stderr, code := moveCheck(h, allow)
			if code != 0 || report["result"] != "ready" {
				t.Fatalf("check exited %d, result %v: %s\nblockers %v", code, report["result"], stderr, report["blockers"])
			}
			requireMove(t, report, tc.installed, tc.order, who)
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
			requireMove(t, summary, tc.installed, tc.order, who)
			// The record in the backup is written before anything changes.
			var record map[string]any
			if err := json.Unmarshal([]byte(mustRead(t, filepath.Join(backupDir, "move.json"))), &record); err != nil {
				t.Fatal(err)
			}
			if fmt.Sprint(record) != fmt.Sprint(summary["move"]) {
				t.Fatalf("move.json %v, the summary's move %v", record, summary["move"])
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
	notOnlyRoots := func(h *upgradeHost, _ string) string {
		return fmt.Sprintf("the history of the installed and named commits is not in git objects that only uid %d can change: ", os.Getuid())
	}
	cases := []struct {
		name  string
		setup func(h *upgradeHost) string
		says  func(h *upgradeHost, installed string) string
		// what the blocker says about the history
		detail func(h *upgradeHost) string
	}{
		{"another account can change the clone's git objects", func(h *upgradeHost) string {
			h.toHTTPSWithoutKeyring(newerESCommit)
			_ = os.Chmod(filepath.Join(h.modules, ".git", "objects"), 0o777)
			return newerESCommit
		}, notOnlyRoots, func(h *upgradeHost) string {
			return filepath.Join(h.modules, ".git", "objects") + " is writable by its group or others (0777)"
		}},
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
		}, func(h *upgradeHost, installed string) string {
			// git exits 1 on git 2.43, 128 on git 2.56
			return fmt.Sprintf("git cannot read the history of %s and %s in the clone %s: exit ", installed, upgradeTestCommit, h.modules)
		}, func(*upgradeHost) string { return "Could not read " + strings.Repeat("cd", 20) }},
		{"a ref named after the installed commit, about which git warns", func(h *upgradeHost) string {
			// git reads a full commit name as the object even then, and
			// answers "an ancestor", but says on standard error that
			// something in the clone is not as it should be.
			h.toHTTPSWithoutKeyring(previousESCommit)
			fixtureGit(h.t, h.modules, "update-ref", "refs/heads/"+previousESCommit, newerESCommit)
			denyGroupOtherWrite(h.t, h.modules)
			return previousESCommit
		}, func(h *upgradeHost, installed string) string {
			return fmt.Sprintf("git cannot read the history of %s and %s in the clone %s: exit 0, ", installed, upgradeTestCommit, h.modules)
		}, func(*upgradeHost) string { return "refname \\'" + previousESCommit + "\\' is ambiguous" }}, // as repr() quotes it
		{"a grafts file gives the named commit the installed one as its parent", func(h *upgradeHost) string {
			// With git's hint about grafts turned off, nothing on standard
			// error would show that the sideways move reads as forward.
			h.toHTTPSWithoutKeyring(sideESCommit)
			if err := os.MkdirAll(filepath.Join(h.modules, ".git", "info"), 0o755); err != nil {
				h.t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(h.modules, ".git", "info", "grafts"), []byte(upgradeTestCommit+" "+sideESCommit+"\n"), 0o644); err != nil {
				h.t.Fatal(err)
			}
			fixtureGit(h.t, h.modules, "config", "advice.graftFileDeprecated", "false")
			denyGroupOtherWrite(h.t, h.modules)
			return sideESCommit
		}, notOnlyRoots, func(h *upgradeHost) string {
			return filepath.Join(h.modules, ".git") + "/info/grafts exists, which gives commits other parents than their own"
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newUpgradeHost(t, helper)
			installed := tc.setup(h)
			says := tc.says(h, installed)
			report := requireMoveRefused(t, h, says)
			if _, ok := report["move"]; ok {
				t.Fatalf("check reported a move it could not read: %v", report["move"])
			}
			if blockers := moveBlockers(report); !strings.Contains(blockers[0], tc.detail(h)) {
				t.Fatalf("the move blocker %q does not say %q", blockers[0], tc.detail(h))
			}
			requireMoveRefused(t, h, says, installed+".."+upgradeTestCommit)
		})
	}
}

// TestRemoteAlphaUpgradeESTakesTestStandInsOnlyUnderATestRoot keeps
// BOX_ES_COMMIT the box's real first build and LOGINUID_FILE the kernel's,
// and the tests' stand-ins for them (ES_UPGRADE_TEST_BOX_ES_COMMIT,
// ES_UPGRADE_TEST_LOGINUID_FILE) out of reach on a host.
func TestRemoteAlphaUpgradeESTakesTestStandInsOnlyUnderATestRoot(t *testing.T) {
	code := `import importlib.util, json, sys
spec = importlib.util.spec_from_file_location("upgrade", sys.argv[1])
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
found = {"constant": [m.BOX_ES_COMMIT, m.LOGINUID_FILE]}
for root in ("/", sys.argv[2]):
    m.HOST_ROOT = root
    found[root] = [m.box_es_commit(), m.loginuid_file()]
print(json.dumps(found))`
	testRoot := t.TempDir()
	cmd := exec.Command("python3", "-I", "-c", code, repoPath(upgradeESPython), testRoot)
	cmd.Dir = t.TempDir()
	cmd.Env = append(os.Environ(), "ES_UPGRADE_TEST_BOX_ES_COMMIT="+boxESCommit, "ES_UPGRADE_TEST_LOGINUID_FILE=/dev/null")
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("box_es_commit and loginuid_file: %v", err)
	}
	var found map[string][]string
	if err := json.Unmarshal(out, &found); err != nil {
		t.Fatal(err)
	}
	host := []string{realBoxESCommit, "/proc/self/loginuid"}
	if fmt.Sprint(found["constant"]) != fmt.Sprint(host) || fmt.Sprint(found["/"]) != fmt.Sprint(host) ||
		fmt.Sprint(found[testRoot]) != fmt.Sprint([]string{boxESCommit, "/dev/null"}) {
		t.Fatalf("the constants %v, on a host %v, under a test root %v", found["constant"], found["/"], found[testRoot])
	}
}

// TestRemoteAlphaUpgradeESNamesWhoRanIt: the record of a move root named
// or of a rollback names the user SUDO_USER names, none when it is unset or
// empty; the real uid; and the user the audit login uid names, none when it
// is unset (as under systemd-run) or unreadable, and the uid itself when no
// user has it.
func TestRemoteAlphaUpgradeESNamesWhoRanIt(t *testing.T) {
	code := `import importlib.util, json, os, pwd, sys
spec = importlib.util.spec_from_file_location("upgrade", sys.argv[1])
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
m.HOST_ROOT = sys.argv[2]
loginuid = os.path.join(sys.argv[2], "loginuid")
os.environ["ES_UPGRADE_TEST_LOGINUID_FILE"] = loginuid
nobody = next(uid for uid in range(2000000000, 2000100000) if not any(p.pw_uid == uid for p in pwd.getpwall()))
found = {}
for name, sudo_user, content in (("sudo", "operator", "4294967295"), ("empty", "", "4294967295"),
                                 ("unset", None, "0"), ("missing", None, None), ("garbled", None, "x0"),
                                 ("negative", None, "-1"), ("nameless", None, str(nobody))):
    os.environ.pop("SUDO_USER", None)
    if sudo_user is not None:
        os.environ["SUDO_USER"] = sudo_user
    if os.path.exists(loginuid):
        os.remove(loginuid)
    if content is not None:
        with open(loginuid, "w") as handle:
            handle.write(content + "\n")
    found[name] = [m.who_ran(), m.describe_who(m.who_ran())]
found["nobody"] = str(nobody)
print(json.dumps(found))`
	cmd := exec.Command("python3", "-I", "-c", code, repoPath(upgradeESPython), t.TempDir())
	cmd.Dir = t.TempDir()
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("who_ran: %v", err)
	}
	var found map[string]any
	if err := json.Unmarshal(out, &found); err != nil {
		t.Fatal(err)
	}
	uid := os.Getuid()
	nobody := found["nobody"].(string)
	for name, want := range map[string]string{
		"sudo":     fmt.Sprintf("[map[login_user:<nil> sudo_user:operator uid:%d] sudo user operator, uid %d, login user not set]", uid, uid),
		"empty":    fmt.Sprintf("[map[login_user:<nil> sudo_user:<nil> uid:%d] sudo user not named, uid %d, login user not set]", uid, uid),
		"unset":    fmt.Sprintf("[map[login_user:root sudo_user:<nil> uid:%d] sudo user not named, uid %d, login user root]", uid, uid),
		"missing":  fmt.Sprintf("[map[login_user:<nil> sudo_user:<nil> uid:%d] sudo user not named, uid %d, login user not set]", uid, uid),
		"garbled":  fmt.Sprintf("[map[login_user:<nil> sudo_user:<nil> uid:%d] sudo user not named, uid %d, login user not set]", uid, uid),
		"negative": fmt.Sprintf("[map[login_user:<nil> sudo_user:<nil> uid:%d] sudo user not named, uid %d, login user not set]", uid, uid),
		"nameless": fmt.Sprintf("[map[login_user:%s sudo_user:<nil> uid:%d] sudo user not named, uid %d, login user %s]", nobody, uid, uid, nobody),
	} {
		if got := fmt.Sprint(found[name]); got != want {
			t.Errorf("%s: %s, want %s", name, got, want)
		}
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

func TestRemoteAlphaUpgradeESTakesAllowDowngradeOnlyByItsFullName(t *testing.T) {
	// argparse would otherwise take a prefix of an option for it, and the
	// record would not show what was typed.
	helper := buildESConfigCheck(t)
	h := newUpgradeHost(t, helper)
	before := h.snapshot()
	allow := boxESCommit + ".." + upgradeTestCommit
	for _, command := range []string{"check", "apply"} {
		for _, spelling := range []string{"--allow", "--allow-d", "--allow-downgrad"} {
			h.clearCalls()
			_, stderr, code := h.run(command, "--payload", h.payload, "--commit", h.commit, spelling, allow)
			if code != 2 || !strings.Contains(stderr, "unrecognized arguments: "+spelling+" "+allow) {
				t.Fatalf("%s %s exited %d: %s", command, spelling, code, stderr)
			}
			if calls := mustRead(t, filepath.Join(h.state, "calls.log")); calls != "" {
				t.Fatalf("%s %s ran %s", command, spelling, calls)
			}
			assertRestored(t, before, h.snapshot())
			if dirs := backupDirs(t, h); len(dirs) != 0 {
				t.Fatalf("%s %s wrote a backup: %v", command, spelling, dirs)
			}
		}
	}
	// The full name with "=" reaches the move check, which refuses it for a
	// forward move.
	h.clearCalls()
	stdout, stderr, code := h.run("check", "--payload", h.payload, "--commit", h.commit, "--allow-downgrade="+allow)
	var report map[string]any
	if err := json.Unmarshal([]byte(stdout), &report); err != nil || code != 1 {
		t.Fatalf("check with --allow-downgrade=: exit %d, %v: %s", code, err, stderr)
	}
	if blockers := moveBlockers(report); len(blockers) != 1 || !strings.HasPrefix(blockers[0], "--allow-downgrade is only for a move that is not forward") {
		t.Fatalf("move blockers %q", blockers)
	}
	onlyReads(t, h, "check with --allow-downgrade=")
}

// backupsAtStops is what the fake systemctl's backups-at-stop marker
// logged: for each stop, in order, the unit and the files under the backup
// root then.
func backupsAtStops(t *testing.T, h *upgradeHost) [][]string {
	t.Helper()
	var stops [][]string
	for _, line := range strings.Split(strings.TrimSpace(mustRead(t, filepath.Join(h.state, "backups-at-stop.log"))), "\n") {
		if strings.HasPrefix(line, "stop ") {
			stops = append(stops, []string{line})
		} else if len(stops) > 0 {
			stops[len(stops)-1] = append(stops[len(stops)-1], line)
		}
	}
	return stops
}

// requireListedAtStop fails unless, at the n-th stop of unit in stops
// (from 0), a file under backupDir whose name matches pattern
// (filepath.Match) was there.
func requireListedAtStop(t *testing.T, stops [][]string, n int, unit, backupDir, pattern string) {
	t.Helper()
	var listed []string
	found, seen := false, 0
	for _, stop := range stops {
		if stop[0] == "stop "+unit {
			if seen == n {
				listed, found = stop[1:], true
				break
			}
			seen++
		}
	}
	if !found {
		t.Fatalf("no stop %d of %s: %q", n, unit, stops)
	}
	for _, file := range listed {
		dir, name := filepath.Split(file)
		if ok, _ := filepath.Match(pattern, name); ok && dir == "./"+filepath.Base(backupDir)+"/" {
			return
		}
	}
	t.Fatalf("%s/%s was not there at stop %d of %s: %q", backupDir, pattern, n, unit, listed)
}

// TestRemoteAlphaUpgradeESRecordsTheMoveBeforeItChangesAnything: move.json
// is in the backup when apply first stops ES, its first change, whether
// apply then goes on or fails right there (audit 44, A44-2).
func TestRemoteAlphaUpgradeESRecordsTheMoveBeforeItChangesAnything(t *testing.T) {
	helper := buildESConfigCheck(t)
	moves := []struct {
		name  string
		setup func(h *upgradeHost)
		allow []string
	}{
		{"a forward move", func(*upgradeHost) {}, nil},
		{"a move that is not forward, which root named", httpsHostRunning(newerESCommit), []string{newerESCommit + ".." + upgradeTestCommit}},
	}
	for _, move := range moves {
		for _, stopFails := range []bool{false, true} {
			name := move.name + ", apply going on"
			if stopFails {
				name = move.name + ", the first stop of ES failing"
			}
			t.Run(name, func(t *testing.T) {
				h := newUpgradeHost(t, helper)
				move.setup(h)
				before := h.snapshot()
				h.mark("backups-at-stop", "")
				if stopFails {
					// Every stop of ES fails: apply's, and its rollback's.
					h.mark("fail-stop-es", "0")
				}
				stdout, stderr, code := moveRun(h, "apply", move.allow...)
				if stopFails != (code != 0) || stopFails && !strings.Contains(stderr, "result rollback_failed") {
					t.Fatalf("apply exited %d\nstdout %s\nstderr %s", code, stdout, stderr)
				}
				backupDir, summary := readSummary(t, h)
				var record map[string]any
				if err := json.Unmarshal([]byte(mustRead(t, filepath.Join(backupDir, "move.json"))), &record); err != nil {
					t.Fatal(err)
				}
				if record["to"] != upgradeTestCommit || fmt.Sprint(record) != fmt.Sprint(summary["move"]) {
					t.Fatalf("move.json %v, the summary's move %v", record, summary["move"])
				}
				if _, authorized := record["authorized"]; authorized != (move.allow != nil) {
					t.Fatalf("move.json %v, authorized %v", record, move.allow != nil)
				}
				stops := backupsAtStops(t, h)
				requireListedAtStop(t, stops, 0, "es", backupDir, "move.json")
				if stopFails {
					// Nothing past the stop changed.
					assertRestored(t, before, h.snapshot())
					// The rollback was recorded before its own stop of ES.
					requireListedAtStop(t, stops, 1, "es", backupDir, "rollback-*.json")
				}
			})
		}
	}
}

// secondPayload makes a payload of commit beside h's, root's by the test's
// rules: the fixture's commits share one tree, so go.mod and go.sum pin
// the same modules.
func secondPayload(t *testing.T, h *upgradeHost, commit string) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "payload")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	files := map[string][]byte{
		"es":                 stampedBinary("es", "go1.26.5", commit, "false"),
		"es-runtime-support": stampedBinary("es-runtime-support", "go1.26.5", commit, "false"),
		"esconfigcheck":      []byte(mustRead(t, filepath.Join(h.payload, "esconfigcheck"))),
	}
	sums := map[string]string{}
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o755); err != nil {
			t.Fatal(err)
		}
		sums[name] = sha256Hex(data)
	}
	writeJSONFile(t, filepath.Join(dir, "provenance.json"), map[string]any{
		"commit": commit, "go_version": "go1.26.5", "vcs_modified": false, "sha256": sums,
	})
	return dir
}

// backupFiles lists every file under h's backup root.
func backupFiles(t *testing.T, h *upgradeHost) []string {
	t.Helper()
	var files []string
	root := h.path("var/backups/execution-substrate-es-upgrade")
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		files = append(files, path)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return files
}

// requireRollbackRefused fails unless rollback refuses backupDir, saying
// says, before a service stops, with nothing changed and no record written.
func requireRollbackRefused(t *testing.T, h *upgradeHost, backupDir string, says ...string) {
	t.Helper()
	before, files := h.snapshot(), backupFiles(t, h)
	h.clearCalls()
	_, stderr, code := h.run("rollback", "--backup-dir", backupDir)
	if code != 1 || !strings.Contains(stderr, backupDir+" is not the backup of the apply that left the host as it is: ") ||
		!strings.Contains(stderr, "; put back the newest backup first; nothing was changed") {
		t.Fatalf("rollback exited %d: %s", code, stderr)
	}
	for _, s := range says {
		if !strings.Contains(stderr, s) {
			t.Fatalf("the refusal does not say %q: %s", s, stderr)
		}
	}
	onlyReads(t, h, "a refused rollback")
	assertRestored(t, before, h.snapshot())
	if after := backupFiles(t, h); fmt.Sprint(after) != fmt.Sprint(files) {
		t.Fatalf("a refused rollback changed the backups: %q -> %q", files, after)
	}
}

// requireRollback fails unless rollback puts backupDir back, having
// recorded it there before ES stopped: what each installed binary was
// (installed), the commits it moved ES from and to, and who ran it.
func requireRollback(t *testing.T, h *upgradeHost, backupDir string, installed [2]string, from, to [2]string) {
	t.Helper()
	h.mark("backups-at-stop", "")
	if err := os.Remove(filepath.Join(h.state, "backups-at-stop.log")); err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	h.env["SUDO_USER"] = "operator"
	records, _ := filepath.Glob(filepath.Join(backupDir, "rollback-*.json"))
	restored, _ := filepath.Glob(filepath.Join(backupDir, "restored-*.json"))
	stdout, stderr, code := h.run("rollback", "--backup-dir", backupDir)
	if code != 0 {
		t.Fatalf("rollback exited %d\nstdout %s\nstderr %s", code, stdout, stderr)
	}
	requireRestoredRecord(t, backupDir, restored, "rollback", stdout)
	requireListedAtStop(t, backupsAtStops(t, h), 0, "es", backupDir, "rollback-*.json")
	// The new record is the one name that was not there before: two
	// rollbacks in one second sort by their pids, not by when they ran.
	after, _ := filepath.Glob(filepath.Join(backupDir, "rollback-*.json"))
	var added []string
	for _, name := range after {
		if !slices.Contains(records, name) {
			added = append(added, name)
		}
	}
	if len(added) != 1 || len(after) != len(records)+1 {
		t.Fatalf("rollback records before %q, after %q", records, after)
	}
	path := added[0]
	if !regexp.MustCompile(`/rollback-\d{8}T\d{6}Z-\d+\.json$`).MatchString(path) || modeOf(t, path) != 0o600 {
		t.Fatalf("rollback record %s, mode %v", path, modeOf(t, path))
	}
	var record map[string]any
	if err := json.Unmarshal([]byte(mustRead(t, path)), &record); err != nil {
		t.Fatal(err)
	}
	at, _ := record["at"].(string)
	delete(record, "at")
	want := map[string]any{
		"by": "rollback", "sudo_user": "operator", "uid": os.Getuid(), "login_user": nil,
		"installed": map[string]any{"es": installed[0], "es-runtime-support": installed[1]},
		"from":      map[string]any{"es": from[0], "es-runtime-support": from[1]},
		"to":        map[string]any{"es": to[0], "es-runtime-support": to[1]},
	}
	if fmt.Sprint(record) != fmt.Sprint(want) || !strings.Contains(path, "rollback-"+at+"-") {
		t.Fatalf("rollback record %v (at %q), want %v", record, at, want)
	}
	pair := func(commits [2]string) string {
		return fmt.Sprintf("{'es': '%s', 'es-runtime-support': '%s'}", commits[0], commits[1])
	}
	said := fmt.Sprintf("rollback recorded in %s: ES from %s to %s (sudo user operator, uid %d, login user not set)",
		path, pair(from), pair(to), os.Getuid())
	if !strings.Contains(stdout, said) {
		t.Fatalf("rollback did not say %q:\n%s", said, stdout)
	}
}

// requireRestoredRecord fails unless backupDir holds one restored-*.json
// more than the names in before, written by by, and output says so.
func requireRestoredRecord(t *testing.T, backupDir string, before []string, by, output string) {
	t.Helper()
	after, _ := filepath.Glob(filepath.Join(backupDir, "restored-*.json"))
	var added []string
	for _, name := range after {
		if !slices.Contains(before, name) {
			added = append(added, name)
		}
	}
	if len(added) != 1 || len(after) != len(before)+1 {
		t.Fatalf("restored records before %q, after %q", before, after)
	}
	path := added[0]
	if !regexp.MustCompile(`/restored-\d{8}T\d{6}Z-\d+\.json$`).MatchString(path) || modeOf(t, path) != 0o600 {
		t.Fatalf("restored record %s, mode %v", path, modeOf(t, path))
	}
	var record map[string]any
	if err := json.Unmarshal([]byte(mustRead(t, path)), &record); err != nil {
		t.Fatal(err)
	}
	if at, _ := record["at"].(string); record["by"] != by || len(record) != 2 || !strings.Contains(path, "restored-"+at+"-") {
		t.Fatalf("restored record %v, want by %q and its time", record, by)
	}
	if !strings.Contains(output, "put back, recorded in "+path) {
		t.Fatalf("the rollback did not say it recorded %s:\n%s", path, output)
	}
}

// requireEarlierBackups fails unless backupDir's earlier.json names exactly
// the folders in want (by base name), sorted by name as apply writes them
// (two backups made in one second sort by their commits).
func requireEarlierBackups(t *testing.T, backupDir string, want ...string) {
	t.Helper()
	var names []string
	if err := json.Unmarshal([]byte(mustRead(t, filepath.Join(backupDir, "earlier.json"))), &names); err != nil {
		t.Fatal(err)
	}
	var bases []string
	for _, dir := range want {
		bases = append(bases, filepath.Base(dir))
	}
	slices.Sort(bases)
	if fmt.Sprint(names) != fmt.Sprint(bases) || modeOf(t, filepath.Join(backupDir, "earlier.json")) != 0o600 {
		t.Fatalf("%s/earlier.json names %q, want %q", backupDir, names, bases)
	}
}

// waitForTheNextSecond returns once the UTC second has moved on, so that
// two applies of one commit do not name the same backup folder.
func waitForTheNextSecond() {
	time.Sleep(time.Until(time.Now().Truncate(time.Second).Add(time.Second + 10*time.Millisecond)))
}

func TestRemoteAlphaUpgradeESRollsBackOnlyTheApplyThatLeftTheHost(t *testing.T) {
	helper := buildESConfigCheck(t)
	const (
		esPath      = "usr/local/lib/execution-substrate/bin/es"
		supportPath = "usr/local/bin/es-runtime-support"
		staged      = "the payload its apply installed"
		backed      = "the backup's copy"
	)
	box := [2]string{boxESCommit, boxESCommit}
	named := [2]string{upgradeTestCommit, upgradeTestCommit}
	newer := [2]string{newerESCommit, newerESCommit}
	// applied is a locked-http host after a clean apply, the snapshot from
	// before it, and its backup.
	applied := func(t *testing.T) (*upgradeHost, map[string]string, string) {
		h := newUpgradeHost(t, helper)
		before := h.snapshot()
		if stdout, stderr, code := h.apply(); code != 0 {
			t.Fatalf("apply exited %d\nstdout %s\nstderr %s", code, stdout, stderr)
		}
		backupDir, _ := readSummary(t, h)
		return h, before, backupDir
	}

	t.Run("an older backup after a later apply, in and out of order", func(t *testing.T) {
		h, before, first := applied(t)
		afterFirst := h.snapshot()
		h.payload, h.commit = secondPayload(t, h, newerESCommit), newerESCommit
		if stdout, stderr, code := h.apply(); code != 0 {
			t.Fatalf("the later apply exited %d\nstdout %s\nstderr %s", code, stdout, stderr)
		}
		var second string
		for _, dir := range backupDirs(t, h) {
			if dir != first {
				second = dir
			}
		}
		if second == "" || len(backupDirs(t, h)) != 2 {
			t.Fatalf("backups %v", backupDirs(t, h))
		}
		created, moved := mustRead(t, filepath.Join(first, "created.json")), mustRead(t, filepath.Join(first, "move.json"))
		says := []string{"/usr/local/lib/execution-substrate/bin/es (a build of " + newerESCommit + ") is neither the backup's copy nor the payload its apply installed; " +
			"/usr/local/bin/es-runtime-support (a build of " + newerESCommit + ") is neither the backup's copy nor the payload its apply installed"}
		requireRollbackRefused(t, h, first, says...)
		// The same for a backup that ES PR #60's apply left: no move.json,
		// and created.json naming only Nomad's TLS directory.
		if err := os.Remove(filepath.Join(first, "move.json")); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(first, "created.json"), []byte("[\n  \"/etc/nomad.d/tls\"\n]\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		requireRollbackRefused(t, h, first, says...)
		for name, data := range map[string]string{"created.json": created, "move.json": moved} {
			if err := os.WriteFile(filepath.Join(first, name), []byte(data), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		// In order, newest first, both run.
		requireRollback(t, h, second, [2]string{staged, staged}, newer, named)
		assertRestored(t, afterFirst, h.snapshot())
		requireRollback(t, h, first, [2]string{staged, staged}, named, box)
		assertRestored(t, before, h.snapshot())
	})

	// Audit 47, A47-1: builds are reproducible, so after B1 and B2 were put
	// back, a new apply B3 of B2's commit installs bytes equal to B2's
	// staged payload. B2 is still refused while B3 is in effect, whatever
	// the folders' names say: putting it back would leave B2's es.json
	// pinning a key that B3's new TLS material replaced.
	t.Run("an older backup whose payload a later apply installed again", func(t *testing.T) {
		h, before, first := applied(t)
		afterFirst := h.snapshot()
		requireEarlierBackups(t, first)
		h.payload, h.commit = secondPayload(t, h, newerESCommit), newerESCommit
		if stdout, stderr, code := h.apply(); code != 0 {
			t.Fatalf("the later apply exited %d\nstdout %s\nstderr %s", code, stdout, stderr)
		}
		later := func(known ...string) string {
			t.Helper()
			for _, dir := range backupDirs(t, h) {
				if !slices.Contains(known, dir) {
					return dir
				}
			}
			t.Fatalf("no new backup among %v", backupDirs(t, h))
			return ""
		}
		second := later(first)
		requireEarlierBackups(t, second, first)
		requireRollback(t, h, second, [2]string{staged, staged}, newer, named)
		assertRestored(t, afterFirst, h.snapshot())
		requireRollback(t, h, first, [2]string{staged, staged}, named, box)
		assertRestored(t, before, h.snapshot())
		waitForTheNextSecond()
		if stdout, stderr, code := h.apply(); code != 0 {
			t.Fatalf("the apply of the same commit again exited %d\nstdout %s\nstderr %s", code, stdout, stderr)
		}
		third := later(first, second)
		requireEarlierBackups(t, third, first, second)
		requireRollbackRefused(t, h, second, third+" was made after it, and that apply has not been put back (no restored-<UTC>-<pid>.json in it)")
		// The same backup named with a trailing slash.
		requireRollbackRefused(t, h, second+"/", third+" was made after it, and that apply has not been put back")
		// Only a regular file counts as the record that a backup is put back.
		elsewhere := filepath.Join(t.TempDir(), "restored.json")
		if err := os.WriteFile(elsewhere, []byte("{}\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		notARecord := filepath.Join(third, "restored-20991231T235959Z-1.json")
		if err := os.Symlink(elsewhere, notARecord); err != nil {
			t.Fatal(err)
		}
		requireRollbackRefused(t, h, second, third+" was made after it, and that apply has not been put back")
		if err := os.Remove(notARecord); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(notARecord, 0o700); err != nil {
			t.Fatal(err)
		}
		requireRollbackRefused(t, h, second, third+" was made after it, and that apply has not been put back")
		if err := os.Remove(notARecord); err != nil {
			t.Fatal(err)
		}
		// The order is the one apply recorded, not the folders' names.
		renamed := filepath.Join(filepath.Dir(third), "19991231T235959Z-"+newerESCommit[:12])
		if err := os.Rename(third, renamed); err != nil {
			t.Fatal(err)
		}
		requireRollbackRefused(t, h, second, renamed+" was made after it, and that apply has not been put back")
		if err := os.Rename(renamed, third); err != nil {
			t.Fatal(err)
		}
		// Newest first: B3, then (B2 is now refused by its bytes: the host is
		// where B1's backup left it, not B2's) B1 again.
		requireRollback(t, h, third, [2]string{staged, staged}, newer, box)
		assertRestored(t, before, h.snapshot())
		requireRollbackRefused(t, h, second, "/usr/local/lib/execution-substrate/bin/es (a build of "+boxESCommit+") is neither")
		h.clearCalls()
		requireRollback(t, h, first, [2]string{backed, backed}, box, box)
		assertRestored(t, before, h.snapshot())
		if calls := h.calls("tls-identity"); len(calls) != 0 {
			t.Fatalf("the rollback to a locked-http host checked ES's Nomad TLS settings: %v", calls)
		}
	})

	t.Run("a backup outside the backup folder", func(t *testing.T) {
		h, _, backupDir := applied(t)
		copied := filepath.Join(t.TempDir(), filepath.Base(backupDir))
		cp := exec.Command("cp", "-a", backupDir, copied)
		cp.Dir = t.TempDir()
		if out, err := cp.CombinedOutput(); err != nil {
			t.Fatalf("cp: %v %s", err, out)
		}
		requireRollbackRefused(t, h, copied, "host as it is: it is not a folder of /var/backups/execution-substrate-es-upgrade, so the backups made after it cannot be told")
	})

	t.Run("a later backup whose earlier.json cannot be read", func(t *testing.T) {
		h, _, backupDir := applied(t)
		other := filepath.Join(filepath.Dir(backupDir), "20991231T235959Z-"+newerESCommit[:12])
		if err := os.Mkdir(other, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(other, "earlier.json"), []byte("{}\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		requireRollbackRefused(t, h, backupDir, other+"/earlier.json cannot be read (not a list of names)")
		if err := os.WriteFile(filepath.Join(other, "earlier.json"), []byte("[7]\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		requireRollbackRefused(t, h, backupDir, other+"/earlier.json cannot be read (not a list of names)")
		if err := os.WriteFile(filepath.Join(other, "earlier.json"), []byte("[\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		requireRollbackRefused(t, h, backupDir, other+"/earlier.json cannot be read (")
		if err := os.Remove(filepath.Join(other, "earlier.json")); err != nil {
			t.Fatal(err)
		}
		// A folder without earlier.json is not one this version made after it.
		requireRollback(t, h, backupDir, [2]string{staged, staged}, named, box)
	})

	// The record that the backup is put back cannot be written: the
	// rollback goes on and says so, and an earlier backup stays refused
	// until this one is put back again.
	t.Run("a rollback whose restored record cannot be written", func(t *testing.T) {
		h, before, first := applied(t)
		afterFirst := h.snapshot()
		h.payload, h.commit = secondPayload(t, h, newerESCommit), newerESCommit
		if stdout, stderr, code := h.apply(); code != 0 {
			t.Fatalf("the later apply exited %d\nstdout %s\nstderr %s", code, stdout, stderr)
		}
		var second string
		for _, dir := range backupDirs(t, h) {
			if dir != first {
				second = dir
			}
		}
		stdout, stderr, code := runWithPatchedUpgrade(h, `m.RESTORED_RECORD = "no-such-folder/" + m.RESTORED_RECORD`, "rollback", "--backup-dir", second)
		if code != 0 || !strings.Contains(stdout, "that the backup is put back could not be recorded (") ||
			!strings.Contains(stdout, "a rollback of an earlier backup is refused until this one is put back again") {
			t.Fatalf("rollback exited %d\nstdout %s\nstderr %s", code, stdout, stderr)
		}
		assertRestored(t, afterFirst, h.snapshot())
		requireRollbackRefused(t, h, first, second+" was made after it, and that apply has not been put back")
		requireRollback(t, h, second, [2]string{backed, backed}, named, named)
		requireRollback(t, h, first, [2]string{staged, staged}, named, box)
		assertRestored(t, before, h.snapshot())
	})

	// Audit 47, O47-2: after the restore of an https host, ES's es.json must
	// hold against the running Nomad, as after apply.
	t.Run("an https restore whose es.json does not hold against Nomad", func(t *testing.T) {
		h, _, first := applied(t)
		afterFirst := h.snapshot()
		h.payload, h.commit = secondPayload(t, h, newerESCommit), newerESCommit
		if stdout, stderr, code := h.apply(); code != 0 {
			t.Fatalf("the later apply exited %d\nstdout %s\nstderr %s", code, stdout, stderr)
		}
		var second string
		for _, dir := range backupDirs(t, h) {
			if dir != first {
				second = dir
			}
		}
		h.mark("identity-fails", "")
		h.clearCalls()
		stdout, stderr, code := h.run("rollback", "--backup-dir", second)
		if code != 1 || !strings.Contains(stderr, "after the rollback: ES's Nomad TLS settings do not hold against the running Nomad: nomad tls: Nomad's server key does not match nomad.server_spki_sha256") {
			t.Fatalf("rollback exited %d\nstdout %s\nstderr %s", code, stdout, stderr)
		}
		if calls := h.calls("tls-identity"); len(calls) != 1 || calls[0] != "tls-identity check https://127.0.0.1:4646" {
			t.Fatalf("tls-identity calls %v", calls)
		}
		// The files are back all the same.
		assertRestored(t, afterFirst, h.snapshot())
	})

	// A restore cut off after the files are back but before what apply
	// created is gone is not recorded as put back, so the backups before it
	// stay refused until it is put back again.
	t.Run("a restore cut off before it removed what apply created", func(t *testing.T) {
		h, before, backupDir := applied(t)
		tlsDir := h.path("etc/nomad.d/tls")
		if err := os.Chmod(tlsDir, 0o500); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(tlsDir, 0o700) })
		stdout, stderr, code := h.run("rollback", "--backup-dir", backupDir)
		if code != 1 || !strings.Contains(stdout, "es and nomad stopped for the restore") || strings.Contains(stdout, "files restored from") ||
			!strings.Contains(stderr, "PermissionError") {
			t.Fatalf("a rollback that could not remove %s exited %d\nstdout %s\nstderr %s", tlsDir, code, stdout, stderr)
		}
		if records, _ := filepath.Glob(filepath.Join(backupDir, "restored-*.json")); len(records) != 0 {
			t.Fatalf("a restore cut off partway is recorded as put back: %v", records)
		}
		if err := os.Chmod(tlsDir, 0o700); err != nil {
			t.Fatal(err)
		}
		stdout, stderr, code = h.run("rollback", "--backup-dir", backupDir)
		if code != 0 {
			t.Fatalf("the rollback again exited %d\nstdout %s\nstderr %s", code, stdout, stderr)
		}
		requireRestoredRecord(t, backupDir, nil, "rollback", stdout)
		assertRestored(t, before, h.snapshot())
	})

	// ES and AGS that do not answer after the rollback fail it, as before
	// the TLS check joined that step.
	t.Run("a rollback after which ES does not answer", func(t *testing.T) {
		h, before, backupDir := applied(t)
		h.mark("unhealthy", "")
		stdout, stderr, code := h.run("rollback", "--backup-dir", backupDir)
		if code != 1 || !strings.Contains(stderr, "after the rollback: ES and AGS do not all answer 200") {
			t.Fatalf("rollback exited %d\nstdout %s\nstderr %s", code, stdout, stderr)
		}
		assertRestored(t, before, h.snapshot())
	})

	// Audit 47, O47-4 (AUD-1): an installed binary that is missing is
	// neither copy.
	t.Run("an installed binary missing", func(t *testing.T) {
		h, _, backupDir := applied(t)
		if err := os.Remove(h.path(esPath)); err != nil {
			t.Fatal(err)
		}
		requireRollbackRefused(t, h, backupDir, "host as it is: /usr/local/lib/execution-substrate/bin/es cannot be read (")
	})

	// Audit 47, O47-4 (AUD-2): a rollback record never replaces a file of
	// the same name.
	t.Run("a rollback record's name taken", func(t *testing.T) {
		h, _, backupDir := applied(t)
		taken := filepath.Join(backupDir, "rollback-taken.json")
		if err := os.WriteFile(taken, []byte("kept\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		afterApply := h.snapshot()
		h.clearCalls()
		_, stderr, code := runWithPatchedUpgrade(h, `m.ROLLBACK_RECORD = "rollback-taken.json"`, "rollback", "--backup-dir", backupDir)
		if code != 1 || !strings.Contains(stderr, "the rollback cannot be recorded in "+backupDir+" (") {
			t.Fatalf("rollback exited %d: %s", code, stderr)
		}
		onlyReads(t, h, "a rollback whose record's name is taken")
		assertRestored(t, afterApply, h.snapshot())
		if got := mustRead(t, taken); got != "kept\n" {
			t.Fatalf("the rollback record replaced a file: %q", got)
		}
	})

	t.Run("builds put in place without the upgrade", func(t *testing.T) {
		h, _, backupDir := applied(t)
		h.installBuilds(newerESCommit)
		requireRollbackRefused(t, h, backupDir, "/usr/local/lib/execution-substrate/bin/es (a build of "+newerESCommit+") is neither")
	})

	t.Run("only es-runtime-support another build", func(t *testing.T) {
		h, _, backupDir := applied(t)
		h.write(supportPath, string(stampedBinary("es-runtime-support", "go1.26.5", newerESCommit, "false")), 0o755)
		requireRollbackRefused(t, h, backupDir, "host as it is: /usr/local/bin/es-runtime-support (a build of "+newerESCommit+") is neither")
	})

	t.Run("a build of a modified checkout", func(t *testing.T) {
		h, _, backupDir := applied(t)
		h.write(esPath, string(stampedBinary("es", "go1.26.5", upgradeTestCommit, "true")), 0o755)
		requireRollbackRefused(t, h, backupDir, "host as it is: /usr/local/lib/execution-substrate/bin/es (a build of no one clean commit) is neither")
	})

	// Byte for byte, not by commit: another build of the payload's commit,
	// or of the backup's, was put in place without the upgrade.
	t.Run("another build of the payload's commit", func(t *testing.T) {
		h, _, backupDir := applied(t)
		h.write(esPath, string(stampedBinary("es", "go1.26.4", upgradeTestCommit, "false")), 0o755)
		requireRollbackRefused(t, h, backupDir, "host as it is: /usr/local/lib/execution-substrate/bin/es (a build of "+upgradeTestCommit+") is neither")
	})

	t.Run("another build of the backup's commit", func(t *testing.T) {
		h, _, backupDir := applied(t)
		h.installBuilds(boxESCommit)
		h.write(supportPath, string(stampedBinary("es-runtime-support", "go1.26.4", boxESCommit, "false")), 0o755)
		requireRollbackRefused(t, h, backupDir, "host as it is: /usr/local/bin/es-runtime-support (a build of "+boxESCommit+") is neither")
	})

	t.Run("the payload's copy gone from the backup", func(t *testing.T) {
		h, _, backupDir := applied(t)
		if err := os.RemoveAll(filepath.Join(backupDir, "payload")); err != nil {
			t.Fatal(err)
		}
		requireRollbackRefused(t, h, backupDir, "/usr/local/lib/execution-substrate/bin/es (a build of "+upgradeTestCommit+") is neither")
	})

	t.Run("an apply cut off between the two binaries", func(t *testing.T) {
		h, before, backupDir := applied(t)
		h.write(supportPath, string(boxRuntimeSupportBuild), 0o755)
		requireRollback(t, h, backupDir, [2]string{staged, backed}, [2]string{upgradeTestCommit, boxESCommit}, box)
		assertRestored(t, before, h.snapshot())
	})

	t.Run("an apply cut off before it installed either", func(t *testing.T) {
		h, before, backupDir := applied(t)
		h.installBuilds(boxESCommit)
		requireRollback(t, h, backupDir, [2]string{backed, backed}, box, box)
		assertRestored(t, before, h.snapshot())
	})

	t.Run("a backup put back already", func(t *testing.T) {
		h, before, backupDir := applied(t)
		requireRollback(t, h, backupDir, [2]string{staged, staged}, named, box)
		requireRollback(t, h, backupDir, [2]string{backed, backed}, box, box)
		assertRestored(t, before, h.snapshot())
	})

	t.Run("apply putting back its own backup", func(t *testing.T) {
		h := newUpgradeHost(t, helper)
		h.mark("backups-at-stop", "")
		h.mark("acl-check-fails", "")
		stdout, stderr, code := h.apply()
		if code != 1 || !strings.Contains(stderr, "result rolled_back;") {
			t.Fatalf("apply exited %d\nstdout %s\nstderr %s", code, stdout, stderr)
		}
		backupDir, summary := readSummary(t, h)
		requireListedAtStop(t, backupsAtStops(t, h), 1, "es", backupDir, "rollback-*.json")
		records, _ := filepath.Glob(filepath.Join(backupDir, "rollback-*.json"))
		if len(records) != 1 {
			t.Fatalf("rollback records %q", records)
		}
		var record map[string]any
		if err := json.Unmarshal([]byte(mustRead(t, records[0])), &record); err != nil {
			t.Fatal(err)
		}
		// The ACL check fails after ES is installed and started.
		if record["by"] != "apply" || fmt.Sprint(record["installed"]) != "map[es:"+staged+" es-runtime-support:"+staged+"]" ||
			fmt.Sprint(record["from"]) != fmt.Sprint(map[string]any{"es": upgradeTestCommit, "es-runtime-support": upgradeTestCommit}) ||
			fmt.Sprint(record["to"]) != fmt.Sprint(map[string]any{"es": boxESCommit, "es-runtime-support": boxESCommit}) {
			t.Fatalf("apply's rollback record %v", record)
		}
		if !strings.Contains(fmt.Sprint(summary["events"]), "rollback recorded in "+records[0]) {
			t.Fatalf("apply did not log its rollback record: %v", summary["events"])
		}
		requireRestoredRecord(t, backupDir, nil, "apply", fmt.Sprint(summary["events"]))
	})

	// A record that cannot be written stops the rollback command before a
	// service stops, but not apply putting back its own backup: a failed
	// apply must still be undone.
	t.Run("a rollback that cannot be recorded", func(t *testing.T) {
		h, before, backupDir := applied(t)
		afterApply, files := h.snapshot(), backupFiles(t, h)
		h.clearCalls()
		_, stderr, code := runWithUnwritableRollbackRecords(h, "rollback", "--backup-dir", backupDir)
		if code != 1 || !strings.Contains(stderr, "the rollback cannot be recorded in "+backupDir+" (") ||
			!strings.Contains(stderr, "; nothing was changed") {
			t.Fatalf("rollback exited %d: %s", code, stderr)
		}
		onlyReads(t, h, "a rollback that cannot be recorded")
		assertRestored(t, afterApply, h.snapshot())
		if after := backupFiles(t, h); fmt.Sprint(after) != fmt.Sprint(files) {
			t.Fatalf("a refused rollback changed the backups: %q -> %q", files, after)
		}
		requireRollback(t, h, backupDir, [2]string{staged, staged}, named, box)
		assertRestored(t, before, h.snapshot())
	})

	t.Run("apply putting back its own backup that it cannot record", func(t *testing.T) {
		h := newUpgradeHost(t, helper)
		before := h.snapshot()
		h.mark("acl-check-fails", "")
		stdout, stderr, code := runWithUnwritableRollbackRecords(h, "apply", "--payload", h.payload, "--commit", h.commit)
		if code != 1 || !strings.Contains(stderr, "result rolled_back;") {
			t.Fatalf("apply exited %d\nstdout %s\nstderr %s", code, stdout, stderr)
		}
		backupDir, summary := readSummary(t, h)
		if records, _ := filepath.Glob(filepath.Join(backupDir, "rollback-*.json")); len(records) != 0 {
			t.Fatalf("rollback records %q", records)
		}
		if !strings.Contains(fmt.Sprint(summary["events"]), "the rollback could not be recorded (FileNotFoundError(") ||
			!strings.Contains(fmt.Sprint(summary["events"]), "; putting the backup back all the same") {
			t.Fatalf("apply did not log the record it could not write: %v", summary["events"])
		}
		assertRestored(t, before, h.snapshot())
	})
}

// runWithUnwritableRollbackRecords runs the upgrade on h as h.run does,
// with each rollback's record named inside a folder that does not exist,
// so that writing it fails.
func runWithUnwritableRollbackRecords(h *upgradeHost, args ...string) (string, string, int) {
	h.t.Helper()
	return runWithPatchedUpgrade(h, `m.ROLLBACK_RECORD = "no-such-folder/" + m.ROLLBACK_RECORD`, args...)
}

// runWithPatchedUpgrade runs the upgrade on h as h.run does, after the
// Python statement patch, which may change the module m.
func runWithPatchedUpgrade(h *upgradeHost, patch string, args ...string) (string, string, int) {
	h.t.Helper()
	code := `import importlib.util, sys
spec = importlib.util.spec_from_file_location("upgrade", sys.argv[1])
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
` + patch + `
sys.exit(m.main(sys.argv[2:]))`
	cmd := exec.Command("python3", append([]string{"-I", "-c", code, repoPath(upgradeESPython), "--host-root", h.root}, args...)...)
	cmd.Dir = h.state
	cmd.Env = h.environ()
	var stdout, stderr strings.Builder
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	exitCode := 0
	if err != nil {
		exitErr, ok := err.(*exec.ExitError)
		if !ok {
			h.t.Fatalf("run %v: %v", args, err)
		}
		exitCode = exitErr.ExitCode()
	}
	return stdout.String(), stderr.String(), exitCode
}
