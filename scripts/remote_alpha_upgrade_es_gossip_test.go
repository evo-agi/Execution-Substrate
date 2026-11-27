package scripts_test

import (
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"testing"
)

// Red-team RT60-1: Nomad's gossip had no key, so any local process could
// join it as a peer. Supported hosts get a keyring from the setup's
// nomad_gossip_issue (ES PR #66); the box gets the same keyring from this
// upgrade, which now leaves it in the shape "https-gossip".

const hostGossipKeyring = "opt/nomad/data/server/serf.keyring"

var issuedGossipKeyring = regexp.MustCompile(`^\["([A-Za-z0-9+/]{43}=)"\]$`)

// requireIssuedKeyring fails unless the host's gossip keyring is what the
// setup's nomad_gossip_issue writes: one base64 32-byte key in a JSON list,
// mode 0600, the test user's (root's on the box). It returns the key.
func requireIssuedKeyring(t *testing.T, h *upgradeHost) string {
	t.Helper()
	path := h.path(hostGossipKeyring)
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("no gossip keyring: %v", err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || int(info.Sys().(*syscall.Stat_t).Uid) != os.Getuid() {
		t.Fatalf("gossip keyring %s, uid %d", info.Mode(), info.Sys().(*syscall.Stat_t).Uid)
	}
	match := issuedGossipKeyring.FindStringSubmatch(mustRead(t, path))
	if match == nil {
		t.Fatal("the gossip keyring is not one base64 key in a JSON list")
	}
	if key, err := base64.StdEncoding.DecodeString(match[1]); err != nil || len(key) != 32 {
		t.Fatalf("the gossip key is not 32 bytes of base64: %v", err)
	}
	return match[1]
}

// noSecretsInOutputOrCalls fails when the gossip key or a Nomad token shows
// in what the upgrade printed, in the calls the fakes logged, or on any
// curl command line.
func noSecretsInOutputOrCalls(t *testing.T, h *upgradeHost, output string) {
	t.Helper()
	secrets := map[string]string{}
	if data, err := os.ReadFile(h.path(hostGossipKeyring)); err == nil {
		if match := issuedGossipKeyring.FindStringSubmatch(string(data)); match != nil {
			secrets["the gossip key"] = match[1]
		}
	}
	for _, name := range []string{"es-token", "observer-token", "management-token"} {
		if data, err := os.ReadFile(h.path("etc/execution-substrate/nomad-acl/" + name)); err == nil && len(strings.TrimSpace(string(data))) > 0 {
			secrets[name] = strings.TrimSpace(string(data))
		}
	}
	logs := output
	for _, name := range []string{"calls.log", "curl-argv.log"} {
		data, _ := os.ReadFile(filepath.Join(h.state, name))
		logs += string(data)
	}
	for name, secret := range secrets {
		if strings.Contains(logs, secret) {
			t.Fatalf("%s shows in the upgrade's output, a logged call or a curl command line", name)
		}
	}
}

// toHTTPSWithoutKeyring puts h where ES PR #60's upgrade left the box: Nomad
// on HTTPS with ES's pin, ES a clean build of previous, and no gossip
// keyring. It applies this upgrade, then takes the keyring and the payload's
// builds away again and restarts Nomad.
func (h *upgradeHost) toHTTPSWithoutKeyring(previous string) {
	h.t.Helper()
	if stdout, stderr, code := h.apply(); code != 0 {
		h.t.Fatalf("apply to HTTPS exited %d\nstdout %s\nstderr %s", code, stdout, stderr)
	}
	if err := os.Remove(h.path(hostGossipKeyring)); err != nil {
		h.t.Fatal(err)
	}
	h.installBuilds(previous)
	h.systemctl("stop", "nomad")
	h.systemctl("start", "nomad")
	if err := os.RemoveAll(h.path("var/backups/execution-substrate-es-upgrade")); err != nil {
		h.t.Fatal(err)
	}
	h.clearCalls()
}

// installBuilds puts clean builds of revision in place of the host's es and
// es-runtime-support.
func (h *upgradeHost) installBuilds(revision string) {
	h.t.Helper()
	h.write("usr/local/lib/execution-substrate/bin/es", string(stampedBinary("es", "go1.26.5", revision, "false")), 0o755)
	h.write("usr/local/bin/es-runtime-support", string(stampedBinary("es-runtime-support", "go1.26.5", revision, "false")), 0o755)
}

func TestRemoteAlphaUpgradeESAddsTheGossipKeyringToAnHTTPSHost(t *testing.T) {
	helper := buildESConfigCheck(t)
	h := newUpgradeHost(t, helper)
	h.toHTTPSWithoutKeyring(previousESCommit)
	start := h.snapshot()
	startESConfig := mustRead(t, h.path("etc/execution-substrate/es.json"))
	startHCL := mustRead(t, h.path("etc/nomad.d/nomad.hcl"))

	// check names every part and the three changes, and changes nothing.
	report, stderr, code := h.check()
	if code != 0 || report["shape"] != "https" || report["result"] != "ready" {
		t.Fatalf("check of an https host: exit %d, shape %v, result %v, blockers %v, %s", code, report["shape"], report["result"], report["blockers"], stderr)
	}
	parts := report["parts"].(map[string]any)
	for part, want := range map[string]string{
		"nomad.hcl": "https (", "Nomad's TLS directory": "https (", "es.json": "https (",
		"the ES binaries":        "other (clean builds of " + previousESCommit + ", which apply replaces)",
		"Nomad's gossip keyring": "absent",
	} {
		if state, _ := parts[part].(string); !strings.HasPrefix(state, want) {
			t.Errorf("part %s: %q, want %q", part, state, want)
		}
	}
	if got := fmt.Sprint(report["changes"]); got != "[write Nomad's gossip keyring to /opt/nomad/data/server/serf.keyring with the setup's nomad_gossip_issue "+
		"restart Nomad on HTTPS, which then encrypts its gossip, and check its ACLs and placement "+
		"install es and es-runtime-support built from "+upgradeTestCommit+"]" {
		t.Fatalf("changes %s", got)
	}
	if esConfig := report["es_config"].(map[string]any); fmt.Sprint(esConfig["changes"]) != "[]" || esConfig["new_es_accepts_migrated_config"] != true {
		t.Fatalf("es_config report: %v", esConfig)
	}
	if _, ok := report["nomad_gossip"]; ok {
		t.Fatalf("check asked a Nomad without a keyring about its gossip: %v", report["nomad_gossip"])
	}
	onlyReads(t, h, "check of an https host")
	assertRestored(t, start, h.snapshot())

	// apply writes the keyring, restarts Nomad, which then encrypts its
	// gossip, and installs the payload's builds; es.json and nomad.hcl stay.
	h.clearCalls()
	stdout, stderr, code := h.apply()
	if code != 0 {
		t.Fatalf("apply exited %d\nstdout %s\nstderr %s", code, stdout, stderr)
	}
	requireIssuedKeyring(t, h)
	if !h.marked("gossip") || !h.marked("tls") {
		t.Fatalf("after apply: gossip %v, tls %v", h.marked("gossip"), h.marked("tls"))
	}
	if mustRead(t, h.path("etc/execution-substrate/es.json")) != startESConfig || mustRead(t, h.path("etc/nomad.d/nomad.hcl")) != startHCL {
		t.Fatal("apply changed es.json or nomad.hcl of an https host")
	}
	if !strings.Contains(stdout, "es.json unchanged") {
		t.Fatalf("apply did not say es.json stays: %s", stdout)
	}
	if mustRead(t, h.path("usr/local/lib/execution-substrate/bin/es")) != string(newESBuild) ||
		mustRead(t, h.path("usr/local/bin/es-runtime-support")) != string(newRuntimeSupportBuild) {
		t.Fatal("the binaries are not the payload's")
	}
	noSecretsInOutputOrCalls(t, h, stdout+stderr)
	if got, want := strings.Join(h.calls("systemctl st"), " | "), "systemctl stop es | systemctl stop nomad | systemctl start nomad | systemctl start es"; got != want {
		t.Fatalf("service calls %q, want %q", got, want)
	}
	acl := " ES_USER=es OBSERVER_USER=root NOMAD_USER=root NOMAD_ADDR=https://127.0.0.1:4646 NOMAD_CACERT=/etc/nomad.d/tls/ca.pem"
	if got, want := strings.Join(h.calls("acl-setup"), " | "), "acl-setup check"+acl+" | acl-setup placement"+acl+" | acl-setup check"+acl; got != want {
		t.Fatalf("ACL setup calls %q\nwant %q", got, want)
	}
	if calls := h.calls("nomad config validate"); len(calls) != 0 {
		t.Fatalf("apply validated a nomad.hcl it does not change: %v", calls)
	}
	log := mustRead(t, filepath.Join(h.state, "calls.log"))
	at := 0
	for _, step := range []string{"systemctl stop es", "mv onto the gossip keyring", "systemctl stop nomad", "systemctl start nomad", "curl https://127.0.0.1:4646/v1/status/leader",
		"acl-setup check", "curl https://127.0.0.1:4646/v1/agent/self", "acl-setup placement", "systemctl start es",
		"tls-identity check https://127.0.0.1:4646", "acl-setup check", "curl https://127.0.0.1:4646/v1/agent/self"} {
		next := strings.Index(log[at:], step)
		if next < 0 {
			t.Fatalf("%q does not follow the steps before it in:\n%s", step, log)
		}
		at += next + len(step)
	}
	backupDir, summary := readSummary(t, h)
	if summary["result"] != "applied" || summary["shape"] != "https" {
		t.Fatalf("summary result %v, shape %v", summary["result"], summary["shape"])
	}
	if events := fmt.Sprint(summary["events"]); !strings.Contains(events, "Nomad's gossip keyring written to /opt/nomad/data/server/serf.keyring") ||
		!strings.Contains(events, `Nomad reports its gossip encrypted (stats.serf.encrypted "true")`) {
		t.Fatalf("apply's events %s", events)
	}
	if got := strings.Join(strings.Fields(mustRead(t, filepath.Join(backupDir, "created.json"))), ""); got != `["/opt/nomad/data/server/serf.keyring"]` {
		t.Fatalf("created.json %s", got)
	}
	after := h.snapshot()
	for path, entry := range start {
		switch path {
		case "usr/local/lib/execution-substrate/bin/es", "usr/local/bin/es-runtime-support":
			continue
		}
		if after[path] != entry {
			t.Errorf("%s changed: %q -> %q", path, entry, after[path])
		}
	}

	// The shape apply leaves: check and apply prove it in place.
	h.clearCalls()
	report, stderr, code = h.check()
	if code != 0 || report["shape"] != "https-gossip" || report["result"] != "nothing to do" || report["nomad_gossip"] != "stats.serf.encrypted 'true'" {
		t.Fatalf("check after apply: exit %d, shape %v, result %v, gossip %v, blockers %v, %s",
			code, report["shape"], report["result"], report["nomad_gossip"], report["blockers"], stderr)
	}
	if stdout, stderr, code := h.apply(); code != 0 || !strings.Contains(stdout, `"result": "nothing to do"`) {
		t.Fatalf("apply after apply: exit %d\nstdout %s\nstderr %s", code, stdout, stderr)
	}
	onlyReads(t, h, "a check and an apply of an https-gossip host")

	// rollback takes the keyring away again and restarts Nomad without it.
	h.clearCalls()
	if stdout, stderr, code := h.run("rollback", "--backup-dir", backupDir); code != 0 {
		t.Fatalf("rollback exited %d\nstdout %s\nstderr %s", code, stdout, stderr)
	}
	assertRestored(t, start, h.snapshot())
	if h.marked("gossip") || !h.marked("tls") || h.marked("inactive-nomad") || h.marked("inactive-es") {
		t.Fatalf("after the rollback: gossip %v, tls %v, nomad down %v, es down %v", h.marked("gossip"), h.marked("tls"), h.marked("inactive-nomad"), h.marked("inactive-es"))
	}
	if len(h.calls("curl https://127.0.0.1:4646/v1/status/leader")) == 0 {
		t.Fatalf("the rollback did not wait for Nomad's leader over HTTPS: %v", h.calls("curl"))
	}
}

// With the keyring in place, a later upgrade only replaces the builds: no
// Nomad restart, nothing created, the keyring kept.
func TestRemoteAlphaUpgradeESKeepsASoundGossipKeyring(t *testing.T) {
	helper := buildESConfigCheck(t)
	h := newUpgradeHost(t, helper)
	if stdout, stderr, code := h.apply(); code != 0 {
		t.Fatalf("apply exited %d\nstdout %s\nstderr %s", code, stdout, stderr)
	}
	key := requireIssuedKeyring(t, h)
	h.installBuilds(previousESCommit)
	if err := os.RemoveAll(h.path("var/backups/execution-substrate-es-upgrade")); err != nil {
		t.Fatal(err)
	}
	h.clearCalls()
	report, stderr, code := h.check()
	if code != 0 || report["shape"] != "https" || report["nomad_gossip"] != "stats.serf.encrypted 'true'" ||
		fmt.Sprint(report["changes"]) != "[install es and es-runtime-support built from "+upgradeTestCommit+"]" {
		t.Fatalf("check: exit %d, shape %v, gossip %v, changes %v, blockers %v, %s", code, report["shape"], report["nomad_gossip"], report["changes"], report["blockers"], stderr)
	}
	if parts := report["parts"].(map[string]any); !strings.HasPrefix(fmt.Sprint(parts["Nomad's gossip keyring"]), "sound (") {
		t.Fatalf("keyring part %v", parts["Nomad's gossip keyring"])
	}
	stdout, stderr, code := h.apply()
	if code != 0 {
		t.Fatalf("apply exited %d\nstdout %s\nstderr %s", code, stdout, stderr)
	}
	if got := requireIssuedKeyring(t, h); got != key {
		t.Fatal("apply replaced a sound keyring")
	}
	if got, want := strings.Join(h.calls("systemctl st"), " | "), "systemctl stop es | systemctl start es"; got != want {
		t.Fatalf("service calls %q, want %q", got, want)
	}
	if got := strings.Join(h.calls("acl-setup"), " | "); !strings.HasPrefix(got, "acl-setup check ") || strings.Contains(got, "|") {
		t.Fatalf("ACL setup calls %q", got)
	}
	backupDir, summary := readSummary(t, h)
	if summary["result"] != "applied" {
		t.Fatalf("summary result %v", summary["result"])
	}
	if got := strings.Join(strings.Fields(mustRead(t, filepath.Join(backupDir, "created.json"))), ""); got != `[]` {
		t.Fatalf("created.json %s", got)
	}
	noSecretsInOutputOrCalls(t, h, stdout+stderr)
}

// Only the keyring missing: apply writes it and restarts Nomad, and installs
// the builds that were already there.
func TestRemoteAlphaUpgradeESAddsOnlyTheMissingKeyring(t *testing.T) {
	helper := buildESConfigCheck(t)
	h := newUpgradeHost(t, helper)
	h.toHTTPSWithoutKeyring(upgradeTestCommit)
	h.installBuilds(upgradeTestCommit) // stampedBinary is the payload's build
	report, stderr, code := h.check()
	if code != 0 || report["shape"] != "https" || len(report["changes"].([]any)) != 2 {
		t.Fatalf("check: exit %d, shape %v, changes %v, blockers %v, %s", code, report["shape"], report["changes"], report["blockers"], stderr)
	}
	if stdout, stderr, code := h.apply(); code != 0 {
		t.Fatalf("apply exited %d\nstdout %s\nstderr %s", code, stdout, stderr)
	}
	requireIssuedKeyring(t, h)
	if report, _, code := h.check(); code != 0 || report["shape"] != "https-gossip" {
		t.Fatalf("check after apply: exit %d, shape %v", code, report["shape"])
	}
}

func TestRemoteAlphaUpgradeESRollsBackTheGossipKeyring(t *testing.T) {
	helper := buildESConfigCheck(t)
	for _, tc := range []struct{ name, marker, failure string }{
		{"Nomad does not read its gossip keyring", "gossip-ignored", "Nomad does not report its gossip encrypted: stats.serf.encrypted 'false'"},
		{"Nomad names no leader after its restart", "no-leader-once", "Nomad named no leader at https://127.0.0.1:4646"},
		{"Nomad cannot place ES's jobs after its restart", "placement-fails", "nomad_acl_setup.sh placement failed"},
		{"the ACL check fails after Nomad's restart", "acl-check-fails", "nomad_acl_setup.sh check failed"},
		{"ES does not start", "fail-start-es-once", "systemctl start es"},
		{"the issuer leaves the keyring readable by others", "issued-keyring-loose",
			"Nomad's new gossip keyring is present, but it fails the setup's nomad_gossip_keyring_ok"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newUpgradeHost(t, helper)
			h.toHTTPSWithoutKeyring(previousESCommit)
			before := h.snapshot()
			h.mark(tc.marker, "")
			stdout, stderr, code := h.apply()
			if code != 1 || !strings.Contains(stderr, "apply failed; result rolled_back;") {
				t.Fatalf("apply exited %d\nstdout %s\nstderr %s", code, stdout, stderr)
			}
			assertRestored(t, before, h.snapshot())
			if h.marked("gossip") || !h.marked("tls") || h.marked("inactive-es") || h.marked("inactive-nomad") {
				t.Fatalf("after the rollback: gossip %v, tls %v, es down %v, nomad down %v", h.marked("gossip"), h.marked("tls"), h.marked("inactive-es"), h.marked("inactive-nomad"))
			}
			_, summary := readSummary(t, h)
			if summary["result"] != "rolled_back" || !strings.Contains(fmt.Sprint(summary["failure"]), tc.failure) {
				t.Fatalf("summary result %v, failure %v", summary["result"], summary["failure"])
			}
			if removed := fmt.Sprint(summary["rollback"].(map[string]any)["removed"]); removed != "[/opt/nomad/data/server/serf.keyring]" {
				t.Fatalf("the rollback removed %s", removed)
			}
			noSecretsInOutputOrCalls(t, h, stdout+stderr)
		})
	}
}

// Audit 47, O47-2: apply's own rollback of an https host checks ES's es.json
// against the running Nomad too, and reports the host unhealthy when it
// does not hold.
func TestRemoteAlphaUpgradeESChecksTLSAfterRollingBackAnHTTPSHost(t *testing.T) {
	helper := buildESConfigCheck(t)
	h := newUpgradeHost(t, helper)
	h.toHTTPSWithoutKeyring(previousESCommit)
	before := h.snapshot()
	h.mark("identity-fails-after-first", "")
	stdout, stderr, code := h.apply()
	if code != 1 || !strings.Contains(stderr, "apply failed; result rolled_back_unhealthy;") {
		t.Fatalf("apply exited %d\nstdout %s\nstderr %s", code, stdout, stderr)
	}
	assertRestored(t, before, h.snapshot())
	// One look before the changes, one after them, one after the rollback.
	calls := h.calls("tls-identity")
	if len(calls) != 3 || calls[0] != "tls-identity check https://127.0.0.1:4646" || calls[1] != calls[0] || calls[2] != calls[0] {
		t.Fatalf("tls-identity calls %v", calls)
	}
	_, summary := readSummary(t, h)
	afterRollback, _ := summary["after_rollback"].(map[string]any)
	if summary["result"] != "rolled_back_unhealthy" || afterRollback == nil ||
		!strings.Contains(fmt.Sprint(afterRollback["problems"]), "ES's Nomad TLS settings do not hold against the running Nomad: nomad tls: Nomad's server key does not match nomad.server_spki_sha256") ||
		!strings.Contains(fmt.Sprint(afterRollback["nomad_tls_identity"]), "does not match nomad.server_spki_sha256") {
		t.Fatalf("summary result %v, after_rollback %v", summary["result"], summary["after_rollback"])
	}
	noSecretsInOutputOrCalls(t, h, stdout+stderr)
}

func TestRemoteAlphaUpgradeESRefusesAGossipKeyringItDidNotExpect(t *testing.T) {
	helper := buildESConfigCheck(t)
	writeKeyring := func(h *upgradeHost, text string, mode os.FileMode) { h.write(hostGossipKeyring, text, mode) }
	soundKeyring := `["` + base64.StdEncoding.EncodeToString(make([]byte, 32)) + `"]`
	cases := []struct {
		name   string
		https  bool
		break_ func(h *upgradeHost)
		says   string
	}{
		{"the keyring is readable by others", true, func(h *upgradeHost) { writeKeyring(h, soundKeyring, 0o644) },
			"Nomad's gossip keyring: present, but it fails the setup's nomad_gossip_keyring_ok"},
		{"the keyring holds a 16-byte key", true, func(h *upgradeHost) {
			writeKeyring(h, `["`+base64.StdEncoding.EncodeToString(make([]byte, 16))+`"]`, 0o600)
		}, "Nomad's gossip keyring: present, but it fails the setup's nomad_gossip_keyring_ok"},
		{"the keyring is a symbolic link", true, func(h *upgradeHost) {
			writeKeyring(h, soundKeyring, 0o600)
			_ = os.Rename(h.path(hostGossipKeyring), h.path("opt/nomad/data/server/elsewhere"))
			_ = os.Symlink("elsewhere", h.path(hostGossipKeyring))
		}, "Nomad's gossip keyring: present, but it fails the setup's nomad_gossip_keyring_ok"},
		{"the keyring is a dangling symbolic link", true, func(h *upgradeHost) { _ = os.Symlink("nowhere", h.path(hostGossipKeyring)) },
			"Nomad's gossip keyring: present, but it fails the setup's nomad_gossip_keyring_ok"},
		{"a dangling keyring link on a locked-http host", false, func(h *upgradeHost) { _ = os.Symlink("nowhere", h.path(hostGossipKeyring)) },
			"Nomad's gossip keyring: present, but it fails the setup's nomad_gossip_keyring_ok"},
		{"Nomad's server folder is a file", true, func(h *upgradeHost) {
			_ = os.RemoveAll(h.path("opt/nomad/data/server"))
			h.write("opt/nomad/data/server", "", 0o755)
		}, "Nomad's gossip keyring: /opt/nomad/data/server is not a root:root directory only root can write"},
		{"Nomad's server folder is group-writable", true, func(h *upgradeHost) { _ = os.Chmod(h.path("opt/nomad/data/server"), 0o775) },
			"Nomad's gossip keyring: /opt/nomad/data/server is not a root:root directory only root can write"},
		{"Nomad's server folder belongs to another group", true, func(h *upgradeHost) { giveAnotherGroup(h.t, h.path("opt/nomad/data/server")) },
			"Nomad's gossip keyring: /opt/nomad/data/server is not a root:root directory only root can write"},
		{"Nomad's server folder is missing", true, func(h *upgradeHost) { _ = os.RemoveAll(h.path("opt/nomad/data/server")) },
			"Nomad's gossip keyring: /opt/nomad/data/server is missing"},
		{"a sound keyring that Nomad has not read", true, func(h *upgradeHost) { writeKeyring(h, soundKeyring, 0o600) },
			"Nomad has a gossip keyring but does not report its gossip encrypted: stats.serf.encrypted 'false'"},
		{"Nomad answers its agent read with 500", true, func(h *upgradeHost) {
			writeKeyring(h, soundKeyring, 0o600)
			h.systemctl("stop", "nomad")
			h.systemctl("start", "nomad")
			h.mark("agent-self-fails", "")
		}, "Nomad has a gossip keyring but does not report its gossip encrypted: /v1/agent/self answered 500"},
		{"the observer token is not a secret ID", true, func(h *upgradeHost) {
			writeKeyring(h, soundKeyring, 0o600)
			h.write("etc/execution-substrate/nomad-acl/observer-token", "not-a-token\n", 0o400)
		}, "the observer token file does not hold a Nomad secret ID"},
		{"es and es-runtime-support are builds of different commits", true, func(h *upgradeHost) {
			h.write("usr/local/bin/es-runtime-support", string(stampedBinary("es-runtime-support", "go1.26.5", strings.Repeat("a", 40), "false")), 0o755)
		}, "the ES binaries: unknown (es built from " + previousESCommit + ", es-runtime-support built from " + strings.Repeat("a", 40) + ")"},
		{"the builds of an https host are the box's first", true, func(h *upgradeHost) { h.installBuilds(boxESCommit) },
			"it takes locked-http or https to https-gossip: nomad.hcl: https"},
		{"es is a build of a modified checkout", true, func(h *upgradeHost) {
			h.write("usr/local/lib/execution-substrate/bin/es", string(stampedBinary("es", "go1.26.5", previousESCommit, "true")), 0o755)
		}, "the ES binaries: unknown (es is a build of a modified checkout of " + previousESCommit + ")"},
		{"a keyring on a locked-http host", false, func(h *upgradeHost) { writeKeyring(h, soundKeyring, 0o600) },
			"Nomad's gossip keyring: sound ("},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newUpgradeHost(t, helper)
			if tc.https {
				h.toHTTPSWithoutKeyring(previousESCommit)
			}
			tc.break_(h)
			before := h.snapshot()
			h.clearCalls()
			report, stderr, code := h.check()
			if code != 1 || !strings.Contains(stderr, "blocker(s); nothing was changed") || !strings.Contains(fmt.Sprint(report["blockers"]), tc.says) {
				t.Fatalf("check: exit %d, blockers %v, want %q; %s", code, report["blockers"], tc.says, stderr)
			}
			if _, stderr, code := h.apply(); code != 1 || !strings.Contains(stderr, "nothing was changed") {
				t.Fatalf("apply: exit %d: %s", code, stderr)
			}
			onlyReads(t, h, "a refused check and apply")
			if dirs, err := filepath.Glob(h.path("var/backups/*")); err != nil || len(dirs) != 0 {
				t.Fatalf("the refused apply wrote %v (%v)", dirs, err)
			}
			assertRestored(t, before, h.snapshot())
		})
	}
}

// What apply does follows from what check found, so a host that changes in
// between is refused before the backup, with nothing changed: a keyring
// that appears, turns unsound or goes away on either start, and on a
// locked-http host a TLS directory that appears. The fake docker makes the
// change once the check has listed the allocations.
// es.json is read again after the backup; one that gained a key since the
// check is refused there by the key-path check of a locked-http host's
// es.json (START_ES_PATHS), and the backup is put back. Like nomad.hcl
// (audit 41, O41-2), es.json is not compared with what the check read
// before the backup.
func TestRemoteAlphaUpgradeESRollsBackWhenESConfigGainsAKeyAfterCheck(t *testing.T) {
	helper := buildESConfigCheck(t)
	h := newUpgradeHost(t, helper)
	before := h.snapshot()
	h.mark("after-check", "es-json-key")
	stdout, stderr, code := h.apply()
	if code != 1 || !strings.Contains(stderr, "apply failed; result rolled_back;") {
		t.Fatalf("apply exited %d\nstdout %s\nstderr %s", code, stdout, stderr)
	}
	if h.marked("after-check") || !h.marked("after-check-done") {
		t.Fatal("the check did not list the allocations")
	}
	_, summary := readSummary(t, h)
	if summary["result"] != "rolled_back" ||
		!strings.Contains(fmt.Sprint(summary["failure"]), "es.json's keys differ from the build this upgrade was written for: unexpected ['http.extra']") {
		t.Fatalf("summary result %v, failure %v", summary["result"], summary["failure"])
	}
	if h.marked("tls") || !h.marked("locked") {
		t.Fatalf("after the rollback: tls %v, locked %v", h.marked("tls"), h.marked("locked"))
	}
	// The host is as it was, but for the change itself, which the backup
	// holds and the rollback put back.
	const esConfig = "etc/execution-substrate/es.json"
	if !strings.Contains(mustRead(t, h.path(esConfig)), `"extra": 1`) {
		t.Fatal("the rollback did not put back the es.json the backup holds")
	}
	after := h.snapshot()
	delete(before, esConfig)
	delete(after, esConfig)
	assertRestored(t, before, after)
}

func TestRemoteAlphaUpgradeESRefusesAHostThatChangedAfterCheck(t *testing.T) {
	helper := buildESConfigCheck(t)
	soundKeyring := `["` + base64.StdEncoding.EncodeToString(make([]byte, 32)) + `"]`
	keyringChanged := "refused: Nomad's gossip keyring changed after check: "
	for _, tc := range []struct {
		name   string
		start  string
		change string
		says   string
	}{
		{"a keyring others can read appears on an https host", "https", "keyring-loose",
			keyringChanged + "present, but it fails the setup's nomad_gossip_keyring_ok; nothing was changed"},
		{"a sound keyring appears on an https host", "https", "keyring-sound", keyringChanged + "sound ("},
		{"the keyring goes away on an https host", "https-keyring", "keyring-taken", keyringChanged + "absent; nothing was changed"},
		{"a sound keyring appears on a locked-http host", "locked-http", "keyring-sound", keyringChanged + "sound ("},
		{"Nomad's TLS directory appears on a locked-http host", "locked-http", "tls-dir",
			"refused: /etc/nomad.d/tls exists already; nothing was changed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newUpgradeHost(t, helper)
			if tc.start != "locked-http" {
				h.toHTTPSWithoutKeyring(previousESCommit)
			}
			if tc.start == "https-keyring" {
				h.write(hostGossipKeyring, soundKeyring, 0o600)
				h.systemctl("stop", "nomad")
				h.systemctl("start", "nomad")
				h.clearCalls()
			}
			before := h.snapshot()
			h.mark("after-check", tc.change)
			stdout, stderr, code := h.apply()
			if code != 1 || !strings.Contains(stderr, tc.says) || !strings.Contains(stderr, "nothing was changed") {
				t.Fatalf("apply exited %d, want %q\nstdout %s\nstderr %s", code, tc.says, stdout, stderr)
			}
			if h.marked("after-check") || !h.marked("after-check-done") {
				t.Fatal("the check did not list the allocations")
			}
			onlyReads(t, h, "an apply refused for a host changed after check")
			if dirs, err := filepath.Glob(h.path("var/backups/*")); err != nil || len(dirs) != 0 {
				t.Fatalf("the refused apply wrote %v (%v)", dirs, err)
			}
			// Nothing but the change itself differs.
			after := h.snapshot()
			for _, snapshot := range []map[string]string{before, after} {
				delete(snapshot, hostGossipKeyring)
				delete(snapshot, "etc/nomad.d/tls")
			}
			assertRestored(t, before, after)
		})
	}
}
