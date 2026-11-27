package scripts_test

// Regression tests for the boundary between root and the SPIRE data check
// in the SPIRE agent helper (re-checks 25 and 26 of the bundle refresh):
// nothing that SPIRE produces is parsed as a certificate in root's process.
// The SPIRE data check, the helper's own code run as the SPIRE account,
// fetches the server bundle and parses it, the bundle file and the agent's
// SVID; root checks its JSON reply field by field and writes the bundle's
// PEM text as opaque bytes. The helper runs against the fake systemctl,
// setpriv, spire-server and spire-agent of the guard tests, with a fake
// python_argv that logs each run of the SPIRE data check and either runs
// the real one or prints a canned reply.

import (
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// The fake python_argv. It reads what root sends (the helper's source,
// then the JSON request), logs the op, and prints view-reply-<op> with the
// exit code in view-reply-<op>.rc when that file exists. Otherwise it runs
// the real Python with the same arguments and input.
const spireAgentDataCheckFakeView = `import json, os, subprocess, sys, time
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
data = sys.stdin.buffer.read()
header, _, rest = data.partition(b"\n")
request = json.loads(rest[int(header):])
op = request["op"]
with open(os.path.join(ROOT, "view.log"), "a") as log:
    log.write(json.dumps({"op": op, "args": sys.argv[1:2]}) + "\n")
canned = os.path.join(ROOT, "view-reply-" + op)
if os.path.exists(canned + ".sleep"):
    time.sleep(60)
if os.path.exists(canned):
    sys.stdout.buffer.write(open(canned, "rb").read())
    sys.stdout.flush()
    sys.exit(int(open(canned + ".rc").read()) if os.path.exists(canned + ".rc") else 0)
real = json.load(open(os.path.join(ROOT, "view-python.json")))
sys.exit(subprocess.run(real + sys.argv[1:], input=data).returncode)
`

// An openssl that logs the command line of the process that ran it, then
// runs the real openssl.
const spireAgentDataCheckOpenSSL = `import os, subprocess, sys
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
parent = subprocess.run(["ps", "-ww", "-o", "args=", "-p", str(os.getppid())], capture_output=True, text=True).stdout
with open(os.path.join(ROOT, "openssl.log"), "a") as log:
    log.write(" ".join(parent.split()) + "\n")
real = open(os.path.join(ROOT, "openssl-real")).read()
os.execv(real, [real] + sys.argv[1:])
`

func newSPIREAgentDataCheckRoot(t *testing.T) *spireAgentGuardRoot {
	t.Helper()
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skipf("needs python3: %v", err)
	}
	openssl, err := exec.LookPath("openssl")
	if err != nil {
		t.Skipf("needs openssl: %v", err)
	}
	a := newSPIREAgentGuardRoot(t, python, openssl)
	real, err := json.Marshal(a.layout["python_argv"])
	if err != nil {
		t.Fatal(err)
	}
	a.write(filepath.Join(a.root, "view-python.json"), string(real), 0o644)
	view := filepath.Join(a.root, "bin", "fake-view")
	a.write(view, "#!"+python+" -I\n"+spireAgentDataCheckFakeView, 0o755)
	a.layout["python_argv"] = []string{view}
	shim := filepath.Join(a.root, "bin", "openssl")
	a.write(shim, "#!"+python+" -I\n"+spireAgentDataCheckOpenSSL, 0o755)
	a.write(filepath.Join(a.root, "openssl-real"), openssl, 0o644)
	a.layout["openssl_bin"] = shim
	return a
}

// spireAgentDataCheckLog is the lines of a log file under the fixture root.
func spireAgentDataCheckLog(t *testing.T, a *spireAgentGuardRoot, name string) []string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(a.root, name))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	return strings.Split(strings.TrimRight(string(data), "\n"), "\n")
}

func spireAgentDataCheckCA(t *testing.T) []byte {
	t.Helper()
	der := spireAgentHelperTestCert(t, true, "spiffe://"+spireAgentHelperTrustDomain, time.Now().Add(time.Hour))
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestRemoteAlphaSPIREAgentRootParsesNoSPIREData(t *testing.T) {
	const placeholder = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"

	t.Run("the_parsers_refuse_to_run_in_roots_process", func(t *testing.T) {
		a := newSPIREAgentDataCheckRoot(t)
		_, doc := a.run("root-parse")
		for _, name := range []string{"pem", "openssl"} {
			got, _ := doc[name].(string)
			if !strings.HasPrefix(got, "refused: ") || !strings.Contains(got, "never as root") {
				t.Errorf("%s called in root's process: %q", name, got)
			}
		}
		if lines := spireAgentDataCheckLog(t, a, "openssl.log"); len(lines) != 0 {
			t.Errorf("openssl ran: %q", lines)
		}
	})

	t.Run("every_openssl_run_is_in_the_spire_data_check", func(t *testing.T) {
		a := newSPIREAgentDataCheckRoot(t)
		// A bundle file that differs from the server bundle, so that the
		// check reads the server bundle, the file and how the file covers
		// the server's authorities.
		a.write(a.layout["bundle_path"].(string), string(spireAgentDataCheckCA(t)), 0o644)
		code, doc := a.run("refresh")
		if code != 0 || doc["result"] != "ok" {
			t.Fatalf("refresh: %d %v %v", code, doc["result"], doc["message"])
		}
		want, err := os.ReadFile(filepath.Join(a.root, "server-bundle.pem"))
		if err != nil {
			t.Fatal(err)
		}
		if got, err := os.ReadFile(a.layout["bundle_path"].(string)); err != nil || string(got) != string(want) {
			t.Fatalf("bundle file after refresh: %q, %v; want the server bundle", got, err)
		}
		views := spireAgentDataCheckLog(t, a, "view.log")
		if len(views) != 1 || !strings.Contains(views[0], `"op": "bundle"`) || !strings.Contains(views[0], `"args": ["-c"]`) {
			t.Fatalf("runs of the SPIRE data check: %q; want one bundle check started with -c", views)
		}
		// Root starts the check through setpriv; the check runs spire-server
		// and openssl itself, as the account it already is.
		view, server := 0, a.layout["spire_server_bin"].(string)
		for _, line := range spireAgentDataCheckLog(t, a, "setpriv.log") {
			var argv []string
			if err := json.Unmarshal([]byte(line), &argv); err != nil || len(argv) == 0 {
				t.Fatalf("setpriv log line %q: %v", line, err)
			}
			switch {
			case argv[0] == a.layout["python_argv"].([]string)[0]:
				view++
			case argv[0] == server && len(argv) > 1 && argv[1] == "bundle", argv[0] == a.layout["openssl_bin"]:
				t.Errorf("setpriv ran %q: the SPIRE data check runs it directly", argv)
			}
		}
		if view != 1 {
			t.Errorf("setpriv started the SPIRE data check %d times; want 1", view)
		}
		runs := spireAgentDataCheckLog(t, a, "openssl.log")
		if len(runs) < 2 {
			t.Fatalf("openssl ran %d times; want at least the server's and the file's certificates", len(runs))
		}
		for _, parent := range runs {
			if !strings.Contains(parent, "remote_alpha_spire_agent_view") || !strings.Contains(parent, " -c ") {
				t.Errorf("openssl ran outside the SPIRE data check, from %q", parent)
			}
		}
	})

	t.Run("root_writes_the_checked_pem_without_parsing_it", func(t *testing.T) {
		// The SPIRE account already decides what the server bundle is. Root
		// takes the PEM text it is given and parses none of it: here it is
		// not a certificate at all, and root writes it unchanged.
		a := newSPIREAgentDataCheckRoot(t)
		reply, _ := json.Marshal(map[string]any{"server": map[string]any{"ok": true, "pem": placeholder, "count": 1}, "file": nil})
		a.write(filepath.Join(a.root, "view-reply-bundle"), string(reply), 0o644)
		code, doc := a.run("refresh")
		if code != 0 || doc["result"] != "ok" {
			t.Fatalf("refresh: %d %v %v", code, doc["result"], doc["message"])
		}
		if got, err := os.ReadFile(a.layout["bundle_path"].(string)); err != nil || string(got) != placeholder {
			t.Fatalf("bundle file: %q, %v; want the reply's PEM text", got, err)
		}
		if lines := spireAgentDataCheckLog(t, a, "openssl.log"); len(lines) != 0 {
			t.Errorf("openssl ran: %q", lines)
		}
	})

	t.Run("a_reply_root_does_not_accept_writes_nothing", func(t *testing.T) {
		for _, c := range []struct{ name, reply, rc, want string }{
			{"extra_key", `{"server": {"ok": true, "pem": "` + strings.ReplaceAll(placeholder, "\n", `\n`) + `", "count": 1}, "file": null, "x": 1}`, "", "not one root accepts"},
			{"escape_in_pem", `{"server": {"ok": true, "pem": "-----BEGIN CERTIFICATE-----\n\u001b[2J\n-----END CERTIFICATE-----\n", "count": 1}, "file": null}`, "", "PEM characters only"},
			{"not_json", `certificate`, "", "printed no JSON"},
			{"nested_too_deep", strings.Repeat("[", 200000), "", "printed no JSON"},
			{"not_an_object", `[]`, "", "printed JSON that is not an object"},
			{"non_zero_exit", `{}`, "3", "exited 3"},
		} {
			t.Run(c.name, func(t *testing.T) {
				a := newSPIREAgentDataCheckRoot(t)
				a.write(filepath.Join(a.root, "view-reply-bundle"), c.reply, 0o644)
				if c.rc != "" {
					a.write(filepath.Join(a.root, "view-reply-bundle.rc"), c.rc, 0o644)
				}
				code, doc := a.run("refresh")
				msg, _ := doc["message"].(string)
				if code != 1 || doc["result"] != "failed" || !strings.Contains(msg, c.want) || !strings.Contains(msg, "SPIRE data check") {
					t.Fatalf("refresh: %d %v %q; want a failure naming the SPIRE data check and %q", code, doc["result"], msg, c.want)
				}
				if _, err := os.Lstat(a.layout["bundle_path"].(string)); !os.IsNotExist(err) {
					t.Fatalf("refresh wrote the bundle file (%v)", err)
				}
			})
		}
	})

	t.Run("the_check_is_stopped_at_its_output_bound_and_time_limit", func(t *testing.T) {
		a := newSPIREAgentDataCheckRoot(t)
		limit := 2*(1<<20) + (64 << 10)
		a.write(filepath.Join(a.root, "view-reply-bundle"), strings.Repeat(" ", limit+1), 0o644)
		code, doc := a.run("refresh")
		msg, _ := doc["message"].(string)
		if code != 1 || !strings.Contains(msg, "the SPIRE data check (bundle) as") || !strings.Contains(msg, "printed more than "+strconv.Itoa(limit)+" bytes; it was stopped") {
			t.Fatalf("a check that prints %d bytes: %d %q", limit+1, code, msg)
		}

		a = newSPIREAgentDataCheckRoot(t)
		a.layout["spire_view_timeout_seconds"] = 1
		a.write(filepath.Join(a.root, "view-reply-bundle.sleep"), "", 0o644)
		start := time.Now()
		code, doc = a.run("refresh")
		msg, _ = doc["message"].(string)
		if code != 1 || !strings.Contains(msg, "the SPIRE data check (bundle) as") || !strings.Contains(msg, "timed out") {
			t.Fatalf("a check that runs past its time limit: %d %q", code, msg)
		}
		if took := time.Since(start); took > 30*time.Second {
			t.Fatalf("refresh took %s with a 1 s limit on the check", took)
		}
		if _, err := os.Lstat(a.layout["bundle_path"].(string)); !os.IsNotExist(err) {
			t.Fatalf("refresh wrote the bundle file (%v)", err)
		}
	})

	t.Run("sixteen_server_certificates_pass_and_seventeen_do_not", func(t *testing.T) {
		for _, n := range []int{16, 17} {
			a := newSPIREAgentDataCheckRoot(t)
			var b strings.Builder
			for i := 0; i < n; i++ {
				b.Write(spireAgentDataCheckCA(t))
			}
			a.write(filepath.Join(a.root, "server-bundle.pem"), b.String(), 0o644)
			code, doc := a.run("refresh")
			msg, _ := doc["message"].(string)
			got, err := os.ReadFile(a.layout["bundle_path"].(string))
			if n == 16 {
				if code != 0 || err != nil || string(got) != b.String() {
					t.Fatalf("16 certificates: %d %q, file %d bytes (%v); want the server bundle written", code, msg, len(got), err)
				}
				continue
			}
			if code != 1 || doc["result"] != "refused" || !strings.Contains(msg, "holds 17 certificates, more than the 16") || !os.IsNotExist(err) {
				t.Fatalf("17 certificates: %d %v %q (file: %v)", code, doc["result"], msg, err)
			}
		}
	})

	t.Run("a_bundle_file_of_exactly_1_mib_goes_to_the_check", func(t *testing.T) {
		// Up to 1 MiB the file's bytes go to the SPIRE data check; one byte
		// more is oversized by lstat, and never read.
		for _, c := range []struct {
			size int
			want string
		}{{1 << 20, "unparseable"}, {1<<20 + 1, "oversized"}} {
			a := newSPIREAgentDataCheckRoot(t)
			a.write(a.layout["bundle_path"].(string), strings.Repeat("A", c.size), 0o644)
			code, doc := a.run("refresh")
			state, detail := spireAgentGuardCheck(doc, "bundle file")
			if code != 0 || state != "info" || !strings.HasSuffix(detail, ": "+c.want) {
				t.Fatalf("refresh over a %d-byte bundle file: %d, bundle file %s %q; want %s", c.size, code, state, detail, c.want)
			}
			views := spireAgentDataCheckLog(t, a, "view.log")
			if len(views) != 1 {
				t.Fatalf("runs of the SPIRE data check: %q", views)
			}
		}
	})

	t.Run("root_checks_every_field_of_a_reply", func(t *testing.T) {
		a := newSPIREAgentDataCheckRoot(t)
		pemText := strings.ReplaceAll(placeholder, "\n", `\n`)
		okServer := `{"ok": true, "pem": "` + pemText + `", "count": 1}`
		agentID := "spiffe://" + spireAgentHelperTrustDomain + "/spire/agent/join_token/x"
		type replyCase struct {
			name, kind, reply string
			fetch, sent       bool
			want              string // empty: accepted
		}
		cases := []replyCase{
			{"server_ok", "bundle", `{"server": ` + okServer + `, "file": null}`, true, false, ""},
			{"server_ok_file_matches", "bundle", `{"server": ` + okServer + `, "file": {"state": "matches"}}`, true, true, ""},
			{"server_ok_file_differs", "bundle", `{"server": ` + okServer + `, "file": {"state": "differs", "coverage": {"state": "attention", "detail": "d"}}}`, true, true, ""},
			{"server_ok_file_differs_error", "bundle", `{"server": ` + okServer + `, "file": {"state": "differs", "error": "e"}}`, true, true, ""},
			{"server_refused", "bundle", `{"server": {"ok": false, "kind": "refusal", "error": "no"}, "file": {"state": "unknown"}}`, true, true, ""},
			{"server_failed", "bundle", `{"server": {"ok": false, "kind": "command", "error": "no"}, "file": null}`, true, false, ""},
			{"no_server_asked", "bundle", `{"server": null, "file": {"state": "unparseable"}}`, false, true, ""},
			{"extra_top_key", "bundle", `{"server": ` + okServer + `, "file": null, "more": 1}`, true, false, "exactly the keys server, file"},
			{"missing_file_key", "bundle", `{"server": ` + okServer + `}`, true, false, "exactly the keys server, file"},
			{"server_extra_key", "bundle", `{"server": {"ok": true, "pem": "` + pemText + `", "count": 1, "x": 0}, "file": null}`, true, false, "the server part must be an object"},
			{"server_not_asked_for", "bundle", `{"server": ` + okServer + `, "file": null}`, false, false, "not asked for"},
			{"server_null_when_asked", "bundle", `{"server": null, "file": null}`, true, false, "must say ok true or false"},
			{"server_ok_is_a_string", "bundle", `{"server": {"ok": "true", "pem": "` + pemText + `", "count": 1}, "file": null}`, true, false, "must say ok true or false"},
			{"pem_empty", "bundle", `{"server": {"ok": true, "pem": "", "count": 1}, "file": null}`, true, false, "PEM characters only"},
			{"pem_control_character", "bundle", `{"server": {"ok": true, "pem": "-----BEGIN\u0007", "count": 1}, "file": null}`, true, false, "PEM characters only"},
			{"pem_not_ascii", "bundle", `{"server": {"ok": true, "pem": "é", "count": 1}, "file": null}`, true, false, "PEM characters only"},
			{"pem_too_large", "bundle", `{"server": {"ok": true, "pem": "` + strings.Repeat("A", 1<<20+1) + `", "count": 1}, "file": null}`, true, false, "1 to 1048576 of them"},
			{"pem_largest", "bundle", `{"server": {"ok": true, "pem": "` + strings.Repeat("A", 1<<20) + `", "count": 1}, "file": null}`, true, false, ""},
			{"pem_a_number", "bundle", `{"server": {"ok": true, "pem": 5, "count": 1}, "file": null}`, true, false, "PEM characters only"},
			{"count_zero", "bundle", `{"server": {"ok": true, "pem": "` + pemText + `", "count": 0}, "file": null}`, true, false, "from 1 to 16"},
			{"count_seventeen", "bundle", `{"server": {"ok": true, "pem": "` + pemText + `", "count": 17}, "file": null}`, true, false, "from 1 to 16"},
			{"count_sixteen", "bundle", `{"server": {"ok": true, "pem": "` + pemText + `", "count": 16}, "file": null}`, true, false, ""},
			{"count_true", "bundle", `{"server": {"ok": true, "pem": "` + pemText + `", "count": true}, "file": null}`, true, false, "from 1 to 16"},
			{"count_float", "bundle", `{"server": {"ok": true, "pem": "` + pemText + `", "count": 1.0}, "file": null}`, true, false, "from 1 to 16"},
			{"count_string", "bundle", `{"server": {"ok": true, "pem": "` + pemText + `", "count": "1"}, "file": null}`, true, false, "from 1 to 16"},
			{"error_kind_unknown", "bundle", `{"server": {"ok": false, "kind": "other", "error": "no"}, "file": null}`, true, false, "refusal or command"},
			{"error_text_control_character", "bundle", `{"server": {"ok": false, "kind": "refusal", "error": "\u001b[2J"}, "file": null}`, true, false, "printable ASCII"},
			{"error_text_too_long", "bundle", `{"server": {"ok": false, "kind": "refusal", "error": "` + strings.Repeat("e", 2001) + `"}, "file": null}`, true, false, "at most 2000"},
			{"file_state_for_no_file", "bundle", `{"server": ` + okServer + `, "file": {"state": "matches"}}`, true, false, "not sent"},
			{"no_file_state_for_a_file", "bundle", `{"server": ` + okServer + `, "file": null}`, true, true, "does not fit"},
			{"file_unknown_with_a_server_bundle", "bundle", `{"server": ` + okServer + `, "file": {"state": "unknown"}}`, true, true, "does not fit"},
			{"file_matches_without_a_server_bundle", "bundle", `{"server": {"ok": false, "kind": "refusal", "error": "no"}, "file": {"state": "matches"}}`, true, true, "does not fit"},
			{"file_differs_without_a_server_bundle", "bundle", `{"server": null, "file": {"state": "differs", "error": "e"}}`, false, true, "does not fit"},
			{"file_state_unknown_name", "bundle", `{"server": ` + okServer + `, "file": {"state": "absent"}}`, true, true, "does not fit"},
			{"file_extra_key", "bundle", `{"server": ` + okServer + `, "file": {"state": "matches", "x": 1}}`, true, true, "the file part must be an object"},
			{"coverage_state_fail", "bundle", `{"server": ` + okServer + `, "file": {"state": "differs", "coverage": {"state": "fail", "detail": "d"}}}`, true, true, "ok, info or attention"},
			{"coverage_extra_key", "bundle", `{"server": ` + okServer + `, "file": {"state": "differs", "coverage": {"state": "ok", "detail": "d", "x": 1}}}`, true, true, "the coverage verdict must be an object"},
			{"coverage_detail_too_long", "bundle", `{"server": ` + okServer + `, "file": {"state": "differs", "coverage": {"state": "ok", "detail": "` + strings.Repeat("d", 8001) + `"}}}`, true, true, "at most 8000"},
			{"agent_attested", "agent", `{"state": "attested", "agent_id": "` + agentID + `", "not_after": 1e9, "reattestable": false}`, false, false, ""},
			{"agent_not_json", "agent", `{"state": "not_json"}`, false, false, ""},
			{"agent_unattested", "agent", `{"state": "unattested", "reason": "r"}`, false, false, ""},
			{"agent_state_unknown", "agent", `{"state": "valid", "agent_id": "` + agentID + `", "not_after": 1e9, "reattestable": false}`, false, false, "is not one view_agent gives"},
			{"agent_extra_key", "agent", `{"state": "attested", "agent_id": "` + agentID + `", "not_after": 1e9, "reattestable": false, "x": 1}`, false, false, "exactly the keys"},
			{"agent_other_trust_domain", "agent", `{"state": "attested", "agent_id": "spiffe://other.internal/spire/agent/x", "not_after": 1e9, "reattestable": false}`, false, false, "under spiffe://" + spireAgentHelperTrustDomain + "/spire/agent/"},
			{"agent_id_prefix_only", "agent", `{"state": "attested", "agent_id": "spiffe://` + spireAgentHelperTrustDomain + `/spire/agent/", "not_after": 1e9, "reattestable": false}`, false, false, "without spaces"},
			{"agent_id_with_newline", "agent", `{"state": "attested", "agent_id": "` + agentID + `\n", "not_after": 1e9, "reattestable": false}`, false, false, "without spaces"},
			{"agent_not_after_nan", "agent", `{"state": "attested", "agent_id": "` + agentID + `", "not_after": NaN, "reattestable": false}`, false, false, "finite number"},
			{"agent_not_after_infinite", "agent", `{"state": "attested", "agent_id": "` + agentID + `", "not_after": 1e999, "reattestable": false}`, false, false, "finite number"},
			{"agent_not_after_string", "agent", `{"state": "attested", "agent_id": "` + agentID + `", "not_after": "1e9", "reattestable": false}`, false, false, "finite number"},
			{"agent_not_after_bool", "agent", `{"state": "attested", "agent_id": "` + agentID + `", "not_after": true, "reattestable": false}`, false, false, "finite number"},
			{"agent_reattestable_number", "agent", `{"state": "attested", "agent_id": "` + agentID + `", "not_after": 1e9, "reattestable": 1}`, false, false, "true or false"},
			{"agent_reason_too_long", "agent", `{"state": "unreadable", "reason": "` + strings.Repeat("r", 501) + `"}`, false, false, "at most 500"},
		}
		var items []string
		for _, c := range cases {
			items = append(items, `{"kind": "`+c.kind+`", "fetch_server": `+strconv.FormatBool(c.fetch)+`, "sent_file": `+strconv.FormatBool(c.sent)+`, "reply": `+c.reply+`}`)
		}
		a.write(filepath.Join(a.root, "replies.json"), "["+strings.Join(items, ",\n")+"]", 0o644)
		_, doc := a.run("check-replies")
		results, _ := doc["results"].([]any)
		if len(results) != len(cases) {
			t.Fatalf("check-replies: %v", doc)
		}
		for i, c := range cases {
			res := results[i].(map[string]any)
			reason, _ := res["reason"].(string)
			switch {
			case c.want == "" && res["ok"] != true:
				t.Errorf("%s: refused a reply the SPIRE data check gives: %s", c.name, reason)
			case c.want != "" && res["ok"] != false:
				t.Errorf("%s: accepted %v", c.name, res)
			case c.want != "" && (!strings.Contains(reason, c.want) || !strings.Contains(reason, "not one root accepts")):
				t.Errorf("%s: refused with %q; want it to name %q", c.name, reason, c.want)
			}
		}
		if res := results[0].(map[string]any); res["ok"] == true {
			bundle := res["server"].(map[string]any)["bundle"].(map[string]any)
			if bundle["pem"] != placeholder || bundle["count"] != float64(1) {
				t.Errorf("server_ok: root keeps %v; want the reply's PEM text and count", bundle)
			}
		}
	})

	t.Run("the_agent_svid_is_read_in_the_spire_data_check", func(t *testing.T) {
		a := newSPIREAgentDataCheckRoot(t)
		dir := filepath.Join(a.root, "agent-data")
		if err := os.Mkdir(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		a.chmod(dir, 0o755)
		a.layout["agent_data_dir"] = dir
		agentID := "spiffe://" + spireAgentHelperTrustDomain + "/spire/agent/join_token/0123"
		notAfter := time.Now().Add(time.Hour).Truncate(time.Second)
		leaf := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: spireAgentHelperTestCert(t, false, agentID, notAfter)})
		data, err := json.Marshal(map[string]any{"svid": []string{base64.StdEncoding.EncodeToString(leaf)}, "reattestable": true})
		if err != nil {
			t.Fatal(err)
		}
		a.write(filepath.Join(dir, "agent-data.json"), string(data), 0o644)
		_, doc := a.run("agent")
		agent, _ := doc["agent"].(map[string]any)
		if agent["state"] != "valid" || agent["agent_id"] != agentID || agent["reattestable"] != true || agent["not_after"] != float64(notAfter.Unix()) {
			t.Fatalf("agent read through the SPIRE data check: %v", doc)
		}
		views := spireAgentDataCheckLog(t, a, "view.log")
		if len(views) != 1 || !strings.Contains(views[0], `"op": "agent"`) {
			t.Fatalf("runs of the SPIRE data check: %q", views)
		}
		runs := spireAgentDataCheckLog(t, a, "openssl.log")
		if len(runs) != 1 || !strings.Contains(runs[0], "remote_alpha_spire_agent_view") {
			t.Fatalf("openssl runs: %q; want one, from the SPIRE data check", runs)
		}

		// A reply naming an agent outside the trust domain leaves the agent
		// unreadable, with root's reason.
		reply, _ := json.Marshal(map[string]any{"state": "attested", "agent_id": "spiffe://other.internal/spire/agent/x", "not_after": 4e9, "reattestable": false})
		a.write(filepath.Join(a.root, "view-reply-agent"), string(reply), 0o644)
		_, doc = a.run("agent")
		agent, _ = doc["agent"].(map[string]any)
		reason, _ := agent["reason"].(string)
		if agent["state"] != "unreadable" || !strings.Contains(reason, "not one root accepts") {
			t.Fatalf("agent with a reply outside the trust domain: %v", doc)
		}
	})

	t.Run("root_checks_the_size_and_reads_the_bytes_back", func(t *testing.T) {
		a := newSPIREAgentDataCheckRoot(t)
		_, doc := a.run("write-checks")
		for _, name := range []string{"empty", "oversized"} {
			got, _ := doc[name].(string)
			if !strings.Contains(got, "outside 1 to 1048576") || doc[name+"_file"] != false {
				t.Errorf("write_bundle with an %s bundle: %q, file written: %v", name, got, doc[name+"_file"])
			}
		}
		if got, _ := doc["readback"].(string); !strings.Contains(got, "was written but does not read back as the server bundle (different bytes)") {
			t.Errorf("write_bundle when the file reads back with other bytes: %q", got)
		}
	})

	t.Run("a_missing_python_for_the_check_is_refused_up_front", func(t *testing.T) {
		a := newSPIREAgentDataCheckRoot(t)
		missing := filepath.Join(a.root, "bin", "no-python")
		a.layout["python_argv"] = []string{missing}
		code, doc := a.run("refresh")
		msg, _ := doc["message"].(string)
		if code != 1 || doc["result"] != "refused" || !strings.Contains(msg, "required command "+missing+" is missing") {
			t.Fatalf("refresh with no Python for the SPIRE data check: %d %v %q", code, doc["result"], msg)
		}
	})

	t.Run("the_check_refuses_to_run_as_another_account", func(t *testing.T) {
		a := newSPIREAgentDataCheckRoot(t)
		_, doc := a.run("view-other-account")
		reason, _ := doc["reason"].(string)
		if doc["ok"] != false || !strings.Contains(reason, "runs only as") || !strings.Contains(reason, "exited 3") {
			t.Fatalf("the SPIRE data check started for an account it does not run as: %v", doc)
		}
	})
}

// Root still decodes JSON from SPIRE: the SPIRE data check's reply, and in
// pin, recover and status the output of spire-server agent list, entry show
// and token generate. Python's decoder is not certificate parsing; what
// root does with the result must still hold for any JSON the SPIRE account
// can print. A wrong shape is a command error, never a crash, and a text
// report shows no control character that a detail quoted.
func TestRemoteAlphaSPIREAgentRootHandlesSPIREJSONStrictly(t *testing.T) {
	t.Run("agent_list", func(t *testing.T) {
		for _, c := range []struct{ name, out, want string }{
			{"agents_an_object", `{"agents": {"a": 1}}`, "printed agents that is not a list of objects"},
			{"agents_strings", `{"agents": ["a"]}`, "printed agents that is not a list of objects"},
			{"nested_too_deep", strings.Repeat("[", 200000), "printed no JSON"},
			{"not_an_object", `[1]`, "printed unexpected JSON"},
			{"expiry_infinite", `{"agents": [{"id": {"trust_domain": "t", "path": "/p"}, "x509svid_expires_at": 1e999}]}`, ""},
			{"expiry_nan", `{"agents": [{"id": {"trust_domain": "t", "path": "/p"}, "x509svid_expires_at": NaN}]}`, ""},
			{"id_parts_not_text", `{"agents": [{"id": {"trust_domain": ["t"], "path": {"p": 1}}}]}`, ""},
		} {
			t.Run(c.name, func(t *testing.T) {
				a := newSPIREAgentDataCheckRoot(t)
				a.write(filepath.Join(a.root, "agent-list.json"), c.out, 0o644)
				_, doc := a.run("list-agents")
				reason, _ := doc["reason"].(string)
				if c.want != "" {
					if doc["ok"] != false || !strings.Contains(reason, c.want) {
						t.Fatalf("agent list printing %.40q: %v; want a command error naming %q", c.out, doc, c.want)
					}
					return
				}
				agents, _ := doc["agents"].([]any)
				if doc["ok"] != true || len(agents) != 1 {
					t.Fatalf("agent list printing %.40q: %v", c.out, doc)
				}
				agent := agents[0].(map[string]any)
				if agent["expires_at"] != float64(0) {
					t.Errorf("an expiry that is no whole number reads as %v; want 0", agent["expires_at"])
				}
				if c.name == "id_parts_not_text" && agent["id"] != "" {
					t.Errorf("an ID whose parts are not text reads as %q; want none", agent["id"])
				}
			})
		}
	})
	t.Run("text_report_shows_no_control_characters", func(t *testing.T) {
		a := newSPIREAgentDataCheckRoot(t)
		_, doc := a.run("render")
		text, _ := doc["text"].(string)
		if !strings.Contains(text, "[info] quoted: a?[2Jb?c?d?e\tf\ng\n") {
			t.Fatalf("text report: %q", text)
		}
	})
}
