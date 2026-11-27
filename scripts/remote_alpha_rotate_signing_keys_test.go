package scripts_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	agsconfig "execution-substrate/ags/config"
	egsconfig "execution-substrate/egs/config"
	esconfig "execution-substrate/es/config"
	"execution-substrate/internal/knownkeys"
)

const rotateSigningKeysPython = "scripts/internal/remote_alpha_rotate_signing_keys.py"

// The rotation's fake openssl is this test binary run again: a bash script
// on the host's /usr/bin/openssl path execs it with this variable set, and
// init answers as openssl would for the two commands the rotation runs.
const fakeOpenSSLEnv = "SIGNING_KEY_ROTATION_FAKE_OPENSSL"

func init() {
	if os.Getenv(fakeOpenSSLEnv) == "1" {
		os.Exit(fakeOpenSSL(os.Args[1:]))
	}
}

// fakeOpenSSL makes an Ed25519 key with crypto/rand, or from the seed in
// FAKE_OPENSSL_SEED_HEX, and logs each call, without its key, to calls.log.
func fakeOpenSSL(args []string) int {
	if log, err := os.OpenFile(filepath.Join(os.Getenv("FAKE_STATE"), "calls.log"), os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600); err == nil {
		fmt.Fprintf(log, "openssl %s\n", strings.Join(args, " "))
		log.Close()
	}
	switch strings.Join(args, " ") {
	case "genpkey -algorithm ED25519 -outform DER":
		var private ed25519.PrivateKey
		if seed := os.Getenv("FAKE_OPENSSL_SEED_HEX"); seed != "" {
			b, err := hex.DecodeString(seed)
			if err != nil {
				return 1
			}
			private = ed25519.NewKeyFromSeed(b)
		} else {
			_, generated, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				return 1
			}
			private = generated
		}
		der, err := x509.MarshalPKCS8PrivateKey(private)
		if err != nil {
			return 1
		}
		os.Stdout.Write(der)
		return 0
	case "pkey -inform DER -pubout -outform DER":
		in, err := io.ReadAll(os.Stdin)
		if err != nil {
			return 1
		}
		key, err := x509.ParsePKCS8PrivateKey(in)
		if err != nil {
			fmt.Fprintln(os.Stderr, "fake openssl: not a PKCS #8 key")
			return 1
		}
		der, err := x509.MarshalPKIXPublicKey(key.(ed25519.PrivateKey).Public())
		if err != nil {
			return 1
		}
		os.Stdout.Write(der)
		return 0
	}
	fmt.Fprintf(os.Stderr, "fake openssl: unexpected %v\n", args)
	return 2
}

// The fakes for systemctl and curl log every call to calls.log and act on
// marker files in the state directory: inactive-<unit> (is-active says
// inactive), fail-restart-<unit>-once, unhealthy (every request answers
// 503), and unhealthy-after-es-start-1 (requests answer 503 after the first
// start of es and before the second).
const rotationFakeSystemctl = `#!/usr/bin/env bash
set -u
s="$FAKE_STATE"
echo "systemctl $*" >> "$s/calls.log"
case "$1" in
  is-active)
    shift
    for u in "$@"; do if [[ -e "$s/inactive-$u" ]]; then echo inactive; else echo active; fi; done ;;
  stop) touch "$s/inactive-$2" ;;
  restart|start)
    if [[ -e "$s/fail-$1-$2-once" ]]; then rm -f "$s/fail-$1-$2-once"; echo "Job for $2.service failed" >&2; exit 1; fi
    if [[ "$1 $2" == "start es" ]]; then echo x >> "$s/es-starts"; fi
    rm -f "$s/inactive-$2" ;;
  *) echo "fake systemctl: unexpected $*" >&2; exit 2 ;;
esac
`

const rotationFakeCurl = `#!/usr/bin/env bash
set -u
s="$FAKE_STATE"
url="${@: -1}"
echo "curl $url" >> "$s/calls.log"
starts=$(wc -l < "$s/es-starts" 2>/dev/null || echo 0)
if [[ -e "$s/unhealthy" ]] || { [[ -e "$s/unhealthy-after-es-start-1" ]] && (( starts == 1 )); }; then
  printf 503
else
  printf 200
fi
`

type rotationHost struct {
	t     *testing.T
	root  string
	bin   string
	state string
}

var rotationConfigPaths = map[string]string{
	"ags": "etc/execution-substrate/ags.json",
	"egs": "etc/execution-substrate/egs.json",
	"es":  "etc/execution-substrate/es.json",
}

// newRotationHost is the box as the read-only check of 2026-11-27 found it:
// AGS, EGS and ES on the keys of the example configurations, each config
// root:<service> 0640 (under the test, the test user and its group stand in
// for both), and ARS's index with a few records.
func newRotationHost(t *testing.T) *rotationHost {
	t.Helper()
	base := t.TempDir()
	h := &rotationHost{t: t, root: filepath.Join(base, "root"), bin: filepath.Join(base, "bin"), state: filepath.Join(base, "state")}
	for _, dir := range []string{h.bin, h.state, filepath.Join(h.root, "etc/execution-substrate"), filepath.Join(h.root, "var/backups"),
		filepath.Join(h.root, "var/lib/ars"), filepath.Join(h.root, "usr/bin")} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for name, path := range rotationConfigPaths {
		data, err := os.ReadFile(repoPath(".examples/config/" + name + ".json"))
		if err != nil {
			t.Fatal(err)
		}
		h.write(path, data, 0o640)
	}
	ars := map[string]any{"storage": map[string]any{"root_dir": "/var/lib/ars/blobs", "index_file": "/var/lib/ars/index.json"}}
	h.writeJSON("etc/execution-substrate/ars.json", ars, 0o640)
	h.writeJSON("var/lib/ars/index.json", map[string]any{"a": 1, "b": 2, "c": 3}, 0o640)
	h.write("etc/execution-substrate/healthcheck.env",
		[]byte("CA_CERT=/etc/execution-substrate/tls/ca.pem\nOPERATOR_CERT=/etc/x/op.pem\nOPERATOR_KEY=/etc/x/op-key.pem\n"), 0o640)
	for name, script := range map[string]string{"systemctl": rotationFakeSystemctl, "curl": rotationFakeCurl} {
		if err := os.WriteFile(filepath.Join(h.bin, name), []byte(script), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	h.fakeOpenSSL("")
	return h
}

// fakeOpenSSL installs the fake openssl, making keys from seedHex when it
// is not empty.
func (h *rotationHost) fakeOpenSSL(seedHex string) {
	h.t.Helper()
	self, err := os.Executable()
	if err != nil {
		h.t.Fatal(err)
	}
	script := fmt.Sprintf("#!/bin/bash\nexport %s=1 FAKE_STATE=%q FAKE_OPENSSL_SEED_HEX=%q\nexec %q \"$@\"\n",
		fakeOpenSSLEnv, h.state, seedHex, self)
	if err := os.WriteFile(filepath.Join(h.root, "usr/bin/openssl"), []byte(script), 0o755); err != nil {
		h.t.Fatal(err)
	}
}

func (h *rotationHost) path(rel string) string { return filepath.Join(h.root, rel) }

func (h *rotationHost) write(rel string, data []byte, mode os.FileMode) {
	h.t.Helper()
	path := h.path(rel)
	if err := os.WriteFile(path, data, mode); err != nil {
		h.t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		h.t.Fatal(err)
	}
}

func (h *rotationHost) writeJSON(rel string, doc any, mode os.FileMode) {
	h.t.Helper()
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		h.t.Fatal(err)
	}
	h.write(rel, append(data, '\n'), mode)
}

func (h *rotationHost) read(rel string) []byte {
	h.t.Helper()
	data, err := os.ReadFile(h.path(rel))
	if err != nil {
		h.t.Fatal(err)
	}
	return data
}

func (h *rotationHost) doc(name string) map[string]any {
	h.t.Helper()
	var doc map[string]any
	if err := json.Unmarshal(h.read(rotationConfigPaths[name]), &doc); err != nil {
		h.t.Fatal(err)
	}
	return doc
}

func (h *rotationHost) edit(name string, change func(map[string]any)) {
	h.t.Helper()
	doc := h.doc(name)
	change(doc)
	h.writeJSON(rotationConfigPaths[name], doc, 0o640)
}

func (h *rotationHost) mark(name string) {
	h.t.Helper()
	if err := os.WriteFile(filepath.Join(h.state, name), nil, 0o644); err != nil {
		h.t.Fatal(err)
	}
}

func (h *rotationHost) configBytes() map[string][]byte {
	out := map[string][]byte{}
	for name, rel := range rotationConfigPaths {
		out[name] = h.read(rel)
	}
	return out
}

func (h *rotationHost) calls(prefix string) []string {
	data, err := os.ReadFile(filepath.Join(h.state, "calls.log"))
	if err != nil && !os.IsNotExist(err) {
		h.t.Fatal(err)
	}
	var out []string
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if line != "" && strings.HasPrefix(line, prefix) {
			out = append(out, line)
		}
	}
	return out
}

func (h *rotationHost) run(args ...string) (string, string, int) {
	h.t.Helper()
	cmd := exec.Command("python3", append([]string{"-I", "-B", repoPath(rotateSigningKeysPython), "--host-root", h.root}, args...)...)
	cmd.Dir = h.state
	cmd.Env = append(os.Environ(),
		"PATH="+h.bin+string(os.PathListSeparator)+os.Getenv("PATH"),
		"FAKE_STATE="+h.state,
		"SIGNING_KEY_ROTATION_TEST_OPENSSL="+h.path("usr/bin/openssl"),
		"SIGNING_KEY_ROTATION_TEST_WAIT_SECONDS=1",
	)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	code := 0
	if err != nil {
		exitErr, ok := err.(*exec.ExitError)
		if !ok {
			h.t.Fatalf("run %v: %v", args, err)
		}
		code = exitErr.ExitCode()
	}
	return stdout.String(), stderr.String(), code
}

func (h *rotationHost) report(stdout, stderr string, code int) map[string]any {
	h.t.Helper()
	var report map[string]any
	if err := json.Unmarshal([]byte(stdout), &report); err != nil {
		h.t.Fatalf("no JSON report (exit %d): %v\nstdout %s\nstderr %s", code, err, stdout, stderr)
	}
	return report
}

func (h *rotationHost) backupDirs() []string {
	h.t.Helper()
	entries, err := os.ReadDir(h.path("var/backups/execution-substrate-signing-keys"))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		h.t.Fatal(err)
	}
	var out []string
	for _, entry := range entries {
		out = append(out, filepath.Join(h.path("var/backups/execution-substrate-signing-keys"), entry.Name()))
	}
	return out
}

// rotatedSigner checks a rotated signer object: an Ed25519 seed and its
// public key, the key ID scripts/internal/signingkeygen gives it, and not a
// known key. It returns the seed in hex.
func rotatedSigner(t *testing.T, role string, signer map[string]any) (seedHex string, public string, keyID string) {
	t.Helper()
	seedHex, _ = signer["private_key_hex"].(string)
	public, _ = signer["public_key_hex"].(string)
	keyID, _ = signer["key_id"].(string)
	seed, err := hex.DecodeString(seedHex)
	if err != nil || len(seed) != ed25519.SeedSize {
		t.Fatalf("%s signer.private_key_hex is not a 32-byte seed", role)
	}
	derived := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	if hex.EncodeToString(derived) != public {
		t.Fatalf("%s signer.public_key_hex is not the public key of its seed", role)
	}
	sum := sha256.Sum256(derived)
	if want := role + "-" + hex.EncodeToString(sum[:8]); keyID != want {
		t.Fatalf("%s signer.key_id = %q, want %q (the key ID signingkeygen gives)", role, keyID, want)
	}
	if signer["algorithm"] != "ed25519" || len(signer) != 4 {
		t.Fatalf("%s signer is not exactly the four fields signingkeygen writes: %v", role, keysOf(signer))
	}
	if err := knownkeys.CheckPrivate(role+" signer", seed); err != nil {
		t.Fatal(err)
	}
	return seedHex, public, keyID
}

func keysOf(doc map[string]any) []string {
	var out []string
	for key := range doc {
		out = append(out, key)
	}
	return out
}

func withoutKeys(t *testing.T, doc map[string]any, paths ...[]string) map[string]any {
	t.Helper()
	data, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatal(err)
	}
	for _, path := range paths {
		node := out
		for _, key := range path[:len(path)-1] {
			node = node[key].(map[string]any)
		}
		delete(node, path[len(path)-1])
	}
	return out
}

// TestSigningKeyRotationCheckChangesNothing runs check on the box as it is:
// it reports the published keys and every change apply would make, and
// touches nothing.
func TestSigningKeyRotationCheckChangesNothing(t *testing.T) {
	h := newRotationHost(t)
	before := h.configBytes()
	stdout, stderr, code := h.run("check")
	report := h.report(stdout, stderr, code)
	if code != 0 || report["result"] != "ready" {
		t.Fatalf("check exit %d result %v problems %v\nstderr %s", code, report["result"], report["problems"], stderr)
	}
	current := report["current"].(map[string]any)
	for role, keyID := range map[string]string{"ags": "ags-key-1", "egs": "egs-key-1"} {
		entry := current[role].(map[string]any)
		if entry["key_id"] != keyID || entry["private_seed_is_one_byte_repeated"] != true {
			t.Fatalf("check reports %s as %v", role, entry)
		}
	}
	changes := fmt.Sprint(report["changes"])
	for _, want := range []string{"ags.json signer", "egs.json signer", "instead of ags-key-1", "revoked_signers: add ags-key-1",
		"update_revision: 1 to 2", "verification.trust_model", "verification.provenance", "verification.derivation_attestation",
		"verification.workload_identity_binding"} {
		if !strings.Contains(changes, want) {
			t.Fatalf("check's changes do not say %q: %s", want, changes)
		}
	}
	if report["ars_index_entries"] != float64(3) {
		t.Fatalf("check counts %v ARS index entries, want 3", report["ars_index_entries"])
	}
	if !reflect.DeepEqual(h.configBytes(), before) || h.backupDirs() != nil {
		t.Fatal("check changed a config or wrote a backup")
	}
	for _, call := range append(h.calls("systemctl"), h.calls("openssl")...) {
		if !strings.HasPrefix(call, "systemctl is-active") {
			t.Fatalf("check ran %q", call)
		}
	}
	if strings.Contains(stdout+stderr, "1111111111111111111111111111111111111111111111111111111111111111") ||
		strings.Contains(stdout+stderr, "private_key_hex") {
		t.Fatal("check printed private key material")
	}
}

// TestSigningKeyRotationApplyRotatesAllThreeConfigs runs apply on the box as
// it is and checks every config it writes, the order of the restarts, the
// backup, and that no output holds a private key.
func TestSigningKeyRotationApplyRotatesAllThreeConfigs(t *testing.T) {
	h := newRotationHost(t)
	before := h.configBytes()
	beforeDocs := map[string]map[string]any{"ags": h.doc("ags"), "egs": h.doc("egs"), "es": h.doc("es")}
	stdout, stderr, code := h.run("apply")
	report := h.report(stdout, stderr, code)
	if code != 0 || report["result"] != "rotated" {
		t.Fatalf("apply exit %d result %v failure %v problems %v\nstderr %s", code, report["result"], report["failure"], report["problems"], stderr)
	}

	ags, egs, es := h.doc("ags"), h.doc("egs"), h.doc("es")
	agsSeed, agsPublic, agsID := rotatedSigner(t, "ags", ags["signer"].(map[string]any))
	egsSeed, egsPublic, egsID := rotatedSigner(t, "egs", egs["signer"].(map[string]any))
	if agsPublic == egsPublic {
		t.Fatal("AGS and EGS got the same key")
	}
	policy := egs["runtime_trust"].(map[string]any)["signer_policy"].(map[string]any)
	if !reflect.DeepEqual(policy["allowed_signers"], []any{agsID}) || !reflect.DeepEqual(policy["revoked_signers"], []any{"ags-key-1"}) {
		t.Fatalf("EGS signer policy after the rotation: %v", policy)
	}
	if got := egs["publication"].(map[string]any)["update_revision"]; got != float64(2) {
		t.Fatalf("EGS publication.update_revision = %v, want 2", got)
	}
	verification := es["verification"].(map[string]any)
	want := map[string]map[string]any{
		"trust_model":               {"algorithm": "ed25519", "key_id": egsID, "public_key_hex": egsPublic},
		"provenance":                {"algorithm": "ed25519", "key_id": agsID, "public_key_hex": agsPublic},
		"derivation_attestation":    {"algorithm": "ed25519", "key_id": agsID, "public_key_hex": agsPublic},
		"workload_identity_binding": {"algorithm": "ed25519", "key_id": agsID, "public_key_hex": agsPublic},
	}
	for name, entry := range want {
		if !reflect.DeepEqual(verification[name], map[string]any(entry)) {
			t.Fatalf("es.json verification.%s = %v, want %v", name, verification[name], entry)
		}
	}
	// Nothing else changed.
	for name, paths := range map[string][][]string{
		"ags": {{"signer"}},
		"egs": {{"signer"}, {"runtime_trust", "signer_policy"}, {"publication", "update_revision"}},
		"es":  {{"verification"}},
	} {
		doc := map[string]map[string]any{"ags": ags, "egs": egs, "es": es}[name]
		if !reflect.DeepEqual(withoutKeys(t, doc, paths...), withoutKeys(t, beforeDocs[name], paths...)) {
			t.Fatalf("apply changed more of %s.json than its keys", name)
		}
	}
	for name, rel := range rotationConfigPaths {
		info, err := os.Lstat(h.path(rel))
		if err != nil || info.Mode().Perm() != 0o640 || !info.Mode().IsRegular() {
			t.Fatalf("%s.json after apply: %v %v, want a regular 0640 file", name, info.Mode(), err)
		}
	}
	// The product's own loaders accept the rotated configs.
	if _, err := agsconfig.Load(h.path(rotationConfigPaths["ags"])); err != nil {
		t.Fatalf("AGS refuses the rotated ags.json: %v", err)
	}
	if _, err := egsconfig.Load(h.path(rotationConfigPaths["egs"])); err != nil {
		t.Fatalf("EGS refuses the rotated egs.json: %v", err)
	}
	if _, err := esconfig.Load(h.path(rotationConfigPaths["es"])); err != nil {
		t.Fatalf("ES refuses the rotated es.json: %v", err)
	}

	var order []string
	for _, call := range h.calls("systemctl") {
		if !strings.HasPrefix(call, "systemctl is-active") {
			order = append(order, call)
		}
	}
	if got, want := strings.Join(order, " | "), "systemctl stop es | systemctl restart egs | systemctl restart ags | systemctl start es"; got != want {
		t.Fatalf("apply ran %q, want %q", got, want)
	}

	dirs := h.backupDirs()
	if len(dirs) != 1 || !strings.HasSuffix(dirs[0], "-"+agsID) || report["backup_dir"] != dirs[0] {
		t.Fatalf("backups %v, report backup_dir %v", dirs, report["backup_dir"])
	}
	if info, err := os.Lstat(dirs[0]); err != nil || info.Mode().Perm() != 0o700 {
		t.Fatalf("backup directory mode %v %v, want 0700", info.Mode(), err)
	}
	for name, data := range before {
		copyPath := filepath.Join(dirs[0], name+".json")
		info, err := os.Lstat(copyPath)
		if err != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("backup copy %s: %v %v, want 0600", name, info.Mode(), err)
		}
		if got, _ := os.ReadFile(copyPath); !bytes.Equal(got, data) {
			t.Fatalf("backup copy of %s.json is not the config before the rotation", name)
		}
	}
	summary, err := os.ReadFile(filepath.Join(dirs[0], "summary.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, seed := range []string{agsSeed, egsSeed} {
		if strings.Contains(stdout+stderr+string(summary), seed) {
			t.Fatal("apply printed or summarised a new private key")
		}
	}
	if strings.Contains(stdout+stderr+string(summary), "private_key_hex") {
		t.Fatal("apply's output names private_key_hex")
	}
	newKeys := report["new"].(map[string]any)
	if newKeys["ags"].(map[string]any)["key_id"] != agsID || newKeys["egs"].(map[string]any)["key_id"] != egsID {
		t.Fatalf("report names new keys %v", newKeys)
	}
	if got := len(h.calls("openssl genpkey")); got != 2 {
		t.Fatalf("apply made %d keys, want 2", got)
	}
}

// TestSigningKeyRotationRollsBack makes the services fail after the configs
// are written: apply puts every config back, restarts the services on them,
// and exits 1.
func TestSigningKeyRotationRollsBack(t *testing.T) {
	for _, tc := range []struct{ name, marker string }{
		{"ES does not answer after the restart", "unhealthy-after-es-start-1"},
		{"AGS does not restart", "fail-restart-ags-once"},
		{"EGS does not restart", "fail-restart-egs-once"},
		{"ES does not start", "fail-start-es-once"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newRotationHost(t)
			before := h.configBytes()
			h.mark(tc.marker)
			stdout, stderr, code := h.run("apply")
			report := h.report(stdout, stderr, code)
			if code != 1 || report["result"] != "rolled_back" {
				t.Fatalf("apply exit %d result %v failure %v\nstderr %s", code, report["result"], report["failure"], stderr)
			}
			if !reflect.DeepEqual(h.configBytes(), before) {
				t.Fatal("the configs are not the ones before the rotation after the rollback")
			}
			calls := h.calls("systemctl")
			if n := len(calls); n < 4 || calls[n-1] != "systemctl is-active egs ags es" {
				t.Fatalf("the rollback did not end with a check of the units: %v", calls)
			}
			var last []string
			for _, call := range calls {
				if !strings.HasPrefix(call, "systemctl is-active") {
					last = append(last, call)
				}
			}
			if got := strings.Join(last[len(last)-4:], " | "); got != "systemctl stop es | systemctl restart egs | systemctl restart ags | systemctl start es" {
				t.Fatalf("the rollback restarted %q", got)
			}
			if len(h.backupDirs()) != 1 {
				t.Fatal("the rollback left no backup")
			}
		})
	}
}

// TestSigningKeyRotationRollbackCommand puts a rotation's backup back.
func TestSigningKeyRotationRollbackCommand(t *testing.T) {
	h := newRotationHost(t)
	before := h.configBytes()
	stdout, stderr, code := h.run("apply")
	report := h.report(stdout, stderr, code)
	if code != 0 {
		t.Fatalf("apply exit %d: %s", code, stderr)
	}
	stdout, stderr, code = h.run("rollback", "--backup-dir", report["backup_dir"].(string))
	if result := h.report(stdout, stderr, code); code != 0 || result["result"] != "rolled_back" {
		t.Fatalf("rollback exit %d result %v\nstderr %s", code, result["result"], stderr)
	}
	if !reflect.DeepEqual(h.configBytes(), before) {
		t.Fatal("rollback did not put the configs back")
	}
	if _, _, code := h.run("rollback", "--backup-dir", h.path("var/backups")); code != 1 {
		t.Fatalf("rollback of a directory that is not a backup exited %d, want 1", code)
	}
}

// TestSigningKeyRotationUpdatesWorkloadGrants gives es.json workload grants
// that name the AGS key: apply moves each to the new key, and refuses a
// grant that names another key.
func TestSigningKeyRotationUpdatesWorkloadGrants(t *testing.T) {
	grants := func(signers ...string) func(map[string]any) {
		return func(doc map[string]any) {
			var rules []any
			for i, signer := range signers {
				rules = append(rules, map[string]any{"id": fmt.Sprintf("rule-%d", i), "signer_key_id": signer})
			}
			doc["admission_policy"] = map[string]any{"workload_grants": map[string]any{"egress_lanes": []any{}, "rules": rules}}
		}
	}
	h := newRotationHost(t)
	h.edit("es", grants("ags-key-1", "ags-key-1"))
	stdout, stderr, code := h.run("apply")
	if report := h.report(stdout, stderr, code); code != 0 {
		t.Fatalf("apply exit %d problems %v failure %v", code, report["problems"], report["failure"])
	}
	agsID := h.doc("ags")["signer"].(map[string]any)["key_id"]
	for _, rule := range h.doc("es")["admission_policy"].(map[string]any)["workload_grants"].(map[string]any)["rules"].([]any) {
		if rule.(map[string]any)["signer_key_id"] != agsID {
			t.Fatalf("grant %v does not name the new AGS key %v", rule, agsID)
		}
	}

	other := newRotationHost(t)
	other.edit("es", grants("ags-key-1", "ags-other"))
	before := other.configBytes()
	stdout, stderr, code = other.run("apply")
	report := other.report(stdout, stderr, code)
	if code != 1 || !strings.Contains(fmt.Sprint(report["problems"]), "rule-1") || !reflect.DeepEqual(other.configBytes(), before) {
		t.Fatalf("apply on a grant naming another key: exit %d problems %v", code, report["problems"])
	}
}

// TestSigningKeyRotationRefuses gives apply hosts it was not written for,
// and a host whose openssl gives a known key: apply changes nothing, makes
// no backup and restarts nothing.
func TestSigningKeyRotationRefuses(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(*rotationHost)
		want  string
	}{
		{"ES trusts another provenance key", func(h *rotationHost) {
			h.edit("es", func(d map[string]any) {
				d["verification"].(map[string]any)["provenance"].(map[string]any)["key_id"] = "ags-other"
			})
		}, "verification.provenance is not AGS's signer key"},
		{"ES trusts another EGS key", func(h *rotationHost) {
			h.edit("es", func(d map[string]any) {
				d["verification"].(map[string]any)["trust_model"].(map[string]any)["public_key_hex"] = strings.Repeat("ab", 32)
			})
		}, "verification.trust_model is not EGS's signer key"},
		{"EGS does not allow AGS", func(h *rotationHost) {
			h.edit("egs", func(d map[string]any) {
				d["runtime_trust"].(map[string]any)["signer_policy"].(map[string]any)["allowed_signers"] = []any{"ags-other"}
			})
		}, "does not allow AGS's signer key ID"},
		{"EGS has no publication revision", func(h *rotationHost) {
			h.edit("egs", func(d map[string]any) { delete(d, "publication") })
		}, "publication.update_revision"},
		{"AGS and EGS share a key", func(h *rotationHost) {
			egs := h.doc("egs")["signer"].(map[string]any)
			h.edit("ags", func(d map[string]any) {
				signer := d["signer"].(map[string]any)
				signer["private_key_hex"], signer["public_key_hex"] = egs["private_key_hex"], egs["public_key_hex"]
			})
		}, "AGS and EGS sign with the same key"},
		{"es.json is world-readable", func(h *rotationHost) {
			if err := os.Chmod(h.path(rotationConfigPaths["es"]), 0o644); err != nil {
				t.Fatal(err)
			}
		}, "es.json is not root:es 0640"},
		{"es.json has a second link", func(h *rotationHost) {
			if err := os.Link(h.path(rotationConfigPaths["es"]), h.path("etc/execution-substrate/es.json.old")); err != nil {
				t.Fatal(err)
			}
		}, "with one link"},
		{"EGS is not running", func(h *rotationHost) { h.mark("inactive-egs") }, "must all run"},
		{"ES does not answer", func(h *rotationHost) { h.mark("unhealthy") }, "must all run"},
		{"openssl gives a known key", func(h *rotationHost) { h.fakeOpenSSL(strings.Repeat("11", 32)) }, "known key"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newRotationHost(t)
			tc.setup(h)
			before := h.configBytes()
			stdout, stderr, code := h.run("apply")
			if code != 1 || !strings.Contains(stdout+stderr, tc.want) {
				t.Fatalf("apply exit %d, want 1 naming %q\nstdout %s\nstderr %s", code, tc.want, stdout, stderr)
			}
			if !reflect.DeepEqual(h.configBytes(), before) || h.backupDirs() != nil {
				t.Fatal("a refused apply changed a config or wrote a backup")
			}
			for _, call := range h.calls("systemctl") {
				if !strings.HasPrefix(call, "systemctl is-active") {
					t.Fatalf("a refused apply ran %q", call)
				}
			}
		})
	}

	// A config that is a symbolic link is refused before anything is read
	// through it.
	h := newRotationHost(t)
	real := h.path("etc/execution-substrate/es-real.json")
	if err := os.Rename(h.path(rotationConfigPaths["es"]), real); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, h.path(rotationConfigPaths["es"])); err != nil {
		t.Fatal(err)
	}
	if _, stderr, code := h.run("apply"); code != 1 || !strings.Contains(stderr, "is a symbolic link") {
		t.Fatalf("apply on a linked es.json: exit %d stderr %s", code, stderr)
	}
}

// TestSigningKeyRotationKeysFromOpenSSL runs apply with the openssl of the
// machine running the test, as the box's /usr/bin/openssl runs it, and
// checks the keys it gives with crypto/ed25519. The rotation runs only on
// the Linux box, whose /usr/bin/openssl is OpenSSL. The /usr/bin/openssl of
// macOS is LibreSSL, whose genpkey has no Ed25519, so the test skips itself
// on any other system. On Linux a missing or unfit openssl fails it.
func TestSigningKeyRotationKeysFromOpenSSL(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the rotation runs only on the Linux box, whose /usr/bin/openssl is OpenSSL")
	}
	h := newRotationHost(t)
	if err := os.Remove(h.path("usr/bin/openssl")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/usr/bin/openssl", h.path("usr/bin/openssl")); err != nil {
		t.Fatal(err)
	}
	stdout, stderr, code := h.run("apply")
	if report := h.report(stdout, stderr, code); code != 0 || report["result"] != "rotated" {
		t.Fatalf("apply with /usr/bin/openssl: exit %d result %v failure %v problems %v\nstderr %s",
			code, report["result"], report["failure"], report["problems"], stderr)
	}
	rotatedSigner(t, "ags", h.doc("ags")["signer"].(map[string]any))
	rotatedSigner(t, "egs", h.doc("egs")["signer"].(map[string]any))
}
