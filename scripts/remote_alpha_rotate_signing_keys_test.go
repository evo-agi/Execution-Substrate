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
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	agsconfig "execution-substrate/ags/config"
	egsconfig "execution-substrate/egs/config"
	egscontract "execution-substrate/egs/contract"
	esconfig "execution-substrate/es/config"
	"execution-substrate/internal/knownkeys"
)

const (
	rotateSigningKeysPython  = "scripts/internal/remote_alpha_rotate_signing_keys.py"
	rotateSigningKeysWrapper = "scripts/remote_alpha_rotate_signing_keys.sh"
	rotationBackupRoot       = "var/backups/execution-substrate-signing-keys"
	rotationIndex            = "var/lib/ars/index.json"
	// The published example seeds, which the box runs on and no output may
	// print.
	agsExampleSeedHex = "1111111111111111111111111111111111111111111111111111111111111111"
	egsExampleSeedHex = "3333333333333333333333333333333333333333333333333333333333333333"
)

// The rotation's fake openssl is this test binary run again: a bash script
// at the path the rotation runs as openssl execs it with this variable set,
// and init answers as openssl would for the two commands the rotation runs.
const fakeOpenSSLEnv = "SIGNING_KEY_ROTATION_FAKE_OPENSSL"

func init() {
	if os.Getenv(fakeOpenSSLEnv) == "1" {
		os.Exit(fakeOpenSSL(os.Args[1:]))
	}
}

// fakeOpenSSL makes an Ed25519 key with crypto/rand, or from the seed in
// FAKE_OPENSSL_SEED_HEX, and logs each call, without its key, to calls.log.
// With openssl-bad-der in the state folder it answers genpkey with bytes
// that are not an Ed25519 key, and with openssl-bad-pub-der it answers pkey
// with bytes that are not an Ed25519 public key.
func fakeOpenSSL(args []string) int {
	state := os.Getenv("FAKE_STATE")
	if log, err := os.OpenFile(filepath.Join(state, "calls.log"), os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600); err == nil {
		fmt.Fprintf(log, "openssl %s\n", strings.Join(args, " "))
		log.Close()
	}
	switch strings.Join(args, " ") {
	case "genpkey -algorithm ED25519 -outform DER":
		if _, err := os.Stat(filepath.Join(state, "openssl-bad-der")); err == nil {
			os.Stdout.Write(make([]byte, 48))
			return 0
		}
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
		if _, err := os.Stat(filepath.Join(state, "openssl-bad-pub-der")); err == nil {
			os.Stdout.Write(make([]byte, 44))
			return 0
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

// The fake systemctl logs every call to calls.log and acts on marker files
// in the state folder:
//
//   - inactive-<unit>: is-active says inactive (stop makes one, start and
//     restart remove it);
//   - execstart-<unit>: show prints this file instead of the unit's usual
//     ExecStart;
//   - fail-<verb>-<unit>-once and fail-<verb>-<unit>-always: the job fails,
//     and leaves the unit as systemd would: running after a failed stop,
//     stopped after a failed start or restart;
//   - stop-leaves-running-<unit>-once: stop answers success but the unit
//     keeps running, as one something starts again at once would;
//   - no-listen-once-<unit>, no-listen-<unit>, listen-delay-<unit>: ARS's and
//     EGS's stand-in listeners, which start and restart run on the port in
//     port-<unit>, do not listen, once or always, or listen after a delay;
//   - signal-<SIG>-at-<verb>-<unit>: after the job, send SIG to the rotation;
//   - symlink-at-<verb>-<unit>: after the job, make the symbolic link named
//     on the file's first line, pointing at its second;
//   - rm-healthcheck-at-es-start-<n>: the nth start of es removes
//     healthcheck.env.
//
// Each start of es is counted in es-starts, and one that finds EGS not
// accepting connections is counted in es-started-before-egs.
const rotationFakeSystemctl = `#!/usr/bin/env bash
set -u
s=%q
root=%q
echo "systemctl $*" >> "$s/calls.log"
stop_listener() {
  local pid
  [[ -e "$s/listener-$1.pid" ]] || return 0
  pid=$(cat "$s/listener-$1.pid")
  rm -f "$s/listener-$1.pid"
  kill "$pid" 2>/dev/null || return 0
  for _ in $(seq 200); do
    kill -0 "$pid" 2>/dev/null || break
    case "$(ps -o stat= -p "$pid" 2>/dev/null)" in Z*) break ;; esac
    sleep 0.01
  done
}
listen() {
  local port delay=0
  port=$(cat "$s/port-$1" 2>/dev/null) || return 0
  stop_listener "$1"
  if [[ -e "$s/no-listen-once-$1" ]]; then rm -f "$s/no-listen-once-$1"; return 0; fi
  [[ -e "$s/no-listen-$1" ]] && return 0
  [[ -e "$s/listen-delay-$1" ]] && delay=$(cat "$s/listen-delay-$1")
  python3 -I -c '
import socket, sys, time
time.sleep(float(sys.argv[2]))
deadline = time.monotonic() + 5
while True:
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.bind(("127.0.0.1", int(sys.argv[1])))
        break
    except OSError:
        s.close()
        if time.monotonic() > deadline:
            raise
        time.sleep(0.02)
s.listen(64)
time.sleep(3600)
' "$port" "$delay" </dev/null >/dev/null 2>&1 &
  echo $! > "$s/listener-$1.pid"
}
case "$1" in
  is-active)
    shift
    for u in "$@"; do if [[ -e "$s/inactive-$u" ]]; then echo inactive; else echo active; fi; done ;;
  show)
    u=${2%%.service}
    if [[ -e "$s/execstart-$u" ]]; then cat "$s/execstart-$u"; else
      echo "ExecStart={ path=/usr/local/lib/execution-substrate/bin/$u ; argv[]=/usr/local/lib/execution-substrate/bin/$u -config /etc/execution-substrate/$u.json ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }"
    fi ;;
  stop|restart|start)
    failed=
    if [[ -e "$s/fail-$1-$2-once" ]]; then rm -f "$s/fail-$1-$2-once"; failed=1; fi
    [[ -e "$s/fail-$1-$2-always" ]] && failed=1
    if [[ -n "$failed" ]]; then
      # As systemd leaves it: a stop that fails leaves the unit running, a
      # restart or start that fails leaves it stopped.
      if [[ "$1" != stop ]]; then touch "$s/inactive-$2"; stop_listener "$2"; fi
      echo "Job for $2.service failed" >&2
      exit 1
    fi
    if [[ "$1" == stop && -e "$s/stop-leaves-running-$2-once" ]]; then
      rm -f "$s/stop-leaves-running-$2-once"
    elif [[ "$1" == stop ]]; then
      touch "$s/inactive-$2"
      stop_listener "$2"
    else
      if [[ "$1 $2" == "start es" ]]; then
        echo x >> "$s/es-starts"
        if port=$(cat "$s/port-egs" 2>/dev/null) && ! (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null; then
          echo x >> "$s/es-started-before-egs"
        fi
        n=$(( $(wc -l < "$s/es-starts") ))
        [[ -e "$s/rm-healthcheck-at-es-start-$n" ]] && rm -f "$root/etc/execution-substrate/healthcheck.env"
      fi
      rm -f "$s/inactive-$2"
      if [[ "$2" == ars || "$2" == egs ]]; then listen "$2"; fi
    fi ;;
  *) echo "fake systemctl: unexpected $*" >&2; exit 2 ;;
esac
if [[ -e "$s/symlink-at-$1-${2:-}" ]]; then
  { read -r link; read -r target; } < "$s/symlink-at-$1-${2:-}"
  rm -f "$s/symlink-at-$1-${2:-}"
  ln -s "$target" "$link"
fi
for sig in TERM HUP INT QUIT KILL; do
  if [[ -e "$s/signal-$sig-at-$1-${2:-}" ]]; then rm -f "$s/signal-$sig-at-$1-${2:-}"; kill -s "$sig" "$PPID"; fi
done
`

// The fake curl refuses to run unless -q comes first, logs the URL, and
// answers 503 with unhealthy in the state folder, with
// unhealthy-after-es-start-1 between the first and the second start of es,
// and for as many requests after the first start of es as slow-es-polls
// says; 200 otherwise.
const rotationFakeCurl = `#!/usr/bin/env bash
set -u
s=%q
if [[ "${1:-}" != "-q" ]]; then echo "fake curl: -q is not the first argument" >&2; exit 99; fi
url="${@: -1}"
echo "curl $url" >> "$s/calls.log"
starts=$(( $(wc -l < "$s/es-starts" 2>/dev/null || echo 0) ))
if [[ -e "$s/unhealthy" ]] || { [[ -e "$s/unhealthy-after-es-start-1" ]] && (( starts == 1 )); }; then
  printf 503
  exit 0
fi
if [[ -e "$s/slow-es-polls" ]] && (( starts >= 1 )); then
  n=$(cat "$s/slow-es-polls")
  if (( n > 0 )); then echo $(( n - 1 )) > "$s/slow-es-polls"; printf 503; exit 0; fi
fi
printf 200
`

type rotationHost struct {
	t      *testing.T
	root   string
	bin    string
	state  string
	helper string
	env    []string
}

var rotationConfigPaths = map[string]string{
	"ags": "etc/execution-substrate/ags.json",
	"egs": "etc/execution-substrate/egs.json",
	"es":  "etc/execution-substrate/es.json",
}

func freeLocalPort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// newRotationHost is the box as the read-only check of 2026-11-27 found it:
// AGS, EGS and ES on the keys of the example configurations, each config
// root:<service> 0640 (under the test, the test user and its group stand in
// for root and every service account), ARS's index with a few records in a
// folder ARS's account owns, and ARS and EGS accepting connections through
// stand-in listeners the fake systemctl runs.
func newRotationHost(t *testing.T) *rotationHost {
	t.Helper()
	base := t.TempDir()
	h := &rotationHost{t: t, root: filepath.Join(base, "root"), bin: filepath.Join(base, "bin"), state: filepath.Join(base, "state"),
		helper: repoPath(rotateSigningKeysPython)}
	for _, dir := range []string{h.bin, h.state, filepath.Join(h.root, "etc/execution-substrate"), filepath.Join(h.root, "var/backups"),
		filepath.Join(h.root, "var/lib/ars"), filepath.Join(h.root, "usr/bin")} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(filepath.Join(h.root, "var/lib/ars"), 0o750); err != nil {
		t.Fatal(err)
	}
	ports := map[string]int{"ars": freeLocalPort(t), "egs": freeLocalPort(t)}
	for name, path := range rotationConfigPaths {
		data, err := os.ReadFile(repoPath(".examples/config/" + name + ".json"))
		if err != nil {
			t.Fatal(err)
		}
		h.write(path, data, 0o640)
	}
	h.edit("egs", func(d map[string]any) { d["http"].(map[string]any)["port"] = ports["egs"] })
	h.writeJSON("etc/execution-substrate/ars.json", map[string]any{
		"http":    map[string]any{"bind_address": "127.0.0.1", "port": ports["ars"]},
		"storage": map[string]any{"root_dir": "/var/lib/ars/blobs", "index_file": "/" + rotationIndex},
	}, 0o640)
	h.writeJSON(rotationIndex, map[string]any{"a": 1, "b": 2, "c": 3}, 0o600)
	h.write("etc/execution-substrate/healthcheck.env",
		[]byte("CA_CERT=/etc/execution-substrate/tls/ca.pem\nOPERATOR_CERT=/etc/x/op.pem\nOPERATOR_KEY=/etc/x/op-key.pem\n"), 0o640)
	for name, script := range map[string]string{
		"systemctl": fmt.Sprintf(rotationFakeSystemctl, h.state, h.root),
		"curl":      fmt.Sprintf(rotationFakeCurl, h.state),
	} {
		if err := os.WriteFile(filepath.Join(h.bin, name), []byte(script), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	h.fakeOpenSSL("")
	t.Cleanup(h.stopListeners)
	for unit, port := range ports {
		if err := os.WriteFile(filepath.Join(h.state, "port-"+unit), []byte(strconv.Itoa(port)), 0o644); err != nil {
			t.Fatal(err)
		}
		start := exec.Command(filepath.Join(h.bin, "systemctl"), "start", unit)
		start.Dir = h.state
		if out, err := start.CombinedOutput(); err != nil {
			t.Fatalf("start the %s stand-in: %v %s", unit, err, out)
		}
		h.waitAccepting(unit, true)
	}
	if err := os.Remove(filepath.Join(h.state, "calls.log")); err != nil {
		t.Fatal(err)
	}
	return h
}

func (h *rotationHost) stopListeners() {
	for _, unit := range []string{"ars", "egs"} {
		data, err := os.ReadFile(filepath.Join(h.state, "listener-"+unit+".pid"))
		if err != nil {
			continue
		}
		if pid, err := strconv.Atoi(strings.TrimSpace(string(data))); err == nil {
			if process, err := os.FindProcess(pid); err == nil {
				_ = process.Kill()
			}
		}
	}
}

func (h *rotationHost) port(unit string) int {
	h.t.Helper()
	data, err := os.ReadFile(filepath.Join(h.state, "port-"+unit))
	if err != nil {
		h.t.Fatal(err)
	}
	port, err := strconv.Atoi(string(data))
	if err != nil {
		h.t.Fatal(err)
	}
	return port
}

func (h *rotationHost) accepting(unit string) bool {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", h.port(unit)), time.Second)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func (h *rotationHost) waitAccepting(unit string, want bool) {
	h.t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for h.accepting(unit) != want {
		if time.Now().After(deadline) {
			h.t.Fatalf("%s accepting connections: want %v", unit, want)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// fakeOpenSSL installs the fake openssl, making keys from seedHex when it
// is not empty. It records the environment it was started with in
// openssl-env.<pid>.
func (h *rotationHost) fakeOpenSSL(seedHex string) {
	h.t.Helper()
	self, err := os.Executable()
	if err != nil {
		h.t.Fatal(err)
	}
	script := fmt.Sprintf("#!/bin/bash\nenv > %q.$$\nexport %s=1 FAKE_STATE=%q FAKE_OPENSSL_SEED_HEX=%q\nexec %q \"$@\"\n",
		filepath.Join(h.state, "openssl-env"), fakeOpenSSLEnv, h.state, seedHex, self)
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

// appendMember adds a member to the end of a config's top-level object as
// text, so that a key may repeat one already there.
func (h *rotationHost) appendMember(rel, member string) {
	h.t.Helper()
	text := strings.TrimRight(string(h.read(rel)), "\n \t")
	text = strings.TrimRight(text[:len(text)-1], "\n \t") + ",\n  " + member + "\n}\n"
	h.write(rel, []byte(text), 0o640)
}

func (h *rotationHost) mark(name string) { h.markWith(name, "") }

func (h *rotationHost) markWith(name, content string) {
	h.t.Helper()
	if err := os.WriteFile(filepath.Join(h.state, name), []byte(content), 0o644); err != nil {
		h.t.Fatal(err)
	}
}

func (h *rotationHost) exists(name string) bool {
	_, err := os.Lstat(filepath.Join(h.state, name))
	return err == nil
}

// snapshot is every file the rotation may change: the three configs and
// ARS's index.
func (h *rotationHost) snapshot() map[string][]byte {
	out := map[string][]byte{}
	for name, rel := range rotationConfigPaths {
		out[name] = h.read(rel)
	}
	out["index"] = h.read(rotationIndex)
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

// serviceCalls is every systemctl call other than the reads.
func (h *rotationHost) serviceCalls() []string {
	var out []string
	for _, call := range h.calls("systemctl") {
		if !strings.HasPrefix(call, "systemctl is-active") && !strings.HasPrefix(call, "systemctl show") {
			out = append(out, call)
		}
	}
	return out
}

func (h *rotationHost) command(args ...string) *exec.Cmd {
	cmd := exec.Command("python3", append([]string{"-I", "-B", h.helper, "--host-root", h.root}, args...)...)
	cmd.Dir = h.state
	cmd.Env = append(append(os.Environ(),
		"SIGNING_KEY_ROTATION_TEST_SYSTEMCTL="+filepath.Join(h.bin, "systemctl"),
		"SIGNING_KEY_ROTATION_TEST_CURL="+filepath.Join(h.bin, "curl"),
		"SIGNING_KEY_ROTATION_TEST_OPENSSL="+h.path("usr/bin/openssl"),
		"SIGNING_KEY_ROTATION_TEST_WAIT_SECONDS=1",
	), h.env...)
	return cmd
}

func (h *rotationHost) run(args ...string) (string, string, int) {
	h.t.Helper()
	cmd := h.command(args...)
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

// apply runs apply and requires it to rotate.
func (h *rotationHost) apply() map[string]any {
	h.t.Helper()
	stdout, stderr, code := h.run("apply")
	report := h.report(stdout, stderr, code)
	if code != 0 || report["result"] != "rotated" {
		h.t.Fatalf("apply exit %d result %v failure %v problems %v\nstderr %s", code, report["result"], report["failure"], report["problems"], stderr)
	}
	return report
}

// requireReady runs check and requires it to find nothing to refuse.
func (h *rotationHost) requireReady() {
	h.t.Helper()
	stdout, stderr, code := h.run("check")
	if report := h.report(stdout, stderr, code); code != 0 || report["result"] != "ready" {
		h.t.Fatalf("check exit %d problems %v\nstderr %s", code, report["problems"], stderr)
	}
}

func (h *rotationHost) backupDirs() []string {
	h.t.Helper()
	entries, err := os.ReadDir(h.path(rotationBackupRoot))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		h.t.Fatal(err)
	}
	var out []string
	for _, entry := range entries {
		out = append(out, filepath.Join(h.path(rotationBackupRoot), entry.Name()))
	}
	return out
}

// tempFiles lists the temporary files the rotation leaves next to the files
// it replaces when it is killed.
func (h *rotationHost) tempFiles() []string {
	h.t.Helper()
	var out []string
	for _, dir := range []string{"etc/execution-substrate", "var/lib/ars"} {
		entries, err := os.ReadDir(h.path(dir))
		if err != nil {
			h.t.Fatal(err)
		}
		for _, entry := range entries {
			if strings.Contains(entry.Name(), ".signing-key-rotation.") {
				out = append(out, filepath.Join(dir, entry.Name()))
			}
		}
	}
	return out
}

func fileModeOf(t *testing.T, path string) os.FileMode {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	return info.Mode()
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
	sort.Strings(out)
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

const rotationOrder = "systemctl stop es | systemctl stop ags | systemctl stop ars | systemctl start ars | systemctl restart egs | systemctl start ags | systemctl start es"

// TestSigningKeyRotationCheckChangesNothing runs check on the box as it is:
// it reports the published keys and every change apply would make, and
// touches nothing.
func TestSigningKeyRotationCheckChangesNothing(t *testing.T) {
	h := newRotationHost(t)
	before := h.snapshot()
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
		"verification.workload_identity_binding", "ARS index /var/lib/ars/index.json: its 3 record(s)", "empty index"} {
		if !strings.Contains(changes, want) {
			t.Fatalf("check's changes do not say %q: %s", want, changes)
		}
	}
	if report["ars_index_entries"] != float64(3) {
		t.Fatalf("check counts %v ARS index entries, want 3", report["ars_index_entries"])
	}
	if !reflect.DeepEqual(h.snapshot(), before) || h.backupDirs() != nil {
		t.Fatal("check changed a config or the index, or wrote a backup")
	}
	if calls := append(h.serviceCalls(), h.calls("openssl")...); len(calls) != 0 {
		t.Fatalf("check ran %q", calls)
	}
	for _, unit := range []string{"ars", "egs", "ags", "es"} {
		want := "systemctl show " + unit + ".service -p ExecStart"
		if !strings.Contains(strings.Join(h.calls("systemctl show"), "\n"), want) {
			t.Fatalf("check did not ask how %s starts", unit)
		}
	}
	for _, secret := range []string{agsExampleSeedHex, egsExampleSeedHex, "private_key_hex"} {
		if strings.Contains(stdout+stderr, secret) {
			t.Fatalf("check printed private key material (%s…)", secret[:8])
		}
	}
}

// TestSigningKeyRotationApplyRotatesAllThreeConfigs runs apply on the box as
// it is, under umask 000, and checks every config it writes, ARS's index,
// the order of the restarts, the backup, and that no output and no child's
// environment holds a private key.
func TestSigningKeyRotationApplyRotatesAllThreeConfigs(t *testing.T) {
	h := newRotationHost(t)
	h.env = append(h.env, "SIGNING_KEY_ROTATION_MARKER=reaches-a-child")
	before := h.snapshot()
	beforeDocs := map[string]map[string]any{"ags": h.doc("ags"), "egs": h.doc("egs"), "es": h.doc("es")}
	// A backup root another run left open to reading: apply makes it 0700.
	if err := os.Mkdir(h.path(rotationBackupRoot), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(h.path(rotationBackupRoot), 0o755); err != nil {
		t.Fatal(err)
	}
	old := syscall.Umask(0)
	stdout, stderr, code := h.run("apply")
	syscall.Umask(old)
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
		if mode := fileModeOf(t, h.path(rel)); mode.Perm() != 0o640 || !mode.IsRegular() {
			t.Fatalf("%s.json after apply: %v, want a regular 0640 file", name, mode)
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

	// ARS's index is empty, with its owner and mode, and the old one is in
	// the backup.
	if got := string(h.read(rotationIndex)); got != "{}\n" {
		t.Fatalf("ARS's index after apply is %q, want an empty object", got)
	}
	if mode := fileModeOf(t, h.path(rotationIndex)); mode.Perm() != 0o600 || !mode.IsRegular() {
		t.Fatalf("ARS's index after apply: %v, want a regular 0600 file", mode)
	}

	if got := strings.Join(h.serviceCalls(), " | "); got != rotationOrder {
		t.Fatalf("apply ran %q, want %q", got, rotationOrder)
	}
	if h.exists("es-started-before-egs") {
		t.Fatal("apply started ES before EGS accepted connections")
	}
	if !h.accepting("ars") || !h.accepting("egs") {
		t.Fatal("ARS's or EGS's stand-in does not accept connections after apply")
	}

	dirs := h.backupDirs()
	if len(dirs) != 1 || !strings.HasSuffix(dirs[0], "-"+agsID) || report["backup_dir"] != dirs[0] {
		t.Fatalf("backups %v, report backup_dir %v", dirs, report["backup_dir"])
	}
	for _, dir := range []string{h.path(rotationBackupRoot), dirs[0]} {
		if mode := fileModeOf(t, dir); mode.Perm() != 0o700 {
			t.Fatalf("%s mode %v, want 0700", dir, mode)
		}
	}
	copies := map[string][]byte{"egs.json": before["egs"], "ags.json": before["ags"], "es.json": before["es"], "ars-index.json": before["index"]}
	for name, data := range copies {
		copyPath := filepath.Join(dirs[0], name)
		if mode := fileModeOf(t, copyPath); mode.Perm() != 0o600 {
			t.Fatalf("backup copy %s: %v, want 0600", name, mode)
		}
		if got, _ := os.ReadFile(copyPath); !bytes.Equal(got, data) {
			t.Fatalf("backup copy %s is not the file before the rotation", name)
		}
	}
	for _, name := range []string{"manifest.json", "ars-index.manifest.json", "summary.json"} {
		if mode := fileModeOf(t, filepath.Join(dirs[0], name)); mode.Perm() != 0o600 {
			t.Fatalf("%s: %v, want 0600", name, mode)
		}
	}
	var manifest struct {
		Files []map[string]any `json:"files"`
	}
	data, err := os.ReadFile(filepath.Join(dirs[0], "manifest.json"))
	if err != nil || json.Unmarshal(data, &manifest) != nil || len(manifest.Files) != 3 {
		t.Fatalf("backup manifest: %v %s", err, data)
	}
	for _, entry := range manifest.Files {
		name := strings.TrimSuffix(entry["copy"].(string), ".json")
		if entry["sha256"] != sha256Hex(before[name]) || entry["rotated_sha256"] != sha256Hex(h.read(rotationConfigPaths[name])) {
			t.Fatalf("manifest entry %v does not record the config before and after", entry)
		}
	}
	summary, err := os.ReadFile(filepath.Join(dirs[0], "summary.json"))
	if err != nil {
		t.Fatal(err)
	}
	outputs := stdout + stderr + string(summary) + string(data)
	for _, secret := range []string{agsSeed, egsSeed, agsExampleSeedHex, egsExampleSeedHex, "private_key_hex"} {
		if strings.Contains(outputs, secret) {
			t.Fatalf("apply printed or summarised private key material (%s…)", secret[:8])
		}
	}
	newKeys := report["new"].(map[string]any)
	if newKeys["ags"].(map[string]any)["key_id"] != agsID || newKeys["egs"].(map[string]any)["key_id"] != egsID {
		t.Fatalf("report names new keys %v", newKeys)
	}
	if got := len(h.calls("openssl genpkey")); got != 2 {
		t.Fatalf("apply made %d keys, want 2", got)
	}
	// openssl gets only PATH and LC_ALL from the rotation.
	envs, _ := filepath.Glob(filepath.Join(h.state, "openssl-env.*"))
	if len(envs) != 4 {
		t.Fatalf("openssl ran %d times, want 4", len(envs))
	}
	for _, path := range envs {
		env, _ := os.ReadFile(path)
		if strings.Contains(string(env), "SIGNING_KEY_ROTATION") || !strings.Contains(string(env), "LC_ALL=C") {
			t.Fatalf("openssl's environment is not the rotation's own:\n%s", env)
		}
	}
	h.requireReady()
}

// TestSigningKeyRotationRollsBack makes a step after the configs are
// written fail: apply puts every config and the index back, starts the
// services on them, and exits 1 without calling the host unchanged.
func TestSigningKeyRotationRollsBack(t *testing.T) {
	for _, tc := range []struct{ name, marker, failure string }{
		{"ES does not answer after the restart", "unhealthy-after-es-start-1", "do not all run and answer"},
		{"AGS does not start", "fail-start-ags-once", "systemctl start ags failed"},
		{"EGS does not restart", "fail-restart-egs-once", "systemctl restart egs failed"},
		{"ES does not start", "fail-start-es-once", "systemctl start es failed"},
		{"ARS does not start", "fail-start-ars-once", "systemctl start ars failed"},
		{"ARS does not stop", "fail-stop-ars-once", "systemctl stop ars failed"},
		// ARS must not be running while its index is replaced, so a stop
		// that reports success but leaves it running stops the rotation
		// before the index is touched.
		{"ARS still runs after a stop that succeeded", "stop-leaves-running-ars-once", "ars is active after systemctl stop ars"},
		{"EGS does not accept connections after its restart", "no-listen-once-egs", "EGS does not accept connections"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newRotationHost(t)
			before := h.snapshot()
			h.mark(tc.marker)
			stdout, stderr, code := h.run("apply")
			report := h.report(stdout, stderr, code)
			if code != 1 || report["result"] != "rolled_back" {
				t.Fatalf("apply exit %d result %v failure %v steps %v\nstderr %s", code, report["result"], report["failure"], report["rollback_steps"], stderr)
			}
			if strings.Contains(stderr, "refused") || !strings.Contains(stderr, "result rolled_back") {
				t.Fatalf("apply's last line does not say it rolled back: %s", stderr)
			}
			if failure, _ := report["failure"].(string); !strings.Contains(failure, tc.failure) {
				t.Fatalf("apply failed with %q, want it to name %q", failure, tc.failure)
			}
			if !reflect.DeepEqual(h.snapshot(), before) {
				t.Fatal("the configs or the index are not the ones before the rotation after the rollback")
			}
			for name, rel := range map[string]string{"ags": rotationConfigPaths["ags"], "index": rotationIndex} {
				want := os.FileMode(0o640)
				if name == "index" {
					want = 0o600
				}
				if mode := fileModeOf(t, h.path(rel)); mode.Perm() != want {
					t.Fatalf("%s after the rollback: %v, want %v", name, mode, want)
				}
			}
			calls := h.serviceCalls()
			if got := strings.Join(calls[len(calls)-7:], " | "); got != rotationOrder {
				t.Fatalf("the rollback ran %q, want %q", got, rotationOrder)
			}
			if !h.accepting("ars") || !h.accepting("egs") {
				t.Fatal("ARS's or EGS's stand-in does not accept connections after the rollback")
			}
			dirs := h.backupDirs()
			if len(dirs) != 1 {
				t.Fatal("the rollback left no backup")
			}
			if _, err := os.Stat(filepath.Join(dirs[0], "summary.json")); err != nil {
				t.Fatal("the rollback wrote no summary")
			}
			h.requireReady()
		})
	}
}

// TestSigningKeyRotationRechecksEachConfigBeforeWritingIt changes es.json
// after the backup is written and before apply writes the configs, as
// someone editing it by hand would. apply writes egs.json and ags.json,
// finds es.json changed, writes nothing over it, and rolls back the two it
// wrote, so the edit is kept and nothing else changes.
func TestSigningKeyRotationRechecksEachConfigBeforeWritingIt(t *testing.T) {
	h := newRotationHost(t)
	before := h.snapshot()
	marker := filepath.Join(h.state, "paused")
	h.env = []string{"SIGNING_KEY_ROTATION_TEST_PAUSE_AT=backup-written", "SIGNING_KEY_ROTATION_TEST_PAUSE_MARKER=" + marker}
	cmd := h.command("apply")
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill() })
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()
	paused := make(chan struct{})
	go func() {
		for deadline := time.Now().Add(60 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
			if _, err := os.Lstat(marker); err == nil {
				close(paused)
				return
			}
		}
	}()
	select {
	case err := <-exited:
		t.Fatalf("apply ended (%v) before it reached the pause\nstdout %s\nstderr %s", err, stdout.String(), stderr.String())
	case <-paused:
	case <-time.After(60 * time.Second):
		t.Fatal("apply did not reach the pause")
	}
	esPath := h.path(rotationConfigPaths["es"])
	edited := append(h.read(rotationConfigPaths["es"]), '\n')
	if err := os.WriteFile(esPath, edited, 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(marker); err != nil {
		t.Fatal(err)
	}
	runErr := <-exited
	code := 0
	if exitErr, ok := runErr.(*exec.ExitError); ok {
		code = exitErr.ExitCode()
	} else if runErr != nil {
		t.Fatal(runErr)
	}
	report := h.report(stdout.String(), stderr.String(), code)
	if failure, _ := report["failure"].(string); code != 1 || report["result"] != "rolled_back" ||
		!strings.Contains(failure, "/etc/execution-substrate/es.json changed while apply ran") {
		t.Fatalf("apply exit %d result %v failure %v\nstderr %s", code, report["result"], report["failure"], stderr.String())
	}
	var written []string
	events, _ := report["events"].([]any)
	for _, event := range events {
		if text, _ := event.(map[string]any)["event"].(string); strings.HasSuffix(text, ".json written") {
			written = append(written, text)
		}
	}
	if want := []string{"/etc/execution-substrate/egs.json written", "/etc/execution-substrate/ags.json written"}; !reflect.DeepEqual(written, want) {
		t.Fatalf("apply wrote %v before it found es.json changed, want %v", written, want)
	}
	after := h.snapshot()
	if !bytes.Equal(after["es"], edited) {
		t.Fatal("apply wrote over the es.json someone changed while it ran")
	}
	after["es"] = before["es"]
	if !reflect.DeepEqual(after, before) {
		t.Fatal("the rollback did not put egs.json, ags.json and the index back")
	}
	if left := h.tempFiles(); len(left) != 0 {
		t.Fatalf("the rollback left %v", left)
	}
	h.requireReady()
}

// TestSigningKeyRotationRollbackCommand puts a rotation's backup back with
// the configs' owner and mode and the index, and records that it did.
func TestSigningKeyRotationRollbackCommand(t *testing.T) {
	h := newRotationHost(t)
	before := h.snapshot()
	report := h.apply()
	backup := report["backup_dir"].(string)
	h.write(rotationIndex, []byte("{\"published-after-the-rotation\": 1}\n"), 0o600)
	stdout, stderr, code := h.run("rollback", "--backup-dir", backup)
	result := h.report(stdout, stderr, code)
	if code != 0 || result["result"] != "rolled_back" {
		t.Fatalf("rollback exit %d result %v steps %v\nstderr %s", code, result["result"], result["rollback_steps"], stderr)
	}
	if !reflect.DeepEqual(h.snapshot(), before) {
		t.Fatal("rollback did not put the configs and the index back")
	}
	for _, rel := range rotationConfigPaths {
		if mode := fileModeOf(t, h.path(rel)); mode.Perm() != 0o640 {
			t.Fatalf("%s after the rollback: %v, want 0640", rel, mode)
		}
	}
	if mode := fileModeOf(t, h.path(rotationIndex)); mode.Perm() != 0o600 {
		t.Fatalf("the index after the rollback: %v, want 0600", mode)
	}
	newAGS := report["new"].(map[string]any)["ags"].(map[string]any)["key_id"]
	if !strings.Contains(stderr, "putting back AGS key ags-key-1 and EGS key egs-key-1") || !strings.Contains(stderr, fmt.Sprintf("now %v", newAGS)) {
		t.Fatalf("rollback did not say which keys it puts back: %s", stderr)
	}
	calls := h.serviceCalls()
	if got := strings.Join(calls[len(calls)-7:], " | "); got != rotationOrder {
		t.Fatalf("rollback ran %q, want %q", got, rotationOrder)
	}
	if _, err := os.Stat(filepath.Join(backup, "rollback.json")); err != nil {
		t.Fatal("rollback wrote no record into the backup")
	}
	h.requireReady()
	if _, _, code := h.run("rollback", "--backup-dir", h.path("var/backups")); code != 1 {
		t.Fatalf("rollback of a folder that is not a backup exited %d, want 1", code)
	}
}

// TestSigningKeyRotationRollbackRefusesABackupThatIsNotTheLatest: a rollback
// puts a backup back only over the configs its own rotation wrote (or over
// its own copies), so a backup from two rotations ago, or one older than a
// later config change, is refused with nothing changed.
func TestSigningKeyRotationRollbackRefusesABackupThatIsNotTheLatest(t *testing.T) {
	h := newRotationHost(t)
	first := h.apply()["backup_dir"].(string)
	h.apply()
	before := h.snapshot()
	stdout, stderr, code := h.run("rollback", "--backup-dir", first)
	if code != 1 || !strings.Contains(stderr, "not the latest rotation's") || stdout != "" {
		t.Fatalf("rollback of the first of two rotations: exit %d\nstdout %s\nstderr %s", code, stdout, stderr)
	}
	if !reflect.DeepEqual(h.snapshot(), before) || len(h.serviceCalls()) != 14 {
		t.Fatal("a refused rollback changed a file or a service")
	}

	other := newRotationHost(t)
	backup := other.apply()["backup_dir"].(string)
	other.edit("es", func(d map[string]any) { d["http"].(map[string]any)["read_timeout_seconds"] = 7 })
	before = other.snapshot()
	if _, stderr, code := other.run("rollback", "--backup-dir", backup); code != 1 || !strings.Contains(stderr, "es.json is neither") {
		t.Fatalf("rollback over a config changed after the rotation: exit %d stderr %s", code, stderr)
	}
	if !reflect.DeepEqual(other.snapshot(), before) {
		t.Fatal("a refused rollback changed a file")
	}
}

// TestSigningKeyRotationRollbackRefusesABrokenBackup checks the whole backup
// before it changes anything: a manifest with the wrong shape or types, a
// copy changed after the manifest, a folder others can read, and owners or
// modes the rotation does not restore.
func TestSigningKeyRotationRollbackRefusesABrokenBackup(t *testing.T) {
	editManifest := func(name string, change func(m map[string]any)) func(*rotationHost, string) {
		return func(h *rotationHost, backup string) {
			path := filepath.Join(backup, name)
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var m map[string]any
			if err := json.Unmarshal(data, &m); err != nil {
				t.Fatal(err)
			}
			change(m)
			out, _ := json.Marshal(m)
			if err := os.WriteFile(path, out, 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	entry := func(m map[string]any, i int) map[string]any { return m["files"].([]any)[i].(map[string]any) }
	for _, tc := range []struct {
		name   string
		break_ func(*rotationHost, string)
		want   string
	}{
		{"files is not a list", editManifest("manifest.json", func(m map[string]any) { m["files"] = "x" }), "does not list the three configs"},
		{"an entry is a string", editManifest("manifest.json", func(m map[string]any) { m["files"].([]any)[1] = "x" }), "does not have exactly the fields"},
		{"an entry has no size", editManifest("manifest.json", func(m map[string]any) { delete(entry(m, 2), "size") }), "does not have exactly the fields"},
		{"a uid is a string", editManifest("manifest.json", func(m map[string]any) { entry(m, 1)["uid"] = "0" }), "owner or mode"},
		{"a mode others can read", editManifest("manifest.json", func(m map[string]any) { entry(m, 0)["mode"] = "0644" }), "owner or mode"},
		{"the configs out of order", editManifest("manifest.json", func(m map[string]any) {
			files := m["files"].([]any)
			files[0], files[1] = files[1], files[0]
		}), "in order"},
		{"an extra field", editManifest("manifest.json", func(m map[string]any) { m["extra"] = 1 }), "does not have exactly the fields"},
		{"another schema", editManifest("manifest.json", func(m map[string]any) { m["schema"] = "x" }), "not one of this rotation"},
		{"a copy changed after the manifest", func(h *rotationHost, backup string) {
			if err := os.WriteFile(filepath.Join(backup, "es.json"), []byte("{}\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		}, "does not match its manifest"},
		{"the index copy changed", func(h *rotationHost, backup string) {
			if err := os.WriteFile(filepath.Join(backup, "ars-index.json"), []byte("{}\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		}, "index does not match its manifest"},
		{"the index manifest names another file", editManifest("ars-index.manifest.json", func(m map[string]any) { m["path"] = "/etc/shadow" }), "names another index"},
		{"the index manifest gives a mode others can write", editManifest("ars-index.manifest.json", func(m map[string]any) { m["mode"] = "0666" }), "owner or mode"},
		{"the folder others can read", func(h *rotationHost, backup string) {
			if err := os.Chmod(backup, 0o755); err != nil {
				t.Fatal(err)
			}
		}, "0700 folder root owns"},
		{"the manifest is a link", func(h *rotationHost, backup string) {
			path := filepath.Join(backup, "manifest.json")
			if err := os.Rename(path, path+".real"); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(path+".real", path); err != nil {
				t.Fatal(err)
			}
		}, "symbolic link"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newRotationHost(t)
			backup := h.apply()["backup_dir"].(string)
			tc.break_(h, backup)
			before := h.snapshot()
			calls := len(h.serviceCalls())
			stdout, stderr, code := h.run("rollback", "--backup-dir", backup)
			if code != 1 || !strings.Contains(stderr, "refused") || !strings.Contains(stderr, tc.want) {
				t.Fatalf("rollback exit %d, want 1 refusing with %q\nstdout %s\nstderr %s", code, tc.want, stdout, stderr)
			}
			if !reflect.DeepEqual(h.snapshot(), before) || len(h.serviceCalls()) != calls {
				t.Fatal("a refused rollback changed a file or a service")
			}
		})
	}
}

// TestSigningKeyRotationUpdatesWorkloadGrants gives es.json workload grants
// that name the AGS key: apply moves each to the new key, and refuses a
// grant that names another key.
func TestSigningKeyRotationUpdatesWorkloadGrants(t *testing.T) {
	// ES's config loader in this tree does not read workload grants, so the
	// rules below carry only the fields the rotation touches and the rotated
	// es.json is not loaded with them. Once the grants loader is here
	// (es/config/workload_grants.go), this test must use rules of the shape
	// it loads and require esconfig.Load to accept the rotated es.json; it
	// fails until it does.
	if _, err := os.Stat(repoPath("es/config/workload_grants.go")); err == nil {
		t.Fatal("es/config loads workload grants now: give these rules its shape and load the rotated es.json with esconfig.Load")
	} else if !os.IsNotExist(err) {
		t.Fatal(err)
	}
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
	h.apply()
	agsID := h.doc("ags")["signer"].(map[string]any)["key_id"]
	for _, rule := range h.doc("es")["admission_policy"].(map[string]any)["workload_grants"].(map[string]any)["rules"].([]any) {
		if rule.(map[string]any)["signer_key_id"] != agsID {
			t.Fatalf("grant %v does not name the new AGS key %v", rule, agsID)
		}
	}

	other := newRotationHost(t)
	other.edit("es", grants("ags-key-1", "ags-other"))
	before := other.snapshot()
	stdout, stderr, code := other.run("apply")
	report := other.report(stdout, stderr, code)
	if code != 1 || !strings.Contains(fmt.Sprint(report["problems"]), "rule-1") || !reflect.DeepEqual(other.snapshot(), before) {
		t.Fatalf("apply on a grant naming another key: exit %d problems %v", code, report["problems"])
	}
}

// TestSigningKeyRotationRefuses gives check and apply hosts they were not
// written for: each refuses, changes nothing, makes no backup and restarts
// nothing.
func TestSigningKeyRotationRefuses(t *testing.T) {
	signer := `{"algorithm": "ed25519", "key_id": "shadow-ags", "private_key_hex": "` + strings.Repeat("ab", 32) +
		`", "public_key_hex": "` + strings.Repeat("cd", 32) + `"}`
	for _, tc := range []struct {
		name      string
		setup     func(*rotationHost)
		want      string
		applyOnly bool
		noReport  bool
	}{
		{"ES trusts another provenance key", func(h *rotationHost) {
			h.edit("es", func(d map[string]any) {
				d["verification"].(map[string]any)["provenance"].(map[string]any)["key_id"] = "ags-other"
			})
		}, "verification.provenance is not AGS's signer key", false, false},
		{"ES trusts another EGS key", func(h *rotationHost) {
			h.edit("es", func(d map[string]any) {
				d["verification"].(map[string]any)["trust_model"].(map[string]any)["public_key_hex"] = strings.Repeat("ab", 32)
			})
		}, "verification.trust_model is not EGS's signer key", false, false},
		{"ES has a fifth verification entry", func(h *rotationHost) {
			h.edit("es", func(d map[string]any) {
				v := d["verification"].(map[string]any)
				v["a_fifth_entry"] = v["provenance"]
			})
		}, "not exactly", false, false},
		{"AGS's signer spelled twice in letter case", func(h *rotationHost) {
			h.appendMember(rotationConfigPaths["ags"], `"Signer": `+signer)
		}, "differ only in letter case", false, false},
		{"ES's verification spelled twice in letter case", func(h *rotationHost) {
			h.appendMember(rotationConfigPaths["es"], `"VERIFICATION": {}`)
		}, "differ only in letter case", false, false},
		{"AGS's signer spelled with a long s", func(h *rotationHost) {
			h.appendMember(rotationConfigPaths["ags"], `"ſigner": `+signer)
		}, "is not ASCII", false, false},
		{"AGS's signer twice", func(h *rotationHost) {
			h.appendMember(rotationConfigPaths["ags"], `"signer": `+signer)
		}, "appears twice", false, false},
		{"a config with NaN", func(h *rotationHost) {
			h.appendMember(rotationConfigPaths["egs"], `"x": NaN`)
		}, "NaN is not JSON", false, false},
		// Go reads \ud800 alone as U+FFFD; Python keeps it and could not
		// write the config back, so check must refuse what apply cannot do
		// (audit S76-2).
		{"a config with half a surrogate pair", func(h *rotationHost) {
			h.appendMember(rotationConfigPaths["es"], `"audit_note": "a\ud800b"`)
		}, "half a UTF-16 surrogate pair", false, false},
		{"a config with a number too large for the services", func(h *rotationHost) {
			h.appendMember(rotationConfigPaths["egs"], `"audit_note": 1e400`)
		}, "too large for the services to read", false, false},
		{"a config that is not UTF-8", func(h *rotationHost) {
			h.appendMember(rotationConfigPaths["egs"], "\"audit_note\": \"x\xffy\"")
		}, "egs.json is not UTF-8", false, false},
		{"EGS's signer policy has a field the rotation does not know", func(h *rotationHost) {
			h.edit("egs", func(d map[string]any) {
				d["runtime_trust"].(map[string]any)["signer_policy"].(map[string]any)["allowed_signers_next"] = []any{"ags-key-1"}
			})
		}, "signer_policy has fields other than", false, false},
		{"AGS's signer with an extra field", func(h *rotationHost) {
			h.edit("ags", func(d map[string]any) { d["signer"].(map[string]any)["extra"] = "x" })
		}, "not exactly", false, false},
		{"EGS does not allow AGS", func(h *rotationHost) {
			h.edit("egs", func(d map[string]any) {
				d["runtime_trust"].(map[string]any)["signer_policy"].(map[string]any)["allowed_signers"] = []any{"ags-other"}
			})
		}, "does not allow AGS's signer key ID", false, false},
		{"EGS has no publication revision", func(h *rotationHost) {
			h.edit("egs", func(d map[string]any) { delete(d, "publication") })
		}, "publication.update_revision", false, false},
		{"AGS and EGS share a key", func(h *rotationHost) {
			egs := h.doc("egs")["signer"].(map[string]any)
			h.edit("ags", func(d map[string]any) {
				signer := d["signer"].(map[string]any)
				signer["private_key_hex"], signer["public_key_hex"] = egs["private_key_hex"], egs["public_key_hex"]
			})
		}, "AGS and EGS sign with the same key", false, false},
		{"es.json is world-readable", func(h *rotationHost) {
			if err := os.Chmod(h.path(rotationConfigPaths["es"]), 0o644); err != nil {
				t.Fatal(err)
			}
		}, "es.json is not root:es 0640", false, false},
		{"ars.json is world-readable", func(h *rotationHost) {
			if err := os.Chmod(h.path("etc/execution-substrate/ars.json"), 0o644); err != nil {
				t.Fatal(err)
			}
		}, "ars.json is not root:ars 0640", false, false},
		{"es.json has a second link", func(h *rotationHost) {
			if err := os.Link(h.path(rotationConfigPaths["es"]), h.path("etc/execution-substrate/es.json.old")); err != nil {
				t.Fatal(err)
			}
		}, "with one link", false, false},
		{"es.json is in another group", func(h *rotationHost) {
			h.env = append(h.env, fmt.Sprintf("SIGNING_KEY_ROTATION_TEST_GID_ES=%d", os.Getgid()+1))
		}, "es.json is not root:es 0640", false, false},
		{"the configs belong to someone other than root", func(h *rotationHost) {
			h.env = append(h.env, fmt.Sprintf("SIGNING_KEY_ROTATION_TEST_ROOT_UID=%d", os.Getuid()+1))
		}, "ags.json is not root:ags 0640", false, false},
		{"others can write the config folder", func(h *rotationHost) {
			if err := os.Chmod(h.path("etc/execution-substrate"), 0o777); err != nil {
				t.Fatal(err)
			}
		}, "the folder /etc/execution-substrate is writable by its group or others", false, false},
		{"others can write healthcheck.env", func(h *rotationHost) {
			if err := os.Chmod(h.path("etc/execution-substrate/healthcheck.env"), 0o666); err != nil {
				t.Fatal(err)
			}
		}, "healthcheck.env is not a file root owns", false, false},
		{"healthcheck.env has a second link", func(h *rotationHost) {
			if err := os.Link(h.path("etc/execution-substrate/healthcheck.env"), h.path("var/healthcheck-second-name")); err != nil {
				t.Fatal(err)
			}
		}, "healthcheck.env is not a file root owns with one link", false, false},
		{"EGS starts with another config", func(h *rotationHost) {
			h.markWith("execstart-egs", "ExecStart={ path=/usr/local/lib/execution-substrate/bin/egs ; argv[]=/usr/local/lib/execution-substrate/bin/egs -config /etc/execution-substrate/egs.unit.json ; ignore_errors=no }\n")
		}, "egs.service does not start /usr/local/lib/execution-substrate/bin/egs with -config /etc/execution-substrate/egs.json", false, false},
		// With systemd's @ prefix, argv[0] is only the name the program gets;
		// path= is what runs (Opus re-audit F2).
		{"ES runs another program under its binary's name", func(h *rotationHost) {
			h.markWith("execstart-es", "ExecStart={ path=/usr/local/sbin/es-shim ; argv[]=/usr/local/lib/execution-substrate/bin/es -config /etc/execution-substrate/es.json ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }\n")
		}, "es.service does not start /usr/local/lib/execution-substrate/bin/es with -config /etc/execution-substrate/es.json (its ExecStart runs /usr/local/sbin/es-shim as", false, false},
		{"ARS's ExecStart is not in the form systemctl show prints", func(h *rotationHost) {
			h.markWith("execstart-ars", "ExecStart=/usr/local/lib/execution-substrate/bin/ars -config /etc/execution-substrate/ars.json\n")
		}, "ars.service does not start /usr/local/lib/execution-substrate/bin/ars", false, false},
		{"AGS starts two commands", func(h *rotationHost) {
			line := "ExecStart={ path=/usr/local/lib/execution-substrate/bin/ags ; argv[]=/usr/local/lib/execution-substrate/bin/ags -config /etc/execution-substrate/ags.json ; ignore_errors=no }\n"
			h.markWith("execstart-ags", line+line)
		}, "ags.service has 2 ExecStart commands", false, false},
		{"ARS's index folder is a link", func(h *rotationHost) {
			if err := os.Rename(h.path("var/lib/ars"), h.path("var/lib/ars-real")); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(h.path("var/lib/ars-real"), h.path("var/lib/ars")); err != nil {
				t.Fatal(err)
			}
		}, "the folder /var/lib/ars is a symbolic link or not a folder", false, false},
		{"others can write ARS's index folder", func(h *rotationHost) {
			if err := os.Chmod(h.path("var/lib/ars"), 0o777); err != nil {
				t.Fatal(err)
			}
		}, "the folder /var/lib/ars is writable by its group or others", false, false},
		{"others can write ARS's index", func(h *rotationHost) {
			if err := os.Chmod(h.path(rotationIndex), 0o620); err != nil {
				t.Fatal(err)
			}
		}, "index.json is writable by its group or others", false, false},
		{"ARS's index path is not in normal form", func(h *rotationHost) {
			data := bytes.Replace(h.read("etc/execution-substrate/ars.json"), []byte(`/var/lib/ars/index.json`), []byte(`/var/lib/ars/../ars/index.json`), 1)
			h.write("etc/execution-substrate/ars.json", data, 0o640)
		}, "storage.index_file is not an absolute path in normal form", false, false},
		// Above the index's own folder only root may own a folder: ARS's
		// account could otherwise swap the index folder.
		{"a folder above ARS's index folder belongs to ARS's account", func(h *rotationHost) {
			h.env = append(h.env, fmt.Sprintf("SIGNING_KEY_ROTATION_TEST_UID_ARS=%d", os.Getuid()),
				fmt.Sprintf("SIGNING_KEY_ROTATION_TEST_ROOT_UID=%d", os.Getuid()+1))
		}, fmt.Sprintf("the folder /var/lib belongs to uid %d", os.Getuid()), false, false},
		{"ARS's index has a second link", func(h *rotationHost) {
			if err := os.Link(h.path(rotationIndex), h.path("var/lib/ars/index.json.old")); err != nil {
				t.Fatal(err)
			}
		}, "index.json has 2 links", false, false},
		{"ARS's index belongs to another account", func(h *rotationHost) {
			h.env = append(h.env, fmt.Sprintf("SIGNING_KEY_ROTATION_TEST_UID_ARS=%d", os.Getuid()+1),
				fmt.Sprintf("SIGNING_KEY_ROTATION_TEST_ROOT_UID=%d", os.Getuid()+2))
		}, "not ARS's account or root", false, false},
		{"ARS's index is nested too deeply to count", func(h *rotationHost) {
			h.write(rotationIndex, []byte(strings.Repeat("[", 200000)+strings.Repeat("]", 200000)), 0o600)
			h.edit("es", func(d map[string]any) { delete(d, "verification") })
		}, "es.json has no verification object", false, false},
		{"a rotation did not finish", func(h *rotationHost) {
			if err := os.MkdirAll(h.path(rotationBackupRoot+"/20261127T000000Z-ags-x"), 0o700); err != nil {
				t.Fatal(err)
			}
		}, "a rotation did not finish", false, false},
		// A rollback writes rollback-started.json before it changes
		// anything and rollback.json, with the same ID, when it ends (Opus
		// re-audit F3).
		{"a rollback did not finish", func(h *rotationHost) {
			dir := rotationBackupRoot + "/20261127T000000Z-ags-x"
			if err := os.MkdirAll(h.path(dir), 0o700); err != nil {
				t.Fatal(err)
			}
			h.writeJSON(dir+"/summary.json", map[string]any{"result": "rotated"}, 0o600)
			h.writeJSON(dir+"/rollback-started.json", map[string]any{"rollback_id": "second"}, 0o600)
			h.writeJSON(dir+"/rollback.json", map[string]any{"result": "rollback_failed", "rollback_id": "first"}, 0o600)
		}, "a rollback of /var/backups/execution-substrate-signing-keys/20261127T000000Z-ags-x did not finish", false, false},
		{"a rollback did not finish: it could not put everything back", func(h *rotationHost) {
			dir := rotationBackupRoot + "/20261127T000000Z-ags-x"
			if err := os.MkdirAll(h.path(dir), 0o700); err != nil {
				t.Fatal(err)
			}
			h.writeJSON(dir+"/summary.json", map[string]any{"result": "rotated"}, 0o600)
			h.writeJSON(dir+"/rollback-started.json", map[string]any{"rollback_id": "first"}, 0o600)
			h.writeJSON(dir+"/rollback.json", map[string]any{"result": "rollback_failed", "rollback_id": "first"}, 0o600)
		}, "could not put everything back (rollback_failed)", false, false},
		{"a rotation did not finish: its own rollback could not put everything back", func(h *rotationHost) {
			if err := os.MkdirAll(h.path(rotationBackupRoot+"/20261127T000000Z-ags-x"), 0o700); err != nil {
				t.Fatal(err)
			}
			h.writeJSON(rotationBackupRoot+"/20261127T000000Z-ags-x/summary.json", map[string]any{"result": "rollback_failed"}, 0o600)
		}, "could not put everything back (rollback_failed)", false, false},
		{"an apply stopped while it made its backup", func(h *rotationHost) {
			if err := os.MkdirAll(h.path(rotationBackupRoot+"/.incomplete-20261127T000000Z-ags-x"), 0o700); err != nil {
				t.Fatal(err)
			}
		}, "stopped before it changed anything", false, false},
		{"a rotation left a temporary file", func(h *rotationHost) {
			h.write("etc/execution-substrate/.es.json.signing-key-rotation.0123456789abcdef", []byte("{}"), 0o640)
		}, "was left by a rotation that was stopped", false, false},
		{"ARS is not running", func(h *rotationHost) { h.mark("inactive-ars") }, "must all run", false, false},
		{"EGS does not accept connections", func(h *rotationHost) {
			h.stopListeners()
			h.waitAccepting("egs", false)
		}, "must all run", false, false},
		{"ES does not answer", func(h *rotationHost) { h.mark("unhealthy") }, "must all run", false, false},
		{"openssl gives a known key", func(h *rotationHost) { h.fakeOpenSSL(strings.Repeat("11", 32)) }, "known key", true, true},
		{"openssl gives AGS and EGS the same key", func(h *rotationHost) {
			h.fakeOpenSSL("8f1d2c3b4a596877e6d5c4b3a2918f7e6d5c4b3a29180716253443526170819a")
		}, "openssl gave AGS and EGS the same key", true, true},
		{"others can write the folder above the backup root", func(h *rotationHost) {
			if err := os.Chmod(h.path("var/backups"), 0o777); err != nil {
				t.Fatal(err)
			}
		}, "the folder /var/backups is writable by its group or others", true, true},
		// A backup that fails before it is complete leaves no folder.
		{"the disk fills while the backup is written", func(h *rotationHost) {
			h.env = append(h.env, "SIGNING_KEY_ROTATION_TEST_FAIL_AT=backup-written")
		}, "No space left on device; nothing was changed", true, true},
		{"openssl gives something other than an Ed25519 key", func(h *rotationHost) { h.mark("openssl-bad-der") },
			"did not give an Ed25519 PKCS #8 private key", true, true},
		{"openssl gives something other than an Ed25519 public key", func(h *rotationHost) { h.mark("openssl-bad-pub-der") },
			"did not give an Ed25519 public key", true, true},
	} {
		for _, mode := range []string{"check", "apply"} {
			if tc.applyOnly && mode == "check" {
				continue
			}
			t.Run(tc.name+"/"+mode, func(t *testing.T) {
				h := newRotationHost(t)
				tc.setup(h)
				before := h.snapshot()
				stdout, stderr, code := h.run(mode)
				if code != 1 || !strings.Contains(stdout+stderr, tc.want) || !strings.Contains(stderr, "refused") ||
					strings.Contains(stderr, "Traceback") {
					t.Fatalf("%s exit %d, want 1 naming %q\nstdout %s\nstderr %s", mode, code, tc.want, stdout, stderr)
				}
				if !tc.noReport {
					h.report(stdout, stderr, code)
				}
				if !reflect.DeepEqual(h.snapshot(), before) {
					t.Fatal("a refusal changed a config or the index")
				}
				if dirs := h.backupDirs(); len(dirs) > 0 && !strings.Contains(tc.name, "did not finish") && !strings.Contains(tc.name, "stopped while") {
					t.Fatalf("a refusal left a backup: %v", dirs)
				}
				if calls := h.serviceCalls(); len(calls) != 0 {
					t.Fatalf("a refusal ran %q", calls)
				}
			})
		}
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
	if stdout, stderr, code := h.run("apply"); code != 1 || !strings.Contains(stdout, "is a symbolic link") {
		t.Fatalf("apply on a linked es.json: exit %d stdout %s stderr %s", code, stdout, stderr)
	}
}

// TestSigningKeyRotationIndexCountIsAdvisory: an index that cannot be
// counted (nested too deeply for Python's parser) leaves the count empty and
// stops nothing.
func TestSigningKeyRotationIndexCountIsAdvisory(t *testing.T) {
	h := newRotationHost(t)
	h.write(rotationIndex, []byte(strings.Repeat("[", 200000)+strings.Repeat("]", 200000)), 0o600)
	stdout, stderr, code := h.run("check")
	report := h.report(stdout, stderr, code)
	if code != 0 || report["ars_index_entries"] != nil {
		t.Fatalf("check exit %d entries %v problems %v", code, report["ars_index_entries"], report["problems"])
	}
}

// TestSigningKeyRotationSignalsRollBack sends each of SIGTERM, SIGHUP,
// SIGINT and SIGQUIT while EGS restarts: apply rolls back at its next step.
func TestSigningKeyRotationSignalsRollBack(t *testing.T) {
	for _, sig := range []string{"TERM", "HUP", "INT", "QUIT"} {
		t.Run(sig, func(t *testing.T) {
			h := newRotationHost(t)
			before := h.snapshot()
			h.mark("signal-" + sig + "-at-restart-egs")
			stdout, stderr, code := h.run("apply")
			report := h.report(stdout, stderr, code)
			if code != 1 || report["result"] != "rolled_back" || !strings.Contains(fmt.Sprint(report["failure"]), "SIG"+sig) {
				t.Fatalf("apply exit %d result %v failure %v\nstderr %s", code, report["result"], report["failure"], stderr)
			}
			if !reflect.DeepEqual(h.snapshot(), before) {
				t.Fatal("the signal did not put the configs and the index back")
			}
			h.requireReady()
		})
	}
}

// TestSigningKeyRotationAfterAKill kills apply where no handler can run:
// check and apply then name the unfinished rotation and its backup, and
// rollback of that backup puts the host back, removes what the kill left,
// and leaves a host check accepts.
func TestSigningKeyRotationAfterAKill(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(*rotationHost)
		left  int
	}{
		{"while AGS starts", func(h *rotationHost) { h.mark("signal-KILL-at-start-ags") }, 0},
		{"between writing ags.json and renaming it", func(h *rotationHost) {
			h.env = append(h.env, "SIGNING_KEY_ROTATION_TEST_KILL_AT=config-temp-written:ags")
		}, 1},
		{"between writing the empty index and renaming it", func(h *rotationHost) {
			h.env = append(h.env, "SIGNING_KEY_ROTATION_TEST_KILL_AT=index-temp-written")
		}, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newRotationHost(t)
			before := h.snapshot()
			tc.setup(h)
			stdout, stderr, code := h.run("apply")
			if code != -1 && code != 137 {
				t.Fatalf("apply was not killed: exit %d\nstdout %s\nstderr %s", code, stdout, stderr)
			}
			h.env = nil
			left := h.tempFiles()
			if len(left) != tc.left {
				t.Fatalf("the kill left %v, want %d temporary files", left, tc.left)
			}
			dirs := h.backupDirs()
			if len(dirs) != 1 {
				t.Fatalf("backups %v", dirs)
			}
			for _, mode := range []string{"check", "apply"} {
				stdout, stderr, code := h.run(mode)
				report := h.report(stdout, stderr, code)
				problems := fmt.Sprint(report["problems"])
				if code != 1 || !strings.Contains(problems, "a rotation did not finish") || !strings.Contains(problems, filepath.Base(dirs[0])) {
					t.Fatalf("%s after the kill: exit %d problems %s", mode, code, problems)
				}
				for _, path := range left {
					if !strings.Contains(problems, filepath.Base(path)) {
						t.Fatalf("%s after the kill does not name %s: %s", mode, path, problems)
					}
				}
			}
			stdout, stderr, code = h.run("rollback", "--backup-dir", dirs[0])
			result := h.report(stdout, stderr, code)
			if code != 0 || result["result"] != "rolled_back" {
				t.Fatalf("rollback after the kill: exit %d result %v steps %v\nstderr %s", code, result["result"], result["rollback_steps"], stderr)
			}
			if got := h.tempFiles(); len(got) != 0 {
				t.Fatalf("rollback left %v", got)
			}
			if !reflect.DeepEqual(h.snapshot(), before) {
				t.Fatal("rollback after the kill did not put the configs and the index back")
			}
			h.requireReady()
		})
	}

	// Killed while it made its backup: nothing was changed, and rollback of
	// that folder removes it.
	h := newRotationHost(t)
	before := h.snapshot()
	h.env = []string{"SIGNING_KEY_ROTATION_TEST_KILL_AT=backup-written"}
	if _, _, code := h.run("apply"); code != -1 && code != 137 {
		t.Fatalf("apply was not killed: exit %d", code)
	}
	h.env = nil
	dirs := h.backupDirs()
	if len(dirs) != 1 || !strings.HasPrefix(filepath.Base(dirs[0]), ".incomplete-") || !reflect.DeepEqual(h.snapshot(), before) {
		t.Fatalf("after a kill while the backup was made: backups %v", dirs)
	}
	stdout, stderr, code := h.run("check")
	if code != 1 || !strings.Contains(stdout, "stopped before it changed anything") {
		t.Fatalf("check after a kill while the backup was made: exit %d\n%s\n%s", code, stdout, stderr)
	}
	stdout, stderr, code = h.run("rollback", "--backup-dir", dirs[0])
	if code != 0 || !strings.Contains(stdout, "removed_incomplete_backup") || len(h.backupDirs()) != 0 {
		t.Fatalf("rollback of an incomplete backup: exit %d\n%s\n%s", code, stdout, stderr)
	}
	if len(h.serviceCalls()) != 0 {
		t.Fatalf("rollback of an incomplete backup ran %v", h.serviceCalls())
	}
	h.requireReady()
}

// TestSigningKeyRotationReportsWhenItsSummaryCannotBeWritten: the keys are
// rotated but summary.json cannot be written. apply prints its report first
// and says so on its own line, which never says "refused".
func TestSigningKeyRotationReportsWhenItsSummaryCannotBeWritten(t *testing.T) {
	h := newRotationHost(t)
	h.env = []string{"SIGNING_KEY_ROTATION_TEST_FAIL_AT=write-summary.json"}
	stdout, stderr, code := h.run("apply")
	report := h.report(stdout, stderr, code)
	if code != 1 || report["result"] != "rotated" {
		t.Fatalf("apply exit %d result %v\nstderr %s", code, report["result"], stderr)
	}
	if strings.Contains(stderr, "refused") || !strings.Contains(stderr, "the result is rotated, but") || !strings.Contains(stderr, "summary.json could not be written") {
		t.Fatalf("apply's last line: %s", stderr)
	}
	rotatedSigner(t, "ags", h.doc("ags")["signer"].(map[string]any))
}

// TestSigningKeyRotationRollbackTriesEveryStep: EGS fails to restart every
// time, so apply rolls back, and the rollback still starts AGS and ES,
// records the failed step, and ends rolled_back_unhealthy.
func TestSigningKeyRotationRollbackTriesEveryStep(t *testing.T) {
	h := newRotationHost(t)
	before := h.snapshot()
	h.mark("fail-restart-egs-always")
	stdout, stderr, code := h.run("apply")
	report := h.report(stdout, stderr, code)
	if code != 1 || report["result"] != "rolled_back_unhealthy" {
		t.Fatalf("apply exit %d result %v steps %v\nstderr %s", code, report["result"], report["rollback_steps"], stderr)
	}
	if !reflect.DeepEqual(h.snapshot(), before) {
		t.Fatal("the rollback did not put the configs and the index back")
	}
	calls := h.serviceCalls()
	if got := strings.Join(calls[len(calls)-3:], " | "); got != "systemctl restart egs | systemctl start ags | systemctl start es" {
		t.Fatalf("the rollback stopped at the failed restart: %v", calls)
	}
	steps := fmt.Sprint(report["rollback_steps"])
	if !strings.Contains(steps, "restart egs failed") && !strings.Contains(steps, "step:restart egs") {
		t.Fatalf("the rollback did not record the failed restart: %s", steps)
	}
	if _, ok := report["after_rollback"]; !ok {
		t.Fatal("the rollback did not record the state of the services")
	}
}

// TestSigningKeyRotationRollbackNamesAFailedStepEvenWhenTheServicesAnswer:
// a stop of ES that fails during a rollback leaves ES running on the rotated
// config, which the later start does not change, though every service still
// answers. The rollback's result says the host is not clean.
func TestSigningKeyRotationRollbackNamesAFailedStepEvenWhenTheServicesAnswer(t *testing.T) {
	h := newRotationHost(t)
	before := h.snapshot()
	backup := h.apply()["backup_dir"].(string)
	h.mark("fail-stop-es-once")
	stdout, stderr, code := h.run("rollback", "--backup-dir", backup)
	report := h.report(stdout, stderr, code)
	if code != 1 || report["result"] != "rolled_back_unhealthy" {
		t.Fatalf("rollback exit %d result %v steps %v\nstderr %s", code, report["result"], report["rollback_steps"], stderr)
	}
	if steps := fmt.Sprint(report["rollback_steps"]); !strings.Contains(steps, "systemctl stop es failed") {
		t.Fatalf("the rollback did not record the failed stop: %s", steps)
	}
	if after, ok := report["after_rollback"].(map[string]any); !ok || len(after) == 0 {
		t.Fatalf("the rollback did not record that the services answer: %v", report["after_rollback"])
	}
	if !reflect.DeepEqual(h.snapshot(), before) {
		t.Fatal("the rollback did not put the configs and the index back")
	}
}

// TestSigningKeyRotationRollbackWaitErrorKeepsTheReport: the rollback's wait
// for the services fails with an error, not an answer; apply still prints
// its report, writes its summary, and names the error.
func TestSigningKeyRotationRollbackWaitErrorKeepsTheReport(t *testing.T) {
	h := newRotationHost(t)
	h.mark("unhealthy-after-es-start-1")
	h.mark("rm-healthcheck-at-es-start-2")
	stdout, stderr, code := h.run("apply")
	report := h.report(stdout, stderr, code)
	if code != 1 || report["result"] != "rolled_back_unhealthy" || !strings.Contains(fmt.Sprint(report["after_rollback_error"]), "healthcheck.env") {
		t.Fatalf("apply exit %d result %v error %v\nstderr %s", code, report["result"], report["after_rollback_error"], stderr)
	}
	if _, err := os.Stat(filepath.Join(report["backup_dir"].(string), "summary.json")); err != nil {
		t.Fatal("no summary after an error in the rollback's wait")
	}
}

// TestSigningKeyRotationWaitsForEGSBeforeES: EGS's stand-in starts listening
// only a while after its restart, and ES is started only once it does.
func TestSigningKeyRotationWaitsForEGSBeforeES(t *testing.T) {
	h := newRotationHost(t)
	h.markWith("listen-delay-egs", "0.5")
	h.env = []string{"SIGNING_KEY_ROTATION_TEST_WAIT_SECONDS=5"}
	report := h.apply()
	if h.exists("es-started-before-egs") {
		t.Fatal("apply started ES before EGS accepted connections")
	}
	if !strings.Contains(fmt.Sprint(report["steps"]), "wait for egs") {
		t.Fatalf("apply did not wait for EGS: %v", report["steps"])
	}
}

// TestSigningKeyRotationHealthWaitsForSlowServices: ES answers 503 for a few
// requests after it starts, then 200; apply waits and rotates.
func TestSigningKeyRotationHealthWaitsForSlowServices(t *testing.T) {
	h := newRotationHost(t)
	h.markWith("slow-es-polls", "4")
	h.env = []string{"SIGNING_KEY_ROTATION_TEST_WAIT_SECONDS=10"}
	h.apply()
}

// TestSigningKeyRotationTempFileRefusesAPlantedLink: a link planted at the
// name of the temporary file is neither followed nor replaced; apply fails
// there and rolls back.
func TestSigningKeyRotationTempFileRefusesAPlantedLink(t *testing.T) {
	// A link left before the run is a leftover that check names.
	h := newRotationHost(t)
	before := h.snapshot()
	target := filepath.Join(h.state, "target")
	if err := os.WriteFile(target, []byte("untouched"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, h.path("etc/execution-substrate/.egs.json.signing-key-rotation.fixed")); err != nil {
		t.Fatal(err)
	}
	h.env = []string{"SIGNING_KEY_ROTATION_TEST_TEMP_SUFFIX=fixed"}
	stdout, stderr, code := h.run("apply")
	report := h.report(stdout, stderr, code)
	if code != 1 || report["result"] == "rotated" || !strings.Contains(fmt.Sprint(report["problems"]), ".egs.json.signing-key-rotation.fixed") {
		t.Fatalf("apply exit %d result %v problems %v\nstderr %s", code, report["result"], report["problems"], stderr)
	}
	if got, _ := os.ReadFile(target); string(got) != "untouched" {
		t.Fatal("apply wrote through the planted link")
	}
	if !reflect.DeepEqual(h.snapshot(), before) {
		t.Fatal("apply changed a file it could not write safely")
	}

	// A link planted while apply runs, at the name of the index's temporary
	// file, after check looked: the temporary file is created exclusively
	// and without following a link, so apply rolls back and writes nothing
	// through it.
	h = newRotationHost(t)
	before = h.snapshot()
	target = filepath.Join(h.state, "target")
	if err := os.WriteFile(target, []byte("untouched"), 0o644); err != nil {
		t.Fatal(err)
	}
	h.markWith("symlink-at-stop-ars", h.path("var/lib/ars/.index.json.signing-key-rotation.fixed")+"\n"+target+"\n")
	h.env = []string{"SIGNING_KEY_ROTATION_TEST_TEMP_SUFFIX=fixed"}
	stdout, stderr, code = h.run("apply")
	report = h.report(stdout, stderr, code)
	if code != 1 || report["result"] != "rolled_back" {
		t.Fatalf("apply with a link planted at the index's temporary name: exit %d result %v failure %v\nstderr %s",
			code, report["result"], report["failure"], stderr)
	}
	if got, _ := os.ReadFile(target); string(got) != "untouched" {
		t.Fatal("apply wrote the empty index through the planted link")
	}
	if !reflect.DeepEqual(h.snapshot(), before) {
		t.Fatal("the rollback did not put the configs and the index back")
	}
	if left := h.tempFiles(); len(left) != 0 {
		t.Fatalf("the rollback left %v", left)
	}
	h.requireReady()
}

// TestSigningKeyRotationRefusesACheckoutOthersCanChange: check, apply and
// rollback refuse to run from a clone that anyone but root (under the test,
// the uid it names) could change.
func TestSigningKeyRotationRefusesACheckoutOthersCanChange(t *testing.T) {
	// The clone's modes are set outright: a umask of 002, as many user
	// accounts have, would otherwise leave it group-writable.
	clone := func(t *testing.T) (string, string) {
		root := filepath.Join(t.TempDir(), "clone")
		for _, rel := range []string{rotateSigningKeysWrapper, rotateSigningKeysPython} {
			data, err := os.ReadFile(repoPath(rel))
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(root, rel)
			if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, data, 0o755); err != nil {
				t.Fatal(err)
			}
			for p := path; p != filepath.Dir(filepath.Dir(root)); p = filepath.Dir(p) {
				if err := os.Chmod(p, 0o755); err != nil {
					t.Fatal(err)
				}
			}
		}
		return root, filepath.Join(root, rotateSigningKeysPython)
	}
	owner := fmt.Sprintf("SIGNING_KEY_ROTATION_TEST_CHECKOUT_OWNER=%d", os.Getuid())
	for _, tc := range []struct {
		name   string
		break_ func(t *testing.T, root string)
		want   string
	}{
		{"the helper is group-writable", func(t *testing.T, root string) {
			if err := os.Chmod(filepath.Join(root, rotateSigningKeysPython), 0o775); err != nil {
				t.Fatal(err)
			}
		}, "is writable by its group or others"},
		{"a link under scripts", func(t *testing.T, root string) {
			if err := os.Symlink("/tmp", filepath.Join(root, "scripts/internal/elsewhere")); err != nil {
				t.Fatal(err)
			}
		}, "is a symbolic link"},
		{"scripts is writable by others", func(t *testing.T, root string) {
			if err := os.Chmod(filepath.Join(root, "scripts"), 0o777); err != nil {
				t.Fatal(err)
			}
		}, "is writable by its group or others"},
		// Opus A57: the folders above scripts are checked too.
		{"a folder above scripts is writable by others", func(t *testing.T, root string) {
			if err := os.Chmod(root, 0o777); err != nil {
				t.Fatal(err)
			}
		}, " is writable by its group or others (0777) without the sticky bit"},
	} {
		for _, command := range [][]string{{"check"}, {"apply"}, {"rollback", "--backup-dir", "/nonexistent"}} {
			t.Run(tc.name+"/"+command[0], func(t *testing.T) {
				h := newRotationHost(t)
				root, helper := clone(t)
				tc.break_(t, root)
				h.helper = helper
				h.env = []string{owner}
				before := h.snapshot()
				stdout, stderr, code := h.run(command...)
				if code != 1 || stdout != "" || !strings.Contains(stderr, "can change the code this rotation runs as root") || !strings.Contains(stderr, tc.want) {
					t.Fatalf("%s from a clone others can change: exit %d\nstdout %s\nstderr %s", command[0], code, stdout, stderr)
				}
				if !reflect.DeepEqual(h.snapshot(), before) || len(h.calls("")) != 0 {
					t.Fatal("a refused checkout read the host or changed a file")
				}
			})
		}
	}
	h := newRotationHost(t)
	_, helper := clone(t)
	h.helper = helper
	h.env = []string{owner}
	h.requireReady()
}

// TestSigningKeyRotationOnTheRealHostNeedsRoot: without a test host root,
// and with a host root that is / under another spelling, the rotation runs
// against the real host, refuses anyone but root, and turns on no test hook.
func TestSigningKeyRotationOnTheRealHostNeedsRoot(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("as root this would read the machine's own /etc/execution-substrate")
	}
	// A dotted path names the real root only where its folder is not a
	// link: on macOS /etc is a link to /private/etc, so /etc/.. is /private
	// there. Each dotted path is used only where it resolves to /, and at
	// least one must.
	hostRoots := []string{"/", "//", "/."}
	for _, dotted := range []string{"/etc/..", "/usr/.."} {
		if real, err := filepath.EvalSymlinks(dotted); err == nil && real == "/" {
			hostRoots = append(hostRoots, dotted)
		}
	}
	if len(hostRoots) == 3 {
		t.Fatal("neither /etc/.. nor /usr/.. resolves to /")
	}
	for _, hostRoot := range hostRoots {
		for _, command := range [][]string{{"check"}, {"apply"}, {"rollback", "--backup-dir", "/x"}} {
			cmd := exec.Command("python3", append([]string{"-I", "-B", repoPath(rotateSigningKeysPython), "--host-root", hostRoot}, command...)...)
			cmd.Dir = t.TempDir()
			cmd.Env = append(os.Environ(), "SIGNING_KEY_ROTATION_TEST_ROOT_UID="+strconv.Itoa(os.Getuid()))
			out, err := cmd.CombinedOutput()
			if exitErr, ok := err.(*exec.ExitError); !ok || exitErr.ExitCode() != 1 || !strings.Contains(string(out), "refused: run it as root") {
				t.Fatalf("--host-root %s %s as uid %d: %v\n%s", hostRoot, command[0], os.Getuid(), err, out)
			}
		}
	}
}

// TestSigningKeyRotationKeepsOwnersAndGroupsAsRoot runs as root with a
// distinct group for each service and for ARS's index: apply and rollback
// keep every file's owner and group, a config or index of another owner is
// refused, and so is a backup root another account owns.
func TestSigningKeyRotationKeepsOwnersAndGroupsAsRoot(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to give files to other owners and groups")
	}
	gids := map[string]int{"egs": 54321, "ags": 54322, "es": 54323, "ars": 54324}
	const arsUID = 54325
	setup := func(t *testing.T) *rotationHost {
		h := newRotationHost(t)
		for name, gid := range gids {
			h.env = append(h.env, fmt.Sprintf("SIGNING_KEY_ROTATION_TEST_GID_%s=%d", strings.ToUpper(name), gid))
		}
		h.env = append(h.env, "SIGNING_KEY_ROTATION_TEST_ROOT_UID=0", "SIGNING_KEY_ROTATION_TEST_ROOT_GID=0",
			fmt.Sprintf("SIGNING_KEY_ROTATION_TEST_UID_ARS=%d", arsUID))
		for name, rel := range rotationConfigPaths {
			if err := os.Chown(h.path(rel), 0, gids[name]); err != nil {
				t.Fatal(err)
			}
		}
		for _, rel := range []string{"etc/execution-substrate/ars.json"} {
			if err := os.Chown(h.path(rel), 0, gids["ars"]); err != nil {
				t.Fatal(err)
			}
		}
		for _, rel := range []string{"var/lib/ars", rotationIndex} {
			if err := os.Chown(h.path(rel), arsUID, gids["ars"]); err != nil {
				t.Fatal(err)
			}
		}
		return h
	}
	owners := func(t *testing.T, h *rotationHost) map[string]string {
		out := map[string]string{}
		for name, rel := range map[string]string{"egs": rotationConfigPaths["egs"], "ags": rotationConfigPaths["ags"], "es": rotationConfigPaths["es"], "index": rotationIndex} {
			info, err := os.Lstat(h.path(rel))
			if err != nil {
				t.Fatal(err)
			}
			st := info.Sys().(*syscall.Stat_t)
			out[name] = fmt.Sprintf("%d:%d %04o", st.Uid, st.Gid, info.Mode().Perm())
		}
		return out
	}
	h := setup(t)
	want := owners(t, h)
	if want["index"] != fmt.Sprintf("%d:%d 0600", arsUID, gids["ars"]) || want["es"] != fmt.Sprintf("0:%d 0640", gids["es"]) {
		t.Fatalf("setup owners %v", want)
	}
	backup := h.apply()["backup_dir"].(string)
	if got := owners(t, h); !reflect.DeepEqual(got, want) {
		t.Fatalf("owners after apply %v, want %v", got, want)
	}
	if _, stderr, code := h.run("rollback", "--backup-dir", backup); code != 0 {
		t.Fatalf("rollback: exit %d %s", code, stderr)
	}
	if got := owners(t, h); !reflect.DeepEqual(got, want) {
		t.Fatalf("owners after rollback %v, want %v", got, want)
	}

	for _, tc := range []struct {
		name   string
		break_ func(*rotationHost)
		want   string
	}{
		{"a config another uid owns", func(h *rotationHost) {
			if err := os.Chown(h.path(rotationConfigPaths["ags"]), 1, gids["ags"]); err != nil {
				t.Fatal(err)
			}
		}, "ags.json is not root:ags 0640"},
		{"an index another uid owns", func(h *rotationHost) {
			if err := os.Chown(h.path(rotationIndex), 1, gids["ars"]); err != nil {
				t.Fatal(err)
			}
		}, "not ARS's account or root"},
		{"a backup root another uid owns", func(h *rotationHost) {
			if err := os.Mkdir(h.path(rotationBackupRoot), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Chown(h.path(rotationBackupRoot), 1, 0); err != nil {
				t.Fatal(err)
			}
		}, "must be a folder root owns"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := setup(t)
			tc.break_(h)
			before := h.snapshot()
			stdout, stderr, code := h.run("apply")
			if code != 1 || !strings.Contains(stdout+stderr, tc.want) || !strings.Contains(stderr, "refused") {
				t.Fatalf("apply exit %d, want 1 naming %q\nstdout %s\nstderr %s", code, tc.want, stdout, stderr)
			}
			if !reflect.DeepEqual(h.snapshot(), before) || len(h.serviceCalls()) != 0 {
				t.Fatal("a refusal changed a file or a service")
			}
		})
	}
}

// TestSigningKeyRotationKnowsEveryKeyField ties the rotation's lists of
// fields to the Go types the services decode into, so a field added to one
// of them fails here until the rotation knows it.
func TestSigningKeyRotationKnowsEveryKeyField(t *testing.T) {
	read := exec.Command("python3", "-I", "-B", "-c", `
import json, runpy, sys
m = runpy.run_path(sys.argv[1])
print(json.dumps({
    "signer": list(m["SIGNER_FIELDS"]),
    "verifier": list(m["VERIFIER_FIELDS"]),
    "signer_policy": list(m["SIGNER_POLICY_FIELDS"]),
    "verification": [entry for entry, _ in m["VERIFICATION_FROM"]],
}))
`, repoPath(rotateSigningKeysPython))
	read.Dir = t.TempDir()
	out, err := read.Output()
	if err != nil {
		t.Fatalf("read the rotation's field lists: %v", err)
	}
	var lists map[string][]string
	if err := json.Unmarshal(out, &lists); err != nil {
		t.Fatal(err)
	}
	fields := func(value any) []string {
		var names []string
		typ := reflect.TypeOf(value)
		for i := 0; i < typ.NumField(); i++ {
			name := strings.Split(typ.Field(i).Tag.Get("json"), ",")[0]
			if name == "" || name == "-" {
				t.Fatalf("%s.%s has no JSON name", typ, typ.Field(i).Name)
			}
			names = append(names, name)
		}
		sort.Strings(names)
		return names
	}
	sorted := func(names []string) []string {
		out := append([]string(nil), names...)
		sort.Strings(out)
		return out
	}
	for _, tc := range []struct {
		list  string
		value any
	}{
		{"signer", agsconfig.SignerConfig{}},
		{"signer", egsconfig.SignerConfig{}},
		{"verifier", esconfig.SignerVerifierConfig{}},
		{"verification", esconfig.VerificationConfig{}},
		{"signer_policy", egscontract.SignerPolicy{}},
	} {
		if got, want := sorted(lists[tc.list]), fields(tc.value); !reflect.DeepEqual(got, want) {
			t.Fatalf("the rotation's %s fields %v are not %T's %v", tc.list, got, tc.value, want)
		}
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
	h.apply()
	rotatedSigner(t, "ags", h.doc("ags")["signer"].(map[string]any))
	rotatedSigner(t, "egs", h.doc("egs")["signer"].(map[string]any))
}
