package scripts_test

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"debug/elf"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"execution-substrate/internal/testutil"
)

// boxNomadHCL is the box's /etc/nomad.d/nomad.hcl as the read-only
// preflight of 2026-11-24 printed it: 529 bytes, Remote Alpha 0.7's
// one-host config.
const boxNomadHCL = `# Remote Alpha 0.7 one-host substrate config.
data_dir = "/opt/nomad/data"
bind_addr = "127.0.0.1"

addresses {
  http = "127.0.0.1"
  rpc  = "127.0.0.1"
  serf = "127.0.0.1"
}

advertise {
  http = "127.0.0.1:4646"
  rpc  = "127.0.0.1:4647"
  serf = "127.0.0.1:4648"
}

server {
  enabled = true
  bootstrap_expect = 1
}

client {
  enabled = true
  servers = ["127.0.0.1"]
  network_interface = "enp1s0"
  cni_path = "/opt/cni/bin"
  options = {
    "docker.cleanup.image" = "false"
    "docker.volumes.enabled" = "true"
  }
}
`

// boxNomadHCLLocked is the box's nomad.hcl where this upgrade starts: ES PR
// #54's lock of boxNomadHCL (the driver allowlist, the acl block and the
// Docker plugin block of scripts/70_linux_setup.sh) with the loopback pin of
// the host-network repair of 2026-11-24. Its SHA-256, ea333055…5163, is that
// of the box's file after that repair.
const boxNomadHCLLocked = `# Remote Alpha 0.7 one-host substrate config.
data_dir = "/opt/nomad/data"
bind_addr = "127.0.0.1"

addresses {
  http = "127.0.0.1"
  rpc  = "127.0.0.1"
  serf = "127.0.0.1"
}

advertise {
  http = "127.0.0.1:4646"
  rpc  = "127.0.0.1:4647"
  serf = "127.0.0.1:4648"
}

server {
  enabled = true
  bootstrap_expect = 1
}

client {
  enabled = true
  servers = ["127.0.0.1"]
  network_interface = "lo"
  cni_path = "/opt/cni/bin"
  options = {
    "driver.allowlist" = "docker"
  }
}

acl {
  enabled = true
}

# ES runs every task through its runtime helper on the Docker driver, so only
# that driver is enabled and the Docker plugin is limited (audit INF-02): no
# privileged containers, and only the capabilities the helper uses to prepare
# a run and drop to the workload user. ES's bind mounts need volumes enabled.
# Runtime profile images must survive image garbage collection.
plugin "docker" {
  config {
    allow_privileged = false
    allow_caps       = ["chown", "dac_override", "fowner", "kill", "setgid", "setuid", "setpcap"]

    volumes {
      enabled = true
    }

    gc {
      image = false
    }
  }
}
`

// boxNomadTLSBlock is what this upgrade appends to it: the tls block of
// scripts/70_linux_setup.sh at that script's NOMAD_TLS_DIR, /etc/nomad.d/tls.
const boxNomadTLSBlock = `
# HTTPS and RPC over TLS 1.3 only, with the certificate this script issues.
# Clients authenticate with ACL tokens, not certificates.
tls {
  http = true
  rpc  = true

  ca_file   = "/etc/nomad.d/tls/ca.pem"
  cert_file = "/etc/nomad.d/tls/server.pem"
  key_file  = "/etc/nomad.d/tls/server-key.pem"

  verify_server_hostname = true
  verify_https_client    = false
  tls_min_version        = "tls13"
}
`

// boxNomadHCLHTTPS is the box's nomad.hcl where this upgrade leaves it.
const boxNomadHCLHTTPS = boxNomadHCLLocked + boxNomadTLSBlock

const upgradeTestCommit = "0123456789abcdef0123456789abcdef01234567"

// boxESCommit is the ES build that ES PR #54's upgrade installed on the box.
const boxESCommit = "16cbf739eea8c6a673aef8048aefb69cebd5121b"

// The fakes stand in for the host's systemctl, curl, nomad and docker, for
// scripts/nomad_acl_setup.sh and for scripts/internal/nomad_tls_identity.py.
// They log every call to calls.log in the state directory and act on its
// marker files. Starting nomad reads the host's nomad.hcl: with an acl block,
// Nomad is "locked" and refuses anonymous job requests; with a tls block it
// answers only over HTTPS, and only a curl that trusts nothing but the host's
// Nomad CA. With the marker real-nomad, systemctl starts and stops a real
// Nomad agent on the host's nomad.hcl, with the overrides the test wrote
// (data directory, free ports, the TLS files under the test host root), and
// curl hands every request to that Nomad to the real curl.
const fakeSystemctl = `#!/usr/bin/env bash
set -u
s="$FAKE_STATE"
echo "systemctl $*" >> "$s/calls.log"
real_nomad_running() { [[ -s "$s/nomad.pid" ]] && kill -0 "$(cat "$s/nomad.pid")" 2>/dev/null; }
case "$1" in
  is-active)
    shift
    for u in "$@"; do
      if [[ "$u" == nomad && -e "$s/real-nomad" ]]; then
        if real_nomad_running; then echo active; else echo inactive; fi
      elif [[ -e "$s/inactive-$u" ]]; then echo inactive; else echo active; fi
    done ;;
  show)
    printf 'User=%s\n' "$(cat "$s/es-user" 2>/dev/null || echo es)"
    printf 'ExecStart={ path=/usr/local/lib/execution-substrate/bin/es ; argv[]=%s ; ignore_errors=no }\n' \
      "$(cat "$s/es-argv" 2>/dev/null || echo '/usr/local/lib/execution-substrate/bin/es -config /etc/execution-substrate/es.json')" ;;
  stop)
    # fail-stop-<unit> holds how many stops still succeed; after those, the
    # stop fails and the unit keeps running.
    if [[ -e "$s/fail-stop-$2" ]]; then
      n="$(cat "$s/fail-stop-$2")"
      if (( n <= 0 )); then echo "Failed to stop $2.service" >&2; exit 1; fi
      echo $((n - 1)) > "$s/fail-stop-$2"
    fi
    if [[ "$2" == nomad && -e "$s/real-nomad" ]] && real_nomad_running; then
      pid="$(cat "$s/nomad.pid")"
      kill "$pid"
      for _ in $(seq 150); do kill -0 "$pid" 2>/dev/null || break; sleep 0.1; done
      if kill -0 "$pid" 2>/dev/null; then kill -9 "$pid"; sleep 1; fi
      rm -f "$s/nomad.pid"
    fi
    touch "$s/inactive-$2" ;;
  start)
    if [[ -e "$s/fail-start-$2-once" ]]; then rm -f "$s/fail-start-$2-once"; echo "Job for $2.service failed" >&2; exit 1; fi
    if [[ "$2" == nomad ]]; then
      hcl="$FAKE_HOST_ROOT/etc/nomad.d/nomad.hcl"
      if grep -q '^acl {' "$hcl"; then touch "$s/locked"; else rm -f "$s/locked"; fi
      if grep -q '^tls {' "$hcl"; then touch "$s/tls"; else rm -f "$s/tls"; fi
      # leader-starts holds how many Nomad starts still elect a leader.
      if [[ -e "$s/leader-starts" ]]; then
        n="$(cat "$s/leader-starts")"
        if (( n <= 0 )); then touch "$s/no-leader"; else echo $((n - 1)) > "$s/leader-starts"; rm -f "$s/no-leader"; fi
      fi
      if [[ -e "$s/real-nomad" ]] && ! real_nomad_running; then
        args=(-config "$hcl" -config "$s/override.hcl")
        [[ -e "$s/tls" ]] && args+=(-config "$s/override-tls.hcl")
        rm -f "$s/nomad.pid"
        # A session of its own, so that the upgrade's end of systemctl's
        # process group does not end Nomad.
        setsid bash -c 'echo $$ > "$0.tmp" && mv "$0.tmp" "$0" && exec nomad agent "$@"' "$s/nomad.pid" "${args[@]}" \
          >> "$s/nomad.log" 2>&1 < /dev/null &
        for _ in $(seq 100); do [[ -s "$s/nomad.pid" ]] && break; sleep 0.05; done
      fi
    fi
    rm -f "$s/inactive-$2" ;;
  *)
    echo "fake systemctl: unexpected $*" >&2; exit 2 ;;
esac
`

const fakeCurl = `#!/usr/bin/env bash
set -u
s="$FAKE_STATE"
url="${@: -1}"
echo "curl $url" >> "$s/calls.log"
nomad="127.0.0.1:${FAKE_NOMAD_PORT:-4646}"
if [[ -e "$s/real-nomad" && "$url" == http*://"$nomad"/* ]]; then
  exec "$REAL_CURL" "$@"
fi
args=" $* "
body_wanted=1
[[ "$args" == *" -o /dev/null "* ]] && body_wanted=0
code=200
body=''
refuse() { echo "curl: (7) Failed to connect" >&2; exit 7; }
# A request to Nomad must use the scheme Nomad serves, and over HTTPS trust
# only the host's Nomad CA, with TLS 1.3.
nomad_up() {
  [[ -e "$s/inactive-nomad" ]] && refuse
  if [[ "$url" == https://* ]]; then
    [[ -e "$s/tls" ]] || { echo "curl: (35) TLS connect error" >&2; exit 35; }
    [[ "$args" == *" --proto =https --tlsv1.3 --cacert $FAKE_HOST_ROOT/etc/nomad.d/tls/ca.pem --capath /dev/null "* ]] || \
      { echo "curl: (60) not limited to Nomad's CA and TLS 1.3" >&2; exit 60; }
  else
    [[ -e "$s/tls" ]] && { echo "curl: (52) Empty reply from server" >&2; exit 52; }
    [[ "$args" == *" --proto =http "* ]] || { echo "curl: plain-HTTP request without --proto =http" >&2; exit 1; }
  fi
}
case "$url" in
  http://127.0.0.1:4646/v1/status/leader|https://127.0.0.1:4646/v1/status/leader)
    nomad_up
    if [[ -e "$s/no-leader" || ( "$url" == https://* && -e "$s/https-no-leader" ) ]]; then code=500; body='No cluster leader'; else body='"127.0.0.1:4647"'; fi ;;
  http://127.0.0.1:4646/v1/jobs|https://127.0.0.1:4646/v1/jobs)
    nomad_up
    # https-jobs-open: over HTTPS, Nomad lists jobs to anyone, as a Nomad
    # whose ACLs do not hold there would.
    if [[ -e "$s/locked" && ! ( "$url" == https://* && -e "$s/https-jobs-open" ) ]]; then code=403; fi ;;
  http://127.0.0.1:4646/v1/acl/policy/anonymous|https://127.0.0.1:4646/v1/acl/policy/anonymous)
    nomad_up
    # anonymous-policy: Nomad holds an anonymous policy, which it shows to
    # anyone. Its job list stays 403 when the policy names another namespace.
    if [[ ! -e "$s/locked" ]]; then code=400; body='ACL support disabled'
    elif [[ ! -e "$s/anonymous-policy" ]]; then code=404; body='ACL policy not found'; fi ;;
  https://127.0.0.1:8445/*)
    { [[ -e "$s/inactive-es" ]] || [[ -e "$s/unhealthy" ]]; } && refuse ;;
  https://127.0.0.1:8444/*)
    [[ -e "$s/unhealthy" ]] && refuse ;;
  *)
    echo "fake curl: unexpected $url" >&2; exit 2 ;;
esac
if [[ $body_wanted == 1 ]]; then printf '%s\n%s' "$body" "$code"; else printf '%s' "$code"; fi
`

// fakeNomad is nomad config validate as Nomad 2.1 behaves: it exits 0 but
// warns when it cannot read the TLS files a config names, and when a config
// has no TLS.
const fakeNomad = `#!/usr/bin/env bash
set -u
s="$FAKE_STATE"
echo "nomad $*" >> "$s/calls.log"
[[ "$1 $2" == "config validate" ]] || exit 2
if [[ -e "$s/slow-validate" ]]; then touch "$s/validating"; sleep 20; fi
[[ -e "$s/nomad-invalid" ]] && { echo "invalid config" >&2; exit 1; }
f="$3/nomad.hcl"
grep -q '^acl {' "$f" || exit 1
if grep -q '^tls {' "$f"; then
  ca="$(sed -n 's/^  ca_file   = "\(.*\)"$/\1/p' "$f")"
  if [[ -e "$s/tls-unreadable" || ! -r "$ca" ]]; then
    echo "WARNING: Error when parsing TLS configuration: open $ca: no such file or directory"
  fi
else
  echo "WARNING: mTLS is not configured - Nomad is not secure without mTLS!"
fi
echo "Configuration is valid!"
`

const fakeACLSetup = `#!/usr/bin/env bash
set -u
s="$FAKE_STATE"
echo "acl-setup $1 ES_USER=$ES_USER OBSERVER_USER=$OBSERVER_USER NOMAD_USER=$NOMAD_USER NOMAD_ADDR=$NOMAD_ADDR NOMAD_CACERT=${NOMAD_CACERT#"$FAKE_HOST_ROOT"}" >> "$s/calls.log"
[[ "$NOMAD_ADDR" == https://127.0.0.1:4646 && -e "$s/tls" && ! -e "$s/inactive-nomad" && -r "$NOMAD_CACERT" ]] || \
  { echo "nomad acl setup: no Nomad over HTTPS at $NOMAD_ADDR" >&2; exit 1; }
[[ -e "$s/locked" ]] || { echo "nomad acl setup: Nomad does not enforce ACLs" >&2; exit 1; }
for f in management-token es-token observer-token; do
  [[ -f "$NOMAD_ACL_DIR/$f" ]] || { echo "nomad acl setup: no $f" >&2; exit 1; }
done
case "$1" in
  provision)
    if [[ -e "$s/slow-acl" ]]; then
      # A grandchild that would write after its parent is gone.
      ( sleep 2; touch "$s/grandchild-wrote" ) &
      touch "$s/acl-running"
      sleep 20
    fi
    touch "$s/observer-policy-v2" ;;
  placement)
    [[ -e "$s/placement-fails" ]] && { echo "nomad placement: no host-mode network" >&2; exit 1; }
    [[ "$ES_CONFIG" == "$FAKE_HOST_ROOT/etc/execution-substrate/es.json" && -e "$ES_CONFIG" ]] || exit 1
    [[ "$NOMAD_STARTED_AT" =~ ^[1-9][0-9]*$ && "$NOMAD_PLACEMENT_WAIT_SECONDS" == 120 ]] || exit 1 ;;
  check)
    [[ -e "$s/acl-check-fails" ]] && { echo "nomad acl check: failed" >&2; exit 1; }
    [[ -e "$s/observer-policy-v2" ]] || { echo "nomad acl check: the es-observer-v1 policy's rules differ" >&2; exit 1; } ;;
  *) exit 2 ;;
esac
`

// fakeTLSIdentity is nomad_tls_identity.py check against the fake Nomad: the
// config must name Nomad's HTTPS address, the host's CA (read through the
// test host root) and the key of the certificate on disk.
const fakeTLSIdentity = `#!/usr/bin/env bash
set -u
s="$FAKE_STATE"
echo "tls-identity $1 $3" >> "$s/calls.log"
[[ "$1" == check && "$3" == https://127.0.0.1:4646 ]] || exit 2
[[ -e "$s/identity-fails" ]] && { echo "nomad tls: Nomad's server key does not match nomad.server_spki_sha256" >&2; exit 1; }
[[ -e "$s/tls" && ! -e "$s/inactive-nomad" ]] || { echo "nomad tls: no TLS 1.3 connection to $3" >&2; exit 1; }
read -r base ca pin < <(python3 -I -c 'import json, sys
n = json.load(open(sys.argv[1]))["nomad"]
print(n["base_url"], n["root_ca_file"], n["server_spki_sha256"])' "$2")
tls="$FAKE_HOST_ROOT/etc/nomad.d/tls"
[[ "$base" == "$3" ]] || { echo "nomad tls: nomad.base_url is not $3" >&2; exit 1; }
[[ "$ca" == "$tls/ca.pem" ]] || { echo "nomad tls: nomad.root_ca_file $ca is not the host's CA" >&2; exit 1; }
live="$(openssl x509 -in "$tls/server.pem" -noout -pubkey | openssl pkey -pubin -outform DER | openssl dgst -sha256 -r)"
[[ "$pin" == "${live%% *}" ]] || { echo "nomad tls: Nomad's server key does not match nomad.server_spki_sha256" >&2; exit 1; }
echo "nomad tls: tls=1.3 server_name=server.global.nomad key=pinned"
`

const fakeDocker = `#!/usr/bin/env bash
set -u
s="$FAKE_STATE"
echo "docker $*" >> "$s/calls.log"
[[ "$*" == "ps --quiet --no-trunc --filter label=com.hashicorp.nomad.alloc_id" ]] || exit 2
[[ -e "$s/docker-fails" ]] && { echo "Cannot connect to the Docker daemon" >&2; exit 1; }
cat "$s/allocs" 2>/dev/null || true
`

type upgradeHost struct {
	t       *testing.T
	root    string
	state   string
	bin     string
	payload string
	helper  string
	commit  string
	// env overrides the environment the upgrade runs with; an empty value
	// removes the variable.
	env map[string]string
}

func (h *upgradeHost) path(rel string) string { return filepath.Join(h.root, filepath.FromSlash(rel)) }

func (h *upgradeHost) write(rel string, data string, mode os.FileMode) {
	h.t.Helper()
	path := h.path(rel)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		h.t.Fatal(err)
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		h.t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(data), mode); err != nil {
		h.t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		h.t.Fatal(err)
	}
}

func (h *upgradeHost) mkdir(rel string, mode os.FileMode) {
	h.t.Helper()
	if err := os.MkdirAll(h.path(rel), 0o755); err != nil {
		h.t.Fatal(err)
	}
	if err := os.Chmod(h.path(rel), mode); err != nil {
		h.t.Fatal(err)
	}
}

func (h *upgradeHost) mark(name string, content string) {
	h.t.Helper()
	if err := os.WriteFile(filepath.Join(h.state, name), []byte(content), 0o644); err != nil {
		h.t.Fatal(err)
	}
}

func (h *upgradeHost) marked(name string) bool {
	_, err := os.Stat(filepath.Join(h.state, name))
	return err == nil
}

// boxStartESConfig is the box's es.json where this upgrade starts: the
// operator and control-plane example with Nomad at baseURL over plain HTTP,
// none of the Nomad TLS keys, no workload grants (the box's build predates
// them), and the Nomad token file and retained-result auth that ES PR #54's
// upgrade set.
func boxStartESConfig(t *testing.T, baseURL string) []byte {
	t.Helper()
	data, err := os.ReadFile(repoPath(".examples/config/es.operator_and_control_plane.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	// The box verifies with its own keys; the example's are known keys,
	// which ES refuses (contracts.md section 3B).
	testutil.WithFreshSigningKeys(t, doc)
	delete(doc, "admission_policy")
	nomad := doc["nomad"].(map[string]any)
	nomad["base_url"] = baseURL
	for _, key := range []string{"server_name", "root_ca_file", "server_spki_sha256"} {
		delete(nomad, key)
	}
	nomad["token_file"] = "/etc/execution-substrate/nomad-acl/es-token"
	doc["execution"].(map[string]any)["retained_result_auth"] = map[string]any{
		"store_id": "remote-alpha", "key_id": "k1", "key_file": "/etc/execution-substrate/retained-result-auth/es.key",
	}
	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return append(out, '\n')
}

// exampleOperatorAndControlPlaneAdmissionPolicy is the admission_policy of
// the operator and control-plane example: today's workload grants for its
// allowlist and provenance key, which the upgrade's migrate-config also
// writes for that es.json.
func exampleOperatorAndControlPlaneAdmissionPolicy(t *testing.T) map[string]any {
	t.Helper()
	data, err := os.ReadFile(repoPath(".examples/config/es.operator_and_control_plane.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	policy, ok := doc["admission_policy"].(map[string]any)
	if !ok {
		t.Fatal("the operator and control-plane example has no admission_policy")
	}
	return policy
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// goBinaryWithBuildInfo returns a minimal 64-bit little-endian ELF file
// whose .go.buildinfo section carries version and modinfo the way the Go
// linker writes them (inline strings, module info framed by 16-byte
// sentinels), with a load segment covering it so that debug/buildinfo, and
// so `go version -m`, reads it like a real binary. A test checks that.
func goBinaryWithBuildInfo(version, modinfo string) []byte {
	const base = 0x400000
	names := []byte("\x00.shstrtab\x00.go.buildinfo\x00")
	var info bytes.Buffer
	info.WriteString("\xff Go buildinf:")
	info.WriteByte(8) // pointer size
	info.WriteByte(2) // inline strings, little-endian
	info.Write(make([]byte, 16))
	for _, field := range []string{version, "0w\xaf\x0c\x92t\b\x02A\xe1\xc1\a\xe6\xd6\x18\xe6" + modinfo + "\xf92C1\x86\x18 r\x00\x82B\x10A\x16\xd8\xf2"} {
		info.Write(binary.AppendUvarint(nil, uint64(len(field))))
		info.WriteString(field)
	}
	align := func(n, to int) int { return (n + to - 1) / to * to }
	namesAt := 64 + 56
	infoAt := align(namesAt+len(names), 16)
	sectionsAt := align(infoAt+info.Len(), 8)
	size := sectionsAt + 3*64

	var out bytes.Buffer
	header := elf.Header64{
		Type: uint16(elf.ET_EXEC), Machine: uint16(elf.EM_X86_64), Version: uint32(elf.EV_CURRENT), Entry: base,
		Phoff: 64, Shoff: uint64(sectionsAt), Ehsize: 64, Phentsize: 56, Phnum: 1, Shentsize: 64, Shnum: 3, Shstrndx: 1,
	}
	copy(header.Ident[:], []byte{0x7f, 'E', 'L', 'F', byte(elf.ELFCLASS64), byte(elf.ELFDATA2LSB), byte(elf.EV_CURRENT)})
	write := func(v any) {
		if err := binary.Write(&out, binary.LittleEndian, v); err != nil {
			panic(err)
		}
	}
	write(header)
	write(elf.Prog64{Type: uint32(elf.PT_LOAD), Flags: uint32(elf.PF_R | elf.PF_W), Vaddr: base, Paddr: base,
		Filesz: uint64(size), Memsz: uint64(size), Align: 0x1000})
	out.Write(names)
	out.Write(make([]byte, infoAt-out.Len()))
	out.Write(info.Bytes())
	out.Write(make([]byte, sectionsAt-out.Len()))
	write(elf.Section64{})
	write(elf.Section64{Name: 1, Type: uint32(elf.SHT_STRTAB), Off: uint64(namesAt), Size: uint64(len(names)), Addralign: 1})
	write(elf.Section64{Name: 11, Type: uint32(elf.SHT_PROGBITS), Flags: uint64(elf.SHF_WRITE | elf.SHF_ALLOC),
		Addr: uint64(base + infoAt), Off: uint64(infoAt), Size: uint64(info.Len()), Addralign: 16})
	return out.Bytes()
}

// stampedBinary is a payload binary whose own build info names a Go
// version, a commit and whether the checkout was modified.
func stampedBinary(name, goVersion, revision, modified string) []byte {
	return goBinaryWithBuildInfo(goVersion, "path\texecution-substrate/cmd/"+name+"\n"+
		"mod\texecution-substrate\t(devel)\t\n"+
		"build\t-buildmode=exe\nbuild\t-compiler=gc\nbuild\tCGO_ENABLED=0\nbuild\tGOARCH=amd64\nbuild\tGOOS=linux\n"+
		"build\tvcs=git\nbuild\tvcs.revision="+revision+"\nbuild\tvcs.modified="+modified+"\n")
}

// newESBuild and newRuntimeSupportBuild are the payload's binaries: clean
// go1.26.5 builds of upgradeTestCommit by their own build info. boxESBuild
// and boxRuntimeSupportBuild are the box's: builds of boxESCommit.
var (
	newESBuild             = stampedBinary("es", "go1.26.5", upgradeTestCommit, "false")
	newRuntimeSupportBuild = stampedBinary("es-runtime-support", "go1.26.5", upgradeTestCommit, "false")
	boxESBuild             = stampedBinary("es", "go1.26.5", boxESCommit, "false")
	boxRuntimeSupportBuild = stampedBinary("es-runtime-support", "go1.26.5", boxESCommit, "false")
)

// replacePayloadFile puts data in the payload under name and records its
// SHA-256 in provenance.json, so that only the check under test can refuse.
func (h *upgradeHost) replacePayloadFile(name string, data []byte) {
	h.t.Helper()
	if err := os.WriteFile(filepath.Join(h.payload, name), data, 0o755); err != nil {
		h.t.Fatal(err)
	}
	var prov map[string]any
	if err := json.Unmarshal([]byte(mustRead(h.t, filepath.Join(h.payload, "provenance.json"))), &prov); err != nil {
		h.t.Fatal(err)
	}
	prov["sha256"].(map[string]any)[name] = sha256Hex(data)
	writeJSONFile(h.t, filepath.Join(h.payload, "provenance.json"), prov)
}

// newUpgradeHost lays out a host root shaped like the box where this upgrade
// starts (the shape "locked-http"), a payload built from upgradeTestCommit,
// and the fakes.
func newUpgradeHost(t *testing.T, helper string) *upgradeHost {
	t.Helper()
	h := &upgradeHost{t: t, root: t.TempDir(), state: t.TempDir(), bin: t.TempDir(), payload: filepath.Join(t.TempDir(), "payload"),
		helper: helper, commit: upgradeTestCommit, env: map[string]string{}}
	if err := os.WriteFile(filepath.Join(h.state, "calls.log"), nil, 0o644); err != nil {
		t.Fatal(err)
	}

	h.mkdir("etc/execution-substrate", 0o755)
	h.write("etc/execution-substrate/es.json", string(boxStartESConfig(t, "http://127.0.0.1:4646")), 0o640)
	h.write("etc/execution-substrate/ags.json", `{"http": {"bind_address": "127.0.0.1", "port": 8444}}`+"\n", 0o640)
	h.write("etc/execution-substrate/healthcheck.env", "CA_CERT=/etc/execution-substrate/tls/ca.pem\nOPERATOR_CERT=\"/etc/x/operator.pem\"\nOPERATOR_KEY=/etc/x/operator-key.pem\n", 0o640)
	h.write("etc/systemd/system/es.service", "[Service]\nExecStart=/usr/local/lib/execution-substrate/bin/es -config /etc/execution-substrate/es.json\n", 0o644)
	h.write("etc/systemd/system/es.service.d/10-account.conf", "[Service]\nUser=es\nGroup=es\nUMask=0027\n", 0o644)
	h.write("usr/local/lib/execution-substrate/bin/es", string(boxESBuild), 0o755)
	h.write("usr/local/bin/es-runtime-support", string(boxRuntimeSupportBuild), 0o755)
	h.mkdir("etc/nomad.d", 0o755)
	h.write("etc/nomad.d/nomad.hcl", boxNomadHCLLocked, 0o640)
	h.write("etc/nomad.d/nomad.env", "", 0o640)
	h.write("etc/nomad.d/nomad.hcl.pre-alpha0.7.20260422213553", "# an older config Nomad does not load\n", 0o644)
	h.mkdir("opt/nomad", 0o755)
	h.mkdir("opt/nomad/data", 0o700)
	h.write("opt/nomad/data/server/raft/raft.db", "raft state\n", 0o600)
	h.mkdir("etc/execution-substrate/nomad-acl", 0o755)
	h.write("etc/execution-substrate/nomad-acl/management-token", "00000000-1111-2222-3333-444444444444\n", 0o600)
	h.write("etc/execution-substrate/nomad-acl/es-token", "01234567-89ab-cdef-0123-456789abcdef\n", 0o400)
	h.write("etc/execution-substrate/nomad-acl/observer-token", "fedcba98-7654-3210-fedc-ba9876543210\n", 0o400)
	h.mkdir("etc/execution-substrate/retained-result-auth", 0o755)
	h.write("etc/execution-substrate/retained-result-auth/es.key", strings.Repeat("k", 32), 0o400)
	h.mkdir("var/backups", 0o755)
	// Nomad runs, on plain HTTP, and enforces ACLs.
	h.mark("locked", "")

	if err := os.Mkdir(h.payload, 0o755); err != nil {
		t.Fatal(err)
	}
	helperBytes, err := os.ReadFile(helper)
	if err != nil {
		t.Fatal(err)
	}
	files := map[string][]byte{"es": newESBuild, "es-runtime-support": newRuntimeSupportBuild, "esconfigcheck": helperBytes}
	sums := map[string]string{}
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(h.payload, name), data, 0o755); err != nil {
			t.Fatal(err)
		}
		sums[name] = sha256Hex(data)
	}
	writeJSONFile(t, filepath.Join(h.payload, "provenance.json"), map[string]any{
		"commit": upgradeTestCommit, "go_version": "go1.26.5", "vcs_modified": false, "sha256": sums,
	})

	for name, script := range map[string]string{"systemctl": fakeSystemctl, "curl": fakeCurl, "nomad": fakeNomad,
		"acl-setup": fakeACLSetup, "tls-identity": fakeTLSIdentity, "docker": fakeDocker} {
		if err := os.WriteFile(filepath.Join(h.bin, name), []byte(script), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return h
}

func (h *upgradeHost) environ() []string {
	env := map[string]string{
		"PATH":                         h.bin + string(os.PathListSeparator) + os.Getenv("PATH"),
		"FAKE_STATE":                   h.state,
		"FAKE_HOST_ROOT":               h.root,
		"ES_UPGRADE_TEST_ACL_SETUP":    filepath.Join(h.bin, "acl-setup"),
		"ES_UPGRADE_TEST_TLS_IDENTITY": filepath.Join(h.bin, "tls-identity"),
		"ES_UPGRADE_TEST_WAIT_SECONDS": "1",
	}
	for key, value := range h.env {
		env[key] = value
	}
	var out []string
	for _, entry := range os.Environ() {
		key, _, _ := strings.Cut(entry, "=")
		if _, set := env[key]; !set && !strings.HasPrefix(key, "ES_UPGRADE_TEST_") {
			out = append(out, entry)
		}
	}
	for key, value := range env {
		if value != "" {
			out = append(out, key+"="+value)
		}
	}
	return out
}

func (h *upgradeHost) command(args ...string) *exec.Cmd {
	cmd := exec.Command("python3", append([]string{"-I", repoPath(upgradeESPython), "--host-root", h.root}, args...)...)
	cmd.Dir = h.state
	cmd.Env = h.environ()
	return cmd
}

func (h *upgradeHost) run(args ...string) (string, string, int) {
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

func (h *upgradeHost) check() (map[string]any, string, int) {
	h.t.Helper()
	stdout, stderr, code := h.run("check", "--payload", h.payload, "--commit", h.commit)
	var report map[string]any
	if err := json.Unmarshal([]byte(stdout), &report); err != nil {
		h.t.Fatalf("check printed no JSON report (exit %d): %v\nstdout %s\nstderr %s", code, err, stdout, stderr)
	}
	return report, stderr, code
}

func (h *upgradeHost) apply() (string, string, int) {
	h.t.Helper()
	return h.run("apply", "--payload", h.payload, "--commit", h.commit)
}

// systemctl runs the fake systemctl as the upgrade would.
func (h *upgradeHost) systemctl(args ...string) {
	h.t.Helper()
	cmd := exec.Command(filepath.Join(h.bin, "systemctl"), args...)
	cmd.Dir = h.state
	cmd.Env = h.environ()
	if out, err := cmd.CombinedOutput(); err != nil {
		h.t.Fatalf("systemctl %v: %v %s", args, err, out)
	}
}

func (h *upgradeHost) calls(prefix string) []string {
	h.t.Helper()
	data, err := os.ReadFile(filepath.Join(h.state, "calls.log"))
	if err != nil {
		h.t.Fatal(err)
	}
	var out []string
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if strings.HasPrefix(line, prefix) {
			out = append(out, line)
		}
	}
	return out
}

func (h *upgradeHost) clearCalls() {
	h.t.Helper()
	if err := os.WriteFile(filepath.Join(h.state, "calls.log"), nil, 0o644); err != nil {
		h.t.Fatal(err)
	}
}

// snapshot maps every path under the host root to its type, mode, owner
// and, for a file the test can read, the SHA-256 of its content.
func (h *upgradeHost) snapshot() map[string]string {
	h.t.Helper()
	out := map[string]string{}
	err := filepath.WalkDir(h.root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(h.root, path)
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		st := info.Sys().(*syscall.Stat_t)
		entry := fmt.Sprintf("%s %d:%d", info.Mode().String(), st.Uid, st.Gid)
		if info.Mode().IsRegular() {
			data, err := os.ReadFile(path)
			switch {
			case err == nil:
				entry += " " + sha256Hex(data)
			case os.IsPermission(err):
				entry += " unreadable"
			default:
				return err
			}
		}
		out[filepath.ToSlash(rel)] = entry
		return nil
	})
	if err != nil {
		h.t.Fatal(err)
	}
	return out
}

// issueTLS runs scripts/70_linux_setup.sh's nomad_tls_issue into the host's
// Nomad TLS directory, as the test user.
func (h *upgradeHost) issueTLS() {
	h.t.Helper()
	setup := mustRead(h.t, repoPath("scripts/70_linux_setup.sh"))
	begin, end := strings.Index(setup, "# BEGIN nomad_tls"), strings.Index(setup, "# END nomad_tls")
	if begin < 0 || end < begin {
		h.t.Fatal("scripts/70_linux_setup.sh has no nomad_tls region")
	}
	cmd := exec.Command("bash", "-c", "set -euo pipefail\n"+setup[begin:end]+"nomad_tls_issue \"$1\"\n", "issue", h.path("etc/nomad.d/tls"))
	cmd.Dir = h.state
	if out, err := cmd.CombinedOutput(); err != nil {
		h.t.Fatalf("nomad_tls_issue: %v %s", err, out)
	}
}

// serverKeyPin is the SHA-256 of the public key of the certificate at path.
func serverKeyPin(t *testing.T, path string) string {
	t.Helper()
	block, _ := pem.Decode([]byte(mustRead(t, path)))
	if block == nil {
		t.Fatalf("%s holds no PEM block", path)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return sha256Hex(cert.RawSubjectPublicKeyInfo)
}

// upgradeLeftovers are the paths an apply leaves on the host even after a
// rollback: its backups.
var upgradeLeftovers = regexp.MustCompile(`^var/backups/execution-substrate-es-upgrade(/|$)`)

func assertRestored(t *testing.T, before, after map[string]string) {
	t.Helper()
	for path, entry := range before {
		if after[path] != entry {
			t.Errorf("%s: before %q, after %q", path, entry, after[path])
		}
	}
	for path := range after {
		if _, ok := before[path]; !ok && !upgradeLeftovers.MatchString(path) {
			t.Errorf("%s is new after the rollback", path)
		}
	}
}

func backupDirs(t *testing.T, h *upgradeHost) []string {
	t.Helper()
	dirs, err := filepath.Glob(h.path("var/backups/execution-substrate-es-upgrade/*"))
	if err != nil {
		t.Fatal(err)
	}
	return dirs
}

func readSummary(t *testing.T, h *upgradeHost) (string, map[string]any) {
	t.Helper()
	dirs := backupDirs(t, h)
	if len(dirs) != 1 {
		t.Fatalf("want one backup directory, found %v", dirs)
	}
	if !regexp.MustCompile(`/\d{8}T\d{6}Z-` + upgradeTestCommit[:12] + `$`).MatchString(dirs[0]) {
		t.Fatalf("backup directory %s is not named <UTC time>-<commit>", dirs[0])
	}
	if st, err := os.Lstat(dirs[0]); err != nil || st.Mode().Perm() != 0o700 || !st.IsDir() {
		t.Fatalf("backup directory mode: %v %v", st, err)
	}
	if st, err := os.Lstat(filepath.Dir(dirs[0])); err != nil || st.Mode().Perm() != 0o700 {
		t.Fatalf("backup root mode: %v %v", st, err)
	}
	data, err := os.ReadFile(filepath.Join(dirs[0], "summary.json"))
	if err != nil {
		t.Fatal(err)
	}
	var summary map[string]any
	if err := json.Unmarshal(data, &summary); err != nil {
		t.Fatal(err)
	}
	return dirs[0], summary
}

func modeOf(t *testing.T, path string) os.FileMode {
	t.Helper()
	st, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	return st.Mode().Perm()
}

// onlyReads fails when the calls since the last clearCalls stopped or
// started a service or ran the ACL setup.
func onlyReads(t *testing.T, h *upgradeHost, label string) {
	t.Helper()
	for _, call := range h.calls("systemctl") {
		if !strings.HasPrefix(call, "systemctl is-active") && !strings.HasPrefix(call, "systemctl show") {
			t.Fatalf("%s ran %q", label, call)
		}
	}
	if calls := h.calls("acl-setup"); len(calls) != 0 {
		t.Fatalf("%s ran the ACL setup: %v", label, calls)
	}
}

// TestRemoteAlphaUpgradeESReadsGoBuildInfoLikeGoVersion keeps the upgrade's
// own reader of a binary's Go build info, which check and apply use to tie
// es and es-runtime-support to the commit, in agreement with `go version -m`:
// on a real Go binary, and on the fixture binaries the other tests install.
func TestRemoteAlphaUpgradeESReadsGoBuildInfoLikeGoVersion(t *testing.T) {
	dir := t.TempDir()
	fixture := filepath.Join(dir, "es")
	if err := os.WriteFile(fixture, newESBuild, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, binary := range []string{buildESConfigCheck(t), fixture} {
		goVersion := exec.Command("go", "version", "-m", binary)
		goVersion.Dir = dir
		out, err := goVersion.Output()
		if err != nil {
			t.Fatalf("go version -m %s: %v", binary, err)
		}
		lines := strings.Split(strings.TrimRight(string(out), "\n"), "\n")
		want := map[string]any{"version": strings.TrimPrefix(lines[0], binary+": "), "build": []any{}}
		for _, line := range lines[1:] {
			if setting, ok := strings.CutPrefix(line, "\tbuild\t"); ok {
				want["build"] = append(want["build"].([]any), setting)
			}
		}
		if len(want["build"].([]any)) < 3 {
			t.Fatalf("go version -m shows %d build settings for %s; the comparison would check nothing:\n%s", len(want["build"].([]any)), binary, out)
		}

		code := `import importlib.util, json, sys
spec = importlib.util.spec_from_file_location("upgrade", sys.argv[1])
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
with open(sys.argv[2], "rb") as handle:
    version, build = m.go_build_info(handle.read())
print(json.dumps({"version": version, "build": build}))`
		read := exec.Command("python3", "-I", "-c", code, repoPath(upgradeESPython), binary)
		read.Dir = dir
		got, err := read.Output()
		if err != nil {
			t.Fatalf("go_build_info %s: %v", binary, err)
		}
		var gotInfo map[string]any
		if err := json.Unmarshal(got, &gotInfo); err != nil {
			t.Fatal(err)
		}
		if fmt.Sprint(gotInfo) != fmt.Sprint(want) {
			t.Fatalf("%s: the upgrade reads\n%v\ngo version -m reads\n%v", binary, gotInfo, want)
		}
	}
}

// TestRemoteAlphaUpgradeESNomadShapesMatchTheBoxAndTheSupportedConfig ties
// the upgrade's nomad.hcl shapes to the box's files and its tls block to the
// supported config's own text.
func TestRemoteAlphaUpgradeESNomadShapesMatchTheBoxAndTheSupportedConfig(t *testing.T) {
	if len(boxNomadHCL) != 529 || len(boxNomadHCLLocked) != 1126 {
		t.Fatalf("the box's nomad.hcl fixtures are %d and %d bytes; the box's files are 529 and 1126", len(boxNomadHCL), len(boxNomadHCLLocked))
	}
	if got := sha256Hex([]byte(boxNomadHCLLocked)); got != "ea33305501c6f9cfc24fb00c678042580ed7d84ab6867f49c27a335d131d5163" {
		t.Fatalf("the locked fixture's SHA-256 %s is not the box's", got)
	}
	unknown := strings.Replace(boxNomadHCLHTTPS, `tls_min_version        = "tls13"`, `tls_min_version        = "tls12"`, 1)
	code := `import importlib.util, json, sys
spec = importlib.util.spec_from_file_location("upgrade", sys.argv[1])
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
fixtures = json.load(sys.stdin)
print(json.dumps({"prelock": m.NOMAD_HCL_PRELOCK_SHA256, "locked": m.NOMAD_HCL_LOCKED_SHA256, "block": m.NOMAD_TLS_BLOCK,
                  "tls_dir": m.NOMAD_TLS_DIR, "server_name": m.NOMAD_SERVER_NAME,
                  "shapes": [m.nomad_hcl_shape(text.encode())[0] for text in fixtures]}))`
	cmd := exec.Command("python3", "-I", "-c", code, repoPath(upgradeESPython))
	cmd.Dir = t.TempDir()
	fixtures, _ := json.Marshal([]string{boxNomadHCL, boxNomadHCLLocked, boxNomadHCLHTTPS, unknown})
	cmd.Stdin = bytes.NewReader(fixtures)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("nomad_hcl_shape: %v", err)
	}
	var got struct {
		Prelock    string `json:"prelock"`
		Locked     string `json:"locked"`
		Block      string `json:"block"`
		TLSDir     string `json:"tls_dir"`
		ServerName string `json:"server_name"`
		Shapes     []any  `json:"shapes"`
	}
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatal(err)
	}
	if got.Prelock != sha256Hex([]byte(boxNomadHCL)) || got.Locked != sha256Hex([]byte(boxNomadHCLLocked)) {
		t.Fatalf("the upgrade's nomad.hcl hashes %s and %s are not the fixtures'", got.Prelock, got.Locked)
	}
	if got.Block != boxNomadTLSBlock {
		t.Fatalf("NOMAD_TLS_BLOCK is not the fixture's tls block:\n%s", got.Block)
	}
	if fmt.Sprint(got.Shapes) != "[<nil> locked-http https <nil>]" {
		t.Fatalf("the shapes of the pre-lock, locked, https and an unknown nomad.hcl: %v", got.Shapes)
	}
	// The tls block, its directory and the server name are the supported
	// config's own.
	setup := mustRead(t, repoPath("scripts/70_linux_setup.sh"))
	for _, want := range []string{
		strings.ReplaceAll(boxNomadTLSBlock, got.TLSDir, "${NOMAD_TLS_DIR}"),
		`NOMAD_CONFIG_DIR="/etc/nomad.d"`, `NOMAD_TLS_DIR="${NOMAD_CONFIG_DIR}/tls"`,
		`NOMAD_TLS_SERVER_NAME="` + got.ServerName + `"`,
	} {
		if !strings.Contains(setup, want) {
			t.Errorf("scripts/70_linux_setup.sh does not hold:\n%s", want)
		}
	}
	if got.TLSDir != "/etc/nomad.d/tls" {
		t.Fatalf("NOMAD_TLS_DIR %s", got.TLSDir)
	}
}

func TestRemoteAlphaUpgradeESCheckChangesNothing(t *testing.T) {
	h := newUpgradeHost(t, buildESConfigCheck(t))
	before := h.snapshot()
	report, stderr, code := h.check()
	if code != 0 {
		t.Fatalf("check exited %d: %s\n%v", code, stderr, report["blockers"])
	}
	if blockers := report["blockers"].([]any); len(blockers) != 0 {
		t.Fatalf("blockers on a box-shaped host: %v", blockers)
	}
	if report["shape"] != "locked-http" || report["result"] != "ready" {
		t.Fatalf("shape %v, result %v", report["shape"], report["result"])
	}
	parts := report["parts"].(map[string]any)
	for part, want := range map[string]string{
		"nomad.hcl": "locked-http (", "Nomad's TLS directory": "absent", "es.json": "locked-http (Nomad at http://127.0.0.1:4646)",
		"the ES binaries": "locked-http (builds of " + boxESCommit + ")",
	} {
		if state, _ := parts[part].(string); !strings.HasPrefix(state, want) {
			t.Errorf("part %s: %q, want %q", part, state, want)
		}
	}
	esConfig := report["es_config"].(map[string]any)
	if fmt.Sprint(esConfig["changes"]) != "[nomad.base_url nomad.server_name nomad.root_ca_file nomad.server_spki_sha256 admission_policy.workload_grants]" ||
		esConfig["new_es_accepts_migrated_config"] != true {
		t.Fatalf("es_config report: %v", esConfig)
	}
	if report["retained_result_key"] != "exists" || report["nomad_allocation_containers"] != float64(0) {
		t.Fatalf("retained_result_key %v, allocation containers %v", report["retained_result_key"], report["nomad_allocation_containers"])
	}
	if changes := report["changes"].([]any); len(changes) != 5 {
		t.Fatalf("changes %v", changes)
	}
	health := report["health"].(map[string]any)
	for _, url := range []string{"https://127.0.0.1:8445/health", "https://127.0.0.1:8445/v1/executions:contract", "https://127.0.0.1:8444/health"} {
		if health[url] != "200" {
			t.Fatalf("health %v", health)
		}
	}
	assertRestored(t, before, h.snapshot())
	if len(before) != len(h.snapshot()) {
		t.Fatalf("check created files")
	}
	onlyReads(t, h, "check")
	if got := strings.Join(h.calls("curl http://127.0.0.1:4646"), " | "); got != "curl http://127.0.0.1:4646/v1/status/leader" {
		t.Fatalf("check's Nomad requests: %q", got)
	}
}

func TestRemoteAlphaUpgradeESCheckRefusesWhatItWasNotWrittenFor(t *testing.T) {
	helper := buildESConfigCheck(t)
	writeESConfig := func(h *upgradeHost, edit func(doc map[string]any)) {
		var doc map[string]any
		_ = json.Unmarshal(boxStartESConfig(t, "http://127.0.0.1:4646"), &doc)
		edit(doc)
		data, _ := json.Marshal(doc)
		h.write("etc/execution-substrate/es.json", string(data), 0o640)
	}
	cases := []struct {
		name   string
		break_ func(h *upgradeHost)
		scope  string
		says   string
	}{
		// The shape: every part is named whenever one is unknown or the
		// parts disagree.
		{"nomad.hcl is the pre-lock file", func(h *upgradeHost) {
			h.write("etc/nomad.d/nomad.hcl", boxNomadHCL, 0o640)
		}, "shape", "nomad.hcl: pre-lock (Remote Alpha 0.7's config: ES PR #54's upgrade has not run); Nomad's TLS directory: absent; " +
			"es.json: locked-http (Nomad at http://127.0.0.1:4646); the ES binaries: locked-http (builds of " + boxESCommit + ")"},
		{"nomad.hcl is not the box's", func(h *upgradeHost) {
			h.write("etc/nomad.d/nomad.hcl", strings.Replace(boxNomadHCLLocked, `bootstrap_expect = 1`, `bootstrap_expect = 3`, 1), 0o640)
		}, "shape", "nomad.hcl: unknown (SHA-256 "},
		{"nomad.hcl has the tls block but nothing else moved", func(h *upgradeHost) {
			h.write("etc/nomad.d/nomad.hcl", boxNomadHCLHTTPS, 0o640)
		}, "shape", "nomad.hcl: https (the lock and the supported config's tls block); Nomad's TLS directory: absent"},
		{"an empty TLS directory exists", func(h *upgradeHost) {
			h.mkdir("etc/nomad.d/tls", 0o755)
		}, "shape", "Nomad's TLS directory: present, but holds [], not exactly ['ca.pem', 'server-key.pem', 'server.pem']"},
		{"TLS material was issued but nothing else moved", func(h *upgradeHost) { h.issueTLS() },
			"shape", "nomad.hcl: locked-http (ES PR #54's lock, plain HTTP); Nomad's TLS directory: https ("},
		{"the TLS directory is group-writable", func(h *upgradeHost) {
			h.issueTLS()
			_ = os.Chmod(h.path("etc/nomad.d/tls"), 0o775)
		}, "shape", "Nomad's TLS directory: present, but not root:root 0755"},
		{"the TLS key is readable by others", func(h *upgradeHost) {
			h.issueTLS()
			_ = os.Chmod(h.path("etc/nomad.d/tls/server-key.pem"), 0o644)
		}, "shape", "Nomad's TLS directory: present, but its material fails the setup's nomad_tls_material_ok"},
		{"es.json has a key the box's build lacks", func(h *upgradeHost) {
			writeESConfig(h, func(doc map[string]any) { doc["http"].(map[string]any)["idle_timeout_seconds"] = 5 })
		}, "shape", "es.json: unknown (keys: unexpected ['http.idle_timeout_seconds'], missing [])"},
		{"es.json reaches Nomad elsewhere", func(h *upgradeHost) {
			writeESConfig(h, func(doc map[string]any) { doc["nomad"].(map[string]any)["base_url"] = "http://localhost:4646" })
		}, "shape", "es.json: unknown (nomad.base_url 'http://localhost:4646')"},
		{"es.json names another token file", func(h *upgradeHost) {
			writeESConfig(h, func(doc map[string]any) { doc["nomad"].(map[string]any)["token_file"] = "/etc/elsewhere/es-token" })
		}, "shape", "es.json: unknown (nomad.token_file or execution.retained_result_auth is not what ES PR #54's upgrade set)"},
		{"es.json was moved to HTTPS by hand", func(h *upgradeHost) {
			writeESConfig(h, func(doc map[string]any) {
				nomad := doc["nomad"].(map[string]any)
				nomad["base_url"], nomad["server_name"] = "https://127.0.0.1:4646", "server.global.nomad"
				nomad["root_ca_file"], nomad["server_spki_sha256"] = "/etc/nomad.d/tls/ca.pem", strings.Repeat("a", 64)
				doc["admission_policy"] = exampleOperatorAndControlPlaneAdmissionPolicy(t)
			})
		}, "shape", "Nomad's TLS directory: absent; es.json: https keys, but nomad.server_spki_sha256 is not the key of the server certificate on disk"},
		// The box's es.json as ES PR #60's upgrade left it on 2026-11-25: the
		// start keys and the four Nomad TLS keys, no workload grants. This
		// upgrade does not move it (it starts from locked-http); the upgrade
		// between https commits (ES PR #67) does, and writes the grants.
		{"es.json as an upgrade before workload grants left the box", func(h *upgradeHost) {
			writeESConfig(h, func(doc map[string]any) {
				nomad := doc["nomad"].(map[string]any)
				nomad["base_url"], nomad["server_name"] = "https://127.0.0.1:4646", "server.global.nomad"
				nomad["root_ca_file"], nomad["server_spki_sha256"] = "/etc/nomad.d/tls/ca.pem", strings.Repeat("a", 64)
				if _, ok := doc["admission_policy"]; ok {
					panic("the box's es.json has no admission_policy")
				}
			})
		}, "shape", "es.json: https without workload grants (where an upgrade before workload grants left it; " +
			"this upgrade starts from locked-http, and the upgrade between https commits moves it)"},
		{"es.json has workload grants this upgrade did not write", func(h *upgradeHost) {
			writeESConfig(h, func(doc map[string]any) {
				nomad := doc["nomad"].(map[string]any)
				nomad["base_url"], nomad["server_name"] = "https://127.0.0.1:4646", "server.global.nomad"
				nomad["root_ca_file"], nomad["server_spki_sha256"] = "/etc/nomad.d/tls/ca.pem", strings.Repeat("a", 64)
				policy := exampleOperatorAndControlPlaneAdmissionPolicy(t)
				rules := policy["workload_grants"].(map[string]any)["rules"].([]any)
				rules[0].(map[string]any)["artifact_type"] = "static-service"
				doc["admission_policy"] = policy
			})
		}, "shape", "es.json: unknown (es.json already has an admission_policy other than the workload grants this upgrade writes; it was changed by something other than this upgrade)"},
		{"the ES binaries are another build", func(h *upgradeHost) {
			h.write("usr/local/lib/execution-substrate/bin/es", string(stampedBinary("es", "go1.26.5", strings.Repeat("a", 40), "false")), 0o755)
		}, "shape", "the ES binaries: unknown (es built from " + strings.Repeat("a", 40) + ", es-runtime-support built from " + boxESCommit + ")"},
		{"es is a build of a modified checkout", func(h *upgradeHost) {
			h.write("usr/local/lib/execution-substrate/bin/es", string(stampedBinary("es", "go1.26.5", boxESCommit, "true")), 0o755)
		}, "shape", "the ES binaries: unknown (es is a build of a modified checkout of " + boxESCommit + ")"},
		{"es is not a Go binary", func(h *upgradeHost) {
			h.write("usr/local/lib/execution-substrate/bin/es", "old es build\n", 0o755)
		}, "shape", "the ES binaries: unknown (es: not a 64-bit little-endian ELF file)"},
		{"the commit named is the box's own build", func(h *upgradeHost) { h.commit = boxESCommit },
			"commit", boxESCommit + " is the build ES PR #54's upgrade installed"},

		// Owners, modes and what else Nomad loads.
		{"es.json is world-readable", func(h *upgradeHost) {
			_ = os.Chmod(h.path("etc/execution-substrate/es.json"), 0o644)
		}, "es_config", "not root:es 0640"},
		{"nomad.hcl is world-readable", func(h *upgradeHost) {
			_ = os.Chmod(h.path("etc/nomad.d/nomad.hcl"), 0o644)
		}, "nomad_hcl", "nomad.hcl is not root:root 0640"},
		{"Nomad would load another config", func(h *upgradeHost) {
			h.write("etc/nomad.d/tls.hcl", "tls {}\n", 0o644)
		}, "nomad_hcl", "would also load ['tls.hcl']"},
		{"Nomad's data directory is group-readable", func(h *upgradeHost) {
			_ = os.Chmod(h.path("opt/nomad/data"), 0o750)
		}, "nomad_dirs", "/opt/nomad/data is not a root:root 0700 directory"},
		{"Nomad's data directory is a link", func(h *upgradeHost) {
			_ = os.RemoveAll(h.path("opt/nomad/data"))
			_ = os.Symlink(h.path("var/backups"), h.path("opt/nomad/data"))
		}, "nomad_dirs", "/opt/nomad/data is not a root:root 0700 directory"},
		{"the ES token file is missing", func(h *upgradeHost) {
			_ = os.Remove(h.path("etc/execution-substrate/nomad-acl/es-token"))
		}, "nomad_acl", "/etc/execution-substrate/nomad-acl/es-token: No such file or directory"},
		{"the management token is group-readable", func(h *upgradeHost) {
			_ = os.Chmod(h.path("etc/execution-substrate/nomad-acl/management-token"), 0o640)
		}, "nomad_acl", "/etc/execution-substrate/nomad-acl/management-token is not a 0600 file"},
		{"the retained-result key is missing", func(h *upgradeHost) {
			_ = os.Remove(h.path("etc/execution-substrate/retained-result-auth/es.key"))
		}, "retained_result_key", "the retained-result key ES PR #54's upgrade made is missing"},
		{"a retained-result key of the wrong size", func(h *upgradeHost) {
			h.write("etc/execution-substrate/retained-result-auth/es.key", "short", 0o400)
		}, "retained_result_key", "exactly 32 bytes"},

		// Services and Nomad.
		{"a service is down", func(h *upgradeHost) { h.mark("inactive-vault", "") }, "services", "not every service is active"},
		{"es.service runs ES as root", func(h *upgradeHost) { h.mark("es-user", "root") }, "es_unit", "runs as 'root'"},
		{"es.service starts another binary", func(h *upgradeHost) {
			h.mark("es-argv", "/opt/es -config /etc/execution-substrate/es.json")
		}, "es_unit", "does not start"},
		{"ES is not healthy", func(h *upgradeHost) { h.mark("unhealthy", "") }, "health", "do not all answer 200"},
		{"Nomad has no leader", func(h *upgradeHost) { h.mark("no-leader", "") }, "nomad", "Nomad has no named leader at http://127.0.0.1:4646"},
		{"an allocation is running", func(h *upgradeHost) { h.mark("allocs", "3f1c9a\n") },
			"nomad", "1 container(s) of Nomad allocations are running"},
		{"Docker cannot be asked", func(h *upgradeHost) { h.mark("docker-fails", "") },
			"nomad", "cannot list the containers of Nomad's allocations: Cannot connect to the Docker daemon"},

		// The payload.
		{"the payload is from another commit", func(h *upgradeHost) {
			writeJSONFile(t, filepath.Join(h.payload, "provenance.json"), map[string]any{"commit": strings.Repeat("a", 40), "go_version": "go1.26.5", "vcs_modified": false})
		}, "payload", "not the named commit"},
		{"a payload binary changed", func(h *upgradeHost) {
			_ = os.WriteFile(filepath.Join(h.payload, "es"), []byte("tampered\n"), 0o755)
		}, "payload", "does not match its provenance"},
		{"the payload directory is group-writable", func(h *upgradeHost) {
			_ = os.Chmod(h.payload, 0o775)
		}, "payload", "group and others cannot write"},
		{"the payload directory belongs to another account", func(h *upgradeHost) {
			h.payload = foreignOwnedDir(t)
		}, "payload", "a directory that root owns (root:root)"},
		{"the payload directory belongs to another group", func(h *upgradeHost) {
			giveAnotherGroup(t, h.payload)
		}, "payload", "a directory that root owns (root:root)"},
		{"a payload binary belongs to another group", func(h *upgradeHost) {
			giveAnotherGroup(t, filepath.Join(h.payload, "es-runtime-support"))
		}, "payload", "the payload file es-runtime-support must be root:root"},
		{"provenance.json belongs to another group", func(h *upgradeHost) {
			giveAnotherGroup(t, filepath.Join(h.payload, "provenance.json"))
		}, "payload", "provenance.json must be root:root"},
		{"es names another commit in its own build info", func(h *upgradeHost) {
			h.replacePayloadFile("es", stampedBinary("es", "go1.26.5", strings.Repeat("a", 40), "false"))
		}, "payload", "vcs.revision '" + strings.Repeat("a", 40) + "'"},
		{"es-runtime-support is a build of a modified checkout", func(h *upgradeHost) {
			h.replacePayloadFile("es-runtime-support", stampedBinary("es-runtime-support", "go1.26.5", upgradeTestCommit, "true"))
		}, "payload", "vcs.modified 'true'"},
		{"es was built with another Go", func(h *upgradeHost) {
			h.replacePayloadFile("es", stampedBinary("es", "go1.26.1", upgradeTestCommit, "false"))
		}, "payload", "Go 'go1.26.1'"},
		{"es carries no Go build info", func(h *upgradeHost) {
			h.replacePayloadFile("es", []byte("new es build\n"))
		}, "payload", "not a 64-bit little-endian ELF file"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newUpgradeHost(t, helper)
			tc.break_(h)
			before := h.snapshot()
			report, stderr, code := h.check()
			if code != 1 || !strings.Contains(stderr, "blocker(s); nothing was changed") {
				t.Fatalf("check exited %d: %s", code, stderr)
			}
			found := false
			for _, b := range report["blockers"].([]any) {
				blocker := b.(map[string]any)
				if blocker["scope"] == tc.scope && strings.Contains(blocker["summary"].(string), tc.says) {
					found = true
				}
			}
			if !found {
				t.Fatalf("no %s blocker saying %q in %v", tc.scope, tc.says, report["blockers"])
			}
			assertRestored(t, before, h.snapshot())
			onlyReads(t, h, "a refused check")

			// apply refuses the same host before it changes anything.
			h.clearCalls()
			_, stderr, code = h.apply()
			if code != 1 || !strings.Contains(stderr, "nothing was changed") {
				t.Fatalf("apply exited %d: %s", code, stderr)
			}
			assertRestored(t, before, h.snapshot())
			if _, err := os.Lstat(h.path("var/backups/execution-substrate-es-upgrade")); err == nil {
				t.Fatalf("a refused apply wrote a backup")
			}
			onlyReads(t, h, "a refused apply")
		})
	}
}

// otherGroup is a group the test may give files to that is not the group
// of the stand-in root (the test user's own): a supplementary group of the
// test user, or any group when the tests run as root.
func otherGroup(t *testing.T) int {
	t.Helper()
	if os.Geteuid() == 0 {
		return 1
	}
	groups, err := os.Getgroups()
	if err != nil {
		t.Fatal(err)
	}
	for _, gid := range groups {
		if gid != os.Getgid() {
			return gid
		}
	}
	t.Fatalf("the test user has no supplementary group, so no fake Nomad data can have an owner other than the stand-in root")
	return 0
}

// giveAnotherGroup gives path to a group other than the stand-in root's and
// keeps its owner, so that only the group differs.
func giveAnotherGroup(t *testing.T, path string) {
	t.Helper()
	if err := os.Lchown(path, -1, otherGroup(t)); err != nil {
		t.Fatal(err)
	}
}

// foreignOwnedDir is a directory another account owns. When the test runs
// as an ordinary user it is "/", whose owner and group both differ from the
// stand-in root's. When it runs as root, it is a new directory given to uid 1
// with root's own group, so that only the owner differs.
func foreignOwnedDir(t *testing.T) string {
	t.Helper()
	if os.Geteuid() != 0 {
		return "/"
	}
	dir := filepath.Join(t.TempDir(), "payload")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(dir, 1, os.Getgid()); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestRemoteAlphaUpgradeESApply(t *testing.T) {
	helper := buildESConfigCheck(t)
	h := newUpgradeHost(t, helper)
	before := h.snapshot()
	stdout, stderr, code := h.apply()
	if code != 0 {
		t.Fatalf("apply exited %d\nstdout %s\nstderr %s", code, stdout, stderr)
	}

	// Nomad's TLS material: what the setup's nomad_tls_issue writes, with a
	// server certificate for Nomad's names that the CA signed.
	tlsDir := h.path("etc/nomad.d/tls")
	for path, want := range map[string]os.FileMode{
		"etc/nomad.d/tls": 0o755, "etc/nomad.d/tls/ca.pem": 0o644, "etc/nomad.d/tls/server.pem": 0o644, "etc/nomad.d/tls/server-key.pem": 0o600,
	} {
		if got := modeOf(t, h.path(path)); got != want {
			t.Errorf("%s mode %04o, want %04o", path, got, want)
		}
	}
	verify := exec.Command("openssl", "verify", "-CAfile", filepath.Join(tlsDir, "ca.pem"), "-purpose", "sslserver", filepath.Join(tlsDir, "server.pem"))
	verify.Dir = tlsDir
	if out, err := verify.CombinedOutput(); err != nil {
		t.Fatalf("the server certificate does not verify under the CA: %v %s", err, out)
	}
	pin := serverKeyPin(t, filepath.Join(tlsDir, "server.pem"))

	// nomad.hcl gains the tls block and nothing else.
	if got := mustRead(t, h.path("etc/nomad.d/nomad.hcl")); got != boxNomadHCLHTTPS {
		t.Fatalf("nomad.hcl after apply:\n%s", got)
	}

	// ES's own config loader accepts the migrated es.json, which reaches
	// Nomad over HTTPS, pins the server key and carries today's workload
	// grants; nothing else changed.
	loadCheck := exec.Command(helper, h.path("etc/execution-substrate/es.json"))
	loadCheck.Dir = h.state
	if out, err := loadCheck.CombinedOutput(); err != nil {
		t.Fatalf("ES refuses the installed es.json: %v %s", err, out)
	}
	var esConfig, startConfig map[string]any
	if err := json.Unmarshal([]byte(mustRead(t, h.path("etc/execution-substrate/es.json"))), &esConfig); err != nil {
		t.Fatal(err)
	}
	nomad := esConfig["nomad"].(map[string]any)
	if nomad["base_url"] != "https://127.0.0.1:4646" || nomad["server_name"] != "server.global.nomad" ||
		nomad["root_ca_file"] != "/etc/nomad.d/tls/ca.pem" || nomad["server_spki_sha256"] != pin {
		t.Fatalf("es.json's nomad block %v; the server key's SHA-256 is %s", nomad, pin)
	}
	// The grants are those of the operator and control-plane example, whose
	// allowlist and provenance key the box's es.json shares: one exact grant
	// per allowlist entry and runtime profile.
	if want := exampleOperatorAndControlPlaneAdmissionPolicy(t); fmt.Sprint(esConfig["admission_policy"]) != fmt.Sprint(want) {
		t.Fatalf("es.json's admission_policy %v, want today's workload grants %v", esConfig["admission_policy"], want)
	}
	nomad["base_url"] = "http://127.0.0.1:4646"
	delete(nomad, "server_name")
	delete(nomad, "root_ca_file")
	delete(nomad, "server_spki_sha256")
	delete(esConfig, "admission_policy")
	_ = json.Unmarshal(boxStartESConfig(t, "http://127.0.0.1:4646"), &startConfig)
	if fmt.Sprint(esConfig) != fmt.Sprint(startConfig) {
		t.Fatalf("apply changed more of es.json than Nomad's address and TLS keys and the workload grants:\n%v\n%v", esConfig, startConfig)
	}

	for path, want := range map[string]os.FileMode{
		"etc/execution-substrate/es.json":          0o640,
		"usr/local/lib/execution-substrate/bin/es": 0o755,
		"usr/local/bin/es-runtime-support":         0o755,
		"etc/nomad.d/nomad.hcl":                    0o640,
	} {
		if got := modeOf(t, h.path(path)); got != want {
			t.Errorf("%s mode %04o, want %04o", path, got, want)
		}
	}
	if got := mustRead(t, h.path("usr/local/lib/execution-substrate/bin/es")); got != string(newESBuild) {
		t.Fatalf("es binary is not the payload's: %d bytes", len(got))
	}
	if got := mustRead(t, h.path("usr/local/bin/es-runtime-support")); got != string(newRuntimeSupportBuild) {
		t.Fatalf("runtime support binary is not the payload's: %d bytes", len(got))
	}
	if strings.Contains(stdout+stderr, "PRIVATE KEY") || strings.Contains(stdout+stderr, "01234567-89ab-cdef") {
		t.Fatalf("apply printed key or token material")
	}
	// Everything else stays as it was: the ACL token files, the retained-
	// result key, Nomad's state, and the files the upgrade does not own.
	after := h.snapshot()
	for path, entry := range before {
		switch path {
		case "etc/execution-substrate/es.json", "usr/local/lib/execution-substrate/bin/es", "usr/local/bin/es-runtime-support", "etc/nomad.d/nomad.hcl":
			continue
		}
		if after[path] != entry {
			t.Errorf("%s changed: %q -> %q", path, entry, after[path])
		}
	}

	// The order: ES stops; the TLS material is issued and the new nomad.hcl
	// validated before Nomad stops; Nomad starts on HTTPS; its ACLs are
	// provisioned and placement checked; ES starts and is verified.
	if got, want := strings.Join(h.calls("systemctl st"), " | "), "systemctl stop es | systemctl stop nomad | systemctl start nomad | systemctl start es"; got != want {
		t.Fatalf("service calls %q, want %q", got, want)
	}
	acl := " ES_USER=es OBSERVER_USER=root NOMAD_USER=root NOMAD_ADDR=https://127.0.0.1:4646 NOMAD_CACERT=/etc/nomad.d/tls/ca.pem"
	if got, want := strings.Join(h.calls("acl-setup"), " | "), "acl-setup provision"+acl+" | acl-setup placement"+acl+" | acl-setup check"+acl; got != want {
		t.Fatalf("ACL setup calls %q\nwant %q", got, want)
	}
	log := mustRead(t, filepath.Join(h.state, "calls.log"))
	order := []string{"nomad config validate", "systemctl stop nomad", "systemctl start nomad", "curl https://127.0.0.1:4646/v1/status/leader",
		"acl-setup provision", "systemctl start es", "tls-identity check https://127.0.0.1:4646", "curl https://127.0.0.1:4646/v1/jobs",
		"curl https://127.0.0.1:4646/v1/acl/policy/anonymous", "acl-setup check"}
	at := 0
	for _, step := range order {
		next := strings.Index(log[at:], step)
		if next < 0 {
			t.Fatalf("%q does not follow the steps before it in:\n%s", step, log)
		}
		at += next
	}

	backupDir, summary := readSummary(t, h)
	if summary["result"] != "applied" || summary["shape"] != "locked-http" {
		t.Fatalf("summary result %v, shape %v", summary["result"], summary["shape"])
	}
	for _, name := range []string{"manifest.json", "created.json", "payload/es", "payload/es-runtime-support", "payload/esconfigcheck"} {
		if _, err := os.Lstat(filepath.Join(backupDir, name)); err != nil {
			t.Errorf("backup lacks %s: %v", name, err)
		}
	}
	if got := strings.Join(strings.Fields(mustRead(t, filepath.Join(backupDir, "created.json"))), ""); got != `["/etc/nomad.d/tls"]` {
		t.Fatalf("created.json %s", got)
	}

	// The host is now in the shape this upgrade leaves: check and apply
	// verify it in place and change nothing.
	migrated := h.snapshot()
	h.clearCalls()
	report, stderr, code := h.check()
	if code != 0 || report["shape"] != "https" || report["result"] != "nothing to do" || len(report["changes"].([]any)) != 0 {
		t.Fatalf("check after apply: exit %d, shape %v, result %v, changes %v, blockers %v, %s",
			code, report["shape"], report["result"], report["changes"], report["blockers"], stderr)
	}
	if report["nomad_tls_identity"] != "nomad tls: tls=1.3 server_name=server.global.nomad key=pinned" {
		t.Fatalf("nomad_tls_identity %v", report["nomad_tls_identity"])
	}
	stdout, stderr, code = h.apply()
	if code != 0 || !strings.Contains(stdout, `"result": "nothing to do"`) {
		t.Fatalf("apply after apply: exit %d\nstdout %s\nstderr %s", code, stdout, stderr)
	}
	onlyReads(t, h, "a check and an apply of the migrated host")
	assertRestored(t, migrated, h.snapshot())
	if dirs := backupDirs(t, h); len(dirs) != 1 {
		t.Fatalf("the apply of a migrated host wrote a backup: %v", dirs)
	}
	for _, step := range []string{"curl https://127.0.0.1:4646/v1/status/leader", "tls-identity check https://127.0.0.1:4646", "curl https://127.0.0.1:4646/v1/jobs",
		"curl https://127.0.0.1:4646/v1/acl/policy/anonymous"} {
		if len(h.calls(step)) != 2 {
			t.Fatalf("check and apply of the migrated host did not each make %q: %v", step, h.calls(""))
		}
	}

	// On the migrated host two requests without a token prove the lock: the
	// job list shows that Nomad enforces its ACLs, and the anonymous policy's
	// 404 that no policy gives anyone capabilities. A Nomad that lists jobs to
	// anyone over HTTPS is refused by check and apply, and nothing changes.
	h.mark("https-jobs-open", "")
	h.clearCalls()
	report, stderr, code = h.check()
	if code != 1 || !strings.Contains(stderr, "blocker(s); nothing was changed") ||
		!strings.Contains(fmt.Sprint(report["blockers"]), "Nomad answers an anonymous job list over HTTPS with 200, not 403") {
		t.Fatalf("check of a migrated host whose Nomad lists jobs to anyone: exit %d, blockers %v, %s", code, report["blockers"], stderr)
	}
	_, stderr, code = h.apply()
	if code != 1 || !strings.Contains(stderr, "nothing was changed") {
		t.Fatalf("apply of a migrated host whose Nomad lists jobs to anyone: exit %d: %s", code, stderr)
	}
	onlyReads(t, h, "a refused check and apply of the migrated host")
	assertRestored(t, migrated, h.snapshot())
	if err := os.Remove(filepath.Join(h.state, "https-jobs-open")); err != nil {
		t.Fatal(err)
	}

	// An anonymous policy that opens only ES's namespace leaves the job list,
	// which asks about the namespace default, at 403. The policy request
	// alone shows it, and check and apply are refused for it alone.
	h.mark("anonymous-policy", "")
	h.clearCalls()
	report, stderr, code = h.check()
	blockers := fmt.Sprint(report["blockers"])
	if code != 1 || !strings.Contains(stderr, "1 blocker(s); nothing was changed") ||
		!strings.Contains(blockers, "Nomad answers a request without a token for its anonymous ACL policy over HTTPS with 200, not 404") ||
		strings.Contains(blockers, "anonymous job list") {
		t.Fatalf("check of a migrated host whose Nomad holds an anonymous policy: exit %d, blockers %v, %s", code, report["blockers"], stderr)
	}
	_, stderr, code = h.apply()
	if code != 1 || !strings.Contains(stderr, "nothing was changed") {
		t.Fatalf("apply of a migrated host whose Nomad holds an anonymous policy: exit %d: %s", code, stderr)
	}
	onlyReads(t, h, "a refused check and apply of a migrated host with an anonymous policy")
	assertRestored(t, migrated, h.snapshot())
	if err := os.Remove(filepath.Join(h.state, "anonymous-policy")); err != nil {
		t.Fatal(err)
	}

	// A binary that names the commit but is not the payload's build is no
	// part of the shape this upgrade leaves.
	other := stampedBinary("es", "go1.26.5", upgradeTestCommit, "false")
	other = bytes.Replace(other, []byte("build\t-compiler=gc\n"), []byte("build\t-compiler=xx\n"), 1)
	h.write("usr/local/lib/execution-substrate/bin/es", string(other), 0o755)
	report, _, code = h.check()
	if code != 1 || !strings.Contains(fmt.Sprint(report["blockers"]), "the ES binaries: unknown (es names "+upgradeTestCommit+" but is not the verified payload's build)") {
		t.Fatalf("check of a migrated host with another build of the commit: exit %d, %v", code, report["blockers"])
	}
	h.write("usr/local/lib/execution-substrate/bin/es", string(newESBuild), 0o755)

	// rollback puts the host back exactly: Nomad on plain HTTP, no TLS
	// directory.
	h.clearCalls()
	stdout, stderr, code = h.run("rollback", "--backup-dir", backupDir)
	if code != 0 {
		t.Fatalf("rollback exited %d\nstdout %s\nstderr %s", code, stdout, stderr)
	}
	assertRestored(t, before, h.snapshot())
	if h.marked("tls") || !h.marked("locked") || h.marked("inactive-es") || h.marked("inactive-nomad") {
		t.Fatalf("after the rollback: tls %v, locked %v, es down %v, nomad down %v", h.marked("tls"), h.marked("locked"), h.marked("inactive-es"), h.marked("inactive-nomad"))
	}
	if got, want := strings.Join(h.calls("systemctl st"), " | "), "systemctl stop es | systemctl stop nomad | systemctl start nomad | systemctl start es"; got != want {
		t.Fatalf("rollback service calls %q, want %q", got, want)
	}
	if len(h.calls("curl http://127.0.0.1:4646/v1/status/leader")) == 0 {
		t.Fatalf("the rollback did not wait for Nomad's leader on plain HTTP: %v", h.calls("curl"))
	}

	// After the rollback the host checks clean again.
	if report, stderr, code := h.check(); code != 0 || report["shape"] != "locked-http" {
		t.Fatalf("check after rollback exited %d: %s %v", code, stderr, report["blockers"])
	}
}

func TestRemoteAlphaUpgradeESApplyRollsBackOnFailure(t *testing.T) {
	helper := buildESConfigCheck(t)
	cases := []struct {
		name    string
		marker  string
		failure string
	}{
		{"the new Nomad config does not validate", "nomad-invalid", "nomad config validate"},
		{"Nomad cannot read the TLS files the config names", "tls-unreadable", "Error when parsing TLS configuration"},
		{"Nomad names no leader over HTTPS", "https-no-leader", "Nomad named no leader at https://127.0.0.1:4646"},
		{"Nomad cannot place ES's jobs after its start", "placement-fails", "nomad_acl_setup.sh placement failed"},
		{"ES does not start", "fail-start-es-once", "systemctl start es"},
		{"ES's TLS settings do not hold against Nomad", "identity-fails", "do not hold against the running Nomad"},
		{"Nomad lists jobs to anyone over HTTPS", "https-jobs-open", "Nomad answers an anonymous job list over HTTPS with 200, not 403"},
		{"Nomad holds an anonymous policy", "anonymous-policy", "Nomad answers a request without a token for its anonymous ACL policy over HTTPS with 200, not 404"},
		{"the ACL check fails after ES starts", "acl-check-fails", "nomad_acl_setup.sh check failed"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newUpgradeHost(t, helper)
			before := h.snapshot()
			h.mark(tc.marker, "")
			stdout, stderr, code := h.apply()
			if code != 1 || !strings.Contains(stderr, "apply failed; result rolled_back;") {
				t.Fatalf("apply exited %d\nstdout %s\nstderr %s", code, stdout, stderr)
			}
			assertRestored(t, before, h.snapshot())
			if h.marked("tls") || !h.marked("locked") || h.marked("inactive-es") || h.marked("inactive-nomad") {
				t.Fatalf("after the rollback: tls %v, locked %v, es down %v, nomad down %v", h.marked("tls"), h.marked("locked"), h.marked("inactive-es"), h.marked("inactive-nomad"))
			}
			_, summary := readSummary(t, h)
			if summary["result"] != "rolled_back" || !strings.Contains(fmt.Sprint(summary["failure"]), tc.failure) {
				t.Fatalf("summary result %v, failure %v", summary["result"], summary["failure"])
			}
			if removed := fmt.Sprint(summary["rollback"].(map[string]any)["removed"]); removed != "[/etc/nomad.d/tls]" {
				t.Fatalf("the rollback removed %s", removed)
			}
			calls := h.calls("systemctl st")
			if len(calls) < 2 || calls[len(calls)-2] != "systemctl start nomad" || calls[len(calls)-1] != "systemctl start es" {
				t.Fatalf("the rollback did not end by starting Nomad and ES: %v", calls)
			}
		})
	}
}

// An interruption while a command runs ends that command's whole process
// group, grandchildren included, before the rollback starts.
func TestRemoteAlphaUpgradeESApplyRollsBackWhenInterrupted(t *testing.T) {
	helper := buildESConfigCheck(t)
	cases := []struct {
		name, slow, reached string
	}{
		{"during the Nomad config validation", "slow-validate", "validating"},
		{"during the ACL setup", "slow-acl", "acl-running"},
		{"by two signals in a row", "slow-validate", "validating"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newUpgradeHost(t, helper)
			before := h.snapshot()
			h.mark(tc.slow, "")
			cmd := h.command("apply", "--payload", h.payload, "--commit", upgradeTestCommit)
			var stdout, stderr bytes.Buffer
			cmd.Stdout, cmd.Stderr = &stdout, &stderr
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			deadline := time.Now().Add(30 * time.Second)
			for !h.marked(tc.reached) {
				if time.Now().After(deadline) {
					_ = cmd.Process.Kill()
					t.Fatalf("apply never reached %s\n%s\n%s", tc.reached, stdout.String(), stderr.String())
				}
				time.Sleep(50 * time.Millisecond)
			}
			if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
				t.Fatal(err)
			}
			if strings.HasPrefix(tc.name, "by two signals") {
				// A second signal right after the first is ignored and
				// does not break off the drain or the rollback.
				_ = cmd.Process.Signal(syscall.SIGINT)
			}
			err := cmd.Wait()
			exitErr, ok := err.(*exec.ExitError)
			if !ok || exitErr.ExitCode() != 1 || !strings.Contains(stderr.String(), "result rolled_back") {
				t.Fatalf("interrupted apply: %v\nstdout %s\nstderr %s", err, stdout.String(), stderr.String())
			}
			assertRestored(t, before, h.snapshot())
			_, summary := readSummary(t, h)
			if summary["result"] != "rolled_back" || !strings.Contains(fmt.Sprint(summary["failure"]), "Interrupted") {
				t.Fatalf("summary result %v, failure %v", summary["result"], summary["failure"])
			}
			if h.marked("inactive-es") || h.marked("inactive-nomad") {
				t.Fatalf("ES or Nomad left stopped")
			}
			time.Sleep(3 * time.Second)
			if h.marked("grandchild-wrote") {
				t.Fatalf("a grandchild of the interrupted command kept running after the rollback")
			}
		})
	}
}

func TestRemoteAlphaUpgradeESRollbackFailuresAreReported(t *testing.T) {
	helper := buildESConfigCheck(t)

	t.Run("nothing is restored under an ES that will not stop", func(t *testing.T) {
		h := newUpgradeHost(t, helper)
		h.mark("acl-check-fails", "")
		h.mark("fail-stop-es", "1") // apply's own stop works; the rollback's fails
		_, stderr, code := h.apply()
		if code != 1 || !strings.Contains(stderr, "result rollback_failed") {
			t.Fatalf("apply exited %d: %s", code, stderr)
		}
		_, summary := readSummary(t, h)
		if !strings.Contains(fmt.Sprint(summary["rollback_failure"]), "Failed to stop es") {
			t.Fatalf("rollback_failure %v", summary["rollback_failure"])
		}
		if got := mustRead(t, h.path("usr/local/lib/execution-substrate/bin/es")); got != string(newESBuild) {
			t.Fatalf("files were restored under a running ES: es binary of %d bytes", len(got))
		}
	})

	t.Run("a Nomad without a leader after the restore fails it", func(t *testing.T) {
		h := newUpgradeHost(t, helper)
		before := h.snapshot()
		h.mark("acl-check-fails", "")
		h.mark("leader-starts", "1") // the HTTPS start elects a leader; the restore's does not
		_, stderr, code := h.apply()
		if code != 1 || !strings.Contains(stderr, "result rollback_failed") {
			t.Fatalf("apply exited %d: %s", code, stderr)
		}
		_, summary := readSummary(t, h)
		if !strings.Contains(fmt.Sprint(summary["rollback_failure"]), "named no leader at http://127.0.0.1:4646") {
			t.Fatalf("rollback_failure %v", summary["rollback_failure"])
		}
		assertRestored(t, before, h.snapshot())
		if h.marked("inactive-es") || h.marked("inactive-nomad") {
			t.Fatalf("the failed restore left ES or Nomad stopped")
		}
	})

	applied := func(t *testing.T) (*upgradeHost, string) {
		h := newUpgradeHost(t, helper)
		if _, stderr, code := h.apply(); code != 0 {
			t.Fatalf("apply exited %d: %s", code, stderr)
		}
		backupDir, _ := readSummary(t, h)
		h.clearCalls()
		return h, backupDir
	}

	t.Run("rollback exits 1 when Nomad names no leader", func(t *testing.T) {
		h, backupDir := applied(t)
		h.mark("leader-starts", "0")
		_, stderr, code := h.run("rollback", "--backup-dir", backupDir)
		if code != 1 || !strings.Contains(stderr, "named no leader") {
			t.Fatalf("rollback exited %d: %s", code, stderr)
		}
	})

	t.Run("a damaged backup is refused before a service stops", func(t *testing.T) {
		h, backupDir := applied(t)
		copies, _ := filepath.Glob(filepath.Join(backupDir, "files", "*-es.json"))
		if len(copies) != 1 {
			t.Fatalf("backup copies of es.json: %v", copies)
		}
		if err := os.WriteFile(copies[0], []byte("{}\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		migrated := h.snapshot()
		_, stderr, code := h.run("rollback", "--backup-dir", backupDir)
		if code != 1 || !strings.Contains(stderr, "does not match its manifest") {
			t.Fatalf("rollback exited %d: %s", code, stderr)
		}
		onlyReads(t, h, "a refused rollback")
		assertRestored(t, migrated, h.snapshot())
	})

	t.Run("a backup that names another path to remove is refused before a service stops", func(t *testing.T) {
		h, backupDir := applied(t)
		if err := os.WriteFile(filepath.Join(backupDir, "created.json"), []byte(`["/etc/nomad.d"]`+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		migrated := h.snapshot()
		_, stderr, code := h.run("rollback", "--backup-dir", backupDir)
		if code != 1 || !strings.Contains(stderr, "names paths that apply does not create") {
			t.Fatalf("rollback exited %d: %s", code, stderr)
		}
		onlyReads(t, h, "a refused rollback")
		assertRestored(t, migrated, h.snapshot())
	})
}

// freeLoopbackPorts returns n TCP ports on 127.0.0.1 that were free a
// moment ago.
func freeLoopbackPorts(t *testing.T, n int) []int {
	t.Helper()
	var ports []int
	var listeners []net.Listener
	for len(ports) < n {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		listeners = append(listeners, listener)
		ports = append(ports, listener.Addr().(*net.TCPAddr).Port)
	}
	for _, listener := range listeners {
		_ = listener.Close()
	}
	return ports
}

// nomadRequest sends one request to the test's real Nomad and returns the
// status (0 when no answer came) and the body.
func nomadRequest(t *testing.T, client *http.Client, method, url, token string, body any) (int, []byte) {
	t.Helper()
	var reader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		reader = bytes.NewReader(data)
	}
	request, err := http.NewRequest(method, url, reader)
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		request.Header.Set("X-Nomad-Token", token)
	}
	response, err := client.Do(request)
	if err != nil {
		return 0, []byte(err.Error())
	}
	defer response.Body.Close()
	data, _ := io.ReadAll(response.Body)
	return response.StatusCode, data
}

// nomadACLRules are the ES and observer policy rules of
// scripts/internal/nomad_acl.py.
func nomadACLRules(t *testing.T) (string, string) {
	t.Helper()
	code := `import importlib.util, json, sys
spec = importlib.util.spec_from_file_location("nomad_acl", sys.argv[1])
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
print(json.dumps([m.ES_POLICY_RULES, m.OBSERVER_POLICY_RULES]))`
	cmd := exec.Command("python3", "-I", "-c", code, repoPath("scripts/internal/nomad_acl.py"))
	cmd.Dir = t.TempDir()
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("read nomad_acl.py's rules: %v", err)
	}
	var rules []string
	if err := json.Unmarshal(out, &rules); err != nil || len(rules) != 2 {
		t.Fatalf("nomad_acl.py's rules: %s %v", out, err)
	}
	return rules[0], rules[1]
}

// TestRemoteAlphaUpgradeESMovesARealNomadToHTTPS runs check, apply, the
// no-op and rollback against a real Nomad agent on the box's own nomad.hcl,
// and lets apply run the real scripts/nomad_acl_setup.sh (through sudo, as
// root, like on the box) and the real nomad_tls_identity.py, so that no
// stand-in can hide a broken step. The test sets Nomad up the way ES PR
// #54's upgrade left the box: ACLs bootstrapped over plain HTTP, the ES and
// observer tokens in their files, and the observer policy without
// list-jobs. Only ES and the services around it stay fakes.
func TestRemoteAlphaUpgradeESMovesARealNomadToHTTPS(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the box's Nomad client config is Linux's")
	}
	if _, err := exec.LookPath("nomad"); err != nil {
		t.Skipf("nomad binary lookup failed: %v", err)
	}
	sudoCheck := exec.Command("sudo", "-n", "true")
	sudoCheck.Dir = t.TempDir()
	if output, err := sudoCheck.CombinedOutput(); err != nil {
		t.Skipf("needs passwordless sudo, which runs scripts/nomad_acl_setup.sh as root: %v: %s", err, strings.TrimSpace(string(output)))
	}
	realCurl, err := exec.LookPath("curl")
	if err != nil {
		t.Fatalf("curl lookup failed: %v", err)
	}
	h := newUpgradeHost(t, buildESConfigCheck(t))
	ports := freeLoopbackPorts(t, 3)
	port := strconv.Itoa(ports[0])
	plainAddr, httpsAddr := "http://127.0.0.1:"+port, "https://127.0.0.1:"+port
	nomadData := t.TempDir()
	override := fmt.Sprintf(`data_dir = %q
ports {
  http = %d
  rpc  = %d
  serf = %d
}
advertise {
  http = "127.0.0.1:%d"
  rpc  = "127.0.0.1:%d"
  serf = "127.0.0.1:%d"
}
client {
  servers = ["127.0.0.1:%d"]
}
`, nomadData, ports[0], ports[1], ports[2], ports[0], ports[1], ports[2], ports[1])
	overrideTLS := fmt.Sprintf("tls {\n  ca_file   = %q\n  cert_file = %q\n  key_file  = %q\n}\n",
		h.path("etc/nomad.d/tls/ca.pem"), h.path("etc/nomad.d/tls/server.pem"), h.path("etc/nomad.d/tls/server-key.pem"))
	for name, text := range map[string]string{"override.hcl": override, "override-tls.hcl": overrideTLS} {
		if err := os.WriteFile(filepath.Join(h.state, name), []byte(text), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// The real nomad validates configs and runs the agent.
	if err := os.Remove(filepath.Join(h.bin, "nomad")); err != nil {
		t.Fatal(err)
	}
	h.mark("real-nomad", "")
	h.env = map[string]string{
		"ES_UPGRADE_TEST_NOMAD_PORT":   port,
		"ES_UPGRADE_TEST_ACL_SUDO":     "1",
		"ES_UPGRADE_TEST_ACL_SETUP":    "",
		"ES_UPGRADE_TEST_TLS_IDENTITY": "",
		"ES_UPGRADE_TEST_WAIT_SECONDS": "90",
		"FAKE_NOMAD_PORT":              port,
		"REAL_CURL":                    realCurl,
	}
	h.write("etc/execution-substrate/es.json", string(boxStartESConfig(t, plainAddr)), 0o640)
	managementFile := h.path("etc/execution-substrate/nomad-acl/management-token")
	t.Cleanup(func() {
		cmd := exec.Command(filepath.Join(h.bin, "systemctl"), "stop", "nomad")
		cmd.Dir = h.state
		cmd.Env = h.environ()
		_ = cmd.Run()
	})
	dumpNomad := func() string { return mustRead(t, filepath.Join(h.state, "nomad.log")) }

	// Nomad on plain HTTP with ACLs, as ES PR #54's upgrade left the box.
	h.systemctl("start", "nomad")
	plain := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{Proxy: nil}}
	deadline := time.Now().Add(60 * time.Second)
	for {
		status, body := nomadRequest(t, plain, "GET", plainAddr+"/v1/status/leader", "", nil)
		if status == 200 && len(bytes.Trim(body, "\" \n")) > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("Nomad named no leader on plain HTTP: %d %s\n%s", status, body, dumpNomad())
		}
		time.Sleep(200 * time.Millisecond)
	}
	status, body := nomadRequest(t, plain, "POST", plainAddr+"/v1/acl/bootstrap", "", map[string]any{})
	var bootstrap struct{ SecretID string }
	if err := json.Unmarshal(body, &bootstrap); status != 200 || err != nil || bootstrap.SecretID == "" {
		t.Fatalf("ACL bootstrap: %d %s", status, body)
	}
	management := bootstrap.SecretID
	esRules, observerRules := nomadACLRules(t)
	oldObserverRules := strings.Replace(observerRules, `"list-jobs", `, "", 1)
	if oldObserverRules == observerRules {
		t.Fatalf("the observer rules hold no list-jobs to take out:\n%s", observerRules)
	}
	for _, step := range []struct {
		path string
		body map[string]any
	}{
		{"/v1/namespace/es-submit-v1", map[string]any{"Name": "es-submit-v1", "Description": "Execution Substrate submit path"}},
		{"/v1/acl/policy/es-submit-v1", map[string]any{"Name": "es-submit-v1", "Rules": esRules}},
		{"/v1/acl/policy/es-observer-v1", map[string]any{"Name": "es-observer-v1", "Rules": oldObserverRules}},
	} {
		if status, body := nomadRequest(t, plain, "POST", plainAddr+step.path, management, step.body); status != 200 {
			t.Fatalf("POST %s: %d %s", step.path, status, body)
		}
	}
	tokens := map[string]string{}
	for _, name := range []string{"es-submit-v1", "es-observer-v1"} {
		status, body := nomadRequest(t, plain, "POST", plainAddr+"/v1/acl/token", management,
			map[string]any{"Name": name, "Type": "client", "Policies": []string{name}})
		var token struct{ SecretID string }
		if err := json.Unmarshal(body, &token); status != 200 || err != nil || token.SecretID == "" {
			t.Fatalf("create the %s token: %d %s", name, status, body)
		}
		tokens[name] = token.SecretID
	}
	h.write("etc/execution-substrate/nomad-acl/es-token", tokens["es-submit-v1"]+"\n", 0o400)
	h.write("etc/execution-substrate/nomad-acl/observer-token", tokens["es-observer-v1"]+"\n", 0o400)
	staged := filepath.Join(t.TempDir(), "management-token")
	if err := os.WriteFile(staged, []byte(management+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(managementFile); err != nil {
		t.Fatal(err)
	}
	// As on the box, the token files' directory is root's, and the
	// management token root's alone.
	aclDir := filepath.Dir(managementFile)
	t.Cleanup(func() {
		remove := exec.Command("sudo", "-n", "rm", "-rf", "--", aclDir)
		remove.Dir = h.state
		if output, err := remove.CombinedOutput(); err != nil {
			t.Errorf("remove the root-owned token directory: %v %s", err, output)
		}
	})
	for _, argv := range [][]string{{"chown", "root:root", aclDir}, {"install", "-o", "root", "-g", "root", "-m", "0600", staged, managementFile}} {
		cmd := exec.Command("sudo", append([]string{"-n"}, argv...)...)
		cmd.Dir = h.state
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("sudo %v: %v %s", argv, err, output)
		}
	}
	if status, body := nomadRequest(t, plain, "GET", plainAddr+"/v1/jobs?namespace=es-submit-v1", tokens["es-observer-v1"], nil); status != 403 {
		t.Fatalf("before the upgrade the observer token lists ES's jobs: %d %s", status, body)
	}

	before := h.snapshot()
	report, stderr, code := h.check()
	if code != 0 || report["shape"] != "locked-http" {
		t.Fatalf("check exited %d: shape %v, blockers %v, %s", code, report["shape"], report["blockers"], stderr)
	}
	stdout, stderr, code := h.apply()
	if code != 0 {
		t.Fatalf("apply exited %d\nstdout %s\nstderr %s\nnomad log:\n%s", code, stdout, stderr, dumpNomad())
	}

	// Nomad now answers only over HTTPS, as the issued certificate's holder
	// for Nomad's server name, and still refuses anonymous requests.
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(mustRead(t, h.path("etc/nomad.d/tls/ca.pem")))) {
		t.Fatal("ca.pem holds no certificate")
	}
	secure := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{
		RootCAs: pool, ServerName: "server.global.nomad", MinVersion: tls.VersionTLS13,
	}}}
	if status, body := nomadRequest(t, secure, "GET", httpsAddr+"/v1/status/leader", "", nil); status != 200 {
		t.Fatalf("Nomad's leader over HTTPS: %d %s", status, body)
	}
	if status, _ := nomadRequest(t, secure, "GET", httpsAddr+"/v1/jobs", "", nil); status != 403 {
		t.Fatalf("Nomad answers an anonymous job list over HTTPS with %d, not 403", status)
	}
	if status, _ := nomadRequest(t, plain, "GET", plainAddr+"/v1/status/leader", "", nil); status == 200 {
		t.Fatalf("Nomad still answers plain HTTP")
	}
	// The real nomad_acl_setup.sh provision rewrote the observer policy and
	// kept both tokens.
	if status, body := nomadRequest(t, secure, "GET", httpsAddr+"/v1/jobs?namespace=es-submit-v1", tokens["es-observer-v1"], nil); status != 200 {
		t.Fatalf("after the upgrade the observer token cannot list ES's jobs: %d %s", status, body)
	}
	for file, token := range map[string]string{"es-token": tokens["es-submit-v1"], "observer-token": tokens["es-observer-v1"]} {
		if got := strings.TrimSpace(mustRead(t, h.path("etc/execution-substrate/nomad-acl/"+file))); got != token {
			t.Fatalf("provision replaced the %s", file)
		}
	}
	var esConfig map[string]any
	if err := json.Unmarshal([]byte(mustRead(t, h.path("etc/execution-substrate/es.json"))), &esConfig); err != nil {
		t.Fatal(err)
	}
	if nomad := esConfig["nomad"].(map[string]any); nomad["base_url"] != httpsAddr ||
		nomad["server_spki_sha256"] != serverKeyPin(t, h.path("etc/nomad.d/tls/server.pem")) {
		t.Fatalf("es.json's nomad block %v", nomad)
	}
	if got := mustRead(t, h.path("etc/nomad.d/nomad.hcl")); got != boxNomadHCLHTTPS {
		t.Fatalf("nomad.hcl after apply:\n%s", got)
	}
	backupDir, summary := readSummary(t, h)
	events := fmt.Sprint(summary["events"])
	for _, want := range []string{"nomad ACLs provisioned again", "nomad can place ES's jobs", "nomad tls: tls=1.3 server_name=server.global.nomad key=pinned",
		"nomad_acl_setup.sh check passed"} {
		if !strings.Contains(events, want) {
			t.Fatalf("apply's events lack %q: %s", want, events)
		}
	}

	// Already migrated: check and apply prove it in place, with the real
	// identity check, and change nothing.
	migrated := h.snapshot()
	h.clearCalls()
	report, stderr, code = h.check()
	if code != 0 || report["shape"] != "https" || report["result"] != "nothing to do" ||
		!strings.HasPrefix(fmt.Sprint(report["nomad_tls_identity"]), "nomad tls: tls=1.3 server_name=server.global.nomad key=pinned") {
		t.Fatalf("check of the migrated host: exit %d, shape %v, result %v, identity %v, blockers %v, %s",
			code, report["shape"], report["result"], report["nomad_tls_identity"], report["blockers"], stderr)
	}
	if stdout, stderr, code := h.apply(); code != 0 || !strings.Contains(stdout, `"result": "nothing to do"`) {
		t.Fatalf("apply of the migrated host: exit %d\nstdout %s\nstderr %s", code, stdout, stderr)
	}
	onlyReads(t, h, "a check and an apply of the migrated host")
	assertRestored(t, migrated, h.snapshot())
	if dirs := backupDirs(t, h); len(dirs) != 1 {
		t.Fatalf("the apply of a migrated host wrote a backup: %v", dirs)
	}

	// A real Nomad with an anonymous policy that opens ES's namespace: the
	// job list, which asks about the namespace default, still answers 403,
	// while anyone may list and plan jobs in ES's. check and apply refuse the
	// host for the policy request alone.
	anonymousPolicy := map[string]any{"Name": "anonymous",
		"Rules": `namespace "es-submit-v1" { capabilities = ["submit-job", "list-jobs", "read-job"] }`}
	if status, body := nomadRequest(t, secure, "POST", httpsAddr+"/v1/acl/policy/anonymous", management, anonymousPolicy); status != 200 {
		t.Fatalf("create the anonymous policy: %d %s", status, body)
	}
	deadline = time.Now().Add(30 * time.Second)
	for {
		status, body := nomadRequest(t, secure, "GET", httpsAddr+"/v1/jobs?namespace=es-submit-v1", "", nil)
		if status == 200 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the anonymous policy does not open ES's namespace: %d %s", status, body)
		}
		time.Sleep(200 * time.Millisecond)
	}
	if status, body := nomadRequest(t, secure, "GET", httpsAddr+"/v1/jobs", "", nil); status != 403 {
		t.Fatalf("with an anonymous policy for ES's namespace, the anonymous job list answers %d, not 403: %s", status, body)
	}
	h.clearCalls()
	report, stderr, code = h.check()
	blockers := fmt.Sprint(report["blockers"])
	if code != 1 || !strings.Contains(stderr, "1 blocker(s); nothing was changed") ||
		!strings.Contains(blockers, "Nomad answers a request without a token for its anonymous ACL policy over HTTPS with 200, not 404") {
		t.Fatalf("check of the migrated host with an anonymous policy: exit %d, blockers %v, %s", code, report["blockers"], stderr)
	}
	if _, stderr, code := h.apply(); code != 1 || !strings.Contains(stderr, "nothing was changed") {
		t.Fatalf("apply of the migrated host with an anonymous policy: exit %d: %s", code, stderr)
	}
	onlyReads(t, h, "a refused check and apply of the migrated host with an anonymous policy")
	assertRestored(t, migrated, h.snapshot())
	if status, body := nomadRequest(t, secure, "DELETE", httpsAddr+"/v1/acl/policy/anonymous", management, nil); status != 200 {
		t.Fatalf("delete the anonymous policy: %d %s", status, body)
	}
	if report, stderr, code := h.check(); code != 0 || report["result"] != "nothing to do" {
		t.Fatalf("check of the migrated host after the anonymous policy is gone: exit %d, blockers %v, %s", code, report["blockers"], stderr)
	}

	// rollback returns the box to plain HTTP with a leader.
	stdout, stderr, code = h.run("rollback", "--backup-dir", backupDir)
	if code != 0 {
		t.Fatalf("rollback exited %d\nstdout %s\nstderr %s\nnomad log:\n%s", code, stdout, stderr, dumpNomad())
	}
	assertRestored(t, before, h.snapshot())
	if status, body := nomadRequest(t, plain, "GET", plainAddr+"/v1/status/leader", "", nil); status != 200 {
		t.Fatalf("Nomad's leader on plain HTTP after the rollback: %d %s", status, body)
	}
	if report, stderr, code := h.check(); code != 0 || report["shape"] != "locked-http" {
		t.Fatalf("check after the rollback exited %d: shape %v, blockers %v, %s", code, report["shape"], report["blockers"], stderr)
	}
}

func TestRemoteAlphaUpgradeESBuildRefusals(t *testing.T) {
	cases := []struct {
		args []string
		says string
	}{
		{[]string{"build", "--out", repoPath("scripts/payload"), "--commit", upgradeTestCommit}, "outside the checkout"},
		{[]string{"build", "--out", filepath.Join(t.TempDir(), "payload"), "--commit", "cacf5c1"}, "full lower-case 40-character SHA-1"},
	}
	for _, tc := range cases {
		_, stderr, code := runUpgradeESPython(t, tc.args...)
		if code != 1 || !strings.Contains(stderr, tc.says) {
			t.Errorf("%v: exit %d, stderr %q", tc.args, code, stderr)
		}
	}
	if _, err := os.Lstat(repoPath("scripts/payload")); err == nil {
		t.Fatalf("a refused build wrote into the checkout")
	}
}

// fakeGo stands in for the Go toolchain in the build tests: it reports
// FAKE_GOVERSION, writes a small binary per package, and prints build info
// with FAKE_REVISION and FAKE_MODIFIED.
const fakeGo = `#!/usr/bin/env bash
set -eu
case "$1" in
  env) [[ "$2" == GOVERSION ]] && echo "$FAKE_GOVERSION" ;;
  build) out="$4"; printf 'binary of %s\n' "$5" > "$out" ;;
  version) printf '%s: go1.26.5\n\tbuild\tvcs.revision=%s\n\tbuild\tvcs.modified=%s\n' "$3" "$FAKE_REVISION" "$FAKE_MODIFIED" ;;
  *) exit 2 ;;
esac
`

// buildRepo makes a throwaway git repository holding the upgrade script at
// its place in the tree, with one commit, and a fake go next to it.
func buildRepo(t *testing.T) (repo, script, goBin, commit string) {
	t.Helper()
	dir := t.TempDir()
	repo = filepath.Join(dir, "repo")
	script = filepath.Join(repo, "scripts", "internal", "remote_alpha_upgrade_es.py")
	if err := os.MkdirAll(filepath.Dir(script), 0o755); err != nil {
		t.Fatal(err)
	}
	source, err := os.ReadFile(repoPath(upgradeESPython))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(script, source, 0o644); err != nil {
		t.Fatal(err)
	}
	goBin = filepath.Join(dir, "go")
	if err := os.WriteFile(goBin, []byte(fakeGo), 0o755); err != nil {
		t.Fatal(err)
	}
	git := func(args ...string) string {
		cmd := exec.Command("git", append([]string{"-C", repo, "-c", "user.name=test", "-c", "user.email=test@example.invalid", "-c", "commit.gpgsign=false"}, args...)...)
		cmd.Dir = repo
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v %s", args, err, out)
		}
		return strings.TrimSpace(string(out))
	}
	git("init", "-q")
	git("add", ".")
	git("commit", "-q", "-m", "fixture")
	return repo, script, goBin, git("rev-parse", "HEAD")
}

func TestRemoteAlphaUpgradeESBuildChecksToolchainCheckoutAndBuildInfo(t *testing.T) {
	cases := []struct {
		name     string
		prepare  func(repo string)
		env      map[string]string
		commit   func(head string) string
		says     string
		succeeds bool
	}{
		{name: "a clean build", succeeds: true},
		{name: "another Go", env: map[string]string{"FAKE_GOVERSION": "go1.26.1"}, says: "the build needs go1.26.5, found go1.26.1"},
		{name: "the checkout is at another commit", commit: func(string) string { return strings.Repeat("b", 40) }, says: "the checkout is at"},
		{name: "an untracked file", prepare: func(repo string) {
			_ = os.WriteFile(filepath.Join(repo, "stray.txt"), []byte("x"), 0o644)
		}, says: "uncommitted or untracked files"},
		{name: "a changed tracked file", prepare: func(repo string) {
			f, _ := os.OpenFile(filepath.Join(repo, "scripts", "internal", "remote_alpha_upgrade_es.py"), os.O_APPEND|os.O_WRONLY, 0)
			_, _ = f.WriteString("\n# local change\n")
			_ = f.Close()
		}, says: "uncommitted or untracked files"},
		{name: "build info names another commit", env: map[string]string{"FAKE_REVISION": strings.Repeat("c", 40)}, says: "es does not carry the commit as a clean build"},
		{name: "build info says modified", env: map[string]string{"FAKE_MODIFIED": "true"}, says: "es does not carry the commit as a clean build"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			repo, script, goBin, head := buildRepo(t)
			commit := head
			if tc.commit != nil {
				commit = tc.commit(head)
			}
			env := map[string]string{"FAKE_GOVERSION": "go1.26.5", "FAKE_REVISION": head, "FAKE_MODIFIED": "false"}
			for k, v := range tc.env {
				env[k] = v
			}
			if tc.prepare != nil {
				tc.prepare(repo)
			}
			out := filepath.Join(t.TempDir(), "payload")
			cmd := exec.Command("python3", "-I", script, "build", "--out", out, "--commit", commit, "--go", goBin)
			cmd.Dir = t.TempDir()
			cmd.Env = os.Environ()
			for k, v := range env {
				cmd.Env = append(cmd.Env, k+"="+v)
			}
			var stdout, stderr bytes.Buffer
			cmd.Stdout, cmd.Stderr = &stdout, &stderr
			err := cmd.Run()
			if tc.succeeds {
				if err != nil {
					t.Fatalf("build: %v\n%s", err, stderr.String())
				}
				var prov map[string]any
				if err := json.Unmarshal([]byte(mustRead(t, filepath.Join(out, "provenance.json"))), &prov); err != nil {
					t.Fatal(err)
				}
				if prov["commit"] != head || prov["go_version"] != "go1.26.5" || prov["vcs_modified"] != false {
					t.Fatalf("provenance %v", prov)
				}
				sums := prov["sha256"].(map[string]any)
				for name, pkg := range map[string]string{"es": "./cmd/es", "es-runtime-support": "./cmd/es-runtime-support", "esconfigcheck": "./scripts/internal/esconfigcheck"} {
					if sums[name] != sha256Hex([]byte("binary of "+pkg+"\n")) {
						t.Errorf("%s sha256 %v", name, sums[name])
					}
				}
				return
			}
			exitErr, ok := err.(*exec.ExitError)
			if !ok || exitErr.ExitCode() != 1 || !strings.Contains(stderr.String(), tc.says) {
				t.Fatalf("build: %v, stderr %q", err, stderr.String())
			}
			if _, err := os.Lstat(filepath.Join(out, "provenance.json")); err == nil {
				t.Fatalf("a refused build wrote provenance")
			}
		})
	}
}

// ptyDriver runs a command the way an SSH session does and drops the
// session once a marker file appears. Mode tty: the command's output is a
// terminal, and closing it hangs the terminal up (SIGHUP; writes then fail
// with EIO). Mode pipe: no terminal; the output is a pipe whose reader goes
// away with no signal (writes fail with EPIPE).
const ptyDriver = `import json, os, pty, select, sys, time
marker, mode = sys.argv[1], sys.argv[2]
argv = sys.argv[sys.argv.index("--") + 1:]
if mode == "pipe":
    rfd, wfd = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.setsid()
        os.close(rfd); os.dup2(wfd, 1); os.dup2(wfd, 2); os.close(wfd)
        os.execvp(argv[0], argv)
    os.close(wfd)
    fd = rfd
else:
    pid, fd = pty.fork()
    if pid == 0:
        os.execvp(argv[0], argv)
deadline = time.time() + 30
while not os.path.exists(marker) and time.time() < deadline:
    r, _, _ = select.select([fd], [], [], 0.05)
    if r:
        try:
            os.read(fd, 65536)
        except OSError:
            break
reached = os.path.exists(marker)
os.close(fd)
_, status = os.waitpid(pid, 0)
print(json.dumps({"reached": reached, "exit": os.waitstatus_to_exitcode(status)}))
`

func TestRemoteAlphaUpgradeESApplySurvivesALostSession(t *testing.T) {
	helper := buildESConfigCheck(t)
	driver := filepath.Join(t.TempDir(), "session.py")
	if err := os.WriteFile(driver, []byte(ptyDriver), 0o644); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		mode, result string
		exit         int
	}{
		// The hangup's SIGHUP ends the forward path, and the rollback runs
		// although every write to the terminal now fails.
		{"tty", "rolled_back", 1},
		// No signal: apply carries on with its output gone, and the summary
		// records the run.
		{"pipe", "applied", 0},
	}
	for _, tc := range cases {
		t.Run(tc.mode, func(t *testing.T) {
			h := newUpgradeHost(t, helper)
			before := h.snapshot()
			h.mark("slow-validate", "")
			inner := h.command("apply", "--payload", h.payload, "--commit", upgradeTestCommit)
			cmd := exec.Command("python3", append([]string{"-I", driver, filepath.Join(h.state, "validating"), tc.mode, "--"}, inner.Args...)...)
			cmd.Dir = inner.Dir
			cmd.Env = inner.Env
			out, err := cmd.Output()
			if err != nil {
				t.Fatalf("session driver: %v %s", err, out)
			}
			var got struct {
				Reached bool `json:"reached"`
				Exit    int  `json:"exit"`
			}
			if err := json.Unmarshal(out, &got); err != nil || !got.Reached {
				t.Fatalf("session driver: %s (%v)", out, err)
			}
			if got.Exit != tc.exit {
				t.Fatalf("apply exited %d, want %d", got.Exit, tc.exit)
			}
			_, summary := readSummary(t, h)
			if summary["result"] != tc.result || summary["output_lost"] != true {
				t.Fatalf("summary result %v, output_lost %v, failure %v", summary["result"], summary["output_lost"], summary["failure"])
			}
			if h.marked("inactive-es") || h.marked("inactive-nomad") {
				t.Fatalf("ES or Nomad left stopped")
			}
			if tc.result == "rolled_back" {
				assertRestored(t, before, h.snapshot())
			} else if got := mustRead(t, h.path("etc/nomad.d/nomad.hcl")); got != boxNomadHCLHTTPS {
				t.Fatalf("the applied run did not move Nomad to HTTPS")
			}
		})
	}
}
