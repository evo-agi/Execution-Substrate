package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"execution-substrate/internal/knownkeys"
)

func readSigner(t *testing.T, path string) signer {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		t.Fatalf("%s: mode %v, want a regular file with mode 0600", path, info.Mode())
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var keys map[string]any
	if err := json.Unmarshal(data, &keys); err != nil {
		t.Fatal(err)
	}
	if len(keys) != 4 {
		t.Fatalf("%s holds keys %v, want exactly algorithm, key_id, private_key_hex and public_key_hex", path, keys)
	}
	var s signer
	if err := json.Unmarshal(data, &s); err != nil {
		t.Fatal(err)
	}
	return s
}

func TestGenerateWritesAFreshKeyOnlyItsOwnerCanRead(t *testing.T) {
	dir := t.TempDir()
	seen := map[string]bool{}
	for _, role := range []string{"ags", "egs", "ags"} {
		path := filepath.Join(dir, role+"-"+hex.EncodeToString([]byte{byte(len(seen))})+".json")
		// A permissive umask must not widen the file.
		old := syscall.Umask(0)
		public, err := generate(role, path, rand.Reader)
		syscall.Umask(old)
		if err != nil {
			t.Fatal(err)
		}
		full := readSigner(t, path)
		seed, err := hex.DecodeString(full.PrivateKeyHex)
		if err != nil || len(seed) != ed25519.SeedSize {
			t.Fatalf("private_key_hex is not a 32-byte seed: %q", full.PrivateKeyHex)
		}
		derived := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
		if full.Algorithm != "ed25519" || full.PublicKeyHex != hex.EncodeToString(derived) {
			t.Fatalf("written signer does not hold a matching Ed25519 key pair: %+v", full)
		}
		sum := sha256.Sum256(derived)
		if full.KeyID != role+"-"+hex.EncodeToString(sum[:8]) {
			t.Fatalf("key ID %q is not %s- and 16 hex digits of the SHA-256 of the public key", full.KeyID, role)
		}
		if public.PrivateKeyHex != "" || public.KeyID != full.KeyID || public.PublicKeyHex != full.PublicKeyHex || public.Algorithm != "ed25519" {
			t.Fatalf("public part %+v does not match the written key, or carries the private key", public)
		}
		if err := knownkeys.Check("generated", derived); err != nil {
			t.Fatal(err)
		}
		if seen[full.PublicKeyHex] {
			t.Fatal("two runs generated the same key")
		}
		seen[full.PublicKeyHex] = true
	}
}

func TestGenerateRefusesAnythingAlreadyAtThePath(t *testing.T) {
	dir := t.TempDir()
	existing := filepath.Join(dir, "existing.json")
	if err := os.WriteFile(existing, []byte("keep"), 0o644); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dir, "target.json")
	link := filepath.Join(dir, "link.json")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{existing, link, dir} {
		if _, err := generate("ags", path, rand.Reader); err == nil {
			t.Fatalf("generate replaced or followed %s", path)
		}
	}
	if data, err := os.ReadFile(existing); err != nil || string(data) != "keep" {
		t.Fatalf("existing file changed: %q %v", data, err)
	}
	if _, err := os.Lstat(target); !os.IsNotExist(err) {
		t.Fatalf("generate wrote through a symbolic link: %v", err)
	}
}

// A broken random source that returns one byte repeated would give a known
// key; generate refuses it and writes nothing.
func TestGenerateRefusesAKnownKeyFromABrokenRandomSource(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ags.json")
	_, err := generate("ags", path, bytes.NewReader(bytes.Repeat([]byte{0x11}, 64)))
	if err == nil || !strings.Contains(err.Error(), "is a known key") {
		t.Fatalf("got %v, want the known-key refusal", err)
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("a refused key was written: %v", err)
	}
}

// The command prints only the public part, and only after the file holds
// the key; usage errors exit 2 and write nothing.
func TestCommandPrintsOnlyThePublicPart(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "signingkeygen")
	build := exec.Command("go", "build", "-o", bin, "execution-substrate/scripts/internal/signingkeygen")
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "egs.json")
	var stdout, stderr bytes.Buffer
	run := exec.Command(bin, "egs", path)
	run.Stdout, run.Stderr = &stdout, &stderr
	if err := run.Run(); err != nil {
		t.Fatalf("run: %v\n%s", err, stderr.String())
	}
	full := readSigner(t, path)
	var printed map[string]string
	if err := json.Unmarshal(stdout.Bytes(), &printed); err != nil {
		t.Fatalf("stdout is not one JSON object: %q", stdout.String())
	}
	want := map[string]string{"algorithm": "ed25519", "key_id": full.KeyID, "public_key_hex": full.PublicKeyHex}
	if len(printed) != len(want) {
		t.Fatalf("stdout %v, want %v", printed, want)
	}
	for k, v := range want {
		if printed[k] != v {
			t.Fatalf("stdout %v, want %v", printed, want)
		}
	}
	if strings.Contains(stdout.String()+stderr.String(), full.PrivateKeyHex) {
		t.Fatal("the private key reached stdout or stderr")
	}
	for _, args := range [][]string{{}, {"ags"}, {"cgs", filepath.Join(dir, "x.json")}, {"ags", "relative.json"}, {"ags", filepath.Join(dir, "y.json"), "extra"}} {
		cmd := exec.Command(bin, args...)
		cmd.Dir = dir
		err := cmd.Run()
		if exit, ok := err.(*exec.ExitError); !ok || exit.ExitCode() != 2 {
			t.Fatalf("args %q: %v, want exit status 2", args, err)
		}
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 {
		t.Fatalf("usage errors wrote files: %v %v", entries, err)
	}
}
