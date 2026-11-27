package scripts_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
)

// The supported-local renderer reads this install's AGS and EGS signing keys
// from the files generate_supported_local_signing_keys writes, and writes
// them into ags.json and egs.json. These tests hold its defenses around
// those keys (audit F3 of ES PR #75): it reads only a regular key file that
// only the setup user owns and can read, never through a link, in the format
// scripts/internal/signingkeygen writes, and it creates every config new.

// signingKeyRenderSetup is a proof root for the renderer with the inputs it
// needs besides the signing keys. The retained-result key file is only
// named, never opened, so it does not exist.
type signingKeyRenderSetup struct {
	proof   string
	authKey string
	aclDir  string
}

func newSigningKeyRenderSetup(t *testing.T) *signingKeyRenderSetup {
	t.Helper()
	workspace := t.TempDir()
	s := &signingKeyRenderSetup{
		proof:   filepath.Join(workspace, "proof"),
		authKey: filepath.Join(workspace, "auth", "key"),
		aclDir:  filepath.Join(workspace, "nomad-acl"),
	}
	for _, dir := range []string{s.proof, filepath.Join(s.proof, "tls", "vault-dev"), filepath.Join(s.proof, "ars-storage")} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(s.proof, "tls", "vault-dev", "vault-ca.pem"), []byte("test CA\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return s
}

func (s *signingKeyRenderSetup) signingDir() string { return filepath.Join(s.proof, "signing") }

func (s *signingKeyRenderSetup) keyFile(role string) string {
	return filepath.Join(s.signingDir(), role+"-signer.json")
}

// bash runs script after sourcing the setup script, at the repository root.
func (s *signingKeyRenderSetup) bash(script string, extraEnv ...string) (string, error) {
	command := exec.Command("/bin/bash", "-c", `source "$1"
`+script, "bash", repoPath("scripts/72_supported_local_setup.sh"))
	command.Dir = repoPath(".")
	command.Env = append(os.Environ(),
		"SUPPORTED_LOCAL_PROOF_DIR="+s.proof,
		"SUPPORTED_LOCAL_RETAINED_RESULT_AUTH_STORE_ID=stable_store",
		"SUPPORTED_LOCAL_RETAINED_RESULT_AUTH_KEY_ID=stable_key",
		"SUPPORTED_LOCAL_RETAINED_RESULT_AUTH_KEY_FILE="+s.authKey,
		"SUPPORTED_LOCAL_NOMAD_ACL_DIR="+s.aclDir,
	)
	command.Env = append(command.Env, extraEnv...)
	output, err := command.CombinedOutput()
	return string(output), err
}

// render runs setup's renderer.
func (s *signingKeyRenderSetup) render() (string, error) {
	return s.bash(`SUPPORTED_LOCAL_NOMAD_SERVER_SPKI_SHA256="` + strings.Repeat("ab", 32) + `"
write_runtime_blob_and_configs "$SUPPORTED_LOCAL_PROOF_DIR" "https://127.0.0.1:18460" "jwt" "service_execution" "vault" "execution-substrate/control-plane-normal-shell:supported-local" "/usr/local/bin/codex" "proof-secrets/data/codex-runtime-profile" "api_key"`)
}

// refused renders and requires a refusal that says want and leaves no config.
func (s *signingKeyRenderSetup) refused(t *testing.T, want string) {
	t.Helper()
	output, err := s.render()
	if err == nil || !strings.Contains(output, want) {
		t.Fatalf("render: %v, output %q; want a refusal saying %q", err, output, want)
	}
	for _, name := range []string{"ars.json", "egs.json", "ags.json", "es.json"} {
		if _, err := os.Lstat(filepath.Join(s.proof, name)); !os.IsNotExist(err) {
			t.Fatalf("the refused render left %s: %v", name, err)
		}
	}
}

// writeSigner writes a key file as scripts/internal/signingkeygen does and
// returns its seed.
func writeSigner(t *testing.T, path, role string) string {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(public)
	data, err := json.Marshal(map[string]string{
		"algorithm":       "ed25519",
		"key_id":          role + "-" + hex.EncodeToString(sum[:8]),
		"private_key_hex": hex.EncodeToString(private.Seed()),
		"public_key_hex":  hex.EncodeToString(public),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(private.Seed())
}

func skipUnlessSupportedLocalHost(t *testing.T) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("supported-local setup runs on Linux; a Mac runs it in its Lima guest")
	}
}

func TestSupportedLocalRendererKeepsTheSigningKeysPrivate(t *testing.T) {
	skipUnlessSupportedLocalHost(t)
	s := newSigningKeyRenderSetup(t)
	// Under a umask that takes nothing away, the folder and the files are
	// private all the same.
	if output, err := s.bash(`umask 000
generate_supported_local_signing_keys "$SUPPORTED_LOCAL_PROOF_DIR"`); err != nil {
		t.Fatalf("generate_supported_local_signing_keys: %v\n%s", err, output)
	}
	// The keys are in a folder only the setup user can enter, each in a file
	// only that user can read.
	if info, err := os.Lstat(s.signingDir()); err != nil || !info.IsDir() || info.Mode().Perm() != 0o700 {
		t.Fatalf("signing folder: %v %v, want a folder with mode 0700", info, err)
	}
	seeds := map[string]string{}
	original := map[string][]byte{}
	for _, role := range []string{"ags", "egs"} {
		info, err := os.Lstat(s.keyFile(role))
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
			t.Fatalf("%s key file: %v %v, want a regular file with mode 0600", role, info, err)
		}
		if st, ok := info.Sys().(*syscall.Stat_t); !ok || int(st.Uid) != os.Geteuid() {
			t.Fatalf("%s key file is not owned by the setup user", role)
		}
		data, err := os.ReadFile(s.keyFile(role))
		if err != nil {
			t.Fatal(err)
		}
		var signer map[string]string
		if err := json.Unmarshal(data, &signer); err != nil {
			t.Fatal(err)
		}
		seeds[role], original[role] = signer["private_key_hex"], data
	}
	restore := func(role string) {
		t.Helper()
		if err := os.RemoveAll(s.keyFile(role)); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(s.keyFile(role), original[role], 0o600); err != nil {
			t.Fatal(err)
		}
	}

	t.Run("a key file other users can reach", func(t *testing.T) {
		for _, mode := range []os.FileMode{0o640, 0o604, 0o602, 0o660, 0o644} {
			if err := os.Chmod(s.keyFile("ags"), mode); err != nil {
				t.Fatal(err)
			}
			s.refused(t, "supported-local ags signing key must be a regular file that only this user can read")
		}
		restore("ags")
	})
	t.Run("a key file that is a link", func(t *testing.T) {
		real := filepath.Join(s.signingDir(), "egs-real.json")
		if err := os.Rename(s.keyFile("egs"), real); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(real, s.keyFile("egs")); err != nil {
			t.Fatal(err)
		}
		s.refused(t, "supported-local egs signing key cannot be opened without following a link")
		if err := os.Remove(real); err != nil {
			t.Fatal(err)
		}
		restore("egs")
	})
	t.Run("a key path that is not a file", func(t *testing.T) {
		if err := os.Remove(s.keyFile("ags")); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(s.keyFile("ags"), 0o700); err != nil {
			t.Fatal(err)
		}
		s.refused(t, "supported-local ags signing key must be a regular file that only this user can read")
		restore("ags")
	})
	t.Run("a key file in another format", func(t *testing.T) {
		var signer map[string]any
		if err := json.Unmarshal(original["ags"], &signer); err != nil {
			t.Fatal(err)
		}
		hexID := strings.TrimPrefix(signer["key_id"].(string), "ags-")
		for name, change := range map[string]func(map[string]any){
			"the published key ID":    func(m map[string]any) { m["key_id"] = "ags-key-1" },
			"an upper-case key ID":    func(m map[string]any) { m["key_id"] = "ags-" + strings.ToUpper(hexID) },
			"the other role's key ID": func(m map[string]any) { m["key_id"] = "egs-" + hexID },
			"a longer key ID":         func(m map[string]any) { m["key_id"] = "ags-" + hexID + "0" },
			"a 64-byte private key": func(m map[string]any) {
				m["private_key_hex"] = m["private_key_hex"].(string) + m["public_key_hex"].(string)
			},
			"another field":     func(m map[string]any) { m["comment"] = "x" },
			"another algorithm": func(m map[string]any) { m["algorithm"] = "ED25519" },
		} {
			changed := map[string]any{}
			for k, v := range signer {
				changed[k] = v
			}
			change(changed)
			data, err := json.Marshal(changed)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(s.keyFile("ags"), data, 0o600); err != nil {
				t.Fatal(err)
			}
			t.Log(name)
			s.refused(t, "supported-local ags signing key is not what scripts/internal/signingkeygen writes")
		}
		restore("ags")
	})
	t.Run("a config that is already there", func(t *testing.T) {
		target := filepath.Join(s.proof, "elsewhere.json")
		for _, plant := range []func(string) error{
			func(path string) error { return os.WriteFile(path, []byte("keep\n"), 0o600) },
			func(path string) error { return os.Symlink(target, path) },
		} {
			if err := plant(filepath.Join(s.proof, "es.json")); err != nil {
				t.Fatal(err)
			}
			if output, err := s.render(); err == nil {
				t.Fatalf("the renderer wrote over or through an existing es.json: %s", output)
			}
			if info, err := os.Lstat(filepath.Join(s.proof, "es.json")); err != nil {
				t.Fatal(err)
			} else if info.Mode().IsRegular() {
				if data, err := os.ReadFile(filepath.Join(s.proof, "es.json")); err != nil || string(data) != "keep\n" {
					t.Fatalf("the existing es.json changed: %q %v", data, err)
				}
			}
			if _, err := os.Lstat(target); !os.IsNotExist(err) {
				t.Fatalf("the renderer wrote through a link: %v", err)
			}
			// The configs before es.json were written; clear them for the
			// next render. The key files stay until every config is written.
			for _, name := range []string{"ars.json", "egs.json", "ags.json", "es.json"} {
				if err := os.Remove(filepath.Join(s.proof, name)); err != nil {
					t.Fatal(err)
				}
			}
			for _, role := range []string{"ags", "egs"} {
				if data, err := os.ReadFile(s.keyFile(role)); err != nil || string(data) != string(original[role]) {
					t.Fatalf("%s key file changed or is gone after a refused render: %v", role, err)
				}
			}
		}
	})

	// With the files as generate_supported_local_signing_keys left them, the
	// renderer writes every config 0600 with this run's keys and removes the
	// key files.
	if output, err := s.render(); err != nil {
		t.Fatalf("render: %v\n%s", err, output)
	}
	for _, name := range []string{"ars.json", "egs.json", "ags.json", "es.json"} {
		info, err := os.Lstat(filepath.Join(s.proof, name))
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
			t.Fatalf("%s: %v %v, want a regular file with mode 0600", name, info, err)
		}
	}
	for _, role := range []string{"ags", "egs"} {
		var config struct {
			Signer map[string]string `json:"signer"`
		}
		data, err := os.ReadFile(filepath.Join(s.proof, role+".json"))
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(data, &config); err != nil {
			t.Fatal(err)
		}
		if config.Signer["private_key_hex"] != seeds[role] {
			t.Fatalf("%s.json does not sign with the key generate_supported_local_signing_keys made for this install", role)
		}
	}
	if _, err := os.Lstat(s.signingDir()); !os.IsNotExist(err) {
		t.Fatalf("the signing folder is still there after the render: %v", err)
	}
}

// TestSupportedLocalRendererRefusesASigningKeyFileAnotherUserOwns needs a
// file owned by another account, so it runs as root: go.yml's step "Listed
// tests pass as root" runs it, and it skips itself elsewhere. It makes the
// key files itself, since the go command never runs as root there.
func TestSupportedLocalRendererRefusesASigningKeyFileAnotherUserOwns(t *testing.T) {
	skipUnlessSupportedLocalHost(t)
	if os.Geteuid() != 0 {
		t.Skip("needs root to make a key file another account owns")
	}
	s := newSigningKeyRenderSetup(t)
	if err := os.Mkdir(s.signingDir(), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, role := range []string{"ags", "egs"} {
		writeSigner(t, s.keyFile(role), role)
	}
	const nobody = 65534
	if err := os.Chown(s.keyFile("egs"), nobody, nobody); err != nil {
		t.Fatal(err)
	}
	s.refused(t, "supported-local egs signing key must be a regular file that only this user can read")
	if err := os.Chown(s.keyFile("egs"), 0, 0); err != nil {
		t.Fatal(err)
	}
	if output, err := s.render(); err != nil {
		t.Fatalf("render with the key files owned by root: %v\n%s", err, output)
	}
}
