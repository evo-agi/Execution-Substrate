package scripts_test

// Tests for the guards of scripts/internal/remote_alpha_user_identity.py:
// what a stop signal leaves behind, the refusals that keep a run from
// changing an unsafe box, the forward-only revoke, the user CA replacement,
// and the checks around the client CA files and the namespace binding. The
// fixture (newUserIdentityBox and its helpers) is in
// remote_alpha_user_identity_test.go.

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

const userIdentityCACommonName = "Execution Substrate Remote Alpha User CA"

// startBox starts a box mode without waiting for it, so a test
// can signal it mid-run.
func (b *userIdentityBox) startBox(args ...string) (*exec.Cmd, *bytes.Buffer, *bytes.Buffer) {
	b.t.Helper()
	argv := append([]string{"-I", "-B", "-c", userIdentityDriver, userIdentityModule, b.layout}, append(args, "--json")...)
	cmd := exec.Command("/usr/bin/python3", argv...)
	cmd.Env = []string{"PATH=/usr/bin:/bin", "LC_ALL=C"}
	cmd.Dir = b.root
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		b.t.Fatal(err)
	}
	return cmd, &stdout, &stderr
}

// finish waits for a run started with startBox and reads its report.
func (b *userIdentityBox) finish(cmd *exec.Cmd, stdout, stderr *bytes.Buffer) userIdentityRun {
	b.t.Helper()
	err := cmd.Wait()
	run := userIdentityRun{stdout: stdout.String(), stderr: stderr.String()}
	if err != nil {
		exitErr, ok := err.(*exec.ExitError)
		if !ok {
			b.t.Fatal(err)
		}
		run.code = exitErr.ExitCode()
	}
	if err := json.Unmarshal(stdout.Bytes(), &run.doc); err != nil {
		b.t.Fatalf("the stopped run printed no JSON report: %v\n%s", err, run)
	}
	return run
}

// waitForRestarts waits until the fake systemctl has seen n restarts.
func (b *userIdentityBox) waitForRestarts(n int) {
	b.t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if len(b.restarts()) >= n {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	b.t.Fatalf("no restart number %d; restarts so far %v", n, b.restarts())
}

func (b *userIdentityBox) setSettle(seconds float64) {
	b.t.Helper()
	fields := b.layoutFields()
	fields["settle_seconds"] = seconds
	b.writeLayout(fields)
}

// editUserIdentityFile rewrites path through change, keeping its mode.
func editUserIdentityFile(t *testing.T, path string, change func(string) string) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	writeUserIdentityFile(t, path, []byte(change(string(mustReadUserIdentityFile(t, path)))), info.Mode().Perm())
}

func mustReplaceOnce(t *testing.T, s, old, new string) string {
	t.Helper()
	if !strings.Contains(s, old) {
		t.Fatalf("%q is not in:\n%s", old, s)
	}
	return strings.Replace(s, old, new, 1)
}

func ecdsaP256Key() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

// sameSubjectCA is a CA certificate with the user CA's Common Name but
// another key: what a second init-ca, or a CA made by hand, would look like.
func sameSubjectCA(t *testing.T) []byte {
	t.Helper()
	_, _, pemBytes := userIdentityTestCA(t, userIdentityCACommonName)
	return pemBytes
}

// TestUserIdentityStopSignalsLeaveNoHalfChange stops allow and revoke with a
// signal at their slowest step, the settle wait after a restart. allow rolls
// back to the exact bytes; a signal during that rollback is held until the
// rollback ends and does not hide its outcome. revoke keeps what it removed,
// records the restarts still owed, and the next revoke finishes.
func TestUserIdentityStopSignalsLeaveNoHalfChange(t *testing.T) {
	requireUserIdentityOpenSSL3(t)
	for _, tc := range []struct {
		name         string
		sig          syscall.Signal
		after        int
		wantRestarts string
	}{
		{"SIGTERM during allow after the AGS restart", syscall.SIGTERM, 1, "ags.service,ags.service"},
		{"SIGHUP during allow after the ES restart", syscall.SIGHUP, 2, "ags.service,es.service,ags.service,es.service"},
		{"SIGINT during allow after the AGS restart", syscall.SIGINT, 1, "ags.service,ags.service"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			b := newUserIdentityBox(t)
			b.mint("claude")
			b.setSettle(1.5)
			before := b.snapshot()
			b.clearSystemctlLog()
			cmd, stdout, stderr := b.startBox("allow", "--name", "claude", "--apply")
			b.waitForRestarts(tc.after)
			time.Sleep(100 * time.Millisecond)
			if err := cmd.Process.Signal(tc.sig); err != nil {
				t.Fatal(err)
			}
			run := b.finish(cmd, stdout, stderr)
			want := "stopped by " + map[syscall.Signal]string{syscall.SIGTERM: "SIGTERM", syscall.SIGHUP: "SIGHUP", syscall.SIGINT: "SIGINT"}[tc.sig]
			if run.code != 1 || run.result() != "failed" || !strings.Contains(run.message(), want) || !strings.Contains(run.message(), "rolled back") {
				t.Fatalf("allow stopped by %v: want failed, %q, rolled back\n%s", tc.sig, want, run)
			}
			if got := strings.Join(b.restarts(), ","); got != tc.wantRestarts {
				t.Fatalf("restarts %q, want %q", got, tc.wantRestarts)
			}
			requireSameUserIdentitySnapshot(t, withoutUserIdentityBackups(before), withoutUserIdentityBackups(b.snapshot()), "a stopped allow")
		})
	}

	t.Run("SIGTERM during the rollback of an allow", func(t *testing.T) {
		t.Parallel()
		b := newUserIdentityBox(t)
		b.mint("claude")
		b.setSettle(1.5)
		before := b.snapshot()
		b.clearSystemctlLog()
		b.marker("es.service", "fail-next-restart")
		cmd, stdout, stderr := b.startBox("allow", "--name", "claude", "--apply")
		// AGS, ES (fails at once), then the rollback's AGS restart.
		b.waitForRestarts(3)
		time.Sleep(100 * time.Millisecond)
		if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
			t.Fatal(err)
		}
		run := b.finish(cmd, stdout, stderr)
		if run.code != 1 || run.result() != "failed" || !strings.Contains(run.message(), "rolled back to the backed-up bytes") ||
			!strings.Contains(run.message(), "SIGTERM arrived meanwhile and was held until that step finished") {
			t.Fatalf("allow whose rollback got SIGTERM: want the rollback's own outcome with the signal noted\n%s", run)
		}
		if got := strings.Join(b.restarts(), ","); got != "ags.service,es.service,ags.service,es.service" {
			t.Fatalf("restarts %q, want the whole rollback", got)
		}
		requireSameUserIdentitySnapshot(t, withoutUserIdentityBackups(before), withoutUserIdentityBackups(b.snapshot()), "an allow whose rollback was signalled")
	})

	t.Run("SIGTERM during revoke after the ES restart", func(t *testing.T) {
		t.Parallel()
		b := newUserIdentityBox(t)
		b.mint("claude")
		b.mustOK(b.box("allow", "--name", "claude", "--apply"), "allow")
		b.setSettle(1.5)
		b.clearSystemctlLog()
		cmd, stdout, stderr := b.startBox("revoke", "--name", "claude", "--apply")
		b.waitForRestarts(2)
		time.Sleep(100 * time.Millisecond)
		if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
			t.Fatal(err)
		}
		run := b.finish(cmd, stdout, stderr)
		if run.code != 1 || run.result() != "failed" || !strings.Contains(run.message(), "stopped by SIGTERM") ||
			!strings.Contains(run.message(), "run revoke again to finish") {
			t.Fatalf("revoke stopped by SIGTERM\n%s", run)
		}
		for _, path := range []string{b.agsConfig, b.esConfig} {
			if strings.Contains(string(mustReadUserIdentityFile(t, path)), `"user/claude"`) {
				t.Fatalf("a stopped revoke put user/claude back in %s", path)
			}
		}
		if state, pending := b.registryState("claude"), b.pendingRestarts("claude"); state != "revoked" || pending != "ags.service,es.service" {
			t.Fatalf("registry after a stopped revoke: state %q, pending %q", state, pending)
		}
		b.setSettle(0.05)
		b.clearSystemctlLog()
		b.mustOK(b.box("revoke", "--name", "claude", "--apply"), "revoke again")
		if got := strings.Join(b.restarts(), ","); got != "ags.service,es.service" || b.pendingRestarts("claude") != "" {
			t.Fatalf("the second revoke restarted %q and left %q pending", got, b.pendingRestarts("claude"))
		}
	})
	for n := 1; n <= 3; n++ {
		n := n
		t.Run(fmt.Sprintf("SIGTERM during revoke --remove-ca after file write %d", n), func(t *testing.T) {
			t.Parallel()
			b := newUserIdentityBox(t)
			b.mint("claude")
			b.mustOK(b.box("allow", "--name", "claude", "--apply"), "allow")
			b.clearSystemctlLog()
			run := b.boxWithFault(fmt.Sprintf("signal-after-writes=%d", n), "revoke", "--name", "claude", "--remove-ca", "--apply")
			if run.code != 1 || run.result() != "failed" || !strings.Contains(run.message(), "stopped by SIGTERM, held until the service files were written") ||
				!strings.Contains(run.message(), "run revoke again to finish") {
				t.Fatalf("revoke --remove-ca with SIGTERM after write %d\n%s", n, run)
			}
			// Every file was written before the stop took effect, and no
			// service was restarted after it.
			b.requireUserCAGone(fmt.Sprintf("after SIGTERM at write %d", n))
			if got := b.restarts(); len(got) != 0 {
				t.Fatalf("revoke restarted %v after the stop", got)
			}
			if pending := b.pendingRestarts("claude"); pending != "ags.service,es.service" {
				t.Fatalf("registry after the stopped revoke: pending %q", pending)
			}
			b.mustOK(b.box("revoke", "--name", "claude", "--apply"), "revoke again")
			if got := strings.Join(b.restarts(), ","); got != "ags.service,es.service" || b.pendingRestarts("claude") != "" {
				t.Fatalf("the second revoke restarted %q and left %q pending", got, b.pendingRestarts("claude"))
			}
		})
	}
}

// TestUserIdentityRollbackChecksTheRestoredBytes makes the rollback's
// restore write other bytes than it read: allow must say the rollback is
// incomplete, not that it rolled back.
func TestUserIdentityRollbackChecksTheRestoredBytes(t *testing.T) {
	requireUserIdentityOpenSSL3(t)
	b := newUserIdentityBox(t)
	b.mint("claude")
	b.marker("es.service", "fail-next-restart")
	run := b.boxWithFault("restore-writes-other-bytes", "allow", "--name", "claude", "--apply")
	if run.code != 1 || run.result() != "failed" || !strings.Contains(run.message(), "rollback incomplete") ||
		!strings.Contains(run.message(), "does not hold its backed-up bytes") || strings.Contains(run.message(), "rolled back to") {
		t.Fatalf("allow whose restore writes other bytes\n%s", run)
	}
}

// TestUserIdentityRefusesUnsafeStates covers refusals that keep a run from
// changing a box it was not written for, or from leaving trust behind that
// nothing records. Each run must end refused, change nothing and restart
// nothing.
func TestUserIdentityRefusesUnsafeStates(t *testing.T) {
	requireUserIdentityOpenSSL3(t)
	minted := func(t *testing.T, b *userIdentityBox) { b.mint("claude") }
	allowed := func(t *testing.T, b *userIdentityBox) {
		b.mint("claude")
		b.mustOK(b.box("allow", "--name", "claude", "--apply"), "allow")
	}
	bothClientCAFiles := func(t *testing.T, b *userIdentityBox, change func([]byte) []byte) {
		for _, path := range []string{b.agsCA, b.esCA} {
			writeUserIdentityFile(t, path, change(mustReadUserIdentityFile(t, path)), 0o640)
		}
	}
	withSecurityMember := func(member string) func(string) string {
		return func(s string) string {
			return strings.Replace(s, `"bootstrap_issuer_common_name": "`+userIdentityBootstrapCN+`"`,
				`"bootstrap_issuer_common_name": "`+userIdentityBootstrapCN+`", `+member, 1)
		}
	}
	otherSHA := strings.Repeat("ab", 32)
	cases := []struct {
		name    string
		prepare func(t *testing.T, b *userIdentityBox) []string
		code    int
		want    string
	}{
		{"allow when the ES bootstrap issuer is named like the user CA", func(t *testing.T, b *userIdentityBox) []string {
			minted(t, b)
			editUserIdentityFile(t, b.esConfig, func(s string) string { return mustReplaceOnce(t, s, userIdentityBootstrapCN, userIdentityCACommonName) })
			return []string{"allow", "--name", "claude", "--apply"}
		}, 1, "ES bootstrap issuer Common Name equals the user CA's"},
		{"init-ca when the AGS bootstrap issuer is named like the user CA", func(t *testing.T, b *userIdentityBox) []string {
			editUserIdentityFile(t, b.agsConfig, func(s string) string { return mustReplaceOnce(t, s, userIdentityBootstrapCN, userIdentityCACommonName) })
			return []string{"init-ca", "--apply"}
		}, 1, "bootstrap issuer Common Name equals the user CA's"},
		{"init-ca when the box files belong to another UID", func(t *testing.T, b *userIdentityBox) []string {
			fields := b.layoutFields()
			fields["box_owner_uid"] = os.Geteuid() + 1
			b.writeLayout(fields)
			return []string{"init-ca", "--apply"}
		}, 1, "must be owned by UID"},
		{"revoke while a bare user entry still covers the name", func(t *testing.T, b *userIdentityBox) []string {
			allowed(t, b)
			editUserIdentityFile(t, b.agsConfig, func(s string) string { return mustReplaceOnce(t, s, `"user/claude"`, `"user/claude", "user"`) })
			return []string{"revoke", "--name", "claude", "--apply"}
		}, 1, "AGS allowlist entry 'user' would still authorize user/claude"},
		{"allow without an unexpired certificate", func(t *testing.T, b *userIdentityBox) []string {
			minted(t, b)
			editUserIdentityFile(t, b.registryPath(), func(s string) string {
				var doc map[string]any
				if err := json.Unmarshal([]byte(s), &doc); err != nil {
					t.Fatal(err)
				}
				for _, c := range doc["names"].(map[string]any)["claude"].(map[string]any)["certificates"].([]any) {
					c.(map[string]any)["not_after_epoch"] = 1
				}
				out, _ := json.MarshalIndent(doc, "", "  ")
				return string(out) + "\n"
			})
			return []string{"allow", "--name", "claude", "--apply"}
		}, 1, "no unexpired certificate"},
		{"lock path is a symbolic link", func(t *testing.T, b *userIdentityBox) []string {
			minted(t, b)
			// mint's runs left a lock file behind; put something else there.
			if err := os.Remove(b.lock); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(filepath.Join(b.root, "elsewhere"), b.lock); err != nil {
				t.Fatal(err)
			}
			return []string{"allow", "--name", "claude", "--apply"}
		}, 1, "cannot open the lock file"},
		{"lock path is a directory", func(t *testing.T, b *userIdentityBox) []string {
			minted(t, b)
			// mint's runs left a lock file behind; put something else there.
			if err := os.Remove(b.lock); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(b.lock, 0o700); err != nil {
				t.Fatal(err)
			}
			return []string{"allow", "--name", "claude", "--apply"}
		}, 1, "cannot open the lock file"},
		{"lock path is a FIFO", func(t *testing.T, b *userIdentityBox) []string {
			minted(t, b)
			// mint's runs left a lock file behind; put something else there.
			if err := os.Remove(b.lock); err != nil {
				t.Fatal(err)
			}
			if err := syscall.Mkfifo(b.lock, 0o600); err != nil {
				t.Fatal(err)
			}
			return []string{"allow", "--name", "claude", "--apply"}
		}, 1, "is not a regular file owned by this user"},
		{"a case variant of tls.client_ca_file that Go would read", func(t *testing.T, b *userIdentityBox) []string {
			minted(t, b)
			editUserIdentityFile(t, b.esConfig, func(s string) string {
				return mustReplaceOnce(t, s, `"client_ca_file"`, `"Client_CA_File": "/nonexistent/other-ca.pem", "client_ca_file"`)
			})
			return []string{"allow", "--name", "claude", "--apply"}
		}, 1, "only lower-case ASCII keys"},
		{"a case variant of a security key", func(t *testing.T, b *userIdentityBox) []string {
			minted(t, b)
			editUserIdentityFile(t, b.agsConfig, withSecurityMember(`"Namespace_Issuers": []`))
			return []string{"allow", "--name", "claude", "--apply"}
		}, 1, "only lower-case ASCII keys"},
		{"allow while another CA named like the user CA is trusted", func(t *testing.T, b *userIdentityBox) []string {
			minted(t, b)
			stray := sameSubjectCA(t)
			bothClientCAFiles(t, b, func(data []byte) []byte { return append(data, stray...) })
			return []string{"allow", "--name", "claude", "--apply"}
		}, 1, "hold another user CA"},
		{"allow while a retired CA under another name is trusted", func(t *testing.T, b *userIdentityBox) []string {
			minted(t, b)
			// A CA the registry lists as retired is a stray whatever its
			// name, for example after a layout with another Common Name.
			old, _, oldPEM := userIdentityTestCA(t, "Earlier User CA")
			bothClientCAFiles(t, b, func(data []byte) []byte { return append(data, oldPEM...) })
			editUserIdentityFile(t, b.registryPath(), func(s string) string {
				var registry map[string]any
				if err := json.Unmarshal([]byte(s), &registry); err != nil {
					t.Fatal(err)
				}
				sum := sha256.Sum256(old.Raw)
				registry["retired_cas"] = append(registry["retired_cas"].([]any), map[string]any{
					"sha256": hex.EncodeToString(sum[:]), "public_key_sha256": strings.Repeat("0", 64), "retired_at": "2026-01-01T00:00:00Z"})
				data, err := json.MarshalIndent(registry, "", "  ")
				if err != nil {
					t.Fatal(err)
				}
				return string(data) + "\n"
			})
			return []string{"allow", "--name", "claude", "--apply"}
		}, 1, "hold another user CA"},
		{"allow while ARS reads the AGS client CA file", func(t *testing.T, b *userIdentityBox) []string {
			minted(t, b)
			editUserIdentityFile(t, b.arsConfig, func(s string) string { return mustReplaceOnce(t, s, "/abs/path/tls/runtime-ca.pem", b.agsCA) })
			return []string{"allow", "--name", "claude", "--apply"}
		}, 1, "also read elsewhere"},
		{"allow while EGS reads the ES client CA file through a symbolic link", func(t *testing.T, b *userIdentityBox) []string {
			minted(t, b)
			link := filepath.Join(b.root, "client-ca-link.pem")
			if err := os.Symlink(b.esCA, link); err != nil {
				t.Fatal(err)
			}
			editUserIdentityFile(t, b.egsConfig, func(s string) string { return mustReplaceOnce(t, s, "/abs/path/tls/runtime-ca.pem", link) })
			return []string{"allow", "--name", "claude", "--apply"}
		}, 1, "also read elsewhere"},
		{"allow while AGS uses its client CA file as a dependency root", func(t *testing.T, b *userIdentityBox) []string {
			minted(t, b)
			editUserIdentityFile(t, b.agsConfig, func(s string) string {
				return mustReplaceOnce(t, s, `"root_ca_file": "/abs/path/tls/runtime-ca.pem"`, `"root_ca_file": "`+b.agsCA+`"`)
			})
			return []string{"allow", "--name", "claude", "--apply"}
		}, 1, "dependencies.artifact_registry.root_ca_file"},
		{"allow while user is bound to another CA", func(t *testing.T, b *userIdentityBox) []string {
			minted(t, b)
			editUserIdentityFile(t, b.esConfig, withSecurityMember(`"namespace_issuers": [{"path_prefix": "user", "issuer_certificate_sha256": "`+otherSHA+`"}]`))
			return []string{"allow", "--name", "claude", "--apply"}
		}, 1, "binds 'user' to another CA"},
		{"allow while a namespace inside user is bound to another CA", func(t *testing.T, b *userIdentityBox) []string {
			minted(t, b)
			editUserIdentityFile(t, b.agsConfig, withSecurityMember(`"namespace_issuers": [{"path_prefix": "user/team", "issuer_certificate_sha256": "`+otherSHA+`"}]`))
			return []string{"allow", "--name", "claude", "--apply"}
		}, 1, "binds 'user/team' to another CA"},
		{"allow while the user CA is bound to another namespace", func(t *testing.T, b *userIdentityBox) []string {
			minted(t, b)
			editUserIdentityFile(t, b.esConfig, withSecurityMember(`"namespace_issuers": [{"path_prefix": "robot", "issuer_certificate_sha256": "`+b.userCASHA256()+`"}]`))
			return []string{"allow", "--name", "claude", "--apply"}
		}, 1, "binds the user CA to 'robot'"},
		{"a namespace binding that is not two strings", func(t *testing.T, b *userIdentityBox) []string {
			minted(t, b)
			editUserIdentityFile(t, b.esConfig, withSecurityMember(`"namespace_issuers": [{"path_prefix": "user"}]`))
			return []string{"allow", "--name", "claude", "--apply"}
		}, 1, "is not an object of exactly the strings path_prefix and issuer_certificate_sha256"},
		{"a service file with an extended attribute", func(t *testing.T, b *userIdentityBox) []string {
			minted(t, b)
			// An ACL is an extended attribute too (system.posix_acl_access);
			// replacing the file would drop it.
			cmd := exec.Command("/usr/bin/python3", "-I", "-c", "import os, sys; os.setxattr(sys.argv[1], 'user.test', b'1')", b.esConfig)
			cmd.Dir = b.root
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("cannot set an extended attribute on %s: %v\n%s", b.esConfig, err, out)
			}
			return []string{"allow", "--name", "claude", "--apply"}
		}, 1, "carries the extended attribute user.test"},
		{"allow while a revocation is unfinished", func(t *testing.T, b *userIdentityBox) []string {
			allowed(t, b)
			b.mint("second")
			b.marker("es.service", "fail-restarts")
			if run := b.box("revoke", "--name", "claude", "--apply"); run.result() != "failed" {
				t.Fatalf("revoke with ES unable to restart: %s", run)
			}
			if err := os.Remove(filepath.Join(b.units, "es.service.fail-restarts")); err != nil {
				t.Fatal(err)
			}
			return []string{"allow", "--name", "second", "--apply"}
		}, 1, "the revocation of claude is not finished"},
		{"--remove-ca while a slash variant of a user entry remains", func(t *testing.T, b *userIdentityBox) []string {
			allowed(t, b)
			editUserIdentityFile(t, b.agsConfig, func(s string) string {
				return mustReplaceOnce(t, s, `"user/claude"`, `"user/claude", "//user/ghost//"`)
			})
			return []string{"revoke", "--name", "claude", "--remove-ca", "--apply"}
		}, 1, "user entries remain in the allowlists: //user/ghost//"},
		{"allow while the client CA files differ by more than the user CA", func(t *testing.T, b *userIdentityBox) []string {
			minted(t, b)
			_, _, otherPEM := userIdentityTestCA(t, "Another External Client CA")
			writeUserIdentityFile(t, b.esCA, append(append([]byte(nil), b.extCAPEM...), otherPEM...), 0o640)
			return []string{"allow", "--name", "claude", "--apply"}
		}, 1, "differ only by the user CA at the end of one"},
		{"init-ca --replace while a name is active", func(t *testing.T, b *userIdentityBox) []string {
			allowed(t, b)
			return []string{"init-ca", "--replace", "--apply"}
		}, 1, "names are active (revoke them first): claude"},
		{"init-ca --replace while the user CA is still installed", func(t *testing.T, b *userIdentityBox) []string {
			allowed(t, b)
			b.mustOK(b.box("revoke", "--name", "claude", "--apply"), "revoke")
			return []string{"init-ca", "--replace", "--apply"}
		}, 1, "still holds the user CA; run revoke --remove-ca first"},
		{"init-ca --replace while a revocation is unfinished", func(t *testing.T, b *userIdentityBox) []string {
			allowed(t, b)
			b.marker("es.service", "fail-restarts")
			if run := b.box("revoke", "--name", "claude", "--apply"); run.result() != "failed" {
				t.Fatalf("revoke with ES unable to restart: %s", run)
			}
			if err := os.Remove(filepath.Join(b.units, "es.service.fail-restarts")); err != nil {
				t.Fatal(err)
			}
			return []string{"init-ca", "--replace", "--apply"}
		}, 1, "the revocation of claude is not finished"},
		{"init-ca --replace while user is still bound", func(t *testing.T, b *userIdentityBox) []string {
			b.mustOK(b.box("init-ca", "--apply"), "init-ca")
			editUserIdentityFile(t, b.esConfig, withSecurityMember(`"namespace_issuers": [{"path_prefix": "user", "issuer_certificate_sha256": "`+b.userCASHA256()+`"}]`))
			return []string{"init-ca", "--replace", "--apply"}
		}, 1, "ES security.namespace_issuers still binds 'user'"},
		{"init-ca --replace while a user entry remains", func(t *testing.T, b *userIdentityBox) []string {
			b.mustOK(b.box("init-ca", "--apply"), "init-ca")
			b.writeConfig("es", b.esConfig, b.esCA, []string{"operator/local", "service/control-plane", "/user/ghost"})
			return []string{"init-ca", "--replace", "--apply"}
		}, 1, "ES allowlist still holds '/user/ghost'"},
		{"init-ca --replace while another CA named like the user CA is trusted", func(t *testing.T, b *userIdentityBox) []string {
			b.mustOK(b.box("init-ca", "--apply"), "init-ca")
			stray := sameSubjectCA(t)
			bothClientCAFiles(t, b, func(data []byte) []byte { return append(data, stray...) })
			return []string{"init-ca", "--replace", "--apply"}
		}, 1, "holds an older user CA"},
		{"install with a server CA file that holds a leaf", func(t *testing.T, b *userIdentityBox) []string {
			issued := b.mint("claude")
			ca, caKey, _ := userIdentityTestCA(t, "Remote Alpha Server CA")
			leaf := userIdentityServerCert(t, ca, caKey)
			path := filepath.Join(b.root, "server-leaf.pem")
			writeUserIdentityFile(t, path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Certificate[0]}), 0o644)
			return []string{"install", "--name", "claude", "--cert", issued, "--server-ca", path}
		}, 1, "holds a certificate that is not a CA"},
		{"install with a certificate that has carriage returns", func(t *testing.T, b *userIdentityBox) []string {
			issued := b.mint("claude")
			crlf := filepath.Join(b.root, "crlf.crt")
			writeUserIdentityFile(t, crlf, bytes.ReplaceAll(mustReadUserIdentityFile(t, issued), []byte("\n"), []byte("\r\n")), 0o644)
			return []string{"install", "--name", "claude", "--cert", crlf}
		}, 1, "has carriage returns"},
		{"issue when the user CA directory's parent is writable by its group", func(t *testing.T, b *userIdentityBox) []string {
			b.mustOK(b.box("init-ca", "--apply"), "init-ca")
			b.mustOK(b.caller("request", "--name", "claude"), "request")
			csr := filepath.Join(b.root, "claude.csr")
			writeUserIdentityFile(t, csr, mustReadUserIdentityFile(t, filepath.Join(b.callerDir("claude"), "request.csr")), 0o644)
			if err := os.Chmod(filepath.Dir(b.userCADir), 0o775); err != nil {
				t.Fatal(err)
			}
			return []string{"issue", "--name", "claude", "--csr", csr, "--out", filepath.Join(b.root, "claude.crt"), "--apply"}
		}, 1, "must be owned by UID"},
		{"check with a caller root open to others", func(t *testing.T, b *userIdentityBox) []string {
			minted(t, b)
			if err := os.Chmod(b.callers, 0o755); err != nil {
				t.Fatal(err)
			}
			return []string{"check", "--name", "claude"}
		}, 1, "must be owned by you and closed to group and others"},
		{"check with a caller key readable by others", func(t *testing.T, b *userIdentityBox) []string {
			minted(t, b)
			if err := os.Chmod(filepath.Join(b.callerDir("claude"), "key.pem"), 0o644); err != nil {
				t.Fatal(err)
			}
			return []string{"check", "--name", "claude"}
		}, 1, "must be a regular file owned by you with mode 0600"},
		{"an abbreviated --apply", func(t *testing.T, b *userIdentityBox) []string {
			allowed(t, b)
			return []string{"revoke", "--na", "claude", "--app"}
		}, 2, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			b := newUserIdentityBox(t)
			args := tc.prepare(t, b)
			before := b.snapshot()
			callers := func() map[string]string {
				if _, err := os.Lstat(b.callers); os.IsNotExist(err) {
					return nil
				}
				return userIdentityDirDigest(t, b.callers)
			}
			callersBefore := callers()
			b.clearSystemctlLog()
			run := b.runWith("/usr/bin/python3", append(args, "--json")...)
			if run.code != tc.code {
				t.Fatalf("want exit %d\n%s", tc.code, run)
			}
			if tc.want != "" && (run.result() != "refused" || !strings.Contains(run.message(), tc.want)) {
				t.Fatalf("want refused with %q\n%s", tc.want, run)
			}
			if strings.Contains(run.stderr, "Traceback") {
				t.Fatalf("the run ended in a traceback\n%s", run)
			}
			requireSameUserIdentitySnapshot(t, before, b.snapshot(), "a refused run")
			if !reflect.DeepEqual(callersBefore, callers()) {
				t.Fatal("a refused run changed the caller directory")
			}
			if r := b.restarts(); len(r) != 0 {
				t.Fatalf("a refused run restarted %v", r)
			}
		})
	}
}

// TestUserIdentityCheckRefusesAServerForAnotherHost serves AGS's check
// route with a certificate for another address: check must not trust it,
// and must not send the request.
func TestUserIdentityCheckRefusesAServerForAnotherHost(t *testing.T) {
	requireUserIdentityOpenSSL3(t)
	b := newUserIdentityBox(t)
	serverCA, serverCAKey, serverCAPEM := userIdentityTestCA(t, "Remote Alpha Server CA")
	serverCAFile := filepath.Join(b.root, "server-ca.pem")
	writeUserIdentityFile(t, serverCAFile, serverCAPEM, 0o644)
	b.mustOK(b.caller("install", "--name", "claude", "--cert", b.mint("claude"), "--server-ca", serverCAFile), "install")

	key, err := ecdsaP256Key()
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: "elsewhere.test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.2")},
	}, serverCA, &key.PublicKey, serverCAKey)
	if err != nil {
		t.Fatal(err)
	}
	var requests atomic.Int32
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, `{"code":"invalid_request"}`)
	}))
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, ClientAuth: tls.RequireAnyClientCert}
	server.StartTLS()
	defer server.Close()

	run := b.checkOutcome("claude", "ags", server.URL)
	if run.code != 1 || run.fact("outcome") != "server_not_trusted" || !strings.Contains(run.stdout, "not trusted for 127.0.0.1") {
		t.Fatalf("check against a server certified for 127.0.0.2 only: want server_not_trusted\n%s", run)
	}
	if n := requests.Load(); n != 0 {
		t.Fatalf("check sent %d requests to a server it does not trust", n)
	}
}

// TestUserIdentityRevokeRemovesEveryCopyAndGrant puts the name in the
// allowlists more than once and in two spellings, and in workload grant
// rules as publisher and as caller. status flags what it sees; revoke
// removes all of it, keeps every other rule and byte, and status is clean.
func TestUserIdentityRevokeRemovesEveryCopyAndGrant(t *testing.T) {
	requireUserIdentityOpenSSL3(t)
	b := newUserIdentityBox(t)
	b.mint("claude")
	b.mint("alice")
	b.mint("claudette")
	b.mustOK(b.box("allow", "--name", "claude", "--apply"), "allow claude")
	b.mustOK(b.box("allow", "--name", "alice", "--apply"), "allow alice")
	b.mustOK(b.box("allow", "--name", "claudette", "--apply"), "allow claudette")
	const (
		claudeID = "spiffe://execution.internal/user/claude"
		aliceID  = "spiffe://execution.internal/user/alice"
		// A name that starts with "claude" but is another user: its rules stay.
		claudetteID = "spiffe://execution.internal/user/claudette"
	)
	// The rule shape of ES's admission_policy.workload_grants (ES PR #73):
	// the example es.json's provenance key and an admitted runtime profile.
	rule := func(publisher, caller string) string {
		short := func(id string) string {
			return strings.ReplaceAll(strings.TrimPrefix(id, "spiffe://execution.internal/user/"), "/", "-")
		}
		return `{"id": "` + short(publisher) + "-for-" + short(caller) + `", "publisher_principal": "` + publisher + `", "caller_principal": "` + caller +
			`", "signer_key_id": "ags-key-1", "artifact_type": "static-script", "runtime_profile": "static-script/default", "egress_lane": "unrestricted"}`
	}
	// Rules for a path below user/claude: ES admits that caller under the
	// entry user/claude, and refuses to start with the rule once the entry
	// is gone (re-audit R3).
	const claudeSubID = claudeID + "/x"
	addedRules := []string{rule(claudeID, aliceID), rule(aliceID, claudeID), rule(claudeSubID, aliceID), rule(aliceID, claudeSubID), rule(aliceID, aliceID), rule(claudetteID, claudetteID)}
	editUserIdentityFile(t, b.esConfig, func(s string) string {
		s = mustReplaceOnce(t, s, `"user/claude"`, `"user/claude", "user/claude"`)
		var doc map[string]any
		if err := json.Unmarshal([]byte(s), &doc); err != nil {
			t.Fatal(err)
		}
		// Keep the example's own admission_policy and rules, if it has them.
		policy, _ := doc["admission_policy"].(map[string]any)
		if policy == nil {
			policy = map[string]any{}
			doc["admission_policy"] = policy
		}
		grants, _ := policy["workload_grants"].(map[string]any)
		if grants == nil {
			grants = map[string]any{"egress_lanes": []any{map[string]any{"name": "unrestricted", "reaches_workload_vault": true}}}
			policy["workload_grants"] = grants
		}
		rules, _ := grants["rules"].([]any)
		for _, text := range addedRules {
			var r map[string]any
			if err := json.Unmarshal([]byte(text), &r); err != nil {
				t.Fatal(err)
			}
			rules = append(rules, r)
		}
		grants["rules"] = rules
		out, err := json.MarshalIndent(doc, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		return string(out) + "\n"
	})
	editUserIdentityFile(t, b.agsConfig, func(s string) string { return mustReplaceOnce(t, s, `"user/claude"`, `"user/claude", "/user/claude"`) })
	beforeES := mustReadUserIdentityFile(t, b.esConfig)

	status := b.box("status")
	for _, want := range []string{"listed more than once", "not the exact form user/<name>"} {
		if status.result() != "attention" || !strings.Contains(status.stdout, want) {
			t.Fatalf("status before revoke does not say %q:\n%s", want, status)
		}
	}

	b.mustOK(b.box("revoke", "--name", "claude", "--apply"), "revoke claude")
	for _, path := range []string{b.agsConfig, b.esConfig} {
		text := string(mustReadUserIdentityFile(t, path))
		if strings.Contains(text, `user/claude"`) || strings.Contains(text, claudeID+`"`) || strings.Contains(text, claudeID+"/") {
			t.Fatalf("revoke left user/claude in %s:\n%s", path, text)
		}
		if !strings.Contains(text, `"user/alice"`) || !strings.Contains(text, `"user/claudette"`) {
			t.Fatalf("revoke took user/alice or user/claudette out of %s", path)
		}
	}
	var before, after map[string]any
	if err := json.Unmarshal(beforeES, &before); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(mustReadUserIdentityFile(t, b.esConfig), &after); err != nil {
		t.Fatal(err)
	}
	rulesBefore := before["admission_policy"].(map[string]any)["workload_grants"].(map[string]any)["rules"].([]any)
	rules := after["admission_policy"].(map[string]any)["workload_grants"].(map[string]any)["rules"].([]any)
	if len(rules) != len(rulesBefore)-4 {
		t.Fatalf("rules after revoke: %v, want every rule but the four naming user/claude or a path below it", rules)
	}
	claudetteRule := false
	for _, r := range rules {
		for _, field := range []string{"publisher_principal", "caller_principal"} {
			if v, _ := r.(map[string]any)[field].(string); v == claudeID || strings.HasPrefix(v, claudeID+"/") {
				t.Fatalf("revoke left the rule %v", r)
			}
		}
		claudetteRule = claudetteRule || r.(map[string]any)["publisher_principal"] == claudetteID
	}
	if !claudetteRule {
		t.Fatal("revoke of user/claude removed user/claudette's rule")
	}
	if userIdentityESHasWorkloadGrants() {
		// The edited es.json must still start ES.
		if err := userIdentityLoadESConfig(b.esConfig); err != nil {
			t.Fatalf("es/config refuses es.json after revoke: %v", err)
		}
	}
	for _, doc := range []map[string]any{before, after} {
		delete(doc["admission_policy"].(map[string]any)["workload_grants"].(map[string]any), "rules")
		delete(doc["authorization"].(map[string]any), "allowed_spiffe_path_prefixes")
	}
	if !reflect.DeepEqual(before, after) {
		t.Fatal("revoke changed more of es.json than the allowlist and the rules")
	}
	if status := b.box("status"); status.result() != "ok" {
		t.Fatalf("status after revoke:\n%s", status)
	}

	// A rule naming a revoked user, written later by hand.
	editUserIdentityFile(t, b.esConfig, func(s string) string {
		var doc map[string]any
		if err := json.Unmarshal([]byte(s), &doc); err != nil {
			t.Fatal(err)
		}
		var r map[string]any
		if err := json.Unmarshal([]byte(rule(aliceID, claudeID)), &r); err != nil {
			t.Fatal(err)
		}
		grants := doc["admission_policy"].(map[string]any)["workload_grants"].(map[string]any)
		grants["rules"] = append(grants["rules"].([]any), r)
		out, err := json.MarshalIndent(doc, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		return string(out) + "\n"
	})
	if status := b.box("status"); status.result() != "attention" || !strings.Contains(status.stdout, "caller_principal "+claudeID+" is not an active user") {
		t.Fatalf("status with a rule for a revoked user:\n%s", status)
	}
}

// TestUserIdentityInitCAReplaceKeepsRevocations retires the user CA with
// revoke --remove-ca, replaces it, and onboards a new name under the new
// CA. Every revoked name stays revoked; the old CA, if it comes back into
// the client CA files, is flagged and blocks allow.
func TestUserIdentityInitCAReplaceKeepsRevocations(t *testing.T) {
	requireUserIdentityOpenSSL3(t)
	b := newUserIdentityBox(t)
	b.mint("claude")
	b.mustOK(b.box("allow", "--name", "claude", "--apply"), "allow")
	b.mustOK(b.box("revoke", "--name", "claude", "--remove-ca", "--apply"), "revoke --remove-ca")
	oldCert := mustReadUserIdentityFile(t, filepath.Join(b.userCADir, "ca-cert.pem"))
	oldSHA := b.userCASHA256()
	oldKey := mustReadUserIdentityFile(t, filepath.Join(b.userCADir, "ca-key.pem"))

	if status := b.box("status"); !strings.Contains(status.stdout, "retired at") {
		t.Fatalf("status does not show the retired CA:\n%s", status)
	}
	if run := b.box("init-ca", "--apply"); run.result() != "refused" || !strings.Contains(run.message(), "init-ca --replace replaces it") {
		t.Fatalf("init-ca without --replace: %s", run)
	}
	before := b.snapshot()
	b.mustOK(b.box("init-ca", "--replace"), "init-ca --replace without --apply")
	requireSameUserIdentitySnapshot(t, before, b.snapshot(), "a planned replacement")

	run := b.mustOK(b.box("init-ca", "--replace", "--apply"), "init-ca --replace")
	newSHA := b.userCASHA256()
	if newSHA == oldSHA || run.fact("retired_ca_sha256") != oldSHA || run.fact("ca_sha256") != newSHA {
		t.Fatalf("replacement facts: %v; old %s new %s", run.doc["facts"], oldSHA, newSHA)
	}
	if bytes.Equal(mustReadUserIdentityFile(t, filepath.Join(b.userCADir, "ca-key.pem")), oldKey) {
		t.Fatal("the old CA key is still in place")
	}
	if kept := mustReadUserIdentityFile(t, filepath.Join(b.userCADir, "retired", oldSHA+".pem")); !bytes.Equal(kept, oldCert) {
		t.Fatal("the old CA certificate was not kept under retired/")
	}
	if _, err := os.Lstat(filepath.Join(b.userCADir, "next")); !os.IsNotExist(err) {
		t.Fatalf("next/ is still there: %v", err)
	}
	var registry struct {
		CA         map[string]any            `json:"ca"`
		RetiredCAs []map[string]any          `json:"retired_cas"`
		Names      map[string]map[string]any `json:"names"`
	}
	if err := json.Unmarshal(mustReadUserIdentityFile(t, b.registryPath()), &registry); err != nil {
		t.Fatal(err)
	}
	if registry.CA["sha256"] != newSHA || registry.CA["retired_at"] != nil || len(registry.RetiredCAs) != 1 ||
		registry.RetiredCAs[0]["sha256"] != oldSHA || registry.RetiredCAs[0]["retired_at"] == nil || registry.RetiredCAs[0]["replaced_at"] == nil ||
		registry.Names["claude"]["state"] != "revoked" {
		t.Fatalf("registry after the replacement: %+v", registry)
	}

	// The new CA onboards a new name; the revoked name stays refused.
	b.mint("bob")
	b.mustOK(b.box("allow", "--name", "bob", "--apply"), "allow bob under the new CA")
	newCert := mustReadUserIdentityFile(t, filepath.Join(b.userCADir, "ca-cert.pem"))
	for _, path := range []string{b.agsCA, b.esCA} {
		data := mustReadUserIdentityFile(t, path)
		if !bytes.HasSuffix(data, newCert) || bytes.Contains(data, oldCert) {
			t.Fatalf("%s does not end with the new CA alone", path)
		}
	}
	for _, path := range []string{b.agsConfig, b.esConfig} {
		if text := string(mustReadUserIdentityFile(t, path)); !strings.Contains(text, newSHA) || strings.Contains(text, oldSHA) {
			t.Fatalf("%s does not bind user to the new CA alone", path)
		}
	}
	if run := b.box("allow", "--name", "claude", "--apply"); run.result() != "refused" || !strings.Contains(run.message(), "was revoked") {
		t.Fatalf("allow of the revoked name under the new CA: %s", run)
	}

	// The retired CA back in the client CA files, before the new one.
	for _, path := range []string{b.agsCA, b.esCA} {
		data := mustReadUserIdentityFile(t, path)
		writeUserIdentityFile(t, path, append(append(bytes.TrimSuffix(data, newCert), oldCert...), newCert...), 0o640)
	}
	if status := b.box("status"); status.result() != "attention" || !strings.Contains(status.stdout, oldSHA[:16]) {
		t.Fatalf("status with the retired CA back:\n%s", status)
	}
	b.mint("carol")
	if run := b.box("allow", "--name", "carol", "--apply"); run.result() != "refused" || !strings.Contains(run.message(), "hold another user CA ("+oldSHA[:16]) {
		t.Fatalf("allow with the retired CA back: %s", run)
	}
}

// TestUserIdentityInitCAReplaceFinishesAfterAStop leaves a replacement
// unfinished at each point: before the registry names the new CA (staged),
// after it does (committed), and with only the key moved. Every other mode
// refuses until init-ca --replace --apply finishes or discards it.
func TestUserIdentityInitCAReplaceFinishesAfterAStop(t *testing.T) {
	requireUserIdentityOpenSSL3(t)
	certSHA := func(t *testing.T, path string) string {
		sum := sha256.Sum256(parseUserIdentityPEMCert(t, mustReadUserIdentityFile(t, path)).Raw)
		return hex.EncodeToString(sum[:])
	}
	registryCA := func(t *testing.T, b *userIdentityBox) string {
		var registry struct {
			CA map[string]any `json:"ca"`
		}
		if err := json.Unmarshal(mustReadUserIdentityFile(t, b.registryPath()), &registry); err != nil {
			t.Fatal(err)
		}
		s, _ := registry.CA["sha256"].(string)
		return s
	}
	requireBlocked := func(t *testing.T, b *userIdentityBox) {
		t.Helper()
		b.mustOK(b.caller("request", "--name", "dana"), "request")
		csr := filepath.Join(b.callerDir("dana"), "request.csr")
		if run := b.box("issue", "--name", "dana", "--csr", csr, "--out", filepath.Join(b.root, "dana.crt"), "--apply"); run.result() != "refused" ||
			!strings.Contains(run.message(), "an init-ca --replace did not finish") {
			t.Fatalf("issue during an unfinished replacement: %s", run)
		}
		if status := b.box("status"); status.result() != "attention" || !strings.Contains(status.stdout, "did not finish") {
			t.Fatalf("status during an unfinished replacement:\n%s", status)
		}
	}

	t.Run("a staging directory left by a killed build", func(t *testing.T) {
		t.Parallel()
		b := newUserIdentityBox(t)
		b.mustOK(b.box("init-ca", "--apply"), "init-ca")
		staging := filepath.Join(b.userCADir, "next.staging-killed")
		if err := os.Mkdir(staging, 0o700); err != nil {
			t.Fatal(err)
		}
		writeUserIdentityFile(t, filepath.Join(staging, "ca-key.pem"), []byte("half-made"), 0o600)
		// It is not next/: nothing refuses because of it.
		if status := b.box("status"); status.result() != "ok" {
			t.Fatalf("status beside a staging directory:\n%s", status)
		}
		b.mustOK(b.box("init-ca", "--replace", "--apply"), "init-ca --replace")
		if _, err := os.Lstat(staging); !os.IsNotExist(err) {
			t.Fatalf("the staging directory is still there: %v", err)
		}
	})

	t.Run("a build killed before it wrote anything", func(t *testing.T) {
		t.Parallel()
		b := newUserIdentityBox(t)
		b.mustOK(b.box("init-ca", "--apply"), "init-ca")
		oldSHA := b.userCASHA256()
		if run := b.boxWithFault("exit-at-ca-build", "init-ca", "--replace", "--apply"); run.code != 137 {
			t.Fatalf("init-ca --replace killed as its build starts: want exit 137\n%s", run)
		}
		// next/ never exists empty or half-made, so nothing reads the kill
		// as a replacement that took effect, and nothing refuses.
		if _, err := os.Lstat(filepath.Join(b.userCADir, "next")); !os.IsNotExist(err) {
			t.Fatalf("a killed build left next/: %v", err)
		}
		if status := b.box("status"); status.result() != "ok" || registryCA(t, b) != oldSHA {
			t.Fatalf("status after a killed build:\n%s", status)
		}
		b.mustOK(b.box("init-ca", "--replace", "--apply"), "init-ca --replace after a killed build")
		if newSHA := b.userCASHA256(); newSHA == oldSHA || registryCA(t, b) != newSHA {
			t.Fatalf("the replacement after a killed build left the CA %s (old %s, registry %s)", newSHA, oldSHA, registryCA(t, b))
		}
		entries, err := os.ReadDir(b.userCADir)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range entries {
			if strings.HasPrefix(e.Name(), "next") {
				t.Fatalf("%s is still in the CA directory", e.Name())
			}
		}
	})

	t.Run("staged", func(t *testing.T) {
		t.Parallel()
		b := newUserIdentityBox(t)
		b.mustOK(b.box("init-ca", "--apply"), "init-ca")
		oldSHA := b.userCASHA256()
		next := filepath.Join(b.userCADir, "next")
		if err := os.Mkdir(next, 0o700); err != nil {
			t.Fatal(err)
		}
		writeUserIdentityFile(t, filepath.Join(next, "ca-cert.pem"), sameSubjectCA(t), 0o644)
		requireBlocked(t, b)
		run := b.mustOK(b.box("init-ca", "--replace", "--apply"), "init-ca --replace over a staged replacement")
		if !strings.Contains(run.stdout, "discard the unfinished replacement") || registryCA(t, b) == oldSHA || registryCA(t, b) != b.userCASHA256() {
			t.Fatalf("replacement over a staged one:\n%s", run)
		}
		if _, err := os.Lstat(next); !os.IsNotExist(err) {
			t.Fatalf("next/ is still there: %v", err)
		}
	})

	for moved, name := range []string{"committed", "committed with the key already moved", "committed with both files moved"} {
		moved := moved
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			b := newUserIdentityBox(t)
			b.mustOK(b.box("init-ca", "--apply"), "init-ca")
			oldSHA := b.userCASHA256()
			run := b.boxWithFault("finish-replacement-fails", "init-ca", "--replace", "--apply")
			if run.result() != "failed" || !strings.Contains(run.message(), "run init-ca --replace --apply again to finish") {
				t.Fatalf("replacement whose move fails: %s", run)
			}
			next := filepath.Join(b.userCADir, "next")
			newSHA := certSHA(t, filepath.Join(next, "ca-cert.pem"))
			if registryCA(t, b) != newSHA || b.userCASHA256() != oldSHA {
				t.Fatalf("after the failed move the registry names %s; want the new CA %s, with the old %s still in place", registryCA(t, b), newSHA, oldSHA)
			}
			// finish_replacement moves the key, then the certificate, then
			// removes next/: a stop between any two leaves one of these.
			for _, file := range []string{"ca-key.pem", "ca-cert.pem"}[:moved] {
				if err := os.Rename(filepath.Join(next, file), filepath.Join(b.userCADir, file)); err != nil {
					t.Fatal(err)
				}
			}
			requireBlocked(t, b)
			run = b.mustOK(b.box("init-ca", "--replace", "--apply"), "init-ca --replace to finish")
			if !strings.Contains(run.message(), "replacement is finished") || b.userCASHA256() != newSHA || registryCA(t, b) != newSHA {
				t.Fatalf("finishing the replacement (it must not replace the CA a second time):\n%s", run)
			}
			if _, err := os.Lstat(next); !os.IsNotExist(err) {
				t.Fatalf("next/ is still there: %v", err)
			}
			b.mustOK(b.box("issue", "--name", "dana", "--csr", filepath.Join(b.callerDir("dana"), "request.csr"),
				"--out", filepath.Join(b.root, "dana.crt"), "--apply"), "issue under the finished replacement")
		})
	}
}

// TestUserIdentityIssueSaysWhereTheCertificateIsWhenOutFails makes --out
// unwritable: the certificate is recorded and kept in issued/, and the
// message says so and names the file.
func TestUserIdentityIssueSaysWhereTheCertificateIsWhenOutFails(t *testing.T) {
	requireUserIdentityOpenSSL3(t)
	if os.Geteuid() == 0 {
		t.Skip("root writes into a mode 0555 directory; this test needs an ordinary user")
	}
	b := newUserIdentityBox(t)
	b.mustOK(b.box("init-ca", "--apply"), "init-ca")
	b.mustOK(b.caller("request", "--name", "claude"), "request")
	locked := filepath.Join(b.root, "locked")
	if err := os.Mkdir(locked, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(locked, 0o755) })
	run := b.box("issue", "--name", "claude", "--csr", filepath.Join(b.callerDir("claude"), "request.csr"), "--out", filepath.Join(locked, "claude.crt"), "--apply")
	serial := run.fact("serial")
	if serial == "" {
		var registry struct {
			Names map[string]struct {
				Certificates []struct {
					Serial string `json:"serial"`
				} `json:"certificates"`
			} `json:"names"`
		}
		if err := json.Unmarshal(mustReadUserIdentityFile(t, b.registryPath()), &registry); err != nil || len(registry.Names["claude"].Certificates) != 1 {
			t.Fatalf("the registry does not hold one certificate for claude: %v\n%s", err, run)
		}
		serial = registry.Names["claude"].Certificates[0].Serial
	}
	kept := filepath.Join(b.userCADir, "issued", serial+".pem")
	if run.result() != "failed" || !strings.Contains(run.message(), "was signed and recorded") || !strings.Contains(run.message(), "copy "+kept) {
		t.Fatalf("issue with an unwritable --out:\n%s", run)
	}
	if _, err := os.Stat(kept); err != nil || b.registryState("claude") != "active" {
		t.Fatalf("issued certificate %s: %v; registry state %q", kept, err, b.registryState("claude"))
	}
}

// TestUserIdentityRevokeBackupFailureSaysRunAgain makes the backup fail
// after revoke has marked the name revoked: the message says the services
// were not changed and to run revoke again, and the next run finishes.
func TestUserIdentityRevokeBackupFailureSaysRunAgain(t *testing.T) {
	requireUserIdentityOpenSSL3(t)
	b := newUserIdentityBox(t)
	b.mint("claude")
	b.mustOK(b.box("allow", "--name", "claude", "--apply"), "allow")
	b.clearSystemctlLog()
	run := b.boxWithFault("backup-fails", "revoke", "--name", "claude", "--apply")
	if run.result() != "failed" || !strings.Contains(run.message(), "AGS and ES were not changed and may still allow user/claude") ||
		!strings.Contains(run.message(), "No space left on device") || !strings.Contains(run.message(), "run revoke again") {
		t.Fatalf("revoke whose backup fails:\n%s", run)
	}
	if len(b.restarts()) != 0 || !strings.Contains(string(mustReadUserIdentityFile(t, b.esConfig)), `"user/claude"`) {
		t.Fatalf("a revoke whose backup failed changed the services: restarts %v", b.restarts())
	}
	if state, pending := b.registryState("claude"), b.pendingRestarts("claude"); state != "revoked" || pending != "ags.service,es.service" {
		t.Fatalf("registry after the failed backup: state %q, pending %q", state, pending)
	}
	b.mustOK(b.box("revoke", "--name", "claude", "--apply"), "revoke again")
	if strings.Contains(string(mustReadUserIdentityFile(t, b.esConfig)), `"user/claude"`) || b.pendingRestarts("claude") != "" {
		t.Fatal("the second revoke did not finish")
	}
}

// TestUserIdentityRefusesABoxFileOwnedByAnotherUID refuses a config file
// that another UID owns even when its directory and mode are right, before
// anything changes.
func TestUserIdentityRefusesABoxFileOwnedByAnotherUID(t *testing.T) {
	requireUserIdentityOpenSSL3(t)
	b := newUserIdentityBox(t)
	b.mint("claude")
	before := b.snapshot()
	for _, base := range []string{"ags.json", "es.json"} {
		run := b.boxWithFault("owned-by-another-uid="+base, "allow", "--name", "claude", "--apply")
		if run.code != 1 || !strings.Contains(run.message(), base+" must be owned by UID") {
			t.Fatalf("allow with %s owned by another UID:\n%s", base, run)
		}
	}
	requireSameUserIdentitySnapshot(t, before, b.snapshot(), "an allow refused for a file owner")
	if len(b.restarts()) != 0 {
		t.Fatalf("a refused allow restarted %v", b.restarts())
	}
}

// TestUserIdentityAllowRefusesAnExpiredCA swaps in the same CA certificate
// with a validity that has ended (same key, subject and extensions; the
// registry names it) while the name still has an unexpired certificate on
// record. allow refuses and changes nothing.
func TestUserIdentityAllowRefusesAnExpiredCA(t *testing.T) {
	requireUserIdentityOpenSSL3(t)
	b := newUserIdentityBox(t)
	b.mint("claude")
	certPath := filepath.Join(b.userCADir, "ca-cert.pem")
	old := parseUserIdentityPEMCert(t, mustReadUserIdentityFile(t, certPath))
	caKey := userIdentityPrivateKey(t, filepath.Join(b.userCADir, "ca-key.pem"))
	template := *old
	template.RawSubject = old.RawSubject
	template.NotBefore = time.Now().Add(-48 * time.Hour)
	template.NotAfter = time.Now().Add(-time.Hour)
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	writeUserIdentityFile(t, certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644)
	editUserIdentityFile(t, b.registryPath(), func(s string) string {
		var registry map[string]any
		if err := json.Unmarshal([]byte(s), &registry); err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(der)
		registry["ca"].(map[string]any)["sha256"] = hex.EncodeToString(sum[:])
		data, err := json.MarshalIndent(registry, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		return string(data) + "\n"
	})
	before := b.snapshot()
	run := b.box("allow", "--name", "claude", "--apply")
	if run.code != 1 || !strings.Contains(run.message(), "the user CA has expired") {
		t.Fatalf("allow with an expired user CA:\n%s", run)
	}
	requireSameUserIdentitySnapshot(t, before, b.snapshot(), "an allow refused for an expired CA")
	if len(b.restarts()) != 0 {
		t.Fatalf("a refused allow restarted %v", b.restarts())
	}
}

// TestUserIdentityCraftedDERIsRefused feeds the DER readers malformed input
// from the two places it can come from: a caller's CSR and a block in a
// client CA file. Each ends in a report, never a traceback.
func TestUserIdentityCraftedDERIsRefused(t *testing.T) {
	requireUserIdentityOpenSSL3(t)
	b := newUserIdentityBox(t)
	b.mustOK(b.box("init-ca", "--apply"), "init-ca")

	// A CSR whose signatureAlgorithm is an empty SEQUENCE.
	key, err := ecdsaP256Key()
	if err != nil {
		t.Fatal(err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "claude"}}, key)
	if err != nil {
		t.Fatal(err)
	}
	var parts struct {
		Info      asn1.RawValue
		Algorithm asn1.RawValue
		Signature asn1.BitString
	}
	if _, err := asn1.Unmarshal(csrDER, &parts); err != nil {
		t.Fatal(err)
	}
	parts.Algorithm = asn1.RawValue{FullBytes: []byte{0x30, 0x00}}
	crafted, err := asn1.Marshal(parts)
	if err != nil {
		t.Fatal(err)
	}
	csr := filepath.Join(b.root, "crafted.csr")
	writeUserIdentityFile(t, csr, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: crafted}), 0o644)
	before := b.snapshot()
	run := b.box("issue", "--name", "claude", "--csr", csr, "--out", filepath.Join(b.root, "claude.crt"), "--apply")
	if run.result() != "refused" || !strings.Contains(run.message(), "is not a CSR this helper can read") || strings.Contains(run.stderr, "Traceback") {
		t.Fatalf("issue of a crafted CSR:\n%s", run)
	}
	requireSameUserIdentitySnapshot(t, before, b.snapshot(), "issue of a crafted CSR")

	// A client CA block whose notBefore has month 13.
	block, _ := pem.Decode(b.extCAPEM)
	der := append([]byte(nil), block.Bytes...)
	i := bytes.Index(der, []byte{0x17, 0x0d})
	if i < 0 {
		t.Fatal("no UTCTime in the test CA")
	}
	copy(der[i+4:i+6], "13")
	bad := append(append([]byte(nil), b.extCAPEM...), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	writeUserIdentityFile(t, b.agsCA, bad, 0o640)
	writeUserIdentityFile(t, b.esCA, bad, 0o640)
	status := b.box("status")
	if status.result() != "attention" || !strings.Contains(status.stdout, "unreadable certificate") || strings.Contains(status.stderr, "Traceback") {
		t.Fatalf("status with a crafted client CA block:\n%s", status)
	}
}

// bindsUserAlone reports whether the config at path binds the user namespace
// to the CA with SHA-256 sha and holds no other binding of user or of that CA.
func bindsUserAlone(t *testing.T, path, sha string) bool {
	t.Helper()
	var doc struct {
		Security struct {
			NamespaceIssuers []struct {
				PathPrefix string `json:"path_prefix"`
				SHA256     string `json:"issuer_certificate_sha256"`
			} `json:"namespace_issuers"`
		} `json:"security"`
	}
	if err := json.Unmarshal(mustReadUserIdentityFile(t, path), &doc); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	found := 0
	for _, issuer := range doc.Security.NamespaceIssuers {
		if issuer.PathPrefix == "user" || strings.HasPrefix(issuer.PathPrefix, "user/") || issuer.SHA256 == sha {
			if issuer.PathPrefix != "user" || issuer.SHA256 != sha {
				return false
			}
			found++
		}
	}
	return found == 1
}

// userIdentityAGSPublishCode is userIdentityAGSPublishStatus that returns 0
// when the TLS handshake refuses the client certificate.
func userIdentityAGSPublishCode(agsURL string, serverCA []byte, pair tls.Certificate) int {
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(serverCA)
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, Certificates: []tls.Certificate{pair}}}, Timeout: 10 * time.Second}
	defer client.CloseIdleConnections()
	resp, err := client.Post(agsURL+"/v1/artifacts:publish", "application/json", strings.NewReader(""))
	if err != nil {
		return 0
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode
}

// requireNoTrustWithoutBinding checks the service files on disk as AGS and
// ES would load them at their next start: a client CA file that holds the
// user CA has its service's user binding beside it, and both real handlers,
// started from those files, refuse an operator/local certificate signed with
// the user CA key (401, or the TLS handshake fails).
func (b *userIdentityBox) requireNoTrustWithoutBinding(what string) {
	b.t.Helper()
	caPEM := mustReadUserIdentityFile(b.t, filepath.Join(b.userCADir, "ca-cert.pem"))
	sha := b.userCASHA256()
	for _, svc := range []struct{ label, config, ca string }{{"AGS", b.agsConfig, b.agsCA}, {"ES", b.esConfig, b.esCA}} {
		if bytes.HasSuffix(mustReadUserIdentityFile(b.t, svc.ca), caPEM) && !bindsUserAlone(b.t, svc.config, sha) {
			b.t.Fatalf("%s: %s trusts the user CA without its binding", what, svc.label)
		}
	}
	serverCA, serverCAKey, serverCAPEM := userIdentityTestCA(b.t, "Remote Alpha Server CA")
	servers := startUserIdentityServers(b.t, b, userIdentityServerCert(b.t, serverCA, serverCAKey))
	defer servers.Close()
	forged := b.userCASignedPair("operator/local")
	if got, err := userIdentityGet(servers.es.URL+"/v1/executions:contract", serverCAPEM, forged); err == nil && !strings.HasPrefix(got, "401 ") {
		b.t.Fatalf("%s: ES answers an operator/local certificate signed with the user CA key with %s", what, got)
	}
	if code := userIdentityAGSPublishCode(servers.ags.URL, serverCAPEM, forged); code != 0 && code != http.StatusUnauthorized {
		b.t.Fatalf("%s: AGS answers an operator/local certificate signed with the user CA key with %d", what, code)
	}
}

// requireUserCAGone checks that neither client CA file holds the user CA and
// neither config binds user.
func (b *userIdentityBox) requireUserCAGone(what string) {
	b.t.Helper()
	caPEM := mustReadUserIdentityFile(b.t, filepath.Join(b.userCADir, "ca-cert.pem"))
	for _, path := range []string{b.agsCA, b.esCA} {
		if bytes.Contains(mustReadUserIdentityFile(b.t, path), caPEM) {
			b.t.Fatalf("%s: %s still holds the user CA", what, path)
		}
	}
	for _, path := range []string{b.agsConfig, b.esConfig} {
		if strings.Contains(string(mustReadUserIdentityFile(b.t, path)), "namespace_issuers") {
			b.t.Fatalf("%s: %s still has a namespace binding", what, path)
		}
	}
}

// TestUserIdentityNoCutLeavesTrustWithoutBinding kills allow and revoke
// --remove-ca after each of their service file writes but the last, as a
// SIGKILL, the OOM killer or a power cut would, where no signal handler or
// rollback runs. At every point, no service would start trusting the user CA
// without its binding, and running the same mode again finishes the change.
func TestUserIdentityNoCutLeavesTrustWithoutBinding(t *testing.T) {
	requireUserIdentityOpenSSL3(t)
	for n := 1; n <= 3; n++ {
		n := n
		t.Run(fmt.Sprintf("allow killed after write %d", n), func(t *testing.T) {
			t.Parallel()
			b := newUserIdentityBox(t)
			b.mint("claude")
			run := b.boxWithFault(fmt.Sprintf("exit-after-writes=%d", n), "allow", "--name", "claude", "--apply")
			if run.code != 137 {
				t.Fatalf("allow with a kill after write %d: want exit 137\n%s", n, run)
			}
			if len(b.restarts()) != 0 {
				t.Fatalf("a killed allow restarted %v", b.restarts())
			}
			b.requireNoTrustWithoutBinding(fmt.Sprintf("allow killed after write %d", n))
			b.mustOK(b.box("allow", "--name", "claude", "--apply"), "allow again")
			if status := b.box("status"); status.result() != "ok" {
				t.Fatalf("status after allow finished a killed one:\n%s", status)
			}
		})
		t.Run(fmt.Sprintf("revoke --remove-ca killed after write %d", n), func(t *testing.T) {
			t.Parallel()
			b := newUserIdentityBox(t)
			b.mint("claude")
			b.mustOK(b.box("allow", "--name", "claude", "--apply"), "allow")
			b.clearSystemctlLog()
			run := b.boxWithFault(fmt.Sprintf("exit-after-writes=%d", n), "revoke", "--name", "claude", "--remove-ca", "--apply")
			if run.code != 137 {
				t.Fatalf("revoke --remove-ca with a kill after write %d: want exit 137\n%s", n, run)
			}
			b.requireNoTrustWithoutBinding(fmt.Sprintf("revoke --remove-ca killed after write %d", n))
			if status := b.box("status"); status.result() != "attention" || !strings.Contains(status.stdout, "revoke --name claude --remove-ca --apply") {
				t.Fatalf("status after a killed revoke --remove-ca does not say how to finish:\n%s", status)
			}
			// The CA is retired, so a plain revoke finishes its removal.
			b.mustOK(b.box("revoke", "--name", "claude", "--apply"), "revoke again")
			b.requireUserCAGone("after revoke finished a killed one")
			if status := b.box("status"); status.result() != "ok" {
				t.Fatalf("status after revoke finished a killed one:\n%s", status)
			}
		})
	}
}

// TestUserIdentityRemoveCAKeepsTheBindingOfAFileItCannotWrite makes one
// client CA file unwritable during revoke --remove-ca (re-audit R1, red-team
// RT70b-1): that service keeps the user CA and therefore its binding, the
// allowlist removal still lands in both configs, status names what is left,
// and a second revoke finishes it once the file can be written.
func TestUserIdentityRemoveCAKeepsTheBindingOfAFileItCannotWrite(t *testing.T) {
	requireUserIdentityOpenSSL3(t)
	for _, tc := range []struct {
		label, other string
		ca           func(b *userIdentityBox) string
		config       func(b *userIdentityBox) string
		otherConfig  func(b *userIdentityBox) string
		again        []string
	}{
		{"AGS", "ES", func(b *userIdentityBox) string { return b.agsCA }, func(b *userIdentityBox) string { return b.agsConfig },
			func(b *userIdentityBox) string { return b.esConfig }, []string{"revoke", "--name", "claude", "--remove-ca", "--apply"}},
		{"ES", "AGS", func(b *userIdentityBox) string { return b.esCA }, func(b *userIdentityBox) string { return b.esConfig },
			func(b *userIdentityBox) string { return b.agsConfig }, []string{"revoke", "--name", "claude", "--apply"}},
	} {
		tc := tc
		t.Run(tc.label, func(t *testing.T) {
			t.Parallel()
			b := newUserIdentityBox(t)
			b.mint("claude")
			b.mustOK(b.box("allow", "--name", "claude", "--apply"), "allow")
			sha := b.userCASHA256()
			caPEM := mustReadUserIdentityFile(t, filepath.Join(b.userCADir, "ca-cert.pem"))
			b.clearSystemctlLog()
			run := b.boxWithFault("write-fails="+filepath.Base(tc.ca(b)), "revoke", "--name", "claude", "--remove-ca", "--apply")
			if run.code != 1 || run.result() != "failed" || !strings.Contains(run.message(), "could not write "+tc.ca(b)) ||
				!strings.Contains(run.message(), "keeps its user binding") || strings.Contains(run.message(), "does not bind user to it alone") {
				t.Fatalf("revoke --remove-ca with %s unwritable\n%s", tc.ca(b), run)
			}
			for _, path := range []string{b.agsConfig, b.esConfig} {
				if strings.Contains(string(mustReadUserIdentityFile(t, path)), `"user/claude"`) {
					t.Fatalf("a revoke whose client CA write failed left user/claude in %s", path)
				}
			}
			if !bytes.HasSuffix(mustReadUserIdentityFile(t, tc.ca(b)), caPEM) || !bindsUserAlone(t, tc.config(b), sha) {
				t.Fatalf("%s: want the user CA still in the unwritable file and its binding kept", tc.label)
			}
			if strings.Contains(string(mustReadUserIdentityFile(t, tc.otherConfig(b))), "namespace_issuers") {
				t.Fatalf("%s: the binding of the service whose client CA file was written should be gone", tc.other)
			}
			if got := strings.Join(b.restarts(), ","); got != "ags.service,es.service" {
				t.Fatalf("restarts %q", got)
			}
			b.requireNoTrustWithoutBinding("after a revoke --remove-ca whose client CA write failed")
			status := b.box("status")
			if status.result() != "attention" || !strings.Contains(status.stdout, tc.label+" namespace issuer") ||
				!strings.Contains(status.stdout, "the retired user CA is still in "+tc.ca(b)) ||
				!strings.Contains(status.stdout, "revoke --name claude --remove-ca --apply") {
				t.Fatalf("status after the failed write does not name what is left:\n%s", status)
			}
			b.mustOK(b.box(tc.again...), "revoke again")
			b.requireUserCAGone("after the second revoke")
			if status := b.box("status"); status.result() != "ok" {
				t.Fatalf("status after the second revoke:\n%s", status)
			}
		})
	}

	t.Run("a binding already lost beside a retired CA", func(t *testing.T) {
		// The state an earlier helper could leave: the retired user CA in the
		// ES file and no binding in es.json. status names it and revoke
		// removes the CA.
		t.Parallel()
		b := newUserIdentityBox(t)
		b.mint("claude")
		b.mustOK(b.box("allow", "--name", "claude", "--apply"), "allow")
		if run := b.boxWithFault("write-fails="+filepath.Base(b.esCA), "revoke", "--name", "claude", "--remove-ca", "--apply"); run.result() != "failed" {
			t.Fatalf("revoke --remove-ca with the ES client CA file unwritable: %s", run)
		}
		sha := b.userCASHA256()
		editUserIdentityFile(t, b.esConfig, func(s string) string {
			var doc map[string]any
			if err := json.Unmarshal([]byte(s), &doc); err != nil {
				t.Fatal(err)
			}
			delete(doc["security"].(map[string]any), "namespace_issuers")
			out, _ := json.MarshalIndent(doc, "", "  ")
			return string(out) + "\n"
		})
		if bindsUserAlone(t, b.esConfig, sha) {
			t.Fatal("the hand edit kept the binding")
		}
		status := b.box("status")
		if status.result() != "attention" || !strings.Contains(status.stdout, "ES namespace issuer") ||
			!strings.Contains(status.stdout, "the user CA is trusted but user is not bound to it alone") ||
			!strings.Contains(status.stdout, "revoke --name claude --remove-ca --apply") {
			t.Fatalf("status with the retired CA trusted unbound:\n%s", status)
		}
		b.mustOK(b.box("revoke", "--name", "claude", "--remove-ca", "--apply"), "revoke --remove-ca again")
		b.requireUserCAGone("after revoke removed the unbound CA")
	})

	t.Run("revoke never ends ok beside an unbound CA it does not remove", func(t *testing.T) {
		t.Parallel()
		b := newUserIdentityBox(t)
		b.mint("claude")
		b.mint("alice")
		b.mustOK(b.box("allow", "--name", "claude", "--apply"), "allow claude")
		b.mustOK(b.box("allow", "--name", "alice", "--apply"), "allow alice")
		editUserIdentityFile(t, b.agsConfig, func(s string) string {
			var doc map[string]any
			if err := json.Unmarshal([]byte(s), &doc); err != nil {
				t.Fatal(err)
			}
			delete(doc["security"].(map[string]any), "namespace_issuers")
			out, _ := json.MarshalIndent(doc, "", "  ")
			return string(out) + "\n"
		})
		run := b.box("revoke", "--name", "claude", "--apply")
		if run.code != 1 || run.result() != "attention" || !strings.Contains(run.message(), "AGS trusts the user CA but does not bind user to it alone") {
			t.Fatalf("revoke beside an AGS that trusts the user CA unbound\n%s", run)
		}
		if b.registryState("claude") != "revoked" || strings.Contains(string(mustReadUserIdentityFile(t, b.agsConfig)), `"user/claude"`) {
			t.Fatal("the revocation itself did not take effect")
		}
		if run := b.box("revoke", "--name", "claude", "--apply"); run.code != 1 || run.result() != "attention" ||
			!strings.Contains(run.message(), "nothing to do") || !strings.Contains(run.message(), "AGS trusts the user CA but does not bind user to it alone") {
			t.Fatalf("a second revoke, with nothing left to do, beside the same AGS\n%s", run)
		}
	})
	t.Run("revoke never ends ok beside a user CA bound beside another binding", func(t *testing.T) {
		t.Parallel()
		b := newUserIdentityBox(t)
		b.mint("claude")
		b.mint("alice")
		b.mustOK(b.box("allow", "--name", "claude", "--apply"), "allow claude")
		b.mustOK(b.box("allow", "--name", "alice", "--apply"), "allow alice")
		// The user CA also bound to another namespace: it vouches for more
		// than user/ paths there.
		editUserIdentityFile(t, b.esConfig, func(s string) string {
			return mustReplaceOnce(t, s, `"issuer_certificate_sha256": "`+b.userCASHA256()+`"`,
				`"issuer_certificate_sha256": "`+b.userCASHA256()+`"}, {"path_prefix": "robot", "issuer_certificate_sha256": "`+b.userCASHA256()+`"`)
		})
		run := b.box("revoke", "--name", "claude", "--apply")
		if run.code != 1 || run.result() != "attention" || !strings.Contains(run.message(), "ES trusts the user CA but does not bind user to it alone") {
			t.Fatalf("revoke beside an ES that binds the user CA to robot as well\n%s", run)
		}
	})
}

// TestUserIdentityAllowRollbackKeepsTheBindingWhileTheCAMayBeTrusted fails
// allow's rollback at a client CA file. A file that kept its old bytes lets
// the rollback finish exactly; a file that may still hold the user CA keeps
// its service's config, binding included, as allow wrote it.
func TestUserIdentityAllowRollbackKeepsTheBindingWhileTheCAMayBeTrusted(t *testing.T) {
	requireUserIdentityOpenSSL3(t)
	t.Run("the client CA write fails", func(t *testing.T) {
		t.Parallel()
		b := newUserIdentityBox(t)
		b.mint("claude")
		before := b.snapshot()
		b.clearSystemctlLog()
		run := b.boxWithFault("write-fails="+filepath.Base(b.esCA), "allow", "--name", "claude", "--apply")
		if run.code != 1 || run.result() != "failed" || !strings.Contains(run.message(), "rolled back to the backed-up bytes") {
			t.Fatalf("allow whose ES client CA write fails\n%s", run)
		}
		requireSameUserIdentitySnapshot(t, withoutUserIdentityBackups(before), withoutUserIdentityBackups(b.snapshot()), "an allow whose client CA write failed")
		if len(b.restarts()) != 0 {
			t.Fatalf("restarts %v", b.restarts())
		}
	})
	t.Run("the client CA restore fails", func(t *testing.T) {
		t.Parallel()
		b := newUserIdentityBox(t)
		b.mint("claude")
		b.marker("es.service", "fail-next-restart")
		run := b.boxWithFault("restore-fails="+filepath.Base(b.esCA), "allow", "--name", "claude", "--apply")
		if run.code != 1 || run.result() != "failed" || !strings.Contains(run.message(), "rollback incomplete") ||
			!strings.Contains(run.message(), "kept "+b.esConfig+" as written, with the user binding") {
			t.Fatalf("allow whose ES client CA restore fails\n%s", run)
		}
		if !bindsUserAlone(t, b.esConfig, b.userCASHA256()) || strings.Contains(string(mustReadUserIdentityFile(t, b.agsConfig)), "namespace_issuers") {
			t.Fatal("want es.json kept with its binding and ags.json rolled back")
		}
		b.requireNoTrustWithoutBinding("after an allow whose rollback could not restore the ES client CA file")
	})
}

// TestUserIdentityReportEscapesCSRText puts a newline and terminal escape
// sequences in a CSR's subject: the text report shows them escaped, so the
// requester cannot add or erase report lines (shadow audit A70-3).
func TestUserIdentityReportEscapesCSRText(t *testing.T) {
	requireUserIdentityOpenSSL3(t)
	b := newUserIdentityBox(t)
	b.mustOK(b.box("init-ca", "--apply"), "init-ca")
	key, err := ecdsaP256Key()
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "claude\n\x1b[2KResult: ok - forged\u202e"}}, key)
	if err != nil {
		t.Fatal(err)
	}
	csr := filepath.Join(b.root, "odd.csr")
	writeUserIdentityFile(t, csr, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), 0o644)
	run := b.runWith("/usr/bin/python3", "issue", "--name", "claude", "--csr", csr, "--out", filepath.Join(b.root, "odd.crt"), "--apply")
	if run.code != 1 || !strings.Contains(run.stdout, `CN=claude\x0a\x1b[2KResult: ok - forged\u202e, want exactly CN=claude`) {
		t.Fatalf("issue of a CSR with control characters in its subject\n%s", run)
	}
	lines := strings.Split(strings.TrimSuffix(run.stdout, "\n"), "\n")
	if strings.ContainsAny(run.stdout, "\x1b\u202e") || !strings.HasPrefix(lines[len(lines)-1], "Result: refused - ") {
		t.Fatalf("the text report carries raw control characters or a forged last line\n%q", run.stdout)
	}
	for _, line := range lines {
		if strings.HasPrefix(line, "Result: ok") {
			t.Fatalf("the CSR added a line to the report\n%q", run.stdout)
		}
	}
}

// TestUserIdentityIssueRefusesASecondEncodingOfAKey hands issue CSRs whose
// key is in a second encoding: an EC key as a compressed or a hybrid point
// (red-team RT70b-5), an RSA key with a redundant leading byte in an
// integer. The same key in another encoding would pass the key-reuse check,
// and Go, so AGS and ES, cannot read such a certificate.
func TestUserIdentityIssueRefusesASecondEncodingOfAKey(t *testing.T) {
	requireUserIdentityOpenSSL3(t)
	b := newUserIdentityBox(t)
	b.mustOK(b.box("init-ca", "--apply"), "init-ca")
	key, err := ecdsaP256Key()
	if err != nil {
		t.Fatal(err)
	}
	ecdh, err := key.PublicKey.ECDH()
	if err != nil {
		t.Fatal(err)
	}
	uncompressed := ecdh.Bytes()
	compressed := append([]byte{0x02 | uncompressed[64]&1}, uncompressed[1:33]...)
	hybrid := append([]byte{0x06 | uncompressed[64]&1}, uncompressed[1:]...)
	csrFor := func(point []byte) []byte {
		curve, _ := asn1.Marshal(asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7})
		subject, _ := asn1.Marshal(pkix.Name{CommonName: "claude"}.ToRDNSequence())
		info, err := asn1.Marshal(struct {
			Version   int
			Subject   asn1.RawValue
			PublicKey struct {
				Algorithm pkix.AlgorithmIdentifier
				Key       asn1.BitString
			}
			Attributes []asn1.RawValue `asn1:"tag:0"`
		}{
			Subject: asn1.RawValue{FullBytes: subject},
			PublicKey: struct {
				Algorithm pkix.AlgorithmIdentifier
				Key       asn1.BitString
			}{pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}, Parameters: asn1.RawValue{FullBytes: curve}},
				asn1.BitString{Bytes: point, BitLength: 8 * len(point)}},
			Attributes: []asn1.RawValue{},
		})
		if err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(info)
		sig, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
		if err != nil {
			t.Fatal(err)
		}
		der, err := asn1.Marshal(struct {
			Info      asn1.RawValue
			Algorithm pkix.AlgorithmIdentifier
			Signature asn1.BitString
		}{asn1.RawValue{FullBytes: info}, pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}},
			asn1.BitString{Bytes: sig, BitLength: 8 * len(sig)}})
		if err != nil {
			t.Fatal(err)
		}
		return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
	}
	for i, tc := range []struct {
		name  string
		point []byte
		want  string
	}{
		{"compressed", compressed, "not an uncompressed point"},
		{"hybrid", hybrid, "not an uncompressed point"},
		{"uncompressed", uncompressed, ""},
	} {
		csr := filepath.Join(b.root, fmt.Sprintf("ec%d.csr", i))
		out := filepath.Join(b.root, fmt.Sprintf("ec%d.crt", i))
		writeUserIdentityFile(t, csr, csrFor(tc.point), 0o644)
		before := b.snapshot()
		run := b.box("issue", "--name", "claude", "--csr", csr, "--out", out, "--apply")
		if tc.want == "" {
			b.mustOK(run, "issue with the uncompressed point")
			if _, err := x509.ParseCertificate(parseUserIdentityPEMCert(t, mustReadUserIdentityFile(t, out)).Raw); err != nil {
				t.Fatalf("Go cannot parse the issued certificate: %v", err)
			}
			continue
		}
		if run.code != 1 || run.result() != "refused" || !strings.Contains(run.message(), tc.want) {
			t.Fatalf("%s point: want refused with %q\n%s", tc.name, tc.want, run)
		}
		requireSameUserIdentitySnapshot(t, before, b.snapshot(), "a refused issue")
	}

	rb := newUserIdentityBox(t)
	rb.mustOK(rb.box("init-ca", "--apply"), "init-ca")
	rsaKey, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		t.Fatal(err)
	}
	modulus := append([]byte{0x00}, rsaKey.N.Bytes()...) // N's top bit is set
	exponent := big.NewInt(int64(rsaKey.E)).Bytes()
	rsaCSRFor := func(modulus, exponent []byte) []byte {
		key, err := asn1.Marshal(struct{ N, E asn1.RawValue }{
			asn1.RawValue{Tag: asn1.TagInteger, Bytes: modulus}, asn1.RawValue{Tag: asn1.TagInteger, Bytes: exponent}})
		if err != nil {
			t.Fatal(err)
		}
		subject, _ := asn1.Marshal(pkix.Name{CommonName: "claude"}.ToRDNSequence())
		null := asn1.RawValue{FullBytes: []byte{0x05, 0x00}}
		info, err := asn1.Marshal(struct {
			Version   int
			Subject   asn1.RawValue
			PublicKey struct {
				Algorithm pkix.AlgorithmIdentifier
				Key       asn1.BitString
			}
			Attributes []asn1.RawValue `asn1:"tag:0"`
		}{
			Subject: asn1.RawValue{FullBytes: subject},
			PublicKey: struct {
				Algorithm pkix.AlgorithmIdentifier
				Key       asn1.BitString
			}{pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}, Parameters: null},
				asn1.BitString{Bytes: key, BitLength: 8 * len(key)}},
			Attributes: []asn1.RawValue{},
		})
		if err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(info)
		sig, err := rsa.SignPKCS1v15(rand.Reader, rsaKey, crypto.SHA256, digest[:])
		if err != nil {
			t.Fatal(err)
		}
		der, err := asn1.Marshal(struct {
			Info      asn1.RawValue
			Algorithm pkix.AlgorithmIdentifier
			Signature asn1.BitString
		}{asn1.RawValue{FullBytes: info}, pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}, Parameters: null},
			asn1.BitString{Bytes: sig, BitLength: 8 * len(sig)}})
		if err != nil {
			t.Fatal(err)
		}
		return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
	}
	for i, tc := range []struct {
		name              string
		modulus, exponent []byte
		want              string
	}{
		{"modulus with a redundant zero byte", append([]byte{0x00}, modulus...), exponent, "not minimally encoded"},
		{"exponent with a redundant zero byte", modulus, append([]byte{0x00}, exponent...), "not minimally encoded"},
		// A redundant 0xff makes the integer negative, which is refused
		// before its encoding is looked at.
		{"modulus with a redundant sign byte", append([]byte{0xff}, modulus[1:]...), exponent, "bad RSA public key"},
		{"minimal integers", modulus, exponent, ""},
	} {
		csr := filepath.Join(rb.root, fmt.Sprintf("rsa%d.csr", i))
		out := filepath.Join(rb.root, fmt.Sprintf("rsa%d.crt", i))
		writeUserIdentityFile(t, csr, rsaCSRFor(tc.modulus, tc.exponent), 0o644)
		before := rb.snapshot()
		run := rb.box("issue", "--name", "claude", "--csr", csr, "--out", out, "--apply")
		if tc.want == "" {
			rb.mustOK(run, "issue with minimal RSA integers")
			if _, err := x509.ParseCertificate(parseUserIdentityPEMCert(t, mustReadUserIdentityFile(t, out)).Raw); err != nil {
				t.Fatalf("Go cannot parse the issued certificate: %v", err)
			}
			continue
		}
		if run.code != 1 || run.result() != "refused" || !strings.Contains(run.message(), tc.want) {
			t.Fatalf("RSA %s: want refused with %q\n%s", tc.name, tc.want, run)
		}
		requireSameUserIdentitySnapshot(t, before, rb.snapshot(), "a refused issue")
	}
}

// TestUserIdentityRevokeGoesOnWithADriftedCAKeyMode opens the CA key file to
// others, as a leak might: revoke, which needs no key, still revokes and
// says the key needs attention; allow still refuses.
func TestUserIdentityRevokeGoesOnWithADriftedCAKeyMode(t *testing.T) {
	requireUserIdentityOpenSSL3(t)
	b := newUserIdentityBox(t)
	b.mint("claude")
	b.mint("alice")
	b.mustOK(b.box("allow", "--name", "claude", "--apply"), "allow")
	if err := os.Chmod(filepath.Join(b.userCADir, "ca-key.pem"), 0o644); err != nil {
		t.Fatal(err)
	}
	run := b.box("revoke", "--name", "claude", "--apply")
	if run.code != 1 || run.result() != "attention" || !strings.Contains(run.message(), "can no longer call the AGS or ES API") ||
		!strings.Contains(run.message(), "must be owned by UID") || !strings.Contains(run.message(), "init-ca --replace") {
		t.Fatalf("revoke with the CA key open to others\n%s", run)
	}
	var report struct {
		Checks []struct{ Name, State, Detail string } `json:"checks"`
	}
	if err := json.Unmarshal([]byte(run.stdout), &report); err != nil {
		t.Fatal(err)
	}
	keyCheck := false
	for _, c := range report.Checks {
		keyCheck = keyCheck || (c.Name == "user CA key" && c.State == "attention" && strings.Contains(c.Detail, "revoke goes on"))
	}
	if !keyCheck {
		t.Fatalf("revoke does not list the CA key file as a check needing attention\n%s", run)
	}
	if b.registryState("claude") != "revoked" {
		t.Fatal("revoke did not record the revocation")
	}
	for _, path := range []string{b.agsConfig, b.esConfig} {
		if strings.Contains(string(mustReadUserIdentityFile(t, path)), `"user/claude"`) {
			t.Fatalf("revoke left user/claude in %s", path)
		}
	}
	if run := b.box("allow", "--name", "alice", "--apply"); run.result() != "refused" || !strings.Contains(run.message(), "must be owned by UID") {
		t.Fatalf("allow with the CA key open to others: %s", run)
	}
}

// userIdentityRunbookCut is the command that step (3) of the runbook's
// "Revoke by hand" gives for cutting a user CA from the end of a client CA
// file, as the runbook prints it, with the file and the CA certificate set.
func userIdentityRunbookCut(t *testing.T, file, caCert string) string {
	t.Helper()
	runbook := string(mustReadUserIdentityFile(t, filepath.Join(executionSubstrateRepoRoot, ".runbooks", "system",
		"Governed Execution ES Remote Alpha User Identity.md")))
	const lead = "(3) only to remove the user CA as well, first cut it from the end of both client CA files with `"
	start := strings.Index(runbook, lead)
	if start < 0 {
		t.Fatalf("the runbook's \"Revoke by hand\" has no step (3) starting %q", lead)
	}
	cut := runbook[start+len(lead):]
	cut = cut[:strings.Index(cut, "`")]
	const vars = "f=<client CA file>; ca=/etc/execution-substrate/user-ca/ca-cert.pem; "
	if !strings.HasPrefix(cut, vars) {
		t.Fatalf("step (3) of \"Revoke by hand\" no longer starts with %q: %q", vars, cut)
	}
	return "f=" + userIdentityShellQuote(file) + "; ca=" + userIdentityShellQuote(caCert) + "; " + strings.TrimPrefix(cut, vars)
}

func userIdentityShellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// handEditUserIdentityConfig edits a config's JSON as the box owner would by
// hand, keeping its mode.
func handEditUserIdentityConfig(t *testing.T, path string, change func(doc map[string]any)) {
	t.Helper()
	editUserIdentityFile(t, path, func(text string) string {
		var doc map[string]any
		if err := json.Unmarshal([]byte(text), &doc); err != nil {
			t.Fatal(err)
		}
		change(doc)
		data, err := json.MarshalIndent(doc, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		return string(data) + "\n"
	})
}

// handCutUserCA runs the runbook's cut on both client CA files, then deletes
// the user binding from both configs, in the runbook's order.
func (b *userIdentityBox) handCutUserCA(caCert, what string) {
	b.t.Helper()
	for _, file := range []string{b.agsCA, b.esCA} {
		cmd := exec.Command("/bin/bash", "-c", "set -euo pipefail\n"+userIdentityRunbookCut(b.t, file, caCert))
		cmd.Dir = b.root
		cmd.Env = []string{"PATH=/usr/bin:/bin"}
		if out, err := cmd.CombinedOutput(); err != nil {
			b.t.Fatalf("%s: the runbook's cut of %s from %s: %v\n%s", what, caCert, file, err, out)
		}
		if bytes.Contains(mustReadUserIdentityFile(b.t, file), mustReadUserIdentityFile(b.t, caCert)) {
			b.t.Fatalf("%s: %s still holds %s after the runbook's cut", what, file, caCert)
		}
	}
	for _, path := range []string{b.agsConfig, b.esConfig} {
		handEditUserIdentityConfig(b.t, path, func(doc map[string]any) {
			security := doc["security"].(map[string]any)
			var kept []any
			for _, pair := range security["namespace_issuers"].([]any) {
				if pair.(map[string]any)["path_prefix"] != "user" {
					kept = append(kept, pair)
				}
			}
			if len(kept) == 0 {
				delete(security, "namespace_issuers")
			} else {
				security["namespace_issuers"] = kept
			}
		})
	}
}

// TestUserIdentityHandRemovalFollowsTheRunbook follows the runbook's hand
// procedures with the commands it prints: "Revoke by hand", after which the
// helper's revoke records the revocation and finds the files done, and the
// removal of an older user CA that a rollback of the service files put back.
// A rollback that puts back the retired user CA needs no hand step: revoke
// finishes its removal.
func TestUserIdentityHandRemovalFollowsTheRunbook(t *testing.T) {
	requireUserIdentityOpenSSL3(t)
	t.Run("the retired user CA put back by a rollback", func(t *testing.T) {
		t.Parallel()
		b := newUserIdentityBox(t)
		b.mint("claude")
		b.mustOK(b.box("allow", "--name", "claude", "--apply"), "allow")
		saved := map[string][]byte{}
		for _, path := range []string{b.agsConfig, b.esConfig, b.agsCA, b.esCA} {
			saved[path] = mustReadUserIdentityFile(t, path)
		}
		b.mustOK(b.box("revoke", "--name", "claude", "--remove-ca", "--apply"), "revoke --remove-ca")
		for path, data := range saved {
			editUserIdentityFile(t, path, func(string) string { return string(data) })
		}
		if s := b.box("status"); s.result() != "attention" || !strings.Contains(s.stdout, "the retired user CA is still in") || !strings.Contains(s.stdout, "not an active registry name") {
			t.Fatalf("status after the rollback: want the retired user CA and user/claude named\n%s", s)
		}
		b.mustOK(b.box("revoke", "--name", "claude", "--apply"), "revoke after the rollback")
		b.requireUserCAGone("after revoke")
		if s := b.box("status"); s.result() != "ok" {
			t.Fatalf("status after the rollback and revoke: %s", s)
		}
	})
	t.Run("revoke by hand, then revoke --remove-ca", func(t *testing.T) {
		t.Parallel()
		b := newUserIdentityBox(t)
		b.mint("claude")
		b.mustOK(b.box("allow", "--name", "claude", "--apply"), "allow")
		for _, path := range []string{b.agsConfig, b.esConfig} {
			handEditUserIdentityConfig(t, path, func(doc map[string]any) {
				authz := doc["authorization"].(map[string]any)
				var kept []any
				for _, p := range authz["allowed_spiffe_path_prefixes"].([]any) {
					if strings.Trim(p.(string), "/") != "user/claude" {
						kept = append(kept, p)
					}
				}
				authz["allowed_spiffe_path_prefixes"] = kept
			})
		}
		b.handCutUserCA(filepath.Join(b.userCADir, "ca-cert.pem"), "revoke by hand")
		b.requireUserCAGone("after revoke by hand")
		run := b.box("revoke", "--name", "claude", "--remove-ca", "--apply")
		if run.result() != "ok" || b.registryState("claude") != "revoked" {
			t.Fatalf("revoke --remove-ca after revoke by hand: want ok and claude revoked\n%s", run)
		}
		if s := b.box("status"); s.result() != "ok" {
			t.Fatalf("status after revoke by hand and revoke --remove-ca: %s", s)
		}
	})
	t.Run("an older user CA put back by a rollback", func(t *testing.T) {
		t.Parallel()
		b := newUserIdentityBox(t)
		b.mint("claude")
		b.mustOK(b.box("allow", "--name", "claude", "--apply"), "allow")
		oldSHA := b.userCASHA256()
		saved := map[string][]byte{}
		for _, path := range []string{b.agsConfig, b.esConfig, b.agsCA, b.esCA} {
			saved[path] = mustReadUserIdentityFile(t, path)
		}
		b.mustOK(b.box("revoke", "--name", "claude", "--remove-ca", "--apply"), "revoke --remove-ca")
		b.mustOK(b.box("init-ca", "--replace", "--apply"), "init-ca --replace")
		// The recovery runbook's rollback puts back the service files and
		// leaves user-ca/ as it is.
		for path, data := range saved {
			editUserIdentityFile(t, path, func(string) string { return string(data) })
		}
		if s := b.box("status"); s.result() != "attention" || !strings.Contains(s.stdout, "older user CA") || !strings.Contains(s.stdout, "not an active registry name") {
			t.Fatalf("status after the rollback: want the older user CA and user/claude named\n%s", s)
		}
		if run := b.box("revoke", "--name", "claude", "--apply"); run.result() != "attention" || !strings.Contains(run.message(), "another user CA") {
			t.Fatalf("revoke after the rollback: want attention naming the older user CA\n%s", run)
		}
		b.handCutUserCA(filepath.Join(b.userCADir, "retired", oldSHA+".pem"), "removal of the older user CA")
		b.mint("alice")
		b.mustOK(b.box("allow", "--name", "alice", "--apply"), "allow after the removal of the older user CA")
		b.requireNoTrustWithoutBinding("after allow")
		if s := b.box("status"); s.result() != "ok" {
			t.Fatalf("status after the removal of the older user CA and allow: %s", s)
		}
	})
}
