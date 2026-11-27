package scripts_test

// Tests for the guards of scripts/internal/remote_alpha_user_identity.py:
// what a stop signal leaves behind, the refusals that keep a run from
// changing an unsafe box, the forward-only revoke, the user CA replacement,
// and the checks around the client CA files and the namespace binding. The
// fixture (newUserIdentityBox and its helpers) is in
// remote_alpha_user_identity_test.go.

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
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
		{"--remove-ca while only one client CA file holds the user CA", func(t *testing.T, b *userIdentityBox) []string {
			allowed(t, b)
			writeUserIdentityFile(t, b.esCA, b.extCAPEM, 0o640)
			return []string{"revoke", "--name", "claude", "--remove-ca", "--apply"}
		}, 1, "only one client CA file holds the user CA"},
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
	b.mustOK(b.box("allow", "--name", "claude", "--apply"), "allow claude")
	b.mustOK(b.box("allow", "--name", "alice", "--apply"), "allow alice")
	const (
		claudeID = "spiffe://execution.internal/user/claude"
		aliceID  = "spiffe://execution.internal/user/alice"
	)
	// The rule shape of ES's admission_policy.workload_grants (ES PR #73).
	rule := func(publisher, caller string) string {
		id := strings.TrimPrefix(publisher, "spiffe://execution.internal/user/") + "-for-" + strings.TrimPrefix(caller, "spiffe://execution.internal/user/")
		return `{"id": "` + id + `", "publisher_principal": "` + publisher + `", "caller_principal": "` + caller +
			`", "signer_key_id": "ags-signing-key-1", "artifact_type": "governed_workload", "runtime_profile": "default", "egress_lane": "unrestricted"}`
	}
	editUserIdentityFile(t, b.esConfig, func(s string) string {
		s = mustReplaceOnce(t, s, `"user/claude"`, `"user/claude", "user/claude"`)
		s = mustReplaceOnce(t, s, "{\n", "{\n  \"admission_policy\": {\"workload_grants\": {\"egress_lanes\": [{\"name\": \"unrestricted\", \"reaches_workload_vault\": true}], \"rules\": ["+
			rule(claudeID, aliceID)+", "+rule(aliceID, claudeID)+", "+rule(aliceID, aliceID)+"]}},\n")
		return s
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
		if strings.Contains(text, `user/claude"`) || strings.Contains(text, claudeID) {
			t.Fatalf("revoke left user/claude in %s:\n%s", path, text)
		}
		if !strings.Contains(text, `"user/alice"`) {
			t.Fatalf("revoke took user/alice out of %s", path)
		}
	}
	var before, after map[string]any
	if err := json.Unmarshal(beforeES, &before); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(mustReadUserIdentityFile(t, b.esConfig), &after); err != nil {
		t.Fatal(err)
	}
	rules := after["admission_policy"].(map[string]any)["workload_grants"].(map[string]any)["rules"].([]any)
	if len(rules) != 1 || rules[0].(map[string]any)["publisher_principal"] != aliceID || rules[0].(map[string]any)["caller_principal"] != aliceID {
		t.Fatalf("rules after revoke: %v, want alice's own rule only", rules)
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
		return mustReplaceOnce(t, s, rule(aliceID, aliceID), rule(aliceID, aliceID)+", "+rule(aliceID, claudeID))
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

	for _, keyMoved := range []bool{false, true} {
		name := "committed"
		if keyMoved {
			name = "committed with the key already moved"
		}
		keyMoved := keyMoved
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
			if keyMoved {
				if err := os.Rename(filepath.Join(next, "ca-key.pem"), filepath.Join(b.userCADir, "ca-key.pem")); err != nil {
					t.Fatal(err)
				}
			}
			requireBlocked(t, b)
			run = b.mustOK(b.box("init-ca", "--replace", "--apply"), "init-ca --replace to finish")
			if !strings.Contains(run.message(), "replacement is finished") || b.userCASHA256() != newSHA {
				t.Fatalf("finishing the replacement:\n%s", run)
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
