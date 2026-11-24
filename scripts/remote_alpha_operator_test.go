package scripts_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"testing"
	"time"
)

func remoteAlphaOperatorScriptPath() string {
	return filepath.Join(remoteAlphaOperatorRepoRoot(), "scripts", "remote_alpha_operator.sh")
}

func runRemoteAlphaOperator(args ...string) (string, error) {
	scriptPath := remoteAlphaOperatorScriptPath()
	cmd := exec.Command("/bin/bash", append([]string{scriptPath}, args...)...)
	cmd.Dir = remoteAlphaOperatorRepoRoot()
	output, err := cmd.CombinedOutput()
	return string(output), err
}

func runRemoteAlphaOperatorWithEnv(env []string, args ...string) (string, error) {
	scriptPath := remoteAlphaOperatorScriptPath()
	cmd := exec.Command("/bin/bash", append([]string{scriptPath}, args...)...)
	cmd.Dir = remoteAlphaOperatorRepoRoot()
	cmd.Env = env
	output, err := cmd.CombinedOutput()
	return string(output), err
}

func runRemoteAlphaOperatorSeparated(env []string, args ...string) (string, string, error) {
	scriptPath := remoteAlphaOperatorScriptPath()
	cmd := exec.Command("/bin/bash", append([]string{scriptPath}, args...)...)
	cmd.Dir = remoteAlphaOperatorRepoRoot()
	if env != nil {
		cmd.Env = env
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	return stdout.String(), stderr.String(), err
}

func runRemoteAlphaOperatorWithEffectTrap(t *testing.T, args ...string) (string, string, error) {
	t.Helper()
	root := t.TempDir()
	shimDir := filepath.Join(root, "effect-shims")
	if err := os.Mkdir(shimDir, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"ssh", "scp", "sudo", "mktemp", "python3", "dirname", "cp", "rm", "chmod", "install", "tee", "curl", "bash"} {
		writeExecutable(t, shimDir, name, "#!/bin/sh\nprintf 'effect\\n' >> \"$ES_OPERATOR_EFFECT_SENTINEL\"\nexit 97\n")
	}
	sentinel := filepath.Join(root, "effect-sentinel")
	env := remoteAlphaOperatorTestEnv(
		"PATH="+shimDir+":/usr/bin:/bin",
		"HOME="+root,
		"TMPDIR="+root,
		"ES_OPERATOR_EFFECT_SENTINEL="+sentinel,
	)
	stdout, stderr, err := runRemoteAlphaOperatorSeparated(env, args...)
	if _, statErr := os.Lstat(sentinel); !os.IsNotExist(statErr) {
		t.Fatalf("operator invoked an effectful helper: %v", statErr)
	}
	return stdout, stderr, err
}

type remoteAlphaPrivacyRun struct {
	stdout   string
	stderr   string
	err      error
	timedOut bool
	elapsed  time.Duration
}

func remoteAlphaPrivacyRunner(t *testing.T) func(string, time.Duration, ...string) remoteAlphaPrivacyRun {
	t.Helper()
	root := t.TempDir()
	shimDir := filepath.Join(root, "effect-shims")
	if err := os.Mkdir(shimDir, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"ssh", "scp", "sudo", "mktemp", "python3", "dirname", "cp", "rm", "chmod", "install", "tee", "curl", "bash"} {
		writeExecutable(t, shimDir, name, "#!/bin/sh\nprintf 'effect\\n' >> \"$ES_OPERATOR_EFFECT_SENTINEL\"\nexit 97\n")
	}
	sentinel := filepath.Join(root, "effect-sentinel")
	return func(locale string, limit time.Duration, args ...string) remoteAlphaPrivacyRun {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), limit)
		defer cancel()
		scriptPath := remoteAlphaOperatorScriptPath()
		if openingScript := os.Getenv("ES_REMOTE_ALPHA_PRIVACY_TEST_SCRIPT"); openingScript != "" {
			scriptPath = openingScript
		}
		cmd := exec.CommandContext(ctx, "/bin/bash", append([]string{scriptPath}, args...)...)
		cmd.Dir = remoteAlphaOperatorRepoRoot()
		cmd.Env = remoteAlphaOperatorTestEnv(
			"LC_ALL="+locale,
			"PATH="+shimDir+":/usr/bin:/bin",
			"HOME="+root,
			"TMPDIR="+root,
			"ES_OPERATOR_EFFECT_SENTINEL="+sentinel,
		)
		var stdout, stderr bytes.Buffer
		cmd.Stdout, cmd.Stderr = &stdout, &stderr
		start := time.Now()
		err := cmd.Run()
		elapsed := time.Since(start)
		if _, statErr := os.Lstat(sentinel); !os.IsNotExist(statErr) {
			t.Fatalf("privacy runner invoked an effectful helper: %v", statErr)
		}
		return remoteAlphaPrivacyRun{stdout.String(), stderr.String(), err, ctx.Err() == context.DeadlineExceeded, elapsed}
	}
}

func remoteAlphaPrintValueArgs(surface, value string) []string {
	if surface == "recovery-session --next-steps" {
		if strings.HasPrefix(value, "--") {
			value = "ordinary" + value
		}
		return []string{"recovery-session", "--next-steps", "--im-profile-dir", value}
	}
	return []string{surface, "--profile-dir", value}
}

func assertRemoteAlphaPrivacyRefusal(t *testing.T, result remoteAlphaPrivacyRun, marker string) {
	t.Helper()
	const refusal = "error: secret material must never be passed by CLI args/env/logs/reports/artifacts\n"
	exit, ok := result.err.(*exec.ExitError)
	if result.timedOut || !ok || exit.ExitCode() != 2 || result.stdout != "" || result.stderr != refusal ||
		strings.Contains(result.stdout, marker) || strings.Contains(result.stderr, marker) {
		t.Fatal("secret-like token did not receive exact effect-free privacy refusal")
	}
}

func remoteAlphaOperatorTestEnv(overrides ...string) []string {
	keys := make(map[string]struct{}, len(overrides))
	for _, override := range overrides {
		key, _, found := strings.Cut(override, "=")
		if found {
			keys[key] = struct{}{}
		}
	}
	env := make([]string, 0, len(os.Environ())+len(overrides))
	for _, entry := range os.Environ() {
		key, _, found := strings.Cut(entry, "=")
		if found {
			if _, replaced := keys[key]; replaced {
				continue
			}
		}
		env = append(env, entry)
	}
	return append(env, overrides...)
}

func runRemoteAlphaOperatorWithPTY(t *testing.T, env []string, args ...string) (string, error) {
	t.Helper()
	return runRemoteAlphaOperatorWithPTYPath(t, remoteAlphaOperatorScriptPath(), env, args...)
}

func runRemoteAlphaOperatorWithPTYPath(t *testing.T, scriptPath string, env []string, args ...string) (string, error) {
	t.Helper()
	python := `
import os
import pty
import subprocess
import sys

repo_root = os.environ["ES_REPO_ROOT"]
cmd = sys.argv[1:]
master_fd, slave_fd = pty.openpty()
proc = subprocess.Popen(cmd, cwd=repo_root, stdin=slave_fd, stdout=slave_fd, stderr=slave_fd)
os.close(slave_fd)
chunks = []
while True:
    try:
        data = os.read(master_fd, 4096)
    except OSError:
        break
    if not data:
        break
    chunks.append(data)
os.close(master_fd)
status = proc.wait()
sys.stdout.buffer.write(b"".join(chunks))
sys.exit(status)
`
	commandArgs := append([]string{"-c", python, "/bin/bash", scriptPath}, args...)
	cmd := exec.Command("python3", commandArgs...)
	cmd.Dir = remoteAlphaOperatorRepoRoot()
	cmd.Env = append(env, "ES_REPO_ROOT="+remoteAlphaOperatorRepoRoot())
	output, err := cmd.CombinedOutput()
	return string(output), err
}

func runRemoteAlphaOperatorWithPromptPTY(t *testing.T, env []string, args ...string) (string, error) {
	t.Helper()
	python := `
import os
import pty
import secrets
import select
import signal
import subprocess
import sys
import termios
import time

master, slave = pty.openpty()
settings = termios.tcgetattr(slave)
settings[3] &= ~termios.ECHO
termios.tcsetattr(slave, termios.TCSANOW, settings)
sentinel = secrets.token_hex(16).encode("ascii")
proc = subprocess.Popen(sys.argv[1:], cwd=os.environ["ES_REPO_ROOT"],
                        stdin=slave, stdout=slave, stderr=slave, start_new_session=True)
os.close(slave)
output = bytearray()
sent = False
deadline = time.monotonic() + 12
try:
    while True:
        if time.monotonic() >= deadline:
            raise TimeoutError("bounded prompt fixture timed out")
        ready, _, _ = select.select([master], [], [], 0.2)
        if ready:
            try:
                chunk = os.read(master, 4096)
            except OSError:
                break
            if not chunk:
                break
            output.extend(chunk)
            if len(output) > 131072:
                raise RuntimeError("bounded prompt fixture output exceeded limit")
            if not sent and b"FAKE_SUDO_PASSWORD_PROMPT: " in output:
                response = b"\x04" if os.environ.get("FAKE_STATUS_PROMPT_MODE") == "eof" else sentinel + b"\n"
                os.write(master, response)
                sent = True
        elif proc.poll() is not None:
            break
    status = proc.wait(timeout=1)
finally:
    if proc.poll() is None:
        os.killpg(proc.pid, signal.SIGKILL)
        proc.wait()
    os.close(master)
if sentinel in output:
    raise RuntimeError("fixture response appeared in terminal output")
for name in ("FAKE_STATUS_SSH_ARGV", "FAKE_STATUS_SSH_LOG", "FAKE_STATUS_SCP_LOG"):
    path = os.environ[name]
    if os.path.exists(path) and sentinel in open(path, "rb").read():
        raise RuntimeError("fixture response appeared in transport evidence")
sys.stdout.buffer.write(output)
sys.exit(status)
`
	commandArgs := append([]string{"-I", "-B", "-c", python, "/bin/bash", remoteAlphaOperatorScriptPath()}, args...)
	cmd := exec.Command("/usr/bin/python3", commandArgs...)
	cmd.Dir = executionSubstrateRepoRoot
	cmd.Env = append(env, "ES_REPO_ROOT="+executionSubstrateRepoRoot)
	output, err := cmd.CombinedOutput()
	return string(output), err
}

func requireRemoteAlphaOperatorSuccess(t *testing.T, args ...string) string {
	t.Helper()
	output, err := runRemoteAlphaOperator(args...)
	if err != nil {
		t.Fatalf("remote_alpha_operator.sh %v failed: %v\n%s", args, err, output)
	}
	return output
}

func requireRemoteAlphaOperatorFailure(t *testing.T, args ...string) string {
	t.Helper()
	output, err := runRemoteAlphaOperator(args...)
	if err == nil {
		t.Fatalf("remote_alpha_operator.sh %v unexpectedly succeeded:\n%s", args, output)
	}
	return output
}

func assertRemoteAlphaOperatorUnsafeRefusal(t *testing.T, label, output string, args []string, legacyRequired []string) {
	t.Helper()
	fixedMarkers := []string{
		"received a forbidden option category",
		"received a forbidden helper-override category",
		"received a forbidden secret-value category",
		"accepts only fixed documented bootstrap values",
		"proof secret values must never be passed",
		"received an unknown option",
		"received an unexpected positional argument",
		"does not accept equals-form options",
		"secret material must never be passed by CLI args/env/logs/reports/artifacts",
	}
	for _, marker := range fixedMarkers {
		if !strings.Contains(output, marker) {
			continue
		}
		assertContainsAll(t, label, output, marker)
		if !strings.Contains(output, "secret material must never") {
			assertContainsAll(t, label, output, "No recovery-session live helper or IM execution occurred.")
		}
		for _, arg := range args {
			if arg == "unexpected" || arg == "positional" {
				continue
			}
			assertContainsNone(t, label+" non-echo", output, arg)
		}
		return
	}
	assertContainsAll(t, label, output, legacyRequired...)
}

func remoteAlphaOperatorRouteArtifactPaths(extraDirs ...string) []string {
	dirs := append([]string{filepath.Join(".out", "remote-alpha-m75q")}, extraDirs...)
	names := []string{
		"es-writable-state-readiness.json",
		"es-writable-state-readiness-helper-staging-record.json",
	}
	var paths []string
	for _, dir := range dirs {
		paths = append(paths, filepath.Join(remoteAlphaOperatorRepoRoot(), dir))
		for _, name := range names {
			paths = append(paths, filepath.Join(remoteAlphaOperatorRepoRoot(), dir, name))
		}
	}
	return paths
}

func snapshotPathExistence(t *testing.T, paths ...string) map[string]bool {
	t.Helper()
	snapshot := make(map[string]bool, len(paths))
	for _, path := range paths {
		if _, err := os.Stat(path); err == nil {
			snapshot[path] = true
		} else if os.IsNotExist(err) {
			snapshot[path] = false
		} else {
			t.Fatalf("stat %s: %v", path, err)
		}
	}
	return snapshot
}

func assertNoNewPaths(t *testing.T, label string, before map[string]bool) {
	t.Helper()
	for path, existedBefore := range before {
		if existedBefore {
			continue
		}
		if _, err := os.Stat(path); err == nil {
			t.Fatalf("%s created generated artifact path %s", label, path)
		} else if !os.IsNotExist(err) {
			t.Fatalf("stat %s: %v", path, err)
		}
	}
}

func TestRemoteAlphaOperatorHelpAndInventoryExposeRetirementAndPreserveUnrelatedRoutes(t *testing.T) {
	info, err := os.Stat(remoteAlphaOperatorScriptPath())
	if err != nil {
		t.Fatalf("operator script missing: %v", err)
	}
	if info.Mode()&0o111 == 0 {
		t.Fatalf("operator script should remain executable, mode=%v", info.Mode())
	}

	help := requireRemoteAlphaOperatorSuccess(t, "--help")
	inventory := requireRemoteAlphaOperatorSuccess(t, "inventory")
	assertContainsAll(t, "operator help", help,
		"remote_alpha_operator.sh es-writable-state-readiness-check  # retired; fixed exit 2",
		"remote_alpha_operator.sh readiness-session  # retired; fixed exit 2",
		"es-writable-state-readiness-check - retired fixed exit-2 route; no host inspection, staging, mutation, or evidence production",
		"readiness-session - retired fixed exit-2 workflow; no current readiness projection or artifact refresh",
		"recovery-session operator-healthcheck-tls-status",
		"recovery-session es-service-tls-status",
		"recovery-session es-governance-tls-status",
		"Operator ingestion, staging, aggregation, discovery, and projection compatibility for the retired evidence families is unavailable",
	)
	assertContainsAll(t, "operator inventory", inventory,
		"es-writable-state-readiness-check - retired; fixed exit 2 and no effects",
		"readiness-session - retired; fixed exit 2 and no effects",
		"archived readiness artifacts are historical evidence only and are never refreshed by this facade",
		"operator-healthcheck-tls-status-noninteractive",
		"es-service-tls-renew",
		"es-governance-tls-renew",
		"optional owner-local proof emitter under its separate contract; no operator-facade reachability",
	)
	assertContainsNone(t, "retired operator presentations", help+"\n"+inventory,
		"delegates to existing readiness staged helper",
		"readiness artifacts remain delegated helper evidence",
		"--evidence-check",
		"--evidence-dir",
		"--strict-known-schema",
		"recovery-session vault-workload-auth-check",
		"recovery-session runtime-identity-summary",
		"vault-workload-auth-summary.json",
		"runtime-identity-helper-summary.json",
	)
}

func TestRemoteAlphaOperatorP0tDiagnosticStaticListings(t *testing.T) {
	const verifyOnly = "  remote_alpha_operator.sh recovery-session es-governance-tls-grammar-diagnostic --verify-only\n"
	const live = "  remote_alpha_operator.sh recovery-session es-governance-tls-grammar-diagnostic --ssh-target <user@host> --interactive-tty\n"
	tests := []struct {
		name string
		args []string
		line string
	}{
		{"top_inventory", []string{"inventory"}, "  recovery-session es-governance-tls-grammar-diagnostic --verify-only or --ssh-target <target> --interactive-tty - separate bounded P0t first-rejection diagnostic; no status publication, renewal, repair, or restoration.\n"},
		{"recovery_plan", []string{"recovery-session", "--plan"}, "  es-governance-tls-grammar-diagnostic --verify-only or --ssh-target <target> --interactive-tty - separate bounded first-rejection diagnostic; no status publication, renewal, repair, or restoration.\n"},
		{"recovery_inventory", []string{"recovery-session", "--inventory"}, "  recovery-session es-governance-tls-grammar-diagnostic --verify-only or --ssh-target <target> --interactive-tty - separate P0t grammar localization; stages one collector in live mode, emits at most one closed terminal line, and publishes no status summary.\n"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			stdout, stderr, err := runRemoteAlphaOperatorWithEffectTrap(t, tc.args...)
			if err != nil || stderr != "" {
				t.Fatalf("static listing failed: exit=%v stderr=%q", err, stderr)
			}
			if strings.Count(stdout, tc.line) != 1 {
				t.Fatal("official P0t diagnostic listing is missing or duplicated")
			}
		})
	}
	for _, tc := range []struct {
		name string
		args []string
	}{
		{"top_help_control", []string{"--help"}},
		{"recovery_help_control", []string{"recovery-session", "--help"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stdout, stderr, err := runRemoteAlphaOperatorWithEffectTrap(t, tc.args...)
			if err != nil || stderr != "" {
				t.Fatalf("static help failed: exit=%v stderr=%q", err, stderr)
			}
			if strings.Count(stdout, verifyOnly) != 1 || strings.Count(stdout, live) != 1 {
				t.Fatal("official P0t diagnostic help forms are missing or duplicated")
			}
		})
	}
}

func TestRemoteAlphaProductionSchemasAndFixturesHaveNoRetiredESMigrationV2ProtocolSurface(t *testing.T) {
	repoRoot := remoteAlphaOperatorRepoRoot()
	identifier := regexp.MustCompile(`(?i)execution-substrate\.remote-alpha\.(?:es-writable-state(?:[._-][a-z0-9_-]+)*|es-service-user(?:[._-][a-z0-9_-]+)*)\.v2\b`)
	roots := []struct {
		relativePath       string
		kind               string
		missingIsPermitted bool
	}{
		{relativePath: "es", kind: "production-go"},
		{relativePath: filepath.Join("cmd", "es"), kind: "production-go", missingIsPermitted: true},
		{relativePath: "scripts", kind: "producer"},
		{relativePath: "schemas", kind: "artifact", missingIsPermitted: true},
		{relativePath: "testdata", kind: "artifact", missingIsPermitted: true},
		{relativePath: "fixtures", kind: "artifact", missingIsPermitted: true},
	}
	for _, root := range roots {
		absoluteRoot := filepath.Join(repoRoot, root.relativePath)
		if _, err := os.Stat(absoluteRoot); err != nil {
			if root.missingIsPermitted && os.IsNotExist(err) {
				continue
			}
			t.Fatal(err)
		}
		err := filepath.WalkDir(absoluteRoot, func(path string, entry os.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if entry.IsDir() {
				return nil
			}
			relativePath, err := filepath.Rel(repoRoot, path)
			if err != nil {
				return err
			}
			relativePath = filepath.ToSlash(relativePath)
			lowerRelativePath := strings.ToLower(relativePath)
			remotePath := strings.Contains(lowerRelativePath, "remote_alpha") || strings.Contains(lowerRelativePath, "remote-alpha")
			scanContent := false
			switch root.kind {
			case "production-go":
				scanContent = strings.HasSuffix(relativePath, ".go") && !strings.HasSuffix(relativePath, "_test.go")
			case "producer":
				scanContent = remotePath && (strings.HasSuffix(relativePath, ".sh") || strings.HasSuffix(relativePath, ".py"))
			case "artifact":
				scanContent = true
			default:
				t.Fatalf("unknown v2 scan kind %q", root.kind)
			}
			if !scanContent {
				return nil
			}
			if remotePath && remoteAlphaPathContainsRetiredESMigrationV2(relativePath) {
				t.Fatalf("retired-family Remote Alpha v2 path entered current surfaces: %s", relativePath)
			}
			content, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			matches := identifier.FindAllString(string(content), -1)
			for range matches {
				t.Fatalf("retired-family Remote Alpha v2 schema identifier entered current surface %s", relativePath)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}

func remoteAlphaPathContainsRetiredESMigrationV2(relativePath string) bool {
	lower := strings.ToLower(filepath.ToSlash(relativePath))
	retiredFamily := strings.Contains(lower, "es-writable-state") || strings.Contains(lower, "es_writable_state") ||
		strings.Contains(lower, "es-service-user") || strings.Contains(lower, "es_service_user")
	return retiredFamily && regexp.MustCompile(`(^|[/_.-])v2($|[/_.-])`).MatchString(lower)
}

func TestRemoteAlphaOperatorPrintRefreshCommandIsInert(t *testing.T) {
	output := requireRemoteAlphaOperatorSuccess(t, "print-refresh-command")
	assertContainsAll(t, "print-refresh-command output", output,
		"Mac-side Infrastructure Manager live refresh command",
		"printed only",
		"cd \"/Users/ds/Repositories/Infrastructure Manager\"",
		"PYTHONPATH=src python3 -m infra_manager.cli remote-alpha-live-refresh \\",
		"--profile-dir \".out/remote-alpha-m75q\" \\",
		"--ssh-alias \"host_to_remote_linux_m75q\"",
	)
	assertContainsNone(t, "print-refresh-command output", output,
		"executed",
		"collected",
	)
}

func TestRemoteAlphaOperatorPrintSupportBundleCommandIsInert(t *testing.T) {
	output := requireRemoteAlphaOperatorSuccess(t, "print-support-bundle-command")
	assertContainsAll(t, "print-support-bundle-command output", output,
		"Mac-side Infrastructure Manager support-bundle command",
		"printed only",
		"cd \"/Users/ds/Repositories/Infrastructure Manager\"",
		"PYTHONPATH=src python3 -m infra_manager.cli remote-alpha-live-support-bundle \\",
		"--profile-dir \".out/remote-alpha-m75q\" \\",
		"--output-root \".out/remote-alpha-m75q/support-bundles\"",
	)
	assertContainsNone(t, "print-support-bundle-command output", output,
		"executed",
		"collected",
	)
}

func TestRemoteAlphaOperatorPrintIMCommandsPrintsBothCommands(t *testing.T) {
	output := requireRemoteAlphaOperatorSuccess(t, "print-im-commands")
	assertContainsAll(t, "print-im-commands output", output,
		"Mac-side Infrastructure Manager live refresh command",
		"remote-alpha-live-refresh",
		"--ssh-alias \"host_to_remote_linux_m75q\"",
		"Mac-side Infrastructure Manager support-bundle command",
		"remote-alpha-live-support-bundle",
		"--output-root \".out/remote-alpha-m75q/support-bundles\"",
	)
}

func TestRemoteAlphaOperatorCustomPrintOptionsOnlyAffectPrintedText(t *testing.T) {
	output := requireRemoteAlphaOperatorSuccess(t,
		"print-im-commands",
		"--profile-dir", "custom profiles/alpha",
		"--output-root", "custom bundles/alpha",
		"--ssh-alias", "custom_alias",
	)
	assertContainsAll(t, "custom print-im-commands output", output,
		"--profile-dir \"custom profiles/alpha\"",
		"--output-root \"custom bundles/alpha\"",
		"--ssh-alias \"custom_alias\"",
	)
	assertContainsNone(t, "custom print-im-commands output", output,
		"--profile-dir \".out/remote-alpha-m75q\"",
		"--output-root \".out/remote-alpha-m75q/support-bundles\"",
		"--ssh-alias \"host_to_remote_linux_m75q\"",
	)

	inventory := requireRemoteAlphaOperatorSuccess(t,
		"inventory",
		"--profile-dir", "custom profiles/alpha",
		"--output-root", "custom bundles/alpha",
		"--ssh-alias", "custom_alias",
	)
	assertContainsNone(t, "custom inventory output", inventory,
		"custom profiles/alpha",
		"custom bundles/alpha",
		"custom_alias",
	)
}

func TestRemoteAlphaOperatorRejectsSecretBearingFlagsBeforeNormalOutput(t *testing.T) {
	for _, flag := range []string{
		"--root-token",
		"--unseal-key",
		"--client-token",
		"--vault-token",
		"--api-key",
		"--jwt-svid",
		"--private-key",
		"--password",
		"--secret",
	} {
		t.Run(flag, func(t *testing.T) {
			output := requireRemoteAlphaOperatorFailure(t, "print-refresh-command", flag, "value")
			assertContainsAll(t, "secret flag refusal", output,
				"secret material must never be passed by CLI args/env/logs/reports/artifacts",
			)
			assertContainsNone(t, "secret flag refusal", output,
				"remote-alpha-live-refresh",
				"Remote Alpha operator inventory",
			)
		})
	}

	equalsOutput := requireRemoteAlphaOperatorFailure(t, "--api-key=dummy")
	assertContainsAll(t, "equals-form secret flag refusal", equalsOutput,
		"secret material must never be passed by CLI args/env/logs/reports/artifacts",
	)
	assertContainsNone(t, "equals-form secret flag refusal", equalsOutput,
		"Remote Alpha operator facade",
		"Remote Alpha operator inventory",
		"remote-alpha-live-refresh",
		"remote-alpha-live-support-bundle",
	)

	output := requireRemoteAlphaOperatorFailure(t, "print-refresh-command", "--vault-token-file", "path")
	assertContainsAll(t, "secret-like flag refusal", output,
		"secret material must never be passed by CLI args/env/logs/reports/artifacts",
	)

	for _, args := range [][]string{
		{"--VaUlT_ToKeN=dummy"},
		{"inventory", "--PROOF_SECRET_VALUE", "dummy"},
		{"print-refresh-command", "--JWT_TOKEN_FILE=dummy"},
	} {
		stdout, stderr, err := runRemoteAlphaOperatorSeparated(nil, args...)
		if err == nil {
			t.Fatalf("case/underscore secret option bypassed privacy filter: %v", args)
		}
		if stdout != "" || stderr != "error: secret material must never be passed by CLI args/env/logs/reports/artifacts\n" {
			t.Fatalf("privacy refusal for %v stdout=%q stderr=%q", args, stdout, stderr)
		}
		for _, arg := range args {
			assertContainsNone(t, "privacy refusal non-echo", stderr, arg)
		}
	}

	stdout, stderr, err := runRemoteAlphaOperatorSeparated(nil, "inventory", "--profile-dir", "--vault-token")
	if err == nil || stdout != "" || stderr != "error: secret material must never be passed by CLI args/env/logs/reports/artifacts\n" {
		t.Fatal("secret-shaped option value bypassed the privacy filter")
	}
}

func TestRemoteAlphaOperatorRejectsSecretShapedOptionValueBeforePrint(t *testing.T) {
	const canary = "--api-key=CANARY_ONLY_NON_SECRET"
	const refusal = "error: secret material must never be passed by CLI args/env/logs/reports/artifacts\n"

	t.Run("malformed_profile_value", func(t *testing.T) {
		stdout, stderr, err := runRemoteAlphaOperatorWithEffectTrap(t, "print-refresh-command", "--profile-dir", canary)
		if strings.Contains(stdout, canary) || strings.Contains(stderr, canary) {
			t.Fatal("inert canary was emitted")
		}
		if err == nil || stdout != "" || stderr != refusal {
			t.Fatal("malformed secret-shaped option value did not receive the fixed privacy refusal")
		}
	})

	t.Run("direct_secret_control", func(t *testing.T) {
		stdout, stderr, err := runRemoteAlphaOperatorWithEffectTrap(t, "print-refresh-command", canary)
		if err == nil || stdout != "" || stderr != refusal {
			t.Fatal("direct secret-shaped option did not receive the fixed privacy refusal")
		}
	})

	t.Run("ordinary_profile_value_control", func(t *testing.T) {
		stdout, stderr, err := runRemoteAlphaOperatorWithEffectTrap(t, "print-refresh-command", "--profile-dir", "ordinary-profile")
		if err != nil || stderr != "" || !strings.Contains(stdout, "ordinary-profile") {
			t.Fatal("ordinary profile-directory value was rejected or not printed")
		}
	})
}

func TestRemoteAlphaOperatorRejectsEmbeddedSecretGrammarBeforePrint(t *testing.T) {
	const marker = "CANARY_ONLY_NON_SECRET"
	const refusal = "error: secret material must never be passed by CLI args/env/logs/reports/artifacts\n"

	assertPrivacyRefusal := func(t *testing.T, args ...string) {
		t.Helper()
		stdout, stderr, err := runRemoteAlphaOperatorWithEffectTrap(t, args...)
		if strings.Contains(stdout, marker) || strings.Contains(stderr, marker) {
			t.Fatal("inert marker was emitted")
		}
		exit, ok := err.(*exec.ExitError)
		if !ok || exit.ExitCode() != 2 || stdout != "" || stderr != refusal {
			t.Fatal("secret-like argument did not receive the exact privacy refusal")
		}
	}

	for _, route := range []string{"print-refresh-command", "print-support-bundle-command", "print-im-commands"} {
		for _, shape := range []struct {
			name string
			args []string
		}{
			{"entire_equals_value", []string{"--profile-dir=--api-key=" + marker}},
			{"embedded_separate_value", []string{"--profile-dir", "ordinary--api-key=" + marker}},
			{"embedded_equals_value", []string{"--profile-dir=ordinary--api-key=" + marker}},
		} {
			t.Run(route+"/"+shape.name, func(t *testing.T) {
				assertPrivacyRefusal(t, append([]string{route}, shape.args...)...)
			})
		}
	}

	for _, family := range []string{
		"root-token", "unseal-key", "client-token", "vault-token", "api-key",
		"jwt-svid", "private-key", "password", "secret", "token-file", "secret-value",
	} {
		t.Run("direct_family/"+family, func(t *testing.T) {
			assertPrivacyRefusal(t, "print-refresh-command", "--"+family+"="+marker)
		})
	}

	for _, shape := range []struct {
		name string
		args []string
	}{
		{"expected_value_skip", []string{"print-refresh-command", "--profile-dir", "--api-key=" + marker}},
		{"output_root_skip", []string{"print-support-bundle-command", "--output-root", "--JWT_TOKEN_FILE=" + marker}},
		{"nested_recovery", []string{"recovery-session", "--ssh-target", "--api-key=" + marker}},
		{"double_dash", []string{"print-refresh-command", "--", "--api-key=" + marker}},
		{"uppercase_underscore_alias", []string{"print-refresh-command", "--API_KEY=" + marker}},
		{"prefixed_family_alias", []string{"print-refresh-command", "--operator-api-key=" + marker}},
		{"output_root_entire_equals_value", []string{"print-support-bundle-command", "--output-root=--token-file=" + marker}},
		{"output_root_embedded_separate_value", []string{"print-support-bundle-command", "--output-root", "ordinary--secret-value=" + marker}},
		{"ssh_alias_embedded_equals_value", []string{"print-refresh-command", "--ssh-alias=ordinary--client-token=" + marker}},
		{"embedded_with_space", []string{"print-refresh-command", "--profile-dir", "ordinary --api-key=" + marker}},
	} {
		t.Run(shape.name, func(t *testing.T) {
			assertPrivacyRefusal(t, shape.args...)
		})
	}

	for _, control := range []struct {
		name string
		args []string
		want string
	}{
		{"ordinary_separate", []string{"print-refresh-command", "--profile-dir", "ordinary-profile"}, "ordinary-profile"},
		{"ordinary_equals", []string{"print-refresh-command", "--profile-dir=ordinary-profile"}, "ordinary-profile"},
		{"hyphenated_value", []string{"print-support-bundle-command", "--output-root", "ordinary-report-root"}, "ordinary-report-root"},
		{"equals_value", []string{"print-im-commands", "--profile-dir=ordinary=profile"}, "ordinary=profile"},
		{"api_key_token_words", []string{"print-refresh-command", "--profile-dir", "api-key-token-words"}, "api-key-token-words"},
		{"benign_option_fragment", []string{"print-refresh-command", "--profile-dir", "ordinary--not-sensitive-option"}, "ordinary--not-sensitive-option"},
	} {
		t.Run("ordinary/"+control.name, func(t *testing.T) {
			stdout, stderr, err := runRemoteAlphaOperatorWithEffectTrap(t, control.args...)
			if err != nil || stderr != "" || !strings.Contains(stdout, control.want) {
				t.Fatal("ordinary print-option value was rejected or not printed")
			}
		})
	}
}

func TestRemoteAlphaOperatorByteStableUnicodeDelimiterMatrix(t *testing.T) {
	const marker = "CANARY_ONLY_NON_SECRET"
	run := remoteAlphaPrivacyRunner(t)
	surfaces := []string{"print-refresh-command", "print-support-bundle-command", "print-im-commands", "recovery-session --next-steps"}
	boundaries := []struct{ name, value string }{
		{"nbsp", "\u00a0"}, {"em_space", "\u2003"}, {"line_separator", "\u2028"},
	}
	families := []struct{ name, before string }{
		{"api_key_embedded", "ordinary--api-key"},
		{"root_token_direct", "--root-token"},
		{"jwt_svid_equals_value", "ordinary=--jwt-svid"},
		{"private_key_middle", "ordinary--private-key"},
		{"secret_uppercase_underscore", "ordinary--SECRET"},
		{"token_file_prefixed_alias", "ordinary--vault-token-file"},
	}
	for _, surface := range surfaces {
		for _, boundary := range boundaries {
			for _, family := range families {
				for _, locale := range []string{"C", "en_US.UTF-8"} {
					t.Run(surface+"/"+boundary.name+"/"+family.name+"/"+locale, func(t *testing.T) {
						value := family.before + boundary.value + "=" + marker
						result := run(locale, 5*time.Second, remoteAlphaPrintValueArgs(surface, value)...)
						assertRemoteAlphaPrivacyRefusal(t, result, marker)
					})
				}
			}
		}
	}
}

func TestRemoteAlphaOperatorLinearCompleteTokenMatrix(t *testing.T) {
	const marker = "CANARY_ONLY_NON_SECRET"
	run := remoteAlphaPrivacyRunner(t)
	for _, fragments := range []int{1024, 2048, 4096} {
		t.Run(fmt.Sprintf("benign_%d", fragments), func(t *testing.T) {
			value := "ordinary" + strings.Repeat("--not-sensitive-option", fragments)
			result := run("C", 5*time.Second, remoteAlphaPrintValueArgs("print-refresh-command", value)...)
			t.Logf("benign fragments=%d bytes=%d elapsed_ms=%d timeout=%t", fragments, len(value), result.elapsed.Milliseconds(), result.timedOut)
			if result.timedOut || result.err != nil || result.stderr != "" || !strings.Contains(result.stdout, value) {
				t.Fatal("long benign print value did not complete with ordinary print behavior before five seconds")
			}
		})
	}
	for _, placement := range []struct{ name, value string }{
		{"beginning", "--api-key=" + marker + strings.Repeat("--not-sensitive-option", 4096)},
		{"middle", strings.Repeat("--not-sensitive-option", 2048) + "--api-key=" + marker + strings.Repeat("--not-sensitive-option", 2048)},
		{"end", strings.Repeat("--not-sensitive-option", 4096) + "--api-key=" + marker},
	} {
		t.Run("secret_"+placement.name, func(t *testing.T) {
			result := run("C", 5*time.Second, remoteAlphaPrintValueArgs("print-refresh-command", placement.value)...)
			t.Logf("secret placement=%s bytes=%d elapsed_ms=%d timeout=%t", placement.name, len(placement.value), result.elapsed.Milliseconds(), result.timedOut)
			assertRemoteAlphaPrivacyRefusal(t, result, marker)
		})
	}
}

func TestRemoteAlphaOperatorByteStableFalsePositiveMatrix(t *testing.T) {
	run := remoteAlphaPrivacyRunner(t)
	values := []struct{ name, value string }{
		{"ordinary_profile", "ordinary-profile"},
		{"ordinary_equals", "ordinary=profile"},
		{"ordinary_unicode", "ordinary café \u2003 text"},
		{"api_keyboard", "--api-keyboard"},
		{"token_filed", "--token-filed"},
		{"passwordless", "--passwordless"},
		{"secretary", "--secretary"},
		{"private_keyboard", "--private-keyboard"},
		{"api_key_underscore_continuation", "--api-key_extra"},
		{"api_key_hyphen_continuation", "--api-key-extra"},
		{"api_key_alnum_continuation", "--api-key7"},
		{"multiple_benign_fragments", "ordinary" + strings.Repeat("--not-sensitive-option", 8)},
	}
	for _, surface := range []string{"print-refresh-command", "print-support-bundle-command", "print-im-commands", "recovery-session --next-steps"} {
		for _, locale := range []string{"C", "en_US.UTF-8"} {
			for _, item := range values {
				t.Run(surface+"/"+locale+"/"+item.name, func(t *testing.T) {
					result := run(locale, 5*time.Second, remoteAlphaPrintValueArgs(surface, item.value)...)
					if result.timedOut || result.err != nil || result.stderr != "" || !strings.Contains(result.stdout, item.value) {
						t.Fatal("documented ordinary value did not preserve effect-free print behavior")
					}
				})
			}
		}
	}
}

func TestRemoteAlphaOperatorClassifiesRefusalsBeforeHelperPathInitialization(t *testing.T) {
	root := t.TempDir()
	shimDir := filepath.Join(root, "shims")
	if err := os.Mkdir(shimDir, 0o700); err != nil {
		t.Fatal(err)
	}
	sentinel := filepath.Join(root, "path-initialized")
	writeExecutable(t, shimDir, "dirname", "#!/bin/sh\nprintf '%s\\n' invoked > '"+sentinel+"'\nexit 99\n")
	env := remoteAlphaOperatorTestEnv("PATH=" + shimDir + ":/usr/bin:/bin")
	tests := [][]string{
		{"--VAULT_TOKEN=dummy"},
		{"recovery-session", "--evidence-check", "--readiness-summary", filepath.Join(root, "private")},
		{"recovery-session", "--unknown-private-option"},
	}
	for _, args := range tests {
		stdout, _, err := runRemoteAlphaOperatorSeparated(env, args...)
		if err == nil || stdout != "" {
			t.Fatalf("contact-free refusal for %v returned stdout=%q err=%v", args, stdout, err)
		}
		if _, statErr := os.Lstat(sentinel); !os.IsNotExist(statErr) {
			t.Fatalf("refusal for %v initialized helper paths: %v", args, statErr)
		}
	}
}

func TestRemoteAlphaOperatorBlockedSubcommandsRefuseWithoutRouting(t *testing.T) {
	for _, subcommand := range []string{
		"vault-reset-disposable",
		"vault-unseal",
		"vault-unseal-existing",
		"runtime-security-check",
		"es-config-tls-prep",
		"es-binaries-check",
		"es-deploy-binaries",
		"es-writable-state-ownership",
		"es-service-user-migration",
	} {
		t.Run(subcommand, func(t *testing.T) {
			output := requireRemoteAlphaOperatorFailure(t, subcommand)
			assertContainsAll(t, "blocked subcommand refusal", output,
				"this subcommand category is unavailable as a top-level operator route",
				"No helper execution routing occurred.",
			)
			assertContainsNone(t, "blocked subcommand non-echo", output, subcommand)
		})
	}

	output := requireRemoteAlphaOperatorFailure(t, "vault-workload-auth-bootstrap")
	assertContainsAll(t, "bootstrap refusal", output,
		"vault-workload-auth-bootstrap",
		"blocked/reopened",
		"recovery-session vault-workload-auth-bootstrap --plan",
		"explicit P0q recovery-session execution route",
		"No helper execution routing occurred.",
	)
}

func TestRemoteAlphaOperatorExistingHostESRoutesAreFixedEffectFreeTombstones(t *testing.T) {
	variants := [][]string{
		nil,
		{"--help"},
		{"--check-only"},
		{"--apply"},
		{"--malformed"},
		{"arbitrary", "additional", "arguments"},
	}
	for _, subcommand := range []string{"es-writable-state-readiness-check", "readiness-session"} {
		for index, variant := range variants {
			t.Run(fmt.Sprintf("%s/%d", subcommand, index), func(t *testing.T) {
				root := t.TempDir()
				tempDir := filepath.Join(root, "tmp")
				homeDir := filepath.Join(root, "home")
				shimDir := filepath.Join(root, "shims")
				for _, dir := range []string{tempDir, homeDir, shimDir} {
					if err := os.Mkdir(dir, 0o700); err != nil {
						t.Fatal(err)
					}
				}
				sentinel := filepath.Join(root, "command-invoked")
				for _, name := range []string{"ssh", "scp", "sudo", "systemctl", "nomad", "docker", "vault", "curl", "python3", "mktemp"} {
					body := "#!/bin/sh\nprintf '%s\\n' invoked >> '" + sentinel + "'\nexit 99\n"
					if err := os.WriteFile(filepath.Join(shimDir, name), []byte(body), 0o700); err != nil {
						t.Fatal(err)
					}
				}

				args := append([]string{subcommand}, variant...)
				cmd := exec.Command("/bin/bash", append([]string{remoteAlphaOperatorScriptPath()}, args...)...)
				cmd.Dir = remoteAlphaOperatorRepoRoot()
				cmd.Env = []string{"PATH=" + shimDir + ":/usr/bin:/bin", "TMPDIR=" + tempDir, "HOME=" + homeDir}
				var stdout bytes.Buffer
				var stderr bytes.Buffer
				cmd.Stdout = &stdout
				cmd.Stderr = &stderr
				err := cmd.Run()
				exitErr, ok := err.(*exec.ExitError)
				if !ok || exitErr.ExitCode() != 2 {
					t.Fatalf("exit = %v, want 2", err)
				}
				if stdout.Len() != 0 {
					t.Fatalf("stdout = %q, want empty", stdout.String())
				}
				if stderr.String() != retiredRemoteAlphaStderr {
					t.Fatalf("stderr = %q, want %q", stderr.String(), retiredRemoteAlphaStderr)
				}
				if _, err := os.Lstat(sentinel); !os.IsNotExist(err) {
					t.Fatalf("retired route invoked a blocked command: %v", err)
				}
				for _, dir := range []string{tempDir, homeDir} {
					entries, err := os.ReadDir(dir)
					if err != nil {
						t.Fatal(err)
					}
					if len(entries) != 0 {
						t.Fatalf("retired route created artifacts in %s: %v", dir, entries)
					}
				}
			})
		}
	}
}

func TestRemoteAlphaOperatorRetiredRoutesApplyExactPrivacyPrefilterFirst(t *testing.T) {
	const privacyStderr = "error: secret material must never be passed by CLI args/env/logs/reports/artifacts\n"
	for _, subcommand := range []string{"es-writable-state-readiness-check", "readiness-session"} {
		t.Run(subcommand, func(t *testing.T) {
			root := t.TempDir()
			tempDir := filepath.Join(root, "tmp")
			homeDir := filepath.Join(root, "home")
			shimDir := filepath.Join(root, "shims")
			for _, dir := range []string{tempDir, homeDir, shimDir} {
				if err := os.Mkdir(dir, 0o700); err != nil {
					t.Fatal(err)
				}
			}
			sentinel := filepath.Join(root, "command-invoked")
			for _, name := range []string{"ssh", "scp", "sudo", "systemctl", "nomad", "docker", "vault", "curl", "python3", "mktemp"} {
				body := "#!/bin/sh\nprintf '%s\\n' invoked >> '" + sentinel + "'\nexit 99\n"
				if err := os.WriteFile(filepath.Join(shimDir, name), []byte(body), 0o700); err != nil {
					t.Fatal(err)
				}
			}

			env := remoteAlphaOperatorTestEnv(
				"PATH="+shimDir+":/usr/bin:/bin",
				"TMPDIR="+tempDir,
				"HOME="+homeDir,
			)
			stdout, stderr, err := runRemoteAlphaOperatorSeparated(env, subcommand, "--api-key=private-value")
			exitErr, ok := err.(*exec.ExitError)
			if !ok || exitErr.ExitCode() != 2 {
				t.Fatalf("exit = %v, want 2", err)
			}
			if stdout != "" || stderr != privacyStderr {
				t.Fatalf("privacy refusal stdout=%q stderr=%q", stdout, stderr)
			}
			if _, err := os.Lstat(sentinel); !os.IsNotExist(err) {
				t.Fatalf("privacy refusal invoked a blocked command: %v", err)
			}
			for _, dir := range []string{tempDir, homeDir} {
				entries, err := os.ReadDir(dir)
				if err != nil {
					t.Fatal(err)
				}
				if len(entries) != 0 {
					t.Fatalf("privacy refusal created artifacts in %s: %v", dir, entries)
				}
			}
		})
	}
}

func TestRemoteAlphaOperatorRecoverySessionRetiresHistoricalDisplayAndPreservesCurrentRoutes(t *testing.T) {
	help := requireRemoteAlphaOperatorSuccess(t, "recovery-session", "--help")
	assertContainsAll(t, "recovery-session help", help,
		"Remote Alpha operator workflow: recovery-session",
		"The operator facade provides no evidence-file ingestion, schema interpretation, automatic discovery, aggregation, or projection adapter",
		"operator-healthcheck-tls-status-noninteractive",
		"es-service-tls-status",
		"es-governance-tls-status",
	)
	assertContainsNone(t, "recovery-session retired evidence flags", help,
		"--readiness-summary <path>",
		"--staging-record <path>",
		"--evidence-check",
		"--evidence-dir",
		"--strict-known-schema",
		"vault-workload-auth-check",
		"runtime-identity-summary",
		"historical_evidence_only",
	)
}
func TestRemoteAlphaOperatorRecoverySessionVaultUnsealExistingHelpDocumentsHostLocalSecretPosture(t *testing.T) {
	help := requireRemoteAlphaOperatorSuccess(t, "recovery-session", "vault-unseal-existing", "--help")
	assertContainsAll(t, "vault-unseal-existing help", help,
		"Remote Alpha recovery-session mode: vault-unseal-existing",
		"P0j scope: explicit secret-sensitive non-destructive unseal-existing flow with host-local and Mac-side interactive TTY topologies",
		"Host-local mode must be run on the Remote Alpha host where Vault is installed and reachable",
		"Mac-side mode stages only scripts/remote_alpha_reset_disposable_vault.sh to the remote host and invokes only --unseal-only through ssh -tt",
		"No transcript, log, .out, report, support bundle, operator summary, IM refresh, workload-auth check, reset, or CP proof is created or run",
		"Delegates only to: scripts/remote_alpha_reset_disposable_vault.sh --unseal-only",
		"Human operator model",
		"The human remains the operator",
		"The operator enters any unseal key directly into the visible Vault/helper terminal prompt",
		"The operator facade does not prompt for, read, type, log, relay, persist, summarize, or accept unseal keys, root tokens, Vault tokens, API keys, passwords, or secret payloads",
		"Secret material must never be passed by CLI args, env files, logs, .out, reports, support bundles, retained bundles, or Codex output",
		"remote_alpha_operator.sh recovery-session vault-unseal-existing --host-local",
		"remote_alpha_operator.sh recovery-session vault-unseal-existing --ssh-target <user@host> --interactive-tty",
		"Allowed flags",
		"--host-local",
		"--ssh-target <target>",
		"--interactive-tty",
		"Topology rules",
		"--host-local and --ssh-target are mutually exclusive",
		"the SSH target must be a single target, not an option or shell command",
		"Forbidden in P0j",
		"--execute-reset",
		"--post-unseal-check",
		"--keep-staging-on-failure",
		"--interactive-sudo",
		"secret-like flags",
		"equals-form options",
		"Non-claims: not reset, not workload-auth bootstrap or check, not IM refresh/support-bundle, not CP proof, not default noninteractive readiness validation",
		"not ES Vault token brokerage",
		"not Remote Alpha deployment/provisioning/reconciliation architecture",
	)
}

func TestRemoteAlphaOperatorRecoverySessionVaultResetDisposableHelpDocumentsDryRunPosture(t *testing.T) {
	help := requireRemoteAlphaOperatorSuccess(t, "recovery-session", "vault-reset-disposable", "--help")
	assertContainsAll(t, "vault-reset-disposable help", help,
		"Remote Alpha recovery-session mode: vault-reset-disposable",
		"P0m scope: explicit Mac-side disposable Vault reset dry-run planning route plus destructive execute-reset operator route",
		"Dry-run stages only scripts/remote_alpha_reset_disposable_vault.sh to the remote host and invokes only --dry-run",
		"Execute-reset stages only scripts/remote_alpha_reset_disposable_vault.sh to the remote host and invokes only --execute-reset through ssh -tt",
		"Dry-run remains the prerequisite/planning route",
		"Live execute-reset must be run only when the operator intentionally wants to reset disposable Remote Alpha Vault state",
		"The helper supports --dry-run; the operator facade passes it explicitly",
		"No transcript, tee/script capture, log, .out, report, support bundle, operator summary, IM refresh, workload-auth check, post-unseal check, runtime identity summary, or CP proof is created or run",
		"Delegates only to: scripts/remote_alpha_reset_disposable_vault.sh --dry-run or scripts/remote_alpha_reset_disposable_vault.sh --execute-reset",
		"Non-destructive behavior",
		"This is planning/inspection only",
		"It does not stop Vault",
		"It does not move raft storage",
		"It does not run vault operator init",
		"It does not unseal Vault",
		"It does not run post-unseal checks",
		"It does not run Infrastructure Manager",
		"It does not collect support bundles",
		"Execute-reset is a destructive explicit operator route and requires --interactive-tty",
		"Destructive execute-reset behavior",
		"This is destructive for disposable Remote Alpha Vault state",
		"The existing exact confirmation phrase is RESET DISPOSABLE REMOTE ALPHA VAULT",
		"The operator types that phrase only in the visible remote helper/Vault terminal",
		"Vault init output, root token, unseal key, and Vault prompts are handled only by the human operator in the visible remote terminal",
		"The phrase and Vault secrets must never be passed by CLI args, env files, files, logs, .out, reports, support bundles, retained bundles, or Codex output",
		"The operator facade does not receive, parse, log, store, echo, summarize, or persist the phrase or secret material",
		"Artifacts and outputs remain evidence/projection/diagnostics only, never authority",
		"remote_alpha_operator.sh recovery-session vault-reset-disposable --ssh-target <user@host> --dry-run",
		"remote_alpha_operator.sh recovery-session vault-reset-disposable --ssh-target <user@host> --execute-reset --interactive-tty",
		"Allowed flags",
		"--ssh-target <target>",
		"--dry-run",
		"--execute-reset",
		"--interactive-tty",
		"Topology rules: Mac-side only",
		"exactly one of --dry-run or --execute-reset is required",
		"--execute-reset requires --interactive-tty",
		"--dry-run rejects --interactive-tty",
		"--host-local is not accepted",
		"Forbidden in P0m",
		"--unseal-only",
		"--post-unseal-check",
		"--host-local",
		"--keep-staging-on-failure",
		"workload-auth flags",
		"IM commands",
		"support-bundle commands",
		"runtime-identity flags",
		"secret-like flags",
		"equals-form options",
		"Non-claims: not workload-auth bootstrap or check, not IM refresh/support-bundle, not CP proof",
		"not ES Vault token brokerage",
		"not Remote Alpha deployment/provisioning/reconciliation architecture",
	)
}

const remoteAlphaOperatorEvidenceRetirementStderr = "remote alpha operator evidence ingestion, staging, aggregation, and projection compatibility is retired; no artifact inspection, helper execution, staging, or evidence projection occurred\n" +
	"use the owning producer directly only under its separately documented contract; this operator facade provides no compatibility adapter\n"

const remoteAlphaOperatorGenericRefusalStderr = "error: unknown operator subcommand\n" +
	"No helper execution routing occurred.\n"

func TestRemoteAlphaOperatorEvidenceCompatibilitySurfacesAreFixedEffectFreeRetirements(t *testing.T) {
	privateValue := filepath.Join(t.TempDir(), "private-evidence-value.json")
	tests := []struct {
		name string
		args []string
	}{
		{name: "recovery workload auth empty", args: []string{"recovery-session", "vault-workload-auth-check"}},
		{name: "recovery workload auth help", args: []string{"recovery-session", "vault-workload-auth-check", "--help"}},
		{name: "recovery workload auth arbitrary", args: []string{"recovery-session", "vault-workload-auth-check", "ordinary-value"}},
		{name: "recovery runtime identity empty", args: []string{"recovery-session", "runtime-identity-summary"}},
		{name: "recovery runtime identity malformed", args: []string{"recovery-session", "runtime-identity-summary", "--ssh-target=ordinary"}},
		{name: "top workload auth alias", args: []string{"vault-workload-auth-check", "--help"}},
		{name: "top runtime identity alias", args: []string{"runtime-identity-summary", "ordinary-value"}},
		{name: "top service user alias", args: []string{"vault-service-user-check"}},
		{name: "evidence check split", args: []string{"recovery-session", "--evidence-check"}},
		{name: "evidence check equals", args: []string{"recovery-session", "--evidence-check=malformed"}},
		{name: "evidence directory split", args: []string{"recovery-session", "--evidence-dir", privateValue}},
		{name: "evidence directory equals", args: []string{"recovery-session", "--evidence-dir=" + privateValue}},
		{name: "strict schema split", args: []string{"recovery-session", "--strict-known-schema"}},
		{name: "strict schema equals", args: []string{"recovery-session", "--strict-known-schema=true"}},
		{name: "workload summary split", args: []string{"recovery-session", "--vault-workload-auth-summary", privateValue}},
		{name: "workload summary equals", args: []string{"recovery-session", "--vault-workload-auth-summary=" + privateValue}},
		{name: "runtime summary split", args: []string{"recovery-session", "--runtime-identity-summary", privateValue}},
		{name: "runtime summary equals", args: []string{"recovery-session", "--runtime-identity-summary=" + privateValue}},
		{name: "service user summary split", args: []string{"recovery-session", "--vault-service-user-summary", privateValue}},
		{name: "service user summary equals", args: []string{"recovery-session", "--vault-service-user-summary=" + privateValue}},
		{name: "secret-shaped option value gets privacy refusal", args: []string{"recovery-session", "--runtime-identity-summary", "--vault-token"}},
		{name: "top-level retired flag", args: []string{"--vault-service-user-summary", privateValue}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			binDir := filepath.Join(root, "bin")
			homeDir := filepath.Join(root, "home")
			tmpDir := filepath.Join(root, "tmp")
			for _, directory := range []string{binDir, homeDir, tmpDir} {
				if err := os.Mkdir(directory, 0o700); err != nil {
					t.Fatal(err)
				}
			}
			marker := filepath.Join(root, "unexpected-effect")
			shim := "#!/usr/bin/env bash\nprintf '%s\\n' \"$0\" > \"$EFFECT_MARKER\"\nexit 97\n"
			for _, name := range []string{"curl", "dirname", "docker", "lstat", "nomad", "python3", "scp", "spire", "ssh", "sudo", "systemctl", "vault"} {
				writeExecutable(t, binDir, name, shim)
			}
			before, err := os.ReadDir(root)
			if err != nil {
				t.Fatal(err)
			}
			env := remoteAlphaOperatorTestEnv(
				"PATH="+binDir,
				"HOME="+homeDir,
				"TMPDIR="+tmpDir,
				"EFFECT_MARKER="+marker,
			)
			stdout, stderr, runErr := runRemoteAlphaOperatorSeparated(env, test.args...)
			exitErr, ok := runErr.(*exec.ExitError)
			if !ok || exitErr.ExitCode() != 2 {
				t.Fatalf("exit = %v, want 2", runErr)
			}
			wantStderr := remoteAlphaOperatorEvidenceRetirementStderr
			if test.name == "secret-shaped option value gets privacy refusal" {
				wantStderr = "error: secret material must never be passed by CLI args/env/logs/reports/artifacts\n"
			}
			if stdout != "" || stderr != wantStderr {
				t.Fatalf("stdout=%q stderr=%q", stdout, stderr)
			}
			for _, arg := range test.args {
				if arg != "" && strings.Contains(stderr, arg) {
					t.Fatalf("retirement refusal echoed %q", arg)
				}
			}
			if _, err := os.Stat(marker); !os.IsNotExist(err) {
				t.Fatalf("retired surface reached an external helper: %v", err)
			}
			after, err := os.ReadDir(root)
			if err != nil {
				t.Fatal(err)
			}
			if directoryEntryNames(before) != directoryEntryNames(after) {
				t.Fatalf("retired surface changed private test root: before=%s after=%s", directoryEntryNames(before), directoryEntryNames(after))
			}
		})
	}
}

func TestRemoteAlphaOperatorPrefixedStaleInvocationsUseGenericEffectFreeRefusal(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{
			name: "profile dir before workload auth alias",
			args: []string{"--profile-dir", "ordinary", "vault-workload-auth-check"},
		},
		{
			name: "output root before runtime identity alias",
			args: []string{"--output-root=ordinary", "runtime-identity-summary", "--help"},
		},
		{
			name: "ssh alias before service user alias",
			args: []string{"--ssh-alias", "ordinary", "vault-service-user-check", "arbitrary"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			binDir := filepath.Join(root, "bin")
			homeDir := filepath.Join(root, "home")
			tmpDir := filepath.Join(root, "tmp")
			stagingDir := filepath.Join(root, "staging")
			discoveryDir := filepath.Join(root, "discovery")
			projectionDir := filepath.Join(root, "projection")
			for _, directory := range []string{binDir, homeDir, tmpDir, stagingDir, discoveryDir, projectionDir} {
				if err := os.Mkdir(directory, 0o700); err != nil {
					t.Fatal(err)
				}
			}

			effectMarker := filepath.Join(root, "unexpected-effect")
			shim := "#!/bin/sh\nprintf '%s\\n' \"$0\" >> \"$EFFECT_MARKER\"\nexit 97\n"
			for _, name := range []string{
				"bash", "cat", "cp", "curl", "dirname", "docker", "find", "jq", "ln", "ls", "lstat",
				"mkdir", "mktemp", "mv", "nomad", "python3", "readlink", "realpath", "rm", "scp", "sed",
				"spire", "ssh", "stat", "sudo", "systemctl", "touch", "vault",
			} {
				writeExecutable(t, binDir, name, shim)
			}

			before, err := os.ReadDir(root)
			if err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command("/bin/bash", append([]string{remoteAlphaOperatorScriptPath()}, test.args...)...)
			cmd.Dir = root
			cmd.Env = remoteAlphaOperatorTestEnv(
				"PATH="+binDir,
				"HOME="+homeDir,
				"TMPDIR="+tmpDir,
				"EFFECT_MARKER="+effectMarker,
			)
			var stdout bytes.Buffer
			var stderr bytes.Buffer
			cmd.Stdout = &stdout
			cmd.Stderr = &stderr
			runErr := cmd.Run()

			exitErr, ok := runErr.(*exec.ExitError)
			if !ok || exitErr.ExitCode() != 2 {
				t.Fatalf("exit = %v, want 2", runErr)
			}
			if stdout.Len() != 0 {
				t.Fatalf("stdout = %q, want empty", stdout.String())
			}
			if got := stderr.String(); got != remoteAlphaOperatorGenericRefusalStderr {
				t.Fatalf("stderr = %q, want fixed generic refusal %q", got, remoteAlphaOperatorGenericRefusalStderr)
			}
			if stderr.String() == remoteAlphaOperatorEvidenceRetirementStderr {
				t.Fatal("prefixed stale invocation unexpectedly received the exact two-line retirement tombstone")
			}
			for _, rawArg := range test.args {
				if strings.Contains(stderr.String(), rawArg) {
					t.Fatalf("generic refusal echoed raw argument, option, path, or value %q", rawArg)
				}
			}
			if _, err := os.Lstat(effectMarker); !os.IsNotExist(err) {
				t.Fatalf("prefixed stale invocation performed file access, helper initialization, subprocess, host, staging, discovery, or projection effect: %v", err)
			}
			for _, directory := range []string{homeDir, tmpDir, stagingDir, discoveryDir, projectionDir} {
				entries, err := os.ReadDir(directory)
				if err != nil {
					t.Fatal(err)
				}
				if len(entries) != 0 {
					t.Fatalf("prefixed stale invocation created a temporary, staging, discovery, or projection artifact in %s: %v", directory, entries)
				}
			}
			after, err := os.ReadDir(root)
			if err != nil {
				t.Fatal(err)
			}
			if directoryEntryNames(before) != directoryEntryNames(after) {
				t.Fatalf("prefixed stale invocation changed its private root: before=%s after=%s", directoryEntryNames(before), directoryEntryNames(after))
			}
		})
	}
}

func TestRemoteAlphaOperatorEvidenceRetirementKeepsPrivacyPrefilterFirst(t *testing.T) {
	const privacy = "error: secret material must never be passed by CLI args/env/logs/reports/artifacts\n"
	for _, args := range [][]string{
		{"recovery-session", "vault-workload-auth-check", "--vault-token", "private"},
		{"recovery-session", "runtime-identity-summary", "--private-key=private"},
		{"vault-service-user-check", "--password", "private"},
		{"recovery-session", "--runtime-identity-summary", "ordinary", "--api-key", "private"},
		{"--secret-value=private", "vault-workload-auth-check"},
	} {
		stdout, stderr, err := runRemoteAlphaOperatorSeparated(nil, args...)
		exitErr, ok := err.(*exec.ExitError)
		if !ok || exitErr.ExitCode() != 2 {
			t.Fatalf("%v exit = %v, want 2", args, err)
		}
		if stdout != "" || stderr != privacy {
			t.Fatalf("%v stdout=%q stderr=%q", args, stdout, stderr)
		}
		if strings.Contains(stderr, "private") {
			t.Fatalf("privacy refusal echoed private input: %q", stderr)
		}
	}
}

func directoryEntryNames(entries []os.DirEntry) string {
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	return strings.Join(names, "\\x00")
}

func TestRemoteAlphaOperatorRecoverySessionRejectsForbiddenFlagsAndUnsafeArgs(t *testing.T) {
	for _, tc := range []struct {
		name     string
		args     []string
		required []string
	}{
		{
			name:     "ssh target",
			args:     []string{"--ssh-target", "host"},
			required: []string{"recovery-session received an option reserved for an explicit submode", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "interactive sudo",
			args:     []string{"--interactive-sudo"},
			required: []string{"recovery-session received an option reserved for an explicit submode", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "apply",
			args:     []string{"--apply"},
			required: []string{"recovery-session received an option reserved for an explicit submode", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "dry run",
			args:     []string{"--dry-run"},
			required: []string{"recovery-session received an option reserved for an explicit submode", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "execute reset",
			args:     []string{"--execute-reset"},
			required: []string{"recovery-session received an option reserved for an explicit submode", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "unseal only",
			args:     []string{"--unseal-only"},
			required: []string{"recovery-session received an option reserved for an explicit submode", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "post unseal check",
			args:     []string{"--post-unseal-check"},
			required: []string{"recovery-session received an option reserved for an explicit submode", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "governed smoke command",
			args:     []string{"--governed-smoke-command", "echo hi"},
			required: []string{"recovery-session received an option reserved for an explicit submode", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "secret equals form",
			args:     []string{"--api-key=dummy"},
			required: []string{"secret material must never be passed by CLI args/env/logs/reports/artifacts"},
		},
		{
			name:     "unknown flag",
			args:     []string{"--unknown-flag"},
			required: []string{"recovery-session received an unknown option", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "positional",
			args:     []string{"opaque-invalid-value-7b9f"},
			required: []string{"recovery-session received an unexpected positional argument", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "retired service user nested alias remains absent",
			args:     []string{"vault-service-user-check"},
			required: []string{"recovery-session received an unexpected positional argument", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "equals form",
			args:     []string{"--plan=true"},
			required: []string{"recovery-session does not accept equals-form options", "No recovery-session live helper or IM execution occurred."},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			output := requireRemoteAlphaOperatorFailure(t, append([]string{"recovery-session"}, tc.args...)...)
			assertRemoteAlphaOperatorUnsafeRefusal(t, "recovery-session refusal", output, tc.args, tc.required)
			for _, arg := range tc.args {
				if strings.HasPrefix(arg, "--unknown") || arg == "opaque-invalid-value-7b9f" || arg == "vault-service-user-check" || strings.Contains(arg, "=true") {
					assertContainsNone(t, "recovery-session non-echo refusal", output, arg)
				}
			}
		})
	}
}

func TestRemoteAlphaOperatorRecoverySessionVaultUnsealExistingRejectsUnsafeArgsBeforeDelegation(t *testing.T) {
	for _, tc := range []struct {
		name     string
		args     []string
		required []string
	}{
		{
			name:     "missing topology",
			args:     []string{},
			required: []string{"recovery-session vault-unseal-existing requires --host-local or --ssh-target <target> --interactive-tty", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "missing interactive tty",
			args:     []string{"--ssh-target", "host"},
			required: []string{"recovery-session vault-unseal-existing --ssh-target requires --interactive-tty", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "missing ssh target",
			args:     []string{"--interactive-tty"},
			required: []string{"recovery-session vault-unseal-existing --interactive-tty requires --ssh-target <target>", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "host local plus ssh target",
			args:     []string{"--host-local", "--ssh-target", "host", "--interactive-tty"},
			required: []string{"recovery-session vault-unseal-existing requires exactly one topology", "--host-local or --ssh-target <target> --interactive-tty", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "execute reset",
			args:     []string{"--execute-reset"},
			required: []string{"recovery-session vault-unseal-existing forbids --execute-reset", "unseal-only, non-destructive, and does not combine checks", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "post unseal check",
			args:     []string{"--post-unseal-check"},
			required: []string{"recovery-session vault-unseal-existing forbids --post-unseal-check", "unseal-only, non-destructive, and does not combine checks", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "unseal only direct flag",
			args:     []string{"--unseal-only"},
			required: []string{"recovery-session vault-unseal-existing forbids --unseal-only", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "keep staging",
			args:     []string{"--keep-staging-on-failure"},
			required: []string{"recovery-session vault-unseal-existing forbids --keep-staging-on-failure", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "apply",
			args:     []string{"--apply"},
			required: []string{"recovery-session vault-unseal-existing forbids --apply", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "dry run",
			args:     []string{"--dry-run"},
			required: []string{"recovery-session vault-unseal-existing forbids --dry-run", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "interactive sudo",
			args:     []string{"--interactive-sudo"},
			required: []string{"recovery-session vault-unseal-existing forbids --interactive-sudo", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "governed smoke command",
			args:     []string{"--governed-smoke-command", "echo hi"},
			required: []string{"recovery-session vault-unseal-existing forbids --governed-smoke-command", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "unknown flag",
			args:     []string{"--unknown-flag"},
			required: []string{"unknown option for recovery-session vault-unseal-existing: --unknown-flag", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "equals form",
			args:     []string{"--host-local=true"},
			required: []string{"recovery-session vault-unseal-existing does not accept equals-form options: --host-local=true", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "positional",
			args:     []string{"unexpected"},
			required: []string{"unexpected positional argument for recovery-session vault-unseal-existing: unexpected", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "duplicate host local",
			args:     []string{"--host-local", "--host-local"},
			required: []string{"duplicate option for recovery-session: --host-local", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "duplicate ssh target",
			args:     []string{"--ssh-target", "a", "--ssh-target", "b", "--interactive-tty"},
			required: []string{"duplicate option for recovery-session: --ssh-target", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "duplicate interactive tty",
			args:     []string{"--ssh-target", "host", "--interactive-tty", "--interactive-tty"},
			required: []string{"duplicate option for recovery-session: --interactive-tty", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "ssh target option injection",
			args:     []string{"--ssh-target", "-oProxyCommand=sh", "--interactive-tty"},
			required: []string{"--ssh-target must be a single SSH target, not an option or shell command", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "ssh target shell command",
			args:     []string{"--ssh-target", "host;echo", "--interactive-tty"},
			required: []string{"--ssh-target must be a single SSH target, not an option or shell command", "No recovery-session live helper or IM execution occurred."},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			output := requireRemoteAlphaOperatorFailure(t, append([]string{"recovery-session", "vault-unseal-existing"}, tc.args...)...)
			assertRemoteAlphaOperatorUnsafeRefusal(t, "vault-unseal-existing refusal", output, tc.args, tc.required)
			assertContainsNone(t, "vault-unseal-existing refusal", output,
				"Running host-local Vault unseal-only helper",
				"remote_alpha_reset_disposable_vault.sh --unseal-only",
			)
		})
	}
}

func TestRemoteAlphaOperatorRecoverySessionVaultUnsealExistingRejectsSecretLikeArgsBeforeDelegation(t *testing.T) {
	for _, args := range [][]string{
		{"--api-key=dummy"},
		{"--api-key", "dummy"},
		{"--unseal-key", "dummy"},
		{"--unseal-key=dummy"},
		{"--root-token", "dummy"},
		{"--root-token=dummy"},
		{"--vault-token", "dummy"},
		{"--client-token", "dummy"},
		{"--jwt-svid", "dummy"},
		{"--private-key", "dummy"},
		{"--password", "dummy"},
		{"--secret", "dummy"},
	} {
		t.Run(strings.Join(args, "_"), func(t *testing.T) {
			output := requireRemoteAlphaOperatorFailure(t, append([]string{"recovery-session", "vault-unseal-existing"}, args...)...)
			assertContainsAll(t, "vault-unseal-existing secret flag refusal", output,
				"secret material must never be passed by CLI args/env/logs/reports/artifacts",
			)
			assertContainsNone(t, "vault-unseal-existing secret flag refusal", output,
				"Running host-local Vault unseal-only helper",
				"remote_alpha_reset_disposable_vault.sh --unseal-only",
			)
		})
	}
}

func TestRemoteAlphaOperatorRecoverySessionVaultResetDisposableRejectsUnsafeArgsBeforeDelegation(t *testing.T) {
	for _, tc := range []struct {
		name     string
		args     []string
		required []string
	}{
		{
			name:     "missing ssh target",
			args:     []string{},
			required: []string{"recovery-session vault-reset-disposable requires --ssh-target <target>", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "missing dry run",
			args:     []string{"--ssh-target", "host"},
			required: []string{"recovery-session vault-reset-disposable requires --dry-run or --execute-reset", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "execute reset missing ssh target",
			args:     []string{"--execute-reset"},
			required: []string{"recovery-session vault-reset-disposable requires --ssh-target <target>", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "execute reset missing interactive tty",
			args:     []string{"--ssh-target", "host", "--execute-reset"},
			required: []string{"recovery-session vault-reset-disposable --execute-reset requires --interactive-tty", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "execute reset plus dry run",
			args:     []string{"--ssh-target", "host", "--execute-reset", "--dry-run"},
			required: []string{"recovery-session vault-reset-disposable requires exactly one mode: --dry-run or --execute-reset", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "unseal only",
			args:     []string{"--unseal-only"},
			required: []string{"recovery-session vault-reset-disposable forbids --unseal-only", "does not combine reset, unseal, post-unseal checks", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "post unseal check",
			args:     []string{"--ssh-target", "host", "--execute-reset", "--post-unseal-check"},
			required: []string{"recovery-session vault-reset-disposable forbids --post-unseal-check", "does not combine reset, unseal, post-unseal checks", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "host local",
			args:     []string{"--ssh-target", "host", "--execute-reset", "--host-local"},
			required: []string{"recovery-session vault-reset-disposable forbids --host-local", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "interactive tty",
			args:     []string{"--ssh-target", "host", "--dry-run", "--interactive-tty"},
			required: []string{"recovery-session vault-reset-disposable forbids --interactive-tty", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "interactive sudo",
			args:     []string{"--interactive-sudo"},
			required: []string{"recovery-session vault-reset-disposable forbids --interactive-sudo", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "apply",
			args:     []string{"--apply"},
			required: []string{"recovery-session vault-reset-disposable forbids --apply", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "keep staging",
			args:     []string{"--keep-staging-on-failure"},
			required: []string{"recovery-session vault-reset-disposable forbids --keep-staging-on-failure", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "governed smoke command",
			args:     []string{"--governed-smoke-command", "echo hi"},
			required: []string{"recovery-session vault-reset-disposable forbids --governed-smoke-command", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "unknown flag",
			args:     []string{"--ssh-target", "host", "--dry-run", "--unknown-flag"},
			required: []string{"unknown option for recovery-session vault-reset-disposable: --unknown-flag", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "equals form",
			args:     []string{"--ssh-target=host", "--dry-run"},
			required: []string{"recovery-session vault-reset-disposable does not accept equals-form options: --ssh-target=host", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "positional",
			args:     []string{"--ssh-target", "host", "--dry-run", "unexpected"},
			required: []string{"unexpected positional argument for recovery-session vault-reset-disposable: unexpected", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "duplicate ssh target",
			args:     []string{"--ssh-target", "a", "--ssh-target", "b", "--dry-run"},
			required: []string{"duplicate option for recovery-session: --ssh-target", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "duplicate dry run",
			args:     []string{"--ssh-target", "host", "--dry-run", "--dry-run"},
			required: []string{"duplicate option for recovery-session: --dry-run", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "duplicate execute reset",
			args:     []string{"--ssh-target", "host", "--execute-reset", "--execute-reset", "--interactive-tty"},
			required: []string{"duplicate option for recovery-session: --execute-reset", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "duplicate interactive tty",
			args:     []string{"--ssh-target", "host", "--execute-reset", "--interactive-tty", "--interactive-tty"},
			required: []string{"duplicate option for recovery-session: --interactive-tty", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "ssh target option injection",
			args:     []string{"--ssh-target", "-oProxyCommand=sh", "--dry-run"},
			required: []string{"--ssh-target must be a single SSH target, not an option or shell command", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "ssh target shell command",
			args:     []string{"--ssh-target", "host;echo", "--dry-run"},
			required: []string{"--ssh-target must be a single SSH target, not an option or shell command", "No recovery-session live helper or IM execution occurred."},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			output := requireRemoteAlphaOperatorFailure(t, append([]string{"recovery-session", "vault-reset-disposable"}, tc.args...)...)
			assertRemoteAlphaOperatorUnsafeRefusal(t, "vault-reset-disposable refusal", output, tc.args, tc.required)
			assertContainsNone(t, "vault-reset-disposable refusal", output,
				"Running Mac-side disposable Vault reset dry-run planning route",
				"Running Mac-side disposable Vault execute-reset",
				"remote_alpha_reset_disposable_vault.sh --dry-run",
				"remote_alpha_reset_disposable_vault.sh --execute-reset",
			)
		})
	}
}

func TestRemoteAlphaOperatorRecoverySessionVaultResetDisposableRejectsSecretLikeArgsBeforeDelegation(t *testing.T) {
	for _, args := range [][]string{
		{"--api-key=dummy"},
		{"--api-key", "dummy"},
		{"--unseal-key", "dummy"},
		{"--unseal-key=dummy"},
		{"--root-token", "dummy"},
		{"--root-token=dummy"},
		{"--vault-token", "dummy"},
		{"--client-token", "dummy"},
		{"--jwt-svid", "dummy"},
		{"--private-key", "dummy"},
		{"--password", "dummy"},
		{"--secret", "dummy"},
	} {
		t.Run(strings.Join(args, "_"), func(t *testing.T) {
			output := requireRemoteAlphaOperatorFailure(t, append([]string{"recovery-session", "vault-reset-disposable"}, args...)...)
			assertContainsAll(t, "vault-reset-disposable secret flag refusal", output,
				"secret material must never be passed by CLI args/env/logs/reports/artifacts",
			)
			assertContainsNone(t, "vault-reset-disposable secret flag refusal", output,
				"Running Mac-side disposable Vault reset dry-run planning route",
				"Running Mac-side disposable Vault execute-reset",
				"remote_alpha_reset_disposable_vault.sh --dry-run",
				"remote_alpha_reset_disposable_vault.sh --execute-reset",
			)
		})
	}
}

func TestRemoteAlphaOperatorRecoverySessionVaultWorkloadAuthBootstrapPrintsPlanInventoryAndHelp(t *testing.T) {
	for _, tc := range []struct {
		name     string
		args     []string
		required []string
	}{
		{
			name: "default plan",
			args: []string{"recovery-session", "vault-workload-auth-bootstrap"},
			required: []string{
				"Remote Alpha Vault workload-auth bootstrap plan (P0q safe modes plus staged execution)",
				"route mechanics partially passed",
				"vault.initialized=true",
				"vault.sealed=false",
				"vault.auth_mount=jwt",
				"vault.role=service_execution",
				"vault.audience=vault",
				"vault_workload_auth_smoke=fail",
				"auth_smoke.vault_login=fail",
				"Vault JWT login rejected or not configured",
				"auth mount: jwt",
				"JWT auth config: SPIRE JWT validation material selected for the workload trust domain and bound issuer",
				"role: service_execution",
				"role_type=jwt",
				"user_claim=sub",
				"bound_audiences=vault",
				"bound_subject=spiffe://execution.internal/workload",
				"policy such as runtime-identity-proof",
				"proof-secrets/data/runtime-identity-vault-login",
				"proof-secrets/data/codex-runtime-profile",
				"api_key present and non-empty; value never printed",
				"/etc/execution-substrate/vault/workload-zone-vault-config.json",
				"Implemented execution contract",
				"recovery-session vault-workload-auth-bootstrap --ssh-target <target> --prepare-summary-path --interactive-tty",
				"runs only bounded remote filesystem preparation",
				"may use visible OS sudo",
				"recovery-session vault-workload-auth-bootstrap --ssh-target <target> --prepare-config-readability --interactive-tty",
				"fixed-path user ACLs",
				"config contents are never printed",
				"recovery-session vault-workload-auth-bootstrap --ssh-target <target> --prepare-spire-bundle-read --interactive-tty",
				"fixed SPIRE server bundle-read access",
				"bundle output is discarded and never printed",
				"optional combined form may add --prepare-summary-path, --prepare-config-readability, and --prepare-spire-bundle-read",
				"recovery-session vault-workload-auth-bootstrap --ssh-target <target> --execute-bootstrap --interactive-tty",
				"stages only scripts/remote_alpha_vault_workload_auth_bootstrap.sh and scripts/internal/remote_alpha_vault_workload_auth_bootstrap.sh",
				"root token must never be accepted as a CLI arg, env var, file, .out, report, support bundle, retained bundle, or Codex output",
				"explicit visible or silent operator prompt",
				"no transcript capture, no tee, no script",
				"proof secret values must never be printed, copied, summarized, or logged",
				"must not claim workload-auth success",
				"vault-workload-auth-bootstrap-summary.json",
				"workload-auth check remains a separate command after bootstrap",
				"not ES Vault token brokerage",
				"not Remote Alpha deployment, provisioning, or reconciliation architecture",
			},
		},
		{
			name: "explicit plan",
			args: []string{"recovery-session", "vault-workload-auth-bootstrap", "--plan"},
			required: []string{
				"Remote Alpha Vault workload-auth bootstrap plan (P0q safe modes plus staged execution)",
				"conservative classification: Vault JWT login rejected or not configured",
				"bootstrap configures expected Vault objects only and must not claim workload-auth success",
			},
		},
		{
			name: "help",
			args: []string{"recovery-session", "vault-workload-auth-bootstrap", "--help"},
			required: []string{
				"Remote Alpha recovery-session mode: vault-workload-auth-bootstrap",
				"P0q scope: safe local/print-only planning plus bounded summary-path, config-readability, and SPIRE bundle-read preparation and Mac-side staged bootstrap execution",
				"Allowed flags:",
				"--help",
				"--plan",
				"--inventory",
				"--ssh-target <target>",
				"--execute-bootstrap",
				"--prepare-summary-path",
				"--prepare-config-readability",
				"--prepare-spire-bundle-read",
				"--interactive-tty",
				"Default behavior: print the bootstrap plan/help and exit zero.",
				"Topology rules:",
				"summary-path, config-readability, and SPIRE bundle-read preparation may prompt only for OS sudo",
				"Secret posture:",
				"not workload-auth success",
				"not ES Vault token brokerage",
			},
		},
		{
			name: "inventory",
			args: []string{"recovery-session", "vault-workload-auth-bootstrap", "--inventory"},
			required: []string{
				"Remote Alpha Vault workload-auth bootstrap inventory (P0q)",
				"static local inventory only",
				"recovery-session vault-workload-auth-bootstrap --help",
				"recovery-session vault-workload-auth-bootstrap --plan",
				"recovery-session vault-workload-auth-bootstrap --inventory",
				"recovery-session vault-workload-auth-bootstrap --ssh-target <target> --prepare-summary-path --interactive-tty",
				"run only the bounded remote filesystem preparation command",
				"recovery-session vault-workload-auth-bootstrap --ssh-target <target> --prepare-config-readability --interactive-tty",
				"fixed workload-zone config readability",
				"recovery-session vault-workload-auth-bootstrap --ssh-target <target> --prepare-spire-bundle-read --interactive-tty",
				"fixed SPIRE server bundle-read access",
				"recovery-session vault-workload-auth-bootstrap --ssh-target <target> --execute-bootstrap --prepare-summary-path --prepare-config-readability --prepare-spire-bundle-read --interactive-tty",
				"prepare the summary path, then config readability, then SPIRE bundle-read access before staging",
				"recovery-session vault-workload-auth-bootstrap --ssh-target <target> --execute-bootstrap --interactive-tty",
				"stage the dedicated bootstrap helper pair",
				"live validation - not performed",
				"workload-auth check execution, reset/unseal, IM, support bundle, CP proof, and runtime identity generation - not part of bootstrap",
				"role service_execution with role_type=jwt",
				"proof-secrets/data/runtime-identity-vault-login",
				"proof-secrets/data/codex-runtime-profile",
				"api_key field present and non-empty; proof secret value never printed",
				"preparation creates no final bootstrap summary and no Mac artifact",
				"execution writes only a remote non-secret summary; no Mac .out; no operator summary",
				"Vault owns token, secret, and lease authority",
				"SPIRE owns JWT-SVID issuance",
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			output := requireRemoteAlphaOperatorSuccess(t, tc.args...)
			assertContainsAll(t, "vault-workload-auth-bootstrap output", output, tc.required...)
			assertContainsNone(t, "vault-workload-auth-bootstrap output", output,
				"Running Mac-side Vault workload-auth evidence check",
				"wrote /var/tmp",
				"not available in P0q",
			)
		})
	}
}

func TestRemoteAlphaOperatorRecoverySessionVaultWorkloadAuthBootstrapRejectsUnsafeArgs(t *testing.T) {
	for _, tc := range []struct {
		name     string
		args     []string
		required []string
	}{
		{
			name:     "execute bootstrap",
			args:     []string{"--execute-bootstrap"},
			required: []string{"recovery-session vault-workload-auth-bootstrap --execute-bootstrap requires --ssh-target <target>", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "ssh target",
			args:     []string{"--ssh-target", "host"},
			required: []string{"recovery-session vault-workload-auth-bootstrap --ssh-target is valid only with --execute-bootstrap, --prepare-summary-path, --prepare-config-readability, or --prepare-spire-bundle-read", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "interactive tty",
			args:     []string{"--interactive-tty"},
			required: []string{"recovery-session vault-workload-auth-bootstrap --interactive-tty is valid only with --execute-bootstrap, --prepare-summary-path, --prepare-config-readability, or --prepare-spire-bundle-read", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "prepare summary path missing ssh target and tty",
			args:     []string{"--prepare-summary-path"},
			required: []string{"recovery-session vault-workload-auth-bootstrap --prepare-summary-path requires --ssh-target <target>", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "prepare summary path missing tty",
			args:     []string{"--ssh-target", "host", "--prepare-summary-path"},
			required: []string{"recovery-session vault-workload-auth-bootstrap --prepare-summary-path requires --interactive-tty", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "prepare summary path missing ssh target",
			args:     []string{"--interactive-tty", "--prepare-summary-path"},
			required: []string{"recovery-session vault-workload-auth-bootstrap --prepare-summary-path requires --ssh-target <target>", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "prepare config readability missing ssh target and tty",
			args:     []string{"--prepare-config-readability"},
			required: []string{"recovery-session vault-workload-auth-bootstrap --prepare-config-readability requires --ssh-target <target>", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "prepare config readability missing tty",
			args:     []string{"--ssh-target", "host", "--prepare-config-readability"},
			required: []string{"recovery-session vault-workload-auth-bootstrap --prepare-config-readability requires --interactive-tty", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "prepare config readability missing ssh target",
			args:     []string{"--interactive-tty", "--prepare-config-readability"},
			required: []string{"recovery-session vault-workload-auth-bootstrap --prepare-config-readability requires --ssh-target <target>", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "prepare spire bundle read missing ssh target and tty",
			args:     []string{"--prepare-spire-bundle-read"},
			required: []string{"recovery-session vault-workload-auth-bootstrap --prepare-spire-bundle-read requires --ssh-target <target>", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "prepare spire bundle read missing tty",
			args:     []string{"--ssh-target", "host", "--prepare-spire-bundle-read"},
			required: []string{"recovery-session vault-workload-auth-bootstrap --prepare-spire-bundle-read requires --interactive-tty", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "prepare spire bundle read missing ssh target",
			args:     []string{"--interactive-tty", "--prepare-spire-bundle-read"},
			required: []string{"recovery-session vault-workload-auth-bootstrap --prepare-spire-bundle-read requires --ssh-target <target>", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "host local",
			args:     []string{"--host-local"},
			required: []string{"recovery-session vault-workload-auth-bootstrap forbids --host-local", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "execute reset",
			args:     []string{"--execute-reset"},
			required: []string{"recovery-session vault-workload-auth-bootstrap forbids --execute-reset", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "dry run",
			args:     []string{"--dry-run"},
			required: []string{"recovery-session vault-workload-auth-bootstrap forbids --dry-run", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "unseal only",
			args:     []string{"--unseal-only"},
			required: []string{"recovery-session vault-workload-auth-bootstrap forbids --unseal-only", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "post unseal",
			args:     []string{"--post-unseal-check"},
			required: []string{"recovery-session vault-workload-auth-bootstrap forbids --post-unseal-check", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "apply",
			args:     []string{"--apply"},
			required: []string{"recovery-session vault-workload-auth-bootstrap forbids --apply", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "governed smoke",
			args:     []string{"--governed-smoke-command", "echo hi"},
			required: []string{"recovery-session vault-workload-auth-bootstrap forbids --governed-smoke-command", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "helper override",
			args:     []string{"--vault-role", "other"},
			required: []string{"forbids helper override flag --vault-role", "fixed documented bootstrap values", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "proof value",
			args:     []string{"--proof-secret-value", "dummy"},
			required: []string{"forbids proof secret value flag --proof-secret-value", "proof secret values must never be passed", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "unknown flag",
			args:     []string{"--unknown-flag"},
			required: []string{"unknown option for recovery-session vault-workload-auth-bootstrap: --unknown-flag", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "equals form",
			args:     []string{"--plan=true"},
			required: []string{"recovery-session vault-workload-auth-bootstrap does not accept equals-form options: --plan=true", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "positional",
			args:     []string{"unexpected"},
			required: []string{"unexpected positional argument for recovery-session vault-workload-auth-bootstrap: unexpected", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "duplicate mode",
			args:     []string{"--plan", "--inventory"},
			required: []string{"duplicate option for recovery-session: --inventory", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "duplicate prepare summary path",
			args:     []string{"--ssh-target", "host", "--prepare-summary-path", "--prepare-summary-path", "--interactive-tty"},
			required: []string{"duplicate option for recovery-session: --prepare-summary-path", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "duplicate prepare config readability",
			args:     []string{"--ssh-target", "host", "--prepare-config-readability", "--prepare-config-readability", "--interactive-tty"},
			required: []string{"duplicate option for recovery-session: --prepare-config-readability", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "duplicate prepare spire bundle read",
			args:     []string{"--ssh-target", "host", "--prepare-spire-bundle-read", "--prepare-spire-bundle-read", "--interactive-tty"},
			required: []string{"duplicate option for recovery-session: --prepare-spire-bundle-read", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "safe mode with prepare config readability",
			args:     []string{"--plan", "--prepare-config-readability"},
			required: []string{"safe modes are mutually exclusive with --execute-bootstrap, --prepare-summary-path, --prepare-config-readability, and --prepare-spire-bundle-read", "No recovery-session live helper or IM execution occurred."},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			output := requireRemoteAlphaOperatorFailure(t, append([]string{"recovery-session", "vault-workload-auth-bootstrap"}, tc.args...)...)
			assertRemoteAlphaOperatorUnsafeRefusal(t, "vault-workload-auth-bootstrap refusal", output, tc.args, tc.required)
			assertContainsNone(t, "vault-workload-auth-bootstrap refusal", output,
				"Remote Alpha Vault workload-auth bootstrap plan (P0o print-only)",
				"Remote Alpha Vault workload-auth bootstrap plan (P0q safe modes plus staged execution)",
				"Running Mac-side Vault workload-auth evidence check",
				"remote_alpha_vault_workload_auth_check.sh",
			)
		})
	}
}

func TestRemoteAlphaOperatorRecoverySessionVaultWorkloadAuthBootstrapRejectsSecretLikeArgsBeforePlanning(t *testing.T) {
	for _, args := range [][]string{
		{"--root-token", "dummy"},
		{"--unseal-key", "dummy"},
		{"--client-token", "dummy"},
		{"--vault-token", "dummy"},
		{"--api-key", "dummy"},
		{"--api-key=dummy"},
		{"--jwt-svid", "dummy"},
		{"--private-key", "dummy"},
		{"--password", "dummy"},
		{"--secret", "dummy"},
	} {
		t.Run(strings.Join(args, "_"), func(t *testing.T) {
			output := requireRemoteAlphaOperatorFailure(t, append([]string{"recovery-session", "vault-workload-auth-bootstrap"}, args...)...)
			assertContainsAll(t, "vault-workload-auth-bootstrap secret flag refusal", output,
				"secret material must never be passed by CLI args/env/logs/reports/artifacts",
			)
			assertContainsNone(t, "vault-workload-auth-bootstrap secret flag refusal", output,
				"Remote Alpha Vault workload-auth bootstrap plan (P0o print-only)",
				"Remote Alpha Vault workload-auth bootstrap plan (P0q safe modes plus staged execution)",
				"Remote Alpha Vault workload-auth bootstrap inventory",
			)
		})
	}
}

func TestRemoteAlphaOperatorRecoverySessionVaultResetDisposableExecuteResetRejectsSecretLikeArgsBeforeDelegation(t *testing.T) {
	for _, args := range [][]string{
		{"--api-key=dummy"},
		{"--root-token", "dummy"},
		{"--unseal-key", "dummy"},
		{"--vault-token", "dummy"},
		{"--client-token", "dummy"},
		{"--jwt-svid", "dummy"},
		{"--private-key", "dummy"},
		{"--password", "dummy"},
		{"--secret", "dummy"},
	} {
		t.Run(strings.Join(args, "_"), func(t *testing.T) {
			routeArgs := append([]string{
				"recovery-session", "vault-reset-disposable",
				"--ssh-target", "host",
				"--execute-reset",
				"--interactive-tty",
			}, args...)
			output := requireRemoteAlphaOperatorFailure(t, routeArgs...)
			assertContainsAll(t, "vault-reset-disposable execute secret flag refusal", output,
				"secret material must never be passed by CLI args/env/logs/reports/artifacts",
			)
			assertContainsNone(t, "vault-reset-disposable execute secret flag refusal", output,
				"Running Mac-side disposable Vault execute-reset",
				"remote_alpha_reset_disposable_vault.sh --execute-reset",
			)
		})
	}
}

type fakeRemoteAlphaUnsealHarness struct {
	localBin   string
	remoteBin  string
	remoteRoot string
	sshLogPath string
	scpLogPath string
	rmLogPath  string
	helperLog  string
}

func setupFakeRemoteAlphaUnsealHarness(t *testing.T) *fakeRemoteAlphaUnsealHarness {
	t.Helper()

	tmpDir := t.TempDir()
	h := &fakeRemoteAlphaUnsealHarness{
		localBin:   filepath.Join(tmpDir, "local-bin"),
		remoteBin:  filepath.Join(tmpDir, "remote-bin"),
		remoteRoot: filepath.Join(tmpDir, "remote-root"),
		sshLogPath: filepath.Join(tmpDir, "ssh.log"),
		scpLogPath: filepath.Join(tmpDir, "scp.log"),
		rmLogPath:  filepath.Join(tmpDir, "rm.log"),
		helperLog:  filepath.Join(tmpDir, "helper.log"),
	}
	for _, dir := range []string{h.localBin, h.remoteBin, h.remoteRoot} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", dir, err)
		}
	}
	mkdirFakeRemoteAlphaHostTmp(t, h.remoteRoot)

	writeExecutable(t, h.localBin, "ssh", fmt.Sprintf(`#!/usr/bin/env bash
set -euo pipefail
tty=false
while [[ "${1:-}" == "-tt" ]]; do
  tty=true
  shift
done
target="${1:-}"
shift || true
printf 'tty=%%s target=%%s args=%%s\n' "${tty}" "${target}" "$*" >> %q
export PATH="${FAKE_REMOTE_BIN}:${PATH}"
if [[ "${1:-}" == "/bin/bash" && "${2:-}" == "-s" ]]; then
  shift 2
  if [[ "${1:-}" == "--" ]]; then
    shift
  fi
  mapped_args=()
  for arg in "$@"; do
    if [[ "${arg}" == /* ]]; then
      mapped_args+=("${FAKE_REMOTE_ROOT}${arg}")
    else
      mapped_args+=("${arg}")
    fi
  done
  payload="$(mktemp)"
  cat >"${payload}"
  set +e
  /bin/bash "${payload}" "${mapped_args[@]}"
  status=$?
  set -e
  rm -f -- "${payload}"
  exit "${status}"
fi
if [[ "${1:-}" == "/bin/bash" && "${2:-}" == "-c" ]]; then
  command_string="${3:-}"
  remote_prefix="/tmp/execution-substrate-remote-alpha-vault-unseal-existing"
  mapped_prefix="${FAKE_REMOTE_ROOT}${remote_prefix}"
  mapped_command="${command_string//${remote_prefix}/${mapped_prefix}}"
  exec /bin/bash -c "${mapped_command}"
fi
if [[ "$#" -eq 1 && "${1:-}" == exec\ /bin/bash\ -c* ]]; then
  command_string="${1}"
  remote_prefix="/tmp/execution-substrate-remote-alpha-vault-unseal-existing"
  mapped_prefix="${FAKE_REMOTE_ROOT}${remote_prefix}"
  mapped_command="${command_string//${remote_prefix}/${mapped_prefix}}"
  exec /bin/bash -c "${mapped_command}"
fi
echo "unexpected fake ssh invocation: $*" >&2
exit 64
`, h.sshLogPath))

	writeExecutable(t, h.localBin, "scp", fmt.Sprintf(`#!/usr/bin/env bash
set -euo pipefail
if [[ "$#" -ne 2 ]]; then
  echo "unexpected fake scp args: $*" >&2
  exit 64
fi
src=$1
dest=$2
printf '%%s\t%%s\n' "${src}" "${dest}" >> %q
if [[ "${src}" == *:* || "${dest}" != *:* ]]; then
  echo "fake scp supports one local-to-remote helper upload" >&2
  exit 64
fi
remote_path="${dest#*:}"
mapped_dest="${FAKE_REMOTE_ROOT}${remote_path}"
mkdir -p -- "$(dirname "${mapped_dest}")"
cat >"${mapped_dest}" <<'REMOTE_ALPHA_FAKE_UNSEAL_HELPER'
#!/usr/bin/env bash
set -euo pipefail
printf '%%s\n' "$*" >> %q
REMOTE_ALPHA_FAKE_UNSEAL_HELPER
chmod 0700 "${mapped_dest}"
`, h.scpLogPath, h.helperLog))

	writeExecutable(t, h.remoteBin, "rm", fmt.Sprintf(`#!/usr/bin/env bash
set -euo pipefail
printf '%%s\n' "$*" >> %q
exec /bin/rm "$@"
`, h.rmLogPath))

	return h
}

func (h *fakeRemoteAlphaUnsealHarness) env() []string {
	return envWithPath(h.localBin,
		"FAKE_REMOTE_BIN="+h.remoteBin,
		"FAKE_REMOTE_ROOT="+h.remoteRoot,
	)
}

func TestRemoteAlphaOperatorRecoverySessionVaultUnsealExistingNoTTYFailsBeforeStaging(t *testing.T) {
	h := setupFakeRemoteAlphaUnsealHarness(t)
	output, err := runRemoteAlphaOperatorWithEnv(h.env(),
		"recovery-session", "vault-unseal-existing",
		"--ssh-target", "ds@m75q-test",
		"--interactive-tty",
	)
	if err == nil {
		t.Fatalf("expected no-TTY failure before staging, got success:\n%s", output)
	}
	assertContainsAll(t, "vault-unseal-existing no tty refusal", output,
		"requires visible local terminal",
		"no staging or SSH occurred",
		"No recovery-session live helper or IM execution occurred.",
	)
	if _, err := os.Stat(h.sshLogPath); !os.IsNotExist(err) {
		t.Fatalf("ssh should not run when local TTY guard fails: %v", err)
	}
	if _, err := os.Stat(h.scpLogPath); !os.IsNotExist(err) {
		t.Fatalf("scp should not run when local TTY guard fails: %v", err)
	}
}

func TestRemoteAlphaOperatorRecoverySessionVaultUnsealExistingMacSideStagesSingleHelperWithTTYAndCleanup(t *testing.T) {
	h := setupFakeRemoteAlphaUnsealHarness(t)
	before := snapshotPathExistence(t, remoteAlphaOperatorRouteArtifactPaths()...)

	output, err := runRemoteAlphaOperatorWithPTY(t, h.env(),
		"recovery-session", "vault-unseal-existing",
		"--ssh-target", "ds@m75q-test",
		"--interactive-tty",
	)
	if err != nil {
		t.Fatalf("Mac-side fake unseal route failed: %v\noutput=%s\nssh=%s\nscp=%s\nhelper=%s\nrm=%s",
			err, output, readIfExists(h.sshLogPath), readIfExists(h.scpLogPath), readIfExists(h.helperLog), readIfExists(h.rmLogPath))
	}

	assertContainsAll(t, "Mac-side fake unseal output", output,
		"Running Mac-side Vault unseal-existing through an explicit interactive SSH TTY.",
		"Staging only scripts/remote_alpha_reset_disposable_vault.sh and invoking only --unseal-only.",
		"The operator enters any unseal key directly into the visible SSH/Vault/helper prompt.",
		"staged helper cleanup was attempted",
		"Post-unseal evidence checks, IM refresh, support-bundle collection, and workload-auth checks are separate follow-up actions and were not executed here.",
	)

	scpLog := strings.TrimSpace(mustRead(t, h.scpLogPath))
	scpLines := strings.Split(scpLog, "\n")
	if len(scpLines) != 1 {
		t.Fatalf("expected exactly one staged file upload, got %q", scpLog)
	}
	assertContainsAll(t, "fake scp log", scpLog,
		filepath.Join(remoteAlphaOperatorRepoRoot(), "scripts", "remote_alpha_reset_disposable_vault.sh"),
	)
	assertContainsNone(t, "fake scp log", scpLog,
		"remote_alpha_operator.sh",
		"scripts/internal",
		"bundle",
	)

	sshLog := mustRead(t, h.sshLogPath)
	if got := strings.Count(sshLog, "tty=true"); got != 1 {
		t.Fatalf("expected exactly one interactive ssh -tt invocation, got %d log=%q", got, sshLog)
	}
	assertContainsAll(t, "fake ssh log", sshLog,
		"tty=true target=ds@m75q-test",
	)
	assertContainsNone(t, "fake ssh log forbidden capture", sshLog,
		" tee ",
		"script ",
		"transcript",
	)

	helperLog := strings.TrimSpace(mustRead(t, h.helperLog))
	if helperLog != "--unseal-only" {
		t.Fatalf("expected staged helper to receive only --unseal-only, got %q", helperLog)
	}
	assertContainsNone(t, "fake helper log forbidden modes", helperLog,
		"--execute-reset",
		"--post-unseal-check",
		"workload-auth",
		"remote-alpha-live-refresh",
		"remote-alpha-live-support-bundle",
	)

	rmLog := mustRead(t, h.rmLogPath)
	assertContainsAll(t, "fake remote cleanup log", rmLog,
		"execution-substrate-remote-alpha-vault-unseal-existing",
	)
	assertRemoteAlphaOperatorStageFoldersGone(t, h.remoteRoot, "execution-substrate-remote-alpha-vault-unseal-existing")
	assertNoNewPaths(t, "Mac-side fake unseal route", before)
}

type fakeRemoteAlphaResetDryRunHarness struct {
	localBin   string
	remoteBin  string
	remoteRoot string
	sshLogPath string
	scpLogPath string
	rmLogPath  string
	helperLog  string
}

func setupFakeRemoteAlphaResetDryRunHarness(t *testing.T) *fakeRemoteAlphaResetDryRunHarness {
	t.Helper()

	tmpDir := t.TempDir()
	h := &fakeRemoteAlphaResetDryRunHarness{
		localBin:   filepath.Join(tmpDir, "local-bin"),
		remoteBin:  filepath.Join(tmpDir, "remote-bin"),
		remoteRoot: filepath.Join(tmpDir, "remote-root"),
		sshLogPath: filepath.Join(tmpDir, "ssh.log"),
		scpLogPath: filepath.Join(tmpDir, "scp.log"),
		rmLogPath:  filepath.Join(tmpDir, "rm.log"),
		helperLog:  filepath.Join(tmpDir, "helper.log"),
	}
	for _, dir := range []string{h.localBin, h.remoteBin, h.remoteRoot} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", dir, err)
		}
	}
	mkdirFakeRemoteAlphaHostTmp(t, h.remoteRoot)

	writeExecutable(t, h.localBin, "ssh", fmt.Sprintf(`#!/usr/bin/env bash
set -euo pipefail
tty=false
while [[ "${1:-}" == "-tt" ]]; do
  tty=true
  shift
done
target="${1:-}"
shift || true
printf 'tty=%%s target=%%s args=%%s\n' "${tty}" "${target}" "$*" >> %q
export PATH="${FAKE_REMOTE_BIN}:${PATH}"
if [[ "${1:-}" == "/bin/bash" && "${2:-}" == "-s" ]]; then
  shift 2
  if [[ "${1:-}" == "--" ]]; then
    shift
  fi
  mapped_args=()
  for arg in "$@"; do
    if [[ "${arg}" == /* ]]; then
      mapped_args+=("${FAKE_REMOTE_ROOT}${arg}")
    else
      mapped_args+=("${arg}")
    fi
  done
  payload="$(mktemp)"
  cat >"${payload}"
  set +e
  /bin/bash "${payload}" "${mapped_args[@]}"
  status=$?
  set -e
  rm -f -- "${payload}"
  exit "${status}"
fi
if [[ "$#" -eq 1 && "${1:-}" == exec\ /bin/bash\ -c* ]]; then
  command_string="${1}"
  dry_run_prefix="/tmp/execution-substrate-remote-alpha-vault-reset-disposable-dry-run"
  execute_prefix="/tmp/execution-substrate-remote-alpha-vault-reset-disposable-execute"
  mapped_command="${command_string//${dry_run_prefix}/${FAKE_REMOTE_ROOT}${dry_run_prefix}}"
  mapped_command="${mapped_command//${execute_prefix}/${FAKE_REMOTE_ROOT}${execute_prefix}}"
  exec /bin/bash -c "${mapped_command}"
fi
echo "unexpected fake ssh invocation: $*" >&2
exit 64
`, h.sshLogPath))

	writeExecutable(t, h.localBin, "scp", fmt.Sprintf(`#!/usr/bin/env bash
set -euo pipefail
if [[ "$#" -ne 2 ]]; then
  echo "unexpected fake scp args: $*" >&2
  exit 64
fi
src=$1
dest=$2
printf '%%s\t%%s\n' "${src}" "${dest}" >> %q
if [[ "${src}" == *:* || "${dest}" != *:* ]]; then
  echo "fake scp supports one local-to-remote helper upload" >&2
  exit 64
fi
remote_path="${dest#*:}"
mapped_dest="${FAKE_REMOTE_ROOT}${remote_path}"
mkdir -p -- "$(dirname "${mapped_dest}")"
cat >"${mapped_dest}" <<'REMOTE_ALPHA_FAKE_RESET_DRY_RUN_HELPER'
#!/usr/bin/env bash
set -euo pipefail
printf '%%s\n' "$*" >> %q
REMOTE_ALPHA_FAKE_RESET_DRY_RUN_HELPER
chmod 0700 "${mapped_dest}"
`, h.scpLogPath, h.helperLog))

	writeExecutable(t, h.remoteBin, "rm", fmt.Sprintf(`#!/usr/bin/env bash
set -euo pipefail
printf '%%s\n' "$*" >> %q
exec /bin/rm "$@"
`, h.rmLogPath))

	return h
}

func (h *fakeRemoteAlphaResetDryRunHarness) env() []string {
	return envWithPath(h.localBin,
		"FAKE_REMOTE_BIN="+h.remoteBin,
		"FAKE_REMOTE_ROOT="+h.remoteRoot,
	)
}

func TestRemoteAlphaOperatorRecoverySessionVaultResetDisposableMacSideDryRunStagesSingleHelperAndCleanup(t *testing.T) {
	h := setupFakeRemoteAlphaResetDryRunHarness(t)
	before := snapshotPathExistence(t, remoteAlphaOperatorRouteArtifactPaths()...)

	output, err := runRemoteAlphaOperatorWithEnv(h.env(),
		"recovery-session", "vault-reset-disposable",
		"--ssh-target", "ds@m75q-test",
		"--dry-run",
	)
	if err != nil {
		t.Fatalf("Mac-side fake reset dry-run route failed: %v\noutput=%s\nssh=%s\nscp=%s\nhelper=%s\nrm=%s",
			err, output, readIfExists(h.sshLogPath), readIfExists(h.scpLogPath), readIfExists(h.helperLog), readIfExists(h.rmLogPath))
	}

	assertContainsAll(t, "Mac-side fake reset dry-run output", output,
		"Running Mac-side disposable Vault reset dry-run planning route.",
		"Staging only scripts/remote_alpha_reset_disposable_vault.sh and invoking only --dry-run.",
		"This route is non-destructive",
		"does not stop Vault, move raft storage, init or unseal Vault, run post-unseal checks, run workload-auth checks, run IM, or collect support bundles",
		"No transcript, tee/script capture, .out, report, support bundle, operator summary, or generated JSON is created.",
		"staged helper cleanup was attempted",
		"Execute-reset is a separate destructive exact-phrase route; IM refresh and support-bundle collection were not executed here.",
	)

	scpLog := strings.TrimSpace(mustRead(t, h.scpLogPath))
	scpLines := strings.Split(scpLog, "\n")
	if len(scpLines) != 1 {
		t.Fatalf("expected exactly one staged file upload, got %q", scpLog)
	}
	assertContainsAll(t, "fake reset dry-run scp log", scpLog,
		filepath.Join(remoteAlphaOperatorRepoRoot(), "scripts", "remote_alpha_reset_disposable_vault.sh"),
	)
	assertContainsNone(t, "fake reset dry-run scp log", scpLog,
		"remote_alpha_operator.sh",
		"scripts/internal",
		"bundle",
	)

	sshLog := mustRead(t, h.sshLogPath)
	if strings.Contains(sshLog, "tty=true") {
		t.Fatalf("dry-run route must not allocate an interactive TTY, log=%q", sshLog)
	}
	assertContainsAll(t, "fake reset dry-run ssh log", sshLog,
		"tty=false target=ds@m75q-test",
	)
	assertContainsNone(t, "fake reset dry-run ssh log forbidden capture", sshLog,
		" tee ",
		"script ",
		"transcript",
		".out",
	)

	helperLog := strings.TrimSpace(mustRead(t, h.helperLog))
	if helperLog != "--dry-run" {
		t.Fatalf("expected staged helper to receive only --dry-run, got %q", helperLog)
	}
	assertContainsNone(t, "fake reset dry-run helper log forbidden modes", helperLog,
		"--execute-reset",
		"--unseal-only",
		"--post-unseal-check",
		"workload-auth",
		"remote-alpha-live-refresh",
		"remote-alpha-live-support-bundle",
	)

	rmLog := mustRead(t, h.rmLogPath)
	assertContainsAll(t, "fake reset dry-run remote cleanup log", rmLog,
		"execution-substrate-remote-alpha-vault-reset-disposable-dry-run",
	)
	assertRemoteAlphaOperatorStageFoldersGone(t, h.remoteRoot, "execution-substrate-remote-alpha-vault-reset-disposable-dry-run")
	assertNoNewPaths(t, "Mac-side fake reset dry-run route", before)
}

func TestRemoteAlphaOperatorRecoverySessionVaultResetDisposableExecuteResetNoTTYFailsBeforeStaging(t *testing.T) {
	h := setupFakeRemoteAlphaResetDryRunHarness(t)
	output, err := runRemoteAlphaOperatorWithEnv(h.env(),
		"recovery-session", "vault-reset-disposable",
		"--ssh-target", "ds@m75q-test",
		"--execute-reset",
		"--interactive-tty",
	)
	if err == nil {
		t.Fatalf("expected no-TTY failure before execute-reset staging, got success:\n%s", output)
	}
	assertContainsAll(t, "vault-reset-disposable execute no tty refusal", output,
		"requires visible local terminal",
		"no staging or SSH occurred",
		"No recovery-session live helper or IM execution occurred.",
	)
	if _, err := os.Stat(h.sshLogPath); !os.IsNotExist(err) {
		t.Fatalf("ssh should not run when execute-reset local TTY guard fails: %v", err)
	}
	if _, err := os.Stat(h.scpLogPath); !os.IsNotExist(err) {
		t.Fatalf("scp should not run when execute-reset local TTY guard fails: %v", err)
	}
}

func TestRemoteAlphaOperatorRecoverySessionVaultResetDisposableExecuteResetStagesSingleHelperWithTTYAndCleanup(t *testing.T) {
	h := setupFakeRemoteAlphaResetDryRunHarness(t)
	before := snapshotPathExistence(t, remoteAlphaOperatorRouteArtifactPaths()...)

	output, err := runRemoteAlphaOperatorWithPTY(t, h.env(),
		"recovery-session", "vault-reset-disposable",
		"--ssh-target", "ds@m75q-test",
		"--execute-reset",
		"--interactive-tty",
	)
	if err != nil {
		t.Fatalf("Mac-side fake reset execute route failed: %v\noutput=%s\nssh=%s\nscp=%s\nhelper=%s\nrm=%s",
			err, output, readIfExists(h.sshLogPath), readIfExists(h.scpLogPath), readIfExists(h.helperLog), readIfExists(h.rmLogPath))
	}

	assertContainsAll(t, "Mac-side fake reset execute output", output,
		"Running Mac-side disposable Vault execute-reset through an explicit interactive SSH TTY.",
		"Staging only scripts/remote_alpha_reset_disposable_vault.sh and invoking only --execute-reset.",
		"destructive for disposable Remote Alpha Vault state",
		"The operator handles confirmation, Vault init output, root token, unseal key, and Vault prompts only in the visible SSH/Vault/helper terminal.",
		"The operator facade will not read, log, relay, persist, summarize, or capture the confirmation phrase or secret material.",
		"No transcript, tee/script capture, .out, report, support bundle, operator summary, generated JSON, post-unseal check, workload-auth check, runtime identity summary, IM refresh, or CP proof is created or run.",
		"staged helper cleanup was attempted",
		"Post-reset evidence checks, post-unseal checks, workload-auth checks, runtime identity summaries, IM refresh, support-bundle collection, and CP proof were not executed here.",
	)
	assertContainsNone(t, "Mac-side fake reset execute output must not print phrase", output,
		"RESET DISPOSABLE REMOTE ALPHA VAULT",
	)

	scpLog := strings.TrimSpace(mustRead(t, h.scpLogPath))
	scpLines := strings.Split(scpLog, "\n")
	if len(scpLines) != 1 {
		t.Fatalf("expected exactly one staged file upload, got %q", scpLog)
	}
	assertContainsAll(t, "fake reset execute scp log", scpLog,
		filepath.Join(remoteAlphaOperatorRepoRoot(), "scripts", "remote_alpha_reset_disposable_vault.sh"),
	)
	assertContainsNone(t, "fake reset execute scp log", scpLog,
		"remote_alpha_operator.sh",
		"scripts/internal",
		"bundle",
	)

	sshLog := mustRead(t, h.sshLogPath)
	if got := strings.Count(sshLog, "tty=true"); got != 1 {
		t.Fatalf("expected exactly one interactive ssh -tt invocation, got %d log=%q", got, sshLog)
	}
	assertContainsAll(t, "fake reset execute ssh log", sshLog,
		"tty=true target=ds@m75q-test",
	)
	assertContainsNone(t, "fake reset execute ssh log forbidden capture", sshLog,
		" tee ",
		"script ",
		"transcript",
		".out",
	)

	helperLog := strings.TrimSpace(mustRead(t, h.helperLog))
	if helperLog != "--execute-reset" {
		t.Fatalf("expected staged helper to receive only --execute-reset, got %q", helperLog)
	}
	assertContainsNone(t, "fake reset execute helper log forbidden modes", helperLog,
		"--dry-run",
		"--unseal-only",
		"--post-unseal-check",
		"workload-auth",
		"remote-alpha-live-refresh",
		"remote-alpha-live-support-bundle",
	)

	rmLog := mustRead(t, h.rmLogPath)
	assertContainsAll(t, "fake reset execute remote cleanup log", rmLog,
		"execution-substrate-remote-alpha-vault-reset-disposable-execute",
	)
	assertRemoteAlphaOperatorStageFoldersGone(t, h.remoteRoot, "execution-substrate-remote-alpha-vault-reset-disposable-execute")
	assertNoNewPaths(t, "Mac-side fake reset execute route", before)
}

type fakeRemoteAlphaESServiceTLSHarness struct {
	localBin   string
	remoteBin  string
	remoteRoot string
	sshLogPath string
	scpLogPath string
	rmLogPath  string
	sudoLog    string
	helperLog  string
}

func setupFakeRemoteAlphaESServiceTLSHarness(t *testing.T) *fakeRemoteAlphaESServiceTLSHarness {
	t.Helper()

	tmpDir := t.TempDir()
	h := &fakeRemoteAlphaESServiceTLSHarness{
		localBin:   filepath.Join(tmpDir, "local-bin"),
		remoteBin:  filepath.Join(tmpDir, "remote-bin"),
		remoteRoot: filepath.Join(tmpDir, "remote-root"),
		sshLogPath: filepath.Join(tmpDir, "ssh.log"),
		scpLogPath: filepath.Join(tmpDir, "scp.log"),
		rmLogPath:  filepath.Join(tmpDir, "rm.log"),
		sudoLog:    filepath.Join(tmpDir, "sudo.log"),
		helperLog:  filepath.Join(tmpDir, "helper.log"),
	}
	for _, dir := range []string{h.localBin, h.remoteBin, h.remoteRoot} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", dir, err)
		}
	}
	mkdirFakeRemoteAlphaHostTmp(t, h.remoteRoot)

	writeExecutable(t, h.localBin, "ssh", fmt.Sprintf(`#!/usr/bin/env bash
set -euo pipefail
tty=false
while [[ "${1:-}" == "-tt" ]]; do
  tty=true
  shift
done
target="${1:-}"
shift || true
printf 'tty=%%s target=%%s args=%%s\n' "${tty}" "${target}" "$*" >> %q
export PATH="${FAKE_REMOTE_BIN}:${PATH}"
if [[ "${1:-}" == "/bin/bash" && "${2:-}" == "-s" ]]; then
  shift 2
  if [[ "${1:-}" == "--" ]]; then
    shift
  fi
  mapped_args=()
  for arg in "$@"; do
    if [[ "${arg}" == /* ]]; then
      mapped_args+=("${FAKE_REMOTE_ROOT}${arg}")
    else
      mapped_args+=("${arg}")
    fi
  done
  payload="$(mktemp)"
  cat >"${payload}"
  set +e
  /bin/bash "${payload}" "${mapped_args[@]}"
  status=$?
  set -e
  rm -f -- "${payload}"
  exit "${status}"
fi
if [[ "$#" -eq 1 && "${1:-}" == exec\ /bin/bash\ -c* ]]; then
  command_string="${1}"
  tls_prefix="/tmp/execution-substrate-remote-alpha-es-service-tls-renew"
  mapped_command="${command_string//${tls_prefix}/${FAKE_REMOTE_ROOT}${tls_prefix}}"
  governance_tls_prefix="/tmp/execution-substrate-remote-alpha-es-governance-tls-renew"
  mapped_command="${mapped_command//${governance_tls_prefix}/${FAKE_REMOTE_ROOT}${governance_tls_prefix}}"
  operator_healthcheck_tls_prefix="/tmp/execution-substrate-remote-alpha-operator-healthcheck-tls-renew"
  mapped_command="${mapped_command//${operator_healthcheck_tls_prefix}/${FAKE_REMOTE_ROOT}${operator_healthcheck_tls_prefix}}"
  exec /bin/bash -c "${mapped_command}"
fi
echo "unexpected fake ssh invocation: $*" >&2
exit 64
`, h.sshLogPath))

	writeExecutable(t, h.localBin, "scp", fmt.Sprintf(`#!/usr/bin/env bash
set -euo pipefail
if [[ "$#" -ne 2 ]]; then
  echo "unexpected fake scp args: $*" >&2
  exit 64
fi
src=$1
dest=$2
printf '%%s\t%%s\n' "${src}" "${dest}" >> %q
if [[ "${src}" == *:* || "${dest}" != *:* ]]; then
  echo "fake scp supports one local-to-remote upload" >&2
  exit 64
fi
remote_path="${dest#*:}"
mapped_dest="${FAKE_REMOTE_ROOT}${remote_path}"
mkdir -p -- "$(dirname "${mapped_dest}")"
if [[ "${src}" == */scripts/internal/remote_alpha_es_service_tls_renew.sh ]]; then
  cat >"${mapped_dest}" <<'REMOTE_ALPHA_FAKE_ES_SERVICE_TLS_INTERNAL'
# fake ES service TLS internal helper staged for layout verification
REMOTE_ALPHA_FAKE_ES_SERVICE_TLS_INTERNAL
elif [[ "${src}" == */scripts/internal/remote_alpha_operator_healthcheck_tls_renew.sh ]]; then
  cat >"${mapped_dest}" <<'REMOTE_ALPHA_FAKE_OPERATOR_HEALTHCHECK_TLS_INTERNAL'
# fake operator healthcheck TLS internal helper staged for layout verification
REMOTE_ALPHA_FAKE_OPERATOR_HEALTHCHECK_TLS_INTERNAL
elif [[ "$(basename "${src}")" == "remote_alpha_operator_healthcheck_tls_renew.sh" ]]; then
  cat >"${mapped_dest}" <<'REMOTE_ALPHA_FAKE_OPERATOR_HEALTHCHECK_TLS_PUBLIC'
#!/usr/bin/env bash
set -euo pipefail
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
internal="${script_dir}/internal/remote_alpha_operator_healthcheck_tls_renew.sh"
if [[ ! -f "${internal}" ]]; then
  echo "missing internal helper: ${internal}" >&2
  exit 65
fi
printf 'public_args=%%s\n' "$*" >> %q
printf 'internal=%%s\n' "${internal}" >> %q
printf 'Remote Alpha operator healthcheck TLS helper finished.\n'
printf 'Remote summary path: /var/tmp/execution-substrate-remote-alpha/operator-healthcheck-tls-renew-summary.json\n'
printf 'IM refresh, support-bundle collection, CP proof, Vault, SPIRE, Nomad, reset/unseal, workload-auth, runtime identity, and ES restart were not run.\n'
REMOTE_ALPHA_FAKE_OPERATOR_HEALTHCHECK_TLS_PUBLIC
elif [[ "$(basename "${src}")" == "remote_alpha_es_service_tls_renew.sh" ]]; then
  cat >"${mapped_dest}" <<'REMOTE_ALPHA_FAKE_ES_SERVICE_TLS_PUBLIC'
#!/usr/bin/env bash
set -euo pipefail
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
internal="${script_dir}/internal/remote_alpha_es_service_tls_renew.sh"
if [[ ! -f "${internal}" ]]; then
  echo "missing internal helper: ${internal}" >&2
  exit 65
fi
printf 'public_args=%%s\n' "$*" >> %q
printf 'internal=%%s\n' "${internal}" >> %q
printf 'Remote Alpha ES service TLS helper finished.\n'
if [[ "$*" == *"execution-governance"* ]]; then
  printf 'Remote summary path: /var/tmp/execution-substrate-remote-alpha/es-governance-tls-renew-summary.json\n'
else
  printf 'Remote summary path: /var/tmp/execution-substrate-remote-alpha/es-service-tls-renew-summary.json\n'
fi
printf 'IM refresh, support-bundle collection, CP proof, Vault, SPIRE, Nomad, reset/unseal, workload-auth, and runtime identity were not run.\n'
REMOTE_ALPHA_FAKE_ES_SERVICE_TLS_PUBLIC
else
  echo "unexpected fake scp source: ${src}" >&2
  exit 64
fi
chmod 0700 "${mapped_dest}"
`, h.scpLogPath, h.helperLog, h.helperLog, h.helperLog, h.helperLog))

	writeExecutable(t, h.remoteBin, "id", `#!/usr/bin/env bash
set -euo pipefail
if [[ "${1:-}" == "-u" ]]; then
  echo 1000
  exit 0
fi
exec /usr/bin/id "$@"
`)
	writeExecutable(t, h.remoteBin, "sudo", fmt.Sprintf(`#!/usr/bin/env bash
set -euo pipefail
printf 'sudo_args=%%s\n' "$*" >> %q
exec "$@"
`, h.sudoLog))
	writeExecutable(t, h.remoteBin, "rm", fmt.Sprintf(`#!/usr/bin/env bash
set -euo pipefail
printf '%%s\n' "$*" >> %q
exec /bin/rm "$@"
`, h.rmLogPath))

	return h
}

func (h *fakeRemoteAlphaESServiceTLSHarness) env() []string {
	return envWithPath(h.localBin,
		"FAKE_REMOTE_BIN="+h.remoteBin,
		"FAKE_REMOTE_ROOT="+h.remoteRoot,
	)
}

type fakeRemoteAlphaESTLSStatusHarness struct {
	localBin  string
	sshLog    string
	sshArgv   string
	scpLog    string
	stageRoot string
}

func setupFakeRemoteAlphaESTLSStatusHarness(t *testing.T) *fakeRemoteAlphaESTLSStatusHarness {
	t.Helper()
	root := t.TempDir()
	h := &fakeRemoteAlphaESTLSStatusHarness{
		localBin:  filepath.Join(root, "bin"),
		sshLog:    filepath.Join(root, "ssh.log"),
		sshArgv:   filepath.Join(root, "ssh-argv.bin"),
		scpLog:    filepath.Join(root, "scp.log"),
		stageRoot: filepath.Join(root, "stages"),
	}
	if err := os.MkdirAll(h.localBin, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(h.stageRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	writeExecutable(t, h.localBin, "ssh", fmt.Sprintf(`#!/usr/bin/env bash
set -euo pipefail
if [[ "${1:-}" == -tt ]]; then
  [[ "$#" -eq 3 && "${2:-}" == ds@m75q-test && -t 0 ]] || exit 64
  printf '%%s\0' "$@" > "$FAKE_STATUS_SSH_ARGV"
  remote_command=$3
  [[ "$remote_command" =~ /tmp/\.es-tls-status-[0-9a-f]{32} ]] || exit 64
  stage_dir=${BASH_REMATCH[0]}
  stage="$FAKE_STATUS_STAGE_ROOT/$(/usr/bin/basename "$stage_dir")"
  printf 'COLLECT_WRAPPER\n' >> %q
  [[ "${FAKE_STATUS_WRAPPER_FAIL:-0}" != 1 ]] || exit 1
  if [[ "${FAKE_STATUS_PROMPT_MODE:-none}" != none ]]; then
    [[ "${FAKE_STATUS_PROMPT_MODE}" != before_prompt ]] || exit 1
    printf 'FAKE_SUDO_PASSWORD_PROMPT: ' >&2
    if ! IFS= read -r reply; then exit 1; fi
    [[ "$reply" =~ ^[0-9a-f]{32}$ ]] || exit 1
    unset reply
    [[ "${FAKE_STATUS_PROMPT_MODE}" != refuse ]] || exit 1
    printf 'PROMPT_READ\n' >> %q
  fi
  /bin/rm -- "$stage/remote_alpha_es_tls_status.py"
  /bin/rmdir -- "$stage"
  [[ "${FAKE_STATUS_PROMPT_MODE:-none}" != remote_nonzero ]] || exit 12
else
  printf 'ARGS:%%s\n' "$*" >> %q
  cat >> %q
  stage_dir=${@: -1}
  [[ "$stage_dir" == /tmp/.es-tls-status-* ]] || exit 64
  stage="$FAKE_STATUS_STAGE_ROOT/$(/usr/bin/basename "$stage_dir")"
  printf 'STAGE_CREATE\n' >> %q
  [[ "${FAKE_STATUS_STAGE_CREATE_FAIL:-0}" != 1 ]] || exit 1
  /bin/mkdir -m 0700 -- "$stage"
  printf '%%s\n' "${FAKE_STATUS_STAGE_OUTPUT:-123:456}"
fi
`, h.sshLog, h.sshLog, h.sshLog, h.sshLog, h.sshLog))
	writeExecutable(t, h.localBin, "scp", fmt.Sprintf(`#!/usr/bin/env bash
set -euo pipefail
printf '%%s\n' "$*" >> %q
remote="${2#*:}"
stage_dir="$(/usr/bin/dirname "$remote")"
stage="$FAKE_STATUS_STAGE_ROOT/$(/usr/bin/basename "$stage_dir")"
[[ "${FAKE_STATUS_UPLOAD_FAIL:-0}" != 1 ]] || exit 1
/bin/cp -- "$1" "$stage/remote_alpha_es_tls_status.py"
`, h.scpLog))
	return h
}

func (h *fakeRemoteAlphaESTLSStatusHarness) env() []string {
	return envWithPath(h.localBin,
		"FAKE_STATUS_STAGE_ROOT="+h.stageRoot,
		"FAKE_STATUS_SSH_ARGV="+h.sshArgv,
		"FAKE_STATUS_SSH_LOG="+h.sshLog,
		"FAKE_STATUS_SCP_LOG="+h.scpLog)
}

func statusSSHCommandTokens(t *testing.T, h *fakeRemoteAlphaESTLSStatusHarness) []string {
	t.Helper()
	raw, err := os.ReadFile(h.sshArgv)
	if err != nil {
		t.Fatalf("read captured SSH argv: %v", err)
	}
	argv := strings.Split(string(raw), "\x00")
	if len(argv) != 4 || argv[0] != "-tt" || argv[1] != "ds@m75q-test" || argv[3] != "" {
		t.Fatal("status SSH argv has unexpected shape")
	}
	parser := exec.Command("/usr/bin/python3", "-I", "-B", "-c",
		"import json,shlex,sys; print(json.dumps(shlex.split(sys.stdin.read())))")
	parser.Dir = executionSubstrateRepoRoot
	parser.Stdin = strings.NewReader(argv[2])
	decoded, err := parser.Output()
	if err != nil {
		t.Fatalf("parse fixed remote command: %v", err)
	}
	var tokens []string
	if err := json.Unmarshal(decoded, &tokens); err != nil {
		t.Fatalf("decode fixed remote command tokens: %v", err)
	}
	if len(tokens) != 8 || tokens[0] != "/bin/bash" || tokens[1] != "-c" || tokens[3] != "--" {
		t.Fatal("fixed remote command does not invoke Bash with exact operands")
	}
	if len(argv[2]) > 32768 {
		t.Fatal("fixed remote command exceeded the documented byte bound")
	}
	return tokens
}

func assertStatusFixedRemoteCommand(t *testing.T, h *fakeRemoteAlphaESTLSStatusHarness, scope string) {
	t.Helper()
	tokens := statusSSHCommandTokens(t, h)
	source := mustRead(t, remoteAlphaOperatorScriptPath())
	const opening = "IFS= read -r -d '' wrapper <<'REMOTE_ALPHA_ES_TLS_STATUS_REMOTE_WRAPPER' || true\n"
	const closing = "\nREMOTE_ALPHA_ES_TLS_STATUS_REMOTE_WRAPPER\n"
	start := strings.Index(source, opening)
	if start < 0 {
		t.Fatal("fixed remote wrapper source missing")
	}
	start += len(opening)
	end := strings.Index(source[start:], closing)
	if end < 0 || tokens[2] != source[start:start+end+1] {
		t.Fatal("remote command program differs from the fixed source-controlled wrapper")
	}
	if !regexp.MustCompile(`^/tmp/\.es-tls-status-[0-9a-f]{32}$`).MatchString(tokens[4]) ||
		tokens[5] != "123:456" || tokens[6] != scope {
		t.Fatal("remote command stage, custody identity, or scope boundaries changed")
	}
	collector, err := os.ReadFile(filepath.Join(executionSubstrateRepoRoot,
		"scripts", "internal", "remote_alpha_es_tls_status.py"))
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(collector)
	if tokens[7] != hex.EncodeToString(digest[:]) {
		t.Fatal("remote command collector digest differs from fixed local source")
	}
}

func TestRemoteAlphaOperatorRecoverySessionESServiceTLSStatusStagesOnlyCollector(t *testing.T) {
	h := setupFakeRemoteAlphaESTLSStatusHarness(t)
	output, err := runRemoteAlphaOperatorWithPTY(t, h.env(),
		"recovery-session", "es-service-tls-status", "--ssh-target", "ds@m75q-test", "--interactive-tty")
	if err != nil {
		t.Fatalf("fake P0s status route failed: %v\n%s", err, output)
	}
	scp := mustRead(t, h.scpLog)
	if strings.Count(strings.TrimSpace(scp), "\n") != 0 {
		t.Fatalf("expected exactly one staged collector: %q", scp)
	}
	assertContainsAll(t, "P0s collector staging", scp, "scripts/internal/remote_alpha_es_tls_status.py")
	assertContainsNone(t, "P0s collector staging", scp, "remote_alpha_es_service_tls_renew.sh")
	assertStatusFixedRemoteCommand(t, h, "artifact-registry")
	ssh := mustRead(t, h.sshLog)
	assertContainsAll(t, "P0s transport", ssh, "STAGE_CREATE", "COLLECT_WRAPPER")
}

func TestRemoteAlphaOperatorRecoverySessionESTLSStatusFixedRootBootstrapArgv(t *testing.T) {
	source := mustRead(t, remoteAlphaOperatorScriptPath())
	section := docSection(t, source, "remote_alpha_es_tls_status_remote_wrapper() {", "\nrecovery_session_es_service_tls() {")
	assertContainsAll(t, "fixed status bootstrap", section,
		`collector_digest="$(/usr/bin/shasum -a 256 "${REMOTE_ALPHA_ES_TLS_STATUS_COLLECTOR}"`,
		`[[ "${collector_digest}" =~ ^[0-9a-f]{64}$ ]]`,
		`sudo LC_ALL=C /usr/bin/python3 -I -B -c "${bootstrap}" "${stage_dir}"`,
		`remote_alpha_es_tls_status.py "${collector_digest}" "${scope}"`,
		`hashlib.sha256(payload).hexdigest() != digest`,
		`compiled_payload = compile(payload, label, "exec")`,
		`exec(compiled_payload, namespace)`)
	assertContainsNone(t, "root pathname execution", section,
		`sudo LC_ALL=C /usr/bin/python3 -I -B "${collector}"`,
		`--digest`, `--script-path`)
}

func TestRemoteAlphaOperatorRecoverySessionESGovernanceTLSStatusStagesOnlyCollector(t *testing.T) {
	h := setupFakeRemoteAlphaESTLSStatusHarness(t)
	output, err := runRemoteAlphaOperatorWithPTY(t, h.env(),
		"recovery-session", "es-governance-tls-status", "--ssh-target", "ds@m75q-test", "--interactive-tty")
	if err != nil {
		t.Fatalf("fake P0t status route failed: %v\n%s", err, output)
	}
	scp := mustRead(t, h.scpLog)
	if strings.Count(strings.TrimSpace(scp), "\n") != 0 {
		t.Fatalf("expected exactly one staged collector: %q", scp)
	}
	assertContainsAll(t, "P0t collector staging", scp, "scripts/internal/remote_alpha_es_tls_status.py")
	assertContainsNone(t, "P0t collector staging", scp, "remote_alpha_es_service_tls_renew.sh")
	assertStatusFixedRemoteCommand(t, h, "execution-governance")
	ssh := mustRead(t, h.sshLog)
	assertContainsAll(t, "P0t transport", ssh, "STAGE_CREATE", "COLLECT_WRAPPER")
}

func TestRemoteAlphaOperatorRecoverySessionESTLSStatusInteractiveStdinSourceGuard(t *testing.T) {
	source := mustRead(t, remoteAlphaOperatorScriptPath())
	start := strings.Index(source, "remote_alpha_es_tls_status_shell_quote() {")
	end := strings.Index(source, "\nrecovery_session_es_service_tls() {")
	if start < 0 || end < start {
		t.Fatal("P0s/P0t status transport source boundaries missing")
	}
	section := source[start:end]
	if regexp.MustCompile(`\|\s*ssh\s+-tt\b`).MatchString(section) ||
		strings.Contains(section, `ssh -tt "${target}" /bin/bash -s`) ||
		strings.Contains(section, "sudo -n") {
		t.Fatal("P0s/P0t status transport still consumes wrapper bytes from SSH stdin")
	}
	if !strings.Contains(section, `os.open("/dev/tty", os.O_WRONLY | os.O_NONBLOCK | os.O_NOCTTY | os.O_CLOEXEC)`) ||
		strings.Contains(section, "os.set_blocking(0") || strings.Contains(section, "os.set_blocking(1") ||
		strings.Contains(section, "sys.stdin.read(") {
		t.Fatal("fixed witness terminal output changed inherited streams or captured input")
	}
	for _, fixed := range []string{
		`ssh -tt "${ssh_target}" "${remote_command}"`,
		`remote_alpha_es_tls_status_remote_wrapper "${remote_stage_dir}" "18446744073709551615:18446744073709551615" "${scope}" "${collector_digest}"`,
		`[[ ${#remote_command} -le 32768 ]]`,
	} {
		if !strings.Contains(section, fixed) {
			t.Fatal("P0s/P0t fixed command construction or preflight is missing")
		}
	}
	preflight := strings.Index(section, `remote_alpha_es_tls_status_remote_wrapper "${remote_stage_dir}" "18446744073709551615:18446744073709551615"`)
	contact := strings.Index(section, `stage_identity="$(ssh "${ssh_target}"`)
	if preflight < 0 || contact < 0 || preflight > contact {
		t.Fatal("remote command size preflight does not precede host contact")
	}
}

func TestRemoteAlphaOperatorRecoverySessionESTLSStatusRejectsHostileTransportInputs(t *testing.T) {
	for _, route := range []string{"es-service-tls-status", "es-governance-tls-status"} {
		for _, target := range []string{"-oProxyCommand=sh", "host;id", "host'quote", "user@@host", "host/path", "host$(id)"} {
			t.Run(route+"/"+target, func(t *testing.T) {
				h := setupFakeRemoteAlphaESTLSStatusHarness(t)
				output, err := runRemoteAlphaOperatorWithEnv(h.env(), "recovery-session", route,
					"--ssh-target", target, "--interactive-tty")
				if err == nil || !strings.Contains(output, "single SSH target") {
					t.Fatal("hostile target was not rejected before contact")
				}
				for _, path := range []string{h.sshLog, h.scpLog, h.sshArgv} {
					if _, err := os.Lstat(path); !os.IsNotExist(err) {
						t.Fatal("hostile target contacted fake transport")
					}
				}
			})
		}
	}
	source := mustRead(t, remoteAlphaOperatorScriptPath())
	start := strings.Index(source, "remote_alpha_es_tls_status_shell_quote() {")
	end := strings.Index(source, "\nrecovery_session_es_tls_status() {")
	if start < 0 || end < start {
		t.Fatal("fixed command builder source boundaries missing")
	}
	build := "set -euo pipefail\n" + source[start:end] + "\nremote_alpha_es_tls_status_remote_wrapper \"$@\""
	validStage := "/tmp/.es-tls-status-" + strings.Repeat("a", 32)
	validDigest := strings.Repeat("b", 64)
	for _, operands := range [][]string{
		{validStage + "';id", "123:456", "artifact-registry", validDigest},
		{validStage, "123:456;id", "artifact-registry", validDigest},
		{validStage, "123:456", "artifact-registry;id", validDigest},
		{validStage, "123:456", "artifact-registry", validDigest + "'"},
		{validStage, "18446744073709551616:1", "artifact-registry", validDigest},
	} {
		cmd := exec.Command("/bin/bash", append([]string{"-c", build, "status-builder"}, operands...)...)
		cmd.Dir = executionSubstrateRepoRoot
		output, err := cmd.CombinedOutput()
		if err == nil || len(output) != 0 {
			t.Fatal("hostile fixed-command operand was accepted or echoed")
		}
	}
	const sizeGuard = `[[ ${#remote_command} -le 32768 ]]`
	if !strings.Contains(build, sizeGuard) {
		t.Fatal("fixed command size guard missing")
	}
	forcedOverlarge := strings.Replace(build, sizeGuard, `[[ ${#remote_command} -le 1 ]]`, 1)
	cmd := exec.Command("/bin/bash", "-c", forcedOverlarge, "status-builder",
		validStage, "123:456", "artifact-registry", validDigest)
	cmd.Dir = executionSubstrateRepoRoot
	output, err := cmd.CombinedOutput()
	if err == nil || len(output) != 0 {
		t.Fatal("overlarge fixed command was accepted or echoed")
	}
}

func TestRemoteAlphaOperatorRecoverySessionESTLSStatusInteractivePromptAndFailureResidue(t *testing.T) {
	for _, route := range []string{"es-service-tls-status", "es-governance-tls-status"} {
		for _, tc := range []struct {
			mode         string
			wantSuccess  bool
			wantPrompt   bool
			wantResponse bool
			wantResidue  bool
		}{
			{"success", true, true, true, false},
			{"before_prompt", false, false, false, true},
			{"refuse", false, true, false, true},
			{"eof", false, true, false, true},
			{"remote_nonzero", false, true, true, false},
		} {
			t.Run(route+"/"+tc.mode, func(t *testing.T) {
				h := setupFakeRemoteAlphaESTLSStatusHarness(t)
				env := append(h.env(), "FAKE_STATUS_PROMPT_MODE="+tc.mode)
				output, err := runRemoteAlphaOperatorWithPromptPTY(t, env, "recovery-session", route,
					"--ssh-target", "ds@m75q-test", "--interactive-tty")
				if (err == nil) != tc.wantSuccess {
					t.Fatalf("interactive route result differs for %s: %v", tc.mode, err)
				}
				if !tc.wantSuccess {
					if !strings.Contains(output, "remote phase unproved after status contact") ||
						strings.Contains(output, "No recovery-session live helper or IM execution occurred.") {
						t.Fatal("post-contact status failure fabricated or hid remote phase")
					}
				}
				if strings.Contains(output, "FAKE_SUDO_PASSWORD_PROMPT: ") != tc.wantPrompt {
					t.Fatal("fake sudo prompt visibility differs")
				}
				log := mustRead(t, h.sshLog)
				if strings.Contains(log, "PROMPT_READ") != tc.wantResponse {
					t.Fatal("fake sudo prompt response result differs")
				}
				entries, err := os.ReadDir(h.stageRoot)
				if err != nil || (len(entries) == 1) != tc.wantResidue {
					t.Fatal("stage residue disposition differs after interactive result")
				}
				if tc.wantResidue {
					leaves, err := os.ReadDir(filepath.Join(h.stageRoot, entries[0].Name()))
					if err != nil || len(leaves) != 1 || leaves[0].Name() != "remote_alpha_es_tls_status.py" {
						t.Fatal("failed interactive handoff did not retain only diagnostic collector residue")
					}
				}
			})
		}
	}
	for _, route := range []string{"es-service-tls-status", "es-governance-tls-status"} {
		h := setupFakeRemoteAlphaESTLSStatusHarness(t)
		output, err := runRemoteAlphaOperatorWithEnv(h.env(), "recovery-session", route,
			"--ssh-target", "ds@m75q-test", "--interactive-tty")
		if err == nil || !strings.Contains(output, "requires a visible local terminal") {
			t.Fatal("status route did not require a real local terminal")
		}
		for _, path := range []string{h.sshLog, h.scpLog, h.sshArgv} {
			if _, err := os.Lstat(path); !os.IsNotExist(err) {
				t.Fatal("non-terminal route contacted fake transport")
			}
		}
	}
}

func TestRemoteAlphaOperatorRecoverySessionESServiceTLSRenewHeldBeforeContact(t *testing.T) {
	for _, route := range []string{"es-service-tls-renew", "es-governance-tls-renew"} {
		t.Run(route, func(t *testing.T) {
			h := setupFakeRemoteAlphaESTLSStatusHarness(t)
			output, err := runRemoteAlphaOperatorWithEnv(h.env(), "recovery-session", route,
				"--ssh-target", "ds@m75q-test", "--interactive-tty", "--execute-renew")
			if err == nil {
				t.Fatalf("held renewal route unexpectedly succeeded: %s", output)
			}
			assertContainsAll(t, "renewal refusal", output, "held")
			if _, err := os.Stat(h.sshLog); !os.IsNotExist(err) {
				t.Fatalf("SSH was contacted: %v", err)
			}
			if _, err := os.Stat(h.scpLog); !os.IsNotExist(err) {
				t.Fatalf("SCP was contacted: %v", err)
			}
		})
	}
}

func TestRemoteAlphaOperatorRecoverySessionESServiceTLSStatusRejectsRenewBeforeContact(t *testing.T) {
	for _, route := range []string{"es-service-tls-status", "es-governance-tls-status"} {
		t.Run(route, func(t *testing.T) {
			h := setupFakeRemoteAlphaESTLSStatusHarness(t)
			output, err := runRemoteAlphaOperatorWithEnv(h.env(), "recovery-session", route,
				"--ssh-target", "ds@m75q-test", "--interactive-tty", "--execute-renew")
			if err == nil {
				t.Fatalf("renew flag unexpectedly accepted: %s", output)
			}
			if _, err := os.Stat(h.sshLog); !os.IsNotExist(err) {
				t.Fatalf("SSH was contacted: %v", err)
			}
			if _, err := os.Stat(h.scpLog); !os.IsNotExist(err) {
				t.Fatalf("SCP was contacted: %v", err)
			}
		})
	}
}

func TestRemoteAlphaOperatorRecoverySessionOperatorHealthcheckTLSRejectsUnsafeArgsBeforeDelegation(t *testing.T) {
	for _, tc := range []struct {
		name     string
		args     []string
		required []string
	}{
		{
			name:     "status missing ssh target",
			args:     []string{"operator-healthcheck-tls-status", "--interactive-tty"},
			required: []string{"recovery-session operator-healthcheck-tls requires --ssh-target <target>", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "status missing tty",
			args:     []string{"operator-healthcheck-tls-status", "--ssh-target", "host"},
			required: []string{"recovery-session operator-healthcheck-tls requires --interactive-tty", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "status execute renew forbidden",
			args:     []string{"operator-healthcheck-tls-status", "--ssh-target", "host", "--interactive-tty", "--execute-renew"},
			required: []string{"recovery-session operator-healthcheck-tls-status forbids --execute-renew", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "renew missing execute renew",
			args:     []string{"operator-healthcheck-tls-renew", "--ssh-target", "host", "--interactive-tty"},
			required: []string{"recovery-session operator-healthcheck-tls-renew requires --execute-renew", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "renew missing ssh target",
			args:     []string{"operator-healthcheck-tls-renew", "--execute-renew", "--interactive-tty"},
			required: []string{"recovery-session operator-healthcheck-tls requires --ssh-target <target>", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "renew missing tty",
			args:     []string{"operator-healthcheck-tls-renew", "--ssh-target", "host", "--execute-renew"},
			required: []string{"recovery-session operator-healthcheck-tls requires --interactive-tty", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "helper override",
			args:     []string{"operator-healthcheck-tls-status", "--ssh-target", "host", "--interactive-tty", "--summary-path", "/tmp/x"},
			required: []string{"forbids helper override flag --summary-path", "fixed documented operator healthcheck TLS paths", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "forbidden status flag",
			args:     []string{"operator-healthcheck-tls-status", "--ssh-target", "host", "--interactive-tty", "--status"},
			required: []string{"recovery-session operator-healthcheck-tls forbids --status", "bounded host-local operator healthcheck client TLS status/renew route", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "unknown flag",
			args:     []string{"operator-healthcheck-tls-status", "--ssh-target", "host", "--interactive-tty", "--unknown-flag"},
			required: []string{"unknown option for recovery-session operator-healthcheck-tls: --unknown-flag", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "equals form",
			args:     []string{"operator-healthcheck-tls-status", "--ssh-target=host", "--interactive-tty"},
			required: []string{"recovery-session operator-healthcheck-tls does not accept equals-form options: --ssh-target=host", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "ssh target option injection",
			args:     []string{"operator-healthcheck-tls-status", "--ssh-target", "-oProxyCommand=sh", "--interactive-tty"},
			required: []string{"--ssh-target must be a single SSH target, not an option or shell command", "No recovery-session live helper or IM execution occurred."},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			output := requireRemoteAlphaOperatorFailure(t, append([]string{"recovery-session"}, tc.args...)...)
			assertContainsAll(t, "operator-healthcheck-tls refusal", output, tc.required...)
			assertContainsNone(t, "operator-healthcheck-tls refusal", output,
				"Running Mac-side operator healthcheck TLS",
				"remote_alpha_operator_healthcheck_tls_renew.sh",
			)
		})
	}
}

func TestRemoteAlphaOperatorRecoverySessionOperatorHealthcheckTLSRejectsSecretLikeArgsBeforeDelegation(t *testing.T) {
	for _, args := range [][]string{
		{"--api-key=dummy"},
		{"--root-token", "dummy"},
		{"--unseal-key", "dummy"},
		{"--vault-token", "dummy"},
		{"--client-token", "dummy"},
		{"--jwt-svid", "dummy"},
		{"--private-key", "dummy"},
		{"--password", "dummy"},
		{"--secret", "dummy"},
	} {
		t.Run(strings.Join(args, "_"), func(t *testing.T) {
			routeArgs := append([]string{
				"recovery-session", "operator-healthcheck-tls-renew",
				"--ssh-target", "host",
				"--interactive-tty",
				"--execute-renew",
			}, args...)
			output := requireRemoteAlphaOperatorFailure(t, routeArgs...)
			assertContainsAll(t, "operator-healthcheck-tls secret flag refusal", output,
				"secret material must never be passed by CLI args/env/logs/reports/artifacts",
			)
			assertContainsNone(t, "operator-healthcheck-tls secret flag refusal", output,
				"Running Mac-side operator healthcheck TLS",
				"remote_alpha_operator_healthcheck_tls_renew.sh",
			)
		})
	}
}

func TestRemoteAlphaOperatorRecoverySessionOperatorHealthcheckTLSNoTTYFailsBeforeStaging(t *testing.T) {
	h := setupFakeRemoteAlphaESServiceTLSHarness(t)
	output, err := runRemoteAlphaOperatorWithEnv(h.env(),
		"recovery-session", "operator-healthcheck-tls-status",
		"--ssh-target", "ds@m75q-test",
		"--interactive-tty",
	)
	if err == nil {
		t.Fatalf("expected no-TTY failure before operator healthcheck TLS staging, got success:\n%s", output)
	}
	assertContainsAll(t, "operator-healthcheck-tls no tty refusal", output,
		"requires visible local terminal",
		"no staging or SSH occurred",
		"No recovery-session live helper or IM execution occurred.",
	)
	if _, err := os.Stat(h.sshLogPath); !os.IsNotExist(err) {
		t.Fatalf("ssh should not run when operator healthcheck TLS local TTY guard fails: %v", err)
	}
	if _, err := os.Stat(h.scpLogPath); !os.IsNotExist(err) {
		t.Fatalf("scp should not run when operator healthcheck TLS local TTY guard fails: %v", err)
	}
}

func TestRemoteAlphaOperatorRecoverySessionOperatorHealthcheckTLSStatusStagesOnlyFixedHelperPair(t *testing.T) {
	h := setupFakeRemoteAlphaESServiceTLSHarness(t)
	before := snapshotPathExistence(t, remoteAlphaOperatorRouteArtifactPaths(filepath.Join(".out", "remote-alpha-m75q", "operator-healthcheck-tls-renew-summary.json"))...)

	output, err := runRemoteAlphaOperatorWithPTY(t, h.env(),
		"recovery-session", "operator-healthcheck-tls-status",
		"--ssh-target", "ds@m75q-test",
		"--interactive-tty",
	)
	if err != nil {
		t.Fatalf("Mac-side fake operator healthcheck TLS status route failed: %v\noutput=%s\nssh=%s\nscp=%s\nsudo=%s\nhelper=%s\nrm=%s",
			err, output, readIfExists(h.sshLogPath), readIfExists(h.scpLogPath), readIfExists(h.sudoLog), readIfExists(h.helperLog), readIfExists(h.rmLogPath))
	}

	assertOperatorHealthcheckTLSFakeRoute(t, h, output, "--status")
	assertContainsAll(t, "Mac-side fake operator healthcheck TLS status output", output,
		"Running Mac-side operator healthcheck TLS status through an explicit interactive SSH TTY.",
		"Invoking only the staged public helper with --status",
		"Status mode is non-mutating",
		"Status mode is non-mutating and does not restart services.",
	)
	assertContainsNone(t, "Mac-side fake operator healthcheck TLS status output", output,
		"--execute-renew",
		"remote-alpha-live-refresh",
		"remote-alpha-live-support-bundle",
		"cp-proof",
		"BEGIN PRIVATE KEY",
		"BEGIN CERTIFICATE",
	)
	assertNoNewPaths(t, "Mac-side fake operator healthcheck TLS status route", before)
}

func TestRemoteAlphaOperatorRecoverySessionOperatorHealthcheckTLSRenewStagesOnlyFixedHelperPair(t *testing.T) {
	h := setupFakeRemoteAlphaESServiceTLSHarness(t)
	before := snapshotPathExistence(t, remoteAlphaOperatorRouteArtifactPaths(filepath.Join(".out", "remote-alpha-m75q", "operator-healthcheck-tls-renew-summary.json"))...)

	output, err := runRemoteAlphaOperatorWithPTY(t, h.env(),
		"recovery-session", "operator-healthcheck-tls-renew",
		"--ssh-target", "ds@m75q-test",
		"--interactive-tty",
		"--execute-renew",
	)
	if err != nil {
		t.Fatalf("Mac-side fake operator healthcheck TLS renew route failed: %v\noutput=%s\nssh=%s\nscp=%s\nsudo=%s\nhelper=%s\nrm=%s",
			err, output, readIfExists(h.sshLogPath), readIfExists(h.scpLogPath), readIfExists(h.sudoLog), readIfExists(h.helperLog), readIfExists(h.rmLogPath))
	}

	assertOperatorHealthcheckTLSFakeRoute(t, h, output, "--execute-renew")
	assertContainsAll(t, "Mac-side fake operator healthcheck TLS renew output", output,
		"Running Mac-side operator healthcheck TLS renewal through an explicit interactive SSH TTY.",
		"Invoking only the staged public helper with --execute-renew",
		"unsupported_signing_topology",
		"documented CA custody/signing design",
		"spiffe://execution.internal/operator/local",
		"did not restart ES",
	)
	assertContainsNone(t, "Mac-side fake operator healthcheck TLS renew output", output,
		"remote-alpha-live-refresh",
		"remote-alpha-live-support-bundle",
		"cp-proof",
		"BEGIN PRIVATE KEY",
		"BEGIN CERTIFICATE",
	)
	assertNoNewPaths(t, "Mac-side fake operator healthcheck TLS renew route", before)
}

func assertOperatorHealthcheckTLSFakeRoute(t *testing.T, h *fakeRemoteAlphaESServiceTLSHarness, output string, helperMode string) {
	t.Helper()
	assertContainsAll(t, "Mac-side fake operator healthcheck TLS output", output,
		"Staging only scripts/remote_alpha_operator_healthcheck_tls_renew.sh and scripts/internal/remote_alpha_operator_healthcheck_tls_renew.sh.",
		"Canonical summary stays remote at /var/tmp/execution-substrate-remote-alpha/operator-healthcheck-tls-renew-summary.json.",
		"Remote Alpha operator healthcheck TLS helper finished.",
		"Canonical remote summary path: /var/tmp/execution-substrate-remote-alpha/operator-healthcheck-tls-renew-summary.json",
		"did not copy it back to Mac .out",
		"did not print full summary JSON",
	)

	scpLog := strings.TrimSpace(mustRead(t, h.scpLogPath))
	scpLines := strings.Split(scpLog, "\n")
	if len(scpLines) != 2 {
		t.Fatalf("expected exactly two staged file uploads, got %q", scpLog)
	}
	assertContainsAll(t, "fake operator healthcheck TLS scp log", scpLog,
		filepath.Join(executionSubstrateRepoRoot, "scripts", "remote_alpha_operator_healthcheck_tls_renew.sh"),
		filepath.Join(executionSubstrateRepoRoot, "scripts", "internal", "remote_alpha_operator_healthcheck_tls_renew.sh"),
		"/scripts/remote_alpha_operator_healthcheck_tls_renew.sh",
		"/scripts/internal/remote_alpha_operator_healthcheck_tls_renew.sh",
	)
	assertContainsNone(t, "fake operator healthcheck TLS scp log", scpLog,
		"remote_alpha_operator.sh",
		"remote_alpha_reset_disposable_vault.sh",
		"remote_alpha_vault_workload_auth_check.sh",
		"remote_alpha_vault_workload_auth_bootstrap.sh",
		"remote_alpha_runtime_identity_helper_summary.sh",
		"remote_alpha_es_service_tls_renew.sh",
		"remote_alpha_migrate_vault_service_user.sh",
		"remote_alpha_prepare_es_config_tls",
		"remote_alpha_deploy_es_binaries",
		"bundle",
	)

	sshLog := mustRead(t, h.sshLogPath)
	if got := strings.Count(sshLog, "tty=true"); got != 1 {
		t.Fatalf("expected exactly one interactive ssh -tt invocation, got %d log=%q", got, sshLog)
	}
	assertContainsAll(t, "fake operator healthcheck TLS ssh log", sshLog,
		"tty=true target=ds@m75q-test",
		"execution-substrate-remote-alpha-operator-healthcheck-tls-renew",
		"exec /bin/bash -c",
	)
	assertContainsNone(t, "fake operator healthcheck TLS ssh log forbidden capture", sshLog,
		" tee ",
		"script ",
		"transcript",
		"remote-alpha-live-refresh",
		"remote-alpha-live-support-bundle",
		"cp-proof",
		".out",
	)

	sudoLog := strings.TrimSpace(mustRead(t, h.sudoLog))
	assertContainsAll(t, "fake operator healthcheck TLS sudo log", sudoLog,
		"sudo_args=",
		"/scripts/remote_alpha_operator_healthcheck_tls_renew.sh",
		helperMode,
	)
	assertContainsNone(t, "fake operator healthcheck TLS sudo log forbidden args", sudoLog,
		"--summary-path",
		"--dry-run",
		"--check-only",
		"--operator-cert-path",
		"--es-config-path",
		"remote_alpha_vault_workload_auth_check.sh",
		"remote_alpha_reset_disposable_vault.sh",
	)

	helperLog := strings.TrimSpace(mustRead(t, h.helperLog))
	assertContainsAll(t, "fake operator healthcheck TLS helper log", helperLog,
		"public_args="+helperMode,
		"/scripts/internal/remote_alpha_operator_healthcheck_tls_renew.sh",
	)
	assertContainsNone(t, "fake operator healthcheck TLS helper log forbidden args", helperLog,
		"--summary-path",
		"--dry-run",
		"--check-only",
		"--root-token",
	)

	rmLog := mustRead(t, h.rmLogPath)
	assertContainsAll(t, "fake operator healthcheck TLS remote cleanup log", rmLog,
		"execution-substrate-remote-alpha-operator-healthcheck-tls-renew",
	)
	assertRemoteAlphaOperatorStageFoldersGone(t, h.remoteRoot, "execution-substrate-remote-alpha-operator-healthcheck-tls-renew")
}

type fakeRemoteAlphaOperatorP0vFacadeHarness struct {
	localBin  string
	pythonLog string
	sshLog    string
	scpLog    string
}

func setupFakeRemoteAlphaOperatorP0vFacadeHarness(t *testing.T) *fakeRemoteAlphaOperatorP0vFacadeHarness {
	t.Helper()
	tmpDir := t.TempDir()
	h := &fakeRemoteAlphaOperatorP0vFacadeHarness{
		localBin:  filepath.Join(tmpDir, "bin"),
		pythonLog: filepath.Join(tmpDir, "python.log"),
		sshLog:    filepath.Join(tmpDir, "ssh.log"),
		scpLog:    filepath.Join(tmpDir, "scp.log"),
	}
	if err := os.MkdirAll(h.localBin, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", h.localBin, err)
	}
	writeExecutable(t, h.localBin, "python3", fmt.Sprintf(`#!/usr/bin/env bash
set -euo pipefail
if [[ "$#" -ge 5 && "$1" == "-I" && "$2" == "-S" && "$3" == "-B" && "$4" == "-c" ]]; then
  exit 0
fi
printf 'argc=%%s\n' "$#" >> %q
for arg in "$@"; do
  printf 'arg=%%s\n' "${arg}" >> %q
done
printf '{"fake_p0v_runtime":true}\n'
`, h.pythonLog, h.pythonLog))
	writeExecutable(t, h.localBin, "ssh", fmt.Sprintf(`#!/usr/bin/env bash
set -euo pipefail
printf 'ssh-called %%s\n' "$*" >> %q
exit 91
`, h.sshLog))
	writeExecutable(t, h.localBin, "scp", fmt.Sprintf(`#!/usr/bin/env bash
set -euo pipefail
printf 'scp-called %%s\n' "$*" >> %q
exit 92
`, h.scpLog))
	return h
}

func (h *fakeRemoteAlphaOperatorP0vFacadeHarness) env() []string {
	return append(os.Environ(), "PATH="+h.localBin+string(os.PathListSeparator)+os.Getenv("PATH"))
}

func TestRemoteAlphaOperatorP0vHelpInventoryAndRecoveryTextExposeImplementedRoute(t *testing.T) {
	help := requireRemoteAlphaOperatorSuccess(t, "--help")
	assertContainsAll(t, "P0v operator help", help,
		"P0v adds recovery-session operator-healthcheck-tls-status-noninteractive --ssh-target <target> --format json",
		"implemented read-only no-prompt status observation route",
		"fixed local Python runtime",
		"streamed fixed remote collector",
		"operator-healthcheck-tls-status-noninteractive --ssh-target <user@host> --format json",
	)

	inventory := requireRemoteAlphaOperatorSuccess(t, "inventory")
	assertContainsAll(t, "P0v operator inventory", inventory,
		"implemented through the retained P0q, P0s, P0t, P0u, and P0v surfaces",
		"operator-healthcheck-tls-status-noninteractive --ssh-target <target> --format json",
		"Bash performs contact-free preflight only",
		"streams a fixed collector over SSH stdin",
		"no Bash JSON",
		"no scp",
		"no remote helper staging",
		"no remote summary",
		"not scheduled execution",
	)

	recoveryHelp := requireRemoteAlphaOperatorSuccess(t, "recovery-session", "operator-healthcheck-tls-status-noninteractive", "--help")
	assertContainsAll(t, "P0v route help", recoveryHelp,
		"Remote Alpha recovery-session mode: operator-healthcheck-tls-status-noninteractive",
		"P0v scope",
		"Bash parses/refuses route args",
		"constructs no JSON",
		"performs no SSH/SCP/sudo/staging/cleanup/summary behavior",
		"execs the fixed local Python runtime",
		"--format json",
		"no local TTY requirement",
		"no pseudo-TTY",
		"no Bash SSH invocation",
		"no renewal",
		"no scheduling",
	)
}

func TestRemoteAlphaOperatorP0vFacadeExecsOnlyFixedPythonRuntime(t *testing.T) {
	h := setupFakeRemoteAlphaOperatorP0vFacadeHarness(t)
	output, err := runRemoteAlphaOperatorWithEnv(h.env(),
		"recovery-session", "operator-healthcheck-tls-status-noninteractive",
		"--ssh-target", "ds@m75q-test",
		"--format", "json",
	)
	if err != nil {
		t.Fatalf("P0v facade with fake python failed: %v\noutput=%s\npython=%s\nssh=%s\nscp=%s",
			err, output, readIfExists(h.pythonLog), readIfExists(h.sshLog), readIfExists(h.scpLog))
	}
	assertContainsAll(t, "P0v fake runtime output", output, `"fake_p0v_runtime":true`)
	pythonLog := mustRead(t, h.pythonLog)
	assertContainsAll(t, "P0v fake python argv", pythonLog,
		"argc=8",
		"arg=-I",
		"arg=-S",
		"arg=-B",
		"arg="+filepath.Join(remoteAlphaOperatorRepoRoot(), "scripts", "remote_alpha_operator_healthcheck_tls_status_noninteractive.py"),
		"arg=--ssh-target",
		"arg=ds@m75q-test",
		"arg=--format",
		"arg=json",
	)
	if _, err := os.Stat(h.sshLog); !os.IsNotExist(err) {
		t.Fatalf("P0v Bash facade must not invoke ssh directly: %s", readIfExists(h.sshLog))
	}
	if _, err := os.Stat(h.scpLog); !os.IsNotExist(err) {
		t.Fatalf("P0v Bash facade must not invoke scp directly: %s", readIfExists(h.scpLog))
	}
}

func TestRemoteAlphaOperatorP0vFacadeRejectsUnsafeArgsBeforeRuntime(t *testing.T) {
	for _, tc := range []struct {
		name      string
		args      []string
		required  []string
		forbidden []string
	}{
		{
			name:     "missing ssh target",
			args:     []string{"--format", "json"},
			required: []string{"requires --ssh-target <target>", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "missing format",
			args:     []string{"--ssh-target", "host"},
			required: []string{"requires --format json", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:      "duplicate target",
			args:      []string{"--ssh-target", "host", "--ssh-target", "other", "--format", "json"},
			required:  []string{"duplicate option for operator-healthcheck-tls-status-noninteractive: --ssh-target"},
			forbidden: []string{"other"},
		},
		{
			name:     "duplicate format",
			args:     []string{"--ssh-target", "host", "--format", "json", "--format", "json"},
			required: []string{"duplicate option for operator-healthcheck-tls-status-noninteractive: --format"},
		},
		{
			name:      "equals form",
			args:      []string{"--ssh-target=host", "--format", "json"},
			required:  []string{"does not accept equals-form options"},
			forbidden: []string{"--ssh-target=host"},
		},
		{
			name:      "unknown flag",
			args:      []string{"--ssh-target", "host", "--format", "json", "--unknown"},
			required:  []string{"unknown option for operator-healthcheck-tls-status-noninteractive"},
			forbidden: []string{"--unknown"},
		},
		{
			name:      "positional",
			args:      []string{"--ssh-target", "host", "--format", "json", "extra"},
			required:  []string{"unexpected positional argument for operator-healthcheck-tls-status-noninteractive"},
			forbidden: []string{"extra"},
		},
		{
			name:      "target injection",
			args:      []string{"--ssh-target", "-oProxyCommand=sh", "--format", "json"},
			required:  []string{"--ssh-target must be a single SSH target, not an option or shell command"},
			forbidden: []string{"ProxyCommand"},
		},
		{
			name:     "interactive tty forbidden",
			args:     []string{"--ssh-target", "host", "--format", "json", "--interactive-tty"},
			required: []string{"forbids interactive, renewal, status-helper, summary, and output override flags"},
		},
		{
			name:     "renew forbidden",
			args:     []string{"--ssh-target", "host", "--format", "json", "--execute-renew"},
			required: []string{"forbids interactive, renewal, status-helper, summary, and output override flags"},
		},
		{
			name:      "summary forbidden",
			args:      []string{"--ssh-target", "host", "--format", "json", "--summary-path", "/tmp/x"},
			required:  []string{"forbids interactive, renewal, status-helper, summary, and output override flags"},
			forbidden: []string{"/tmp/x"},
		},
		{
			name:      "helper override forbidden",
			args:      []string{"--ssh-target", "host", "--format", "json", "--collector-path", "x"},
			required:  []string{"forbids helper, path, command, SSH, privilege, runtime, collector, schema, timeout, and limit overrides"},
			forbidden: []string{" x"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := setupFakeRemoteAlphaOperatorP0vFacadeHarness(t)
			output, err := runRemoteAlphaOperatorWithEnv(h.env(), append([]string{"recovery-session", "operator-healthcheck-tls-status-noninteractive"}, tc.args...)...)
			if err == nil {
				t.Fatalf("P0v facade refusal unexpectedly succeeded: %s", output)
			}
			assertContainsAll(t, "P0v facade refusal", output, tc.required...)
			assertContainsNone(t, "P0v facade refusal", output,
				append([]string{
					"fake_p0v_runtime",
					"Running Mac-side operator healthcheck TLS",
				}, tc.forbidden...)...,
			)
			if _, err := os.Stat(h.pythonLog); !os.IsNotExist(err) {
				t.Fatalf("P0v facade should reject before runtime: %s", readIfExists(h.pythonLog))
			}
			if _, err := os.Stat(h.sshLog); !os.IsNotExist(err) {
				t.Fatalf("P0v facade should not call ssh on refusal: %s", readIfExists(h.sshLog))
			}
		})
	}
}

func TestRemoteAlphaOperatorP0vFacadeRejectsSecretLikeArgsWithoutEcho(t *testing.T) {
	for _, token := range []string{
		"--private-key",
		"--PRIVATE_KEY",
		"--client_token_file",
		"--proof-secret-value=dummy",
	} {
		t.Run(token, func(t *testing.T) {
			output := requireRemoteAlphaOperatorFailure(t,
				"recovery-session", "operator-healthcheck-tls-status-noninteractive",
				"--ssh-target", "host",
				"--format", "json",
				token, "super-secret-value",
			)
			assertContainsAll(t, "P0v secret refusal", output,
				"secret material must never be passed by CLI args/env/logs/reports/artifacts",
			)
			assertContainsNone(t, "P0v secret refusal", output,
				"super-secret-value",
				"abcdefghijklmnopqrstuvwxyz",
				"fake_p0v_runtime",
				"Running Mac-side operator healthcheck TLS",
			)
		})
	}
}

func TestRemoteAlphaOperatorP0vFacadeAllowsOrdinarySHostShape(t *testing.T) {
	for _, target := range []string{"s.example-host", "hvs.abcdefghijklmnopqrstuvwxyz", "sk-abcdefghijklmnopqrstuvwxyz"} {
		t.Run(target, func(t *testing.T) {
			h := setupFakeRemoteAlphaOperatorP0vFacadeHarness(t)
			output, err := runRemoteAlphaOperatorWithEnv(h.env(),
				"recovery-session", "operator-healthcheck-tls-status-noninteractive",
				"--ssh-target", target,
				"--format", "json",
			)
			if err != nil {
				t.Fatalf("P0v facade should not scan ordinary option values: %v\n%s", err, output)
			}
			assertContainsAll(t, "P0v ordinary option value", output, `"fake_p0v_runtime":true`)
		})
	}
}

func TestRemoteAlphaOperatorP0vFacadeDoesNotRequireLocalTTY(t *testing.T) {
	h := setupFakeRemoteAlphaOperatorP0vFacadeHarness(t)
	output, err := runRemoteAlphaOperatorWithEnv(h.env(),
		"recovery-session", "operator-healthcheck-tls-status-noninteractive",
		"--ssh-target", "ds@m75q-test",
		"--format", "json",
	)
	if err != nil {
		t.Fatalf("P0v facade should not require a PTY: %v\n%s", err, output)
	}
	assertContainsNone(t, "P0v no TTY output", output,
		"requires visible local terminal",
		"no staging or SSH occurred",
	)
}

type fakeRemoteAlphaWorkloadAuthBootstrapHarness struct {
	localBin    string
	remoteBin   string
	remoteRoot  string
	sshLogPath  string
	scpLogPath  string
	rmLogPath   string
	sudoLogPath string
	spireLog    string
	helperLog   string
}

func setupFakeRemoteAlphaWorkloadAuthBootstrapHarness(t *testing.T) *fakeRemoteAlphaWorkloadAuthBootstrapHarness {
	t.Helper()

	tmpDir := t.TempDir()
	remoteRoot, err := os.MkdirTemp("/tmp", "es-ra-bootstrap-")
	if err != nil {
		t.Fatalf("mkdir short fake remote root: %v", err)
	}
	t.Cleanup(func() {
		_ = os.RemoveAll(remoteRoot)
	})
	h := &fakeRemoteAlphaWorkloadAuthBootstrapHarness{
		localBin:    filepath.Join(tmpDir, "local-bin"),
		remoteBin:   filepath.Join(tmpDir, "remote-bin"),
		remoteRoot:  remoteRoot,
		sshLogPath:  filepath.Join(tmpDir, "ssh.log"),
		scpLogPath:  filepath.Join(tmpDir, "scp.log"),
		rmLogPath:   filepath.Join(tmpDir, "rm.log"),
		sudoLogPath: filepath.Join(tmpDir, "sudo.log"),
		spireLog:    filepath.Join(tmpDir, "spire.log"),
		helperLog:   filepath.Join(tmpDir, "helper.log"),
	}
	for _, dir := range []string{h.localBin, h.remoteBin, h.remoteRoot} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", dir, err)
		}
	}
	mkdirFakeRemoteAlphaHostTmp(t, h.remoteRoot)

	writeExecutable(t, h.localBin, "ssh", fmt.Sprintf(`#!/usr/bin/env bash
set -euo pipefail
tty=false
while [[ "${1:-}" == "-tt" ]]; do
  tty=true
  shift
done
target="${1:-}"
shift || true
printf 'tty=%%s target=%%s args=%%s\n' "${tty}" "${target}" "$*" >> %q
export PATH="${FAKE_REMOTE_BIN}:${PATH}"
command_joined="$*"
if [[ "${command_joined}" == *"summary_path_prepare_status=pass"* ]]; then
  command_string="${command_joined}"
  summary_prefix="/var/tmp/execution-substrate-remote-alpha"
  mapped_command="${command_string//${summary_prefix}/${FAKE_REMOTE_ROOT}${summary_prefix}}"
  exec /bin/bash -c "${mapped_command}"
fi
if [[ "${command_joined}" == *"config_readability_prepare_status=pass"* ]]; then
  command_string="${command_joined}"
  config_prefix="/etc/execution-substrate"
  mapped_command="${command_string//${config_prefix}/${FAKE_REMOTE_ROOT}${config_prefix}}"
  exec /bin/bash -c "${mapped_command}"
fi
if [[ "${command_joined}" == *"spire_bundle_read_prepare_status=pass"* ]]; then
  command_string="${command_joined}"
  spire_prefix="/run/spire"
  mapped_command="${command_string//${spire_prefix}/${FAKE_REMOTE_ROOT}${spire_prefix}}"
  exec /bin/bash -c "${mapped_command}"
fi
if [[ "${1:-}" == "/bin/bash" && "${2:-}" == "-s" ]]; then
  shift 2
  if [[ "${1:-}" == "--" ]]; then
    shift
  fi
  mapped_args=()
  for arg in "$@"; do
    if [[ "${arg}" == /* ]]; then
      mapped_args+=("${FAKE_REMOTE_ROOT}${arg}")
    else
      mapped_args+=("${arg}")
    fi
  done
  payload="$(mktemp)"
  cat >"${payload}"
  set +e
  /bin/bash "${payload}" "${mapped_args[@]}"
  status=$?
  set -e
  rm -f -- "${payload}"
  exit "${status}"
fi
if [[ "$#" -eq 1 && "${1:-}" == exec\ /bin/bash\ -c* ]]; then
  command_string="${1}"
  bootstrap_prefix="/tmp/execution-substrate-remote-alpha-vault-workload-auth-bootstrap"
  mapped_command="${command_string//${bootstrap_prefix}/${FAKE_REMOTE_ROOT}${bootstrap_prefix}}"
  exec /bin/bash -c "${mapped_command}"
fi
echo "unexpected fake ssh invocation: $*" >&2
exit 64
`, h.sshLogPath))

	writeExecutable(t, h.localBin, "scp", fmt.Sprintf(`#!/usr/bin/env bash
set -euo pipefail
if [[ "$#" -ne 2 ]]; then
  echo "unexpected fake scp args: $*" >&2
  exit 64
fi
src=$1
dest=$2
printf '%%s\t%%s\n' "${src}" "${dest}" >> %q
if [[ "${src}" == *:* || "${dest}" != *:* ]]; then
  echo "fake scp supports one local-to-remote upload" >&2
  exit 64
fi
remote_path="${dest#*:}"
mapped_dest="${FAKE_REMOTE_ROOT}${remote_path}"
mkdir -p -- "$(dirname "${mapped_dest}")"
if [[ "${src}" == */scripts/internal/remote_alpha_vault_workload_auth_bootstrap.sh ]]; then
  cat >"${mapped_dest}" <<'REMOTE_ALPHA_FAKE_BOOTSTRAP_INTERNAL'
# fake internal bootstrap helper staged for layout verification
REMOTE_ALPHA_FAKE_BOOTSTRAP_INTERNAL
elif [[ "$(basename "${src}")" == "remote_alpha_vault_workload_auth_bootstrap.sh" ]]; then
  cat >"${mapped_dest}" <<'REMOTE_ALPHA_FAKE_BOOTSTRAP_PUBLIC'
#!/usr/bin/env bash
set -euo pipefail
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
internal="${script_dir}/internal/remote_alpha_vault_workload_auth_bootstrap.sh"
if [[ ! -f "${internal}" ]]; then
  echo "missing internal helper: ${internal}" >&2
  exit 65
fi
printf 'public_args=%%s\n' "$*" >> %q
printf 'internal=%%s\n' "${internal}" >> %q
printf 'Remote Alpha Vault workload-auth bootstrap helper finished.\n'
printf 'Remote summary path: /var/tmp/execution-substrate-remote-alpha/vault-workload-auth-bootstrap-summary.json\n'
printf 'Workload-auth check, reset/unseal, IM refresh, support-bundle collection, CP proof, and runtime identity generation were not run.\n'
printf 'Non-claims: not workload-auth success, not ES Vault token brokerage.\n'
REMOTE_ALPHA_FAKE_BOOTSTRAP_PUBLIC
else
  echo "unexpected fake scp source: ${src}" >&2
  exit 64
fi
chmod 0700 "${mapped_dest}"
`, h.scpLogPath, h.helperLog, h.helperLog))

	writeExecutable(t, h.remoteBin, "rm", fmt.Sprintf(`#!/usr/bin/env bash
set -euo pipefail
printf '%%s\n' "$*" >> %q
exec /bin/rm "$@"
	`, h.rmLogPath))

	writeExecutable(t, h.remoteBin, "setfacl", `#!/usr/bin/env bash
set -euo pipefail
exit 0
`)

	writeExecutable(t, h.remoteBin, "systemctl", `#!/usr/bin/env bash
set -euo pipefail
if [[ "$#" -eq 3 && "${1:-}" == "is-active" && "${2:-}" == "--quiet" && "${3:-}" == "spire-server" ]]; then
  exit "${REMOTE_ALPHA_FAKE_SYSTEMCTL_SPIRE_ACTIVE_STATUS:-0}"
fi
echo "unexpected fake systemctl args: $*" >&2
exit 64
`)

	writeExecutable(t, h.remoteBin, "spire-server", fmt.Sprintf(`#!/usr/bin/env bash
set -euo pipefail
printf 'args=%%s\n' "$*" >> %q
if [[ "$#" -ne 6 || "${1:-}" != "bundle" || "${2:-}" != "show" || "${3:-}" != "-format" || "${4:-}" != "spiffe" || "${5:-}" != "-socketPath" ]]; then
  echo "unexpected fake spire-server args: $*" >&2
  exit 64
fi
socket_path="${6:-}"
if [[ "${REMOTE_ALPHA_FAKE_SPIRE_SERVER_FORCE_FAIL:-false}" == "true" ]]; then
  echo "raw fake SPIRE stderr must not print" >&2
  exit 17
fi
if [[ ! -S "${socket_path}" || ! -r "${socket_path}" || ! -w "${socket_path}" ]]; then
  exit 13
fi
cat <<'JSON'
{"keys":[{"kty":"RSA","use":"jwt-svid","n":"FAKE-SPIRE-BUNDLE-MATERIAL-MUST-NOT-PRINT","e":"AQAB"}]}
JSON
`, h.spireLog))

	writeExecutable(t, h.remoteBin, "sudo", fmt.Sprintf(`#!/usr/bin/env bash
set -euo pipefail
printf '%%s\n' "$*" >> %q
cmd="${1:-}"
shift || true
if [[ "${cmd}" == "-n" ]]; then
  cmd="${1:-}"
  shift || true
fi
case "${cmd}" in
  -v)
    ;;
  install)
    mode=""
    dir=""
    while [[ "$#" -gt 0 ]]; do
      case "$1" in
        -d)
          shift
          ;;
        -m)
          mode="$2"
          shift 2
          ;;
        -o|-g)
          shift 2
          ;;
        --)
          shift
          dir="$1"
          shift
          ;;
        -*)
          echo "unexpected fake sudo install arg: $1" >&2
          exit 64
          ;;
        *)
          dir="$1"
          shift
          ;;
      esac
    done
    if [[ -z "${dir}" ]]; then
      echo "fake sudo install missing directory" >&2
      exit 64
    fi
    mkdir -p -- "${dir}"
    if [[ -n "${mode}" ]]; then
      chmod "${mode}" "${dir}"
    fi
    ;;
  chown)
    while [[ "$#" -gt 0 && "${1:-}" != "--" ]]; do
      shift
    done
    if [[ "${1:-}" == "--" ]]; then
      shift
    fi
    ;;
	  chmod)
	    mode="${1:-}"
	    shift || true
	    if [[ "${1:-}" == "--" ]]; then
	      shift
	    fi
	    exec /bin/chmod "${mode}" "$@"
	    ;;
	  test)
	    predicate="${1:-}"
	    path="${2:-}"
	    restore_path=""
	    restore_mode=""
	    if [[ -n "${FAKE_REMOTE_ROOT:-}" && "${path}" == "${FAKE_REMOTE_ROOT}/run/spire/server/"* ]]; then
	      server_dir="${FAKE_REMOTE_ROOT}/run/spire/server"
	      if [[ -d "${server_dir}" && ! -x "${server_dir}" ]]; then
	        restore_path="${server_dir}"
	        restore_mode="$(stat -c '%%a' "${server_dir}" 2>/dev/null || stat -f '%%Lp' "${server_dir}")"
	        /bin/chmod u+x "${server_dir}"
	      fi
	    fi
	    set +e
	    /bin/test "${predicate}" "${path}"
	    status=$?
	    set -e
	    if [[ -n "${restore_path}" ]]; then
	      /bin/chmod "${restore_mode}" "${restore_path}"
	    fi
	    exit "${status}"
	    ;;
	  setfacl)
	    acl_spec=""
	    path=""
	    while [[ "$#" -gt 0 ]]; do
	      case "$1" in
	        -m)
	          acl_spec="$2"
	          shift 2
	          ;;
	        --)
	          shift
	          path="$1"
	          shift
	          ;;
	        -*)
	          echo "unexpected fake sudo setfacl arg: $1" >&2
	          exit 64
	          ;;
	        *)
	          path="$1"
	          shift
	          ;;
	      esac
	    done
	    if [[ -z "${path}" ]]; then
	      echo "fake sudo setfacl missing path" >&2
	      exit 64
	    fi
	    case "${acl_spec}" in
	      u:*:--x)
	        /bin/chmod u+x "${path}"
	        ;;
	      u:*:r--)
	        /bin/chmod u+r "${path}"
	        ;;
	      u:*:rw-)
	        /bin/chmod u+rw "${path}"
	        ;;
	      *)
	        echo "unexpected fake sudo setfacl acl: ${acl_spec}" >&2
	        exit 64
	        ;;
	    esac
	    ;;
	  *)
	    echo "unexpected fake sudo command: ${cmd}" >&2
	    exit 64
    ;;
esac
`, h.sudoLogPath))

	return h
}

func (h *fakeRemoteAlphaWorkloadAuthBootstrapHarness) env() []string {
	return envWithPath(h.localBin,
		"FAKE_REMOTE_BIN="+h.remoteBin,
		"FAKE_REMOTE_ROOT="+h.remoteRoot,
	)
}

func createFakeBootstrapSpireSocket(t *testing.T, h *fakeRemoteAlphaWorkloadAuthBootstrapHarness, mode os.FileMode) string {
	t.Helper()
	socketPath := filepath.Join(h.remoteRoot, "run", "spire", "server", "private", "api.sock")
	if err := os.MkdirAll(filepath.Dir(socketPath), 0o755); err != nil {
		t.Fatalf("mkdir fake SPIRE socket parent: %v", err)
	}
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listen on fake SPIRE socket: %v", err)
	}
	t.Cleanup(func() {
		_ = listener.Close()
		_ = os.Remove(socketPath)
	})
	if err := os.Chmod(socketPath, mode); err != nil {
		t.Fatalf("chmod fake SPIRE socket: %v", err)
	}
	return socketPath
}

func TestRemoteAlphaOperatorRecoverySessionVaultWorkloadAuthBootstrapNoTTYFailsBeforeStaging(t *testing.T) {
	h := setupFakeRemoteAlphaWorkloadAuthBootstrapHarness(t)
	output, err := runRemoteAlphaOperatorWithEnv(h.env(),
		"recovery-session", "vault-workload-auth-bootstrap",
		"--ssh-target", "ds@m75q-test",
		"--execute-bootstrap",
		"--interactive-tty",
	)
	if err == nil {
		t.Fatalf("expected no-TTY failure before workload-auth bootstrap staging, got success:\n%s", output)
	}
	assertContainsAll(t, "vault-workload-auth-bootstrap no tty refusal", output,
		"requires visible local terminal",
		"no staging or SSH occurred",
		"No recovery-session live helper or IM execution occurred.",
	)
	if _, err := os.Stat(h.sshLogPath); !os.IsNotExist(err) {
		t.Fatalf("ssh should not run when workload-auth bootstrap local TTY guard fails: %v", err)
	}
	if _, err := os.Stat(h.scpLogPath); !os.IsNotExist(err) {
		t.Fatalf("scp should not run when workload-auth bootstrap local TTY guard fails: %v", err)
	}
}

func TestRemoteAlphaOperatorRecoverySessionVaultWorkloadAuthBootstrapPrepareSummaryPathUsesBoundedRemoteCommand(t *testing.T) {
	h := setupFakeRemoteAlphaWorkloadAuthBootstrapHarness(t)
	before := snapshotPathExistence(t, remoteAlphaOperatorRouteArtifactPaths(filepath.Join(".out", "remote-alpha-m75q", "vault-workload-auth-bootstrap-summary.json"))...)

	summaryParent := filepath.Join(h.remoteRoot, "var", "tmp", "execution-substrate-remote-alpha")
	if err := os.MkdirAll(summaryParent, 0o755); err != nil {
		t.Fatalf("mkdir summary parent: %v", err)
	}
	if err := os.Chmod(summaryParent, 0o555); err != nil {
		t.Fatalf("chmod summary parent: %v", err)
	}

	output, err := runRemoteAlphaOperatorWithPTY(t, h.env(),
		"recovery-session", "vault-workload-auth-bootstrap",
		"--ssh-target", "ds@m75q-test",
		"--prepare-summary-path",
		"--interactive-tty",
	)
	if err != nil {
		t.Fatalf("Mac-side fake workload-auth bootstrap prepare route failed: %v\noutput=%s\nssh=%s\nsudo=%s\nscp=%s\nhelper=%s\nrm=%s",
			err, output, readIfExists(h.sshLogPath), readIfExists(h.sudoLogPath), readIfExists(h.scpLogPath), readIfExists(h.helperLog), readIfExists(h.rmLogPath))
	}

	assertContainsAll(t, "Mac-side fake workload-auth bootstrap prepare output", output,
		"Preparing Remote Alpha Vault workload-auth bootstrap summary path through an explicit interactive SSH TTY.",
		"OS/filesystem preparation only",
		"may request only an OS sudo password",
		"summary_path_prepare_status=pass",
		"summary_parent_policy=owner_writable_0750_when_sudo_needed",
		"summary_file_policy=existing_regular_file_owner_writable_0600_when_sudo_needed",
		"final_summary_created=false",
		"vault_run=false",
		"workload_auth_check_run=false",
		"reset_unseal_im_support_bundle_cp_runtime_identity_run=false",
	)
	assertContainsNone(t, "Mac-side fake workload-auth bootstrap prepare output forbidden surfaces", output,
		"Running Mac-side Vault workload-auth bootstrap through an explicit interactive SSH TTY.",
		"Remote Alpha Vault workload-auth bootstrap helper finished.",
		"root-token-for-fake-bootstrap",
		"proof-value-for-fake-bootstrap",
		"remote-alpha-live-refresh",
		"remote-alpha-live-support-bundle",
		"cp-proof",
		"runtime identity generation was run",
	)

	sshLog := mustRead(t, h.sshLogPath)
	if got := strings.Count(sshLog, "tty=true"); got != 1 {
		t.Fatalf("expected exactly one interactive ssh -tt invocation for prepare, got %d log=%q", got, sshLog)
	}
	assertContainsAll(t, "fake workload-auth bootstrap prepare ssh log", sshLog,
		"tty=true target=ds@m75q-test",
		"/bin/bash -c",
		"vault-workload-auth-bootstrap-summary.json",
	)
	assertContainsNone(t, "fake workload-auth bootstrap prepare ssh log forbidden capture", sshLog,
		"/bin/bash -s -- /var/tmp/execution-substrate-remote-alpha",
		"exec /bin/bash -c",
		"execution-substrate-remote-alpha-vault-workload-auth-bootstrap",
		" tee ",
		"script ",
		"transcript",
		"remote-alpha-live-refresh",
		"remote-alpha-live-support-bundle",
		"cp-proof",
		".out",
	)

	sudoLog := mustRead(t, h.sudoLogPath)
	assertContainsAll(t, "fake workload-auth bootstrap prepare sudo log", sudoLog,
		"-v -p Remote Alpha OS sudo password for summary path preparation: ",
		"-n chown -h",
		"execution-substrate-remote-alpha",
	)
	assertContainsNone(t, "fake workload-auth bootstrap prepare sudo log forbidden surfaces", sudoLog,
		"install -d",
		"vault",
		"remote_alpha_vault_workload_auth_bootstrap.sh",
		"remote_alpha_vault_workload_auth_check.sh",
		"remote_alpha_reset_disposable_vault.sh",
		"tee ",
		"script ",
	)
	if _, err := os.Stat(h.scpLogPath); !os.IsNotExist(err) {
		t.Fatalf("scp should not run for prepare-summary-path-only route: %v log=%s", err, readIfExists(h.scpLogPath))
	}
	if _, err := os.Stat(h.helperLog); !os.IsNotExist(err) {
		t.Fatalf("bootstrap helper should not run for prepare-summary-path-only route: %v log=%s", err, readIfExists(h.helperLog))
	}
	rmLog := readIfExists(h.rmLogPath)
	assertContainsAll(t, "fake workload-auth bootstrap prepare rm log", rmLog,
		".vault-workload-auth-bootstrap-summary.prepare.",
	)
	assertContainsNone(t, "fake workload-auth bootstrap prepare rm log forbidden staging cleanup", rmLog,
		"execution-substrate-remote-alpha-vault-workload-auth-bootstrap",
		"remote_alpha_vault_workload_auth_bootstrap.sh",
	)
	if _, err := os.Stat(filepath.Join(summaryParent, "vault-workload-auth-bootstrap-summary.json")); !os.IsNotExist(err) {
		t.Fatalf("prepare-summary-path-only route should not create final summary: %v", err)
	}
	matches, err := filepath.Glob(filepath.Join(summaryParent, ".vault-workload-auth-bootstrap-summary.prepare.*"))
	if err != nil {
		t.Fatalf("glob prepare temp: %v", err)
	}
	if len(matches) != 0 {
		t.Fatalf("prepare-summary-path-only route left temp summary probes: %v", matches)
	}
	assertNoNewPaths(t, "Mac-side fake workload-auth bootstrap prepare route", before)
}

func TestRemoteAlphaOperatorRecoverySessionVaultWorkloadAuthBootstrapPrepareConfigReadabilityUsesBoundedRemoteCommand(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("fake unreadable config preparation requires a non-root test process")
	}

	h := setupFakeRemoteAlphaWorkloadAuthBootstrapHarness(t)
	before := snapshotPathExistence(t, remoteAlphaOperatorRouteArtifactPaths(filepath.Join(".out", "remote-alpha-m75q", "vault-workload-auth-bootstrap-summary.json"))...)

	configPath := filepath.Join(h.remoteRoot, "etc", "execution-substrate", "vault", "workload-zone-vault-config.json")
	if err := os.MkdirAll(filepath.Dir(configPath), 0o755); err != nil {
		t.Fatalf("mkdir config parent: %v", err)
	}
	const configContentSentinel = "config-content-sentinel"
	if err := os.WriteFile(configPath, []byte(`{"vault_config":{"address":"https://example.invalid","note":"`+configContentSentinel+`"}}`), 0o600); err != nil {
		t.Fatalf("write config fixture: %v", err)
	}
	if err := os.Chmod(configPath, 0o000); err != nil {
		t.Fatalf("chmod unreadable config fixture: %v", err)
	}
	if err := os.Chmod(filepath.Dir(configPath), 0o600); err != nil {
		t.Fatalf("chmod config parent fixture: %v", err)
	}
	t.Cleanup(func() {
		_ = os.Chmod(filepath.Dir(configPath), 0o700)
		_ = os.Chmod(configPath, 0o600)
	})

	output, err := runRemoteAlphaOperatorWithPTY(t, h.env(),
		"recovery-session", "vault-workload-auth-bootstrap",
		"--ssh-target", "ds@m75q-test",
		"--prepare-config-readability",
		"--interactive-tty",
	)
	if err != nil {
		t.Fatalf("Mac-side fake workload-auth bootstrap config prepare route failed: %v\noutput=%s\nssh=%s\nsudo=%s\nscp=%s\nhelper=%s\nrm=%s",
			err, output, readIfExists(h.sshLogPath), readIfExists(h.sudoLogPath), readIfExists(h.scpLogPath), readIfExists(h.helperLog), readIfExists(h.rmLogPath))
	}

	assertContainsAll(t, "Mac-side fake workload-auth bootstrap config prepare output", output,
		"Preparing Remote Alpha Vault workload-auth bootstrap config readability through an explicit interactive SSH TTY.",
		"OS/filesystem preparation only",
		"may request only an OS sudo password",
		"fixed-path user ACLs",
		"config_readability_prepare_status=pass",
		"workload-zone-vault-config.json",
		"config_readability_policy=fixed_path_user_acl_when_needed",
		"config_acl_applied=true",
		"config_contents_printed=false",
		"vault_run=false",
		"workload_auth_check_run=false",
		"reset_unseal_im_support_bundle_cp_runtime_identity_run=false",
	)
	assertContainsNone(t, "Mac-side fake workload-auth bootstrap config prepare output forbidden surfaces", output,
		configContentSentinel,
		"Running Mac-side Vault workload-auth bootstrap through an explicit interactive SSH TTY.",
		"Remote Alpha Vault workload-auth bootstrap helper finished.",
		"root-token-for-fake-bootstrap",
		"proof-value-for-fake-bootstrap",
		"remote-alpha-live-refresh",
		"remote-alpha-live-support-bundle",
		"cp-proof",
		"runtime identity generation was run",
	)

	sshLog := mustRead(t, h.sshLogPath)
	if got := strings.Count(sshLog, "tty=true"); got != 1 {
		t.Fatalf("expected exactly one interactive ssh -tt invocation for config prepare, got %d log=%q", got, sshLog)
	}
	assertContainsAll(t, "fake workload-auth bootstrap config prepare ssh log", sshLog,
		"tty=true target=ds@m75q-test",
		"/bin/bash -c",
		"workload-zone-vault-config.json",
	)
	assertContainsNone(t, "fake workload-auth bootstrap config prepare ssh log forbidden capture", sshLog,
		configContentSentinel,
		"/bin/bash -s -- /var/tmp/execution-substrate-remote-alpha",
		"exec /bin/bash -c",
		"execution-substrate-remote-alpha-vault-workload-auth-bootstrap",
		" tee ",
		"script ",
		"transcript",
		".out",
	)

	sudoLog := mustRead(t, h.sudoLogPath)
	assertContainsAll(t, "fake workload-auth bootstrap config prepare sudo log", sudoLog,
		"-v -p Remote Alpha OS sudo password for config readability preparation: ",
		"-n setfacl -m u:",
		":--x --",
		":r-- --",
		"workload-zone-vault-config.json",
	)
	assertContainsNone(t, "fake workload-auth bootstrap config prepare sudo log forbidden surfaces", sudoLog,
		configContentSentinel,
		"remote_alpha_vault_workload_auth_bootstrap.sh",
		"remote_alpha_vault_workload_auth_check.sh",
		"remote_alpha_reset_disposable_vault.sh",
		"chmod 777",
		"chown",
		"tee ",
		"script ",
	)
	if _, err := os.Stat(h.scpLogPath); !os.IsNotExist(err) {
		t.Fatalf("scp should not run for prepare-config-readability-only route: %v log=%s", err, readIfExists(h.scpLogPath))
	}
	if _, err := os.Stat(h.helperLog); !os.IsNotExist(err) {
		t.Fatalf("bootstrap helper should not run for prepare-config-readability-only route: %v log=%s", err, readIfExists(h.helperLog))
	}
	if rmLog := readIfExists(h.rmLogPath); rmLog != "" && rmLog != "<missing>" {
		t.Fatalf("prepare-config-readability-only route should not delete summaries or staging paths: %s", rmLog)
	}
	assertNoNewPaths(t, "Mac-side fake workload-auth bootstrap config prepare route", before)
}

func TestRemoteAlphaOperatorRecoverySessionVaultWorkloadAuthBootstrapPrepareSpireBundleReadUsesBoundedRemoteCommand(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("fake SPIRE socket ACL preparation requires a non-root test process")
	}

	h := setupFakeRemoteAlphaWorkloadAuthBootstrapHarness(t)
	before := snapshotPathExistence(t, remoteAlphaOperatorRouteArtifactPaths(filepath.Join(".out", "remote-alpha-m75q", "vault-workload-auth-bootstrap-summary.json"))...)

	socketPath := createFakeBootstrapSpireSocket(t, h, 0o000)
	if err := os.Chmod(filepath.Dir(socketPath), 0o700); err != nil {
		t.Fatalf("chmod fake SPIRE socket parent: %v", err)
	}
	t.Cleanup(func() {
		_ = os.Chmod(filepath.Dir(socketPath), 0o700)
		_ = os.Chmod(socketPath, 0o600)
	})

	output, err := runRemoteAlphaOperatorWithPTY(t, h.env(),
		"recovery-session", "vault-workload-auth-bootstrap",
		"--ssh-target", "ds@m75q-test",
		"--prepare-spire-bundle-read",
		"--interactive-tty",
	)
	if err != nil {
		t.Fatalf("Mac-side fake workload-auth bootstrap SPIRE prepare route failed: %v\noutput=%s\nssh=%s\nsudo=%s\nspire=%s\nscp=%s\nhelper=%s\nrm=%s",
			err, output, readIfExists(h.sshLogPath), readIfExists(h.sudoLogPath), readIfExists(h.spireLog), readIfExists(h.scpLogPath), readIfExists(h.helperLog), readIfExists(h.rmLogPath))
	}

	assertContainsAll(t, "Mac-side fake workload-auth bootstrap SPIRE prepare output", output,
		"Preparing Remote Alpha Vault workload-auth bootstrap SPIRE bundle-read access through an explicit interactive SSH TTY.",
		"OS/filesystem/capability preparation only",
		"may request only an OS sudo password",
		"fixed-path user ACLs",
		"spire_bundle_read_prepare_status=pass",
		"api.sock",
		"spire_bundle_read_policy=fixed_path_user_acl_when_needed",
		"spire_socket_access_classification=spire_socket_present_needs_acl",
		"spire_socket_acl_applied=true",
		"bundle_output_discarded=true",
		"bundle_contents_printed=false",
		"vault_run=false",
		"workload_auth_check_run=false",
		"reset_unseal_im_support_bundle_cp_runtime_identity_run=false",
	)
	assertContainsNone(t, "Mac-side fake workload-auth bootstrap SPIRE prepare output forbidden surfaces", output,
		"FAKE-SPIRE-BUNDLE-MATERIAL-MUST-NOT-PRINT",
		"Running Mac-side Vault workload-auth bootstrap through an explicit interactive SSH TTY.",
		"Remote Alpha Vault workload-auth bootstrap helper finished.",
		"root-token-for-fake-bootstrap",
		"proof-value-for-fake-bootstrap",
		"remote-alpha-live-refresh",
		"remote-alpha-live-support-bundle",
		"cp-proof",
		"runtime identity generation was run",
	)

	sshLog := mustRead(t, h.sshLogPath)
	if got := strings.Count(sshLog, "tty=true"); got != 1 {
		t.Fatalf("expected exactly one interactive ssh -tt invocation for SPIRE prepare, got %d log=%q", got, sshLog)
	}
	assertContainsAll(t, "fake workload-auth bootstrap SPIRE prepare ssh log", sshLog,
		"tty=true target=ds@m75q-test",
		"/bin/bash -c",
		"/run/spire/server/private/api.sock",
		"spire_bundle_read_prepare_status=pass",
	)
	assertContainsNone(t, "fake workload-auth bootstrap SPIRE prepare ssh log forbidden capture", sshLog,
		"FAKE-SPIRE-BUNDLE-MATERIAL-MUST-NOT-PRINT",
		"/bin/bash -s -- /var/tmp/execution-substrate-remote-alpha",
		"exec /bin/bash -c",
		"execution-substrate-remote-alpha-vault-workload-auth-bootstrap",
		" tee ",
		"script ",
		"transcript",
		".out",
	)

	sudoLog := mustRead(t, h.sudoLogPath)
	assertContainsAll(t, "fake workload-auth bootstrap SPIRE prepare sudo log", sudoLog,
		"-v -p Remote Alpha OS sudo password for SPIRE bundle-read preparation: ",
		"-n setfacl -m u:",
		":rw- --",
		"api.sock",
	)
	assertContainsNone(t, "fake workload-auth bootstrap SPIRE prepare sudo log forbidden surfaces", sudoLog,
		"FAKE-SPIRE-BUNDLE-MATERIAL-MUST-NOT-PRINT",
		"remote_alpha_vault_workload_auth_bootstrap.sh",
		"remote_alpha_vault_workload_auth_check.sh",
		"remote_alpha_reset_disposable_vault.sh",
		"chmod 777",
		"chown",
		"tee ",
		"script ",
	)
	spireLog := mustRead(t, h.spireLog)
	assertContainsAll(t, "fake workload-auth bootstrap SPIRE command log", spireLog,
		"bundle show -format spiffe -socketPath",
		"api.sock",
	)
	if _, err := os.Stat(h.scpLogPath); !os.IsNotExist(err) {
		t.Fatalf("scp should not run for prepare-spire-bundle-read-only route: %v log=%s", err, readIfExists(h.scpLogPath))
	}
	if _, err := os.Stat(h.helperLog); !os.IsNotExist(err) {
		t.Fatalf("bootstrap helper should not run for prepare-spire-bundle-read-only route: %v log=%s", err, readIfExists(h.helperLog))
	}
	if rmLog := readIfExists(h.rmLogPath); rmLog != "" && rmLog != "<missing>" {
		t.Fatalf("prepare-spire-bundle-read-only route should not delete summaries or staging paths: %s", rmLog)
	}
	assertNoNewPaths(t, "Mac-side fake workload-auth bootstrap SPIRE prepare route", before)
}

func TestRemoteAlphaOperatorRecoverySessionVaultWorkloadAuthBootstrapPrepareSpireBundleReadClassifiesTraversalAmbiguityWithSudoVisibleInspection(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("fake no-sudo traversal ambiguity requires a non-root test process")
	}

	h := setupFakeRemoteAlphaWorkloadAuthBootstrapHarness(t)
	socketPath := createFakeBootstrapSpireSocket(t, h, 0o600)
	spireServerDir := filepath.Dir(filepath.Dir(socketPath))
	if err := os.Chmod(spireServerDir, 0o000); err != nil {
		t.Fatalf("chmod fake SPIRE server dir: %v", err)
	}
	t.Cleanup(func() {
		_ = os.Chmod(spireServerDir, 0o700)
		_ = os.Chmod(socketPath, 0o600)
	})

	output, err := runRemoteAlphaOperatorWithPTY(t, h.env(),
		"recovery-session", "vault-workload-auth-bootstrap",
		"--ssh-target", "ds@m75q-test",
		"--prepare-spire-bundle-read",
		"--interactive-tty",
	)
	if err != nil {
		t.Fatalf("expected sudo-visible SPIRE path inspection to disambiguate traversal denial: %v\noutput=%s\nsudo=%s\nspire=%s",
			err, output, readIfExists(h.sudoLogPath), readIfExists(h.spireLog))
	}

	assertContainsAll(t, "SPIRE traversal ambiguity prepare output", output,
		"spire_bundle_read_prepare_status=pass",
		"spire_socket_access_classification=spire_socket_present_needs_acl",
		"spire_socket_acl_applied=true",
		"bundle_contents_printed=false",
		"vault_run=false",
		"workload_auth_check_run=false",
		"reset_unseal_im_support_bundle_cp_runtime_identity_run=false",
	)
	assertContainsNone(t, "SPIRE traversal ambiguity output forbidden classifications", output,
		"spire_socket_parent_missing",
		"FAKE-SPIRE-BUNDLE-MATERIAL-MUST-NOT-PRINT",
		"raw fake SPIRE stderr",
	)

	sudoLog := mustRead(t, h.sudoLogPath)
	assertContainsAll(t, "SPIRE traversal ambiguity sudo log", sudoLog,
		"-n test -d",
		"-n test -S",
		"-n setfacl -m u:",
		":--x --",
		"run/spire/server",
	)
	assertContainsNone(t, "SPIRE traversal ambiguity sudo log forbidden broad changes", sudoLog,
		"chmod 777",
		"chown",
		" o:",
		"g:",
		"workload-zone-vault-config.json",
		"remote_alpha_vault_workload_auth_bootstrap.sh",
	)
}

func TestRemoteAlphaOperatorRecoverySessionVaultWorkloadAuthBootstrapPrepareSpireBundleReadFailsForTrueMissingParentUnderSudoVisibleInspection(t *testing.T) {
	h := setupFakeRemoteAlphaWorkloadAuthBootstrapHarness(t)
	spireServerDir := filepath.Join(h.remoteRoot, "run", "spire", "server")
	if err := os.MkdirAll(spireServerDir, 0o755); err != nil {
		t.Fatalf("mkdir fake SPIRE server dir: %v", err)
	}

	output, err := runRemoteAlphaOperatorWithPTY(t, h.env(),
		"recovery-session", "vault-workload-auth-bootstrap",
		"--ssh-target", "ds@m75q-test",
		"--prepare-spire-bundle-read",
		"--interactive-tty",
	)
	if err == nil {
		t.Fatalf("expected missing SPIRE socket parent failure:\n%s", output)
	}

	assertContainsAll(t, "missing SPIRE parent prepare output", output,
		"spire_bundle_read_prepare_status=fail",
		"error_classification=spire_socket_parent_missing",
		"spire_server_socket_path=",
		"bundle_contents_printed=false",
		"vault_run=false",
		"workload_auth_check_run=false",
		"reset_unseal_im_support_bundle_cp_runtime_identity_run=false",
	)
	assertContainsNone(t, "missing SPIRE parent output forbidden", output,
		"FAKE-SPIRE-BUNDLE-MATERIAL-MUST-NOT-PRINT",
		"Remote Alpha Vault workload-auth bootstrap helper finished.",
	)
	if _, statErr := os.Stat(filepath.Join(spireServerDir, "private")); !os.IsNotExist(statErr) {
		t.Fatalf("SPIRE prep must not create missing parent, stat err=%v", statErr)
	}
	sudoLog := mustRead(t, h.sudoLogPath)
	assertContainsNone(t, "missing SPIRE parent sudo log forbidden ACL", sudoLog,
		"setfacl",
		"chmod 777",
		"chown",
	)
}

func TestRemoteAlphaOperatorRecoverySessionVaultWorkloadAuthBootstrapPrepareSpireBundleReadFailsForTrueMissingSocketUnderSudoVisibleInspection(t *testing.T) {
	h := setupFakeRemoteAlphaWorkloadAuthBootstrapHarness(t)
	spireParent := filepath.Join(h.remoteRoot, "run", "spire", "server", "private")
	if err := os.MkdirAll(spireParent, 0o755); err != nil {
		t.Fatalf("mkdir fake SPIRE socket parent: %v", err)
	}

	output, err := runRemoteAlphaOperatorWithPTY(t, h.env(),
		"recovery-session", "vault-workload-auth-bootstrap",
		"--ssh-target", "ds@m75q-test",
		"--prepare-spire-bundle-read",
		"--interactive-tty",
	)
	if err == nil {
		t.Fatalf("expected missing SPIRE socket failure:\n%s", output)
	}

	assertContainsAll(t, "missing SPIRE socket prepare output", output,
		"spire_bundle_read_prepare_status=fail",
		"error_classification=spire_socket_missing",
		"bundle_contents_printed=false",
		"vault_run=false",
		"workload_auth_check_run=false",
		"reset_unseal_im_support_bundle_cp_runtime_identity_run=false",
	)
	if _, statErr := os.Stat(filepath.Join(spireParent, "api.sock")); !os.IsNotExist(statErr) {
		t.Fatalf("SPIRE prep must not create missing socket, stat err=%v", statErr)
	}
	sudoLog := mustRead(t, h.sudoLogPath)
	assertContainsNone(t, "missing SPIRE socket sudo log forbidden ACL", sudoLog,
		"setfacl",
		"chmod 777",
		"chown",
	)
}

func TestRemoteAlphaOperatorRecoverySessionVaultWorkloadAuthBootstrapPrepareSpireBundleReadFailsForWrongSocketType(t *testing.T) {
	h := setupFakeRemoteAlphaWorkloadAuthBootstrapHarness(t)
	socketPath := filepath.Join(h.remoteRoot, "run", "spire", "server", "private", "api.sock")
	if err := os.MkdirAll(filepath.Dir(socketPath), 0o755); err != nil {
		t.Fatalf("mkdir fake SPIRE socket parent: %v", err)
	}
	if err := os.WriteFile(socketPath, []byte("not a socket"), 0o600); err != nil {
		t.Fatalf("write wrong-type SPIRE path fixture: %v", err)
	}

	output, err := runRemoteAlphaOperatorWithPTY(t, h.env(),
		"recovery-session", "vault-workload-auth-bootstrap",
		"--ssh-target", "ds@m75q-test",
		"--prepare-spire-bundle-read",
		"--interactive-tty",
	)
	if err == nil {
		t.Fatalf("expected wrong-type SPIRE socket failure:\n%s", output)
	}

	assertContainsAll(t, "wrong-type SPIRE socket prepare output", output,
		"spire_bundle_read_prepare_status=fail",
		"error_classification=spire_socket_not_socket",
		"bundle_contents_printed=false",
		"vault_run=false",
		"workload_auth_check_run=false",
		"reset_unseal_im_support_bundle_cp_runtime_identity_run=false",
	)
	sudoLog := mustRead(t, h.sudoLogPath)
	assertContainsNone(t, "wrong-type SPIRE socket sudo log forbidden ACL", sudoLog,
		"setfacl",
		"chmod 777",
		"chown",
	)
}

func TestRemoteAlphaOperatorRecoverySessionVaultWorkloadAuthBootstrapPrepareSpireBundleReadClassifiesInactiveServerBeforeAcl(t *testing.T) {
	h := setupFakeRemoteAlphaWorkloadAuthBootstrapHarness(t)

	output, err := runRemoteAlphaOperatorWithPTY(t, append(h.env(), "REMOTE_ALPHA_FAKE_SYSTEMCTL_SPIRE_ACTIVE_STATUS=3"),
		"recovery-session", "vault-workload-auth-bootstrap",
		"--ssh-target", "ds@m75q-test",
		"--prepare-spire-bundle-read",
		"--interactive-tty",
	)
	if err == nil {
		t.Fatalf("expected inactive SPIRE server failure:\n%s", output)
	}

	assertContainsAll(t, "inactive SPIRE server prepare output", output,
		"spire_bundle_read_prepare_status=fail",
		"error_classification=spire_server_inactive_or_unknown",
		"bundle_contents_printed=false",
		"vault_run=false",
		"workload_auth_check_run=false",
		"reset_unseal_im_support_bundle_cp_runtime_identity_run=false",
	)
	sudoLog := readIfExists(h.sudoLogPath)
	assertContainsNone(t, "inactive SPIRE server must not apply ACL", sudoLog,
		"setfacl",
		"chmod 777",
		"chown",
	)
}

func TestRemoteAlphaOperatorRecoverySessionVaultWorkloadAuthBootstrapPrepareSpireBundleReadClassifiesAccessibleBundleShowFailure(t *testing.T) {
	h := setupFakeRemoteAlphaWorkloadAuthBootstrapHarness(t)
	createFakeBootstrapSpireSocket(t, h, 0o600)

	output, err := runRemoteAlphaOperatorWithPTY(t, append(h.env(), "REMOTE_ALPHA_FAKE_SPIRE_SERVER_FORCE_FAIL=true"),
		"recovery-session", "vault-workload-auth-bootstrap",
		"--ssh-target", "ds@m75q-test",
		"--prepare-spire-bundle-read",
		"--interactive-tty",
	)
	if err == nil {
		t.Fatalf("expected SPIRE bundle show failure:\n%s", output)
	}

	assertContainsAll(t, "accessible SPIRE bundle show failure output", output,
		"spire_bundle_read_prepare_status=fail",
		"error_classification=spire_bundle_show_failed",
		"spire_socket_access_classification=spire_socket_present_accessible",
		"bundle_contents_printed=false",
		"vault_run=false",
		"workload_auth_check_run=false",
		"reset_unseal_im_support_bundle_cp_runtime_identity_run=false",
	)
	assertContainsNone(t, "accessible SPIRE bundle show failure output forbidden raw content", output,
		"raw fake SPIRE stderr",
		"FAKE-SPIRE-BUNDLE-MATERIAL-MUST-NOT-PRINT",
	)
	sudoLog := readIfExists(h.sudoLogPath)
	assertContainsNone(t, "accessible SPIRE bundle show failure must not apply ACL", sudoLog,
		"setfacl",
		"chmod 777",
		"chown",
	)
}

func TestRemoteAlphaOperatorRecoverySessionVaultWorkloadAuthBootstrapPrepareRunsBeforeHelperExecution(t *testing.T) {
	h := setupFakeRemoteAlphaWorkloadAuthBootstrapHarness(t)
	before := snapshotPathExistence(t, remoteAlphaOperatorRouteArtifactPaths(filepath.Join(".out", "remote-alpha-m75q", "vault-workload-auth-bootstrap-summary.json"))...)

	summaryParent := filepath.Join(h.remoteRoot, "var", "tmp", "execution-substrate-remote-alpha")
	if err := os.MkdirAll(summaryParent, 0o755); err != nil {
		t.Fatalf("mkdir summary parent: %v", err)
	}
	if err := os.Chmod(summaryParent, 0o555); err != nil {
		t.Fatalf("chmod summary parent: %v", err)
	}
	configPath := filepath.Join(h.remoteRoot, "etc", "execution-substrate", "vault", "workload-zone-vault-config.json")
	if err := os.MkdirAll(filepath.Dir(configPath), 0o755); err != nil {
		t.Fatalf("mkdir config parent: %v", err)
	}
	if err := os.WriteFile(configPath, []byte(`{"vault_config":{"address":"https://example.invalid"}}`), 0o644); err != nil {
		t.Fatalf("write config fixture: %v", err)
	}
	createFakeBootstrapSpireSocket(t, h, 0o600)

	output, err := runRemoteAlphaOperatorWithPTY(t, h.env(),
		"recovery-session", "vault-workload-auth-bootstrap",
		"--ssh-target", "ds@m75q-test",
		"--execute-bootstrap",
		"--prepare-summary-path",
		"--prepare-config-readability",
		"--prepare-spire-bundle-read",
		"--interactive-tty",
	)
	if err != nil {
		t.Fatalf("Mac-side fake workload-auth bootstrap combined prepare+execute route failed: %v\noutput=%s\nssh=%s\nscp=%s\nsudo=%s\nhelper=%s\nrm=%s",
			err, output, readIfExists(h.sshLogPath), readIfExists(h.scpLogPath), readIfExists(h.sudoLogPath), readIfExists(h.helperLog), readIfExists(h.rmLogPath))
	}

	assertContainsAll(t, "Mac-side fake workload-auth bootstrap combined output", output,
		"Preparing Remote Alpha Vault workload-auth bootstrap summary path through an explicit interactive SSH TTY.",
		"summary_path_prepare_status=pass",
		"Preparing Remote Alpha Vault workload-auth bootstrap config readability through an explicit interactive SSH TTY.",
		"config_readability_prepare_status=pass",
		"Preparing Remote Alpha Vault workload-auth bootstrap SPIRE bundle-read access through an explicit interactive SSH TTY.",
		"spire_bundle_read_prepare_status=pass",
		"Running Mac-side Vault workload-auth bootstrap through an explicit interactive SSH TTY.",
		"Staging only scripts/remote_alpha_vault_workload_auth_bootstrap.sh and scripts/internal/remote_alpha_vault_workload_auth_bootstrap.sh.",
		"Remote Alpha Vault workload-auth bootstrap helper finished.",
		"Workload-auth check remains a separate post-bootstrap command and was not run here.",
	)
	prepareOutputIndex := strings.Index(output, "Preparing Remote Alpha Vault workload-auth bootstrap summary path")
	configPrepareOutputIndex := strings.Index(output, "Preparing Remote Alpha Vault workload-auth bootstrap config readability")
	spirePrepareOutputIndex := strings.Index(output, "Preparing Remote Alpha Vault workload-auth bootstrap SPIRE bundle-read access")
	executeOutputIndex := strings.Index(output, "Running Mac-side Vault workload-auth bootstrap")
	if prepareOutputIndex < 0 || configPrepareOutputIndex < 0 || spirePrepareOutputIndex < 0 || executeOutputIndex < 0 || !(prepareOutputIndex < configPrepareOutputIndex && configPrepareOutputIndex < spirePrepareOutputIndex && spirePrepareOutputIndex < executeOutputIndex) {
		t.Fatalf("expected prepare output before execute output, got output=%s", output)
	}

	sshLog := mustRead(t, h.sshLogPath)
	prepareIndex := strings.Index(sshLog, "vault-workload-auth-bootstrap-summary.json")
	configPrepareIndex := strings.Index(sshLog, "workload-zone-vault-config.json")
	spirePrepareIndex := strings.Index(sshLog, "/run/spire/server/private/api.sock")
	stageIndex := strings.Index(sshLog, "execution-substrate-remote-alpha-vault-workload-auth-bootstrap")
	helperIndex := strings.Index(sshLog, "exec /bin/bash -c")
	if prepareIndex < 0 || configPrepareIndex < 0 || spirePrepareIndex < 0 || stageIndex < 0 || helperIndex < 0 {
		t.Fatalf("expected summary prepare, config prepare, SPIRE prepare, stage, and helper ssh invocations in log=%q", sshLog)
	}
	if !(prepareIndex < configPrepareIndex && configPrepareIndex < spirePrepareIndex && spirePrepareIndex < stageIndex && stageIndex < helperIndex) {
		t.Fatalf("expected summary prepare before config prepare before SPIRE prepare before stage before helper execution, log=%q", sshLog)
	}
	if got := strings.Count(sshLog, "tty=true"); got != 4 {
		t.Fatalf("expected four interactive ssh -tt invocations for summary prepare, config prepare, SPIRE prepare, and helper, got %d log=%q", got, sshLog)
	}
	assertContainsNone(t, "fake workload-auth bootstrap combined ssh log forbidden capture", sshLog,
		" tee ",
		"script ",
		"transcript",
		"--execute-reset",
		"--unseal-only",
		"--post-unseal-check",
		"remote-alpha-live-refresh",
		"remote-alpha-live-support-bundle",
		"cp-proof",
		".out",
	)

	scpLog := strings.TrimSpace(mustRead(t, h.scpLogPath))
	if scpLines := strings.Split(scpLog, "\n"); len(scpLines) != 2 {
		t.Fatalf("expected exactly two staged file uploads after prepare, got %q", scpLog)
	}
	helperLog := mustRead(t, h.helperLog)
	assertContainsAll(t, "fake workload-auth bootstrap combined helper log", helperLog,
		"public_args=",
		"/scripts/internal/remote_alpha_vault_workload_auth_bootstrap.sh",
	)
	assertContainsNone(t, "fake workload-auth bootstrap combined helper log forbidden args", helperLog,
		"--prepare-summary-path",
		"--vault-addr",
		"--vault-role",
		"--api-key",
		"--prepare-spire-bundle-read",
		"--proof-secret-value",
		"--execute-reset",
		"remote-alpha-live-refresh",
		"remote-alpha-live-support-bundle",
	)
	sudoLog := mustRead(t, h.sudoLogPath)
	assertContainsAll(t, "fake workload-auth bootstrap combined sudo log", sudoLog,
		"-v -p Remote Alpha OS sudo password for summary path preparation: ",
		"-n chown -h",
	)
	assertNoNewPaths(t, "Mac-side fake workload-auth bootstrap combined route", before)
}

func TestRemoteAlphaOperatorRecoverySessionVaultWorkloadAuthBootstrapStagesOnlyApprovedHelpersWithTTYAndCleanup(t *testing.T) {
	h := setupFakeRemoteAlphaWorkloadAuthBootstrapHarness(t)
	before := snapshotPathExistence(t, remoteAlphaOperatorRouteArtifactPaths(filepath.Join(".out", "remote-alpha-m75q", "vault-workload-auth-bootstrap-summary.json"))...)

	output, err := runRemoteAlphaOperatorWithPTY(t, h.env(),
		"recovery-session", "vault-workload-auth-bootstrap",
		"--ssh-target", "ds@m75q-test",
		"--execute-bootstrap",
		"--interactive-tty",
	)
	if err != nil {
		t.Fatalf("Mac-side fake workload-auth bootstrap route failed: %v\noutput=%s\nssh=%s\nscp=%s\nhelper=%s\nrm=%s",
			err, output, readIfExists(h.sshLogPath), readIfExists(h.scpLogPath), readIfExists(h.helperLog), readIfExists(h.rmLogPath))
	}

	assertContainsAll(t, "Mac-side fake workload-auth bootstrap output", output,
		"Running Mac-side Vault workload-auth bootstrap through an explicit interactive SSH TTY.",
		"Staging only scripts/remote_alpha_vault_workload_auth_bootstrap.sh and scripts/internal/remote_alpha_vault_workload_auth_bootstrap.sh.",
		"Invoking only the staged public bootstrap helper; no helper override flags are accepted or passed.",
		"The operator enters Vault bootstrap authority and any proof secret value only into the visible remote helper prompt.",
		"Canonical bootstrap summary stays remote at /var/tmp/execution-substrate-remote-alpha/vault-workload-auth-bootstrap-summary.json.",
		"No transcript, tee/script capture, .out, report, support bundle, operator summary, generated Mac artifact, workload-auth check, reset/unseal, IM refresh, runtime identity generation, ES token brokerage, or CP proof is created or run.",
		"staged helper cleanup was attempted",
		"Canonical remote bootstrap summary path: /var/tmp/execution-substrate-remote-alpha/vault-workload-auth-bootstrap-summary.json",
		"The summary remains on the remote host",
		"did not copy it back to Mac .out",
		"did not print full summary JSON",
		"Workload-auth check remains a separate post-bootstrap command and was not run here.",
	)
	assertContainsNone(t, "Mac-side fake workload-auth bootstrap output forbidden capture", output,
		"root-token-for-fake-bootstrap",
		"proof-value-for-fake-bootstrap",
		"remote-alpha-live-refresh",
		"remote-alpha-live-support-bundle",
		"cp-proof",
		"runtime identity generation was run",
	)

	scpLog := strings.TrimSpace(mustRead(t, h.scpLogPath))
	scpLines := strings.Split(scpLog, "\n")
	if len(scpLines) != 2 {
		t.Fatalf("expected exactly two staged file uploads, got %q", scpLog)
	}
	assertContainsAll(t, "fake workload-auth bootstrap scp log", scpLog,
		filepath.Join(remoteAlphaOperatorRepoRoot(), "scripts", "remote_alpha_vault_workload_auth_bootstrap.sh"),
		filepath.Join(remoteAlphaOperatorRepoRoot(), "scripts", "internal", "remote_alpha_vault_workload_auth_bootstrap.sh"),
		"/scripts/remote_alpha_vault_workload_auth_bootstrap.sh",
		"/scripts/internal/remote_alpha_vault_workload_auth_bootstrap.sh",
	)
	assertContainsNone(t, "fake workload-auth bootstrap scp log", scpLog,
		"remote_alpha_operator.sh",
		"remote_alpha_reset_disposable_vault.sh",
		"remote_alpha_vault_workload_auth_check.sh",
		"remote_alpha_runtime_identity_helper_summary.sh",
		"remote_alpha_migrate_vault_service_user.sh",
		"remote_alpha_prepare_es_config_tls",
		"remote_alpha_deploy_es_binaries",
		"bundle",
	)

	sshLog := mustRead(t, h.sshLogPath)
	if got := strings.Count(sshLog, "tty=true"); got != 1 {
		t.Fatalf("expected exactly one interactive ssh -tt invocation, got %d log=%q", got, sshLog)
	}
	assertContainsAll(t, "fake workload-auth bootstrap ssh log", sshLog,
		"tty=true target=ds@m75q-test",
	)
	assertContainsNone(t, "fake workload-auth bootstrap ssh log forbidden capture", sshLog,
		" tee ",
		"script ",
		"transcript",
		"--execute-reset",
		"--unseal-only",
		"--post-unseal-check",
		"remote-alpha-live-refresh",
		"remote-alpha-live-support-bundle",
		"cp-proof",
		".out",
	)

	helperLog := mustRead(t, h.helperLog)
	assertContainsAll(t, "fake workload-auth bootstrap helper log", helperLog,
		"public_args=",
		"/scripts/internal/remote_alpha_vault_workload_auth_bootstrap.sh",
	)
	assertContainsNone(t, "fake workload-auth bootstrap helper log forbidden args", helperLog,
		"--vault-addr",
		"--vault-role",
		"--vault-audience",
		"--spiffe-id",
		"--summary-path",
		"--config-path",
		"--root-token",
		"--vault-token",
		"--api-key",
		"--proof-secret-value",
		"--execute-reset",
		"--unseal-only",
		"--post-unseal-check",
		"remote-alpha-live-refresh",
		"remote-alpha-live-support-bundle",
	)

	rmLog := mustRead(t, h.rmLogPath)
	assertContainsAll(t, "fake workload-auth bootstrap remote cleanup log", rmLog,
		"execution-substrate-remote-alpha-vault-workload-auth-bootstrap",
	)
	assertRemoteAlphaOperatorStageFoldersGone(t, h.remoteRoot, "execution-substrate-remote-alpha-vault-workload-auth-bootstrap")
	assertNoNewPaths(t, "Mac-side fake workload-auth bootstrap route", before)
}

func TestRemoteAlphaOperatorRecoverySessionVaultResetDisposableSourceKeepsExecuteRouteNarrow(t *testing.T) {
	source := mustRead(t, remoteAlphaOperatorScriptPath())
	section := docSection(t, source, "recovery_session_vault_reset_disposable_require_command() {", "\nrecovery_session_es_service_tls_require_command() {")

	assertContainsAll(t, "vault-reset-disposable source section", section,
		"REMOTE_ALPHA_VAULT_RESET_HELPER",
		"REMOTE_ALPHA_VAULT_RESET_DRY_RUN_STAGE_ROOT",
		"REMOTE_ALPHA_VAULT_RESET_EXECUTE_STAGE_ROOT",
		"recovery_session_vault_reset_disposable_require_local_tty",
		"ssh -tt",
		`"${helper_path}" --execute-reset`,
		`"${helper_path}" --dry-run`,
		"staged helper cleanup was attempted",
	)
	assertContainsNone(t, "vault-reset-disposable source section", section,
		"scripts/internal/",
		`scp "${SCRIPT_DIR}/remote_alpha_operator.sh"`,
		"remote_alpha_vault_workload_auth_check.sh",
		"remote_alpha_runtime_identity_helper_summary.sh",
		"remote_alpha_migrate_vault_service_user.sh",
		"remote_alpha_prepare_es_config_tls.sh",
		"remote_alpha_deploy_es_binaries.sh",
		"remote_alpha_prepare_es_writable_state_ownership.sh",
		"remote-alpha-live-refresh",
		"remote-alpha-live-support-bundle",
		"print_refresh_command",
		"print_support_bundle_command",
		"--workload-auth",
		"--runtime-identity",
		"operator_summary",
		"summary_path",
		"support_output_root",
	)
}

func TestRemoteAlphaOperatorRecoverySessionVaultWorkloadAuthBootstrapSourceKeepsRouteNarrow(t *testing.T) {
	source := mustRead(t, remoteAlphaOperatorScriptPath())
	section := docSection(t, source, "recovery_session_vault_workload_auth_bootstrap() {", "\nrecovery_session_vault_unseal_existing_require_command() {")

	assertContainsAll(t, "vault-workload-auth-bootstrap source section", section,
		"REMOTE_ALPHA_VAULT_WORKLOAD_AUTH_BOOTSTRAP_PUBLIC_HELPER",
		"REMOTE_ALPHA_VAULT_WORKLOAD_AUTH_BOOTSTRAP_INTERNAL_HELPER",
		"REMOTE_ALPHA_VAULT_WORKLOAD_AUTH_BOOTSTRAP_STAGE_ROOT",
		"REMOTE_ALPHA_VAULT_WORKLOAD_AUTH_BOOTSTRAP_REMOTE_SUMMARY_DIR",
		"REMOTE_ALPHA_VAULT_WORKLOAD_AUTH_BOOTSTRAP_REMOTE_SUMMARY",
		"REMOTE_ALPHA_VAULT_WORKLOAD_AUTH_BOOTSTRAP_CONFIG",
		"REMOTE_ALPHA_VAULT_WORKLOAD_AUTH_BOOTSTRAP_SPIRE_SERVER_SOCKET",
		"recovery_session_vault_workload_auth_bootstrap_plan",
		"recovery_session_vault_workload_auth_bootstrap_inventory",
		"recovery_session_vault_workload_auth_bootstrap_require_local_tty",
		"--execute-bootstrap",
		"--prepare-summary-path",
		"--prepare-config-readability",
		"--prepare-spire-bundle-read",
		"--ssh-target",
		"--interactive-tty",
		"--host-local",
		"--execute-reset",
		"--unseal-only",
		"--post-unseal-check",
		"--governed-smoke-command",
		"--proof-secret-value",
		"fixed documented bootstrap values",
		"proof secret values must never be passed",
		"recovery_session_vault_workload_auth_bootstrap_prepare_summary_path_remote",
		"summary_path_prepare_status=pass",
		`ssh -tt "${ssh_target}" "/bin/bash -c ${remote_prepare_command_quoted}"`,
		`sudo -v -p "Remote Alpha OS sudo password for summary path preparation: "`,
		`sudo -n "$@"`,
		"REMOTE_ALPHA_OUTPUT_DIR_DEFINITION",
		`remote_alpha_prepare_output_dir "${summary_dir}"`,
		"summary_parent_unsafe",
		`run_sudo chown -h "${helper_user}:${helper_group}" -- "${summary_dir}"`,
		"summary_path_symlink",
		`run_sudo chown -h "${helper_user}:${helper_group}" -- "${summary_path}"`,
		"final_summary_created=false",
		"recovery_session_vault_workload_auth_bootstrap_prepare_config_readability_remote",
		"config_readability_prepare_status=pass",
		`sudo -v -p "Remote Alpha OS sudo password for config readability preparation: "`,
		`run_sudo setfacl -m "u:${helper_user}:--x"`,
		`run_sudo setfacl -m "u:${helper_user}:r--"`,
		"config_contents_printed=false",
		"recovery_session_vault_workload_auth_bootstrap_prepare_spire_bundle_read_remote",
		"spire_bundle_read_prepare_status=pass",
		`sudo -v -p "Remote Alpha OS sudo password for SPIRE bundle-read preparation: "`,
		"require_spire_server_active_when_systemd_visible",
		"sudo_path_test",
		"require_sudo_visible_spire_path_shape",
		"helper_can_access_spire_socket",
		"spire_socket_present_accessible",
		"spire_socket_present_needs_acl",
		"spire_socket_parent_missing",
		"spire_socket_missing",
		"spire_socket_not_socket",
		"spire_server_inactive_or_unknown",
		"spire_server_command_missing",
		"spire_bundle_show_failed",
		`run_sudo setfacl -m "u:${helper_user}:rw-"`,
		"bundle_output_discarded=true",
		"bundle_contents_printed=false",
		`scp "${REMOTE_ALPHA_VAULT_WORKLOAD_AUTH_BOOTSTRAP_PUBLIC_HELPER}" "${ssh_target}:${remote_public_helper_path}"`,
		`scp "${REMOTE_ALPHA_VAULT_WORKLOAD_AUTH_BOOTSTRAP_INTERNAL_HELPER}" "${ssh_target}:${remote_internal_helper_path}"`,
		`ssh -tt "${ssh_target}"`,
		`"${helper_path}"`,
		"remote_alpha_vault_workload_auth_bootstrap.sh",
		"scripts/internal/remote_alpha_vault_workload_auth_bootstrap.sh",
		"staged helper cleanup was attempted",
		"Canonical remote bootstrap summary path",
	)
	assertContainsNone(t, "vault-workload-auth-bootstrap source forbidden execution surfaces", section,
		"recovery_session_vault_workload_auth_check_remote",
		"recovery_session_vault_workload_auth_check_run_remote",
		"recovery_session_vault_reset_disposable_remote",
		"recovery_session_vault_unseal_existing_remote",
		"recovery_session_vault_unseal_existing_run_remote",
		"recovery_session_vault_reset_disposable_run_remote",
		"REMOTE_ALPHA_VAULT_WORKLOAD_AUTH_PUBLIC_HELPER",
		"REMOTE_ALPHA_VAULT_WORKLOAD_AUTH_INTERNAL_HELPER",
		"REMOTE_ALPHA_VAULT_RESET_HELPER",
		"REMOTE_ALPHA_VAULT_WORKLOAD_AUTH_STAGE_ROOT",
		"REMOTE_ALPHA_VAULT_UNSEAL_STAGE_ROOT",
		"REMOTE_ALPHA_VAULT_RESET_DRY_RUN_STAGE_ROOT",
		"REMOTE_ALPHA_VAULT_RESET_EXECUTE_STAGE_ROOT",
		`sudo "${helper_path}"`,
		`exec "`,
		"print_refresh_command",
		"print_support_bundle_command",
		"remote-alpha-live-refresh",
		"remote-alpha-live-support-bundle",
		"remote_alpha_reset_disposable_vault.sh",
		"remote_alpha_vault_workload_auth_check.sh",
		"remote_alpha_runtime_identity_helper_summary.sh",
		"mktemp",
		"operator-summary",
		"recovery-session-summary",
		"tee ",
		"run_sudo install -d",
		`run_sudo chown "`,
	)
}

func TestRemoteAlphaOperatorP0qBootstrapExecutionContractIsImplementedNarrowly(t *testing.T) {
	routeRules := compactText(mustRead(t, standingRouteRulesPath))
	remoteRaw := mustRead(t, ".docs/system_overview/remote_supported_host_alpha.md")
	remoteSection := compactDocSection(t, remoteRaw, "### P0q Vault Workload-Auth Bootstrap Execution Route", "### Historical P0d interactive validation evidence — superseded and non-authoritative")
	source := mustRead(t, remoteAlphaOperatorScriptPath())
	sourceSection := docSection(t, source, "recovery_session_vault_workload_auth_bootstrap() {", "\nrecovery_session_vault_unseal_existing_require_command() {")

	assertContainsAll(t, "P0q bootstrap execution route rules", routeRules,
		"The P0q implementation/self-audit/merge-readiness slice may implement exactly one dedicated secret-sensitive workload-auth bootstrap helper, exactly one Mac-side recovery-session execution route, one bounded preparation form for the bootstrap summary path, and one bounded preparation form for fixed workload-zone config readability, and one bounded preparation form for fixed SPIRE server bundle-read access",
		"`scripts/remote_alpha_operator.sh recovery-session vault-workload-auth-bootstrap --ssh-target <target> --execute-bootstrap --interactive-tty`",
		"`scripts/remote_alpha_operator.sh recovery-session vault-workload-auth-bootstrap --ssh-target <target> --prepare-summary-path --interactive-tty`",
		"`scripts/remote_alpha_operator.sh recovery-session vault-workload-auth-bootstrap --ssh-target <target> --prepare-config-readability --interactive-tty`",
		"`scripts/remote_alpha_operator.sh recovery-session vault-workload-auth-bootstrap --ssh-target <target> --prepare-spire-bundle-read --interactive-tty`",
		"`scripts/remote_alpha_vault_workload_auth_bootstrap.sh`",
		"`scripts/internal/remote_alpha_vault_workload_auth_bootstrap.sh`",
		"`--ssh-target <target> --execute-bootstrap --prepare-summary-path --prepare-config-readability --prepare-spire-bundle-read --interactive-tty`",
		"summary preparation runs first, config-readability preparation runs second, SPIRE bundle-read preparation runs third",
		"`--prepare-summary-path` follow-up is OS/filesystem preparation only",
		"`--prepare-config-readability` follow-up is OS/filesystem preparation only",
		"`--prepare-spire-bundle-read` follow-up is OS/filesystem/capability preparation only",
		"fixed-path user ACL",
		"`spire_socket_present_accessible`",
		"`spire_socket_present_needs_acl`",
		"`spire_socket_parent_missing`",
		"`spire_socket_missing`",
		"`spire_socket_not_socket`",
		"`spire_server_inactive_or_unknown`",
		"`spire_server_command_missing`",
		"`spire_bundle_show_failed`",
		"sudo-visible inspection shows",
		"do not create SPIRE parents or sockets",
		"config readability preflight before prompts and Vault writes",
		"SPIRE bundle-read preflight before prompts and Vault writes",
		"public JWT validation material for the workload SPIFFE ID trust domain",
		"safe source/shape labels, key counts, selected trust-domain labels, and a digest",
		"visible/silent remote helper TTY prompt",
		"in-process Vault API client",
		"must not use `VAULT_TOKEN`",
		"`vault login`",
		"`/var/tmp/execution-substrate-remote-alpha/vault-workload-auth-bootstrap-summary.json`",
		"`execution-substrate.remote-alpha.vault-workload-auth-bootstrap-summary.v1`",
		"P0q validation remains fake/static only",
	)
	assertContainsAll(t, "P0q bootstrap execution remote docs", remoteSection,
		"`Bounded slice rule`: P0q implements the dedicated secret-sensitive workload-auth bootstrap execution route and bounded summary-path preparation route plus bounded config-readability and SPIRE bundle-read preparation routes",
		"`scripts/remote_alpha_vault_workload_auth_bootstrap.sh`",
		"`scripts/internal/remote_alpha_vault_workload_auth_bootstrap.sh`",
		"Mac-side operator route:",
		"`scripts/remote_alpha_operator.sh recovery-session vault-workload-auth-bootstrap --ssh-target <target> --execute-bootstrap --interactive-tty`",
		"`scripts/remote_alpha_operator.sh recovery-session vault-workload-auth-bootstrap --ssh-target <target> --prepare-summary-path --interactive-tty`",
		"`scripts/remote_alpha_operator.sh recovery-session vault-workload-auth-bootstrap --ssh-target <target> --prepare-config-readability --interactive-tty`",
		"`scripts/remote_alpha_operator.sh recovery-session vault-workload-auth-bootstrap --ssh-target <target> --prepare-spire-bundle-read --interactive-tty`",
		"Combined form:",
		"Secret prompt model:",
		"The human remains the operator.",
		"ES remains a bounded Remote Alpha operator facade/workflow, not a Vault token broker.",
		"The helper prompts for Vault bootstrap authority and proof secret values only on the visible/silent remote TTY",
		"Summary-path preparation:",
		"Preparation is OS/filesystem setup only",
		"helper-user/group owned with mode `0750`",
		"creates no final bootstrap summary in standalone mode",
		"Config-readability preparation:",
		"fixed-path user ACLs",
		"does not print config contents",
		"SPIRE bundle-read preparation:",
		"fixed SPIRE server socket path",
		"`spire_socket_present_accessible`",
		"`spire_socket_present_needs_acl`",
		"`spire_socket_parent_missing`",
		"`spire_socket_missing`",
		"`spire_socket_not_socket`",
		"`spire_server_inactive_or_unknown`",
		"`spire_bundle_show_failed`",
		"sudo-visible inspection shows",
		"do not create SPIRE parents or sockets",
		"bundle output is discarded",
		"summary-path preparation, then config-readability preparation, then SPIRE bundle-read preparation, then helper staging/execution",
		"Vault API strategy:",
		"in-process HTTPS client",
		"must not use `VAULT_TOKEN`",
		"`vault login`",
		"Execution boundaries:",
		"must not run a workload-auth check",
		"must not run Infrastructure Manager refresh",
		"must not collect support bundles",
		"must not run CP proof",
		"must not run runtime identity summary or runtime identity generation",
		"must not claim workload-auth success",
		"Summary/evidence behavior:",
		"`/var/tmp/execution-substrate-remote-alpha/vault-workload-auth-bootstrap-summary.json`",
		"`execution-substrate.remote-alpha.vault-workload-auth-bootstrap-summary.v1`",
		"source labels, shape labels, counts, digests",
		"Allowed execution flags:",
		"`--execute-bootstrap`",
		"`--prepare-summary-path`",
		"`--prepare-config-readability`",
		"`--prepare-spire-bundle-read`",
		"Standalone `--prepare-summary-path` runs only the fixed bounded remote preparation command",
		"Standalone `--prepare-config-readability` runs only the fixed bounded remote preparation command",
		"Standalone `--prepare-spire-bundle-read` runs only the fixed bounded remote preparation command",
		"Forbidden execution flags and inputs include:",
		"`--root-token`",
		"`--vault-token`",
		"proof secret value flags",
		"P0q tests:",
		"fake bootstrap writes the Vault JWT auth config with the expected validation material and bound issuer shape",
		"fake workload-auth check JWT claims align with the bootstrap config labels",
		"fake SSH/SCP",
		"fake Vault API capture",
	)
	assertContainsAll(t, "P0q bootstrap execution operator source", sourceSection,
		"REMOTE_ALPHA_VAULT_WORKLOAD_AUTH_BOOTSTRAP_PUBLIC_HELPER",
		"REMOTE_ALPHA_VAULT_WORKLOAD_AUTH_BOOTSTRAP_INTERNAL_HELPER",
		"REMOTE_ALPHA_VAULT_WORKLOAD_AUTH_BOOTSTRAP_STAGE_ROOT",
		"REMOTE_ALPHA_VAULT_WORKLOAD_AUTH_BOOTSTRAP_REMOTE_SUMMARY_DIR",
		"REMOTE_ALPHA_VAULT_WORKLOAD_AUTH_BOOTSTRAP_REMOTE_SUMMARY",
		"--prepare-summary-path",
		"--prepare-config-readability",
		"--prepare-spire-bundle-read",
		"recovery_session_vault_workload_auth_bootstrap_prepare_summary_path_remote",
		"recovery_session_vault_workload_auth_bootstrap_prepare_config_readability_remote",
		"recovery_session_vault_workload_auth_bootstrap_prepare_spire_bundle_read_remote",
		`ssh -tt "${ssh_target}"`,
		`"${helper_path}"`,
	)
	assertContainsNone(t, "P0q bootstrap execution operator source forbidden bundle", sourceSection,
		"remote_alpha_vault_workload_auth_check.sh",
		"remote_alpha_reset_disposable_vault.sh",
		"remote_alpha_runtime_identity_helper_summary.sh",
		"remote-alpha-live-refresh",
		"remote-alpha-live-support-bundle",
		`sudo "${helper_path}"`,
	)

	for _, path := range []string{
		filepath.Join(remoteAlphaOperatorRepoRoot(), "scripts", "remote_alpha_vault_workload_auth_bootstrap.sh"),
		filepath.Join(remoteAlphaOperatorRepoRoot(), "scripts", "internal", "remote_alpha_vault_workload_auth_bootstrap.sh"),
	} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("stat %s: %v", path, err)
		}
	}
}

func TestRemoteAlphaOperatorRecoverySessionRejectsDuplicateAndMisplacedFlags(t *testing.T) {
	for _, tc := range []struct {
		name      string
		args      []string
		duplicate string
	}{
		{
			name:      "duplicate mode",
			args:      []string{"--plan", "--inventory"},
			duplicate: "--inventory",
		},
		{
			name:      "duplicate ssh alias",
			args:      []string{"--next-steps", "--ssh-alias", "a", "--ssh-alias", "b"},
			duplicate: "--ssh-alias",
		},
		{
			name:      "duplicate im profile dir",
			args:      []string{"--next-steps", "--im-profile-dir", "a", "--im-profile-dir", "b"},
			duplicate: "--im-profile-dir",
		},
		{
			name:      "duplicate support output root",
			args:      []string{"--next-steps", "--support-output-root", "a", "--support-output-root", "b"},
			duplicate: "--support-output-root",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			output := requireRemoteAlphaOperatorFailure(t, append([]string{"recovery-session"}, tc.args...)...)
			assertContainsAll(t, "duplicate recovery-session flag refusal", output,
				"duplicate option for recovery-session: "+tc.duplicate,
				"No recovery-session live helper or IM execution occurred.",
			)
		})
	}
}

func TestRemoteAlphaOperatorWritableStateRouteRejectsSecretLikeArgsBeforeRouting(t *testing.T) {
	for _, args := range [][]string{
		{"--api-key=dummy"},
		{"--api-key", "dummy"},
		{"--root-token", "dummy"},
		{"--unseal-key", "dummy"},
		{"--client-token", "dummy"},
		{"--vault-token", "dummy"},
		{"--jwt-svid", "dummy"},
		{"--private-key", "dummy"},
		{"--password", "dummy"},
		{"--secret", "dummy"},
	} {
		t.Run(strings.Join(args, "_"), func(t *testing.T) {
			output := requireRemoteAlphaOperatorFailure(t, append([]string{"es-writable-state-readiness-check"}, args...)...)
			assertContainsAll(t, "route secret flag refusal", output,
				"secret material must never be passed by CLI args/env/logs/reports/artifacts",
			)
			assertContainsNone(t, "route secret flag refusal", output,
				"Remote Alpha operator route: es-writable-state-readiness-check",
				"scripts/remote_alpha_stage_es_writable_state_readiness_check.sh --ssh-target",
			)
		})
	}
}

func TestRemoteAlphaOperatorReadinessSessionRejectsSecretLikeArgsBeforeRouting(t *testing.T) {
	for _, args := range [][]string{
		{"--api-key=dummy"},
		{"--api-key", "dummy"},
		{"--root-token", "dummy"},
		{"--unseal-key", "dummy"},
		{"--client-token", "dummy"},
		{"--vault-token", "dummy"},
		{"--jwt-svid", "dummy"},
		{"--private-key", "dummy"},
		{"--password", "dummy"},
		{"--secret", "dummy"},
	} {
		t.Run(strings.Join(args, "_"), func(t *testing.T) {
			output := requireRemoteAlphaOperatorFailure(t, append([]string{"readiness-session"}, args...)...)
			assertContainsAll(t, "readiness-session secret flag refusal", output,
				"secret material must never be passed by CLI args/env/logs/reports/artifacts",
			)
			assertContainsNone(t, "readiness-session secret flag refusal", output,
				"Readiness session artifact metadata",
				"remote-alpha-live-refresh",
				"remote-alpha-live-support-bundle",
			)
		})
	}
}

func TestRemoteAlphaOperatorUnknownSubcommandRefuses(t *testing.T) {
	output := requireRemoteAlphaOperatorFailure(t, "definitely-unknown")
	assertContainsAll(t, "unknown subcommand refusal", output,
		"unknown operator subcommand",
		"No helper execution routing occurred.",
	)
	assertContainsNone(t, "unknown subcommand non-echo", output, "definitely-unknown")
}

func TestRemoteAlphaOperatorSourceCutsOffEvidenceCompatibilityAndPreservesUnrelatedRoutes(t *testing.T) {
	source := mustRead(t, remoteAlphaOperatorScriptPath())
	assertContainsAll(t, "operator source retained boundaries", source,
		"set -euo pipefail",
		"set +x",
		`SCRIPT_DIR=""`,
		`initialize_operator_paths() {`,
		`REMOTE_ALPHA_VAULT_RESET_HELPER="${SCRIPT_DIR}/remote_alpha_reset_disposable_vault.sh"`,
		`REMOTE_ALPHA_VAULT_WORKLOAD_AUTH_BOOTSTRAP_PUBLIC_HELPER="${SCRIPT_DIR}/remote_alpha_vault_workload_auth_bootstrap.sh"`,
		`REMOTE_ALPHA_ES_SERVICE_TLS_RENEW_PUBLIC_HELPER="${SCRIPT_DIR}/remote_alpha_es_service_tls_renew.sh"`,
		`REMOTE_ALPHA_OPERATOR_HEALTHCHECK_TLS_RENEW_PUBLIC_HELPER="${SCRIPT_DIR}/remote_alpha_operator_healthcheck_tls_renew.sh"`,
		"retired_operator_evidence_compatibility() {",
		"reject_retired_operator_evidence_args() {",
		"recovery_session_vault_unseal_existing",
		"recovery_session_vault_reset_disposable",
		"recovery_session_vault_workload_auth_bootstrap",
		"recovery_session_es_service_tls",
		"recovery_session_es_governance_tls",
		"recovery_session_operator_healthcheck_tls",
		"recovery_session_operator_healthcheck_tls_status_noninteractive",
	)
	assertContainsNone(t, "operator source retired compatibility removed", source,
		"REMOTE_ALPHA_VAULT_WORKLOAD_AUTH_PUBLIC_HELPER",
		"REMOTE_ALPHA_VAULT_WORKLOAD_AUTH_INTERNAL_HELPER",
		"REMOTE_ALPHA_VAULT_WORKLOAD_AUTH_STAGE_ROOT",
		"REMOTE_ALPHA_VAULT_WORKLOAD_AUTH_REMOTE_SUMMARY",
		"REMOTE_ALPHA_RUNTIME_IDENTITY_SUMMARY_HELPER",
		"REMOTE_ALPHA_RUNTIME_IDENTITY_SUMMARY_STAGE_ROOT",
		"REMOTE_ALPHA_RUNTIME_IDENTITY_SUMMARY_REMOTE_SUMMARY",
		"recovery_session_vault_workload_auth_check",
		"recovery_session_runtime_identity_summary",
		"recovery_session_evidence_check",
		"expected_evidence_filenames",
		"schema_interpretations",
		"execution-substrate.remote-alpha.vault-workload-auth-summary.v1",
		"execution-substrate.remote-runtime-identity-helper-summary.v1alpha1",
		"execution-substrate.remote-alpha.vault-service-user-migration-summary.v1",
		"vault-workload-auth-summary.json",
		"runtime-identity-helper-summary.json",
		"vault-service-user-migration-check-only.json",
		"vault-service-user-migration-apply-summary.json",
		`{"vault_workload_auth_smoke"`,
	)

	for _, helper := range []string{
		"remote_alpha_vault_workload_auth_check.sh",
		"remote_alpha_runtime_identity_helper_summary.sh",
		"remote_alpha_migrate_vault_service_user.sh",
	} {
		for lineNumber, line := range strings.Split(source, "\n") {
			if !strings.Contains(line, helper) {
				continue
			}
			trimmed := strings.TrimSpace(line)
			if !strings.HasPrefix(trimmed, "\"") || !strings.Contains(trimmed, "owner-local") || !strings.Contains(trimmed, "no operator-facade reachability") {
				t.Fatalf("operator source line %d references owner-local helper outside inert inventory: %s", lineNumber+1, line)
			}
		}
	}
}

func TestRemoteAlphaOperatorRetiredRouteSourceInventoryIsExact(t *testing.T) {
	source := mustRead(t, remoteAlphaOperatorScriptPath())
	if err := validateRemoteAlphaOperatorSemanticInventory(source); err != nil {
		t.Fatal(err)
	}
}

func TestRemoteAlphaOperatorEvidenceRetirementSourceInventoryIsExact(t *testing.T) {
	source := mustRead(t, remoteAlphaOperatorScriptPath())
	if err := validateRemoteAlphaOperatorSemanticInventory(source); err != nil {
		t.Fatal(err)
	}
}

type shellFunctionDefinition struct {
	name string
	body []string
}

type shellSemanticCommand struct {
	name string
	args []string
}

type shellCaseBranch struct {
	patterns []string
	commands []shellSemanticCommand
}

func validateRemoteAlphaOperatorSemanticInventory(source string) error {
	functions, err := parseShellFunctionDefinitions(source)
	if err != nil {
		return err
	}
	require := func(name string) (shellFunctionDefinition, error) {
		function, ok := functions[name]
		if !ok {
			return shellFunctionDefinition{}, fmt.Errorf("shell function %s is missing", name)
		}
		return function, nil
	}
	if err := validateRemoteAlphaProtectedScannerGrammar(functions); err != nil {
		return err
	}

	parseArgs, err := require("parse_args")
	if err != nil {
		return err
	}
	parseCommands := shellSemanticCommands(parseArgs.body)
	if len(parseCommands) < 2 || parseCommands[0].name != "reject_secret_args" || parseCommands[1].name != "reject_retired_operator_evidence_args" {
		return fmt.Errorf("privacy prefilter and retired-route classification order changed: %v", shellCommandNames(parseCommands))
	}

	existingHandler, err := require("retired_es_existing_host_route")
	if err != nil {
		return err
	}
	if err := requireExactShellTerminal(existingHandler, []string{"printf", "printf", "return"}, "return", "2"); err != nil {
		return err
	}
	wantExistingLines := strings.Split(strings.TrimSuffix(retiredRemoteAlphaStderr, "\n"), "\n")
	if got := shellPrintedLiteralLines(existingHandler); !equalStringSlices(got, wantExistingLines) {
		return fmt.Errorf("existing-host fixed refusal text changed: got %q want %q", got, wantExistingLines)
	}
	for _, wrapperName := range []string{"route_es_writable_state_readiness_check", "readiness_session"} {
		wrapper, err := require(wrapperName)
		if err != nil {
			return err
		}
		commands := shellSemanticCommands(wrapper.body)
		if len(commands) != 1 || commands[0].name != "retired_es_existing_host_route" {
			return fmt.Errorf("%s has wrong semantic handler ownership: %v", wrapperName, shellCommandNames(commands))
		}
	}
	if err := requireExactShellCallers(functions, "retired_es_existing_host_route", map[string]int{
		"readiness_session":                       1,
		"route_es_writable_state_readiness_check": 1,
	}); err != nil {
		return err
	}
	if err := requireExactShellCallers(functions, "route_es_writable_state_readiness_check", map[string]int{"main": 1}); err != nil {
		return err
	}
	if err := requireExactShellCallers(functions, "readiness_session", map[string]int{"main": 1}); err != nil {
		return err
	}

	evidenceHandler, err := require("retired_operator_evidence_compatibility")
	if err != nil {
		return err
	}
	if err := requireExactShellTerminal(evidenceHandler, []string{"printf", "printf", "exit"}, "exit", "2"); err != nil {
		return err
	}
	wantEvidenceLines := strings.Split(strings.TrimSuffix(remoteAlphaOperatorEvidenceRetirementStderr, "\n"), "\n")
	if got := shellPrintedLiteralLines(evidenceHandler); !equalStringSlices(got, wantEvidenceLines) {
		return fmt.Errorf("evidence-retirement fixed refusal text changed: got %q want %q", got, wantEvidenceLines)
	}
	scanner, err := require("reject_retired_operator_evidence_args")
	if err != nil {
		return err
	}
	scannerBranches := shellCaseBranches(scanner.body)
	for pattern, count := range map[string]int{
		"vault-workload-auth-check": 2,
		"runtime-identity-summary":  2,
		"vault-service-user-check":  1,
	} {
		if err := requireShellDispatch(scannerBranches, pattern, "retired_operator_evidence_compatibility", count); err != nil {
			return fmt.Errorf("retired route %s: %w", pattern, err)
		}
	}
	for _, flag := range []string{
		"--evidence-check", "--evidence-dir", "--strict-known-schema",
		"--vault-workload-auth-summary", "--runtime-identity-summary", "--vault-service-user-summary",
	} {
		for _, pattern := range []string{flag, flag + "=*"} {
			if err := requireShellDispatch(scannerBranches, pattern, "retired_operator_evidence_compatibility", 1); err != nil {
				return fmt.Errorf("retired flag %s: %w", pattern, err)
			}
		}
	}
	if err := requireExactShellCallers(functions, "retired_operator_evidence_compatibility", map[string]int{"reject_retired_operator_evidence_args": 3}); err != nil {
		return err
	}
	if err := requireExactShellCallers(functions, "reject_retired_operator_evidence_args", map[string]int{"parse_args": 1}); err != nil {
		return err
	}

	privacy, err := require("reject_secret_args")
	if err != nil {
		return err
	}
	privacyBranches := shellCaseBranches(privacy.body)
	for _, option := range []string{
		"evidence-dir", "vault-workload-auth-summary", "runtime-identity-summary",
		"vault-service-user-summary", "readiness-summary", "staging-record",
	} {
		if count := shellPatternCount(privacyBranches, option); count != 1 {
			return fmt.Errorf("privacy value-option inventory for %s = %d, want 1", option, count)
		}
	}

	recovery, err := require("recovery_session")
	if err != nil {
		return err
	}
	recoveryBranches := shellCaseBranches(recovery.body)
	for _, pattern := range []string{"--readiness-summary", "--readiness-summary=*", "--staging-record", "--staging-record=*"} {
		if err := requireShellDispatch(recoveryBranches, pattern, "refuse_retired_historical_evidence_option", 1); err != nil {
			return fmt.Errorf("historical evidence flag %s: %w", pattern, err)
		}
	}

	mainFunction, err := require("main")
	if err != nil {
		return err
	}
	mainBranches := shellCaseBranches(mainFunction.body)
	for pattern, handler := range map[string]string{
		"es-writable-state-readiness-check": "route_es_writable_state_readiness_check",
		"readiness-session":                 "readiness_session",
		"recovery-session":                  "recovery_session",
	} {
		if err := requireShellDispatch(mainBranches, pattern, handler, 1); err != nil {
			return fmt.Errorf("main dispatch %s: %w", pattern, err)
		}
	}
	for _, absent := range []string{"vault-workload-auth-check", "runtime-identity-summary", "vault-service-user-check"} {
		if count := shellPatternCount(mainBranches, absent); count != 0 {
			return fmt.Errorf("retired evidence route %s entered active main dispatch %d time(s)", absent, count)
		}
	}
	return nil
}

func validateRemoteAlphaProtectedScannerGrammar(functions map[string]shellFunctionDefinition) error {
	privacy, ok := functions["reject_secret_args"]
	if !ok {
		return fmt.Errorf("protected scanner reject_secret_args is missing")
	}
	retirement, ok := functions["reject_retired_operator_evidence_args"]
	if !ok {
		return fmt.Errorf("protected scanner reject_retired_operator_evidence_args is missing")
	}
	parseArgs, ok := functions["parse_args"]
	if !ok {
		return fmt.Errorf("protected scanner entry parse_args is missing")
	}

	privacyExpected := []string{
		"local arg option_name skip_next=false nocasematch_was_set=false",
		"local normalized_arg",
		"local LC_ALL=C",
		"if shopt -q nocasematch ; then",
		"nocasematch_was_set=true",
		"else",
		"shopt -s nocasematch",
		"fi",
		"for arg in $@ ; do",
		"normalized_arg=${arg//_/-}",
		protectedPrivacyMatcherCanonical,
		"privacy_refuse",
		"fi",
		"if [[ ${skip_next} == true ]] ; then",
		"skip_next=false",
		"continue",
		"fi",
		"if [[ ${arg} != --* ]] ; then",
		"continue",
		"fi",
		"option_name=${arg%%=*}",
		"option_name=${option_name#--}",
		"option_name=${option_name//_/-}",
		"if [[ ${arg} != *=* ]] ; then",
		"case ${option_name} in",
		"profile-dir | output-root | ssh-alias | im-profile-dir | support-output-root | evidence-dir | vault-workload-auth-summary | runtime-identity-summary | vault-service-user-summary | readiness-summary | staging-record | ssh-target | format )",
		"skip_next=true",
		";;",
		"esac",
		"fi",
		"done",
		"if [[ ${nocasematch_was_set} != true ]] ; then",
		"shopt -u nocasematch",
		"fi",
	}
	retirementExpected := []string{
		"local first=${1:-} second=${2:-} arg",
		"case ${first} in",
		"vault-workload-auth-check | runtime-identity-summary | vault-service-user-check )",
		"retired_operator_evidence_compatibility",
		";;",
		"esac",
		"if [[ ${first} == recovery-session ]] ; then",
		"case ${second} in",
		"vault-workload-auth-check | runtime-identity-summary )",
		"retired_operator_evidence_compatibility",
		";;",
		"esac",
		"fi",
		"for arg in $@ ; do",
		"case ${arg} in",
		"--evidence-check | --evidence-check=* | --evidence-dir | --evidence-dir=* | --strict-known-schema | --strict-known-schema=* | --vault-workload-auth-summary | --vault-workload-auth-summary=* | --runtime-identity-summary | --runtime-identity-summary=* | --vault-service-user-summary | --vault-service-user-summary=* )",
		"retired_operator_evidence_compatibility",
		";;",
		"esac",
		"done",
	}
	if err := validateProtectedScannerBody(privacy, privacyExpected); err != nil {
		return err
	}
	if err := validateProtectedScannerBody(retirement, retirementExpected); err != nil {
		return err
	}
	return validateProtectedParseArgsPrefix(parseArgs)
}

const protectedPrivacyMatcherSource = `if [[ "${normalized_arg}" =~ --([A-Za-z0-9_-]*-)?(root-token|unseal-key|client-token|vault-token|api-key|jwt-svid|private-key|password|secret|token-file|secret-value)([^A-Za-z0-9_-]|$) ]]; then`
const protectedPrivacyMatcherCanonical = `if [[ ${normalized_arg} =~ --([A-Za-z0-9_-]*-)?(root-token|unseal-key|client-token|vault-token|api-key|jwt-svid|private-key|password|secret|token-file|secret-value)([^A-Za-z0-9_-]|$) ]] ; then`

func validateProtectedScannerBody(function shellFunctionDefinition, expected []string) error {
	canonical := make([]string, 0, len(function.body))
	inertNames := make(map[string]struct{})
	for lineIndex, line := range function.body {
		if function.name == "reject_secret_args" && strings.TrimSpace(line) == protectedPrivacyMatcherSource {
			canonical = append(canonical, protectedPrivacyMatcherCanonical)
			continue
		}
		tokens, err := lexProtectedShellLine(line)
		if err != nil {
			return fmt.Errorf("protected scanner %s line %d: %w", function.name, lineIndex+1, err)
		}
		if len(tokens) == 0 {
			continue
		}
		if tokens[0] == "local" && len(tokens) > 1 && protectedInertLocalTokens(tokens[1:]) && protectedInertLocalUsesOnlyLiteralWords(line) {
			for _, token := range tokens[1:] {
				name := token[:strings.IndexByte(token, '=')]
				if _, duplicate := inertNames[name]; duplicate {
					return fmt.Errorf("protected scanner %s repeats inert local %s", function.name, name)
				}
				inertNames[name] = struct{}{}
			}
			continue
		}
		canonical = append(canonical, strings.Join(tokens, " "))
	}
	if !equalStringSlices(canonical, expected) {
		return fmt.Errorf("protected scanner %s grammar changed: got %q want %q", function.name, canonical, expected)
	}
	for name := range inertNames {
		needleBraced := "${" + name
		needlePlain := "$" + name
		for _, statement := range canonical {
			if strings.Contains(statement, needleBraced) || strings.Contains(statement, needlePlain) {
				return fmt.Errorf("protected scanner %s references inert local %s", function.name, name)
			}
		}
	}
	return nil
}

func protectedInertLocalTokens(tokens []string) bool {
	inertName := regexp.MustCompile(`^inert(?:_[A-Za-z0-9_]*)?=`)
	for _, token := range tokens {
		if !inertName.MatchString(token) {
			return false
		}
	}
	return true
}

func protectedInertLocalUsesOnlyLiteralWords(line string) bool {
	quote := byte(0)
	escaped := false
	for index := 0; index < len(line); index++ {
		character := line[index]
		if quote == '\'' {
			if character == '\'' {
				quote = 0
			}
			continue
		}
		if quote == '"' {
			if escaped {
				escaped = false
				continue
			}
			if character == '\\' {
				escaped = true
				continue
			}
			if character == '"' {
				quote = 0
				continue
			}
			if character == '$' || character == '`' {
				return false
			}
			continue
		}
		switch character {
		case '\'', '"':
			quote = character
		case '#':
			if index == 0 || line[index-1] == ' ' || line[index-1] == '\t' {
				return true
			}
		case '$', '`', '*', '?', '[', ']', '~':
			return false
		}
	}
	return quote == 0 && !escaped
}

func validateProtectedParseArgsPrefix(function shellFunctionDefinition) error {
	statements := make([]string, 0, 2)
	for lineIndex, line := range function.body {
		tokens, err := lexProtectedShellLine(line)
		if err != nil {
			return fmt.Errorf("protected parse_args prefix line %d: %w", lineIndex+1, err)
		}
		if len(tokens) == 0 {
			continue
		}
		statements = append(statements, strings.Join(tokens, " "))
		if len(statements) == 2 {
			break
		}
	}
	want := []string{"reject_secret_args $@", "reject_retired_operator_evidence_args $@"}
	if !equalStringSlices(statements, want) {
		return fmt.Errorf("protected parse_args prefix changed: got %q want %q", statements, want)
	}
	return nil
}

func lexProtectedShellLine(line string) ([]string, error) {
	tokens := make([]string, 0)
	var word strings.Builder
	flush := func() {
		if word.Len() != 0 {
			tokens = append(tokens, word.String())
			word.Reset()
		}
	}
	for index := 0; index < len(line); {
		character := line[index]
		if character == ' ' || character == '\t' || character == '\r' {
			flush()
			index++
			continue
		}
		if character == '#' && word.Len() == 0 {
			break
		}
		if character == '\'' {
			end := strings.IndexByte(line[index+1:], '\'')
			if end < 0 {
				return nil, fmt.Errorf("unterminated single quote")
			}
			word.WriteString(line[index+1 : index+1+end])
			index += end + 2
			continue
		}
		if character == '"' {
			index++
			closed := false
			for index < len(line) {
				character = line[index]
				if character == '"' {
					index++
					closed = true
					break
				}
				if character == '`' {
					return nil, fmt.Errorf("backtick substitution is not accepted")
				}
				if character == '\\' {
					if index+1 >= len(line) {
						return nil, fmt.Errorf("truncated double-quote escape")
					}
					word.WriteByte(line[index+1])
					index += 2
					continue
				}
				if character == '$' {
					expansion, next, err := lexProtectedParameterExpansion(line, index)
					if err != nil {
						return nil, err
					}
					word.WriteString(expansion)
					index = next
					continue
				}
				word.WriteByte(character)
				index++
			}
			if !closed {
				return nil, fmt.Errorf("unterminated double quote")
			}
			continue
		}
		if character == '`' {
			return nil, fmt.Errorf("backtick substitution is not accepted")
		}
		if character == '$' {
			expansion, next, err := lexProtectedParameterExpansion(line, index)
			if err != nil {
				return nil, err
			}
			word.WriteString(expansion)
			index = next
			continue
		}
		if character == '<' || character == '>' || character == '&' || character == '{' || character == '}' {
			return nil, fmt.Errorf("redirection, backgrounding, or brace syntax is not accepted")
		}
		if character == '(' {
			return nil, fmt.Errorf("subshell or process-substitution syntax is not accepted")
		}
		if character == '[' && index+1 < len(line) && line[index+1] == '[' {
			flush()
			tokens = append(tokens, "[[")
			index += 2
			continue
		}
		if character == ']' && index+1 < len(line) && line[index+1] == ']' {
			flush()
			tokens = append(tokens, "]]")
			index += 2
			continue
		}
		if character == ';' {
			flush()
			if index+1 < len(line) && line[index+1] == ';' {
				tokens = append(tokens, ";;")
				index += 2
			} else {
				tokens = append(tokens, ";")
				index++
			}
			continue
		}
		if character == '|' {
			flush()
			if index+1 < len(line) && line[index+1] == '|' {
				return nil, fmt.Errorf("conditional pipeline syntax is not accepted")
			}
			tokens = append(tokens, "|")
			index++
			continue
		}
		if character == ')' {
			flush()
			tokens = append(tokens, ")")
			index++
			continue
		}
		word.WriteByte(character)
		index++
	}
	flush()
	return tokens, nil
}

func lexProtectedParameterExpansion(line string, start int) (string, int, error) {
	if start+1 >= len(line) {
		return "", 0, fmt.Errorf("truncated parameter expansion")
	}
	if line[start+1] == '(' {
		return "", 0, fmt.Errorf("command or arithmetic substitution is not accepted")
	}
	if line[start+1] == '@' || line[start+1] == '#' {
		return line[start : start+2], start + 2, nil
	}
	if line[start+1] != '{' {
		return "", 0, fmt.Errorf("unsupported parameter expansion")
	}
	end := strings.IndexByte(line[start+2:], '}')
	if end < 0 {
		return "", 0, fmt.Errorf("unterminated parameter expansion")
	}
	end += start + 2
	expansion := line[start : end+1]
	allowed := map[string]bool{
		"${1:-}": true, "${2:-}": true, "${arg}": true,
		"${first}": true, "${second}": true,
		"${arg%%=*}": true, "${arg//_/-}": true,
		"${scan_remainder}": true, "${scan_remainder#*--}": true,
		"${scan_remainder%%[=[:space:]]*}": true,
		"${option_name}":                   true,
		"${option_name#--}":                true, "${option_name//_/-}": true,
		"${skip_next}": true, "${nocasematch_was_set}": true,
	}
	if !allowed[expansion] {
		return "", 0, fmt.Errorf("unsupported parameter expansion %q", expansion)
	}
	return expansion, end + 1, nil
}

func parseShellFunctionDefinitions(source string) (map[string]shellFunctionDefinition, error) {
	lines, err := shellLinesWithoutHeredocBodies(source)
	if err != nil {
		return nil, err
	}
	functionStart := regexp.MustCompile(`^[[:space:]]*([A-Za-z_][A-Za-z0-9_]*)[[:space:]]*\([[:space:]]*\)[[:space:]]*\{[[:space:]]*(?:#.*)?$`)
	functions := make(map[string]shellFunctionDefinition)
	for index := 0; index < len(lines); index++ {
		match := functionStart.FindStringSubmatch(lines[index])
		if match == nil {
			continue
		}
		name := match[1]
		if _, duplicate := functions[name]; duplicate {
			return nil, fmt.Errorf("shell function %s is defined more than once", name)
		}
		body := make([]string, 0)
		closed := false
		for index = index + 1; index < len(lines); index++ {
			if strings.TrimSpace(shellUnquotedCode(lines[index])) == "}" {
				closed = true
				break
			}
			body = append(body, lines[index])
		}
		if !closed {
			return nil, fmt.Errorf("shell function %s has no structural closing brace", name)
		}
		functions[name] = shellFunctionDefinition{name: name, body: body}
	}
	return functions, nil
}

func shellLinesWithoutHeredocBodies(source string) ([]string, error) {
	heredoc := regexp.MustCompile(`<<-?[[:space:]]*(?:'([A-Za-z_][A-Za-z0-9_]*)'|"([A-Za-z_][A-Za-z0-9_]*)"|([A-Za-z_][A-Za-z0-9_]*))`)
	lines := strings.Split(source, "\n")
	result := make([]string, 0, len(lines))
	var pending []string
	for _, line := range lines {
		if len(pending) != 0 {
			result = append(result, "")
			if strings.TrimSpace(line) == pending[0] {
				pending = pending[1:]
			}
			continue
		}
		result = append(result, line)
		for _, match := range heredoc.FindAllStringSubmatch(line, -1) {
			for _, candidate := range match[1:] {
				if candidate != "" {
					pending = append(pending, candidate)
					break
				}
			}
		}
	}
	if len(pending) != 0 {
		return nil, fmt.Errorf("unterminated shell heredoc %s", pending[0])
	}
	return result, nil
}

func shellUnquotedCode(line string) string {
	var result strings.Builder
	quote := byte(0)
	escaped := false
	for index := 0; index < len(line); index++ {
		character := line[index]
		if quote != 0 {
			result.WriteByte(' ')
			if escaped {
				escaped = false
				continue
			}
			if quote == '"' && character == '\\' {
				escaped = true
				continue
			}
			if character == quote {
				quote = 0
			}
			continue
		}
		if character == '\'' || character == '"' {
			quote = character
			result.WriteByte(' ')
			continue
		}
		if character == '#' {
			startsWord := index == 0 || strings.ContainsRune(" \t;|&(){}", rune(line[index-1]))
			if startsWord {
				break
			}
		}
		if character == '\\' && index+1 < len(line) {
			index++
			result.WriteByte(line[index])
			continue
		}
		result.WriteByte(character)
	}
	return result.String()
}

func shellSemanticWords(line string) []string {
	word := regexp.MustCompile(`--[A-Za-z0-9_-]+(?:=\*)?|[A-Za-z_][A-Za-z0-9_.*:+/-]*|[0-9]+`)
	return word.FindAllString(shellUnquotedCode(line), -1)
}

func shellSemanticCommands(lines []string) []shellSemanticCommand {
	reserved := map[string]bool{
		"case": true, "do": true, "done": true, "elif": true, "else": true, "esac": true,
		"fi": true, "for": true, "if": true, "in": true, "local": true, "then": true,
		"while": true,
	}
	commands := make([]shellSemanticCommand, 0)
	for _, line := range lines {
		code := strings.TrimSpace(shellUnquotedCode(line))
		if code == "" || code == ";;" || strings.HasSuffix(code, ")") || strings.HasPrefix(code, "[[") || strings.HasPrefix(code, "((") {
			continue
		}
		words := shellSemanticWords(line)
		if len(words) == 0 || reserved[words[0]] {
			continue
		}
		firstField := strings.Fields(code)
		if len(firstField) != 0 && strings.Contains(firstField[0], "=") {
			continue
		}
		commands = append(commands, shellSemanticCommand{name: words[0], args: append([]string(nil), words[1:]...)})
	}
	return commands
}

func shellCaseBranches(lines []string) []shellCaseBranch {
	branches := make([]shellCaseBranch, 0)
	for index := 0; index < len(lines); index++ {
		code := strings.TrimSpace(shellUnquotedCode(lines[index]))
		if !strings.HasSuffix(code, ")") || strings.HasPrefix(code, "case ") || strings.HasPrefix(code, "if ") || strings.Contains(code, "[[") {
			continue
		}
		patternText := strings.TrimSpace(strings.TrimSuffix(code, ")"))
		if patternText == "" || strings.Contains(patternText, "(") {
			continue
		}
		patterns := make([]string, 0)
		for _, pattern := range strings.Split(patternText, "|") {
			pattern = strings.TrimSpace(pattern)
			if pattern != "" {
				patterns = append(patterns, pattern)
			}
		}
		if len(patterns) == 0 {
			continue
		}
		body := make([]string, 0)
		for next := index + 1; next < len(lines); next++ {
			if strings.Contains(shellUnquotedCode(lines[next]), ";;") {
				break
			}
			body = append(body, lines[next])
		}
		branches = append(branches, shellCaseBranch{patterns: patterns, commands: shellSemanticCommands(body)})
	}
	return branches
}

func shellCommandNames(commands []shellSemanticCommand) []string {
	result := make([]string, 0, len(commands))
	for _, command := range commands {
		result = append(result, command.name)
	}
	return result
}

func requireExactShellTerminal(function shellFunctionDefinition, wantCommands []string, terminal string, argument string) error {
	commands := shellSemanticCommands(function.body)
	if got := shellCommandNames(commands); !equalStringSlices(got, wantCommands) {
		return fmt.Errorf("shell function %s command ownership changed: got %v want %v", function.name, got, wantCommands)
	}
	last := commands[len(commands)-1]
	if last.name != terminal || len(last.args) != 1 || last.args[0] != argument {
		return fmt.Errorf("shell function %s terminal status changed: %+v", function.name, last)
	}
	return nil
}

func shellPrintedLiteralLines(function shellFunctionDefinition) []string {
	result := make([]string, 0)
	for _, line := range function.body {
		commands := shellSemanticCommands([]string{line})
		if len(commands) != 1 || commands[0].name != "printf" {
			continue
		}
		literals := shellQuotedLiterals(line)
		if len(literals) >= 2 {
			result = append(result, literals[len(literals)-1])
		}
	}
	return result
}

func shellQuotedLiterals(line string) []string {
	result := make([]string, 0)
	for index := 0; index < len(line); index++ {
		quote := line[index]
		if quote != '\'' && quote != '"' {
			if quote == '#' && (index == 0 || strings.ContainsRune(" \t;|&(){}", rune(line[index-1]))) {
				break
			}
			continue
		}
		var literal strings.Builder
		for index = index + 1; index < len(line); index++ {
			character := line[index]
			if character == quote {
				break
			}
			if quote == '"' && character == '\\' && index+1 < len(line) {
				index++
				literal.WriteByte(line[index])
				continue
			}
			literal.WriteByte(character)
		}
		result = append(result, literal.String())
	}
	return result
}

func shellPatternCount(branches []shellCaseBranch, pattern string) int {
	count := 0
	for _, branch := range branches {
		for _, candidate := range branch.patterns {
			if candidate == pattern {
				count++
			}
		}
	}
	return count
}

func requireShellDispatch(branches []shellCaseBranch, pattern string, handler string, want int) error {
	total := 0
	correct := 0
	for _, branch := range branches {
		for _, candidate := range branch.patterns {
			if candidate != pattern {
				continue
			}
			total++
			if len(branch.commands) == 1 && branch.commands[0].name == handler {
				correct++
			}
		}
	}
	if total != want || correct != want {
		return fmt.Errorf("pattern %s dispatch inventory: total=%d correct-handler=%d want=%d handler=%s", pattern, total, correct, want, handler)
	}
	return nil
}

func requireExactShellCallers(functions map[string]shellFunctionDefinition, target string, want map[string]int) error {
	got := make(map[string]int)
	for name, function := range functions {
		for _, command := range shellSemanticCommands(function.body) {
			if command.name == target {
				got[name]++
			}
		}
	}
	if len(got) != len(want) {
		return fmt.Errorf("shell semantic callers for %s changed: got %v want %v", target, got, want)
	}
	for caller, count := range want {
		if got[caller] != count {
			return fmt.Errorf("shell semantic caller %s -> %s count=%d want=%d", caller, target, got[caller], count)
		}
	}
	return nil
}

func equalStringSlices(left []string, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func TestRemoteAlphaOperatorSemanticInventoryRejectsLayoutAndOwnershipMutations(t *testing.T) {
	base := mustRead(t, remoteAlphaOperatorScriptPath())
	positive := map[string]string{
		"whitespace-only function formatting": strings.NewReplacer(
			"retired_es_existing_host_route() {", "retired_es_existing_host_route ()   {",
			"  reject_secret_args \"$@\"", "      reject_secret_args \"$@\"",
			"  reject_retired_operator_evidence_args \"$@\"", "    reject_retired_operator_evidence_args \"$@\"",
		).Replace(base),
		"comment and inert string": strings.Replace(base,
			"  local first=${1:-} second=${2:-} arg",
			"  local first=${1:-} second=${2:-} arg\n  # vault-workload-auth-check calls retired_operator_evidence_compatibility\n  local inert='--evidence-check --vault-service-user-summary'",
			1,
		),
	}
	for name, source := range positive {
		t.Run(name, func(t *testing.T) {
			if err := validateRemoteAlphaOperatorSemanticInventory(source); err != nil {
				t.Fatalf("structure-insensitive inventory rejected equivalent shell: %v", err)
			}
		})
	}

	negative := map[string]string{
		"duplicate active dispatch route": strings.Replace(base,
			"    es-writable-state-readiness-check)",
			"    es-writable-state-readiness-check|es-writable-state-readiness-check)",
			1,
		),
		"missing retired flag": strings.Replace(base, "--evidence-check=*", "--removed-evidence-check=*", 1),
		"wrong existing-host handler": strings.Replace(base,
			"route_es_writable_state_readiness_check() {\n  retired_es_existing_host_route",
			"route_es_writable_state_readiness_check() {\n  refuse_not_implemented",
			1,
		),
		"privacy order reversal": strings.Replace(base,
			"  reject_secret_args \"$@\"\n  reject_retired_operator_evidence_args \"$@\"",
			"  reject_retired_operator_evidence_args \"$@\"\n  reject_secret_args \"$@\"",
			1,
		),
		"fixed evidence refusal drift": strings.Replace(base,
			"remote alpha operator evidence ingestion, staging, aggregation, and projection compatibility is retired; no artifact inspection, helper execution, staging, or evidence projection occurred",
			"retired evidence behavior changed",
			1,
		),
		"unrelated live route removed": strings.Replace(base, "    recovery-session)", "    removed-recovery-session)", 1),
	}
	for name, source := range negative {
		t.Run(name, func(t *testing.T) {
			if err := validateRemoteAlphaOperatorSemanticInventory(source); err == nil {
				t.Fatal("shell semantic ownership mutation escaped")
			}
		})
	}
}

func TestRemoteAlphaOperatorProtectedScannerGrammarAcceptsEquivalentInertSource(t *testing.T) {
	base := mustRead(t, remoteAlphaOperatorScriptPath())
	positive := map[string]string{
		"current source": base,
		"formatting comments and inert literals": strings.Replace(base,
			"  local first=${1:-} second=${2:-} arg",
			"\n    local first=${1:-} second=${2:-} arg   # equivalent declaration\n    # $(touch /tmp/comment-is-inert)\n    local inert_flags='--evidence-check --vault-service-user-summary'",
			1,
		),
		"single quoted command-looking inert local": strings.Replace(base,
			"  local first=${1:-} second=${2:-} arg",
			"  local first=${1:-} second=${2:-} arg\n  local inert_command='$(touch /tmp/not-executed); > ${HOME}/not-executed'",
			1,
		),
		"equivalent literal quoting": strings.Replace(base,
			"      privacy_refuse\n    fi",
			"      'privacy_refuse'\n    fi",
			1,
		),
	}
	for name, source := range positive {
		t.Run(name, func(t *testing.T) {
			functions, err := parseShellFunctionDefinitions(source)
			if err != nil {
				t.Fatal(err)
			}
			if err := validateRemoteAlphaProtectedScannerGrammar(functions); err != nil {
				t.Fatalf("equivalent protected scanner source was rejected: %v", err)
			}
		})
	}
}

func TestRemoteAlphaOperatorProtectedScannerGrammarRejectsExecutableMutations(t *testing.T) {
	base := mustRead(t, remoteAlphaOperatorScriptPath())
	privacyDeclaration := "  local arg option_name skip_next=\"false\" nocasematch_was_set=\"false\""
	parsePrefix := "  reject_secret_args \"$@\"\n  reject_retired_operator_evidence_args \"$@\""
	mutations := map[string]string{
		"standalone command":                 privacyDeclaration + "\n  touch /tmp/unexpected-effect",
		"assignment command substitution":    privacyDeclaration + "\n  inert_bad=$(touch /tmp/unexpected-effect)",
		"double quoted command substitution": privacyDeclaration + "\n  local inert_bad=\"$(touch /tmp/unexpected-effect)\"",
		"live parameter in inert local":      privacyDeclaration + "\n  local inert_bad=\"${arg}\"",
		"unquoted glob in inert local":       privacyDeclaration + "\n  local inert_bad=/tmp/*",
		"backtick substitution":              privacyDeclaration + "\n  local inert_bad=`touch /tmp/unexpected-effect`",
		"arithmetic substitution":            privacyDeclaration + "\n  local inert_bad=$((1+1))",
		"process substitution":               privacyDeclaration + "\n  local inert_bad=<(touch /tmp/unexpected-effect)",
		"redirection only":                   privacyDeclaration + "\n  > \"${HOME}/unexpected-effect\"",
		"attached redirection":               privacyDeclaration + "\n  privacy_refuse > /tmp/unexpected-effect",
		"quoted heredoc":                     privacyDeclaration + "\n  cat <<'EOF'\nignored\nEOF",
		"semicolon effect":                   privacyDeclaration + "; touch /tmp/unexpected-effect",
		"brace group":                        privacyDeclaration + "\n  { touch /tmp/unexpected-effect; }",
		"subshell":                           privacyDeclaration + "\n  (touch /tmp/unexpected-effect)",
		"pipeline":                           privacyDeclaration + "\n  privacy_refuse | touch /tmp/unexpected-effect",
		"conditional command":                privacyDeclaration + "\n  privacy_refuse && touch /tmp/unexpected-effect",
		"extra loop":                         privacyDeclaration + "\n  for inert_bad in one; do touch /tmp/unexpected-effect; done",
		"live variable reassignment":         privacyDeclaration + "\n  skip_next=true",
		"extra shopt":                        privacyDeclaration + "\n  shopt -s extglob",
		"unknown trailing syntax":            privacyDeclaration + "\n  : unexpected",
	}
	for name, replacement := range mutations {
		t.Run(name, func(t *testing.T) {
			source := strings.Replace(base, privacyDeclaration, replacement, 1)
			functions, err := parseShellFunctionDefinitions(source)
			if err == nil {
				err = validateRemoteAlphaProtectedScannerGrammar(functions)
			}
			if err == nil {
				t.Fatal("executable protected-scanner mutation escaped")
			}
		})
	}

	prefixMutations := map[string]string{
		"effect before privacy scan": "  touch /tmp/unexpected-effect\n" + parsePrefix,
		"effect between scans":       strings.Replace(parsePrefix, "\n", "\n  touch /tmp/unexpected-effect\n", 1),
		"privacy order reversal":     "  reject_retired_operator_evidence_args \"$@\"\n  reject_secret_args \"$@\"",
	}
	for name, replacement := range prefixMutations {
		t.Run(name, func(t *testing.T) {
			source := strings.Replace(base, parsePrefix, replacement, 1)
			functions, err := parseShellFunctionDefinitions(source)
			if err == nil {
				err = validateRemoteAlphaProtectedScannerGrammar(functions)
			}
			if err == nil {
				t.Fatal("parse_args privacy-prefix mutation escaped")
			}
		})
	}
}

func TestRemoteAlphaOperatorRecoverySessionESServiceTLSStatusHelpInventoryHeld(t *testing.T) {
	for _, args := range [][]string{{"help"}, {"inventory"}, {"recovery-session", "--help"}, {"recovery-session", "--inventory"}} {
		output := requireRemoteAlphaOperatorSuccess(t, args...)
		assertContainsAll(t, "P0s/P0t held route text", output,
			"es-service-tls-status", "es-governance-tls-status",
			"es-service-tls-renew", "es-governance-tls-renew", "held")
		assertContainsNone(t, "P0s/P0t held route text", output,
			"ES service TLS public/internal helper pair", "renews only bounded ARS/AGS/ES")
	}
}

func TestRemoteAlphaOperatorRecoverySessionESTLSStatusPreCollectorStageCleanup(t *testing.T) {
	facade := mustRead(t, remoteAlphaOperatorScriptPath())
	section := docSection(t, facade, "remote_alpha_es_tls_status_remote_wrapper() {", "\nrecovery_session_es_service_tls() {")
	assertContainsAll(t, "P0s/P0t custody owner", section,
		"REMOTE_ALPHA_ES_TLS_STATUS_CREATE", "os.mkdir(name, 0o700, dir_fd=parent_fd)",
		"O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC", "os.listdir(directory_fd) != []",
		"os.fchown(dir_fd, 0, 0)", "os.unlink(basename, dir_fd=dir_fd)")
	assertContainsNone(t, "no destructive caller cleanup", section,
		"cleanup-only", "CALLER_CLEANUP", "STATUS_CLEANUP", "cleanup_stage()",
		"mkdir -m 0700 --", "rm -rf /tmp/.es-tls-status-*")
	for _, tc := range []struct {
		name          string
		extra         []string
		wantNoSCP     bool
		wantNoCollect bool
		wantStage     bool
	}{
		{"stage create failure", []string{"FAKE_STATUS_STAGE_CREATE_FAIL=1"}, true, true, false},
		{"malformed identity", []string{"FAKE_STATUS_STAGE_OUTPUT=123:456\nextra"}, true, true, true},
		{"overflow identity", []string{"FAKE_STATUS_STAGE_OUTPUT=18446744073709551616:2"}, true, true, true},
		{"upload failure", []string{"FAKE_STATUS_UPLOAD_FAIL=1"}, false, true, true},
		{"wrapper failure before collector", []string{"FAKE_STATUS_WRAPPER_FAIL=1"}, false, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := setupFakeRemoteAlphaESTLSStatusHarness(t)
			env := append(h.env(), tc.extra...)
			output, err := runRemoteAlphaOperatorWithPTY(t, env,
				"recovery-session", "es-service-tls-status", "--ssh-target", "ds@m75q-test", "--interactive-tty")
			if err == nil {
				t.Fatalf("pre-collector failure unexpectedly succeeded: %s", output)
			}
			ssh := mustRead(t, h.sshLog)
			assertContainsAll(t, tc.name+" SSH", ssh, "STAGE_CREATE")
			assertContainsNone(t, tc.name+" SSH", ssh, "CLEANUP_ONLY", "WRAPPER_CLEANUP_TRAP")
			if tc.wantNoCollect {
				assertContainsNone(t, tc.name+" SSH", ssh, "COLLECT_WRAPPER")
			}
			if tc.wantNoSCP {
				if _, err := os.Stat(h.scpLog); !os.IsNotExist(err) {
					t.Fatalf("SCP ran after stage creation failed: %v", err)
				}
			} else {
				assertContainsAll(t, tc.name+" SCP", mustRead(t, h.scpLog), "remote_alpha_es_tls_status.py")
			}
			assertContainsNone(t, "no accepted generation on failure", output, "collector published a completed observation")
			assertContainsNone(t, "bounded failure text", output, "ds@m75q-test", "123:456")
			stages, err := os.ReadDir(h.stageRoot)
			if err != nil {
				t.Fatal(err)
			}
			if tc.wantStage != (len(stages) == 1) {
				t.Fatalf("stage residue count=%d wantStage=%v", len(stages), tc.wantStage)
			}
			if tc.wantStage {
				entries, err := os.ReadDir(filepath.Join(h.stageRoot, stages[0].Name()))
				if err != nil || len(entries) > 1 || (len(entries) == 1 && entries[0].Name() != "remote_alpha_es_tls_status.py") {
					t.Fatalf("unsafe residue entry set: %v %v", entries, err)
				}
				if len(entries) == 1 {
					got := mustRead(t, filepath.Join(h.stageRoot, stages[0].Name(), entries[0].Name()))
					want := mustRead(t, "scripts/internal/remote_alpha_es_tls_status.py")
					if got != want {
						t.Fatal("residue payload differs from fixed public collector")
					}
				}
			}
		})
	}
	for _, scope := range []string{"es-service-tls-status", "es-governance-tls-status"} {
		t.Run(scope+" success has no later cleanup", func(t *testing.T) {
			h := setupFakeRemoteAlphaESTLSStatusHarness(t)
			output, err := runRemoteAlphaOperatorWithPTY(t, h.env(),
				"recovery-session", scope, "--ssh-target", "ds@m75q-test", "--interactive-tty")
			if err != nil {
				t.Fatalf("status route failed: %v\n%s", err, output)
			}
			ssh := mustRead(t, h.sshLog)
			assertContainsAll(t, scope, ssh, "STAGE_CREATE", "COLLECT_WRAPPER")
			assertContainsNone(t, scope, ssh, "CLEANUP_ONLY", "WRAPPER_CLEANUP_TRAP")
			stages, err := os.ReadDir(h.stageRoot)
			if err != nil || len(stages) != 0 {
				t.Fatalf("successful fake root cleanup left stage: %v %v", stages, err)
			}
		})
	}
}

func TestRemoteAlphaOperatorRecoverySessionESTLSStatusPostContactRefusals(t *testing.T) {
	const commandBuildLine = `remote_command="$(remote_alpha_es_tls_status_remote_wrapper "${remote_stage_dir}" "${stage_identity}" "${scope}" "${collector_digest}")" || recovery_es_tls_status_postcontact_die "${route}" "fixed remote command construction failed; stage retained as diagnostic residue; no fresh status generation accepted"`
	for _, route := range []string{"es-service-tls-status", "es-governance-tls-status"} {
		for _, tc := range []struct {
			name, injected          string
			stage, scp, interactive int
			residue                 bool
			fragment                string
		}{
			{"stage transport failure", "FAKE_STATUS_STAGE_CREATE_FAIL=1", 1, 0, 0, false, "stage creation or custody acquisition failed"},
			{"malformed custody response", "FAKE_STATUS_STAGE_OUTPUT=malformed", 1, 0, 0, true, "stage creation or custody acquisition failed"},
			{"upload failure", "FAKE_STATUS_UPLOAD_FAIL=1", 1, 1, 0, true, "upload failed"},
			{"command construction failure", "", 1, 1, 0, true, "fixed remote command construction failed"},
			{"interactive SSH failure", "FAKE_STATUS_WRAPPER_FAIL=1", 1, 1, 1, true, "remote phase unproved"},
		} {
			t.Run(route+"/"+tc.name, func(t *testing.T) {
				h := setupFakeRemoteAlphaESTLSStatusHarness(t)
				env := h.env()
				if tc.injected != "" {
					env = append(env, tc.injected)
				}
				scriptPath := remoteAlphaOperatorScriptPath()
				if tc.name == "command construction failure" {
					original := mustRead(t, scriptPath)
					if strings.Count(original, commandBuildLine) != 1 {
						t.Fatal("post-stage command construction site changed")
					}
					copyDir := filepath.Join(t.TempDir(), "scripts")
					if err := os.MkdirAll(filepath.Join(copyDir, "internal"), 0o700); err != nil {
						t.Fatal(err)
					}
					scriptPath = filepath.Join(copyDir, "remote_alpha_operator.sh")
					injected := strings.Replace(original, commandBuildLine,
						`remote_command="$(false)" || recovery_es_tls_status_postcontact_die "${route}" "fixed remote command construction failed; stage retained as diagnostic residue; no fresh status generation accepted"`, 1)
					if err := os.WriteFile(scriptPath, []byte(injected), 0o600); err != nil {
						t.Fatal(err)
					}
					collector := mustRead(t, remoteAlphaESServiceTLSStatusCollectorPath())
					if err := os.WriteFile(filepath.Join(copyDir, "internal", "remote_alpha_es_tls_status.py"), []byte(collector), 0o600); err != nil {
						t.Fatal(err)
					}
					if mustRead(t, remoteAlphaOperatorScriptPath()) != original {
						t.Fatal("source-bound construction fault changed the repository source")
					}
				}
				output, err := runRemoteAlphaOperatorWithPTYPath(t, scriptPath, env, "recovery-session", route,
					"--ssh-target", "ds@m75q-test", "--interactive-tty")
				exitErr, ok := err.(*exec.ExitError)
				if !ok || exitErr.ExitCode() != 2 || !strings.Contains(output, tc.fragment) ||
					!strings.Contains(output, "remote phase unproved after status contact") ||
					strings.Contains(output, "No recovery-session live helper or IM execution occurred.") {
					t.Fatalf("post-contact refusal mislabeled remote effects: exit=%v output=%s", err, output)
				}
				ssh := mustRead(t, h.sshLog)
				if strings.Count(ssh, "STAGE_CREATE\n") != tc.stage || strings.Count(ssh, "COLLECT_WRAPPER\n") != tc.interactive ||
					strings.Contains(ssh, "CLEANUP_ONLY") || strings.Contains(ssh, "WRAPPER_CLEANUP_TRAP") {
					t.Fatalf("unexpected stage/interactive transport count or cleanup: %s", ssh)
				}
				if tc.scp == 0 {
					if _, err := os.Lstat(h.scpLog); !os.IsNotExist(err) {
						t.Fatalf("unexpected SCP: %v", err)
					}
				} else if strings.Count(mustRead(t, h.scpLog), "\n") != tc.scp {
					t.Fatal("SCP count changed")
				}
				stages, err := os.ReadDir(h.stageRoot)
				if err != nil || (len(stages) == 1) != tc.residue {
					t.Fatalf("stage residue changed: %v %v", stages, err)
				}
			})
		}
		t.Run(route+"/pre-contact refusal", func(t *testing.T) {
			h := setupFakeRemoteAlphaESTLSStatusHarness(t)
			output, err := runRemoteAlphaOperatorWithPTY(t, h.env(), "recovery-session", route,
				"--ssh-target", "bad;target", "--interactive-tty")
			exitErr, ok := err.(*exec.ExitError)
			if !ok || exitErr.ExitCode() != 2 || !strings.Contains(output, "No recovery-session live helper or IM execution occurred.") ||
				strings.Contains(output, "remote phase unproved after status contact") {
				t.Fatalf("pre-contact refusal changed: exit=%v output=%s", err, output)
			}
			for _, path := range []string{h.sshLog, h.scpLog, h.sshArgv} {
				if _, err := os.Lstat(path); !os.IsNotExist(err) {
					t.Fatalf("pre-contact transport ran: %v", err)
				}
			}
		})
	}
}

func TestRemoteAlphaOperatorRecoverySessionESTLSStatusStageFIFORefusal(t *testing.T) {
	source := mustRead(t, remoteAlphaOperatorScriptPath())
	assertContainsAll(t, "staged-leaf boundary", source,
		"entry = os.stat(basename, dir_fd=dir_fd, follow_symlinks=False)",
		"stat.S_ISREG(entry.st_mode)", "os.O_NONBLOCK")
	for _, mode := range []string{"fifo", "safe"} {
		t.Run(mode, func(t *testing.T) {
			for label, ok := range runRemoteAlphaESStatusBootstrapCase(t, mode) {
				if !ok {
					t.Errorf("%s did not reach the staged-leaf boundary or expected outcome", label)
				}
			}
		})
	}
}

func TestRemoteAlphaOperatorRecoverySessionESTLSStatusRemoteWrapperTrap(t *testing.T) {
	source := mustRead(t, remoteAlphaOperatorScriptPath())
	const opening = "<<'REMOTE_ALPHA_ES_TLS_STATUS_REMOTE_WRAPPER' || true\n"
	const closing = "\nREMOTE_ALPHA_ES_TLS_STATUS_REMOTE_WRAPPER\n"
	start := strings.Index(source, opening)
	if start < 0 {
		t.Fatal("remote wrapper heredoc missing")
	}
	start += len(opening)
	end := strings.Index(source[start:], closing)
	if end < 0 {
		t.Fatal("remote wrapper heredoc closure missing")
	}
	wrapper := source[start : start+end]
	// The fixed target /tmp is a real directory. The local macOS fixture uses
	// /private/tmp because its /tmp is a symlink.
	wrapper = strings.ReplaceAll(wrapper, "/tmp", "/private/tmp")
	wrapper = strings.ReplaceAll(wrapper,
		`if any(attr not in ("security.selinux", "com.apple.provenance") for attr in os.listxattr(fd)):`,
		"if False:")
	for _, tc := range []struct {
		name, outcome string
		filePresent   bool
		wantCalls     int
		wantSuccess   bool
		wantStage     bool
	}{
		{"setup failure before sudo", "fail", false, 0, false, true},
		{"sudo authentication failure", "fail", true, 1, false, true},
		{"sudo launch failure", "launchfail", true, 1, false, true},
		{"bootstrap rejection", "reject", true, 1, false, true},
		{"substituted stage refusal", "substitute", true, 1, false, true},
		{"collector success", "success", true, 1, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			identifier := make([]byte, 16)
			if _, err := rand.Read(identifier); err != nil {
				t.Fatal(err)
			}
			stage := "/private/tmp/.es-tls-status-" + hex.EncodeToString(identifier)
			moved := stage + ".moved"
			if err := os.Mkdir(stage, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Chown(stage, os.Getuid(), os.Getgid()); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				_ = os.Remove(filepath.Join(stage, "remote_alpha_es_tls_status.py"))
				_ = os.Remove(stage)
				_ = os.Remove(filepath.Join(moved, "remote_alpha_es_tls_status.py"))
				_ = os.Remove(moved)
			})
			if tc.filePresent {
				if err := os.WriteFile(filepath.Join(stage, "remote_alpha_es_tls_status.py"), []byte("# fixture\n"), 0o644); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(filepath.Join(stage, "remote_alpha_es_tls_status.py"), 0o644); err != nil {
					t.Fatal(err)
				}
				if err := os.Chown(filepath.Join(stage, "remote_alpha_es_tls_status.py"), os.Getuid(), os.Getgid()); err != nil {
					t.Fatal(err)
				}
			}
			info, err := os.Stat(stage)
			if err != nil {
				t.Fatal(err)
			}
			identity := fmt.Sprintf("%d:%d", info.Sys().(*syscall.Stat_t).Dev, info.Sys().(*syscall.Stat_t).Ino)
			root := t.TempDir()
			bin := filepath.Join(root, "bin")
			if err := os.Mkdir(bin, 0o755); err != nil {
				t.Fatal(err)
			}
			log := filepath.Join(root, "sudo.log")
			writeExecutable(t, bin, "sudo", `#!/usr/bin/env bash
set -euo pipefail
if [[ "$*" == *" -c "* ]]; then
  printf 'BOOTSTRAP\n' >> "$FAKE_STATUS_SUDO_LOG"
  if [[ "$FAKE_STATUS_COLLECT_OUTCOME" == success ]]; then
    /bin/rm -- "$FAKE_STATUS_STAGE/remote_alpha_es_tls_status.py"
    /bin/rmdir -- "$FAKE_STATUS_STAGE"
    exit 0
  fi
  if [[ "$FAKE_STATUS_COLLECT_OUTCOME" == substitute ]]; then
    /bin/mv -- "$FAKE_STATUS_STAGE" "$FAKE_STATUS_STAGE.moved"
    /bin/mkdir -m 0700 -- "$FAKE_STATUS_STAGE"
    /bin/cp -- "$FAKE_STATUS_STAGE.moved/remote_alpha_es_tls_status.py" "$FAKE_STATUS_STAGE/remote_alpha_es_tls_status.py"
  fi
  if [[ "$FAKE_STATUS_COLLECT_OUTCOME" == launchfail ]]; then
    exit 127
  fi
  exit 1
fi
printf 'CLEANUP\n' >> "$FAKE_STATUS_SUDO_LOG"
exit 0
`)
			cmd := exec.Command("/bin/bash", "-s", "--", stage, identity, "artifact-registry", strings.Repeat("a", 64))
			cmd.Dir = executionSubstrateRepoRoot
			cmd.Stdin = strings.NewReader(wrapper)
			cmd.Env = envWithPath(bin,
				"FAKE_STATUS_SUDO_LOG="+log,
				"FAKE_STATUS_COLLECT_OUTCOME="+tc.outcome,
				"FAKE_STATUS_STAGE="+stage)
			output, err := cmd.CombinedOutput()
			if tc.wantSuccess != (err == nil) {
				t.Fatalf("remote wrapper result: %v\n%s", err, output)
			}
			calls := []string{}
			if data, readErr := os.ReadFile(log); readErr == nil {
				calls = strings.Split(strings.TrimSpace(string(data)), "\n")
			} else if !os.IsNotExist(readErr) {
				t.Fatal(readErr)
			}
			if len(calls) != tc.wantCalls {
				t.Fatalf("sudo call count %d, want %d: %q; wrapper output: %s", len(calls), tc.wantCalls, calls, output)
			}
			if tc.filePresent && calls[0] != "BOOTSTRAP" {
				t.Fatalf("first call was not bootstrap: %q", calls)
			}
			_, stageErr := os.Lstat(stage)
			if tc.wantStage != (stageErr == nil) {
				t.Fatalf("stage residue mismatch: stage=%v, err=%v, sudo=%q, wrapper=%s", tc.wantStage, stageErr, calls, output)
			}
			if tc.outcome == "substitute" {
				if _, err := os.Lstat(moved); err != nil {
					t.Fatalf("original stage was deleted after substitution: %v", err)
				}
			}
			if tc.wantStage {
				entries, err := os.ReadDir(stage)
				if err != nil || len(entries) > 1 || (len(entries) == 1 && entries[0].Name() != "remote_alpha_es_tls_status.py") {
					t.Fatalf("stage residue must contain only the public collector: entries=%v err=%v", entries, err)
				}
			}
			for _, call := range calls {
				if call != "BOOTSTRAP" {
					t.Fatalf("unexpected post-stage cleanup call: %q", calls)
				}
			}
		})
	}
}

func TestRemoteAlphaOperatorRecoverySessionESTLSStatusStageCustodyAcquisition(t *testing.T) {
	source := mustRead(t, remoteAlphaOperatorScriptPath())
	const opening = "<<'REMOTE_ALPHA_ES_TLS_STATUS_CREATE'\n"
	const closing = "\nREMOTE_ALPHA_ES_TLS_STATUS_CREATE\n"
	start := strings.Index(source, opening)
	if start < 0 {
		t.Fatal("fixed stage creator missing")
	}
	start += len(opening)
	end := strings.Index(source[start:], closing)
	if end < 0 {
		t.Fatal("fixed stage creator closure missing")
	}
	script := source[start : start+end]
	assertContainsAll(t, "one fixed creator", script,
		"os.open(\"/tmp\", flags)", "os.mkdir(name, 0o700, dir_fd=parent_fd)",
		"os.open(name, flags, dir_fd=parent_fd)", "os.fstat(directory_fd)",
		"os.listdir(directory_fd) != []", "os.close(directory_fd)", "os.close(parent_fd)")
	parent := filepath.Join(t.TempDir(), "stage-parent")
	if err := os.Mkdir(parent, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(parent, os.ModeSticky|0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(parent, os.Getuid(), os.Getgid()); err != nil {
		t.Fatal(err)
	}
	script = strings.ReplaceAll(script, "/tmp", parent)
	script = strings.ReplaceAll(script, "parent.st_uid != 0 or parent.st_gid != 0",
		"parent.st_uid != os.geteuid() or parent.st_gid != os.getegid()")
	script = strings.Replace(script,
		`if any(attr not in ("security.selinux", "com.apple.provenance") for attr in os.listxattr(fd)):`,
		"if False:", 1)
	identifier := make([]byte, 16)
	if _, err := rand.Read(identifier); err != nil {
		t.Fatal(err)
	}
	stage := filepath.Join(parent, ".es-tls-status-"+hex.EncodeToString(identifier))
	run := func(path string) (string, error) {
		t.Helper()
		cmd := exec.Command("/usr/bin/python3", "-I", "-B", "-", path)
		cmd.Dir = executionSubstrateRepoRoot
		cmd.Stdin = strings.NewReader(script)
		cmd.Env = append(os.Environ(), "PYTHONDONTWRITEBYTECODE=1")
		output, err := cmd.CombinedOutput()
		return string(output), err
	}
	output, err := run(stage)
	if err != nil {
		t.Fatalf("creator refused valid stage: %v %s", err, output)
	}
	if !regexp.MustCompile(`^[1-9][0-9]{0,19}:[1-9][0-9]{0,19}\n$`).MatchString(output) {
		t.Fatalf("creator emitted malformed identity: %q", output)
	}
	info, err := os.Lstat(stage)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0o700 {
		t.Fatalf("stage metadata: %v %v", info, err)
	}
	identity := fmt.Sprintf("%d:%d\n", info.Sys().(*syscall.Stat_t).Dev, info.Sys().(*syscall.Stat_t).Ino)
	if output != identity {
		t.Fatalf("identity output %q, want %q", output, identity)
	}
	entries, err := os.ReadDir(stage)
	if err != nil || len(entries) != 0 {
		t.Fatalf("new stage not empty: %v %v", entries, err)
	}
	if second, err := run(stage); err == nil || second != "" {
		t.Fatalf("existing stage accepted: %v %q", err, second)
	}
	if err := os.Remove(stage); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(parent, "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, stage); err != nil {
		t.Fatal(err)
	}
	if second, err := run(stage); err == nil || second != "" {
		t.Fatalf("symlink stage accepted: %v %q", err, second)
	}
	if err := os.Remove(stage); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(target); err != nil {
		t.Fatal(err)
	}
	// The same no-follow parent open rejects a symlink or non-directory parent.
	parentLink := filepath.Join(filepath.Dir(parent), "parent-link")
	if err := os.Symlink(parent, parentLink); err != nil {
		t.Fatal(err)
	}
	linkedScript := strings.ReplaceAll(script, parent, parentLink)
	linkedStage := filepath.Join(parentLink, filepath.Base(stage))
	cmd := exec.Command("/usr/bin/python3", "-I", "-B", "-", linkedStage)
	cmd.Dir = executionSubstrateRepoRoot
	cmd.Stdin = strings.NewReader(linkedScript)
	cmd.Env = append(os.Environ(), "PYTHONDONTWRITEBYTECODE=1")
	if output, err := cmd.CombinedOutput(); err == nil || len(output) != 0 {
		t.Fatalf("symlink parent accepted: %v %q", err, output)
	}
	nonDir := filepath.Join(filepath.Dir(parent), "not-a-directory")
	if err := os.WriteFile(nonDir, []byte("fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	nonDirScript := strings.ReplaceAll(script, parent, nonDir)
	cmd = exec.Command("/usr/bin/python3", "-I", "-B", "-", filepath.Join(nonDir, filepath.Base(stage)))
	cmd.Dir = executionSubstrateRepoRoot
	cmd.Stdin = strings.NewReader(nonDirScript)
	cmd.Env = append(os.Environ(), "PYTHONDONTWRITEBYTECODE=1")
	if output, err := cmd.CombinedOutput(); err == nil || len(output) != 0 {
		t.Fatalf("non-directory parent accepted: %v %q", err, output)
	}
}
