package executionsubstrate_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func p0vLocalRuntimePath() string {
	return filepath.Join(executionSubstrateRepoRoot, "scripts", "remote_alpha_operator_healthcheck_tls_status_noninteractive.py")
}

func p0vRemoteCollectorPath() string {
	return filepath.Join(executionSubstrateRepoRoot, "scripts", "internal", "remote_alpha_operator_healthcheck_tls_status_noninteractive_remote.py")
}

type p0vRuntimeHarness struct {
	binDir string
	sshLog string
	mode   string
}

func setupP0vRuntimeHarness(t *testing.T, mode string) *p0vRuntimeHarness {
	t.Helper()
	tmpDir := t.TempDir()
	h := &p0vRuntimeHarness{
		binDir: filepath.Join(tmpDir, "bin"),
		sshLog: filepath.Join(tmpDir, "ssh.jsonl"),
		mode:   mode,
	}
	if err := os.MkdirAll(h.binDir, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", h.binDir, err)
	}
	return h
}

func (h *p0vRuntimeHarness) env() []string {
	return append(os.Environ(),
		"PATH="+h.binDir+string(os.PathListSeparator)+os.Getenv("PATH"),
		"FAKE_P0V_MODE="+h.mode,
		"PYTHONDONTWRITEBYTECODE=1",
	)
}

func p0vRuntimeHarnessCode(t *testing.T, h *p0vRuntimeHarness) string {
	t.Helper()
	return fmt.Sprintf(`
import hashlib
import importlib.util
import json
import os
import re
import sys

spec = importlib.util.spec_from_file_location("p0v", %q)
m = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = m
spec.loader.exec_module(m)

mode = os.environ.get("FAKE_P0V_MODE", "success")
ssh_log = %q

def protocol(collector_hash, ok=True, failure=None, helper_exit=0, status_available=True):
    status = "pass" if ok else ("not_available" if not status_available else "fail")
    return {
        "protocol_version": m.REMOTE_PROTOCOL_VERSION,
        "collector_sha256": collector_hash,
        "helper_exit_code": helper_exit,
        "status_available": status_available,
        "result": {"status": status, "ok": ok, "summary_label": "remote_status_passed" if ok else "remote_status_blocked", "failure_class": failure},
        "auth_posture": {"runs_as_root": False, "fixed_sudo_used": False, "noninteractive_auth_required": failure == "noninteractive_auth_required", "direct_read_succeeded": True, "sudo_prompt_allowed": False},
        "certificate": {"status": "pass" if ok else "not_available", "not_before": "2026-01-01T00:00:00Z", "not_after": "2027-01-01T00:00:00Z", "expired": False, "not_yet_valid": False, "public_fingerprint_sha256": "1" * 64, "file_sha256": "2" * 64, "public_key_sha256": "3" * 64, "subject_label": "client_operator", "issuer_label": "issuer_present", "issuer_digest_sha256": "4" * 64, "failure_class": None if ok else failure},
        "key_pair": {"status": "pass" if ok else "not_available", "public_key_match": True if ok else None, "cert_public_key_sha256": "3" * 64, "key_public_key_sha256": "3" * 64, "failure_class": None if ok else failure},
        "identity": {"status": "pass" if ok else "not_available", "expected_uri_label": "operator/local", "matches_expected": True if ok else None, "legacy_operator_uri_present": False if ok else None, "classification": "expected_operator_local_identity", "failure_class": None if ok else failure},
        "trust_chain": {"status": "pass" if ok else "not_available", "classification": "trusted_by_fixed_ca", "issuer_digest_sha256": "4" * 64, "failure_class": None if ok else failure},
        "file_posture": {"certificate": "owner_only_or_root_controlled", "key": "owner_only_or_root_controlled", "trust_bundle": "owner_only_or_root_controlled", "safe_mode_labels": ["fixed_operator_cert_path", "fixed_operator_key_path", "fixed_server_client_ca_path"]},
        "redaction": {"private_key_pem_bodies_included": False, "certificate_pem_bodies_included": False, "raw_stdout_retained": False, "raw_stderr_retained": False, "raw_logs_retained": False, "env_values_included": False, "remote_paths_included": False, "endpoint_secrets_included": False, "raw_openssl_output_included": False, "raw_exceptions_included": False, "command_strings_included": False},
    }

def runner(argv, stdin):
    if mode == "runner_exception":
        raise RuntimeError("runner failed")
    remote_command = argv[-1] if argv else ""
    match = re.search(r"--collector-sha256 ([0-9a-f]{64})$", remote_command)
    collector_hash = match.group(1) if match else "0" * 64
    if mode == "spawn_failed":
        return m.ProcessResult("spawn_failed", None, b"", b"", False)
    with open(ssh_log, "a", encoding="utf-8") as handle:
        handle.write(json.dumps({"argv": argv, "stdin_sha256": hashlib.sha256(stdin).hexdigest(), "stdin_size": len(stdin)}) + "\n")
    if mode == "local_runtime_after_start":
        return m.ProcessResult("local_runtime_failed", None, b"", b"", True)
    if mode == "transport":
        return m.ProcessResult("ok", 255, b"", b"")
    if mode == "remote_python_unavailable":
        return m.ProcessResult("ok", 127, b"", b"")
    if mode == "malformed":
        return m.ProcessResult("ok", 0, b"{not-json\n", b"")
    if mode == "duplicate":
        return m.ProcessResult("ok", 0, b'{"protocol_version":"a","protocol_version":"b"}\n', b"")
    if mode == "unknown_field":
        data = protocol(collector_hash)
        data["unexpected"] = True
        return m.ProcessResult("ok", 0, (json.dumps(data, separators=(",", ":")) + "\n").encode(), b"")
    if mode == "unknown_enum":
        data = protocol(collector_hash)
        data["certificate"]["subject_label"] = "freeform_remote_label_should_not_survive"
        data["identity"]["classification"] = "freeform_identity_label_should_not_survive"
        return m.ProcessResult("ok", 0, (json.dumps(data, separators=(",", ":")) + "\n").encode(), b"")
    if mode == "wrong_protocol":
        data = protocol(collector_hash)
        data["protocol_version"] = "wrong"
        return m.ProcessResult("ok", 0, (json.dumps(data, separators=(",", ":")) + "\n").encode(), b"")
    if mode == "wrong_hash":
        data = protocol(collector_hash)
        data["collector_sha256"] = "0" * 64
        return m.ProcessResult("ok", 0, (json.dumps(data, separators=(",", ":")) + "\n").encode(), b"")
    if mode == "mixed_output":
        return m.ProcessResult("ok", 0, (json.dumps(protocol(collector_hash), separators=(",", ":")) + "\n").encode(), b"remote banner\n")
    if mode == "exit_disagree":
        return m.ProcessResult("ok", 1, (json.dumps(protocol(collector_hash, ok=True, helper_exit=0), separators=(",", ":")) + "\n").encode(), b"")
    if mode == "blocked":
        return m.ProcessResult("ok", 1, (json.dumps(protocol(collector_hash, ok=False, failure="noninteractive_auth_required", helper_exit=1, status_available=False), separators=(",", ":")) + "\n").encode(), b"")
    if mode == "cleanup_after_valid_success":
        return m.ProcessResult("ok", 0, (json.dumps(protocol(collector_hash), separators=(",", ":")) + "\n").encode(), b"", True, True)
    if mode == "cleanup_after_transport":
        return m.ProcessResult("ok", 255, b"", b"", True, True)
    if mode == "cleanup_after_malformed":
        return m.ProcessResult("ok", 0, b"{not-json\n", b"", True, True)
    if mode == "cleanup_after_blocked":
        return m.ProcessResult("ok", 1, (json.dumps(protocol(collector_hash, ok=False, failure="noninteractive_auth_required", helper_exit=1, status_available=False), separators=(",", ":")) + "\n").encode(), b"", True, True)
    if mode == "oversized_stdout":
        return m.ProcessResult("stdout_overflow", 0, b"", b"")
    if mode == "oversized_stderr":
        return m.ProcessResult("stderr_overflow", 255, b"", b"")
    return m.ProcessResult("ok", 0, (json.dumps(protocol(collector_hash), separators=(",", ":")) + "\n").encode(), b"")

if mode == "final_schema_reject":
    def reject_schema(document):
        raise m.FinalSchemaError()
    m.validate_final_document = reject_schema
if mode == "final_redaction_reject":
    def reject_redaction(payload):
        raise m.ForbiddenMaterialError()
    m.scan_forbidden_material = reject_redaction
if mode == "final_size_reject":
    m.MAX_FINAL_JSON_BYTES = 1

raise SystemExit(m.run_route(sys.argv[1:], runner=runner, now_func=lambda: "2026-07-27T00:00:00Z"))
`, p0vLocalRuntimePath(), h.sshLog)
}

func runP0vRuntimeRaw(t *testing.T, h *p0vRuntimeHarness, args ...string) (string, string, error) {
	t.Helper()
	cmd := exec.Command("python3", append([]string{"-I", "-S", "-B", "-c", p0vRuntimeHarnessCode(t, h)}, args...)...)
	cmd.Dir = executionSubstrateRepoRoot
	cmd.Env = h.env()
	var stdout strings.Builder
	var stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	return stdout.String(), stderr.String(), err
}

func runP0vRuntime(t *testing.T, h *p0vRuntimeHarness, args ...string) (map[string]any, string, error) {
	t.Helper()
	stdout, stderr, err := runP0vRuntimeRaw(t, h, args...)
	combined := stdout + stderr
	if len(strings.TrimSpace(stdout)) == 0 {
		return nil, combined, err
	}
	var payload map[string]any
	if parseErr := json.Unmarshal([]byte(stdout), &payload); parseErr != nil {
		return nil, combined, err
	}
	return payload, combined, err
}

func requireExitCode(t *testing.T, err error, want int, output string) {
	t.Helper()
	got := 0
	if err != nil {
		exitErr, ok := err.(*exec.ExitError)
		if !ok {
			t.Fatalf("unexpected non-exit error: %v\n%s", err, output)
		}
		got = exitErr.ExitCode()
	}
	if got != want {
		t.Fatalf("exit code=%d, want %d\n%s", got, want, output)
	}
}

func TestRemoteAlphaOperatorHealthcheckTLSStatusNoninteractiveRuntimeExactSSHArgvAndSuccessSchema(t *testing.T) {
	h := setupP0vRuntimeHarness(t, "success")
	payload, output, err := runP0vRuntime(t, h, "--ssh-target", "ds@m75q-test", "--format", "json")
	requireExitCode(t, err, 0, output)
	assertJSONPathEquals(t, payload, "schema_version", "execution-substrate.remote-alpha.operator-healthcheck-tls-status-noninteractive.v1")
	assertJSONPathEquals(t, payload, "route.id", "operator-healthcheck-tls-status-noninteractive")
	assertJSONPathEquals(t, payload, "route.current_status", "implemented")
	assertJSONPathEquals(t, payload, "route.requires_interactive_tty", false)
	assertJSONPathEquals(t, payload, "route.supports_noninteractive", true)
	assertJSONPathEquals(t, payload, "route.scheduled_execution_allowed", false)
	assertJSONPathEquals(t, payload, "result.ok", true)
	assertJSONPathEquals(t, payload, "status_available", true)
	assertJSONPathEquals(t, payload, "auth_posture.pseudo_tty_created", false)
	assertJSONPathEquals(t, payload, "auth_posture.sudo_prompt_allowed", false)
	assertJSONPathEquals(t, payload, "key_pair.public_key_match", true)
	assertJSONPathEquals(t, payload, "provenance.source_revision", nil)

	assertContainsNone(t, "P0v final JSON redaction", output,
		"ds@m75q-test",
		"BEGIN PRIVATE KEY",
		"BEGIN CERTIFICATE",
		"/etc/execution-substrate",
		"remote banner",
	)

	var logEntry struct {
		Argv        []string `json:"argv"`
		StdinSHA256 string   `json:"stdin_sha256"`
		StdinSize   int      `json:"stdin_size"`
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(mustRead(t, h.sshLog))), &logEntry); err != nil {
		t.Fatalf("parse fake ssh log: %v", err)
	}
	expectedPrefix := []string{
		"/usr/bin/ssh",
		"-F", "/dev/null",
		"-T",
		"-o", "BatchMode=yes",
		"-o", "NumberOfPasswordPrompts=0",
		"-o", "KbdInteractiveAuthentication=no",
		"-o", "PasswordAuthentication=no",
		"-o", "StrictHostKeyChecking=yes",
		"-o", "ConnectTimeout=10",
		"-o", "ConnectionAttempts=1",
		"-o", "ProxyCommand=none",
		"-o", "ProxyJump=none",
		"-o", "PermitLocalCommand=no",
		"-o", "ClearAllForwardings=yes",
		"-o", "ForwardAgent=no",
		"-o", "RequestTTY=no",
		"-o", "ControlMaster=no",
		"-o", "ControlPath=none",
		"-o", "ControlPersist=no",
		"-o", "CanonicalizeHostname=no",
		"ds@m75q-test",
	}
	if fmt.Sprint(logEntry.Argv[:len(expectedPrefix)]) != fmt.Sprint(expectedPrefix) {
		t.Fatalf("unexpected ssh argv prefix: %#v", logEntry.Argv)
	}
	assertContainsNone(t, "P0v ssh argv", strings.Join(logEntry.Argv, " "), "-tt", "StrictHostKeyChecking=no")
	if !strings.HasPrefix(logEntry.Argv[len(logEntry.Argv)-1], "exec /usr/bin/python3 -I -S -B - --protocol execution-substrate.remote-alpha.operator-healthcheck-tls-status-noninteractive.remote.v1 --collector-sha256 ") {
		t.Fatalf("unexpected remote command: %q", logEntry.Argv[len(logEntry.Argv)-1])
	}
	collectorBytes, err := os.ReadFile(p0vRemoteCollectorPath())
	if err != nil {
		t.Fatalf("read collector: %v", err)
	}
	sum := sha256.Sum256(collectorBytes)
	if logEntry.StdinSHA256 != hex.EncodeToString(sum[:]) {
		t.Fatalf("collector stdin sha=%s want %s", logEntry.StdinSHA256, hex.EncodeToString(sum[:]))
	}
	if logEntry.StdinSize != len(collectorBytes) {
		t.Fatalf("collector stdin size=%d want %d", logEntry.StdinSize, len(collectorBytes))
	}
	assertJSONPathEquals(t, payload, "provenance.remote_collector_sha256", hex.EncodeToString(sum[:]))
}

func TestRemoteAlphaOperatorHealthcheckTLSStatusNoninteractiveStructuredTargetPrivacyAllowsVocabularyAliases(t *testing.T) {
	for _, target := range []string{"operator", "status", "remote", "ds@m75q-test"} {
		t.Run(target, func(t *testing.T) {
			h := setupP0vRuntimeHarness(t, "success")
			payload, output, err := runP0vRuntime(t, h, "--ssh-target", target, "--format", "json")
			requireExitCode(t, err, 0, output)
			sum := sha256.Sum256([]byte(target))
			assertJSONPathEquals(t, payload, "target.kind", "ssh_target_sha256")
			assertJSONPathEquals(t, payload, "target.sha256", hex.EncodeToString(sum[:]))
			if jsonValueContainsString(payload, target) {
				t.Fatalf("raw target appeared as a final JSON string value: target=%q output=%s", target, output)
			}
			assertContainsNone(t, "P0v structured target privacy", output, "Traceback")
			if target == "ds@m75q-test" {
				assertContainsNone(t, "P0v structured target privacy", output, target)
			}
		})
	}
}

func TestRemoteAlphaOperatorHealthcheckTLSStatusNoninteractiveDoesNotInvokeGit(t *testing.T) {
	h := setupP0vRuntimeHarness(t, "success")
	marker := filepath.Join(t.TempDir(), "fake-git-invoked")
	fakeGit := filepath.Join(h.binDir, "git")
	if err := os.WriteFile(fakeGit, []byte("#!/bin/sh\n: > "+marker+"\nprintf '%s\\n' 0123456789abcdef0123456789abcdef01234567\n"), 0o755); err != nil {
		t.Fatalf("write fake git: %v", err)
	}
	payload, output, err := runP0vRuntime(t, h, "--ssh-target", "ds@m75q-test", "--format", "json")
	requireExitCode(t, err, 0, output)
	assertJSONPathEquals(t, payload, "provenance.source_revision", nil)
	if _, statErr := os.Stat(marker); !os.IsNotExist(statErr) {
		t.Fatalf("runtime invoked ambient git")
	}
}

func TestRemoteAlphaOperatorHealthcheckTLSStatusNoninteractiveRuntimeFailureMapping(t *testing.T) {
	for _, tc := range []struct {
		mode      string
		exit      int
		failure   string
		status    string
		available bool
	}{
		{mode: "blocked", exit: 1, failure: "noninteractive_auth_required", status: "not_available", available: false},
		{mode: "transport", exit: 1, failure: "ssh_batch_mode_failed", status: "not_available", available: false},
		{mode: "remote_python_unavailable", exit: 1, failure: "remote_status_unavailable", status: "not_available", available: false},
		{mode: "malformed", exit: 1, failure: "unexpected_output_shape", status: "not_available", available: false},
		{mode: "duplicate", exit: 1, failure: "unexpected_output_shape", status: "not_available", available: false},
		{mode: "unknown_field", exit: 1, failure: "unexpected_output_shape", status: "not_available", available: false},
		{mode: "unknown_enum", exit: 1, failure: "unexpected_output_shape", status: "not_available", available: false},
		{mode: "wrong_protocol", exit: 1, failure: "unexpected_output_shape", status: "not_available", available: false},
		{mode: "wrong_hash", exit: 1, failure: "unexpected_output_shape", status: "not_available", available: false},
		{mode: "mixed_output", exit: 1, failure: "unexpected_output_shape", status: "not_available", available: false},
		{mode: "exit_disagree", exit: 1, failure: "unexpected_output_shape", status: "not_available", available: false},
		{mode: "cleanup_after_transport", exit: 1, failure: "ssh_batch_mode_failed", status: "not_available", available: false},
		{mode: "cleanup_after_malformed", exit: 1, failure: "unexpected_output_shape", status: "not_available", available: false},
		{mode: "cleanup_after_blocked", exit: 1, failure: "noninteractive_auth_required", status: "not_available", available: false},
		{mode: "oversized_stdout", exit: 1, failure: "unexpected_output_shape", status: "not_available", available: false},
		{mode: "oversized_stderr", exit: 1, failure: "unexpected_output_shape", status: "not_available", available: false},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			h := setupP0vRuntimeHarness(t, tc.mode)
			payload, output, err := runP0vRuntime(t, h, "--ssh-target", "ds@m75q-test", "--format", "json")
			requireExitCode(t, err, tc.exit, output)
			assertJSONPathEquals(t, payload, "failure_class", tc.failure)
			assertJSONPathEquals(t, payload, "result.status", tc.status)
			assertJSONPathEquals(t, payload, "status_available", tc.available)
			assertContainsNone(t, "P0v failure output", output,
				"ds@m75q-test",
				"remote banner",
				"freeform_remote_label_should_not_survive",
				"freeform_identity_label_should_not_survive",
				"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
				"BEGIN PRIVATE KEY",
				"BEGIN CERTIFICATE",
				"selector close failed",
				"cleanup_failed",
			)
			if got := strings.Count(strings.TrimSpace(readIfExists(h.sshLog)), "\n") + boolToCount(strings.TrimSpace(readIfExists(h.sshLog)) != ""); got != 1 {
				t.Fatalf("expected no retry, fake ssh log count=%d log=%s", got, readIfExists(h.sshLog))
			}
		})
	}
}

func TestRemoteAlphaOperatorHealthcheckTLSStatusNoninteractiveLocalRuntimeFailureIsTyped(t *testing.T) {
	for _, tc := range []struct {
		mode                 string
		liveContactAttempted bool
	}{
		{mode: "spawn_failed", liveContactAttempted: false},
		{mode: "runner_exception", liveContactAttempted: false},
		{mode: "local_runtime_after_start", liveContactAttempted: true},
		{mode: "cleanup_after_valid_success", liveContactAttempted: true},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			h := setupP0vRuntimeHarness(t, tc.mode)
			payload, output, err := runP0vRuntime(t, h, "--ssh-target", "ds@m75q-test", "--format", "json")
			requireExitCode(t, err, 1, output)
			assertJSONPathEquals(t, payload, "failure_class", "local_runtime_failed")
			assertJSONPathEquals(t, payload, "result.status", "not_available")
			assertJSONPathEquals(t, payload, "status_available", false)
			assertJSONPathEquals(t, payload, "live_contact_attempted", tc.liveContactAttempted)
			assertContainsNone(t, "P0v local runtime failure", output, "Traceback", "runner failed", "selector close failed", "cleanup_failed", "ds@m75q-test")
		})
	}
}

func TestRemoteAlphaOperatorHealthcheckTLSStatusNoninteractiveFinalEmitterInvariantFailureNoJSON(t *testing.T) {
	for _, mode := range []string{"final_schema_reject", "final_redaction_reject", "final_size_reject"} {
		t.Run(mode, func(t *testing.T) {
			h := setupP0vRuntimeHarness(t, mode)
			stdout, stderr, err := runP0vRuntimeRaw(t, h, "--ssh-target", "operator", "--format", "json")
			requireExitCode(t, err, 1, stdout+stderr)
			if stdout != "" {
				t.Fatalf("final-emitter invariant failure wrote stdout: %q", stdout)
			}
			assertContainsAll(t, "P0v final emitter invariant failure", stderr, "p0v_final_emission_failed")
			assertContainsNone(t, "P0v final emitter invariant failure", stdout+stderr,
				"schema_version",
				"operator-healthcheck-tls-status-noninteractive",
				"Traceback",
				"operator",
				"forbidden_output_material_detected",
			)
		})
	}
}

func TestRemoteAlphaOperatorHealthcheckTLSStatusNoninteractiveFinalSchemaValidatorRejectsTampering(t *testing.T) {
	code := fmt.Sprintf(`
import copy
import importlib.util
import sys

spec = importlib.util.spec_from_file_location("p0v", %q)
m = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = m
spec.loader.exec_module(m)

def remote():
    return {
        "protocol_version": m.REMOTE_PROTOCOL_VERSION,
        "collector_sha256": "b" * 64,
        "helper_exit_code": 0,
        "status_available": True,
        "result": {"status": "pass", "ok": True, "summary_label": "remote_status_passed", "failure_class": None},
        "auth_posture": {"runs_as_root": False, "fixed_sudo_used": False, "noninteractive_auth_required": False, "direct_read_succeeded": True, "sudo_prompt_allowed": False},
        "certificate": {"status": "pass", "not_before": "2026-01-01T00:00:00Z", "not_after": "2027-01-01T00:00:00Z", "expired": False, "not_yet_valid": False, "public_fingerprint_sha256": "1" * 64, "file_sha256": "2" * 64, "public_key_sha256": "3" * 64, "subject_label": "client_operator", "issuer_label": "issuer_present", "issuer_digest_sha256": "4" * 64, "failure_class": None},
        "key_pair": {"status": "pass", "public_key_match": True, "cert_public_key_sha256": "3" * 64, "key_public_key_sha256": "3" * 64, "failure_class": None},
        "identity": {"status": "pass", "expected_uri_label": "operator/local", "matches_expected": True, "legacy_operator_uri_present": False, "classification": "expected_operator_local_identity", "failure_class": None},
        "trust_chain": {"status": "pass", "classification": "trusted_by_fixed_ca", "issuer_digest_sha256": "4" * 64, "failure_class": None},
        "file_posture": {"certificate": "owner_only_or_root_controlled", "key": "owner_only_or_root_controlled", "trust_bundle": "owner_only_or_root_controlled", "safe_mode_labels": ["fixed_operator_cert_path", "fixed_operator_key_path", "fixed_server_client_ca_path"]},
        "redaction": {"private_key_pem_bodies_included": False, "certificate_pem_bodies_included": False, "raw_stdout_retained": False, "raw_stderr_retained": False, "raw_logs_retained": False, "env_values_included": False, "remote_paths_included": False, "endpoint_secrets_included": False, "raw_openssl_output_included": False, "raw_exceptions_included": False, "command_strings_included": False},
    }

def document():
    return m.build_document(m.RouteOutcome(
        generated_at="2026-07-27T00:00:00Z",
        target_hash="a" * 64,
        route_runtime_sha256="c" * 64,
        collector_sha256="b" * 64,
        source_rev=None,
        live_contact_attempted=True,
        failure_class=None,
        transport_exit_code=0,
        helper_exit_code=0,
        remote=remote(),
    ))

def must_reject(label, mutate):
    doc = document()
    mutate(doc)
    try:
        m.validate_final_document(doc)
    except (m.FinalSchemaError, m.ForbiddenMaterialError):
        return
    raise AssertionError(label)

m.validate_final_document(document())
mutations = {
    "unknown_top": lambda d: d.update({"extra": True}),
    "missing_route": lambda d: d.pop("route"),
    "invalid_enum": lambda d: d["certificate"].update({"subject_label": "freeform"}),
    "arbitrary_string": lambda d: d["identity"].update({"classification": "freeform_identity"}),
    "wrong_bool_type": lambda d: d["result"].update({"ok": 1}),
    "bad_hash": lambda d: d["target"].update({"sha256": "not-a-hash"}),
    "bad_revision": lambda d: d["provenance"].update({"source_revision": "ABC"}),
    "bad_time": lambda d: d.update({"generated_at": "yesterday"}),
    "contradiction": lambda d: d["result"].update({"ok": True, "status": "pass", "summary": "remote_status_failed"}),
    "scheduled": lambda d: d["route"].update({"scheduled_execution_allowed": True}),
    "forbidden_material": lambda d: d["certificate"].update({"subject_label": "client_operator", "issuer_label": "issuer_present", "issuer_digest_sha256": "4" * 64, "file_sha256": "2" * 64, "public_fingerprint_sha256": "1" * 64, "public_key_sha256": "3" * 64, "not_before": "2026-01-01T00:00:00Z", "not_after": "2027-01-01T00:00:00Z"}) or d.update({"non_authority_labels": m.EXPECTED_NON_AUTHORITY_LABELS + ["-----BEGIN"]}),
}
for label, mutate in mutations.items():
    must_reject(label, mutate)
print("ok")
`, p0vLocalRuntimePath())
	runPythonSnippet(t, code)
}

func boolToCount(value bool) int {
	if value {
		return 1
	}
	return 0
}

func jsonValueContainsString(value any, needle string) bool {
	switch typed := value.(type) {
	case string:
		return typed == needle
	case []any:
		for _, item := range typed {
			if jsonValueContainsString(item, needle) {
				return true
			}
		}
	case map[string]any:
		for _, item := range typed {
			if jsonValueContainsString(item, needle) {
				return true
			}
		}
	}
	return false
}

func TestRemoteAlphaOperatorHealthcheckTLSStatusNoninteractiveRuntimeUsageExit2NoJSON(t *testing.T) {
	h := setupP0vRuntimeHarness(t, "success")
	cmd := exec.Command("python3", "-I", "-S", "-B", p0vLocalRuntimePath(), "--ssh-target=ds@m75q-test", "--format", "json")
	cmd.Dir = executionSubstrateRepoRoot
	cmd.Env = h.env()
	output, err := cmd.CombinedOutput()
	requireExitCode(t, err, 2, string(output))
	assertContainsAll(t, "P0v runtime usage", string(output), "invalid operator-healthcheck TLS noninteractive status invocation")
	assertContainsNone(t, "P0v runtime usage", string(output), "ds@m75q-test", "schema_version")
	if _, statErr := os.Stat(h.sshLog); !os.IsNotExist(statErr) {
		t.Fatalf("runtime usage failure should not invoke ssh: %s", readIfExists(h.sshLog))
	}
}

func TestRemoteAlphaOperatorHealthcheckTLSStatusNoninteractiveRuntimeRefusesUnisolatedDirectInvocation(t *testing.T) {
	h := setupP0vRuntimeHarness(t, "success")
	cmd := exec.Command("python3", "-B", p0vLocalRuntimePath(), "--ssh-target", "ds@m75q-test", "--format", "json")
	cmd.Dir = executionSubstrateRepoRoot
	cmd.Env = h.env()
	output, err := cmd.CombinedOutput()
	requireExitCode(t, err, 2, string(output))
	assertContainsAll(t, "P0v unisolated runtime refusal", string(output), "p0v_isolated_runtime_required")
	assertContainsNone(t, "P0v unisolated runtime refusal", string(output), "ds@m75q-test", "schema_version", "Traceback")
	if _, statErr := os.Stat(h.sshLog); !os.IsNotExist(statErr) {
		t.Fatalf("unisolated runtime refusal should not invoke ssh: %s", readIfExists(h.sshLog))
	}
}

func TestRemoteAlphaOperatorHealthcheckTLSStatusNoninteractiveRuntimeSourceMode(t *testing.T) {
	info, err := os.Stat(p0vLocalRuntimePath())
	if err != nil {
		t.Fatalf("stat local runtime: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o644 {
		t.Fatalf("local runtime mode=%#o, want 0644", got)
	}
	if info.Mode()&0o111 != 0 {
		t.Fatalf("local runtime must not be directly executable: mode=%#o", info.Mode().Perm())
	}
}

func TestRemoteAlphaOperatorHealthcheckTLSStatusNoninteractiveRuntimeRejectsSecretLikeTargetsBeforeContact(t *testing.T) {
	for _, target := range []string{
		"hvs.abcdefghijklmnopqrstuvwxyz",
		"hvb.abcdefghijklmnopqrstuvwxyz",
		"s.abcdefghijklmnopqrstuvwxyz",
		"sk-abcdefghijklmnopqrstuvwxyz",
		"token=abcdefghijklmnopqrstuvwxyz",
		"s.example-host",
	} {
		t.Run(target, func(t *testing.T) {
			h := setupP0vRuntimeHarness(t, "success")
			payload, output, err := runP0vRuntime(t, h, "--ssh-target", target, "--format", "json")
			if target == "s.example-host" {
				requireExitCode(t, err, 0, output)
				if payload == nil {
					t.Fatalf("ordinary s. host should produce payload")
				}
				return
			}
			requireExitCode(t, err, 2, output)
			assertContainsAll(t, "P0v runtime secret-like refusal", output, "invalid operator-healthcheck TLS noninteractive status invocation")
			assertContainsNone(t, "P0v runtime secret-like refusal", output, target, "schema_version")
			if _, statErr := os.Stat(h.sshLog); !os.IsNotExist(statErr) {
				t.Fatalf("runtime secret-like refusal should not invoke runner: %s", readIfExists(h.sshLog))
			}
		})
	}
}

func TestRemoteAlphaOperatorHealthcheckTLSStatusNoninteractivePythonIsolationFlagsSuppressAmbientStartup(t *testing.T) {
	tmp := t.TempDir()
	sentinel := filepath.Join(tmp, "sentinel")
	if err := os.WriteFile(filepath.Join(tmp, "sitecustomize.py"), []byte("import pathlib; pathlib.Path("+fmt.Sprintf("%q", sentinel)+").write_text('site')\n"), 0o644); err != nil {
		t.Fatalf("write sitecustomize: %v", err)
	}
	if err := os.WriteFile(filepath.Join(tmp, "usercustomize.py"), []byte("import pathlib; pathlib.Path("+fmt.Sprintf("%q", sentinel)+").write_text('user')\n"), 0o644); err != nil {
		t.Fatalf("write usercustomize: %v", err)
	}
	cmd := exec.Command("python3", "-I", "-S", "-B", "-c", "import sys; assert not sys.flags.inspect; print('ok')")
	cmd.Env = append(os.Environ(),
		"PYTHONPATH="+tmp,
		"PYTHONINSPECT=1",
		"PYTHONSTARTUP="+filepath.Join(tmp, "startup.py"),
		"PYTHONDONTWRITEBYTECODE=1",
	)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("isolated python failed: %v\n%s", err, output)
	}
	if strings.TrimSpace(string(output)) != "ok" {
		t.Fatalf("unexpected isolated python output: %s", output)
	}
	if _, err := os.Stat(sentinel); !os.IsNotExist(err) {
		t.Fatalf("isolated python loaded ambient customization")
	}
}

func TestRemoteAlphaOperatorHealthcheckTLSStatusNoninteractiveRuntimeBoundsAndTermination(t *testing.T) {
	code := fmt.Sprintf(`
import importlib.util
import sys
spec = importlib.util.spec_from_file_location("p0v", %q)
m = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = m
spec.loader.exec_module(m)

closed = []
OriginalSelector = m.selectors.DefaultSelector
class TrackingSelector:
    def __init__(self):
        self.inner = OriginalSelector()
    def register(self, *args, **kwargs):
        return self.inner.register(*args, **kwargs)
    def unregister(self, *args, **kwargs):
        return self.inner.unregister(*args, **kwargs)
    def select(self, *args, **kwargs):
        return self.inner.select(*args, **kwargs)
    def close(self):
        closed.append(True)
        return self.inner.close()

m.selectors.DefaultSelector = TrackingSelector
def require_closed(result):
    assert closed, result
    closed.clear()
    return result

timeout = require_closed(m.bounded_subprocess_run([sys.executable, "-c", "import time; time.sleep(5)"], b"", timeout_seconds=0.2))
assert timeout.status == "timeout", timeout
missing = m.bounded_subprocess_run(["/definitely/not/present"], b"")
assert missing.status == "spawn_failed" and missing.child_started is False, missing
stdout = require_closed(m.bounded_subprocess_run([sys.executable, "-c", "import sys; sys.stdout.write('x'*10000)"], b"", stdout_limit=100))
assert stdout.status == "stdout_overflow", stdout
stderr = require_closed(m.bounded_subprocess_run([sys.executable, "-c", "import sys; sys.stderr.write('x'*10000)"], b"", stderr_limit=100))
assert stderr.status == "stderr_overflow", stderr
normal = require_closed(m.bounded_subprocess_run([sys.executable, "-c", "print('done')"], b""))
assert normal.status == "ok" and normal.cleanup_failed is False, normal

class RaisingCloseSelector(TrackingSelector):
    def close(self):
        closed.append(True)
        try:
            self.inner.close()
        finally:
            raise RuntimeError("selector close failed")

m.selectors.DefaultSelector = RaisingCloseSelector
cleanup_success = require_closed(m.bounded_subprocess_run([sys.executable, "-c", "print('done')"], b""))
assert cleanup_success.status == "ok" and cleanup_success.cleanup_failed is True and cleanup_success.child_started is True, cleanup_success
cleanup_transport = require_closed(m.bounded_subprocess_run([sys.executable, "-c", "import sys; sys.exit(255)"], b""))
assert cleanup_transport.status == "ok" and cleanup_transport.returncode == 255 and cleanup_transport.cleanup_failed is True and cleanup_transport.child_started is True, cleanup_transport
cleanup_timeout = require_closed(m.bounded_subprocess_run([sys.executable, "-c", "import time; time.sleep(5)"], b"", timeout_seconds=0.2))
assert cleanup_timeout.status == "timeout" and cleanup_timeout.cleanup_failed is True and cleanup_timeout.child_started is True, cleanup_timeout
cleanup_stdout = require_closed(m.bounded_subprocess_run([sys.executable, "-c", "import sys; sys.stdout.write('x'*10000)"], b"", stdout_limit=100))
assert cleanup_stdout.status == "stdout_overflow" and cleanup_stdout.cleanup_failed is True and cleanup_stdout.child_started is True, cleanup_stdout
cleanup_stderr = require_closed(m.bounded_subprocess_run([sys.executable, "-c", "import sys; sys.stderr.write('x'*10000)"], b"", stderr_limit=100))
assert cleanup_stderr.status == "stderr_overflow" and cleanup_stderr.cleanup_failed is True and cleanup_stderr.child_started is True, cleanup_stderr

class RaisingSelector(RaisingCloseSelector):
    def select(self, *args, **kwargs):
        raise RuntimeError("selector boom")

m.selectors.DefaultSelector = RaisingSelector
result = m.bounded_subprocess_run([sys.executable, "-c", "import time; time.sleep(5)"], b"", timeout_seconds=5)
assert result.status == "local_runtime_failed" and result.child_started is True, result
assert closed, "selector close was not called on exception"
closed.clear()

m.selectors.DefaultSelector = TrackingSelector
original_terminate = m.terminate_process_group
def unresolved_terminate(proc, grace_seconds=m.TERMINATION_GRACE_SECONDS):
    original_terminate(proc, grace_seconds)
    return False
m.terminate_process_group = unresolved_terminate
try:
    unresolved = require_closed(m.bounded_subprocess_run([sys.executable, "-c", "import time; time.sleep(5)"], b"", timeout_seconds=0.2))
finally:
    m.terminate_process_group = original_terminate
assert unresolved.status == "local_runtime_failed" and unresolved.child_started is True, unresolved

class DummySelector:
    def unregister(self, fileobj):
        raise KeyError("already gone")
    def close(self):
        return None
class DummyFile:
    def close(self):
        return None
assert m.cleanup_registered_fileobjs(DummySelector(), [DummyFile()]) is False

m.selectors.DefaultSelector = TrackingSelector
original_read = m.os.read
original_popen = m.subprocess.Popen
def boom_read(fd, count):
    raise RuntimeError("pipe read failed")
def popen_then_boom(*args, **kwargs):
    m.os.read = original_read
    try:
        return original_popen(*args, **kwargs)
    finally:
        m.os.read = boom_read
m.subprocess.Popen = popen_then_boom
try:
    result = m.bounded_subprocess_run([sys.executable, "-c", "print('done')"], b"", timeout_seconds=5)
finally:
    m.subprocess.Popen = original_popen
    m.os.read = original_read
assert result.status == "local_runtime_failed", result
assert closed, "selector close was not called on pipe read exception"
print("ok")
	`, p0vLocalRuntimePath())
	runPythonSnippet(t, code)
}

func TestRemoteAlphaOperatorHealthcheckTLSStatusNoninteractiveRemoteCollectorPureFunctions(t *testing.T) {
	tmpDir := t.TempDir()
	code := fmt.Sprintf(`
import datetime as dt
import hashlib
import importlib.util
import json
import os
import pathlib
import sys

spec = importlib.util.spec_from_file_location("remote", %q)
m = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = m
spec.loader.exec_module(m)
%s
tmp = pathlib.Path(%q)
cert = tmp / "operator-client-cert.pem"
key = tmp / "operator-client-key.pem"
ca = tmp / "server-client-ca.pem"
cert.write_bytes(b"certificate-public-bytes")
key.write_bytes(b"key-private-bytes-not-emitted")
ca.write_bytes(b"ca-public-bytes")
paths = m.Paths(str(cert), str(key), str(ca))

class Runner:
    def __init__(self, mode="valid"):
        self.mode = mode
        self.calls = []
    def __call__(self, args, input_bytes=None):
        self.calls.append(tuple(args))
        if args and args[0] == m.SUDO:
            if self.mode == "sudo_refusal":
                return m.CommandResult(1, b"", b"sudo password required")
            args = tuple(args[2:])
            if self.mode == "sudo_success":
                return self.direct(args, input_bytes)
        if self.mode in {"sudo_success", "sudo_refusal"} and tuple(args) in m.sudo_allowlist(paths):
            return m.CommandResult(1, b"", b"permission denied")
        return self.direct(tuple(args), input_bytes)
    def direct(self, args, input_bytes):
        if args == (m.OPENSSL, "x509", "-in", str(cert), "-pubkey", "-noout"):
            return m.CommandResult(0, b"PUBLIC KEY")
        if args[:5] == (m.OPENSSL, "x509", "-in", str(cert), "-noout"):
            if args[-1] == "-dates":
                if self.mode == "dates_overflow":
                    return m.CommandResult(125, b"", b"", False, True)
                if self.mode == "expired":
                    return m.CommandResult(0, b"notBefore=Jan  1 00:00:00 2025 GMT\nnotAfter=Jan  2 00:00:00 2025 GMT\n")
                if self.mode == "not_yet_valid":
                    return m.CommandResult(0, b"notBefore=Jan  1 00:00:00 2030 GMT\nnotAfter=Jan  2 00:00:00 2030 GMT\n")
                return m.CommandResult(0, b"notBefore=Jan  1 00:00:00 2026 GMT\nnotAfter=Jan  1 00:00:00 2027 GMT\n")
            if args[-1] == "-sha256":
                return m.CommandResult(0, ("sha256 Fingerprint=" + "AA:"*31 + "AA\n").encode())
            if args[-2:] == ("-nameopt", "RFC2253"):
                if self.mode == "subject_spoof":
                    return m.CommandResult(0, b"subject=CN=client.operator.evil\nissuer=CN=operator-ca\n")
                if self.mode == "escaped_subject":
                    return m.CommandResult(0, b"subject=OU=ops,CN=client\\.operator\nissuer=CN=operator-ca\n")
                if self.mode == "control_subject":
                    return m.CommandResult(0, b"subject=CN=client.operator\x01\nissuer=CN=operator-ca\n")
                return m.CommandResult(0, b"subject=CN=client.operator\nissuer=CN=operator-ca\n")
            if args[-1] == "subjectAltName":
                if self.mode == "legacy":
                    return m.CommandResult(0, b"URI:spiffe://execution.internal/operator\n")
                if self.mode == "expected_suffix":
                    return m.CommandResult(0, b"URI:spiffe://execution.internal/operator/local-evil\n")
                if self.mode == "expected_prefix":
                    return m.CommandResult(0, b"URI:xspiffe://execution.internal/operator/local\n")
                if self.mode == "expected_substring":
                    return m.CommandResult(0, b"URI:https://example.invalid/spiffe://execution.internal/operator/local\n")
                if self.mode == "multiple_exact":
                    return m.CommandResult(0, b"DNS:client.operator, URI:spiffe://execution.internal/other, URI:spiffe://execution.internal/operator/local\n")
                if self.mode == "multiple_without_exact":
                    return m.CommandResult(0, b"URI:spiffe://execution.internal/other, URI:spiffe://execution.internal/operator/local-evil\n")
                if self.mode == "malformed_san":
                    return m.CommandResult(0, b"URI:spiffe://execution.internal/operator/local\x01\n")
                return m.CommandResult(0, b"URI:spiffe://execution.internal/operator/local\n")
        if args[:3] == (m.OPENSSL, "pkey", "-pubin"):
            return m.CommandResult(0, b"cert-public-key-der")
        if args[:3] == (m.OPENSSL, "pkey", "-in"):
            if self.mode == "mismatch":
                return m.CommandResult(0, b"different-key-der")
            return m.CommandResult(0, b"cert-public-key-der")
        if args[:2] == (m.OPENSSL, "verify"):
            if self.mode == "trust_fail":
                return m.CommandResult(2, b"", b"verify failed")
            if self.mode == "trust_unavailable":
                return m.CommandResult(127, b"", b"missing")
            if self.mode == "trust_overflow":
                return m.CommandResult(125, b"", b"", False, True)
            return m.CommandResult(0, b"ok\n")
        if args[0] == m.SHA256SUM:
            return m.CommandResult(0, hashlib.sha256(cert.read_bytes()).hexdigest().encode() + b"  x\n")
        if args[0] == m.STAT:
            return m.CommandResult(0, b"600:0:0:regular file\n")
        return m.CommandResult(127, b"", b"missing")

def collect(mode):
    runner = Runner(mode)
    payload = m.collect_status(paths=paths, runner=runner, now=lambda: dt.datetime(2026, 7, 27, tzinfo=dt.timezone.utc))
    text = json.dumps(payload, sort_keys=True)
    assert str(cert) not in text and str(key) not in text and str(ca) not in text, text
    assert "BEGIN" not in text and "PRIVATE KEY" not in text, text
    return payload, runner

payload, runner = collect("valid")
assert payload["result"]["ok"] is True, payload
assert payload["certificate"]["status"] == "pass", payload
assert payload["identity"]["matches_expected"] is True, payload
assert payload["key_pair"]["public_key_match"] is True, payload
assert payload["trust_chain"]["status"] == "pass", payload

payload, _ = collect("multiple_exact")
assert payload["identity"]["matches_expected"] is True, payload
assert payload["identity"]["legacy_operator_uri_present"] is False, payload

for mode in ["expected_suffix", "expected_prefix", "expected_substring", "multiple_without_exact", "malformed_san"]:
    payload, _ = collect(mode)
    assert payload["result"]["failure_class"] == "identity_mismatch", (mode, payload)
    assert payload["identity"]["matches_expected"] is False, (mode, payload)
    assert "operator/local-evil" not in json.dumps(payload), payload

for mode in ["subject_spoof", "escaped_subject"]:
    payload, _ = collect(mode)
    assert payload["certificate"]["subject_label"] == "other_subject", (mode, payload)
    assert "client.operator" not in json.dumps(payload), payload

payload, _ = collect("control_subject")
assert payload["certificate"]["subject_label"] == "subject_malformed", payload

for mode, failure in [
    ("expired", "cert_metadata_expired"),
    ("not_yet_valid", "cert_metadata_not_yet_valid"),
    ("legacy", "identity_mismatch"),
    ("mismatch", "key_pair_mismatch"),
    ("trust_fail", "trust_chain_failed"),
    ("trust_unavailable", "trust_chain_unavailable"),
    ("trust_overflow", "trust_chain_unavailable"),
    ("dates_overflow", "remote_status_unavailable"),
]:
    payload, _ = collect(mode)
    assert payload["result"]["failure_class"] == failure, (mode, payload)

payload, runner = collect("sudo_success")
assert payload["auth_posture"]["fixed_sudo_used"] is True, payload
assert any(call[:2] == (m.SUDO, "-n") for call in runner.calls), runner.calls
assert not any("python" in " ".join(call) or "bash" in " ".join(call) or " sh" in " ".join(call) for call in runner.calls), runner.calls

payload, runner = collect("sudo_refusal")
assert payload["result"]["failure_class"] == "noninteractive_auth_required", payload
assert payload["auth_posture"]["noninteractive_auth_required"] is True, payload

hostile = {
    "OPENSSL_CONF": "/tmp/hostile",
    "OPENSSL_MODULES": "/tmp/modules",
    "RANDFILE": "/tmp/rand",
    "SSL_CERT_FILE": "/tmp/cert",
    "SSL_CERT_DIR": "/tmp/certs",
    "LC_ALL": "zz_ZZ",
    "LANG": "zz_ZZ",
    "HOME": "/tmp/hostile-home",
    "PATH": "/tmp/hostile-bin",
    "PYTHONPATH": "/tmp/hostile-python",
}
old_env = {key: os.environ.get(key) for key in hostile}
try:
    os.environ.update(hostile)
    seen_popen = {}
    original_popen = m.subprocess.Popen
    def fake_popen(args, **kwargs):
        seen_popen["args"] = args
        seen_popen["env"] = kwargs.get("env")
        seen_popen["stdin"] = kwargs.get("stdin")
        seen_popen["shell"] = kwargs.get("shell")
        seen_popen["start_new_session"] = kwargs.get("start_new_session")
        raise OSError("no process")
    m.subprocess.Popen = fake_popen
    result = m.run_command((m.OPENSSL, "version"))
    m.subprocess.Popen = original_popen
    assert result.returncode == 127, result
    child_env = seen_popen["env"]
    assert seen_popen["stdin"] == m.subprocess.DEVNULL, seen_popen
    assert seen_popen["shell"] is False, seen_popen
    assert seen_popen["start_new_session"] is True, seen_popen
    assert child_env["LC_ALL"] == "C", child_env
    assert child_env["LANG"] == "C", child_env
    assert child_env["TZ"] == "UTC", child_env
    assert child_env["OPENSSL_CONF"] == "/dev/null", child_env
    for forbidden in ["OPENSSL_MODULES", "RANDFILE", "SSL_CERT_FILE", "SSL_CERT_DIR", "PYTHONPATH", "PYTHONHOME"]:
        assert forbidden not in child_env, child_env
finally:
    try:
        m.subprocess.Popen = original_popen
    except NameError:
        pass
    for key, value in old_env.items():
        if value is None:
            os.environ.pop(key, None)
        else:
            os.environ[key] = value

print("ok")
`, p0vRemoteCollectorPath(), remoteCollectorDescendantStandIn, tmpDir)
	runPythonSnippet(t, code)
	matches, err := filepath.Glob(filepath.Join(os.TempDir(), "p0v-collector-test-*"))
	if err != nil {
		t.Fatalf("glob p0v collector temp residue: %v", err)
	}
	if len(matches) != 0 {
		t.Fatalf("collector test must not create /tmp/p0v-collector-test-* residue: %v", matches)
	}
}

func TestRemoteAlphaOperatorHealthcheckTLSStatusNoninteractiveRemoteCollectorHardBounds(t *testing.T) {
	tmpDir := t.TempDir()
	code := fmt.Sprintf(`
import hashlib
import importlib.util
import os
import pathlib
import sys

spec = importlib.util.spec_from_file_location("remote", %q)
m = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = m
spec.loader.exec_module(m)
%s
tmp = pathlib.Path(%q)
cert = tmp / "operator-client-cert.pem"
key = tmp / "operator-client-key.pem"
ca = tmp / "server-client-ca.pem"
paths = m.Paths(str(cert), str(key), str(ca))

cert.write_bytes(b"x" * m.MAX_FIXED_TLS_FILE_BYTES)
exact = m.direct_file_sha256(str(cert), paths=paths)
assert exact == hashlib.sha256(b"x" * m.MAX_FIXED_TLS_FILE_BYTES).hexdigest(), exact
cert.write_bytes(b"x" * (m.MAX_FIXED_TLS_FILE_BYTES + 1))
assert m.direct_file_sha256(str(cert), paths=paths) is None
assert m.direct_file_sha256(str(tmp / "not-fixed"), paths=paths) is None

stdout_exact = m.run_command((sys.executable, "-c", "import sys; sys.stdout.buffer.write(b'x' * %d)"))
assert stdout_exact.returncode == 0 and len(stdout_exact.stdout) == m.MAX_COMMAND_STDOUT_BYTES, stdout_exact
stdout_over = m.run_command((sys.executable, "-c", "import sys; sys.stdout.buffer.write(b'x' * %d)"))
assert stdout_over.overflow and stdout_over.stdout == b"" and stdout_over.stderr == b"", stdout_over

stderr_exact = m.run_command((sys.executable, "-c", "import sys; sys.stderr.buffer.write(b'x' * %d)"))
assert stderr_exact.returncode == 0 and len(stderr_exact.stderr) == m.MAX_COMMAND_STDERR_BYTES, stderr_exact
stderr_over = m.run_command((sys.executable, "-c", "import sys; sys.stderr.buffer.write(b'x' * %d)"))
assert stderr_over.overflow and stderr_over.stdout == b"" and stderr_over.stderr == b"", stderr_over

stdin_exact = m.run_command((sys.executable, "-c", "import sys; data=sys.stdin.buffer.read(); sys.stdout.write(str(len(data)))"), b"x" * m.MAX_COMMAND_STDIN_BYTES)
assert stdin_exact.returncode == 0 and stdin_exact.stdout == str(m.MAX_COMMAND_STDIN_BYTES).encode(), stdin_exact
stdin_over = m.run_command((sys.executable, "-c", "import sys; sys.stdin.buffer.read()"), b"x" * (m.MAX_COMMAND_STDIN_BYTES + 1))
assert stdin_over.overflow and stdin_over.stdout == b"" and stdin_over.stderr == b"", stdin_over

old_timeout = m.COMMAND_TIMEOUT_SECONDS
old_grace = m.COMMAND_TERMINATION_GRACE_SECONDS
m.COMMAND_TIMEOUT_SECONDS = 0.2
m.COMMAND_TERMINATION_GRACE_SECONDS = 0.1
try:
    timed = m.run_command((sys.executable, "-c", "import signal,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(5)"))
finally:
    m.COMMAND_TIMEOUT_SECONDS = old_timeout
    m.COMMAND_TERMINATION_GRACE_SECONDS = old_grace
assert timed.timed_out and timed.stdout == b"" and timed.stderr == b"", timed

closed = []
OriginalSelector = m.selectors.DefaultSelector
class TrackingSelector:
    def __init__(self):
        self.inner = OriginalSelector()
    def register(self, *args, **kwargs):
        return self.inner.register(*args, **kwargs)
    def unregister(self, *args, **kwargs):
        return self.inner.unregister(*args, **kwargs)
    def select(self, *args, **kwargs):
        return self.inner.select(*args, **kwargs)
    def close(self):
        closed.append(True)
        return self.inner.close()

m.selectors.DefaultSelector = TrackingSelector
try:
    result = m.run_command((sys.executable, "-c", "print('ok')"))
finally:
    m.selectors.DefaultSelector = OriginalSelector
assert result.returncode == 0 and closed, (result, closed)

print("ok")
	`, p0vRemoteCollectorPath(), remoteCollectorDescendantStandIn, tmpDir, 65536, 65537, 8192, 8193)
	runPythonSnippet(t, code)
}

func TestRemoteAlphaOperatorHealthcheckTLSStatusNoninteractiveRemoteCollectorLifecycleOrdering(t *testing.T) {
	code := fmt.Sprintf(`
import errno
import importlib.util
import os
import signal
import subprocess
import sys

spec = importlib.util.spec_from_file_location("remote", %q)
m = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = m
spec.loader.exec_module(m)
%s
class Key:
    def __init__(self, fileobj, data):
        self.fileobj = fileobj
        self.data = data

class FakeFile:
    next_fd = 1000
    fd_map = {}
    def __init__(self, name, events):
        self.name = name
        self.events = events
        self.closed = False
        self.fd = FakeFile.next_fd
        FakeFile.next_fd += 1
        FakeFile.fd_map[self.fd] = self
    def fileno(self):
        return self.fd
    def close(self):
        self.events.append("stream.close:" + self.name)
        if self.closed:
            self.events.append("stream.double_close:" + self.name)
        self.closed = True

class FakeProc:
    def __init__(self, name, events, stdin_pipe):
        self.name = name
        self.events = events
        self.stdin = FakeFile("stdin", events) if stdin_pipe else None
        self.stdout = FakeFile("stdout", events)
        self.stderr = FakeFile("stderr", events)
        self.pid = 4242
        self.returncode = None
        self.exited = False
        self.stdout_reads = 0
        self.stderr_reads = 0
        self.term_count = 0
        self.kill_count = 0
        self.wait_count = 0
    def poll(self):
        self.events.append("poll")
        if self.name == "normal" and self.stdout_reads >= 2 and self.stderr_reads >= 1:
            self.exited = True
            self.returncode = 0
        if self.exited:
            if self.returncode is None:
                self.returncode = 0
            return self.returncode
        return None
    def wait(self, timeout=None):
        self.events.append("wait")
        self.wait_count += 1
        if self.name == "lifecycle_unresolved":
            raise subprocess.TimeoutExpired("fake", timeout)
        if not self.exited:
            raise subprocess.TimeoutExpired("fake", timeout)
        if self.returncode is None:
            self.returncode = 0
        return self.returncode
    def terminate(self):
        self.events.append("fallback.terminate")
        self.term_count += 1
    def kill(self):
        self.events.append("fallback.kill")
        self.kill_count += 1

class FakeSelector:
    def __init__(self):
        self.proc = current["proc"]
        self.registered = set()
    def register(self, fileobj, _events, data):
        self.registered.add(fileobj.name)
        current["events"].append("selector.register:" + data)
    def unregister(self, fileobj):
        if fileobj.name not in self.registered:
            raise KeyError(fileobj.name)
        self.registered.remove(fileobj.name)
        current["events"].append("selector.unregister:" + fileobj.name)
    def select(self, _timeout):
        name = current["name"]
        current["events"].append("select")
        if name == "selector_failure" or name == "lifecycle_unresolved":
            raise RuntimeError("selector failure detail must stay private")
        if name in {"stderr_overflow", "stderr_read_oserror"}:
            return [(Key(self.proc.stderr, "stderr"), None)]
        if name in {"timeout"}:
            return []
        return [(Key(self.proc.stdout, "stdout"), None), (Key(self.proc.stderr, "stderr"), None)]
    def close(self):
        current["events"].append("selector.close")
        if current["name"] == "selector_close_failure":
            raise RuntimeError("selector close detail must stay private")

current = {"name": "", "events": [], "proc": None, "popen_count": 0}

OriginalPopen = m.subprocess.Popen
OriginalSelector = m.selectors.DefaultSelector
original_killpg = m.os.killpg
original_set_blocking = m.os.set_blocking
original_read = m.os.read
original_write = m.os.write
old_timeout = m.COMMAND_TIMEOUT_SECONDS
old_grace = m.COMMAND_TERMINATION_GRACE_SECONDS

def fake_popen(_args, **kwargs):
    current["popen_count"] += 1
    proc = FakeProc(current["name"], current["events"], kwargs.get("stdin") == m.subprocess.PIPE)
    current["proc"] = proc
    return proc

def fake_killpg(_pid, sig):
    proc = current["proc"]
    if sig == signal.SIGTERM:
        current["events"].append("terminate")
        proc.term_count += 1
        if proc.name in {"stdout_overflow", "stderr_overflow", "selector_failure", "pipe_read_failure", "stdout_read_oserror", "stderr_read_oserror", "partial_stdout_oserror", "selector_close_failure"}:
            proc.exited = True
            proc.returncode = -signal.SIGTERM
    elif sig == signal.SIGKILL:
        current["events"].append("kill")
        proc.kill_count += 1
        if proc.name != "lifecycle_unresolved":
            proc.exited = True
            proc.returncode = -signal.SIGKILL

def fake_read(fd, _count):
    fileobj = FakeFile.fd_map[fd]
    proc = current["proc"]
    current["events"].append("read:" + fileobj.name)
    if current["name"] == "pipe_read_failure":
        raise RuntimeError("pipe read detail must stay private")
    if fileobj.name == "stdout":
        proc.stdout_reads += 1
        if current["name"] == "stdout_read_oserror":
            raise OSError(errno.EIO, "pipe read detail must stay private")
        if current["name"] == "partial_stdout_oserror":
            if proc.stdout_reads == 1:
                return b"{\"protocol_version\":\"partial\""
            raise OSError(errno.EIO, "pipe read detail must stay private")
        if current["name"] == "stdout_eagain_then_data":
            if proc.stdout_reads == 1:
                raise BlockingIOError(errno.EAGAIN, "transient")
            if proc.stdout_reads == 2:
                return b"ok"
            proc.exited = True
            proc.returncode = 0
            return b""
        if current["name"] == "stdout_ewouldblock_then_data":
            if proc.stdout_reads == 1:
                raise BlockingIOError(errno.EWOULDBLOCK, "transient")
            if proc.stdout_reads == 2:
                return b"ok"
            proc.exited = True
            proc.returncode = 0
            return b""
        if current["name"] == "stdout_interrupted_then_data":
            if proc.stdout_reads == 1:
                raise InterruptedError("interrupted")
            if proc.stdout_reads == 2:
                return b"ok"
            proc.exited = True
            proc.returncode = 0
            return b""
        if current["name"] == "genuine_eof":
            if proc.stderr_reads >= 1:
                proc.exited = True
                proc.returncode = 0
            return b""
        if current["name"] in {"stdout_overflow", "already_exited", "selector_close_failure"}:
            if current["name"] == "already_exited":
                proc.exited = True
                proc.returncode = 0
            return b"x" * (m.MAX_COMMAND_STDOUT_BYTES + 1)
        if current["name"] == "normal" and proc.stdout_reads == 1:
            return b"ok"
        if current["name"] == "normal":
            proc.exited = True
            proc.returncode = 0
        return b""
    if fileobj.name == "stderr":
        proc.stderr_reads += 1
        if current["name"] == "stderr_read_oserror":
            raise OSError(errno.EIO, "pipe read detail must stay private")
        if current["name"] == "stderr_overflow":
            return b"x" * (m.MAX_COMMAND_STDERR_BYTES + 1)
        if current["name"] == "genuine_eof" and proc.stdout_reads >= 1:
            proc.exited = True
            proc.returncode = 0
        return b""
    return b""

def fake_write(_fd, payload):
    current["events"].append("write:stdin")
    return len(payload)

def index_of(events, value):
    try:
        return events.index(value)
    except ValueError:
        raise AssertionError((value, events))

def assert_before(events, first, second):
    assert index_of(events, first) < index_of(events, second), events

def assert_lifecycle_before_cleanup(events):
    assert_before(events, "wait", "selector.unregister:stdout")
    assert_before(events, "wait", "selector.close")
    assert_before(events, "selector.close", "stream.close:stdout")
    assert_before(events, "selector.close", "stream.close:stderr")

def assert_final_cleanup_after_lifecycle(events):
    assert_before(events, "wait", "selector.close")
    assert_before(events, "wait", "stream.close:stdout")
    assert_before(events, "wait", "stream.close:stderr")

def assert_no_duplicate_actions(proc, events):
    assert current["popen_count"] == 1, events
    assert proc.term_count <= 1, events
    assert proc.kill_count <= 1, events
    assert proc.wait_count == 1, events
    assert events.count("selector.close") == 1, events
    assert events.count("stream.close:stdout") == 1, events
    assert events.count("stream.close:stderr") == 1, events
    assert "stream.double_close:stdout" not in events, events
    assert "stream.double_close:stderr" not in events, events

def assert_select_between_stdout_reads(events):
    reads = [i for i, event in enumerate(events) if event == "read:stdout"]
    assert len(reads) >= 2, events
    assert "select" in events[reads[0] + 1 : reads[1]], events

def run_case(name):
    FakeFile.fd_map = {}
    current["name"] = name
    current["events"] = []
    current["proc"] = None
    current["popen_count"] = 0
    m.COMMAND_TIMEOUT_SECONDS = 0.0 if name == "timeout" else old_timeout
    m.COMMAND_TERMINATION_GRACE_SECONDS = 0.0
    result = m.run_command((m.OPENSSL, "version"))
    events = list(current["events"])
    proc = current["proc"]
    assert proc is not None, events
    assert_no_duplicate_actions(proc, events)
    return result, events, proc

try:
    m.subprocess.Popen = fake_popen
    m.selectors.DefaultSelector = FakeSelector
    m.os.killpg = fake_killpg
    m.os.set_blocking = lambda _fd, _flag: None
    m.os.read = fake_read
    m.os.write = fake_write

    result, events, proc = run_case("timeout")
    assert result.timed_out and result.stdout == b"" and result.stderr == b"", (result, events)
    assert proc.term_count == 1 and proc.kill_count == 1, events
    assert_before(events, "poll", "terminate")
    assert_before(events, "terminate", "kill")
    assert_lifecycle_before_cleanup(events)

    result, events, proc = run_case("stdout_overflow")
    assert result.overflow and result.stdout == b"" and result.stderr == b"", (result, events)
    assert proc.term_count == 1 and proc.kill_count == 0, events
    assert_lifecycle_before_cleanup(events)

    result, events, proc = run_case("stderr_overflow")
    assert result.overflow and result.stdout == b"" and result.stderr == b"", (result, events)
    assert proc.term_count == 1 and proc.kill_count == 0, events
    assert_lifecycle_before_cleanup(events)

    for name in ("selector_failure", "pipe_read_failure", "stdout_read_oserror", "stderr_read_oserror", "partial_stdout_oserror"):
        result, events, proc = run_case(name)
        assert result.runtime_failed and result.stdout == b"" and result.stderr == b"", (result, events)
        assert proc.term_count == 1 and proc.kill_count == 0, events
        assert_lifecycle_before_cleanup(events)
        assert "selector failure detail must stay private" not in repr(result), result
        assert "pipe read detail must stay private" not in repr(result), result
        assert "EIO" not in repr(result), result
        assert "partial" not in repr(result), result

    for name in ("stdout_eagain_then_data", "stdout_ewouldblock_then_data", "stdout_interrupted_then_data"):
        result, events, proc = run_case(name)
        assert result.returncode == 0 and result.stdout == b"ok" and result.stderr == b"", (result, events)
        assert proc.term_count == 0 and proc.kill_count == 0, events
        assert_select_between_stdout_reads(events)
        assert_final_cleanup_after_lifecycle(events)

    result, events, proc = run_case("genuine_eof")
    assert result.returncode == 0 and result.stdout == b"" and result.stderr == b"", (result, events)
    assert proc.term_count == 0 and proc.kill_count == 0, events
    assert_before(events, "selector.unregister:stdout", "wait")
    assert_before(events, "selector.unregister:stderr", "wait")
    assert_final_cleanup_after_lifecycle(events)

    result, events, proc = run_case("normal")
    assert result.returncode == 0 and result.stdout == b"ok" and result.stderr == b"", (result, events)
    assert proc.term_count == 0 and proc.kill_count == 0, events
    assert_final_cleanup_after_lifecycle(events)

    result, events, proc = run_case("already_exited")
    assert result.overflow and result.stdout == b"" and result.stderr == b"", (result, events)
    assert proc.term_count == 0 and proc.kill_count == 0, events
    assert_lifecycle_before_cleanup(events)

    result, events, proc = run_case("lifecycle_unresolved")
    assert result.runtime_failed and result.stdout == b"" and result.stderr == b"", (result, events)
    assert proc.term_count == 1 and proc.kill_count == 1, events
    assert_lifecycle_before_cleanup(events)
    assert "fake" not in repr(result), result

    result, events, proc = run_case("selector_close_failure")
    assert result.overflow and result.stdout == b"" and result.stderr == b"", (result, events)
    assert proc.term_count == 1 and proc.kill_count == 0, events
    assert_lifecycle_before_cleanup(events)
    assert "selector close detail must stay private" not in repr(result), result
finally:
    m.subprocess.Popen = OriginalPopen
    m.selectors.DefaultSelector = OriginalSelector
    m.os.killpg = original_killpg
    m.os.set_blocking = original_set_blocking
    m.os.read = original_read
    m.os.write = original_write
    m.COMMAND_TIMEOUT_SECONDS = old_timeout
    m.COMMAND_TERMINATION_GRACE_SECONDS = old_grace

print("ok")
	`, p0vRemoteCollectorPath(), remoteCollectorDescendantStandIn)
	runPythonSnippet(t, code)
}

func TestRemoteAlphaOperatorHealthcheckTLSStatusNoninteractiveLocalRuntimePipeReadSemantics(t *testing.T) {
	code := fmt.Sprintf(`
import errno
import importlib.util
import json
import signal
import subprocess
import sys

spec = importlib.util.spec_from_file_location("p0v", %q)
m = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = m
spec.loader.exec_module(m)

class Key:
    def __init__(self, fileobj, data):
        self.fileobj = fileobj
        self.data = data

class FakeFile:
    next_fd = 2000
    fd_map = {}
    def __init__(self, name, events):
        self.name = name
        self.events = events
        self.closed = False
        self.fd = FakeFile.next_fd
        FakeFile.next_fd += 1
        FakeFile.fd_map[self.fd] = self
    def fileno(self):
        return self.fd
    def close(self):
        self.events.append("stream.close:" + self.name)
        if self.closed:
            self.events.append("stream.double_close:" + self.name)
        self.closed = True

class FakeProc:
    def __init__(self, name, events, stdin_pipe):
        self.name = name
        self.events = events
        self.stdin = FakeFile("stdin", events) if stdin_pipe else None
        self.stdout = FakeFile("stdout", events)
        self.stderr = FakeFile("stderr", events)
        self.pid = 5252
        self.returncode = None
        self.exited = False
        self.stdout_reads = 0
        self.stderr_reads = 0
        self.term_count = 0
        self.kill_count = 0
        self.wait_count = 0
    def poll(self):
        self.events.append("poll")
        if self.name in {"local_stdout_eagain_then_data", "local_stdout_ewouldblock_then_data", "local_stdout_interrupted_then_data"} and self.stdout_reads >= 3 and self.stderr_reads >= 1:
            self.exited = True
            self.returncode = 0
        if self.name == "local_genuine_eof" and self.stdout_reads >= 1 and self.stderr_reads >= 1:
            self.exited = True
            self.returncode = 0
        if self.exited:
            if self.returncode is None:
                self.returncode = 0
            return self.returncode
        return None
    def wait(self, timeout=None):
        self.events.append("wait")
        self.wait_count += 1
        if not self.exited:
            raise subprocess.TimeoutExpired("fake", timeout)
        if self.returncode is None:
            self.returncode = 0
        return self.returncode
    def terminate(self):
        self.events.append("fallback.terminate")
        self.term_count += 1
    def kill(self):
        self.events.append("fallback.kill")
        self.kill_count += 1

class FakeSelector:
    def __init__(self):
        self.proc = current["proc"]
        self.registered = set()
    def register(self, fileobj, _events, data):
        self.registered.add(fileobj.name)
        current["events"].append("selector.register:" + data)
    def unregister(self, fileobj):
        if fileobj.name not in self.registered:
            raise KeyError(fileobj.name)
        self.registered.remove(fileobj.name)
        current["events"].append("selector.unregister:" + fileobj.name)
    def select(self, _timeout):
        name = current["name"]
        current["events"].append("select")
        if name == "local_stderr_oserror":
            return [(Key(self.proc.stderr, "stderr"), None)]
        return [(Key(self.proc.stdout, "stdout"), None), (Key(self.proc.stderr, "stderr"), None)]
    def close(self):
        current["events"].append("selector.close")

class CaptureBuffer:
    def __init__(self):
        self.data = b""
    def write(self, payload):
        self.data += payload
        return len(payload)

class CaptureText:
    def __init__(self):
        self.buffer = CaptureBuffer()
    def write(self, text):
        payload = text.encode("utf-8")
        self.buffer.write(payload)
        return len(text)
    def flush(self):
        return None

current = {"name": "", "events": [], "proc": None, "popen_count": 0}

OriginalPopen = m.subprocess.Popen
OriginalSelector = m.selectors.DefaultSelector
original_killpg = m.os.killpg
original_set_blocking = m.os.set_blocking
original_read = m.os.read
original_write = m.os.write

def fake_popen(_args, **kwargs):
    current["popen_count"] += 1
    proc = FakeProc(current["name"], current["events"], kwargs.get("stdin") == m.subprocess.PIPE)
    current["proc"] = proc
    return proc

def fake_killpg(_pid, sig):
    proc = current["proc"]
    if sig == signal.SIGTERM:
        current["events"].append("terminate")
        proc.term_count += 1
        if proc.name in {"local_stdout_oserror", "local_stderr_oserror", "local_partial_stdout_oserror"}:
            proc.exited = True
            proc.returncode = -signal.SIGTERM
    elif sig == signal.SIGKILL:
        current["events"].append("kill")
        proc.kill_count += 1
        proc.exited = True
        proc.returncode = -signal.SIGKILL

def fake_read(fd, _count):
    fileobj = FakeFile.fd_map[fd]
    proc = current["proc"]
    current["events"].append("read:" + fileobj.name)
    if fileobj.name == "stdout":
        proc.stdout_reads += 1
        if current["name"] == "local_stdout_oserror":
            raise OSError(errno.EIO, "pipe read detail must stay private")
        if current["name"] == "local_partial_stdout_oserror":
            if proc.stdout_reads == 1:
                return b"{\"protocol_version\":\"" + m.REMOTE_PROTOCOL_VERSION.encode("ascii")
            raise OSError(errno.EIO, "pipe read detail must stay private")
        if current["name"] == "local_stdout_eagain_then_data":
            if proc.stdout_reads == 1:
                raise BlockingIOError(errno.EAGAIN, "transient")
            if proc.stdout_reads == 2:
                return b"ok"
            return b""
        if current["name"] == "local_stdout_ewouldblock_then_data":
            if proc.stdout_reads == 1:
                raise BlockingIOError(errno.EWOULDBLOCK, "transient")
            if proc.stdout_reads == 2:
                return b"ok"
            return b""
        if current["name"] == "local_stdout_interrupted_then_data":
            if proc.stdout_reads == 1:
                raise InterruptedError("interrupted")
            if proc.stdout_reads == 2:
                return b"ok"
            return b""
        return b""
    if fileobj.name == "stderr":
        proc.stderr_reads += 1
        if current["name"] == "local_stderr_oserror":
            raise OSError(errno.EIO, "pipe read detail must stay private")
        return b""
    return b""

def fake_write(_fd, payload):
    current["events"].append("write:stdin")
    return len(payload)

def index_of(events, value):
    try:
        return events.index(value)
    except ValueError:
        raise AssertionError((value, events))

def assert_before(events, first, second):
    assert index_of(events, first) < index_of(events, second), events

def assert_final_cleanup_after_lifecycle(events):
    assert_before(events, "wait", "selector.close")
    assert_before(events, "wait", "stream.close:stdout")
    assert_before(events, "wait", "stream.close:stderr")

def assert_select_between_stdout_reads(events):
    reads = [i for i, event in enumerate(events) if event == "read:stdout"]
    assert len(reads) >= 2, events
    assert "select" in events[reads[0] + 1 : reads[1]], events

def reset_case(name):
    FakeFile.fd_map = {}
    current["name"] = name
    current["events"] = []
    current["proc"] = None
    current["popen_count"] = 0

def run_process_case(name):
    reset_case(name)
    result = m.bounded_subprocess_run(["/usr/bin/ssh"], b"collector")
    events = list(current["events"])
    proc = current["proc"]
    assert proc is not None, events
    assert current["popen_count"] == 1, events
    assert events.count("selector.close") == 1, events
    assert events.count("stream.close:stdout") == 1, events
    assert events.count("stream.close:stderr") == 1, events
    assert "stream.double_close:stdout" not in events, events
    assert "stream.double_close:stderr" not in events, events
    return result, events, proc

def run_route_case(name):
    reset_case(name)
    captured = CaptureText()
    old_stdout = sys.stdout
    sys.stdout = captured
    try:
        exit_code = m.run_route(["--ssh-target", "ds@m75q-test", "--format", "json"], now_func=lambda: "2026-07-28T00:00:00Z")
    finally:
        sys.stdout = old_stdout
    output = captured.buffer.data.decode("utf-8", "strict")
    payload = json.loads(output)
    events = list(current["events"])
    proc = current["proc"]
    assert proc is not None, events
    assert current["popen_count"] == 1, events
    return exit_code, payload, output, events, proc

try:
    m.subprocess.Popen = fake_popen
    m.selectors.DefaultSelector = FakeSelector
    m.os.killpg = fake_killpg
    m.os.set_blocking = lambda _fd, _flag: None
    m.os.read = fake_read
    m.os.write = fake_write

    for name in ("local_stdout_oserror", "local_stderr_oserror", "local_partial_stdout_oserror"):
        exit_code, payload, output, events, proc = run_route_case(name)
        assert exit_code == 1, (name, exit_code, output)
        assert payload["failure_class"] == "local_runtime_failed", payload
        assert payload["result"]["ok"] is False and payload["result"]["status"] == "not_available", payload
        assert payload["live_contact_attempted"] is True, payload
        assert payload["exit_codes"]["helper_exit_code"] is None, payload
        assert proc.term_count == 1 and proc.kill_count == 0, events
        assert_final_cleanup_after_lifecycle(events)
        assert "Traceback" not in output, output
        assert "ds@m75q-test" not in output, output
        assert "pipe read detail must stay private" not in output, output
        assert "EIO" not in output, output
        assert "partial" not in output, output
        assert "remote_status_passed" not in output, output
        assert "BEGIN" not in output and "PRIVATE KEY" not in output, output

    for name in ("local_stdout_eagain_then_data", "local_stdout_ewouldblock_then_data", "local_stdout_interrupted_then_data"):
        result, events, proc = run_process_case(name)
        assert result.status == "ok" and result.stdout == b"ok" and result.stderr == b"", (name, result, events)
        assert proc.term_count == 0 and proc.kill_count == 0, events
        assert_select_between_stdout_reads(events)
        assert_final_cleanup_after_lifecycle(events)

    result, events, proc = run_process_case("local_genuine_eof")
    assert result.status == "ok" and result.stdout == b"" and result.stderr == b"", (result, events)
    assert proc.term_count == 0 and proc.kill_count == 0, events
    assert_before(events, "selector.unregister:stdout", "wait")
    assert_before(events, "selector.unregister:stderr", "wait")
    assert_final_cleanup_after_lifecycle(events)
finally:
    m.subprocess.Popen = OriginalPopen
    m.selectors.DefaultSelector = OriginalSelector
    m.os.killpg = original_killpg
    m.os.set_blocking = original_set_blocking
    m.os.read = original_read
    m.os.write = original_write

print("ok")
	`, p0vLocalRuntimePath())
	runIsolatedPythonSnippet(t, code)
}

func TestRemoteAlphaOperatorHealthcheckTLSStatusNoninteractiveStaticSourceGuards(t *testing.T) {
	bash := mustRead(t, remoteAlphaOperatorScriptPath())
	runtime := mustRead(t, p0vLocalRuntimePath())
	collector := mustRead(t, p0vRemoteCollectorPath())

	if strings.Count(runtime, "execution-substrate.remote-alpha.operator-healthcheck-tls-status-noninteractive.v1") != 1 {
		t.Fatalf("final schema identity must appear exactly once in local runtime")
	}
	if strings.Count(runtime, "def build_document(") != 1 {
		t.Fatalf("local runtime must have exactly one final document builder")
	}
	assertContainsNone(t, "final schema not in Bash or remote collector", bash+"\n"+collector,
		"execution-substrate.remote-alpha.operator-healthcheck-tls-status-noninteractive.v1",
	)
	assertContainsAll(t, "remote collector internal protocol", collector,
		"execution-substrate.remote-alpha.operator-healthcheck-tls-status-noninteractive.remote.v1",
	)
	p0vBashSection := docSection(t, bash, "recovery_session_operator_healthcheck_tls_status_noninteractive_usage() {", "\nrecovery_session_operator_healthcheck_tls_usage() {")
	assertContainsAll(t, "P0v Bash source", p0vBashSection,
		"REMOTE_ALPHA_OPERATOR_HEALTHCHECK_TLS_STATUS_NONINTERACTIVE_RUNTIME",
		"REMOTE_ALPHA_OPERATOR_HEALTHCHECK_TLS_STATUS_NONINTERACTIVE_REMOTE_COLLECTOR",
		"exec \"${recovery_session_p0v_python3_path}\" -I -S -B",
		"--ssh-target",
		"--format json",
	)
	assertContainsNone(t, "P0v Bash forbidden source", p0vBashSection,
		"scp ",
		"ssh -tt",
		"ssh \"${ssh_target}\"",
		"sudo ",
		"summary_path",
		"remote_stage_dir",
		"fallback",
		"schema_version",
	)
	assertContainsNone(t, "P0v runtime forbidden source", runtime,
		"shell=True",
		"scp",
		"sudo -n python3",
		"sudo python3",
		"sudo bash",
		"sudo sh",
		"--collector-path",
		"--ssh-option",
		"--timeout",
		"fallback",
		"subprocess.run(",
		"git",
		"raw_target",
		"subprocess.run(argv",
	)
	assertContainsNone(t, "P0v collector forbidden source", collector,
		"sudo -n python3",
		"sudo python3",
		"sudo -n bash",
		"sudo bash",
		"sudo sh",
		"/health",
		"/v1/executions:contract",
		"mktemp",
		"communicate(",
		"read_bytes(",
		"socket",
		"curl",
		"chmod",
		"chown",
		" rm ",
		" tee ",
	)
}

func runPythonSnippet(t *testing.T, code string) {
	t.Helper()
	cmd := exec.Command("python3", "-B", "-c", code)
	cmd.Dir = executionSubstrateRepoRoot
	cmd.Env = append(os.Environ(), "PYTHONDONTWRITEBYTECODE=1")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("python snippet failed: %v\n%s", err, output)
	}
	if strings.TrimSpace(string(output)) != "ok" {
		t.Fatalf("unexpected python snippet output: %s", output)
	}
}

func runIsolatedPythonSnippet(t *testing.T, code string) {
	t.Helper()
	cmd := exec.Command("python3", "-I", "-S", "-B", "-c", code)
	cmd.Dir = executionSubstrateRepoRoot
	cmd.Env = append(os.Environ(), "PYTHONDONTWRITEBYTECODE=1")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("isolated python snippet failed: %v\n%s", err, output)
	}
	if strings.TrimSpace(string(output)) != "ok" {
		t.Fatalf("unexpected isolated python snippet output: %s", output)
	}
}
