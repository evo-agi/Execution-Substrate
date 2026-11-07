package executionsubstrate_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// This fixture imports the source without entering __main__. Every material and
// native response below is synthetic; no installed TLS material or OpenSSL runs.
const grammarPythonFixture = `
import copy
import importlib.util
import json
import os
import stat
import sys
from unittest import mock

spec = importlib.util.spec_from_file_location("grammar_fixture", sys.argv[1])
m = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = m
spec.loader.exec_module(m)
digest = "a" * 64
cert = b"-----BEGIN CERTIFICATE-----\nQUJD\n-----END CERTIFICATE-----\n"
key = b"synthetic-key"
pem = b"-----BEGIN PUBLIC KEY-----\nQUJD\n-----END PUBLIC KEY-----\n"
der = b"\x30\x3e" + b"\x00" * 62
metadata = (b"subject=CN=synthetic\nissuer=CN=synthetic\n"
            b"notBefore=Nov  1 00:00:00 2026 GMT\n"
            b"notAfter=Nov  1 00:00:00 2027 GMT\n"
            b"sha256 Fingerprint=" + b":".join([b"AA"] * 32) + b"\n")
text = (b"Certificate:\n    Data:\n"
        b"    Signature Algorithm: sha256WithRSAEncryption\n"
        b"    Signature Value:\n        aa\n")
original_reader = m.open_fixed_regular
original_runner = m.run_fixed
original_topology = m.collect_topology
original_diagnose = m.diagnose_first_rejection

def successful_tuple(argv):
    if "verify" in argv: return (0, b"/dev/stdin: OK\n", b"")
    if "-text" in argv: return (0, text, b"")
    if "-pubkey" in argv: return (0, pem, b"")
    if "-pubin" in argv: return (0, der, b"")
    if "-pubout" in argv: return (0, der, b"")
    return (0, metadata, b"")

def traverse(target=0, bad=None, reader=None):
    calls = []
    def run(argv, input_bytes=None, anchor_bytes=None):
        calls.append((argv, input_bytes, anchor_bytes))
        if len(calls) == target: return bad
        return successful_tuple(argv)
    m.run_fixed = run
    m.open_fixed_regular = reader or (lambda path, limit, read_content=True:
                                      key if path.endswith("-key.pem") else cert)
    m.collect_topology = lambda scope: []
    context = m.DiagnosticContext()
    failure = None
    try:
        original_diagnose(context)
    except m.Incomplete as exc:
        failure = str(exc)
    return context, calls, failure

def closed_line(result):
    line = m.format_diagnostic_line(result, digest)
    assert line is not None and line.startswith(b"ES_TLS_GRAMMAR_DIAGNOSTIC_V1 ")
    assert line.endswith(b"\n") and line.count(b"\n") == 1 and line.isascii()
    assert len(line) <= 2048
    return line
`

func runGrammarPython(t *testing.T, body string) {
	t.Helper()
	source := filepath.Join(executionSubstrateRepoRoot, "scripts", "internal", "remote_alpha_es_tls_status.py")
	cmd := exec.Command("/usr/bin/python3", "-I", "-B", "-c", grammarPythonFixture+"\n"+body, source)
	cmd.Dir = executionSubstrateRepoRoot
	cmd.Env = append(os.Environ(), "PYTHONDONTWRITEBYTECODE=1")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("synthetic grammar fixture failed: %v\n%s", err, output)
	}
	if strings.TrimSpace(string(output)) != "OK" {
		t.Fatalf("synthetic grammar fixture did not complete: %q", output)
	}
}

func TestRemoteAlphaP0tGrammarDiagnosticSourceAndPublicationBoundary(t *testing.T) {
	source := mustRead(t, filepath.Join(executionSubstrateRepoRoot, "scripts", "internal", "remote_alpha_es_tls_status.py"))
	facade := mustRead(t, remoteAlphaOperatorScriptPath())
	schemaPath := filepath.Join(executionSubstrateRepoRoot, "testdata", "remote_alpha_es_tls_status",
		"grammar_diagnostic_schema.json")
	var schema map[string]any
	if err := json.Unmarshal([]byte(mustRead(t, schemaPath)), &schema); err != nil {
		t.Fatalf("parse reference diagnostic schema as data: %v", err)
	}
	if schema["$id"] != "urn:es-p0t-openssl-grammar-diagnostic-private-contract-v1" ||
		schema["additionalProperties"] != false {
		t.Fatal("diagnostic schema lost its closed private identity")
	}
	if _, ok := schema["x-semantic-constraints"]; !ok {
		t.Fatal("reference schema lost its explicit semantic annotations")
	}
	assertContainsAll(t, "diagnostic source boundary", source,
		"def open_existing_scope_lock(", "def diagnostic_main()", "def diagnose_first_rejection(",
		"def format_diagnostic_line(", "ES_TLS_GRAMMAR_DIAGNOSTIC_BOOTSTRAP_VERIFIED",
		"diagnose_first_rejection(diagnostic)", "preexisting_generation(status_fd, \"execution-governance\")")
	diagnostic := docSection(t, source, "def diagnose_first_rejection(", "\ndef _diagnostic_shape_valid(")
	assertContainsNone(t, "diagnostic publisher boundary", diagnostic,
		"publish(", "encode_document(", "collect(", "open_scope_lock(", "os.replace(", "os._exit(")
	assertContainsAll(t, "verified bootstrap mode", facade,
		"es-governance-tls-grammar-diagnostic", "if diagnostic_mode:",
		"\"__name__\": \"_es_tls_grammar_diagnostic\"", "line = formatter(result, digest)",
		"write_failure_witness(line)")
	bootstrap := docSection(t, facade,
		"# The fixed root bootstrap loads only digest-bound bytes from the staged leaf.",
		"REMOTE_ALPHA_ES_TLS_STATUS_BOOTSTRAP\nstage_dev=")
	digestCheck := strings.Index(bootstrap, "hashlib.sha256(payload).hexdigest() != digest")
	stageRemoval := strings.Index(bootstrap, "os.unlink(basename, dir_fd=dir_fd)")
	diagnosticLoad := strings.Index(bootstrap, "if diagnostic_mode:\n    label =")
	if digestCheck < 0 || stageRemoval <= digestCheck || diagnosticLoad <= stageRemoval {
		t.Fatal("diagnostic module selection bypasses same-stage source custody and removal")
	}
	if strings.Count(facade, "atexit.register(emit_failure_witness)") != 1 {
		t.Fatal("status failure emitter registration must have one conditional call site")
	}
	runGrammarPython(t, `
assert m.diagnostic_main() is None
assert m.parse_cli(["--scope", "execution-governance"]) == "execution-governance"
try: m.parse_cli(["--scope", "execution-governance", "grammar-diagnostic"])
except m.Incomplete: pass
else: raise AssertionError("direct diagnostic CLI accepted")
print("OK")
`)
	h := setupFakeRemoteAlphaESTLSStatusHarness(t)
	output, err := runRemoteAlphaOperatorWithEnv(h.env(),
		"recovery-session", "es-governance-tls-grammar-diagnostic", "--verify-only")
	if err != nil {
		t.Fatalf("contact-free diagnostic verification failed: %v\n%s", err, output)
	}
	assertContainsAll(t, "diagnostic verification", output, "local source and command construction verified", "no host contact")
	for _, path := range []string{h.sshLog, h.sshArgv, h.scpLog} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatalf("verification created transport evidence %s: %v", path, err)
		}
	}
	for _, args := range [][]string{
		{"--verify-only", "--ssh-target", "ds@m75q-test"},
		{"--verify-only", "--interactive-tty"},
		{"--execute-renew"},
		{"--scope", "artifact-registry"},
		{"--verify-only", "--verify-only"},
		{"--output=/tmp/unexpected"},
	} {
		argv := append([]string{"recovery-session", "es-governance-tls-grammar-diagnostic"}, args...)
		if out, err := runRemoteAlphaOperatorWithEnv(h.env(), argv...); err == nil {
			t.Fatalf("hostile diagnostic args accepted %v: %s", args, out)
		}
	}
	for _, path := range []string{h.sshLog, h.sshArgv, h.scpLog} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatalf("refusal contacted transport at %s: %v", path, err)
		}
	}
}

func TestRemoteAlphaP0tGrammarDiagnosticTenSites(t *testing.T) {
	runGrammarPython(t, `
baseline, expected_calls, failure = traverse()
assert failure is None and baseline.fixed_call_attempts == 18
cases = [
 ("META_NEGATIVE_UNADMITTED", (1,4,8,12), (3,b"unexpected",b"error"), "negative_exit_not_one"),
 ("META_FIELDS_UNADMITTED", (1,4,8,12), (0,b"bad",b""), "metadata_final_lf_missing"),
 ("CERT_PUBLIC_PEM_UNADMITTED", (2,5,9,13), (0,b"bad",b""), "public_pem_envelope"),
 ("CERT_PUBLIC_DER_UNADMITTED", (3,6,10,14), (0,b"bad",b""), "public_der_sequence"),
 ("ROLE_TEXT_EXIT_UNADMITTED", (7,11), (2,b"",b""), "text_exit_nonzero"),
 ("ROLE_TEXT_ENVELOPE_UNADMITTED", (7,11), (0,b"bad",b""), "text_prefix"),
 ("KEY_NEGATIVE_UNADMITTED", (15,16), (3,b"bad",b"error"), "negative_exit_not_one"),
 ("KEY_DER_UNADMITTED", (15,16), (0,b"bad",b""), "key_der_sequence"),
 ("VERIFY_SUCCESS_ENVELOPE_UNADMITTED", (17,18), (0,b"bad",b""), "verify_success_stdout_not_exact"),
 ("VERIFY_FAILURE_ENVELOPE_UNADMITTED", (17,18), (2,b"",b"unadmitted"), "verify_failure_whole_alternative_unadmitted"),
]
for site, ordinals, bad, predicate in cases:
    for ordinal in ordinals:
        context, calls, failure = traverse(ordinal, bad)
        assert failure == "unexpected_openssl_grammar", (site, ordinal, failure)
        first = context.first_rejection
        assert first and first["site"] == site and first["predicate"] == predicate
        assert first["call_ordinal"] == context.fixed_call_attempts == ordinal
        assert calls == expected_calls[:ordinal], (site, ordinal, "argv/input/anchor drift")
        assert first["role"] in m.DIAGNOSTIC_OPERATION_ROLES[first["operation"]]
        result = dict(schema_version="es-p0t-openssl-grammar-diagnostic/v1",
                      scope="execution-governance", source_sha256=digest,
                      outcome="first_grammar_rejection", fixed_call_attempts=ordinal,
                      first_rejection=first, other_failure=None)
        closed_line(result)
# Source-ordered precedence when two structural predicates are simultaneously bad.
for ordinal, bad, expected in [
    (1,(3,b"bad",b"error"),"negative_exit_not_one"),
    (1,(0,b"bad",b"error"),"metadata_stderr_nonempty"),
    (17,(2,b"bad",b"error"),"verify_failure_stream_placement")]:
    context, _, failure = traverse(ordinal,bad)
    assert failure == "unexpected_openssl_grammar"
    assert context.first_rejection["predicate"] == expected
for ordinal, reason, expected in [
    (17,b"error 62 at 0 depth lookup: hostname mismatch\n","verify_failure_context_coupling"),
    (18,b"error 26 at 0 depth lookup: unsuitable certificate purpose\n","verify_failure_context_coupling"),
    (17,b"error 20 at 0 depth lookup: unable to get local issuer certificate\n","verify_failure_whole_alternative_unadmitted")]:
    context,_,failure=traverse(ordinal,(2,b"",reason))
    assert failure=="unexpected_openssl_grammar"
    assert context.first_rejection["predicate"]==expected
    token=context.first_rejection["response_shape"]["verify_token"]
    assert token==("20_0_issuer_unavailable" if expected=="verify_failure_whole_alternative_unadmitted" else "other")
print("OK")
`)
}

func TestRemoteAlphaP0tGrammarDiagnosticTokenStreamBoundaries(t *testing.T) {
	runGrammarPython(t, `
issuer = b"error 20 at 0 depth lookup: unable to get local issuer certificate\n"
expired = b"error 10 at 0 depth lookup: certificate has expired\n"
cases = [
    (b"error 20 at 0 depth lookup: ", b"unable to get local issuer certificate\n",
     "other", "verify_failure_stream_placement"),
    (b"", issuer + issuer, "other", "verify_failure_whole_alternative_unadmitted"),
    (issuer + issuer, b"", "other", "verify_failure_whole_alternative_unadmitted"),
    (issuer, issuer, "other", "verify_failure_stream_placement"),
    (b"", issuer + expired, "other", "verify_failure_whole_alternative_unadmitted"),
    (issuer, b"", "20_0_issuer_unavailable", "verify_failure_whole_alternative_unadmitted"),
    (b"", issuer, "20_0_issuer_unavailable", "verify_failure_whole_alternative_unadmitted"),
    (issuer[:-1], b"", "other", "verify_failure_whole_alternative_unadmitted"),
    (b"prefix\n" + issuer, b"", "20_0_issuer_unavailable", "verify_failure_whole_alternative_unadmitted"),
]
for purpose, label, hostname in (
        ("sslclient", m.DIAGNOSTIC_VERIFY_CLIENT, ""),
        ("sslserver", m.DIAGNOSTIC_VERIFY_SERVER, "egs.internal")):
    for out, err, expected_token, expected_predicate in cases:
        calls = []
        def fixed(argv, input_bytes=None, anchor_bytes=None):
            calls.append((argv, input_bytes, anchor_bytes))
            return 2, out, err
        m.run_fixed = fixed
        context = m.DiagnosticContext()
        try:
            m.verify_chain(label, {"sha256": "a"}, {"sha256": "b"},
                           b"anchor", b"certificate", purpose, hostname, context)
        except m.Incomplete as exc:
            assert str(exc) == "unexpected_openssl_grammar"
        else:
            raise AssertionError("unadmitted tuple accepted")
        assert len(calls) == context.fixed_call_attempts == 1
        assert calls[0][1:] == (b"certificate", b"anchor")
        first = context.first_rejection
        assert first["predicate"] == expected_predicate, (purpose, out, err, first)
        assert first["response_shape"]["verify_token"] == expected_token, (purpose, out, err, first)
# The context mismatch still downgrades a recognized line, without changing
# the native call budget or the first predicate.
for purpose, label, hostname, line in (
        ("sslclient", m.DIAGNOSTIC_VERIFY_CLIENT, "",
         b"error 62 at 0 depth lookup: hostname mismatch\n"),
        ("sslserver", m.DIAGNOSTIC_VERIFY_SERVER, "egs.internal",
         b"error 26 at 0 depth lookup: unsuitable certificate purpose\n")):
    m.run_fixed = lambda *args: (2, b"", line)
    context = m.DiagnosticContext()
    try:
        m.verify_chain(label, {"sha256": "a"}, {"sha256": "b"},
                       b"anchor", b"certificate", purpose, hostname, context)
    except m.Incomplete as exc:
        assert str(exc) == "unexpected_openssl_grammar"
    else:
        raise AssertionError("context mismatch accepted")
    assert context.fixed_call_attempts == 1
    assert context.first_rejection["predicate"] == "verify_failure_context_coupling"
    assert context.first_rejection["response_shape"]["verify_token"] == "other"
print("OK")
`)
}

func TestRemoteAlphaP0tGrammarDiagnosticResultSemanticConsistency(t *testing.T) {
	runGrammarPython(t, `
shape = lambda raw: m._diagnostic_stream_shape(raw, m.MAX_OUTPUT)
for raw in (b"", b"\n", b"a", b"a\n", b"\r\n", b"\x00\n",
            b"\xff\n", b"\r\x00\xff\n", b"\n\r", b"\n\x00\xff"):
    assert m._diagnostic_shape_valid(shape(raw), m.MAX_OUTPUT), raw
for raw, changes in (
        (b"a", {"has_cr": True, "has_nul": True}),
        (b"\n", {"has_cr": True}),
        (b"\n", {"utf8": False}),
        (b"\n\r", {"has_cr": True, "has_nul": True}),
        (b"\n\xff", {"has_cr": True, "utf8": False}),
        (b"\r\n", {"has_cr": True, "utf8": False}),
        (b"\x00\n", {"has_cr": True, "has_nul": True}),
):
    forged = shape(raw) | changes
    assert not m._diagnostic_shape_valid(forged, m.MAX_OUTPUT), (raw, forged)
issuer = b"error 20 at 0 depth lookup: unable to get local issuer certificate\n"
context, _, failure = traverse(17, (2, b"", issuer))
assert failure == "unexpected_openssl_grammar"
record = dict(schema_version="es-p0t-openssl-grammar-diagnostic/v1",
              scope="execution-governance", source_sha256=digest,
              outcome="first_grammar_rejection", fixed_call_attempts=17,
              first_rejection=context.first_rejection, other_failure=None)
assert record["first_rejection"]["response_shape"]["verify_token"] == "20_0_issuer_unavailable"
closed_line(record)
for out, err in ((b"", b""), (issuer[:-1], b""),
                 (b"x" * (len(issuer)-1), b"\n")):
    forged = copy.deepcopy(record)
    forged["first_rejection"]["response_shape"]["stdout"] = shape(out)
    forged["first_rejection"]["response_shape"]["stderr"] = shape(err)
    assert m.format_diagnostic_line(forged, digest) is None, (out, err)
# Counts are necessary capacity checks, not authentication of private bytes.
opaque = copy.deepcopy(record)
opaque["first_rejection"]["response_shape"]["stdout"] = shape(b"x" * (len(issuer)-1) + b"\n")
opaque["first_rejection"]["response_shape"]["stderr"] = shape(b"")
closed_line(opaque)
key_context, _, failure = traverse(15, (0, b"x", b""))
assert failure == "unexpected_openssl_grammar"
key_record = dict(schema_version="es-p0t-openssl-grammar-diagnostic/v1",
                  scope="execution-governance", source_sha256=digest,
                  outcome="first_grammar_rejection", fixed_call_attempts=15,
                  first_rejection=key_context.first_rejection, other_failure=None)
closed_line(key_record)
for raw, changes in ((b"x", {"has_cr": True, "has_nul": True}),
                     (b"\n", {"utf8": False}),
                     (b"\n\r", {"has_cr": True, "has_nul": True})):
    forged = copy.deepcopy(key_record)
    forged["first_rejection"]["response_shape"]["stdout"] = shape(raw) | changes
    assert m.format_diagnostic_line(forged, digest) is None
# Every known token is produced by the actual verification caller in each
# permitted context and each original stream, with either admitted line length.
known = (
    ("20_0_issuer_unavailable", b"error 20 at 0 depth lookup:unable to get local issuer certificate\n", ("sslclient", "sslserver")),
    ("10_0_expired", b"error 10 at 0 depth lookup:certificate has expired\n", ("sslclient", "sslserver")),
    ("10_1_expired", b"error 10 at 1 depth lookup:certificate has expired\n", ("sslclient", "sslserver")),
    ("9_0_not_yet_valid", b"error 9 at 0 depth lookup:certificate is not yet valid\n", ("sslclient", "sslserver")),
    ("26_0_purpose_unsuitable", b"error 26 at 0 depth lookup:unsuitable certificate purpose\n", ("sslclient",)),
    ("62_0_hostname_mismatch", b"error 62 at 0 depth lookup:hostname mismatch\n", ("sslserver",)),
)
for token, minimum, purposes in known:
    optional = minimum.replace(b"lookup:", b"lookup: ", 1)
    assert len(optional) == len(minimum) + 1
    for purpose in purposes:
        label = m.DIAGNOSTIC_VERIFY_CLIENT if purpose == "sslclient" else m.DIAGNOSTIC_VERIFY_SERVER
        hostname = "" if purpose == "sslclient" else "egs.internal"
        for native in (minimum, optional):
            for stream_position in ("stdout", "stderr"):
                out, err = (native, b"") if stream_position == "stdout" else (b"", native)
                calls = []
                def fixed(argv, input_bytes=None, anchor_bytes=None):
                    calls.append((argv, input_bytes, anchor_bytes))
                    return (2, out, err)
                m.run_fixed = fixed
                context = m.DiagnosticContext()
                try:
                    m.verify_chain(label, {"sha256": "a"}, {"sha256": "b"},
                                   b"synthetic-anchor", b"synthetic-certificate",
                                   purpose, hostname, context)
                except m.Incomplete as exc:
                    assert str(exc) == "unexpected_openssl_grammar"
                else:
                    raise AssertionError("specific diagnostic token widened status grammar")
                assert len(calls) == context.fixed_call_attempts == 1
                assert calls[0][1:] == (b"synthetic-certificate", b"synthetic-anchor")
                first = context.first_rejection
                assert first["predicate"] == "verify_failure_whole_alternative_unadmitted"
                assert first["response_shape"]["verify_token"] == token
                result = dict(schema_version="es-p0t-openssl-grammar-diagnostic/v1",
                              scope="execution-governance", source_sha256=digest,
                              outcome="first_grammar_rejection", fixed_call_attempts=1,
                              first_rejection=first, other_failure=None)
                line = closed_line(result)
                assert native not in line and b"lookup:" not in line
                assert b"synthetic-anchor" not in line and b"synthetic-certificate" not in line
                if purpose == purposes[0] and native == minimum and stream_position == "stderr":
                    reference = result
    target = "stderr"
    def candidate(raw):
        changed = copy.deepcopy(reference)
        changed["first_rejection"]["response_shape"][target] = shape(raw)
        changed["first_rejection"]["response_shape"]["stdout"] = shape(b"")
        return changed
    def refuses(raw, changes=None):
        changed = candidate(raw)
        if changes:
            changed["first_rejection"]["response_shape"][target].update(changes)
        assert m._diagnostic_shape_valid(changed["first_rejection"]["response_shape"][target], m.MAX_ERROR)
        assert m.format_diagnostic_line(changed, digest) is None, (token, raw, changes)
    def admits(raw):
        changed = candidate(raw)
        closed_line(changed)
    # Ordinary shape feasibility alone does not reserve the known ASCII body.
    refuses(b"\n" * len(minimum))
    refuses(b"x" + b"\n" * len(minimum))
    refuses(b"x" * (len(minimum) - 2) + b"\n")
    refuses(b"x" * (len(minimum) + 1) + b"\n")  # One line beyond both exact lengths.
    refuses(minimum, {"has_cr": True})
    refuses(minimum, {"has_nul": True})
    refuses(minimum, {"utf8": False})
    refuses(optional, {"has_cr": True})
    refuses(minimum + b"\x00\n", {"has_cr": True})  # One outside byte cannot carry two flags.
    refuses(minimum + b"\r", {"has_nul": True})  # The tail also needs distinct evidence.
    refuses(minimum + b"\r\x00", {"utf8": False})
    # An extra complete line can be empty or carry distinct nonliteral flags.
    admits(minimum)
    admits(optional)
    admits(minimum + b"\n")
    admits(minimum + b"\r\x00\xff\n")
    admits(minimum + b"x")
    admits(minimum + b"\r\x00\xff")
    admits(b"x" * (len(minimum)-1) + b"\n")  # Feasible counts do not authenticate content.
    changed = candidate(b"\n" * len(minimum))
    changed["first_rejection"]["response_shape"]["verify_token"] = "other"
    closed_line(changed)  # Unknown/other has ordinary shape rules only.
    changed["first_rejection"]["response_shape"]["verify_token"] = "none"
    assert m.format_diagnostic_line(changed, digest) is None
m.run_fixed = original_runner
print("OK")
`)
}

func TestRemoteAlphaP0tGrammarDiagnosticNonpublishingMatrix(t *testing.T) {
	runGrammarPython(t, `
for prior_state, target, bad, expected_outcome in [
    (m._PriorSummaryState.ABSENT, 0, None, "no_grammar_rejection_reached"),
    (m._PriorSummaryState.ABSENT, 18, (2,b"",b"unadmitted"), "first_grammar_rejection"),
    (m._PriorSummaryState.VALID, 0, None, "incomplete_other"),
    (m._PriorSummaryState.INVALID_OR_UNACCEPTED, 0, None, "incomplete_other")]:
    m.ES_TLS_GRAMMAR_DIAGNOSTIC_BOOTSTRAP_VERIFIED = True
    m.ES_TLS_GRAMMAR_DIAGNOSTIC_BOOTSTRAP_INTERRUPTED = [False]
    m.ES_TLS_GRAMMAR_DIAGNOSTIC_SOURCE_SHA256 = digest
    m.ES_TLS_STATUS_BOOTSTRAP_VERIFIED = False
    closed = []
    def forbidden(*args, **kwargs): raise AssertionError("status publisher reached")
    def snapshot(fd, scope):
        assert fd == 10 and scope == "execution-governance"
        return m._PriorSummarySnapshot(prior_state)
    def walk(context):
        context2, calls, failure = traverse(target,bad)
        # Keep the actual caller path and transfer its first rejection/count.
        context.fixed_call_attempts = context2.fixed_call_attempts
        context.last_role = context2.last_role
        context.last_operation = context2.last_operation
        context.first_rejection = context2.first_rejection
        if failure: raise m.Incomplete(failure)
    with mock.patch.object(m, "open_status_dir", return_value=10), \
         mock.patch.object(m, "open_existing_scope_lock", return_value=11), \
         mock.patch.object(m, "validate_process_capability"), \
         mock.patch.object(m, "preexisting_generation", side_effect=snapshot), \
         mock.patch.object(m, "diagnose_first_rejection", side_effect=walk), \
         mock.patch.object(m, "collect", side_effect=forbidden), \
         mock.patch.object(m, "publish", side_effect=forbidden), \
         mock.patch.object(m, "encode_document", side_effect=forbidden), \
         mock.patch.object(m, "open_scope_lock", side_effect=forbidden), \
         mock.patch.object(m.signal, "signal"), \
         mock.patch.object(m.os, "close", side_effect=lambda fd: closed.append(fd)):
        result = m.diagnostic_main()
    assert result and result["outcome"] == expected_outcome, (prior_state,target,result,expected_outcome)
    assert closed == [11,10], closed
    if prior_state is not m._PriorSummaryState.ABSENT:
        assert result["fixed_call_attempts"] == 0
        assert result["other_failure"] == "canonical_not_absent"
    closed_line(result)
# Typed absence/dependency skips cannot become a grammar rejection.
def missing(path,limit,read_content=True):
    raise m._VerifiedFinalLeafAbsent()
typed,calls,failure=traverse(reader=missing)
assert failure is None and typed.first_rejection is None and not calls
# A lock close fault suppresses even an otherwise completed measurement, while
# the independently owned status descriptor still receives its close attempt.
m.ES_TLS_GRAMMAR_DIAGNOSTIC_BOOTSTRAP_VERIFIED=True
m.ES_TLS_GRAMMAR_DIAGNOSTIC_BOOTSTRAP_INTERRUPTED=[False]
m.ES_TLS_GRAMMAR_DIAGNOSTIC_SOURCE_SHA256=digest
m.ES_TLS_STATUS_BOOTSTRAP_VERIFIED=False
closed=[]
def faulty_close(fd):
    closed.append(fd)
    if fd==11:raise OSError("synthetic close fault")
with mock.patch.object(m,"open_status_dir",return_value=10), \
     mock.patch.object(m,"open_existing_scope_lock",return_value=11), \
     mock.patch.object(m,"validate_process_capability"), \
     mock.patch.object(m,"preexisting_generation",return_value=m._PriorSummarySnapshot(m._PriorSummaryState.ABSENT)), \
     mock.patch.object(m,"diagnose_first_rejection",side_effect=lambda ctx: None), \
     mock.patch.object(m.signal,"signal"), \
     mock.patch.object(m.os,"close",side_effect=faulty_close):
    suppressed=m.diagnostic_main()
assert suppressed is None and closed==[11,10] and m.WITNESS_DISPOSITION_UNPROVED
# A simultaneous signal cannot turn a first rejection into a completed result.
closed=[]
def rejected_with_signal(context):
    observed,_,failure=traverse(1,(0,b"bad",b""))
    context.fixed_call_attempts=observed.fixed_call_attempts
    context.first_rejection=observed.first_rejection
    m.LATCHED_SIGNAL=m.signal.SIGINT
    raise m.Incomplete(failure)
with mock.patch.object(m,"open_status_dir",return_value=10), \
     mock.patch.object(m,"open_existing_scope_lock",return_value=11), \
     mock.patch.object(m,"validate_process_capability"), \
     mock.patch.object(m,"preexisting_generation",return_value=m._PriorSummarySnapshot(m._PriorSummaryState.ABSENT)), \
     mock.patch.object(m,"diagnose_first_rejection",side_effect=rejected_with_signal), \
     mock.patch.object(m.signal,"signal"), \
     mock.patch.object(m.os,"close",side_effect=lambda fd:closed.append(fd)):
    interrupted=m.diagnostic_main()
assert interrupted["outcome"]=="incomplete_other" and interrupted["other_failure"]=="interrupted"
assert interrupted["first_rejection"] is None and closed==[11,10]
closed_line(interrupted)
print("OK")
`)
}

func TestRemoteAlphaP0tGrammarDiagnosticOutputPrivacy(t *testing.T) {
	runGrammarPython(t, `
for secret in (b"subject-secret", b"provider-secret", b"-----BEGIN PRIVATE KEY-----",
               b"\x00\xff DER secret", b"exception-secret"):
    context, _, failure = traverse(1,(0,secret,b""))
    assert failure == "unexpected_openssl_grammar"
    result = dict(schema_version="es-p0t-openssl-grammar-diagnostic/v1",
                  scope="execution-governance",source_sha256=digest,
                  outcome="first_grammar_rejection",fixed_call_attempts=1,
                  first_rejection=context.first_rejection,other_failure=None)
    line = closed_line(result)
    assert secret not in line and b"PRIVATE KEY" not in line
    assert b"subject-secret" not in line and b"provider-secret" not in line
first,_,_ = traverse(1,(0,b"alpha",b""))
second,_,_ = traverse(1,(0,b"omega",b""))
assert first.first_rejection == second.first_rejection
base = dict(schema_version="es-p0t-openssl-grammar-diagnostic/v1",
            scope="execution-governance",source_sha256=digest,
            outcome="first_grammar_rejection",fixed_call_attempts=1,
            first_rejection=first.first_rejection,other_failure=None)
for mutation in (
    lambda x: x.update(extra="smuggle"),
    lambda x: x.update(source_sha256="b"*64),
    lambda x: x.update(fixed_call_attempts=2),
    lambda x: x["first_rejection"].update(call_ordinal=2),
    lambda x: x["first_rejection"].update(predicate="not-closed"),
    lambda x: x["first_rejection"]["response_shape"].update(verify_token="20_0_issuer_unavailable"),
    lambda x: x["first_rejection"]["response_shape"]["stdout"].update(bytes=-1),
    lambda x: x["first_rejection"]["response_shape"]["stdout"].update(secret="hidden"),
    lambda x: x["first_rejection"]["response_shape"].update(exit_class="one"),
    lambda x: x["first_rejection"]["response_shape"].update(
        stderr=m._diagnostic_stream_shape(b"provider",m.MAX_ERROR)),
    lambda x: x["first_rejection"]["response_shape"]["stdout"].update(
        bytes=1,lines=1,empty=False,utf8=True,final_lf=True,has_cr=True,has_nul=False),
):
    changed=copy.deepcopy(base);mutation(changed)
    assert m.format_diagnostic_line(changed,digest) is None, changed
no_rejection=copy.deepcopy(base)
no_rejection.update(outcome="no_grammar_rejection_reached",first_rejection=None,fixed_call_attempts=18)
assert b"no_grammar_rejection_reached" in closed_line(no_rejection)
no_rejection["other_failure"]="other_unproved"
assert m.format_diagnostic_line(no_rejection,digest) is None
print("OK")
`)
}

func TestRemoteAlphaP0tGrammarDiagnosticCustodyAndEffects(t *testing.T) {
	runGrammarPython(t, `
from types import SimpleNamespace
def info(kind=stat.S_IFREG, uid=0, gid=0, mode=0o600, nlink=1, size=0, ino=7):
    return SimpleNamespace(st_mode=kind|mode,st_uid=uid,st_gid=gid,st_nlink=nlink,
                           st_size=size,st_dev=3,st_ino=ino,st_mtime_ns=1,st_ctime_ns=2)
for entry, should_open in [
    (info(),True),(info(kind=stat.S_IFIFO),False),(info(uid=1),False),
    (info(gid=1),False),(info(mode=0o644),False),(info(nlink=2),False),
    (info(size=1),False)]:
    opened=[];closed=[];flocks=[]
    with mock.patch.object(m.os,"stat",return_value=entry), \
         mock.patch.object(m.os,"open",side_effect=lambda *a,**k: opened.append((a,k)) or 22), \
         mock.patch.object(m.os,"close",side_effect=lambda fd: closed.append(fd)), \
         mock.patch.object(m,"check_protected_file",return_value=entry), \
         mock.patch.object(m.fcntl,"flock",side_effect=lambda *a: flocks.append(a)):
        try: fd=m.open_existing_scope_lock(21)
        except m.Incomplete: assert not should_open
        else: assert should_open and fd==22
    assert len(opened)==int(should_open) and len(flocks)==int(should_open)
    assert closed==[]
    if should_open:
        flags=opened[0][0][1]
        assert flags & os.O_RDWR and flags & os.O_NOFOLLOW
        assert flags & os.O_CLOEXEC and flags & os.O_NONBLOCK
        assert not flags & os.O_CREAT and not flags & os.O_TRUNC
opened=[]
with mock.patch.object(m.os,"stat",side_effect=FileNotFoundError()), \
     mock.patch.object(m.os,"open",side_effect=lambda *a,**k: opened.append(a)):
    try:m.open_existing_scope_lock(21)
    except m.Incomplete:pass
    else:raise AssertionError("missing lock accepted")
assert not opened
# Type substitution after the initial stat must be refused after one close.
closed=[]
with mock.patch.object(m.os,"stat",side_effect=[info(),info(kind=stat.S_IFIFO)]), \
     mock.patch.object(m.os,"open",return_value=22), \
     mock.patch.object(m.os,"close",side_effect=lambda fd:closed.append(fd)), \
     mock.patch.object(m,"check_protected_file",return_value=info()):
    try:m.open_existing_scope_lock(21)
    except m.Incomplete:pass
    else:raise AssertionError("regular-to-FIFO substitution accepted")
assert closed==[22]
# A substituted regular entry after open, a FIFO after initial stat, and
# every post-open failure consume exactly one descriptor close attempt.
for phase in ("opened_metadata","same_leaf_before","flock","opened_after","same_leaf_after"):
    calls=[];same=[0];checked=[0]
    def checked_file(fd, mode):
        checked[0]+=1
        if phase=="opened_metadata" or (phase=="opened_after" and checked[0]==2):
            raise m.Incomplete("synthetic")
        return info()
    def same_leaf(parent,name,entry):
        same[0]+=1
        if phase=="same_leaf_before" or (phase=="same_leaf_after" and same[0]==2):
            raise m.Incomplete("synthetic")
    def flock(*a):
        if phase=="flock": raise OSError("synthetic")
    with mock.patch.object(m.os,"stat",return_value=info()), \
         mock.patch.object(m.os,"open",return_value=22), \
         mock.patch.object(m.os,"close",side_effect=lambda fd: calls.append(fd)), \
         mock.patch.object(m,"check_protected_file",side_effect=checked_file), \
         mock.patch.object(m,"same_leaf",side_effect=same_leaf), \
         mock.patch.object(m.fcntl,"flock",side_effect=flock):
        try:m.open_existing_scope_lock(21)
        except (m.Incomplete,OSError): pass
        else: raise AssertionError(phase)
    assert calls==[22], (phase,calls)
with mock.patch.object(m.os,"fstat",return_value=info()), \
     mock.patch.object(m.os,"listxattr",return_value=["user.unexpected"],create=True):
    try:m.check_protected_file(22,0o600)
    except m.Incomplete:pass
    else:raise AssertionError("xattr admitted")
# A post-open proof failure followed by a close fault receives one attempt
# and makes disposition uncertainty sticky. There is no descriptor rescue.
m.WITNESS_DISPOSITION_UNPROVED=False
closed=[]
with mock.patch.object(m.os,"stat",return_value=info()), \
     mock.patch.object(m.os,"open",return_value=22), \
     mock.patch.object(m,"check_protected_file",side_effect=m.Incomplete("synthetic")), \
     mock.patch.object(m.os,"close",side_effect=lambda fd: (closed.append(fd), (_ for _ in ()).throw(OSError("close fault")))):
    try:m.open_existing_scope_lock(21)
    except m.Incomplete:pass
    else:raise AssertionError("post-open failure accepted")
assert closed==[22] and m.WITNESS_DISPOSITION_UNPROVED
print("OK")
`)
	h := setupFakeRemoteAlphaESTLSStatusHarness(t)
	output, err := runRemoteAlphaOperatorWithPTY(t, h.env(),
		"recovery-session", "es-governance-tls-grammar-diagnostic",
		"--ssh-target", "ds@m75q-test", "--interactive-tty")
	if err != nil {
		t.Fatalf("fake diagnostic transport failed: %v\n%s", err, output)
	}
	assertContainsAll(t, "fake diagnostic transport", output,
		"staging one fixed diagnostic source", "diagnostic invocation acknowledged")
	if scp := strings.TrimSpace(mustRead(t, h.scpLog)); strings.Count(scp, "\n") != 0 ||
		!strings.Contains(scp, "scripts/internal/remote_alpha_es_tls_status.py") {
		t.Fatalf("diagnostic changed one-source staging budget: %q", scp)
	}
	raw := mustRead(t, h.sshArgv)
	fields := strings.Split(raw, "\x00")
	if len(fields) != 4 || fields[0] != "-tt" || fields[1] != "ds@m75q-test" {
		t.Fatalf("diagnostic SSH argv changed: %q", raw)
	}
	parser := exec.Command("/usr/bin/python3", "-I", "-B", "-c",
		"import json,shlex,sys;print(json.dumps(shlex.split(sys.stdin.read())))")
	parser.Stdin = strings.NewReader(fields[2])
	decoded, err := parser.Output()
	if err != nil {
		t.Fatalf("parse diagnostic command: %v", err)
	}
	var tokens []string
	if err := json.Unmarshal(decoded, &tokens); err != nil {
		t.Fatal(err)
	}
	if len(tokens) != 9 || tokens[0] != "/bin/bash" || tokens[1] != "-c" ||
		tokens[3] != "--" || tokens[6] != "execution-governance" ||
		tokens[8] != "grammar-diagnostic" || len(fields[2]) > 32768 {
		t.Fatalf("diagnostic command boundary changed: %#v", tokens)
	}
	source, err := os.ReadFile(filepath.Join(executionSubstrateRepoRoot,
		"scripts", "internal", "remote_alpha_es_tls_status.py"))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(source)
	if tokens[7] != hex.EncodeToString(sum[:]) {
		t.Fatal("remote command digest does not bind the staged source")
	}
}

func TestRemoteAlphaP0tGrammarDiagnosticOwnershipComposition(t *testing.T) {
	runGrammarPython(t, `
# Exercise the actual owner/termination loop with a controlled process model:
# terminal leader remains reserved while one descendant is live.
from types import SimpleNamespace
proc=SimpleNamespace(pid=4242,_status_terminal=True,_status_reaped=False,returncode=None)
alive=[True];reaped=[];signals=[]
def members(pgid):
    assert pgid==4242
    return [(4242,1)]+([(4243,2)] if alive[0] else [])
def signal_group(pgid,signum):
    signals.append(signum)
    alive[0]=False
def reap(p):
    assert not alive[0]
    p._status_reaped=True;reaped.append(True);return 0
with mock.patch.object(m,"leader_terminal",return_value=True), \
     mock.patch.object(m,"scan_group_members",side_effect=members), \
     mock.patch.object(m,"signal_same_group_members",side_effect=signal_group), \
     mock.patch.object(m,"reap_child",side_effect=reap), \
     mock.patch.object(m,"prove_group_absent",return_value=False), \
     mock.patch.object(m.os,"killpg",side_effect=PermissionError("modeled")):
    uncertain=m.own_child_until_proved(proc)
assert uncertain and reaped==[True] and not alive[0] and signals
# A close fault in a member signal is sticky even after a later successful
# recovery. The original owner function, not a recorder, handles the retry.
proc=SimpleNamespace(pid=4242,_status_terminal=True,_status_reaped=False,returncode=None)
alive[0]=True;reaped=[];attempt=[0]
def transient_member(pgid,signum):
    attempt[0]+=1
    if attempt[0]==1: raise m.Incomplete("member close fault")
    alive[0]=False
with mock.patch.object(m,"leader_terminal",return_value=True), \
     mock.patch.object(m,"scan_group_members",side_effect=members), \
     mock.patch.object(m,"signal_same_group_members",side_effect=transient_member), \
     mock.patch.object(m,"reap_child",side_effect=reap), \
     mock.patch.object(m,"prove_group_absent",return_value=False), \
     mock.patch.object(m.os,"killpg",side_effect=PermissionError("modeled")):
    uncertain=m.own_child_until_proved(proc)
assert uncertain and reaped==[True] and attempt[0]>=2
# The actual member-signaling routine treats a per-member pidfd close failure
# as sticky uncertainty while preserving the single close attempt.
m.WITNESS_DISPOSITION_UNPROVED=False
closed=[];sent=[]
def close_member(fd):
    closed.append(fd)
    if fd==52:raise OSError("synthetic pidfd close fault")
with mock.patch.object(m,"scan_group_members",return_value=[(51,1),(52,2)]), \
     mock.patch.object(m,"read_proc_identity",side_effect=lambda pid:(4242,1 if pid==51 else 2)), \
     mock.patch.object(m.os,"pidfd_open",side_effect=lambda pid,flags:pid,create=True), \
     mock.patch.object(m.signal,"pidfd_send_signal",side_effect=lambda fd,signum,info,flags:sent.append(fd),create=True), \
     mock.patch.object(m.os,"close",side_effect=close_member):
    try:m.signal_same_group_members(4242,m.signal.SIGTERM)
    except m.Incomplete:pass
    else:raise AssertionError("member close fault accepted")
assert closed==[51,52] and sent==[51,52] and m.WITNESS_DISPOSITION_UNPROVED
print("OK")
`)
}

func TestRemoteAlphaP0tGrammarDiagnosticBootstrapLifecycleComposition(t *testing.T) {
	source := filepath.Join(executionSubstrateRepoRoot, "scripts", "internal", "remote_alpha_es_tls_status.py")
	facade := remoteAlphaOperatorScriptPath()
	cmd := exec.Command("/usr/bin/python3", "-I", "-B", "-c", grammarBootstrapCompositionFixture, source, facade)
	cmd.Dir = executionSubstrateRepoRoot
	cmd.Env = append(os.Environ(), "PYTHONDONTWRITEBYTECODE=1")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("contained bootstrap composition failed: %v\n%s", err, output)
	}
	if strings.TrimSpace(string(output)) != "OK" {
		t.Fatalf("contained bootstrap composition did not complete: %q", output)
	}
}

// The exact embedded bootstrap reads the exact current candidate payload from
// one owned stage. Only caller/root metadata, protected-input observations,
// native process primitives and output-only terminal primitives are synthetic.
const grammarBootstrapCompositionFixture = `
import atexit
from contextlib import ExitStack
import hashlib
import os
import pwd
import secrets
import signal
import stat
import subprocess
import sys
from types import SimpleNamespace
from unittest import mock

source = open(sys.argv[1], "rb").read()
facade = open(sys.argv[2], "r", encoding="utf-8").read()
start = "IFS= read -r -d '' bootstrap <<'REMOTE_ALPHA_ES_TLS_STATUS_BOOTSTRAP' || true\n"
end = "\nREMOTE_ALPHA_ES_TLS_STATUS_BOOTSTRAP\n"
assert facade.count(start) == facade.count(end) == 1
bootstrap = facade.split(start, 1)[1].split(end, 1)[0]
filename = "<exact-test-bootstrap>"
entry_line = bootstrap[:bootstrap.index('        entry = namespace.get("diagnostic_main")')].count("\n") + 1
operator = pwd.getpwnam("ds")
assert operator.pw_uid != 0
cert = b"-----BEGIN CERTIFICATE-----\nQUJD\n-----END CERTIFICATE-----\n"
key = b"synthetic-key"
pem = b"-----BEGIN PUBLIC KEY-----\nQUJD\n-----END PUBLIC KEY-----\n"
der = b"\x30\x3e" + b"\x00" * 62
metadata = (b"subject=CN=synthetic\nissuer=CN=synthetic\n"
            b"notBefore=Nov  1 00:00:00 2026 GMT\n"
            b"notAfter=Nov  1 00:00:00 2027 GMT\n"
            b"sha256 Fingerprint=" + b":".join([b"AA"] * 32) + b"\n")
text = (b"Certificate:\n    Data:\n"
        b"    Signature Algorithm: sha256WithRSAEncryption\n"
        b"    Signature Value:\n        aa\n")

def response(argv):
    if "verify" in argv: return (0, b"/dev/stdin: OK\n", b"")
    if "-text" in argv: return (0, text, b"")
    if "-pubkey" in argv: return (0, pem, b"")
    if "-pubin" in argv or "-pubout" in argv: return (0, der, b"")
    return (0, metadata, b"")

def run_case(mode):
    token = secrets.token_hex(16)
    stage_name = ".es-tls-status-" + token
    physical_stage = "/private/tmp/" + stage_name
    declared_stage = "/tmp/" + stage_name
    os.mkdir(physical_stage, 0o700)
    staged_leaf = physical_stage + "/remote_alpha_es_tls_status.py"
    staged = source + (b"# substituted\n" if mode == "source_substitution" else b"")
    with open(staged_leaf, "xb") as stream:
        stream.write(staged)
    os.chmod(staged_leaf, 0o600)
    identity = os.stat(physical_stage)
    digest = hashlib.sha256(source).hexdigest()
    events = {"writes": [], "terminal_closes": [], "status_closes": [], "canonical_closes": [], "atexit": [],
              "native": 0, "holds": 0, "loaded": False, "published": False}
    processes = {}
    stage_fd = [None]
    file_fd = [None]
    parent_fd = [None]
    chowned = [False]
    leaf_stats = [0]
    fail_pidfd_close = [mode == "recovered_fault"]
    original_open, original_stat, original_read = os.open, os.stat, os.read
    original_fstat, original_close = os.fstat, os.close
    original_write, original_isatty = os.write, os.isatty
    original_waitpid = os.waitpid
    original_argv, original_hook = sys.argv, sys.excepthook

    def metadata_view(info, **changes):
        keys = ("st_mode", "st_uid", "st_gid", "st_dev", "st_ino", "st_nlink",
                "st_size", "st_mtime_ns", "st_ctime_ns")
        values = {field: getattr(info, field) for field in keys}
        values.update(changes)
        return SimpleNamespace(**values)

    def opened(path, *args, **kwargs):
        if path == "es-governance-tls-status-summary.json" and kwargs.get("dir_fd") == 700000:
            assert mode == "prior_reader_close_fault"
            return 700003
        if path == "/tmp":
            fd = original_open("/private/tmp", *args, **kwargs)
            parent_fd[0] = fd
            return fd
        if path == "/dev/tty":
            if mode == "terminal_unavailable": raise OSError("modeled terminal unavailable")
            return 700002
        fd = original_open(path, *args, **kwargs)
        if path == stage_name and kwargs.get("dir_fd") == parent_fd[0]: stage_fd[0] = fd
        if path == "remote_alpha_es_tls_status.py" and kwargs.get("dir_fd") == stage_fd[0]:
            file_fd[0] = fd
        return fd

    def stated(path, *args, **kwargs):
        if path == "es-governance-tls-status-summary.json" and kwargs.get("dir_fd") == 700000:
            assert mode == "prior_reader_close_fault"
            return metadata_view(identity, st_dev=987, st_ino=988,
                                 st_mode=stat.S_IFREG | 0o644, st_uid=0, st_gid=0,
                                 st_nlink=1, st_size=3, st_mtime_ns=101, st_ctime_ns=102)
        info = original_stat(path, *args, **kwargs)
        if path == stage_name and kwargs.get("dir_fd") == parent_fd[0]:
            return metadata_view(info, st_uid=0 if chowned[0] else operator.pw_uid,
                                 st_gid=0 if chowned[0] else operator.pw_gid)
        if path == "remote_alpha_es_tls_status.py" and kwargs.get("dir_fd") == stage_fd[0]:
            leaf_stats[0] += 1
            if mode == "same_stage_substitution" and leaf_stats[0] == 2:
                return metadata_view(info, st_ino=info.st_ino + 1, st_gid=operator.pw_gid)
            return metadata_view(info, st_gid=operator.pw_gid)
        return info

    def fstated(fd):
        if fd == 700003:
            assert mode == "prior_reader_close_fault"
            return metadata_view(identity, st_dev=987, st_ino=988,
                                 st_mode=stat.S_IFREG | 0o644, st_uid=0, st_gid=0,
                                 st_nlink=1, st_size=3, st_mtime_ns=101, st_ctime_ns=102)
        info = original_fstat(fd)
        if fd == stage_fd[0]:
            return metadata_view(info, st_uid=0 if chowned[0] else operator.pw_uid,
                                 st_gid=0 if chowned[0] else operator.pw_gid)
        if fd == file_fd[0]: return metadata_view(info, st_gid=operator.pw_gid)
        return info

    def closed(fd):
        if fd == 700003:
            events["canonical_closes"].append(fd)
            raise OSError("modeled canonical close failure")
        if fd in (700000, 700001):
            events["status_closes"].append(fd)
            if fd == 700001 and mode == "lock_close_fault": raise OSError("modeled lock close")
            return
        if fd == 700002:
            events["terminal_closes"].append(fd)
            return
        if fd >= 800000:
            if fail_pidfd_close[0]:
                fail_pidfd_close[0] = False
                raise OSError("modeled pidfd close fault")
            return
        return original_close(fd)

    def read(fd, size):
        if fd == 700003:
            assert mode == "prior_reader_close_fault" and size > 0
            events.setdefault("canonical_reads", 0)
            events["canonical_reads"] += 1
            return b"{}\n" if events["canonical_reads"] == 1 else b""
        return original_read(fd, size)

    def written(fd, payload):
        if fd == 700002:
            events["writes"].append(bytes(payload))
            return 1 if mode == "terminal_short" else len(payload)
        return original_write(fd, payload)

    def members(pgid):
        proc = processes[pgid]
        if proc._status_reaped: return []
        if proc.descendant_live:
            assert events["status_closes"] == [] and events["writes"] == []
            events["holds"] += 1
        return [(pgid, 1)] + ([(pgid + 1, 2)] if proc.descendant_live else [])

    def killed_group(pgid, signum):
        proc = processes[pgid]
        assert events["status_closes"] == [] and events["writes"] == []
        if mode == "recovered_fault": raise PermissionError("modeled group signal denial")
        if signum == signal.SIGKILL or mode != "hold": proc.descendant_live = False

    def pidfd_signal(fd, signum, _info, _flags):
        for proc in processes.values():
            if fd in (800000 + proc.pid, 800000 + proc.pid + 1):
                if fd == 800000 + proc.pid + 1: proc.descendant_live = False
                return
        raise AssertionError("foreign pidfd")

    def waited(pid, flags):
        assert flags == os.WNOHANG
        proc = processes[pid]
        assert not proc.descendant_live
        original_close(proc.stdin_read_fd)
        proc.stdin_read_fd = -1
        return pid, proc.expected_code << 8

    class FakePopen:
        def __init__(self, argv, **kwargs):
            assert argv[0] == "/usr/bin/openssl" and kwargs["shell"] is False
            events["native"] += 1
            if mode == "non_grammar_incomplete" and events["native"] == 1:
                raise OSError("modeled spawn failure")
            self.pid = 4000 + events["native"]
            self.returncode = None
            self._status_reaped = False
            self._status_terminal = False
            self.descendant_live = True
            self.expected_code, out, err = response(argv)
            if mode in ("first_rejection", "hold") and events["native"] == 1:
                self.expected_code, out, err = 0, b"bad", b""
            stdin_read, stdin_write = os.pipe()
            self.stdin_read_fd = stdin_read
            self.stdin = os.fdopen(stdin_write, "wb", buffering=0)
            out_read, out_write = os.pipe()
            err_read, err_write = os.pipe()
            self.stdout = os.fdopen(out_read, "rb", buffering=0)
            self.stderr = os.fdopen(err_read, "rb", buffering=0)
            original_write(out_write, out)
            original_write(err_write, err)
            original_close(out_write)
            original_close(err_write)
            processes[self.pid] = self

    def install(namespace):
        events["loaded"] = True
        assert namespace["__name__"] == "_es_tls_grammar_diagnostic"
        assert namespace["ES_TLS_GRAMMAR_DIAGNOSTIC_SOURCE_SHA256"] == digest
        assert namespace["ES_TLS_GRAMMAR_DIAGNOSTIC_BOOTSTRAP_VERIFIED"] is True
        assert "diagnostic_main" in namespace and "format_diagnostic_line" in namespace
        def forbidden(*_args, **_kwargs):
            events["published"] = True
            raise AssertionError("status publication or generation reached")
        for name in ("main", "collect", "publish", "encode_document", "open_scope_lock"):
            namespace[name] = forbidden
        namespace["secrets"] = SimpleNamespace(token_hex=forbidden)
        namespace["open_status_dir"] = lambda: 700000
        namespace["open_existing_scope_lock"] = lambda fd: 700001 if fd == 700000 else forbidden()
        if mode != "prior_reader_close_fault":
            namespace["read_protected_summary_leaf"] = lambda fd, name: None
        namespace["open_fixed_regular"] = lambda path, limit, read_content=True: (
            key if path.endswith("-key.pem") else cert if path.endswith(".pem") else b"{}")
        backend = SimpleNamespace(
            wnowait=1, p_pid=1, wexited=1, wnohang=os.WNOHANG,
            pidfd_open=lambda pid, flags: 810000,
            pidfd_send_signal=lambda *args: None,
            terminal=lambda pid: True,
            pipe=lambda: (810001, 810002), fork=lambda: 3999,
            close=lambda fd: None, read=lambda fd, size: b"x",
            write=lambda fd, data: len(data), waitpid=lambda pid, flags: (pid, 0),
            kill=lambda *args: None, read_identity=lambda pid: (pid, 1),
            scan_members=lambda pgid: [(3999, 1)])
        actual_capability = namespace["validate_process_capability"]
        namespace["validate_process_capability"] = lambda: actual_capability(backend)
        namespace["waitid_terminal"] = lambda pid: True
        namespace["scan_group_members"] = members
        namespace["read_proc_identity"] = lambda pid: (pid if pid in processes else pid-1, 1 if pid in processes else 2)

    def trace(frame, event, _arg):
        if frame.f_code.co_filename != filename: return None
        if event == "line" and frame.f_lineno == entry_line:
            install(frame.f_globals["namespace"])
        return trace

    try:
        with ExitStack() as stack:
            patches = (
                mock.patch.dict(os.environ, SUDO_USER="ds", SUDO_UID=str(operator.pw_uid),
                                SUDO_GID=str(operator.pw_gid)),
                mock.patch.object(os, "geteuid", return_value=0),
                mock.patch.object(os, "open", side_effect=opened),
                mock.patch.object(os, "stat", side_effect=stated),
                mock.patch.object(os, "fstat", side_effect=fstated),
                mock.patch.object(os, "fchown", side_effect=lambda fd,uid,gid: chowned.__setitem__(0, True)),
                mock.patch.object(os, "listxattr", return_value=[], create=True),
                mock.patch.object(os, "close", side_effect=closed),
                mock.patch.object(os, "read", side_effect=read),
                mock.patch.object(os, "write", side_effect=written),
                mock.patch.object(os, "isatty", side_effect=lambda fd: fd == 700002 or original_isatty(fd)),
                mock.patch.object(os, "killpg", side_effect=killed_group),
                mock.patch.object(os, "waitpid", side_effect=waited),
                mock.patch.object(os, "pidfd_open", side_effect=lambda pid,flags: 800000+pid, create=True),
                mock.patch.object(signal, "pidfd_send_signal", side_effect=pidfd_signal, create=True),
                mock.patch.object(signal, "signal", side_effect=lambda *args: None),
                mock.patch.object(subprocess, "Popen", FakePopen),
                mock.patch.object(atexit, "register", side_effect=lambda fn: events["atexit"].append(fn)),
                mock.patch.object(os, "replace", side_effect=AssertionError("status replacement")),
                mock.patch.object(os, "_exit", side_effect=AssertionError("status exit")))
            for patch in patches: stack.enter_context(patch)
            sys.argv = [filename, declared_stage, "remote_alpha_es_tls_status.py", digest,
                        "execution-governance", str(identity.st_dev), str(identity.st_ino),
                        "grammar-diagnostic"]
            sys.settrace(trace)
            try:
                exec(compile(bootstrap, filename, "exec"), {})
            except SystemExit as stopped:
                exit_code = stopped.code
            else:
                raise AssertionError("bootstrap unexpectedly returned")
            finally:
                sys.settrace(None)
        return exit_code, events
    finally:
        sys.argv, sys.excepthook = original_argv, original_hook
        if os.path.exists(staged_leaf): os.unlink(staged_leaf)
        if os.path.exists(physical_stage): os.rmdir(physical_stage)

for mode, expected_exit, marker, attempts in (
        ("all_success", 0, b"no_grammar_rejection_reached", 18),
        ("first_rejection", 0, b"first_grammar_rejection", 1),
        ("hold", 0, b"first_grammar_rejection", 1),
        ("non_grammar_incomplete", 1, b"incomplete_other", 1),
        ("recovered_fault", 1, None, 1),
        ("lock_close_fault", 1, None, 18),
        ("prior_reader_close_fault", 1, None, 0),
        ("terminal_unavailable", 0, None, 18),
        ("terminal_short", 0, b"no_grammar_rejection_reached", 18),
        ("source_substitution", 1, None, 0),
        ("same_stage_substitution", 1, None, 0)):
    if sys.argv[3:] and mode not in sys.argv[3:]: continue
    code, events = run_case(mode)
    assert code == expected_exit, (mode, code, events)
    assert events["native"] == attempts, (mode, events)
    assert not events["atexit"] and not events["published"], (mode, events)
    assert events["loaded"] is (mode not in ("source_substitution", "same_stage_substitution"))
    assert len(events["writes"]) <= 1 and len(events["terminal_closes"]) <= 1
    assert events["status_closes"] == ([700001, 700000] if events["loaded"] else [])
    assert events["canonical_closes"] == ([700003] if mode == "prior_reader_close_fault" else [])
    if marker is None:
        assert events["writes"] == [], (mode, events)
    else:
        assert len(events["writes"]) == 1 and marker in events["writes"][0], (mode, events)
        assert events["writes"][0].startswith(b"ES_TLS_GRAMMAR_DIAGNOSTIC_V1 ")
        assert b"ES_TLS_STATUS_FAILURE_V1" not in events["writes"][0]
    if mode == "hold": assert events["holds"] > 0
print("OK")
`

func TestRemoteAlphaP0tGrammarDiagnosticVerifySuccessPredicateShape(t *testing.T) {
	runGrammarPython(t, `
for purpose, role, hostname in (
        ("sslclient", m.DIAGNOSTIC_VERIFY_CLIENT, ""),
        ("sslserver", m.DIAGNOSTIC_VERIFY_SERVER, "synthetic.example")):
    for warning in (b"synthetic warning", b"\n", b"\xff\r\x00\n"):
        calls = []
        def fixed(argv, input_bytes, anchor_bytes=None):
            calls.append((argv, input_bytes, anchor_bytes))
            return (0, b"/dev/stdin: OK\n", warning)
        m.run_fixed = fixed
        context = m.DiagnosticContext()
        try:
            m.verify_chain(role, {"sha256": "a"}, {"sha256": "b"},
                           b"synthetic anchor", b"synthetic certificate",
                           purpose, hostname, context)
        except m.Incomplete as exc:
            assert exc.args == ("unexpected_openssl_grammar",)
        else:
            raise AssertionError("stderr-bearing verify success was accepted")
        assert len(calls) == context.fixed_call_attempts == 1
        assert calls[0][1:] == (b"synthetic certificate", b"synthetic anchor")
        first = context.first_rejection
        assert first["role"] == role and first["operation"] == ("verify_client" if purpose == "sslclient" else "verify_server")
        assert first["site"] == "VERIFY_SUCCESS_ENVELOPE_UNADMITTED"
        assert first["predicate"] == "verify_success_stderr_nonempty"
        assert first["response_shape"]["stdout"] == {
            "bytes": 15, "lines": 1, "empty": False, "utf8": True,
            "final_lf": True, "has_cr": False, "has_nul": False}
        record = dict(schema_version="es-p0t-openssl-grammar-diagnostic/v1",
                      scope="execution-governance", source_sha256=digest,
                      outcome="first_grammar_rejection", fixed_call_attempts=1,
                      first_rejection=first, other_failure=None)
        closed_line(record)
        for field, altered in (("bytes", 14), ("bytes", 16), ("lines", 0),
                               ("lines", 2), ("empty", True), ("utf8", False),
                               ("final_lf", False), ("has_cr", True), ("has_nul", True)):
            forged = copy.deepcopy(record)
            forged["first_rejection"]["response_shape"]["stdout"][field] = altered
            assert m.format_diagnostic_line(forged, digest) is None, (purpose, warning, field, altered)
        forged = copy.deepcopy(record)
        forged["first_rejection"]["response_shape"]["stdout"].update(
            utf8=False, has_cr=True, has_nul=True)
        assert m.format_diagnostic_line(forged, digest) is None
        for change in (lambda x: x["first_rejection"]["response_shape"].update(exit_class="one"),
                       lambda x: x["first_rejection"]["response_shape"].update(verify_token="other"),
                       lambda x: x["first_rejection"]["response_shape"].update(
                           stderr=m._diagnostic_stream_shape(b"", m.MAX_ERROR))):
            forged = copy.deepcopy(record)
            change(forged)
            assert m.format_diagnostic_line(forged, digest) is None
        # Equal shape cannot authenticate equal native bytes. Keep this other
        # predicate's same-shape, different-stdout observation admissible.
        calls.clear()
        m.run_fixed = lambda argv, stdin, anchor=None: (calls.append(argv) or
                                                      (0, b"/dev/stdin: NO\n", b""))
        other = m.DiagnosticContext()
        try:
            m.verify_chain(role, {"sha256": "a"}, {"sha256": "b"},
                           b"synthetic anchor", b"synthetic certificate",
                           purpose, hostname, other)
        except m.Incomplete as exc:
            assert exc.args == ("unexpected_openssl_grammar",)
        else:
            raise AssertionError("same-shape different stdout was accepted")
        assert len(calls) == other.fixed_call_attempts == 1
        assert other.first_rejection["predicate"] == "verify_success_stdout_not_exact"
        assert other.first_rejection["response_shape"]["stdout"] == first["response_shape"]["stdout"]
        alternate = copy.deepcopy(record)
        alternate["first_rejection"] = other.first_rejection
        closed_line(alternate)
        # Both-empty stdout/stderr is still rejected by the original parser.
        m.run_fixed = lambda *args: (0, b"", b"")
        empty = m.DiagnosticContext()
        try:
            m.verify_chain(role, {"sha256": "a"}, {"sha256": "b"},
                           b"synthetic anchor", b"synthetic certificate",
                           purpose, hostname, empty)
        except m.Incomplete as exc:
            assert exc.args == ("unexpected_openssl_grammar",)
        else:
            raise AssertionError("both-empty verify tuple was accepted")
        assert empty.fixed_call_attempts == 1
        assert empty.first_rejection["predicate"] == "verify_success_stdout_not_exact"
        empty_record = copy.deepcopy(record)
        empty_record["first_rejection"] = empty.first_rejection
        closed_line(empty_record)
        for outcome, other_failure in (("no_grammar_rejection_reached", None),
                                       ("incomplete_other", "other_unproved")):
            ordinary = copy.deepcopy(record)
            ordinary.update(outcome=outcome, first_rejection=None, other_failure=other_failure)
            closed_line(ordinary)
        class Hostile(str):
            def __eq__(self, other):
                touched.append("equality")
                return True
            def __str__(self):
                touched.append("conversion")
                return "hostile"
        for field in ("schema_version", "scope"):
            touched = []
            hostile = copy.deepcopy(record)
            hostile[field] = Hostile("forged-private-value")
            assert m.format_diagnostic_line(hostile, digest) is None
            assert touched == [], (field, touched)
# Existing recognized literal remains a closed diagnostic, not status acceptance.
issuer = b"error 20 at 0 depth lookup: unable to get local issuer certificate\n"
context, _, failure = traverse(17, (2, b"", issuer))
assert failure == "unexpected_openssl_grammar"
assert context.first_rejection["response_shape"]["verify_token"] == "20_0_issuer_unavailable"
print("OK")
`)
}

func TestRemoteAlphaP0tGrammarDiagnosticPriorReaderCloseSuppression(t *testing.T) {
	runGrammarPython(t, `
from types import SimpleNamespace

native = []
def forbidden(*args, **kwargs):
    native.append((args, kwargs))
    raise AssertionError("collection, publication, or native dispatch reached")

class FakeOS:
    O_RDONLY, O_NONBLOCK = os.O_RDONLY, os.O_NONBLOCK
    def __init__(self, name, raw, close_error=None, read_error=None,
                 stat_error_at=None, lock_error=None, status_error=None):
        self.name, self.raw = name, raw
        self.close_error, self.read_error = close_error, read_error
        self.stat_error_at = stat_error_at
        self.lock_error, self.status_error = lock_error, status_error
        self.closes, self.stats, self.opens, self.reads = [], 0, 0, 0
        self.leaf = SimpleNamespace(st_dev=44, st_ino=55,
            st_mode=stat.S_IFREG | 0o644, st_uid=0, st_gid=0,
            st_nlink=1, st_size=len(raw or b""), st_mtime_ns=101, st_ctime_ns=102)
    def stat(self, name, *, dir_fd=None, follow_symlinks=True):
        assert name == self.name and dir_fd == 10 and follow_symlinks is False
        self.stats += 1
        if self.stat_error_at == self.stats: raise OSError("modeled metadata failure")
        if self.raw is None: raise FileNotFoundError("modeled absent canonical")
        return self.leaf
    def open(self, name, flags, *, dir_fd=None):
        assert name == self.name and dir_fd == 10
        assert flags == os.O_RDONLY | os.O_NONBLOCK | m.FILE_FLAGS
        self.opens += 1
        return 12
    def fstat(self, fd):
        assert fd == 12
        return self.leaf
    def listxattr(self, fd):
        assert fd == 12
        return []
    def read(self, fd, size):
        assert fd == 12 and size > 0
        self.reads += 1
        if self.read_error is not None: raise self.read_error("modeled read failure")
        return self.raw if self.reads == 1 else b""
    def close(self, fd):
        self.closes.append(fd)
        if fd == 12 and self.close_error is not None:
            raise self.close_error("modeled canonical close failure")
        if fd == 11 and self.lock_error is not None:
            raise self.lock_error("modeled lock close failure")
        if fd == 10 and self.status_error is not None:
            raise self.status_error("modeled status close failure")
        assert fd in (10, 11, 12)

def install(fake):
    m.os = fake
    m.signal = SimpleNamespace(signal=lambda *_: None)
    m.open_status_dir = lambda: 10
    m.open_existing_scope_lock = lambda fd: 11 if fd == 10 else forbidden()
    m.open_scope_lock = lambda fd, name: 11 if fd == 10 else forbidden()
    m.validate_process_capability = lambda: None
    m.diagnose_first_rejection = forbidden
    m.collect = m.publish = m.encode_document = forbidden
    m.ES_TLS_GRAMMAR_DIAGNOSTIC_BOOTSTRAP_VERIFIED = True
    m.ES_TLS_GRAMMAR_DIAGNOSTIC_SOURCE_SHA256 = digest
    m.ES_TLS_GRAMMAR_DIAGNOSTIC_BOOTSTRAP_INTERRUPTED = [False]
    m.ES_TLS_STATUS_BOOTSTRAP_VERIFIED = False
    m.ES_TLS_STATUS_BOOTSTRAP_INTERRUPTED = [False]
    m.LATCHED_SIGNAL = None

canonical = m.SCOPES["execution-governance"]["canonical"]
valid = {"schema_version": m.SCOPES["execution-governance"]["schema"],
         "collector_contract": m.CONTRACT, "finalized": True,
         "scope": "execution-governance", "route": m.SCOPES["execution-governance"]["route"],
         "generation": "0" * 32}
valid_raw = json.dumps(valid, separators=(",", ":")).encode() + b"\n"
for raw, read_fault, stat_fault, close_fault in (
        (b"{}\n", None, None, OSError),
        (valid_raw, None, None, OSError),
        (b"{}\n", OSError, None, OSError),
        (b"{}\n", None, 2, OSError),
        (b"{}\n", None, None, FileNotFoundError),
        (b"{}\n", None, None, KeyboardInterrupt)):
    fake = FakeOS(canonical, raw, close_fault, read_fault, stat_fault)
    install(fake)
    if close_fault is KeyboardInterrupt:
        try: m.diagnostic_main()
        except KeyboardInterrupt: pass
        else: raise AssertionError("canonical close interruption swallowed")
    else:
        result = m.diagnostic_main()
        assert result is None and m.format_diagnostic_line(result, digest) is None
    assert fake.closes == [12, 11, 10], fake.closes
    assert fake.opens == 1 and m.WITNESS_DISPOSITION_UNPROVED is True
    assert m.PROCESS_CAPABILITY_READY is False and native == []

# A subsequent verified call resets the sticky flag, then applies the settled
# present/absent and read-failure rules without accepting prior close faults.
for raw, read_fault, expected in (
        (b"{}\n", None, "canonical_not_absent"),
        (valid_raw, None, "canonical_not_absent"),
        (None, None, "other_unproved"),
        (b"{}\n", OSError, "prior_snapshot_unproved")):
    fake = FakeOS(canonical, raw, read_error=read_fault)
    install(fake)
    if raw is None:
        m.diagnose_first_rejection = lambda ctx: (_ for _ in ()).throw(
            m.Incomplete("fixed_input_unproved"))
    result = m.diagnostic_main()
    assert result is not None and result["outcome"] == "incomplete_other"
    assert result["other_failure"] == expected, (raw, expected, result, fake.closes)
    closed_line(result)
    assert fake.closes == ([11, 10] if raw is None else [12, 11, 10])
    assert m.WITNESS_DISPOSITION_UNPROVED is False and native == []

# The reader never clears a prior uncertainty within the same invocation.
fake = FakeOS(canonical, b"{}\n")
install(fake)
m.WITNESS_DISPOSITION_UNPROVED = True
assert m.read_protected_summary_leaf(10, canonical) == b"{}\n"
assert fake.closes == [12] and m.WITNESS_DISPOSITION_UNPROVED is True

# Both shared-reader entry points retain their existing signatures and scopes.
for scope_name, scope in m.SCOPES.items():
    name = scope["canonical"]
    for raw, expected_state in ((None, m._PriorSummaryState.ABSENT),
                                (b"{}\n", m._PriorSummaryState.INVALID_OR_UNACCEPTED)):
        fake = FakeOS(name, raw)
        install(fake)
        m.WITNESS_DISPOSITION_UNPROVED = False
        assert m.preexisting_generation(10, scope_name).state is expected_state
        assert fake.closes == ([] if raw is None else [12])
        assert m.WITNESS_DISPOSITION_UNPROVED is False
    for caller in ("check_existing", "read_accepted_status"):
        fake = FakeOS(name, b"{}\n", close_error=OSError)
        install(fake)
        m.WITNESS_DISPOSITION_UNPROVED = False
        try:
            if caller == "check_existing": m.check_existing(10, name)
            else: m.read_accepted_status(scope_name, None)
        except OSError as exc:
            assert exc.args == ("modeled canonical close failure",)
        else: raise AssertionError("shared reader close failure swallowed")
        assert fake.closes == ([12] if caller == "check_existing" else [12, 10])
        assert m.WITNESS_DISPOSITION_UNPROVED is True and native == []

# Status collection also refuses the failed canonical close, even when both
# outer closes fail and its failure witness cannot be proved.
for lock_fault, status_fault in ((None, None), (OSError, OSError)):
    fake = FakeOS(canonical, b"{}\n", close_error=OSError,
                  lock_error=lock_fault, status_error=status_fault)
    install(fake)
    m.ES_TLS_STATUS_BOOTSTRAP_VERIFIED = True
    assert m.main(["--scope", "execution-governance"]) == 1
    assert fake.closes == [12, 11, 10]
    assert m.WITNESS_DISPOSITION_UNPROVED is True
    assert m.WITNESS_CLOSEOUT_PROVED is False and native == []
print("OK")
`)
	source := filepath.Join(executionSubstrateRepoRoot, "scripts", "internal", "remote_alpha_es_tls_status.py")
	facade := remoteAlphaOperatorScriptPath()
	cmd := exec.Command("/usr/bin/python3", "-I", "-B", "-c", grammarBootstrapCompositionFixture,
		source, facade, "prior_reader_close_fault")
	cmd.Dir = executionSubstrateRepoRoot
	cmd.Env = append(os.Environ(), "PYTHONDONTWRITEBYTECODE=1")
	output, err := cmd.CombinedOutput()
	if err != nil || strings.TrimSpace(string(output)) != "OK" {
		t.Fatalf("contained prior-close bootstrap composition failed: %v\n%s", err, output)
	}
}
