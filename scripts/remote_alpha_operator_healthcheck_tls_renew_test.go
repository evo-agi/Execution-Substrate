package scripts_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

type remoteAlphaOperatorHealthcheckTLSFixture struct {
	root       string
	localBin   string
	summary    string
	backupRoot string
	sentinel   string
	installLog string
	curlLog    string
	tlsDir     string
	esConfig   string
	healthEnv  string
}

func remoteAlphaOperatorHealthcheckTLSScriptPath() string {
	return filepath.Join(executionSubstrateRepoRoot, "scripts", "remote_alpha_operator_healthcheck_tls_renew.sh")
}

func setupRemoteAlphaOperatorHealthcheckTLSFixture(t *testing.T, expired bool, spiffeURIs ...string) *remoteAlphaOperatorHealthcheckTLSFixture {
	t.Helper()
	now := time.Now().UTC()
	notBefore := now.Add(-48 * time.Hour)
	notAfter := now.Add(30 * 24 * time.Hour)
	if expired {
		notBefore = now.Add(-96 * time.Hour)
		notAfter = now.Add(-24 * time.Hour)
	}

	root := t.TempDir()
	fixture := &remoteAlphaOperatorHealthcheckTLSFixture{
		root:       root,
		localBin:   filepath.Join(root, "bin"),
		summary:    filepath.Join(root, "summary", "operator-healthcheck-tls-renew-summary.json"),
		backupRoot: filepath.Join(root, "backup"),
		sentinel:   filepath.Join(root, "backup-sentinel.txt"),
		installLog: filepath.Join(root, "install.log"),
		curlLog:    filepath.Join(root, "curl.log"),
		tlsDir:     filepath.Join(root, "etc", "execution-substrate", "tls"),
		esConfig:   filepath.Join(root, "etc", "execution-substrate", "es.json"),
		healthEnv:  filepath.Join(root, "etc", "execution-substrate", "healthcheck.env"),
	}
	for _, dir := range []string{fixture.localBin, fixture.tlsDir, filepath.Dir(fixture.summary), fixture.backupRoot, filepath.Dir(fixture.esConfig)} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", dir, err)
		}
	}

	caCertPEM, caKey, _ := remoteAlphaGenerateCA(t, now.Add(-48*time.Hour), now.Add(365*24*time.Hour))
	writeFile(t, filepath.Join(fixture.tlsDir, "runtime-ca.pem"), caCertPEM, 0o640)
	writeFile(t, filepath.Join(fixture.tlsDir, "server-client-ca.pem"), caCertPEM, 0o640)
	writeFile(t, filepath.Join(fixture.tlsDir, "combined-service-ca-bundle.pem"), caCertPEM, 0o640)

	cert, key := remoteAlphaGenerateOperatorClientLeaf(t, caCertPEM, caKey, spiffeURIs, notBefore, notAfter)
	writeFile(t, filepath.Join(fixture.tlsDir, "operator-client-cert.pem"), cert, 0o644)
	writeFile(t, filepath.Join(fixture.tlsDir, "operator-client-key.pem"), key, 0o600)

	writeFile(t, fixture.esConfig, []byte(fmt.Sprintf(`{"tls":{"client_ca_file":%q}}`,
		filepath.Join(fixture.tlsDir, "server-client-ca.pem"),
	)), 0o600)
	writeFile(t, fixture.healthEnv, []byte(fmt.Sprintf("OPERATOR_CERT=%s\nOPERATOR_KEY=%s\nCA_CERT=%s\nES_BASE_URL=https://127.0.0.1:9443\n",
		filepath.Join(fixture.tlsDir, "operator-client-cert.pem"),
		filepath.Join(fixture.tlsDir, "operator-client-key.pem"),
		filepath.Join(fixture.tlsDir, "combined-service-ca-bundle.pem"),
	)), 0o600)

	return fixture
}

func (f *remoteAlphaOperatorHealthcheckTLSFixture) helperEnv(extra ...string) []string {
	env := append(os.Environ(),
		"REMOTE_ALPHA_TEST_ALLOW_NON_ROOT=1",
		"REMOTE_ALPHA_TEST_BACKUP_ROOT="+f.backupRoot,
		"REMOTE_ALPHA_TEST_BACKUP_SENTINEL_PATH="+f.sentinel,
		"REMOTE_ALPHA_TEST_TIMESTAMP=20260525T040000Z",
		"remote_alpha_operator_healthcheck_tls_expected_es_config_path="+f.esConfig,
		"remote_alpha_operator_healthcheck_tls_expected_healthcheck_env_path="+f.healthEnv,
		"remote_alpha_operator_healthcheck_tls_expected_operator_cert_path="+filepath.Join(f.tlsDir, "operator-client-cert.pem"),
		"remote_alpha_operator_healthcheck_tls_expected_operator_key_path="+filepath.Join(f.tlsDir, "operator-client-key.pem"),
		"remote_alpha_operator_healthcheck_tls_expected_healthcheck_server_ca_path="+filepath.Join(f.tlsDir, "combined-service-ca-bundle.pem"),
	)
	env = append(env, extra...)
	return env
}

func runRemoteAlphaOperatorHealthcheckTLSRenew(t *testing.T, env []string, args ...string) (string, error) {
	t.Helper()
	cmd := exec.Command("/bin/bash", append([]string{remoteAlphaOperatorHealthcheckTLSScriptPath()}, args...)...)
	cmd.Dir = executionSubstrateRepoRoot
	cmd.Env = env
	output, err := cmd.CombinedOutput()
	return string(output), err
}

func TestRemoteAlphaOperatorHealthcheckTLSStatusDetectsExpiredLegacyOperatorCertAndExpectedIdentity(t *testing.T) {
	fixture := setupRemoteAlphaOperatorHealthcheckTLSFixture(t, true, "spiffe://execution.internal/operator")
	output, err := runRemoteAlphaOperatorHealthcheckTLSRenew(t, fixture.helperEnv("REMOTE_ALPHA_TEST_SKIP_OPERATOR_HEALTHCHECK_TLS_PROBES=1"), "--status", "--summary-path", fixture.summary)
	if err == nil {
		t.Fatalf("expected expired operator healthcheck cert status to fail, output=%s", output)
	}
	assertContainsAll(t, "expired operator healthcheck status output", output, fixture.summary)
	assertContainsNone(t, "expired operator healthcheck status output", output, "BEGIN PRIVATE KEY", "BEGIN RSA PRIVATE KEY", "BEGIN CERTIFICATE")

	summary := readJSONMap(t, fixture.summary)
	assertJSONPathEquals(t, summary, "mode.name", "status")
	assertJSONPathEquals(t, summary, "mode.non_mutating", true)
	assertJSONPathEquals(t, summary, "result.status", "fail")
	assertJSONPathEquals(t, summary, "certificate.expired", true)
	assertJSONPathEquals(t, summary, "identity.expected_uri", "spiffe://execution.internal/operator/local")
	assertJSONPathEquals(t, summary, "identity.legacy_operator_uri_present", true)
	assertJSONPathEquals(t, summary, "identity.matches_current_allowlist", false)
	assertJSONPathEquals(t, summary, "security.private_key_pem_bodies_in_summary", false)
	assertFileContainsNoSecrets(t, fixture.summary)
}

func TestRemoteAlphaOperatorHealthcheckTLSStatusDetectsLegacyOperatorIdentityMismatch(t *testing.T) {
	fixture := setupRemoteAlphaOperatorHealthcheckTLSFixture(t, false, "spiffe://execution.internal/operator")
	output, err := runRemoteAlphaOperatorHealthcheckTLSRenew(t, fixture.helperEnv("REMOTE_ALPHA_TEST_SKIP_OPERATOR_HEALTHCHECK_TLS_PROBES=1"), "--status", "--summary-path", fixture.summary)
	if err == nil {
		t.Fatalf("expected legacy operator URI status to fail, output=%s", output)
	}
	summary := readJSONMap(t, fixture.summary)
	assertJSONPathEquals(t, summary, "identity.expected_uri", "spiffe://execution.internal/operator/local")
	assertJSONPathEquals(t, summary, "identity.legacy_operator_uri_present", true)
	assertJSONPathEquals(t, summary, "identity.matches_current_allowlist", false)
	assertJSONPathEquals(t, summary, "identity.classification", "legacy_operator_identity_requires_operator_local_renewal")
	assertFileContainsNoSecrets(t, fixture.summary)
}

func TestRemoteAlphaOperatorHealthcheckTLSStatusDetectsValidOperatorCert(t *testing.T) {
	fixture := setupRemoteAlphaOperatorHealthcheckTLSFixture(t, false, "spiffe://execution.internal/operator/local")
	output, err := runRemoteAlphaOperatorHealthcheckTLSRenew(t, fixture.helperEnv("REMOTE_ALPHA_TEST_SKIP_OPERATOR_HEALTHCHECK_TLS_PROBES=1"), "--status", "--summary-path", fixture.summary)
	if err != nil {
		t.Fatalf("expected valid operator healthcheck cert status to pass: %v\n%s\nsummary=%s", err, output, readIfExists(fixture.summary))
	}
	summary := readJSONMap(t, fixture.summary)
	assertJSONPathEquals(t, summary, "result.status", "pass")
	assertJSONPathEquals(t, summary, "result.ok", true)
	assertJSONPathEquals(t, summary, "identity.matches_current_allowlist", true)
	assertJSONPathEquals(t, summary, "identity.uri_san_count", float64(1))
	assertJSONPathEquals(t, summary, "key_pair.matches", true)
	for _, item := range summary["verification"].([]any) {
		record := item.(map[string]any)
		if record["status"] != "pass" {
			t.Fatalf("expected operator verification pass, got %#v", record)
		}
	}
	assertFileContainsNoSecrets(t, fixture.summary)
}

// ES refuses a certificate with more than one URI SAN (caller authentication
// contract, contracts.md section 3A), so the status fails even when one of
// the URI SANs is the expected identity. URI SANs are compared whole, not as
// substrings of the OpenSSL text.
func TestRemoteAlphaOperatorHealthcheckTLSStatusRequiresExactlyTheExpectedURISAN(t *testing.T) {
	for _, tc := range []struct {
		name           string
		uris           []string
		count          int
		legacy         bool
		classification string
	}{
		{name: "expected and another identity", uris: []string{"spiffe://execution.internal/operator/local", "spiffe://execution.internal/service/execution"}, count: 2, classification: "operator_identity_mismatch"},
		{name: "legacy and expected", uris: []string{"spiffe://execution.internal/operator", "spiffe://execution.internal/operator/local"}, count: 2, legacy: true, classification: "legacy_operator_identity_requires_operator_local_renewal"},
		{name: "expected twice", uris: []string{"spiffe://execution.internal/operator/local", "spiffe://execution.internal/operator/local"}, count: 2, classification: "operator_identity_mismatch"},
		{name: "expected as a prefix", uris: []string{"spiffe://execution.internal/operator/local-evil"}, count: 1, classification: "operator_identity_mismatch"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fixture := setupRemoteAlphaOperatorHealthcheckTLSFixture(t, false, tc.uris...)
			output, err := runRemoteAlphaOperatorHealthcheckTLSRenew(t, fixture.helperEnv("REMOTE_ALPHA_TEST_SKIP_OPERATOR_HEALTHCHECK_TLS_PROBES=1"), "--status", "--summary-path", fixture.summary)
			if err == nil {
				t.Fatalf("expected operator certificate with URI SANs %q to fail status, output=%s", tc.uris, output)
			}
			summary := readJSONMap(t, fixture.summary)
			assertJSONPathEquals(t, summary, "result.status", "fail")
			assertJSONPathEquals(t, summary, "identity.status", "fail")
			assertJSONPathEquals(t, summary, "identity.matches_current_allowlist", false)
			assertJSONPathEquals(t, summary, "identity.uri_san_count", float64(tc.count))
			assertJSONPathEquals(t, summary, "identity.legacy_operator_uri_present", tc.legacy)
			assertJSONPathEquals(t, summary, "identity.classification", tc.classification)
			assertContainsAll(t, "operator certificate URI SAN blocker", readIfExists(fixture.summary), "operator certificate must carry exactly one URI SAN, spiffe://execution.internal/operator/local")
			assertFileContainsNoSecrets(t, fixture.summary)
		})
	}
}

func TestRemoteAlphaOperatorHealthcheckTLSRenewHelperRejectsSecretLikeArgs(t *testing.T) {
	fixture := setupRemoteAlphaOperatorHealthcheckTLSFixture(t, false, "spiffe://execution.internal/operator/local")
	output, err := runRemoteAlphaOperatorHealthcheckTLSRenew(t, fixture.helperEnv(), "--private-key", "dummy")
	if err == nil {
		t.Fatalf("expected secret-like helper args to fail")
	}
	assertContainsAll(t, "operator healthcheck secret arg refusal", output, "does not accept secret-like CLI arguments")
	assertContainsNone(t, "operator healthcheck secret arg refusal", output, "dummy", "BEGIN PRIVATE KEY", "BEGIN CERTIFICATE")
}

func TestRemoteAlphaOperatorHealthcheckTLSRenewFailsBeforeMutationWithoutDocumentedSignerTopology(t *testing.T) {
	fixture := setupRemoteAlphaOperatorHealthcheckTLSFixture(t, true, "spiffe://execution.internal/operator")

	output, err := runRemoteAlphaOperatorHealthcheckTLSRenew(t, fixture.helperEnv(), "--execute-renew", "--summary-path", fixture.summary)
	if err == nil {
		t.Fatalf("expected unsupported operator healthcheck renew topology to fail\noutput=%s\nsummary=%s",
			output, readIfExists(fixture.summary))
	}
	assertContainsAll(t, "unsupported operator healthcheck renew output",
		output,
		"unsupported_signing_topology",
		"future documented CA custody/signing design",
		fixture.summary,
	)
	assertContainsNone(t, "unsupported operator healthcheck renew output",
		output,
		"runtime-ca-key.pem",
		"BEGIN PRIVATE KEY",
		"BEGIN RSA PRIVATE KEY",
		"BEGIN CERTIFICATE",
	)
	assertFileContainsNoSecrets(t, fixture.summary)

	if _, err := os.Stat(fixture.sentinel); !os.IsNotExist(err) {
		t.Fatalf("backup sentinel should not be written before unsupported renew failure: %v", err)
	}
	if _, err := os.Stat(fixture.installLog); !os.IsNotExist(err) {
		t.Fatalf("install should not run before unsupported renew failure: %v", err)
	}
	if _, err := os.Stat(fixture.curlLog); !os.IsNotExist(err) {
		t.Fatalf("post-renew probes should not run before unsupported renew failure: %v", err)
	}

	summary := readJSONMap(t, fixture.summary)
	assertJSONPathEquals(t, summary, "mode.name", "execute_renew")
	assertJSONPathEquals(t, summary, "result.status", "fail")
	assertJSONPathEquals(t, summary, "result.failure_class", "unsupported_signing_topology")
	assertJSONPathEquals(t, summary, "renewal_topology.status", "unsupported")
	assertJSONPathEquals(t, summary, "renewal_topology.failure_class", "unsupported_signing_topology")
	assertJSONPathEquals(t, summary, "renewal_topology.mutation_started", false)
	assertJSONPathEquals(t, summary, "renewal_topology.retained_remote_ca_key_required", false)
	assertJSONPathEquals(t, summary, "renewal_topology.documented_signing_topology", false)
	assertJSONPathEquals(t, summary, "backup.status", "not_run")
	assertJSONPathEquals(t, summary, "install_policy.status", "not_run")
	assertJSONPathEquals(t, summary, "service_restarts.status", "not_required")
	assertJSONPathEquals(t, summary, "probes.status", "not_run")
	assertJSONPathEquals(t, summary, "identity.expected_uri", "spiffe://execution.internal/operator/local")
	assertJSONPathEquals(t, summary, "identity.legacy_operator_uri_present", true)
	assertJSONPathEquals(t, summary, "identity.matches_current_allowlist", false)
	assertJSONPathEquals(t, summary, "certificate.expired", true)
	assertJSONPathEquals(t, summary, "security.private_key_pem_bodies_printed", false)
	assertContainsNone(t, "unsupported operator healthcheck renew summary", readIfExists(fixture.summary), "runtime-ca-key.pem", "BEGIN PRIVATE KEY", "BEGIN CERTIFICATE")
}

func TestRemoteAlphaOperatorHealthcheckTLSRenewDoesNotUseRetainedRuntimeCAKeyTopology(t *testing.T) {
	source := mustRead(t, filepath.Join(executionSubstrateRepoRoot, "scripts", "internal", "remote_alpha_operator_healthcheck_tls_renew.sh"))
	assertContainsNone(t, "operator healthcheck renew retained CA-key topology",
		source,
		"runtime-ca-key.pem",
		"REMOTE_ALPHA_SIGNING_CA_KEY_PATH",
		"signing CA private key is missing",
	)
}

func remoteAlphaGenerateOperatorClientLeaf(t *testing.T, caPEM []byte, caKey *rsa.PrivateKey, spiffeURIs []string, notBefore, notAfter time.Time) ([]byte, []byte) {
	t.Helper()
	block, _ := pem.Decode(caPEM)
	if block == nil {
		t.Fatalf("decode CA PEM")
	}
	caCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse CA cert: %v", err)
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate operator client key: %v", err)
	}
	parsedURIs := make([]*url.URL, 0, len(spiffeURIs))
	for _, spiffeURI := range spiffeURIs {
		parsedURI, err := url.Parse(spiffeURI)
		if err != nil {
			t.Fatalf("parse SPIFFE URI %q: %v", spiffeURI, err)
		}
		parsedURIs = append(parsedURIs, parsedURI)
	}
	template := &x509.Certificate{
		SerialNumber:          remoteAlphaSerial(t),
		Subject:               pkix.Name{CommonName: "client.operator"},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"client.operator"},
		URIs:                  parsedURIs,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, caCert, &key.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create operator client cert: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
}

func remoteAlphaSerial(t *testing.T) *big.Int {
	t.Helper()
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		t.Fatalf("generate serial: %v", err)
	}
	return serial
}

func assertJSONProbeUsesRenewedOperatorIdentity(t *testing.T, record map[string]any) {
	t.Helper()
	if record["uses_renewed_operator_identity"] != true {
		t.Fatalf("expected probe to use renewed operator identity, got %#v", record)
	}
	if record["response_body_recorded"] != false {
		t.Fatalf("expected probe response body to stay out of summary, got %#v", record)
	}
}
