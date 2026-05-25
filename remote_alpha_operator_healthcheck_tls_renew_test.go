package executionsubstrate_test

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
	"strings"
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

func setupRemoteAlphaOperatorHealthcheckTLSFixture(t *testing.T, expired bool, spiffeURI string) *remoteAlphaOperatorHealthcheckTLSFixture {
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

	caCertPEM, caKey, caKeyPEM := remoteAlphaGenerateCA(t, now.Add(-48*time.Hour), now.Add(365*24*time.Hour))
	writeFile(t, filepath.Join(fixture.tlsDir, "runtime-ca.pem"), caCertPEM, 0o640)
	writeFile(t, filepath.Join(fixture.tlsDir, "runtime-ca-key.pem"), caKeyPEM, 0o600)
	writeFile(t, filepath.Join(fixture.tlsDir, "server-client-ca.pem"), caCertPEM, 0o640)
	writeFile(t, filepath.Join(fixture.tlsDir, "combined-service-ca-bundle.pem"), caCertPEM, 0o640)

	cert, key := remoteAlphaGenerateOperatorClientLeaf(t, caCertPEM, caKey, spiffeURI, notBefore, notAfter)
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
		"REMOTE_ALPHA_TEST_CERT_DAYS=30",
		"remote_alpha_operator_healthcheck_tls_expected_es_config_path="+f.esConfig,
		"remote_alpha_operator_healthcheck_tls_expected_healthcheck_env_path="+f.healthEnv,
		"remote_alpha_operator_healthcheck_tls_expected_operator_cert_path="+filepath.Join(f.tlsDir, "operator-client-cert.pem"),
		"remote_alpha_operator_healthcheck_tls_expected_operator_key_path="+filepath.Join(f.tlsDir, "operator-client-key.pem"),
		"remote_alpha_operator_healthcheck_tls_expected_healthcheck_server_ca_path="+filepath.Join(f.tlsDir, "combined-service-ca-bundle.pem"),
		"remote_alpha_operator_healthcheck_tls_expected_signing_ca_cert_path="+filepath.Join(f.tlsDir, "runtime-ca.pem"),
		"remote_alpha_operator_healthcheck_tls_expected_signing_ca_key_path="+filepath.Join(f.tlsDir, "runtime-ca-key.pem"),
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

func TestRemoteAlphaOperatorHealthcheckTLSStatusDetectsExpiredOperatorCert(t *testing.T) {
	fixture := setupRemoteAlphaOperatorHealthcheckTLSFixture(t, true, "spiffe://execution.internal/operator/local")
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
	assertJSONPathEquals(t, summary, "identity.matches_current_allowlist", true)
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
	assertJSONPathEquals(t, summary, "key_pair.matches", true)
	for _, item := range summary["verification"].([]any) {
		record := item.(map[string]any)
		if record["status"] != "pass" {
			t.Fatalf("expected operator verification pass, got %#v", record)
		}
	}
	assertFileContainsNoSecrets(t, fixture.summary)
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

func TestRemoteAlphaOperatorHealthcheckTLSRenewFakeApplyBacksUpPreservesPolicyAndVerifies(t *testing.T) {
	fixture := setupRemoteAlphaOperatorHealthcheckTLSFixture(t, true, "spiffe://execution.internal/operator")
	fixture.writeFakeRenewCommands(t)
	env := fixture.helperEnv("PATH=" + fixture.localBin + string(os.PathListSeparator) + os.Getenv("PATH"))

	output, err := runRemoteAlphaOperatorHealthcheckTLSRenew(t, env, "--execute-renew", "--summary-path", fixture.summary)
	if err != nil {
		t.Fatalf("fake operator healthcheck renew failed: %v\noutput=%s\nsummary=%s\ninstall=%s\ncurl=%s",
			err, output, readIfExists(fixture.summary), readIfExists(fixture.installLog), readIfExists(fixture.curlLog))
	}
	assertContainsAll(t, "fake operator healthcheck renew output", output, fixture.summary)
	assertContainsNone(t, "fake operator healthcheck renew output", output, "BEGIN PRIVATE KEY", "BEGIN RSA PRIVATE KEY", "BEGIN CERTIFICATE")
	assertFileContainsNoSecrets(t, fixture.summary)

	backupDir := strings.TrimSpace(mustRead(t, fixture.sentinel))
	if backupDir == "" {
		t.Fatalf("expected backup sentinel")
	}
	for _, originalPath := range []string{
		filepath.Join(fixture.tlsDir, "operator-client-cert.pem"),
		filepath.Join(fixture.tlsDir, "operator-client-key.pem"),
	} {
		rel := strings.TrimPrefix(originalPath, string(os.PathSeparator))
		if _, err := os.Stat(filepath.Join(backupDir, "material", rel)); err != nil {
			t.Fatalf("expected backup material %s: %v", rel, err)
		}
	}

	installLog := mustRead(t, fixture.installLog)
	assertContainsAll(t, "operator healthcheck install policy", installLog,
		"file owner=",
		"mode=0644 dest="+filepath.Join(fixture.tlsDir, "operator-client-cert.pem"),
		"mode=0600 dest="+filepath.Join(fixture.tlsDir, "operator-client-key.pem"),
	)
	curlLog := mustRead(t, fixture.curlLog)
	assertContainsAll(t, "operator healthcheck renewed identity probes", curlLog,
		"--cert "+filepath.Join(fixture.tlsDir, "operator-client-cert.pem"),
		"--key "+filepath.Join(fixture.tlsDir, "operator-client-key.pem"),
		"https://127.0.0.1:9443/health",
		"https://127.0.0.1:9443/v1/executions:contract",
	)

	summary := readJSONMap(t, fixture.summary)
	assertJSONPathEquals(t, summary, "result.status", "pass")
	assertJSONPathEquals(t, summary, "backup.status", "created")
	assertJSONPathEquals(t, summary, "backup.private_key_material_in_summary", false)
	assertJSONPathEquals(t, summary, "install_policy.status", "pass")
	assertJSONPathEquals(t, summary, "service_restarts.status", "not_required")
	assertJSONPathEquals(t, summary, "probes.status", "pass")
	assertJSONPathEquals(t, summary, "identity.expected_uri", "spiffe://execution.internal/operator/local")
	assertJSONPathEquals(t, summary, "identity.matches_current_allowlist", true)
	assertJSONPathEquals(t, summary, "certificate.expired", false)
	assertJSONPathEquals(t, summary, "security.private_key_pem_bodies_printed", false)
	for _, item := range summary["probes"].(map[string]any)["items"].([]any) {
		record := item.(map[string]any)
		assertJSONProbeUsesRenewedOperatorIdentity(t, record)
	}
}

func (f *remoteAlphaOperatorHealthcheckTLSFixture) writeFakeRenewCommands(t *testing.T) {
	t.Helper()
	writeExecutable(t, f.localBin, "install", fmt.Sprintf(`#!/usr/bin/env bash
set -euo pipefail
owner=""
group=""
mode=""
operands=()
while [[ "$#" -gt 0 ]]; do
  case "$1" in
    -o)
      owner="$2"
      shift 2
      ;;
    -g)
      group="$2"
      shift 2
      ;;
    -m)
      mode="$2"
      shift 2
      ;;
    --)
      shift
      ;;
    -*)
      echo "unexpected fake install arg: $1" >&2
      exit 64
      ;;
    *)
      operands+=("$1")
      shift
      ;;
  esac
done
if [[ "${#operands[@]}" -ne 2 ]]; then
  echo "fake install expected src dest" >&2
  exit 64
fi
if [[ ! -s "${REMOTE_ALPHA_TEST_BACKUP_SENTINEL_PATH}" ]]; then
  echo "backup sentinel missing before replacement" >&2
  exit 65
fi
src="${operands[0]}"
dest="${operands[1]}"
mkdir -p -- "$(dirname "${dest}")"
cp -- "${src}" "${dest}"
[[ -z "${mode}" ]] || chmod "${mode}" "${dest}"
printf 'file owner=%%s group=%%s mode=%%s dest=%%s\n' "${owner}" "${group}" "${mode}" "${dest}" >> %q
`, f.installLog))

	writeExecutable(t, f.localBin, "curl", fmt.Sprintf(`#!/usr/bin/env bash
set -euo pipefail
printf '%%s\n' "$*" >> %q
printf '{"status":"ok"}\n'
`, f.curlLog))
}

func remoteAlphaGenerateOperatorClientLeaf(t *testing.T, caPEM []byte, caKey *rsa.PrivateKey, spiffeURI string, notBefore, notAfter time.Time) ([]byte, []byte) {
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
	parsedURI, err := url.Parse(spiffeURI)
	if err != nil {
		t.Fatalf("parse SPIFFE URI %q: %v", spiffeURI, err)
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
		URIs:                  []*url.URL{parsedURI},
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
