package executionsubstrate_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type remoteAlphaESServiceTLSFixture struct {
	root       string
	localBin   string
	summary    string
	backupRoot string
	sentinel   string
	installLog string
	systemLog  string
	curlLog    string
	arsTLSDir  string
	agsTLSDir  string
	esTLSDir   string
	egsTLSDir  string
	arsConfig  string
	agsConfig  string
	esConfig   string
	egsConfig  string
}

func remoteAlphaESServiceTLSRenewScriptPath() string {
	return filepath.Join(executionSubstrateRepoRoot, "scripts", "remote_alpha_es_service_tls_renew.sh")
}

func setupRemoteAlphaESServiceTLSFixture(t *testing.T, expired bool) *remoteAlphaESServiceTLSFixture {
	t.Helper()
	now := time.Now().UTC()
	notBefore := now.Add(-48 * time.Hour)
	notAfter := now.Add(30 * 24 * time.Hour)
	if expired {
		notBefore = now.Add(-96 * time.Hour)
		notAfter = now.Add(-24 * time.Hour)
	}

	root := t.TempDir()
	fixture := &remoteAlphaESServiceTLSFixture{
		root:       root,
		localBin:   filepath.Join(root, "bin"),
		summary:    filepath.Join(root, "summary", "es-service-tls-renew-summary.json"),
		backupRoot: filepath.Join(root, "backup"),
		sentinel:   filepath.Join(root, "backup-sentinel.txt"),
		installLog: filepath.Join(root, "install.log"),
		systemLog:  filepath.Join(root, "systemctl.log"),
		curlLog:    filepath.Join(root, "curl.log"),
		arsTLSDir:  filepath.Join(root, "etc", "execution-substrate", "ars-tls"),
		agsTLSDir:  filepath.Join(root, "etc", "execution-substrate", "tls"),
		esTLSDir:   filepath.Join(root, "etc", "execution-substrate", "es-tls"),
		egsTLSDir:  filepath.Join(root, "etc", "execution-substrate", "egs-tls"),
		arsConfig:  filepath.Join(root, "etc", "execution-substrate", "ars.json"),
		agsConfig:  filepath.Join(root, "etc", "execution-substrate", "ags.json"),
		esConfig:   filepath.Join(root, "etc", "execution-substrate", "es.json"),
		egsConfig:  filepath.Join(root, "etc", "execution-substrate", "egs.json"),
	}
	for _, dir := range []string{fixture.localBin, fixture.arsTLSDir, fixture.agsTLSDir, fixture.esTLSDir, fixture.egsTLSDir, filepath.Dir(fixture.arsConfig), filepath.Dir(fixture.summary), fixture.backupRoot} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", dir, err)
		}
	}

	caCertPEM, caKey, caKeyPEM := remoteAlphaGenerateCA(t, notBefore, notAfter)
	writeFile(t, filepath.Join(fixture.arsTLSDir, "runtime-ca.pem"), caCertPEM, 0o640)
	writeFile(t, filepath.Join(fixture.agsTLSDir, "runtime-ca.pem"), caCertPEM, 0o640)
	writeFile(t, filepath.Join(fixture.esTLSDir, "artifact-registry-root-ca.pem"), caCertPEM, 0o640)

	serverCert, serverKey := remoteAlphaGenerateLeaf(t, caCertPEM, caKey, "server.artifact-registry.internal", x509.ExtKeyUsageServerAuth, notBefore, notAfter)
	writeFile(t, filepath.Join(fixture.arsTLSDir, "ars-server-cert.pem"), serverCert, 0o640)
	writeFile(t, filepath.Join(fixture.arsTLSDir, "ars-server-key.pem"), serverKey, 0o640)
	agsCert, agsKey := remoteAlphaGenerateLeaf(t, caCertPEM, caKey, "client.service.artifact-governance", x509.ExtKeyUsageClientAuth, notBefore, notAfter)
	writeFile(t, filepath.Join(fixture.agsTLSDir, "ags-client-cert.pem"), agsCert, 0o640)
	writeFile(t, filepath.Join(fixture.agsTLSDir, "ags-client-key.pem"), agsKey, 0o640)
	esCert, esKey := remoteAlphaGenerateLeaf(t, caCertPEM, caKey, "client.service.execution", x509.ExtKeyUsageClientAuth, notBefore, notAfter)
	writeFile(t, filepath.Join(fixture.esTLSDir, "artifact-registry-client-cert.pem"), esCert, 0o640)
	writeFile(t, filepath.Join(fixture.esTLSDir, "artifact-registry-client-key.pem"), esKey, 0o640)
	_ = caKeyPEM

	writeFile(t, fixture.arsConfig, []byte(fmt.Sprintf(`{"tls":{"client_ca_file":%q,"cert_file":%q,"key_file":%q}}`,
		filepath.Join(fixture.arsTLSDir, "runtime-ca.pem"),
		filepath.Join(fixture.arsTLSDir, "ars-server-cert.pem"),
		filepath.Join(fixture.arsTLSDir, "ars-server-key.pem"),
	)), 0o600)
	writeFile(t, fixture.agsConfig, []byte(fmt.Sprintf(`{"dependencies":{"artifact_registry":{"base_url":"https://127.0.0.1:8442","client_cert_file":%q,"client_key_file":%q,"root_ca_file":%q}},"tls":{"cert_file":%q,"key_file":%q}}`,
		filepath.Join(fixture.agsTLSDir, "ags-client-cert.pem"),
		filepath.Join(fixture.agsTLSDir, "ags-client-key.pem"),
		filepath.Join(fixture.agsTLSDir, "runtime-ca.pem"),
		filepath.Join(root, "etc", "execution-substrate", "tls", "ags-server-cert.pem"),
		filepath.Join(root, "etc", "execution-substrate", "tls", "ags-server-key.pem"),
	)), 0o600)
	writeFile(t, fixture.esConfig, []byte(fmt.Sprintf(`{"dependencies":{"artifact_registry":{"base_url":"https://127.0.0.1:8442","client_cert_file":%q,"client_key_file":%q,"root_ca_file":%q}},"tls":{"cert_file":%q,"key_file":%q}}`,
		filepath.Join(fixture.esTLSDir, "artifact-registry-client-cert.pem"),
		filepath.Join(fixture.esTLSDir, "artifact-registry-client-key.pem"),
		filepath.Join(fixture.esTLSDir, "artifact-registry-root-ca.pem"),
		filepath.Join(root, "etc", "execution-substrate", "es-tls", "es-server-cert.pem"),
		filepath.Join(root, "etc", "execution-substrate", "es-tls", "es-server-key.pem"),
	)), 0o600)
	writeFile(t, fixture.egsConfig, []byte(`{"tls":{"cert_file":"/non-covered/egs-cert.pem","key_file":"/non-covered/egs-key.pem","client_ca_file":"/non-covered/egs-ca.pem"}}`), 0o600)

	return fixture
}

func setupRemoteAlphaESGovernanceTLSFixture(t *testing.T, expired bool) *remoteAlphaESServiceTLSFixture {
	t.Helper()
	now := time.Now().UTC()
	notBefore := now.Add(-48 * time.Hour)
	notAfter := now.Add(30 * 24 * time.Hour)
	if expired {
		notBefore = now.Add(-96 * time.Hour)
		notAfter = now.Add(-24 * time.Hour)
	}

	root := t.TempDir()
	fixture := &remoteAlphaESServiceTLSFixture{
		root:       root,
		localBin:   filepath.Join(root, "bin"),
		summary:    filepath.Join(root, "summary", "es-governance-tls-renew-summary.json"),
		backupRoot: filepath.Join(root, "backup"),
		sentinel:   filepath.Join(root, "backup-sentinel.txt"),
		installLog: filepath.Join(root, "install.log"),
		systemLog:  filepath.Join(root, "systemctl.log"),
		curlLog:    filepath.Join(root, "curl.log"),
		arsTLSDir:  filepath.Join(root, "etc", "execution-substrate", "ars-tls"),
		agsTLSDir:  filepath.Join(root, "etc", "execution-substrate", "tls"),
		esTLSDir:   filepath.Join(root, "etc", "execution-substrate", "es-tls"),
		egsTLSDir:  filepath.Join(root, "etc", "execution-substrate", "egs-tls"),
		arsConfig:  filepath.Join(root, "etc", "execution-substrate", "ars.json"),
		agsConfig:  filepath.Join(root, "etc", "execution-substrate", "ags.json"),
		esConfig:   filepath.Join(root, "etc", "execution-substrate", "es.json"),
		egsConfig:  filepath.Join(root, "etc", "execution-substrate", "egs.json"),
	}
	for _, dir := range []string{fixture.localBin, fixture.arsTLSDir, fixture.agsTLSDir, fixture.esTLSDir, fixture.egsTLSDir, filepath.Dir(fixture.arsConfig), filepath.Dir(fixture.summary), fixture.backupRoot} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", dir, err)
		}
	}

	caCertPEM, caKey, _ := remoteAlphaGenerateCA(t, notBefore, notAfter)
	writeFile(t, filepath.Join(fixture.egsTLSDir, "runtime-ca.pem"), caCertPEM, 0o640)
	writeFile(t, filepath.Join(fixture.esTLSDir, "execution-governance-root-ca.pem"), caCertPEM, 0o640)

	serverCert, serverKey := remoteAlphaGenerateLeaf(t, caCertPEM, caKey, "server.execution-governance.internal", x509.ExtKeyUsageServerAuth, notBefore, notAfter)
	writeFile(t, filepath.Join(fixture.egsTLSDir, "egs-server-cert.pem"), serverCert, 0o640)
	writeFile(t, filepath.Join(fixture.egsTLSDir, "egs-server-key.pem"), serverKey, 0o640)
	esCert, esKey := remoteAlphaGenerateLeaf(t, caCertPEM, caKey, "client.service.execution", x509.ExtKeyUsageClientAuth, notBefore, notAfter)
	writeFile(t, filepath.Join(fixture.esTLSDir, "execution-governance-client-cert.pem"), esCert, 0o640)
	writeFile(t, filepath.Join(fixture.esTLSDir, "execution-governance-client-key.pem"), esKey, 0o640)

	writeFile(t, fixture.arsConfig, []byte(fmt.Sprintf(`{"tls":{"client_ca_file":%q,"cert_file":%q,"key_file":%q}}`,
		filepath.Join(fixture.arsTLSDir, "runtime-ca.pem"),
		filepath.Join(fixture.arsTLSDir, "ars-server-cert.pem"),
		filepath.Join(fixture.arsTLSDir, "ars-server-key.pem"),
	)), 0o600)
	writeFile(t, fixture.agsConfig, []byte(fmt.Sprintf(`{"dependencies":{"artifact_registry":{"base_url":"https://127.0.0.1:8442","client_cert_file":%q,"client_key_file":%q,"root_ca_file":%q}},"tls":{"cert_file":%q,"key_file":%q,"client_ca_file":%q}}`,
		filepath.Join(fixture.agsTLSDir, "ags-client-cert.pem"),
		filepath.Join(fixture.agsTLSDir, "ags-client-key.pem"),
		filepath.Join(fixture.agsTLSDir, "runtime-ca.pem"),
		filepath.Join(fixture.agsTLSDir, "ags-server-cert.pem"),
		filepath.Join(fixture.agsTLSDir, "ags-server-key.pem"),
		filepath.Join(fixture.agsTLSDir, "server-client-ca.pem"),
	)), 0o600)
	writeFile(t, fixture.esConfig, []byte(fmt.Sprintf(`{"dependencies":{"artifact_registry":{"base_url":"https://127.0.0.1:8442","client_cert_file":%q,"client_key_file":%q,"root_ca_file":%q},"execution_governance":{"base_url":"https://127.0.0.1:8443","client_cert_file":%q,"client_key_file":%q,"root_ca_file":%q,"server_name":"server.execution-governance.internal"}},"tls":{"cert_file":%q,"key_file":%q,"client_ca_file":%q}}`,
		filepath.Join(fixture.esTLSDir, "artifact-registry-client-cert.pem"),
		filepath.Join(fixture.esTLSDir, "artifact-registry-client-key.pem"),
		filepath.Join(fixture.esTLSDir, "artifact-registry-root-ca.pem"),
		filepath.Join(fixture.esTLSDir, "execution-governance-client-cert.pem"),
		filepath.Join(fixture.esTLSDir, "execution-governance-client-key.pem"),
		filepath.Join(fixture.esTLSDir, "execution-governance-root-ca.pem"),
		filepath.Join(fixture.esTLSDir, "es-server-cert.pem"),
		filepath.Join(fixture.esTLSDir, "es-server-key.pem"),
		filepath.Join(fixture.esTLSDir, "server-client-ca.pem"),
	)), 0o600)
	writeFile(t, fixture.egsConfig, []byte(fmt.Sprintf(`{"tls":{"cert_file":%q,"key_file":%q,"client_ca_file":%q}}`,
		filepath.Join(fixture.egsTLSDir, "egs-server-cert.pem"),
		filepath.Join(fixture.egsTLSDir, "egs-server-key.pem"),
		filepath.Join(fixture.egsTLSDir, "runtime-ca.pem"),
	)), 0o600)

	return fixture
}

func (f *remoteAlphaESServiceTLSFixture) helperEnv(extra ...string) []string {
	env := append(os.Environ(),
		"REMOTE_ALPHA_TEST_ALLOW_NON_ROOT=1",
		"REMOTE_ALPHA_TEST_BACKUP_ROOT="+f.backupRoot,
		"REMOTE_ALPHA_TEST_BACKUP_SENTINEL_PATH="+f.sentinel,
		"REMOTE_ALPHA_TEST_TIMESTAMP=20260525T030000Z",
		"remote_alpha_es_service_tls_renew_expected_ars_config_path="+f.arsConfig,
		"remote_alpha_es_service_tls_renew_expected_ags_config_path="+f.agsConfig,
		"remote_alpha_es_service_tls_renew_expected_es_config_path="+f.esConfig,
		"remote_alpha_es_service_tls_renew_expected_egs_config_path="+f.egsConfig,
		"remote_alpha_es_service_tls_renew_expected_ars_tls_dir="+f.arsTLSDir,
		"remote_alpha_es_service_tls_renew_expected_ags_tls_dir="+f.agsTLSDir,
		"remote_alpha_es_service_tls_renew_expected_es_tls_dir="+f.esTLSDir,
		"remote_alpha_es_service_tls_renew_expected_egs_tls_dir="+f.egsTLSDir,
	)
	env = append(env, extra...)
	return env
}

func runRemoteAlphaESServiceTLSRenew(t *testing.T, env []string, args ...string) (string, error) {
	t.Helper()
	cmd := exec.Command("/bin/bash", append([]string{remoteAlphaESServiceTLSRenewScriptPath()}, args...)...)
	cmd.Dir = executionSubstrateRepoRoot
	cmd.Env = env
	output, err := cmd.CombinedOutput()
	return string(output), err
}

func TestRemoteAlphaESServiceTLSStatusDetectsExpiredCertsAndSafeFields(t *testing.T) {
	fixture := setupRemoteAlphaESServiceTLSFixture(t, true)
	output, err := runRemoteAlphaESServiceTLSRenew(t, fixture.helperEnv(), "--status", "--summary-path", fixture.summary)
	if err == nil {
		t.Fatalf("expected expired status to fail, output=%s", output)
	}
	assertContainsAll(t, "expired status output", output, fixture.summary)
	assertContainsNone(t, "expired status output", output, "BEGIN PRIVATE KEY", "BEGIN RSA PRIVATE KEY", "BEGIN CERTIFICATE")

	summary := readJSONMap(t, fixture.summary)
	assertJSONPathEquals(t, summary, "mode.name", "status")
	assertJSONPathEquals(t, summary, "mode.non_mutating", true)
	assertJSONPathEquals(t, summary, "result.status", "fail")
	assertJSONPathEquals(t, summary, "security.private_key_pem_bodies_printed", false)
	assertJSONPathEquals(t, summary, "security.private_key_pem_bodies_in_summary", false)

	certs := summary["certificates"].([]any)
	if len(certs) == 0 {
		t.Fatalf("expected certificate records")
	}
	for _, item := range certs {
		record := item.(map[string]any)
		if record["subject"] == "" || record["issuer"] == "" || record["not_after"] == "" || record["fingerprint_sha256"] == "" || record["public_key_sha256"] == "" {
			t.Fatalf("status cert record missing safe public metadata: %#v", record)
		}
		if record["expired"] != true {
			t.Fatalf("expected expired cert record, got %#v", record)
		}
	}
	assertFileContainsNoSecrets(t, fixture.summary)
}

func TestRemoteAlphaESServiceTLSStatusDetectsValidCerts(t *testing.T) {
	fixture := setupRemoteAlphaESServiceTLSFixture(t, false)
	output, err := runRemoteAlphaESServiceTLSRenew(t, fixture.helperEnv(), "--status", "--summary-path", fixture.summary)
	if err != nil {
		t.Fatalf("expected valid status to pass: %v\n%s\nsummary=%s", err, output, readIfExists(fixture.summary))
	}
	summary := readJSONMap(t, fixture.summary)
	assertJSONPathEquals(t, summary, "result.status", "pass")
	assertJSONPathEquals(t, summary, "result.ok", true)
	for _, item := range summary["verification"].([]any) {
		record := item.(map[string]any)
		if record["status"] != "pass" {
			t.Fatalf("expected verification pass, got %#v", record)
		}
	}
	assertFileContainsNoSecrets(t, fixture.summary)
}

func TestRemoteAlphaESServiceTLSGovernanceStatusDetectsExpiredCertsAndSafeFields(t *testing.T) {
	fixture := setupRemoteAlphaESGovernanceTLSFixture(t, true)
	output, err := runRemoteAlphaESServiceTLSRenew(t, fixture.helperEnv(), "--scope", "execution-governance", "--status", "--summary-path", fixture.summary)
	if err == nil {
		t.Fatalf("expected expired governance status to fail, output=%s", output)
	}
	assertContainsAll(t, "expired governance status output", output, fixture.summary)
	assertContainsNone(t, "expired governance status output", output, "BEGIN PRIVATE KEY", "BEGIN RSA PRIVATE KEY", "BEGIN CERTIFICATE")

	summary := readJSONMap(t, fixture.summary)
	assertJSONPathEquals(t, summary, "scope.name", "execution-governance")
	assertJSONPathEquals(t, summary, "mode.name", "status")
	assertJSONPathEquals(t, summary, "mode.non_mutating", true)
	assertJSONPathEquals(t, summary, "result.status", "fail")
	assertJSONPathEquals(t, summary, "security.private_key_pem_bodies_printed", false)
	assertJSONPathEquals(t, summary, "security.private_key_pem_bodies_in_summary", false)

	certs := summary["certificates"].([]any)
	if len(certs) == 0 {
		t.Fatalf("expected governance certificate records")
	}
	for _, item := range certs {
		record := item.(map[string]any)
		if record["subject"] == "" || record["issuer"] == "" || record["not_after"] == "" || record["fingerprint_sha256"] == "" || record["public_key_sha256"] == "" {
			t.Fatalf("governance status cert record missing safe public metadata: %#v", record)
		}
		if record["expired"] != true {
			t.Fatalf("expected expired governance cert record, got %#v", record)
		}
	}
	assertFileContainsNoSecrets(t, fixture.summary)
}

func TestRemoteAlphaESServiceTLSGovernanceStatusDetectsValidCerts(t *testing.T) {
	fixture := setupRemoteAlphaESGovernanceTLSFixture(t, false)
	output, err := runRemoteAlphaESServiceTLSRenew(t, fixture.helperEnv(), "--scope", "execution-governance", "--status", "--summary-path", fixture.summary)
	if err != nil {
		t.Fatalf("expected valid governance status to pass: %v\n%s\nsummary=%s", err, output, readIfExists(fixture.summary))
	}
	summary := readJSONMap(t, fixture.summary)
	assertJSONPathEquals(t, summary, "scope.name", "execution-governance")
	assertJSONPathEquals(t, summary, "result.status", "pass")
	assertJSONPathEquals(t, summary, "result.ok", true)
	assertJSONPathEquals(t, summary, "topology.bounded_topology.egs_client_ca_same_runtime_ca_file", true)
	assertJSONPathEquals(t, summary, "topology.bounded_topology.ags_client_to_egs_material", "out_of_scope_absent")
	for _, item := range summary["verification"].([]any) {
		record := item.(map[string]any)
		if record["status"] != "pass" {
			t.Fatalf("expected governance verification pass, got %#v", record)
		}
	}
	assertFileContainsNoSecrets(t, fixture.summary)
}

func TestRemoteAlphaESServiceTLSRenewHelperRejectsSecretLikeArgs(t *testing.T) {
	fixture := setupRemoteAlphaESServiceTLSFixture(t, false)
	output, err := runRemoteAlphaESServiceTLSRenew(t, fixture.helperEnv(), "--private-key", "dummy")
	if err == nil {
		t.Fatalf("expected secret-like helper args to fail")
	}
	assertContainsAll(t, "secret arg refusal", output, "does not accept secret-like CLI arguments")
	assertContainsNone(t, "secret arg refusal", output, "dummy", "BEGIN PRIVATE KEY", "BEGIN CERTIFICATE")
}

func TestRemoteAlphaESServiceTLSRenewFakeApplyBacksUpInstallsRestartsAndVerifies(t *testing.T) {
	fixture := setupRemoteAlphaESServiceTLSFixture(t, true)
	fixture.writeFakeRenewCommands(t)
	env := fixture.helperEnv("PATH=" + fixture.localBin + string(os.PathListSeparator) + os.Getenv("PATH"))

	output, err := runRemoteAlphaESServiceTLSRenew(t, env, "--execute-renew", "--summary-path", fixture.summary)
	if err != nil {
		t.Fatalf("fake renew failed: %v\noutput=%s\nsummary=%s\ninstall=%s\nsystem=%s\ncurl=%s",
			err, output, readIfExists(fixture.summary), readIfExists(fixture.installLog), readIfExists(fixture.systemLog), readIfExists(fixture.curlLog))
	}
	assertContainsAll(t, "fake renew output", output, fixture.summary)
	assertContainsNone(t, "fake renew output", output, "BEGIN PRIVATE KEY", "BEGIN RSA PRIVATE KEY", "BEGIN CERTIFICATE")
	assertFileContainsNoSecrets(t, fixture.summary)

	backupDir := strings.TrimSpace(mustRead(t, fixture.sentinel))
	if backupDir == "" {
		t.Fatalf("expected backup sentinel")
	}
	for _, originalPath := range []string{
		filepath.Join(fixture.arsTLSDir, "runtime-ca.pem"),
		filepath.Join(fixture.arsTLSDir, "ars-server-key.pem"),
		filepath.Join(fixture.agsTLSDir, "ags-client-key.pem"),
		filepath.Join(fixture.esTLSDir, "artifact-registry-client-key.pem"),
	} {
		rel := strings.TrimPrefix(originalPath, string(os.PathSeparator))
		if _, err := os.Stat(filepath.Join(backupDir, "material", rel)); err != nil {
			t.Fatalf("expected backup material %s: %v", rel, err)
		}
	}

	installLog := mustRead(t, fixture.installLog)
	assertContainsAll(t, "install ownership/mode policy", installLog,
		"dir owner=root group=ars mode=0710 dest="+fixture.arsTLSDir,
		"dir owner=root group=ags mode=0710 dest="+fixture.agsTLSDir,
		"dir owner=root group=es mode=0710 dest="+fixture.esTLSDir,
		"file owner=root group=ars mode=0640 dest="+filepath.Join(fixture.arsTLSDir, "runtime-ca.pem"),
		"file owner=root group=ars mode=0640 dest="+filepath.Join(fixture.arsTLSDir, "ars-server-key.pem"),
		"file owner=root group=ags mode=0640 dest="+filepath.Join(fixture.agsTLSDir, "ags-client-key.pem"),
		"file owner=root group=es mode=0640 dest="+filepath.Join(fixture.esTLSDir, "artifact-registry-client-key.pem"),
	)
	assertContainsAll(t, "restart bounded service set", mustRead(t, fixture.systemLog),
		"restart ars.service",
		"restart ags.service",
		"restart es.service",
	)
	assertContainsNone(t, "restart forbidden service set", mustRead(t, fixture.systemLog),
		"egs.service",
		"vault.service",
		"spire",
		"nomad",
	)
	assertContainsAll(t, "curl probes", mustRead(t, fixture.curlLog),
		"--cert "+filepath.Join(fixture.agsTLSDir, "ags-client-cert.pem"),
		"--key "+filepath.Join(fixture.agsTLSDir, "ags-client-key.pem"),
		"--cert "+filepath.Join(fixture.esTLSDir, "artifact-registry-client-cert.pem"),
		"--key "+filepath.Join(fixture.esTLSDir, "artifact-registry-client-key.pem"),
		"https://server.artifact-registry.internal:8442/health",
	)

	summary := readJSONMap(t, fixture.summary)
	assertJSONPathEquals(t, summary, "result.status", "pass")
	assertJSONPathEquals(t, summary, "backup.status", "created")
	assertJSONPathEquals(t, summary, "backup.private_key_material_in_summary", false)
	assertJSONPathEquals(t, summary, "service_restarts.status", "pass")
	assertJSONPathEquals(t, summary, "mtls_probes.status", "pass")
	for _, item := range summary["verification"].([]any) {
		record := item.(map[string]any)
		if record["status"] != "pass" {
			t.Fatalf("expected post-renew verification pass, got %#v", record)
		}
	}
	for _, item := range summary["certificates"].([]any) {
		record := item.(map[string]any)
		notAfter, err := time.Parse(time.RFC3339, record["not_after"].(string))
		if err != nil {
			t.Fatalf("parse not_after %#v: %v", record, err)
		}
		if !notAfter.After(time.Now()) {
			t.Fatalf("expected renewed not_after in future, got %s", notAfter)
		}
	}
}

func TestRemoteAlphaESServiceTLSGovernanceRenewFakeApplyBacksUpInstallsRestartsAndVerifies(t *testing.T) {
	fixture := setupRemoteAlphaESGovernanceTLSFixture(t, true)
	fixture.writeFakeGovernanceRenewCommands(t)
	env := fixture.helperEnv("PATH=" + fixture.localBin + string(os.PathListSeparator) + os.Getenv("PATH"))

	output, err := runRemoteAlphaESServiceTLSRenew(t, env, "--scope", "execution-governance", "--execute-renew", "--summary-path", fixture.summary)
	if err != nil {
		t.Fatalf("fake governance renew failed: %v\noutput=%s\nsummary=%s\ninstall=%s\nsystem=%s\ncurl=%s",
			err, output, readIfExists(fixture.summary), readIfExists(fixture.installLog), readIfExists(fixture.systemLog), readIfExists(fixture.curlLog))
	}
	assertContainsAll(t, "fake governance renew output", output, fixture.summary)
	assertContainsNone(t, "fake governance renew output", output, "BEGIN PRIVATE KEY", "BEGIN RSA PRIVATE KEY", "BEGIN CERTIFICATE")
	assertFileContainsNoSecrets(t, fixture.summary)

	backupDir := strings.TrimSpace(mustRead(t, fixture.sentinel))
	if backupDir == "" {
		t.Fatalf("expected governance backup sentinel")
	}
	for _, originalPath := range []string{
		filepath.Join(fixture.egsTLSDir, "runtime-ca.pem"),
		filepath.Join(fixture.egsTLSDir, "egs-server-key.pem"),
		filepath.Join(fixture.esTLSDir, "execution-governance-client-key.pem"),
		filepath.Join(fixture.esTLSDir, "execution-governance-root-ca.pem"),
	} {
		rel := strings.TrimPrefix(originalPath, string(os.PathSeparator))
		if _, err := os.Stat(filepath.Join(backupDir, "material", rel)); err != nil {
			t.Fatalf("expected governance backup material %s: %v", rel, err)
		}
	}

	installLog := mustRead(t, fixture.installLog)
	assertContainsAll(t, "governance install ownership/mode policy", installLog,
		"dir owner=root group=egs mode=0710 dest="+fixture.egsTLSDir,
		"dir owner=root group=es mode=0710 dest="+fixture.esTLSDir,
		"file owner=root group=egs mode=0640 dest="+filepath.Join(fixture.egsTLSDir, "runtime-ca.pem"),
		"file owner=root group=egs mode=0640 dest="+filepath.Join(fixture.egsTLSDir, "egs-server-key.pem"),
		"file owner=root group=es mode=0640 dest="+filepath.Join(fixture.esTLSDir, "execution-governance-client-key.pem"),
		"file owner=root group=es mode=0640 dest="+filepath.Join(fixture.esTLSDir, "execution-governance-root-ca.pem"),
	)
	systemLog := mustRead(t, fixture.systemLog)
	assertContainsAll(t, "governance restart bounded service set", systemLog,
		"restart egs.service",
		"restart es.service",
		"is-active --quiet es.service",
	)
	assertContainsNone(t, "governance restart forbidden service set", systemLog,
		"ars.service",
		"ags.service",
		"vault.service",
		"spire",
		"nomad",
	)
	assertContainsAll(t, "governance curl probe", mustRead(t, fixture.curlLog),
		"--cert "+filepath.Join(fixture.esTLSDir, "execution-governance-client-cert.pem"),
		"--key "+filepath.Join(fixture.esTLSDir, "execution-governance-client-key.pem"),
		"https://server.execution-governance.internal:8443/v1/trust-model",
	)

	summary := readJSONMap(t, fixture.summary)
	assertJSONPathEquals(t, summary, "scope.name", "execution-governance")
	assertJSONPathEquals(t, summary, "result.status", "pass")
	assertJSONPathEquals(t, summary, "backup.status", "created")
	assertJSONPathEquals(t, summary, "backup.private_key_material_in_summary", false)
	assertJSONPathEquals(t, summary, "service_restarts.status", "pass")
	assertJSONPathEquals(t, summary, "service_restarts.es_service_active.status", "pass")
	assertJSONPathEquals(t, summary, "mtls_probes.status", "pass")
	for _, item := range summary["verification"].([]any) {
		record := item.(map[string]any)
		if record["status"] != "pass" {
			t.Fatalf("expected governance post-renew verification pass, got %#v", record)
		}
	}
	for _, item := range summary["certificates"].([]any) {
		record := item.(map[string]any)
		notAfter, err := time.Parse(time.RFC3339, record["not_after"].(string))
		if err != nil {
			t.Fatalf("parse governance not_after %#v: %v", record, err)
		}
		if !notAfter.After(time.Now()) {
			t.Fatalf("expected governance renewed not_after in future, got %s", notAfter)
		}
	}
}

func (f *remoteAlphaESServiceTLSFixture) writeFakeRenewCommands(t *testing.T) {
	t.Helper()
	writeExecutable(t, f.localBin, "install", fmt.Sprintf(`#!/usr/bin/env bash
set -euo pipefail
directory=false
owner=""
group=""
mode=""
operands=()
while [[ "$#" -gt 0 ]]; do
  case "$1" in
    -d)
      directory=true
      shift
      ;;
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
if [[ "${directory}" == "true" ]]; then
  for dest in "${operands[@]}"; do
    mkdir -p -- "${dest}"
    [[ -z "${mode}" ]] || chmod "${mode}" "${dest}"
    printf 'dir owner=%%s group=%%s mode=%%s dest=%%s\n' "${owner}" "${group}" "${mode}" "${dest}" >> %q
  done
  exit 0
fi
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
`, f.installLog, f.installLog))

	writeExecutable(t, f.localBin, "systemctl", fmt.Sprintf(`#!/usr/bin/env bash
set -euo pipefail
if [[ "$#" -eq 2 && "${1:-}" == "restart" ]]; then
  printf 'restart %%s\n' "${2:-}" >> %q
  exit 0
fi
echo "unexpected fake systemctl args: $*" >&2
exit 64
`, f.systemLog))

	writeExecutable(t, f.localBin, "curl", fmt.Sprintf(`#!/usr/bin/env bash
set -euo pipefail
printf '%%s\n' "$*" >> %q
printf '{"status":"ok"}\n'
`, f.curlLog))
}

func (f *remoteAlphaESServiceTLSFixture) writeFakeGovernanceRenewCommands(t *testing.T) {
	t.Helper()
	writeExecutable(t, f.localBin, "install", fmt.Sprintf(`#!/usr/bin/env bash
set -euo pipefail
directory=false
owner=""
group=""
mode=""
operands=()
while [[ "$#" -gt 0 ]]; do
  case "$1" in
    -d)
      directory=true
      shift
      ;;
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
if [[ "${directory}" == "true" ]]; then
  for dest in "${operands[@]}"; do
    mkdir -p -- "${dest}"
    [[ -z "${mode}" ]] || chmod "${mode}" "${dest}"
    printf 'dir owner=%%s group=%%s mode=%%s dest=%%s\n' "${owner}" "${group}" "${mode}" "${dest}" >> %q
  done
  exit 0
fi
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
`, f.installLog, f.installLog))

	writeExecutable(t, f.localBin, "systemctl", fmt.Sprintf(`#!/usr/bin/env bash
set -euo pipefail
printf '%%s\n' "$*" >> %q
if [[ "$#" -eq 2 && "${1:-}" == "restart" ]]; then
  case "${2:-}" in
    egs.service|es.service)
      exit 0
      ;;
  esac
fi
if [[ "$#" -eq 3 && "${1:-}" == "is-active" && "${2:-}" == "--quiet" && "${3:-}" == "es.service" ]]; then
  exit 0
fi
echo "unexpected fake governance systemctl args: $*" >&2
exit 64
`, f.systemLog))

	writeExecutable(t, f.localBin, "curl", fmt.Sprintf(`#!/usr/bin/env bash
set -euo pipefail
printf '%%s\n' "$*" >> %q
printf '{"status":"ok","runtime_trust":{}}\n'
`, f.curlLog))
}

func remoteAlphaGenerateCA(t *testing.T, notBefore, notAfter time.Time) ([]byte, *rsa.PrivateKey, []byte) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Remote Alpha Internal Runtime Root CA"},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create CA cert: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	return certPEM, key, keyPEM
}

func remoteAlphaGenerateLeaf(t *testing.T, caPEM []byte, caKey *rsa.PrivateKey, commonName string, eku x509.ExtKeyUsage, notBefore, notAfter time.Time) ([]byte, []byte) {
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
		t.Fatalf("generate leaf key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{eku},
		BasicConstraintsValid: true,
	}
	if eku == x509.ExtKeyUsageServerAuth {
		template.DNSNames = []string{commonName}
		template.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
	} else {
		template.DNSNames = []string{strings.TrimPrefix(commonName, "client.service.")}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, caCert, &key.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create leaf cert: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
}

func writeFile(t *testing.T, path string, data []byte, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, data, mode); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func readJSONMap(t *testing.T, path string) map[string]any {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read summary %s: %v", path, err)
	}
	var payload map[string]any
	if err := json.Unmarshal(data, &payload); err != nil {
		t.Fatalf("parse summary %s: %v", path, err)
	}
	return payload
}

func assertJSONPathEquals(t *testing.T, payload map[string]any, path string, expected any) {
	t.Helper()
	var current any = payload
	for _, part := range strings.Split(path, ".") {
		object, ok := current.(map[string]any)
		if !ok {
			t.Fatalf("json path %s reached non-object %#v", path, current)
		}
		current = object[part]
	}
	if fmt.Sprint(current) != fmt.Sprint(expected) {
		t.Fatalf("json path %s = %#v, want %#v", path, current, expected)
	}
}

func assertFileContainsNoSecrets(t *testing.T, path string) {
	t.Helper()
	text := mustRead(t, path)
	assertContainsNone(t, "secret-free file "+path, text,
		"-----BEGIN RSA PRIVATE KEY-----",
		"-----BEGIN PRIVATE KEY-----",
		"-----BEGIN EC PRIVATE KEY-----",
		"api_key",
		"vault_token",
		"root_token",
		"unseal_key",
	)
}
