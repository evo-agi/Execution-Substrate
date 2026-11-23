package scripts_test

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

func TestRemoteAlphaESServiceTLSRenewPublicWrapperHeld(t *testing.T) {
	for _, args := range [][]string{
		{"--status"},
		{"--execute-renew"},
		{"--scope", "execution-governance", "--status"},
		{"--scope", "execution-governance", "--execute-renew"},
	} {
		output, err := runRemoteAlphaESServiceTLSRenew(t, os.Environ(), args...)
		if err == nil {
			t.Fatalf("held public wrapper unexpectedly succeeded for %q", args)
		}
		assertContainsAll(t, "held public wrapper", output, "renewal is held")
		assertContainsNone(t, "held public wrapper", output,
			"BEGIN PRIVATE KEY", "BEGIN CERTIFICATE", "remote_alpha_es_service_tls_renew_main")
	}
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
