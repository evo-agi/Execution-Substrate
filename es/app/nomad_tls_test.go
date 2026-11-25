package app_test

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	esconfig "execution-substrate/es/config"
)

// nomadTLSServerName is the DNS name in the server certificate
// scripts/70_linux_setup.sh issues, the name ES verifies.
const nomadTLSServerName = "server.global.nomad"

// supportedNomadTLSBlock is the tls block of the supported Nomad
// configuration for TLS material in dir, byte for byte as
// scripts/70_linux_setup.sh (dir "${NOMAD_TLS_DIR}") and
// .examples/config/nomad.hcl (dir /etc/nomad.d/tls) write it.
func supportedNomadTLSBlock(dir string) string {
	return fmt.Sprintf(`tls {
  http = true
  rpc  = true

  ca_file   = "%[1]s/ca.pem"
  cert_file = "%[1]s/server.pem"
  key_file  = "%[1]s/server-key.pem"

  verify_server_hostname = true
  verify_https_client    = false
  tls_min_version        = "tls13"
}
`, dir)
}

// nomadTLSMaterial is Nomad's HTTPS identity as scripts/70_linux_setup.sh
// issues it: a CA that signed only this server certificate (its key is gone),
// the certificate, its key, and the key's pin.
type nomadTLSMaterial struct {
	dir        string
	caFile     string
	certFile   string
	keyFile    string
	spkiSHA256 string
}

// nomadTLSSetupFunctions runs a shell snippet with the setup script's
// nomad_tls functions defined (and nothing else from the script).
func nomadTLSSetupFunctions(snippet string, env []string, args ...string) (string, error) {
	setup := filepath.Join(executionPlatformRepoRootPath(), "scripts", "70_linux_setup.sh")
	command := exec.Command("bash", append([]string{"-c",
		`set -euo pipefail; eval "$(sed -n '/^# BEGIN nomad_tls/,/^# END nomad_tls/p' "$1")"; shift; ` + snippet,
		"bash", setup}, args...)...)
	command.Env = append([]string{"PATH=" + os.Getenv("PATH")}, env...)
	output, err := command.CombinedOutput()
	return string(output), err
}

// issueNomadTLSMaterial issues Nomad TLS material into dir with the setup
// script's own nomad_tls_issue, so every test Nomad runs with what hosts run.
func issueNomadTLSMaterial(dir string) (nomadTLSMaterial, error) {
	if output, err := nomadTLSSetupFunctions(`nomad_tls_issue "$1"`, nil, dir); err != nil {
		return nomadTLSMaterial{}, fmt.Errorf("issue nomad tls material: %v: %s", err, strings.TrimSpace(output))
	}
	return loadNomadTLSMaterial(dir)
}

// loadNomadTLSMaterial reads material that nomad_tls_issue wrote into dir.
func loadNomadTLSMaterial(dir string) (nomadTLSMaterial, error) {
	material := nomadTLSMaterial{
		dir:      dir,
		caFile:   filepath.Join(dir, "ca.pem"),
		certFile: filepath.Join(dir, "server.pem"),
		keyFile:  filepath.Join(dir, "server-key.pem"),
	}
	certificate, err := readPEMCertificate(material.certFile)
	if err != nil {
		return nomadTLSMaterial{}, err
	}
	pin := sha256.Sum256(certificate.RawSubjectPublicKeyInfo)
	material.spkiSHA256 = hex.EncodeToString(pin[:])
	return material, nil
}

func readPEMCertificate(path string) (*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, rest := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" || len(strings.TrimSpace(string(rest))) != 0 {
		return nil, fmt.Errorf("%s does not hold one PEM certificate", path)
	}
	return x509.ParseCertificate(block.Bytes)
}

// clientTLSConfig trusts only the material's CA, over TLS 1.3: what the
// scripts and the nomad CLI use.
func (m nomadTLSMaterial) clientTLSConfig() *tls.Config {
	roots := x509.NewCertPool()
	if data, err := os.ReadFile(m.caFile); err == nil {
		roots.AppendCertsFromPEM(data)
	}
	return &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots}
}

// transport is a no-proxy transport that trusts only the material's CA.
func (m nomadTLSMaterial) transport() *http.Transport {
	return &http.Transport{Proxy: nil, TLSClientConfig: m.clientTLSConfig()}
}

// esNomadConfig is ES's Nomad config for a Nomad (or a stand-in) at baseURL
// that presents this material's certificate.
func (m nomadTLSMaterial) esNomadConfig(baseURL string, tokenFile string) esconfig.NomadConfig {
	return esconfig.NomadConfig{
		BaseURL:          baseURL,
		ServerName:       nomadTLSServerName,
		RootCAFile:       m.caFile,
		ServerSPKISHA256: m.spkiSHA256,
		Datacenter:       "dc1",
		TimeoutSeconds:   5,
		TokenFile:        tokenFile,
	}
}

// esNomadConfigJSON is esNomadConfig in es.json form.
func (m nomadTLSMaterial) esNomadConfigJSON(baseURL string, tokenFile string) map[string]any {
	return map[string]any{
		"base_url":           baseURL,
		"server_name":        nomadTLSServerName,
		"root_ca_file":       m.caFile,
		"server_spki_sha256": m.spkiSHA256,
		"datacenter":         "dc1",
		"timeout_seconds":    5,
		"token_file":         tokenFile,
	}
}

// startTLSServer serves handler over TLS 1.3 with the material's certificate
// (a stand-in for Nomad that ES and the scripts accept).
func (m nomadTLSMaterial) startTLSServer(handler http.Handler) (*httptest.Server, error) {
	certificate, err := tls.LoadX509KeyPair(m.certFile, m.keyFile)
	if err != nil {
		return nil, err
	}
	server := httptest.NewUnstartedServer(handler)
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate}}
	server.StartTLS()
	return server, nil
}

// startNomadTLSStandIn issues fresh material and serves handler with it: a
// fake Nomad that ES, the scripts and the ACL tool reach over TLS 1.3.
func startNomadTLSStandIn(t *testing.T, handler http.Handler) (*httptest.Server, nomadTLSMaterial) {
	t.Helper()
	material, err := issueNomadTLSMaterial(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	server, err := material.startTLSServer(handler)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(server.Close)
	return server, material
}

// testNomadRoots holds the CA of every test Nomad this process started, so
// helpers that take only a URL (nomadRawRequest) can reach any of them over
// TLS 1.3 without trusting system CAs.
var testNomadRoots = struct {
	sync.Mutex
	pool *x509.CertPool
}{pool: x509.NewCertPool()}

func registerTestNomadCA(caFile string) error {
	data, err := os.ReadFile(caFile)
	if err != nil {
		return err
	}
	testNomadRoots.Lock()
	defer testNomadRoots.Unlock()
	if !testNomadRoots.pool.AppendCertsFromPEM(data) {
		return fmt.Errorf("%s holds no certificate", caFile)
	}
	return nil
}

func testNomadRawTransport() *http.Transport {
	testNomadRoots.Lock()
	defer testNomadRoots.Unlock()
	return &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: testNomadRoots.pool.Clone()}}
}

// writeUnusedNomadCACertFile writes a CA file for a script run against a
// stand-in curl that never opens it.
func writeUnusedNomadCACertFile(dir string) string {
	path := filepath.Join(dir, "unused-nomad-ca.pem")
	_ = os.WriteFile(path, []byte("unused by the stand-in curl\n"), 0o644)
	return path
}
