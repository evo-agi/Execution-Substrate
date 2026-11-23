package admission

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	esconfig "execution-substrate/es/config"
)

// testNomadServerName is the name in every test Nomad server certificate,
// the same name a supported Nomad's certificate carries.
const testNomadServerName = "server.global.nomad"

// testNomadPKI is a CA that issues test Nomad server certificates.
type testNomadPKI struct {
	ca     *x509.Certificate
	caKey  *ecdsa.PrivateKey
	caFile string
}

func newTestNomadPKI(t *testing.T) *testNomadPKI {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test Nomad CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	caFile := filepath.Join(t.TempDir(), "nomad-ca.pem")
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		t.Fatal(err)
	}
	return &testNomadPKI{ca: ca, caKey: key, caFile: caFile}
}

type testNomadServerCertOptions struct {
	key       *ecdsa.PrivateKey
	dnsNames  []string
	notAfter  time.Time
	selfIssue bool
}

// serverCert issues a server certificate (a new key unless one is given) for
// testNomadServerName and 127.0.0.1, valid for a day unless set otherwise.
func (p *testNomadPKI) serverCert(t *testing.T, opts testNomadServerCertOptions) (tls.Certificate, string) {
	t.Helper()
	key := opts.key
	if key == nil {
		var err error
		if key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader); err != nil {
			t.Fatal(err)
		}
	}
	dnsNames := opts.dnsNames
	if dnsNames == nil {
		dnsNames = []string{testNomadServerName, "localhost"}
	}
	notAfter := opts.notAfter
	if notAfter.IsZero() {
		notAfter = time.Now().Add(24 * time.Hour)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: dnsNames[0]},
		NotBefore:             time.Now().Add(-2 * time.Hour),
		NotAfter:              notAfter,
		DNSNames:              dnsNames,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	parent, signer := p.ca, any(p.caKey)
	if opts.selfIssue {
		parent, signer = template, key
	}
	der, err := x509.CreateCertificate(rand.Reader, template, parent, &key.PublicKey, signer)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pin := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, hex.EncodeToString(pin[:])
}

// startTestNomadTLSServer serves handler over TLS with certificate, at most
// up to maxVersion when it is not zero.
func startTestNomadTLSServer(t *testing.T, handler http.Handler, certificate tls.Certificate, maxVersion uint16) *httptest.Server {
	t.Helper()
	server := httptest.NewUnstartedServer(handler)
	server.TLS = &tls.Config{Certificates: []tls.Certificate{certificate}, MaxVersion: maxVersion}
	server.StartTLS()
	t.Cleanup(server.Close)
	return server
}

// testNomadTLSConfigFor returns the HTTPS part of an ES Nomad config for a
// test server: its URL, the test server name, the CA file and the pin.
func testNomadTLSConfigFor(server *httptest.Server, pki *testNomadPKI, pin string) esconfig.NomadConfig {
	return esconfig.NomadConfig{BaseURL: server.URL, ServerName: testNomadServerName, RootCAFile: pki.caFile, ServerSPKISHA256: pin}
}

// newTLSTestNomadClient builds a nomadClient for server with ES's own TLS
// configuration and transport, so every test through it exercises the
// production HTTPS checks.
func newTLSTestNomadClient(t *testing.T, cfg esconfig.NomadConfig) *nomadClient {
	t.Helper()
	tlsConfig, err := newNomadTLSConfig(cfg)
	if err != nil {
		t.Fatalf("nomad TLS config: %v", err)
	}
	baseURL, err := url.Parse(cfg.BaseURL)
	if err != nil {
		t.Fatal(err)
	}
	return &nomadClient{
		baseURL:    baseURL,
		datacenter: "dc1",
		token:      testNomadToken,
		client:     &http.Client{Transport: newNomadTransport(tlsConfig), CheckRedirect: refuseNomadRedirect, Timeout: 10 * time.Second},
	}
}

// ES sends its token only to the Nomad whose certificate chains to the
// configured CA, names the configured server, and carries the pinned key,
// over TLS 1.3. Every other server gets no request at all.
func TestNomadClientSendsItsTokenOnlyToThePinnedNomadOverTLS13(t *testing.T) {
	pki := newTestNomadPKI(t)
	pinnedKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pinnedCert, pin := pki.serverCert(t, testNomadServerCertOptions{key: pinnedKey})

	var good atomic.Int32
	goodServer := startTestNomadTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		good.Add(1)
		if request.TLS == nil || request.TLS.Version != tls.VersionTLS13 {
			t.Errorf("request not over TLS 1.3: %+v", request.TLS)
		}
		assertNomadJobRequestAuthenticated(t, request)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"EvalID":"eval-1"}`))
	}), pinnedCert, 0)
	client := newTLSTestNomadClient(t, testNomadTLSConfigFor(goodServer, pki, pin))
	if evalID, err := client.submitJob(context.Background(), map[string]any{"Job": map[string]any{"ID": "tls-probe"}}); err != nil || evalID != "eval-1" {
		t.Fatalf("submit to the pinned Nomad: eval=%q err=%v", evalID, err)
	}
	if good.Load() != 1 {
		t.Fatalf("pinned Nomad saw %d requests", good.Load())
	}

	otherCA := newTestNomadPKI(t)
	sameCAOtherKey, _ := pki.serverCert(t, testNomadServerCertOptions{})
	otherCAPinnedKey, _ := otherCA.serverCert(t, testNomadServerCertOptions{key: pinnedKey})
	selfIssuedPinnedKey, _ := pki.serverCert(t, testNomadServerCertOptions{key: pinnedKey, selfIssue: true})
	otherNamePinnedKey, _ := pki.serverCert(t, testNomadServerCertOptions{key: pinnedKey, dnsNames: []string{"client.global.nomad"}})
	expiredPinnedKey, _ := pki.serverCert(t, testNomadServerCertOptions{key: pinnedKey, notAfter: time.Now().Add(-time.Hour)})

	for _, test := range []struct {
		name       string
		cert       tls.Certificate
		maxVersion uint16
		plainHTTP  bool
	}{
		{name: "same CA, another key", cert: sameCAOtherKey},
		{name: "pinned key, another CA", cert: otherCAPinnedKey},
		{name: "pinned key, self-issued", cert: selfIssuedPinnedKey},
		{name: "pinned key, another server name", cert: otherNamePinnedKey},
		{name: "pinned key, expired", cert: expiredPinnedKey},
		{name: "pinned certificate, TLS 1.2 only", cert: pinnedCert, maxVersion: tls.VersionTLS12},
		{name: "plain HTTP", plainHTTP: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			var requests atomic.Int32
			handler := http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
				requests.Add(1)
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"EvalID":"impostor"}`))
			})
			var server *httptest.Server
			cfg := esconfig.NomadConfig{}
			if test.plainHTTP {
				server = httptest.NewServer(handler)
				t.Cleanup(server.Close)
				cfg = testNomadTLSConfigFor(server, pki, pin)
				cfg.BaseURL = strings.Replace(server.URL, "http://", "https://", 1)
			} else {
				server = startTestNomadTLSServer(t, handler, test.cert, test.maxVersion)
				cfg = testNomadTLSConfigFor(server, pki, pin)
			}
			client := newTLSTestNomadClient(t, cfg)
			if accessErr := client.verifyAccessControl(context.Background()); accessErr == nil ||
				accessErr.Status != http.StatusServiceUnavailable || accessErr.Code != codeExecutionRuntimeUnavailable {
				t.Fatalf("access control check against an impostor = %+v", accessErr)
			}
			if _, err := client.submitJob(context.Background(), map[string]any{"Job": map[string]any{"ID": "impostor-probe"}}); err == nil {
				t.Fatal("submit to an impostor succeeded")
			}
			if requests.Load() != 0 {
				t.Fatalf("an impostor Nomad received %d request(s)", requests.Load())
			}
		})
	}
}

func TestNewNomadClientRefusesWithoutAUsableRootCAOrPin(t *testing.T) {
	pki := newTestNomadPKI(t)
	_, pin := pki.serverCert(t, testNomadServerCertOptions{})
	tokenFile := writeNomadTokenFile(t, privateNomadTokenDir(t), testNomadToken, 0o400)
	base := minimalNomadConfigForTest(t, tokenFile)
	base.RootCAFile, base.ServerSPKISHA256 = pki.caFile, pin
	if client, err := newNomadClient(base); err != nil || client == nil {
		t.Fatalf("client refused a usable CA and pin: %v", err)
	}

	dir := t.TempDir()
	write := func(name string, data []byte) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, data, 0o644); err != nil {
			t.Fatal(err)
		}
		return path
	}
	caPEM, err := os.ReadFile(pki.caFile)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name string
		edit func(*esconfig.NomadConfig)
	}{
		{"missing CA file", func(c *esconfig.NomadConfig) { c.RootCAFile = filepath.Join(dir, "absent.pem") }},
		{"CA path is a directory", func(c *esconfig.NomadConfig) { c.RootCAFile = dir }},
		{"empty CA file", func(c *esconfig.NomadConfig) { c.RootCAFile = write("empty.pem", nil) }},
		{"key instead of certificate", func(c *esconfig.NomadConfig) {
			c.RootCAFile = write("key.pem", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte{1, 2, 3}}))
		}},
		{"certificate followed by other data", func(c *esconfig.NomadConfig) {
			c.RootCAFile = write("trailing.pem", append(append([]byte{}, caPEM...), []byte("not pem\n")...))
		}},
		{"certificate with PEM headers", func(c *esconfig.NomadConfig) {
			block, _ := pem.Decode(caPEM)
			block.Headers = map[string]string{"Proc-Type": "4,ENCRYPTED"}
			c.RootCAFile = write("headers.pem", pem.EncodeToMemory(block))
		}},
		{"certificate that does not parse", func(c *esconfig.NomadConfig) {
			c.RootCAFile = write("garbage.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("garbage")}))
		}},
		{"oversized CA file", func(c *esconfig.NomadConfig) {
			c.RootCAFile = write("huge.pem", append(append([]byte{}, caPEM...), make([]byte, nomadRootCAFileMaxBytes)...))
		}},
		{"upper-case pin", func(c *esconfig.NomadConfig) { c.ServerSPKISHA256 = strings.ToUpper(pin) }},
		{"short pin", func(c *esconfig.NomadConfig) { c.ServerSPKISHA256 = pin[:62] }},
	} {
		t.Run(test.name, func(t *testing.T) {
			cfg := base
			test.edit(&cfg)
			if client, err := newNomadClient(cfg); err == nil || client != nil {
				t.Fatalf("client built: %v", err)
			}
		})
	}
}
