package app_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	esconfig "execution-substrate/es/config"
)

// Nomad's HTTPS identity as scripts/70_linux_setup.sh issues and checks it,
// and as scripts/internal/nomad_tls_identity.py observes it for readiness.

// TestSetupIssuesNomadTLSMaterialAsSupported checks every property of the
// material nomad_tls_issue writes: a P-256 CA limited to signing one level
// (pathlen 0) whose key is gone, a server certificate for Nomad's names that
// verifies under it, the matching key readable only by its owner, and a pin
// the shell computes exactly as ES does.
func TestSetupIssuesNomadTLSMaterialAsSupported(t *testing.T) {
	work := t.TempDir()
	dir := filepath.Join(t.TempDir(), "tls")
	if output, err := nomadTLSSetupFunctions(`nomad_tls_issue "$1"`, []string{"TMPDIR=" + work}, dir); err != nil {
		t.Fatalf("nomad_tls_issue: %v: %s", err, output)
	}
	// The CA key lived only in the work directory, which is gone.
	if entries, err := os.ReadDir(work); err != nil || len(entries) != 0 {
		t.Fatalf("issuance left files in its work directory: entries=%v err=%v", entries, err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	if !reflect.DeepEqual(names, []string{"ca.pem", "server-key.pem", "server.pem"}) {
		t.Fatalf("issued files = %v, want only ca.pem, server-key.pem and server.pem", names)
	}
	for name, want := range map[string]os.FileMode{".": 0o755, "ca.pem": 0o644, "server.pem": 0o644, "server-key.pem": 0o600} {
		info, err := os.Lstat(filepath.Join(dir, name))
		if err != nil || info.Mode().Perm() != want || (name != "." && !info.Mode().IsRegular()) {
			t.Fatalf("%s: mode %v err %v, want %v", name, info.Mode(), err, want)
		}
	}
	if data, err := os.ReadFile(filepath.Join(dir, "server-key.pem")); err != nil || strings.Count(string(data), "-----BEGIN ") != 1 {
		t.Fatalf("server-key.pem must hold exactly one key: err=%v", err)
	}

	ca, err := readPEMCertificate(filepath.Join(dir, "ca.pem"))
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := readPEMCertificate(filepath.Join(dir, "server.pem"))
	if err != nil {
		t.Fatal(err)
	}
	const validity = 825 * 24 * time.Hour
	for label, certificate := range map[string]*x509.Certificate{"CA": ca, "server": leaf} {
		key, ok := certificate.PublicKey.(*ecdsa.PublicKey)
		if !ok || key.Curve != elliptic.P256() {
			t.Fatalf("%s key is not ECDSA P-256: %T", label, certificate.PublicKey)
		}
		if lifetime := certificate.NotAfter.Sub(certificate.NotBefore); lifetime < validity-time.Hour || lifetime > validity+time.Hour {
			t.Fatalf("%s certificate is valid for %v, want 825 days", label, lifetime)
		}
	}
	if !ca.IsCA || !ca.BasicConstraintsValid || ca.MaxPathLen != 0 || !ca.MaxPathLenZero || ca.KeyUsage != x509.KeyUsageCertSign ||
		ca.Subject.CommonName != "Execution Substrate Nomad CA" {
		t.Fatalf("CA = IsCA %v pathlen %d/%v usage %v subject %q", ca.IsCA, ca.MaxPathLen, ca.MaxPathLenZero, ca.KeyUsage, ca.Subject.CommonName)
	}
	wantIPs := []string{"127.0.0.1", "::1"}
	var gotIPs []string
	for _, ip := range leaf.IPAddresses {
		gotIPs = append(gotIPs, ip.String())
	}
	if leaf.IsCA || !leaf.BasicConstraintsValid || leaf.KeyUsage != x509.KeyUsageDigitalSignature ||
		!reflect.DeepEqual(leaf.ExtKeyUsage, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}) ||
		!reflect.DeepEqual(leaf.DNSNames, []string{nomadTLSServerName, "localhost"}) || !reflect.DeepEqual(gotIPs, wantIPs) ||
		leaf.Subject.CommonName != nomadTLSServerName || leaf.SerialNumber.BitLen() < 64 {
		t.Fatalf("server certificate = IsCA %v usage %v ext %v DNS %v IP %v CN %q serial bits %d", leaf.IsCA, leaf.KeyUsage,
			leaf.ExtKeyUsage, leaf.DNSNames, gotIPs, leaf.Subject.CommonName, leaf.SerialNumber.BitLen())
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	for _, name := range append([]string{nomadTLSServerName, "localhost"}, wantIPs...) {
		if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: name, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
			t.Fatalf("server certificate does not verify for %s: %v", name, err)
		}
	}
	if _, err := tls.LoadX509KeyPair(filepath.Join(dir, "server.pem"), filepath.Join(dir, "server-key.pem")); err != nil {
		t.Fatalf("server key does not match the certificate: %v", err)
	}

	pin := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
	output, err := nomadTLSSetupFunctions(`nomad_tls_spki_sha256 "$1"`, nil, filepath.Join(dir, "server.pem"))
	if err != nil || output != hex.EncodeToString(pin[:])+"\n" {
		t.Fatalf("shell pin = %q (%v), want ES's %s", output, err, hex.EncodeToString(pin[:]))
	}
	if output, err := nomadTLSSetupFunctions(`nomad_tls_material_ok "$1"`, nil, dir); err != nil {
		t.Fatalf("nomad_tls_material_ok refused fresh material: %v %s", err, output)
	}

	// Reissuing replaces all three: a new key (so a new pin) under a new CA
	// that the old certificate does not chain to.
	if output, err := nomadTLSSetupFunctions(`nomad_tls_issue "$1"`, nil, dir); err != nil {
		t.Fatalf("reissue: %v: %s", err, output)
	}
	reissued, err := readPEMCertificate(filepath.Join(dir, "server.pem"))
	if err != nil {
		t.Fatal(err)
	}
	newCA, err := readPEMCertificate(filepath.Join(dir, "ca.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if sha256.Sum256(reissued.RawSubjectPublicKeyInfo) == pin {
		t.Fatal("reissue kept the server key")
	}
	newRoots := x509.NewCertPool()
	newRoots.AddCert(newCA)
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: newRoots, DNSName: nomadTLSServerName}); err == nil {
		t.Fatal("the old server certificate chains to the reissued CA")
	}
}

// nomad_tls_material_ok keeps material only when it is still what setup
// issued; each departure on its own makes setup issue new material.
func TestSetupReissuesNomadTLSMaterialThatIsNotSound(t *testing.T) {
	other, err := issueNomadTLSMaterial(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ok := func(dir string, prelude string) error {
		output, err := nomadTLSSetupFunctions(prelude+`nomad_tls_material_ok "$1"`, nil, dir)
		if err != nil && strings.TrimSpace(output) != "" {
			t.Fatalf("nomad_tls_material_ok printed output: %s", output)
		}
		return err
	}
	copyFile := func(t *testing.T, from string, to string, mode os.FileMode) {
		t.Helper()
		data, err := os.ReadFile(from)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(to); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(to, data, mode); err != nil {
			t.Fatal(err)
		}
	}
	for _, test := range []struct {
		name    string
		prelude string
		tamper  func(t *testing.T, m nomadTLSMaterial)
	}{
		{"key readable by others", "", func(t *testing.T, m nomadTLSMaterial) {
			if err := os.Chmod(m.keyFile, 0o644); err != nil {
				t.Fatal(err)
			}
		}},
		{"certificate is a symbolic link", "", func(t *testing.T, m nomadTLSMaterial) {
			moved := m.certFile + ".real"
			if err := os.Rename(m.certFile, moved); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(moved, m.certFile); err != nil {
				t.Fatal(err)
			}
		}},
		{"CA missing", "", func(t *testing.T, m nomadTLSMaterial) {
			if err := os.Remove(m.caFile); err != nil {
				t.Fatal(err)
			}
		}},
		{"CA from other material", "", func(t *testing.T, m nomadTLSMaterial) { copyFile(t, other.caFile, m.caFile, 0o644) }},
		{"key from other material", "", func(t *testing.T, m nomadTLSMaterial) { copyFile(t, other.keyFile, m.keyFile, 0o600) }},
		{"certificate inside the renewal window", "NOMAD_TLS_RENEW_DAYS=826; ", func(*testing.T, nomadTLSMaterial) {}},
	} {
		t.Run(test.name, func(t *testing.T) {
			material, err := issueNomadTLSMaterial(filepath.Join(t.TempDir(), "tls"))
			if err != nil {
				t.Fatal(err)
			}
			if err := ok(material.dir, ""); err != nil {
				t.Fatalf("fresh material refused: %v", err)
			}
			test.tamper(t, material)
			if err := ok(material.dir, test.prelude); err == nil {
				t.Fatal("nomad_tls_material_ok kept material that is not sound")
			}
		})
	}

	// The names: a certificate otherwise sound but without one of Nomad's
	// names is replaced. The control with every name is kept, so only the
	// missing name causes the refusal.
	for _, test := range []struct {
		name string
		dns  []string
		ips  []string
		keep bool
	}{
		{"every name", []string{nomadTLSServerName, "localhost"}, []string{"127.0.0.1", "::1"}, true},
		{"no server name", []string{"localhost"}, []string{"127.0.0.1", "::1"}, false},
		{"no localhost", []string{nomadTLSServerName}, []string{"127.0.0.1", "::1"}, false},
		{"no IPv4 loopback", []string{nomadTLSServerName, "localhost"}, []string{"::1"}, false},
		{"no IPv6 loopback", []string{nomadTLSServerName, "localhost"}, []string{"127.0.0.1"}, false},
	} {
		t.Run("names: "+test.name, func(t *testing.T) {
			dir := writeGoIssuedNomadTLSMaterial(t, test.dns, test.ips)
			if err := ok(dir, ""); (err == nil) != test.keep {
				t.Fatalf("nomad_tls_material_ok = %v, want kept %v", err, test.keep)
			}
		})
	}
}

// writeGoIssuedNomadTLSMaterial writes material shaped like setup's (P-256,
// a pathlen-0 CA, 825 days) with the given server names, to test the
// checks one name at a time.
func writeGoIssuedNomadTLSMaterial(t *testing.T, dnsNames []string, ips []string) string {
	t.Helper()
	newKey := func() *ecdsa.PrivateKey {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return key
	}
	caKey, serverKey := newKey(), newKey()
	now := time.Now()
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test Nomad CA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(825 * 24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, MaxPathLenZero: true, KeyUsage: x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	var addresses []net.IP
	for _, ip := range ips {
		addresses = append(addresses, net.ParseIP(ip))
	}
	serverTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: nomadTLSServerName},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(825 * 24 * time.Hour),
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		DNSNames:    dnsNames, IPAddresses: addresses,
	}
	serverDER, err := x509.CreateCertificate(rand.Reader, serverTemplate, caTemplate, &serverKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(serverKey)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "tls")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, file := range map[string]struct {
		block *pem.Block
		mode  os.FileMode
	}{
		"ca.pem":         {&pem.Block{Type: "CERTIFICATE", Bytes: caDER}, 0o644},
		"server.pem":     {&pem.Block{Type: "CERTIFICATE", Bytes: serverDER}, 0o644},
		"server-key.pem": {&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}, 0o600},
	} {
		if err := os.WriteFile(filepath.Join(dir, name), pem.EncodeToMemory(file.block), file.mode); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// runNomadTLSIdentity runs scripts/internal/nomad_tls_identity.py.
func runNomadTLSIdentity(t *testing.T, args ...string) (string, error) {
	t.Helper()
	tool := filepath.Join(executionPlatformRepoRoot(t), "scripts", "internal", "nomad_tls_identity.py")
	command := exec.Command("python3", append([]string{"-I", tool}, args...)...)
	command.Env = []string{"PATH=" + os.Getenv("PATH")}
	output, err := command.CombinedOutput()
	return string(output), err
}

// Readiness makes ES's own checks against the running Nomad: TLS 1.3, the
// configured CA and name, and the pinned key, plus the address the operator
// checks use and the certificate's remaining validity. pin prints the value
// for nomad.server_spki_sha256 only for a certificate from the given CA.
// Neither sends a request.
func TestNomadTLSIdentityChecksWhatESChecks(t *testing.T) {
	var requests atomic.Int32
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests.Add(1) })
	server, material := startNomadTLSStandIn(t, handler)
	other, err := issueNomadTLSMaterial(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	tokenFile := filepath.Join(t.TempDir(), "unused-token")
	writeConfig := func(t *testing.T, nomad map[string]any) string {
		t.Helper()
		path := filepath.Join(t.TempDir(), "es.json")
		data, err := json.Marshal(map[string]any{"nomad": nomad})
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}

	output, err := runNomadTLSIdentity(t, "check", writeConfig(t, material.esNomadConfigJSON(server.URL, tokenFile)), server.URL)
	leaf, readErr := readPEMCertificate(material.certFile)
	if readErr != nil {
		t.Fatal(readErr)
	}
	daysLeft := int(time.Until(leaf.NotAfter).Hours() / 24)
	want := "nomad tls: tls=1.3 server_name=" + nomadTLSServerName + " key=pinned expires=" + leaf.NotAfter.UTC().Format("2006-01-02") +
		" days_left=" + strconv.Itoa(daysLeft) + "\n"
	if err != nil || output != want {
		t.Fatalf("check = %q (%v), want %q", output, err, want)
	}
	if output, err := runNomadTLSIdentity(t, "pin", server.URL, material.caFile, nomadTLSServerName); err != nil || output != material.spkiSHA256+"\n" {
		t.Fatalf("pin = %q (%v), want %s", output, err, material.spkiSHA256)
	}

	tls12 := httptestTLS12Server(t, material, handler)
	port := strings.TrimPrefix(server.URL, "https://127.0.0.1:")
	for _, test := range []struct {
		name   string
		change func(map[string]any)
		addr   string
		want   string
	}{
		{"another key pinned", func(c map[string]any) { c["server_spki_sha256"] = other.spkiSHA256 },
			"", "nomad tls: Nomad's server key does not match nomad.server_spki_sha256 (Nomad presents " + material.spkiSHA256 + ")"},
		{"pin not lowercase hex", func(c map[string]any) { c["server_spki_sha256"] = strings.ToUpper(material.spkiSHA256) },
			"", "nomad.server_spki_sha256 must be 64 lowercase hex characters"},
		{"another CA", func(c map[string]any) { c["root_ca_file"] = other.caFile }, "", "Nomad's certificate does not verify under the CA"},
		{"CA file missing", func(c map[string]any) { c["root_ca_file"] = filepath.Join(t.TempDir(), "missing.pem") },
			"", "nomad.root_ca_file is not a readable CA certificate file"},
		{"another server name", func(c map[string]any) { c["server_name"] = "client.global.nomad" }, "", "does not verify under the CA for client.global.nomad"},
		{"plain HTTP address", func(c map[string]any) { c["base_url"] = "http://127.0.0.1:" + port },
			"http://127.0.0.1:" + port, "nomad.base_url must be https://<loopback IP>:<port>"},
		{"host name address", func(c map[string]any) { c["base_url"] = "https://localhost:" + port },
			"https://localhost:" + port, "nomad.base_url must be https://<loopback IP>:<port>"},
		{"address other than the checks use", nil, "https://127.0.0.1:1", "is not the Nomad address the checks use"},
		{"Nomad offers only TLS 1.2", func(c map[string]any) { c["base_url"] = tls12.URL }, tls12.URL, "nomad tls: no TLS 1.3 connection to " + tls12.URL},
	} {
		t.Run(test.name, func(t *testing.T) {
			config := material.esNomadConfigJSON(server.URL, tokenFile)
			if test.change != nil {
				test.change(config)
			}
			addr := test.addr
			if addr == "" {
				addr = server.URL
			}
			output, err := runNomadTLSIdentity(t, "check", writeConfig(t, config), addr)
			if err == nil || !strings.Contains(output, test.want) {
				t.Fatalf("check did not refuse with %q: %v output=%s", test.want, err, output)
			}
		})
	}
	t.Run("pin refuses a certificate from another CA", func(t *testing.T) {
		if output, err := runNomadTLSIdentity(t, "pin", server.URL, other.caFile, nomadTLSServerName); err == nil || strings.Contains(output, material.spkiSHA256) {
			t.Fatalf("pin printed a key from a certificate another CA signed: %v output=%s", err, output)
		}
	})

	// A certificate with fewer than 14 days left is refused, so the operator
	// reissues it before ES and the scripts stop trusting Nomad.
	t.Run("certificate about to expire", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "tls")
		if output, err := nomadTLSSetupFunctions(`NOMAD_TLS_VALID_DAYS=10; nomad_tls_issue "$1"`, nil, dir); err != nil {
			t.Fatalf("issue short-lived material: %v: %s", err, output)
		}
		expiring, err := loadNomadTLSMaterial(dir)
		if err != nil {
			t.Fatal(err)
		}
		expiringServer, err := expiring.startTLSServer(handler)
		if err != nil {
			t.Fatal(err)
		}
		defer expiringServer.Close()
		output, err := runNomadTLSIdentity(t, "check", writeConfig(t, expiring.esNomadConfigJSON(expiringServer.URL, tokenFile)), expiringServer.URL)
		if err == nil || !strings.Contains(output, "rerun scripts/70_linux_setup.sh to issue a new one") {
			t.Fatalf("check accepted a certificate with 10 days left: %v output=%s", err, output)
		}
	})
	if got := requests.Load(); got != 0 {
		t.Fatalf("nomad_tls_identity.py sent %d request(s)", got)
	}
}

// httptestTLS12Server serves handler with material's certificate but at most
// TLS 1.2.
func httptestTLS12Server(t *testing.T, material nomadTLSMaterial, handler http.Handler) *httptest.Server {
	t.Helper()
	certificate, err := tls.LoadX509KeyPair(material.certFile, material.keyFile)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(handler)
	server.TLS = &tls.Config{MaxVersion: tls.VersionTLS12, Certificates: []tls.Certificate{certificate}}
	server.StartTLS()
	t.Cleanup(server.Close)
	return server
}

// ES refuses a Nomad that presents a certificate other than the pinned one,
// one from another CA or one for another name, before it registers
// anything: the handshake fails before ES sends a request, so submit refuses
// as execution runtime unavailable, and the real Nomad gets no job.
func TestSubmitRefusesANomadOtherThanThePinnedOne(t *testing.T) {
	other, err := issueNomadTLSMaterial(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name   string
		change func(*esconfig.NomadConfig)
	}{
		{"another key pinned", func(c *esconfig.NomadConfig) { c.ServerSPKISHA256 = other.spkiSHA256 }},
		{"another CA trusted", func(c *esconfig.NomadConfig) { c.RootCAFile = other.caFile }},
		{"another server name", func(c *esconfig.NomadConfig) { c.ServerName = "client.global.nomad" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			stack := startRuntimeIdentitySubmitStackWithOptions(t, submitStackOptions{nomadESConfig: test.change})
			status, payload := submitExecutionExpectingRefusal(t, stack)
			if status != http.StatusServiceUnavailable || payload["code"] != "execution_runtime_unavailable" ||
				payload["error"] != "execution runtime is unavailable" {
				t.Fatalf("submit returned HTTP %d %v, want 503 execution_runtime_unavailable", status, payload)
			}
			if jobs := nomadJobIDsInEveryNamespace(t, stack.nomad); len(jobs) != 0 {
				t.Fatalf("refused submit registered jobs: %v", jobs)
			}
		})
	}
}

// On a host, setup issues and checks the material as root
// (nomad_tls_as_root): every file is root-owned, the key readable by root
// alone, and material another user owns is not kept.
func TestSetupIssuesNomadTLSMaterialAsRoot(t *testing.T) {
	if output, err := exec.Command("sudo", "-n", "true").CombinedOutput(); err != nil {
		t.Skipf("needs passwordless sudo, as setup uses: %v: %s", err, strings.TrimSpace(string(output)))
	}
	dir := filepath.Join(t.TempDir(), "tls")
	t.Cleanup(func() {
		if output, err := exec.Command("sudo", "-n", "rm", "-rf", "--", dir).CombinedOutput(); err != nil {
			t.Errorf("remove root-owned TLS material: %v: %s", err, output)
		}
	})
	if output, err := nomadTLSSetupFunctions(`nomad_tls_as_root nomad_tls_issue "$1"`, nil, dir); err != nil {
		t.Fatalf("nomad_tls_as_root nomad_tls_issue: %v: %s", err, output)
	}
	for name, mode := range map[string]os.FileMode{"ca.pem": 0o644, "server.pem": 0o644, "server-key.pem": 0o600} {
		info, err := os.Lstat(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != 0 || stat.Gid != 0 || info.Mode().Perm() != mode {
			t.Fatalf("%s: mode %v owner %v, want %v root:root", name, info.Mode(), info.Sys(), mode)
		}
	}
	if output, err := nomadTLSSetupFunctions(`nomad_tls_as_root nomad_tls_material_ok "$1"`, nil, dir); err != nil {
		t.Fatalf("root refused the material it issued: %v: %s", err, output)
	}
	if os.Geteuid() != 0 {
		if _, err := os.ReadFile(filepath.Join(dir, "server-key.pem")); err == nil {
			t.Fatal("the server key is readable by a user other than root")
		}
		if output, err := nomadTLSSetupFunctions(`nomad_tls_material_ok "$1"`, nil, dir); err == nil {
			t.Fatalf("material owned by root was kept for another user: %s", output)
		}
		// Material another user owns is not kept by root, even when root
		// can read all of it.
		userOwned, err := issueNomadTLSMaterial(filepath.Join(t.TempDir(), "tls"))
		if err != nil {
			t.Fatal(err)
		}
		if output, err := nomadTLSSetupFunctions(`nomad_tls_as_root nomad_tls_material_ok "$1"`, nil, userOwned.dir); err == nil {
			t.Fatalf("root kept material owned by another user: %s", output)
		}
	}
	output, err := nomadTLSSetupFunctions(`nomad_tls_spki_sha256 "$1"`, nil, filepath.Join(dir, "server.pem"))
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := readPEMCertificate(filepath.Join(dir, "server.pem"))
	if err != nil {
		t.Fatal(err)
	}
	pin := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
	if output != hex.EncodeToString(pin[:])+"\n" {
		t.Fatalf("shell pin of root's certificate = %q, want %x", output, pin)
	}
}
