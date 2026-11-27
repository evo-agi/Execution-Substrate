package app_test

// The Remote Alpha signing key rotation
// (scripts/internal/remote_alpha_rotate_signing_keys.py) end to end: the
// real script rewrites config files that real ARS, EGS, AGS and ES then load
// with their own config loaders. Only systemctl, curl and openssl are fakes.
// This is the regression test of finding RT76-1 of the red-team of pull
// request #76: an artifact published before the rotation must publish again
// after it, which works because the rotation retires ARS's index.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	agsapp "execution-substrate/ags/app"
	agsconfig "execution-substrate/ags/config"
	arsapp "execution-substrate/ars/app"
	arscontract "execution-substrate/ars/contract"
	egsapp "execution-substrate/egs/app"
	egsconfig "execution-substrate/egs/config"
	egscontract "execution-substrate/egs/contract"
	esapp "execution-substrate/es/app"
	esconfig "execution-substrate/es/config"
	evidencev1 "execution-substrate/internal/contracts/evidence/v1"
	runtimeconfigv1 "execution-substrate/internal/contracts/runtimeconfig/v1"
	"execution-substrate/internal/testutil"
)

const rotationScript = "scripts/internal/remote_alpha_rotate_signing_keys.py"

// The rotation's openssl is this test binary run again with this variable
// set. It answers the two commands the rotation runs with a key from
// crypto/rand, so the test runs the same on every system; the scripts
// package runs the rotation with the machine's real /usr/bin/openssl.
const rotationFakeOpenSSLEnv = "SIGNING_KEY_ROTATION_E2E_FAKE_OPENSSL"

func init() {
	if os.Getenv(rotationFakeOpenSSLEnv) == "1" {
		os.Exit(rotationFakeOpenSSL(os.Args[1:]))
	}
}

func rotationFakeOpenSSL(args []string) int {
	switch strings.Join(args, " ") {
	case "genpkey -algorithm ED25519 -outform DER":
		_, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return 1
		}
		der, err := x509.MarshalPKCS8PrivateKey(private)
		if err != nil {
			return 1
		}
		os.Stdout.Write(der)
		return 0
	case "pkey -inform DER -pubout -outform DER":
		in, err := io.ReadAll(os.Stdin)
		if err != nil {
			return 1
		}
		key, err := x509.ParsePKCS8PrivateKey(in)
		if err != nil {
			return 1
		}
		private, ok := key.(ed25519.PrivateKey)
		if !ok {
			return 1
		}
		der, err := x509.MarshalPKIXPublicKey(private.Public())
		if err != nil {
			return 1
		}
		os.Stdout.Write(der)
		return 0
	}
	fmt.Fprintf(os.Stderr, "fake openssl: unexpected %v\n", args)
	return 2
}

// The fake systemctl logs each call, says a unit is inactive between its
// stop and its next start, and shows each unit starting its binary with
// its config, as the box's units do. It does not touch the services: the
// test restarts them itself after the rotation, as systemd would. The
// services run in the test's process, so each unit's main process ID
// (410<n> while it runs) has a root folder under proc/ in the state folder
// that is a link to /: they see the host's files, as the rotation checks.
const rotationE2ESystemctl = `#!/usr/bin/env bash
set -u
s=%q
echo "systemctl $*" >> "$s/calls.log"
case "$1" in
  is-active)
    shift
    for u in "$@"; do if [[ -e "$s/inactive-$u" ]]; then echo inactive; else echo active; fi; done ;;
  show)
    u=${2%%.service}
    if [[ "${4:-}" == MainPID ]]; then
      if [[ -e "$s/inactive-$u" ]]; then echo MainPID=0; else
        case "$u" in ars) echo MainPID=4101 ;; egs) echo MainPID=4102 ;; ags) echo MainPID=4103 ;; es) echo MainPID=4104 ;; esac
      fi
      exit 0
    fi
    echo "ExecStart={ path=/usr/local/lib/execution-substrate/bin/$u ; argv[]=/usr/local/lib/execution-substrate/bin/$u -config /etc/execution-substrate/$u.json ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }" ;;
  stop) touch "$s/inactive-$2" ;;
  start|restart) rm -f "$s/inactive-$2" ;;
  *) echo "fake systemctl: unexpected $*" >&2; exit 2 ;;
esac
`

// The fake curl stands in for the operator's health requests to ES and AGS.
const rotationE2ECurl = `#!/usr/bin/env bash
[[ "${1:-}" == "-q" ]] || exit 99
printf 200
`

const rotationE2EIndex = "var/lib/ars/index.json"

type rotationE2EHost struct {
	t     *testing.T
	stack *publishedStack
	root  string
	bin   string
	state string
	ports map[string]int
}

func rotationE2EPort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// in is the host for a subtest: its helpers fail t, not the parent test.
func (h *rotationE2EHost) in(t *testing.T) *rotationE2EHost {
	c := *h
	c.t = t
	return &c
}

func (h *rotationE2EHost) path(rel string) string { return filepath.Join(h.root, rel) }

func (h *rotationE2EHost) config(name string) string {
	return h.path("etc/execution-substrate/" + name + ".json")
}

func (h *rotationE2EHost) writeJSON(path string, value any, mode os.FileMode) {
	h.t.Helper()
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		h.t.Fatal(err)
	}
	if err := os.WriteFile(path, append(data, '\n'), mode); err != nil {
		h.t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		h.t.Fatal(err)
	}
}

func (h *rotationE2EHost) read(path string) []byte {
	h.t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		h.t.Fatal(err)
	}
	return data
}

// newRotationE2EHost lays out the box under a host root: the four configs
// root:<service> 0640 (the test user stands in for root and every service
// account), ARS's index in a folder ARS owns, healthcheck.env, and the
// fakes. ARS, EGS, AGS and ES each listen on a fixed port, so the configs
// that name each other stay right across restarts.
func newRotationE2EHost(t *testing.T) *rotationE2EHost {
	t.Helper()
	// Opened here so that the go command's test cache sees the script.
	testutil.Read(t, rotationScript)
	fixture := newTLSFixture(t)
	base := t.TempDir()
	h := &rotationE2EHost{t: t, root: filepath.Join(base, "root"), bin: filepath.Join(base, "bin"), state: filepath.Join(base, "state"),
		ports: map[string]int{}}
	for _, dir := range []string{h.path("etc/execution-substrate"), h.path("var/lib/ars"), h.path("var/backups"), h.bin, h.state} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	// Folders the rotation checks must be writable by nobody but their
	// owner, whatever the umask.
	for dir := h.path("var/lib/ars"); ; dir = filepath.Dir(dir) {
		if err := os.Chmod(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if dir == h.root {
			break
		}
	}
	for _, dir := range []string{h.path("etc/execution-substrate"), h.path("etc"), h.path("var/backups")} {
		if err := os.Chmod(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"ars", "egs", "ags", "es"} {
		h.ports[name] = rotationE2EPort(t)
	}

	rootDir := filepath.Join(base, "ars-storage")
	if err := os.MkdirAll(rootDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(h.path(rotationE2EIndex), []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	vaultDigest := writeBlobBytes(t, rootDir, mustMarshalJSON(t, map[string]any{
		"vault_config": map[string]any{"address": "https://vault.internal:8200", "auth_mount": "jwt", "auth_role": "service_execution", "jwt_audience": "vault"},
	}))
	h.stack = &publishedStack{fixture: fixture, rootDir: rootDir, indexPath: h.path(rotationE2EIndex), intentDigest: labeledDigest("aa"),
		derivationSpecDigest: labeledDigest("bb"), outputID: "runtime", workloadZoneVaultDigest: vaultDigest}

	httpConfig := func(name string) map[string]any {
		return map[string]any{"bind_address": "127.0.0.1", "port": h.ports[name], "read_timeout_seconds": 5,
			"write_timeout_seconds": 5, "shutdown_timeout_seconds": 5}
	}
	// ars.json as the rotation reads it: the index path is the box's. The
	// ARS this test runs is built from buildARSConfig with the same port and
	// the index under the host root.
	h.writeJSON(h.config("ars"), map[string]any{
		"http":    httpConfig("ars"),
		"storage": map[string]any{"root_dir": "/var/lib/ars/blobs", "index_file": "/" + rotationE2EIndex},
	}, 0o640)
	arsURL := fmt.Sprintf("https://127.0.0.1:%d", h.ports["ars"])
	h.writeJSON(h.config("egs"), egsconfig.Config{
		HTTP:     egsconfig.HTTPConfig{BindAddress: "127.0.0.1", Port: h.ports["egs"], ReadTimeoutSeconds: 5, WriteTimeoutSeconds: 5, ShutdownTimeoutSeconds: 5},
		TLS:      egsconfig.TLSConfig{CertFile: fixture.egsServerCertPath, KeyFile: fixture.egsServerKeyPath, ClientCAFile: fixture.clientCAPath},
		Security: egsconfig.SecurityConfig{BootstrapIssuerCommonName: fixture.bootstrapCACN},
		Signer:   egsconfig.SignerConfig{Algorithm: "ed25519", KeyID: fixture.egsKeyID, PrivateKeyHex: fixture.egsPrivateKeyHex[:64], PublicKeyHex: fixture.egsPublicKeyHex},
		RuntimeTrust: egscontract.RuntimeTrustPolicy{
			SignerPolicy:   egscontract.SignerPolicy{AllowedSigners: []string{fixture.agsKeyID}, RevokedSigners: []string{}},
			ArtifactPolicy: egscontract.ArtifactPolicy{RevokedArtifacts: []string{}},
		},
		Publication: egscontract.PublicationMetadata{UpdateRevision: 7, Version: "1.0.0"},
	}, 0o640)
	h.writeJSON(h.config("ags"), agsconfig.Config{
		HTTP:          agsconfig.HTTPConfig{BindAddress: "127.0.0.1", Port: h.ports["ags"], ReadTimeoutSeconds: 5, WriteTimeoutSeconds: 5, ShutdownTimeoutSeconds: 5},
		TLS:           agsconfig.TLSConfig{CertFile: fixture.agsServerCertPath, KeyFile: fixture.agsServerKeyPath, ClientCAFile: fixture.clientCAPath},
		Security:      agsconfig.SecurityConfig{BootstrapIssuerCommonName: fixture.bootstrapCACN},
		Authorization: agsconfig.AuthorizationConfig{AllowedSPIFFEPathPrefixes: []string{operatorCallerPath}},
		Dependencies: agsconfig.DependenciesConfig{ArtifactRegistry: agsconfig.DependencyConfig{
			BaseURL: arsURL, ServerName: fixture.arsServerName, ClientCertFile: fixture.agsClientCertPath,
			ClientKeyFile: fixture.agsClientKeyPath, RootCAFile: fixture.runtimeCAPath, TimeoutSeconds: 5}},
		Signer: agsconfig.SignerConfig{Algorithm: "ed25519", KeyID: fixture.agsKeyID, PrivateKeyHex: fixture.agsPrivateKeyHex[:64], PublicKeyHex: fixture.agsPublicKeyHex},
	}, 0o640)
	agsVerifier := esconfig.SignerVerifierConfig{Algorithm: "ed25519", KeyID: fixture.agsKeyID, PublicKeyHex: fixture.agsPublicKeyHex}
	dependency := func(baseURL, serverName string) esconfig.DependencyConfig {
		return esconfig.DependencyConfig{BaseURL: baseURL, ServerName: serverName, ClientCertFile: fixture.executionClientCertPath,
			ClientKeyFile: fixture.executionClientKeyPath, RootCAFile: fixture.runtimeCAPath, TimeoutSeconds: 5}
	}
	var esDoc map[string]any
	if err := json.Unmarshal(mustMarshalJSON(t, esconfig.Config{
		HTTP:          esconfig.HTTPConfig{BindAddress: "127.0.0.1", Port: h.ports["es"], ReadTimeoutSeconds: 5, WriteTimeoutSeconds: 5, ShutdownTimeoutSeconds: 5},
		TLS:           esconfig.TLSConfig{CertFile: fixture.esServerCertPath, KeyFile: fixture.esServerKeyPath, ClientCAFile: fixture.clientCAPath},
		Security:      esconfig.SecurityConfig{BootstrapIssuerCommonName: fixture.bootstrapCACN},
		Authorization: esconfig.AuthorizationConfig{AllowedSPIFFEPathPrefixes: []string{operatorCallerPath}},
		Dependencies: esconfig.DependenciesConfig{
			ArtifactRegistry:    dependency(arsURL, fixture.arsServerName),
			ExecutionGovernance: dependency(fmt.Sprintf("https://127.0.0.1:%d", h.ports["egs"]), fixture.egsServerName),
		},
		RuntimeConfig: esconfig.RuntimeConfigConfig{WorkloadZoneVaultConfigRef: runtimeconfigv1.WorkloadZoneVaultConfigRef{Digest: vaultDigest}},
		Verification: esconfig.VerificationConfig{
			TrustModel:              esconfig.SignerVerifierConfig{Algorithm: "ed25519", KeyID: fixture.egsKeyID, PublicKeyHex: fixture.egsPublicKeyHex},
			Provenance:              agsVerifier,
			DerivationAttestation:   agsVerifier,
			WorkloadIdentityBinding: agsVerifier,
		},
		WorkloadVaultAuth: esconfig.WorkloadVaultAuthConfig{DefaultMode: esconfig.WorkloadVaultAuthModeVaultIdentityJWT},
	}), &esDoc); err != nil {
		t.Fatal(err)
	}
	// This ES only prepares: it has no Nomad and no execution roots.
	delete(esDoc, "nomad")
	delete(esDoc, "execution")
	h.writeJSON(h.config("es"), esDoc, 0o640)
	if err := os.WriteFile(h.path("etc/execution-substrate/healthcheck.env"),
		[]byte("CA_CERT=/x/ca.pem\nOPERATOR_CERT=/x/op.pem\nOPERATOR_KEY=/x/op-key.pem\n"), 0o640); err != nil {
		t.Fatal(err)
	}

	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{
		"systemctl": fmt.Sprintf(rotationE2ESystemctl, h.state),
		"curl":      rotationE2ECurl,
		"openssl":   fmt.Sprintf("#!/usr/bin/env bash\nexport %s=1\nexec %q \"$@\"\n", rotationFakeOpenSSLEnv, self),
	} {
		if err := os.WriteFile(filepath.Join(h.bin, name), []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, pid := range []string{"4101", "4102", "4103", "4104"} {
		if err := os.MkdirAll(filepath.Join(h.state, "proc", pid), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("/", filepath.Join(h.state, "proc", pid, "root")); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() { h.stopAll() })
	if err := h.startAll(); err != nil {
		t.Fatalf("es start: %v", err)
	}
	return h
}

func (h *rotationE2EHost) run(args ...string) (map[string]any, string, int) {
	h.t.Helper()
	cmd := exec.Command("python3", append([]string{"-I", "-B", testutil.Path(rotationScript), "--host-root", h.root}, args...)...)
	cmd.Dir = h.state
	cmd.Env = append(os.Environ(),
		"SIGNING_KEY_ROTATION_TEST_SYSTEMCTL="+filepath.Join(h.bin, "systemctl"),
		"SIGNING_KEY_ROTATION_TEST_CURL="+filepath.Join(h.bin, "curl"),
		"SIGNING_KEY_ROTATION_TEST_OPENSSL="+filepath.Join(h.bin, "openssl"),
		"SIGNING_KEY_ROTATION_TEST_WAIT_SECONDS=5",
		"SIGNING_KEY_ROTATION_TEST_PROC="+filepath.Join(h.state, "proc"))
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	code := 0
	if err := cmd.Run(); err != nil {
		exitErr, ok := err.(*exec.ExitError)
		if !ok {
			h.t.Fatalf("run %v: %v", args, err)
		}
		code = exitErr.ExitCode()
	}
	var report map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		h.t.Fatalf("%v: no JSON report (exit %d): %v\nstdout %s\nstderr %s", args, code, err, stdout.String(), stderr.String())
	}
	return report, stderr.String(), code
}

func (h *rotationE2EHost) stopAll() {
	s := h.stack
	for _, step := range []struct {
		running *bool
		stop    func(context.Context) error
	}{
		{&s.esRunning, func(ctx context.Context) error { return s.es.Shutdown(ctx) }},
		{&s.agsRunning, func(ctx context.Context) error { return s.ags.Shutdown(ctx) }},
		{&s.egsRunning, func(ctx context.Context) error { return s.egs.Shutdown(ctx) }},
		{&s.arsRunning, func(ctx context.Context) error { return s.ars.Shutdown(ctx) }},
	} {
		if !*step.running {
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_ = step.stop(ctx)
		cancel()
		*step.running = false
	}
}

// startAll starts ARS on the index under the host root, then EGS, AGS and
// ES from the config files, each read by its own service's loader. It
// returns ES's start error, if any.
func (h *rotationE2EHost) startAll() error {
	t, s, f := h.t, h.stack, h.stack.fixture
	t.Helper()
	arsConfig := buildARSConfig(s)
	arsConfig.HTTP.Port = h.ports["ars"]
	arsService, err := arsapp.New(arsConfig)
	if err != nil {
		t.Fatalf("ars New: %v", err)
	}
	s.ars = arsService
	startService(t, arsService.Start, arsService.Addr, f.clientTLSConfigForServer(t, f.arsServerName, "service/execution", false))
	s.arsRunning = true

	egsConfig, err := egsconfig.Load(h.config("egs"))
	if err != nil {
		t.Fatalf("egs config.Load: %v", err)
	}
	egsService, err := egsapp.New(egsConfig)
	if err != nil {
		t.Fatalf("egs New: %v", err)
	}
	s.egs = egsService
	startService(t, egsService.Start, egsService.Addr, f.clientTLSConfigForServer(t, f.egsServerName, "service/execution", false))
	s.egsRunning = true

	agsConfig, err := agsconfig.Load(h.config("ags"))
	if err != nil {
		t.Fatalf("ags config.Load: %v", err)
	}
	agsService, err := agsapp.New(agsConfig)
	if err != nil {
		t.Fatalf("ags New: %v", err)
	}
	s.ags = agsService
	startService(t, agsService.Start, agsService.Addr, f.clientTLSConfigForServer(t, f.agsServerName, operatorCallerPath, false))
	s.agsRunning = true

	esConfig, err := esconfig.Load(h.config("es"))
	if err != nil {
		t.Fatalf("es config.Load: %v", err)
	}
	esService, err := esapp.New(esConfig)
	if err != nil {
		t.Fatalf("es New: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := esService.Start(ctx); err != nil {
		return err
	}
	s.es = esService
	s.esRunning = true
	waitForHealthy(t, esService.Addr(), f.clientTLSConfigForServer(t, f.esServerName, operatorCallerPath, false))
	return nil
}

// restartAll is what the rotation's systemctl calls do on the box.
func (h *rotationE2EHost) restartAll() {
	h.t.Helper()
	h.stopAll()
	if err := h.startAll(); err != nil {
		h.t.Fatalf("es start: %v", err)
	}
}

func (h *rotationE2EHost) prepare(artifactDigest string) (int, string) {
	h.t.Helper()
	s := h.stack
	body := mustMarshalJSON(h.t, map[string]any{
		"schema_version": "v1",
		"mode":           "async",
		"invocation": map[string]any{
			"schema_version": "v1", "artifact_digest": artifactDigest, "derivation_spec_digest": s.derivationSpecDigest,
			"output_id": s.outputID, "env": map[string]string{"APP_MODE": "test"},
		},
	})
	response := doJSONRequest(h.t, s.es.Addr(), http.MethodPost, "/v1/executions:prepare",
		s.fixture.clientTLSConfigForServer(h.t, s.fixture.esServerName, operatorCallerPath, false), body)
	defer response.Body.Close()
	var payload struct {
		Code string `json:"code"`
	}
	_ = json.Unmarshal(mustReadBody(h.t, response.Body), &payload)
	return response.StatusCode, payload.Code
}

func (h *rotationE2EHost) publish(payload string) (int, string, publishResponse) {
	h.t.Helper()
	response := publishArtifactRequest(h.t, h.stack, operatorCallerPath, false, func(body map[string]any) {
		body["artifact_payload_b64"] = base64.StdEncoding.EncodeToString([]byte(payload))
	})
	defer response.Body.Close()
	raw := mustReadBody(h.t, response.Body)
	var out publishResponse
	_ = json.Unmarshal(raw, &out)
	return response.StatusCode, strings.TrimSpace(string(raw)), out
}

// forge registers in ARS, as a holder of AGS's ARS client certificate
// could, a record for a new payload sealed with the given key, and returns
// its artifact digest.
func (h *rotationE2EHost) forge(payload string, keyID string, key ed25519.PrivateKey) string {
	t, s := h.t, h.stack
	t.Helper()
	payloadDigest := writeBlobBytes(t, s.rootDir, []byte(payload))
	identity, err := evidencev1.NewArtifactIdentity(payloadDigest, "static-service", s.intentDigest)
	if err != nil {
		t.Fatal(err)
	}
	record := evidencev1.ArtifactEvidence{Claims: evidencev1.Claims{
		SchemaVersion: evidencev1.Version,
		Package: evidencev1.PackageClaims{
			Identity: identity,
			Publication: evidencev1.Publication{BuilderService: "artifact-governance",
				Invoker:         evidencev1.Invoker{Service: operatorCallerPath, Principal: operatorSPIFFEID},
				PolicyDecisions: []evidencev1.PolicyDecision{{Rule: "allow", Result: "applied"}}, BuildLogDigest: labeledDigest("ee")},
		},
		Admission: evidencev1.AdmissionClaims{
			Authorization: evidencev1.AuthorizationClaims{Derivation: evidencev1.DerivationAuthorization{DerivationSpecDigest: s.derivationSpecDigest, OutputID: s.outputID}},
			Execution: evidencev1.ExecutionClaims{
				Runtime:  evidencev1.ExecutionRuntime{EnvironmentVariables: []string{"APP_MODE"}, RequiredCapabilities: []string{}},
				Workload: evidencev1.ExecutionWorkload{TargetPlatform: "docker"},
				Access:   evidencev1.ExecutionAccess{NetworkAccess: false},
			},
		},
	}}
	canonical, err := record.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	record.Seal = evidencev1.NewSeal(canonical, keyID, "ed25519", base64.StdEncoding.EncodeToString(ed25519.Sign(key, canonical)))
	evidenceDigest := writeBlobBytes(t, s.rootDir, mustMarshalJSON(t, record))
	discovery := arscontract.ArtifactDiscovery{SchemaVersion: arscontract.ArtifactDiscoverySchemaVersion,
		Artifact: arscontract.ArtifactIdentity{ArtifactDigest: identity.ArtifactDigest, ArtifactType: "static-service", IntentDigest: s.intentDigest},
		Evidence: arscontract.ArtifactBlobRef{Digest: evidenceDigest, MediaType: "application/json"},
		Payload:  arscontract.ArtifactBlobRef{Digest: payloadDigest, MediaType: "application/octet-stream"}}
	discoveryDigest := writeBlobBytes(t, s.rootDir, mustMarshalJSON(t, discovery))
	response := doJSONRequest(t, s.ars.Addr(), http.MethodPost, "/v1/artifacts:register",
		s.fixture.clientTLSConfigForServer(t, s.fixture.arsServerName, "service/artifact-governance", false),
		mustMarshalJSON(t, arscontract.RegisterArtifactRequest{DiscoveryDigest: discoveryDigest}))
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK && response.StatusCode != http.StatusCreated {
		t.Fatalf("register the forged record: %d %s", response.StatusCode, mustReadBody(t, response.Body))
	}
	return identity.ArtifactDigest
}

func (h *rotationE2EHost) signer(name string) (string, ed25519.PrivateKey) {
	h.t.Helper()
	var doc struct {
		Signer struct {
			KeyID         string `json:"key_id"`
			PrivateKeyHex string `json:"private_key_hex"`
		} `json:"signer"`
	}
	if err := json.Unmarshal(h.read(h.config(name)), &doc); err != nil {
		h.t.Fatal(err)
	}
	seed, err := hex.DecodeString(doc.Signer.PrivateKeyHex[:64])
	if err != nil {
		h.t.Fatal(err)
	}
	return doc.Signer.KeyID, ed25519.NewKeyFromSeed(seed)
}

// TestSigningKeyRotationEndToEnd publishes artifact X, rotates the keys,
// and restarts the four services from the rotated files. ES refuses a
// record sealed with the old AGS key and an EGS that still signs with the
// old EGS key; X publishes again and prepares (RT76-1), and so does a new
// artifact. Rollback then puts back the old keys and the old index, and X's
// first record prepares again.
func TestSigningKeyRotationEndToEnd(t *testing.T) {
	h := newRotationE2EHost(t)
	indexBefore := h.read(h.path(rotationE2EIndex))
	oldAGSKeyID, oldAGSKey := h.signer("ags")
	oldEGS := h.read(h.config("egs"))

	status, body, published := h.publish("artifact payload bytes")
	if status != http.StatusOK {
		t.Fatalf("publish X before the rotation: %d %s", status, body)
	}
	x := published.ArtifactDigest
	if code, name := h.prepare(x); code != http.StatusOK {
		t.Fatalf("prepare X before the rotation: %d %s", code, name)
	}
	indexWithX := h.read(h.path(rotationE2EIndex))
	if bytes.Equal(indexWithX, indexBefore) {
		t.Fatal("ARS did not record X in its index")
	}

	report, stderr, code := h.run("apply")
	if code != 0 || report["result"] != "rotated" {
		t.Fatalf("apply exit %d result %v failure %v problems %v\nstderr %s", code, report["result"], report["failure"], report["problems"], stderr)
	}
	backupDir, _ := report["backup_dir"].(string)
	if got := h.read(h.path(rotationE2EIndex)); string(got) != "{}\n" {
		t.Fatalf("the rotation left ARS's index as %q", got)
	}
	if got := h.read(filepath.Join(backupDir, "ars-index.json")); !bytes.Equal(got, indexWithX) {
		t.Fatal("the backup's copy of ARS's index is not the index the rotation retired")
	}
	h.restartAll()
	newAGSKeyID, newAGSKey := h.signer("ags")
	if newAGSKeyID == oldAGSKeyID || newAGSKey.Equal(oldAGSKey) {
		t.Fatal("the AGS key did not change")
	}

	t.Run("X has no record until it is published again", func(t *testing.T) {
		h := h.in(t)
		if code, name := h.prepare(x); code != http.StatusNotFound || name != "artifact_evidence_not_found" {
			t.Fatalf("prepare X with a retired index: %d %s", code, name)
		}
	})
	t.Run("a record sealed with the old AGS key is refused", func(t *testing.T) {
		h := h.in(t)
		for _, keyID := range []string{oldAGSKeyID, newAGSKeyID} {
			digest := h.forge("forged payload under "+keyID, keyID, oldAGSKey)
			if code, name := h.prepare(digest); code != http.StatusForbidden || name != "artifact_evidence_invalid" {
				t.Fatalf("prepare of a record sealed with the old key under key ID %s: %d %s", keyID, code, name)
			}
		}
	})
	t.Run("an artifact published before the rotation publishes again", func(t *testing.T) {
		h := h.in(t)
		status, body, again := h.publish("artifact payload bytes")
		if status != http.StatusOK {
			t.Fatalf("publish X again after the rotation: %d %s", status, body)
		}
		if again.ArtifactDigest != x || again.EvidenceDigest == published.EvidenceDigest {
			t.Fatalf("X again: artifact %s evidence %s; first publish: artifact %s evidence %s",
				again.ArtifactDigest, again.EvidenceDigest, x, published.EvidenceDigest)
		}
		if code, name := h.prepare(x); code != http.StatusOK {
			t.Fatalf("prepare X after it was published again: %d %s", code, name)
		}
	})
	t.Run("a new artifact publishes and prepares", func(t *testing.T) {
		h := h.in(t)
		status, body, z := h.publish("a payload first published after the rotation")
		if status != http.StatusOK {
			t.Fatalf("publish Z after the rotation: %d %s", status, body)
		}
		if code, name := h.prepare(z.ArtifactDigest); code != http.StatusOK {
			t.Fatalf("prepare Z after the rotation: %d %s", code, name)
		}
	})
	t.Run("ES refuses an EGS that still signs with the old key", func(t *testing.T) {
		h := h.in(t)
		rotatedEGS := h.read(h.config("egs"))
		h.stopAll()
		if err := os.WriteFile(h.config("egs"), oldEGS, 0o640); err != nil {
			t.Fatal(err)
		}
		if err := h.startAll(); err == nil {
			t.Fatal("ES started against an EGS that signs with the old key")
		}
		h.stopAll()
		if err := os.WriteFile(h.config("egs"), rotatedEGS, 0o640); err != nil {
			t.Fatal(err)
		}
		h.restartAll()
	})
	t.Run("rollback puts back the old keys and the old index", func(t *testing.T) {
		h := h.in(t)
		report, stderr, code := h.run("rollback", "--backup-dir", backupDir)
		if code != 0 || report["result"] != "rolled_back" {
			t.Fatalf("rollback exit %d result %v steps %v\nstderr %s", code, report["result"], report["rollback_steps"], stderr)
		}
		if got := h.read(h.path(rotationE2EIndex)); !bytes.Equal(got, indexWithX) {
			t.Fatal("rollback did not put back ARS's index")
		}
		h.restartAll()
		if id, key := h.signer("ags"); id != oldAGSKeyID || !key.Equal(oldAGSKey) {
			t.Fatal("rollback did not put back the old AGS key")
		}
		if code, name := h.prepare(x); code != http.StatusOK {
			t.Fatalf("prepare X's first record after the rollback: %d %s", code, name)
		}
	})
}
