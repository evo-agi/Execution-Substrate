package publish

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"execution-substrate/ags/sign"
	evidencev1 "execution-substrate/internal/contracts/evidence/v1"
)

// publishRuntimeInterface publishes one artifact with the given runtime
// interface and returns the uploaded evidence and manifest bytes.
func publishRuntimeInterface(t *testing.T, runtime RuntimeInterface) (ed25519.PublicKey, []byte, []byte) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := sign.NewEd25519Signer("ags-artifact-fact-signer", hex.EncodeToString(privateKey), hex.EncodeToString(publicKey))
	if err != nil {
		t.Fatal(err)
	}
	uploaded := map[string][]byte{}
	registry := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut && strings.HasPrefix(r.URL.Path, "/v1/blobs/") {
			body, _ := io.ReadAll(r.Body)
			uploaded[strings.TrimPrefix(r.URL.Path, "/v1/blobs/")] = body
		}
		w.WriteHeader(http.StatusCreated)
	}))
	defer registry.Close()
	baseURL, err := url.Parse(registry.URL)
	if err != nil {
		t.Fatal(err)
	}
	service := Service{arsClient: &dependencyClient{baseURL: baseURL, client: registry.Client()}, signer: signer}
	result, publishErr := service.Publish(context.Background(), CallerIdentity{
		Path:     "operator/local",
		SPIFFEID: "spiffe://execution.internal/operator/local",
	}, PublishRequest{
		ArtifactPayloadB64: base64.StdEncoding.EncodeToString([]byte("artifact payload bytes")),
		Artifact:           ArtifactInput{ArtifactType: "static-script", IntentDigest: testWorkstreamBLabeledDigest("aa")},
		Publication:        PublicationInput{PolicyDecisions: []PolicyDecision{{Rule: "allow", Result: "applied"}}, BuildLogDigest: testWorkstreamBLabeledDigest("bb")},
		Admission: AdmissionInput{
			Runtime:    runtime,
			Derivation: DerivationInput{DerivationSpecDigest: testWorkstreamBLabeledDigest("cc"), OutputID: "runtime"},
			Workload:   WorkloadInput{TargetPlatform: "docker"},
		},
	})
	if publishErr != nil || !result.Published {
		t.Fatalf("publish: %+v %+v", result, publishErr)
	}
	return publicKey, uploaded[result.EvidenceDigest], uploaded[result.ManifestDigest]
}

func TestPublishWithoutMountTargetsWritesTheSameShapeAsBefore(t *testing.T) {
	_, evidence, manifest := publishRuntimeInterface(t, RuntimeInterface{EnvironmentVariables: []string{"APP_MODE"}, RequiredCapabilities: []string{}})
	for name, document := range map[string][]byte{"evidence": evidence, "manifest": manifest} {
		if len(document) == 0 || strings.Contains(string(document), "mount_targets") {
			t.Fatalf("%s of an artifact that declares no mount target must not carry the key: %s", name, document)
		}
	}
}

func TestPublishSignsTheDeclaredMountTargets(t *testing.T) {
	targets := []string{"/execution/mounts/source", "/execution/mounts/config"}
	publicKey, evidenceBytes, manifestBytes := publishRuntimeInterface(t, RuntimeInterface{
		EnvironmentVariables: []string{},
		RequiredCapabilities: []string{},
		MountTargets:         targets,
	})
	var evidence evidencev1.ArtifactEvidence
	if err := json.Unmarshal(evidenceBytes, &evidence); err != nil {
		t.Fatal(err)
	}
	if err := evidencev1.Verify(evidence, "ags-artifact-fact-signer", "ed25519", publicKey); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if got := evidence.Claims.Admission.Execution.Runtime.MountTargets; !reflect.DeepEqual(got, targets) {
		t.Fatalf("signed mount targets = %v, want %v", got, targets)
	}
	canonical, err := evidence.CanonicalBytes()
	if err != nil || !strings.Contains(string(canonical), `"mount_targets":["/execution/mounts/config","/execution/mounts/source"]`) {
		t.Fatalf("canonical bytes do not sign the mount targets: %s %v", canonical, err)
	}
	var manifest Manifest
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil || !reflect.DeepEqual(manifest.RuntimeInterface.MountTargets, targets) {
		t.Fatalf("manifest mount targets = %+v %v", manifest.RuntimeInterface, err)
	}
	// Tampering with the declaration breaks the seal.
	evidence.Claims.Admission.Execution.Runtime.MountTargets = append(evidence.Claims.Admission.Execution.Runtime.MountTargets, "/execution/mounts/extra")
	if err := evidencev1.Verify(evidence, "ags-artifact-fact-signer", "ed25519", publicKey); err == nil {
		t.Fatal("an added mount target must break the seal")
	}
}
