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
	"strings"
	"testing"

	"execution-substrate/ags/sign"
	arsapi "execution-substrate/ars/api"
	evidencev1 "execution-substrate/internal/contracts/evidence/v1"
)

func TestWorkstreamBPublicationOutputProducesSignedEvidenceAndRuntimeDiscovery(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate signing key: %v", err)
	}
	signer, err := sign.NewEd25519Signer("ags-artifact-fact-signer", hex.EncodeToString(privateKey), hex.EncodeToString(publicKey))
	if err != nil {
		t.Fatalf("build signer: %v", err)
	}

	uploaded := map[string][]byte{}
	var registerRequest arsapi.RegisterArtifactRequest
	registry := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPut && strings.HasPrefix(r.URL.Path, "/v1/blobs/"):
			digest := strings.TrimPrefix(r.URL.Path, "/v1/blobs/")
			body, err := io.ReadAll(r.Body)
			if err != nil {
				t.Fatalf("read upload body: %v", err)
			}
			uploaded[digest] = body
			w.WriteHeader(http.StatusCreated)
		case r.Method == http.MethodPost && r.URL.Path == "/v1/artifacts:register":
			if err := json.NewDecoder(r.Body).Decode(&registerRequest); err != nil {
				t.Fatalf("decode register request: %v", err)
			}
			w.WriteHeader(http.StatusCreated)
		default:
			t.Fatalf("unexpected ARS request %s %q", r.Method, r.URL.Path)
		}
	}))
	defer registry.Close()

	baseURL, err := url.Parse(registry.URL)
	if err != nil {
		t.Fatalf("parse registry URL: %v", err)
	}
	service := Service{
		arsClient: &dependencyClient{
			baseURL: baseURL,
			client:  registry.Client(),
		},
		signer: signer,
	}

	result, publishErr := service.Publish(context.Background(), CallerIdentity{
		Path:     "operator/local",
		SPIFFEID: "spiffe://execution.internal/operator/local",
	}, PublishRequest{
		ArtifactPayloadB64: base64.StdEncoding.EncodeToString([]byte("artifact payload bytes")),
		Artifact: ArtifactInput{
			ArtifactType: "static-script",
			IntentDigest: testWorkstreamBLabeledDigest("aa"),
		},
		Publication: PublicationInput{
			PolicyDecisions: []PolicyDecision{{Rule: "allow", Result: "applied"}},
			BuildLogDigest:  testWorkstreamBLabeledDigest("bb"),
		},
		Admission: AdmissionInput{
			Runtime: RuntimeInterface{
				EnvironmentVariables: []string{"APP_MODE"},
			},
			Derivation: DerivationInput{
				DerivationSpecDigest: testWorkstreamBLabeledDigest("cc"),
				OutputID:             "runtime",
			},
			Workload: WorkloadInput{
				TargetPlatform: "docker",
			},
		},
	})
	if publishErr != nil {
		t.Fatalf("publish: %+v", publishErr)
	}
	if !result.Published {
		t.Fatalf("expected published result, got %+v", result)
	}
	if result.ArtifactDigest == result.PayloadDigest {
		t.Fatalf("artifact_digest must remain distinct from payload_digest, both were %q", result.ArtifactDigest)
	}
	if registerRequest.DiscoveryDigest != result.DiscoveryDigest {
		t.Fatalf("expected registration to use discovery digest %q, got %+v", result.DiscoveryDigest, registerRequest)
	}
	if registerRequest.DescriptorDigest != result.DescriptorDigest {
		t.Fatalf("expected descriptor support digest %q in registration, got %+v", result.DescriptorDigest, registerRequest)
	}

	var evidence evidencev1.ArtifactEvidence
	if err := json.Unmarshal(uploaded[result.EvidenceDigest], &evidence); err != nil {
		t.Fatalf("decode uploaded evidence: %v", err)
	}
	if err := evidencev1.Verify(evidence, "ags-artifact-fact-signer", "ed25519", publicKey); err != nil {
		t.Fatalf("verify uploaded evidence: %v", err)
	}
	if evidence.Claims.Package.Identity.ArtifactDigest != result.ArtifactDigest {
		t.Fatalf("evidence package identity artifact digest mismatch: %+v", evidence.Claims.Package.Identity)
	}
	if evidence.Claims.Package.Identity.PayloadDigest != result.PayloadDigest {
		t.Fatalf("evidence package identity payload digest mismatch: %+v", evidence.Claims.Package.Identity)
	}
	if evidence.Claims.Package.Publication.BuilderService != builderServiceName {
		t.Fatalf("expected AGS-owned builder service %q, got %+v", builderServiceName, evidence.Claims.Package.Publication)
	}
	if evidence.Claims.Package.Publication.Invoker.Service != "operator/local" {
		t.Fatalf("expected caller-bound publication invoker, got %+v", evidence.Claims.Package.Publication.Invoker)
	}

	var discovery arsapi.ArtifactDiscovery
	if err := json.Unmarshal(uploaded[result.DiscoveryDigest], &discovery); err != nil {
		t.Fatalf("decode uploaded discovery: %v", err)
	}
	if discovery.Artifact.ArtifactDigest != result.ArtifactDigest {
		t.Fatalf("discovery artifact digest mismatch: %+v", discovery)
	}
	if discovery.Evidence.Digest != result.EvidenceDigest || discovery.Payload.Digest != result.PayloadDigest {
		t.Fatalf("discovery must expose evidence and payload refs, got %+v", discovery)
	}
	assertWorkstreamBJSONOmits(t, uploaded[result.DiscoveryDigest],
		"descriptor_digest",
		"manifest_digest",
		"supporting",
		"attempt_manifest",
		"retained_result_manifest",
		"review",
		"checkpoint",
		"finalization",
	)
}

func assertWorkstreamBJSONOmits(t *testing.T, payload []byte, forbidden ...string) {
	t.Helper()

	text := string(payload)
	for _, item := range forbidden {
		if strings.Contains(text, item) {
			t.Fatalf("expected JSON to omit %q, got %s", item, text)
		}
	}
}

func testWorkstreamBLabeledDigest(hexPair string) string {
	return "sha256:" + strings.Repeat(hexPair, 32)
}
