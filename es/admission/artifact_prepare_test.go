package admission

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	arsapi "execution-substrate/ars/api"
	egsmodel "execution-substrate/egs/model"
	evidencev1 "execution-substrate/internal/contracts/evidence/v1"
)

func TestFetchArtifactDiscoveryRecordReturnsDiscoveryPayload(t *testing.T) {
	discovery := validArtifactDiscoveryFixture()
	service := Service{
		arsClient: newArtifactRegistryTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/v1/artifacts/"+discovery.Artifact.ArtifactDigest+"/discovery" {
				t.Fatalf("unexpected discovery path %q", r.URL.Path)
			}
			writeJSONResponse(t, w, http.StatusOK, discovery)
		})),
	}

	got, err := service.fetchArtifactDiscoveryRecord(context.Background(), discovery.Artifact.ArtifactDigest)
	if err != nil {
		t.Fatalf("fetch artifact discovery record: %+v", err)
	}
	if got.Artifact.ArtifactDigest != discovery.Artifact.ArtifactDigest || got.Evidence.Digest != discovery.Evidence.Digest {
		t.Fatalf("unexpected discovery payload %+v", got)
	}
}

func TestFetchArtifactDiscoveryRecordMapsNotFoundAndInvalidPayload(t *testing.T) {
	discovery := validArtifactDiscoveryFixture()

	t.Run("not found maps to artifact evidence not found", func(t *testing.T) {
		service := Service{
			arsClient: newArtifactRegistryTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				writeJSONResponse(t, w, http.StatusNotFound, artifactRegistryErrorResponse{Error: "artifact not found"})
			})),
		}

		_, err := service.fetchArtifactDiscoveryRecord(context.Background(), discovery.Artifact.ArtifactDigest)
		if err == nil || err.Code != codeArtifactEvidenceNotFound || err.Status != http.StatusNotFound {
			t.Fatalf("expected artifact evidence not found mapping, got %+v", err)
		}
	})

	t.Run("invalid payload maps to unavailable", func(t *testing.T) {
		service := Service{
			arsClient: newArtifactRegistryTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte(`{"schema_version":`))
			})),
		}

		_, err := service.fetchArtifactDiscoveryRecord(context.Background(), discovery.Artifact.ArtifactDigest)
		if err == nil || err.Code != codeArtifactEvidenceUnavailable || err.Status != http.StatusServiceUnavailable {
			t.Fatalf("expected unavailable mapping for invalid discovery payload, got %+v", err)
		}
	})
}

func TestFetchArtifactEvidenceBlobReturnsEvidencePayloadAndMapsFailure(t *testing.T) {
	fixture := newPreparedArtifactFixture(t)

	t.Run("success", func(t *testing.T) {
		service := Service{
			arsClient: newArtifactRegistryTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/v1/blobs/"+fixture.discovery.Evidence.Digest+":json" {
					t.Fatalf("unexpected evidence path %q", r.URL.Path)
				}
				writeJSONResponse(t, w, http.StatusOK, fixture.evidence)
			})),
		}

		got, err := service.fetchArtifactEvidenceBlob(context.Background(), fixture.discovery.Artifact.ArtifactDigest, fixture.discovery.Evidence.Digest)
		if err != nil {
			t.Fatalf("fetch artifact evidence blob: %+v", err)
		}
		if got.Claims.Package.Identity.ArtifactDigest != fixture.evidence.Claims.Package.Identity.ArtifactDigest {
			t.Fatalf("unexpected evidence payload %+v", got)
		}
	})

	// Each body is named by its own digest, so the read verifies and the
	// strict decoder is what refuses it.
	for _, test := range []struct {
		name string
		body []byte
	}{
		{name: "invalid payload", body: []byte(`{"claims":`)},
		{name: "unknown field", body: []byte(`{"unknown_field":true}`)},
		{name: "trailing document", body: append(servedJSONDocument(t, fixture.evidence), []byte("{}")...)},
	} {
		t.Run(test.name, func(t *testing.T) {
			service := Service{
				arsClient: newArtifactRegistryTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					_, _ = w.Write(test.body)
				})),
			}

			_, err := service.fetchArtifactEvidenceBlob(context.Background(), fixture.discovery.Artifact.ArtifactDigest, digestBytes(test.body))
			if err == nil || err.Code != codeArtifactEvidenceUnavailable || err.Status != http.StatusServiceUnavailable || err.Message != "artifact evidence payload was invalid" {
				t.Fatalf("expected artifact evidence payload invalid mapping, got %+v", err)
			}
		})
	}
}

func TestPrepareArtifactFromDiscoveryValidatesRequestBindingAndReturnsPreparedArtifact(t *testing.T) {
	fixture := newPreparedArtifactFixture(t)
	service := fixture.service()
	req := fixture.prepareRequest()

	artifact, err := service.prepareArtifactFromDiscovery(req, fixture.trustModel, discoveredArtifact{
		discovery: fixture.discovery,
		evidence:  fixture.evidence,
	})
	if err != nil {
		t.Fatalf("prepare artifact from discovery: %+v", err)
	}
	if artifact.payloadDigest != fixture.discovery.Payload.Digest {
		t.Fatalf("expected payload digest %q, got %q", fixture.discovery.Payload.Digest, artifact.payloadDigest)
	}
	if artifact.targetPlatform != "docker" || !artifact.networkAccess {
		t.Fatalf("unexpected prepared artifact %+v", artifact)
	}
	if artifact.manifest.ArtifactDigest != fixture.discovery.Artifact.ArtifactDigest {
		t.Fatalf("unexpected manifest %+v", artifact.manifest)
	}

	mismatchReq := fixture.prepareRequest()
	mismatchReq.Invocation.DerivationSpecDigest = labeledDigest("ff")
	_, err = service.prepareArtifactFromDiscovery(mismatchReq, fixture.trustModel, discoveredArtifact{
		discovery: fixture.discovery,
		evidence:  fixture.evidence,
	})
	if err == nil || err.Code != codeInvalidRequest || !strings.Contains(err.Message, "derivation_spec_digest does not match artifact evidence") {
		t.Fatalf("expected derivation mismatch error, got %+v", err)
	}
}

func TestPrepareArtifactFromEvidenceRecordValidatesConsistencySignatureAndTrust(t *testing.T) {
	fixture := newPreparedArtifactFixture(t)
	service := fixture.service()

	artifact, err := service.prepareArtifactFromEvidenceRecord(fixture.trustModel, fixture.discovery, fixture.evidence)
	if err != nil {
		t.Fatalf("prepare artifact from evidence record: %+v", err)
	}
	if artifact.manifest.RuntimeInterface.EnvironmentVariables[0] != "APP_MODE" {
		t.Fatalf("expected manifest env allowlist from evidence, got %+v", artifact.manifest)
	}

	mismatchedDiscovery := fixture.discovery
	mismatchedDiscovery.Payload.Digest = labeledDigest("99")
	_, err = service.prepareArtifactFromEvidenceRecord(fixture.trustModel, mismatchedDiscovery, fixture.evidence)
	if err == nil || err.Code != codeArtifactEvidenceInvalid || !strings.Contains(err.Message, "payload reference does not match artifact evidence") {
		t.Fatalf("expected payload mismatch error, got %+v", err)
	}

	tamperedEvidence := fixture.evidence
	tamperedEvidence.Seal.Signature = base64.StdEncoding.EncodeToString([]byte("not-a-valid-signature"))
	_, err = service.prepareArtifactFromEvidenceRecord(fixture.trustModel, fixture.discovery, tamperedEvidence)
	if err == nil || err.Code != codeArtifactEvidenceInvalid || !strings.Contains(err.Message, "signature verification failed") {
		t.Fatalf("expected signature verification failure, got %+v", err)
	}

	disallowedTrust := fixture.trustModel
	disallowedTrust.SignerPolicy.AllowedSigners = []string{"other-signer"}
	_, err = service.prepareArtifactFromEvidenceRecord(disallowedTrust, fixture.discovery, fixture.evidence)
	if err == nil || err.Code != codeSignerNotAllowed {
		t.Fatalf("expected signer-not-allowed error, got %+v", err)
	}
}

type preparedArtifactFixture struct {
	publicKey  ed25519.PublicKey
	privateKey ed25519.PrivateKey
	keyID      string

	discovery  arsapi.ArtifactDiscovery
	evidence   evidencev1.ArtifactEvidence
	trustModel egsmodel.RuntimeTrustPolicy
}

func newPreparedArtifactFixture(t *testing.T) preparedArtifactFixture {
	t.Helper()

	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate ed25519 keypair: %v", err)
	}

	payloadDigest := labeledDigest("11")
	intentDigest := labeledDigest("22")
	buildLogDigest := labeledDigest("33")
	derivationSpecDigest := labeledDigest("44")
	artifactIdentity, err := evidencev1.NewArtifactIdentity(payloadDigest, "static-script", intentDigest)
	if err != nil {
		t.Fatalf("derive artifact identity: %v", err)
	}

	evidence := evidencev1.ArtifactEvidence{
		Claims: evidencev1.Claims{
			SchemaVersion: evidencev1.Version,
			Package: evidencev1.PackageClaims{
				Identity: artifactIdentity,
				Publication: evidencev1.Publication{
					BuilderService: "artifact-governance",
					Invoker: evidencev1.Invoker{
						Service:   "operator/local",
						Principal: "spiffe://execution.internal/operator/local",
					},
					PolicyDecisions: []evidencev1.PolicyDecision{
						{Rule: "allow", Result: "applied"},
					},
					BuildLogDigest: buildLogDigest,
				},
			},
			Admission: evidencev1.AdmissionClaims{
				Authorization: evidencev1.AuthorizationClaims{
					Derivation: evidencev1.DerivationAuthorization{
						DerivationSpecDigest: derivationSpecDigest,
						OutputID:             "runtime",
					},
				},
				Execution: evidencev1.ExecutionClaims{
					Runtime: evidencev1.ExecutionRuntime{
						EnvironmentVariables: []string{"APP_MODE"},
						RequiredCapabilities: []string{},
					},
					Workload: evidencev1.ExecutionWorkload{
						TargetPlatform: "docker",
					},
					Access: evidencev1.ExecutionAccess{
						NetworkAccess: true,
					},
				},
			},
		},
	}
	keyID := "ags-artifact-signer"
	fixture := preparedArtifactFixture{
		publicKey:  publicKey,
		privateKey: privateKey,
		keyID:      keyID,
		discovery:  validArtifactDiscoveryFixture(),
		evidence:   evidence,
		trustModel: egsmodel.RuntimeTrustPolicy{
			SignerPolicy: egsmodel.SignerPolicy{
				AllowedSigners: []string{keyID},
			},
		},
	}
	return fixture.resealed(t)
}

// withPayload returns a copy of the fixture whose signed evidence names the
// exact payload bytes a test serves. ES hashes every ARS blob it reads and
// uses it only when it equals the requested digest, so a fixture that serves
// a payload must sign that payload's digest. The payload digest, the derived
// artifact digest, the evidence seal and the discovery record are recomputed
// with the fixture's own signing key; the key, key ID and trust model stay the
// same, so a service built from the original fixture still verifies it.
func (f preparedArtifactFixture) withPayload(t *testing.T, payload []byte) preparedArtifactFixture {
	t.Helper()
	identity := f.evidence.Claims.Package.Identity
	rederived, err := evidencev1.NewArtifactIdentity(digestBytes(payload), identity.ArtifactType, identity.IntentDigest)
	if err != nil {
		t.Fatalf("derive artifact identity for served payload: %v", err)
	}
	f.evidence.Claims.Package.Identity = rederived
	return f.resealed(t)
}

// resealed signs the fixture's evidence claims again and points the discovery
// record at the exact evidence bytes writeJSONResponse serves.
func (f preparedArtifactFixture) resealed(t *testing.T) preparedArtifactFixture {
	t.Helper()
	canonical, err := f.evidence.CanonicalBytes()
	if err != nil {
		t.Fatalf("canonicalize evidence: %v", err)
	}
	f.evidence.Seal = evidencev1.NewSeal(canonical, f.keyID, "ed25519", base64.StdEncoding.EncodeToString(ed25519.Sign(f.privateKey, canonical)))

	identity := f.evidence.Claims.Package.Identity
	f.discovery.Artifact.ArtifactDigest = identity.ArtifactDigest
	f.discovery.Artifact.ArtifactType = identity.ArtifactType
	f.discovery.Artifact.IntentDigest = identity.IntentDigest
	f.discovery.Evidence.Digest = digestBytes(servedJSONDocument(t, f.evidence))
	f.discovery.Payload.Digest = identity.PayloadDigest
	return f
}

func (f preparedArtifactFixture) service() Service {
	return Service{
		provenanceVerifier: &ed25519Verifier{
			algorithm: "ed25519",
			keyID:     f.keyID,
			publicKey: f.publicKey,
		},
	}
}

func (f preparedArtifactFixture) prepareRequest() PrepareRequest {
	return PrepareRequest{
		SchemaVersion: "v1",
		Invocation: ArtifactInvocation{
			SchemaVersion:        "v1",
			ArtifactDigest:       f.discovery.Artifact.ArtifactDigest,
			DerivationSpecDigest: f.evidence.Claims.Admission.Authorization.Derivation.DerivationSpecDigest,
			OutputID:             f.evidence.Claims.Admission.Authorization.Derivation.OutputID,
			Env: map[string]string{
				"APP_MODE": "test",
			},
		},
	}
}

func validArtifactDiscoveryFixture() arsapi.ArtifactDiscovery {
	return arsapi.ArtifactDiscovery{
		SchemaVersion: arsapi.ArtifactDiscoverySchemaVersion,
		Artifact: arsapi.ArtifactIdentity{
			ArtifactDigest: labeledDigest("aa"),
			ArtifactType:   "static-script",
			IntentDigest:   labeledDigest("bb"),
		},
		Evidence: arsapi.ArtifactBlobRef{
			Digest: labeledDigest("cc"),
		},
		Payload: arsapi.ArtifactBlobRef{
			Digest: labeledDigest("dd"),
		},
	}
}

func newArtifactRegistryTestClient(t *testing.T, handler http.Handler) *dependencyClient {
	t.Helper()

	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)

	baseURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("parse artifact registry test url: %v", err)
	}
	return &dependencyClient{
		dependencyName: "artifact-registry",
		baseURL:        baseURL,
		client: &http.Client{
			Timeout: time.Second,
		},
	}
}

func writeJSONResponse(t *testing.T, w http.ResponseWriter, status int, payload any) {
	t.Helper()

	document := servedJSONDocument(t, payload)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if _, err := w.Write(document); err != nil {
		t.Fatalf("write json response: %v", err)
	}
}

// servedJSONDocument returns the exact bytes writeJSONResponse serves for a
// payload, so a fixture can name a JSON blob by the digest of those bytes.
func servedJSONDocument(t *testing.T, payload any) []byte {
	t.Helper()

	var document bytes.Buffer
	if err := json.NewEncoder(&document).Encode(payload); err != nil {
		t.Fatalf("encode json response: %v", err)
	}
	return document.Bytes()
}

func labeledDigest(bytePair string) string {
	return "sha256:" + strings.Repeat(bytePair, 32)
}
