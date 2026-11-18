package admission

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"execution-substrate/es/internal/staticarchive/testcorpus"
	evidencev1 "execution-substrate/internal/contracts/evidence/v1"
)

func TestA2PolicyEntrypointInterpretation(t *testing.T) {
	for _, fixture := range testcorpus.Cases() {
		t.Run(fixture.Name, func(t *testing.T) {
			payload := a2Archive(t, fixture.Entries, nil)
			text, err := staticScriptPayloadTextForAdmissionPolicy(payload)
			if fixture.Valid {
				if err != nil || text != fixture.WantText {
					t.Fatalf("accepted text mismatch: length=%d err=%+v", len(text), err)
				}
				return
			}
			a2AssertUnavailable(t, err)
			if text != "" {
				t.Fatalf("ambiguous input returned %d text bytes", len(text))
			}
		})
	}
}

func TestA2SparseAdmissionRefusal(t *testing.T) {
	for _, fixture := range testcorpus.SparseCases() {
		t.Run(fixture.Name, func(t *testing.T) {
			text, err := staticScriptPayloadTextForAdmissionPolicy(a2Archive(t, fixture.Entries, nil))
			a2AssertUnavailable(t, err)
			if text != "" {
				t.Fatalf("sparse archive returned %d entrypoint bytes", len(text))
			}
		})
	}
}

func TestA2OnceOnlyPolicyAgreement(t *testing.T) {
	for _, fixture := range testcorpus.OnceOnlyCases() {
		t.Run(fixture.Name, func(t *testing.T) {
			text, err := staticScriptPayloadTextForAdmissionPolicy(a2Archive(t, fixture.Entries, nil))
			if err != nil || text != fixture.WantText {
				t.Fatalf("once-cleaned policy entrypoint mismatch: length=%d err=%+v", len(text), err)
			}
		})
	}
}

func TestA2PrepareAndSubmitRejectAmbiguousEntrypoint(t *testing.T) {
	for _, fixture := range testcorpus.Cases() {
		if fixture.Valid {
			continue
		}
		for _, operation := range []string{"prepare", "submit"} {
			t.Run(fixture.Name+"/"+operation, func(t *testing.T) {
				payload := a2Archive(t, fixture.Entries, nil)
				artifact := newPreparedArtifactFixture(t)
				a2BindSignedPayload(t, &artifact, payload)
				service, stagingRoot, resultsRoot := newWorkstreamCTestService(t, artifact)
				configureConfiguredStaticScriptLiteralDenyService(service, "A2_INERT_DENY_MARKER")
				arsCalls := map[string]int{}
				service.arsClient = newArtifactRegistryTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					arsCalls[r.URL.Path]++
					switch r.URL.Path {
					case "/v1/artifacts/" + artifact.discovery.Artifact.ArtifactDigest + "/discovery":
						writeJSONResponse(t, w, http.StatusOK, artifact.discovery)
					case "/v1/blobs/" + artifact.discovery.Evidence.Digest + ":json":
						writeJSONResponse(t, w, http.StatusOK, artifact.evidence)
					case "/v1/blobs/" + testWorkloadZoneVaultConfigDigest + ":json":
						_, _ = w.Write([]byte(validWorkloadZoneVaultConfigBlob))
					case "/v1/blobs/" + artifact.discovery.Payload.Digest + ":bytes":
						_, _ = w.Write(payload)
					default:
						t.Errorf("unexpected ARS path %q", r.URL.Path)
					}
				}))
				nomadCalls := 0
				service.nomadClient = newTestNomadClient(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { nomadCalls++ }))
				request := artifact.prepareRequest()
				if operation == "submit" {
					request.Mode = ExecutionModeAsync
					result, err := service.Submit(context.Background(), request)
					a2AssertUnavailable(t, err)
					if result.RunID != "" || result.Submitted {
						t.Fatalf("ambiguous input got receipt %+v", result)
					}
				} else {
					result, err := service.Prepare(context.Background(), request)
					a2AssertUnavailable(t, err)
					if result.Success {
						t.Fatalf("ambiguous input prepared successfully: %+v", result)
					}
				}
				if nomadCalls != 0 {
					t.Fatalf("ambiguous input reached Nomad %d time(s)", nomadCalls)
				}
				assertDirectoryEmpty(t, stagingRoot)
				assertDirectoryEmpty(t, resultsRoot)
				assertExactCallCount(t, arsCalls, "/v1/artifacts/"+artifact.discovery.Artifact.ArtifactDigest+"/discovery", 1)
				assertExactCallCount(t, arsCalls, "/v1/blobs/"+artifact.discovery.Evidence.Digest+":json", 1)
				assertExactCallCount(t, arsCalls, "/v1/blobs/"+testWorkloadZoneVaultConfigDigest+":json", 1)
				assertExactCallCount(t, arsCalls, "/v1/blobs/"+artifact.discovery.Payload.Digest+":bytes", 1)
				if len(arsCalls) != 4 {
					t.Fatalf("unexpected admission reads: %v", arsCalls)
				}
			})
		}
	}
}

func TestA2PolicyRuntimeEntrypointAgreement(t *testing.T) {
	// Runtimehelper runs this same ordered corpus and compares the materialized
	// entrypoint to WantText; this side checks the policy-approved bytes.
	for _, fixture := range testcorpus.Cases() {
		t.Run(fixture.Name, func(t *testing.T) {
			text, err := staticScriptPayloadTextForAdmissionPolicy(a2Archive(t, fixture.Entries, nil))
			if fixture.Valid {
				if err != nil || text != fixture.WantText {
					t.Fatalf("policy bytes differ from common corpus: length=%d err=%+v", len(text), err)
				}
			} else {
				a2AssertUnavailable(t, err)
			}
		})
	}
}

func TestA2PayloadScanBounds(t *testing.T) {
	benign := testcorpus.Entry{Name: "entrypoint", Body: []byte(testcorpus.BenignText)}
	for _, tc := range []struct {
		name     string
		entries  []testcorpus.Entry
		trailing []byte
		valid    bool
	}{
		{"text at limit", []testcorpus.Entry{{Name: "entrypoint", Body: bytes.Repeat([]byte("a"), maxAdmissionPolicyStaticScriptTextBytes)}}, nil, true},
		{"text beyond limit", []testcorpus.Entry{{Name: "entrypoint", Body: bytes.Repeat([]byte("a"), maxAdmissionPolicyStaticScriptTextBytes+1)}}, nil, false},
		{"zero tar tail", []testcorpus.Entry{benign}, []byte{0, 0}, true},
		{"nonzero tar tail", []testcorpus.Entry{benign}, []byte{0, 1}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			text, err := staticScriptPayloadTextForAdmissionPolicy(a2Archive(t, tc.entries, tc.trailing))
			if tc.valid {
				if err != nil || len(text) == 0 {
					t.Fatalf("valid boundary rejected: %+v", err)
				}
			} else {
				a2AssertUnavailable(t, err)
			}
		})
	}
	for _, count := range []int{maxAdmissionPolicyStaticScriptEntries, maxAdmissionPolicyStaticScriptEntries + 1} {
		t.Run(fmt.Sprintf("entry count %d", count), func(t *testing.T) {
			entries := make([]testcorpus.Entry, count)
			entries[0] = benign
			for i := 1; i < count; i++ {
				entries[i] = testcorpus.Entry{Name: "support/" + string(rune('A'+i)), Body: nil}
			}
			_, err := staticScriptPayloadTextForAdmissionPolicy(a2Archive(t, entries, nil))
			if count == maxAdmissionPolicyStaticScriptEntries {
				if err != nil {
					t.Fatalf("at-limit entry count rejected: %+v", err)
				}
			} else {
				a2AssertUnavailable(t, err)
			}
		})
	}
	decoded, err := testcorpus.Tar([]testcorpus.Entry{benign, {Name: "padding", Body: bytes.Repeat([]byte{0}, maxAdmissionPolicyDecodedArchiveBytes-2560)}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(decoded) != maxAdmissionPolicyDecodedArchiveBytes {
		t.Fatalf("unexpected decoded boundary fixture length %d", len(decoded))
	}
	for _, tc := range []struct {
		name    string
		decoded []byte
		valid   bool
	}{
		{"decoded at limit", decoded, true},
		{"decoded beyond limit", append(bytes.Clone(decoded), 0), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			payload, err := testcorpus.Gzip(tc.decoded)
			if err != nil {
				t.Fatal(err)
			}
			if len(payload) > maxAdmissionPolicyPayloadBytes {
				t.Fatalf("compressed boundary fixture exceeds compressed cap: %d", len(payload))
			}
			_, policyErr := staticScriptPayloadTextForAdmissionPolicy(payload)
			if tc.valid {
				if policyErr != nil {
					t.Fatalf("decoded limit equality rejected: %+v", policyErr)
				}
			} else {
				a2AssertUnavailable(t, policyErr)
			}
		})
	}
	base := a2Archive(t, []testcorpus.Entry{benign, {Name: "late", Body: bytes.Repeat([]byte("a"), 1024)}}, nil)
	t.Run("truncated late gzip", func(t *testing.T) {
		_, err := staticScriptPayloadTextForAdmissionPolicy(base[:len(base)-5])
		a2AssertUnavailable(t, err)
	})
	t.Run("truncated late member with valid gzip", func(t *testing.T) {
		decoded, err := testcorpus.Tar([]testcorpus.Entry{benign, {Name: "late", Body: bytes.Repeat([]byte("a"), 1024)}}, nil)
		if err != nil {
			t.Fatal(err)
		}
		payload, err := testcorpus.Gzip(decoded[:1536+10])
		if err != nil {
			t.Fatal(err)
		}
		_, policyErr := staticScriptPayloadTextForAdmissionPolicy(payload)
		a2AssertUnavailable(t, policyErr)
	})
	t.Run("concatenated gzip", func(t *testing.T) {
		_, err := staticScriptPayloadTextForAdmissionPolicy(append(bytes.Clone(base), base...))
		a2AssertUnavailable(t, err)
	})
	t.Run("late unsupported after entrypoint", func(t *testing.T) {
		_, err := staticScriptPayloadTextForAdmissionPolicy(a2Archive(t, []testcorpus.Entry{benign, {Name: "late-link", Type: tar.TypeSymlink}}, nil))
		a2AssertUnavailable(t, err)
	})
}

func a2Archive(t *testing.T, entries []testcorpus.Entry, trailing []byte) []byte {
	t.Helper()
	payload, err := testcorpus.Archive(entries, trailing)
	if err != nil {
		t.Fatal(err)
	}
	return payload
}

func a2AssertUnavailable(t *testing.T, err *Error) {
	t.Helper()
	assertAdmissionError(t, err, http.StatusForbidden, codeAdmissionPolicyInputUnavailable)
	if err.Message != "admission policy input unavailable" {
		t.Fatalf("unsafe admission message %q", err.Message)
	}
	encoded, marshalErr := json.Marshal(ErrorResponse{Success: false, Error: err.Message, Code: err.Code})
	if marshalErr != nil {
		t.Fatal(marshalErr)
	}
	if bytes.Contains(encoded, []byte(testcorpus.DeniedText)) || bytes.Contains(encoded, []byte("A2_INERT_DENY_MARKER")) {
		t.Fatalf("policy input exposed in error envelope")
	}
}

func a2BindSignedPayload(t *testing.T, fixture *preparedArtifactFixture, payload []byte) {
	t.Helper()
	identity, err := evidencev1.NewArtifactIdentity(digestBytes(payload), "static-script", fixture.evidence.Claims.Package.Identity.IntentDigest)
	if err != nil {
		t.Fatal(err)
	}
	fixture.evidence.Claims.Package.Identity = identity
	fixture.discovery.Artifact.ArtifactDigest = identity.ArtifactDigest
	fixture.discovery.Artifact.ArtifactType = identity.ArtifactType
	fixture.discovery.Artifact.IntentDigest = identity.IntentDigest
	fixture.discovery.Payload.Digest = identity.PayloadDigest
	resignPreparedArtifactFixture(t, fixture)
}
