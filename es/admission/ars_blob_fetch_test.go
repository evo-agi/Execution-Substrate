package admission

import (
	"bytes"
	"context"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"

	runtimeconfigv1 "execution-substrate/internal/contracts/runtimeconfig/v1"
)

// arsRequestLog records every ARS request path a test server receives. The
// handler runs on the server goroutine, so access is locked.
type arsRequestLog struct {
	mu    sync.Mutex
	paths map[string]int
	total int
}

func newARSRequestLog() *arsRequestLog {
	return &arsRequestLog{paths: map[string]int{}}
}

func (l *arsRequestLog) record(path string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.paths[path]++
	l.total++
}

func (l *arsRequestLog) count(path string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.paths[path]
}

func (l *arsRequestLog) requests() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.total
}

// payloadBlindAdmissionPolicy allows every artifact and asks for no payload
// input, so Submit acquires the primary payload through its own read instead
// of reusing the admission-policy read.
type payloadBlindAdmissionPolicy struct{}

func (payloadBlindAdmissionPolicy) RequiredInputClasses(AdmissionPolicyContext) []AdmissionPolicyInputClass {
	return nil
}

func (payloadBlindAdmissionPolicy) Evaluate(context.Context, AdmissionPolicyContext) AdmissionPolicyDecision {
	return AllowAdmissionPolicyDecision()
}

// reencodedJSONDocument returns the same JSON value as servedJSONDocument but
// with different bytes, so a decoder accepts it while its SHA-256 differs.
func reencodedJSONDocument(t *testing.T, payload any) []byte {
	t.Helper()
	document, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		t.Fatalf("re-encode JSON document: %v", err)
	}
	if bytes.Equal(document, servedJSONDocument(t, payload)) {
		t.Fatal("re-encoded JSON document did not change its bytes")
	}
	return document
}

func newARSBlobTestService(t *testing.T, log *arsRequestLog, serve func(w http.ResponseWriter, r *http.Request)) *Service {
	t.Helper()
	return &Service{
		arsClient: newArtifactRegistryTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			log.record(r.URL.Path)
			serve(w, r)
		})),
	}
}

func TestFetchVerifiedARSBlobReturnsOnlyBytesThatHashToTheRequestedDigest(t *testing.T) {
	blob := []byte(`{"verified":"exact bytes"}`)
	digest := digestBytes(blob)
	flipped := append([]byte(nil), blob...)
	flipped[len(flipped)-2] ^= 0x01
	other := []byte(`{"verified":"other bytes"}`)

	for _, test := range []struct {
		name   string
		served []byte
		accept bool
	}{
		{name: "exact bytes", served: blob, accept: true},
		{name: "one flipped bit", served: flipped},
		{name: "one extra trailing byte", served: append(append([]byte(nil), blob...), '\n')},
		{name: "one byte short", served: blob[:len(blob)-1]},
		{name: "empty body", served: []byte{}},
		{name: "another stored blob", served: other},
	} {
		for _, view := range []arsBlobView{arsBlobViewBytes, arsBlobViewJSON} {
			t.Run(test.name+string(view), func(t *testing.T) {
				log := newARSRequestLog()
				service := newARSBlobTestService(t, log, func(w http.ResponseWriter, r *http.Request) {
					if r.Method != http.MethodGet || r.URL.Path != "/v1/blobs/"+digest+string(view) {
						t.Errorf("unexpected ARS request %s %q", r.Method, r.URL.Path)
						w.WriteHeader(http.StatusTeapot)
						return
					}
					_, _ = w.Write(test.served)
				})
				got, fetchErr := service.fetchVerifiedARSBlob(context.Background(), digest, view, maxDependencyJSONResponseBytes)
				if log.requests() != 1 {
					t.Fatalf("expected exactly one ARS request, got %d", log.requests())
				}
				if test.accept {
					if fetchErr != nil || !bytes.Equal(got, blob) {
						t.Fatalf("exact bytes were refused: %+v", fetchErr)
					}
					return
				}
				if fetchErr == nil || fetchErr.failure != arsBlobDigestMismatch || got != nil {
					t.Fatalf("bytes that do not hash to the digest were not refused: bytes=%q err=%+v", got, fetchErr)
				}
				if fetchErr.cause != errARSBlobDigestMismatch {
					t.Fatalf("digest mismatch carried cause %v", fetchErr.cause)
				}
			})
		}
	}
}

func TestFetchVerifiedARSBlobAcceptsTheEmptyBlobOnlyUnderTheEmptyDigest(t *testing.T) {
	log := newARSRequestLog()
	service := newARSBlobTestService(t, log, func(w http.ResponseWriter, r *http.Request) {})
	got, fetchErr := service.fetchVerifiedARSBlob(context.Background(), digestBytes(nil), arsBlobViewBytes, 16)
	if fetchErr != nil || got == nil || len(got) != 0 {
		t.Fatalf("empty blob under its own digest was refused: %+v", fetchErr)
	}
	_, fetchErr = service.fetchVerifiedARSBlob(context.Background(), labeledDigest("ab"), arsBlobViewBytes, 16)
	if fetchErr == nil || fetchErr.failure != arsBlobDigestMismatch {
		t.Fatalf("empty body under another digest was not refused: %+v", fetchErr)
	}
}

func TestFetchVerifiedARSBlobRefusesNonCanonicalDigestsWithoutARequest(t *testing.T) {
	canonical := digestBytes([]byte("canonical"))
	hex := strings.TrimPrefix(canonical, "sha256:")
	for _, digest := range []string{
		"",
		"sha256:",
		hex,
		"sha256:" + hex[:63],
		"sha256:" + hex + "0",
		"sha256:" + strings.ToUpper(hex),
		"SHA256:" + hex,
		"sha512:" + hex,
		" " + canonical,
		canonical + " ",
		canonical + "\n",
		"\t" + canonical,
		canonical + ":bytes",
		canonical + "/../" + hex,
		"sha256:" + hex[:62] + "g0",
	} {
		t.Run(strconv.Quote(digest), func(t *testing.T) {
			log := newARSRequestLog()
			service := newARSBlobTestService(t, log, func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte("canonical"))
			})
			for _, view := range []arsBlobView{arsBlobViewBytes, arsBlobViewJSON} {
				got, fetchErr := service.fetchVerifiedARSBlob(context.Background(), digest, view, maxDependencyJSONResponseBytes)
				if got != nil || fetchErr == nil || fetchErr.failure != arsBlobDigestNotCanonical {
					t.Fatalf("non-canonical digest was not refused before the request: bytes=%q err=%+v", got, fetchErr)
				}
			}
			if log.requests() != 0 {
				t.Fatalf("non-canonical digest sent %d ARS requests", log.requests())
			}
		})
	}
}

func TestFetchVerifiedARSBlobClassifiesTransportFailuresWithoutBytes(t *testing.T) {
	blob := []byte("bounded")
	digest := digestBytes(blob)
	for _, test := range []struct {
		name   string
		serve  func(w http.ResponseWriter)
		limit  int64
		want   arsBlobFetchFailure
		status int
	}{
		{name: "not found", serve: func(w http.ResponseWriter) { w.WriteHeader(http.StatusNotFound) }, limit: 64, want: arsBlobNotFound, status: http.StatusNotFound},
		{name: "server error with the right bytes", serve: func(w http.ResponseWriter) { w.WriteHeader(http.StatusInternalServerError); _, _ = w.Write(blob) }, limit: 64, want: arsBlobUnexpectedStatus, status: http.StatusInternalServerError},
		{name: "partial content with the right bytes", serve: func(w http.ResponseWriter) { w.WriteHeader(http.StatusPartialContent); _, _ = w.Write(blob) }, limit: 64, want: arsBlobUnexpectedStatus, status: http.StatusPartialContent},
		{name: "over the read limit", serve: func(w http.ResponseWriter) { _, _ = w.Write(blob) }, limit: int64(len(blob) - 1), want: arsBlobReadFailed},
	} {
		t.Run(test.name, func(t *testing.T) {
			log := newARSRequestLog()
			service := newARSBlobTestService(t, log, func(w http.ResponseWriter, r *http.Request) { test.serve(w) })
			got, fetchErr := service.fetchVerifiedARSBlob(context.Background(), digest, arsBlobViewBytes, test.limit)
			if got != nil || fetchErr == nil || fetchErr.failure != test.want || fetchErr.status != test.status {
				t.Fatalf("unexpected result bytes=%q err=%+v", got, fetchErr)
			}
		})
	}
}

// TestARSBlobDigestMismatchPublicMappings drives each covered read with bytes
// that ARS answers with 200 but that do not hash to the requested digest, and
// checks the public error each call site returns.
func TestARSBlobDigestMismatchPublicMappings(t *testing.T) {
	signed := []byte("signed payload bytes")
	signedDigest := digestBytes(signed)
	served := []byte("substituted payload bytes")
	log := newARSRequestLog()
	service := newARSBlobTestService(t, log, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(served)
	})

	t.Run("primary payload", func(t *testing.T) {
		got, publicErr := service.fetchPayloadBytes(context.Background(), signedDigest)
		assertAdmissionError(t, publicErr, http.StatusServiceUnavailable, codePayloadUnavailable)
		if got != nil || publicErr.Message != artifactPayloadDigestMismatchMessage {
			t.Fatalf("unexpected primary payload mismatch result: %+v", publicErr)
		}
	})
	t.Run("mount payload", func(t *testing.T) {
		got, acquisitionErr, publicErr := service.fetchPayloadBytesWithin(context.Background(), signedDigest, maxRuntimeMountBytes)
		assertAdmissionError(t, publicErr, http.StatusServiceUnavailable, codePayloadUnavailable)
		if got != nil || publicErr.Message != artifactPayloadDigestMismatchMessage || acquisitionErr != errARSBlobDigestMismatch || boundedResponseTooLarge(acquisitionErr) {
			t.Fatalf("unexpected mount payload mismatch result: %+v cause=%v", publicErr, acquisitionErr)
		}
	})
	t.Run("admission policy payload", func(t *testing.T) {
		got, publicErr := service.fetchAdmissionPolicyPayloadBytes(context.Background(), signedDigest)
		if got != nil || publicErr == nil || *publicErr != *admissionPolicyInputUnavailableError() {
			t.Fatalf("unexpected admission policy payload mismatch result: %+v", publicErr)
		}
	})
	t.Run("artifact evidence", func(t *testing.T) {
		_, publicErr := service.fetchArtifactEvidenceBlob(context.Background(), labeledDigest("aa"), signedDigest)
		assertAdmissionError(t, publicErr, http.StatusServiceUnavailable, codeArtifactEvidenceUnavailable)
		if publicErr.Message != artifactEvidenceDigestMismatchMessage {
			t.Fatalf("unexpected evidence mismatch message %q", publicErr.Message)
		}
	})
	t.Run("workload-zone vault blob", func(t *testing.T) {
		_, publicErr := service.fetchWorkloadZoneVaultConfig(context.Background(), runtimeconfigv1.WorkloadZoneVaultConfigRef{Digest: signedDigest})
		assertAdmissionError(t, publicErr, http.StatusServiceUnavailable, codeWorkloadZoneVaultUnavailable)
		if publicErr.Message != workloadZoneVaultBlobDigestMismatchMessage {
			t.Fatalf("unexpected vault blob mismatch message %q", publicErr.Message)
		}
	})
	for _, message := range []string{artifactPayloadDigestMismatchMessage, artifactEvidenceDigestMismatchMessage, workloadZoneVaultBlobDigestMismatchMessage} {
		if strings.Contains(message, "sha256") || strings.Contains(message, string(served)) || strings.Contains(message, strings.TrimPrefix(signedDigest, "sha256:")) {
			t.Fatalf("public mismatch message leaks digest or bytes: %q", message)
		}
	}
	if log.requests() != 5 {
		t.Fatalf("expected one ARS read per covered call site, got %d", log.requests())
	}
}

// TestARSBlobCallSitesRequestTheDigestExactlyAsGiven passes each covered call
// site a non-canonical spelling of the digest of the bytes ARS serves. A call
// site that trimmed or lowercased the digest before the helper would read and
// accept those bytes; each must instead refuse with its "unavailable" mapping
// and send no request. Evidence validation accepts uppercase hex, so a sealed
// uppercase payload_digest reaches the payload reads in this form.
func TestARSBlobCallSitesRequestTheDigestExactlyAsGiven(t *testing.T) {
	blob := []byte(validWorkloadZoneVaultConfigBlob)
	canonical := digestBytes(blob)
	hex := strings.TrimPrefix(canonical, "sha256:")
	for _, digest := range []string{
		"sha256:" + strings.ToUpper(hex),
		" " + canonical,
		canonical + "\n",
	} {
		t.Run(strconv.Quote(digest), func(t *testing.T) {
			log := newARSRequestLog()
			service := newARSBlobTestService(t, log, func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write(blob)
			})
			t.Run("primary payload", func(t *testing.T) {
				got, publicErr := service.fetchPayloadBytes(context.Background(), digest)
				assertAdmissionError(t, publicErr, http.StatusServiceUnavailable, codePayloadUnavailable)
				if got != nil || publicErr.Message != "artifact payload is unavailable" {
					t.Fatalf("primary payload call site did not refuse the digest as given: bytes=%d err=%+v", len(got), publicErr)
				}
			})
			t.Run("mount payload", func(t *testing.T) {
				got, acquisitionErr, publicErr := service.fetchPayloadBytesWithin(context.Background(), digest, maxRuntimeMountBytes)
				assertAdmissionError(t, publicErr, http.StatusServiceUnavailable, codePayloadUnavailable)
				if got != nil || acquisitionErr != nil || publicErr.Message != "artifact payload is unavailable" {
					t.Fatalf("mount payload call site did not refuse the digest as given: bytes=%d cause=%v err=%+v", len(got), acquisitionErr, publicErr)
				}
			})
			t.Run("admission policy payload", func(t *testing.T) {
				got, publicErr := service.fetchAdmissionPolicyPayloadBytes(context.Background(), digest)
				if got != nil || publicErr == nil || *publicErr != *admissionPolicyInputUnavailableError() {
					t.Fatalf("admission policy call site did not refuse the digest as given: bytes=%d err=%+v", len(got), publicErr)
				}
			})
			t.Run("artifact evidence", func(t *testing.T) {
				_, publicErr := service.fetchArtifactEvidenceBlob(context.Background(), labeledDigest("aa"), digest)
				assertAdmissionError(t, publicErr, http.StatusServiceUnavailable, codeArtifactEvidenceUnavailable)
				if publicErr.Message != "artifact evidence is unavailable" {
					t.Fatalf("evidence call site did not refuse the digest as given: %q", publicErr.Message)
				}
			})
			t.Run("workload-zone vault blob", func(t *testing.T) {
				_, publicErr := service.fetchWorkloadZoneVaultConfig(context.Background(), runtimeconfigv1.WorkloadZoneVaultConfigRef{Digest: digest})
				assertAdmissionError(t, publicErr, http.StatusServiceUnavailable, codeWorkloadZoneVaultUnavailable)
				if publicErr.Message != "artifact registry workload-zone vault blob is unavailable" {
					t.Fatalf("vault call site did not refuse the digest as given: %q", publicErr.Message)
				}
			})
			if log.requests() != 0 {
				t.Fatalf("a call site sent %d ARS requests for a non-canonical digest", log.requests())
			}
		})
	}
}

// TestARSBlobCallSitesMapNotFound has ARS answer 404 for every covered read
// and checks each call site's own "unavailable" mapping, which no other test
// reaches through the not-found class.
func TestARSBlobCallSitesMapNotFound(t *testing.T) {
	digest := digestBytes([]byte("absent blob"))
	log := newARSRequestLog()
	service := newARSBlobTestService(t, log, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	t.Run("primary payload", func(t *testing.T) {
		got, publicErr := service.fetchPayloadBytes(context.Background(), digest)
		assertAdmissionError(t, publicErr, http.StatusServiceUnavailable, codePayloadUnavailable)
		if got != nil || publicErr.Message != "artifact payload is unavailable" {
			t.Fatalf("unexpected primary payload not-found mapping: %+v", publicErr)
		}
	})
	t.Run("mount payload", func(t *testing.T) {
		got, acquisitionErr, publicErr := service.fetchPayloadBytesWithin(context.Background(), digest, maxRuntimeMountBytes)
		assertAdmissionError(t, publicErr, http.StatusServiceUnavailable, codePayloadUnavailable)
		if got != nil || acquisitionErr != nil || publicErr.Message != "artifact payload is unavailable" {
			t.Fatalf("unexpected mount payload not-found mapping: cause=%v err=%+v", acquisitionErr, publicErr)
		}
	})
	t.Run("admission policy payload", func(t *testing.T) {
		got, publicErr := service.fetchAdmissionPolicyPayloadBytes(context.Background(), digest)
		if got != nil || publicErr == nil || *publicErr != *admissionPolicyInputUnavailableError() {
			t.Fatalf("unexpected admission policy not-found mapping: %+v", publicErr)
		}
	})
	t.Run("artifact evidence", func(t *testing.T) {
		_, publicErr := service.fetchArtifactEvidenceBlob(context.Background(), labeledDigest("aa"), digest)
		assertAdmissionError(t, publicErr, http.StatusServiceUnavailable, codeArtifactEvidenceUnavailable)
		if publicErr.Message != "artifact evidence is unavailable" {
			t.Fatalf("unexpected evidence not-found message %q", publicErr.Message)
		}
	})
	t.Run("workload-zone vault blob", func(t *testing.T) {
		_, publicErr := service.fetchWorkloadZoneVaultConfig(context.Background(), runtimeconfigv1.WorkloadZoneVaultConfigRef{Digest: digest})
		assertAdmissionError(t, publicErr, http.StatusServiceUnavailable, codeWorkloadZoneVaultUnavailable)
		if publicErr.Message != "artifact registry workload-zone vault blob is unavailable" {
			t.Fatalf("unexpected vault blob not-found message %q", publicErr.Message)
		}
	})
	if log.requests() != 5 {
		t.Fatalf("expected one ARS read per covered call site, got %d", log.requests())
	}
}

// TestWorkloadZoneVaultBlobIsDecodedStrictlyFromVerifiedBytes names each body
// by its own digest, so the read verifies and the strict decoder refuses it.
func TestWorkloadZoneVaultBlobIsDecodedStrictlyFromVerifiedBytes(t *testing.T) {
	for _, body := range []string{
		`{"vault_config":`,
		`{"vault_config":{"address":"https://vault.internal:8200","auth_mount":"jwt","auth_role":"execution","jwt_audience":"vault"},"unknown_field":true}`,
		validWorkloadZoneVaultConfigBlob + `{}`,
	} {
		service := newARSBlobTestService(t, newARSRequestLog(), func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(body))
		})
		_, publicErr := service.fetchWorkloadZoneVaultConfig(context.Background(), runtimeconfigv1.WorkloadZoneVaultConfigRef{Digest: digestBytes([]byte(body))})
		assertAdmissionError(t, publicErr, http.StatusServiceUnavailable, codeWorkloadZoneVaultUnavailable)
		if publicErr.Message != "artifact registry workload-zone vault blob was invalid" {
			t.Fatalf("vault blob %q was not refused by the strict decoder: %q", body, publicErr.Message)
		}
	}
}

// signedPayloadHandler serves a primary artifact, and optionally one mount
// artifact, with every blob except the ones a case overrides.
type signedPayloadHandler struct {
	t                *testing.T
	log              *arsRequestLog
	fixture          preparedArtifactFixture
	payload          []byte
	evidenceDocument []byte
	vaultBlob        []byte
	mount            *preparedArtifactFixture
	mountPayload     []byte
	mountEvidence    []byte
}

func newSignedPayloadHandler(t *testing.T, fixture preparedArtifactFixture, payload []byte) *signedPayloadHandler {
	return &signedPayloadHandler{
		t:                t,
		log:              newARSRequestLog(),
		fixture:          fixture,
		payload:          payload,
		evidenceDocument: servedJSONDocument(t, fixture.evidence),
		vaultBlob:        []byte(validWorkloadZoneVaultConfigBlob),
	}
}

func (h *signedPayloadHandler) withMount(mount preparedArtifactFixture, payload []byte) *signedPayloadHandler {
	h.mount = &mount
	h.mountPayload = payload
	h.mountEvidence = servedJSONDocument(h.t, mount.evidence)
	return h
}

func (h *signedPayloadHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.log.record(r.URL.Path)
	switch r.URL.Path {
	case "/v1/artifacts/" + h.fixture.discovery.Artifact.ArtifactDigest + "/discovery":
		writeJSONResponse(h.t, w, http.StatusOK, h.fixture.discovery)
		return
	case "/v1/blobs/" + h.fixture.discovery.Evidence.Digest + ":json":
		_, _ = w.Write(h.evidenceDocument)
		return
	case "/v1/blobs/" + testWorkloadZoneVaultConfigDigest + ":json":
		_, _ = w.Write(h.vaultBlob)
		return
	case "/v1/blobs/" + h.fixture.discovery.Payload.Digest + ":bytes":
		_, _ = w.Write(h.payload)
		return
	}
	if h.mount != nil {
		switch r.URL.Path {
		case "/v1/artifacts/" + h.mount.discovery.Artifact.ArtifactDigest + "/discovery":
			writeJSONResponse(h.t, w, http.StatusOK, h.mount.discovery)
			return
		case "/v1/blobs/" + h.mount.discovery.Evidence.Digest + ":json":
			_, _ = w.Write(h.mountEvidence)
			return
		case "/v1/blobs/" + h.mount.discovery.Payload.Digest + ":bytes":
			_, _ = w.Write(h.mountPayload)
			return
		}
	}
	h.t.Errorf("unexpected ARS path %q", r.URL.Path)
	w.WriteHeader(http.StatusTeapot)
}

type nomadRegistrationLog struct {
	mu    sync.Mutex
	calls int
}

func (l *nomadRegistrationLog) count() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.calls
}

func newCountingNomadClient(t *testing.T, log *nomadRegistrationLog) *nomadClient {
	t.Helper()
	return newResolvedPlanNomadClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.mu.Lock()
		log.calls++
		log.mu.Unlock()
		if r.Method != http.MethodPost || r.URL.Path != "/v1/jobs" {
			t.Errorf("unexpected Nomad request %s %q", r.Method, r.URL.Path)
		}
		_, _ = w.Write([]byte(`{"EvalID":"eval-verified-bytes"}`))
	}))
}

func signedStaticScriptFixture(t *testing.T) (preparedArtifactFixture, []byte) {
	t.Helper()
	payload := buildAdmissionPolicyStaticScriptArchive(t, map[string][]byte{
		staticScriptEntrypointName: []byte(benignPolicyFixtureText()),
	})
	return newPreparedArtifactFixture(t).withPayload(t, payload), payload
}

// substitutedStaticScriptPayload is a different, policy-clean static-script
// archive: only the digest check tells it apart from the signed payload.
func substitutedStaticScriptPayload(t *testing.T) []byte {
	t.Helper()
	return buildAdmissionPolicyStaticScriptArchive(t, map[string][]byte{
		staticScriptEntrypointName: []byte("#!/bin/sh\nprintf '%s\\n' substituted-but-benign\n"),
	})
}

func assertNoRunEffects(t *testing.T, nomad *nomadRegistrationLog, roots ...string) {
	t.Helper()
	if nomad.count() != 0 {
		t.Fatalf("refused bytes reached Nomad registration %d times", nomad.count())
	}
	for _, root := range roots {
		assertDirectoryEmpty(t, root)
	}
}

func TestSubmitStagesOnlyThePayloadBytesThatHashToTheSignedDigest(t *testing.T) {
	fixture, signed := signedStaticScriptFixture(t)
	for _, test := range []struct {
		name   string
		served []byte
	}{
		{name: "signed bytes", served: signed},
		{name: "substituted bytes", served: substitutedStaticScriptPayload(t)},
		{name: "signed bytes with a trailing byte", served: append(append([]byte(nil), signed...), 0)},
	} {
		t.Run(test.name, func(t *testing.T) {
			service, stagingRoot, resultsRoot := newWorkstreamCTestService(t, fixture)
			service.admissionPolicyEvaluator = payloadBlindAdmissionPolicy{}
			handler := newSignedPayloadHandler(t, fixture, test.served)
			service.arsClient = newResolvedPlanDependencyClient(t, handler)
			nomad := &nomadRegistrationLog{}
			service.nomadClient = newCountingNomadClient(t, nomad)
			request := fixture.prepareRequest()
			request.Mode = ExecutionModeAsync

			result, publicErr := service.Submit(context.Background(), request)
			payloadPath := "/v1/blobs/" + fixture.discovery.Payload.Digest + ":bytes"
			if handler.log.count(payloadPath) != 1 {
				t.Fatalf("expected exactly one primary payload read, got %d", handler.log.count(payloadPath))
			}
			if bytes.Equal(test.served, signed) {
				if publicErr != nil || !result.Submitted || nomad.count() != 1 {
					t.Fatalf("signed payload was not submitted: result=%+v err=%+v nomad=%d", result, publicErr, nomad.count())
				}
				assertFileContent(t, filepath.Join(stagingRoot, result.RunID, executionPayloadStageDirName, executionPayloadArchiveName), string(signed))
				return
			}
			assertAdmissionError(t, publicErr, http.StatusServiceUnavailable, codePayloadUnavailable)
			if publicErr.Message != artifactPayloadDigestMismatchMessage || result.Submitted || result.RunID != "" {
				t.Fatalf("substituted payload was not refused with the integrity message: result=%+v err=%+v", result, publicErr)
			}
			assertNoRunEffects(t, nomad, stagingRoot, resultsRoot)
		})
	}
}

func TestAdmissionPolicyInspectsOnlyPayloadBytesThatHashToTheSignedDigest(t *testing.T) {
	fixture, signed := signedStaticScriptFixture(t)
	substituted := substitutedStaticScriptPayload(t)
	for _, mode := range []ExecutionMode{"", ExecutionModeAsync} {
		for _, test := range []struct {
			name   string
			served []byte
		}{
			{name: "signed bytes", served: signed},
			{name: "substituted bytes", served: substituted},
		} {
			t.Run(string(mode)+" "+test.name, func(t *testing.T) {
				service, stagingRoot, resultsRoot := newWorkstreamCTestService(t, fixture)
				handler := newSignedPayloadHandler(t, fixture, test.served)
				service.arsClient = newResolvedPlanDependencyClient(t, handler)
				nomad := &nomadRegistrationLog{}
				service.nomadClient = newCountingNomadClient(t, nomad)
				request := fixture.prepareRequest()
				request.Mode = mode

				var publicErr *Error
				var submitted bool
				if mode == ExecutionModeAsync {
					result, err := service.Submit(context.Background(), request)
					publicErr, submitted = err, result.Submitted
				} else {
					_, publicErr = service.Prepare(context.Background(), request)
				}
				payloadPath := "/v1/blobs/" + fixture.discovery.Payload.Digest + ":bytes"
				if handler.log.count(payloadPath) != 1 {
					t.Fatalf("expected the policy read to be the only payload read, got %d", handler.log.count(payloadPath))
				}
				if bytes.Equal(test.served, signed) {
					if publicErr != nil || (mode == ExecutionModeAsync && (!submitted || nomad.count() != 1)) {
						t.Fatalf("signed payload was not admitted: err=%+v nomad=%d", publicErr, nomad.count())
					}
					return
				}
				if publicErr == nil || *publicErr != *admissionPolicyInputUnavailableError() {
					t.Fatalf("policy inspected substituted bytes: %+v", publicErr)
				}
				assertNoRunEffects(t, nomad, stagingRoot, resultsRoot)
			})
		}
	}
}

func TestSubmitRefusesMountBytesAndEvidenceThatDoNotHashToTheirDigests(t *testing.T) {
	fixture, signed := signedStaticScriptFixture(t)
	mountArchive := mustRuntimeMountArchiveBytes(t, runtimeMountArchiveEntry{name: "config.txt", body: []byte("signed mount"), typeflag: '0', mode: 0o644})
	mountFixture := fixture.withPayload(t, mountArchive)
	substitutedMount := mustRuntimeMountArchiveBytes(t, runtimeMountArchiveEntry{name: "config.txt", body: []byte("swapped mount"), typeflag: '0', mode: 0o644})
	for _, test := range []struct {
		name          string
		mountPayload  []byte
		mountEvidence []byte
		wantCode      string
		wantMessage   string
	}{
		{name: "signed mount", mountPayload: mountArchive},
		{name: "substituted mount bytes", mountPayload: substitutedMount, wantCode: codePayloadUnavailable, wantMessage: artifactPayloadDigestMismatchMessage},
		{name: "re-encoded mount evidence", mountPayload: mountArchive, mountEvidence: reencodedJSONDocument(t, mountFixture.evidence), wantCode: codeArtifactEvidenceUnavailable, wantMessage: artifactEvidenceDigestMismatchMessage},
	} {
		t.Run(test.name, func(t *testing.T) {
			service, stagingRoot, resultsRoot := newWorkstreamCTestService(t, fixture)
			handler := newSignedPayloadHandler(t, fixture, signed).withMount(mountFixture, test.mountPayload)
			if test.mountEvidence != nil {
				handler.mountEvidence = test.mountEvidence
			}
			service.arsClient = newResolvedPlanDependencyClient(t, handler)
			nomad := &nomadRegistrationLog{}
			service.nomadClient = newCountingNomadClient(t, nomad)
			request := fixture.prepareRequest()
			request.Mode = ExecutionModeAsync
			request.Invocation.Mounts = []RuntimeMount{{
				Source:     MountSource{ArtifactDigest: mountFixture.discovery.Artifact.ArtifactDigest},
				TargetPath: "/execution/mounts/config",
				ReadOnly:   true,
			}}

			result, publicErr := service.Submit(context.Background(), request)
			if test.wantCode == "" {
				if publicErr != nil || !result.Submitted || nomad.count() != 1 {
					t.Fatalf("signed mount was not submitted: result=%+v err=%+v nomad=%d", result, publicErr, nomad.count())
				}
				assertFileContent(t, filepath.Join(stagingRoot, result.RunID, executionMountsStageDirName, "00", "contents", "config.txt"), "signed mount")
				return
			}
			assertAdmissionError(t, publicErr, http.StatusServiceUnavailable, test.wantCode)
			if publicErr.Message != test.wantMessage || result.Submitted || result.RunID != "" {
				t.Fatalf("mount integrity failure was not refused with its message: result=%+v err=%+v", result, publicErr)
			}
			assertNoRunEffects(t, nomad, stagingRoot, resultsRoot)
		})
	}
}

// TestSubmitRefusesAMountDiscoveryRecordForAnotherArtifact has ARS answer
// the discovery read for the requested mount with the record of a different,
// validly sealed artifact. Every blob ES then reads hashes to its digest, so
// only the artifact-digest binding tells them apart: Submit must refuse
// instead of staging the other artifact's bytes as the mount. (:prepare does
// not resolve mounts.)
func TestSubmitRefusesAMountDiscoveryRecordForAnotherArtifact(t *testing.T) {
	fixture, signed := signedStaticScriptFixture(t)
	requestedArchive := mustRuntimeMountArchiveBytes(t, runtimeMountArchiveEntry{name: "config.txt", body: []byte("requested mount"), typeflag: '0', mode: 0o644})
	requested := fixture.withPayload(t, requestedArchive)
	otherArchive := mustRuntimeMountArchiveBytes(t, runtimeMountArchiveEntry{name: "config.txt", body: []byte("other sealed artifact"), typeflag: '0', mode: 0o644})
	other := fixture.withPayload(t, otherArchive)
	if other.discovery.Artifact.ArtifactDigest == requested.discovery.Artifact.ArtifactDigest {
		t.Fatal("the two mount artifacts must differ")
	}
	requestedDiscovery := "/v1/artifacts/" + requested.discovery.Artifact.ArtifactDigest + "/discovery"
	for _, mode := range []ExecutionMode{"", ExecutionModeAsync} {
		for _, substitute := range []bool{false, true} {
			t.Run(strconv.Quote(string(mode))+" substitute="+strconv.FormatBool(substitute), func(t *testing.T) {
				served, servedArchive := requested, requestedArchive
				if substitute {
					served, servedArchive = other, otherArchive
				}
				service, stagingRoot, resultsRoot := newWorkstreamCTestService(t, fixture)
				service.admissionPolicyEvaluator = payloadBlindAdmissionPolicy{}
				inner := newSignedPayloadHandler(t, fixture, signed).withMount(served, servedArchive)
				var mu sync.Mutex
				asked := 0
				service.arsClient = newResolvedPlanDependencyClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.URL.Path == requestedDiscovery {
						mu.Lock()
						asked++
						mu.Unlock()
						r.URL.Path = "/v1/artifacts/" + served.discovery.Artifact.ArtifactDigest + "/discovery"
					}
					inner.ServeHTTP(w, r)
				}))
				nomad := &nomadRegistrationLog{}
				service.nomadClient = newCountingNomadClient(t, nomad)
				request := fixture.prepareRequest()
				request.Mode = mode
				request.Invocation.Mounts = []RuntimeMount{{
					Source:     MountSource{ArtifactDigest: requested.discovery.Artifact.ArtifactDigest},
					TargetPath: "/execution/mounts/config",
					ReadOnly:   true,
				}}

				result, publicErr := service.Submit(context.Background(), request)
				mu.Lock()
				gotAsked := asked
				mu.Unlock()
				if gotAsked != 1 {
					t.Fatalf("expected one discovery read for the requested mount, got %d", gotAsked)
				}
				if !substitute {
					if publicErr != nil || !result.Submitted || nomad.count() != 1 {
						t.Fatalf("requested mount was not submitted: result=%+v err=%+v nomad=%d", result, publicErr, nomad.count())
					}
					assertFileContent(t, filepath.Join(stagingRoot, result.RunID, executionMountsStageDirName, "00", "contents", "config.txt"), "requested mount")
					return
				}
				assertAdmissionError(t, publicErr, http.StatusConflict, codeMountArtifactInvalid)
				if publicErr.Message != "artifact digest mismatch between mount source and artifact discovery" || result.Submitted || result.RunID != "" {
					t.Fatalf("another artifact's discovery record was not refused for the mount: result=%+v err=%+v", result, publicErr)
				}
				if reads := inner.log.count("/v1/blobs/" + other.discovery.Payload.Digest + ":bytes"); reads != 0 {
					t.Fatalf("the other artifact's payload was read %d times", reads)
				}
				assertNoRunEffects(t, nomad, stagingRoot, resultsRoot)
			})
		}
	}
}

func TestPrepareRefusesEvidenceAndVaultBlobsThatDoNotHashToTheirDigests(t *testing.T) {
	fixture, signed := signedStaticScriptFixture(t)
	substitutedVault, err := json.Marshal(runtimeconfigv1.WorkloadZoneVaultConfigBlob{VaultConfig: runtimeconfigv1.WorkloadZoneVaultConfig{
		Address:     "https://vault.substituted.invalid:8200",
		AuthMount:   "jwt",
		AuthRole:    "execution",
		JWTAudience: "vault",
	}})
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name        string
		evidence    []byte
		vault       []byte
		wantCode    string
		wantMessage string
	}{
		{name: "re-encoded evidence", evidence: reencodedJSONDocument(t, fixture.evidence), wantCode: codeArtifactEvidenceUnavailable, wantMessage: artifactEvidenceDigestMismatchMessage},
		{name: "valid but different vault config", vault: substitutedVault, wantCode: codeWorkloadZoneVaultUnavailable, wantMessage: workloadZoneVaultBlobDigestMismatchMessage},
		{name: "re-encoded vault config", vault: append([]byte(validWorkloadZoneVaultConfigBlob), '\n'), wantCode: codeWorkloadZoneVaultUnavailable, wantMessage: workloadZoneVaultBlobDigestMismatchMessage},
	} {
		for _, mode := range []ExecutionMode{"", ExecutionModeAsync} {
			t.Run(string(mode)+" "+test.name, func(t *testing.T) {
				service, stagingRoot, resultsRoot := newWorkstreamCTestService(t, fixture)
				handler := newSignedPayloadHandler(t, fixture, signed)
				if test.evidence != nil {
					handler.evidenceDocument = test.evidence
				}
				if test.vault != nil {
					handler.vaultBlob = test.vault
				}
				service.arsClient = newResolvedPlanDependencyClient(t, handler)
				nomad := &nomadRegistrationLog{}
				service.nomadClient = newCountingNomadClient(t, nomad)
				request := fixture.prepareRequest()
				request.Mode = mode

				var publicErr *Error
				if mode == ExecutionModeAsync {
					result, err := service.Submit(context.Background(), request)
					if result.Submitted || result.RunID != "" {
						t.Fatalf("refused dependency blob produced a run receipt: %+v", result)
					}
					publicErr = err
				} else {
					_, publicErr = service.Prepare(context.Background(), request)
				}
				assertAdmissionError(t, publicErr, http.StatusServiceUnavailable, test.wantCode)
				if publicErr.Message != test.wantMessage {
					t.Fatalf("unexpected integrity message %q", publicErr.Message)
				}
				if reads := handler.log.count("/v1/blobs/" + fixture.discovery.Payload.Digest + ":bytes"); reads != 0 {
					t.Fatalf("payload was read %d times after a dependency blob was refused", reads)
				}
				assertNoRunEffects(t, nomad, stagingRoot, resultsRoot)
			})
		}
	}
}

// TestFetchVerifiedARSBlobIsTheOnlyARSBlobReadInES keeps every ES read of an
// ARS blob on the verified path. In ES production code the ARS blob route may
// appear only inside fetchVerifiedARSBlob, and the ARS client may be used only
// there, by the discovery-record read and by the health check. A new read,
// including one merged in from another branch, fails here until it goes
// through the helper or is classified here.
func TestFetchVerifiedARSBlobIsTheOnlyARSBlobReadInES(t *testing.T) {
	esRoot, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(esRoot) != "es" {
		t.Fatalf("unexpected ES source root %q", esRoot)
	}
	type site struct {
		file string
		fn   string
		text string
	}
	var sites []site
	var clientUses []site
	var clientIdentifiers []site
	var registryConfigUses []site
	var discoveryReads []site
	files := 0
	walkErr := filepath.WalkDir(esRoot, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			if name := entry.Name(); path != esRoot && (name == "testdata" || strings.HasPrefix(name, ".") || strings.HasPrefix(name, "_")) {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		source, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		files++
		fset := token.NewFileSet()
		parsed, err := parser.ParseFile(fset, path, source, parser.SkipObjectResolution)
		if err != nil {
			return err
		}
		relative, _ := filepath.Rel(esRoot, path)
		for _, decl := range parsed.Decls {
			name := "<package scope>"
			if fn, ok := decl.(*ast.FuncDecl); ok {
				name = fn.Name.Name
			}
			calledClients := map[*ast.SelectorExpr]string{}
			clientFieldNames := map[*ast.Ident]bool{}
			ast.Inspect(decl, func(node ast.Node) bool {
				// A bare arsClient identifier (the field declaration, the
				// NewService local, a composite-literal key or value) is
				// recorded too, so the client cannot be copied into a second
				// field where no arsClient selector would show it.
				if ident, ok := node.(*ast.Ident); ok && ident.Name == "arsClient" && !clientFieldNames[ident] {
					clientIdentifiers = append(clientIdentifiers, site{file: filepath.ToSlash(relative), fn: name})
				}
				if call, ok := node.(*ast.CallExpr); ok {
					if method, ok := call.Fun.(*ast.SelectorExpr); ok {
						if client, ok := method.X.(*ast.SelectorExpr); ok && client.Sel.Name == "arsClient" {
							calledClients[client] = method.Sel.Name
						}
					}
				}
				if selector, ok := node.(*ast.SelectorExpr); ok && selector.Sel.Name == "ArtifactRegistry" {
					registryConfigUses = append(registryConfigUses, site{file: filepath.ToSlash(relative), fn: name})
				}
				if selector, ok := node.(*ast.SelectorExpr); ok && (selector.Sel.Name == "fetchArtifactDiscovery" || selector.Sel.Name == "fetchArtifactDiscoveryRecord") {
					discoveryReads = append(discoveryReads, site{file: filepath.ToSlash(relative), fn: name, text: selector.Sel.Name})
				}
				if selector, ok := node.(*ast.SelectorExpr); ok && selector.Sel.Name == "arsClient" {
					clientFieldNames[selector.Sel] = true
					// A use that is not the receiver of a direct method call
					// (an alias, a method value, an argument) is recorded as
					// such, so a second read cannot hide behind one selector.
					method, called := calledClients[selector]
					if !called {
						method = "<not a direct call>"
					}
					clientUses = append(clientUses, site{file: filepath.ToSlash(relative), fn: name, text: method})
					return true
				}
				literal, ok := node.(*ast.BasicLit)
				if !ok || literal.Kind != token.STRING {
					return true
				}
				value, err := strconv.Unquote(literal.Value)
				if err != nil {
					t.Errorf("unquote %s literal %s: %v", relative, literal.Value, err)
					return true
				}
				if strings.Contains(strings.ToLower(value), "blobs") {
					sites = append(sites, site{file: filepath.ToSlash(relative), fn: name, text: value})
				}
				return true
			})
		}
		return nil
	})
	if walkErr != nil {
		t.Fatal(walkErr)
	}
	if files < 50 {
		t.Fatalf("ES source walk found only %d production files", files)
	}
	want := site{file: "admission/ars_blob_fetch.go", fn: "fetchVerifiedARSBlob", text: "/v1/blobs/"}
	if len(sites) != 1 || sites[0] != want {
		t.Fatalf("ARS blob reads in ES production code must go through fetchVerifiedARSBlob; found %+v", sites)
	}
	wantClientUses := []site{
		{file: "admission/ars_blob_fetch.go", fn: "fetchVerifiedARSBlob", text: "get"},
		{file: "admission/service.go", fn: "Health", text: "checkReady"},
		{file: "admission/service.go", fn: "fetchArtifactDiscoveryRecord", text: "get"},
	}
	slices.SortFunc(clientUses, func(a, b site) int { return strings.Compare(a.file+" "+a.fn, b.file+" "+b.fn) })
	if !slices.Equal(clientUses, wantClientUses) {
		t.Fatalf("the ARS client is used outside the verified blob read, the discovery read and the health check: %+v", clientUses)
	}
	// The ARS client is declared once, built once in NewService and stored
	// once: the struct field, the local, and the literal's key and value.
	wantClientIdentifiers := []site{
		{file: "admission/service.go", fn: "<package scope>"},
		{file: "admission/service.go", fn: "NewService"},
		{file: "admission/service.go", fn: "NewService"},
		{file: "admission/service.go", fn: "NewService"},
	}
	slices.SortFunc(clientIdentifiers, func(a, b site) int { return strings.Compare(a.file+" "+a.fn, b.file+" "+b.fn) })
	if !slices.Equal(clientIdentifiers, wantClientIdentifiers) {
		t.Fatalf("the ARS client is declared, built or stored outside its one field and NewService: %+v", clientIdentifiers)
	}
	// The ARS dependency config may build only the one ARS client; a second
	// client would read ARS without going through arsClient.
	wantRegistryConfigUses := []site{
		{file: "admission/service.go", fn: "NewService"},
		{file: "config/config.go", fn: "Validate"},
	}
	slices.SortFunc(registryConfigUses, func(a, b site) int { return strings.Compare(a.file+" "+a.fn, b.file+" "+b.fn) })
	if !slices.Equal(registryConfigUses, wantRegistryConfigUses) {
		t.Fatalf("the ARS dependency config is read outside NewService and its validation: %+v", registryConfigUses)
	}
	// The discovery record is not verified, so every caller of the discovery
	// read must refuse a record that names another artifact than the one it
	// asked for: prepareArtifactFromDiscovery does for the primary artifact,
	// prepareMountArtifact for each mount, and both refusals are tested. A new
	// caller belongs here only with the same check and a test for it.
	wantDiscoveryReads := []site{
		{file: "admission/mounts.go", fn: "prepareMountArtifact", text: "fetchArtifactDiscovery"},
		{file: "admission/service.go", fn: "fetchArtifactDiscovery", text: "fetchArtifactDiscoveryRecord"},
		{file: "admission/service.go", fn: "prepareArtifact", text: "fetchArtifactDiscovery"},
	}
	slices.SortFunc(discoveryReads, func(a, b site) int { return strings.Compare(a.file+" "+a.fn, b.file+" "+b.fn) })
	if !slices.Equal(discoveryReads, wantDiscoveryReads) {
		t.Fatalf("the unverified discovery read has a caller that is not known to bind the record to the requested artifact: %+v", discoveryReads)
	}
}

// TestARSBlobReadsKeepTheirOwnReadLimits serves one byte more than each read's
// limit with no Content-Length, so the limit and not the header must stop the
// read. A wider limit would read the body and then answer differently: the
// evidence, Vault and payload reads with their mismatch message (the digest
// does not match), the policy read with the bytes (the digest matches).
func TestARSBlobReadsKeepTheirOwnReadLimits(t *testing.T) {
	serve := func(t *testing.T, body []byte) *Service {
		return newARSBlobTestService(t, newARSRequestLog(), func(w http.ResponseWriter, r *http.Request) {
			w.(http.Flusher).Flush()
			_, _ = w.Write(body)
		})
	}
	overLimit := func(limit int64) []byte { return bytes.Repeat([]byte{'a'}, int(limit+1)) }

	t.Run("artifact evidence", func(t *testing.T) {
		_, publicErr := serve(t, overLimit(maxDependencyJSONResponseBytes)).fetchArtifactEvidenceBlob(context.Background(), labeledDigest("aa"), labeledDigest("ab"))
		assertAdmissionError(t, publicErr, http.StatusServiceUnavailable, codeArtifactEvidenceUnavailable)
		if publicErr.Message != "artifact evidence payload was invalid" {
			t.Fatalf("evidence read was not stopped at its limit: %q", publicErr.Message)
		}
	})
	t.Run("workload-zone vault blob", func(t *testing.T) {
		_, publicErr := serve(t, overLimit(maxDependencyJSONResponseBytes)).fetchWorkloadZoneVaultConfig(context.Background(), runtimeconfigv1.WorkloadZoneVaultConfigRef{Digest: labeledDigest("ac")})
		assertAdmissionError(t, publicErr, http.StatusServiceUnavailable, codeWorkloadZoneVaultUnavailable)
		if publicErr.Message != "artifact registry workload-zone vault blob was invalid" {
			t.Fatalf("vault read was not stopped at its limit: %q", publicErr.Message)
		}
	})
	t.Run("admission policy payload", func(t *testing.T) {
		body := overLimit(maxAdmissionPolicyPayloadBytes)
		got, publicErr := serve(t, body).fetchAdmissionPolicyPayloadBytes(context.Background(), digestBytes(body))
		if got != nil || publicErr == nil || *publicErr != *admissionPolicyInputUnavailableError() {
			t.Fatalf("policy read was not stopped at its limit: bytes=%d err=%+v", len(got), publicErr)
		}
	})
	t.Run("primary payload", func(t *testing.T) {
		_, publicErr := serve(t, overLimit(maxPrimaryPayloadBytes)).fetchPayloadBytes(context.Background(), labeledDigest("ad"))
		assertAdmissionError(t, publicErr, http.StatusServiceUnavailable, codePayloadUnavailable)
		if publicErr.Message != "artifact payload read failed" {
			t.Fatalf("primary payload read was not stopped at its limit: %q", publicErr.Message)
		}
	})
}
