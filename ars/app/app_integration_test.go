package app_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"execution-platform/ars/app"
	"execution-platform/ars/config"
	"execution-platform/ars/index"
	"execution-platform/ars/store"
	evidencev1 "execution-platform/contracts/evidence/v1"
)

func TestLoadConfigRejectsMissingFile(t *testing.T) {
	t.Parallel()

	_, err := config.Load(filepath.Join(t.TempDir(), "missing.json"))
	if err == nil || !strings.Contains(err.Error(), "open config") {
		t.Fatalf("expected missing-file error, got %v", err)
	}
}

func TestLoadConfigRejectsMalformedJSON(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte("{"), 0o600); err != nil {
		t.Fatalf("write malformed config: %v", err)
	}

	_, err := config.Load(path)
	if err == nil || !strings.Contains(err.Error(), "decode config") {
		t.Fatalf("expected malformed-json error, got %v", err)
	}
}

func TestLoadConfigRejectsTrailingData(t *testing.T) {
	t.Parallel()

	fixture := newTLSFixture(t)
	rootDir := filepath.Join(t.TempDir(), "storage")
	indexPath := filepath.Join(t.TempDir(), "artifact-index.json")
	if err := os.MkdirAll(rootDir, 0o755); err != nil {
		t.Fatalf("create storage root: %v", err)
	}
	if err := os.WriteFile(indexPath, []byte("{}"), 0o600); err != nil {
		t.Fatalf("write empty index: %v", err)
	}

	cfg := buildConfig(fixture, rootDir, indexPath)
	payload, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		t.Fatalf("marshal config: %v", err)
	}

	path := filepath.Join(t.TempDir(), "ars.json")
	payload = append(payload, []byte("\n{\"trailing\":true}\n")...)
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	_, err = config.Load(path)
	if err == nil || !strings.Contains(err.Error(), "trailing data after first JSON document") {
		t.Fatalf("expected trailing-data error, got %v", err)
	}
}

func TestNewRejectsMissingArtifactIndex(t *testing.T) {
	t.Parallel()

	fixture := newTLSFixture(t)
	rootDir := filepath.Join(t.TempDir(), "storage")
	if err := os.MkdirAll(rootDir, 0o755); err != nil {
		t.Fatalf("create storage root: %v", err)
	}

	cfgPath := writeConfig(t, fixture, rootDir, filepath.Join(t.TempDir(), "missing-index.json"))
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}

	_, err = app.New(cfg)
	if err == nil || !strings.Contains(err.Error(), "open artifact index") {
		t.Fatalf("expected missing-index error, got %v", err)
	}
}

func TestBlobUploadStoresAndServesUploadedBlob(t *testing.T) {
	fixture := newTLSFixture(t)
	service, _ := startTestApp(t, fixture, seedEmptyStorageFixture(t))

	content := []byte("uploaded artifact payload")
	digest := store.DigestBytes(content)

	response := doRequestWithBody(t, service.Addr(), http.MethodPut, "/v1/blobs/"+digest, content, fixture.clientTLSConfig(t, "service/artifact-governance"))
	defer response.Body.Close()

	if response.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201, got %d", response.StatusCode)
	}
	if response.Header.Get("Content-Digest") != digest {
		t.Fatalf("unexpected digest header: %q", response.Header.Get("Content-Digest"))
	}
	if body := mustReadBody(t, response.Body); len(body) != 0 {
		t.Fatalf("expected empty body, got %q", string(body))
	}

	readResponse := doRequest(t, service.Addr(), http.MethodGet, "/v1/blobs/"+digest+":bytes", fixture.clientTLSConfig(t, "service/execution"))
	defer readResponse.Body.Close()

	if readResponse.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", readResponse.StatusCode)
	}
	if got := mustReadBody(t, readResponse.Body); !bytes.Equal(got, content) {
		t.Fatalf("unexpected blob content: %q", string(got))
	}
}

func TestBlobUploadRejectsInvalidDigestFormat(t *testing.T) {
	fixture := newTLSFixture(t)
	service, _ := startTestApp(t, fixture, seedEmptyStorageFixture(t))

	response := doRequestWithBody(t, service.Addr(), http.MethodPut, "/v1/blobs/sha256:not-a-digest", []byte("payload"), fixture.clientTLSConfig(t, "service/artifact-governance"))
	defer response.Body.Close()

	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", response.StatusCode)
	}

	var payload struct {
		Error  string `json:"error"`
		Digest string `json:"digest"`
	}
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if payload.Error != "invalid digest" || payload.Digest != "sha256:not-a-digest" {
		t.Fatalf("unexpected payload: %+v", payload)
	}
}

func TestBlobUploadRejectsDigestMismatch(t *testing.T) {
	fixture := newTLSFixture(t)
	service, _ := startTestApp(t, fixture, seedEmptyStorageFixture(t))

	requestDigest := store.DigestBytes([]byte("expected"))
	response := doRequestWithBody(t, service.Addr(), http.MethodPut, "/v1/blobs/"+requestDigest, []byte("actual"), fixture.clientTLSConfig(t, "service/artifact-governance"))
	defer response.Body.Close()

	if response.StatusCode != http.StatusConflict {
		t.Fatalf("expected 409, got %d", response.StatusCode)
	}

	var payload struct {
		Error  string `json:"error"`
		Digest string `json:"digest"`
	}
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if payload.Error != "blob digest does not match request path" || payload.Digest != requestDigest {
		t.Fatalf("unexpected payload: %+v", payload)
	}
}

func TestBlobUploadIsIdempotentForSameContent(t *testing.T) {
	fixture := newTLSFixture(t)
	service, _ := startTestApp(t, fixture, seedEmptyStorageFixture(t))

	content := []byte("stable payload")
	digest := store.DigestBytes(content)

	first := doRequestWithBody(t, service.Addr(), http.MethodPut, "/v1/blobs/"+digest, content, fixture.clientTLSConfig(t, "service/artifact-governance"))
	defer first.Body.Close()
	if first.StatusCode != http.StatusCreated {
		t.Fatalf("expected first upload to return 201, got %d", first.StatusCode)
	}

	second := doRequestWithBody(t, service.Addr(), http.MethodPut, "/v1/blobs/"+digest, content, fixture.clientTLSConfig(t, "service/artifact-governance"))
	defer second.Body.Close()
	if second.StatusCode != http.StatusOK {
		t.Fatalf("expected second upload to return 200, got %d", second.StatusCode)
	}
	if second.Header.Get("Content-Digest") != digest {
		t.Fatalf("unexpected digest header: %q", second.Header.Get("Content-Digest"))
	}
}

func TestArtifactNotVisibleBeforeRegister(t *testing.T) {
	fixture := newTLSFixture(t)
	service, seeded := startTestApp(t, fixture, seedUnregisteredStorageFixture(t))

	response := doRequest(t, service.Addr(), http.MethodGet, "/v1/artifacts/"+seeded.ArtifactDigest+"/manifest", fixture.clientTLSConfig(t, "service/execution"))
	defer response.Body.Close()

	if response.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", response.StatusCode)
	}

	var payload struct {
		Error          string `json:"error"`
		ArtifactDigest string `json:"artifact_digest"`
	}
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if payload.Error != "artifact not found" || payload.ArtifactDigest != seeded.ArtifactDigest {
		t.Fatalf("unexpected payload: %+v", payload)
	}
}

func TestPartialUploadDoesNotMakeArtifactVisible(t *testing.T) {
	fixture := newTLSFixture(t)
	service, seeded := startTestApp(t, fixture, seedEmptyStorageFixture(t))

	uploads := []struct {
		digest string
		body   []byte
	}{
		{digest: seeded.ManifestDigest, body: seeded.ManifestJSON},
		{digest: seeded.EvidenceDigest, body: seeded.EvidenceJSON},
		{digest: seeded.PayloadDigest, body: seeded.PayloadBytes},
	}
	for _, upload := range uploads {
		response := doRequestWithBody(t, service.Addr(), http.MethodPut, "/v1/blobs/"+upload.digest, upload.body, fixture.clientTLSConfig(t, "service/artifact-governance"))
		response.Body.Close()
		if response.StatusCode != http.StatusCreated {
			t.Fatalf("expected 201 for upload %s, got %d", upload.digest, response.StatusCode)
		}
	}

	readResponse := doRequest(t, service.Addr(), http.MethodGet, "/v1/artifacts/"+seeded.ArtifactDigest+"/manifest", fixture.clientTLSConfig(t, "service/execution"))
	defer readResponse.Body.Close()
	if readResponse.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", readResponse.StatusCode)
	}
}

func TestArtifactRegistrationMakesArtifactVisible(t *testing.T) {
	fixture := newTLSFixture(t)
	service, seeded := startTestApp(t, fixture, seedUnregisteredStorageFixture(t))

	response := doJSONRequest(t, service.Addr(), http.MethodPost, "/v1/artifacts:register", artifactRegisterRequestFromSeeded(seeded), fixture.clientTLSConfig(t, "service/artifact-governance"))
	defer response.Body.Close()

	if response.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201, got %d", response.StatusCode)
	}

	var payload struct {
		Registered     bool   `json:"registered"`
		Created        bool   `json:"created"`
		ArtifactDigest string `json:"artifact_digest"`
	}
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !payload.Registered || !payload.Created || payload.ArtifactDigest != seeded.ArtifactDigest {
		t.Fatalf("unexpected payload: %+v", payload)
	}
	if seeded.ArtifactDigest == seeded.PayloadDigest {
		t.Fatalf("expected distinct artifact and payload digests in seeded registration fixture, both were %q", seeded.ArtifactDigest)
	}

	readResponse := doRequest(t, service.Addr(), http.MethodGet, "/v1/artifacts/"+seeded.ArtifactDigest+"/manifest", fixture.clientTLSConfig(t, "service/execution"))
	defer readResponse.Body.Close()
	if readResponse.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", readResponse.StatusCode)
	}
}

func TestArtifactEvidenceReadReturnsRegisteredEvidence(t *testing.T) {
	fixture := newTLSFixture(t)
	service, seeded := startTestApp(t, fixture, seedStorageFixture(t))

	response := doRequest(t, service.Addr(), http.MethodGet, "/v1/artifacts/"+seeded.ArtifactDigest+"/evidence", fixture.clientTLSConfig(t, "service/execution"))
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", response.StatusCode)
	}
	if got := response.Header.Get("Content-Digest"); got != seeded.EvidenceDigest {
		t.Fatalf("unexpected evidence digest header: %q", got)
	}
	if body := mustReadBody(t, response.Body); string(body) != string(seeded.EvidenceJSON) {
		t.Fatalf("unexpected evidence body: %q", string(body))
	}
}

func TestLegacyArtifactCompatibilityRoutesAreNotExposed(t *testing.T) {
	fixture := newTLSFixture(t)
	service, seeded := startTestApp(t, fixture, seedStorageFixture(t))

	for _, path := range []string{
		"/v1/artifacts/" + seeded.ArtifactDigest + "/provenance",
		"/v1/artifacts/" + seeded.ArtifactDigest + "/derivation-metadata",
		"/v1/artifacts/" + seeded.ArtifactDigest + "/derivation-authorization-attestation",
		"/v1/artifacts/" + seeded.ArtifactDigest + "/workload-identity-binding",
	} {
		response := doRequest(t, service.Addr(), http.MethodGet, path, fixture.clientTLSConfig(t, "service/execution"))
		response.Body.Close()
		if response.StatusCode != http.StatusNotFound {
			t.Fatalf("expected 404 for %s, got %d", path, response.StatusCode)
		}
	}
}

func TestArtifactRegistrationRejectsMissingReferencedBlobAndKeepsArtifactHidden(t *testing.T) {
	fixture := newTLSFixture(t)
	state := seedUnregisteredStorageFixture(t)

	missingPath, err := store.ResolvePath(state.RootDir, state.ManifestDigest)
	if err != nil {
		t.Fatalf("resolve manifest path: %v", err)
	}
	if err := os.Remove(missingPath); err != nil {
		t.Fatalf("remove manifest blob: %v", err)
	}

	service, seeded := startTestApp(t, fixture, state)

	response := doJSONRequest(t, service.Addr(), http.MethodPost, "/v1/artifacts:register", artifactRegisterRequestFromSeeded(seeded), fixture.clientTLSConfig(t, "service/artifact-governance"))
	defer response.Body.Close()

	if response.StatusCode != http.StatusConflict {
		t.Fatalf("expected 409, got %d", response.StatusCode)
	}

	var payload struct {
		Error          string `json:"error"`
		ArtifactDigest string `json:"artifact_digest"`
		Digest         string `json:"digest"`
	}
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if payload.Error != "referenced blob not found" || payload.ArtifactDigest != seeded.ArtifactDigest || payload.Digest != seeded.ManifestDigest {
		t.Fatalf("unexpected payload: %+v", payload)
	}

	readResponse := doRequest(t, service.Addr(), http.MethodGet, "/v1/artifacts/"+seeded.ArtifactDigest+"/manifest", fixture.clientTLSConfig(t, "service/execution"))
	defer readResponse.Body.Close()
	if readResponse.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", readResponse.StatusCode)
	}
}

func TestArtifactRegistrationRejectsReferencedBlobIntegrityFailureAndKeepsArtifactHidden(t *testing.T) {
	fixture := newTLSFixture(t)
	state := seedUnregisteredStorageFixture(t)

	corruptPath, err := store.ResolvePath(state.RootDir, state.ManifestDigest)
	if err != nil {
		t.Fatalf("resolve manifest path: %v", err)
	}
	if err := os.WriteFile(corruptPath, []byte(`{"corrupted":true}`), 0o600); err != nil {
		t.Fatalf("write corrupt manifest blob: %v", err)
	}

	service, seeded := startTestApp(t, fixture, state)

	response := doJSONRequest(t, service.Addr(), http.MethodPost, "/v1/artifacts:register", artifactRegisterRequestFromSeeded(seeded), fixture.clientTLSConfig(t, "service/artifact-governance"))
	defer response.Body.Close()

	if response.StatusCode != http.StatusConflict {
		t.Fatalf("expected 409, got %d", response.StatusCode)
	}

	var payload struct {
		Error          string `json:"error"`
		ArtifactDigest string `json:"artifact_digest"`
		Digest         string `json:"digest"`
	}
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if payload.Error != "stored blob digest mismatch" || payload.ArtifactDigest != seeded.ArtifactDigest || payload.Digest != seeded.ManifestDigest {
		t.Fatalf("unexpected payload: %+v", payload)
	}

	readResponse := doRequest(t, service.Addr(), http.MethodGet, "/v1/artifacts/"+seeded.ArtifactDigest+"/manifest", fixture.clientTLSConfig(t, "service/execution"))
	defer readResponse.Body.Close()
	if readResponse.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", readResponse.StatusCode)
	}
}

func TestArtifactRegistrationIsIdempotentForSameTuple(t *testing.T) {
	fixture := newTLSFixture(t)
	service, seeded := startTestApp(t, fixture, seedUnregisteredStorageFixture(t))

	first := doJSONRequest(t, service.Addr(), http.MethodPost, "/v1/artifacts:register", artifactRegisterRequestFromSeeded(seeded), fixture.clientTLSConfig(t, "service/artifact-governance"))
	defer first.Body.Close()
	if first.StatusCode != http.StatusCreated {
		t.Fatalf("expected first register to return 201, got %d", first.StatusCode)
	}

	second := doJSONRequest(t, service.Addr(), http.MethodPost, "/v1/artifacts:register", artifactRegisterRequestFromSeeded(seeded), fixture.clientTLSConfig(t, "service/artifact-governance"))
	defer second.Body.Close()
	if second.StatusCode != http.StatusOK {
		t.Fatalf("expected second register to return 200, got %d", second.StatusCode)
	}

	var payload struct {
		Registered     bool   `json:"registered"`
		Created        bool   `json:"created"`
		ArtifactDigest string `json:"artifact_digest"`
	}
	if err := json.NewDecoder(second.Body).Decode(&payload); err != nil {
		t.Fatalf("decode second response: %v", err)
	}
	if !payload.Registered || payload.Created || payload.ArtifactDigest != seeded.ArtifactDigest {
		t.Fatalf("unexpected payload: %+v", payload)
	}
}

func TestArtifactRegistrationRejectsDifferentTuple(t *testing.T) {
	fixture := newTLSFixture(t)
	state := seedStorageFixture(t)

	alternateManifest := []byte(`{"schema_version":"v1","name":"alternate"}`)
	alternateManifestDigest := store.DigestBytes(alternateManifest)
	writeBlobAtDigest(t, state.RootDir, alternateManifestDigest, alternateManifest)
	var descriptor map[string]any
	if err := json.Unmarshal(state.DescriptorJSON, &descriptor); err != nil {
		t.Fatalf("decode descriptor json: %v", err)
	}
	pkg := descriptor["package"].(map[string]any)
	supporting := pkg["supporting"].([]any)
	supporting[0].(map[string]any)["digest"] = alternateManifestDigest
	alternateDescriptorJSON := mustMarshalJSON(t, descriptor)
	alternateDescriptorDigest := store.DigestBytes(alternateDescriptorJSON)
	writeBlobAtDigest(t, state.RootDir, alternateDescriptorDigest, alternateDescriptorJSON)

	service, seeded := startTestApp(t, fixture, state)
	request := artifactRegisterRequestFromSeeded(seeded)
	request.DescriptorDigest = alternateDescriptorDigest

	response := doJSONRequest(t, service.Addr(), http.MethodPost, "/v1/artifacts:register", request, fixture.clientTLSConfig(t, "service/artifact-governance"))
	defer response.Body.Close()

	if response.StatusCode != http.StatusConflict {
		t.Fatalf("expected 409, got %d", response.StatusCode)
	}

	var payload struct {
		Error          string `json:"error"`
		ArtifactDigest string `json:"artifact_digest"`
	}
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if payload.Error != "artifact already registered with different digests" || payload.ArtifactDigest != seeded.ArtifactDigest {
		t.Fatalf("unexpected payload: %+v", payload)
	}

	readResponse := doRequest(t, service.Addr(), http.MethodGet, "/v1/artifacts/"+seeded.ArtifactDigest+"/manifest", fixture.clientTLSConfig(t, "service/execution"))
	defer readResponse.Body.Close()
	if readResponse.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", readResponse.StatusCode)
	}
	if got := strings.TrimSpace(string(mustReadBody(t, readResponse.Body))); got != string(seeded.ManifestJSON) {
		t.Fatalf("unexpected manifest body: %q", got)
	}
}

func TestBlobEndpointsReturnExpectedResponses(t *testing.T) {
	fixture := newTLSFixture(t)
	service, seeded := startTestApp(t, fixture, seedStorageFixture(t))

	headResponse := doRequest(t, service.Addr(), http.MethodHead, "/v1/blobs/"+seeded.BlobDigest, fixture.clientTLSConfig(t, "service/execution"))
	defer headResponse.Body.Close()

	if headResponse.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", headResponse.StatusCode)
	}
	if headResponse.Header.Get("Content-Digest") != seeded.BlobDigest {
		t.Fatalf("unexpected HEAD digest header: %q", headResponse.Header.Get("Content-Digest"))
	}
	if body := mustReadBody(t, headResponse.Body); len(body) != 0 {
		t.Fatalf("expected empty HEAD body, got %q", string(body))
	}

	bytesResponse := doRequest(t, service.Addr(), http.MethodGet, "/v1/blobs/"+seeded.BlobDigest+":bytes", fixture.clientTLSConfig(t, "service/execution"))
	defer bytesResponse.Body.Close()

	if bytesResponse.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", bytesResponse.StatusCode)
	}
	if bytesResponse.Header.Get("Content-Type") != "application/octet-stream" {
		t.Fatalf("unexpected content type: %q", bytesResponse.Header.Get("Content-Type"))
	}
	if bytesResponse.Header.Get("Content-Digest") != seeded.BlobDigest {
		t.Fatalf("unexpected digest header: %q", bytesResponse.Header.Get("Content-Digest"))
	}
	if got := mustReadBody(t, bytesResponse.Body); string(got) != string(seeded.BlobContent) {
		t.Fatalf("unexpected bytes payload: %q", string(got))
	}

	jsonResponse := doRequest(t, service.Addr(), http.MethodGet, "/v1/blobs/"+seeded.JSONDigest+":json", fixture.clientTLSConfig(t, "service/execution"))
	defer jsonResponse.Body.Close()

	if jsonResponse.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", jsonResponse.StatusCode)
	}
	if jsonResponse.Header.Get("Content-Digest") != seeded.JSONDigest {
		t.Fatalf("unexpected digest header: %q", jsonResponse.Header.Get("Content-Digest"))
	}
	if got := strings.TrimSpace(string(mustReadBody(t, jsonResponse.Body))); got != string(seeded.JSONBlob) {
		t.Fatalf("unexpected json payload: %q", got)
	}
}

func TestReadLargerBlobSucceeds(t *testing.T) {
	fixture := newTLSFixture(t)
	state := seedStorageFixture(t)

	largeBlob := bytes.Repeat([]byte("a"), 1024*1024)
	largeDigest := store.DigestBytes(largeBlob)
	writeBlobAtDigest(t, state.RootDir, largeDigest, largeBlob)

	service, _ := startTestApp(t, fixture, state)

	response := doRequest(t, service.Addr(), http.MethodGet, "/v1/blobs/"+largeDigest+":bytes", fixture.clientTLSConfig(t, "service/execution"))
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", response.StatusCode)
	}
	if response.Header.Get("Content-Digest") != largeDigest {
		t.Fatalf("unexpected digest header: %q", response.Header.Get("Content-Digest"))
	}
	if response.Header.Get("Content-Length") != "1048576" {
		t.Fatalf("unexpected content length: %q", response.Header.Get("Content-Length"))
	}
	if got := mustReadBody(t, response.Body); len(got) != len(largeBlob) {
		t.Fatalf("unexpected blob length: %d", len(got))
	}
}

func TestArtifactEndpointsReturnExpectedResponses(t *testing.T) {
	fixture := newTLSFixture(t)
	service, seeded := startTestApp(t, fixture, seedStorageFixture(t))

	cases := []struct {
		name   string
		path   string
		digest string
		body   string
	}{
		{
			name:   "descriptor",
			path:   "/v1/artifacts/" + seeded.ArtifactDigest + "/descriptor",
			digest: seeded.DescriptorDigest,
			body:   string(seeded.DescriptorJSON),
		},
		{
			name:   "manifest",
			path:   "/v1/artifacts/" + seeded.ArtifactDigest + "/manifest",
			digest: seeded.ManifestDigest,
			body:   string(seeded.ManifestJSON),
		},
		{
			name:   "evidence",
			path:   "/v1/artifacts/" + seeded.ArtifactDigest + "/evidence",
			digest: seeded.EvidenceDigest,
			body:   string(seeded.EvidenceJSON),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			response := doRequest(t, service.Addr(), http.MethodGet, tc.path, fixture.clientTLSConfig(t, "service/execution"))
			defer response.Body.Close()

			if response.StatusCode != http.StatusOK {
				t.Fatalf("expected 200, got %d", response.StatusCode)
			}
			if response.Header.Get("Content-Type") != "application/json" {
				t.Fatalf("unexpected content type: %q", response.Header.Get("Content-Type"))
			}
			if response.Header.Get("Content-Digest") != tc.digest {
				t.Fatalf("unexpected digest header: %q", response.Header.Get("Content-Digest"))
			}
			if got := strings.TrimSpace(string(mustReadBody(t, response.Body))); got != tc.body {
				t.Fatalf("unexpected body: %q", got)
			}
		})
	}
}

func TestBlobNotFoundReturnsExpectedResponse(t *testing.T) {
	fixture := newTLSFixture(t)
	service, _ := startTestApp(t, fixture, seedStorageFixture(t))

	missingDigest := store.DigestBytes([]byte("missing"))
	response := doRequest(t, service.Addr(), http.MethodGet, "/v1/blobs/"+missingDigest+":bytes", fixture.clientTLSConfig(t, "service/execution"))
	defer response.Body.Close()

	if response.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", response.StatusCode)
	}

	var payload struct {
		Error  string `json:"error"`
		Digest string `json:"digest"`
	}
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if payload.Error != "blob not found" || payload.Digest != missingDigest {
		t.Fatalf("unexpected payload: %+v", payload)
	}
}

func TestArtifactNotFoundReturnsExpectedResponse(t *testing.T) {
	fixture := newTLSFixture(t)
	service, _ := startTestApp(t, fixture, seedStorageFixture(t))

	missingArtifact := store.DigestBytes([]byte("missing artifact"))
	response := doRequest(t, service.Addr(), http.MethodGet, "/v1/artifacts/"+missingArtifact+"/manifest", fixture.clientTLSConfig(t, "service/execution"))
	defer response.Body.Close()

	if response.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", response.StatusCode)
	}

	var payload struct {
		Error          string `json:"error"`
		ArtifactDigest string `json:"artifact_digest"`
	}
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if payload.Error != "artifact not found" || payload.ArtifactDigest != missingArtifact {
		t.Fatalf("unexpected payload: %+v", payload)
	}
}

func TestArtifactEndpointsReturnNotFoundForMissingReferencedBlobs(t *testing.T) {
	fixture := newTLSFixture(t)

	cases := []struct {
		name   string
		pathFn func(seededStorage) string
		digest func(seededStorage) string
	}{
		{
			name:   "descriptor",
			pathFn: func(seeded seededStorage) string { return "/v1/artifacts/" + seeded.ArtifactDigest + "/descriptor" },
			digest: func(seeded seededStorage) string { return seeded.DescriptorDigest },
		},
		{
			name:   "evidence",
			pathFn: func(seeded seededStorage) string { return "/v1/artifacts/" + seeded.ArtifactDigest + "/evidence" },
			digest: func(seeded seededStorage) string { return seeded.EvidenceDigest },
		},
		{
			name:   "manifest",
			pathFn: func(seeded seededStorage) string { return "/v1/artifacts/" + seeded.ArtifactDigest + "/manifest" },
			digest: func(seeded seededStorage) string { return seeded.ManifestDigest },
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			state := seedStorageFixture(t)

			missingPath, err := store.ResolvePath(state.RootDir, tc.digest(state))
			if err != nil {
				t.Fatalf("resolve referenced blob path: %v", err)
			}
			if err := os.Remove(missingPath); err != nil {
				t.Fatalf("remove referenced blob: %v", err)
			}

			service, seeded := startTestApp(t, fixture, state)

			response := doRequest(t, service.Addr(), http.MethodGet, tc.pathFn(seeded), fixture.clientTLSConfig(t, "service/execution"))
			defer response.Body.Close()

			if response.StatusCode != http.StatusNotFound {
				t.Fatalf("expected 404, got %d", response.StatusCode)
			}

			var payload struct {
				Error          string `json:"error"`
				ArtifactDigest string `json:"artifact_digest"`
				Digest         string `json:"digest"`
			}
			if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
				t.Fatalf("decode response: %v", err)
			}
			if payload.Error != "referenced blob not found" || payload.ArtifactDigest != seeded.ArtifactDigest || payload.Digest != tc.digest(seeded) {
				t.Fatalf("unexpected payload: %+v", payload)
			}
		})
	}
}

func TestCorruptedBlobReturnsInternalServerError(t *testing.T) {
	fixture := newTLSFixture(t)
	state := seedStorageFixture(t)

	corruptPath, err := store.ResolvePath(state.RootDir, state.JSONDigest)
	if err != nil {
		t.Fatalf("resolve json path: %v", err)
	}
	if err := os.WriteFile(corruptPath, []byte(`{"corrupted":true}`), 0o600); err != nil {
		t.Fatalf("write corrupt blob: %v", err)
	}

	service, seeded := startTestApp(t, fixture, state)

	response := doRequest(t, service.Addr(), http.MethodGet, "/v1/blobs/"+seeded.JSONDigest+":json", fixture.clientTLSConfig(t, "service/execution"))
	defer response.Body.Close()

	if response.StatusCode != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", response.StatusCode)
	}

	var payload struct {
		Error  string `json:"error"`
		Digest string `json:"digest"`
	}
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if payload.Error != "stored blob digest mismatch" || payload.Digest != seeded.JSONDigest {
		t.Fatalf("unexpected payload: %+v", payload)
	}
}

func TestCorruptedBlobBytesReturnsInternalServerError(t *testing.T) {
	fixture := newTLSFixture(t)
	state := seedStorageFixture(t)

	corruptPath, err := store.ResolvePath(state.RootDir, state.BlobDigest)
	if err != nil {
		t.Fatalf("resolve blob path: %v", err)
	}
	if err := os.WriteFile(corruptPath, []byte("corrupted-bytes"), 0o600); err != nil {
		t.Fatalf("write corrupt blob: %v", err)
	}

	service, seeded := startTestApp(t, fixture, state)

	response := doRequest(t, service.Addr(), http.MethodGet, "/v1/blobs/"+seeded.BlobDigest+":bytes", fixture.clientTLSConfig(t, "service/execution"))
	defer response.Body.Close()

	if response.StatusCode != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", response.StatusCode)
	}

	var payload struct {
		Error  string `json:"error"`
		Digest string `json:"digest"`
	}
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if payload.Error != "stored blob digest mismatch" || payload.Digest != seeded.BlobDigest {
		t.Fatalf("unexpected payload: %+v", payload)
	}
}

func TestArtifactEndpointsReturnCorruptionForReferencedBlobs(t *testing.T) {
	fixture := newTLSFixture(t)

	cases := []struct {
		name   string
		pathFn func(seededStorage) string
		digest func(seededStorage) string
	}{
		{
			name:   "descriptor",
			pathFn: func(seeded seededStorage) string { return "/v1/artifacts/" + seeded.ArtifactDigest + "/descriptor" },
			digest: func(seeded seededStorage) string { return seeded.DescriptorDigest },
		},
		{
			name:   "evidence",
			pathFn: func(seeded seededStorage) string { return "/v1/artifacts/" + seeded.ArtifactDigest + "/evidence" },
			digest: func(seeded seededStorage) string { return seeded.EvidenceDigest },
		},
		{
			name:   "manifest",
			pathFn: func(seeded seededStorage) string { return "/v1/artifacts/" + seeded.ArtifactDigest + "/manifest" },
			digest: func(seeded seededStorage) string { return seeded.ManifestDigest },
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			state := seedStorageFixture(t)

			corruptPath, err := store.ResolvePath(state.RootDir, tc.digest(state))
			if err != nil {
				t.Fatalf("resolve referenced blob path: %v", err)
			}
			if err := os.WriteFile(corruptPath, []byte(`{"corrupted":true}`), 0o600); err != nil {
				t.Fatalf("write corrupt referenced blob: %v", err)
			}

			service, seeded := startTestApp(t, fixture, state)

			response := doRequest(t, service.Addr(), http.MethodGet, tc.pathFn(seeded), fixture.clientTLSConfig(t, "service/execution"))
			defer response.Body.Close()

			if response.StatusCode != http.StatusInternalServerError {
				t.Fatalf("expected 500, got %d", response.StatusCode)
			}

			var payload struct {
				Error          string `json:"error"`
				ArtifactDigest string `json:"artifact_digest"`
				Digest         string `json:"digest"`
			}
			if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
				t.Fatalf("decode response: %v", err)
			}
			if payload.Error != "stored blob digest mismatch" || payload.ArtifactDigest != seeded.ArtifactDigest || payload.Digest != tc.digest(seeded) {
				t.Fatalf("unexpected payload: %+v", payload)
			}
		})
	}
}

func TestBlobJSONRejectsStoredNonJSONContent(t *testing.T) {
	fixture := newTLSFixture(t)
	service, seeded := startTestApp(t, fixture, seedStorageFixture(t))

	response := doRequest(t, service.Addr(), http.MethodGet, "/v1/blobs/"+seeded.BlobDigest+":json", fixture.clientTLSConfig(t, "service/execution"))
	defer response.Body.Close()

	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", response.StatusCode)
	}

	var payload struct {
		Error  string `json:"error"`
		Digest string `json:"digest"`
	}
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if payload.Error != "blob is not valid JSON" || payload.Digest != seeded.BlobDigest {
		t.Fatalf("unexpected payload: %+v", payload)
	}
}

func TestInvalidDigestReturnsBadRequest(t *testing.T) {
	fixture := newTLSFixture(t)
	service, _ := startTestApp(t, fixture, seedStorageFixture(t))

	cases := []struct {
		name   string
		method string
		path   string
		field  string
	}{
		{
			name:   "blob bytes invalid digest",
			method: http.MethodGet,
			path:   "/v1/blobs/sha256:not-a-digest:bytes",
			field:  "digest",
		},
		{
			name:   "artifact invalid digest",
			method: http.MethodGet,
			path:   "/v1/artifacts/sha256:not-a-digest/manifest",
			field:  "artifact_digest",
		},
		{
			name:   "empty artifact digest segment",
			method: http.MethodGet,
			path:   "/v1/artifacts//manifest",
			field:  "artifact_digest",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			response := doRequest(t, service.Addr(), tc.method, tc.path, fixture.clientTLSConfig(t, "service/execution"))
			defer response.Body.Close()

			if response.StatusCode != http.StatusBadRequest {
				t.Fatalf("expected 400, got %d", response.StatusCode)
			}

			switch tc.field {
			case "digest":
				var payload struct {
					Error  string `json:"error"`
					Digest string `json:"digest"`
				}
				if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
					t.Fatalf("decode response: %v", err)
				}
				if payload.Error != "invalid digest" {
					t.Fatalf("unexpected error: %+v", payload)
				}
				expectedDigest := strings.TrimPrefix(strings.TrimSuffix(tc.path, ":bytes"), "/v1/blobs/")
				if payload.Digest != expectedDigest {
					t.Fatalf("unexpected digest payload: %+v", payload)
				}
			case "artifact_digest":
				var payload struct {
					Error          string `json:"error"`
					ArtifactDigest string `json:"artifact_digest"`
				}
				if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
					t.Fatalf("decode response: %v", err)
				}
				if payload.Error != "invalid artifact digest" {
					t.Fatalf("unexpected error: %+v", payload)
				}
				expectedArtifactDigest := strings.TrimPrefix(strings.TrimSuffix(tc.path, "/manifest"), "/v1/artifacts/")
				if tc.path == "/v1/artifacts//manifest" {
					expectedArtifactDigest = ""
				}
				if payload.ArtifactDigest != expectedArtifactDigest {
					t.Fatalf("unexpected artifact digest payload: %+v", payload)
				}
			default:
				t.Fatalf("unhandled field %q", tc.field)
			}
		})
	}
}

func TestHeadInvalidDigestReturnsBadRequestWithoutSuccess(t *testing.T) {
	fixture := newTLSFixture(t)
	service, _ := startTestApp(t, fixture, seedStorageFixture(t))

	response := doRequest(t, service.Addr(), http.MethodHead, "/v1/blobs/sha256:not-a-digest", fixture.clientTLSConfig(t, "service/execution"))
	defer response.Body.Close()

	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", response.StatusCode)
	}
	if body := mustReadBody(t, response.Body); len(body) != 0 {
		t.Fatalf("expected empty HEAD body, got %q", string(body))
	}
}

func TestHeadCorruptBlobReturnsInternalServerError(t *testing.T) {
	fixture := newTLSFixture(t)
	state := seedStorageFixture(t)

	corruptPath, err := store.ResolvePath(state.RootDir, state.BlobDigest)
	if err != nil {
		t.Fatalf("resolve blob path: %v", err)
	}
	if err := os.WriteFile(corruptPath, []byte("corrupted-bytes"), 0o600); err != nil {
		t.Fatalf("write corrupt blob: %v", err)
	}

	service, seeded := startTestApp(t, fixture, state)

	response := doRequest(t, service.Addr(), http.MethodHead, "/v1/blobs/"+seeded.BlobDigest, fixture.clientTLSConfig(t, "service/execution"))
	defer response.Body.Close()

	if response.StatusCode != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", response.StatusCode)
	}
	if body := mustReadBody(t, response.Body); len(body) != 0 {
		t.Fatalf("expected empty HEAD body, got %q", string(body))
	}
}

func TestWrongMethodsReturnMethodNotAllowed(t *testing.T) {
	fixture := newTLSFixture(t)
	service, seeded := startTestApp(t, fixture, seedStorageFixture(t))

	cases := []struct {
		name        string
		method      string
		path        string
		allowHeader string
		config      *tls.Config
	}{
		{
			name:        "post health",
			method:      http.MethodPost,
			path:        "/health",
			allowHeader: http.MethodGet,
			config:      fixture.baseClientTLSConfig(t),
		},
		{
			name:        "get head-only blob route",
			method:      http.MethodGet,
			path:        "/v1/blobs/" + seeded.BlobDigest,
			allowHeader: http.MethodHead,
			config:      fixture.clientTLSConfig(t, "service/execution"),
		},
		{
			name:        "post artifact route",
			method:      http.MethodPost,
			path:        "/v1/artifacts/" + seeded.ArtifactDigest + "/manifest",
			allowHeader: http.MethodGet,
			config:      fixture.clientTLSConfig(t, "service/execution"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			response := doRequest(t, service.Addr(), tc.method, tc.path, tc.config)
			defer response.Body.Close()

			if response.StatusCode != http.StatusMethodNotAllowed {
				t.Fatalf("expected 405, got %d", response.StatusCode)
			}
			if allow := response.Header.Get("Allow"); !strings.Contains(allow, tc.allowHeader) {
				t.Fatalf("expected Allow header to mention %s, got %q", tc.allowHeader, allow)
			}
		})
	}
}

func TestProtectedRouteWithoutClientCertReturnsUnauthorizedWithExactBody(t *testing.T) {
	fixture := newTLSFixture(t)
	service, _ := startTestApp(t, fixture, seedStorageFixture(t))

	response := doRequest(t, service.Addr(), http.MethodGet, "/v1/blobs/"+store.DigestBytes([]byte("hello"))+":bytes", fixture.baseClientTLSConfig(t))
	defer response.Body.Close()

	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", response.StatusCode)
	}
	if body := string(mustReadBody(t, response.Body)); body != "Authenticated caller identity required" {
		t.Fatalf("unexpected 401 body: %q", body)
	}
}

func TestProtectedRouteWithUnauthorizedClientReturnsForbiddenWithExactBody(t *testing.T) {
	fixture := newTLSFixture(t)
	service, seeded := startTestApp(t, fixture, seedStorageFixture(t))

	response := doRequest(t, service.Addr(), http.MethodGet, "/v1/blobs/"+seeded.BlobDigest+":bytes", fixture.clientTLSConfig(t, "service/execution-governance"))
	defer response.Body.Close()

	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", response.StatusCode)
	}
	if body := string(mustReadBody(t, response.Body)); body != "Caller not authorized for this operation" {
		t.Fatalf("unexpected 403 body: %q", body)
	}
}

func TestHealthReturnsHealthyWhenStarted(t *testing.T) {
	fixture := newTLSFixture(t)
	service, _ := startTestApp(t, fixture, seedStorageFixture(t))

	response := doRequest(t, service.Addr(), http.MethodGet, "/health", fixture.baseClientTLSConfig(t))
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", response.StatusCode)
	}

	var payload struct {
		Status               string `json:"status"`
		Ready                bool   `json:"ready"`
		Service              string `json:"service"`
		AdditionalProperties struct {
			Dependencies struct {
				Storage string `json:"storage"`
				Index   string `json:"index"`
			} `json:"dependencies"`
			Readiness struct {
				Storage       string `json:"storage"`
				Index         string `json:"index"`
				ServerStarted string `json:"server_started"`
			} `json:"readiness"`
		} `json:"additional_properties"`
	}
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		t.Fatalf("decode health response: %v", err)
	}

	if payload.Status != "healthy" || !payload.Ready || payload.Service != "artifact-registry" {
		t.Fatalf("unexpected health payload: %+v", payload)
	}
	if payload.AdditionalProperties.Dependencies.Storage != "healthy" || payload.AdditionalProperties.Dependencies.Index != "healthy" {
		t.Fatalf("unexpected dependency health: %+v", payload)
	}
	if payload.AdditionalProperties.Readiness.Storage != "ready" ||
		payload.AdditionalProperties.Readiness.Index != "ready" ||
		payload.AdditionalProperties.Readiness.ServerStarted != "ready" {
		t.Fatalf("unexpected readiness payload: %+v", payload)
	}
}

type tlsFixture struct {
	caPath         string
	serverCertPath string
	serverKeyPath  string
	caCert         *x509.Certificate
	caKey          *rsa.PrivateKey
}

type rawHTTPResponse struct {
	StatusCode int
	Header     http.Header
	Body       string
}

type artifactRegisterRequest struct {
	DescriptorDigest string `json:"descriptor_digest"`
}

type seededStorage struct {
	RootDir   string
	IndexPath string

	BlobDigest  string
	BlobContent []byte

	JSONDigest string
	JSONBlob   []byte

	ArtifactDigest   string
	DescriptorDigest string
	DescriptorJSON   []byte
	EvidenceDigest   string
	EvidenceJSON     []byte
	ManifestDigest   string
	ManifestJSON     []byte
	PayloadDigest    string
	PayloadBytes     []byte
}

func newTLSFixture(t *testing.T) tlsFixture {
	t.Helper()

	dir := t.TempDir()

	caCert, caKey, caCertPEM := createCertificateAuthority(t)
	serverCertPEM, serverKeyPEM := createLeafCertificate(t, caCert, caKey, certificateRequest{
		commonName: "artifact-registry.internal",
		dnsNames:   []string{"localhost"},
		ipAddrs:    []net.IP{net.ParseIP("127.0.0.1")},
	})

	fixture := tlsFixture{
		caPath:         filepath.Join(dir, "ca.pem"),
		serverCertPath: filepath.Join(dir, "server.pem"),
		serverKeyPath:  filepath.Join(dir, "server.key"),
		caCert:         caCert,
		caKey:          caKey,
	}

	writePEMFile(t, fixture.caPath, caCertPEM)
	writePEMFile(t, fixture.serverCertPath, serverCertPEM)
	writePEMFile(t, fixture.serverKeyPath, serverKeyPEM)

	return fixture
}

func (f tlsFixture) baseClientTLSConfig(t *testing.T) *tls.Config {
	t.Helper()

	pool := x509.NewCertPool()
	pemBytes, err := os.ReadFile(f.caPath)
	if err != nil {
		t.Fatalf("read ca pem: %v", err)
	}
	if !pool.AppendCertsFromPEM(pemBytes) {
		t.Fatal("append ca pem: no valid certificates found")
	}

	return &tls.Config{
		RootCAs:    pool,
		ServerName: "localhost",
		MinVersion: tls.VersionTLS12,
	}
}

func (f tlsFixture) clientTLSConfig(t *testing.T, spiffePath string) *tls.Config {
	t.Helper()

	certPEM, keyPEM := createLeafCertificate(t, f.caCert, f.caKey, certificateRequest{
		commonName: "client",
		uris:       []string{"spiffe://monolith.internal/" + spiffePath},
		clientAuth: true,
	})

	certificate, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("load client key pair: %v", err)
	}

	cfg := f.baseClientTLSConfig(t)
	cfg.Certificates = []tls.Certificate{certificate}
	return cfg
}

func seedStorageFixture(t *testing.T) seededStorage {
	t.Helper()

	rootDir := filepath.Join(t.TempDir(), "storage")
	if err := os.MkdirAll(rootDir, 0o755); err != nil {
		t.Fatalf("create storage root: %v", err)
	}

	state := seededStorage{
		RootDir: rootDir,

		BlobContent:  []byte("Hello, Artifact Registry!"),
		JSONBlob:     []byte(`{"kind":"blob","value":"json"}`),
		ManifestJSON: []byte(`{"schema_version":"v1","name":"runtime"}`),
		PayloadBytes: []byte("payload archive bytes"),
	}

	state.BlobDigest = store.DigestBytes(state.BlobContent)
	state.JSONDigest = store.DigestBytes(state.JSONBlob)
	state.ManifestDigest = store.DigestBytes(state.ManifestJSON)
	state.PayloadDigest = store.DigestBytes(state.PayloadBytes)
	identity, err := evidencev1.NewArtifactIdentity(
		state.PayloadDigest,
		"static-script",
		"sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
	)
	if err != nil {
		t.Fatalf("derive artifact identity: %v", err)
	}
	state.ArtifactDigest = identity.ArtifactDigest
	state.EvidenceJSON = mustMarshalJSON(t, map[string]any{
		"claims": map[string]any{
			"schema_version": "v1",
			"package": map[string]any{
				"identity": map[string]any{
					"artifact_digest": state.ArtifactDigest,
					"payload_digest":  state.PayloadDigest,
					"artifact_type":   "static-script",
					"intent_digest":   "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
				},
				"publication": map[string]any{
					"builder_service": "artifact-governance",
					"invoker": map[string]any{
						"service":   "deployment",
						"principal": "spiffe://monolith.internal/service/deployment",
					},
					"policy_decisions": []any{},
					"build_log_digest": "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
				},
			},
			"admission": map[string]any{
				"authorization": map[string]any{
					"derivation": map[string]any{
						"derivation_spec_digest": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
						"output_id":              "runtime",
						"producer_run_id":        "run-1",
						"policy_version":         "2026-03-31",
						"expected_artifact_type": "static-script",
						"constraints": map[string]any{
							"allowed_toolchains":      []any{},
							"forbidden_toolchains":    []any{},
							"os":                      "linux",
							"arch":                    "amd64",
							"writable_paths":          []any{},
							"forbidden_paths":         []any{},
							"determinism_expectation": "deterministic",
						},
					},
					"workload_binding": map[string]any{
						"module_path":    "services.execution.ExecutionServer",
						"policy_version": "2026-03-31",
					},
				},
				"execution": map[string]any{
					"runtime": map[string]any{
						"parameters":            []any{},
						"environment_variables": []string{"APP_MODE"},
						"required_capabilities": []any{},
					},
					"workload": map[string]any{
						"artifact_class":       "service",
						"workload_type":        "service",
						"service_name":         "execution",
						"workload_identity_id": "spiffe://monolith.internal/service/execution",
					},
					"access": map[string]any{
						"network_access": false,
					},
				},
			},
		},
		"seal": map[string]any{
			"algorithm":      "ed25519",
			"key_id":         "ags-artifact-fact-signer",
			"content_digest": "sha256:4444444444444444444444444444444444444444444444444444444444444444",
			"signature":      "test-signature",
		},
	})
	state.EvidenceDigest = store.DigestBytes(state.EvidenceJSON)
	state.DescriptorJSON = mustMarshalJSON(t, map[string]any{
		"schema_version": "v1",
		"artifact": map[string]any{
			"artifact_digest": state.ArtifactDigest,
			"artifact_type":   "static-script",
			"intent_digest":   "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
		},
		"package": map[string]any{
			"evidence": map[string]any{
				"digest":     state.EvidenceDigest,
				"media_type": "application/json",
			},
			"payload": map[string]any{
				"digest":     state.PayloadDigest,
				"media_type": "application/octet-stream",
			},
			"supporting": []map[string]any{
				{
					"name":       "manifest",
					"digest":     state.ManifestDigest,
					"media_type": "application/json",
				},
			},
		},
	})
	state.DescriptorDigest = store.DigestBytes(state.DescriptorJSON)

	writeBlobAtDigest(t, rootDir, state.BlobDigest, state.BlobContent)
	writeBlobAtDigest(t, rootDir, state.JSONDigest, state.JSONBlob)
	writeBlobAtDigest(t, rootDir, state.DescriptorDigest, state.DescriptorJSON)
	writeBlobAtDigest(t, rootDir, state.EvidenceDigest, state.EvidenceJSON)
	writeBlobAtDigest(t, rootDir, state.ManifestDigest, state.ManifestJSON)
	writeBlobAtDigest(t, rootDir, state.PayloadDigest, state.PayloadBytes)

	state.IndexPath = filepath.Join(rootDir, "artifact-index.json")
	indexPayload, err := json.MarshalIndent(map[string]index.Entry{
		state.ArtifactDigest: {
			ArtifactDigest:   state.ArtifactDigest,
			DescriptorDigest: state.DescriptorDigest,
			CreatedAt:        "2026-03-31T00:00:00Z",
		},
	}, "", "  ")
	if err != nil {
		t.Fatalf("marshal artifact index: %v", err)
	}
	if err := os.WriteFile(state.IndexPath, indexPayload, 0o600); err != nil {
		t.Fatalf("write artifact index: %v", err)
	}

	return state
}

func seedUnregisteredStorageFixture(t *testing.T) seededStorage {
	t.Helper()

	state := seedStorageFixture(t)
	if err := os.WriteFile(state.IndexPath, []byte("{}\n"), 0o600); err != nil {
		t.Fatalf("write empty artifact index: %v", err)
	}
	return state
}

func seedEmptyStorageFixture(t *testing.T) seededStorage {
	t.Helper()

	state := seedStorageFixture(t)
	if err := os.WriteFile(state.IndexPath, []byte("{}\n"), 0o600); err != nil {
		t.Fatalf("write empty artifact index: %v", err)
	}

	digests := []string{
		state.BlobDigest,
		state.JSONDigest,
		state.DescriptorDigest,
		state.EvidenceDigest,
		state.ManifestDigest,
		state.PayloadDigest,
	}
	for _, digest := range digests {
		blobPath, err := store.ResolvePath(state.RootDir, digest)
		if err != nil {
			t.Fatalf("resolve blob path: %v", err)
		}
		if err := os.Remove(blobPath); err != nil {
			t.Fatalf("remove seeded blob: %v", err)
		}
	}

	return state
}

func artifactRegisterRequestFromSeeded(seeded seededStorage) artifactRegisterRequest {
	return artifactRegisterRequest{
		DescriptorDigest: seeded.DescriptorDigest,
	}
}

func writeBlobAtDigest(t *testing.T, rootDir string, digest string, content []byte) {
	t.Helper()

	blobPath, err := store.ResolvePath(rootDir, digest)
	if err != nil {
		t.Fatalf("resolve blob path: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(blobPath), 0o755); err != nil {
		t.Fatalf("create blob directory: %v", err)
	}
	if err := os.WriteFile(blobPath, content, 0o600); err != nil {
		t.Fatalf("write blob: %v", err)
	}
}

func mustMarshalJSON(t *testing.T, value any) []byte {
	t.Helper()

	data, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal json: %v", err)
	}
	return data
}

func startTestApp(t *testing.T, fixture tlsFixture, seeded seededStorage) (*app.App, seededStorage) {
	t.Helper()

	cfgPath := writeConfig(t, fixture, seeded.RootDir, seeded.IndexPath)
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}

	service, err := app.New(cfg)
	if err != nil {
		t.Fatalf("build app: %v", err)
	}

	if _, err := service.Start(context.Background()); err != nil {
		t.Fatalf("start app: %v", err)
	}

	waitForHealth(t, service.Addr(), fixture.baseClientTLSConfig(t))

	t.Cleanup(func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := service.Shutdown(shutdownCtx); err != nil {
			t.Errorf("shutdown app: %v", err)
		}
	})

	return service, seeded
}

func waitForHealth(t *testing.T, addr string, tlsConfig *tls.Config) {
	t.Helper()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		response, err := makeClient(tlsConfig).Get("https://" + addr + "/health")
		if err == nil {
			var payload struct {
				Ready bool `json:"ready"`
			}
			decodeErr := json.NewDecoder(response.Body).Decode(&payload)
			response.Body.Close()
			if response.StatusCode == http.StatusOK && decodeErr == nil && payload.Ready {
				return
			}
		}
		time.Sleep(50 * time.Millisecond)
	}

	t.Fatalf("server at %s did not become ready in time", addr)
}

func doRequest(t *testing.T, addr string, method string, path string, tlsConfig *tls.Config) *http.Response {
	t.Helper()

	request, err := http.NewRequest(method, "https://"+addr+path, nil)
	if err != nil {
		t.Fatalf("build request %s %s: %v", method, path, err)
	}

	response, err := makeClient(tlsConfig).Do(request)
	if err != nil {
		t.Fatalf("request %s %s failed: %v", method, path, err)
	}

	return response
}

func doRequestWithBody(t *testing.T, addr string, method string, path string, body []byte, tlsConfig *tls.Config) *http.Response {
	t.Helper()

	request, err := http.NewRequest(method, "https://"+addr+path, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("build request %s %s: %v", method, path, err)
	}

	response, err := makeClient(tlsConfig).Do(request)
	if err != nil {
		t.Fatalf("request %s %s failed: %v", method, path, err)
	}

	return response
}

func doJSONRequest(t *testing.T, addr string, method string, path string, body any, tlsConfig *tls.Config) *http.Response {
	t.Helper()

	payload, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal request body: %v", err)
	}

	request, err := http.NewRequest(method, "https://"+addr+path, bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("build request %s %s: %v", method, path, err)
	}
	request.Header.Set("Content-Type", "application/json")

	response, err := makeClient(tlsConfig).Do(request)
	if err != nil {
		t.Fatalf("request %s %s failed: %v", method, path, err)
	}

	return response
}

func doRawRequest(t *testing.T, addr string, tlsConfig *tls.Config, method string, rawPath string) rawHTTPResponse {
	t.Helper()

	conn, err := tls.Dial("tcp", addr, tlsConfig)
	if err != nil {
		t.Fatalf("raw tls dial: %v", err)
	}
	defer conn.Close()

	if _, err := fmt.Fprintf(conn, "%s %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", method, rawPath, addr); err != nil {
		t.Fatalf("write raw request: %v", err)
	}

	response, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read raw response: %v", err)
	}
	defer response.Body.Close()

	body := mustReadBody(t, response.Body)
	return rawHTTPResponse{
		StatusCode: response.StatusCode,
		Header:     response.Header.Clone(),
		Body:       string(body),
	}
}

func makeClient(tlsConfig *tls.Config) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
		Timeout: 5 * time.Second,
	}
}

func buildConfig(fixture tlsFixture, rootDir string, indexPath string) config.Config {
	return config.Config{
		HTTP: config.HTTPConfig{
			BindAddress:            "127.0.0.1",
			Port:                   0,
			ReadTimeoutSeconds:     5,
			WriteTimeoutSeconds:    5,
			ShutdownTimeoutSeconds: 5,
		},
		TLS: config.TLSConfig{
			CertFile:     fixture.serverCertPath,
			KeyFile:      fixture.serverKeyPath,
			ClientCAFile: fixture.caPath,
		},
		Authorization: config.AuthorizationConfig{
			AllowedSPIFFEPathPrefixes: []string{
				"service/artifact-governance",
				"service/execution",
				"service/deployment",
				"service/credential-governance",
				"operator",
			},
		},
		Storage: config.StorageConfig{
			RootDir:   rootDir,
			IndexFile: indexPath,
		},
	}
}

func writeConfig(t *testing.T, fixture tlsFixture, rootDir string, indexPath string) string {
	t.Helper()

	payload, err := json.MarshalIndent(buildConfig(fixture, rootDir, indexPath), "", "  ")
	if err != nil {
		t.Fatalf("marshal config: %v", err)
	}

	path := filepath.Join(t.TempDir(), "ars.json")
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	return path
}

func mustReadBody(t *testing.T, reader io.Reader) []byte {
	t.Helper()

	data, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}

	return data
}

type certificateRequest struct {
	commonName string
	dnsNames   []string
	ipAddrs    []net.IP
	uris       []string
	clientAuth bool
}

func createCertificateAuthority(t *testing.T) (*x509.Certificate, *rsa.PrivateKey, []byte) {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate ca key: %v", err)
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("generate ca serial: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               pkix.Name{CommonName: "ARS Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}

	certificateDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("create ca certificate: %v", err)
	}

	certificate, err := x509.ParseCertificate(certificateDER)
	if err != nil {
		t.Fatalf("parse ca certificate: %v", err)
	}

	return certificate, privateKey, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateDER})
}

func createLeafCertificate(t *testing.T, caCert *x509.Certificate, caKey *rsa.PrivateKey, request certificateRequest) ([]byte, []byte) {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate leaf key: %v", err)
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("generate leaf serial: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: request.commonName,
		},
		NotBefore:   time.Now().Add(-time.Hour),
		NotAfter:    time.Now().Add(24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		DNSNames:    request.dnsNames,
		IPAddresses: request.ipAddrs,
	}

	if request.clientAuth {
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	} else {
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	}

	for _, rawURI := range request.uris {
		parsed, err := url.Parse(rawURI)
		if err != nil {
			t.Fatalf("parse uri %q: %v", rawURI, err)
		}
		template.URIs = append(template.URIs, parsed)
	}

	certificateDER, err := x509.CreateCertificate(rand.Reader, template, caCert, &privateKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create leaf certificate: %v", err)
	}

	keyDER := x509.MarshalPKCS1PrivateKey(privateKey)

	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateDER}),
		pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: keyDER})
}

func writePEMFile(t *testing.T, path string, data []byte) {
	t.Helper()

	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write pem file %s: %v", path, err)
	}
}
