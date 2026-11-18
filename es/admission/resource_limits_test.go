package admission

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	runtimeconfigv1 "execution-substrate/internal/contracts/runtimeconfig/v1"
	"golang.org/x/sys/unix"
)

type countedReadCloser struct {
	reader io.Reader
	reads  int
}

func (body *countedReadCloser) Read(buffer []byte) (int, error) {
	body.reads++
	return body.reader.Read(buffer)
}

func (*countedReadCloser) Close() error { return nil }

func TestBoundedResponseAcquisitionCoversFixedChunkedDishonestAndTruncatedBodies(t *testing.T) {
	limit := int64(4)
	tests := []struct {
		name          string
		contentLength int64
		body          string
		want          string
		wantError     error
	}{
		{name: "fixed exact", contentLength: 4, body: "1234", want: "1234"},
		{name: "chunked exact", contentLength: -1, body: "1234", want: "1234"},
		{name: "chunked plus one", contentLength: -1, body: "12345", wantError: errBoundedResponseTooLarge},
		{name: "dishonest surplus", contentLength: 3, body: "1234", wantError: errBoundedResponseLengthMismatch},
		{name: "fixed truncated", contentLength: 4, body: "123", wantError: errBoundedResponseLengthMismatch},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response := &http.Response{
				Body:          io.NopCloser(strings.NewReader(test.body)),
				ContentLength: test.contentLength,
			}
			payload, err := readBoundedResponseBody(response, limit)
			if test.wantError != nil {
				if !errors.Is(err, test.wantError) {
					t.Fatalf("expected %v, got payload=%q err=%v", test.wantError, payload, err)
				}
				return
			}
			if err != nil || string(payload) != test.want {
				t.Fatalf("unexpected bounded payload=%q err=%v", payload, err)
			}
		})
	}
}

func TestBoundedResponseAcquisitionRejectsOversizedContentLengthBeforeRead(t *testing.T) {
	body := &countedReadCloser{reader: strings.NewReader("12345")}
	response := &http.Response{Body: body, ContentLength: 5}
	if _, err := readBoundedResponseBody(response, 4); !errors.Is(err, errBoundedResponseTooLarge) {
		t.Fatalf("expected early Content-Length refusal, got %v", err)
	}
	if body.reads != 0 {
		t.Fatalf("oversized known response was read %d times", body.reads)
	}
}

func TestTrancheAResourceLimitLedgerConstantsAndAggregateCeiling(t *testing.T) {
	tests := []struct {
		name string
		got  int64
		want int64
	}{
		{name: "dependency JSON", got: maxDependencyJSONResponseBytes, want: 256 << 10},
		{name: "policy payload", got: maxAdmissionPolicyPayloadBytes, want: 256 << 10},
		{name: "primary payload", got: maxPrimaryPayloadBytes, want: 32 << 20},
		{name: "mount compressed per component", got: maxRuntimeMountBytes, want: 8 << 20},
		{name: "mount compressed aggregate", got: maxRuntimeMountTotalBytes, want: 32 << 20},
		{name: "mount stream per component", got: maxRuntimeMountStreamBytes, want: 16 << 20},
		{name: "mount stream aggregate", got: maxRuntimeMountTotalStreamBytes, want: 64 << 20},
		{name: "runtime support", got: maxRuntimeSupportBytes, want: 32 << 20},
		{name: "Vault CA", got: maxWorkloadVaultCABytes, want: 256 << 10},
		{name: "system CA", got: maxSystemCABundleBytes, want: 256 << 10},
		{name: "combined workload CA", got: maxWorkloadTLSBundleBytes, want: 524289},
		{name: "retained material ceiling", got: maxResolvedExecutionMaterialBytes, want: 168558593},
		{name: "temporary material ceiling", got: maxResolvedExecutionTemporaryMaterialBytes, want: 262144},
		{name: "accounted peak", got: maxResolvedExecutionAccountedPeakBytes, want: 168820737},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if test.got != test.want {
				t.Fatalf("got %d, want %d", test.got, test.want)
			}
		})
	}
}

func TestTrancheABoundedDependencyPublicErrorMappings(t *testing.T) {
	oversizedClient := func(t *testing.T, limit int64) *dependencyClient {
		t.Helper()
		return newArtifactRegistryTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Length", strconv.FormatInt(limit+1, 10))
			w.WriteHeader(http.StatusOK)
		}))
	}

	t.Run("artifact discovery", func(t *testing.T) {
		service := Service{arsClient: oversizedClient(t, maxDependencyJSONResponseBytes)}
		_, got := service.fetchArtifactDiscoveryRecord(t.Context(), labeledDigest("a1"))
		if got == nil || got.Status != http.StatusServiceUnavailable || got.Code != codeArtifactEvidenceUnavailable || got.Message != "artifact discovery payload was invalid" {
			t.Fatalf("unexpected discovery limit mapping: %+v", got)
		}
	})
	t.Run("artifact evidence", func(t *testing.T) {
		service := Service{arsClient: oversizedClient(t, maxDependencyJSONResponseBytes)}
		_, got := service.fetchArtifactEvidenceBlob(t.Context(), labeledDigest("a2"), labeledDigest("a3"))
		if got == nil || got.Status != http.StatusServiceUnavailable || got.Code != codeArtifactEvidenceUnavailable || got.Message != "artifact evidence payload was invalid" {
			t.Fatalf("unexpected evidence limit mapping: %+v", got)
		}
	})
	t.Run("workload runtime config", func(t *testing.T) {
		service := Service{arsClient: oversizedClient(t, maxDependencyJSONResponseBytes)}
		_, got := service.fetchWorkloadZoneVaultConfig(t.Context(), runtimeconfigv1.WorkloadZoneVaultConfigRef{Digest: labeledDigest("a4")})
		if got == nil || got.Status != http.StatusServiceUnavailable || got.Code != codeWorkloadZoneVaultUnavailable || got.Message != "artifact registry workload-zone vault blob was invalid" {
			t.Fatalf("unexpected runtime-config limit mapping: %+v", got)
		}
	})
	t.Run("admission policy", func(t *testing.T) {
		service := Service{arsClient: oversizedClient(t, maxAdmissionPolicyPayloadBytes)}
		_, got := service.fetchAdmissionPolicyPayloadBytes(t.Context(), labeledDigest("a5"))
		if got == nil || got.Status != http.StatusForbidden || got.Code != codeAdmissionPolicyInputUnavailable || got.Message != admissionPolicyInputUnavailableMessage {
			t.Fatalf("unexpected admission-policy limit mapping: %+v", got)
		}
	})
	t.Run("primary payload", func(t *testing.T) {
		service := Service{arsClient: oversizedClient(t, maxPrimaryPayloadBytes)}
		_, got := service.fetchPayloadBytes(t.Context(), labeledDigest("a6"))
		if got == nil || got.Status != http.StatusServiceUnavailable || got.Code != codePayloadUnavailable || got.Message != "artifact payload read failed" {
			t.Fatalf("unexpected primary-payload limit mapping: %+v", got)
		}
	})
}

func TestBoundedDependencyHealthPreservesExtensionTolerance(t *testing.T) {
	client := newArtifactRegistryTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeJSONResponse(t, w, http.StatusOK, map[string]any{
			"status": "healthy",
			"ready":  true,
			"extension": map[string]any{
				"version": "v2",
			},
		})
	}))
	if !client.checkReady(t.Context()) {
		t.Fatal("expected bounded dependency health decoding to preserve extension tolerance")
	}

	client = newArtifactRegistryTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Length", strconv.FormatInt(maxDependencyJSONResponseBytes+1, 10))
		w.WriteHeader(http.StatusOK)
	}))
	if client.checkReady(t.Context()) {
		t.Fatal("expected oversized dependency health response to remain not ready")
	}
}

func TestTrancheAMountTransportLimitUsesPublicMountError(t *testing.T) {
	fixture := newPreparedArtifactFixture(t)
	service := fixture.service()
	service.arsClient = newArtifactRegistryTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/artifacts/" + fixture.discovery.Artifact.ArtifactDigest + "/discovery":
			writeJSONResponse(t, w, http.StatusOK, fixture.discovery)
		case "/v1/blobs/" + fixture.discovery.Evidence.Digest + ":json":
			writeJSONResponse(t, w, http.StatusOK, fixture.evidence)
		case "/v1/blobs/" + fixture.discovery.Payload.Digest + ":bytes":
			w.Header().Set("Content-Length", strconv.FormatInt(maxRuntimeMountBytes+1, 10))
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("unexpected mount acquisition path %q", r.URL.Path)
		}
	}))
	mounts := []RuntimeMount{{
		Source:     MountSource{ArtifactDigest: fixture.discovery.Artifact.ArtifactDigest},
		TargetPath: "/execution/mounts/config",
		ReadOnly:   true,
	}}
	if err := validateRuntimeMounts(mounts); err != nil {
		t.Fatal(err)
	}
	_, _, got := service.resolveRuntimeMounts(t.Context(), fixture.trustModel, mounts)
	if got == nil || got.Status != http.StatusConflict || got.Code != codeMountArtifactInvalid || got.Message != "mount payload exceeds the per-mount size limit" {
		t.Fatalf("unexpected mount transport limit mapping: %+v", got)
	}
}

func TestTrancheALocalMaterialBoundariesUseSelectedLimits(t *testing.T) {
	root := physicalTestTempDir(t)
	runtimeSupport := filepath.Join(root, "runtime-support")
	if err := os.WriteFile(runtimeSupport, nil, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(runtimeSupport, maxRuntimeSupportBytes); err != nil {
		t.Fatal(err)
	}
	content, err := captureStableRegularFile(runtimeSupport, maxRuntimeSupportBytes)
	if err != nil || int64(len(content)) != maxRuntimeSupportBytes {
		t.Fatalf("exact runtime-support limit failed: bytes=%d err=%v", len(content), err)
	}
	content = nil
	if err := os.Truncate(runtimeSupport, maxRuntimeSupportBytes+1); err != nil {
		t.Fatal(err)
	}
	if _, err := captureStableRegularFile(runtimeSupport, maxRuntimeSupportBytes); err == nil {
		t.Fatal("expected runtime-support plus-one refusal")
	}

	systemCA := filepath.Join(root, "system-ca.pem")
	exactCA := append(bytes.Repeat([]byte{'s'}, int(maxSystemCABundleBytes)-1), '\n')
	if err := os.WriteFile(systemCA, exactCA, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SSL_CERT_FILE", systemCA)
	capturedCA, err := readSystemCABundle()
	if err != nil || int64(len(capturedCA)) != maxSystemCABundleBytes {
		t.Fatalf("exact system-CA limit failed: bytes=%d err=%v", len(capturedCA), err)
	}
	if err := os.WriteFile(systemCA, bytes.Repeat([]byte{'s'}, int(maxSystemCABundleBytes)+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readSystemCABundle(); err == nil {
		t.Fatal("expected configured system-CA plus-one refusal")
	}

	exactVaultCA := normalizePEMBytesForRuntimeFile(bytes.Repeat([]byte{'v'}, int(maxWorkloadVaultCABytes)-1))
	if int64(len(exactVaultCA)) != maxWorkloadVaultCABytes {
		t.Fatalf("unexpected exact normalized Vault CA length %d", len(exactVaultCA))
	}
	combined := appendNormalizedPEMBundle(exactCA, exactVaultCA)
	if int64(len(combined)) != maxWorkloadTLSBundleBytes {
		t.Fatalf("unexpected exact combined trust length %d", len(combined))
	}
	if &combined[0] == &exactCA[0] || &combined[len(exactCA)+1] == &exactVaultCA[0] {
		t.Fatal("combined trust bundle unexpectedly aliases an input")
	}
}

func TestStableLocalCaptureEnforcesExactLimitNoFollowSingleLinkAndLeafIdentity(t *testing.T) {
	root := physicalTestTempDir(t)
	path := filepath.Join(root, "material")
	if err := os.WriteFile(path, []byte("1234"), 0o600); err != nil {
		t.Fatal(err)
	}
	if payload, err := captureStableRegularFile(path, 4); err != nil || string(payload) != "1234" {
		t.Fatalf("exact-limit capture failed payload=%q err=%v", payload, err)
	}
	if _, err := captureStableRegularFile(path, 3); err == nil {
		t.Fatal("expected plus-one local material refusal")
	}

	symlinkPath := filepath.Join(root, "material-link")
	if err := os.Symlink(path, symlinkPath); err != nil {
		t.Fatal(err)
	}
	if _, err := captureStableRegularFile(symlinkPath, 4); err == nil {
		t.Fatal("expected no-follow local material refusal")
	}
	fifoPath := filepath.Join(root, "material-fifo")
	if err := unix.Mkfifo(fifoPath, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := captureStableRegularFile(fifoPath, 4); err == nil {
		t.Fatal("expected FIFO local material refusal")
	}
	if _, err := captureStableRegularFile("/dev/null", 4); err == nil {
		t.Fatal("expected device local material refusal")
	}

	hardlinkPath := filepath.Join(root, "material-hardlink")
	if err := os.Link(path, hardlinkPath); err != nil {
		t.Fatal(err)
	}
	if _, err := captureStableRegularFile(path, 4); err == nil {
		t.Fatal("expected multi-link local material refusal")
	}
	if err := os.Remove(hardlinkPath); err != nil {
		t.Fatal(err)
	}

	replacement := filepath.Join(root, "replacement")
	if err := os.WriteFile(replacement, []byte("5678"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := captureStableRegularFileWithHook(path, 4, func() {
		if renameErr := os.Rename(replacement, path); renameErr != nil {
			t.Fatalf("replace captured leaf: %v", renameErr)
		}
	})
	if err == nil || !strings.Contains(err.Error(), "source") {
		t.Fatalf("expected opened-source replacement refusal, got %v", err)
	}
}

func TestStableLocalCaptureDetectsAncestorReplacement(t *testing.T) {
	root := physicalTestTempDir(t)
	sourceDir := filepath.Join(root, "source")
	if err := os.Mkdir(sourceDir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(sourceDir, "material")
	if err := os.WriteFile(path, []byte("1234"), 0o600); err != nil {
		t.Fatal(err)
	}
	displaced := filepath.Join(root, "displaced")
	_, err := captureStableRegularFileWithHook(path, 4, func() {
		if renameErr := os.Rename(sourceDir, displaced); renameErr != nil {
			t.Fatalf("displace captured ancestor: %v", renameErr)
		}
		if mkdirErr := os.Mkdir(sourceDir, 0o700); mkdirErr != nil {
			t.Fatalf("replace captured ancestor: %v", mkdirErr)
		}
		if writeErr := os.WriteFile(filepath.Join(sourceDir, "material"), []byte("5678"), 0o600); writeErr != nil {
			t.Fatalf("write replacement source: %v", writeErr)
		}
	})
	if err == nil || !strings.Contains(err.Error(), "source ancestry changed") {
		t.Fatalf("expected captured-ancestor replacement refusal, got %v", err)
	}
}

func TestResolvedMaterialAggregateAccountingUsesTransferredVariableContent(t *testing.T) {
	facts := resolvedMaterialFacts{
		payloadBytes:        bytes.Repeat([]byte{'p'}, 8),
		runtimeSupportBytes: bytes.Repeat([]byte{'s'}, 8),
		mounts: []validatedMountArchive{{
			compressedBytes: []byte("compressed"),
			entries:         []validatedMountEntry{{name: "name", contents: []byte("body")}},
		}},
		trust: resolvedTrustMaterial{vaultCACertBytes: []byte("vault"), workloadTLSBundleBytes: []byte("combined")},
	}
	material, err := newResolvedExecutionMaterial(&facts)
	if err != nil {
		t.Fatal(err)
	}
	if facts.payloadBytes != nil || len(material.mounts) != 1 {
		t.Fatal("material ownership was not transferred exactly once")
	}
}
