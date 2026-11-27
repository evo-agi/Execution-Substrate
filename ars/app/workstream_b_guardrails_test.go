package app_test

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	arscontract "execution-substrate/ars/contract"
)

func TestWorkstreamBDiscoveryRecordIsRuntimeFacingSurface(t *testing.T) {
	fixture := newTLSFixture(t)
	service, seeded := startTestApp(t, fixture, seedStorageFixture(t))

	response := doRequest(t, service.Addr(), http.MethodGet, "/v1/artifacts/"+seeded.ArtifactDigest+"/discovery", fixture.clientTLSConfig(t, "service/execution"))
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", response.StatusCode)
	}
	if got := response.Header.Get("Content-Digest"); got != seeded.DiscoveryDigest {
		t.Fatalf("expected discovery content digest %q, got %q", seeded.DiscoveryDigest, got)
	}
	body := mustReadBody(t, response.Body)

	var discovery arscontract.ArtifactDiscovery
	if err := json.Unmarshal(body, &discovery); err != nil {
		t.Fatalf("decode discovery: %v", err)
	}
	if discovery.Artifact.ArtifactDigest != seeded.ArtifactDigest {
		t.Fatalf("unexpected discovery artifact identity: %+v", discovery.Artifact)
	}
	if discovery.Evidence.Digest != seeded.EvidenceDigest || discovery.Payload.Digest != seeded.PayloadDigest {
		t.Fatalf("discovery must expose runtime-facing evidence and payload refs, got %+v", discovery)
	}
	if discovery.Artifact.ArtifactDigest == discovery.Payload.Digest {
		t.Fatalf("artifact_digest must not be treated as payload_digest, both were %q", discovery.Artifact.ArtifactDigest)
	}

	var raw map[string]any
	if err := json.Unmarshal(body, &raw); err != nil {
		t.Fatalf("decode raw discovery: %v", err)
	}
	for _, required := range []string{"schema_version", "artifact", "evidence", "payload"} {
		if _, ok := raw[required]; !ok {
			t.Fatalf("discovery record missing runtime-facing field %q: %s", required, string(body))
		}
	}
	for _, forbidden := range []string{
		"descriptor_digest",
		"manifest_digest",
		"index",
		"support",
		"supporting",
		"attempt_manifest",
		"retained_result_manifest",
		"review",
		"checkpoint",
		"finalization",
	} {
		if strings.Contains(string(body), forbidden) {
			t.Fatalf("runtime-facing discovery record must not expose support or CP proof grammar %q: %s", forbidden, string(body))
		}
	}
}

func TestWorkstreamBDiscoveryOnlyRegistrationDoesNotRequireDescriptorManifestSupport(t *testing.T) {
	fixture := newTLSFixture(t)
	service, seeded := startTestApp(t, fixture, seedUnregisteredStorageFixture(t))

	register := doJSONRequest(t, service.Addr(), http.MethodPost, "/v1/artifacts:register", artifactRegisterRequest{
		DiscoveryDigest: seeded.DiscoveryDigest,
	}, fixture.clientTLSConfig(t, "service/artifact-governance"))
	defer register.Body.Close()
	if register.StatusCode != http.StatusCreated {
		t.Fatalf("expected discovery-only registration to return 201, got %d body=%s", register.StatusCode, strings.TrimSpace(string(mustReadBody(t, register.Body))))
	}
	var registerPayload arscontract.RegisterArtifactResponse
	if err := json.NewDecoder(register.Body).Decode(&registerPayload); err != nil {
		t.Fatalf("decode registration response: %v", err)
	}
	if !registerPayload.Registered || registerPayload.ArtifactDigest != seeded.ArtifactDigest {
		t.Fatalf("unexpected registration payload: %+v", registerPayload)
	}
	if registerPayload.DescriptorDigest != "" {
		t.Fatalf("expected descriptor support to remain optional, got %+v", registerPayload)
	}

	for _, tc := range []struct {
		name       string
		path       string
		wantStatus int
	}{
		{name: "discovery", path: "/v1/artifacts/" + seeded.ArtifactDigest + "/discovery", wantStatus: http.StatusOK},
		{name: "evidence", path: "/v1/artifacts/" + seeded.ArtifactDigest + "/evidence", wantStatus: http.StatusOK},
		{name: "descriptor support", path: "/v1/artifacts/" + seeded.ArtifactDigest + "/descriptor", wantStatus: http.StatusNotFound},
		{name: "manifest support", path: "/v1/artifacts/" + seeded.ArtifactDigest + "/manifest", wantStatus: http.StatusNotFound},
	} {
		t.Run(tc.name, func(t *testing.T) {
			response := doRequest(t, service.Addr(), http.MethodGet, tc.path, fixture.clientTLSConfig(t, "service/execution"))
			defer response.Body.Close()
			if response.StatusCode != tc.wantStatus {
				t.Fatalf("expected %s to return %d, got %d body=%s", tc.path, tc.wantStatus, response.StatusCode, strings.TrimSpace(string(mustReadBody(t, response.Body))))
			}
		})
	}
}
