package admission

import (
	"context"
	"net/http"
	"strings"
	"testing"
)

func TestWorkstreamBAdmissionHotPathUsesDiscoveryAndEvidenceNotSupportTupleGrammar(t *testing.T) {
	fixture := newPreparedArtifactFixture(t)
	service, stagingRoot, resultsRoot := newWorkstreamCTestService(t, fixture)
	request := fixture.prepareRequest()

	arsCalls := map[string]int{}
	service.arsClient = newArtifactRegistryTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		arsCalls[r.URL.Path]++
		switch r.URL.Path {
		case "/v1/artifacts/" + fixture.discovery.Artifact.ArtifactDigest + "/discovery":
			writeJSONResponse(t, w, http.StatusOK, fixture.discovery)
		case "/v1/blobs/" + fixture.discovery.Evidence.Digest + ":json":
			writeJSONResponse(t, w, http.StatusOK, fixture.evidence)
		case "/v1/blobs/" + testWorkloadZoneVaultConfigDigest + ":json":
			_, _ = w.Write([]byte(validWorkloadZoneVaultConfigBlob))
		default:
			t.Fatalf("admission hot path reached unexpected ARS support path %q", r.URL.Path)
		}
	}))
	service.nomadClient = newTestNomadClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("prepare must not call nomad, got %s %q", r.Method, r.URL.Path)
	}))

	result, err := service.Prepare(context.Background(), request)
	if err != nil {
		t.Fatalf("prepare: %+v", err)
	}
	if !result.Success {
		t.Fatalf("expected successful prepare result, got %+v", result)
	}
	assertDirectoryEmpty(t, stagingRoot)
	assertDirectoryEmpty(t, resultsRoot)
	assertExactCallCount(t, arsCalls, "/v1/artifacts/"+fixture.discovery.Artifact.ArtifactDigest+"/discovery", 1)
	assertExactCallCount(t, arsCalls, "/v1/blobs/"+fixture.discovery.Evidence.Digest+":json", 1)
	assertExactCallCount(t, arsCalls, "/v1/blobs/"+testWorkloadZoneVaultConfigDigest+":json", 1)
	for path := range arsCalls {
		for _, forbidden := range []string{"/descriptor", "/manifest", "/index", "/support"} {
			if strings.Contains(path, forbidden) {
				t.Fatalf("ES admission hot path must not require ARS support tuple path %q; calls=%v", path, arsCalls)
			}
		}
	}
}

func TestWorkstreamBAdmissionDistinguishesPayloadDigestFromArtifactDigest(t *testing.T) {
	fixture := newPreparedArtifactFixture(t)
	service := fixture.service()
	request := fixture.prepareRequest()

	payloadAsArtifactRequest := request
	payloadAsArtifactRequest.Invocation.ArtifactDigest = fixture.evidence.Claims.Package.Identity.PayloadDigest
	_, err := service.prepareArtifactFromDiscovery(payloadAsArtifactRequest, fixture.trustModel, discoveredArtifact{
		discovery: fixture.discovery,
		evidence:  fixture.evidence,
	})
	if err == nil || err.Code != codeInvalidRequest || !strings.Contains(err.Message, "artifact digest mismatch between request and artifact discovery") {
		t.Fatalf("expected payload digest in artifact request position to fail as request/package identity mismatch, got %+v", err)
	}

	payloadReferenceUsesArtifactDigest := fixture.discovery
	payloadReferenceUsesArtifactDigest.Payload.Digest = fixture.evidence.Claims.Package.Identity.ArtifactDigest
	_, err = service.prepareArtifactFromDiscovery(request, fixture.trustModel, discoveredArtifact{
		discovery: payloadReferenceUsesArtifactDigest,
		evidence:  fixture.evidence,
	})
	if err == nil || err.Code != codeArtifactEvidenceInvalid || !strings.Contains(err.Message, "payload reference does not match artifact evidence") {
		t.Fatalf("expected artifact digest in payload reference position to fail as evidence/discovery mismatch, got %+v", err)
	}
}

func TestWorkstreamBAdmissionPublicGrammarExcludesARSSupportTuplesAndCPProofFields(t *testing.T) {
	fieldNames := collectJSONFieldNames(t,
		PrepareRequest{},
		ArtifactInvocation{},
		ExecutionResources{},
		RuntimeMount{},
		MountSource{},
		PrepareResult{},
		SubmitResult{},
		ExecutionStatusResult{},
		ExecutionCancelResult{},
		ProducerContractDeclaration{},
	)

	for _, forbidden := range []string{
		"payload_digest",
		"discovery_digest",
		"descriptor",
		"descriptor_digest",
		"manifest",
		"manifest_digest",
		"index",
		"index_entry",
		"support",
		"supporting",
		"publication",
		"builder_service",
		"invoker",
		"policy_decisions",
		"build_log_digest",
		"attempt_manifest",
		"retained_result_manifest",
		"review",
		"checkpoint",
		"finalization",
	} {
		if _, ok := fieldNames[forbidden]; ok {
			t.Fatalf("ES public admission/lifecycle DTOs must not expose Workstream B support or CP proof grammar field %q", forbidden)
		}
	}
}

func TestWorkstreamBControlPlaneNormalShellCompatibilitySurfaceUnchanged(t *testing.T) {
	if runtimeProfileAnnotationKey != "execution_substrate.runtime_profile" {
		t.Fatalf("runtime profile annotation compatibility key changed to %q", runtimeProfileAnnotationKey)
	}
	if runtimeProfileControlPlaneNormalShell != "control-plane-normal-shell/v1" {
		t.Fatalf("control-plane normal-shell profile compatibility name changed to %q", runtimeProfileControlPlaneNormalShell)
	}
}
