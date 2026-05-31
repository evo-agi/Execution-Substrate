package admission

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
)

func TestAdmissionPolicyPrepareRejectsSelectedStaticScriptPayloadSafely(t *testing.T) {
	fixture := newPreparedArtifactFixture(t)
	service, stagingRoot, resultsRoot := newWorkstreamCTestService(t, fixture)
	request := fixture.prepareRequest()
	rawFixture := selectedPatternFixtureText()
	payload := buildAdmissionPolicyStaticScriptArchive(t, map[string][]byte{
		staticScriptEntrypointName: []byte(rawFixture),
	})

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
		case "/v1/blobs/" + fixture.discovery.Payload.Digest + ":bytes":
			_, _ = w.Write(payload)
		default:
			t.Fatalf("prepare reached unexpected ARS path %q", r.URL.Path)
		}
	}))
	service.nomadClient = newTestNomadClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("prepare policy denial must not call nomad, got %s %q", r.Method, r.URL.Path)
	}))

	result, err := service.Prepare(context.Background(), request)
	assertAdmissionError(t, err, http.StatusForbidden, codeDestructiveShellCommandDenied)
	if result.Success {
		t.Fatalf("expected denied prepare result to remain unsuccessful")
	}
	if err.Message != selectedDestructiveShellCommandMessage {
		t.Fatalf("unexpected safe policy message %q", err.Message)
	}
	assertOmitsPolicyFixture(t, err.Code+" "+err.Message, rawFixture)
	response := ErrorResponse{Success: false, Error: err.Message, Code: err.Code}
	body, marshalErr := json.Marshal(response)
	if marshalErr != nil {
		t.Fatalf("marshal redacted prepare response: %v", marshalErr)
	}
	assertTextOmitsAll(t, string(body), `"run_id"`, `"staging"`, `"nomad"`, `"matched"`)
	assertOmitsPolicyFixture(t, string(body), rawFixture)
	assertDirectoryEmpty(t, stagingRoot)
	assertDirectoryEmpty(t, resultsRoot)
	assertExactCallCount(t, arsCalls, "/v1/artifacts/"+fixture.discovery.Artifact.ArtifactDigest+"/discovery", 1)
	assertExactCallCount(t, arsCalls, "/v1/blobs/"+fixture.discovery.Evidence.Digest+":json", 1)
	assertExactCallCount(t, arsCalls, "/v1/blobs/"+testWorkloadZoneVaultConfigDigest+":json", 1)
	assertExactCallCount(t, arsCalls, "/v1/blobs/"+fixture.discovery.Payload.Digest+":bytes", 1)
	if len(arsCalls) != 4 {
		t.Fatalf("expected prepare policy denial to use discovery, evidence, runtime-config, and explicit payload reads only, got %d calls", len(arsCalls))
	}
}

func TestAdmissionPolicySubmitBackstopRejectsBeforeStagingAndNomad(t *testing.T) {
	fixture := newPreparedArtifactFixture(t)
	service, stagingRoot, resultsRoot := newWorkstreamCTestService(t, fixture)
	request := fixture.prepareRequest()
	request.Mode = ExecutionModeAsync
	rawFixture := selectedPatternFixtureText()
	payload := buildAdmissionPolicyStaticScriptArchive(t, map[string][]byte{
		staticScriptEntrypointName: []byte(rawFixture),
	})

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
		case "/v1/blobs/" + fixture.discovery.Payload.Digest + ":bytes":
			_, _ = w.Write(payload)
		default:
			t.Fatalf("submit reached unexpected ARS path before policy denial: %q", r.URL.Path)
		}
	}))
	service.nomadClient = newTestNomadClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("submit policy denial must not call nomad, got %s %q", r.Method, r.URL.Path)
	}))

	result, err := service.Submit(context.Background(), request)
	assertAdmissionError(t, err, http.StatusForbidden, codeDestructiveShellCommandDenied)
	if result.RunID != "" || result.Submitted {
		t.Fatalf("expected denied submit to create no run receipt")
	}
	if err.Message != selectedDestructiveShellCommandMessage {
		t.Fatalf("unexpected safe policy message %q", err.Message)
	}
	assertOmitsPolicyFixture(t, err.Code+" "+err.Message, rawFixture)
	assertDirectoryEmpty(t, stagingRoot)
	assertDirectoryEmpty(t, resultsRoot)
	assertExactCallCount(t, arsCalls, "/v1/artifacts/"+fixture.discovery.Artifact.ArtifactDigest+"/discovery", 1)
	assertExactCallCount(t, arsCalls, "/v1/blobs/"+fixture.discovery.Evidence.Digest+":json", 1)
	assertExactCallCount(t, arsCalls, "/v1/blobs/"+testWorkloadZoneVaultConfigDigest+":json", 1)
	assertExactCallCount(t, arsCalls, "/v1/blobs/"+fixture.discovery.Payload.Digest+":bytes", 1)
	if len(arsCalls) != 4 {
		t.Fatalf("expected submit policy denial to stop before staging and submit payload reread, got %d ARS calls", len(arsCalls))
	}
}

func TestAdmissionPolicyAllowsBenignControlPlaneNormalShellCompatibilityPath(t *testing.T) {
	fixture := newPreparedArtifactFixture(t)
	service, stagingRoot, resultsRoot := newWorkstreamCTestService(t, fixture)
	service.cfg.Execution = controlPlaneNormalShellProfileExecutionConfig()
	request := fixture.prepareRequest()
	request.Invocation.Annotations = map[string]string{
		runtimeProfileAnnotationKey: runtimeProfileControlPlaneNormalShell,
	}
	payload := buildAdmissionPolicyStaticScriptArchive(t, map[string][]byte{
		staticScriptEntrypointName: []byte(benignPolicyFixtureText()),
	})

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
		case "/v1/blobs/" + fixture.discovery.Payload.Digest + ":bytes":
			_, _ = w.Write(payload)
		default:
			t.Fatalf("prepare reached unexpected ARS path %q", r.URL.Path)
		}
	}))
	service.nomadClient = newTestNomadClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("prepare must not call nomad, got %s %q", r.Method, r.URL.Path)
	}))

	result, err := service.Prepare(context.Background(), request)
	if err != nil {
		t.Fatalf("expected benign control-plane normal-shell compatibility prepare to succeed, got %+v", err)
	}
	if !result.Success {
		t.Fatalf("expected successful prepare result")
	}
	assertDirectoryEmpty(t, stagingRoot)
	assertDirectoryEmpty(t, resultsRoot)
	if len(arsCalls) != 4 {
		t.Fatalf("expected benign prepare to include bounded policy payload read, got %d ARS calls", len(arsCalls))
	}
}

func TestAdmissionPolicyPreservesUnsupportedRuntimeProfileResult(t *testing.T) {
	fixture := newPreparedArtifactFixture(t)
	service, stagingRoot, resultsRoot := newWorkstreamCTestService(t, fixture)
	request := fixture.prepareRequest()
	request.Invocation.Annotations = map[string]string{
		runtimeProfileAnnotationKey: runtimeProfileControlPlaneNormalShell,
	}
	payload := buildAdmissionPolicyStaticScriptArchive(t, map[string][]byte{
		staticScriptEntrypointName: []byte(benignPolicyFixtureText()),
	})

	service.arsClient = newArtifactRegistryTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/artifacts/" + fixture.discovery.Artifact.ArtifactDigest + "/discovery":
			writeJSONResponse(t, w, http.StatusOK, fixture.discovery)
		case "/v1/blobs/" + fixture.discovery.Evidence.Digest + ":json":
			writeJSONResponse(t, w, http.StatusOK, fixture.evidence)
		case "/v1/blobs/" + testWorkloadZoneVaultConfigDigest + ":json":
			_, _ = w.Write([]byte(validWorkloadZoneVaultConfigBlob))
		case "/v1/blobs/" + fixture.discovery.Payload.Digest + ":bytes":
			_, _ = w.Write(payload)
		default:
			t.Fatalf("prepare reached unexpected ARS path %q", r.URL.Path)
		}
	}))
	service.nomadClient = newTestNomadClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("unsupported runtime-profile prepare must not call nomad, got %s %q", r.Method, r.URL.Path)
	}))

	_, err := service.Prepare(context.Background(), request)
	assertAdmissionError(t, err, http.StatusBadRequest, codeUnsupportedRuntimeProfile)
	assertDirectoryEmpty(t, stagingRoot)
	assertDirectoryEmpty(t, resultsRoot)
}
