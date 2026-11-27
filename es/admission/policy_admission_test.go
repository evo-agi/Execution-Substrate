package admission

import (
	"encoding/json"
	"net/http"
	"testing"

	esconfig "execution-substrate/es/config"
)

func TestAdmissionPolicyPrepareRejectsSelectedStaticScriptPayloadSafely(t *testing.T) {
	fixture := newPreparedArtifactFixture(t)
	service, stagingRoot, resultsRoot := newWorkstreamCTestService(t, fixture)
	rawFixture := selectedPatternFixtureText()
	payload := buildAdmissionPolicyStaticScriptArchive(t, map[string][]byte{
		staticScriptEntrypointName: []byte(rawFixture),
	})
	fixture = fixture.withPayload(t, payload)
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
		case "/v1/blobs/" + fixture.discovery.Payload.Digest + ":bytes":
			_, _ = w.Write(payload)
		default:
			t.Fatalf("prepare reached unexpected ARS path %q", r.URL.Path)
		}
	}))
	service.nomadClient = newTestNomadClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("prepare policy denial must not call nomad, got %s %q", r.Method, r.URL.Path)
	}))

	result, err := service.Prepare(testCallerContext(), request)
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
	rawFixture := selectedPatternFixtureText()
	payload := buildAdmissionPolicyStaticScriptArchive(t, map[string][]byte{
		staticScriptEntrypointName: []byte(rawFixture),
	})
	fixture = fixture.withPayload(t, payload)
	request := fixture.prepareRequest()
	request.Mode = ExecutionModeAsync

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

	result, err := service.Submit(testCallerContext(), request)
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

func TestConfiguredStaticScriptLiteralDenyPrepareRejectsConfiguredMarkerSafely(t *testing.T) {
	fixture := newPreparedArtifactFixture(t)
	service, stagingRoot, resultsRoot := newWorkstreamCTestService(t, fixture)
	marker := configuredPolicyFixtureMarker()
	configureConfiguredStaticScriptLiteralDenyService(service, marker)
	payload := buildAdmissionPolicyStaticScriptArchive(t, map[string][]byte{
		staticScriptEntrypointName: []byte("echo before\n" + marker + "\necho after\n"),
	})
	fixture = fixture.withPayload(t, payload)
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
		case "/v1/blobs/" + fixture.discovery.Payload.Digest + ":bytes":
			_, _ = w.Write(payload)
		default:
			t.Fatalf("prepare reached unexpected ARS path before configured literal denial: %q", r.URL.Path)
		}
	}))
	service.nomadClient = newTestNomadClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("configured literal prepare denial must not call nomad, got %s %q", r.Method, r.URL.Path)
	}))

	result, err := service.Prepare(testCallerContext(), request)
	assertAdmissionError(t, err, http.StatusForbidden, codeConfiguredStaticScriptDenied)
	if result.Success {
		t.Fatalf("prepare must not report success on configured literal denial")
	}
	if err.Message != configuredStaticScriptLiteralDenyMessage {
		t.Fatalf("unexpected configured literal denial message %q", err.Message)
	}
	body, marshalErr := json.Marshal(ErrorResponse{Success: false, Error: err.Message, Code: err.Code})
	if marshalErr != nil {
		t.Fatalf("marshal error response: %v", marshalErr)
	}
	assertOmitsPolicyFixture(t, string(body), marker)
	assertDirectoryEmpty(t, stagingRoot)
	assertDirectoryEmpty(t, resultsRoot)
	assertExactCallCount(t, arsCalls, "/v1/artifacts/"+fixture.discovery.Artifact.ArtifactDigest+"/discovery", 1)
	assertExactCallCount(t, arsCalls, "/v1/blobs/"+fixture.discovery.Evidence.Digest+":json", 1)
	assertExactCallCount(t, arsCalls, "/v1/blobs/"+testWorkloadZoneVaultConfigDigest+":json", 1)
	assertExactCallCount(t, arsCalls, "/v1/blobs/"+fixture.discovery.Payload.Digest+":bytes", 1)
	if len(arsCalls) != 4 {
		t.Fatalf("expected configured literal prepare denial to stop before staging, got %d ARS calls", len(arsCalls))
	}
}

func TestConfiguredStaticScriptLiteralDenySubmitBackstopRejectsBeforeStagingAndNomad(t *testing.T) {
	fixture := newPreparedArtifactFixture(t)
	service, stagingRoot, resultsRoot := newWorkstreamCTestService(t, fixture)
	marker := configuredPolicyFixtureMarker()
	configureConfiguredStaticScriptLiteralDenyService(service, marker)
	payload := buildAdmissionPolicyStaticScriptArchive(t, map[string][]byte{
		staticScriptEntrypointName: []byte("echo before\n" + marker + "\necho after\n"),
	})
	fixture = fixture.withPayload(t, payload)
	request := fixture.prepareRequest()
	request.Mode = ExecutionModeAsync

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
			t.Fatalf("submit reached unexpected ARS path before configured literal denial: %q", r.URL.Path)
		}
	}))
	service.nomadClient = newTestNomadClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("configured literal submit denial must not call nomad, got %s %q", r.Method, r.URL.Path)
	}))

	result, err := service.Submit(testCallerContext(), request)
	assertAdmissionError(t, err, http.StatusForbidden, codeConfiguredStaticScriptDenied)
	if result.RunID != "" || result.Submitted {
		t.Fatalf("submit denial must not create run ID or submitted receipt")
	}
	if err.Message != configuredStaticScriptLiteralDenyMessage {
		t.Fatalf("unexpected configured literal denial message %q", err.Message)
	}
	assertOmitsPolicyFixture(t, err.Code+" "+err.Message, marker)
	assertDirectoryEmpty(t, stagingRoot)
	assertDirectoryEmpty(t, resultsRoot)
	assertExactCallCount(t, arsCalls, "/v1/artifacts/"+fixture.discovery.Artifact.ArtifactDigest+"/discovery", 1)
	assertExactCallCount(t, arsCalls, "/v1/blobs/"+fixture.discovery.Evidence.Digest+":json", 1)
	assertExactCallCount(t, arsCalls, "/v1/blobs/"+testWorkloadZoneVaultConfigDigest+":json", 1)
	assertExactCallCount(t, arsCalls, "/v1/blobs/"+fixture.discovery.Payload.Digest+":bytes", 1)
	if len(arsCalls) != 4 {
		t.Fatalf("expected configured literal submit denial to stop before staging and nomad, got %d ARS calls", len(arsCalls))
	}
}

func TestConfiguredStaticScriptLiteralDenyDisabledModeAllowsMatchingPayload(t *testing.T) {
	fixture := newPreparedArtifactFixture(t)
	service, stagingRoot, resultsRoot := newWorkstreamCTestService(t, fixture)
	marker := configuredPolicyFixtureMarker()
	configureConfiguredStaticScriptLiteralDenyServiceMode(service, esconfig.ConfiguredStaticScriptLiteralDenyModeDisabled, marker)
	payload := buildAdmissionPolicyStaticScriptArchive(t, map[string][]byte{
		staticScriptEntrypointName: []byte("echo " + marker),
	})
	fixture = fixture.withPayload(t, payload)
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
		case "/v1/blobs/" + fixture.discovery.Payload.Digest + ":bytes":
			_, _ = w.Write(payload)
		default:
			t.Fatalf("prepare reached unexpected ARS path %q", r.URL.Path)
		}
	}))
	service.nomadClient = newTestNomadClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("prepare must not call nomad, got %s %q", r.Method, r.URL.Path)
	}))

	result, err := service.Prepare(testCallerContext(), request)
	if err != nil {
		t.Fatalf("expected disabled configured literal policy to allow prepare, got %+v", err)
	}
	if !result.Success {
		t.Fatalf("expected disabled configured literal policy prepare to succeed")
	}
	assertDirectoryEmpty(t, stagingRoot)
	assertDirectoryEmpty(t, resultsRoot)
	assertExactCallCount(t, arsCalls, "/v1/artifacts/"+fixture.discovery.Artifact.ArtifactDigest+"/discovery", 1)
	assertExactCallCount(t, arsCalls, "/v1/blobs/"+fixture.discovery.Evidence.Digest+":json", 1)
	assertExactCallCount(t, arsCalls, "/v1/blobs/"+testWorkloadZoneVaultConfigDigest+":json", 1)
	assertExactCallCount(t, arsCalls, "/v1/blobs/"+fixture.discovery.Payload.Digest+":bytes", 1)
	if len(arsCalls) != 4 {
		t.Fatalf("expected disabled configured literal prepare to use only bounded admission reads, got %d ARS calls", len(arsCalls))
	}
}

func TestAdmissionPolicyAllowsBenignControlPlaneNormalShellCompatibilityPath(t *testing.T) {
	fixture := newPreparedArtifactFixture(t)
	service, stagingRoot, resultsRoot := newWorkstreamCTestService(t, fixture)
	service.cfg.Execution = controlPlaneNormalShellProfileExecutionConfig()
	payload := buildAdmissionPolicyStaticScriptArchive(t, map[string][]byte{
		staticScriptEntrypointName: []byte(benignPolicyFixtureText()),
	})
	fixture = fixture.withPayload(t, payload)
	request := fixture.prepareRequest()
	request.Invocation.Annotations = map[string]string{
		runtimeProfileAnnotationKey: runtimeProfileControlPlaneNormalShell,
	}

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

	result, err := service.Prepare(testCallerContext(), request)
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
	payload := buildAdmissionPolicyStaticScriptArchive(t, map[string][]byte{
		staticScriptEntrypointName: []byte(benignPolicyFixtureText()),
	})
	fixture = fixture.withPayload(t, payload)
	request := fixture.prepareRequest()
	request.Invocation.Annotations = map[string]string{
		runtimeProfileAnnotationKey: runtimeProfileControlPlaneNormalShell,
	}

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

	_, err := service.Prepare(testCallerContext(), request)
	assertAdmissionError(t, err, http.StatusBadRequest, codeUnsupportedRuntimeProfile)
	assertDirectoryEmpty(t, stagingRoot)
	assertDirectoryEmpty(t, resultsRoot)
}
