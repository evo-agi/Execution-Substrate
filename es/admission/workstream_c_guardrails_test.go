package admission

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"testing"

	esconfig "execution-substrate/es/config"
	runtimeconfigv1 "execution-substrate/internal/contracts/runtimeconfig/v1"
)

const validWorkloadZoneVaultConfigBlob = `{"vault_config":{"address":"https://vault.internal:8200","auth_mount":"jwt","auth_role":"execution","jwt_audience":"vault"}}`

func TestWorkstreamCPrepareStaysBoundedAndAvoidsDescriptorGrammar(t *testing.T) {
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
			t.Fatalf("prepare reached unexpected ARS path %q", r.URL.Path)
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
		t.Fatalf("expected successful bounded prepare result, got %+v", result)
	}

	assertDirectoryEmpty(t, stagingRoot)
	assertDirectoryEmpty(t, resultsRoot)
	assertExactCallCount(t, arsCalls, "/v1/artifacts/"+fixture.discovery.Artifact.ArtifactDigest+"/discovery", 1)
	assertExactCallCount(t, arsCalls, "/v1/blobs/"+fixture.discovery.Evidence.Digest+":json", 1)
	assertExactCallCount(t, arsCalls, "/v1/blobs/"+testWorkloadZoneVaultConfigDigest+":json", 1)
	if len(arsCalls) != 3 {
		t.Fatalf("expected prepare to use only discovery, evidence, and runtime-config reads, got %v", arsCalls)
	}

	payload := mustMarshalWorkstreamCTestJSON(t, result)
	assertTextOmitsAll(t, payload,
		`"run_id"`,
		`"status"`,
		`"lifecycle_projection"`,
		`"authority_handoff"`,
		`"artifact_digest"`,
		`"descriptor"`,
		`"manifest"`,
	)
}

func TestWorkstreamCPrepareRejectsUnsupportedRuntimeProfileWithoutRunState(t *testing.T) {
	fixture := newPreparedArtifactFixture(t)
	service, stagingRoot, resultsRoot := newWorkstreamCTestService(t, fixture)
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
		default:
			t.Fatalf("prepare reached unexpected ARS path %q", r.URL.Path)
		}
	}))
	service.nomadClient = newTestNomadClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("prepare must not call nomad, got %s %q", r.Method, r.URL.Path)
	}))

	_, err := service.Prepare(context.Background(), request)
	assertAdmissionError(t, err, http.StatusBadRequest, codeUnsupportedRuntimeProfile)
	assertDirectoryEmpty(t, stagingRoot)
	assertDirectoryEmpty(t, resultsRoot)
	if len(arsCalls) != 3 {
		t.Fatalf("expected runtime-profile failure to remain admission-bounded, got ARS calls %v", arsCalls)
	}
}

func TestWorkstreamCSubmitRejectsSyncModeBeforeAdmission(t *testing.T) {
	fixture := newPreparedArtifactFixture(t)
	service, stagingRoot, resultsRoot := newWorkstreamCTestService(t, fixture)
	request := fixture.prepareRequest()
	request.Mode = ExecutionModeSync

	arsCalled := false
	service.arsClient = newArtifactRegistryTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		arsCalled = true
		t.Fatalf("sync submit must not read ARS before rejection, got %s %q", r.Method, r.URL.Path)
	}))
	service.nomadClient = newTestNomadClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("sync submit must not call nomad, got %s %q", r.Method, r.URL.Path)
	}))

	_, err := service.Submit(context.Background(), request)
	assertAdmissionError(t, err, http.StatusBadRequest, codeUnsupportedExecutionMode)
	if arsCalled {
		t.Fatal("expected sync submit to reject before admission reads")
	}
	assertDirectoryEmpty(t, stagingRoot)
	assertDirectoryEmpty(t, resultsRoot)
}

func TestWorkstreamCSubmitDoesNotBypassAdmissionBeforePayloadOrNomad(t *testing.T) {
	fixture := newPreparedArtifactFixture(t)
	service, stagingRoot, resultsRoot := newWorkstreamCTestService(t, fixture)
	request := fixture.prepareRequest()
	request.Mode = ExecutionModeAsync
	request.Invocation.DerivationSpecDigest = labeledDigest("ff")

	arsCalls := map[string]int{}
	service.arsClient = newArtifactRegistryTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		arsCalls[r.URL.Path]++
		switch r.URL.Path {
		case "/v1/artifacts/" + fixture.discovery.Artifact.ArtifactDigest + "/discovery":
			writeJSONResponse(t, w, http.StatusOK, fixture.discovery)
		case "/v1/blobs/" + fixture.discovery.Evidence.Digest + ":json":
			writeJSONResponse(t, w, http.StatusOK, fixture.evidence)
		default:
			t.Fatalf("submit reached unexpected ARS path before admission failed: %q", r.URL.Path)
		}
	}))
	service.nomadClient = newTestNomadClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("submit must not call nomad when admission fails, got %s %q", r.Method, r.URL.Path)
	}))

	_, err := service.Submit(context.Background(), request)
	assertAdmissionError(t, err, http.StatusBadRequest, codeInvalidRequest)
	assertDirectoryEmpty(t, stagingRoot)
	assertDirectoryEmpty(t, resultsRoot)
	assertExactCallCount(t, arsCalls, "/v1/artifacts/"+fixture.discovery.Artifact.ArtifactDigest+"/discovery", 1)
	assertExactCallCount(t, arsCalls, "/v1/blobs/"+fixture.discovery.Evidence.Digest+":json", 1)
	if len(arsCalls) != 2 {
		t.Fatalf("expected submit admission failure to stop before runtime-config or payload reads, got %v", arsCalls)
	}
}

func TestWorkstreamCSubmitReceiptRemainsBoundedAndHidesSchedulerIdentifiers(t *testing.T) {
	fixture := newPreparedArtifactFixture(t)
	service, _, _ := newWorkstreamCTestService(t, fixture)
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
			_, _ = w.Write([]byte("#!/bin/sh\necho bounded-submit\n"))
		default:
			t.Fatalf("submit reached unexpected ARS path %q", r.URL.Path)
		}
	}))

	nomadCalls := 0
	service.nomadClient = newTestNomadClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nomadCalls++
		if r.Method != http.MethodPost || r.URL.Path != "/v1/jobs" {
			t.Fatalf("unexpected nomad request %s %q", r.Method, r.URL.Path)
		}
		_, _ = w.Write([]byte(`{"EvalID":"eval-123"}`))
	}))

	result, err := service.Submit(context.Background(), request)
	if err != nil {
		t.Fatalf("submit: %+v", err)
	}
	if !result.Success || !result.Submitted || strings.TrimSpace(result.RunID) == "" {
		t.Fatalf("expected bounded submit receipt, got %+v", result)
	}
	if result.Status != executionLifecycleStatusSubmitted {
		t.Fatalf("expected submitted receipt status, got %+v", result)
	}
	if result.AuthorityHandoff == nil {
		t.Fatalf("expected authority_handoff in submit receipt")
	}
	if nomadCalls != 1 {
		t.Fatalf("expected exactly one nomad submission call, got %d", nomadCalls)
	}
	if len(arsCalls) != 4 {
		t.Fatalf("expected submit to use discovery, evidence, runtime-config, and payload reads only, got %v", arsCalls)
	}

	payload := mustMarshalWorkstreamCTestJSON(t, result)
	assertTextOmitsAll(t, payload,
		`"job_id"`,
		`"allocation_id"`,
		`"task_id"`,
		`"eval_id"`,
		`"lifecycle_projection"`,
		"exec-"+result.RunID,
	)
}

func TestWorkstreamCLifecycleProjectionAndCancelReceiptsHideNomadIdentifiers(t *testing.T) {
	service := Service{
		cfg: minimalLifecycleConfig(t),
		nomadClient: newTestNomadClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch {
			case r.Method == http.MethodGet && r.URL.Path == "/v1/job/exec-run-0123456789abcdef":
				_, _ = w.Write([]byte(`{"ID":"exec-run-0123456789abcdef","Status":"running","ModifyIndex":10,"Meta":{"execution_substrate.authority_handoff.schema":"v1","execution_substrate.authority_handoff.runtime_profile":"static-script/default","execution_substrate.authority_handoff.workload_zone_vault_config_digest":"` + testWorkloadZoneVaultConfigDigest + `"},"TaskGroups":[{"Tasks":[{"Name":"task","Env":{"EXEC_WORKLOAD_IDENTITY_ENDPOINT":"unix:///run/es-runtime-identity/run-0123456789abcdef/endpoint","VAULT_ADDR":"https://vault.internal:8200","EXEC_WORKLOAD_VAULT_AUTH_MODE":"vault_identity_jwt","EXEC_WORKLOAD_VAULT_AUTH_MOUNT":"jwt","EXEC_WORKLOAD_VAULT_AUTH_ROLE":"execution","EXEC_WORKLOAD_VAULT_JWT_AUDIENCE":"vault"}}]}]}`))
			case r.Method == http.MethodGet && r.URL.Path == "/v1/job/exec-run-0123456789abcdef/allocations":
				_, _ = w.Write([]byte(`[{"ID":"alloc-new","ModifyIndex":20}]`))
			case r.Method == http.MethodGet && r.URL.Path == "/v1/allocation/alloc-new":
				_, _ = w.Write([]byte(`{"ID":"alloc-new","ClientStatus":"complete","ModifyIndex":25,"TaskStates":{"task":{"State":"dead","Events":[{"Type":"Terminated","ExitCode":7}]}}}`))
			case r.Method == http.MethodDelete && r.URL.Path == "/v1/job/exec-run-0123456789abcdef":
				_, _ = w.Write([]byte(`{"EvalID":"eval-1"}`))
			default:
				t.Fatalf("unexpected nomad request %s %q", r.Method, r.URL.Path)
			}
		})),
	}

	statusResult, err := service.Status(context.Background(), "run-0123456789abcdef")
	if err != nil {
		t.Fatalf("status: %+v", err)
	}
	if statusResult.AuthorityHandoff == nil {
		t.Fatalf("expected bounded authority_handoff recovery on status")
	}
	assertOpaqueLifecycleProjectionRevision(t, statusResult.LifecycleProjection.Revision)
	if statusResult.OutcomeEvidence.LifecycleProjection == nil || statusResult.OutcomeEvidence.LifecycleProjection.Revision != statusResult.LifecycleProjection.Revision {
		t.Fatalf("expected status outcome evidence to repeat the opaque lifecycle projection, got %+v", statusResult.OutcomeEvidence)
	}
	statusPayload := mustMarshalWorkstreamCTestJSON(t, statusResult)
	assertTextOmitsAll(t, statusPayload,
		`"job_id"`,
		`"allocation_id"`,
		`"task_id"`,
		"exec-run-0123456789abcdef",
		"alloc-new",
	)

	cancelResult, err := service.Cancel(context.Background(), "run-0123456789abcdef")
	if err != nil {
		t.Fatalf("cancel: %+v", err)
	}
	if cancelResult.OutcomeEvidence.ProviderTerminalObserved == nil || *cancelResult.OutcomeEvidence.ProviderTerminalObserved {
		t.Fatalf("expected bounded cancel receipt without terminal truth claim, got %+v", cancelResult)
	}
	cancelPayload := mustMarshalWorkstreamCTestJSON(t, cancelResult)
	assertTextOmitsAll(t, cancelPayload,
		`"job_id"`,
		`"allocation_id"`,
		`"task_id"`,
		"exec-run-0123456789abcdef",
		"alloc-new",
	)
}

func newWorkstreamCTestService(t *testing.T, fixture preparedArtifactFixture) (*Service, string, string) {
	t.Helper()

	stagingRoot := t.TempDir()
	resultsRoot := t.TempDir()

	service := fixture.service()
	service.cfg = esconfig.Config{
		RuntimeConfig: esconfig.RuntimeConfigConfig{
			WorkloadZoneVaultConfigRef: runtimeconfigv1.WorkloadZoneVaultConfigRef{
				Digest: testWorkloadZoneVaultConfigDigest,
			},
		},
		WorkloadVaultAuth: esconfig.WorkloadVaultAuthConfig{
			DefaultMode: esconfig.WorkloadVaultAuthModeVaultIdentityJWT,
		},
		Nomad: esconfig.NomadConfig{
			BaseURL:        "http://127.0.0.1:4646",
			Datacenter:     "dc1",
			TimeoutSeconds: 1,
		},
		Execution: esconfig.ExecutionConfig{
			StagingRootDir:             stagingRoot,
			ResultsRootDir:             resultsRoot,
			BaseImage:                  "alpine:3.20",
			RuntimeSupportBinary:       "/bin/sh",
			SPIREWorkloadAPISocketPath: "/run/spire/sockets/agent.sock",
		},
	}
	service.workloadZoneVaultConfigRef = service.cfg.RuntimeConfig.WorkloadZoneVaultConfigRef
	service.trustModel = &fixture.trustModel

	return &service, stagingRoot, resultsRoot
}

func assertAdmissionError(t *testing.T, err *Error, status int, code string) {
	t.Helper()

	if err == nil {
		t.Fatalf("expected error status=%d code=%s", status, code)
	}
	if err.Status != status || err.Code != code {
		t.Fatalf("expected error status=%d code=%s, got %+v", status, code, err)
	}
}

func assertExactCallCount(t *testing.T, counts map[string]int, path string, want int) {
	t.Helper()

	if got := counts[path]; got != want {
		t.Fatalf("expected %s to be called %d time(s), got %d in %v", path, want, got, counts)
	}
}

func assertDirectoryEmpty(t *testing.T, dir string) {
	t.Helper()

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read directory %s: %v", dir, err)
	}
	if len(entries) != 0 {
		names := make([]string, 0, len(entries))
		for _, entry := range entries {
			names = append(names, entry.Name())
		}
		t.Fatalf("expected %s to remain empty, found %v", dir, names)
	}
}

func mustMarshalWorkstreamCTestJSON(t *testing.T, payload any) string {
	t.Helper()

	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	return string(data)
}

func assertTextOmitsAll(t *testing.T, text string, forbidden ...string) {
	t.Helper()

	for _, item := range forbidden {
		if strings.Contains(text, item) {
			t.Fatalf("expected text to omit %q, got %s", item, text)
		}
	}
}
