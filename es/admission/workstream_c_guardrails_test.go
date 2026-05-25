package admission

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"reflect"
	"strings"
	"testing"

	esconfig "execution-substrate/es/config"
	evidencev1 "execution-substrate/internal/contracts/evidence/v1"
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
	assertJSONFieldsExact(t, result, "success")

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
		`"request_id"`,
		`"decision_id"`,
		`"audit"`,
		`"allowed"`,
		`"policy_approval"`,
		`"provider_run_id"`,
		`"cp_workflow_id"`,
		`"scheduler_handoff"`,
		`"retained_result_bundle"`,
		`"lifecycle_store"`,
		`"runtime_auth_plan"`,
		`"artifact_digest"`,
		`"descriptor"`,
		`"manifest"`,
	)
}

func TestWorkstreamCAdmissionConsumesDiscoveryEvidencePackageIdentityAndRuntimeClaims(t *testing.T) {
	fixture := newPreparedArtifactFixture(t)
	service := fixture.service()
	request := fixture.prepareRequest()
	request.Invocation.Env = map[string]string{
		"C1_ALLOWED_ENV": "true",
	}

	evidence := signedWorkstreamAEvidence(t, fixture, func(record *evidencev1.ArtifactEvidence) {
		record.Claims.Admission.Execution.Runtime.EnvironmentVariables = []string{"C1_ALLOWED_ENV"}
		record.Claims.Admission.Execution.Runtime.RequiredCapabilities = []string{"c1-special-runtime"}
		record.Claims.Admission.Execution.Workload.TargetPlatform = "docker"
		record.Claims.Admission.Execution.Access.NetworkAccess = false
	})

	artifact, err := service.prepareArtifactFromDiscovery(request, fixture.trustModel, discoveredArtifactWithEvidence(t, fixture.discovery, evidence))
	if err != nil {
		t.Fatalf("expected discovery, signed evidence, package identity, and runtime claims to prepare, got %+v", err)
	}
	if artifact.payloadDigest != evidence.Claims.Package.Identity.PayloadDigest {
		t.Fatalf("expected payload digest from claims.package.identity, got %q", artifact.payloadDigest)
	}
	if artifact.manifest.ArtifactDigest != evidence.Claims.Package.Identity.ArtifactDigest ||
		artifact.manifest.ArtifactType != evidence.Claims.Package.Identity.ArtifactType ||
		artifact.manifest.IntentDigest != evidence.Claims.Package.Identity.IntentDigest {
		t.Fatalf("expected manifest projection from claims.package.identity, got %+v", artifact.manifest)
	}
	if !reflect.DeepEqual(artifact.manifest.RuntimeInterface.EnvironmentVariables, []string{"C1_ALLOWED_ENV"}) {
		t.Fatalf("expected runtime env allowlist from signed execution claims, got %+v", artifact.manifest.RuntimeInterface.EnvironmentVariables)
	}
	if !reflect.DeepEqual(artifact.manifest.RuntimeInterface.RequiredCapabilities, []string{"c1-special-runtime"}) {
		t.Fatalf("expected required capabilities from signed execution claims, got %+v", artifact.manifest.RuntimeInterface.RequiredCapabilities)
	}
	if artifact.targetPlatform != "docker" || artifact.networkAccess {
		t.Fatalf("expected narrow workload/access claims from signed evidence, got target_platform=%q network_access=%t", artifact.targetPlatform, artifact.networkAccess)
	}

	tampered := evidence
	tampered.Claims.Admission.Execution.Runtime.EnvironmentVariables = append(tampered.Claims.Admission.Execution.Runtime.EnvironmentVariables, "UNSIGNED_AFTER_SEAL")
	_, err = service.prepareArtifactFromDiscovery(request, fixture.trustModel, discoveredArtifactWithEvidence(t, fixture.discovery, tampered))
	if err == nil || err.Code != codeArtifactEvidenceInvalid || !strings.Contains(err.Message, "signature verification failed") {
		t.Fatalf("expected signed evidence envelope/seal verification to reject tampered runtime claims, got %+v", err)
	}
}

func TestWorkstreamCAdmissionKeepsPayloadDigestAndPackageIdentityMismatchDistinct(t *testing.T) {
	fixture := newPreparedArtifactFixture(t)
	service := fixture.service()
	request := fixture.prepareRequest()

	payloadDigestUsedAsArtifactID := request
	payloadDigestUsedAsArtifactID.Invocation.ArtifactDigest = fixture.evidence.Claims.Package.Identity.PayloadDigest
	_, err := service.prepareArtifactFromDiscovery(payloadDigestUsedAsArtifactID, fixture.trustModel, discoveredArtifact{
		discovery: fixture.discovery,
		evidence:  fixture.evidence,
	})
	if err == nil || err.Code != codeInvalidRequest || !strings.Contains(err.Message, "artifact digest mismatch between request and artifact discovery") {
		t.Fatalf("expected artifact/package identity request mismatch to remain invalid_request, got %+v", err)
	}

	evidencePackageIdentityMismatch := fixture.evidence
	evidencePackageIdentityMismatch.Claims.Package.Identity.ArtifactDigest = labeledDigest("ee")
	_, err = service.prepareArtifactFromDiscovery(request, fixture.trustModel, discoveredArtifact{
		discovery: fixture.discovery,
		evidence:  evidencePackageIdentityMismatch,
	})
	if err == nil || err.Code != codeInvalidRequest || !strings.Contains(err.Message, "artifact digest mismatch between request and artifact evidence") {
		t.Fatalf("expected artifact/package identity evidence mismatch to remain invalid_request, got %+v", err)
	}

	payloadReferenceMismatch := fixture.discovery
	payloadReferenceMismatch.Payload.Digest = fixture.evidence.Claims.Package.Identity.ArtifactDigest
	_, err = service.prepareArtifactFromDiscovery(request, fixture.trustModel, discoveredArtifact{
		discovery: payloadReferenceMismatch,
		evidence:  fixture.evidence,
	})
	if err == nil || err.Code != codeArtifactEvidenceInvalid || !strings.Contains(err.Message, "payload reference does not match artifact evidence") {
		t.Fatalf("expected payload digest reference mismatch to remain artifact_evidence_invalid, got %+v", err)
	}
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
	var submittedNomadJob string
	service.nomadClient = newTestNomadClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nomadCalls++
		if r.Method != http.MethodPost || r.URL.Path != "/v1/jobs" {
			t.Fatalf("unexpected nomad request %s %q", r.Method, r.URL.Path)
		}
		body, readErr := io.ReadAll(r.Body)
		if readErr == nil {
			submittedNomadJob = string(body)
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
	if !strings.Contains(submittedNomadJob, `"ID":"exec-`) || !strings.Contains(submittedNomadJob, `"Driver":"docker"`) {
		t.Fatalf("expected submit to hand one Docker job through ES/Nomad, got %s", submittedNomadJob)
	}
	assertTextOmitsAll(t, submittedNomadJob,
		`"review"`,
		`"checkpoint"`,
		`"finalization"`,
		`"intervention"`,
		`"approval"`,
		`"hold"`,
		`"resume"`,
		`"reject"`,
		`"temporal"`,
		`"Temporal"`,
		`"workflow"`,
		`"workflow_id"`,
		`"cp_workflow_id"`,
	)
	if len(arsCalls) != 4 {
		t.Fatalf("expected submit to use discovery, evidence, runtime-config, and payload reads only, got %v", arsCalls)
	}

	payload := mustMarshalWorkstreamCTestJSON(t, result)
	assertJSONFieldsExact(t, result, "success", "submitted", "run_id", "status", "authority_handoff")
	assertTextOmitsAll(t, payload,
		`"attempt"`,
		`"task_attempt"`,
		`"review"`,
		`"checkpoint"`,
		`"finalization"`,
		`"intervention"`,
		`"approval"`,
		`"hold"`,
		`"resume"`,
		`"reject"`,
		`"temporal"`,
		`"Temporal"`,
		`"workflow"`,
		`"workflow_id"`,
		`"cp_workflow_id"`,
		`"run_control"`,
		`"job_id"`,
		`"allocation_id"`,
		`"task_id"`,
		`"eval_id"`,
		`"nomad_job_id"`,
		`"nomad_allocation_id"`,
		`"scheduler_id"`,
		`"provider_run_id"`,
		`"lifecycle_store"`,
		`"lifecycle_store_key"`,
		`"write_guard"`,
		`"write_precondition"`,
		`"lifecycle_projection"`,
		`"request_id"`,
		`"decision_id"`,
		`"audit"`,
		`"allowed"`,
		`"policy_approval"`,
		`"runtime_auth_plan"`,
		"exec-"+result.RunID,
	)
}

func TestWorkstreamC2PublicSubmitAndLifecycleDTOsExcludeCPRunControlGrammar(t *testing.T) {
	fieldNames := collectJSONFieldNames(t,
		SubmitResult{},
		ExecutionStatusResult{},
		ExecutionCancelResult{},
		LifecycleProjection{},
		ExecutionOutcomeEvidence{},
		ExecutionAuthorityHandoff{},
		ExecutionAuthorityRuntimeProfile{},
		ExecutionAuthorityIdentityHandoff{},
		ExecutionAuthorityWorkloadVault{},
		ExecutionAuthorityRuntimeConfigRefs{},
		ExecutionAuthorityCodexCredential{},
		ExecutionAuthorityEvidence{},
	)

	for _, forbidden := range []string{
		"attempt",
		"task_attempt",
		"review",
		"checkpoint",
		"finalization",
		"intervention",
		"approval",
		"hold",
		"resume",
		"reject",
		"temporal",
		"workflow",
		"workflow_id",
		"cp_workflow_id",
		"run_control",
		"review_state",
		"checkpoint_state",
		"finalization_state",
		"intervention_state",
		"provider_run_id",
		"nomad_job_id",
		"job_id",
		"allocation_id",
		"scheduler_id",
		"lifecycle_store",
		"lifecycle_store_key",
		"write_guard",
		"write_precondition",
		"retained_result_id",
	} {
		if _, ok := fieldNames[forbidden]; ok {
			t.Fatalf("C2 submit/lifecycle public DTOs must not expose CP run-control or scheduler-authority field %q", forbidden)
		}
	}
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
		`"request_id"`,
		`"decision_id"`,
		`"audit"`,
		`"allowed"`,
		`"policy_approval"`,
		`"runtime_auth_plan"`,
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
		`"request_id"`,
		`"decision_id"`,
		`"audit"`,
		`"allowed"`,
		`"policy_approval"`,
		`"runtime_auth_plan"`,
		"exec-run-0123456789abcdef",
		"alloc-new",
	)
}

func TestWorkstreamC2LifecycleProjectionRevisionIsOpaqueNomadReadCoordinationOnly(t *testing.T) {
	service := Service{
		cfg: minimalLifecycleConfig(t),
		nomadClient: newTestNomadClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch {
			case r.Method == http.MethodGet && r.URL.Path == "/v1/job/exec-run-0123456789abcdef":
				_, _ = w.Write([]byte(`{"ID":"exec-run-0123456789abcdef","Status":"running","ModifyIndex":42}`))
			case r.Method == http.MethodGet && r.URL.Path == "/v1/job/exec-run-0123456789abcdef/allocations":
				_, _ = w.Write([]byte(`[{"ID":"alloc-c2-latest","ModifyIndex":314}]`))
			case r.Method == http.MethodGet && r.URL.Path == "/v1/allocation/alloc-c2-latest":
				_, _ = w.Write([]byte(`{"ID":"alloc-c2-latest","ClientStatus":"running","ModifyIndex":2718,"TaskStates":{"task":{"State":"running"}}}`))
			default:
				t.Fatalf("unexpected nomad request %s %q", r.Method, r.URL.Path)
			}
		})),
	}

	result, err := service.Status(context.Background(), "run-0123456789abcdef")
	if err != nil {
		t.Fatalf("status: %+v", err)
	}
	if result.LifecycleProjection.Source != lifecycleProjectionSourceNomad {
		t.Fatalf("expected lifecycle projection source=nomad, got %+v", result.LifecycleProjection)
	}
	assertOpaqueLifecycleProjectionRevision(t, result.LifecycleProjection.Revision)
	for _, forbiddenRevision := range []string{
		"42",
		"314",
		"2718",
	} {
		if result.LifecycleProjection.Revision == forbiddenRevision {
			t.Fatalf("lifecycle projection revision must not be raw Nomad observation value %q", forbiddenRevision)
		}
	}
	for _, forbiddenRevisionFragment := range []string{
		"exec-run-0123456789abcdef",
		"alloc-c2-latest",
		result.RunID,
		result.RunID + "/result.tar.gz",
	} {
		if result.LifecycleProjection.Revision == forbiddenRevisionFragment || strings.Contains(result.LifecycleProjection.Revision, forbiddenRevisionFragment) {
			t.Fatalf("lifecycle projection revision must not be scheduler, store, or retained-result identity %q; got %q", forbiddenRevisionFragment, result.LifecycleProjection.Revision)
		}
	}
	if result.OutcomeEvidence.LifecycleProjection == nil || *result.OutcomeEvidence.LifecycleProjection != result.LifecycleProjection {
		t.Fatalf("expected outcome evidence to repeat opaque projection token, got %+v", result.OutcomeEvidence)
	}

	payload := mustMarshalWorkstreamCTestJSON(t, result)
	assertTextOmitsAll(t, payload,
		`"nomad_job_id"`,
		`"job_id"`,
		`"allocation_id"`,
		`"task_id"`,
		`"scheduler_id"`,
		`"lifecycle_store"`,
		`"lifecycle_store_key"`,
		`"write_guard"`,
		`"write_precondition"`,
		`"workflow_revision"`,
		`"cp_workflow_revision"`,
		`"retained_result_id"`,
		`"retained_result_bundle"`,
		"exec-run-0123456789abcdef",
		"alloc-c2-latest",
	)
}

func TestWorkstreamCAuthorityHandoffAndOutcomeEvidenceRemainBoundedNonAuthority(t *testing.T) {
	handoff := buildExecutionAuthorityHandoff(
		executionRuntimeProfile{name: runtimeProfileDefaultStaticScript},
		runtimeIdentityHandoff{
			endpointEnvKey: runtimeIdentityEndpointEnvKey,
			endpointURI:    "unix:///run/es-runtime-identity/run-0123456789abcdef/endpoint",
		},
		esconfig.ResolvedWorkloadVaultAuthPlan{
			Mode:        esconfig.WorkloadVaultAuthModeVaultIdentityJWT,
			Address:     "https://vault.internal:8200",
			AuthMount:   "jwt",
			AuthRole:    "execution",
			JWTAudience: "vault",
		},
		testWorkloadZoneVaultConfigDigest,
		stagedWorkloadTrustMaterial{},
	)
	if handoff.Evidence.Source != executionAuthorityEvidenceSourceSubmittedRuntimeSpec ||
		handoff.Evidence.RuntimeProfile != executionAuthorityEvidenceRuntimeProfile ||
		handoff.Evidence.IdentityHandoff != executionAuthorityEvidenceIdentityHandoff ||
		handoff.Evidence.WorkloadVault != executionAuthorityEvidenceWorkloadVault {
		t.Fatalf("expected bounded handoff evidence labels, got %+v", handoff.Evidence)
	}

	projection := LifecycleProjection{Source: lifecycleProjectionSourceNomad, Revision: "opaque-c1-read-token"}
	payload := mustMarshalWorkstreamCTestJSON(t, struct {
		AuthorityHandoff ExecutionAuthorityHandoff  `json:"authority_handoff"`
		OutcomeEvidence  []ExecutionOutcomeEvidence `json:"outcome_evidence"`
	}{
		AuthorityHandoff: handoff,
		OutcomeEvidence: []ExecutionOutcomeEvidence{
			statusOutcomeEvidence(outcomeObservationNomadTaskStateProjection, projection, true),
			logsOutcomeEvidence(false),
			cancelOutcomeEvidence(),
			retainedResultOutcomeEvidence(),
		},
	})

	assertTextOmitsAll(t, payload,
		`"vault_token"`,
		`"codex_token"`,
		`"jwt_svid_token"`,
		`"lease"`,
		`"lease_id"`,
		`"lease_duration"`,
		`"token_expiry"`,
		`"credential_material"`,
		`"credential_value"`,
		`"approval"`,
		`"policy_approval"`,
		`"intervention"`,
		`"hold"`,
		`"resume"`,
		`"reject"`,
		`"temporal"`,
		`"Temporal"`,
		`"run_control"`,
		`"workflow"`,
		`"workflow_id"`,
		`"checkpoint"`,
		`"finalization"`,
		`"job_id"`,
		`"allocation_id"`,
		`"task_id"`,
		`"eval_id"`,
		`"provider_run_id"`,
		`"scheduler_id"`,
		`"private_key_pem"`,
		`"pem_body"`,
		`"raw_spire_socket"`,
	)
}

func TestWorkstreamC2ControlPlaneNormalShellCompatibilitySurfaceUnchanged(t *testing.T) {
	if runtimeProfileAnnotationKey != "execution_substrate.runtime_profile" {
		t.Fatalf("runtime profile annotation compatibility key changed to %q", runtimeProfileAnnotationKey)
	}
	if runtimeProfileControlPlaneNormalShell != "control-plane-normal-shell/v1" {
		t.Fatalf("control-plane normal-shell profile compatibility name changed to %q", runtimeProfileControlPlaneNormalShell)
	}

	profile, err := resolveExecutionRuntimeProfile(controlPlaneNormalShellProfileExecutionConfig(), PrepareRequest{
		Invocation: ArtifactInvocation{
			Annotations: map[string]string{
				runtimeProfileAnnotationKey: runtimeProfileControlPlaneNormalShell,
			},
		},
	}, preparedArtifact{
		manifest: Manifest{
			ArtifactType: "static-script",
		},
		networkAccess: true,
	})
	if err != nil {
		t.Fatalf("expected existing control-plane normal-shell profile to resolve, got %+v", err)
	}
	if profile.name != runtimeProfileControlPlaneNormalShell ||
		profile.image != "execution-substrate/control-plane-normal-shell:test" ||
		profile.env[codexCLIPathEnvKey] != "/usr/local/bin/codex" ||
		profile.env[codexCredentialSourceEnvKey] != codexCredentialSourceWorkloadVault {
		t.Fatalf("expected existing profile image and non-secret metadata compatibility, got %+v", profile)
	}
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

func assertJSONFieldsExact(t *testing.T, payload any, want ...string) {
	t.Helper()

	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		t.Fatalf("decode marshaled payload: %v", err)
	}
	if len(fields) != len(want) {
		t.Fatalf("expected JSON fields %v, got %s", want, string(data))
	}
	for _, field := range want {
		if _, ok := fields[field]; !ok {
			t.Fatalf("expected JSON field %q in %s", field, string(data))
		}
	}
}

func assertTextOmitsAll(t *testing.T, text string, forbidden ...string) {
	t.Helper()

	for _, item := range forbidden {
		if strings.Contains(text, item) {
			t.Fatalf("expected text to omit %q, got %s", item, text)
		}
	}
}
