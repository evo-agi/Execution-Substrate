package admission

import (
	"context"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"net/http"
	"os"
	"reflect"
	"strconv"
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
	policyPayload := buildAdmissionPolicyStaticScriptArchive(t, map[string][]byte{
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
			_, _ = w.Write(policyPayload)
		default:
			t.Fatal("ARS request path classification mismatch")
		}
	}))
	service.nomadClient = newTestNomadClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("prepare must not call nomad")
	}))

	result, err := service.Prepare(context.Background(), request)
	if err != nil {
		t.Fatalf("prepare: %+v", err)
	}
	if !result.Success {
		t.Fatal("expected successful bounded prepare result")
	}
	prepareResultFields := collectDirectJSONFieldNames(t, PrepareResult{})
	if len(prepareResultFields) != 1 {
		t.Fatalf("JSON field count mismatch: got %d want 1", len(prepareResultFields))
	}
	if _, ok := prepareResultFields["success"]; !ok {
		t.Fatal("expected bounded prepare-result JSON field")
	}

	assertDirectoryEmpty(t, stagingRoot)
	assertDirectoryEmpty(t, resultsRoot)
	if got := arsCalls["/v1/artifacts/"+fixture.discovery.Artifact.ArtifactDigest+"/discovery"]; got != 1 {
		t.Fatalf("ARS request count mismatch: got %d want 1", got)
	}
	if got := arsCalls["/v1/blobs/"+fixture.discovery.Evidence.Digest+":json"]; got != 1 {
		t.Fatalf("ARS request count mismatch: got %d want 1", got)
	}
	if got := arsCalls["/v1/blobs/"+testWorkloadZoneVaultConfigDigest+":json"]; got != 1 {
		t.Fatalf("ARS request count mismatch: got %d want 1", got)
	}
	if got := arsCalls["/v1/blobs/"+fixture.discovery.Payload.Digest+":bytes"]; got != 1 {
		t.Fatalf("ARS request count mismatch: got %d want 1", got)
	}
	if len(arsCalls) != 4 {
		t.Fatalf("ARS request count mismatch: got %d want 4", len(arsCalls))
	}

	payload := mustMarshalWorkstreamCTestJSON(t, result)
	assertTextOmitsAllFixed(t, payload, []string{
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
	})
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
		t.Fatal("expected payload digest from claims.package.identity")
	}
	if artifact.manifest.ArtifactDigest != evidence.Claims.Package.Identity.ArtifactDigest ||
		artifact.manifest.ArtifactType != evidence.Claims.Package.Identity.ArtifactType ||
		artifact.manifest.IntentDigest != evidence.Claims.Package.Identity.IntentDigest {
		t.Fatal("expected manifest projection from claims.package.identity")
	}
	runtimeEnv := artifact.manifest.RuntimeInterface.EnvironmentVariables
	if len(runtimeEnv) != 1 || runtimeEnv[0] != "C1_ALLOWED_ENV" {
		t.Fatal("expected runtime env allowlist from signed execution claims")
	}
	requiredCapabilities := artifact.manifest.RuntimeInterface.RequiredCapabilities
	if len(requiredCapabilities) != 1 || requiredCapabilities[0] != "c1-special-runtime" {
		t.Fatal("expected required capabilities from signed execution claims")
	}
	if artifact.targetPlatform != "docker" || artifact.networkAccess {
		t.Fatal("expected narrow workload/access claims from signed evidence")
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
	policyPayload := buildAdmissionPolicyStaticScriptArchive(t, map[string][]byte{
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
			_, _ = w.Write(policyPayload)
		default:
			t.Fatal("ARS request path classification mismatch")
		}
	}))
	service.nomadClient = newTestNomadClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("prepare must not call nomad")
	}))

	_, err := service.Prepare(context.Background(), request)
	assertAdmissionError(t, err, http.StatusBadRequest, codeUnsupportedRuntimeProfile)
	assertDirectoryEmpty(t, stagingRoot)
	assertDirectoryEmpty(t, resultsRoot)
	if len(arsCalls) != 4 {
		t.Fatalf("ARS request count mismatch: got %d want 4", len(arsCalls))
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
		t.Fatal("sync submit must not read ARS before rejection")
	}))
	service.nomadClient = newTestNomadClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("sync submit must not call nomad")
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
			t.Fatal("ARS request path classification mismatch")
		}
	}))
	service.nomadClient = newTestNomadClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("submit must not call nomad when admission fails")
	}))

	_, err := service.Submit(context.Background(), request)
	assertAdmissionError(t, err, http.StatusBadRequest, codeInvalidRequest)
	assertDirectoryEmpty(t, stagingRoot)
	assertDirectoryEmpty(t, resultsRoot)
	if got := arsCalls["/v1/artifacts/"+fixture.discovery.Artifact.ArtifactDigest+"/discovery"]; got != 1 {
		t.Fatalf("ARS request count mismatch: got %d want 1", got)
	}
	if got := arsCalls["/v1/blobs/"+fixture.discovery.Evidence.Digest+":json"]; got != 1 {
		t.Fatalf("ARS request count mismatch: got %d want 1", got)
	}
	if len(arsCalls) != 2 {
		t.Fatalf("ARS request count mismatch: got %d want 2", len(arsCalls))
	}
}

func TestWorkstreamCSubmitReceiptRemainsBoundedAndHidesSchedulerIdentifiers(t *testing.T) {
	fixture := newPreparedArtifactFixture(t)
	service, _, _ := newWorkstreamCTestService(t, fixture)
	request := fixture.prepareRequest()
	request.Mode = ExecutionModeAsync
	policyPayload := buildAdmissionPolicyStaticScriptArchive(t, map[string][]byte{
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
			_, _ = w.Write(policyPayload)
		default:
			t.Fatal("ARS request path classification mismatch")
		}
	}))

	nomadCalls := 0
	var submittedNomadJob string
	service.nomadClient = newTestNomadClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nomadCalls++
		if r.Method != http.MethodPost || r.URL.Path != "/v1/jobs" {
			t.Fatal("unexpected nomad request")
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
		t.Fatal("bounded submit receipt mismatch")
	}
	if result.Status != executionLifecycleStatusSubmitted {
		t.Fatal("bounded submit receipt status mismatch")
	}
	if result.AuthorityHandoff == nil {
		t.Fatalf("expected authority_handoff in submit receipt")
	}
	if nomadCalls != 1 {
		t.Fatalf("expected exactly one nomad submission call, got %d", nomadCalls)
	}
	if !strings.Contains(submittedNomadJob, `"ID":"exec-`) || !strings.Contains(submittedNomadJob, `"Driver":"docker"`) {
		t.Fatal("expected submit to hand one Docker job through ES/Nomad")
	}
	assertTextOmitsAllFixed(t, submittedNomadJob, []string{
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
	})
	if len(arsCalls) != 4 {
		t.Fatalf("ARS request count mismatch: got %d want 4", len(arsCalls))
	}

	payload := mustMarshalWorkstreamCTestJSON(t, result)
	submitResultFields := collectDirectJSONFieldNames(t, SubmitResult{})
	if len(submitResultFields) != 5 {
		t.Fatalf("JSON field count mismatch: got %d want 5", len(submitResultFields))
	}
	for _, field := range []string{"success", "submitted", "run_id", "status", "authority_handoff"} {
		if _, ok := submitResultFields[field]; !ok {
			t.Fatal("expected bounded submit-result JSON field")
		}
	}
	assertTextOmitsAllFixed(t, payload, []string{
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
	})
	if strings.Contains(payload, "exec-"+result.RunID) {
		t.Fatal("bounded submit receipt scheduler identity mismatch")
	}
}

func TestWorkstreamCSubmitResolvedPlanPreservesLegacyJobAndCallSemantics(t *testing.T) {
	fixture := newPreparedArtifactFixture(t)
	service, _, _ := newWorkstreamCTestService(t, fixture)
	request := fixture.prepareRequest()
	request.Mode = ExecutionModeAsync
	request.TimeoutSeconds = 31
	request.Resources = &ExecutionResources{CPU: 42, MemoryMB: 1536}
	request.Invocation.Argv = []string{"--flag", "value"}
	request.Invocation.Env = map[string]string{"APP_MODE": "submit-plan"}
	policyPayload := buildAdmissionPolicyStaticScriptArchive(t, map[string][]byte{
		staticScriptEntrypointName: []byte(benignPolicyFixtureText()),
	})

	var arsOrder []string
	service.arsClient = newArtifactRegistryTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		arsOrder = append(arsOrder, r.URL.Path)
		switch r.URL.Path {
		case "/v1/artifacts/" + fixture.discovery.Artifact.ArtifactDigest + "/discovery":
			writeJSONResponse(t, w, http.StatusOK, fixture.discovery)
		case "/v1/blobs/" + fixture.discovery.Evidence.Digest + ":json":
			writeJSONResponse(t, w, http.StatusOK, fixture.evidence)
		case "/v1/blobs/" + testWorkloadZoneVaultConfigDigest + ":json":
			_, _ = w.Write([]byte(validWorkloadZoneVaultConfigBlob))
		case "/v1/blobs/" + fixture.discovery.Payload.Digest + ":bytes":
			_, _ = w.Write(policyPayload)
		default:
			t.Fatal("ARS request path classification mismatch")
		}
	}))

	nomadCalls := 0
	var submitted map[string]any
	service.nomadClient = newTestNomadClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nomadCalls++
		if r.Method != http.MethodPost || r.URL.Path != "/v1/jobs" {
			t.Fatal("unexpected nomad request")
		}
		if err := json.NewDecoder(r.Body).Decode(&submitted); err != nil {
			t.Fatalf("decode submitted nomad job: %v", err)
		}
		_, _ = w.Write([]byte(`{"EvalID":"eval-123"}`))
	}))

	result, err := service.Submit(context.Background(), request)
	if err != nil {
		t.Fatalf("submit: %+v", err)
	}
	if !result.Success || !result.Submitted || result.Status != executionLifecycleStatusSubmitted || strings.TrimSpace(result.RunID) == "" {
		t.Fatal("bounded submitted result mismatch")
	}
	if result.AuthorityHandoff == nil ||
		result.AuthorityHandoff.RuntimeProfile.Name != runtimeProfileDefaultStaticScript ||
		result.AuthorityHandoff.WorkloadVault.Address != "https://vault.internal:8200" ||
		result.AuthorityHandoff.RuntimeConfigRefs.WorkloadZoneVaultConfig.Digest != testWorkloadZoneVaultConfigDigest {
		t.Fatal("legacy authority_handoff semantics mismatch")
	}
	if nomadCalls != 1 {
		t.Fatalf("expected one Nomad submission, got %d", nomadCalls)
	}
	expectedARSOrder := []string{
		"/v1/artifacts/" + fixture.discovery.Artifact.ArtifactDigest + "/discovery",
		"/v1/blobs/" + fixture.discovery.Evidence.Digest + ":json",
		"/v1/blobs/" + testWorkloadZoneVaultConfigDigest + ":json",
		"/v1/blobs/" + fixture.discovery.Payload.Digest + ":bytes",
	}
	if len(arsOrder) != len(expectedARSOrder) {
		t.Fatalf("ARS request count mismatch: got %d want %d", len(arsOrder), len(expectedARSOrder))
	}
	for index := range expectedARSOrder {
		if arsOrder[index] != expectedARSOrder[index] {
			t.Fatalf("ARS request order mismatch at index %d", index)
		}
	}

	job := submitted["Job"].(map[string]any)
	if job["ID"] != "exec-"+result.RunID || job["Name"] != "exec-"+result.RunID {
		t.Fatal("existing run-to-Nomad job identity mapping mismatch")
	}
	meta := job["Meta"].(map[string]any)
	if meta["run_id"] != result.RunID ||
		meta[executionAuthorityMetadataRuntimeProfileKey] != runtimeProfileDefaultStaticScript ||
		meta[executionAuthorityMetadataWorkloadZoneVaultConfigKey] != testWorkloadZoneVaultConfigDigest {
		t.Fatal("existing job metadata mismatch")
	}
	taskGroups := job["TaskGroups"].([]any)
	group := taskGroups[0].(map[string]any)
	tasks := group["Tasks"].([]any)
	task := tasks[0].(map[string]any)
	config := task["Config"].(map[string]any)
	if config["image"] != "alpine:3.20" || config["command"] != executionRuntimeSupportPath || config["network_mode"] != "bridge" {
		t.Fatal("selected image/command/network semantics mismatch")
	}
	expectedArgs := []any{
		"supervisor",
		"--payload-archive", "/execution/staged/artifact.tar.gz",
		"--work-dir", "/execution/run/work",
		"--result-dir", "/execution/run/result",
		"--entrypoint", "/execution/run/work/entrypoint",
		"--timeout-seconds", "31",
		"--",
		"--flag", "value",
	}
	gotArgs, ok := config["args"].([]any)
	if !ok || len(gotArgs) != len(expectedArgs) {
		t.Fatalf("existing supervisor args count mismatch: got %d want %d", len(gotArgs), len(expectedArgs))
	}
	for index := range expectedArgs {
		if gotArgs[index] != expectedArgs[index] {
			t.Fatalf("existing supervisor args mismatch at index %d", index)
		}
	}
	env := task["Env"].(map[string]any)
	if env["APP_MODE"] != "submit-plan" ||
		env["EXEC_RUN_ID"] != result.RunID ||
		env["EXEC_ARTIFACT_DIGEST"] != fixture.discovery.Artifact.ArtifactDigest ||
		env["EXEC_WORK_DIR"] != executionRuntimeWorkDir ||
		env["VAULT_ADDR"] != "https://vault.internal:8200" ||
		env[runtimeIdentityEndpointEnvKey] == "" {
		t.Fatal("existing runtime environment semantics mismatch")
	}
	resources := task["Resources"].(map[string]any)
	if resources["CPU"] != float64(42) || resources["MemoryMB"] != float64(1536) {
		t.Fatal("explicit resources from resolved plan mismatch")
	}
	taskMeta := task["Meta"].(map[string]any)
	if taskMeta["artifact_digest"] != fixture.discovery.Artifact.ArtifactDigest ||
		taskMeta["derivation_spec_digest"] != fixture.evidence.Claims.Admission.Authorization.Derivation.DerivationSpecDigest ||
		taskMeta["output_id"] != fixture.evidence.Claims.Admission.Authorization.Derivation.OutputID {
		t.Fatal("existing task metadata semantics mismatch")
	}
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

func TestWorkstreamC3PublicResultAuthorityAndOutcomeDTOsExcludeRunControlAndLiveAuthorityFields(t *testing.T) {
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
		ExecutionAuthorityRuntimeConfigRef{},
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
		"retained_result_ref",
		"retained_result_reference",
		"retained_result_id",
		"retained_result_manifest",
		"retained_result_archive",
		"retained_result_path",
		"materialized_workspace",
		"workspace_archive",
		"operator_authorization",
		"scheduler_truth",
		"scheduler_id",
		"nomad_job_id",
		"job_id",
		"allocation_id",
		"task_id",
		"token",
		"lease",
		"credential",
		"secret",
		"api_key",
		"vault_token",
		"codex_credential",
		"credential_material",
		"credential_value",
		"secret_material",
		"secret_value",
	} {
		if _, ok := fieldNames[forbidden]; ok {
			t.Fatalf("C3 public result/authority/outcome DTOs must not expose run-control or live-authority field %q", forbidden)
		}
	}

	for _, compatibilityField := range []string{
		"codex_credential_location",
		"credential_source",
		"vault_secret_path",
		"vault_secret_field",
	} {
		if _, ok := fieldNames[compatibilityField]; !ok {
			t.Fatalf("expected current control-plane normal-shell credential-location compatibility field %q to remain present", compatibilityField)
		}
	}
}

func TestWorkstreamC4RuntimeIdentityVaultPublicDTOsExcludeCredentialLeaseAndRawSPIREFields(t *testing.T) {
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
		ExecutionAuthorityRuntimeConfigRef{},
		ExecutionAuthorityCodexCredential{},
		ExecutionAuthorityEvidence{},
		ProducerContractDeclaration{},
		GovernedExecutionProducerContractDeclaration{},
		ProducerRuntimeProfileDeclaration{},
		ProducerOutcomeEvidenceDeclaration{},
		ProducerOutcomeEvidenceSurfaceDeclaration{},
	)

	for _, forbidden := range workstreamC4ForbiddenCredentialFieldNames() {
		if _, ok := fieldNames[forbidden]; ok {
			t.Fatalf("C4 public DTOs must not expose runtime credential, Vault lease, or raw SPIRE field %q", forbidden)
		}
	}

	for _, compatibilityField := range []string{
		"endpoint_env",
		"endpoint_uri",
		"jwt_svid_target",
		"workload_vault",
		"runtime_config_refs",
		"codex_credential_location",
		"vault_secret_path",
		"vault_secret_field",
	} {
		if _, ok := fieldNames[compatibilityField]; !ok {
			t.Fatalf("expected non-secret C4 compatibility metadata field %q to remain present", compatibilityField)
		}
	}
}

func TestWorkstreamC4AuthorityHandoffCarriesOnlyNonSecretRuntimeIdentityVaultMetadata(t *testing.T) {
	handoff := buildExecutionAuthorityHandoff(
		executionRuntimeProfile{
			name: runtimeProfileControlPlaneNormalShell,
			env: map[string]string{
				codexCLIPathEnvKey:                    "/usr/local/bin/codex",
				codexCredentialSourceEnvKey:           codexCredentialSourceWorkloadVault,
				codexCredentialVaultSecretPathEnvKey:  "proof-secrets/data/codex-runtime-profile",
				codexCredentialVaultSecretFieldEnvKey: "runtime_profile_key_label",
			},
		},
		runtimeIdentityHandoff{
			endpointEnvKey: runtimeIdentityEndpointEnvKey,
			endpointURI:    "unix:///run/es-runtime-identity/run-0123456789abcdef/endpoint",
		},
		esconfig.ResolvedWorkloadVaultAuthPlan{
			Mode:        esconfig.WorkloadVaultAuthModeVaultIdentityJWT,
			Address:     "https://vault.internal:8200",
			AuthMount:   "jwt",
			AuthRole:    "service_execution",
			JWTAudience: "vault",
		},
		testWorkloadZoneVaultConfigDigest,
		stagedWorkloadTrustMaterial{
			vaultCACert:       true,
			workloadTLSBundle: true,
		},
	)

	if handoff.IdentityHandoff.EndpointEnv != runtimeIdentityEndpointEnvKey {
		t.Fatal("workload-visible identity endpoint metadata mismatch")
	}
	if strings.Contains(handoff.IdentityHandoff.EndpointURI, "spire") || strings.Contains(handoff.IdentityHandoff.EndpointURI, "/internal/") {
		t.Fatal("authority_handoff endpoint URI exposed raw SPIRE internals")
	}
	if handoff.WorkloadVault.AuthMode != string(esconfig.WorkloadVaultAuthModeVaultIdentityJWT) ||
		handoff.WorkloadVault.Address != "https://vault.internal:8200" ||
		handoff.WorkloadVault.AuthMount != "jwt" ||
		handoff.WorkloadVault.AuthRole != "service_execution" ||
		handoff.WorkloadVault.JWTAudience != "vault" ||
		handoff.RuntimeConfigRefs.WorkloadZoneVaultConfig.Digest != testWorkloadZoneVaultConfigDigest {
		t.Fatal("workload-zone Vault handoff metadata mismatch")
	}

	payload := mustMarshalWorkstreamCTestJSON(t, handoff)
	assertTextOmitsAllFixed(t, payload, workstreamC4ForbiddenCredentialJSONKeys())
	assertTextOmitsAllFixed(t, payload, []string{
		"/run/spire/sockets/agent.sock",
		"/run/spire/server/private/api.sock",
		"/run/es-runtime-identity/run-0123456789abcdef/internal/spire-agent.sock",
		`"raw_spire_socket_path":`,
	})
}

func TestWorkstreamC4AuthorityHandoffRecoveryIgnoresCredentialLikeSubmittedEnv(t *testing.T) {
	env := map[string]string{
		runtimeIdentityEndpointEnvKey:      "unix:///run/es-runtime-identity/run-0123456789abcdef/endpoint",
		"VAULT_ADDR":                       "https://vault.internal:8200",
		"EXEC_WORKLOAD_VAULT_AUTH_MODE":    string(esconfig.WorkloadVaultAuthModeVaultIdentityJWT),
		"EXEC_WORKLOAD_VAULT_AUTH_MOUNT":   "jwt",
		"EXEC_WORKLOAD_VAULT_AUTH_ROLE":    "service_execution",
		"EXEC_WORKLOAD_VAULT_JWT_AUDIENCE": "vault",
		"VAULT_TOKEN":                      "blocked-test-value",
		"CLIENT_TOKEN":                     "blocked-test-value",
		"ROOT_TOKEN":                       "blocked-test-value",
		"UNSEAL_KEY":                       "blocked-test-value",
		"JWT_SVID":                         "blocked-test-value",
		"X509_SVID":                        "blocked-test-value",
		"PRIVATE_KEY":                      "blocked-test-value",
		"API_KEY":                          "blocked-test-value",
		"PROOF_SECRET":                     "blocked-test-value",
		"SECRET_PAYLOAD":                   "blocked-test-value",
		"LEASE_ID":                         "blocked-test-value",
		"LEASE_DURATION":                   "blocked-test-value",
		"SPIRE_WORKLOAD_API_SOCKET":        "/run/spire/sockets/agent.sock",
	}

	handoff, ok := executionAuthorityHandoffFromSubmittedRuntimeSpec(
		runtimeProfileDefaultStaticScript,
		testWorkloadZoneVaultConfigDigest,
		env,
	)
	if !ok {
		t.Fatal("expected authority handoff recovery from submitted non-secret runtime metadata")
	}
	payload := mustMarshalWorkstreamCTestJSON(t, handoff)
	assertTextOmitsAllFixed(t, payload, workstreamC4ForbiddenCredentialJSONKeys())
	assertTextOmitsAllFixed(t, payload, []string{
		"blocked-test-value",
		"/run/spire/sockets/agent.sock",
		`"spire_workload_api_socket":`,
	})
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
				t.Fatal("unexpected nomad request")
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
	if statusResult.LifecycleProjection.Revision == "" {
		t.Fatal("lifecycle projection revision opacity invariant failed")
	}
	if !opaqueLifecycleProjectionRevisionPattern.MatchString(statusResult.LifecycleProjection.Revision) {
		t.Fatal("lifecycle projection revision opacity invariant failed")
	}
	for index, forbiddenRevisionFragment := range []string{
		"nomad-index",
		"exec-run",
		"alloc-",
		"task",
		":",
		"/",
	} {
		if strings.Contains(statusResult.LifecycleProjection.Revision, forbiddenRevisionFragment) {
			t.Fatalf("lifecycle projection revision opacity invariant failed at index %d", index)
		}
	}
	if statusResult.OutcomeEvidence.LifecycleProjection == nil || statusResult.OutcomeEvidence.LifecycleProjection.Revision != statusResult.LifecycleProjection.Revision {
		t.Fatal("expected status outcome evidence to repeat the opaque lifecycle projection")
	}
	statusPayload := mustMarshalWorkstreamCTestJSON(t, statusResult)
	assertTextOmitsAllFixed(t, statusPayload, []string{
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
	})

	cancelResult, err := service.Cancel(context.Background(), "run-0123456789abcdef")
	if err != nil {
		t.Fatalf("cancel: %+v", err)
	}
	if cancelResult.OutcomeEvidence.ProviderTerminalObserved == nil || *cancelResult.OutcomeEvidence.ProviderTerminalObserved {
		t.Fatal("expected bounded cancel receipt without terminal truth claim")
	}
	cancelPayload := mustMarshalWorkstreamCTestJSON(t, cancelResult)
	assertTextOmitsAllFixed(t, cancelPayload, []string{
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
	})
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
				t.Fatal("unexpected nomad request")
			}
		})),
	}

	result, err := service.Status(context.Background(), "run-0123456789abcdef")
	if err != nil {
		t.Fatalf("status: %+v", err)
	}
	if result.LifecycleProjection.Source != lifecycleProjectionSourceNomad {
		t.Fatal("expected lifecycle projection source=nomad")
	}
	if result.LifecycleProjection.Revision == "" {
		t.Fatal("lifecycle projection revision opacity invariant failed")
	}
	if !opaqueLifecycleProjectionRevisionPattern.MatchString(result.LifecycleProjection.Revision) {
		t.Fatal("lifecycle projection revision opacity invariant failed")
	}
	for index, forbiddenRevisionFragment := range []string{
		"nomad-index",
		"exec-run",
		"alloc-",
		"task",
		":",
		"/",
	} {
		if strings.Contains(result.LifecycleProjection.Revision, forbiddenRevisionFragment) {
			t.Fatalf("lifecycle projection revision opacity invariant failed at index %d", index)
		}
	}
	for index, forbiddenRevision := range []string{
		"42",
		"314",
		"2718",
	} {
		if result.LifecycleProjection.Revision == forbiddenRevision {
			t.Fatalf("lifecycle projection raw observation equality invariant failed at index %d", index)
		}
	}
	for index, forbiddenRevisionFragment := range []string{
		"exec-run-0123456789abcdef",
		"alloc-c2-latest",
		result.RunID,
		result.RunID + "/result.tar.gz",
	} {
		if result.LifecycleProjection.Revision == forbiddenRevisionFragment || strings.Contains(result.LifecycleProjection.Revision, forbiddenRevisionFragment) {
			t.Fatalf("lifecycle projection revision forbidden fragment at index %d", index)
		}
	}
	if result.OutcomeEvidence.LifecycleProjection == nil || *result.OutcomeEvidence.LifecycleProjection != result.LifecycleProjection {
		t.Fatal("expected outcome evidence to repeat opaque projection token")
	}

	payload := mustMarshalWorkstreamCTestJSON(t, result)
	assertTextOmitsAllFixed(t, payload, []string{
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
	})
}

func TestWorkstreamCLifecycleRevisionOpacityDiagnosticsRemainBounded(t *testing.T) {
	source := mustReadAdmissionRepoSource(t, admissionRepoRoot(t), "es/admission/workstream_c_guardrails_test.go")
	legacyHelperCall := "assertOpaqueLifecycleProjection" + "Revision("
	unsafeHexDiagnostic := "expected opaque hex lifecycle projection revision, got " + "%q"
	unsafeOmitDiagnostic := "expected lifecycle projection revision to omit " + "%q, got %q"
	assertTextOmitsAllFixed(t, source, []string{
		legacyHelperCall,
		unsafeHexDiagnostic,
		unsafeOmitDiagnostic,
	})

	findings := lifecycleRevisionOpacityInlineBlockFindings(source, lifecycleRevisionOpacityTargetTests())
	if len(findings) != 0 {
		t.Fatalf("lifecycle revision opacity source invariant mismatch: %s", strings.Join(findings, ", "))
	}
}

func TestWorkstreamCLifecycleRevisionOpacitySourceGuardFixtures(t *testing.T) {
	const target = "TestLifecycleRevisionFixture"
	targets := []string{target}
	valid := `
package admission

import (
	"strings"
	"testing"
)

func TestLifecycleRevisionFixture(t *testing.T) {
	result := struct {
		LifecycleProjection struct{ Revision string }
	}{}
	if result.LifecycleProjection.Revision == "" {
		t.Fatal("lifecycle projection revision opacity invariant failed")
	}
	if !opaqueLifecycleProjectionRevisionPattern.MatchString(result.LifecycleProjection.Revision) {
		t.Fatal("lifecycle projection revision opacity invariant failed")
	}
	for index, forbiddenRevisionFragment := range []string{
		"nomad-index",
		"exec-run",
		"alloc-",
		"task",
		":",
		"/",
	} {
		if strings.Contains(result.LifecycleProjection.Revision, forbiddenRevisionFragment) {
			t.Fatalf("lifecycle projection revision opacity invariant failed at index %d", index)
		}
	}
}
`
	if findings := lifecycleRevisionOpacityInlineBlockFindings(valid, targets); len(findings) != 0 {
		t.Fatalf("valid lifecycle opacity fixture rejected: %s", strings.Join(findings, ", "))
	}

	duplicateTargetSource := strings.TrimSuffix(valid, "\n") + `

func TestLifecycleRevisionFixture(t *testing.T) {
	result := struct {
		LifecycleProjection struct{ Revision string }
	}{}
	if result.LifecycleProjection.Revision == "" {
		t.Fatal("lifecycle projection revision opacity invariant failed")
	}
	if !opaqueLifecycleProjectionRevisionPattern.MatchString(result.LifecycleProjection.Revision) {
		t.Fatal("lifecycle projection revision opacity invariant failed")
	}
	for index, forbiddenRevisionFragment := range []string{"nomad-index", "exec-run", "alloc-", "task", ":", "/"} {
		if strings.Contains(result.LifecycleProjection.Revision, forbiddenRevisionFragment) {
			t.Fatalf("lifecycle projection revision opacity invariant failed at index %d", index)
		}
	}
}
`
	if findings := lifecycleRevisionOpacityInlineBlockFindings(duplicateTargetSource, targets); !containsWorkstreamCFinding(findings, target+":duplicate-target:2") {
		t.Fatalf("duplicate target lifecycle opacity fixture mismatch: %s", strings.Join(findings, ", "))
	}

	for _, tc := range []struct {
		name   string
		source string
	}{
		{
			name: "missing length and hex check",
			source: `
package admission

import (
	"strings"
	"testing"
)

func TestLifecycleRevisionFixture(t *testing.T) {
	result := struct {
		LifecycleProjection struct{ Revision string }
	}{}
	if result.LifecycleProjection.Revision == "" {
		t.Fatal("lifecycle projection revision opacity invariant failed")
	}
	for index, forbiddenRevisionFragment := range []string{"nomad-index", "exec-run", "alloc-", "task", ":", "/"} {
		if strings.Contains(result.LifecycleProjection.Revision, forbiddenRevisionFragment) {
			t.Fatalf("lifecycle projection revision opacity invariant failed at index %d", index)
		}
	}
}
`,
		},
		{
			name: "missing forbidden fragment",
			source: `
package admission

import (
	"strings"
	"testing"
)

func TestLifecycleRevisionFixture(t *testing.T) {
	result := struct {
		LifecycleProjection struct{ Revision string }
	}{}
	if result.LifecycleProjection.Revision == "" {
		t.Fatal("lifecycle projection revision opacity invariant failed")
	}
	if !opaqueLifecycleProjectionRevisionPattern.MatchString(result.LifecycleProjection.Revision) {
		t.Fatal("lifecycle projection revision opacity invariant failed")
	}
	for index, forbiddenRevisionFragment := range []string{"nomad-index", "exec-run", "alloc-", "task", ":"} {
		if strings.Contains(result.LifecycleProjection.Revision, forbiddenRevisionFragment) {
			t.Fatalf("lifecycle projection revision opacity invariant failed at index %d", index)
		}
	}
}
`,
		},
		{
			name: "prints revision",
			source: `
package admission

import (
	"strings"
	"testing"
)

func TestLifecycleRevisionFixture(t *testing.T) {
	result := struct {
		LifecycleProjection struct{ Revision string }
	}{}
	if result.LifecycleProjection.Revision == "" {
		t.Fatalf("revision mismatch: %s", result.LifecycleProjection.Revision)
	}
	if !opaqueLifecycleProjectionRevisionPattern.MatchString(result.LifecycleProjection.Revision) {
		t.Fatal("lifecycle projection revision opacity invariant failed")
	}
	for index, forbiddenRevisionFragment := range []string{"nomad-index", "exec-run", "alloc-", "task", ":", "/"} {
		if strings.Contains(result.LifecycleProjection.Revision, forbiddenRevisionFragment) {
			t.Fatalf("lifecycle projection revision opacity invariant failed at index %d", index)
		}
	}
}
`,
		},
		{
			name: "prints lifecycle result",
			source: `
package admission

import (
	"strings"
	"testing"
)

func TestLifecycleRevisionFixture(t *testing.T) {
	result := struct {
		LifecycleProjection struct{ Revision string }
	}{}
	if result.LifecycleProjection.Revision == "" {
		tt := t
		tt.Log(result)
	}
	if !opaqueLifecycleProjectionRevisionPattern.MatchString(result.LifecycleProjection.Revision) {
		t.Fatal("lifecycle projection revision opacity invariant failed")
	}
	for index, forbiddenRevisionFragment := range []string{"nomad-index", "exec-run", "alloc-", "task", ":", "/"} {
		if strings.Contains(result.LifecycleProjection.Revision, forbiddenRevisionFragment) {
			t.Fatalf("lifecycle projection revision opacity invariant failed at index %d", index)
		}
	}
}
`,
		},
		{
			name: "target missing",
			source: `
package admission
`,
		},
	} {
		if findings := lifecycleRevisionOpacityInlineBlockFindings(tc.source, targets); len(findings) == 0 {
			t.Fatalf("%s lifecycle opacity fixture was not rejected", tc.name)
		}
	}
}

func TestWorkstreamCLifecycleRevisionOpacitySourceGuardIgnoresMethodOnlyTarget(t *testing.T) {
	targets := lifecycleRevisionOpacityTargetTests()
	methodOnlyTarget := targets[0]

	declarations := []string{
		"type lifecycleRevisionValueFixtureReceiver struct{}\n",
		lifecycleRevisionOpacityValidMethodFixtureSource("lifecycleRevisionValueFixtureReceiver", methodOnlyTarget),
	}
	for _, target := range targets[1:] {
		declarations = append(declarations, lifecycleRevisionOpacityValidFunctionFixtureSource(target))
	}

	findings := lifecycleRevisionOpacityInlineBlockFindings(lifecycleRevisionOpacityFixtureSource(declarations), targets)
	if len(findings) != 1 || !containsWorkstreamCFinding(findings, methodOnlyTarget+":missing-target") {
		t.Fatalf("method-only lifecycle opacity target fixture mismatch: %s", strings.Join(findings, ", "))
	}
}

func TestWorkstreamCLifecycleRevisionOpacitySourceGuardIgnoresSameNameMethodWithPackageFunction(t *testing.T) {
	targets := lifecycleRevisionOpacityTargetTests()
	functionTarget := targets[1]

	declarations := []string{"type lifecycleRevisionPointerFixtureReceiver struct{}\n"}
	for _, target := range targets {
		declarations = append(declarations, lifecycleRevisionOpacityValidFunctionFixtureSource(target))
	}
	declarations = append(declarations, lifecycleRevisionOpacityValidMethodFixtureSource("*lifecycleRevisionPointerFixtureReceiver", functionTarget))

	if findings := lifecycleRevisionOpacityInlineBlockFindings(lifecycleRevisionOpacityFixtureSource(declarations), targets); len(findings) != 0 {
		t.Fatalf("package function plus same-name method lifecycle opacity fixture mismatch: %s", strings.Join(findings, ", "))
	}
}

func lifecycleRevisionOpacityFixtureSource(declarations []string) string {
	return `package admission

import (
	"strings"
	"testing"
)

` + strings.Join(declarations, "\n")
}

func lifecycleRevisionOpacityValidFunctionFixtureSource(name string) string {
	return `
func ` + name + `(t *testing.T) {
` + lifecycleRevisionOpacityValidFixtureBodySource() + `}
`
}

func lifecycleRevisionOpacityValidMethodFixtureSource(receiver string, name string) string {
	return `
func (` + receiver + `) ` + name + `(t *testing.T) {
` + lifecycleRevisionOpacityValidFixtureBodySource() + `}
`
}

func lifecycleRevisionOpacityValidFixtureBodySource() string {
	return `	result := struct {
		LifecycleProjection struct{ Revision string }
	}{}
	if result.LifecycleProjection.Revision == "" {
		t.Fatal("lifecycle projection revision opacity invariant failed")
	}
	if !opaqueLifecycleProjectionRevisionPattern.MatchString(result.LifecycleProjection.Revision) {
		t.Fatal("lifecycle projection revision opacity invariant failed")
	}
	for index, forbiddenRevisionFragment := range []string{
		"nomad-index",
		"exec-run",
		"alloc-",
		"task",
		":",
		"/",
	} {
		if strings.Contains(result.LifecycleProjection.Revision, forbiddenRevisionFragment) {
			t.Fatalf("lifecycle projection revision opacity invariant failed at index %d", index)
		}
	}
`
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
		t.Fatal("expected bounded handoff evidence labels")
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

	assertTextOmitsAllFixed(t, payload, []string{
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
	})
}

func TestWorkstreamC3DefaultAuthorityHandoffExcludesLiveCredentialAndRetainedResultAuthority(t *testing.T) {
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

	payload := mustMarshalWorkstreamCTestJSON(t, handoff)
	assertTextOmitsAllFixed(t, payload, []string{
		`"token"`,
		`"lease"`,
		`"approval"`,
		`"credential"`,
		`"secret"`,
		`"api_key"`,
		`"vault_token"`,
		`"codex_credential"`,
		`"scheduler_id"`,
		`"operator_authorization"`,
		`"workflow"`,
		`"workflow_id"`,
		`"checkpoint"`,
		`"finalization"`,
		`"retained_result_authority"`,
		`"retained_result_id"`,
		`"retained_result_path"`,
	})
}

func TestWorkstreamC3ControlPlaneNormalShellAuthorityHandoffOnlyCarriesCredentialLocationCompatibility(t *testing.T) {
	handoff := buildExecutionAuthorityHandoff(
		executionRuntimeProfile{
			name: runtimeProfileControlPlaneNormalShell,
			env: map[string]string{
				codexCLIPathEnvKey:                    "/usr/local/bin/codex",
				codexCredentialSourceEnvKey:           codexCredentialSourceWorkloadVault,
				codexCredentialVaultSecretPathEnvKey:  "proof-secrets/data/codex-runtime-profile",
				codexCredentialVaultSecretFieldEnvKey: "api_key",
			},
		},
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
	if handoff.CodexCredentialLocation == nil ||
		handoff.CodexCredentialLocation.CredentialSource != codexCredentialSourceWorkloadVault ||
		handoff.CodexCredentialLocation.VaultSecretPath != "proof-secrets/data/codex-runtime-profile" ||
		handoff.CodexCredentialLocation.VaultSecretField != "api_key" {
		t.Fatal("current non-secret credential-location compatibility metadata mismatch")
	}

	payload := mustMarshalWorkstreamCTestJSON(t, handoff)
	assertTextOmitsAllFixed(t, payload, []string{
		`"token"`,
		`"lease"`,
		`"approval"`,
		`"vault_token"`,
		`"codex_token"`,
		`"credential_material"`,
		`"credential_value"`,
		`"secret_material"`,
		`"secret_value"`,
		`"scheduler_id"`,
		`"operator_authorization"`,
		`"workflow"`,
		`"workflow_id"`,
		`"checkpoint"`,
		`"finalization"`,
		`"retained_result_authority"`,
		`"retained_result_id"`,
	})
}

func TestWorkstreamC3OutcomeEvidenceLabelsRemainBoundedCompatibilityVocabulary(t *testing.T) {
	projection := LifecycleProjection{Source: lifecycleProjectionSourceNomad, Revision: "opaque-c3-read-token"}

	tests := []struct {
		name     string
		evidence ExecutionOutcomeEvidence
		want     ExecutionOutcomeEvidence
	}{
		{
			name:     "status",
			evidence: statusOutcomeEvidence(outcomeObservationNomadTaskStateProjection, projection, true),
			want: ExecutionOutcomeEvidence{
				Source:      outcomeEvidenceSourceNomad,
				Observation: outcomeObservationNomadTaskStateProjection,
				LifecycleProjection: &LifecycleProjection{
					Source:   lifecycleProjectionSourceNomad,
					Revision: "opaque-c3-read-token",
				},
				ProviderTerminalObserved: boolPointer(true),
			},
		},
		{
			name:     "logs",
			evidence: logsOutcomeEvidence(false),
			want: ExecutionOutcomeEvidence{
				Source:                   outcomeEvidenceSourceNomad,
				Observation:              outcomeObservationNomadTaskStdout,
				AccessClass:              outcomeAccessClassPlaintextStdout,
				ProviderTerminalObserved: boolPointer(false),
			},
		},
		{
			name:     "cancel",
			evidence: cancelOutcomeEvidence(),
			want: ExecutionOutcomeEvidence{
				Source:                   outcomeEvidenceSourceNomad,
				Observation:              outcomeObservationNomadStopAccepted,
				ProviderTerminalObserved: boolPointer(false),
			},
		},
		{
			name:     "retained result",
			evidence: retainedResultOutcomeEvidence(),
			want: ExecutionOutcomeEvidence{
				Source:      outcomeEvidenceSourceRetainedResultStore,
				Observation: outcomeObservationRetainedResultBundle,
				AccessClass: outcomeAccessClassOpaqueResultBundle,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.evidence.Source != tt.want.Source ||
				tt.evidence.Observation != tt.want.Observation ||
				tt.evidence.AccessClass != tt.want.AccessClass {
				t.Fatal("outcome evidence label compatibility changed")
			}
			if (tt.evidence.LifecycleProjection == nil) != (tt.want.LifecycleProjection == nil) {
				t.Fatal("outcome evidence lifecycle projection presence changed")
			}
			if tt.evidence.LifecycleProjection != nil && *tt.evidence.LifecycleProjection != *tt.want.LifecycleProjection {
				t.Fatal("outcome evidence lifecycle projection changed")
			}
			if (tt.evidence.ProviderTerminalObserved == nil) != (tt.want.ProviderTerminalObserved == nil) {
				t.Fatal("outcome evidence terminal observation presence changed")
			}
			if tt.evidence.ProviderTerminalObserved != nil && *tt.evidence.ProviderTerminalObserved != *tt.want.ProviderTerminalObserved {
				t.Fatal("outcome evidence terminal observation changed")
			}
			payload := mustMarshalWorkstreamCTestJSON(t, tt.evidence)
			assertTextOmitsAllFixed(t, payload, []string{
				`"scheduler_id"`,
				`"workflow"`,
				`"checkpoint"`,
				`"finalization"`,
				`"approval"`,
				`"credential"`,
				`"token"`,
				`"retained_result_authority"`,
			})
		})
	}
}

func TestWorkstreamC5LifecycleCompatibilityDTOsAndEvidenceStayNonAuthority(t *testing.T) {
	fieldNames := collectJSONFieldNames(t,
		ExecutionStatusResult{},
		ExecutionCancelResult{},
		LifecycleProjection{},
		ExecutionOutcomeEvidence{},
		ExecutionAuthorityHandoff{},
		ExecutionAuthorityRuntimeProfile{},
		ExecutionAuthorityIdentityHandoff{},
		ExecutionAuthorityWorkloadVault{},
		ExecutionAuthorityRuntimeConfigRefs{},
		ExecutionAuthorityRuntimeConfigRef{},
		ExecutionAuthorityCodexCredential{},
		ExecutionAuthorityEvidence{},
	)

	for _, forbidden := range []string{
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
		"operator_approval",
		"operator_authorization",
		"cp_run_control",
		"nomad_job_id",
		"job_id",
		"allocation_id",
		"task_id",
		"scheduler_id",
		"scheduler_authority",
		"lifecycle_store",
		"write_guard",
		"write_precondition",
		"retained_result_id",
		"vault_token",
		"client_token",
		"root_token",
		"unseal_key",
		"jwt_svid",
		"x509_svid",
		"private_key",
		"api_key",
		"proof_secret",
		"secret_payload",
		"lease_id",
		"lease_duration",
	} {
		if _, ok := fieldNames[forbidden]; ok {
			t.Fatalf("C5 status/cancel envelopes and evidence DTOs must not expose authority field %q", forbidden)
		}
	}

	for _, compatibilityField := range []string{
		"success",
		"run_id",
		"status",
		"lifecycle_projection",
		"source",
		"revision",
		"outcome_evidence",
		"provider_terminal_observed",
		"access_class",
		"authority_handoff",
		"runtime_profile",
		"workload_vault",
		"runtime_config_refs",
		"codex_credential_location",
	} {
		if _, ok := fieldNames[compatibilityField]; !ok {
			t.Fatalf("expected C5 compatibility field %q to remain present", compatibilityField)
		}
	}

	if runtimeProfileAnnotationKey != "execution_substrate.runtime_profile" {
		t.Fatalf("runtime profile annotation compatibility key changed to %q", runtimeProfileAnnotationKey)
	}
	if runtimeProfileControlPlaneNormalShell != "control-plane-normal-shell/v1" {
		t.Fatalf("control-plane normal-shell profile compatibility name changed to %q", runtimeProfileControlPlaneNormalShell)
	}

	projection := lifecycleProjectionFromNomad(42, 314)
	if projection.Revision == "" {
		t.Fatal("lifecycle projection revision opacity invariant failed")
	}
	if !opaqueLifecycleProjectionRevisionPattern.MatchString(projection.Revision) {
		t.Fatal("lifecycle projection revision opacity invariant failed")
	}
	for index, forbiddenRevisionFragment := range []string{
		"nomad-index",
		"exec-run",
		"alloc-",
		"task",
		":",
		"/",
	} {
		if strings.Contains(projection.Revision, forbiddenRevisionFragment) {
			t.Fatalf("lifecycle projection revision opacity invariant failed at index %d", index)
		}
	}
	if strings.Contains(projection.Revision, "42") ||
		strings.Contains(projection.Revision, "314") ||
		strings.Contains(projection.Revision, "exec-run-") ||
		strings.Contains(projection.Revision, "alloc-") {
		t.Fatal("C5 lifecycle projection revision must stay opaque")
	}

	evidenceBySurface := map[string]ExecutionOutcomeEvidence{
		"status": statusOutcomeEvidence(outcomeObservationNomadTaskStateProjection, projection, true),
		"logs":   logsOutcomeEvidence(false),
		"result": retainedResultOutcomeEvidence(),
		"cancel": cancelOutcomeEvidence(),
	}
	if evidenceBySurface["status"].Source != outcomeEvidenceSourceNomad ||
		evidenceBySurface["status"].Observation != outcomeObservationNomadTaskStateProjection ||
		evidenceBySurface["status"].LifecycleProjection == nil ||
		*evidenceBySurface["status"].LifecycleProjection != projection {
		t.Fatal("unexpected C5 status outcome evidence")
	}
	if evidenceBySurface["logs"].Source != outcomeEvidenceSourceNomad ||
		evidenceBySurface["logs"].Observation != outcomeObservationNomadTaskStdout ||
		evidenceBySurface["logs"].AccessClass != outcomeAccessClassPlaintextStdout {
		t.Fatal("unexpected C5 logs outcome evidence")
	}
	if evidenceBySurface["result"].Source != outcomeEvidenceSourceRetainedResultStore ||
		evidenceBySurface["result"].Observation != outcomeObservationRetainedResultBundle ||
		evidenceBySurface["result"].AccessClass != outcomeAccessClassOpaqueResultBundle {
		t.Fatal("unexpected C5 retained result outcome evidence")
	}
	if evidenceBySurface["cancel"].Source != outcomeEvidenceSourceNomad ||
		evidenceBySurface["cancel"].Observation != outcomeObservationNomadStopAccepted ||
		evidenceBySurface["cancel"].ProviderTerminalObserved == nil ||
		*evidenceBySurface["cancel"].ProviderTerminalObserved {
		t.Fatal("unexpected C5 cancel outcome evidence")
	}

	payload := mustMarshalWorkstreamCTestJSON(t, evidenceBySurface)
	assertTextOmitsAllFixed(t, payload, []string{
		`"review":`,
		`"checkpoint":`,
		`"finalization":`,
		`"intervention":`,
		`"approval":`,
		`"hold":`,
		`"resume":`,
		`"reject":`,
		`"temporal":`,
		`"workflow":`,
		`"nomad_job_id":`,
		`"job_id":`,
		`"allocation_id":`,
		`"task_id":`,
		`"scheduler_id":`,
		`"vault_token":`,
		`"client_token":`,
		`"root_token":`,
		`"unseal_key":`,
		`"jwt_svid":`,
		`"x509_svid":`,
		`"private_key":`,
		`"api_key":`,
		`"proof_secret":`,
		`"secret_payload":`,
		`"lease_id":`,
		`"lease_duration":`,
	})
}

func TestWorkstreamCLifecycleProjectionAuthorityLabelsStayNomadReadModelOnly(t *testing.T) {
	fieldNames := collectJSONFieldNames(t,
		ExecutionStatusResult{},
		ExecutionCancelResult{},
		LifecycleProjection{},
		ExecutionOutcomeEvidence{},
		ExecutionLogsResult{},
		ExecutionResultBundle{},
	)

	for _, forbidden := range workstreamCLifecycleProjectionAuthorityForbiddenFields() {
		if _, ok := fieldNames[forbidden]; ok {
			t.Fatalf("lifecycle/status projection DTOs must not expose authority field %q", forbidden)
		}
	}

	projection := lifecycleProjectionFromNomad(101, 202, 303)
	if projection.Source != lifecycleProjectionSourceNomad {
		t.Fatal("expected current documented projection source nomad")
	}
	if projection.Revision == "" {
		t.Fatal("lifecycle projection revision opacity invariant failed")
	}
	if !opaqueLifecycleProjectionRevisionPattern.MatchString(projection.Revision) {
		t.Fatal("lifecycle projection revision opacity invariant failed")
	}
	for index, forbiddenRevisionFragment := range []string{
		"nomad-index",
		"exec-run",
		"alloc-",
		"task",
		":",
		"/",
	} {
		if strings.Contains(projection.Revision, forbiddenRevisionFragment) {
			t.Fatalf("lifecycle projection revision opacity invariant failed at index %d", index)
		}
	}
	for index, forbidden := range []string{
		"101",
		"202",
		"303",
		"exec-run-0123456789abcdef",
		"alloc-authority",
		"workflow",
		"cp-workflow",
		"fresh",
		"result.tar.gz",
	} {
		if strings.Contains(projection.Revision, forbidden) {
			t.Fatalf("lifecycle projection revision forbidden authority fragment at index %d", index)
		}
	}

	statusEvidence := statusOutcomeEvidence(outcomeObservationNomadTaskStateProjection, projection, true)
	if statusEvidence.Source != outcomeEvidenceSourceNomad ||
		statusEvidence.LifecycleProjection == nil ||
		*statusEvidence.LifecycleProjection != projection {
		t.Fatal("status outcome evidence must repeat the same opaque Nomad projection token")
	}
	if logsOutcomeEvidence(false).Source != outcomeEvidenceSourceNomad ||
		cancelOutcomeEvidence().Source != outcomeEvidenceSourceNomad ||
		retainedResultOutcomeEvidence().Source != outcomeEvidenceSourceRetainedResultStore {
		t.Fatal("expected status/logs/cancel labels to stay Nomad-backed and result labels to stay retained-result-store backed")
	}

	payload := mustMarshalWorkstreamCTestJSON(t, struct {
		Status ExecutionStatusResult          `json:"status"`
		Logs   ExecutionOutcomeEvidence       `json:"logs"`
		Result ExecutionOutcomeEvidence       `json:"result"`
		Cancel ExecutionCancelResult          `json:"cancel"`
		Meta   map[string]LifecycleProjection `json:"meta"`
	}{
		Status: ExecutionStatusResult{
			Success:             true,
			RunID:               "run-0123456789abcdef",
			Status:              "terminal",
			LifecycleProjection: projection,
			OutcomeEvidence:     statusEvidence,
			Terminal:            true,
		},
		Logs:   logsOutcomeEvidence(false),
		Result: retainedResultOutcomeEvidence(),
		Cancel: ExecutionCancelResult{
			Success:         true,
			RunID:           "run-0123456789abcdef",
			Status:          "cancel_requested",
			OutcomeEvidence: cancelOutcomeEvidence(),
		},
		Meta: map[string]LifecycleProjection{"same_run_read_model": projection},
	})
	assertTextOmitsAllFixed(t, payload, workstreamCLifecycleProjectionAuthorityForbiddenJSONTerms())
	assertTextOmitsAllFixed(t, payload, []string{
		"exec-run-0123456789abcdef",
		"alloc-authority",
		"cp-workflow-version",
		"global_freshness",
		"support payload",
		"proof payload",
		"raw log payload",
	})
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
		t.Fatal("existing profile image and non-secret metadata compatibility mismatch")
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
		t.Fatalf("expected admission error with status %d", status)
	}
	if err.Status != status || err.Code != code {
		t.Fatalf("admission error classification mismatch: got status %d want %d", err.Status, status)
	}
}

func assertDirectoryEmpty(t *testing.T, dir string) {
	t.Helper()

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal("read guarded directory failed")
	}
	if len(entries) != 0 {
		t.Fatalf("guarded directory entry count mismatch: got %d want 0", len(entries))
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

func collectDirectJSONFieldNames(t *testing.T, value any) map[string]struct{} {
	t.Helper()

	typ := reflect.TypeOf(value)
	if typ.Kind() == reflect.Pointer {
		typ = typ.Elem()
	}
	if typ.Kind() != reflect.Struct {
		t.Fatal("expected struct value for direct JSON field collection")
	}

	names := map[string]struct{}{}
	for index := 0; index < typ.NumField(); index++ {
		tag := typ.Field(index).Tag.Get("json")
		if tag == "" || tag == "-" {
			continue
		}
		name, _, _ := strings.Cut(tag, ",")
		if name != "" && name != "-" {
			names[name] = struct{}{}
		}
	}
	return names
}

func assertTextOmitsAllFixed(t *testing.T, text string, forbidden []string) {
	t.Helper()

	for index, item := range forbidden {
		if strings.Contains(text, item) {
			t.Fatalf("forbidden text fragment present at index %d", index)
		}
	}
}

func lifecycleRevisionOpacityTargetTests() []string {
	return []string{
		"TestWorkstreamCLifecycleProjectionAndCancelReceiptsHideNomadIdentifiers",
		"TestWorkstreamC2LifecycleProjectionRevisionIsOpaqueNomadReadCoordinationOnly",
		"TestWorkstreamC5LifecycleCompatibilityDTOsAndEvidenceStayNonAuthority",
		"TestWorkstreamCLifecycleProjectionAuthorityLabelsStayNomadReadModelOnly",
	}
}

func lifecycleRevisionOpacityInlineBlockFindings(source string, targets []string) []string {
	if opaqueLifecycleProjectionRevisionPattern.String() != `^[0-9a-f]{64}$` {
		return []string{"lifecycle-revision-pattern-contract"}
	}

	fileSet := token.NewFileSet()
	file, err := parser.ParseFile(fileSet, "workstream-c-lifecycle-opacity-source.go", source, parser.ParseComments)
	if err != nil {
		return []string{"parse-source"}
	}

	targetNames := map[string]bool{}
	for _, target := range targets {
		targetNames[target] = true
	}
	functions := map[string][]*ast.FuncDecl{}
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Recv != nil || fn.Body == nil {
			continue
		}
		if targetNames[fn.Name.Name] {
			functions[fn.Name.Name] = append(functions[fn.Name.Name], fn)
		}
	}

	var findings []string
	for _, target := range targets {
		matches := functions[target]
		switch len(matches) {
		case 0:
			findings = append(findings, target+":missing-target")
			continue
		case 1:
			findings = append(findings, lifecycleRevisionOpacityFunctionFindings(source, fileSet, target, matches[0])...)
		default:
			findings = append(findings, target+":duplicate-target:"+strconv.Itoa(len(matches)))
		}
	}
	return findings
}

func containsWorkstreamCFinding(findings []string, want string) bool {
	for _, finding := range findings {
		if finding == want {
			return true
		}
	}
	return false
}

func lifecycleRevisionOpacityFunctionFindings(source string, fileSet *token.FileSet, name string, fn *ast.FuncDecl) []string {
	var findings []string
	if strings.Contains(sourceForWorkstreamNode(source, fileSet, fn.Body), "assertOpaqueLifecycleProjection"+"Revision(") {
		findings = append(findings, name+":legacy-helper-call")
	}

	revisionExprs := lifecycleRevisionMatchStringExprs(source, fileSet, fn)
	if len(revisionExprs) == 0 {
		findings = append(findings, name+":missing-hex-length-check")
	}
	if !lifecycleRevisionHasNonemptyCheck(source, fileSet, fn, revisionExprs) {
		findings = append(findings, name+":missing-nonempty-check")
	}

	rejected := lifecycleRevisionForbiddenFragmentsRejected(source, fileSet, fn, revisionExprs)
	for _, fragment := range lifecycleRevisionForbiddenFragments() {
		if !rejected[fragment] {
			findings = append(findings, name+":missing-forbidden-fragment")
			break
		}
	}

	findings = append(findings, lifecycleRevisionDiagnosticFindings(source, fileSet, name, fn, revisionExprs)...)
	return findings
}

func lifecycleRevisionForbiddenFragments() []string {
	return []string{
		"nomad-index",
		"exec-run",
		"alloc-",
		"task",
		":",
		"/",
	}
}

func lifecycleRevisionMatchStringExprs(source string, fileSet *token.FileSet, fn *ast.FuncDecl) map[string]struct{} {
	expressions := map[string]struct{}{}
	ast.Inspect(fn.Body, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok || len(call.Args) != 1 {
			return true
		}
		selector, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || selector.Sel.Name != "MatchString" {
			return true
		}
		if normalizedWorkstreamExpr(source, fileSet, selector.X) != "opaqueLifecycleProjectionRevisionPattern" {
			return true
		}
		expressions[normalizedWorkstreamExpr(source, fileSet, call.Args[0])] = struct{}{}
		return true
	})
	return expressions
}

func lifecycleRevisionHasNonemptyCheck(source string, fileSet *token.FileSet, fn *ast.FuncDecl, revisionExprs map[string]struct{}) bool {
	found := false
	ast.Inspect(fn.Body, func(node ast.Node) bool {
		if found {
			return false
		}
		condition, ok := node.(*ast.BinaryExpr)
		if !ok || condition.Op != token.EQL {
			return true
		}
		if lifecycleRevisionExprMatches(source, fileSet, condition.X, revisionExprs) && isEmptyStringLiteral(condition.Y) {
			found = true
			return false
		}
		if lifecycleRevisionExprMatches(source, fileSet, condition.Y, revisionExprs) && isEmptyStringLiteral(condition.X) {
			found = true
			return false
		}
		return true
	})
	return found
}

func lifecycleRevisionForbiddenFragmentsRejected(source string, fileSet *token.FileSet, fn *ast.FuncDecl, revisionExprs map[string]struct{}) map[string]bool {
	rejected := map[string]bool{}
	ast.Inspect(fn.Body, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if ok {
			if fragment, ok := lifecycleDirectForbiddenFragmentCheck(source, fileSet, call, revisionExprs); ok {
				rejected[fragment] = true
			}
			return true
		}

		ranged, ok := node.(*ast.RangeStmt)
		if !ok {
			return true
		}
		fragments := lifecycleStringLiteralSet(ranged.X)
		if len(fragments) == 0 {
			return true
		}
		rangeNames := map[string]bool{}
		for _, expr := range []ast.Expr{ranged.Key, ranged.Value} {
			ident, ok := expr.(*ast.Ident)
			if ok && ident.Name != "_" {
				rangeNames[ident.Name] = true
			}
		}
		if len(rangeNames) == 0 {
			return true
		}
		if lifecycleRangeBodyContainsRevisionFragmentCheck(source, fileSet, ranged.Body, revisionExprs, rangeNames) {
			for fragment := range fragments {
				rejected[fragment] = true
			}
		}
		return true
	})
	return rejected
}

func lifecycleDirectForbiddenFragmentCheck(source string, fileSet *token.FileSet, call *ast.CallExpr, revisionExprs map[string]struct{}) (string, bool) {
	if !isStringsContainsCall(source, fileSet, call) || len(call.Args) != 2 {
		return "", false
	}
	if !lifecycleRevisionExprMatches(source, fileSet, call.Args[0], revisionExprs) {
		return "", false
	}
	fragment, ok := stringLiteralValueFromExpr(call.Args[1])
	if !ok {
		return "", false
	}
	for _, required := range lifecycleRevisionForbiddenFragments() {
		if fragment == required {
			return fragment, true
		}
	}
	return "", false
}

func lifecycleRangeBodyContainsRevisionFragmentCheck(source string, fileSet *token.FileSet, body *ast.BlockStmt, revisionExprs map[string]struct{}, rangeNames map[string]bool) bool {
	found := false
	ast.Inspect(body, func(node ast.Node) bool {
		if found {
			return false
		}
		call, ok := node.(*ast.CallExpr)
		if !ok || !isStringsContainsCall(source, fileSet, call) || len(call.Args) != 2 {
			return true
		}
		if !lifecycleRevisionExprMatches(source, fileSet, call.Args[0], revisionExprs) {
			return true
		}
		ident, ok := call.Args[1].(*ast.Ident)
		if ok && rangeNames[ident.Name] {
			found = true
			return false
		}
		return true
	})
	return found
}

func lifecycleRevisionDiagnosticFindings(source string, fileSet *token.FileSet, name string, fn *ast.FuncDecl, revisionExprs map[string]struct{}) []string {
	testingHandles := lifecycleTestingHandleNames(fn)
	var findings []string
	ast.Inspect(fn.Body, func(node ast.Node) bool {
		branch, ok := node.(*ast.IfStmt)
		if !ok || !lifecycleConditionMentionsRevision(source, fileSet, branch.Cond, revisionExprs) {
			return true
		}
		ast.Inspect(branch.Body, func(child ast.Node) bool {
			call, ok := child.(*ast.CallExpr)
			if !ok {
				return true
			}
			method, ok := lifecycleTestingOutputMethod(call, testingHandles)
			if !ok {
				return true
			}
			if !lifecycleTestingDiagnosticIsBounded(method, call) {
				findings = append(findings, name+":unbounded-lifecycle-diagnostic")
			}
			return true
		})
		return true
	})
	return findings
}

func lifecycleConditionMentionsRevision(source string, fileSet *token.FileSet, condition ast.Expr, revisionExprs map[string]struct{}) bool {
	conditionSource := sourceForWorkstreamNode(source, fileSet, condition)
	conditionKey := normalizeWorkstreamSource(conditionSource)
	for revisionExpr := range revisionExprs {
		if strings.Contains(conditionKey, revisionExpr) {
			return true
		}
	}
	return strings.Contains(conditionSource, "LifecycleProjection") && strings.Contains(conditionSource, "Revision")
}

func lifecycleTestingDiagnosticIsBounded(method string, call *ast.CallExpr) bool {
	if lifecycleTestingFormattedOutputMethod(method) {
		if len(call.Args) == 0 || !lifecycleStaticDiagnosticArg(call.Args[0]) {
			return false
		}
		for _, arg := range call.Args[1:] {
			if !lifecycleSafeDiagnosticIndexArg(arg) {
				return false
			}
		}
		return true
	}
	for _, arg := range call.Args {
		if !lifecycleStaticDiagnosticArg(arg) {
			return false
		}
	}
	return true
}

func lifecycleTestingOutputMethod(call *ast.CallExpr, testingHandles map[string]bool) (string, bool) {
	selector, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return "", false
	}
	receiver, ok := selector.X.(*ast.Ident)
	if !ok || !testingHandles[receiver.Name] {
		return "", false
	}
	if lifecycleTestingFormattedOutputMethod(selector.Sel.Name) || lifecycleTestingUnformattedOutputMethod(selector.Sel.Name) {
		return selector.Sel.Name, true
	}
	return "", false
}

func lifecycleTestingFormattedOutputMethod(name string) bool {
	switch name {
	case "Fatalf", "Errorf", "Logf", "Skipf":
		return true
	default:
		return false
	}
}

func lifecycleTestingUnformattedOutputMethod(name string) bool {
	switch name {
	case "Fatal", "Error", "Log", "Skip":
		return true
	default:
		return false
	}
}

func lifecycleTestingHandleNames(fn *ast.FuncDecl) map[string]bool {
	handles := map[string]bool{}
	if fn.Type.Params != nil {
		for _, param := range fn.Type.Params.List {
			if !lifecycleIsTestingHandleType(param.Type) {
				continue
			}
			for _, name := range param.Names {
				handles[name.Name] = true
			}
		}
	}

	changed := true
	for changed {
		changed = false
		ast.Inspect(fn.Body, func(node ast.Node) bool {
			switch typed := node.(type) {
			case *ast.AssignStmt:
				for index, lhs := range typed.Lhs {
					if index >= len(typed.Rhs) {
						continue
					}
					left, ok := lhs.(*ast.Ident)
					if !ok || left.Name == "_" || handles[left.Name] {
						continue
					}
					right, ok := typed.Rhs[index].(*ast.Ident)
					if ok && handles[right.Name] {
						handles[left.Name] = true
						changed = true
					}
				}
			case *ast.ValueSpec:
				for index, name := range typed.Names {
					if name.Name == "_" || handles[name.Name] || index >= len(typed.Values) {
						continue
					}
					value, ok := typed.Values[index].(*ast.Ident)
					if ok && handles[value.Name] {
						handles[name.Name] = true
						changed = true
					}
				}
			}
			return true
		})
	}
	return handles
}

func lifecycleIsTestingHandleType(expr ast.Expr) bool {
	switch typed := expr.(type) {
	case *ast.StarExpr:
		selector, ok := typed.X.(*ast.SelectorExpr)
		return ok && selectedWorkstreamPackageName(selector.X) == "testing" && selector.Sel.Name == "T"
	case *ast.SelectorExpr:
		return selectedWorkstreamPackageName(typed.X) == "testing" && typed.Sel.Name == "TB"
	default:
		return false
	}
}

func lifecycleStaticDiagnosticArg(expr ast.Expr) bool {
	if _, ok := stringLiteralValueFromExpr(expr); ok {
		return true
	}
	ident, ok := expr.(*ast.Ident)
	if !ok {
		return false
	}
	return strings.HasSuffix(ident.Name, "Classification") || strings.HasSuffix(ident.Name, "Diagnostic")
}

func lifecycleSafeDiagnosticIndexArg(expr ast.Expr) bool {
	ident, ok := expr.(*ast.Ident)
	return ok && ident.Name == "index"
}

func lifecycleRevisionExprMatches(source string, fileSet *token.FileSet, expr ast.Expr, revisionExprs map[string]struct{}) bool {
	_, ok := revisionExprs[normalizedWorkstreamExpr(source, fileSet, expr)]
	return ok
}

func isStringsContainsCall(source string, fileSet *token.FileSet, call *ast.CallExpr) bool {
	selector, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || selector.Sel.Name != "Contains" {
		return false
	}
	return normalizedWorkstreamExpr(source, fileSet, selector.X) == "strings"
}

func lifecycleStringLiteralSet(expr ast.Expr) map[string]bool {
	literals := map[string]bool{}
	composite, ok := expr.(*ast.CompositeLit)
	if !ok {
		return literals
	}
	for _, element := range composite.Elts {
		value, ok := stringLiteralValueFromExpr(element)
		if ok {
			literals[value] = true
		}
	}
	return literals
}

func isEmptyStringLiteral(expr ast.Expr) bool {
	value, ok := stringLiteralValueFromExpr(expr)
	return ok && value == ""
}

func stringLiteralValueFromExpr(expr ast.Expr) (string, bool) {
	literal, ok := expr.(*ast.BasicLit)
	if !ok || literal.Kind != token.STRING {
		return "", false
	}
	value, err := strconv.Unquote(literal.Value)
	if err != nil {
		return "", false
	}
	return value, true
}

func normalizedWorkstreamExpr(source string, fileSet *token.FileSet, expr ast.Expr) string {
	return normalizeWorkstreamSource(sourceForWorkstreamNode(source, fileSet, expr))
}

func normalizeWorkstreamSource(text string) string {
	return strings.Join(strings.Fields(text), "")
}

func selectedWorkstreamPackageName(expr ast.Expr) string {
	ident, ok := expr.(*ast.Ident)
	if !ok {
		return ""
	}
	return ident.Name
}

func sourceForWorkstreamNode(source string, fileSet *token.FileSet, node ast.Node) string {
	start := fileSet.Position(node.Pos()).Offset
	end := fileSet.Position(node.End()).Offset
	if start < 0 || end < start || end > len(source) {
		return ""
	}
	return source[start:end]
}

func workstreamC4ForbiddenCredentialFieldNames() []string {
	return []string{
		"vault_token",
		"client_token",
		"root_token",
		"unseal_key",
		"jwt_svid",
		"x509_svid",
		"private_key",
		"api_key",
		"proof_secret",
		"secret_payload",
		"lease_id",
		"lease_duration",
		"raw_spire_socket",
	}
}

func workstreamC4ForbiddenCredentialJSONKeys() []string {
	fields := workstreamC4ForbiddenCredentialFieldNames()
	keys := make([]string, 0, len(fields))
	for _, field := range fields {
		keys = append(keys, `"`+field+`":`)
	}
	return keys
}

func workstreamCLifecycleProjectionAuthorityForbiddenFields() []string {
	return []string{
		"nomad_job_id",
		"job_id",
		"allocation_id",
		"nomad_allocation_id",
		"task_id",
		"scheduler_id",
		"scheduler_revision",
		"scheduler_authority",
		"lifecycle_store",
		"lifecycle_store_key",
		"write_guard",
		"write_precondition",
		"cp_workflow_id",
		"cp_workflow_version",
		"workflow_version",
		"workflow_revision",
		"cp_workflow_revision",
		"global_freshness",
		"freshness_proof",
		"retained_result_id",
		"retained_result_path",
		"retained_bundle_internals",
		"raw_logs",
		"support_payload",
		"proof_payload",
		"env_values",
		"endpoint_secret",
		"pem_body",
		"raw_cert_body",
		"private_key",
		"vault_token",
		"jwt_svid",
		"x509_svid",
	}
}

func workstreamCLifecycleProjectionAuthorityForbiddenJSONTerms() []string {
	fields := workstreamCLifecycleProjectionAuthorityForbiddenFields()
	terms := make([]string, 0, len(fields))
	for _, field := range fields {
		terms = append(terms, `"`+field+`":`)
	}
	return terms
}
