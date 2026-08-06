package admission

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	esconfig "execution-substrate/es/config"
	evidencev1 "execution-substrate/internal/contracts/evidence/v1"
)

type allowAllResolvedPlanAdmissionPolicy struct{}

func (allowAllResolvedPlanAdmissionPolicy) RequiredInputClasses(AdmissionPolicyContext) []AdmissionPolicyInputClass {
	return nil
}

func (allowAllResolvedPlanAdmissionPolicy) Evaluate(context.Context, AdmissionPolicyContext) AdmissionPolicyDecision {
	return AllowAdmissionPolicyDecision()
}

func TestResolvedExecutionPlanUsesPreparedNormalizedRequestAndClones(t *testing.T) {
	fixture := newPreparedArtifactFixture(t)
	service, _, _ := newWorkstreamCTestService(t, fixture)
	service.admissionPolicyEvaluator = allowAllResolvedPlanAdmissionPolicy{}

	request := fixture.prepareRequest()
	request.SchemaVersion = ""
	request.Invocation.SchemaVersion = ""
	request.Mode = ExecutionModeAsync
	request.TimeoutSeconds = 23
	request.Resources = &ExecutionResources{CPU: 77, MemoryMB: 2048}
	request.Invocation.Argv = []string{"--alpha", "beta"}
	request.Invocation.Env = map[string]string{"APP_MODE": "resolved"}
	request.Invocation.Mounts = []RuntimeMount{
		{
			Source:     MountSource{ArtifactDigest: labeledDigest("55")},
			TargetPath: "/execution/mounts/alpha",
			ReadOnly:   true,
		},
		{
			Source:     MountSource{ArtifactDigest: labeledDigest("66")},
			TargetPath: "/execution/mounts/beta",
			ReadOnly:   true,
		},
	}
	request.Invocation.Annotations = map[string]string{
		"caller_annotation": "retained only as normalized request custody",
	}

	configureResolvedPlanAdmissionARS(t, service, fixture, nil)
	prepared, admissionErr := service.prepareAdmission(context.Background(), request)
	if admissionErr != nil {
		t.Fatal("prepareAdmission failed")
	}

	request.Resources.CPU = 1
	request.Invocation.Argv[0] = "--mutated"
	request.Invocation.Env["APP_MODE"] = "mutated"
	request.Invocation.Mounts[0].TargetPath = "/execution/mounts/mutated"
	request.Invocation.Annotations["caller_annotation"] = "mutated"
	if prepared.normalizedRequest.SchemaVersion != "v1" ||
		prepared.normalizedRequest.Invocation.SchemaVersion != "v1" {
		t.Fatal("prepared normalized request schema default mismatch")
	}
	if prepared.normalizedRequest.Resources.CPU != 77 ||
		prepared.normalizedRequest.Invocation.Argv[0] != "--alpha" ||
		prepared.normalizedRequest.Invocation.Env["APP_MODE"] != "resolved" ||
		prepared.normalizedRequest.Invocation.Mounts[0].TargetPath != "/execution/mounts/alpha" ||
		prepared.normalizedRequest.Invocation.Annotations["caller_annotation"] != "retained only as normalized request custody" {
		t.Fatal("prepared normalized request aliases caller-owned input")
	}

	plan, err := service.resolveCurrentSubmitExecutionPlan(prepared)
	if err != nil {
		t.Fatal("resolve plan failed")
	}

	prepared.normalizedRequest.Resources.CPU = 2
	prepared.normalizedRequest.Invocation.Argv[0] = "--prepared-mutated"
	prepared.normalizedRequest.Invocation.Env["APP_MODE"] = "prepared-mutated"
	prepared.normalizedRequest.Invocation.Mounts[0].TargetPath = "/execution/mounts/prepared-mutated"
	if plan.resources.cpu != 77 ||
		plan.command.workloadArgv[0] != "--alpha" ||
		plan.environment.callerEnv["APP_MODE"] != "resolved" ||
		plan.mounts[0].targetPath != "/execution/mounts/alpha" {
		t.Fatal("resolved plan aliases prepared normalized request")
	}

	mounts := plan.runtimeMounts()
	mounts[0].TargetPath = "/execution/mounts/returned-mutated"
	if plan.mounts[0].targetPath != "/execution/mounts/alpha" {
		t.Fatalf("runtimeMounts must return cloned mount declarations")
	}

	if plan.request.outerSchemaVersion != "v1" || plan.request.invocationSchemaVersion != "v1" {
		t.Fatal("request schema/version category mismatch")
	}
	if plan.mode != ExecutionModeAsync {
		t.Fatal("execution mode category mismatch")
	}
	if plan.timeout.seconds != 23 || plan.command.timeoutSeconds != 23 {
		t.Fatal("timeout category mismatch")
	}
	if plan.resources.cpu != 77 || plan.resources.memoryMB != 2048 {
		t.Fatal("resource categories mismatch")
	}
	if plan.profile.name != runtimeProfileDefaultStaticScript || plan.profile.selectedImage != "alpine:3.20" {
		t.Fatal("runtime profile category mismatch")
	}
	if plan.artifact.artifactDigest != fixture.discovery.Artifact.ArtifactDigest ||
		plan.artifact.payloadDigest != fixture.discovery.Payload.Digest ||
		plan.artifact.artifactType != "static-script" ||
		plan.artifact.intentDigest != fixture.discovery.Artifact.IntentDigest ||
		plan.artifact.targetPlatform != "docker" {
		t.Fatal("artifact identity category mismatch")
	}
	if plan.derivation.derivationSpecDigest != fixture.evidence.Claims.Admission.Authorization.Derivation.DerivationSpecDigest {
		t.Fatal("derivation category mismatch")
	}
	if plan.output.outputID != fixture.evidence.Claims.Admission.Authorization.Derivation.OutputID {
		t.Fatal("output category mismatch")
	}
	if plan.command.runtimeSupportCommandIdentity != executionRuntimeSupportPath ||
		plan.command.supervisorOperationIdentity != resolvedSupervisorOperationIdentity ||
		len(plan.command.workloadArgv) != 2 ||
		plan.command.workloadArgv[0] != "--alpha" ||
		plan.command.workloadArgv[1] != "beta" {
		t.Fatal("command/argv category mismatch")
	}
	if plan.environment.callerEnv["APP_MODE"] != "resolved" {
		t.Fatal("environment category mismatch")
	}
	if len(plan.mounts) != 2 ||
		plan.mounts[0].sourceArtifactDigest != labeledDigest("55") ||
		plan.mounts[0].targetPath != "/execution/mounts/alpha" ||
		!plan.mounts[0].readOnly ||
		plan.mounts[1].sourceArtifactDigest != labeledDigest("66") ||
		plan.mounts[1].targetPath != "/execution/mounts/beta" ||
		!plan.mounts[1].readOnly {
		t.Fatalf("mount category mismatch: got count %d want 2", len(plan.mounts))
	}
	if plan.network != resolvedNetworkPostureBridge || !plan.network.networkAccess() {
		t.Fatal("network category mismatch")
	}
	if !plan.authority.applicable ||
		plan.authority.workloadVaultPlan.Mode != esconfig.WorkloadVaultAuthModeVaultIdentityJWT ||
		plan.authority.workloadVaultPlan.Address != "https://vault.internal:8200" ||
		plan.authority.workloadZoneVaultConfigDigest != testWorkloadZoneVaultConfigDigest {
		t.Fatal("authority category mismatch")
	}
}

func TestResolvedExecutionPlanCoversControlPlaneProfileAuthorityMetadata(t *testing.T) {
	fixture := newPreparedArtifactFixture(t)
	service, _, _ := newWorkstreamCTestService(t, fixture)
	service.admissionPolicyEvaluator = allowAllResolvedPlanAdmissionPolicy{}
	service.cfg.Execution.RuntimeProfiles.ControlPlaneNormalShell = esconfig.ControlPlaneNormalShellProfileConfig{
		Enabled:                    true,
		Image:                      "execution-substrate/control-plane-normal-shell:supported-local",
		CodexCLIPath:               "/usr/local/bin/codex",
		CredentialVaultSecretPath:  "proof-secrets/data/codex-runtime-profile",
		CredentialVaultSecretField: "api_key",
	}

	request := fixture.prepareRequest()
	request.Mode = ExecutionModeAsync
	request.Invocation.Annotations = map[string]string{
		runtimeProfileAnnotationKey: runtimeProfileControlPlaneNormalShell,
	}

	configureResolvedPlanAdmissionARS(t, service, fixture, nil)
	prepared, admissionErr := service.prepareAdmission(context.Background(), request)
	if admissionErr != nil {
		t.Fatal("prepareAdmission failed")
	}
	plan, err := service.resolveCurrentSubmitExecutionPlan(prepared)
	if err != nil {
		t.Fatal("resolve control-plane plan failed")
	}

	if plan.profile.name != runtimeProfileControlPlaneNormalShell ||
		plan.profile.selectedImage != "execution-substrate/control-plane-normal-shell:supported-local" {
		t.Fatal("resolved plan control-plane profile/image mismatch")
	}
	if plan.environment.profileEnv[codexCLIPathEnvKey] != "/usr/local/bin/codex" ||
		plan.environment.profileEnv[codexCredentialSourceEnvKey] != codexCredentialSourceWorkloadVault ||
		plan.environment.profileEnv[codexCredentialVaultSecretPathEnvKey] != "proof-secrets/data/codex-runtime-profile" ||
		plan.environment.profileEnv[codexCredentialVaultSecretFieldEnvKey] != "api_key" {
		t.Fatal("resolved plan profile environment additions mismatch")
	}
	profile := plan.executionRuntimeProfile()
	profile.env[codexCLIPathEnvKey] = "mutated"
	if plan.profile.env[codexCLIPathEnvKey] != "/usr/local/bin/codex" {
		t.Fatalf("executionRuntimeProfile must return cloned profile env")
	}
	if plan.authority.codexCredentialLocationMetadata == nil ||
		plan.authority.codexCredentialLocationMetadata.cliPath != "/usr/local/bin/codex" ||
		plan.authority.codexCredentialLocationMetadata.credentialSource != codexCredentialSourceWorkloadVault ||
		plan.authority.codexCredentialLocationMetadata.vaultSecretPath != "proof-secrets/data/codex-runtime-profile" ||
		plan.authority.codexCredentialLocationMetadata.vaultSecretField != "api_key" {
		t.Fatal("resolved plan credential-location metadata mismatch")
	}
	if !plan.authority.applicable {
		t.Fatalf("current supported submit must resolve authority handoff as applicable")
	}
}

func TestResolvedExecutionPlanPreservesEnvironmentAllowlistSemantics(t *testing.T) {
	fixture := newPreparedArtifactFixture(t)
	service, _, _ := newWorkstreamCTestService(t, fixture)
	service.admissionPolicyEvaluator = allowAllResolvedPlanAdmissionPolicy{}

	emptyAllowlistRequest := fixture.prepareRequest()
	emptyAllowlistRequest.Mode = ExecutionModeAsync
	emptyAllowlistRequest.Invocation.Env = map[string]string{"FREE_FORM_ENV": "allowed by empty manifest allowlist"}
	configureResolvedPlanAdmissionARS(t, service, fixture, func(record *evidencev1.ArtifactEvidence) {
		record.Claims.Admission.Execution.Runtime.EnvironmentVariables = nil
	})
	emptyPrepared, admissionErr := service.prepareAdmission(context.Background(), emptyAllowlistRequest)
	if admissionErr != nil {
		t.Fatal("prepareAdmission failed")
	}
	emptyPlan, err := service.resolveCurrentSubmitExecutionPlan(emptyPrepared)
	if err != nil {
		t.Fatal("resolve empty allowlist plan failed")
	}
	if emptyPlan.environment.callerEnv["FREE_FORM_ENV"] != "allowed by empty manifest allowlist" {
		t.Fatal("resolved plan empty allowlist environment mismatch")
	}

	explicitAllowlistRequest := fixture.prepareRequest()
	explicitAllowlistRequest.Mode = ExecutionModeAsync
	explicitAllowlistRequest.Invocation.Env = map[string]string{"APP_MODE": "allowed explicitly"}
	configureResolvedPlanAdmissionARS(t, service, fixture, func(record *evidencev1.ArtifactEvidence) {
		record.Claims.Admission.Execution.Runtime.EnvironmentVariables = []string{"APP_MODE"}
	})
	explicitPrepared, admissionErr := service.prepareAdmission(context.Background(), explicitAllowlistRequest)
	if admissionErr != nil {
		t.Fatal("prepareAdmission failed")
	}
	explicitPlan, err := service.resolveCurrentSubmitExecutionPlan(explicitPrepared)
	if err != nil {
		t.Fatal("resolve explicit allowlist plan failed")
	}
	if explicitPlan.environment.callerEnv["APP_MODE"] != "allowed explicitly" {
		t.Fatal("resolved plan explicit allowlist environment mismatch")
	}

	rejectedRequest := fixture.prepareRequest()
	rejectedRequest.Mode = ExecutionModeAsync
	rejectedRequest.Invocation.Env = map[string]string{"NOT_ALLOWED": "reject"}
	_, admissionErr = service.prepareAdmission(context.Background(), rejectedRequest)
	if admissionErr == nil || admissionErr.Code != codeInvalidRequest || !strings.Contains(admissionErr.Message, "environment key is not allowed") {
		t.Fatal("expected existing explicit manifest allowlist rejection")
	}
}

func TestResolvedExecutionPlanCoversNetworkMountAndResourceVariants(t *testing.T) {
	fixture := newPreparedArtifactFixture(t)
	service, _, _ := newWorkstreamCTestService(t, fixture)
	service.admissionPolicyEvaluator = allowAllResolvedPlanAdmissionPolicy{}

	defaultRequest := fixture.prepareRequest()
	defaultRequest.Mode = ExecutionModeAsync
	configureResolvedPlanAdmissionARS(t, service, fixture, func(record *evidencev1.ArtifactEvidence) {
		record.Claims.Admission.Execution.Access.NetworkAccess = false
	})
	defaultPrepared, admissionErr := service.prepareAdmission(context.Background(), defaultRequest)
	if admissionErr != nil {
		t.Fatal("prepareAdmission failed")
	}
	defaultPlan, err := service.resolveCurrentSubmitExecutionPlan(defaultPrepared)
	if err != nil {
		t.Fatal("resolve default plan failed")
	}
	if defaultPlan.resources.cpu != defaultSubmitCPU || defaultPlan.resources.memoryMB != defaultSubmitMemoryMB {
		t.Fatal("resolved plan default resource mismatch")
	}
	if defaultPlan.network != resolvedNetworkPostureNone || defaultPlan.network.networkAccess() {
		t.Fatal("resolved plan disabled network posture mismatch")
	}
	if len(defaultPlan.command.workloadArgv) != 0 ||
		len(defaultPlan.environment.profileEnv) != 0 ||
		len(defaultPlan.mounts) != 0 {
		t.Fatal("resolved plan empty argv/profile-env/mount categories mismatch")
	}

	oneMountRequest := fixture.prepareRequest()
	oneMountRequest.Mode = ExecutionModeAsync
	oneMountRequest.Resources = &ExecutionResources{CPU: 22, MemoryMB: 512}
	oneMountRequest.Invocation.Mounts = []RuntimeMount{{
		Source:     MountSource{ArtifactDigest: labeledDigest("77")},
		TargetPath: "/execution/mounts/one",
		ReadOnly:   true,
	}}
	configureResolvedPlanAdmissionARS(t, service, fixture, nil)
	oneMountPrepared, admissionErr := service.prepareAdmission(context.Background(), oneMountRequest)
	if admissionErr != nil {
		t.Fatal("prepareAdmission failed")
	}
	oneMountPlan, err := service.resolveCurrentSubmitExecutionPlan(oneMountPrepared)
	if err != nil {
		t.Fatal("resolve one-mount plan failed")
	}
	if oneMountPlan.resources.cpu != 22 || oneMountPlan.resources.memoryMB != 512 {
		t.Fatal("resolved plan explicit resource mismatch")
	}
	if len(oneMountPlan.mounts) != 1 || oneMountPlan.mounts[0].sourceArtifactDigest != labeledDigest("77") ||
		oneMountPlan.mounts[0].targetPath != "/execution/mounts/one" || !oneMountPlan.mounts[0].readOnly {
		t.Fatalf("resolved plan single mount mismatch: got count %d want 1", len(oneMountPlan.mounts))
	}
}

func TestResolvedExecutionPlanSubmitOnlyErrorOrderMatchesLegacyRules(t *testing.T) {
	fixture := newPreparedArtifactFixture(t)
	service, _, _ := newWorkstreamCTestService(t, fixture)
	service.admissionPolicyEvaluator = allowAllResolvedPlanAdmissionPolicy{}
	configureResolvedPlanAdmissionARS(t, service, fixture, nil)
	preparedRequest := fixture.prepareRequest()
	prepared, admissionErr := service.prepareAdmission(context.Background(), preparedRequest)
	if admissionErr != nil {
		t.Fatal("prepareAdmission failed")
	}

	artifactTypeFirst := prepared
	artifactTypeFirst.artifact.manifest.ArtifactType = "wasm"
	artifactTypeFirst.artifact.manifest.RuntimeInterface.RequiredCapabilities = []string{"capability"}
	artifactTypeFirst.artifact.targetPlatform = "kubernetes"
	_, err := service.resolveCurrentSubmitExecutionPlan(artifactTypeFirst)
	assertAdmissionError(t, err, http.StatusBadRequest, codeUnsupportedArtifactType)
	if err.Message != "only static-script artifacts are supported in this execution slice" {
		t.Fatal("unexpected artifact-type error message")
	}

	requiredCapabilitiesSecond := prepared
	requiredCapabilitiesSecond.artifact.manifest.RuntimeInterface.RequiredCapabilities = []string{"capability"}
	requiredCapabilitiesSecond.artifact.targetPlatform = "kubernetes"
	_, err = service.resolveCurrentSubmitExecutionPlan(requiredCapabilitiesSecond)
	assertAdmissionError(t, err, http.StatusBadRequest, codeUnsupportedCapabilities)

	targetPlatformThird := prepared
	targetPlatformThird.artifact.targetPlatform = "kubernetes"
	_, err = service.resolveCurrentSubmitExecutionPlan(targetPlatformThird)
	assertAdmissionError(t, err, http.StatusBadRequest, codeUnsupportedArtifactType)
	if err.Message != "only docker target_platform is supported in this execution slice" {
		t.Fatal("unexpected target-platform error message")
	}

	runtimeProfileLast := prepared
	runtimeProfileLast.normalizedRequest.Invocation.Annotations = map[string]string{
		runtimeProfileAnnotationKey: runtimeProfileControlPlaneNormalShell,
	}
	_, err = service.resolveCurrentSubmitExecutionPlan(runtimeProfileLast)
	assertAdmissionError(t, err, http.StatusBadRequest, codeUnsupportedRuntimeProfile)
}

func TestResolvedExecutionPlanExcludesRunMaterializationAndPolicyPayload(t *testing.T) {
	fixture := newPreparedArtifactFixture(t)
	service, _, _ := newWorkstreamCTestService(t, fixture)
	service.admissionPolicyEvaluator = allowAllResolvedPlanAdmissionPolicy{}

	configureResolvedPlanAdmissionARS(t, service, fixture, nil)
	preparedRequest := fixture.prepareRequest()
	prepared, admissionErr := service.prepareAdmission(context.Background(), preparedRequest)
	if admissionErr != nil {
		t.Fatal("prepareAdmission failed")
	}
	prepared.policyPayloadBytes = []byte("POLICY_PAYLOAD_BYTES_SENTINEL")
	prepared.policyPayloadBytesAvailable = true
	prepared.trustModel.SignerPolicy.AllowedSigners = append(prepared.trustModel.SignerPolicy.AllowedSigners, "TRUST_MODEL_SENTINEL")

	plan, err := service.resolveCurrentSubmitExecutionPlan(prepared)
	if err != nil {
		t.Fatal("resolve plan failed")
	}

	if plan.artifact.payloadDigest != fixture.discovery.Payload.Digest ||
		plan.artifact.artifactDigest != fixture.discovery.Artifact.ArtifactDigest ||
		plan.artifact.artifactType != "static-script" ||
		plan.artifact.targetPlatform != "docker" {
		t.Fatal("artifact category mismatch")
	}
	if plan.command.runtimeSupportCommandIdentity != resolvedRuntimeSupportCommandIdentity ||
		plan.command.supervisorOperationIdentity != resolvedSupervisorOperationIdentity ||
		plan.command.timeoutSeconds != prepared.normalizedRequest.TimeoutSeconds ||
		len(plan.command.workloadArgv) != 0 {
		t.Fatal("command category mismatch")
	}
	if len(plan.environment.callerEnv) != 1 ||
		plan.environment.callerEnv["APP_MODE"] != "test" ||
		len(plan.environment.profileEnv) != 0 {
		t.Fatal("environment category mismatch")
	}
	if len(plan.mounts) != 0 {
		t.Fatalf("mount category count mismatch: got %d want 0", len(plan.mounts))
	}
	if !plan.authority.applicable ||
		plan.authority.workloadVaultPlan.Mode != esconfig.WorkloadVaultAuthModeVaultIdentityJWT ||
		plan.authority.workloadVaultPlan.Address != "https://vault.internal:8200" ||
		plan.authority.workloadZoneVaultConfigDigest != testWorkloadZoneVaultConfigDigest ||
		plan.authority.codexCredentialLocationMetadata != nil {
		t.Fatal("authority category mismatch")
	}
}

func configureResolvedPlanAdmissionARS(t *testing.T, service *Service, fixture preparedArtifactFixture, mutateEvidence func(*evidencev1.ArtifactEvidence)) {
	t.Helper()

	evidence := fixture.evidence
	if mutateEvidence != nil {
		evidence = signedWorkstreamAEvidence(t, fixture, mutateEvidence)
	}
	evidenceBytes, err := json.Marshal(evidence)
	if err != nil {
		t.Fatalf("marshal evidence: %v", err)
	}
	discovery := fixture.discovery
	discovery.Evidence.Digest = digestBytes(evidenceBytes)
	discovery.Payload.Digest = evidence.Claims.Package.Identity.PayloadDigest
	discovery.Artifact.ArtifactDigest = evidence.Claims.Package.Identity.ArtifactDigest
	discovery.Artifact.ArtifactType = evidence.Claims.Package.Identity.ArtifactType
	discovery.Artifact.IntentDigest = evidence.Claims.Package.Identity.IntentDigest

	service.arsClient = newArtifactRegistryTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/artifacts/" + discovery.Artifact.ArtifactDigest + "/discovery":
			writeJSONResponse(t, w, http.StatusOK, discovery)
		case "/v1/blobs/" + discovery.Evidence.Digest + ":json":
			writeJSONResponse(t, w, http.StatusOK, evidence)
		case "/v1/blobs/" + testWorkloadZoneVaultConfigDigest + ":json":
			_, _ = w.Write([]byte(validWorkloadZoneVaultConfigBlob))
		default:
			t.Fatal("unexpected ARS path during resolved-plan prepare")
		}
	}))

}
