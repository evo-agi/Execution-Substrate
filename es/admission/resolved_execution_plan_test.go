package admission

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"testing"

	egsmodel "execution-substrate/egs/model"
	esconfig "execution-substrate/es/config"
	evidencev1 "execution-substrate/internal/contracts/evidence/v1"
	runtimeconfigv1 "execution-substrate/internal/contracts/runtimeconfig/v1"
)

func TestResolvedExecutionAdmissionSnapshotDeepCopiesAndPreservesCollectionPresence(t *testing.T) {
	request := PrepareRequest{
		SchemaVersion: "v1",
		Invocation: ArtifactInvocation{
			SchemaVersion:        "v1",
			ArtifactDigest:       labeledDigest("11"),
			DerivationSpecDigest: labeledDigest("22"),
			OutputID:             "runtime",
			Argv:                 []string{"first"},
			Env:                  map[string]string{"APP_MODE": "test"},
			Mounts: []RuntimeMount{{
				Source:     MountSource{ArtifactDigest: labeledDigest("33")},
				TargetPath: "/execution/mounts/config",
				ReadOnly:   true,
			}},
			Annotations: map[string]string{"profile": "default"},
		},
		Resources: &ExecutionResources{CPU: 10, MemoryMB: 128},
	}

	snapshot := snapshotAdmissionRequest(request)
	request.Invocation.Argv[0] = "mutated"
	request.Invocation.Env["APP_MODE"] = "mutated"
	request.Invocation.Mounts[0].TargetPath = "/execution/mounts/mutated"
	request.Invocation.Annotations["profile"] = "mutated"
	request.Resources.CPU = 999

	if snapshot.Invocation.Argv[0] != "first" || snapshot.Invocation.Env["APP_MODE"] != "test" {
		t.Fatal("admitted request retained mutable argv or environment aliases")
	}
	if snapshot.Invocation.Mounts[0].TargetPath != "/execution/mounts/config" || snapshot.Invocation.Annotations["profile"] != "default" {
		t.Fatal("admitted request retained mutable mount or annotation aliases")
	}
	if snapshot.Resources == nil || snapshot.Resources.CPU != 10 {
		t.Fatal("admitted request retained the mutable resources pointer")
	}

	nilCollections := snapshotAdmissionRequest(PrepareRequest{})
	if nilCollections.Invocation.Argv != nil || nilCollections.Invocation.Env != nil || nilCollections.Invocation.Mounts != nil || nilCollections.Invocation.Annotations != nil || nilCollections.Resources != nil {
		t.Fatal("nil collection and pointer presence must be preserved")
	}
	concreteEmpty := snapshotAdmissionRequest(PrepareRequest{Invocation: ArtifactInvocation{
		Argv:        []string{},
		Env:         map[string]string{},
		Mounts:      []RuntimeMount{},
		Annotations: map[string]string{},
	}})
	if concreteEmpty.Invocation.Argv == nil || concreteEmpty.Invocation.Env == nil || concreteEmpty.Invocation.Mounts == nil || concreteEmpty.Invocation.Annotations == nil {
		t.Fatal("concrete empty collection presence must be preserved")
	}
	ownedMountRequest := snapshotAdmissionRequest(PrepareRequest{Invocation: ArtifactInvocation{Mounts: []RuntimeMount{{
		Source:     MountSource{ArtifactDigest: labeledDigest("33")},
		TargetPath: "  /execution/mounts/config  ",
		ReadOnly:   true,
	}}}})
	if err := validateRuntimeMounts(ownedMountRequest.Invocation.Mounts); err != nil || ownedMountRequest.Invocation.Mounts[0].TargetPath != "/execution/mounts/config" {
		t.Fatal("owned admitted request did not retain the single normalized mount target")
	}
	service := &Service{}
	nilPlans, nilMaterial, nilErr := service.resolveRuntimeMounts(context.Background(), egsmodel.RuntimeTrustPolicy{}, nil)
	emptyPlans, emptyMaterial, emptyErr := service.resolveRuntimeMounts(context.Background(), egsmodel.RuntimeTrustPolicy{}, []RuntimeMount{})
	if nilErr != nil || emptyErr != nil || nilPlans != nil || nilMaterial != nil || emptyPlans == nil || emptyMaterial == nil {
		t.Fatal("resolved mount inputs did not preserve nil versus concrete-empty presence")
	}
}

func TestResolvedExecutionPrivateValuesFormatAsOneFixedRedaction(t *testing.T) {
	plan := resolvedExecutionPlan{artifactDigest: "private-artifact", semanticEnvironment: map[string]string{"TOKEN": "private"}}
	material := resolvedExecutionMaterial{payloadBytes: []byte("private-payload")}
	host := hostMaterializationContext{stagingRootDir: "/private/stage"}
	run := resolvedRunProjection{environment: map[string]string{"TOKEN": "private"}}
	job := resolvedNomadJobProjection{environment: map[string]string{"TOKEN": "private"}}
	archive := validatedMountArchive{compressedBytes: []byte("private-archive")}
	entry := validatedMountEntry{contents: []byte("private-entry")}
	values := []any{
		submitConfigSnapshot{}, &submitConfigSnapshot{},
		resolvedTaskResources{}, &resolvedTaskResources{},
		resolvedRuntimeProfile{}, &resolvedRuntimeProfile{},
		resolvedWorkloadVaultPlan{}, &resolvedWorkloadVaultPlan{},
		resolvedMountPlan{}, &resolvedMountPlan{},
		resolvedRuntimeMountInputs{}, &resolvedRuntimeMountInputs{},
		resolvedRuntimeCommand{}, &resolvedRuntimeCommand{},
		resolvedRestartPolicy{}, &resolvedRestartPolicy{},
		resolvedReschedulePolicy{}, &resolvedReschedulePolicy{},
		resolvedJobEnvelope{}, &resolvedJobEnvelope{},
		resolvedCodexCredentialLocation{}, &resolvedCodexCredentialLocation{},
		resolvedAuthorityPlan{}, &resolvedAuthorityPlan{},
		resolvedPlanFacts{}, &resolvedPlanFacts{},
		plan, &plan,
		resolvedTrustMaterial{}, &resolvedTrustMaterial{},
		archive, &archive,
		entry, &entry,
		resolvedMaterialFacts{}, &resolvedMaterialFacts{},
		material, &material,
		host, &host,
		run, &run,
		job, &job,
		executionAuthorityHandoffProjection{}, &executionAuthorityHandoffProjection{},
		executionAuthorityMetadataProjection{}, &executionAuthorityMetadataProjection{},
		resolvedExecution{}, &resolvedExecution{},
	}
	formats := []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X", "%20v", "%-20v", "%.3v"}
	for _, value := range values {
		for _, format := range formats {
			if got := fmt.Sprintf(format, value); got != privateExecutionValueRedaction {
				t.Fatal("private execution value did not produce the fixed redaction")
			}
		}
	}
}

func TestResolvedExecutionPlanAndRunProjectionOwnMutableFacts(t *testing.T) {
	facts := resolvedPlanFacts{
		runtimeCommand:      resolvedRuntimeCommand{executable: executionRuntimeSupportPath, arguments: []string{"supervisor", "--", "first"}},
		semanticEnvironment: map[string]string{"APP_MODE": "test"},
		mounts: []resolvedMountPlan{{
			artifactDigest: labeledDigest("44"),
			targetPath:     "/execution/mounts/config",
			readOnly:       true,
		}},
		jobEnvelope: resolvedJobEnvelope{securityOptions: []string{"no-new-privileges"}},
	}
	plan := newResolvedExecutionPlan(facts)
	facts.runtimeCommand.arguments[2] = "mutated"
	facts.semanticEnvironment["APP_MODE"] = "mutated"
	facts.mounts[0].targetPath = "/execution/mounts/mutated"
	facts.jobEnvelope.securityOptions[0] = "mutated"

	if plan.runtimeCommand.arguments[2] != "first" || plan.semanticEnvironment["APP_MODE"] != "test" {
		t.Fatal("resolved plan retained mutable argument or environment aliases")
	}
	if plan.mounts[0].targetPath != "/execution/mounts/config" || plan.jobEnvelope.securityOptions[0] != "no-new-privileges" {
		t.Fatal("resolved plan retained mutable mount or job-envelope aliases")
	}

	host := newHostMaterializationContext(t.TempDir(), t.TempDir(), executionPlatformStateOwner{UID: os.Getuid(), GID: os.Getgid()}, "/run/spire/sockets", "dc1")
	run := newResolvedRunProjection(plan, host, newExecutionLocatorFromRunID("run-0123456789abcdef"))
	run.runtimeCommand.arguments[2] = "projection-mutation"
	run.environment["APP_MODE"] = "projection-mutation"
	if plan.runtimeCommand.arguments[2] != "first" || plan.semanticEnvironment["APP_MODE"] != "test" {
		t.Fatal("run projection retained mutable aliases into the frozen plan")
	}
	stagedMounts := []stagedRuntimeMount{{sourceDir: "/captured/source", targetPath: "/execution/mounts/config", readOnly: true}}
	job := run.nomadJobProjection(stagedMounts)
	job.runtimeCommand.arguments[2] = "job-mutation"
	job.environment["APP_MODE"] = "job-mutation"
	job.stagedMounts[0].sourceDir = "/mutated/source"
	if run.runtimeCommand.arguments[2] != "projection-mutation" || run.environment["APP_MODE"] != "projection-mutation" || stagedMounts[0].sourceDir != "/captured/source" {
		t.Fatal("Nomad projection retained mutable aliases into its typed inputs")
	}
}

func TestResolvedExecutionPlanCoversEffectiveCategoriesAndExecutionEnvelope(t *testing.T) {
	profileEnvironment := map[string]string{"APP_MODE": "test", "PROFILE_FIELD": "profile-value"}
	authorityEnvironment := map[string]string{
		codexCLIPathEnvKey:                    "/usr/local/bin/codex",
		codexCredentialSourceEnvKey:           codexCredentialSourceWorkloadVault,
		codexCredentialVaultSecretPathEnvKey:  "proof-secrets/data/codex-runtime-profile",
		codexCredentialVaultSecretFieldEnvKey: "api_key",
	}
	facts := resolvedPlanFacts{
		requestSchemaVersion:    "v1",
		invocationSchemaVersion: "v1",
		mode:                    ExecutionModeAsync,
		timeoutSeconds:          17,
		resources:               resolvedTaskResources{cpu: 23, memoryMB: 257},
		runtimeProfile: resolvedRuntimeProfile{
			name:  runtimeProfileControlPlaneNormalShell,
			image: "execution-substrate/control-plane-normal-shell:test",
		},
		artifactDigest:       labeledDigest("11"),
		payloadDigest:        labeledDigest("55"),
		derivationSpecDigest: labeledDigest("22"),
		outputID:             "runtime",
		runtimeCommand:       resolvedRuntimeCommand{executable: executionRuntimeSupportPath, arguments: []string{"supervisor", "--timeout-seconds", "17", "--", "--work"}},
		semanticEnvironment:  profileEnvironment,
		mounts: []resolvedMountPlan{{
			artifactDigest: labeledDigest("33"),
			targetPath:     "/execution/mounts/config",
			readOnly:       true,
		}},
		networkAccess: true,
		authority: resolvedAuthorityPlan{
			runtimeProfileName:            runtimeProfileControlPlaneNormalShell,
			codexCredential:               resolveCodexCredentialLocation(authorityEnvironment),
			workloadZoneVaultConfigDigest: testWorkloadZoneVaultConfigDigest,
			trustMaterial: stagedWorkloadTrustMaterial{
				vaultCACert:       true,
				workloadTLSBundle: true,
			},
		},
		runtimeSupportDigest:     labeledDigest("44"),
		runtimeIdentityTmpfsSize: 2 << 20,
		jobEnvelope: resolvedJobEnvelope{
			jobType:         "batch",
			groupName:       "group",
			groupCount:      1,
			taskName:        "task",
			driver:          "docker",
			user:            "0:0",
			privileged:      false,
			securityOptions: []string{"no-new-privileges"},
			restartPolicy: resolvedRestartPolicy{
				attempts: 0,
				mode:     "fail",
				interval: int64(60_000_000_000),
				delay:    int64(10_000_000_000),
			},
			reschedulePolicy: resolvedReschedulePolicy{
				attempts:      0,
				unlimited:     false,
				delayFunction: "constant",
			},
		},
	}
	plan := newResolvedExecutionPlan(facts)
	profileEnvironment["PROFILE_FIELD"] = "mutated"
	authorityEnvironment[codexCLIPathEnvKey] = "mutated"

	if plan.requestSchemaVersion != "v1" || plan.invocationSchemaVersion != "v1" || plan.mode != ExecutionModeAsync || plan.timeoutSeconds != 17 {
		t.Fatal("resolved plan lost request schema, invocation schema, mode, or timeout category")
	}
	if plan.resources.cpu != 23 || plan.resources.memoryMB != 257 || plan.runtimeProfile.name != runtimeProfileControlPlaneNormalShell {
		t.Fatal("resolved plan lost CPU, memory, or runtime-profile category")
	}
	if plan.artifactDigest != labeledDigest("11") || plan.payloadDigest != labeledDigest("55") || plan.derivationSpecDigest != labeledDigest("22") || plan.outputID != "runtime" {
		t.Fatal("resolved plan lost artifact, payload, derivation, or output identity category")
	}
	if plan.runtimeCommand.executable != executionRuntimeSupportPath || len(plan.runtimeCommand.arguments) != 5 || len(plan.semanticEnvironment) != 2 || len(plan.mounts) != 1 {
		t.Fatal("resolved plan lost command, complete arguments, environment, or mount category")
	}
	if !plan.networkAccess || plan.authority.runtimeProfileName == "" {
		t.Fatal("resolved plan lost network posture or structurally applicable authority handoff")
	}
	if plan.runtimeProfile.image == "" || plan.jobEnvelope.driver != "docker" || plan.jobEnvelope.user != "0:0" || plan.jobEnvelope.privileged {
		t.Fatal("resolved plan lost selected image, driver, user, or privilege envelope facts")
	}
	if len(plan.jobEnvelope.securityOptions) != 1 || plan.jobEnvelope.restartPolicy.mode != "fail" || plan.jobEnvelope.reschedulePolicy.delayFunction != "constant" {
		t.Fatal("resolved plan lost security, restart, or reschedule envelope facts")
	}
	if plan.runtimeIdentityTmpfsSize != 2<<20 || plan.runtimeSupportDigest != labeledDigest("44") {
		t.Fatal("resolved plan lost runtime-identity placement or runtime-support identity")
	}
	if plan.semanticEnvironment["PROFILE_FIELD"] != "profile-value" || plan.authority.codexCredential.cliPath != "/usr/local/bin/codex" {
		t.Fatal("resolved plan retained a mutable runtime-profile environment alias")
	}
}

func TestResolvedExecutionAdmissionDefaultsOnlyTheOwnedSnapshot(t *testing.T) {
	request := PrepareRequest{
		Invocation: ArtifactInvocation{
			ArtifactDigest:       labeledDigest("11"),
			DerivationSpecDigest: labeledDigest("22"),
			OutputID:             "runtime",
			Argv:                 []string{},
			Env:                  map[string]string{},
			Mounts:               []RuntimeMount{},
			Annotations:          map[string]string{},
		},
	}
	owned := snapshotAdmissionRequest(request)
	if err := validatePrepareRequest(&owned); err != nil {
		t.Fatal("owned admission snapshot did not accept current schema defaults")
	}
	if owned.SchemaVersion != "v1" || owned.Invocation.SchemaVersion != "v1" {
		t.Fatal("owned admission snapshot did not retain current schema defaults")
	}
	if request.SchemaVersion != "" || request.Invocation.SchemaVersion != "" {
		t.Fatal("admission defaulting mutated the caller request")
	}
	if owned.Invocation.Argv == nil || owned.Invocation.Env == nil || owned.Invocation.Mounts == nil || owned.Invocation.Annotations == nil {
		t.Fatal("schema defaulting collapsed concrete empty invocation collections")
	}
}

func TestResolvedExecutionTrustAndConfigSnapshotsOwnMutableInputs(t *testing.T) {
	trust := egsmodel.RuntimeTrustPolicy{
		SignerPolicy: egsmodel.SignerPolicy{
			AllowedSigners: []string{"allowed"},
			RevokedSigners: []string{"revoked"},
		},
		ArtifactPolicy: egsmodel.ArtifactPolicy{RevokedArtifacts: []string{labeledDigest("11")}},
	}
	trustSnapshot := snapshotRuntimeTrustModel(trust)
	trust.SignerPolicy.AllowedSigners[0] = "mutated"
	trust.SignerPolicy.RevokedSigners[0] = "mutated"
	trust.ArtifactPolicy.RevokedArtifacts[0] = labeledDigest("99")
	if trustSnapshot.SignerPolicy.AllowedSigners[0] != "allowed" || trustSnapshot.SignerPolicy.RevokedSigners[0] != "revoked" || trustSnapshot.ArtifactPolicy.RevokedArtifacts[0] != labeledDigest("11") {
		t.Fatal("trust snapshot retained mutable policy slice aliases")
	}

	config := esconfig.Config{
		Execution: esconfig.ExecutionConfig{
			StagingRootDir:             "/stage-a",
			ResultsRootDir:             "/results-a",
			BaseImage:                  "base-a",
			RuntimeSupportBinary:       "/support-a",
			SPIREWorkloadAPISocketPath: "/run/spire/a.sock",
			RuntimeIdentityTmpfsSize:   2 << 20,
		},
		Nomad: esconfig.NomadConfig{Datacenter: " dc-a "},
	}
	configSnapshot := newSubmitConfigSnapshot(config)
	config.Execution.StagingRootDir = "/stage-b"
	config.Execution.BaseImage = "base-b"
	config.Execution.RuntimeSupportBinary = "/support-b"
	config.Nomad.Datacenter = "dc-b"
	if configSnapshot.stagingRootDir != "/stage-a" || configSnapshot.baseImage != "base-a" || configSnapshot.runtimeSupportBinary != "/support-a" || configSnapshot.datacenter != " dc-a " {
		t.Fatal("submit/config snapshot did not retain its captured facts")
	}
}

func TestResolvedExecutionMaterialOwnsBytesBeforeHostMaterialization(t *testing.T) {
	stagingRoot := physicalTestTempDir(t)
	resultsRoot := physicalTestTempDir(t)
	payload := []byte("captured-payload")
	runtimeSupport := []byte("captured-runtime-support")
	mountCompressed := []byte("captured-compressed-mount")
	mountContents := []byte("captured-mount-entry")
	vaultCA := []byte("captured-vault-ca")
	combinedTrust := []byte("captured-combined-trust")
	mounts := []validatedMountArchive{{
		compressedBytes: mountCompressed,
		entries: []validatedMountEntry{{
			name:     "config.txt",
			mode:     stableStageFileMode,
			contents: mountContents,
		}},
	}}
	facts := resolvedMaterialFacts{
		payloadBytes:        payload,
		runtimeSupportBytes: runtimeSupport,
		mounts:              mounts,
		trust: resolvedTrustMaterial{
			vaultCACertBytes:       vaultCA,
			workloadTLSBundleBytes: combinedTrust,
		},
	}
	material, materialErr := newResolvedExecutionMaterial(&facts)
	if materialErr != nil {
		t.Fatal("transfer resolved material ownership failed")
	}
	if facts.payloadBytes != nil || facts.runtimeSupportBytes != nil || facts.mounts != nil || facts.trust.vaultCACertBytes != nil || facts.trust.workloadTLSBundleBytes != nil {
		t.Fatal("resolved material facts retained ownership after transfer")
	}
	if &material.payloadBytes[0] != &payload[0] || &material.runtimeSupportBytes[0] != &runtimeSupport[0] || &material.mounts[0].compressedBytes[0] != &mountCompressed[0] || &material.mounts[0].entries[0].contents[0] != &mountContents[0] || &material.trust.vaultCACertBytes[0] != &vaultCA[0] || &material.trust.workloadTLSBundleBytes[0] != &combinedTrust[0] {
		t.Fatal("resolved material transfer introduced an avoidable bulk copy")
	}

	assertDirectoryEmpty(t, stagingRoot)
	host := newHostMaterializationContext(stagingRoot, resultsRoot, executionPlatformStateOwner{UID: os.Getuid(), GID: os.Getgid()}, "/run/spire/sockets", "dc1")
	run := newResolvedRunProjection(newResolvedExecutionPlan(resolvedPlanFacts{
		mounts: []resolvedMountPlan{{targetPath: "/execution/mounts/config", readOnly: true}},
	}), host, newExecutionLocatorFromRunID("run-0123456789abcdef"))
	custody, claimErr := claimStagingCustody(stagingRoot, run.runID, host.owner)
	if claimErr != nil {
		t.Fatal("claim staging custody failed")
	}
	defer custody.close()
	stage, err := materializeExecutionInputs(custody, run, material)
	if err != nil {
		t.Fatal("materialize captured execution inputs failed")
	}

	stagedPayload, readPayloadErr := os.ReadFile(stage.layout.payloadArchivePath)
	if readPayloadErr != nil {
		t.Fatal("read staged payload failed")
	}
	stagedSupport, readSupportErr := os.ReadFile(stage.layout.runtimeSupportPath)
	if readSupportErr != nil {
		t.Fatal("read staged runtime support failed")
	}
	if string(stagedPayload) != "captured-payload" || string(stagedSupport) != "captured-runtime-support" {
		t.Fatal("materialization did not use captured payload and runtime-support ownership")
	}
	stagedMount, readMountErr := os.ReadFile(filepath.Join(stage.mounts[0].sourceDir, "config.txt"))
	if readMountErr != nil || !bytes.Equal(stagedMount, []byte("captured-mount-entry")) {
		t.Fatal("materialization did not use captured parsed mount-entry ownership")
	}
	stagedVault, readVaultErr := os.ReadFile(stage.layout.workloadVaultCACertStagePath())
	stagedCombined, readCombinedErr := os.ReadFile(stage.layout.workloadTLSBundleStagePath())
	if readVaultErr != nil || readCombinedErr != nil || !bytes.Equal(stagedVault, []byte("captured-vault-ca")) || !bytes.Equal(stagedCombined, []byte("captured-combined-trust")) {
		t.Fatal("materialization did not use captured trust-byte ownership")
	}
}

func TestResolvedExecutionPrepareAdmissionRetainsExactVaultReferenceAndAdmittedRequest(t *testing.T) {
	fixture := newPreparedArtifactFixture(t)
	service, _, _ := newWorkstreamCTestService(t, fixture)
	request := fixture.prepareRequest()
	request.SchemaVersion = ""
	request.Invocation.SchemaVersion = ""
	request.Invocation.Argv = []string{"first"}
	policyPayload := buildAdmissionPolicyStaticScriptArchive(t, map[string][]byte{
		staticScriptEntrypointName: []byte(benignPolicyFixtureText()),
	})
	originalRef := service.workloadZoneVaultConfigRef
	mutatedDigest := labeledDigest("99")

	service.arsClient = newResolvedPlanDependencyClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/artifacts/" + fixture.discovery.Artifact.ArtifactDigest + "/discovery":
			writeJSONResponse(t, w, http.StatusOK, fixture.discovery)
		case "/v1/blobs/" + fixture.discovery.Evidence.Digest + ":json":
			writeJSONResponse(t, w, http.StatusOK, fixture.evidence)
		case "/v1/blobs/" + originalRef.Digest + ":json":
			_, _ = w.Write([]byte(validWorkloadZoneVaultConfigBlob))
			service.workloadZoneVaultConfigRef.Digest = mutatedDigest
			service.cfg.RuntimeConfig.WorkloadZoneVaultConfigRef.Digest = mutatedDigest
		case "/v1/blobs/" + fixture.discovery.Payload.Digest + ":bytes":
			_, _ = w.Write(policyPayload)
		default:
			t.Fatalf("prepare reached unexpected ARS path %q", r.URL.Path)
		}
	}))

	prepared, admissionErr := service.prepareAdmission(context.Background(), request, admissionIntentPrepare)
	if admissionErr != nil {
		t.Fatal("prepare admission failed")
	}
	request.Invocation.Argv[0] = "mutated"
	if prepared.workloadZoneVaultConfigRef.Digest != originalRef.Digest {
		t.Fatalf("prepared admission lost exact successful Vault ref: got %q want %q", prepared.workloadZoneVaultConfigRef.Digest, originalRef.Digest)
	}
	if prepared.admittedRequest.Invocation.Argv[0] != "first" {
		t.Fatal("prepared admission retained a mutable caller request alias")
	}
	if prepared.admittedRequest.SchemaVersion != "v1" || prepared.admittedRequest.Invocation.SchemaVersion != "v1" || request.SchemaVersion != "" || request.Invocation.SchemaVersion != "" {
		t.Fatal("prepare admission did not default only its owned request snapshot")
	}
	if prepared.workloadZoneVaultConfigRef.Digest == service.cfg.RuntimeConfig.WorkloadZoneVaultConfigRef.Digest {
		t.Fatal("prepared admission re-derived the Vault ref from later mutable config")
	}
}

func TestSubmitStopsBeforeFreezeWithoutRunOrFilesystemEffects(t *testing.T) {
	fixture := newPreparedArtifactFixture(t)
	service, stagingRoot, resultsRoot := newWorkstreamCTestService(t, fixture)
	request := fixture.prepareRequest()
	request.Mode = ExecutionModeAsync
	policyPayload := buildAdmissionPolicyStaticScriptArchive(t, map[string][]byte{
		staticScriptEntrypointName: []byte(benignPolicyFixtureText()),
	})
	service.cfg.Execution.RuntimeSupportBinary = filepath.Join(physicalTestTempDir(t), "missing-runtime-support")
	service.arsClient = newResolvedPlanDependencyClient(t, resolvedPlanArtifactHandler(t, fixture, policyPayload, nil))
	nomadCalls := 0
	service.nomadClient = newResolvedPlanNomadClient(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		nomadCalls++
	}))

	result, submitErr := service.Submit(context.Background(), request)
	if submitErr == nil || submitErr.Status != http.StatusInternalServerError || submitErr.Code != codeSubmissionFailed || submitErr.Message != "stage artifact payload failed" {
		t.Fatal("runtime-support capture failure did not preserve the fixed submit failure")
	}
	if result.RunID != "" || result.Submitted || nomadCalls != 0 {
		t.Fatal("pre-freeze failure assigned a run, returned submission, or called Nomad")
	}
	assertDirectoryEmpty(t, stagingRoot)
	assertDirectoryEmpty(t, resultsRoot)
}

func TestSubmitAmbiguousNomadFailurePreservesPrimaryErrorAndRetainsRoot(t *testing.T) {
	fixture := newPreparedArtifactFixture(t)
	service, stagingRoot, resultsRoot := newWorkstreamCTestService(t, fixture)
	for _, root := range []string{stagingRoot, resultsRoot} {
		if err := os.Chown(root, os.Getuid(), os.Getgid()); err != nil {
			t.Fatalf("align golden fixture owner with process identity: %v", err)
		}
	}
	request := fixture.prepareRequest()
	request.Mode = ExecutionModeAsync
	policyPayload := buildAdmissionPolicyStaticScriptArchive(t, map[string][]byte{
		staticScriptEntrypointName: []byte(benignPolicyFixtureText()),
	})
	service.arsClient = newResolvedPlanDependencyClient(t, resolvedPlanArtifactHandler(t, fixture, policyPayload, nil))
	var runID string
	service.nomadClient = newResolvedPlanNomadClient(t, http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		var submitted resolvedNomadFixture
		body, err := io.ReadAll(request.Body)
		if err != nil || json.Unmarshal(body, &submitted) != nil {
			t.Fatal("decode submitted Nomad job failed")
		}
		runID = submitted.Job.Meta["run_id"]
		outside := filepath.Join(stagingRoot, "outside")
		if err := os.WriteFile(outside, []byte("retain"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(outside, filepath.Join(stagingRoot, runID, "ambiguous-link")); err != nil {
			t.Fatal(err)
		}
		w.WriteHeader(http.StatusServiceUnavailable)
	}))

	result, submitErr := service.Submit(context.Background(), request)
	if result.Submitted || result.RunID != "" {
		t.Fatal("failed submit returned a successful receipt")
	}
	if submitErr == nil || submitErr.Status != http.StatusServiceUnavailable || submitErr.Code != codeSubmissionFailed {
		t.Fatalf("ambiguous Nomad failure did not preserve the primary error class: %+v", submitErr)
	}
	if runID == "" {
		t.Fatal("Nomad failure hook did not observe the run id")
	}
	if _, err := os.Lstat(filepath.Join(stagingRoot, runID, "ambiguous-link")); err != nil {
		t.Fatalf("ambiguous root was moved, descended, or deleted: %v", err)
	}
}

func TestResolvedSubmitLegacyEquivalenceOneNomadRegistrationAndAuthorityRecovery(t *testing.T) {
	fixture := newPreparedArtifactFixture(t)
	service, _, _ := newWorkstreamCTestService(t, fixture)
	request := fixture.prepareRequest()
	request.TimeoutSeconds = 17
	request.Resources = nil
	request.Invocation.Argv = []string{"--flag"}
	policyPayload := buildAdmissionPolicyStaticScriptArchive(t, map[string][]byte{
		staticScriptEntrypointName: []byte(benignPolicyFixtureText()),
	})
	originalVaultRef := service.workloadZoneVaultConfigRef
	service.arsClient = newResolvedPlanDependencyClient(t, resolvedPlanArtifactHandler(t, fixture, policyPayload, func() {
		service.workloadZoneVaultConfigRef.Digest = labeledDigest("99")
		service.cfg.RuntimeConfig.WorkloadZoneVaultConfigRef.Digest = labeledDigest("99")
	}))

	nomadCalls := 0
	var submitted resolvedNomadFixture
	service.nomadClient = newResolvedPlanNomadClient(t, http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		nomadCalls++
		body, readErr := io.ReadAll(request.Body)
		if readErr != nil || json.Unmarshal(body, &submitted) != nil {
			t.Fatal("submitted Nomad fixture could not be decoded")
		}
		_, _ = w.Write([]byte(`{"EvalID":"eval-123"}`))
	}))

	result, submitErr := service.Submit(context.Background(), request)
	if submitErr != nil {
		t.Fatal("resolved legacy submit failed")
	}
	if nomadCalls != 1 || !result.Success || !result.Submitted || result.Status != executionLifecycleStatusSubmitted || result.RunID == "" || result.AuthorityHandoff == nil {
		t.Fatal("resolved legacy submit changed the one-call receipt contract")
	}
	if submitted.Job.ID != "exec-"+result.RunID || submitted.Job.Name != submitted.Job.ID || submitted.Job.Type != "batch" || len(submitted.Job.Datacenters) != 1 || submitted.Job.Datacenters[0] != "dc1" {
		t.Fatal("resolved legacy submit changed the job identity or envelope")
	}
	if submitted.Job.Meta["run_id"] != result.RunID || submitted.Job.Meta[executionAuthorityMetadataSchemaKey] != executionAuthorityMetadataSchemaVersion || submitted.Job.Meta[executionAuthorityMetadataRuntimeProfileKey] != runtimeProfileDefaultStaticScript || submitted.Job.Meta[executionAuthorityMetadataWorkloadZoneVaultConfigKey] != originalVaultRef.Digest {
		t.Fatal("resolved legacy submit changed job metadata")
	}
	if result.AuthorityHandoff.RuntimeConfigRefs.WorkloadZoneVaultConfig.Digest != originalVaultRef.Digest {
		t.Fatal("resolved legacy submit did not preserve the exact admitted Vault reference")
	}
	if len(submitted.Job.TaskGroups) != 1 {
		t.Fatal("resolved legacy submit changed task-group cardinality")
	}
	group := submitted.Job.TaskGroups[0]
	if group.Name != "group" || group.Count != 1 || group.RestartPolicy.Attempts != 0 || group.RestartPolicy.Mode != "fail" || group.RestartPolicy.Interval != int64(60_000_000_000) || group.RestartPolicy.Delay != int64(10_000_000_000) || group.ReschedulePolicy.Attempts != 0 || group.ReschedulePolicy.Unlimited || group.ReschedulePolicy.DelayFunction != "constant" {
		t.Fatal("resolved legacy submit changed restart or reschedule posture")
	}
	if len(group.Tasks) != 1 {
		t.Fatal("resolved legacy submit changed task cardinality")
	}
	task := group.Tasks[0]
	if task.Name != "task" || task.Driver != "docker" || task.User != "0:0" || task.Config.Image != "alpine:3.20" || task.Config.Command != executionRuntimeSupportPath || task.Config.Privileged || task.Config.NetworkMode != "bridge" {
		t.Fatal("resolved legacy submit changed task runtime selection or security posture")
	}
	if len(task.Config.SecurityOptions) != 1 || task.Config.SecurityOptions[0] != "no-new-privileges" || len(task.Config.Mounts) != 4 || len(task.Config.Arguments) != 13 || task.Config.Arguments[0] != "supervisor" || task.Config.Arguments[11] != "--" || task.Config.Arguments[12] != "--flag" {
		t.Fatal("resolved legacy submit changed task arguments, security options, or base mounts")
	}
	if task.Resources.CPU != defaultSubmitCPU || task.Resources.MemoryMB != defaultSubmitMemoryMB || task.Meta["run_id"] != result.RunID || task.Meta["artifact_digest"] != request.Invocation.ArtifactDigest || task.Meta["derivation_spec_digest"] != request.Invocation.DerivationSpecDigest || task.Meta["output_id"] != request.Invocation.OutputID {
		t.Fatal("resolved legacy submit changed resources or task metadata")
	}
	if task.Environment["APP_MODE"] != "test" || task.Environment["EXEC_RUN_ID"] != result.RunID || task.Environment["SERVICE_ID"] != "execution" || task.Environment["VAULT_ADDR"] != "https://vault.internal:8200" || task.Environment[runtimeIdentityEndpointEnvKey] == "" {
		t.Fatal("resolved legacy submit changed effective environment semantics")
	}
	recovered, ok := executionAuthorityHandoffFromSubmittedRuntimeSpec(
		submitted.Job.Meta[executionAuthorityMetadataRuntimeProfileKey],
		submitted.Job.Meta[executionAuthorityMetadataWorkloadZoneVaultConfigKey],
		task.Environment,
	)
	if !ok || !authorityHandoffsEquivalent(*result.AuthorityHandoff, *recovered) {
		t.Fatal("submit authority handoff and status reconstruction diverged")
	}
}

func TestResolvedSubmitLegacyEquivalenceEnvironmentPrecedence(t *testing.T) {
	owner := executionPlatformStateOwner{UID: os.Getuid(), GID: os.Getgid()}
	semanticEnvironment := resolvedSemanticRuntimeEnvironment(
		map[string]string{"SHARED": "invocation", "SERVICE_ID": "invocation-service"},
		map[string]string{"SHARED": "profile", "SERVICE_ID": "profile-service"},
		labeledDigest("11"),
		resolvedWorkloadVaultPlan{},
		stagedWorkloadTrustMaterial{},
	)
	plan := newResolvedExecutionPlan(resolvedPlanFacts{semanticEnvironment: semanticEnvironment})
	host := newHostMaterializationContext("/stage", "/results", owner, "/spire", "dc1")
	environment := newResolvedRunProjection(plan, host, newExecutionLocatorFromRunID("run-0123456789abcdef")).environment
	if environment["SHARED"] != "profile" || environment["SERVICE_ID"] != "execution" {
		t.Fatal("resolved environment changed invocation, profile, and platform precedence")
	}
}

func TestRuntimeSupportMaterialIdentityMatchesCapturedBytes(t *testing.T) {
	content := []byte("runtime-support-content")
	path := filepath.Join(physicalTestTempDir(t), "runtime-support")
	if err := os.WriteFile(path, content, 0o700); err != nil {
		t.Fatal("write runtime support fixture failed")
	}
	captured, identity, err := captureRuntimeSupport(path)
	if err != nil {
		t.Fatal("capture runtime support failed")
	}
	if err := os.WriteFile(path, []byte("mutated-runtime-support"), 0o700); err != nil {
		t.Fatal("mutate runtime support fixture failed")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal("remove runtime support fixture failed")
	}
	if identity != digestBytes(content) || string(captured) != string(content) {
		t.Fatal("runtime-support capture changed after source mutation and removal")
	}
	host := newHostMaterializationContext(physicalTestTempDir(t), physicalTestTempDir(t), executionPlatformStateOwner{UID: os.Getuid(), GID: os.Getgid()}, "/run/spire/sockets", "dc1")
	run := newResolvedRunProjection(newResolvedExecutionPlan(resolvedPlanFacts{}), host, newExecutionLocatorFromRunID("run-0123456789abcdef"))
	materialFacts := resolvedMaterialFacts{
		payloadBytes:        []byte("payload"),
		runtimeSupportBytes: captured,
	}
	material, materialErr := newResolvedExecutionMaterial(&materialFacts)
	if materialErr != nil {
		t.Fatal("construct captured runtime-support material failed")
	}
	custody, claimErr := claimStagingCustody(host.stagingRootDir, run.runID, host.owner)
	if claimErr != nil {
		t.Fatal("claim staging custody failed")
	}
	defer custody.close()
	stage, stageErr := materializeExecutionInputs(custody, run, material)
	if stageErr != nil {
		t.Fatal("captured runtime-support materialization failed")
	}
	staged, readErr := os.ReadFile(stage.layout.runtimeSupportPath)
	if readErr != nil || digestBytes(staged) != identity {
		t.Fatal("staged runtime-support bytes did not match the captured identity")
	}
}

func TestTrancheB1SemanticPlanIsHostInvariantAndHostProjectionIsFinite(t *testing.T) {
	facts := resolvedPlanFacts{
		requestSchemaVersion:    "v1",
		invocationSchemaVersion: "v1",
		mode:                    ExecutionModeAsync,
		timeoutSeconds:          17,
		resources:               resolvedTaskResources{cpu: 23, memoryMB: 257},
		runtimeProfile: resolvedRuntimeProfile{
			name:  runtimeProfileDefaultStaticScript,
			image: "alpine:3.20",
		},
		artifactDigest:           labeledDigest("11"),
		payloadDigest:            labeledDigest("22"),
		derivationSpecDigest:     labeledDigest("33"),
		outputID:                 "runtime",
		runtimeCommand:           newResolvedRuntimeCommand([]string{"first", "second"}, 17),
		semanticEnvironment:      map[string]string{"CALLER_SEMANTIC": "caller", "PROFILE_SEMANTIC": "profile"},
		mounts:                   []resolvedMountPlan{{artifactDigest: labeledDigest("55"), targetPath: "/workspace/config", readOnly: true}},
		networkAccess:            false,
		runtimeSupportDigest:     labeledDigest("44"),
		runtimeIdentityTmpfsSize: 2 << 20,
		authority: resolvedAuthorityPlan{
			runtimeProfileName: runtimeProfileDefaultStaticScript,
			workloadVault: resolvedWorkloadVaultPlan{
				mode:        string(esconfig.WorkloadVaultAuthModeVaultIdentityJWT),
				address:     "https://vault.internal:8200",
				authMount:   "jwt",
				authRole:    "execution",
				jwtAudience: "vault",
			},
			workloadZoneVaultConfigDigest: testWorkloadZoneVaultConfigDigest,
		},
		jobEnvelope: defaultResolvedJobEnvelope(),
	}
	plan := newResolvedExecutionPlan(facts)
	planBeforeProjection := newResolvedExecutionPlan(facts)
	baseHost := newHostMaterializationContext("/qualified/a/staging", "/qualified/a/results", executionPlatformStateOwner{UID: 111, GID: 222}, "/qualified/a/spire", "dc-a")
	locator := newExecutionLocatorFromRunID("run-0123456789abcdef")
	providerJob := func(host hostMaterializationContext) any {
		t.Helper()
		run := newResolvedRunProjection(plan, host, locator)
		stagedMounts := []stagedRuntimeMount{{sourceDir: run.layout.mountContentsDir(0), targetPath: "/workspace/config", readOnly: true}}
		return trancheB1GenericJSON(t, buildNomadJobSpec(run.nomadJobProjection(stagedMounts)))
	}
	baseJob := providerJob(baseHost)

	resultsA, err := normalizeSubmitPlacementFacts(submitConfigSnapshot{
		stagingRootDir:             baseHost.stagingRootDir,
		resultsRootDir:             "/qualified/a/results",
		spireWorkloadAPISocketPath: baseHost.spireSourceDir + "/agent.sock",
		datacenter:                 baseHost.datacenter,
	})
	if err != nil {
		t.Fatal(err)
	}
	resultsB, err := normalizeSubmitPlacementFacts(submitConfigSnapshot{
		stagingRootDir:             baseHost.stagingRootDir,
		resultsRootDir:             "/qualified/b/results",
		spireWorkloadAPISocketPath: baseHost.spireSourceDir + "/agent.sock",
		datacenter:                 baseHost.datacenter,
	})
	if err != nil {
		t.Fatal(err)
	}
	if resultsA.resultsRootDir == resultsB.resultsRootDir {
		t.Fatal("results-root service/custody dimension fixture did not vary")
	}

	for _, test := range []struct {
		name              string
		host              hostMaterializationContext
		wantHostDiffs     []string
		wantProviderDiffs []string
		resultsDimension  bool
	}{
		{
			name:          "staging root with governed mount",
			host:          newHostMaterializationContext("/qualified/b/staging", "/qualified/a/results", baseHost.owner, baseHost.spireSourceDir, baseHost.datacenter),
			wantHostDiffs: []string{"stagingRootDir"},
			wantProviderDiffs: []string{
				"/Job/TaskGroups/0/Tasks/0/Config/mounts/0/source",
				"/Job/TaskGroups/0/Tasks/0/Config/mounts/1/source",
				"/Job/TaskGroups/0/Tasks/0/Config/mounts/4/source",
			},
		},
		{
			name:              "owner UID",
			host:              newHostMaterializationContext(baseHost.stagingRootDir, "/qualified/a/results", executionPlatformStateOwner{UID: 333, GID: baseHost.owner.GID}, baseHost.spireSourceDir, baseHost.datacenter),
			wantHostDiffs:     []string{"owner.UID"},
			wantProviderDiffs: []string{"/Job/TaskGroups/0/Tasks/0/Env/EXEC_PLATFORM_STATE_OWNER_UID"},
		},
		{
			name:              "owner GID",
			host:              newHostMaterializationContext(baseHost.stagingRootDir, "/qualified/a/results", executionPlatformStateOwner{UID: baseHost.owner.UID, GID: 444}, baseHost.spireSourceDir, baseHost.datacenter),
			wantHostDiffs:     []string{"owner.GID"},
			wantProviderDiffs: []string{"/Job/TaskGroups/0/Tasks/0/Env/EXEC_PLATFORM_STATE_OWNER_GID"},
		},
		{
			name:              "SPIRE source",
			host:              newHostMaterializationContext(baseHost.stagingRootDir, "/qualified/a/results", baseHost.owner, "/qualified/b/spire", baseHost.datacenter),
			wantHostDiffs:     []string{"spireSourceDir"},
			wantProviderDiffs: []string{"/Job/TaskGroups/0/Tasks/0/Config/mounts/3/source"},
		},
		{
			name:              "Nomad datacenter",
			host:              newHostMaterializationContext(baseHost.stagingRootDir, "/qualified/a/results", baseHost.owner, baseHost.spireSourceDir, "dc-b"),
			wantHostDiffs:     []string{"datacenter"},
			wantProviderDiffs: []string{"/Job/Datacenters/0"},
		},
		{
			name:              "results root outside B1 provider binding",
			host:              newHostMaterializationContext(baseHost.stagingRootDir, resultsB.resultsRootDir, baseHost.owner, baseHost.spireSourceDir, baseHost.datacenter),
			wantHostDiffs:     []string{},
			wantProviderDiffs: []string{},
			resultsDimension:  true,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			if !reflect.DeepEqual(plan, planBeforeProjection) {
				t.Fatal("host dimension changed admitted semantic truth")
			}
			hostDiffs := trancheB1HostContextDifferences(baseHost, test.host)
			if !reflect.DeepEqual(hostDiffs, test.wantHostDiffs) {
				t.Fatalf("host-context differences = %v, want %v", hostDiffs, test.wantHostDiffs)
			}
			job := providerJob(test.host)
			providerDiffs := make([]string, 0)
			trancheB1JSONDifferences(baseJob, job, "", &providerDiffs)
			sort.Strings(providerDiffs)
			if !reflect.DeepEqual(providerDiffs, test.wantProviderDiffs) {
				t.Fatalf("provider JSON-pointer differences = %v, want %v", providerDiffs, test.wantProviderDiffs)
			}
			if test.resultsDimension && (!reflect.DeepEqual(baseHost, test.host) || !reflect.DeepEqual(baseJob, job)) {
				t.Fatal("results-root service/custody placement entered host context or provider projection")
			}
			// This no-leaf result is limited to the current host and provider JSON
			// shapes. It is not a claim of provider-effect or future binding equality.
		})
	}
}

func trancheB1HostContextDifferences(first hostMaterializationContext, second hostMaterializationContext) []string {
	differences := make([]string, 0)
	if first.stagingRootDir != second.stagingRootDir {
		differences = append(differences, "stagingRootDir")
	}
	if first.owner.UID != second.owner.UID {
		differences = append(differences, "owner.UID")
	}
	if first.owner.GID != second.owner.GID {
		differences = append(differences, "owner.GID")
	}
	if first.spireSourceDir != second.spireSourceDir {
		differences = append(differences, "spireSourceDir")
	}
	if first.datacenter != second.datacenter {
		differences = append(differences, "datacenter")
	}
	return differences
}

func TestTrancheB1QualifiedHostCaptureNormalizesEquivalentConfiguration(t *testing.T) {
	fixture := newPreparedArtifactFixture(t)
	service, stagingRoot, resultsRoot := newWorkstreamCTestService(t, fixture)
	policyPayload := buildAdmissionPolicyStaticScriptArchive(t, map[string][]byte{
		staticScriptEntrypointName: []byte(benignPolicyFixtureText()),
	})
	service.arsClient = newResolvedPlanDependencyClient(t, resolvedPlanArtifactHandler(t, fixture, policyPayload, nil))
	service.nomadClient = newResolvedPlanNomadClient(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))

	canonical, canonicalErr := service.resolveExecutionForSubmit(context.Background(), fixture.prepareRequest())
	if canonicalErr != nil {
		t.Fatalf("canonical host capture failed: %+v", canonicalErr)
	}
	service.cfg.Execution.StagingRootDir = "  " + filepath.Join(stagingRoot, "unused", "..") + "  "
	service.cfg.Execution.ResultsRootDir = "\t" + filepath.Join(resultsRoot, "unused", "..") + "\n"
	service.cfg.Execution.SPIREWorkloadAPISocketPath = "  /run/spire/sockets/../sockets/agent.sock  "
	service.cfg.Nomad.Datacenter = "  dc1\t"
	normalized, normalizedErr := service.resolveExecutionForSubmit(context.Background(), fixture.prepareRequest())
	if normalizedErr != nil {
		t.Fatalf("whitespace/path-cleaning host capture failed: %+v", normalizedErr)
	}
	if !reflect.DeepEqual(canonical.plan, normalized.plan) {
		t.Fatal("equivalent host configuration changed admitted semantic truth")
	}
	if !reflect.DeepEqual(canonical.host, normalized.host) {
		t.Fatalf("equivalent host configuration produced distinct contexts: canonical=%+v normalized=%+v", canonical.host, normalized.host)
	}
	locator := newExecutionLocatorFromRunID("run-0123456789abcdef")
	canonicalJob := trancheB1GenericJSON(t, buildNomadJobSpec(newResolvedRunProjection(canonical.plan, canonical.host, locator).nomadJobProjection(nil)))
	normalizedJob := trancheB1GenericJSON(t, buildNomadJobSpec(newResolvedRunProjection(normalized.plan, normalized.host, locator).nomadJobProjection(nil)))
	if !reflect.DeepEqual(canonicalJob, normalizedJob) {
		t.Fatal("equivalent host configuration changed provider values")
	}
	if normalized.host.stagingRootDir != filepath.Clean(stagingRoot) || !filepath.IsAbs(normalized.host.spireSourceDir) || normalized.host.spireSourceDir != "/run/spire/sockets" || normalized.host.datacenter != "dc1" {
		t.Fatalf("captured host values were not normalized and absolute: %+v", normalized.host)
	}
}

func TestTrancheB1QualifiedHostCaptureRejectsEmptyOrRelativeFacts(t *testing.T) {
	base := submitConfigSnapshot{
		stagingRootDir:             "/stage",
		resultsRootDir:             "/results",
		spireWorkloadAPISocketPath: "/run/spire/agent.sock",
		datacenter:                 "dc1",
	}
	for _, test := range []struct {
		name   string
		mutate func(*submitConfigSnapshot)
	}{
		{"empty staging", func(value *submitConfigSnapshot) { value.stagingRootDir = " \t " }},
		{"relative staging", func(value *submitConfigSnapshot) { value.stagingRootDir = "stage" }},
		{"empty results", func(value *submitConfigSnapshot) { value.resultsRootDir = " " }},
		{"relative results", func(value *submitConfigSnapshot) { value.resultsRootDir = "results" }},
		{"empty SPIRE socket", func(value *submitConfigSnapshot) { value.spireWorkloadAPISocketPath = " " }},
		{"relative SPIRE socket", func(value *submitConfigSnapshot) { value.spireWorkloadAPISocketPath = "run/spire/agent.sock" }},
		{"empty datacenter", func(value *submitConfigSnapshot) { value.datacenter = " \n " }},
	} {
		t.Run(test.name, func(t *testing.T) {
			value := base
			test.mutate(&value)
			if _, err := normalizeSubmitPlacementFacts(value); err == nil {
				t.Fatal("invalid host placement fact was accepted")
			}
		})
	}
}

func TestTrancheB1PayloadDigestLineageIsDistinctPrivateAndPreEffect(t *testing.T) {
	fixture := newPreparedArtifactFixture(t)
	service, stagingRoot, resultsRoot := newWorkstreamCTestService(t, fixture)
	request := fixture.prepareRequest()
	policyPayload := buildAdmissionPolicyStaticScriptArchive(t, map[string][]byte{
		staticScriptEntrypointName: []byte(benignPolicyFixtureText()),
	})
	service.arsClient = newResolvedPlanDependencyClient(t, resolvedPlanArtifactHandler(t, fixture, policyPayload, nil))
	service.nomadClient = newResolvedPlanNomadClient(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("plan resolution must not register a Nomad job")
	}))

	resolved, resolveErr := service.resolveExecutionForSubmit(context.Background(), request)
	if resolveErr != nil {
		t.Fatalf("resolve execution for submit failed: %+v", resolveErr)
	}
	wantPayloadDigest := fixture.evidence.Claims.Package.Identity.PayloadDigest
	if resolved.plan.payloadDigest != wantPayloadDigest || wantPayloadDigest != fixture.discovery.Payload.Digest {
		t.Fatal("semantic plan payload digest did not come from the cross-checked discovery/evidence relationship")
	}
	if resolved.plan.payloadDigest == resolved.plan.artifactDigest || resolved.plan.payloadDigest == resolved.plan.derivationSpecDigest || resolved.plan.payloadDigest == resolved.plan.outputID {
		t.Fatal("payload identity was conflated with artifact, derivation, or output identity")
	}
	frozenPayloadDigest := resolved.plan.payloadDigest
	resolved.material.payloadBytes[0] ^= 0xff
	if resolved.plan.payloadDigest != frozenPayloadDigest {
		t.Fatal("raw material mutation changed the frozen payload identity")
	}
	run := newResolvedRunProjection(resolved.plan, resolved.host, newExecutionLocatorFromRunID("run-0123456789abcdef"))
	jobBytes, jobErr := json.Marshal(buildNomadJobSpec(run.nomadJobProjection(nil)))
	if jobErr != nil {
		t.Fatal(jobErr)
	}
	handoffBytes, handoffErr := json.Marshal(buildResolvedExecutionAuthorityHandoff(run.authorityHandoff))
	if handoffErr != nil {
		t.Fatal(handoffErr)
	}
	if bytes.Contains(jobBytes, []byte(frozenPayloadDigest)) || bytes.Contains(handoffBytes, []byte(frozenPayloadDigest)) {
		t.Fatal("private payload identity widened into the Nomad or public authority projection")
	}
	assertDirectoryEmpty(t, stagingRoot)
	assertDirectoryEmpty(t, resultsRoot)

	mismatchedDiscovery := fixture.discovery
	mismatchedDiscovery.Payload.Digest = fixture.evidence.Claims.Package.Identity.ArtifactDigest
	_, mismatchErr := service.prepareArtifactFromDiscovery(request, fixture.trustModel, discoveredArtifact{
		discovery: mismatchedDiscovery,
		evidence:  fixture.evidence,
	})
	if mismatchErr == nil || mismatchErr.Code != codeArtifactEvidenceInvalid || !strings.Contains(mismatchErr.Message, "payload reference does not match artifact evidence") {
		t.Fatalf("payload mismatch did not stop before effects: %+v", mismatchErr)
	}
	assertDirectoryEmpty(t, stagingRoot)
	assertDirectoryEmpty(t, resultsRoot)
}

func TestResolvedMountProvenanceCarriesSignedPayloadDigest(t *testing.T) {
	fixture := newPreparedArtifactFixture(t)
	policyPayload := buildAdmissionPolicyStaticScriptArchive(t, map[string][]byte{
		staticScriptEntrypointName: []byte(benignPolicyFixtureText()),
	})
	a2BindSignedPayload(t, &fixture, policyPayload)
	service, stagingRoot, resultsRoot := newWorkstreamCTestService(t, fixture)
	request := fixture.prepareRequest()
	request.Invocation.Mounts = []RuntimeMount{
		{Source: MountSource{ArtifactDigest: fixture.discovery.Artifact.ArtifactDigest}, TargetPath: "/execution/mounts/first", ReadOnly: true},
		{Source: MountSource{ArtifactDigest: fixture.discovery.Artifact.ArtifactDigest}, TargetPath: "/execution/mounts/second", ReadOnly: true},
	}

	readCounts := make(map[string]int)
	baseHandler := resolvedPlanArtifactHandler(t, fixture, policyPayload, nil)
	service.arsClient = newResolvedPlanDependencyClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		readCounts[r.URL.Path]++
		baseHandler.ServeHTTP(w, r)
	}))
	service.nomadClient = newResolvedPlanNomadClient(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("source resolver must not register a Nomad job")
	}))

	resolved, resolveErr := service.resolveExecutionForSubmit(context.Background(), request)
	if resolveErr != nil {
		t.Fatalf("resolve signed multiple mounts: %+v", resolveErr)
	}
	if len(resolved.plan.mounts) != 2 || len(resolved.material.mounts) != 2 {
		t.Fatal("resolved mount plan and material cardinality diverged")
	}
	for index := range resolved.plan.mounts {
		mount := resolved.plan.mounts[index]
		if mount.artifactDigest != request.Invocation.Mounts[index].Source.ArtifactDigest ||
			mount.verifiedArtifactDigest != fixture.evidence.Claims.Package.Identity.ArtifactDigest ||
			mount.payloadDigest != fixture.evidence.Claims.Package.Identity.PayloadDigest {
			t.Fatalf("mount %d did not retain distinct requested, signed artifact and signed payload provenance", index)
		}
		if !bytes.Equal(resolved.material.mounts[index].compressedBytes, policyPayload) {
			t.Fatalf("mount %d lost the captured compressed payload", index)
		}
	}
	request.Invocation.Mounts[0].Source.ArtifactDigest = labeledDigest("99")
	if resolved.plan.mounts[0].artifactDigest != fixture.discovery.Artifact.ArtifactDigest {
		t.Fatal("frozen requested mount identity followed caller mutation")
	}
	for path, want := range map[string]int{
		"/v1/artifacts/" + fixture.discovery.Artifact.ArtifactDigest + "/discovery": 3,
		"/v1/blobs/" + fixture.discovery.Evidence.Digest + ":json":                  3,
		"/v1/blobs/" + fixture.discovery.Payload.Digest + ":bytes":                  3,
		"/v1/blobs/" + testWorkloadZoneVaultConfigDigest + ":json":                  1,
	} {
		if readCounts[path] != want {
			t.Fatalf("source resolver acquisition count for %s = %d, want %d", path, readCounts[path], want)
		}
		delete(readCounts, path)
	}
	if len(readCounts) != 0 {
		t.Fatalf("source resolver made unexpected artifact reads: %v", readCounts)
	}
	assertDirectoryEmpty(t, stagingRoot)
	assertDirectoryEmpty(t, resultsRoot)
}

func TestTrancheB1PayloadDigestIsAbsentFromEveryCurrentProfileProjection(t *testing.T) {
	const payloadSentinel = "sha256:feedfacefeedfacefeedfacefeedfacefeedfacefeedfacefeedfacefeedface"
	profiles := []struct {
		name  string
		image string
		codex bool
	}{
		{runtimeProfileDefaultStaticScript, "alpine:3.20", false},
		{runtimeProfileControlPlaneNormalShell, "execution-substrate/control-plane-normal-shell:test", true},
	}
	if len(profiles) != 2 {
		t.Fatal("current admitted runtime-profile inventory changed")
	}
	for _, profile := range profiles {
		t.Run(profile.name, func(t *testing.T) {
			authority := resolvedAuthorityPlan{
				runtimeProfileName: profile.name,
				codexCredential: resolvedCodexCredentialLocation{
					applicable:       profile.codex,
					cliPath:          "/usr/local/bin/codex",
					credentialSource: codexCredentialSourceWorkloadVault,
					vaultSecretPath:  "secret/data/codex",
					vaultSecretField: "credentials",
				},
				workloadVault: resolvedWorkloadVaultPlan{
					mode:        string(esconfig.WorkloadVaultAuthModeVaultIdentityJWT),
					address:     "https://vault.internal:8200",
					authMount:   "jwt",
					authRole:    "execution",
					jwtAudience: "vault",
				},
				workloadZoneVaultConfigDigest: testWorkloadZoneVaultConfigDigest,
			}
			plan := newResolvedExecutionPlan(resolvedPlanFacts{
				payloadDigest:            payloadSentinel,
				runtimeProfile:           resolvedRuntimeProfile{name: profile.name, image: profile.image},
				runtimeCommand:           newResolvedRuntimeCommand(nil, 0),
				authority:                authority,
				runtimeIdentityTmpfsSize: 1 << 20,
				jobEnvelope:              defaultResolvedJobEnvelope(),
			})
			host := newHostMaterializationContext("/stage", "/results", executionPlatformStateOwner{UID: 1, GID: 2}, "/run/spire", "dc1")
			run := newResolvedRunProjection(plan, host, newExecutionLocatorFromRunID("run-0123456789abcdef"))
			job := buildNomadJobSpec(run.nomadJobProjection(nil))
			handoff := buildResolvedExecutionAuthorityHandoff(run.authorityHandoff)
			receipt := SubmitResult{Success: true, Submitted: true, RunID: run.runID, Status: executionLifecycleStatusSubmitted, AuthorityHandoff: &handoff}
			publicDTOs := []any{
				PrepareResult{Success: true},
				receipt,
				ExecutionStatusResult{Success: true, RunID: run.runID, AuthorityHandoff: &handoff},
				ExecutionCancelResult{Success: true, RunID: run.runID},
				ExecutionLogsResult{},
				ExecutionResultBundle{},
				ErrorResponse{},
				ProducerContractDeclaration{},
			}
			jobRoot := job["Job"].(map[string]any)
			group := jobRoot["TaskGroups"].([]any)[0].(map[string]any)
			task := group["Tasks"].([]any)[0].(map[string]any)
			for name, value := range map[string]any{
				"complete Nomad job": job,
				"Nomad metadata":     jobRoot["Meta"],
				"environment":        task["Env"],
				"authority handoff":  handoff,
				"public receipt":     receipt,
				"public DTO set":     publicDTOs,
			} {
				encoded, err := json.Marshal(value)
				if err != nil {
					t.Fatalf("marshal %s: %v", name, err)
				}
				if bytes.Contains(encoded, []byte(payloadSentinel)) {
					t.Fatalf("private payload digest escaped through %s", name)
				}
			}
		})
	}
}

func TestTrancheB1AdmissionOwnedCopyIsolatesPostCopyCallerMutation(t *testing.T) {
	fixture := newPreparedArtifactFixture(t)
	service, _, _ := newWorkstreamCTestService(t, fixture)
	request := fixture.prepareRequest()
	request.SchemaVersion = ""
	request.Invocation.SchemaVersion = ""
	request.Invocation.Argv = []string{"first"}
	request.Invocation.Env = map[string]string{"APP_MODE": "test"}
	policyPayload := buildAdmissionPolicyStaticScriptArchive(t, map[string][]byte{
		staticScriptEntrypointName: []byte(benignPolicyFixtureText()),
	})
	service.arsClient = newResolvedPlanDependencyClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/artifacts/"+fixture.discovery.Artifact.ArtifactDigest+"/discovery" {
			request.Invocation.Argv[0] = "mutated-after-owned-copy"
			request.Invocation.Env["APP_MODE"] = "mutated-after-owned-copy"
		}
		resolvedPlanArtifactHandler(t, fixture, policyPayload, nil).ServeHTTP(w, r)
	}))
	prepared, admissionErr := service.prepareAdmission(context.Background(), request, admissionIntentSubmit)
	if admissionErr != nil {
		t.Fatalf("submit-intent admission failed: %+v", admissionErr)
	}
	if prepared.admittedRequest.Mode != ExecutionModeAsync || request.Mode != "" {
		t.Fatal("submit intent did not default only the admission-owned request")
	}
	if prepared.admittedRequest.SchemaVersion != "v1" || prepared.admittedRequest.Invocation.SchemaVersion != "v1" {
		t.Fatal("admission-owned request did not retain schema defaults")
	}
	if prepared.admittedRequest.Invocation.Argv[0] != "first" || prepared.admittedRequest.Invocation.Env["APP_MODE"] != "test" {
		t.Fatal("caller mutation after the owned copy changed the frozen admitted snapshot")
	}

	prepareService, _, _ := newWorkstreamCTestService(t, fixture)
	prepareService.arsClient = newResolvedPlanDependencyClient(t, resolvedPlanArtifactHandler(t, fixture, policyPayload, nil))
	prepareRequest := fixture.prepareRequest()
	prepareRequest.Mode = ExecutionModeSync
	preparedForPrepare, prepareErr := prepareService.prepareAdmission(context.Background(), prepareRequest, admissionIntentPrepare)
	if prepareErr != nil || preparedForPrepare.admittedRequest.Mode != ExecutionModeSync {
		t.Fatalf("Prepare intent changed its existing mode behavior: prepared=%v err=%+v", preparedForPrepare.admittedRequest.Mode, prepareErr)
	}

	unsupportedService, _, _ := newWorkstreamCTestService(t, fixture)
	dependencyCalls := 0
	unsupportedService.arsClient = newResolvedPlanDependencyClient(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		dependencyCalls++
	}))
	unsupportedService.nomadClient = newResolvedPlanNomadClient(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("unsupported mode must not reach Nomad")
	}))
	unsupported := fixture.prepareRequest()
	unsupported.Mode = ExecutionModeSync
	_, unsupportedErr := unsupportedService.Submit(context.Background(), unsupported)
	if unsupportedErr == nil || unsupportedErr.Status != http.StatusBadRequest || unsupportedErr.Code != codeUnsupportedExecutionMode || unsupportedErr.Message != "only async submission is supported in this execution slice" || dependencyCalls != 0 {
		t.Fatalf("unsupported Submit mode changed error or dependency-I/O precedence: err=%+v calls=%d", unsupportedErr, dependencyCalls)
	}
	unsupportedService.nomadClient = nil
	_, unavailableErr := unsupportedService.Submit(context.Background(), unsupported)
	if unavailableErr == nil || unavailableErr.Code != codeExecutionRuntimeUnavailable {
		t.Fatalf("runtime-unavailable precedence changed: %+v", unavailableErr)
	}
}

func TestTrancheB1AuthorityApplicabilityIsStructuralForCurrentProfiles(t *testing.T) {
	profiles := []struct {
		name               string
		profile            resolvedRuntimeProfile
		profileEnvironment map[string]string
		wantCodex          bool
	}{
		{
			name:    "default static script",
			profile: resolvedRuntimeProfile{name: runtimeProfileDefaultStaticScript, image: "alpine:3.20"},
		},
		{
			name: "control plane normal shell",
			profile: resolvedRuntimeProfile{
				name:  runtimeProfileControlPlaneNormalShell,
				image: "execution-substrate/control-plane-normal-shell:test",
			},
			profileEnvironment: map[string]string{
				codexCLIPathEnvKey:                    "/usr/local/bin/codex",
				codexCredentialSourceEnvKey:           codexCredentialSourceWorkloadVault,
				codexCredentialVaultSecretPathEnvKey:  "proof-secrets/data/codex-runtime-profile",
				codexCredentialVaultSecretFieldEnvKey: "api_key",
			},
			wantCodex: true,
		},
	}
	for _, test := range profiles {
		t.Run(test.name, func(t *testing.T) {
			authority := resolvedAuthorityPlan{
				runtimeProfileName: test.profile.name,
				codexCredential:    resolveCodexCredentialLocation(test.profileEnvironment),
				workloadVault: resolvedWorkloadVaultPlan{
					mode:        string(esconfig.WorkloadVaultAuthModeVaultIdentityJWT),
					address:     "https://vault.internal:8200",
					authMount:   "jwt",
					authRole:    "execution",
					jwtAudience: "vault",
				},
				workloadZoneVaultConfigDigest: testWorkloadZoneVaultConfigDigest,
			}
			plan := newResolvedExecutionPlan(resolvedPlanFacts{runtimeProfile: test.profile, authority: authority})
			host := newHostMaterializationContext("/stage", "/results", executionPlatformStateOwner{UID: 1, GID: 2}, "/spire", "dc1")
			run := newResolvedRunProjection(plan, host, newExecutionLocatorFromRunID("run-0123456789abcdef"))
			handoff := buildResolvedExecutionAuthorityHandoff(run.authorityHandoff)
			if handoff.AuthorityPath == "" || handoff.RuntimeProfile.Name != test.profile.name || handoff.IdentityHandoff.EndpointURI == "" {
				t.Fatal("currently admitted profile did not produce an authority handoff")
			}
			if (handoff.CodexCredentialLocation != nil) != test.wantCodex {
				t.Fatal("optional Codex credential-location applicability changed")
			}
		})
	}
}

func TestTrancheB2PreSubmissionOperationalCausesUseFixedPublicMessages(t *testing.T) {
	const marker = "private-path-uid-9123-argv-secret-env-secret"
	fixture := newPreparedArtifactFixture(t)
	policyPayload := buildAdmissionPolicyStaticScriptArchive(t, map[string][]byte{
		staticScriptEntrypointName: []byte(benignPolicyFixtureText()),
	})
	var captured bytes.Buffer
	previousWriter := log.Writer()
	previousFlags := log.Flags()
	previousPrefix := log.Prefix()
	log.SetOutput(&captured)
	log.SetFlags(0)
	log.SetPrefix("")
	t.Cleanup(func() {
		log.SetOutput(previousWriter)
		log.SetFlags(previousFlags)
		log.SetPrefix(previousPrefix)
	})
	assertMarkerAbsentFromLogs := func(t *testing.T) {
		t.Helper()
		if strings.Contains(captured.String(), marker) {
			t.Fatalf("operational cause escaped into ordinary logs: %q", captured.String())
		}
	}

	t.Run("host context", func(t *testing.T) {
		captured.Reset()
		service, _, _ := newWorkstreamCTestService(t, fixture)
		service.cfg.Execution.StagingRootDir = "relative/" + marker
		service.arsClient = newResolvedPlanDependencyClient(t, resolvedPlanArtifactHandler(t, fixture, policyPayload, nil))
		service.nomadClient = newResolvedPlanNomadClient(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			t.Fatal("host-context failure reached Nomad")
		}))
		_, publicErr := service.Submit(context.Background(), fixture.prepareRequest())
		trancheB2AssertFixedPublicError(t, publicErr, http.StatusInternalServerError, codeSubmissionFailed, "derive execution host context failed", marker)
		assertMarkerAbsentFromLogs(t)
	})

	t.Run("trust capture", func(t *testing.T) {
		captured.Reset()
		service, _, _ := newWorkstreamCTestService(t, fixture)
		tlsFixture := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
		certificateDER := tlsFixture.TLS.Certificates[0].Certificate[0]
		tlsFixture.Close()
		vaultBlob, err := json.Marshal(runtimeconfigv1.WorkloadZoneVaultConfigBlob{VaultConfig: runtimeconfigv1.WorkloadZoneVaultConfig{
			Address:     "https://vault.internal:8200",
			AuthMount:   "jwt",
			AuthRole:    "execution",
			JWTAudience: "vault",
			CABundlePEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateDER})),
		}})
		if err != nil {
			t.Fatal(err)
		}
		t.Setenv("SSL_CERT_FILE", filepath.Join(physicalTestTempDir(t), marker, "missing-ca.pem"))
		service.arsClient = newResolvedPlanDependencyClient(t, http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
			switch request.URL.Path {
			case "/v1/artifacts/" + fixture.discovery.Artifact.ArtifactDigest + "/discovery":
				writeJSONResponse(t, w, http.StatusOK, fixture.discovery)
			case "/v1/blobs/" + fixture.discovery.Evidence.Digest + ":json":
				writeJSONResponse(t, w, http.StatusOK, fixture.evidence)
			case "/v1/blobs/" + testWorkloadZoneVaultConfigDigest + ":json":
				_, _ = w.Write(vaultBlob)
			case "/v1/blobs/" + fixture.discovery.Payload.Digest + ":bytes":
				_, _ = w.Write(policyPayload)
			default:
				t.Fatalf("unexpected dependency path %q", request.URL.Path)
			}
		}))
		service.nomadClient = newResolvedPlanNomadClient(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			t.Fatal("trust-capture failure reached Nomad")
		}))
		_, publicErr := service.Submit(context.Background(), fixture.prepareRequest())
		trancheB2AssertFixedPublicError(t, publicErr, http.StatusInternalServerError, codeSubmissionFailed, "stage workload vault trust material failed", marker)
		assertMarkerAbsentFromLogs(t)
	})

	t.Run("platform owner", func(t *testing.T) {
		captured.Reset()
		service, _, _ := newWorkstreamCTestService(t, fixture)
		service.cfg.Execution.ResultsRootDir = filepath.Join(physicalTestTempDir(t), marker, "missing-results")
		service.arsClient = newResolvedPlanDependencyClient(t, resolvedPlanArtifactHandler(t, fixture, policyPayload, nil))
		service.nomadClient = newResolvedPlanNomadClient(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			t.Fatal("owner-derivation failure reached Nomad")
		}))
		_, publicErr := service.Submit(context.Background(), fixture.prepareRequest())
		trancheB2AssertFixedPublicError(t, publicErr, http.StatusInternalServerError, codeSubmissionFailed, "derive execution platform state owner failed", marker)
		assertMarkerAbsentFromLogs(t)
	})
}

func trancheB2AssertFixedPublicError(t *testing.T, publicErr *Error, status int, code string, message string, forbidden ...string) {
	t.Helper()
	if publicErr == nil || publicErr.Status != status || publicErr.Code != code || publicErr.Message != message {
		t.Fatalf("unexpected fixed public error: %+v", publicErr)
	}
	payload, err := json.Marshal(ErrorResponse{Success: false, Error: publicErr.Message, Code: publicErr.Code})
	if err != nil {
		t.Fatal(err)
	}
	want, err := json.Marshal(ErrorResponse{Success: false, Error: message, Code: code})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(payload, want) {
		t.Fatalf("public error DTO changed: got %s want %s", payload, want)
	}
	for _, marker := range forbidden {
		if strings.Contains(string(payload), marker) {
			t.Fatalf("private marker %q escaped in %s", marker, payload)
		}
	}
}

func TestTrancheB1DefaultProfileLiteralNomadJobAndAuthorityHandoff(t *testing.T) {
	fixture := newPreparedArtifactFixture(t)
	fixture.evidence.Claims.Admission.Execution.Access.NetworkAccess = false
	resignPreparedArtifactFixture(t, &fixture)
	service, stagingRoot, _ := newWorkstreamCTestService(t, fixture)
	request := fixture.prepareRequest()
	request.Mode = ""
	request.TimeoutSeconds = 0
	request.Resources = nil
	request.Invocation.Argv = []string{}
	request.Invocation.Env = map[string]string{}
	request.Invocation.Mounts = []RuntimeMount{}
	request.Invocation.Annotations = map[string]string{}
	policyPayload := buildAdmissionPolicyStaticScriptArchive(t, map[string][]byte{
		staticScriptEntrypointName: []byte(benignPolicyFixtureText()),
	})
	service.arsClient = newResolvedPlanDependencyClient(t, resolvedPlanArtifactHandler(t, fixture, policyPayload, nil))
	registrationCalls := 0
	var submittedBody []byte
	service.nomadClient = newResolvedPlanNomadClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		registrationCalls++
		if r.Method != http.MethodPost || r.URL.Path != "/v1/jobs" {
			t.Fatalf("unexpected Nomad registration route %s %q", r.Method, r.URL.Path)
		}
		var readErr error
		submittedBody, readErr = io.ReadAll(r.Body)
		if readErr != nil {
			t.Fatal(readErr)
		}
		_, _ = w.Write([]byte(`{"EvalID":"eval-b1"}`))
	}))

	result, submitErr := service.Submit(context.Background(), request)
	if submitErr != nil {
		t.Fatalf("default-profile Submit failed: %+v", submitErr)
	}
	if registrationCalls != 1 || !result.Success || !result.Submitted || result.Status != executionLifecycleStatusSubmitted || result.AuthorityHandoff == nil {
		t.Fatalf("successful receipt or one-registration contract changed: calls=%d result=%+v", registrationCalls, result)
	}

	var actualJob any
	if err := json.Unmarshal(submittedBody, &actualJob); err != nil {
		t.Fatal(err)
	}
	var expectedJob any
	if err := json.Unmarshal([]byte(trancheB1DefaultNomadJobGolden), &expectedJob); err != nil {
		t.Fatal(err)
	}
	stagingInfo, statErr := os.Stat(stagingRoot)
	if statErr != nil {
		t.Fatal(statErr)
	}
	stagingStat, ok := stagingInfo.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatal("golden fixture did not expose native owner metadata")
	}
	values := trancheB1DefaultGoldenTokenValues(result.RunID, stagingRoot, service.cfg.Execution.SPIREWorkloadAPISocketPath, int(stagingStat.Uid), int(stagingStat.Gid))
	if actualErr := rejectTrancheB1ActualGoldenTokens(actualJob); actualErr != nil {
		t.Fatal(actualErr)
	}
	expandedJob, expandErr := expandTrancheB1ExpectedGolden(expectedJob, trancheB1DefaultNomadJobTokenLedger, values)
	if expandErr != nil {
		t.Fatal(expandErr)
	}
	if compareErr := trancheB1CompareCompleteGolden(actualJob, expandedJob); compareErr != nil {
		actualPretty, _ := json.MarshalIndent(actualJob, "", "  ")
		expectedPretty, _ := json.MarshalIndent(expandedJob, "", "  ")
		t.Fatalf("complete literal Nomad job changed: %v\nactual:\n%s\nexpected:\n%s", compareErr, actualPretty, expectedPretty)
	}

	actualHandoff := trancheB1GenericJSON(t, result.AuthorityHandoff)
	var expectedHandoff any
	if err := json.Unmarshal([]byte(trancheB1DefaultAuthorityHandoffGolden), &expectedHandoff); err != nil {
		t.Fatal(err)
	}
	if actualErr := rejectTrancheB1ActualGoldenTokens(actualHandoff); actualErr != nil {
		t.Fatal(actualErr)
	}
	expandedHandoff, expandHandoffErr := expandTrancheB1ExpectedGolden(expectedHandoff, trancheB1DefaultAuthorityHandoffTokenLedger, values)
	if expandHandoffErr != nil {
		t.Fatal(expandHandoffErr)
	}
	if compareErr := trancheB1CompareCompleteGolden(actualHandoff, expandedHandoff); compareErr != nil {
		actualPretty, _ := json.MarshalIndent(actualHandoff, "", "  ")
		expectedPretty, _ := json.MarshalIndent(expandedHandoff, "", "  ")
		t.Fatalf("literal authority handoff changed: %v\nactual:\n%s\nexpected:\n%s", compareErr, actualPretty, expectedPretty)
	}
}

func TestTrancheB2ControlPlaneNormalShellLiteralNomadJobAndAuthorityHandoff(t *testing.T) {
	if len(trancheB2ControlPlaneNormalShellNomadJobTokenLedger) != 14 || len(trancheB2ControlPlaneNormalShellAuthorityHandoffTokenLedger) != 1 {
		t.Fatal("control-plane golden token occurrence inventory changed")
	}
	fixture := newPreparedArtifactFixture(t)
	service, stagingRoot, _ := newWorkstreamCTestService(t, fixture)
	profileConfig := controlPlaneNormalShellProfileExecutionConfig()
	service.cfg.Execution.RuntimeProfiles = profileConfig.RuntimeProfiles
	request := fixture.prepareRequest()
	request.Mode = ExecutionModeAsync
	request.TimeoutSeconds = 17
	request.Resources = &ExecutionResources{CPU: 23, MemoryMB: 257}
	request.Invocation.Argv = []string{"python3", "control_plane_remote_normal_shell.py"}
	request.Invocation.Env = map[string]string{"APP_MODE": "control-plane"}
	request.Invocation.Annotations = map[string]string{runtimeProfileAnnotationKey: runtimeProfileControlPlaneNormalShell}
	request.Invocation.Mounts = []RuntimeMount{{
		Source:     MountSource{ArtifactDigest: fixture.discovery.Artifact.ArtifactDigest},
		TargetPath: "/execution/mounts/config",
		ReadOnly:   true,
	}}
	policyPayload := buildAdmissionPolicyStaticScriptArchive(t, map[string][]byte{
		staticScriptEntrypointName: []byte(benignPolicyFixtureText()),
	})
	service.arsClient = newResolvedPlanDependencyClient(t, resolvedPlanArtifactHandler(t, fixture, policyPayload, nil))

	registrationCalls := 0
	var submittedBody []byte
	service.nomadClient = newResolvedPlanNomadClient(t, http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		registrationCalls++
		if request.Method != http.MethodPost || request.URL.Path != "/v1/jobs" {
			t.Fatalf("unexpected Nomad registration route %s %q", request.Method, request.URL.Path)
		}
		var err error
		submittedBody, err = io.ReadAll(request.Body)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = w.Write([]byte(`{"EvalID":"eval-b2"}`))
	}))

	result, submitErr := service.Submit(context.Background(), request)
	if submitErr != nil {
		t.Fatalf("control-plane profile Submit failed: %+v", submitErr)
	}
	if registrationCalls != 1 || !result.Success || !result.Submitted || result.Status != executionLifecycleStatusSubmitted || result.AuthorityHandoff == nil {
		t.Fatalf("successful receipt or one-registration contract changed: calls=%d result=%+v", registrationCalls, result)
	}

	var actualJob any
	if err := json.Unmarshal(submittedBody, &actualJob); err != nil {
		t.Fatal(err)
	}
	var expectedJob any
	if err := json.Unmarshal([]byte(trancheB2ControlPlaneNormalShellNomadJobGolden), &expectedJob); err != nil {
		t.Fatal(err)
	}
	stagingInfo, err := os.Stat(stagingRoot)
	if err != nil {
		t.Fatal(err)
	}
	stagingStat, ok := stagingInfo.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatal("golden fixture did not expose native owner metadata")
	}
	values := map[string]string{
		"<JOB_ID>":       "exec-" + result.RunID,
		"<RUN_ID>":       result.RunID,
		"<STAGING_ROOT>": filepath.Join(stagingRoot, result.RunID),
		"<UID>":          strconv.Itoa(int(stagingStat.Uid)),
		"<GID>":          strconv.Itoa(int(stagingStat.Gid)),
		"<SPIRE_SOURCE>": filepath.Dir(service.cfg.Execution.SPIREWorkloadAPISocketPath),
	}
	if err := rejectTrancheB1ActualGoldenTokens(actualJob); err != nil {
		t.Fatal(err)
	}
	expandedJob, err := expandTrancheB1ExpectedGolden(expectedJob, trancheB2ControlPlaneNormalShellNomadJobTokenLedger, values)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(actualJob, expandedJob) {
		differences := make([]string, 0)
		trancheB1JSONDifferences(actualJob, expandedJob, "", &differences)
		sort.Strings(differences)
		actualPretty, _ := json.MarshalIndent(actualJob, "", "  ")
		expectedPretty, _ := json.MarshalIndent(expandedJob, "", "  ")
		t.Fatalf("complete control-plane literal Nomad job changed at JSON pointers %v\nactual:\n%s\nexpected:\n%s", differences, actualPretty, expectedPretty)
	}

	actualHandoff := trancheB1GenericJSON(t, result.AuthorityHandoff)
	var expectedHandoff any
	if err := json.Unmarshal([]byte(trancheB2ControlPlaneNormalShellAuthorityHandoffGolden), &expectedHandoff); err != nil {
		t.Fatal(err)
	}
	if err := rejectTrancheB1ActualGoldenTokens(actualHandoff); err != nil {
		t.Fatal(err)
	}
	expandedHandoff, err := expandTrancheB1ExpectedGolden(expectedHandoff, trancheB2ControlPlaneNormalShellAuthorityHandoffTokenLedger, values)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(actualHandoff, expandedHandoff) {
		differences := make([]string, 0)
		trancheB1JSONDifferences(actualHandoff, expandedHandoff, "", &differences)
		sort.Strings(differences)
		actualPretty, _ := json.MarshalIndent(actualHandoff, "", "  ")
		expectedPretty, _ := json.MarshalIndent(expandedHandoff, "", "  ")
		t.Fatalf("literal control-plane authority handoff changed at JSON pointers %v\nactual:\n%s\nexpected:\n%s", differences, actualPretty, expectedPretty)
	}

	actualJobBeforeNegatives := trancheB1CloneGenericJSON(t, actualJob)
	for _, negative := range []struct {
		name        string
		pointer     string
		replacement any
	}{
		{name: "runtime command", pointer: "/Job/TaskGroups/0/Tasks/0/Config/command", replacement: "/execution/run/platform/not-the-runtime"},
		{name: "workload environment", pointer: "/Job/TaskGroups/0/Tasks/0/Env/APP_MODE", replacement: "wrong-mode"},
		{name: "governed mount", pointer: "/Job/TaskGroups/0/Tasks/0/Config/mounts/4/target", replacement: "/execution/mounts/wrong"},
		{name: "job metadata", pointer: "/Job/TaskGroups/0/Tasks/0/Meta/output_id", replacement: "wrong-output"},
		{name: "job envelope", pointer: "/Job/Type", replacement: "service"},
	} {
		t.Run("wrong job "+negative.name, func(t *testing.T) {
			mutatedExpected := trancheB1CloneGenericJSON(t, expandedJob)
			if err := trancheB1SetJSONPointer(mutatedExpected, negative.pointer, negative.replacement); err != nil {
				t.Fatal(err)
			}
			if reflect.DeepEqual(actualJob, mutatedExpected) {
				t.Fatalf("actual job accepted independently cloned expected tree with wrong %s", negative.name)
			}
		})
	}

	actualHandoffBeforeNegatives := trancheB1CloneGenericJSON(t, actualHandoff)
	for _, negative := range []struct {
		name        string
		pointer     string
		replacement any
	}{
		{name: "runtime profile identity", pointer: "/runtime_profile/name", replacement: "wrong-profile/v1"},
		{name: "Vault credential path", pointer: "/codex_credential_location/vault_secret_path", replacement: "wrong/data/path"},
		{name: "workload identity endpoint", pointer: "/identity_handoff/endpoint_uri", replacement: "unix:///wrong/endpoint"},
	} {
		t.Run("wrong handoff "+negative.name, func(t *testing.T) {
			mutatedExpected := trancheB1CloneGenericJSON(t, expandedHandoff)
			if err := trancheB1SetJSONPointer(mutatedExpected, negative.pointer, negative.replacement); err != nil {
				t.Fatal(err)
			}
			if reflect.DeepEqual(actualHandoff, mutatedExpected) {
				t.Fatalf("actual handoff accepted independently cloned expected tree with wrong %s", negative.name)
			}
		})
	}
	if !reflect.DeepEqual(actualJob, actualJobBeforeNegatives) || !reflect.DeepEqual(actualHandoff, actualHandoffBeforeNegatives) {
		t.Fatal("material negative controls mutated an actual tree")
	}
}

func TestTrancheB1LiteralGoldenTokenStrictness(t *testing.T) {
	values := trancheB1DefaultGoldenTokenValues("run-0123456789abcdef", "/stage", "/spire/agent.sock", os.Getuid(), os.Getgid())
	assertFailure := func(name string, expected any, ledger []trancheB1GoldenTokenOccurrence, tokenValues map[string]string, want string) {
		t.Helper()
		if _, err := expandTrancheB1ExpectedGolden(expected, ledger, tokenValues); err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("%s: got error %v, want failure containing %q", name, err, want)
		}
	}
	if err := rejectTrancheB1ActualGoldenTokens(map[string]any{"value": "prefix-<RUN_ID>"}); err == nil || !strings.Contains(err.Error(), "actual JSON contains reserved token") {
		t.Fatalf("reserved actual token: got error %v", err)
	}
	assertFailure("unknown expected token", map[string]any{"value": "<UNKNOWN>"}, nil, values, "unknown golden token")
	missingRun := trancheB1CopyGoldenTokenValues(values)
	missingRun["<RUN_ID>"] = ""
	assertFailure("unresolved token", map[string]any{"value": "<RUN_ID>"}, []trancheB1GoldenTokenOccurrence{{token: "<RUN_ID>", pointer: "/value", template: "<RUN_ID>"}}, missingRun, "has no concrete value")
	assertFailure("unapproved pointer", map[string]any{"value": "<RUN_ID>"}, nil, values, "outside its exact pointer inventory")
	assertFailure("multiple token candidates", map[string]any{"value": "<RUN_ID>"}, []trancheB1GoldenTokenOccurrence{
		{token: "<RUN_ID>", pointer: "/value", template: "<RUN_ID>"},
		{token: "<JOB_ID>", pointer: "/value", template: "<RUN_ID>"},
	}, values, "multiple token candidates")
}

func TestTrancheB1FiniteAssuranceRepairGoldenTokenObjectKeys(t *testing.T) {
	values := trancheB1DefaultGoldenTokenValues("run-0123456789abcdef", "/stage", "/spire/agent.sock", 1, 2)
	assertActualRejected := func(name string, actual any, want string) {
		t.Helper()
		before := trancheB1CloneGenericJSON(t, actual)
		if err := rejectTrancheB1ActualGoldenTokens(actual); err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("%s: got error %v, want failure containing %q", name, err, want)
		}
		if !reflect.DeepEqual(actual, before) {
			t.Fatalf("%s: actual JSON was modified during token rejection", name)
		}
	}
	assertExpectedRejected := func(name string, expected any, ledger []trancheB1GoldenTokenOccurrence, tokenValues map[string]string, want string) {
		t.Helper()
		if _, err := expandTrancheB1ExpectedGolden(expected, ledger, tokenValues); err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("%s: got error %v, want failure containing %q", name, err, want)
		}
	}

	t.Run("exact actual key", func(t *testing.T) {
		assertActualRejected("exact actual key", map[string]any{"<RUN_ID>": "value"}, "actual JSON contains reserved token in object key")
	})
	t.Run("longer actual key", func(t *testing.T) {
		assertActualRejected("longer actual key", map[string]any{"prefix-<RUN_ID>-suffix": "value"}, "actual JSON contains reserved token in object key")
	})
	t.Run("exact expected key", func(t *testing.T) {
		assertExpectedRejected("exact expected key", map[string]any{"<RUN_ID>": "value"}, nil, values, "expected JSON object key contains token-shaped sentinel")
	})
	t.Run("known unledgered expected key", func(t *testing.T) {
		assertExpectedRejected("known unledgered expected key", map[string]any{"prefix-<JOB_ID>-suffix": "value"}, nil, values, "expected JSON object key contains token-shaped sentinel")
	})
	t.Run("unknown expected key", func(t *testing.T) {
		assertExpectedRejected("unknown expected key", map[string]any{"prefix-<UNKNOWN>-suffix": "value"}, nil, values, "expected JSON object key contains token-shaped sentinel")
	})

	t.Run("matching token-bearing actual and expected keys", func(t *testing.T) {
		actual := map[string]any{"<RUN_ID>": "same"}
		expected := map[string]any{"<RUN_ID>": "same"}
		assertActualRejected("matching actual key", actual, "actual JSON contains reserved token in object key")
		assertExpectedRejected("matching expected key", expected, nil, values, "expected JSON object key contains token-shaped sentinel")
	})

	t.Run("nested object key", func(t *testing.T) {
		assertActualRejected("nested object key", map[string]any{"outer": map[string]any{"<RUN_ID>": "value"}}, "actual JSON contains reserved token in object key")
	})
	t.Run("array-contained object key", func(t *testing.T) {
		assertActualRejected("array-contained object key", []any{map[string]any{"<RUN_ID>": "value"}}, "actual JSON contains reserved token in object key")
	})
	t.Run("unapproved value pointer", func(t *testing.T) {
		assertExpectedRejected("unapproved value pointer", map[string]any{"value": "<RUN_ID>"}, nil, values, "outside its exact pointer inventory")
	})
	t.Run("unknown value token", func(t *testing.T) {
		assertExpectedRejected("unknown value token", map[string]any{"value": "<UNKNOWN>"}, nil, values, "unknown golden token")
	})
	t.Run("unresolved value token", func(t *testing.T) {
		missingRun := trancheB1CopyGoldenTokenValues(values)
		missingRun["<RUN_ID>"] = ""
		assertExpectedRejected("unresolved value token", map[string]any{"value": "<RUN_ID>"}, []trancheB1GoldenTokenOccurrence{{token: "<RUN_ID>", pointer: "/value", template: "<RUN_ID>"}}, missingRun, "has no concrete value")
	})

	t.Run("ordinary keys and exact pointer expansion", func(t *testing.T) {
		expected := map[string]any{"ordinary/key~part": map[string]any{"value": "prefix-<RUN_ID>-suffix"}}
		ledger := []trancheB1GoldenTokenOccurrence{{token: "<RUN_ID>", pointer: "/ordinary~1key~0part/value", template: "prefix-<RUN_ID>-suffix"}}
		expanded, err := expandTrancheB1ExpectedGolden(expected, ledger, values)
		if err != nil {
			t.Fatal(err)
		}
		want := map[string]any{"ordinary/key~part": map[string]any{"value": "prefix-" + values["<RUN_ID>"] + "-suffix"}}
		if !reflect.DeepEqual(expanded, want) {
			t.Fatalf("ordinary-key expansion changed: got %#v want %#v", expanded, want)
		}
		if err := rejectTrancheB1ActualGoldenTokens(want); err != nil {
			t.Fatalf("ordinary concrete actual JSON rejected: %v", err)
		}
	})

	for _, test := range []struct {
		name   string
		values map[string]string
	}{
		{name: "equal concrete values", values: map[string]string{"<RUN_ID>": "same", "<JOB_ID>": "same"}},
		{name: "substring-overlapping concrete values", values: map[string]string{"<RUN_ID>": "run", "<JOB_ID>": "exec-run"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			tokenValues := trancheB1CopyGoldenTokenValues(values)
			for token, value := range test.values {
				tokenValues[token] = value
			}
			expected := map[string]any{"run": "<RUN_ID>", "job": "<JOB_ID>"}
			ledger := []trancheB1GoldenTokenOccurrence{
				{token: "<RUN_ID>", pointer: "/run", template: "<RUN_ID>"},
				{token: "<JOB_ID>", pointer: "/job", template: "<JOB_ID>"},
			}
			expanded, err := expandTrancheB1ExpectedGolden(expected, ledger, tokenValues)
			if err != nil {
				t.Fatal(err)
			}
			want := map[string]any{"run": test.values["<RUN_ID>"], "job": test.values["<JOB_ID>"]}
			if !reflect.DeepEqual(expanded, want) {
				t.Fatalf("pointer-owned values became ambiguous: got %#v want %#v", expanded, want)
			}
		})
	}
}

func TestTrancheB1LiteralGoldenPointerOwnershipHandlesEqualAndOverlappingValues(t *testing.T) {
	for _, test := range []struct {
		name   string
		values map[string]string
	}{
		{"equal values", map[string]string{"<RUN_ID>": "same", "<JOB_ID>": "same"}},
		{"substring overlap", map[string]string{"<RUN_ID>": "run", "<JOB_ID>": "exec-run"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			actual := map[string]any{"run": test.values["<RUN_ID>"], "job": test.values["<JOB_ID>"]}
			expected := map[string]any{"run": "<RUN_ID>", "job": "<JOB_ID>"}
			ledger := []trancheB1GoldenTokenOccurrence{
				{token: "<RUN_ID>", pointer: "/run", template: "<RUN_ID>"},
				{token: "<JOB_ID>", pointer: "/job", template: "<JOB_ID>"},
			}
			values := trancheB1DefaultGoldenTokenValues("unused", "/stage", "/spire/agent.sock", 1, 2)
			for token, value := range test.values {
				values[token] = value
			}
			expanded, err := expandTrancheB1ExpectedGolden(expected, ledger, values)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(actual, expanded) || actual["run"] != test.values["<RUN_ID>"] || actual["job"] != test.values["<JOB_ID>"] {
				t.Fatal("pointer-owned expansion changed or ambiguously normalized the actual tree")
			}
		})
	}
}

func TestTrancheB1LiteralGoldenRejectsMateriallyWrongLeaves(t *testing.T) {
	var literal any
	if err := json.Unmarshal([]byte(trancheB1DefaultNomadJobGolden), &literal); err != nil {
		t.Fatal(err)
	}
	values := trancheB1DefaultGoldenTokenValues("run-0123456789abcdef", "/stage", "/run/spire/agent.sock", 1, 2)
	expected, err := expandTrancheB1ExpectedGolden(literal, trancheB1DefaultNomadJobTokenLedger, values)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name    string
		pointer string
		value   any
	}{
		{"command", "/Job/TaskGroups/0/Tasks/0/Config/command", "/wrong-command"},
		{"environment", "/Job/TaskGroups/0/Tasks/0/Env/SERVICE_ID", "wrong-service"},
		{"mount", "/Job/TaskGroups/0/Tasks/0/Config/mounts/3/target", "/wrong-mount"},
		{"metadata", "/Job/Meta/execution_substrate.authority_handoff.schema", "wrong-schema"},
		{"envelope", "/Job/Type", "service"},
	} {
		t.Run(test.name, func(t *testing.T) {
			actual := trancheB1CloneGenericJSON(t, expected)
			if err := trancheB1SetJSONPointer(actual, test.pointer, test.value); err != nil {
				t.Fatal(err)
			}
			compareErr := trancheB1CompareCompleteGolden(actual, expected)
			if compareErr == nil || !strings.Contains(compareErr.Error(), test.pointer) {
				t.Fatalf("wrong %s leaf did not fail at %s: %v", test.name, test.pointer, compareErr)
			}
		})
	}
}

type trancheB1GoldenTokenOccurrence struct {
	token    string
	pointer  string
	template string
}

var trancheB1GoldenTokens = []string{"<RUN_ID>", "<JOB_ID>", "<STAGING_ROOT>", "<UID>", "<GID>", "<SPIRE_SOURCE>"}

var trancheB1DefaultNomadJobTokenLedger = []trancheB1GoldenTokenOccurrence{
	{token: "<JOB_ID>", pointer: "/Job/ID", template: "<JOB_ID>"},
	{token: "<JOB_ID>", pointer: "/Job/Name", template: "<JOB_ID>"},
	{token: "<RUN_ID>", pointer: "/Job/Meta/run_id", template: "<RUN_ID>"},
	{token: "<STAGING_ROOT>", pointer: "/Job/TaskGroups/0/Tasks/0/Config/mounts/0/source", template: "<STAGING_ROOT>/payload"},
	{token: "<STAGING_ROOT>", pointer: "/Job/TaskGroups/0/Tasks/0/Config/mounts/1/source", template: "<STAGING_ROOT>/run"},
	{token: "<RUN_ID>", pointer: "/Job/TaskGroups/0/Tasks/0/Config/mounts/2/target", template: "/run/es-runtime-identity/<RUN_ID>"},
	{token: "<SPIRE_SOURCE>", pointer: "/Job/TaskGroups/0/Tasks/0/Config/mounts/3/source", template: "<SPIRE_SOURCE>"},
	{token: "<RUN_ID>", pointer: "/Job/TaskGroups/0/Tasks/0/Config/mounts/3/target", template: "/run/es-runtime-identity/<RUN_ID>/internal/source"},
	{token: "<GID>", pointer: "/Job/TaskGroups/0/Tasks/0/Env/EXEC_PLATFORM_STATE_OWNER_GID", template: "<GID>"},
	{token: "<UID>", pointer: "/Job/TaskGroups/0/Tasks/0/Env/EXEC_PLATFORM_STATE_OWNER_UID", template: "<UID>"},
	{token: "<RUN_ID>", pointer: "/Job/TaskGroups/0/Tasks/0/Env/EXEC_RUN_ID", template: "<RUN_ID>"},
	{token: "<RUN_ID>", pointer: "/Job/TaskGroups/0/Tasks/0/Env/EXEC_WORKLOAD_IDENTITY_ENDPOINT", template: "unix:///run/es-runtime-identity/<RUN_ID>/endpoint"},
	{token: "<RUN_ID>", pointer: "/Job/TaskGroups/0/Tasks/0/Meta/run_id", template: "<RUN_ID>"},
}

var trancheB1DefaultAuthorityHandoffTokenLedger = []trancheB1GoldenTokenOccurrence{
	{token: "<RUN_ID>", pointer: "/identity_handoff/endpoint_uri", template: "unix:///run/es-runtime-identity/<RUN_ID>/endpoint"},
}

var trancheB2ControlPlaneNormalShellNomadJobTokenLedger = []trancheB1GoldenTokenOccurrence{
	{token: "<JOB_ID>", pointer: "/Job/ID", template: "<JOB_ID>"},
	{token: "<JOB_ID>", pointer: "/Job/Name", template: "<JOB_ID>"},
	{token: "<RUN_ID>", pointer: "/Job/Meta/run_id", template: "<RUN_ID>"},
	{token: "<RUN_ID>", pointer: "/Job/TaskGroups/0/Tasks/0/Config/mounts/2/target", template: "/run/es-runtime-identity/<RUN_ID>"},
	{token: "<RUN_ID>", pointer: "/Job/TaskGroups/0/Tasks/0/Config/mounts/3/target", template: "/run/es-runtime-identity/<RUN_ID>/internal/source"},
	{token: "<RUN_ID>", pointer: "/Job/TaskGroups/0/Tasks/0/Env/EXEC_RUN_ID", template: "<RUN_ID>"},
	{token: "<RUN_ID>", pointer: "/Job/TaskGroups/0/Tasks/0/Env/EXEC_WORKLOAD_IDENTITY_ENDPOINT", template: "unix:///run/es-runtime-identity/<RUN_ID>/endpoint"},
	{token: "<RUN_ID>", pointer: "/Job/TaskGroups/0/Tasks/0/Meta/run_id", template: "<RUN_ID>"},
	{token: "<STAGING_ROOT>", pointer: "/Job/TaskGroups/0/Tasks/0/Config/mounts/0/source", template: "<STAGING_ROOT>/payload"},
	{token: "<STAGING_ROOT>", pointer: "/Job/TaskGroups/0/Tasks/0/Config/mounts/1/source", template: "<STAGING_ROOT>/run"},
	{token: "<STAGING_ROOT>", pointer: "/Job/TaskGroups/0/Tasks/0/Config/mounts/4/source", template: "<STAGING_ROOT>/mounts/00/contents"},
	{token: "<SPIRE_SOURCE>", pointer: "/Job/TaskGroups/0/Tasks/0/Config/mounts/3/source", template: "<SPIRE_SOURCE>"},
	{token: "<UID>", pointer: "/Job/TaskGroups/0/Tasks/0/Env/EXEC_PLATFORM_STATE_OWNER_UID", template: "<UID>"},
	{token: "<GID>", pointer: "/Job/TaskGroups/0/Tasks/0/Env/EXEC_PLATFORM_STATE_OWNER_GID", template: "<GID>"},
}

var trancheB2ControlPlaneNormalShellAuthorityHandoffTokenLedger = []trancheB1GoldenTokenOccurrence{
	{token: "<RUN_ID>", pointer: "/identity_handoff/endpoint_uri", template: "unix:///run/es-runtime-identity/<RUN_ID>/endpoint"},
}

func trancheB1DefaultGoldenTokenValues(runID string, stagingRoot string, spireSocketPath string, ownerUID int, ownerGID int) map[string]string {
	return map[string]string{
		"<JOB_ID>":       "exec-" + runID,
		"<RUN_ID>":       runID,
		"<STAGING_ROOT>": filepath.Join(stagingRoot, runID),
		"<UID>":          strconv.Itoa(ownerUID),
		"<GID>":          strconv.Itoa(ownerGID),
		"<SPIRE_SOURCE>": filepath.Dir(spireSocketPath),
	}
}

func trancheB1CopyGoldenTokenValues(values map[string]string) map[string]string {
	result := make(map[string]string, len(values))
	for token, value := range values {
		result[token] = value
	}
	return result
}

func rejectTrancheB1ActualGoldenTokens(actual any) error {
	knownTokens := make(map[string]bool, len(trancheB1GoldenTokens))
	for _, token := range trancheB1GoldenTokens {
		knownTokens[token] = true
	}
	if match, found := trancheB1TokenInTree(actual, knownTokens, ""); found {
		if match.objectKey {
			if match.known {
				return fmt.Errorf("actual JSON contains reserved token in object key at %s", match.pointer)
			}
			return fmt.Errorf("actual JSON contains token-shaped sentinel in object key at %s", match.pointer)
		}
		if match.known {
			return fmt.Errorf("actual JSON contains reserved token at %s", match.pointer)
		}
		return fmt.Errorf("actual JSON contains token-shaped sentinel at %s", match.pointer)
	}
	return nil
}

func expandTrancheB1ExpectedGolden(expected any, ledger []trancheB1GoldenTokenOccurrence, values map[string]string) (any, error) {
	knownTokens := make(map[string]bool, len(trancheB1GoldenTokens))
	for _, token := range trancheB1GoldenTokens {
		knownTokens[token] = true
		if value, ok := values[token]; !ok || value == "" {
			return nil, fmt.Errorf("golden token %s has no concrete value", token)
		}
	}
	for token := range values {
		if !knownTokens[token] {
			return nil, fmt.Errorf("unknown golden token value %q", token)
		}
	}
	byPointer := make(map[string]trancheB1GoldenTokenOccurrence, len(ledger))
	ledgerTokens := make(map[string]bool, len(knownTokens))
	for _, occurrence := range ledger {
		if !knownTokens[occurrence.token] {
			return nil, fmt.Errorf("unknown golden token %q in ledger", occurrence.token)
		}
		if _, exists := byPointer[occurrence.pointer]; exists {
			return nil, fmt.Errorf("golden pointer %s has multiple token candidates", occurrence.pointer)
		}
		if strings.Count(occurrence.template, occurrence.token) != 1 {
			return nil, fmt.Errorf("golden template at %s must contain assigned token %s exactly once", occurrence.pointer, occurrence.token)
		}
		for token := range knownTokens {
			if token != occurrence.token && strings.Contains(occurrence.template, token) {
				return nil, fmt.Errorf("golden pointer %s has multiple token candidates", occurrence.pointer)
			}
		}
		byPointer[occurrence.pointer] = occurrence
		ledgerTokens[occurrence.token] = true
	}
	for token := range knownTokens {
		if !ledgerTokens[token] && len(ledger) == len(trancheB1DefaultNomadJobTokenLedger) {
			return nil, fmt.Errorf("golden token %s has no exact pointer inventory", token)
		}
	}
	usedPointers := make(map[string]bool, len(byPointer))
	expanded, err := trancheB1ExpandExpectedValue(expected, "", byPointer, values, knownTokens, usedPointers)
	if err != nil {
		return nil, err
	}
	for pointer := range byPointer {
		if !usedPointers[pointer] {
			return nil, fmt.Errorf("golden ledger pointer %s does not identify an expected token", pointer)
		}
	}
	if match, found := trancheB1TokenInTree(expanded, knownTokens, ""); found {
		if match.objectKey {
			return nil, fmt.Errorf("expanded expected JSON has unresolved token-shaped object key at %s", match.pointer)
		}
		return nil, fmt.Errorf("expanded expected JSON has unresolved token-shaped sentinel at %s", match.pointer)
	}
	return expanded, nil
}

func trancheB1ExpandExpectedValue(value any, pointer string, ledger map[string]trancheB1GoldenTokenOccurrence, values map[string]string, knownTokens map[string]bool, used map[string]bool) (any, error) {
	switch typed := value.(type) {
	case map[string]any:
		result := make(map[string]any, len(typed))
		keys := make([]string, 0, len(typed))
		for key := range typed {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			if _, _, found := trancheB1TokenShapeInString(key, knownTokens); found {
				return nil, fmt.Errorf("expected JSON object key contains token-shaped sentinel at %s", trancheB1ObjectKeyDiagnosticPointer(pointer))
			}
			child := typed[key]
			expanded, err := trancheB1ExpandExpectedValue(child, pointer+"/"+trancheB1EscapeJSONPointer(key), ledger, values, knownTokens, used)
			if err != nil {
				return nil, err
			}
			result[key] = expanded
		}
		return result, nil
	case []any:
		result := make([]any, len(typed))
		for index, child := range typed {
			expanded, err := trancheB1ExpandExpectedValue(child, pointer+"/"+strconv.Itoa(index), ledger, values, knownTokens, used)
			if err != nil {
				return nil, err
			}
			result[index] = expanded
		}
		return result, nil
	case string:
		tokens, err := trancheB1TokensInString(typed, knownTokens)
		if err != nil {
			return nil, err
		}
		occurrence, governed := ledger[pointer]
		if len(tokens) == 0 {
			if governed {
				return nil, fmt.Errorf("golden ledger pointer %s does not contain its assigned token", pointer)
			}
			return typed, nil
		}
		if !governed || len(tokens) != 1 || tokens[0] != occurrence.token {
			return nil, fmt.Errorf("golden token %s appears outside its exact pointer inventory at %s", tokens[0], pointer)
		}
		if typed != occurrence.template {
			return nil, fmt.Errorf("golden template at %s changed: got %q want %q", pointer, typed, occurrence.template)
		}
		used[pointer] = true
		return strings.Replace(typed, occurrence.token, values[occurrence.token], 1), nil
	default:
		return typed, nil
	}
}

func trancheB1TokensInString(value string, known map[string]bool) ([]string, error) {
	var tokens []string
	remaining := value
	for {
		start := strings.IndexByte(remaining, '<')
		if start < 0 {
			return tokens, nil
		}
		end := strings.IndexByte(remaining[start:], '>')
		if end < 0 {
			return nil, fmt.Errorf("unterminated golden token in %q", value)
		}
		token := remaining[start : start+end+1]
		if !known[token] {
			return nil, fmt.Errorf("unknown golden token %q", token)
		}
		tokens = append(tokens, token)
		remaining = remaining[start+end+1:]
	}
}

type trancheB1GoldenTreeTokenMatch struct {
	pointer   string
	known     bool
	objectKey bool
}

func trancheB1TokenInTree(value any, known map[string]bool, pointer string) (trancheB1GoldenTreeTokenMatch, bool) {
	switch typed := value.(type) {
	case map[string]any:
		keys := make([]string, 0, len(typed))
		for key := range typed {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			_, knownToken, found := trancheB1TokenShapeInString(key, known)
			if found {
				return trancheB1GoldenTreeTokenMatch{pointer: trancheB1ObjectKeyDiagnosticPointer(pointer), known: knownToken, objectKey: true}, true
			}
			if match, found := trancheB1TokenInTree(typed[key], known, pointer+"/"+trancheB1EscapeJSONPointer(key)); found {
				return match, true
			}
		}
	case []any:
		for index, child := range typed {
			if match, found := trancheB1TokenInTree(child, known, pointer+"/"+strconv.Itoa(index)); found {
				return match, true
			}
		}
	case string:
		_, knownToken, found := trancheB1TokenShapeInString(typed, known)
		if found {
			return trancheB1GoldenTreeTokenMatch{pointer: pointer, known: knownToken}, true
		}
	}
	return trancheB1GoldenTreeTokenMatch{}, false
}

func trancheB1TokenShapeInString(value string, known map[string]bool) (string, bool, bool) {
	start := strings.IndexByte(value, '<')
	if start < 0 {
		return "", false, false
	}
	end := strings.IndexByte(value[start:], '>')
	if end < 0 {
		return "", false, true
	}
	token := value[start : start+end+1]
	return token, known[token], true
}

func trancheB1ObjectKeyDiagnosticPointer(pointer string) string {
	return pointer + "/<object-key>"
}

func trancheB1CompareCompleteGolden(actual any, expected any) error {
	differences := make([]string, 0)
	trancheB1JSONDifferences(actual, expected, "", &differences)
	sort.Strings(differences)
	if len(differences) != 0 {
		return fmt.Errorf("complete literal golden differs at JSON pointers %v", differences)
	}
	return nil
}

func trancheB1CloneGenericJSON(t *testing.T, value any) any {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	var clone any
	if err := json.Unmarshal(encoded, &clone); err != nil {
		t.Fatal(err)
	}
	return clone
}

func trancheB1SetJSONPointer(root any, pointer string, value any) error {
	segments := strings.Split(strings.TrimPrefix(pointer, "/"), "/")
	if pointer == "" || len(segments) == 0 {
		return fmt.Errorf("non-root JSON pointer is required")
	}
	current := root
	for index, rawSegment := range segments {
		segment := strings.ReplaceAll(strings.ReplaceAll(rawSegment, "~1", "/"), "~0", "~")
		last := index == len(segments)-1
		switch typed := current.(type) {
		case map[string]any:
			if last {
				if _, ok := typed[segment]; !ok {
					return fmt.Errorf("JSON pointer %s is absent", pointer)
				}
				typed[segment] = value
				return nil
			}
			next, ok := typed[segment]
			if !ok {
				return fmt.Errorf("JSON pointer %s is absent", pointer)
			}
			current = next
		case []any:
			position, err := strconv.Atoi(segment)
			if err != nil || position < 0 || position >= len(typed) {
				return fmt.Errorf("JSON pointer %s has invalid array position", pointer)
			}
			if last {
				typed[position] = value
				return nil
			}
			current = typed[position]
		default:
			return fmt.Errorf("JSON pointer %s traverses a scalar", pointer)
		}
	}
	return fmt.Errorf("JSON pointer %s was not assigned", pointer)
}

func trancheB1GenericJSON(t *testing.T, value any) any {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	var generic any
	if err := json.Unmarshal(encoded, &generic); err != nil {
		t.Fatal(err)
	}
	return generic
}

func trancheB1JSONDifferences(first any, second any, pointer string, differences *[]string) {
	firstMap, firstIsMap := first.(map[string]any)
	secondMap, secondIsMap := second.(map[string]any)
	if firstIsMap || secondIsMap {
		if !firstIsMap || !secondIsMap {
			*differences = append(*differences, pointer)
			return
		}
		keys := make(map[string]bool, len(firstMap)+len(secondMap))
		for key := range firstMap {
			keys[key] = true
		}
		for key := range secondMap {
			keys[key] = true
		}
		for key := range keys {
			firstValue, firstOK := firstMap[key]
			secondValue, secondOK := secondMap[key]
			childPointer := pointer + "/" + trancheB1EscapeJSONPointer(key)
			if !firstOK || !secondOK {
				*differences = append(*differences, childPointer)
				continue
			}
			trancheB1JSONDifferences(firstValue, secondValue, childPointer, differences)
		}
		return
	}
	firstSlice, firstIsSlice := first.([]any)
	secondSlice, secondIsSlice := second.([]any)
	if firstIsSlice || secondIsSlice {
		if !firstIsSlice || !secondIsSlice || len(firstSlice) != len(secondSlice) {
			*differences = append(*differences, pointer)
			return
		}
		for index := range firstSlice {
			trancheB1JSONDifferences(firstSlice[index], secondSlice[index], pointer+"/"+strconv.Itoa(index), differences)
		}
		return
	}
	if !reflect.DeepEqual(first, second) {
		*differences = append(*differences, pointer)
	}
}

func trancheB1EscapeJSONPointer(value string) string {
	return strings.ReplaceAll(strings.ReplaceAll(value, "~", "~0"), "/", "~1")
}

func resignPreparedArtifactFixture(t *testing.T, fixture *preparedArtifactFixture) {
	t.Helper()
	canonical, err := fixture.evidence.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	fixture.evidence.Seal = evidencev1.NewSeal(canonical, fixture.keyID, "ed25519", base64.StdEncoding.EncodeToString(ed25519.Sign(fixture.privateKey, canonical)))
	evidenceBytes, err := json.Marshal(fixture.evidence)
	if err != nil {
		t.Fatal(err)
	}
	fixture.discovery.Evidence.Digest = digestBytes(evidenceBytes)
}

const trancheB1DefaultNomadJobGolden = `{
  "Job": {
    "Datacenters": [
      "dc1"
    ],
    "ID": "<JOB_ID>",
    "Meta": {
      "execution_substrate.authority_handoff.runtime_profile": "static-script/default",
      "execution_substrate.authority_handoff.schema": "v1",
      "execution_substrate.authority_handoff.workload_zone_vault_config_digest": "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
      "run_id": "<RUN_ID>"
    },
    "Name": "<JOB_ID>",
    "TaskGroups": [
      {
        "Count": 1,
        "Name": "group",
        "ReschedulePolicy": {
          "Attempts": 0,
          "Delay": 0,
          "DelayFunction": "constant",
          "MaxDelay": 0,
          "Unlimited": false
        },
        "RestartPolicy": {
          "Attempts": 0,
          "Delay": 10000000000,
          "Interval": 60000000000,
          "Mode": "fail"
        },
        "Tasks": [
          {
            "Config": {
              "args": [
                "supervisor",
                "--payload-archive",
                "/execution/staged/artifact.tar.gz",
                "--work-dir",
                "/execution/run/work",
                "--result-dir",
                "/execution/run/result",
                "--entrypoint",
                "/execution/run/work/entrypoint",
                "--timeout-seconds",
                "0",
                "--"
              ],
              "command": "/execution/run/platform/es-runtime-support",
              "image": "alpine:3.20",
              "mounts": [
                {
                  "readonly": true,
                  "source": "<STAGING_ROOT>/payload",
                  "target": "/execution/staged",
                  "type": "bind"
                },
                {
                  "readonly": false,
                  "source": "<STAGING_ROOT>/run",
                  "target": "/execution/run",
                  "type": "bind"
                },
                {
                  "readonly": false,
                  "target": "/run/es-runtime-identity/<RUN_ID>",
                  "tmpfs_options": {
                    "size": 1048576
                  },
                  "type": "tmpfs"
                },
                {
                  "readonly": true,
                  "source": "<SPIRE_SOURCE>",
                  "target": "/run/es-runtime-identity/<RUN_ID>/internal/source",
                  "type": "bind"
                }
              ],
              "network_mode": "none",
              "privileged": false,
              "security_opt": [
                "no-new-privileges"
              ]
            },
            "Driver": "docker",
            "Env": {
              "EXEC_ARTIFACT_DIGEST": "sha256:2d18fec2eaba5507f4d265b7b3615e31d72fcb835196109c2eea042e93603613",
              "EXEC_PLATFORM_STATE_OWNER_GID": "<GID>",
              "EXEC_PLATFORM_STATE_OWNER_SCHEMA": "v1",
              "EXEC_PLATFORM_STATE_OWNER_UID": "<UID>",
              "EXEC_RUN_ID": "<RUN_ID>",
              "EXEC_WORKLOAD_IDENTITY_ENDPOINT": "unix:///run/es-runtime-identity/<RUN_ID>/endpoint",
              "EXEC_WORKLOAD_VAULT_AUTH_MODE": "vault_identity_jwt",
              "EXEC_WORKLOAD_VAULT_AUTH_MOUNT": "jwt",
              "EXEC_WORKLOAD_VAULT_AUTH_ROLE": "execution",
              "EXEC_WORKLOAD_VAULT_JWT_AUDIENCE": "vault",
              "EXEC_WORK_DIR": "/execution/run/work",
              "SERVICE_ID": "execution",
              "VAULT_ADDR": "https://vault.internal:8200"
            },
            "Meta": {
              "artifact_digest": "sha256:2d18fec2eaba5507f4d265b7b3615e31d72fcb835196109c2eea042e93603613",
              "derivation_spec_digest": "sha256:4444444444444444444444444444444444444444444444444444444444444444",
              "output_id": "runtime",
              "run_id": "<RUN_ID>"
            },
            "Name": "task",
            "Resources": {
              "CPU": 10,
              "MemoryMB": 128
            },
            "User": "0:0"
          }
        ]
      }
    ],
    "Type": "batch"
  }
}`

const trancheB1DefaultAuthorityHandoffGolden = `{
  "authority_path": "workload_identity_endpoint/workload_vault",
  "evidence": {
    "identity_handoff": "submitted_runtime_environment",
    "runtime_config_refs": "submitted_runtime_metadata",
    "runtime_profile": "es_selected_runtime_profile",
    "source": "submitted_runtime_spec",
    "workload_vault": "submitted_runtime_environment"
  },
  "identity_handoff": {
    "endpoint_env": "EXEC_WORKLOAD_IDENTITY_ENDPOINT",
    "endpoint_uri": "unix:///run/es-runtime-identity/<RUN_ID>/endpoint",
    "jwt_svid_target": "workload_vault",
    "mode": "workload_identity_endpoint"
  },
  "runtime_config_refs": {
    "workload_zone_vault_config": {
      "digest": "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    }
  },
  "runtime_profile": {
    "name": "static-script/default"
  },
  "workload_vault": {
    "address": "https://vault.internal:8200",
    "auth_mode": "vault_identity_jwt",
    "auth_mount": "jwt",
    "auth_role": "execution",
    "jwt_audience": "vault"
  }
}`

const trancheB2ControlPlaneNormalShellNomadJobGolden = `{
  "Job": {
    "Datacenters": [
      "dc1"
    ],
    "ID": "<JOB_ID>",
    "Meta": {
      "execution_substrate.authority_handoff.runtime_profile": "control-plane-normal-shell/v1",
      "execution_substrate.authority_handoff.schema": "v1",
      "execution_substrate.authority_handoff.workload_zone_vault_config_digest": "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
      "run_id": "<RUN_ID>"
    },
    "Name": "<JOB_ID>",
    "TaskGroups": [
      {
        "Count": 1,
        "Name": "group",
        "ReschedulePolicy": {
          "Attempts": 0,
          "Delay": 0,
          "DelayFunction": "constant",
          "MaxDelay": 0,
          "Unlimited": false
        },
        "RestartPolicy": {
          "Attempts": 0,
          "Delay": 10000000000,
          "Interval": 60000000000,
          "Mode": "fail"
        },
        "Tasks": [
          {
            "Config": {
              "args": [
                "supervisor",
                "--payload-archive",
                "/execution/staged/artifact.tar.gz",
                "--work-dir",
                "/execution/run/work",
                "--result-dir",
                "/execution/run/result",
                "--entrypoint",
                "/execution/run/work/entrypoint",
                "--timeout-seconds",
                "17",
                "--",
                "python3",
                "control_plane_remote_normal_shell.py"
              ],
              "command": "/execution/run/platform/es-runtime-support",
              "image": "execution-substrate/control-plane-normal-shell:test",
              "mounts": [
                {
                  "readonly": true,
                  "source": "<STAGING_ROOT>/payload",
                  "target": "/execution/staged",
                  "type": "bind"
                },
                {
                  "readonly": false,
                  "source": "<STAGING_ROOT>/run",
                  "target": "/execution/run",
                  "type": "bind"
                },
                {
                  "readonly": false,
                  "target": "/run/es-runtime-identity/<RUN_ID>",
                  "tmpfs_options": {
                    "size": 1048576
                  },
                  "type": "tmpfs"
                },
                {
                  "readonly": true,
                  "source": "<SPIRE_SOURCE>",
                  "target": "/run/es-runtime-identity/<RUN_ID>/internal/source",
                  "type": "bind"
                },
                {
                  "readonly": true,
                  "source": "<STAGING_ROOT>/mounts/00/contents",
                  "target": "/execution/mounts/config",
                  "type": "bind"
                }
              ],
              "network_mode": "bridge",
              "privileged": false,
              "security_opt": [
                "no-new-privileges"
              ]
            },
            "Driver": "docker",
            "Env": {
              "APP_MODE": "control-plane",
              "EXEC_ARTIFACT_DIGEST": "sha256:2d18fec2eaba5507f4d265b7b3615e31d72fcb835196109c2eea042e93603613",
              "EXEC_CODEX_CLI_PATH": "/usr/local/bin/codex",
              "EXEC_CODEX_CREDENTIAL_SOURCE": "workload_vault",
              "EXEC_CODEX_CREDENTIAL_VAULT_SECRET_FIELD": "api_key",
              "EXEC_CODEX_CREDENTIAL_VAULT_SECRET_PATH": "proof-secrets/data/codex-runtime-profile",
              "EXEC_PLATFORM_STATE_OWNER_GID": "<GID>",
              "EXEC_PLATFORM_STATE_OWNER_SCHEMA": "v1",
              "EXEC_PLATFORM_STATE_OWNER_UID": "<UID>",
              "EXEC_RUN_ID": "<RUN_ID>",
              "EXEC_WORKLOAD_IDENTITY_ENDPOINT": "unix:///run/es-runtime-identity/<RUN_ID>/endpoint",
              "EXEC_WORKLOAD_VAULT_AUTH_MODE": "vault_identity_jwt",
              "EXEC_WORKLOAD_VAULT_AUTH_MOUNT": "jwt",
              "EXEC_WORKLOAD_VAULT_AUTH_ROLE": "execution",
              "EXEC_WORKLOAD_VAULT_JWT_AUDIENCE": "vault",
              "EXEC_WORK_DIR": "/execution/run/work",
              "SERVICE_ID": "execution",
              "VAULT_ADDR": "https://vault.internal:8200"
            },
            "Meta": {
              "artifact_digest": "sha256:2d18fec2eaba5507f4d265b7b3615e31d72fcb835196109c2eea042e93603613",
              "derivation_spec_digest": "sha256:4444444444444444444444444444444444444444444444444444444444444444",
              "output_id": "runtime",
              "run_id": "<RUN_ID>"
            },
            "Name": "task",
            "Resources": {
              "CPU": 23,
              "MemoryMB": 257
            },
            "User": "0:0"
          }
        ]
      }
    ],
    "Type": "batch"
  }
}`

const trancheB2ControlPlaneNormalShellAuthorityHandoffGolden = `{
  "authority_path": "workload_identity_endpoint/workload_vault",
  "codex_credential_location": {
    "cli_path": "/usr/local/bin/codex",
    "credential_source": "workload_vault",
    "vault_secret_field": "api_key",
    "vault_secret_path": "proof-secrets/data/codex-runtime-profile"
  },
  "evidence": {
    "codex_credential_location": "submitted_runtime_environment",
    "identity_handoff": "submitted_runtime_environment",
    "runtime_config_refs": "submitted_runtime_metadata",
    "runtime_profile": "es_selected_runtime_profile",
    "source": "submitted_runtime_spec",
    "workload_vault": "submitted_runtime_environment"
  },
  "identity_handoff": {
    "endpoint_env": "EXEC_WORKLOAD_IDENTITY_ENDPOINT",
    "endpoint_uri": "unix:///run/es-runtime-identity/<RUN_ID>/endpoint",
    "jwt_svid_target": "workload_vault",
    "mode": "workload_identity_endpoint"
  },
  "runtime_config_refs": {
    "workload_zone_vault_config": {
      "digest": "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    }
  },
  "runtime_profile": {
    "name": "control-plane-normal-shell/v1"
  },
  "workload_vault": {
    "address": "https://vault.internal:8200",
    "auth_mode": "vault_identity_jwt",
    "auth_mount": "jwt",
    "auth_role": "execution",
    "jwt_audience": "vault"
  }
}`

type resolvedPlanRoundTripper func(*http.Request) (*http.Response, error)

func (transport resolvedPlanRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	return transport(request)
}

func newResolvedPlanDependencyClient(t *testing.T, handler http.Handler) *dependencyClient {
	t.Helper()
	baseURL, err := url.Parse("http://artifact-registry.test")
	if err != nil {
		t.Fatal("parse test dependency URL failed")
	}
	return &dependencyClient{
		baseURL: baseURL,
		client: &http.Client{Transport: resolvedPlanRoundTripper(func(request *http.Request) (*http.Response, error) {
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, request)
			return recorder.Result(), nil
		})},
	}
}

func newResolvedPlanNomadClient(t *testing.T, handler http.Handler) *nomadClient {
	t.Helper()
	baseURL, err := url.Parse("http://nomad.test")
	if err != nil {
		t.Fatal("parse test Nomad URL failed")
	}
	return &nomadClient{
		baseURL:    baseURL,
		datacenter: "dc1",
		client: &http.Client{Transport: resolvedPlanRoundTripper(func(request *http.Request) (*http.Response, error) {
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, request)
			return recorder.Result(), nil
		})},
	}
}

func resolvedPlanArtifactHandler(t *testing.T, fixture preparedArtifactFixture, policyPayload []byte, vaultHook func()) http.Handler {
	t.Helper()
	return http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/v1/artifacts/" + fixture.discovery.Artifact.ArtifactDigest + "/discovery":
			writeJSONResponse(t, w, http.StatusOK, fixture.discovery)
		case "/v1/blobs/" + fixture.discovery.Evidence.Digest + ":json":
			writeJSONResponse(t, w, http.StatusOK, fixture.evidence)
		case "/v1/blobs/" + testWorkloadZoneVaultConfigDigest + ":json":
			_, _ = w.Write([]byte(validWorkloadZoneVaultConfigBlob))
			if vaultHook != nil {
				vaultHook()
			}
		case "/v1/blobs/" + fixture.discovery.Payload.Digest + ":bytes":
			_, _ = w.Write(policyPayload)
		default:
			t.Fatal("resolved-plan fixture reached an unexpected artifact path")
		}
	})
}

func authorityHandoffsEquivalent(first ExecutionAuthorityHandoff, second ExecutionAuthorityHandoff) bool {
	if first.AuthorityPath != second.AuthorityPath || first.RuntimeProfile.Name != second.RuntimeProfile.Name || first.IdentityHandoff != second.IdentityHandoff || first.WorkloadVault != second.WorkloadVault || first.RuntimeConfigRefs != second.RuntimeConfigRefs || first.Evidence != second.Evidence {
		return false
	}
	if first.CodexCredentialLocation == nil || second.CodexCredentialLocation == nil {
		return first.CodexCredentialLocation == nil && second.CodexCredentialLocation == nil
	}
	return *first.CodexCredentialLocation == *second.CodexCredentialLocation
}

type resolvedNomadFixture struct {
	Job struct {
		ID          string            `json:"ID"`
		Name        string            `json:"Name"`
		Meta        map[string]string `json:"Meta"`
		Type        string            `json:"Type"`
		Datacenters []string          `json:"Datacenters"`
		TaskGroups  []struct {
			Name          string `json:"Name"`
			Count         int    `json:"Count"`
			RestartPolicy struct {
				Attempts int    `json:"Attempts"`
				Mode     string `json:"Mode"`
				Interval int64  `json:"Interval"`
				Delay    int64  `json:"Delay"`
			} `json:"RestartPolicy"`
			ReschedulePolicy struct {
				Attempts      int    `json:"Attempts"`
				Unlimited     bool   `json:"Unlimited"`
				Delay         int64  `json:"Delay"`
				DelayFunction string `json:"DelayFunction"`
				MaxDelay      int64  `json:"MaxDelay"`
			} `json:"ReschedulePolicy"`
			Tasks []struct {
				Name   string `json:"Name"`
				Driver string `json:"Driver"`
				User   string `json:"User"`
				Config struct {
					Image           string   `json:"image"`
					Command         string   `json:"command"`
					Arguments       []string `json:"args"`
					Privileged      bool     `json:"privileged"`
					SecurityOptions []string `json:"security_opt"`
					NetworkMode     string   `json:"network_mode"`
					Mounts          []struct {
						Type     string `json:"type"`
						Source   string `json:"source"`
						Target   string `json:"target"`
						ReadOnly bool   `json:"readonly"`
					} `json:"mounts"`
				} `json:"Config"`
				Environment map[string]string `json:"Env"`
				Resources   struct {
					CPU      int `json:"CPU"`
					MemoryMB int `json:"MemoryMB"`
				} `json:"Resources"`
				Meta map[string]string `json:"Meta"`
			} `json:"Tasks"`
		} `json:"TaskGroups"`
	} `json:"Job"`
}

func TestSubmitUsesSingleCapturedPlacementSnapshot(t *testing.T) {
	fixture := newPreparedArtifactFixture(t)
	service, stagingRoot, resultsRoot := newWorkstreamCTestService(t, fixture)
	request := fixture.prepareRequest()
	policyPayload := buildAdmissionPolicyStaticScriptArchive(t, map[string][]byte{
		staticScriptEntrypointName: []byte(benignPolicyFixtureText()),
	})
	// The successful Vault read occurs before the resolver's configuration
	// snapshot. An independent Submit results-root read sees the earlier value.
	service.cfg.Execution.ResultsRootDir = "relative/pre-capture-results-root"
	service.arsClient = newResolvedPlanDependencyClient(t, resolvedPlanArtifactHandler(t, fixture, policyPayload, func() {
		service.cfg.Execution.ResultsRootDir = resultsRoot
	}))
	nomadCalls := 0
	service.nomadClient = newResolvedPlanNomadClient(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		nomadCalls++
		_, _ = w.Write([]byte(`{"EvalID":"eval-123"}`))
	}))
	result, submitErr := service.Submit(context.Background(), request)
	if submitErr != nil || !result.Submitted || nomadCalls != 1 {
		t.Fatalf("Submit did not use one captured root pair: result=%+v err=%+v calls=%d", result, submitErr, nomadCalls)
	}
	if _, err := os.Stat(filepath.Join(stagingRoot, result.RunID)); err != nil {
		t.Fatalf("captured staging root did not receive run claim: %v", err)
	}

	// Mutation after the resolver returns cannot rewrite its private placement.
	resolved, resolveErr := service.resolveExecutionForSubmit(context.Background(), request)
	if resolveErr != nil {
		t.Fatalf("resolve for post-capture check: %+v", resolveErr)
	}
	service.cfg.Execution.StagingRootDir = "relative/post-capture-staging-root"
	service.cfg.Execution.ResultsRootDir = "relative/post-capture-results-root"
	if resolved.custodyPlacement.stagingRootDir != stagingRoot || resolved.custodyPlacement.resultsRootDir != resultsRoot || resolved.host.stagingRootDir != stagingRoot {
		t.Fatal("post-capture configuration mutation changed resolved root pair")
	}
}

func TestSubmitArtifactAndProfileErrorsPrecedePlacementValidation(t *testing.T) {
	policyPayload := buildAdmissionPolicyStaticScriptArchive(t, map[string][]byte{
		staticScriptEntrypointName: []byte(benignPolicyFixtureText()),
	})
	t.Run("artifact capability", func(t *testing.T) {
		fixture := newPreparedArtifactFixture(t)
		fixture.evidence.Claims.Admission.Execution.Runtime.RequiredCapabilities = []string{"unsupported-device"}
		resignPreparedArtifactFixture(t, &fixture)
		service, stagingRoot, resultsRoot := newWorkstreamCTestService(t, fixture)
		service.cfg.Execution.ResultsRootDir = "relative/invalid-results-root"
		service.arsClient = newResolvedPlanDependencyClient(t, resolvedPlanArtifactHandler(t, fixture, policyPayload, nil))
		service.nomadClient = newResolvedPlanNomadClient(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			t.Fatal("invalid artifact must not reach Nomad")
		}))
		_, submitErr := service.Submit(context.Background(), fixture.prepareRequest())
		if submitErr == nil || submitErr.Code != codeUnsupportedCapabilities || submitErr.Status != http.StatusBadRequest {
			t.Fatalf("placement error displaced artifact gate: %+v", submitErr)
		}
		assertDirectoryEmpty(t, stagingRoot)
		assertDirectoryEmpty(t, resultsRoot)
	})
	t.Run("profile", func(t *testing.T) {
		fixture := newPreparedArtifactFixture(t)
		service, stagingRoot, resultsRoot := newWorkstreamCTestService(t, fixture)
		service.cfg.Execution.ResultsRootDir = "relative/invalid-results-root"
		service.arsClient = newResolvedPlanDependencyClient(t, resolvedPlanArtifactHandler(t, fixture, policyPayload, nil))
		service.nomadClient = newResolvedPlanNomadClient(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			t.Fatal("invalid profile must not reach Nomad")
		}))
		request := fixture.prepareRequest()
		request.Invocation.Annotations = map[string]string{runtimeProfileAnnotationKey: "unsupported/v1"}
		_, submitErr := service.Submit(context.Background(), request)
		if submitErr == nil || submitErr.Code != codeUnsupportedRuntimeProfile || submitErr.Status != http.StatusBadRequest {
			t.Fatalf("placement error displaced profile gate: %+v", submitErr)
		}
		assertDirectoryEmpty(t, stagingRoot)
		assertDirectoryEmpty(t, resultsRoot)
	})
}

func TestSubmitPreservesExplicitNonblankLegacySchemasWithoutReliableEnablement(t *testing.T) {
	fixture := newPreparedArtifactFixture(t)
	service, _, _ := newWorkstreamCTestService(t, fixture)
	policyPayload := buildAdmissionPolicyStaticScriptArchive(t, map[string][]byte{
		staticScriptEntrypointName: []byte(benignPolicyFixtureText()),
	})
	service.arsClient = newResolvedPlanDependencyClient(t, resolvedPlanArtifactHandler(t, fixture, policyPayload, nil))
	calls := 0
	service.nomadClient = newResolvedPlanNomadClient(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		_, _ = w.Write([]byte(`{"EvalID":"eval-123"}`))
	}))
	for _, schema := range []string{"legacy-compat-v2", "execution-substrate.reliable-submit-request/v1"} {
		request := fixture.prepareRequest()
		request.SchemaVersion = schema
		request.Invocation.SchemaVersion = "invocation-compat-v2"
		result, submitErr := service.Submit(context.Background(), request)
		if submitErr != nil || !result.Submitted || result.RunID == "" {
			t.Fatalf("nonblank schema %q changed legacy Submit: result=%+v err=%+v", schema, result, submitErr)
		}
	}
	if calls != 2 {
		t.Fatalf("legacy schema cases registered %d jobs, want 2", calls)
	}
}
