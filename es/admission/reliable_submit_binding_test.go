package admission

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"execution-substrate/es/admission/internal/reliablesubmit"
	evidencev1 "execution-substrate/internal/contracts/evidence/v1"
)

// The success fixture goes through actual admission and submit resolution. The
// ordinary prepared-artifact fixture intentionally uses a synthetic digest
// unrelated to its payload, so bind the signed identity to the bytes here.
func reliableBindingResolvedFixture(t *testing.T) (resolvedExecution, reliableBindingFamily, privateBindingKey, string, string) {
	t.Helper()
	fixture := newPreparedArtifactFixture(t)
	payload := buildAdmissionPolicyStaticScriptArchive(t, map[string][]byte{
		staticScriptEntrypointName: []byte(benignPolicyFixtureText()),
	})
	a2BindSignedPayload(t, &fixture, payload)
	service, stagingRoot, resultsRoot := newWorkstreamCTestService(t, fixture)
	service.arsClient = newResolvedPlanDependencyClient(t, resolvedPlanArtifactHandler(t, fixture, payload, nil))
	service.nomadClient = newResolvedPlanNomadClient(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("private binding resolution must not register a job")
	}))
	resolved, resolveErr := service.resolveExecutionForSubmit(context.Background(), fixture.prepareRequest())
	if resolveErr != nil {
		t.Fatalf("resolve admitted synthetic execution: %v", resolveErr)
	}
	family, err := newReliableBindingFamily(reliableSubmitRequestSchemaV1, reliableSubmitContractV1)
	if err != nil {
		t.Fatal(err)
	}
	key, err := newPrivateBindingKey("test-key-v1", bytes.Repeat([]byte{0x0b}, 32))
	if err != nil {
		t.Fatal(err)
	}
	return resolved, family, key, stagingRoot, resultsRoot
}

func reliableBindingCloneResolved(input resolvedExecution) resolvedExecution {
	result := input
	result.plan.runtimeCommand = copyResolvedRuntimeCommand(input.plan.runtimeCommand)
	result.plan.semanticEnvironment = copyStringMap(input.plan.semanticEnvironment)
	result.plan.mounts = copyResolvedMountPlans(input.plan.mounts)
	result.plan.jobEnvelope = copyResolvedJobEnvelope(input.plan.jobEnvelope)
	result.material.payloadBytes = bytes.Clone(input.material.payloadBytes)
	result.material.runtimeSupportBytes = bytes.Clone(input.material.runtimeSupportBytes)
	result.material.trust.vaultCACertBytes = bytes.Clone(input.material.trust.vaultCACertBytes)
	result.material.trust.workloadTLSBundleBytes = bytes.Clone(input.material.trust.workloadTLSBundleBytes)
	if input.material.mounts != nil {
		result.material.mounts = make([]validatedMountArchive, len(input.material.mounts))
		for index, archive := range input.material.mounts {
			result.material.mounts[index].compressedBytes = bytes.Clone(archive.compressedBytes)
			if archive.entries != nil {
				result.material.mounts[index].entries = make([]validatedMountEntry, len(archive.entries))
				for entryIndex, entry := range archive.entries {
					result.material.mounts[index].entries[entryIndex] = entry
					result.material.mounts[index].entries[entryIndex].contents = bytes.Clone(entry.contents)
				}
			}
		}
	}
	return result
}

func reliableBindingMustBuild(t *testing.T, resolved resolvedExecution, family reliableBindingFamily, key privateBindingKey) admissionBindingAssessment {
	t.Helper()
	assessment, err := buildReliableSubmitAdmissionBinding(resolved, family, key)
	if err != nil {
		t.Fatalf("build private admission binding: %v", err)
	}
	if !assessment.boundPlan.Valid() || assessment.effectReady {
		t.Fatal("successful private binding must contain a bound plan and remain non-effect-ready")
	}
	for _, category := range reliablesubmit.AllEffectivePlanCategories() {
		resolution, err := assessment.boundPlan.Witness().Resolution(category)
		if err != nil || resolution != reliablesubmit.EffectivePlanResolved {
			t.Fatalf("category %d is not resolved: resolution=%d err=%v", category, resolution, err)
		}
	}
	return assessment
}

func reliableBindingMustRefuse(t *testing.T, resolved resolvedExecution, family reliableBindingFamily, key privateBindingKey) {
	t.Helper()
	assessment, err := buildReliableSubmitAdmissionBinding(resolved, family, key)
	if err == nil || assessment.boundPlan.Valid() || assessment.effectReady {
		t.Fatal("incomplete or incoherent source facts produced a bound plan")
	}
}

func reliableBindingAttachMount(t *testing.T, resolved *resolvedExecution, archiveBytes []byte, target, artifactDigest string) {
	t.Helper()
	parsed, _, _, err := validateRuntimeMountArchiveWithinBudgets(
		archiveBytes,
		maxRuntimeMountBytes,
		maxRuntimeMountTotalBytes,
		maxRuntimeMountStreamBytes,
		maxRuntimeMountTotalStreamBytes,
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	resolved.plan.mounts = append(resolved.plan.mounts, resolvedMountPlan{
		artifactDigest:         artifactDigest,
		verifiedArtifactDigest: artifactDigest,
		payloadDigest:          digestBytes(archiveBytes),
		targetPath:             target,
		readOnly:               true,
	})
	resolved.material.mounts = append(resolved.material.mounts, parsed)
}

func TestReliableSubmitBindingCategories(t *testing.T) {
	base, family, key, _, _ := reliableBindingResolvedFixture(t)
	original := reliableBindingMustBuild(t, base, family, key)
	tests := []struct {
		name   string
		change func(*resolvedExecution)
	}{
		{"schema", func(v *resolvedExecution) { v.plan.requestSchemaVersion = "legacy-compat-v2" }},
		{"mode", func(v *resolvedExecution) { v.plan.mode = ExecutionModeSync }},
		{"timeout", func(v *resolvedExecution) {
			v.plan.timeoutSeconds++
			v.plan.runtimeCommand.arguments[10] = "1"
		}},
		{"cpu", func(v *resolvedExecution) { v.plan.resources.cpu++ }},
		{"memory", func(v *resolvedExecution) { v.plan.resources.memoryMB++ }},
		{"profile_image", func(v *resolvedExecution) { v.plan.runtimeProfile.image = "alpine:other" }},
		{"artifact_payload", func(v *resolvedExecution) {
			v.plan.artifactDigest = labeledDigest("dd")
			v.plan.semanticEnvironment["EXEC_ARTIFACT_DIGEST"] = v.plan.artifactDigest
		}},
		{"derivation", func(v *resolvedExecution) { v.plan.derivationSpecDigest = labeledDigest("ee") }},
		{"output", func(v *resolvedExecution) { v.plan.outputID += "-other" }},
		{"command_argv", func(v *resolvedExecution) {
			v.plan.runtimeCommand.arguments = append(v.plan.runtimeCommand.arguments, "extra")
		}},
		{"environment", func(v *resolvedExecution) { v.plan.semanticEnvironment["APP_MODE"] = "different" }},
		{"mounts", func(v *resolvedExecution) {
			reliableBindingAttachMount(t, v, mustRuntimeMountArchiveBytes(t, runtimeMountArchiveEntry{name: "config", body: []byte("x"), typeflag: '0', mode: 0o644}), "/execution/mounts/config", v.plan.artifactDigest)
		}},
		{"network", func(v *resolvedExecution) { v.plan.networkAccess = !v.plan.networkAccess }},
		{"authority", func(v *resolvedExecution) {
			v.plan.authority.workloadVault.authRole = "other"
			v.plan.semanticEnvironment["EXEC_WORKLOAD_VAULT_AUTH_ROLE"] = "other"
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			changed := reliableBindingCloneResolved(base)
			test.change(&changed)
			assessment, err := buildReliableSubmitAdmissionBinding(changed, family, key)
			if test.name == "mode" {
				if err == nil || assessment.boundPlan.Valid() {
					t.Fatal("unsupported execution mode acquired a witness")
				}
				return
			}
			if err != nil {
				t.Fatalf("coherent changed category was rejected: %v", err)
			}
			if original.boundPlan.EqualBinding(assessment.boundPlan.Binding()) {
				t.Fatal("changed category retained the original private binding")
			}
		})
	}
}

func TestReliableSubmitBindingEquivalentSparseAndExplicitInputs(t *testing.T) {
	fixture := newPreparedArtifactFixture(t)
	payload := buildAdmissionPolicyStaticScriptArchive(t, map[string][]byte{
		staticScriptEntrypointName: []byte(benignPolicyFixtureText()),
	})
	a2BindSignedPayload(t, &fixture, payload)
	service, _, _ := newWorkstreamCTestService(t, fixture)
	service.arsClient = newResolvedPlanDependencyClient(t, resolvedPlanArtifactHandler(t, fixture, payload, nil))
	service.nomadClient = newResolvedPlanNomadClient(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("resolver registered a job")
	}))
	sparse := fixture.prepareRequest()
	sparse.SchemaVersion = ""
	sparse.Invocation.SchemaVersion = ""
	sparse.Mode = ""
	sparse.Resources = nil
	sparse.Invocation.Argv = nil
	sparse.Invocation.Env = nil
	sparse.Invocation.Mounts = nil
	explicit := sparse
	explicit.SchemaVersion = "v1"
	explicit.Invocation.SchemaVersion = "v1"
	explicit.Mode = ExecutionModeAsync
	explicit.Resources = &ExecutionResources{CPU: 10, MemoryMB: 128}
	explicit.Invocation.Argv = []string{}
	explicit.Invocation.Env = map[string]string{}
	explicit.Invocation.Mounts = []RuntimeMount{}
	a, errA := service.resolveExecutionForSubmit(context.Background(), sparse)
	b, errB := service.resolveExecutionForSubmit(context.Background(), explicit)
	if errA != nil || errB != nil {
		t.Fatalf("actual admission failed: sparse=%v explicit=%v", errA, errB)
	}
	family, _ := newReliableBindingFamily(reliableSubmitRequestSchemaV1, reliableSubmitContractV1)
	key, _ := newPrivateBindingKey("same-effective", bytes.Repeat([]byte{0x0b}, 32))
	aAssessment := reliableBindingMustBuild(t, a, family, key)
	bAssessment := reliableBindingMustBuild(t, b, family, key)
	if !aAssessment.boundPlan.EqualBinding(bAssessment.boundPlan.Binding()) {
		t.Fatal("sparse and explicit presentations with equal admitted values produced different binding")
	}
}

func TestReliableSubmitBindingCanonicalOrderAndNormalizationCollision(t *testing.T) {
	base, family, key, _, _ := reliableBindingResolvedFixture(t)
	base.plan.semanticEnvironment["alpha"] = "one"
	base.plan.semanticEnvironment["beta"] = "two"
	first := reliableBindingMustBuild(t, base, family, key)
	reordered := reliableBindingCloneResolved(base)
	reordered.plan.semanticEnvironment = map[string]string{}
	for _, name := range []string{"beta", "alpha"} {
		reordered.plan.semanticEnvironment[name] = base.plan.semanticEnvironment[name]
	}
	for name, value := range base.plan.semanticEnvironment {
		if name != "alpha" && name != "beta" {
			reordered.plan.semanticEnvironment[name] = value
		}
	}
	second := reliableBindingMustBuild(t, reordered, family, key)
	if !first.boundPlan.EqualBinding(second.boundPlan.Binding()) {
		t.Fatal("Go map insertion order affected canonical environment encoding")
	}
	argvA := reliableBindingCloneResolved(base)
	argvA.plan.runtimeCommand.arguments = append(argvA.plan.runtimeCommand.arguments, "one", "two")
	argvB := reliableBindingCloneResolved(base)
	argvB.plan.runtimeCommand.arguments = append(argvB.plan.runtimeCommand.arguments, "two", "one")
	if reliableBindingMustBuild(t, argvA, family, key).boundPlan.EqualBinding(reliableBindingMustBuild(t, argvB, family, key).boundPlan.Binding()) {
		t.Fatal("ordered argument change did not change binding")
	}
	archive := mustRuntimeMountArchiveBytes(t, runtimeMountArchiveEntry{name: "file", body: []byte("x"), typeflag: '0', mode: 0o644})
	mountsA := reliableBindingCloneResolved(base)
	reliableBindingAttachMount(t, &mountsA, archive, "/execution/mounts/one", base.plan.artifactDigest)
	reliableBindingAttachMount(t, &mountsA, archive, "/execution/mounts/two", base.plan.artifactDigest)
	mountsB := reliableBindingCloneResolved(mountsA)
	mountsB.plan.mounts[0], mountsB.plan.mounts[1] = mountsB.plan.mounts[1], mountsB.plan.mounts[0]
	mountsB.material.mounts[0], mountsB.material.mounts[1] = mountsB.material.mounts[1], mountsB.material.mounts[0]
	if reliableBindingMustBuild(t, mountsA, family, key).boundPlan.EqualBinding(reliableBindingMustBuild(t, mountsB, family, key).boundPlan.Binding()) {
		t.Fatal("ordered mount change did not change binding")
	}
	unclean := reliableBindingCloneResolved(mountsA)
	unclean.plan.mounts[0].targetPath = "/execution/mounts/../mounts/one"
	reliableBindingMustRefuse(t, unclean, family, key)
	collision := reliableBindingCloneResolved(mountsA)
	collision.plan.mounts[1].targetPath = collision.plan.mounts[0].targetPath
	reliableBindingMustRefuse(t, collision, family, key)
}

func TestReliableSubmitBindingEmptyUnresolvedAndApplicability(t *testing.T) {
	base, family, key, _, _ := reliableBindingResolvedFixture(t)
	empty := reliableBindingCloneResolved(base)
	empty.plan.mounts = []resolvedMountPlan{}
	empty.material.mounts = []validatedMountArchive{}
	a := reliableBindingMustBuild(t, base, family, key)
	b := reliableBindingMustBuild(t, empty, family, key)
	if !a.boundPlan.EqualBinding(b.boundPlan.Binding()) {
		t.Fatal("nil and concrete empty mount collections encoded differently")
	}
	resolution, err := a.boundPlan.Witness().Resolution(reliablesubmit.EffectivePlanCategoryAuthorityHandoffApplicability)
	if err != nil || resolution != reliablesubmit.EffectivePlanResolved || base.plan.authority.codexCredential.applicable {
		t.Fatal("current unconditional handoff and optional Codex location were conflated")
	}
	missing := reliableBindingCloneResolved(base)
	missing.plan.outputID = ""
	reliableBindingMustRefuse(t, missing, family, key)
	contradictoryCodex := reliableBindingCloneResolved(base)
	contradictoryCodex.plan.authority.codexCredential.cliPath = "/private/cli"
	reliableBindingMustRefuse(t, contradictoryCodex, family, key)
	missingFamily := family
	missingFamily.validated = false
	reliableBindingMustRefuse(t, base, missingFamily, key)

	// This positive path uses the real resolver and signed synthetic evidence.
	// No runtime, Codex executable, or real credential is involved.
	fixture := newPreparedArtifactFixture(t)
	payload := buildAdmissionPolicyStaticScriptArchive(t, map[string][]byte{
		staticScriptEntrypointName: []byte(benignPolicyFixtureText()),
	})
	a2BindSignedPayload(t, &fixture, payload)
	service, _, _ := newWorkstreamCTestService(t, fixture)
	service.cfg.Execution.RuntimeProfiles = controlPlaneNormalShellProfileExecutionConfig().RuntimeProfiles
	service.arsClient = newResolvedPlanDependencyClient(t, resolvedPlanArtifactHandler(t, fixture, payload, nil))
	service.nomadClient = newResolvedPlanNomadClient(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("unwired control-plane binding registered a job")
	}))
	request := fixture.prepareRequest()
	request.Invocation.Annotations = map[string]string{runtimeProfileAnnotationKey: runtimeProfileControlPlaneNormalShell}
	profiled, resolveErr := service.resolveExecutionForSubmit(context.Background(), request)
	if resolveErr != nil {
		t.Fatalf("resolve signed synthetic control-plane profile: %v", resolveErr)
	}
	if profiled.plan.runtimeProfile.name != runtimeProfileControlPlaneNormalShell || !profiled.plan.authority.codexCredential.applicable ||
		profiled.plan.authority.runtimeProfileName != profiled.plan.runtimeProfile.name {
		t.Fatal("applicable Codex location did not derive from admitted profile")
	}
	location := profiled.plan.authority.codexCredential
	for field, expected := range map[string]string{
		codexCLIPathEnvKey:                    location.cliPath,
		codexCredentialSourceEnvKey:           location.credentialSource,
		codexCredentialVaultSecretPathEnvKey:  location.vaultSecretPath,
		codexCredentialVaultSecretFieldEnvKey: location.vaultSecretField,
	} {
		if expected == "" || profiled.plan.semanticEnvironment[field] != expected {
			t.Fatalf("applicable Codex location/environment mismatch: %s", field)
		}
	}
	profiledAssessment := reliableBindingMustBuild(t, profiled, family, key)
	if profiledAssessment.effectReady || profiledAssessment.boundPlan.EqualBinding(a.boundPlan.Binding()) {
		t.Fatal("applicable profile was effect-ready or indistinct from default profile")
	}
	for _, change := range []struct {
		name  string
		field string
		apply func(*resolvedCodexCredentialLocation)
	}{
		{"CLI path", codexCLIPathEnvKey, func(v *resolvedCodexCredentialLocation) { v.cliPath = "/opt/synthetic/codex" }},
		{"secret path", codexCredentialVaultSecretPathEnvKey, func(v *resolvedCodexCredentialLocation) { v.vaultSecretPath = "proof-secrets/data/other" }},
		{"secret field", codexCredentialVaultSecretFieldEnvKey, func(v *resolvedCodexCredentialLocation) { v.vaultSecretField = "other_key" }},
	} {
		t.Run(change.name, func(t *testing.T) {
			other := reliableBindingCloneResolved(profiled)
			change.apply(&other.plan.authority.codexCredential)
			switch change.field {
			case codexCLIPathEnvKey:
				other.plan.semanticEnvironment[change.field] = other.plan.authority.codexCredential.cliPath
			case codexCredentialVaultSecretPathEnvKey:
				other.plan.semanticEnvironment[change.field] = other.plan.authority.codexCredential.vaultSecretPath
			case codexCredentialVaultSecretFieldEnvKey:
				other.plan.semanticEnvironment[change.field] = other.plan.authority.codexCredential.vaultSecretField
			}
			if profiledAssessment.boundPlan.EqualBinding(reliableBindingMustBuild(t, other, family, key).boundPlan.Binding()) {
				t.Fatal("coherently changed applicable location retained binding")
			}
		})
	}
	for _, change := range []func(*resolvedExecution){
		func(v *resolvedExecution) { v.plan.authority.codexCredential.applicable = false },
		func(v *resolvedExecution) { v.plan.runtimeProfile.name = runtimeProfileDefaultStaticScript },
		func(v *resolvedExecution) { v.plan.semanticEnvironment[codexCLIPathEnvKey] = "/different/cli" },
		func(v *resolvedExecution) { v.plan.authority.codexCredential.credentialSource = "unreviewed_source" },
	} {
		contradiction := reliableBindingCloneResolved(profiled)
		change(&contradiction)
		reliableBindingMustRefuse(t, contradiction, family, key)
	}
}

func TestReliableSubmitBindingHostAndMutableImageLimits(t *testing.T) {
	base, family, key, _, _ := reliableBindingResolvedFixture(t)
	original := reliableBindingMustBuild(t, base, family, key)
	changed := reliableBindingCloneResolved(base)
	changed.host.stagingRootDir = "/different/staging"
	changed.custodyPlacement.stagingRootDir = changed.host.stagingRootDir
	changed.custodyPlacement.resultsRootDir = "/different/results"
	changed.host.owner.UID++
	changed.host.spireSourceDir = "/different/spire"
	changed.host.datacenter = "different-dc"
	other := reliableBindingMustBuild(t, changed, family, key)
	if !original.boundPlan.EqualBinding(other.boundPlan.Binding()) || original.effectReady || other.effectReady {
		t.Fatal("captured host facts became semantic binding or effect permission")
	}
	if original.placement.stagingRootDir == other.placement.stagingRootDir || original.placement.owner.UID == other.placement.owner.UID {
		t.Fatal("assessment did not retain distinct captured placement prerequisites")
	}
	image := reliableBindingCloneResolved(base)
	image.plan.runtimeProfile.image = "alpine:other-tag"
	if original.boundPlan.EqualBinding(reliableBindingMustBuild(t, image, family, key).boundPlan.Binding()) {
		t.Fatal("selected image reference did not affect semantic binding")
	}
}

func TestReliableSubmitBindingKeyVersionAndRotation(t *testing.T) {
	base, family, key, _, _ := reliableBindingResolvedFixture(t)
	original := reliableBindingMustBuild(t, base, family, key)
	otherID, err := newPrivateBindingKey("other-key", bytes.Repeat([]byte{0x0b}, 32))
	if err != nil {
		t.Fatal(err)
	}
	otherBytes, err := newPrivateBindingKey("test-key-v1", bytes.Repeat([]byte{0x0c}, 32))
	if err != nil {
		t.Fatal(err)
	}
	for _, changed := range []privateBindingKey{otherID, otherBytes} {
		if original.boundPlan.EqualBinding(reliableBindingMustBuild(t, base, family, changed).boundPlan.Binding()) {
			t.Fatal("key ID or key rotation retained original binding")
		}
	}
	for _, invalid := range []struct {
		id  string
		key []byte
	}{
		{"", bytes.Repeat([]byte{1}, 32)},
		{"bad key", bytes.Repeat([]byte{1}, 32)},
		{strings.Repeat("a", 65), bytes.Repeat([]byte{1}, 32)},
		{"ok", bytes.Repeat([]byte{1}, 31)},
	} {
		if _, err := newPrivateBindingKey(invalid.id, invalid.key); err == nil {
			t.Fatal("invalid private binding key or key ID accepted")
		}
	}
}

func TestReliableSubmitBindingInvalidWitnessBeforeEffect(t *testing.T) {
	base, family, key, stagingRoot, resultsRoot := reliableBindingResolvedFixture(t)
	for _, change := range []func(*resolvedExecution){
		func(v *resolvedExecution) { v.plan.resources.cpu = 0 },
		func(v *resolvedExecution) { v.plan.runtimeCommand.arguments[10] = "999" },
		func(v *resolvedExecution) { v.plan.authority.runtimeProfileName = "wrong" },
		func(v *resolvedExecution) { v.plan.mounts = []resolvedMountPlan{{}} },
	} {
		invalid := reliableBindingCloneResolved(base)
		change(&invalid)
		reliableBindingMustRefuse(t, invalid, family, key)
	}
	for _, root := range []string{stagingRoot, resultsRoot} {
		entries, err := os.ReadDir(root)
		if err != nil || len(entries) != 0 {
			t.Fatal("invalid private witness produced a filesystem effect")
		}
	}
}

func TestReliableSubmitBindingCapturedMaterialProvenance(t *testing.T) {
	base, family, key, _, _ := reliableBindingResolvedFixture(t)
	original := reliableBindingMustBuild(t, base, family, key)
	for _, test := range []struct {
		name   string
		change func(*resolvedExecution)
	}{
		{"primary bytes", func(v *resolvedExecution) { v.material.payloadBytes[0] ^= 1 }},
		{"primary signed digest", func(v *resolvedExecution) { v.plan.payloadDigest = digestBytes([]byte("other")) }},
		{"support bytes", func(v *resolvedExecution) { v.material.runtimeSupportBytes[0] ^= 1 }},
		{"support digest", func(v *resolvedExecution) { v.plan.runtimeSupportDigest = digestBytes([]byte("other")) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			changed := reliableBindingCloneResolved(base)
			test.change(&changed)
			reliableBindingMustRefuse(t, changed, family, key)
		})
	}
	t.Run("tmpfs size is bound", func(t *testing.T) {
		changed := reliableBindingCloneResolved(base)
		changed.plan.runtimeIdentityTmpfsSize++
		if original.boundPlan.EqualBinding(reliableBindingMustBuild(t, changed, family, key).boundPlan.Binding()) {
			t.Fatal("changed runtime-identity tmpfs size retained binding")
		}
	})
	t.Run("fixed job envelope coherence", func(t *testing.T) {
		changed := reliableBindingCloneResolved(base)
		changed.plan.jobEnvelope.securityOptions[0] = "other"
		reliableBindingMustRefuse(t, changed, family, key)
	})
	t.Run("trust bytes and flags", func(t *testing.T) {
		changed := reliableBindingCloneResolved(base)
		changed.material.trust.vaultCACertBytes = []byte("synthetic-vault-ca")
		changed.material.trust.workloadTLSBundleBytes = []byte("synthetic-combined-ca")
		changed.plan.authority.trustMaterial.vaultCACert = true
		changed.plan.authority.trustMaterial.workloadTLSBundle = true
		changed.plan.semanticEnvironment["VAULT_CACERT"] = executionRuntimePlatformDir + "/" + executionWorkloadVaultCAName
		changed.plan.semanticEnvironment["SSL_CERT_FILE"] = executionRuntimePlatformDir + "/" + executionWorkloadTLSBundleName
		other := reliableBindingMustBuild(t, changed, family, key)
		if original.boundPlan.EqualBinding(other.boundPlan.Binding()) || other.material.vaultCA.state != bindingStatePresent || other.material.tls.state != bindingStatePresent ||
			other.material.vaultCA.length != int64(len(changed.material.trust.vaultCACertBytes)) ||
			other.material.vaultCA.digest != sha256.Sum256(changed.material.trust.vaultCACertBytes) ||
			other.material.tls.length != int64(len(changed.material.trust.workloadTLSBundleBytes)) ||
			other.material.tls.digest != sha256.Sum256(changed.material.trust.workloadTLSBundleBytes) {
			t.Fatal("captured trust bytes or applicability did not affect private binding")
		}
		invalid := reliableBindingCloneResolved(changed)
		invalid.plan.authority.trustMaterial.vaultCACert = false
		reliableBindingMustRefuse(t, invalid, family, key)
	})
}

func TestReliableSubmitBindingRejectsMismatchedSignedMountArtifact(t *testing.T) {
	fixtureA := newPreparedArtifactFixture(t)
	payloadP := buildAdmissionPolicyStaticScriptArchive(t, map[string][]byte{
		staticScriptEntrypointName: []byte(benignPolicyFixtureText()),
	})
	a2BindSignedPayload(t, &fixtureA, payloadP)
	fixtureB := fixtureA
	identityB, err := evidencev1.NewArtifactIdentity(digestBytes(payloadP), "static-script", labeledDigest("cc"))
	if err != nil {
		t.Fatal(err)
	}
	fixtureB.evidence.Claims.Package.Identity = identityB
	fixtureB.discovery.Artifact.ArtifactDigest = identityB.ArtifactDigest
	fixtureB.discovery.Artifact.ArtifactType = identityB.ArtifactType
	fixtureB.discovery.Artifact.IntentDigest = identityB.IntentDigest
	fixtureB.discovery.Payload.Digest = identityB.PayloadDigest
	resignPreparedArtifactFixture(t, &fixtureB)
	if fixtureA.discovery.Artifact.ArtifactDigest == fixtureB.discovery.Artifact.ArtifactDigest {
		t.Fatal("signed A/B fixture did not change artifact identity")
	}
	mismatchedBytes := mustRuntimeMountArchiveBytes(t, runtimeMountArchiveEntry{name: "different", body: []byte("Q"), typeflag: '0', mode: 0o644})
	for _, test := range []struct {
		name         string
		mountFixture preparedArtifactFixture
		mountBytes   []byte
		wantRefusal  bool
		// wantFetchRefusal: the resolver itself refuses the mount read because
		// the served bytes do not hash to the signed payload digest.
		wantFetchRefusal bool
	}{
		{"A B P substitution", fixtureB, payloadP, true, false},
		{"A A P control", fixtureA, payloadP, false, false},
		{"A A Q byte mismatch", fixtureA, mismatchedBytes, true, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			service, stagingRoot, resultsRoot := newWorkstreamCTestService(t, fixtureA)
			request := fixtureA.prepareRequest()
			request.Invocation.Mounts = []RuntimeMount{{
				Source:     MountSource{ArtifactDigest: fixtureA.discovery.Artifact.ArtifactDigest},
				TargetPath: "/execution/mounts/config",
				ReadOnly:   true,
			}}
			discoveryReads, payloadReads := 0, 0
			service.arsClient = newResolvedPlanDependencyClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/v1/artifacts/" + fixtureA.discovery.Artifact.ArtifactDigest + "/discovery":
					discoveryReads++
					if discoveryReads == 1 {
						writeJSONResponse(t, w, http.StatusOK, fixtureA.discovery)
					} else {
						writeJSONResponse(t, w, http.StatusOK, test.mountFixture.discovery)
					}
				case "/v1/blobs/" + fixtureA.discovery.Evidence.Digest + ":json":
					writeJSONResponse(t, w, http.StatusOK, fixtureA.evidence)
				case "/v1/blobs/" + fixtureB.discovery.Evidence.Digest + ":json":
					writeJSONResponse(t, w, http.StatusOK, fixtureB.evidence)
				case "/v1/blobs/" + testWorkloadZoneVaultConfigDigest + ":json":
					_, _ = w.Write([]byte(validWorkloadZoneVaultConfigBlob))
				case "/v1/blobs/" + fixtureA.discovery.Payload.Digest + ":bytes":
					payloadReads++
					if payloadReads == 1 {
						_, _ = w.Write(payloadP)
					} else {
						_, _ = w.Write(test.mountBytes)
					}
				default:
					t.Fatalf("unexpected synthetic ARS route %q", r.URL.Path)
				}
			}))
			service.nomadClient = newResolvedPlanNomadClient(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				t.Fatal("unwired resolver/builder registered a job")
			}))
			resolved, resolveErr := service.resolveExecutionForSubmit(context.Background(), request)
			if test.wantFetchRefusal {
				assertAdmissionError(t, resolveErr, http.StatusServiceUnavailable, codePayloadUnavailable)
				if resolveErr.Message != artifactPayloadDigestMismatchMessage || discoveryReads != 2 || payloadReads != 2 {
					t.Fatalf("mount bytes that do not match the signed payload digest were not refused at the read: %v", resolveErr)
				}
				assertDirectoryEmpty(t, stagingRoot)
				assertDirectoryEmpty(t, resultsRoot)
				return
			}
			if resolveErr != nil {
				t.Fatalf("current legacy resolver rejection changed: %v", resolveErr)
			}
			if discoveryReads != 2 || payloadReads != 2 || len(resolved.plan.mounts) != 1 {
				t.Fatal("synthetic two-acquisition source path changed")
			}
			if resolved.plan.mounts[0].artifactDigest != fixtureA.discovery.Artifact.ArtifactDigest ||
				resolved.plan.mounts[0].verifiedArtifactDigest != test.mountFixture.discovery.Artifact.ArtifactDigest ||
				resolved.plan.mounts[0].payloadDigest != fixtureA.discovery.Payload.Digest {
				t.Fatal("requested, verified and signed mount provenance was conflated")
			}
			family, _ := newReliableBindingFamily(reliableSubmitRequestSchemaV1, reliableSubmitContractV1)
			key, _ := newPrivateBindingKey("signed-mount-test", bytes.Repeat([]byte{0x0b}, 32))
			if test.wantRefusal {
				reliableBindingMustRefuse(t, resolved, family, key)
			} else {
				reliableBindingMustBuild(t, resolved, family, key)
			}
			for _, root := range []string{stagingRoot, resultsRoot} {
				entries, err := os.ReadDir(root)
				if err != nil || len(entries) != 0 {
					t.Fatal("private producer created run material")
				}
			}
		})
	}
}

// TestReliableSubmitBindingRefusesMountBytesThatDoNotHashToTheMountPayloadDigest
// keeps the binding layer's own mount byte check under test. The resolver now
// refuses such bytes at the ARS read, so the end-to-end case above no longer
// reaches the binding layer.
func TestReliableSubmitBindingRefusesMountBytesThatDoNotHashToTheMountPayloadDigest(t *testing.T) {
	const target = "/execution/mounts/config"
	signed := mustRuntimeMountArchiveBytes(t, runtimeMountArchiveEntry{name: "config.txt", body: []byte("signed"), typeflag: '0', mode: 0o644})
	other := mustRuntimeMountArchiveBytes(t, runtimeMountArchiveEntry{name: "config.txt", body: []byte("other"), typeflag: '0', mode: 0o644})

	control, family, key, _, _ := reliableBindingResolvedFixture(t)
	reliableBindingAttachMount(t, &control, signed, target, control.plan.artifactDigest)
	reliableBindingMustBuild(t, control, family, key)

	mismatched, _, _, _, _ := reliableBindingResolvedFixture(t)
	reliableBindingAttachMount(t, &mismatched, other, target, mismatched.plan.artifactDigest)
	mismatched.plan.mounts[0].payloadDigest = digestBytes(signed)
	reliableBindingMustRefuse(t, mismatched, family, key)
}

func TestReliableSubmitBindingRejectsParsedMountDrift(t *testing.T) {
	base, family, key, _, _ := reliableBindingResolvedFixture(t)
	archive := mustRuntimeMountArchiveBytes(t,
		runtimeMountArchiveEntry{name: "./ name", body: []byte("x"), typeflag: '0', mode: 0o700},
		runtimeMountArchiveEntry{name: "empty", typeflag: '0', mode: 0o644},
		runtimeMountArchiveEntry{name: "ordinary", body: []byte("ordinary"), typeflag: '0', mode: 0o600},
		runtimeMountArchiveEntry{name: "executable", body: []byte("execute"), typeflag: '0', mode: 0o700},
		runtimeMountArchiveEntry{name: "directory", typeflag: '5', mode: 0o755},
		runtimeMountArchiveEntry{name: "directory", typeflag: '5', mode: 0o755},
	)
	reliableBindingAttachMount(t, &base, archive, "/execution/mounts/config", base.plan.artifactDigest)
	parsed := base.material.mounts[0].entries
	if len(parsed) != 6 || parsed[0].name != " name" || parsed[0].directory || parsed[0].mode != 0o755 ||
		!bytes.Equal(parsed[0].contents, []byte("x")) || parsed[1].name != "empty" || parsed[1].directory ||
		len(parsed[1].contents) != 0 || parsed[1].mode != 0o644 || parsed[2].name != "ordinary" ||
		parsed[2].mode != 0o644 || !bytes.Equal(parsed[2].contents, []byte("ordinary")) ||
		parsed[3].name != "executable" || parsed[3].mode != 0o755 || !bytes.Equal(parsed[3].contents, []byte("execute")) ||
		parsed[4].name != "directory" || !parsed[4].directory || parsed[4].mode != 0o755 ||
		parsed[5].name != "directory" || !parsed[5].directory || parsed[5].mode != 0o755 {
		t.Fatal("bounded mount parser lost ordered names, permitted repeats, kinds, modes or contents")
	}
	assessment := reliableBindingMustBuild(t, base, family, key)
	if len(assessment.material.mounts) != 1 || assessment.material.mounts[0].compressed.state != bindingStatePresent ||
		assessment.material.mounts[0].compressed.length != int64(len(archive)) ||
		assessment.material.mounts[0].compressed.digest != sha256.Sum256(archive) ||
		assessment.material.vaultCA.state != bindingStateAbsent || assessment.material.tls.state != bindingStateAbsent {
		t.Fatal("captured compressed or optional absent trust descriptor changed")
	}
	identities := assessment.material.mounts[0].entries
	if len(identities) != len(parsed) {
		t.Fatal("parsed mount entries were not retained as ordered descriptors")
	}
	for index, entry := range parsed {
		identity := identities[index]
		if identity.name != entry.name || identity.directory != entry.directory || identity.mode != uint32(entry.mode) {
			t.Fatalf("entry %d identity lost normalized name, kind or mode", index)
		}
		if entry.directory {
			if identity.content.state != bindingStateInapplicable || identity.content.length != 0 || identity.content.digest != ([sha256.Size]byte{}) {
				t.Fatalf("directory %d acquired a content descriptor", index)
			}
		} else if identity.content.state != bindingStatePresent || identity.content.length != int64(len(entry.contents)) ||
			identity.content.digest != sha256.Sum256(entry.contents) {
			t.Fatalf("regular entry %d lost its present content descriptor", index)
		}
	}
	if identities[1].content.digest != sha256.Sum256(nil) || identities[1].content.length != 0 ||
		identities[4].content.state != bindingStateInapplicable || identities[5].content.state != bindingStateInapplicable {
		t.Fatal("empty regular content, directory content and absence were conflated")
	}
	for _, test := range []struct {
		name   string
		change func(*resolvedExecution)
	}{
		{"name", func(v *resolvedExecution) { v.material.mounts[0].entries[0].name = "name" }},
		{"kind", func(v *resolvedExecution) { v.material.mounts[0].entries[0].directory = true }},
		{"full mode", func(v *resolvedExecution) { v.material.mounts[0].entries[0].mode |= os.ModeSetuid }},
		{"length and bytes", func(v *resolvedExecution) { v.material.mounts[0].entries[0].contents = []byte("xx") }},
		{"entry order", func(v *resolvedExecution) {
			v.material.mounts[0].entries[0], v.material.mounts[0].entries[1] = v.material.mounts[0].entries[1], v.material.mounts[0].entries[0]
		}},
		{"compressed bytes", func(v *resolvedExecution) { v.material.mounts[0].compressedBytes[0] ^= 1 }},
	} {
		t.Run(test.name, func(t *testing.T) {
			changed := reliableBindingCloneResolved(base)
			test.change(&changed)
			reliableBindingMustRefuse(t, changed, family, key)
		})
	}
}

func TestReliableSubmitBindingInputOwnershipAndBounds(t *testing.T) {
	base, family, key, _, _ := reliableBindingResolvedFixture(t)
	archive := mustRuntimeMountArchiveBytes(t, runtimeMountArchiveEntry{name: "owned", body: []byte("nested"), typeflag: '0', mode: 0o644})
	reliableBindingAttachMount(t, &base, archive, "/execution/mounts/owned", base.plan.artifactDigest)
	base.material.trust.vaultCACertBytes = []byte("synthetic-ca")
	base.material.trust.workloadTLSBundleBytes = []byte("synthetic-combined-ca")
	base.plan.authority.trustMaterial.vaultCACert = true
	base.plan.authority.trustMaterial.workloadTLSBundle = true
	base.plan.semanticEnvironment["VAULT_CACERT"] = executionRuntimePlatformDir + "/" + executionWorkloadVaultCAName
	base.plan.semanticEnvironment["SSL_CERT_FILE"] = executionRuntimePlatformDir + "/" + executionWorkloadTLSBundleName
	before := reliableBindingCloneResolved(base)
	beforeFamily, beforeKey := family, key
	assessment := reliableBindingMustBuild(t, base, family, key)
	if !reflect.DeepEqual(base, before) || family != beforeFamily || key != beforeKey {
		t.Fatal("successful producer changed nested input, family or key")
	}
	prior := assessment.boundPlan.Binding()
	priorMaterialDigest := assessment.material.primary.digest
	priorMountDigest := assessment.material.mounts[0].compressed.digest
	priorEntry := assessment.material.mounts[0].entries[0]
	priorCA := assessment.material.vaultCA
	base.material.payloadBytes[0] ^= 1
	base.material.mounts[0].compressedBytes[0] ^= 1
	base.material.mounts[0].entries[0].contents[0] ^= 1
	base.material.mounts[0].entries[0].name = "changed"
	base.material.trust.vaultCACertBytes[0] ^= 1
	base.plan.mounts[0].targetPath = "/execution/mounts/changed"
	base.plan.runtimeCommand.arguments[0] = "changed"
	base.plan.jobEnvelope.securityOptions[0] = "changed"
	base.plan.semanticEnvironment["VAULT_ADDR"] = "mutated"
	base.host.stagingRootDir = "/mutated"
	if !assessment.boundPlan.EqualBinding(prior) || assessment.material.primary.digest != priorMaterialDigest ||
		assessment.material.mounts[0].compressed.digest != priorMountDigest ||
		!reflect.DeepEqual(assessment.material.mounts[0].entries[0], priorEntry) ||
		!reflect.DeepEqual(assessment.material.vaultCA, priorCA) || assessment.effectReady {
		t.Fatal("returned assessment retained a mutable source alias")
	}
	secret := bytes.Repeat([]byte{0x0b}, 32)
	detachedKey, err := newPrivateBindingKey("detached-test-key", secret)
	if err != nil {
		t.Fatal(err)
	}
	secret[0] ^= 1
	if detachedKey.bytes[0] != 0x0b {
		t.Fatal("key constructor retained caller key bytes")
	}

	refused, family2, key2, _, _ := reliableBindingResolvedFixture(t)
	refused.plan.outputID = ""
	refusalBefore := reliableBindingCloneResolved(refused)
	reliableBindingMustRefuse(t, refused, family2, key2)
	if !reflect.DeepEqual(refused, refusalBefore) {
		t.Fatal("refused producer changed its input")
	}
	for _, invalid := range []struct {
		name   string
		change func(*resolvedExecution)
	}{
		{"string", func(v *resolvedExecution) { v.plan.outputID = string([]byte{0xff}) }},
		{"map key", func(v *resolvedExecution) { v.plan.semanticEnvironment[string([]byte{0xff})] = "value" }},
		{"map value", func(v *resolvedExecution) { v.plan.semanticEnvironment["INVALID_VALUE"] = string([]byte{0xff}) }},
	} {
		t.Run(invalid.name, func(t *testing.T) {
			input := reliableBindingCloneResolved(before)
			invalid.change(&input)
			snapshot := reliableBindingCloneResolved(input)
			reliableBindingMustRefuse(t, input, family, key)
			if !reflect.DeepEqual(input, snapshot) {
				t.Fatal("malformed UTF-8 refusal mutated source")
			}
		})
	}

	// An empty added map value contributes its key and framing to fixedSize;
	// changing only that value contributes exactly its byte length. The byte
	// count of the small canonical message independently checks the count pass.
	bounded, family3, key3, _, _ := reliableBindingResolvedFixture(t)
	bounded.plan.semanticEnvironment["LARGE"] = ""
	var fixed bytes.Buffer
	if err := bindingEncodeCanonical(&bindingEncoder{writer: &fixed}, bounded, family3); err != nil {
		t.Fatal(err)
	}
	fixedSize := int64(fixed.Len())
	if measured, err := bindingMeasureCanonical(bounded, family3); err != nil || measured != fixedSize {
		t.Fatalf("small canonical count differs from its framed bytes: count=%d bytes=%d err=%v", measured, fixedSize, err)
	}
	remaining := int(privateBindingCanonicalLimit - fixedSize)
	if remaining <= 0 {
		t.Fatal("synthetic fixed canonical fixture consumed the entire bound")
	}
	const tlvOverhead int64 = 2 + 1 + 8 // ID, tag, length; independent of the encoder.
	if exact, ok := bindingCheckedAdd(tlvOverhead, privateBindingCanonicalLimit-tlvOverhead, privateBindingCanonicalLimit); !ok || exact != privateBindingCanonicalLimit {
		t.Fatal("independently accounted TLV field exactly at 64 MiB was refused")
	}
	if _, ok := bindingCheckedAdd(tlvOverhead, privateBindingCanonicalLimit-tlvOverhead+1, privateBindingCanonicalLimit); ok {
		t.Fatal("TLV field one byte beyond 64 MiB was accepted")
	}
	if exact, ok := bindingCheckedAdd(fixedSize, int64(remaining), privateBindingCanonicalLimit); !ok || exact != privateBindingCanonicalLimit {
		t.Fatal("fixed canonical framing plus exact value bytes did not reach 64 MiB")
	}
	largeValue := strings.Repeat("x", remaining+1)
	bounded.plan.semanticEnvironment["LARGE"] = largeValue[:remaining]
	if measured, err := bindingMeasureCanonical(bounded, family3); err != nil || measured != privateBindingCanonicalLimit {
		t.Fatalf("exact 64 MiB canonical boundary rejected: size=%d err=%v", measured, err)
	}
	reliableBindingMustBuild(t, bounded, family3, key3)
	if bounded.plan.semanticEnvironment["LARGE"] != largeValue[:remaining] {
		t.Fatal("exact-bound success mutated the environment value")
	}
	bounded.plan.semanticEnvironment["LARGE"] = largeValue
	reliableBindingMustRefuse(t, bounded, family3, key3)
	if bounded.plan.semanticEnvironment["LARGE"] != largeValue {
		t.Fatal("over-bound refusal mutated the environment value")
	}
	for _, parts := range [][3]int64{
		{(64 << 20) - 1, 2, 64 << 20},
		{1<<63 - 1, 1, 1<<63 - 1},
		{-1, 1, 64 << 20},
		{1, -1, 64 << 20},
	} {
		if _, ok := bindingCheckedAdd(parts[0], parts[1], parts[2]); ok {
			t.Fatal("canonical length arithmetic accepted an overflowing or invalid sum")
		}
	}
}

func TestReliableSubmitBindingRedactionAndIsolation(t *testing.T) {
	base, family, key, stagingRoot, resultsRoot := reliableBindingResolvedFixture(t)
	assessment := reliableBindingMustBuild(t, base, family, key)
	for _, value := range []any{assessment, &assessment, assessment.material, &assessment.material, assessment.placement, &assessment.placement, key, &key, family, &family} {
		for _, format := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x"} {
			if got := fmt.Sprintf(format, value); got != privateExecutionValueRedaction {
				t.Fatalf("private value formatter leaked source data: %q", got)
			}
		}
		encoded, err := json.Marshal(value)
		if err != nil || string(encoded) != "{}" {
			t.Fatal("private value JSON projection exposed fields")
		}
	}
	for _, leak := range []string{stagingRoot, resultsRoot, base.plan.semanticEnvironment["VAULT_ADDR"], base.plan.artifactDigest} {
		if strings.Contains(fmt.Sprint(assessment), leak) {
			t.Fatal("assessment formatted private data")
		}
	}
	if _, err := os.Stat(filepath.Join(stagingRoot, "unexpected-run")); !os.IsNotExist(err) {
		t.Fatal("unwired producer created run material")
	}
	privateInvalid := reliableBindingCloneResolved(base)
	privateInvalid.plan.semanticEnvironment["PRIVATE_BOUNDARY_CANARY"] = "secret-value-canary"
	privateInvalid.plan.outputID = ""
	_, refusal := buildReliableSubmitAdmissionBinding(privateInvalid, family, key)
	if refusal == nil || strings.Contains(fmt.Sprintf("%+v", refusal), "secret-value-canary") ||
		strings.Contains(fmt.Sprintf("%+v", refusal), "PRIVATE_BOUNDARY_CANARY") {
		t.Fatal("private producer error surfaced a private environment value")
	}
}

func TestReliableSubmitBindingCanonicalGoldenVectors(t *testing.T) {
	// Independent literal values come from the frozen owning-document TLV
	// table, computed without calling the production encoder.
	const canonicalHex = "0001040000000000000084000101000000000000002e657865637574696f6e2d7375627374726174652e72656c6961626c652d7375626d69742d726571756573" +
		"742f76310002010000000000000026657865637574696f6e2d7375627374726174652e72656c6961626c652d7375626d69742f76310003010000000000000002" +
		"76310004010000000000000002763100020100000000000000056173796e63000302000000000000000800000000000000000004020000000000000008000000" +
		"000000000a00050200000000000000080000000000000080000604000000000000003600010100000000000000157374617469632d7363726970742f64656661" +
		"756c74000201000000000000000b6578616d706c653a74616700070400000000000000f900010100000000000000477368613235363a61616161616161616161" +
		"61616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616100020100000000000000" +
		"477368613235363a3563363265303931623863303536356631626166616430646164353933343237363134336165326363656637613533383165386164613562" +
		"3161386432366432000304000000000000004a0001080000000000000001010002020000000000000008000000000000000100030700000000000000205c62e0" +
		"91b8c0565f1bafad0dad5934276143ae2ccef7a5381e8ada5b1a8d26d200080100000000000000477368613235363a6262626262626262626262626262626262" +
		"626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626200090100000000000000016f000a040000" +
		"000000000160000101000000000000002a2f657865637574696f6e2f72756e2f706c6174666f726d2f65732d72756e74696d652d737570706f72740002050000" +
		"000000000120000000000000000c000000000000000a73757065727669736f7200000000000000112d2d7061796c6f61642d6172636869766500000000000000" +
		"212f657865637574696f6e2f7374616765642f61727469666163742e7461722e677a000000000000000a2d2d776f726b2d64697200000000000000132f657865" +
		"637574696f6e2f72756e2f776f726b000000000000000c2d2d726573756c742d64697200000000000000152f657865637574696f6e2f72756e2f726573756c74" +
		"000000000000000c2d2d656e747279706f696e74000000000000001e2f657865637574696f6e2f72756e2f776f726b2f656e747279706f696e74000000000000" +
		"00112d2d74696d656f75742d7365636f6e647300000000000000013000000000000000022d2d000b0600000000000001b8000000000000000800000000000000" +
		"14455845435f41525449464143545f44494745535400000000000000477368613235363a61616161616161616161616161616161616161616161616161616161" +
		"616161616161616161616161616161616161616161616161616161616161616161616161000000000000001d455845435f574f524b4c4f41445f5641554c545f" +
		"415554485f4d4f444500000000000000127661756c745f6964656e746974795f6a7774000000000000001e455845435f574f524b4c4f41445f5641554c545f41" +
		"5554485f4d4f554e5400000000000000036a7774000000000000001d455845435f574f524b4c4f41445f5641554c545f415554485f524f4c4500000000000000" +
		"01720000000000000020455845435f574f524b4c4f41445f5641554c545f4a57545f41554449454e4345000000000000000176000000000000000d455845435f" +
		"574f524b5f44495200000000000000132f657865637574696f6e2f72756e2f776f726b000000000000000a534552564943455f49440000000000000009657865" +
		"637574696f6e000000000000000a5641554c545f41444452000000000000000968747470733a2f2f76000c0500000000000000080000000000000000000d0300" +
		"0000000000000100000e04000000000000011a00010800000000000000010100020100000000000000157374617469632d7363726970742f64656661756c7400" +
		"0304000000000000000c000108000000000000000102000404000000000000005700010100000000000000127661756c745f6964656e746974795f6a77740002" +
		"01000000000000000968747470733a2f2f7600030100000000000000036a77740004010000000000000001720005010000000000000001760005010000000000" +
		"0000477368613235363a636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363" +
		"636363636363636363630006040000000000000018000103000000000000000100000203000000000000000100000f0400000000000000a70001010000000000" +
		"0000477368613235363a386465306233633437663131326335393734356637313761363236393332323634633432326137353633393534383732653233376232" +
		"32336166346164363433000204000000000000004a0001080000000000000001010002020000000000000008000000000000000100030700000000000000208d" +
		"e0b3c47f112c59745f717a626932264c422a7563954872e237b223af4ad64300100200000000000000080000000000100000001104000000000000014f000101" +
		"00000000000000056261746368000201000000000000000567726f75700003020000000000000008000000000000000100040100000000000000047461736b00" +
		"05010000000000000006646f636b65720006010000000000000003303a3000070300000000000000010000080500000000000000210000000000000001000000" +
		"00000000116e6f2d6e65772d70726976696c65676573000904000000000000004800010200000000000000080000000000000000000201000000000000000466" +
		"61696c00030200000000000000080000000df8475800000402000000000000000800000002540be400000a040000000000000058000102000000000000000800" +
		"00000000000000000203000000000000000100000302000000000000000800000000000000000004010000000000000008636f6e7374616e7400050200000000" +
		"000000080000000000000000001204000000000000002e000104000000000000000c000108000000000000000100000204000000000000000c00010800000000" +
		"0000000100"
	const canonicalSHA256 = "0bd66cac18d8becbd0e6f98ff6bcc64777454866c8eaf0e47df600a00ea6680d"
	const bindingHex = "455352532d504200010009676f6c64656e2d763146e0edc396b581619e55e6e62e48bf6f2b6f51acd1d271683f5b2d0f54909c60"
	artifactDigest := "sha256:" + strings.Repeat("a", 64)
	vault := resolvedWorkloadVaultPlan{mode: "vault_identity_jwt", address: "https://v", authMount: "jwt", authRole: "r", jwtAudience: "v"}
	resolved := resolvedExecution{
		plan: resolvedExecutionPlan{
			requestSchemaVersion: "v1", invocationSchemaVersion: "v1", mode: ExecutionModeAsync,
			timeoutSeconds: 0, resources: resolvedTaskResources{cpu: 10, memoryMB: 128},
			runtimeProfile: resolvedRuntimeProfile{name: runtimeProfileDefaultStaticScript, image: "example:tag"},
			artifactDigest: artifactDigest, payloadDigest: digestBytes([]byte("P")),
			derivationSpecDigest: "sha256:" + strings.Repeat("b", 64), outputID: "o",
			runtimeCommand: newResolvedRuntimeCommand(nil, 0),
			semanticEnvironment: map[string]string{
				"EXEC_ARTIFACT_DIGEST":             artifactDigest,
				"EXEC_WORK_DIR":                    "/execution/run/work",
				"SERVICE_ID":                       "execution",
				"VAULT_ADDR":                       "https://v",
				"EXEC_WORKLOAD_VAULT_AUTH_MODE":    "vault_identity_jwt",
				"EXEC_WORKLOAD_VAULT_AUTH_MOUNT":   "jwt",
				"EXEC_WORKLOAD_VAULT_AUTH_ROLE":    "r",
				"EXEC_WORKLOAD_VAULT_JWT_AUDIENCE": "v",
			},
			networkAccess: false,
			authority: resolvedAuthorityPlan{runtimeProfileName: runtimeProfileDefaultStaticScript,
				workloadVault: vault, workloadZoneVaultConfigDigest: "sha256:" + strings.Repeat("c", 64)},
			runtimeSupportDigest:     digestBytes([]byte("S")),
			runtimeIdentityTmpfsSize: 1 << 20,
			jobEnvelope:              defaultResolvedJobEnvelope(),
		},
		material:         resolvedExecutionMaterial{payloadBytes: []byte("P"), runtimeSupportBytes: []byte("S")},
		host:             hostMaterializationContext{stagingRootDir: "/stage", owner: executionPlatformStateOwner{UID: 0, GID: 0}, spireSourceDir: "/spire", datacenter: "dc"},
		custodyPlacement: resolvedCustodyPlacement{stagingRootDir: "/stage", resultsRootDir: "/result"},
	}
	family, err := newReliableBindingFamily(reliableSubmitRequestSchemaV1, reliableSubmitContractV1)
	if err != nil {
		t.Fatal(err)
	}
	key, err := newPrivateBindingKey("golden-v1", bytes.Repeat([]byte{0x0b}, 32))
	if err != nil {
		t.Fatal(err)
	}
	wantCanonical, err := hex.DecodeString(canonicalHex)
	if err != nil {
		t.Fatal(err)
	}
	measured, err := bindingMeasureCanonical(resolved, family)
	if err != nil || measured != int64(len(wantCanonical)) || measured != 2373 {
		t.Fatalf("canonical counted length changed: measured=%d err=%v", measured, err)
	}
	var actual bytes.Buffer
	encoder := bindingEncoder{writer: &actual}
	if err := bindingEncodeCanonical(&encoder, resolved, family); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(actual.Bytes(), wantCanonical) {
		t.Fatal("canonical-v1 bytes differ from the independent literal vector")
	}
	sum := sha256.Sum256(actual.Bytes())
	if hex.EncodeToString(sum[:]) != canonicalSHA256 {
		t.Fatal("canonical-v1 independent digest changed")
	}
	wantBindingBytes, err := hex.DecodeString(bindingHex)
	if err != nil {
		t.Fatal(err)
	}
	wantBinding, err := reliablesubmit.NewPlanBinding(wantBindingBytes)
	if err != nil {
		t.Fatal(err)
	}
	assessment := reliableBindingMustBuild(t, resolved, family, key)
	if !assessment.boundPlan.EqualBinding(wantBinding) {
		t.Fatal("authenticated header and HMAC differ from independent literal vector")
	}
	var framing bytes.Buffer
	framingEncoder := bindingEncoder{writer: &framing}
	if err := bindingEmitString(&framingEncoder, 1, "AB"); err != nil {
		t.Fatal(err)
	}
	if err := bindingEmitI64(&framingEncoder, 2, -1); err != nil {
		t.Fatal(err)
	}
	if err := bindingEmitBool(&framingEncoder, 3, true); err != nil {
		t.Fatal(err)
	}
	wantFraming, _ := hex.DecodeString("000101000000000000000241420002020000000000000008ffffffffffffffff000303000000000000000101")
	if !bytes.Equal(framing.Bytes(), wantFraming) {
		t.Fatal("scalar TLV IDs, types, lengths, signed integer or bool framing changed")
	}

	// The following literal vectors describe a synthetic encoding fixture.
	// Its mount bytes are deliberately not a parsed archive; it proves framing,
	// states and MAC inputs only, and does not establish admission.
	const nonemptyCanonicalLength = 3762
	const nonemptyCanonicalSHA256 = "915d6f6ba3a679a8c9e2bb549c591b3e1fa01a684f667406654c42f55816b22b"
	const mountHex = "000c05000000000000030e000000000000000100000000000002fe00010100000000000000477368613235363a616161616161616161616161616161" +
		"616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161610002010000000000000047" +
		"7368613235363a6161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161" +
		"616161616161616161616100030100000000000000477368613235363a62626565626438373965316466663639313835343664633063313739666464" +
		"65353035663261323135393163396139633936653336623035346563356166383300040100000000000000132f657865637574696f6e2f6d6f756e74" +
		"732f6d000503000000000000000101000604000000000000004a00010800000000000000010100020200000000000000080000000000000001000307" +
		"0000000000000020bbeebd879e1dff6918546dc0c179fdde505f2a21591c9a9c96e36b054ec5af83000705000000000000017e000000000000000300" +
		"0000000000008a0001010000000000000005656d7074790002010000000000000007726567756c6172000302000000000000000800000000000001a4" +
		"000404000000000000004a000108000000000000000101000202000000000000000800000000000000000003070000000000000020e3b0c44298fc1c" +
		"149afbf4c8996fb92427ae41e4649b934ca495991b7852b855000000000000004c000101000000000000000364697200020100000000000000096469" +
		"726563746f7279000302000000000000000800000000000001ed000404000000000000000c0001080000000000000001020000000000000088000101" +
		"000000000000000372756e0002010000000000000007726567756c6172000302000000000000000800000000000001ed000404000000000000004a00" +
		"01080000000000000001010002020000000000000008000000000000000100030700000000000000204b68ab3847feda7d6c62c1fbcbeebfa35eab73" +
		"51ed5e78f4ddadea5df64b8015"
	const authorityHex = "000e04000000000000017a000108000000000000000101000201000000000000001d636f6e74726f6c2d706c616e652d6e6f726d616c2d7368656c6c" +
		"2f76310003040000000000000064000108000000000000000101000201000000000000000a2f6f70742f636f646578000301000000000000000e776f" +
		"726b6c6f61645f7661756c7400040100000000000000117365637265742f646174612f636f64657800050100000000000000036b6579000404000000" +
		"000000005700010100000000000000127661756c745f6964656e746974795f6a7774000201000000000000000968747470733a2f2f76000301000000" +
		"00000000036a777400040100000000000000017200050100000000000000017600050100000000000000477368613235363a63636363636363636363" +
		"636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363000604000000" +
		"0000000018000103000000000000000101000203000000000000000101"
	const trustHex = "00120400000000000000aa000104000000000000004a0001080000000000000001010002020000000000000008000000000000000200030700000000" +
		"000000204b650e5c4785025dee7bd65e3c5c527356717d7a1c0bfef5b4ada8ca1e9cbe17000204000000000000004a00010800000000000000010100" +
		"0202000000000000000800000000000000030003070000000000000020d1c18ec0b109268324269c2da5f0c0dfafbe1058ea4af5653284d714064904" +
		"a1"
	const bindingVectorV1 = "455352532d504200010009766563746f722d76313cdd6025a861b98edfac7006303c348242d673fab7797e97775e4b3c5880fb75"
	const bindingVectorV2 = "455352532d504200010009766563746f722d7632e3058260941fe083ee77df8c6b97edc1f8af16ccceb5f1832600ae8647dc4a30"
	nonempty := reliableBindingCloneResolved(resolved)
	nonempty.plan.runtimeProfile = resolvedRuntimeProfile{name: "control-plane-normal-shell/v1", image: "example:profile"}
	nonempty.plan.networkAccess = true
	nonempty.plan.authority.runtimeProfileName = "control-plane-normal-shell/v1"
	nonempty.plan.authority.codexCredential = resolvedCodexCredentialLocation{
		applicable: true, cliPath: "/opt/codex", credentialSource: "workload_vault",
		vaultSecretPath: "secret/data/codex", vaultSecretField: "key",
	}
	nonempty.plan.authority.trustMaterial.vaultCACert = true
	nonempty.plan.authority.trustMaterial.workloadTLSBundle = true
	nonempty.plan.semanticEnvironment["EXEC_CODEX_CLI_PATH"] = "/opt/codex"
	nonempty.plan.semanticEnvironment["EXEC_CODEX_CREDENTIAL_SOURCE"] = "workload_vault"
	nonempty.plan.semanticEnvironment["EXEC_CODEX_CREDENTIAL_VAULT_SECRET_PATH"] = "secret/data/codex"
	nonempty.plan.semanticEnvironment["EXEC_CODEX_CREDENTIAL_VAULT_SECRET_FIELD"] = "key"
	nonempty.plan.semanticEnvironment["VAULT_CACERT"] = "/execution/run/platform/workload-vault-ca.pem"
	nonempty.plan.semanticEnvironment["SSL_CERT_FILE"] = "/execution/run/platform/workload-tls-bundle.pem"
	nonempty.plan.mounts = []resolvedMountPlan{{
		artifactDigest: artifactDigest, verifiedArtifactDigest: artifactDigest,
		payloadDigest: digestBytes([]byte("Z")), targetPath: "/execution/mounts/m", readOnly: true,
	}}
	nonempty.material.mounts = []validatedMountArchive{{compressedBytes: []byte("Z"), entries: []validatedMountEntry{
		{name: "empty", mode: 0o644},
		{name: "dir", directory: true, mode: 0o755},
		{name: "run", mode: 0o755, contents: []byte("X")},
	}}}
	nonempty.material.trust.vaultCACertBytes = []byte("CA")
	nonempty.material.trust.workloadTLSBundleBytes = []byte("TLS")
	checkLiteralField := func(label, expected string, emit func(*bindingEncoder) error) {
		t.Helper()
		want, err := hex.DecodeString(expected)
		if err != nil {
			t.Fatal(err)
		}
		var actual bytes.Buffer
		if err := emit(&bindingEncoder{writer: &actual}); err != nil || !bytes.Equal(actual.Bytes(), want) {
			t.Fatalf("synthetic %s field differed from independent literal: err=%v", label, err)
		}
	}
	checkLiteralField("mount and ordered entries", mountHex, func(e *bindingEncoder) error {
		return bindingEmitMountSequence(e, 12, nonempty, family)
	})
	checkLiteralField("present Codex location", authorityHex, func(e *bindingEncoder) error {
		return bindingEmitRecord(e, 14, bindingAuthorityRecord, nonempty, family, 0, 0)
	})
	checkLiteralField("present trust descriptors", trustHex, func(e *bindingEncoder) error {
		return bindingEmitRecord(e, 18, bindingTrustRecord, nonempty, family, 0, 0)
	})
	var nonemptyCanonical bytes.Buffer
	if err := bindingEncodeCanonical(&bindingEncoder{writer: &nonemptyCanonical}, nonempty, family); err != nil {
		t.Fatal(err)
	}
	canonicalDigest := sha256.Sum256(nonemptyCanonical.Bytes())
	if nonemptyCanonical.Len() != nonemptyCanonicalLength || hex.EncodeToString(canonicalDigest[:]) != nonemptyCanonicalSHA256 {
		t.Fatal("synthetic nonempty canonical message differs from independent length and digest")
	}
	for _, vector := range []struct{ id, hex string }{{"vector-v1", bindingVectorV1}, {"vector-v2", bindingVectorV2}} {
		header := bindingHeader(vector.id)
		mac := hmac.New(sha256.New, bytes.Repeat([]byte{0x0b}, 32))
		_, _ = mac.Write([]byte("execution-substrate/reliable-effective-plan/v1\x00"))
		_, _ = mac.Write(header)
		_, _ = mac.Write(nonemptyCanonical.Bytes())
		want, err := hex.DecodeString(vector.hex)
		if err != nil || !bytes.Equal(append(header, mac.Sum(nil)...), want) {
			t.Fatalf("synthetic authenticated header/key ID vector %s changed: err=%v", vector.id, err)
		}
	}
	if bindingVectorV1 == bindingVectorV2 {
		t.Fatal("distinct authenticated key IDs retained one binding")
	}
	for _, vector := range []struct {
		label, hex string
		emit       func(*bindingEncoder) error
	}{
		{"sequence [ab,c]", "000205000000000000001b000000000000000200000000000000026162000000000000000163", func(e *bindingEncoder) error { return bindingEmitStringSequence(e, 2, []string{"ab", "c"}) }},
		{"sequence [a,bc]", "000205000000000000001b000000000000000200000000000000016100000000000000026263", func(e *bindingEncoder) error { return bindingEmitStringSequence(e, 2, []string{"a", "bc"}) }},
		{"map a:bc", "000b06000000000000001b000000000000000100000000000000016100000000000000026263", func(e *bindingEncoder) error { return bindingEmitMap(e, 11, map[string]string{"a": "bc"}) }},
		{"map ab:c", "000b06000000000000001b000000000000000100000000000000026162000000000000000163", func(e *bindingEncoder) error { return bindingEmitMap(e, 11, map[string]string{"ab": "c"}) }},
	} {
		checkLiteralField(vector.label, vector.hex, vector.emit)
	}
}
