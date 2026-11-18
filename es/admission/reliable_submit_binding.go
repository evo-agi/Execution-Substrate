package admission

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"slices"
	"strconv"
	"strings"

	"execution-substrate/es/admission/internal/reliablesubmit"
)

const (
	privateBindingCanonicalLimit int64 = 64 << 20
	privateBindingHeaderPrefix         = "ESRS-PB\x00\x01"
	privateBindingMACDomain            = "execution-substrate/reliable-effective-plan/v1\x00"
)

// reliableBindingFamily is only a validated private request-family marker.
// Future runtime wiring must separately prove that its request and the
// resolved tuple belong to the same authenticated delivery.
type reliableBindingFamily struct {
	privateExecutionValue
	schemaVersion string
	contract      string
	validated     bool
}

func newReliableBindingFamily(schemaVersion, contract string) (reliableBindingFamily, error) {
	if schemaVersion != reliableSubmitRequestSchemaV1 || contract != reliableSubmitContractV1 {
		return reliableBindingFamily{}, bindingInvalidFamily()
	}
	return reliableBindingFamily{schemaVersion: schemaVersion, contract: contract, validated: true}, nil
}

type privateBindingKey struct {
	privateExecutionValue
	id        string
	bytes     [sha256.Size]byte
	validated bool
}

func newPrivateBindingKey(id string, secret []byte) (privateBindingKey, error) {
	if !bindingKeyIDValid(id) || len(secret) != sha256.Size {
		return privateBindingKey{}, bindingInvalidKey()
	}
	key := privateBindingKey{id: id, validated: true}
	copy(key.bytes[:], secret)
	return key, nil
}

func bindingKeyIDValid(id string) bool {
	if len(id) < 1 || len(id) > 64 {
		return false
	}
	for index := range id {
		ch := id[index]
		letter := ch >= 'A' && ch <= 'Z' || ch >= 'a' && ch <= 'z'
		digit := ch >= '0' && ch <= '9'
		if index == 0 {
			if !letter && !digit {
				return false
			}
		} else if !letter && !digit && ch != '.' && ch != '_' && ch != '-' {
			return false
		}
	}
	return true
}

type bindingMaterialDescriptor struct {
	privateExecutionValue
	state  byte
	length int64
	digest [sha256.Size]byte
}

type bindingEntryMaterialIdentity struct {
	privateExecutionValue
	name      string
	directory bool
	mode      uint32
	content   bindingMaterialDescriptor
}

type bindingMountMaterialIdentity struct {
	privateExecutionValue
	requestedArtifactDigest string
	verifiedArtifactDigest  string
	payloadDigest           string
	compressed              bindingMaterialDescriptor
	entries                 []bindingEntryMaterialIdentity
}

type bindingMaterialIdentities struct {
	privateExecutionValue
	primary bindingMaterialDescriptor
	support bindingMaterialDescriptor
	mounts  []bindingMountMaterialIdentity
	vaultCA bindingMaterialDescriptor
	tls     bindingMaterialDescriptor
}

type bindingCapturedPlacement struct {
	privateExecutionValue
	stagingRootDir string
	resultsRootDir string
	owner          executionPlatformStateOwner
	spireSourceDir string
	datacenter     string
}

// No member is an effect permit. The source tuple only supplies captured
// placement coordinates, without later behavioral topology or image proof.
type admissionBindingAssessment struct {
	privateExecutionValue
	boundPlan            reliablesubmit.BoundPlan
	material             bindingMaterialIdentities
	placement            bindingCapturedPlacement
	missingPrerequisites [5]string
	effectReady          bool
}

type bindingCategoryValidation struct {
	privateExecutionValue
	category reliablesubmit.EffectivePlanCategory
	complete bool
}

// buildReliableSubmitAdmissionBinding is deliberately runtime-unwired. It
// reads already resolved facts and never calls admission or an effect owner.
func buildReliableSubmitAdmissionBinding(resolved resolvedExecution, family reliableBindingFamily, key privateBindingKey) (admissionBindingAssessment, error) {
	if !family.validated || family.schemaVersion != reliableSubmitRequestSchemaV1 || family.contract != reliableSubmitContractV1 {
		return admissionBindingAssessment{}, bindingInvalidFamily()
	}
	if !key.validated || !bindingKeyIDValid(key.id) {
		return admissionBindingAssessment{}, bindingInvalidKey()
	}
	if !bindingMaterialBudgetValid(resolved) {
		return admissionBindingAssessment{}, bindingInvalidFacts()
	}

	// Each named source validation is paired with its one existing model mask.
	// A complete mask cannot be produced by enumerating categories alone.
	checks := [...]bindingCategoryValidation{
		{category: reliablesubmit.EffectivePlanCategoryRequestSchemaOrVersion, complete: bindingSchemaValid(resolved, family)},
		{category: reliablesubmit.EffectivePlanCategoryExecutionMode, complete: bindingModeValid(resolved)},
		{category: reliablesubmit.EffectivePlanCategoryTimeoutSemantics, complete: bindingTimeoutValid(resolved)},
		{category: reliablesubmit.EffectivePlanCategoryCPU, complete: bindingCPUValid(resolved)},
		{category: reliablesubmit.EffectivePlanCategoryMemory, complete: bindingMemoryValid(resolved)},
		{category: reliablesubmit.EffectivePlanCategoryRuntimeProfile, complete: bindingProfileValid(resolved)},
		{category: reliablesubmit.EffectivePlanCategoryArtifactIdentity, complete: bindingPrimaryValid(resolved)},
		{category: reliablesubmit.EffectivePlanCategoryDerivationSpecIdentity, complete: bindingDerivationValid(resolved)},
		{category: reliablesubmit.EffectivePlanCategoryOutputIdentity, complete: bindingOutputValid(resolved)},
		{category: reliablesubmit.EffectivePlanCategoryCommandAndArgv, complete: bindingCommandValid(resolved)},
		{category: reliablesubmit.EffectivePlanCategoryEnvironmentAdditions, complete: bindingEnvironmentValid(resolved)},
		{category: reliablesubmit.EffectivePlanCategoryMounts, complete: bindingMountsValid(resolved)},
		{category: reliablesubmit.EffectivePlanCategoryNetworkPosture, complete: bindingNetworkValid(resolved)},
		{category: reliablesubmit.EffectivePlanCategoryAuthorityHandoffApplicability, complete: bindingAuthorityValid(resolved)},
	}
	for _, check := range checks {
		if !check.complete {
			return admissionBindingAssessment{}, bindingInvalidFacts()
		}
	}
	if !bindingSupportValid(resolved) || !bindingTmpfsValid(resolved) || !bindingJobEnvelopeValid(resolved) || !bindingTrustValid(resolved) || !bindingPlacementValid(resolved) {
		return admissionBindingAssessment{}, bindingInvalidFacts()
	}
	// The material parser and its existing budgets have now checked source
	// bytes. This count pass checks the complete private message before map
	// sorting or canonical accumulation and never hashes material content.
	canonicalSize, err := bindingMeasureCanonical(resolved, family)
	if err != nil || canonicalSize > privateBindingCanonicalLimit {
		return admissionBindingAssessment{}, bindingInputTooLarge()
	}

	header := bindingHeader(key.id)
	mac := hmac.New(sha256.New, key.bytes[:])
	if _, err := mac.Write([]byte(privateBindingMACDomain)); err != nil {
		return admissionBindingAssessment{}, bindingInvalidFacts()
	}
	if _, err := mac.Write(header); err != nil {
		return admissionBindingAssessment{}, bindingInvalidFacts()
	}
	encoder := bindingEncoder{writer: mac}
	if err := bindingEncodeCanonical(&encoder, resolved, family); err != nil || encoder.used != canonicalSize {
		return admissionBindingAssessment{}, bindingInvalidFacts()
	}
	bindingBytes := append(header, mac.Sum(nil)...)
	planBinding, err := reliablesubmit.NewPlanBinding(bindingBytes)
	if err != nil {
		return admissionBindingAssessment{}, bindingInvalidFacts()
	}
	var resolvedCategories [14]reliablesubmit.EffectivePlanCategoryCompleteness
	for index, check := range checks {
		resolvedCategories[index], err = reliablesubmit.ResolvedCategory(check.category)
		if err != nil {
			return admissionBindingAssessment{}, bindingInvalidFacts()
		}
	}
	witness, err := reliablesubmit.NewEffectivePlanWitness(resolvedCategories[:]...)
	if err != nil {
		return admissionBindingAssessment{}, bindingInvalidFacts()
	}
	boundPlan, err := reliablesubmit.NewBoundPlan(planBinding, witness)
	if err != nil {
		return admissionBindingAssessment{}, bindingInvalidFacts()
	}
	return admissionBindingAssessment{
		boundPlan: boundPlan,
		material:  bindingCaptureMaterialIdentities(resolved),
		placement: bindingCapturedPlacement{
			stagingRootDir: resolved.custodyPlacement.stagingRootDir,
			resultsRootDir: resolved.custodyPlacement.resultsRootDir,
			owner:          resolved.host.owner,
			spireSourceDir: resolved.host.spireSourceDir,
			datacenter:     resolved.host.datacenter,
		},
		missingPrerequisites: [5]string{
			"stable binding-key custody", "durable replay-envelope custody", "immutable image content",
			"behaviorally qualified original placement", "current authorization and effect protocol",
		},
		effectReady: false,
	}, nil
}

func bindingHeader(id string) []byte {
	header := make([]byte, 0, len(privateBindingHeaderPrefix)+2+len(id))
	header = append(header, privateBindingHeaderPrefix...)
	header = append(header, byte(len(id)>>8), byte(len(id)))
	header = append(header, id...)
	return header
}

func bindingMaterialBudgetValid(resolved resolvedExecution) bool {
	material := resolved.material
	if int64(len(material.payloadBytes)) > maxPrimaryPayloadBytes || int64(len(material.runtimeSupportBytes)) > maxRuntimeSupportBytes ||
		int64(len(material.trust.vaultCACertBytes)) > maxWorkloadVaultCABytes || int64(len(material.trust.workloadTLSBundleBytes)) > maxWorkloadTLSBundleBytes {
		return false
	}
	return validateResolvedExecutionMaterialBudget(resolvedMaterialFacts{
		payloadBytes: material.payloadBytes, runtimeSupportBytes: material.runtimeSupportBytes,
		mounts: material.mounts, trust: material.trust,
	}) == nil
}

func bindingSchemaValid(resolved resolvedExecution, family reliableBindingFamily) bool {
	return family.validated && family.schemaVersion == reliableSubmitRequestSchemaV1 && family.contract == reliableSubmitContractV1 &&
		strings.TrimSpace(resolved.plan.requestSchemaVersion) != "" && strings.TrimSpace(resolved.plan.invocationSchemaVersion) != ""
}

func bindingModeValid(resolved resolvedExecution) bool {
	return resolved.plan.mode == ExecutionModeAsync
}

func bindingTimeoutValid(resolved resolvedExecution) bool {
	return resolved.plan.timeoutSeconds >= 0 && bindingCommandValid(resolved)
}

func bindingCPUValid(resolved resolvedExecution) bool    { return resolved.plan.resources.cpu > 0 }
func bindingMemoryValid(resolved resolvedExecution) bool { return resolved.plan.resources.memoryMB > 0 }

func bindingProfileValid(resolved resolvedExecution) bool {
	profile := resolved.plan.runtimeProfile
	if strings.TrimSpace(profile.name) == "" || strings.TrimSpace(profile.image) == "" ||
		profile.name != strings.TrimSpace(profile.name) || profile.image != strings.TrimSpace(profile.image) ||
		profile.name != resolved.plan.authority.runtimeProfileName {
		return false
	}
	return profile.name == runtimeProfileDefaultStaticScript || profile.name == runtimeProfileControlPlaneNormalShell
}

func bindingExactDigest(value string) bool {
	return value == strings.TrimSpace(value) && isLabeledSHA256Digest(value)
}

func bindingPrimaryValid(resolved resolvedExecution) bool {
	return bindingExactDigest(resolved.plan.artifactDigest) && bindingExactDigest(resolved.plan.payloadDigest) &&
		resolved.material.payloadBytes != nil && digestBytes(resolved.material.payloadBytes) == resolved.plan.payloadDigest
}

func bindingDerivationValid(resolved resolvedExecution) bool {
	return bindingExactDigest(resolved.plan.derivationSpecDigest)
}
func bindingOutputValid(resolved resolvedExecution) bool {
	return strings.TrimSpace(resolved.plan.outputID) != ""
}

func bindingCommandValid(resolved resolvedExecution) bool {
	command := resolved.plan.runtimeCommand
	args := command.arguments
	if command.executable != executionRuntimeSupportPath || len(args) < 12 || resolved.plan.timeoutSeconds < 0 {
		return false
	}
	prefix := [...]string{
		"supervisor", "--payload-archive", executionRuntimePayloadRoot + "/" + executionPayloadArchiveName,
		"--work-dir", executionRuntimeWorkDir, "--result-dir", executionRuntimeResultDir,
		"--entrypoint", executionRuntimeEntrypointPath, "--timeout-seconds",
		strconv.Itoa(resolved.plan.timeoutSeconds), "--",
	}
	return slices.Equal(args[:12], prefix[:]) && len(args)-12 <= 100
}

func bindingEnvironmentValid(resolved resolvedExecution) bool {
	env := resolved.plan.semanticEnvironment
	auth := resolved.plan.authority
	if env == nil || env["EXEC_ARTIFACT_DIGEST"] != resolved.plan.artifactDigest || env["EXEC_WORK_DIR"] != executionRuntimeWorkDir ||
		env["SERVICE_ID"] != "execution" || env["VAULT_ADDR"] != auth.workloadVault.address ||
		env["EXEC_WORKLOAD_VAULT_AUTH_MODE"] != auth.workloadVault.mode ||
		env["EXEC_WORKLOAD_VAULT_AUTH_MOUNT"] != auth.workloadVault.authMount ||
		env["EXEC_WORKLOAD_VAULT_AUTH_ROLE"] != auth.workloadVault.authRole ||
		env["EXEC_WORKLOAD_VAULT_JWT_AUDIENCE"] != auth.workloadVault.jwtAudience {
		return false
	}
	for key, present := range map[string]bool{
		"VAULT_CACERT":  auth.trustMaterial.vaultCACert,
		"SSL_CERT_FILE": auth.trustMaterial.workloadTLSBundle,
	} {
		value, exists := env[key]
		if exists != present || present && value == "" {
			return false
		}
	}
	if auth.trustMaterial.vaultCACert && env["VAULT_CACERT"] != executionRuntimePlatformDir+"/"+executionWorkloadVaultCAName {
		return false
	}
	if auth.trustMaterial.workloadTLSBundle && env["SSL_CERT_FILE"] != executionRuntimePlatformDir+"/"+executionWorkloadTLSBundleName {
		return false
	}
	location := auth.codexCredential
	for key, expected := range map[string]string{
		codexCLIPathEnvKey:                    location.cliPath,
		codexCredentialSourceEnvKey:           location.credentialSource,
		codexCredentialVaultSecretPathEnvKey:  location.vaultSecretPath,
		codexCredentialVaultSecretFieldEnvKey: location.vaultSecretField,
	} {
		value, exists := env[key]
		if location.applicable {
			if !exists || value != expected {
				return false
			}
		} else if exists {
			return false
		}
	}
	return true
}

func bindingMountsValid(resolved resolvedExecution) bool {
	if len(resolved.plan.mounts) != len(resolved.material.mounts) || len(resolved.plan.mounts) > maxRuntimeMounts {
		return false
	}
	var totalCompressed, totalBody, totalStream int64
	targets := make([]string, 0, len(resolved.plan.mounts))
	for index, mount := range resolved.plan.mounts {
		archive := resolved.material.mounts[index]
		if !bindingExactDigest(mount.artifactDigest) || !bindingExactDigest(mount.verifiedArtifactDigest) || !bindingExactDigest(mount.payloadDigest) ||
			mount.artifactDigest != mount.verifiedArtifactDigest || !mount.readOnly || archive.compressedBytes == nil ||
			digestBytes(archive.compressedBytes) != mount.payloadDigest {
			return false
		}
		cleaned, err := normalizeRuntimeMountTargetPath(mount.targetPath)
		if err != nil || cleaned != mount.targetPath {
			return false
		}
		targets = append(targets, mount.targetPath)
		var ok bool
		totalCompressed, ok = addWithinLimit(totalCompressed, int64(len(archive.compressedBytes)), maxRuntimeMountTotalBytes)
		if !ok || int64(len(archive.compressedBytes)) > maxRuntimeMountBytes {
			return false
		}
		parsed, body, stream, err := validateRuntimeMountArchiveWithinBudgets(
			archive.compressedBytes, maxRuntimeMountBytes, maxRuntimeMountTotalBytes-totalBody,
			maxRuntimeMountStreamBytes, maxRuntimeMountTotalStreamBytes-totalStream, nil,
		)
		if err != nil || len(parsed.entries) != len(archive.entries) {
			return false
		}
		totalBody += body
		totalStream += stream
		for entryIndex, expected := range parsed.entries {
			captured := archive.entries[entryIndex]
			if captured.name != expected.name || captured.directory != expected.directory || captured.mode != expected.mode ||
				len(captured.contents) != len(expected.contents) || !bytes.Equal(captured.contents, expected.contents) ||
				sha256.Sum256(captured.contents) != sha256.Sum256(expected.contents) ||
				captured.directory && captured.contents != nil ||
				!captured.directory && (captured.contents == nil) != (expected.contents == nil) {
				return false
			}
		}
	}
	if hasOverlappingRuntimeMountTargets(targets) || ValidateReservedRuntimePaths(targets) != nil {
		return false
	}
	return true
}

func bindingNetworkValid(resolved resolvedExecution) bool {
	return resolved.plan.runtimeProfile.name != runtimeProfileControlPlaneNormalShell || resolved.plan.networkAccess
}

func bindingAuthorityValid(resolved resolvedExecution) bool {
	auth := resolved.plan.authority
	if auth.runtimeProfileName != resolved.plan.runtimeProfile.name || !bindingExactDigest(auth.workloadZoneVaultConfigDigest) ||
		auth.workloadVault.mode != "vault_identity_jwt" || strings.TrimSpace(auth.workloadVault.address) == "" ||
		strings.TrimSpace(auth.workloadVault.authMount) == "" || strings.TrimSpace(auth.workloadVault.authRole) == "" ||
		strings.TrimSpace(auth.workloadVault.jwtAudience) == "" ||
		auth.workloadVault.address != strings.TrimSpace(auth.workloadVault.address) ||
		auth.workloadVault.authMount != strings.TrimSpace(auth.workloadVault.authMount) ||
		auth.workloadVault.authRole != strings.TrimSpace(auth.workloadVault.authRole) ||
		auth.workloadVault.jwtAudience != strings.TrimSpace(auth.workloadVault.jwtAudience) {
		return false
	}
	location := auth.codexCredential
	if !location.applicable {
		return location.cliPath == "" && location.credentialSource == "" && location.vaultSecretPath == "" && location.vaultSecretField == "" &&
			resolved.plan.runtimeProfile.name != runtimeProfileControlPlaneNormalShell
	}
	return resolved.plan.runtimeProfile.name == runtimeProfileControlPlaneNormalShell &&
		location.credentialSource == codexCredentialSourceWorkloadVault &&
		strings.TrimSpace(location.cliPath) != "" && strings.TrimSpace(location.vaultSecretPath) != "" && strings.TrimSpace(location.vaultSecretField) != "" &&
		location.cliPath == strings.TrimSpace(location.cliPath) &&
		location.vaultSecretPath == strings.TrimSpace(location.vaultSecretPath) &&
		location.vaultSecretField == strings.TrimSpace(location.vaultSecretField)
}

func bindingSupportValid(resolved resolvedExecution) bool {
	return bindingExactDigest(resolved.plan.runtimeSupportDigest) && resolved.material.runtimeSupportBytes != nil &&
		digestBytes(resolved.material.runtimeSupportBytes) == resolved.plan.runtimeSupportDigest
}

func bindingTmpfsValid(resolved resolvedExecution) bool {
	return resolved.plan.runtimeIdentityTmpfsSize > 0
}

func bindingJobEnvelopeValid(resolved resolvedExecution) bool {
	actual, fixed := resolved.plan.jobEnvelope, defaultResolvedJobEnvelope()
	return actual.jobType == fixed.jobType && actual.groupName == fixed.groupName && actual.groupCount == fixed.groupCount &&
		actual.taskName == fixed.taskName && actual.driver == fixed.driver && actual.user == fixed.user &&
		actual.privileged == fixed.privileged && slices.Equal(actual.securityOptions, fixed.securityOptions) &&
		actual.restartPolicy == fixed.restartPolicy && actual.reschedulePolicy == fixed.reschedulePolicy
}

func bindingTrustValid(resolved resolvedExecution) bool {
	flags, trust := resolved.plan.authority.trustMaterial, resolved.material.trust
	return flags.vaultCACert == (len(trust.vaultCACertBytes) > 0) &&
		flags.workloadTLSBundle == (len(trust.workloadTLSBundleBytes) > 0) &&
		flags.vaultCACert == flags.workloadTLSBundle
}

func bindingPlacementValid(resolved resolvedExecution) bool {
	host, placement := resolved.host, resolved.custodyPlacement
	if host.stagingRootDir != placement.stagingRootDir || host.owner.UID < 0 || host.owner.GID < 0 || strings.TrimSpace(host.datacenter) == "" || host.datacenter != strings.TrimSpace(host.datacenter) {
		return false
	}
	for _, path := range []string{placement.stagingRootDir, placement.resultsRootDir, host.spireSourceDir} {
		cleaned, err := normalizeAbsoluteSubmitPath("captured placement", path)
		if err != nil || path != cleaned {
			return false
		}
	}
	return true
}

func bindingCaptureMaterialIdentities(resolved resolvedExecution) bindingMaterialIdentities {
	identities := bindingMaterialIdentities{
		primary: bindingPresentMaterial(resolved.material.payloadBytes),
		support: bindingPresentMaterial(resolved.material.runtimeSupportBytes),
		mounts:  make([]bindingMountMaterialIdentity, len(resolved.material.mounts)),
		vaultCA: bindingOptionalTrustMaterial(resolved.material.trust.vaultCACertBytes),
		tls:     bindingOptionalTrustMaterial(resolved.material.trust.workloadTLSBundleBytes),
	}
	for index, archive := range resolved.material.mounts {
		plan := resolved.plan.mounts[index]
		mount := bindingMountMaterialIdentity{
			requestedArtifactDigest: plan.artifactDigest,
			verifiedArtifactDigest:  plan.verifiedArtifactDigest,
			payloadDigest:           plan.payloadDigest,
			compressed:              bindingPresentMaterial(archive.compressedBytes),
			entries:                 make([]bindingEntryMaterialIdentity, len(archive.entries)),
		}
		for entryIndex, entry := range archive.entries {
			identity := bindingEntryMaterialIdentity{name: entry.name, directory: entry.directory, mode: uint32(entry.mode)}
			if entry.directory {
				identity.content = bindingMaterialDescriptor{state: bindingStateInapplicable}
			} else {
				identity.content = bindingPresentMaterial(entry.contents)
			}
			mount.entries[entryIndex] = identity
		}
		identities.mounts[index] = mount
	}
	return identities
}

func bindingPresentMaterial(content []byte) bindingMaterialDescriptor {
	return bindingMaterialDescriptor{state: bindingStatePresent, length: int64(len(content)), digest: sha256.Sum256(content)}
}

func bindingOptionalTrustMaterial(content []byte) bindingMaterialDescriptor {
	if len(content) == 0 {
		return bindingMaterialDescriptor{state: bindingStateAbsent}
	}
	return bindingPresentMaterial(content)
}

func bindingInvalidFamily() error {
	return errors.New("private reliable binding: invalid family marker")
}
func bindingInvalidKey() error { return errors.New("private reliable binding: invalid key") }
func bindingInvalidFacts() error {
	return errors.New("private reliable binding: incomplete or incoherent captured facts")
}
func bindingInputTooLarge() error {
	return errors.New("private reliable binding: canonical input is invalid or exceeds producer limit")
}
