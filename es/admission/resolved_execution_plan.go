package admission

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	egsmodel "execution-substrate/egs/model"
	esconfig "execution-substrate/es/config"
)

const privateExecutionValueRedaction = "<private execution value redacted>"

type privateExecutionValue struct{}

func (privateExecutionValue) Format(state fmt.State, _ rune) {
	_, _ = state.Write([]byte(privateExecutionValueRedaction))
}

type submitConfigSnapshot struct {
	privateExecutionValue
	stagingRootDir             string
	resultsRootDir             string
	baseImage                  string
	runtimeIdentityTmpfsSize   int64
	runtimeSupportBinary       string
	spireWorkloadAPISocketPath string
	controlPlaneEnabled        bool
	controlPlaneImage          string
	controlPlaneCodexCLIPath   string
	controlPlaneVaultPath      string
	controlPlaneVaultField     string
	datacenter                 string
}

type resolvedTaskResources struct {
	privateExecutionValue
	cpu      int
	memoryMB int
}

type resolvedRuntimeProfile struct {
	privateExecutionValue
	name  string
	image string
}

type resolvedWorkloadVaultPlan struct {
	privateExecutionValue
	mode        string
	address     string
	authMount   string
	authRole    string
	jwtAudience string
}

type resolvedMountPlan struct {
	privateExecutionValue
	artifactDigest         string
	verifiedArtifactDigest string
	payloadDigest          string
	targetPath             string
	readOnly               bool
}

type resolvedRuntimeMountInputs struct {
	privateExecutionValue
	identityTmpfsSize int64
	spireSourceDir    string
}

type resolvedRestartPolicy struct {
	privateExecutionValue
	attempts int
	mode     string
	interval int64
	delay    int64
}

type resolvedReschedulePolicy struct {
	privateExecutionValue
	attempts      int
	unlimited     bool
	delay         int64
	delayFunction string
	maxDelay      int64
}

type resolvedJobEnvelope struct {
	privateExecutionValue
	jobType          string
	groupName        string
	groupCount       int
	taskName         string
	driver           string
	user             string
	privileged       bool
	securityOptions  []string
	restartPolicy    resolvedRestartPolicy
	reschedulePolicy resolvedReschedulePolicy
}

type resolvedCodexCredentialLocation struct {
	privateExecutionValue
	applicable       bool
	cliPath          string
	credentialSource string
	vaultSecretPath  string
	vaultSecretField string
}

type resolvedAuthorityPlan struct {
	privateExecutionValue
	runtimeProfileName            string
	codexCredential               resolvedCodexCredentialLocation
	workloadVault                 resolvedWorkloadVaultPlan
	workloadZoneVaultConfigDigest string
	trustMaterial                 stagedWorkloadTrustMaterial
}

type resolvedPlanFacts struct {
	privateExecutionValue
	requestSchemaVersion     string
	invocationSchemaVersion  string
	mode                     ExecutionMode
	timeoutSeconds           int
	resources                resolvedTaskResources
	runtimeProfile           resolvedRuntimeProfile
	artifactDigest           string
	payloadDigest            string
	derivationSpecDigest     string
	outputID                 string
	runtimeCommand           resolvedRuntimeCommand
	semanticEnvironment      map[string]string
	mounts                   []resolvedMountPlan
	networkAccess            bool
	authority                resolvedAuthorityPlan
	runtimeSupportDigest     string
	runtimeIdentityTmpfsSize int64
	jobEnvelope              resolvedJobEnvelope
}

type resolvedExecutionPlan struct {
	privateExecutionValue
	requestSchemaVersion     string
	invocationSchemaVersion  string
	mode                     ExecutionMode
	timeoutSeconds           int
	resources                resolvedTaskResources
	runtimeProfile           resolvedRuntimeProfile
	artifactDigest           string
	payloadDigest            string
	derivationSpecDigest     string
	outputID                 string
	runtimeCommand           resolvedRuntimeCommand
	semanticEnvironment      map[string]string
	mounts                   []resolvedMountPlan
	networkAccess            bool
	authority                resolvedAuthorityPlan
	runtimeSupportDigest     string
	runtimeIdentityTmpfsSize int64
	jobEnvelope              resolvedJobEnvelope
}

type resolvedTrustMaterial struct {
	privateExecutionValue
	vaultCACertBytes       []byte
	workloadTLSBundleBytes []byte
}

type validatedMountEntry struct {
	privateExecutionValue
	name      string
	directory bool
	mode      os.FileMode
	contents  []byte
}

type validatedMountArchive struct {
	privateExecutionValue
	compressedBytes []byte
	entries         []validatedMountEntry
}

type resolvedMaterialFacts struct {
	privateExecutionValue
	payloadBytes        []byte
	runtimeSupportBytes []byte
	mounts              []validatedMountArchive
	trust               resolvedTrustMaterial
}

type resolvedExecutionMaterial struct {
	privateExecutionValue
	payloadBytes        []byte
	runtimeSupportBytes []byte
	mounts              []validatedMountArchive
	trust               resolvedTrustMaterial
}

type hostMaterializationContext struct {
	privateExecutionValue
	stagingRootDir string
	owner          executionPlatformStateOwner
	spireSourceDir string
	datacenter     string
}

type normalizedSubmitPlacementFacts struct {
	privateExecutionValue
	stagingRootDir string
	resultsRootDir string
	spireSourceDir string
	datacenter     string
}

// resolvedCustodyPlacement carries filesystem placement only. It is deliberately
// separate from admitted semantics, host/job projection, and future binding input.
type resolvedCustodyPlacement struct {
	privateExecutionValue
	stagingRootDir string
	resultsRootDir string
}

type resolvedRunProjection struct {
	privateExecutionValue
	runID              string
	jobID              string
	layout             executionPackageLayout
	runtimeCommand     resolvedRuntimeCommand
	runtimeImage       string
	environment        map[string]string
	mounts             []resolvedMountPlan
	networkMode        string
	resources          resolvedTaskResources
	runtimeMountInputs resolvedRuntimeMountInputs
	jobEnvelope        resolvedJobEnvelope
	datacenters        []string
	artifactDigest     string
	derivationDigest   string
	outputID           string
	authorityHandoff   executionAuthorityHandoffProjection
}

type resolvedNomadJobProjection struct {
	privateExecutionValue
	runID              string
	jobID              string
	layout             executionPackageLayout
	runtimeCommand     resolvedRuntimeCommand
	runtimeImage       string
	environment        map[string]string
	stagedMounts       []stagedRuntimeMount
	networkMode        string
	resources          resolvedTaskResources
	runtimeMountInputs resolvedRuntimeMountInputs
	jobEnvelope        resolvedJobEnvelope
	datacenters        []string
	artifactDigest     string
	derivationDigest   string
	outputID           string
	authorityMetadata  executionAuthorityMetadataProjection
}

type resolvedExecution struct {
	privateExecutionValue
	plan             resolvedExecutionPlan
	material         resolvedExecutionMaterial
	host             hostMaterializationContext
	custodyPlacement resolvedCustodyPlacement
}

func snapshotAdmissionRequest(request PrepareRequest) PrepareRequest {
	snapshot := request
	snapshot.Invocation.Argv = copyStringSlice(request.Invocation.Argv)
	snapshot.Invocation.Env = copyStringMap(request.Invocation.Env)
	if request.Invocation.Mounts != nil {
		snapshot.Invocation.Mounts = make([]RuntimeMount, len(request.Invocation.Mounts))
		copy(snapshot.Invocation.Mounts, request.Invocation.Mounts)
	}
	snapshot.Invocation.Annotations = copyStringMap(request.Invocation.Annotations)
	if request.Resources != nil {
		resources := *request.Resources
		snapshot.Resources = &resources
	}
	return snapshot
}

func snapshotRuntimeTrustModel(model egsmodel.RuntimeTrustPolicy) egsmodel.RuntimeTrustPolicy {
	snapshot := model
	snapshot.SignerPolicy.AllowedSigners = copyStringSlice(model.SignerPolicy.AllowedSigners)
	snapshot.SignerPolicy.RevokedSigners = copyStringSlice(model.SignerPolicy.RevokedSigners)
	snapshot.ArtifactPolicy.RevokedArtifacts = copyStringSlice(model.ArtifactPolicy.RevokedArtifacts)
	return snapshot
}

func newSubmitConfigSnapshot(cfg esconfig.Config) submitConfigSnapshot {
	profile := cfg.Execution.RuntimeProfiles.ControlPlaneNormalShell
	return submitConfigSnapshot{
		stagingRootDir:             cfg.Execution.StagingRootDir,
		resultsRootDir:             cfg.Execution.ResultsRootDir,
		baseImage:                  strings.TrimSpace(cfg.Execution.BaseImage),
		runtimeIdentityTmpfsSize:   cfg.Execution.EffectiveRuntimeIdentityTmpfsSize(),
		runtimeSupportBinary:       cfg.Execution.RuntimeSupportBinary,
		spireWorkloadAPISocketPath: cfg.Execution.SPIREWorkloadAPISocketPath,
		controlPlaneEnabled:        profile.Enabled,
		controlPlaneImage:          profile.Image,
		controlPlaneCodexCLIPath:   profile.CodexCLIPath,
		controlPlaneVaultPath:      profile.CredentialVaultSecretPath,
		controlPlaneVaultField:     profile.CredentialVaultSecretField,
		datacenter:                 cfg.Nomad.Datacenter,
	}
}

func (snapshot submitConfigSnapshot) executionConfig() esconfig.ExecutionConfig {
	return esconfig.ExecutionConfig{
		BaseImage:                snapshot.baseImage,
		RuntimeIdentityTmpfsSize: snapshot.runtimeIdentityTmpfsSize,
		RuntimeProfiles: esconfig.RuntimeProfilesConfig{
			ControlPlaneNormalShell: esconfig.ControlPlaneNormalShellProfileConfig{
				Enabled:                    snapshot.controlPlaneEnabled,
				Image:                      snapshot.controlPlaneImage,
				CodexCLIPath:               snapshot.controlPlaneCodexCLIPath,
				CredentialVaultSecretPath:  snapshot.controlPlaneVaultPath,
				CredentialVaultSecretField: snapshot.controlPlaneVaultField,
			},
		},
	}
}

func newResolvedExecutionPlan(facts resolvedPlanFacts) resolvedExecutionPlan {
	return resolvedExecutionPlan{
		requestSchemaVersion:     facts.requestSchemaVersion,
		invocationSchemaVersion:  facts.invocationSchemaVersion,
		mode:                     facts.mode,
		timeoutSeconds:           facts.timeoutSeconds,
		resources:                facts.resources,
		runtimeProfile:           copyResolvedRuntimeProfile(facts.runtimeProfile),
		artifactDigest:           facts.artifactDigest,
		payloadDigest:            facts.payloadDigest,
		derivationSpecDigest:     facts.derivationSpecDigest,
		outputID:                 facts.outputID,
		runtimeCommand:           copyResolvedRuntimeCommand(facts.runtimeCommand),
		semanticEnvironment:      copyStringMap(facts.semanticEnvironment),
		mounts:                   copyResolvedMountPlans(facts.mounts),
		networkAccess:            facts.networkAccess,
		authority:                copyResolvedAuthorityPlan(facts.authority),
		runtimeSupportDigest:     facts.runtimeSupportDigest,
		runtimeIdentityTmpfsSize: facts.runtimeIdentityTmpfsSize,
		jobEnvelope:              copyResolvedJobEnvelope(facts.jobEnvelope),
	}
}

func newResolvedExecutionMaterial(facts *resolvedMaterialFacts) (resolvedExecutionMaterial, error) {
	if facts == nil {
		return resolvedExecutionMaterial{}, fmt.Errorf("resolved execution material facts are required")
	}
	if err := validateResolvedExecutionMaterialBudget(*facts); err != nil {
		return resolvedExecutionMaterial{}, err
	}
	material := resolvedExecutionMaterial{
		payloadBytes:        facts.payloadBytes,
		runtimeSupportBytes: facts.runtimeSupportBytes,
		mounts:              facts.mounts,
		trust:               facts.trust,
	}
	facts.payloadBytes = nil
	facts.runtimeSupportBytes = nil
	facts.mounts = nil
	facts.trust = resolvedTrustMaterial{}
	return material, nil
}

func normalizeAbsoluteSubmitPath(name string, raw string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", fmt.Errorf("%s is required", name)
	}
	cleaned := filepath.Clean(trimmed)
	if !filepath.IsAbs(cleaned) {
		return "", fmt.Errorf("%s must be absolute", name)
	}
	return cleaned, nil
}

func normalizeSubmitPlacementFacts(config submitConfigSnapshot) (normalizedSubmitPlacementFacts, error) {
	stagingRootDir, err := normalizeAbsoluteSubmitPath("execution staging root", config.stagingRootDir)
	if err != nil {
		return normalizedSubmitPlacementFacts{}, err
	}
	resultsRootDir, err := normalizeAbsoluteSubmitPath("execution results root", config.resultsRootDir)
	if err != nil {
		return normalizedSubmitPlacementFacts{}, err
	}
	spireSocketPath, err := normalizeAbsoluteSubmitPath("SPIRE workload API socket", config.spireWorkloadAPISocketPath)
	if err != nil {
		return normalizedSubmitPlacementFacts{}, err
	}
	spireSourceDir := filepath.Dir(spireSocketPath)
	if !filepath.IsAbs(spireSourceDir) {
		return normalizedSubmitPlacementFacts{}, fmt.Errorf("SPIRE workload API source directory must be absolute")
	}
	datacenter := strings.TrimSpace(config.datacenter)
	if datacenter == "" {
		return normalizedSubmitPlacementFacts{}, fmt.Errorf("Nomad datacenter is required")
	}
	return normalizedSubmitPlacementFacts{
		stagingRootDir: stagingRootDir,
		resultsRootDir: resultsRootDir,
		spireSourceDir: spireSourceDir,
		datacenter:     datacenter,
	}, nil
}

func newHostMaterializationContext(stagingRootDir string, _ string, owner executionPlatformStateOwner, spireSourceDir string, datacenter string) hostMaterializationContext {
	return hostMaterializationContext{
		stagingRootDir: stagingRootDir,
		owner:          owner,
		spireSourceDir: spireSourceDir,
		datacenter:     datacenter,
	}
}

func (s *Service) resolveExecutionForSubmit(ctx context.Context, request PrepareRequest) (resolvedExecution, *Error) {
	if s.nomadClient == nil || !s.cfg.SubmitConfigured() {
		return resolvedExecution{}, &Error{
			Status:  http.StatusServiceUnavailable,
			Code:    codeExecutionRuntimeUnavailable,
			Message: "execution runtime is unavailable",
		}
	}

	prepared, err := s.prepareAdmission(ctx, request, admissionIntentSubmit)
	if err != nil {
		return resolvedExecution{}, err
	}
	config := newSubmitConfigSnapshot(s.cfg)

	if prepared.artifact.manifest.ArtifactType != "static-script" {
		return resolvedExecution{}, &Error{
			Status:  http.StatusBadRequest,
			Code:    codeUnsupportedArtifactType,
			Message: "only static-script artifacts are supported in this execution slice",
		}
	}
	if len(prepared.artifact.manifest.RuntimeInterface.RequiredCapabilities) > 0 {
		return resolvedExecution{}, &Error{
			Status:  http.StatusBadRequest,
			Code:    codeUnsupportedCapabilities,
			Message: "required_capabilities are not supported in this execution slice",
		}
	}
	if targetPlatform := strings.TrimSpace(prepared.artifact.targetPlatform); targetPlatform != "" && targetPlatform != "docker" {
		return resolvedExecution{}, &Error{
			Status:  http.StatusBadRequest,
			Code:    codeUnsupportedArtifactType,
			Message: "only docker target_platform is supported in this execution slice",
		}
	}
	runtimeProfile, profileErr := resolveExecutionRuntimeProfile(config.executionConfig(), prepared.admittedRequest, prepared.artifact)
	if profileErr != nil {
		return resolvedExecution{}, profileErr
	}
	placement, placementErr := normalizeSubmitPlacementFacts(config)
	if placementErr != nil {
		return resolvedExecution{}, &Error{
			Status:  http.StatusInternalServerError,
			Code:    codeSubmissionFailed,
			Message: "derive execution host context failed",
		}
	}
	resources := resolvedTaskResources{}
	resources.cpu, resources.memoryMB = resolveTaskResources(prepared.admittedRequest.Resources)

	payloadBytes := prepared.policyPayloadBytes
	prepared.policyPayloadBytes = nil
	if !prepared.policyPayloadBytesAvailable {
		payload, payloadErr := s.fetchPayloadBytes(ctx, prepared.artifact.payloadDigest)
		if payloadErr != nil {
			return resolvedExecution{}, payloadErr
		}
		payloadBytes = payload
	}

	runtimeSupportBytes, runtimeSupportDigest, runtimeSupportErr := captureRuntimeSupport(config.runtimeSupportBinary)
	if runtimeSupportErr != nil {
		return resolvedExecution{}, &Error{
			Status:  http.StatusInternalServerError,
			Code:    codeSubmissionFailed,
			Message: "stage artifact payload failed",
		}
	}

	mountPlans, mountMaterial, mountErr := s.resolveRuntimeMounts(ctx, prepared.trustModel, prepared.admittedRequest.Invocation.Mounts)
	if mountErr != nil {
		return resolvedExecution{}, mountErr
	}
	if reservedErr := ValidateReservedRuntimePaths(resolvedRuntimeMountTargets(mountPlans)); reservedErr != nil {
		return resolvedExecution{}, &Error{
			Status:  http.StatusConflict,
			Code:    codeMountConflict,
			Message: reservedErr.Error(),
		}
	}

	trust, trustErr := captureWorkloadTrustMaterial(prepared.workloadVaultPlan)
	if trustErr != nil {
		return resolvedExecution{}, &Error{
			Status:  http.StatusInternalServerError,
			Code:    codeSubmissionFailed,
			Message: "stage workload vault trust material failed",
		}
	}

	owner, ownerErr := resolveExecutionPlatformStateOwnerModel(placement.stagingRootDir, placement.resultsRootDir, nil)
	if ownerErr != nil {
		return resolvedExecution{}, &Error{
			Status:  http.StatusInternalServerError,
			Code:    codeSubmissionFailed,
			Message: "derive execution platform state owner failed",
		}
	}

	profile := resolvedRuntimeProfile{
		name:  runtimeProfile.name,
		image: strings.TrimSpace(runtimeProfile.image),
	}
	if profile.image == "" {
		profile.image = config.baseImage
	}
	workloadVault := resolvedWorkloadVaultPlan{
		mode:        strings.TrimSpace(string(prepared.workloadVaultPlan.Mode)),
		address:     strings.TrimSpace(prepared.workloadVaultPlan.Address),
		authMount:   strings.TrimSpace(prepared.workloadVaultPlan.AuthMount),
		authRole:    strings.TrimSpace(prepared.workloadVaultPlan.AuthRole),
		jwtAudience: strings.TrimSpace(prepared.workloadVaultPlan.JWTAudience),
	}
	trustFlags := stagedWorkloadTrustMaterial{
		vaultCACert:       len(trust.vaultCACertBytes) > 0,
		workloadTLSBundle: len(trust.workloadTLSBundleBytes) > 0,
	}
	authority := resolvedAuthorityPlan{
		runtimeProfileName:            profile.name,
		codexCredential:               resolveCodexCredentialLocation(runtimeProfile.env),
		workloadVault:                 workloadVault,
		workloadZoneVaultConfigDigest: strings.TrimSpace(prepared.workloadZoneVaultConfigRef.Digest),
		trustMaterial:                 trustFlags,
	}
	plan := newResolvedExecutionPlan(resolvedPlanFacts{
		requestSchemaVersion:    prepared.admittedRequest.SchemaVersion,
		invocationSchemaVersion: prepared.admittedRequest.Invocation.SchemaVersion,
		mode:                    prepared.admittedRequest.Mode,
		timeoutSeconds:          prepared.admittedRequest.TimeoutSeconds,
		resources:               resources,
		runtimeProfile:          profile,
		artifactDigest:          prepared.admittedRequest.Invocation.ArtifactDigest,
		payloadDigest:           prepared.artifact.payloadDigest,
		derivationSpecDigest:    prepared.admittedRequest.Invocation.DerivationSpecDigest,
		outputID:                prepared.admittedRequest.Invocation.OutputID,
		runtimeCommand:          newResolvedRuntimeCommand(prepared.admittedRequest.Invocation.Argv, prepared.admittedRequest.TimeoutSeconds),
		semanticEnvironment: resolvedSemanticRuntimeEnvironment(
			prepared.admittedRequest.Invocation.Env,
			runtimeProfile.env,
			prepared.admittedRequest.Invocation.ArtifactDigest,
			workloadVault,
			trustFlags,
		),
		mounts:                   mountPlans,
		networkAccess:            prepared.artifact.networkAccess,
		authority:                authority,
		runtimeSupportDigest:     runtimeSupportDigest,
		runtimeIdentityTmpfsSize: config.runtimeIdentityTmpfsSize,
		jobEnvelope:              defaultResolvedJobEnvelope(),
	})
	materialFacts := resolvedMaterialFacts{
		payloadBytes:        payloadBytes,
		runtimeSupportBytes: runtimeSupportBytes,
		mounts:              mountMaterial,
		trust:               trust,
	}
	material, materialErr := newResolvedExecutionMaterial(&materialFacts)
	if materialErr != nil {
		return resolvedExecution{}, &Error{
			Status:  http.StatusInternalServerError,
			Code:    codeSubmissionFailed,
			Message: "stage artifact payload failed",
		}
	}
	host := newHostMaterializationContext(
		placement.stagingRootDir,
		placement.resultsRootDir,
		owner,
		placement.spireSourceDir,
		placement.datacenter,
	)
	return resolvedExecution{
		plan:     plan,
		material: material,
		host:     host,
		custodyPlacement: resolvedCustodyPlacement{
			stagingRootDir: placement.stagingRootDir,
			resultsRootDir: placement.resultsRootDir,
		},
	}, nil
}

func captureRuntimeSupport(sourcePath string) ([]byte, string, error) {
	content, err := captureStableRegularFile(sourcePath, maxRuntimeSupportBytes)
	if err != nil {
		return nil, "", err
	}
	return content, digestBytes(content), nil
}

func captureWorkloadTrustMaterial(plan esconfig.ResolvedWorkloadVaultAuthPlan) (resolvedTrustMaterial, error) {
	vaultCA := normalizePEMForRuntimeFile(plan.CABundlePEM)
	if len(vaultCA) == 0 {
		return resolvedTrustMaterial{}, nil
	}
	if int64(len(vaultCA)) > maxWorkloadVaultCABytes {
		return resolvedTrustMaterial{}, fmt.Errorf("workload Vault CA bundle exceeds the governed limit")
	}
	systemCA, err := readSystemCABundle()
	if err != nil {
		return resolvedTrustMaterial{}, err
	}
	combined := appendNormalizedPEMBundle(systemCA, vaultCA)
	if int64(len(combined)) > maxWorkloadTLSBundleBytes {
		return resolvedTrustMaterial{}, fmt.Errorf("workload TLS CA bundle exceeds the governed limit")
	}
	return resolvedTrustMaterial{
		vaultCACertBytes:       vaultCA,
		workloadTLSBundleBytes: combined,
	}, nil
}

func validateResolvedExecutionMaterialBudget(facts resolvedMaterialFacts) error {
	var total int64
	components := [][]byte{facts.payloadBytes, facts.runtimeSupportBytes, facts.trust.vaultCACertBytes, facts.trust.workloadTLSBundleBytes}
	for _, component := range components {
		var ok bool
		total, ok = addWithinLimit(total, int64(len(component)), maxResolvedExecutionMaterialBytes)
		if !ok {
			return fmt.Errorf("resolved execution material exceeds the aggregate limit")
		}
	}
	for _, archive := range facts.mounts {
		var ok bool
		total, ok = addWithinLimit(total, int64(len(archive.compressedBytes)), maxResolvedExecutionMaterialBytes)
		if !ok {
			return fmt.Errorf("resolved execution material exceeds the aggregate limit")
		}
		for _, entry := range archive.entries {
			total, ok = addWithinLimit(total, int64(len(entry.name)), maxResolvedExecutionMaterialBytes)
			if !ok {
				return fmt.Errorf("resolved execution material exceeds the aggregate limit")
			}
			total, ok = addWithinLimit(total, int64(len(entry.contents)), maxResolvedExecutionMaterialBytes)
			if !ok {
				return fmt.Errorf("resolved execution material exceeds the aggregate limit")
			}
		}
	}
	return nil
}

func resolvedSemanticRuntimeEnvironment(invocation map[string]string, profileEnvironment map[string]string, artifactDigest string, vault resolvedWorkloadVaultPlan, trust stagedWorkloadTrustMaterial) map[string]string {
	environment := make(map[string]string, len(invocation)+len(profileEnvironment)+13)
	for key, value := range invocation {
		environment[key] = value
	}
	for key, value := range profileEnvironment {
		environment[key] = value
	}
	environment["EXEC_ARTIFACT_DIGEST"] = artifactDigest
	environment["EXEC_WORK_DIR"] = executionRuntimeWorkDir
	environment["SERVICE_ID"] = "execution"
	environment["VAULT_ADDR"] = vault.address
	if trust.vaultCACert {
		environment["VAULT_CACERT"] = executionRuntimePlatformDir + "/" + executionWorkloadVaultCAName
	}
	if trust.workloadTLSBundle {
		environment["SSL_CERT_FILE"] = executionRuntimePlatformDir + "/" + executionWorkloadTLSBundleName
	}
	environment["EXEC_WORKLOAD_VAULT_AUTH_MODE"] = vault.mode
	environment["EXEC_WORKLOAD_VAULT_AUTH_MOUNT"] = vault.authMount
	environment["EXEC_WORKLOAD_VAULT_AUTH_ROLE"] = vault.authRole
	environment["EXEC_WORKLOAD_VAULT_JWT_AUDIENCE"] = vault.jwtAudience
	return environment
}

func defaultResolvedJobEnvelope() resolvedJobEnvelope {
	return resolvedJobEnvelope{
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
			interval: int64(time.Minute),
			delay:    int64(10 * time.Second),
		},
		reschedulePolicy: resolvedReschedulePolicy{
			attempts:      0,
			unlimited:     false,
			delay:         0,
			delayFunction: "constant",
			maxDelay:      0,
		},
	}
}

func newResolvedRunProjection(plan resolvedExecutionPlan, host hostMaterializationContext, locator executionLocator) resolvedRunProjection {
	layout := newExecutionPackageLayoutFromHost(host, locator)
	environment := copyStringMap(plan.semanticEnvironment)
	if environment == nil {
		environment = make(map[string]string, 5)
	}
	environment[platformStateOwnerUIDEnvKey] = strconv.Itoa(host.owner.UID)
	environment[platformStateOwnerGIDEnvKey] = strconv.Itoa(host.owner.GID)
	environment[platformStateOwnerSchemaEnvKey] = platformStateOwnerSchemaV1
	environment["EXEC_RUN_ID"] = locator.RunID
	environment[layout.runtimeIdentity.endpointEnvKey] = layout.runtimeIdentity.endpointURI
	networkMode := "none"
	if plan.networkAccess {
		networkMode = "bridge"
	}
	authority := newExecutionAuthorityHandoffProjectionFromResolvedPlan(plan.authority, layout.runtimeIdentity)
	return resolvedRunProjection{
		runID:          locator.RunID,
		jobID:          locator.JobID(),
		layout:         layout,
		runtimeCommand: copyResolvedRuntimeCommand(plan.runtimeCommand),
		runtimeImage:   plan.runtimeProfile.image,
		environment:    environment,
		mounts:         copyResolvedMountPlans(plan.mounts),
		networkMode:    networkMode,
		resources:      plan.resources,
		runtimeMountInputs: resolvedRuntimeMountInputs{
			identityTmpfsSize: plan.runtimeIdentityTmpfsSize,
			spireSourceDir:    host.spireSourceDir,
		},
		jobEnvelope:      copyResolvedJobEnvelope(plan.jobEnvelope),
		datacenters:      []string{host.datacenter},
		artifactDigest:   plan.artifactDigest,
		derivationDigest: plan.derivationSpecDigest,
		outputID:         plan.outputID,
		authorityHandoff: authority,
	}
}

func (run resolvedRunProjection) nomadJobProjection(stagedMounts []stagedRuntimeMount) resolvedNomadJobProjection {
	return resolvedNomadJobProjection{
		runID:              run.runID,
		jobID:              run.jobID,
		layout:             run.layout,
		runtimeCommand:     copyResolvedRuntimeCommand(run.runtimeCommand),
		runtimeImage:       run.runtimeImage,
		environment:        copyStringMap(run.environment),
		stagedMounts:       copyStagedRuntimeMounts(stagedMounts),
		networkMode:        run.networkMode,
		resources:          run.resources,
		runtimeMountInputs: run.runtimeMountInputs,
		jobEnvelope:        copyResolvedJobEnvelope(run.jobEnvelope),
		datacenters:        copyStringSlice(run.datacenters),
		artifactDigest:     run.artifactDigest,
		derivationDigest:   run.derivationDigest,
		outputID:           run.outputID,
		authorityMetadata: executionAuthorityMetadataProjection{
			runtimeProfileName:            run.authorityHandoff.runtimeProfileName,
			workloadZoneVaultConfigDigest: run.authorityHandoff.workloadZoneVaultConfigDigest,
		},
	}
}

func copyResolvedRuntimeProfile(profile resolvedRuntimeProfile) resolvedRuntimeProfile {
	return profile
}

func copyResolvedAuthorityPlan(plan resolvedAuthorityPlan) resolvedAuthorityPlan {
	return plan
}

func copyResolvedJobEnvelope(envelope resolvedJobEnvelope) resolvedJobEnvelope {
	envelope.securityOptions = copyStringSlice(envelope.securityOptions)
	return envelope
}

func copyResolvedMountPlans(mounts []resolvedMountPlan) []resolvedMountPlan {
	if mounts == nil {
		return nil
	}
	result := make([]resolvedMountPlan, len(mounts))
	copy(result, mounts)
	return result
}

func copyStagedRuntimeMounts(mounts []stagedRuntimeMount) []stagedRuntimeMount {
	if mounts == nil {
		return nil
	}
	result := make([]stagedRuntimeMount, len(mounts))
	copy(result, mounts)
	return result
}

func copyStringSlice(values []string) []string {
	if values == nil {
		return nil
	}
	result := make([]string, len(values))
	copy(result, values)
	return result
}

func copyStringMap(values map[string]string) map[string]string {
	if values == nil {
		return nil
	}
	result := make(map[string]string, len(values))
	for key, value := range values {
		result[key] = value
	}
	return result
}

func copyBytes(values []byte) []byte {
	if values == nil {
		return nil
	}
	result := make([]byte, len(values))
	copy(result, values)
	return result
}
