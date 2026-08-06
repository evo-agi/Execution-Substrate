package admission

import (
	"strings"

	esconfig "execution-substrate/es/config"
)

const (
	resolvedRuntimeSupportCommandIdentity = executionRuntimeSupportPath
	resolvedSupervisorOperationIdentity   = executionRuntimeSupervisorOperation
)

type resolvedExecutionPlan struct {
	request     resolvedRequestPlan
	mode        ExecutionMode
	timeout     resolvedTimeoutPlan
	resources   resolvedResourcePlan
	profile     resolvedRuntimeProfilePlan
	artifact    resolvedArtifactIdentityPlan
	derivation  resolvedDerivationIdentityPlan
	output      resolvedOutputIdentityPlan
	command     resolvedCommandPlan
	environment resolvedEnvironmentPlan
	mounts      []resolvedMountPlan
	network     resolvedNetworkPosture
	authority   resolvedAuthorityHandoffPlan
}

type resolvedRequestPlan struct {
	outerSchemaVersion      string
	invocationSchemaVersion string
}

type resolvedTimeoutPlan struct {
	seconds int
}

type resolvedResourcePlan struct {
	cpu      int
	memoryMB int
}

type resolvedRuntimeProfilePlan struct {
	name          string
	selectedImage string
	env           map[string]string
}

type resolvedArtifactIdentityPlan struct {
	artifactDigest string
	payloadDigest  string
	artifactType   string
	intentDigest   string
	targetPlatform string
}

type resolvedDerivationIdentityPlan struct {
	derivationSpecDigest string
}

type resolvedOutputIdentityPlan struct {
	outputID string
}

type resolvedCommandPlan struct {
	runtimeSupportCommandIdentity string
	supervisorOperationIdentity   string
	timeoutSeconds                int
	workloadArgv                  []string
}

type resolvedEnvironmentPlan struct {
	callerEnv  map[string]string
	profileEnv map[string]string
}

type resolvedMountPlan struct {
	sourceArtifactDigest string
	targetPath           string
	readOnly             bool
}

type resolvedNetworkPosture string

const (
	resolvedNetworkPostureBridge resolvedNetworkPosture = "bridge"
	resolvedNetworkPostureNone   resolvedNetworkPosture = "none"
)

type resolvedAuthorityHandoffPlan struct {
	applicable                      bool
	workloadVaultPlan               esconfig.ResolvedWorkloadVaultAuthPlan
	workloadZoneVaultConfigDigest   string
	codexCredentialLocationMetadata *resolvedCodexCredentialLocationPlan
}

type resolvedCodexCredentialLocationPlan struct {
	cliPath          string
	credentialSource string
	vaultSecretPath  string
	vaultSecretField string
}

func (s *Service) resolveCurrentSubmitExecutionPlan(prepared preparedAdmission) (resolvedExecutionPlan, *Error) {
	req := prepared.normalizedRequest

	if prepared.artifact.manifest.ArtifactType != "static-script" {
		return resolvedExecutionPlan{}, unsupportedSubmitArtifactTypeError()
	}
	if len(prepared.artifact.manifest.RuntimeInterface.RequiredCapabilities) > 0 {
		return resolvedExecutionPlan{}, unsupportedSubmitCapabilitiesError()
	}
	targetPlatform := strings.TrimSpace(prepared.artifact.targetPlatform)
	if targetPlatform != "" && targetPlatform != "docker" {
		return resolvedExecutionPlan{}, unsupportedSubmitTargetPlatformError()
	}
	runtimeProfile, profileErr := resolveExecutionRuntimeProfile(s.cfg.Execution, req, prepared.artifact)
	if profileErr != nil {
		return resolvedExecutionPlan{}, profileErr
	}

	cpu, memoryMB := resolveTaskResources(req.Resources)
	mounts, mountErr := resolveSubmitMountPlan(req.Invocation.Mounts)
	if mountErr != nil {
		return resolvedExecutionPlan{}, mountErr
	}

	network := resolvedNetworkPostureNone
	if prepared.artifact.networkAccess {
		network = resolvedNetworkPostureBridge
	}

	profileEnv := cloneStringMap(runtimeProfile.env)
	authority := resolvedAuthorityHandoffPlan{
		applicable:                    true,
		workloadVaultPlan:             cloneResolvedWorkloadVaultAuthPlan(prepared.workloadVaultPlan),
		workloadZoneVaultConfigDigest: strings.TrimSpace(s.workloadZoneVaultConfigRef.Digest),
	}
	if codex := codexCredentialLocationFromRuntimeProfile(executionRuntimeProfile{
		name: runtimeProfile.name,
		env:  profileEnv,
	}); codex != nil {
		authority.codexCredentialLocationMetadata = &resolvedCodexCredentialLocationPlan{
			cliPath:          codex.CLIPath,
			credentialSource: codex.CredentialSource,
			vaultSecretPath:  codex.VaultSecretPath,
			vaultSecretField: codex.VaultSecretField,
		}
	}

	plan := resolvedExecutionPlan{
		request: resolvedRequestPlan{
			outerSchemaVersion:      strings.TrimSpace(req.SchemaVersion),
			invocationSchemaVersion: strings.TrimSpace(req.Invocation.SchemaVersion),
		},
		mode: ExecutionModeAsync,
		timeout: resolvedTimeoutPlan{
			seconds: req.TimeoutSeconds,
		},
		resources: resolvedResourcePlan{
			cpu:      cpu,
			memoryMB: memoryMB,
		},
		profile: resolvedRuntimeProfilePlan{
			name:          strings.TrimSpace(runtimeProfile.name),
			selectedImage: strings.TrimSpace(selectedRuntimeImage(s.cfg.Execution, runtimeProfile)),
			env:           profileEnv,
		},
		artifact: resolvedArtifactIdentityPlan{
			artifactDigest: strings.TrimSpace(req.Invocation.ArtifactDigest),
			payloadDigest:  strings.TrimSpace(prepared.artifact.payloadDigest),
			artifactType:   strings.TrimSpace(prepared.artifact.manifest.ArtifactType),
			intentDigest:   strings.TrimSpace(prepared.artifact.manifest.IntentDigest),
			targetPlatform: targetPlatform,
		},
		derivation: resolvedDerivationIdentityPlan{
			derivationSpecDigest: req.Invocation.DerivationSpecDigest,
		},
		output: resolvedOutputIdentityPlan{
			outputID: req.Invocation.OutputID,
		},
		command: resolvedCommandPlan{
			runtimeSupportCommandIdentity: resolvedRuntimeSupportCommandIdentity,
			supervisorOperationIdentity:   resolvedSupervisorOperationIdentity,
			timeoutSeconds:                req.TimeoutSeconds,
			workloadArgv:                  cloneStringSlice(req.Invocation.Argv),
		},
		environment: resolvedEnvironmentPlan{
			callerEnv:  cloneStringMap(req.Invocation.Env),
			profileEnv: profileEnv,
		},
		mounts:    mounts,
		network:   network,
		authority: authority,
	}

	return plan.clone(), nil
}

func resolveSubmitMountPlan(mounts []RuntimeMount) ([]resolvedMountPlan, *Error) {
	if len(mounts) == 0 {
		return nil, nil
	}
	resolved := make([]resolvedMountPlan, 0, len(mounts))
	for _, mount := range mounts {
		targetPath, err := normalizeRuntimeMountTargetPath(mount.TargetPath)
		if err != nil {
			return nil, invalidRequestError(err.Error())
		}
		resolved = append(resolved, resolvedMountPlan{
			sourceArtifactDigest: strings.TrimSpace(mount.Source.ArtifactDigest),
			targetPath:           targetPath,
			readOnly:             mount.ReadOnly,
		})
	}
	return resolved, nil
}

func (p resolvedExecutionPlan) clone() resolvedExecutionPlan {
	p.profile.env = cloneStringMap(p.profile.env)
	p.command.workloadArgv = cloneStringSlice(p.command.workloadArgv)
	p.environment.callerEnv = cloneStringMap(p.environment.callerEnv)
	p.environment.profileEnv = cloneStringMap(p.environment.profileEnv)
	p.mounts = cloneResolvedMountPlans(p.mounts)
	p.authority.workloadVaultPlan = cloneResolvedWorkloadVaultAuthPlan(p.authority.workloadVaultPlan)
	if p.authority.codexCredentialLocationMetadata != nil {
		copy := *p.authority.codexCredentialLocationMetadata
		p.authority.codexCredentialLocationMetadata = &copy
	}
	return p
}

func (p resolvedExecutionPlan) executionRuntimeProfile() executionRuntimeProfile {
	return executionRuntimeProfile{
		name:  p.profile.name,
		image: p.profile.selectedImage,
		env:   cloneStringMap(p.profile.env),
	}
}

func (p resolvedExecutionPlan) runtimeMounts() []RuntimeMount {
	if len(p.mounts) == 0 {
		return nil
	}
	mounts := make([]RuntimeMount, 0, len(p.mounts))
	for _, mount := range p.mounts {
		mounts = append(mounts, RuntimeMount{
			Source: MountSource{
				ArtifactDigest: mount.sourceArtifactDigest,
			},
			TargetPath: mount.targetPath,
			ReadOnly:   mount.readOnly,
		})
	}
	return mounts
}

func (p resolvedNetworkPosture) networkAccess() bool {
	return p == resolvedNetworkPostureBridge
}

func clonePrepareRequest(req PrepareRequest) PrepareRequest {
	cloned := req
	if req.Resources != nil {
		resources := *req.Resources
		cloned.Resources = &resources
	}
	cloned.Invocation.Argv = cloneStringSlice(req.Invocation.Argv)
	cloned.Invocation.Env = cloneStringMap(req.Invocation.Env)
	cloned.Invocation.Mounts = cloneRuntimeMounts(req.Invocation.Mounts)
	cloned.Invocation.Annotations = cloneStringMap(req.Invocation.Annotations)
	return cloned
}

func cloneRuntimeMounts(mounts []RuntimeMount) []RuntimeMount {
	if len(mounts) == 0 {
		return nil
	}
	cloned := make([]RuntimeMount, len(mounts))
	copy(cloned, mounts)
	return cloned
}

func cloneResolvedMountPlans(mounts []resolvedMountPlan) []resolvedMountPlan {
	if len(mounts) == 0 {
		return nil
	}
	cloned := make([]resolvedMountPlan, len(mounts))
	copy(cloned, mounts)
	return cloned
}

func cloneStringSlice(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	cloned := make([]string, len(values))
	copy(cloned, values)
	return cloned
}

func cloneStringMap(values map[string]string) map[string]string {
	if len(values) == 0 {
		return nil
	}
	cloned := make(map[string]string, len(values))
	for key, value := range values {
		cloned[key] = value
	}
	return cloned
}

func cloneResolvedWorkloadVaultAuthPlan(plan esconfig.ResolvedWorkloadVaultAuthPlan) esconfig.ResolvedWorkloadVaultAuthPlan {
	return esconfig.ResolvedWorkloadVaultAuthPlan{
		Mode:        plan.Mode,
		Address:     plan.Address,
		AuthMount:   plan.AuthMount,
		AuthRole:    plan.AuthRole,
		JWTAudience: plan.JWTAudience,
		CABundlePEM: plan.CABundlePEM,
	}
}
