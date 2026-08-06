package admission

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"strings"
	"time"

	esconfig "execution-substrate/es/config"
	"execution-substrate/internal/observability"
)

const (
	defaultSubmitCPU               = 10
	defaultSubmitMemoryMB          = 128
	platformStateOwnerUIDEnvKey    = "EXEC_PLATFORM_STATE_OWNER_UID"
	platformStateOwnerGIDEnvKey    = "EXEC_PLATFORM_STATE_OWNER_GID"
	platformStateOwnerSchemaEnvKey = "EXEC_PLATFORM_STATE_OWNER_SCHEMA"
	platformStateOwnerSchemaV1     = "v1"
)

type nomadClient struct {
	baseURL    *url.URL
	datacenter string
	client     *http.Client
}

type nomadJobRegisterResponse struct {
	EvalID string `json:"EvalID"`
}

func (s *Service) Submit(ctx context.Context, req PrepareRequest) (SubmitResult, *Error) {
	if s.nomadClient == nil || !s.cfg.SubmitConfigured() {
		return SubmitResult{}, &Error{
			Status:  http.StatusServiceUnavailable,
			Code:    codeExecutionRuntimeUnavailable,
			Message: "execution runtime is unavailable",
		}
	}

	if req.Mode == "" {
		req.Mode = ExecutionModeAsync
	}
	if req.Mode != ExecutionModeAsync {
		return SubmitResult{}, &Error{
			Status:  http.StatusBadRequest,
			Code:    codeUnsupportedExecutionMode,
			Message: "only async submission is supported in this execution slice",
		}
	}

	prepared, err := s.prepareAdmission(ctx, req)
	if err != nil {
		return SubmitResult{}, err
	}

	plan, planErr := s.resolveCurrentSubmitExecutionPlan(prepared)
	if planErr != nil {
		return SubmitResult{}, planErr
	}

	payloadBytes := prepared.policyPayloadBytes
	if !prepared.policyPayloadBytesAvailable {
		payload, err := s.fetchPayloadBytes(ctx, plan.artifact.payloadDigest)
		if err != nil {
			return SubmitResult{}, err
		}
		payloadBytes = payload
	}

	locator, locatorErr := newExecutionLocator()
	if locatorErr != nil {
		return SubmitResult{}, &Error{
			Status:  http.StatusInternalServerError,
			Code:    codeSubmissionFailed,
			Message: "generate run id failed",
		}
	}

	platformStateOwner, ownerErr := resolveExecutionPlatformStateOwnerModel(
		s.cfg.Execution.StagingRootDir,
		s.cfg.Execution.ResultsRootDir,
		nil,
	)
	if ownerErr != nil {
		return SubmitResult{}, &Error{
			Status:  http.StatusInternalServerError,
			Code:    codeSubmissionFailed,
			Message: fmt.Sprintf("derive execution platform state owner failed: %v", ownerErr),
		}
	}

	stage, stageErr := s.stageExecutionInputs(locator, payloadBytes, platformStateOwner)
	if stageErr != nil {
		return SubmitResult{}, &Error{
			Status:  http.StatusInternalServerError,
			Code:    codeSubmissionFailed,
			Message: "stage artifact payload failed",
		}
	}

	submitted := false
	defer func() {
		if !submitted {
			_ = os.RemoveAll(stage.layout.stageRootDir)
		}
	}()

	// Failed submits are cleaned immediately. Successful submits retain
	// payload/run staging only while the workload may still depend on those bind
	// mounts; the lifecycle path now performs best-effort cleanup after terminal
	// success is observed. The reserved runtime-identity workspace is provisioned
	// as tmpfs and is no longer host-backed by the submit path.

	stage.mounts, err = s.stageRuntimeMounts(ctx, prepared.trustModel, stage.layout, plan.runtimeMounts(), platformStateOwner)
	if err != nil {
		return SubmitResult{}, err
	}
	if err := ValidateReservedRuntimePaths(stagedRuntimeMountTargets(stage.mounts)); err != nil {
		return SubmitResult{}, &Error{
			Status:  http.StatusConflict,
			Code:    codeMountConflict,
			Message: err.Error(),
		}
	}

	var trustErr error
	stage.trustMaterial, trustErr = stage.layout.stageWorkloadVaultTrustMaterial(plan.authority.workloadVaultPlan, platformStateOwner)
	if trustErr != nil {
		return SubmitResult{}, &Error{
			Status:  http.StatusInternalServerError,
			Code:    codeSubmissionFailed,
			Message: fmt.Sprintf("stage workload vault trust material failed: %v", trustErr),
		}
	}

	runtimeProfile := plan.executionRuntimeProfile()
	env := buildRuntimeEnvironment(stage.layout, plan.artifact.artifactDigest, plan.authority.workloadVaultPlan, runtimeProfile, stage.trustMaterial, plan.environment.callerEnv, &platformStateOwner)
	authorityHandoff := buildExecutionAuthorityHandoff(
		runtimeProfile,
		stage.layout.runtimeIdentity,
		plan.authority.workloadVaultPlan,
		plan.authority.workloadZoneVaultConfigDigest,
		stage.trustMaterial,
	)
	jobSpec := buildNomadJobSpec(
		s.cfg,
		locator.JobID(),
		locator.RunID,
		stage,
		plan,
		env,
	)

	_, submitErr := s.nomadClient.submitJob(ctx, jobSpec)
	if submitErr != nil {
		return SubmitResult{}, &Error{
			Status:  http.StatusServiceUnavailable,
			Code:    codeSubmissionFailed,
			Message: submitErr.Error(),
		}
	}
	submitted = true

	return SubmitResult{
		Success:          true,
		Submitted:        true,
		RunID:            locator.RunID,
		Status:           "submitted",
		AuthorityHandoff: &authorityHandoff,
	}, nil
}

func (s *Service) fetchPayloadBytes(ctx context.Context, payloadDigest string) ([]byte, *Error) {
	response, err := s.arsClient.get(ctx, "/v1/blobs/"+payloadDigest+":bytes")
	if err != nil {
		return nil, &Error{
			Status:  http.StatusServiceUnavailable,
			Code:    codePayloadUnavailable,
			Message: "artifact payload read failed",
		}
	}
	defer response.Body.Close()

	switch response.StatusCode {
	case http.StatusOK:
		payload, readErr := io.ReadAll(response.Body)
		if readErr != nil {
			return nil, &Error{
				Status:  http.StatusServiceUnavailable,
				Code:    codePayloadUnavailable,
				Message: "artifact payload read failed",
			}
		}
		return payload, nil
	case http.StatusNotFound:
		return nil, &Error{
			Status:  http.StatusServiceUnavailable,
			Code:    codePayloadUnavailable,
			Message: "artifact payload is unavailable",
		}
	default:
		return nil, &Error{
			Status:  http.StatusServiceUnavailable,
			Code:    codePayloadUnavailable,
			Message: fmt.Sprintf("artifact payload read returned status %d", response.StatusCode),
		}
	}
}

func resolveTaskResources(resources *ExecutionResources) (cpu int, memoryMB int) {
	if resources == nil {
		return defaultSubmitCPU, defaultSubmitMemoryMB
	}
	return resources.CPU, resources.MemoryMB
}

func unsupportedSubmitArtifactTypeError() *Error {
	return &Error{
		Status:  http.StatusBadRequest,
		Code:    codeUnsupportedArtifactType,
		Message: "only static-script artifacts are supported in this execution slice",
	}
}

func unsupportedSubmitCapabilitiesError() *Error {
	return &Error{
		Status:  http.StatusBadRequest,
		Code:    codeUnsupportedCapabilities,
		Message: "required_capabilities are not supported in this execution slice",
	}
}

func unsupportedSubmitTargetPlatformError() *Error {
	return &Error{
		Status:  http.StatusBadRequest,
		Code:    codeUnsupportedArtifactType,
		Message: "only docker target_platform is supported in this execution slice",
	}
}

func invalidRequestError(message string) *Error {
	return &Error{
		Status:  http.StatusBadRequest,
		Code:    codeInvalidRequest,
		Message: message,
	}
}

func buildRuntimeEnvironment(layout executionPackageLayout, artifactDigest string, workloadVaultPlan esconfig.ResolvedWorkloadVaultAuthPlan, runtimeProfile executionRuntimeProfile, trustMaterial stagedWorkloadTrustMaterial, invocationEnv map[string]string, platformStateOwner *executionPlatformStateOwner) map[string]string {
	env := make(map[string]string, len(invocationEnv)+len(runtimeProfile.env)+16)
	for key, value := range invocationEnv {
		env[key] = value
	}
	for key, value := range runtimeProfile.env {
		env[key] = value
	}

	env["EXEC_RUN_ID"] = layout.runID
	env["EXEC_ARTIFACT_DIGEST"] = artifactDigest
	env["EXEC_WORK_DIR"] = layout.runtimeWorkDir
	env["SERVICE_ID"] = "execution"
	env["VAULT_ADDR"] = workloadVaultPlan.Address
	if trustMaterial.vaultCACert {
		env["VAULT_CACERT"] = layout.workloadVaultCACertRuntimePath()
	}
	if trustMaterial.workloadTLSBundle {
		env["SSL_CERT_FILE"] = layout.workloadTLSBundleRuntimePath()
	}
	env[layout.runtimeIdentity.endpointEnvKey] = layout.runtimeIdentity.endpointURI
	env["EXEC_WORKLOAD_VAULT_AUTH_MODE"] = string(workloadVaultPlan.Mode)
	env["EXEC_WORKLOAD_VAULT_AUTH_MOUNT"] = workloadVaultPlan.AuthMount
	env["EXEC_WORKLOAD_VAULT_AUTH_ROLE"] = workloadVaultPlan.AuthRole
	env["EXEC_WORKLOAD_VAULT_JWT_AUDIENCE"] = workloadVaultPlan.JWTAudience
	if platformStateOwner != nil {
		env[platformStateOwnerUIDEnvKey] = fmt.Sprintf("%d", platformStateOwner.UID)
		env[platformStateOwnerGIDEnvKey] = fmt.Sprintf("%d", platformStateOwner.GID)
		env[platformStateOwnerSchemaEnvKey] = platformStateOwnerSchemaV1
	}
	return env
}

func buildNomadJobSpec(
	cfg esconfig.Config,
	jobID string,
	runID string,
	stage stagedExecutionInputs,
	plan resolvedExecutionPlan,
	env map[string]string,
) map[string]any {
	layout := stage.layout
	runtimeProfile := plan.executionRuntimeProfile()
	supervisorArgs := layout.runtimeSupervisorArgs(plan.command.workloadArgv, plan.command.timeoutSeconds, plan.command.supervisorOperationIdentity)
	jobMeta := executionAuthorityMetadata(runtimeProfile, plan.authority.workloadZoneVaultConfigDigest)
	jobMeta["run_id"] = runID

	taskConfig := map[string]any{
		"image":        plan.profile.selectedImage,
		"command":      plan.command.runtimeSupportCommandIdentity,
		"args":         supervisorArgs,
		"privileged":   false,
		"security_opt": []string{"no-new-privileges"},
	}

	taskConfig["mounts"] = layout.runtimeMountSpecs(cfg, stage.mounts)
	if plan.network.networkAccess() {
		taskConfig["network_mode"] = "bridge"
	} else {
		taskConfig["network_mode"] = "none"
	}

	return map[string]any{
		"Job": map[string]any{
			"ID":          jobID,
			"Name":        jobID,
			"Meta":        jobMeta,
			"Type":        "batch",
			"Datacenters": []string{cfg.Nomad.Datacenter},
			"TaskGroups": []any{
				map[string]any{
					"Name":  "group",
					"Count": 1,
					"RestartPolicy": map[string]any{
						"Attempts": 0,
						"Mode":     "fail",
						"Interval": int64(time.Minute),
						"Delay":    int64(10 * time.Second),
					},
					"ReschedulePolicy": map[string]any{
						"Attempts":      0,
						"Unlimited":     false,
						"Delay":         int64(0),
						"DelayFunction": "constant",
						"MaxDelay":      int64(0),
					},
					"Tasks": []any{
						map[string]any{
							"Name":   "task",
							"Driver": "docker",
							"User":   "0:0",
							"Config": taskConfig,
							"Env":    env,
							"Resources": map[string]any{
								"CPU":      plan.resources.cpu,
								"MemoryMB": plan.resources.memoryMB,
							},
							"Meta": map[string]any{
								"run_id":                 runID,
								"artifact_digest":        plan.artifact.artifactDigest,
								"derivation_spec_digest": plan.derivation.derivationSpecDigest,
								"output_id":              plan.output.outputID,
							},
						},
					},
				},
			},
		},
	}
}

func selectedRuntimeImage(cfg esconfig.ExecutionConfig, runtimeProfile executionRuntimeProfile) string {
	if image := strings.TrimSpace(runtimeProfile.image); image != "" {
		return image
	}
	return strings.TrimSpace(cfg.BaseImage)
}

func newNomadClient(cfg esconfig.NomadConfig) (*nomadClient, error) {
	baseURL, err := url.Parse(cfg.BaseURL)
	if err != nil {
		return nil, err
	}

	return &nomadClient{
		baseURL:    baseURL,
		datacenter: strings.TrimSpace(cfg.Datacenter),
		client: &http.Client{
			Timeout: time.Duration(cfg.TimeoutSeconds) * time.Second,
			// TODO: Nomad is treated as an external execution dependency in this
			// 		 slice, so traceparent propagation remains disabled explicitly.
			// 		 Future external dependencies must make the same propagation decision
			// 		 deliberately rather than inheriting internal behavior silently.
			Transport: observability.WrapRoundTripper("execution", "nomad", false, nil),
		},
	}, nil
}

func (c *nomadClient) submitJob(ctx context.Context, jobSpec map[string]any) (string, error) {
	body, err := json.Marshal(jobSpec)
	if err != nil {
		return "", fmt.Errorf("marshal nomad job: %w", err)
	}

	requestURL := c.baseURL.ResolveReference(&url.URL{Path: path.Clean("/v1/jobs")})
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, requestURL.String(), strings.NewReader(string(body)))
	if err != nil {
		return "", err
	}
	request.Header.Set("Content-Type", "application/json")

	response, err := c.client.Do(request)
	if err != nil {
		return "", fmt.Errorf("submit nomad job: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		payload, _ := io.ReadAll(response.Body)
		return "", fmt.Errorf("submit nomad job: unexpected status %d: %s", response.StatusCode, strings.TrimSpace(string(payload)))
	}

	var payload nomadJobRegisterResponse
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		return "", fmt.Errorf("decode nomad submit response: %w", err)
	}
	if strings.TrimSpace(payload.EvalID) == "" {
		return "", fmt.Errorf("submit nomad job: missing eval id")
	}
	return strings.TrimSpace(payload.EvalID), nil
}
