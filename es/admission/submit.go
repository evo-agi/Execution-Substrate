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
	defaultSubmitCPU      = 10
	defaultSubmitMemoryMB = 128
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

	if prepared.artifact.manifest.ArtifactType != "static-script" {
		return SubmitResult{}, &Error{
			Status:  http.StatusBadRequest,
			Code:    codeUnsupportedArtifactType,
			Message: "only static-script artifacts are supported in this execution slice",
		}
	}
	if len(prepared.artifact.manifest.RuntimeInterface.RequiredCapabilities) > 0 {
		return SubmitResult{}, &Error{
			Status:  http.StatusBadRequest,
			Code:    codeUnsupportedCapabilities,
			Message: "required_capabilities are not supported in this execution slice",
		}
	}
	if targetPlatform := strings.TrimSpace(prepared.artifact.targetPlatform); targetPlatform != "" && targetPlatform != "docker" {
		return SubmitResult{}, &Error{
			Status:  http.StatusBadRequest,
			Code:    codeUnsupportedArtifactType,
			Message: "only docker target_platform is supported in this execution slice",
		}
	}

	payloadBytes, err := s.fetchPayloadBytes(ctx, prepared.artifact.payloadDigest)
	if err != nil {
		return SubmitResult{}, err
	}

	locator, locatorErr := newExecutionLocator()
	if locatorErr != nil {
		return SubmitResult{}, &Error{
			Status:  http.StatusInternalServerError,
			Code:    codeSubmissionFailed,
			Message: "generate run id failed",
		}
	}

	stage, stageErr := s.stageExecutionInputs(locator, payloadBytes)
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

	stage.mounts, err = s.stageRuntimeMounts(ctx, prepared.trustModel, stage.layout, req.Invocation.Mounts)
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

	env := buildRuntimeEnvironment(stage.layout, req.Invocation.ArtifactDigest, prepared.workloadVaultPlan, req.Invocation.Env)
	taskCPU, taskMemoryMB := resolveTaskResources(req.Resources)
	jobSpec := buildNomadJobSpec(
		s.cfg,
		locator.JobID(),
		locator.RunID,
		stage,
		req,
		prepared.artifact.networkAccess,
		taskCPU,
		taskMemoryMB,
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
		Success:   true,
		Submitted: true,
		RunID:     locator.RunID,
		Status:    "submitted",
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

func buildRuntimeEnvironment(layout executionPackageLayout, artifactDigest string, workloadVaultPlan esconfig.ResolvedWorkloadVaultAuthPlan, invocationEnv map[string]string) map[string]string {
	env := make(map[string]string, len(invocationEnv)+11)
	for key, value := range invocationEnv {
		env[key] = value
	}

	env["EXEC_RUN_ID"] = layout.runID
	env["EXEC_ARTIFACT_DIGEST"] = artifactDigest
	env["EXEC_WORK_DIR"] = layout.runtimeWorkDir
	env["SERVICE_ID"] = "execution"
	env["VAULT_ADDR"] = workloadVaultPlan.Address
	env[layout.runtimeIdentity.endpointEnvKey] = layout.runtimeIdentity.endpointURI
	env["EXEC_WORKLOAD_VAULT_AUTH_MODE"] = string(workloadVaultPlan.Mode)
	env["EXEC_WORKLOAD_VAULT_AUTH_MOUNT"] = workloadVaultPlan.AuthMount
	env["EXEC_WORKLOAD_VAULT_AUTH_ROLE"] = workloadVaultPlan.AuthRole
	env["EXEC_WORKLOAD_VAULT_JWT_AUDIENCE"] = workloadVaultPlan.JWTAudience
	return env
}

func buildNomadJobSpec(
	cfg esconfig.Config,
	jobID string,
	runID string,
	stage stagedExecutionInputs,
	req PrepareRequest,
	networkAccess bool,
	taskCPU int,
	taskMemoryMB int,
	env map[string]string,
) map[string]any {
	layout := stage.layout
	supervisorArgs := layout.runtimeSupervisorArgs(req.Invocation.Argv, req.TimeoutSeconds)

	taskConfig := map[string]any{
		"image":        cfg.Execution.BaseImage,
		"command":      executionRuntimeSupportPath,
		"args":         supervisorArgs,
		"privileged":   false,
		"security_opt": []string{"no-new-privileges"},
	}

	taskConfig["mounts"] = layout.runtimeMountSpecs(cfg, stage.mounts)
	if networkAccess {
		taskConfig["network_mode"] = "bridge"
	} else {
		taskConfig["network_mode"] = "none"
	}

	return map[string]any{
		"Job": map[string]any{
			"ID":   jobID,
			"Name": jobID,
			"Meta": map[string]any{
				"run_id": runID,
			},
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
								"CPU":      taskCPU,
								"MemoryMB": taskMemoryMB,
							},
							"Meta": map[string]any{
								"run_id":                 runID,
								"artifact_digest":        req.Invocation.ArtifactDigest,
								"derivation_spec_digest": req.Invocation.DerivationSpecDigest,
								"output_id":              req.Invocation.OutputID,
							},
						},
					},
				},
			},
		},
	}
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
