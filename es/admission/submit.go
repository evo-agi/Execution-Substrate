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
	"path/filepath"
	"strconv"
	"strings"
	"time"

	esconfig "execution-platform/es/config"
	"execution-platform/observability"
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

type stagedPayload struct {
	rootDir    string
	payloadDir string
	runDir     string
	mounts     []stagedRuntimeMount
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

	stage, stageErr := s.stagePayload(locator.RunID, payloadBytes)
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
			_ = os.RemoveAll(stage.rootDir)
		}
	}()

	// Failed submits are cleaned immediately. Successful submits currently retain
	// payload/run staging under execution.staging_root_dir unless removed
	// externally, but the reserved runtime-identity workspace is provisioned as
	// tmpfs and is no longer host-backed by the submit path.

	stage.mounts, err = s.stageRuntimeMounts(ctx, prepared.trustModel, stage.rootDir, req.Invocation.Mounts)
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

	env := buildRuntimeEnvironment(locator.RunID, req.Invocation.ArtifactDigest, prepared.workloadVaultPlan, req.Invocation.Env, req.TimeoutSeconds)
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

func (s *Service) stagePayload(runID string, payloadBytes []byte) (stagedPayload, error) {
	stageRoot := filepath.Join(s.cfg.Execution.StagingRootDir, runID)
	payloadDir := filepath.Join(stageRoot, "payload")
	runDir := filepath.Join(stageRoot, "run")
	if err := os.MkdirAll(payloadDir, 0o755); err != nil {
		return stagedPayload{}, err
	}
	if err := os.MkdirAll(runDir, 0o755); err != nil {
		return stagedPayload{}, err
	}
	if err := os.WriteFile(filepath.Join(payloadDir, "artifact.tar.gz"), payloadBytes, 0o600); err != nil {
		return stagedPayload{}, err
	}
	return stagedPayload{
		rootDir:    stageRoot,
		payloadDir: payloadDir,
		runDir:     runDir,
	}, nil
}

func resolveTaskResources(resources *ExecutionResources) (cpu int, memoryMB int) {
	if resources == nil {
		return defaultSubmitCPU, defaultSubmitMemoryMB
	}
	return resources.CPU, resources.MemoryMB
}

func buildRuntimeEnvironment(runID string, artifactDigest string, workloadVaultPlan esconfig.ResolvedWorkloadVaultAuthPlan, invocationEnv map[string]string, timeoutSeconds int) map[string]string {
	handoff := runtimeIdentityHandoffForRun(runID)

	env := make(map[string]string, len(invocationEnv)+12)
	for key, value := range invocationEnv {
		env[key] = value
	}

	// TODO: Do not mention "monolith"
	env["EXEC_RUN_ID"] = runID
	env["EXEC_ARTIFACT_DIGEST"] = artifactDigest
	env["EXEC_WORK_DIR"] = "/monolith/run/work"
	env["SERVICE_ID"] = "execution"
	env["VAULT_ADDR"] = workloadVaultPlan.Address
	env[handoff.endpointEnvKey] = handoff.endpointURI
	env[handoff.compatibilityEndpointEnvKey] = handoff.endpointURI
	env["MONOLITH_WORKLOAD_VAULT_AUTH_MODE"] = string(workloadVaultPlan.Mode)
	env["MONOLITH_WORKLOAD_VAULT_AUTH_MOUNT"] = workloadVaultPlan.AuthMount
	env["MONOLITH_WORKLOAD_VAULT_AUTH_ROLE"] = workloadVaultPlan.AuthRole
	env["MONOLITH_WORKLOAD_VAULT_JWT_AUDIENCE"] = workloadVaultPlan.JWTAudience
	env["EXEC_TIMEOUT_SECONDS"] = strconv.Itoa(timeoutSeconds)
	return env
}

func buildNomadJobSpec(
	cfg esconfig.Config,
	jobID string,
	runID string,
	stage stagedPayload,
	req PrepareRequest,
	networkAccess bool,
	taskCPU int,
	taskMemoryMB int,
	env map[string]string,
) map[string]any {
	handoff := runtimeIdentityHandoffForRun(runID)

	// TODO: Do not mention "monolith"
	wrapper := strings.Join([]string{
		"set -eu",
		"mkdir -p /monolith/run/work",
		"mkdir -p " + handoff.workspaceDir(),
		"tar -xzf /monolith/staged/artifact.tar.gz -C /monolith/run/work",
		"chmod +x /monolith/run/work/entrypoint",
		"if [ \"$EXEC_TIMEOUT_SECONDS\" -gt 0 ]; then",
		"  exec timeout \"$EXEC_TIMEOUT_SECONDS\" /monolith/run/work/entrypoint \"$@\"",
		"fi",
		"exec /monolith/run/work/entrypoint \"$@\"",
	}, "\n")

	shellArgs := []string{"-ec", wrapper, "entrypoint"}
	shellArgs = append(shellArgs, req.Invocation.Argv...)

	taskConfig := map[string]any{
		"image":   cfg.Execution.BaseImage,
		"command": "/bin/sh",
		"args":    shellArgs,
	}

	// TODO: Do not mention "monolith"
	mounts := []any{
		map[string]any{
			"type":     "bind",
			"source":   stage.payloadDir,
			"target":   "/monolith/staged",
			"readonly": true,
		},
		map[string]any{
			"type":     "bind",
			"source":   stage.runDir,
			"target":   "/monolith/run",
			"readonly": false,
		},
		map[string]any{
			"type":     "tmpfs",
			"target":   handoff.workspaceDir(),
			"readonly": false,
			"tmpfs_options": map[string]any{
				"size": cfg.Execution.EffectiveRuntimeIdentityTmpfsSize(),
			},
		},
	}

	for _, mount := range stage.mounts {
		mounts = append(mounts, map[string]any{
			"type":     "bind",
			"source":   mount.sourceDir,
			"target":   mount.targetPath,
			"readonly": true,
		})
	}

	taskConfig["mounts"] = mounts
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
			// slice, so traceparent propagation remains disabled explicitly.
			// Future external dependencies must make the same propagation decision
			// deliberately rather than inheriting internal behavior silently.
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
