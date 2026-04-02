package admission

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	esconfig "execution-platform/es/config"
)

const (
	runtimeIdentityProbeCPU      = 10
	runtimeIdentityProbeMemoryMB = 64
)

type RuntimeIdentityProbeConfig struct {
	BaseImage        string
	EndpointHostPath string
	Datacenter       string
	Runner           runtimeIdentityProbeRunner
}

type runtimeIdentityProbeRunner interface {
	submitJob(ctx context.Context, jobSpec map[string]any) (string, error)
	latestAllocation(ctx context.Context, jobID string) (*nomadAllocationDetail, *Error)
	fetchTaskLogs(ctx context.Context, allocationID string, taskName string) ([]byte, *Error)
	purgeJob(ctx context.Context, jobID string) error
}

func validateRuntimeIdentityPlumbingAtStartup(ctx context.Context, cfg esconfig.Config, runner runtimeIdentityProbeRunner) error {
	if !cfg.SubmitConfigured() {
		return nil
	}
	if err := ValidateIdentityEndpointPath(cfg.Execution.WorkloadIdentityEndpointHostPath); err != nil {
		return err
	}
	return ProbeMountedUnixSocketExposure(ctx, RuntimeIdentityProbeConfig{
		BaseImage:        cfg.Execution.BaseImage,
		EndpointHostPath: cfg.Execution.WorkloadIdentityEndpointHostPath,
		Datacenter:       cfg.Nomad.Datacenter,
		Runner:           runner,
	})
}

func ProbeMountedUnixSocketExposure(ctx context.Context, probeConfig RuntimeIdentityProbeConfig) error {
	if probeConfig.Runner == nil {
		return fmt.Errorf("runtime identity probe runner is required")
	}
	if err := ValidateIdentityEndpointPath(probeConfig.EndpointHostPath); err != nil {
		return err
	}
	if strings.TrimSpace(probeConfig.BaseImage) == "" {
		return fmt.Errorf("runtime identity probe base image is required")
	}
	if strings.TrimSpace(probeConfig.Datacenter) == "" {
		return fmt.Errorf("runtime identity probe datacenter is required")
	}

	jobID, err := newRuntimeIdentityProbeJobID()
	if err != nil {
		return fmt.Errorf("generate runtime identity probe job id: %w", err)
	}

	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = probeConfig.Runner.purgeJob(cleanupCtx, jobID)
	}()

	jobSpec := buildRuntimeIdentityProbeJobSpec(probeConfig, jobID)
	if _, err := probeConfig.Runner.submitJob(ctx, jobSpec); err != nil {
		return fmt.Errorf("runtime identity endpoint exposure capability could not be proven: submit probe job failed: %w", err)
	}

	allocation, err := waitForRuntimeIdentityProbeAllocation(ctx, probeConfig.Runner, jobID)
	if err != nil {
		return fmt.Errorf("runtime identity endpoint exposure capability could not be proven: %w", err)
	}

	taskState, ok := allocation.TaskStates[nomadTaskName]
	if !ok {
		return fmt.Errorf("runtime identity endpoint exposure capability could not be proven: probe task state is unavailable")
	}
	exitCode, ok := taskState.exitCode()
	if !ok {
		return fmt.Errorf("runtime identity endpoint exposure capability could not be proven: probe task exit code is unavailable")
	}
	if exitCode != 0 {
		logSuffix := ""
		if logs, logErr := probeConfig.Runner.fetchTaskLogs(ctx, allocation.ID, nomadTaskName); logErr == nil {
			trimmedLogs := strings.TrimSpace(string(logs))
			if trimmedLogs != "" {
				logSuffix = ": " + trimmedLogs
			}
		}
		return fmt.Errorf("runtime identity endpoint exposure capability could not be proven: probe exited with code %d%s", exitCode, logSuffix)
	}

	return nil
}

func buildRuntimeIdentityProbeJobSpec(probeConfig RuntimeIdentityProbeConfig, jobID string) map[string]any {
	script := strings.Join([]string{
		"set -eu",
		"if [ -S \"" + runtimeIdentityEndpointTargetPath + "\" ]; then",
		"  exit 0",
		"fi",
		"echo runtime-identity-endpoint-not-exposed-as-unix-socket >&2",
		"exit 1",
	}, "\n")

	return map[string]any{
		"Job": map[string]any{
			"ID":          jobID,
			"Name":        jobID,
			"Type":        "batch",
			"Datacenters": []string{probeConfig.Datacenter},
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
							"Name":   nomadTaskName,
							"Driver": "docker",
							"Config": map[string]any{
								"image":   probeConfig.BaseImage,
								"command": "/bin/sh",
								"args":    []string{"-ec", script},
								"mounts": []any{
									map[string]any{
										"type":     "bind",
										"source":   runtimeIdentityEndpointMountSource(probeConfig.EndpointHostPath),
										"target":   runtimeIdentityEndpointTargetDir,
										"readonly": true,
									},
								},
								"network_mode": "none",
							},
							"Resources": map[string]any{
								"CPU":      runtimeIdentityProbeCPU,
								"MemoryMB": runtimeIdentityProbeMemoryMB,
							},
						},
					},
				},
			},
		},
	}
}

func waitForRuntimeIdentityProbeAllocation(ctx context.Context, runner runtimeIdentityProbeRunner, jobID string) (*nomadAllocationDetail, error) {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		allocation, err := runner.latestAllocation(ctx, jobID)
		if err != nil {
			return nil, fmt.Errorf("probe allocation lookup failed: %w", err)
		}
		if allocation != nil {
			taskState, ok := allocation.TaskStates[nomadTaskName]
			if isTerminalAllocationStatus(allocation.ClientStatus) || (ok && strings.TrimSpace(taskState.State) == "dead") {
				return allocation, nil
			}
		}

		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("probe did not reach a terminal allocation before startup timed out")
		case <-ticker.C:
		}
	}
}

func newRuntimeIdentityProbeJobID() (string, error) {
	randomBytes := make([]byte, 8)
	if _, err := rand.Read(randomBytes); err != nil {
		return "", err
	}
	return "es-runtime-identity-probe-" + hex.EncodeToString(randomBytes), nil
}
