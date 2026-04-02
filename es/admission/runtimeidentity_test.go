package admission

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	esconfig "execution-platform/es/config"
)

func TestValidateIdentityEndpointPathAcceptsUnixSocket(t *testing.T) {
	socketPath, cleanup := startTestIdentityEndpointSocket(t)
	defer cleanup()

	if err := ValidateIdentityEndpointPath(socketPath); err != nil {
		t.Fatalf("expected unix socket path to validate, got %v", err)
	}
}

func TestValidateReservedRuntimePathsRejectsReservedOverlap(t *testing.T) {
	err := ValidateReservedRuntimePaths([]string{"/monolith/runtime-identity/endpoint.sock"})
	if err == nil || !strings.Contains(err.Error(), "must not overlap reserved runtime paths") {
		t.Fatalf("expected reserved path overlap error, got %v", err)
	}
}

func TestValidateRuntimeIdentityPlumbingAtStartupRejectsInvalidEndpointPath(t *testing.T) {
	invalidPath := filepath.Join(t.TempDir(), runtimeIdentityEndpointSocketName)
	if err := os.WriteFile(invalidPath, []byte("not-a-socket"), 0o600); err != nil {
		t.Fatalf("write invalid endpoint path: %v", err)
	}

	cfg := esconfig.Config{
		Nomad: esconfig.NomadConfig{
			Datacenter: "dc1",
		},
		Execution: esconfig.ExecutionConfig{
			BaseImage:                        "alpine:3.20",
			WorkloadIdentityEndpointHostPath: invalidPath,
		},
	}

	err := validateRuntimeIdentityPlumbingAtStartup(context.Background(), cfg, nil)
	if err == nil || !strings.Contains(err.Error(), "must reference a unix socket") {
		t.Fatalf("expected invalid endpoint path error, got %v", err)
	}
}

func TestValidateRuntimeIdentityPlumbingAtStartupFailsWhenCapabilityCannotBeProven(t *testing.T) {
	socketPath, cleanup := startTestIdentityEndpointSocket(t)
	defer cleanup()

	cfg := esconfig.Config{
		Nomad: esconfig.NomadConfig{
			Datacenter: "dc1",
		},
		Execution: esconfig.ExecutionConfig{
			BaseImage:                        "alpine:3.20",
			WorkloadIdentityEndpointHostPath: socketPath,
		},
	}

	runner := &fakeRuntimeIdentityProbeRunner{
		submitJobID: "probe-job",
		allocation: &nomadAllocationDetail{
			ID:           "alloc-1",
			ClientStatus: "failed",
			TaskStates: map[string]nomadTaskState{
				nomadTaskName: {
					State: "dead",
					Events: []nomadTaskEvent{
						{Type: "Terminated", ExitCode: 1},
					},
				},
			},
		},
		logs: []byte("runtime-identity-endpoint-not-exposed-as-unix-socket\n"),
	}

	err := validateRuntimeIdentityPlumbingAtStartup(context.Background(), cfg, runner)
	if err == nil || !strings.Contains(err.Error(), "runtime identity endpoint exposure capability could not be proven") {
		t.Fatalf("expected capability probe failure, got %v", err)
	}
	if runner.submitCalls != 1 {
		t.Fatalf("expected one probe submission, got %d", runner.submitCalls)
	}
	if runner.purgeCalls != 1 {
		t.Fatalf("expected one probe cleanup, got %d", runner.purgeCalls)
	}
}

func TestValidateRuntimeIdentityPlumbingAtStartupSucceedsWhenCapabilityIsProven(t *testing.T) {
	socketPath, cleanup := startTestIdentityEndpointSocket(t)
	defer cleanup()

	cfg := esconfig.Config{
		Nomad: esconfig.NomadConfig{
			Datacenter: "dc1",
		},
		Execution: esconfig.ExecutionConfig{
			BaseImage:                        "alpine:3.20",
			WorkloadIdentityEndpointHostPath: socketPath,
		},
	}

	runner := &fakeRuntimeIdentityProbeRunner{
		submitJobID: "probe-job",
		allocation: &nomadAllocationDetail{
			ID:           "alloc-1",
			ClientStatus: "complete",
			TaskStates: map[string]nomadTaskState{
				nomadTaskName: {
					State: "dead",
					Events: []nomadTaskEvent{
						{Type: "Terminated", ExitCode: 0},
					},
				},
			},
		},
	}

	if err := validateRuntimeIdentityPlumbingAtStartup(context.Background(), cfg, runner); err != nil {
		t.Fatalf("expected startup validation success, got %v", err)
	}
	if runner.submitCalls != 1 {
		t.Fatalf("expected one probe submission, got %d", runner.submitCalls)
	}
	if runner.purgeCalls != 1 {
		t.Fatalf("expected one probe cleanup, got %d", runner.purgeCalls)
	}
}

type fakeRuntimeIdentityProbeRunner struct {
	submitJobID string
	submitErr   error

	allocation    *nomadAllocationDetail
	allocationErr *Error

	logs    []byte
	logsErr *Error

	purgeErr error

	submitCalls int
	purgeCalls  int
}

func (f *fakeRuntimeIdentityProbeRunner) submitJob(ctx context.Context, jobSpec map[string]any) (string, error) {
	f.submitCalls++
	if f.submitErr != nil {
		return "", f.submitErr
	}
	return f.submitJobID, nil
}

func (f *fakeRuntimeIdentityProbeRunner) latestAllocation(ctx context.Context, jobID string) (*nomadAllocationDetail, *Error) {
	return f.allocation, f.allocationErr
}

func (f *fakeRuntimeIdentityProbeRunner) fetchTaskLogs(ctx context.Context, allocationID string, taskName string) ([]byte, *Error) {
	return f.logs, f.logsErr
}

func (f *fakeRuntimeIdentityProbeRunner) purgeJob(ctx context.Context, jobID string) error {
	f.purgeCalls++
	return f.purgeErr
}

func startTestIdentityEndpointSocket(t *testing.T) (string, func()) {
	t.Helper()

	socketDir, err := os.MkdirTemp("/tmp", "es-ri-")
	if err != nil {
		t.Fatalf("create short socket temp dir: %v", err)
	}
	socketPath := filepath.Join(socketDir, runtimeIdentityEndpointSocketName)
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listen on test unix socket: %v", err)
	}
	return socketPath, func() {
		_ = listener.Close()
		_ = os.Remove(socketPath)
		_ = os.RemoveAll(socketDir)
	}
}
