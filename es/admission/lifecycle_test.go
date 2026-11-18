package admission

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	esconfig "execution-substrate/es/config"
)

func TestStatusRetainsSuccessfulStageRoot(t *testing.T) {
	stagingRoot := physicalTestTempDir(t)
	resultsRoot := t.TempDir()
	service := Service{
		cfg: esconfig.Config{Execution: esconfig.ExecutionConfig{StagingRootDir: stagingRoot, ResultsRootDir: resultsRoot}},
		nomadClient: newTestNomadClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/v1/job/exec-run-0123456789abcdef":
				_, _ = w.Write([]byte(`{"ID":"exec-run-0123456789abcdef","Status":"dead","ModifyIndex":10}`))
			case "/v1/job/exec-run-0123456789abcdef/allocations":
				_, _ = w.Write([]byte(`[{"ID":"alloc-success","ModifyIndex":20}]`))
			case "/v1/allocation/alloc-success":
				_, _ = w.Write([]byte(`{"ID":"alloc-success","ClientStatus":"complete","ModifyIndex":25,"TaskStates":{"task":{"State":"dead","Events":[{"Type":"Terminated","ExitCode":0}]}}}`))
			default:
				t.Fatalf("unexpected path %q", r.URL.Path)
			}
		})),
	}
	locator := newExecutionLocatorFromRunID("run-0123456789abcdef")
	layout := newExecutionPackageLayout(service.cfg, locator)
	if err := os.MkdirAll(layout.stageRootDir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(layout.stageRootDir, "sentinel"), []byte("retained"), 0o600); err != nil {
		t.Fatal(err)
	}
	result, err := service.Status(context.Background(), locator.RunID)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != executionLifecycleStatusTerminal || !result.Terminal {
		t.Fatalf("unexpected status: %+v", result)
	}
	content, readErr := os.ReadFile(filepath.Join(layout.stageRootDir, "sentinel"))
	if readErr != nil || string(content) != "retained" {
		t.Fatalf("successful observation changed staging: %q %v", content, readErr)
	}
}

func TestDescriptorCloseRetainsSuccessfulRunRoot(t *testing.T) {
	stagingRoot := physicalTestTempDir(t)
	service := Service{cfg: esconfig.Config{Execution: esconfig.ExecutionConfig{StagingRootDir: stagingRoot, ResultsRootDir: t.TempDir()}}}
	locator := newExecutionLocatorFromRunID("run-0123456789abcdef")
	layout := newExecutionPackageLayout(service.cfg, locator)

	custody, err := claimStagingCustody(stagingRoot, locator.RunID, executionPlatformStateOwner{UID: os.Getuid(), GID: os.Getgid()})
	if err != nil {
		t.Fatalf("claim stage root: %v", err)
	}
	if err := custody.writeFile("sentinel", []byte("retained"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := custody.close(); err != nil {
		t.Fatal(err)
	}
	if content, err := os.ReadFile(filepath.Join(layout.stageRootDir, "sentinel")); err != nil || string(content) != "retained" {
		t.Fatalf("close changed retained stage root: %q %v", content, err)
	}
}

func TestStatusRetainsLostStageRootForDebugging(t *testing.T) {
	stagingRoot := t.TempDir()
	service := Service{
		cfg: esconfig.Config{
			Execution: esconfig.ExecutionConfig{
				StagingRootDir: stagingRoot,
				ResultsRootDir: t.TempDir(),
			},
		},
		nomadClient: newTestNomadClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/v1/job/exec-run-0123456789abcdef":
				_, _ = w.Write([]byte(`{"ID":"exec-run-0123456789abcdef","Status":"running","ModifyIndex":10}`))
			case "/v1/job/exec-run-0123456789abcdef/allocations":
				_, _ = w.Write([]byte(`[{"ID":"alloc-lost","ModifyIndex":20}]`))
			case "/v1/allocation/alloc-lost":
				_, _ = w.Write([]byte(`{"ID":"alloc-lost","ClientStatus":"lost","ModifyIndex":25,"TaskStates":{"task":{"State":"dead","Events":[{"Type":"Started"},{"Type":"Terminated","ExitCode":137}]}}}`))
			default:
				t.Fatalf("unexpected path %q", r.URL.Path)
			}
		})),
	}
	if err := os.MkdirAll(service.cfg.Execution.ResultsRootDir, 0o700); err != nil {
		t.Fatalf("mkdir results root: %v", err)
	}
	locator := newExecutionLocatorFromRunID("run-0123456789abcdef")
	layout := newExecutionPackageLayout(service.cfg, locator)

	if err := os.MkdirAll(layout.stageRootDir, 0o755); err != nil {
		t.Fatalf("mkdir stage root: %v", err)
	}
	if err := os.WriteFile(filepath.Join(layout.stageRootDir, "marker"), []byte("retain lost run"), 0o600); err != nil {
		t.Fatalf("write stage marker: %v", err)
	}

	result, err := service.Status(context.Background(), locator.RunID)
	if err != nil {
		t.Fatalf("status: %+v", err)
	}
	if result.Status != executionLifecycleStatusTerminal || !result.Terminal {
		t.Fatalf("expected terminal lost status, got %+v", result)
	}
	if result.ExitCode == nil || *result.ExitCode != 137 {
		t.Fatalf("expected lost allocation exit code 137, got %+v", result)
	}
	if _, statErr := os.Stat(layout.stageRootDir); statErr != nil {
		t.Fatalf("expected lost allocation stage root to remain for debugging, got %v", statErr)
	}
	if _, statErr := os.Stat(filepath.Join(layout.stageRootDir, "marker")); statErr != nil {
		t.Fatalf("expected lost allocation marker to remain, got %v", statErr)
	}
	if _, statErr := os.Stat(service.retainedResultBundlePath(locator)); !os.IsNotExist(statErr) {
		t.Fatalf("did not expect retained result bundle for lost allocation, got %v", statErr)
	}
}

func TestLifecycleStatusReturnsRuntimeUnavailableWithoutNomad(t *testing.T) {
	cases := lifecycleRuntimeUnavailableCases(t)
	for i := range cases {
		tt := &cases[i]
		t.Run(tt.name, func(t *testing.T) {
			err := assertNoPanicRuntimeUnavailable(t, func() *Error {
				_, err := tt.service.Status(context.Background(), "run-0123456789abcdef")
				return err
			})
			assertTextOmitsAll(t, err.Code+" "+err.Message,
				"workflow",
				"review",
				"checkpoint",
				"finalization",
				"temporal",
				"approval",
				"intervention",
			)
		})
	}
}

func TestLifecycleLogsReturnsRuntimeUnavailableWithoutNomad(t *testing.T) {
	cases := lifecycleRuntimeUnavailableCases(t)
	for i := range cases {
		tt := &cases[i]
		t.Run(tt.name, func(t *testing.T) {
			err := assertNoPanicRuntimeUnavailable(t, func() *Error {
				_, err := tt.service.Logs(context.Background(), "run-0123456789abcdef")
				return err
			})
			assertTextOmitsAll(t, err.Code+" "+err.Message,
				"credential",
				"security",
				"vault_token",
				"client_token",
				"root_token",
				"unseal_key",
				"jwt_svid",
				"x509_svid",
				"private_key",
				"api_key",
				"proof_secret",
				"secret_payload",
				"lease",
			)
		})
	}
}

func TestLifecycleCancelReturnsRuntimeUnavailableWithoutNomad(t *testing.T) {
	cases := lifecycleRuntimeUnavailableCases(t)
	for i := range cases {
		tt := &cases[i]
		t.Run(tt.name, func(t *testing.T) {
			err := assertNoPanicRuntimeUnavailable(t, func() *Error {
				_, err := tt.service.Cancel(context.Background(), "run-0123456789abcdef")
				return err
			})
			assertTextOmitsAll(t, err.Code+" "+err.Message,
				"intervention",
				"approval",
				"temporal",
				"authority",
				"workflow",
				"review",
				"checkpoint",
				"finalization",
			)
		})
	}
}

func lifecycleRuntimeUnavailableCases(t *testing.T) []struct {
	name    string
	service Service
} {
	t.Helper()

	return []struct {
		name    string
		service Service
	}{
		{
			name: "configured_service_without_nomad_client",
			service: Service{
				cfg: minimalLifecycleConfig(t),
			},
		},
		{
			name: "unconfigured_service_with_nomad_client",
			service: Service{
				nomadClient: newTestNomadClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					t.Fatalf("runtime-unconfigured lifecycle call reached Nomad: %s %s", r.Method, r.URL.Path)
				})),
			},
		},
	}
}

func assertNoPanicRuntimeUnavailable(t *testing.T, call func() *Error) (err *Error) {
	t.Helper()

	defer func() {
		if recovered := recover(); recovered != nil {
			t.Fatalf("expected runtime-unavailable error without panic, got panic: %v", recovered)
		}
	}()

	err = call()
	assertAdmissionError(t, err, http.StatusServiceUnavailable, codeExecutionRuntimeUnavailable)
	return err
}
