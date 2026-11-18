package admission

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"

	esconfig "execution-substrate/es/config"
	"golang.org/x/sys/unix"
)

func TestTrancheB2SubmitNomadResponseBoundAndOneDocument(t *testing.T) {
	job := map[string]any{"Job": map[string]any{"ID": "exec-run"}}
	exact := trancheB2PaddedJSON(
		`{"EvalID":" arbitrary eval id ","CompatibleUnknown":"`,
		`"}`,
		int(maxDependencyJSONResponseBytes),
	)
	exactResponse := trancheB2Response(http.StatusOK, exact, -1)
	exactProbe := exactResponse.Body.(*trancheB2ReadCloseProbe)
	client := trancheB2NomadClientWithResponse(t, func(*http.Request) *http.Response {
		return exactResponse
	})
	evalID, err := client.submitJob(context.Background(), job)
	if err != nil || evalID != "arbitrary eval id" {
		t.Fatalf("exact-limit compatible registration failed: eval=%q err=%v", evalID, err)
	}
	if !exactProbe.closed {
		t.Fatal("successful registration response body was not closed")
	}

	for name, body := range map[string][]byte{
		"limit plus one":  append(append([]byte(nil), exact...), ' '),
		"malformed":       []byte(`{"EvalID":`),
		"wrong type":      []byte(`{"EvalID":7}`),
		"trailing":        []byte(`{"EvalID":"eval"} trailing`),
		"second document": []byte(`{"EvalID":"eval"} {}`),
		"missing eval":    []byte(`{"CompatibleUnknown":true}`),
	} {
		t.Run(name, func(t *testing.T) {
			client := trancheB2NomadClientWithResponse(t, func(*http.Request) *http.Response {
				return trancheB2Response(http.StatusOK, body, -1)
			})
			if _, err := client.submitJob(context.Background(), job); err == nil {
				t.Fatalf("%s registration response succeeded", name)
			}
		})
	}

	for _, test := range []struct {
		name          string
		status        int
		contentLength int64
		wantRead      bool
	}{
		{name: "known oversize", status: http.StatusOK, contentLength: maxDependencyJSONResponseBytes + 1},
		{name: "fixed truncation", status: http.StatusOK, contentLength: int64(len(`{"EvalID":"eval"}`) + 1), wantRead: true},
		{name: "fixed surplus", status: http.StatusOK, contentLength: int64(len(`{"EvalID":"eval"}`) - 1), wantRead: true},
		{name: "non-success body", status: http.StatusBadGateway, contentLength: int64(len(`{"private":"provider-body"}`))},
	} {
		t.Run(test.name, func(t *testing.T) {
			body := []byte(`{"EvalID":"eval"}`)
			if test.status != http.StatusOK {
				body = []byte(`{"private":"provider-body"}`)
			}
			probe := &trancheB2ReadCloseProbe{reader: bytes.NewReader(body)}
			client := trancheB2NomadClientWithResponse(t, func(*http.Request) *http.Response {
				return &http.Response{StatusCode: test.status, Header: make(http.Header), Body: probe, ContentLength: test.contentLength}
			})
			if _, err := client.submitJob(context.Background(), job); err == nil {
				t.Fatal("invalid registration transport response succeeded")
			}
			if (probe.reads > 0) != test.wantRead {
				t.Fatalf("body reads=%d, wantRead=%v", probe.reads, test.wantRead)
			}
			if !probe.closed {
				t.Fatal("registration response body was not closed")
			}
		})
	}
}

func TestTrancheB2SubmitPublicNomadFailureIsFixedAndProviderBodyFree(t *testing.T) {
	const marker = "/private/provider/path uid=9123 argv=secret ENV=secret"
	fixture := newPreparedArtifactFixture(t)
	service, _, _ := newWorkstreamCTestService(t, fixture)
	policyPayload := buildAdmissionPolicyStaticScriptArchive(t, map[string][]byte{
		staticScriptEntrypointName: []byte(benignPolicyFixtureText()),
	})
	service.arsClient = newResolvedPlanDependencyClient(t, resolvedPlanArtifactHandler(t, fixture, policyPayload, nil))
	service.nomadClient = newResolvedPlanNomadClient(t, http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || request.URL.Path != "/v1/jobs" {
			t.Fatalf("unexpected Nomad request %s %q", request.Method, request.URL.Path)
		}
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte(marker))
	}))

	var logs bytes.Buffer
	previousWriter := log.Writer()
	previousFlags := log.Flags()
	previousPrefix := log.Prefix()
	log.SetOutput(&logs)
	log.SetFlags(0)
	log.SetPrefix("")
	t.Cleanup(func() {
		log.SetOutput(previousWriter)
		log.SetFlags(previousFlags)
		log.SetPrefix(previousPrefix)
	})

	_, publicErr := service.Submit(context.Background(), fixture.prepareRequest())
	if publicErr == nil || publicErr.Status != http.StatusServiceUnavailable || publicErr.Code != codeSubmissionFailed || publicErr.Message != "execution submission failed" {
		t.Fatalf("unexpected public Nomad failure: %+v", publicErr)
	}
	payload, err := json.Marshal(ErrorResponse{Success: false, Error: publicErr.Message, Code: publicErr.Code})
	if err != nil {
		t.Fatal(err)
	}
	if string(payload) != `{"success":false,"error":"execution submission failed","code":"submission_failed"}` {
		t.Fatalf("public error DTO changed: %s", payload)
	}
	if bytes.Contains(payload, []byte(marker)) || strings.Contains(logs.String(), marker) {
		t.Fatalf("provider marker escaped: response=%s logs=%q", payload, logs.String())
	}
}

func TestStagingClaimFailureMappingHasNoCleanupErrorClass(t *testing.T) {
	got := stagingClaimSubmissionError(errors.New("injected claim failure"))
	if got.Status != http.StatusInternalServerError || got.Code != codeSubmissionFailed || got.Message != "claim execution staging root failed" {
		t.Fatal("unexpected fixed staging-claim error mapping")
	}
}

func TestSubmitRejectsUnexpectedStagingChildBeforeNomadAndRetainsTree(t *testing.T) {
	fixture := newPreparedArtifactFixture(t)
	service, stagingRoot, _ := newWorkstreamCTestService(t, fixture)
	policyPayload := buildAdmissionPolicyStaticScriptArchive(t, map[string][]byte{
		staticScriptEntrypointName: []byte(benignPolicyFixtureText()),
	})
	service.arsClient = newResolvedPlanDependencyClient(t, resolvedPlanArtifactHandler(t, fixture, policyPayload, nil))

	nomadCalls := 0
	service.nomadClient = newResolvedPlanNomadClient(t, http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		nomadCalls++
		t.Fatalf("custody failure must precede Nomad registration, got %s %q", request.Method, request.URL.Path)
	}))

	var injectedPath string
	beforeStagingHandoffValidationForTest = func(custody *stagingCustody) {
		injectedPath = filepath.Join(custody.stagingRootPath, custody.runID, "unexpected")
		if err := os.WriteFile(injectedPath, []byte("outside"), 0o600); err != nil {
			t.Fatalf("inject unexpected staging child: %v", err)
		}
	}
	defer func() { beforeStagingHandoffValidationForTest = nil }()

	result, publicErr := service.Submit(context.Background(), fixture.prepareRequest())
	if publicErr == nil || publicErr.Status != http.StatusInternalServerError || publicErr.Code != codeSubmissionFailed || publicErr.Message != "stage artifact payload failed" {
		t.Fatalf("unexpected public custody error: %+v", publicErr)
	}
	if result != (SubmitResult{}) {
		t.Fatalf("failed submit returned a result: %+v", result)
	}
	if nomadCalls != 0 {
		t.Fatalf("failed custody handoff made %d Nomad calls", nomadCalls)
	}
	assertFileContent(t, injectedPath, "outside")

	rootEntries, err := os.ReadDir(stagingRoot)
	if err != nil {
		t.Fatal(err)
	}
	if len(rootEntries) != 1 || !rootEntries[0].IsDir() || !strings.HasPrefix(rootEntries[0].Name(), "run-") {
		t.Fatalf("expected one retained run root without quarantine, got %v", rootEntries)
	}
	runRoot := filepath.Join(stagingRoot, rootEntries[0].Name())
	assertFileContent(t, filepath.Join(runRoot, "payload", executionPayloadArchiveName), string(policyPayload))
	if _, err := os.Stat(filepath.Join(runRoot, "run", "platform", executionRuntimeSupportName)); err != nil {
		t.Fatalf("runtime support was not retained: %v", err)
	}
	if info, err := os.Stat(filepath.Join(runRoot, "run", "result")); err != nil || !info.IsDir() {
		t.Fatalf("result directory was not retained: %v", err)
	}
}

func TestSubmitRejectsSpecialBitMutationBeforeNomadAndRetainsTree(t *testing.T) {
	fixture := newPreparedArtifactFixture(t)
	service, stagingRoot, _ := newWorkstreamCTestService(t, fixture)
	policyPayload := buildAdmissionPolicyStaticScriptArchive(t, map[string][]byte{
		staticScriptEntrypointName: []byte(benignPolicyFixtureText()),
	})
	service.arsClient = newResolvedPlanDependencyClient(t, resolvedPlanArtifactHandler(t, fixture, policyPayload, nil))

	nomadCalls := 0
	service.nomadClient = newResolvedPlanNomadClient(t, http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		nomadCalls++
		t.Fatalf("custody failure must precede Nomad registration, got %s %q", request.Method, request.URL.Path)
	}))

	var mutatedPath string
	var mutated os.FileInfo
	beforeStagingHandoffValidationForTest = func(custody *stagingCustody) {
		mutatedPath = filepath.Join(custody.stagingRootPath, custody.runID, "run", "platform")
		mutated = mutateStagedSpecialBitForTest(t, mutatedPath, stableStageDirMode, true, os.ModeSticky)
	}
	defer func() { beforeStagingHandoffValidationForTest = nil }()

	result, publicErr := service.Submit(context.Background(), fixture.prepareRequest())
	if publicErr == nil || publicErr.Status != http.StatusInternalServerError || publicErr.Code != codeSubmissionFailed || publicErr.Message != "stage artifact payload failed" {
		t.Fatalf("unexpected public custody error: %+v", publicErr)
	}
	if result != (SubmitResult{}) {
		t.Fatalf("failed submit returned a result: %+v", result)
	}
	if nomadCalls != 0 {
		t.Fatalf("failed custody handoff made %d Nomad calls", nomadCalls)
	}
	assertStagedMutationRetained(t, mutatedPath, mutated)

	rootEntries, err := os.ReadDir(stagingRoot)
	if err != nil {
		t.Fatal(err)
	}
	if len(rootEntries) != 1 || !rootEntries[0].IsDir() || !strings.HasPrefix(rootEntries[0].Name(), "run-") {
		t.Fatalf("expected one retained run root without quarantine, got %v", rootEntries)
	}
	runRoot := filepath.Join(stagingRoot, rootEntries[0].Name())
	assertFileContent(t, filepath.Join(runRoot, "payload", executionPayloadArchiveName), string(policyPayload))
	if _, err := os.Stat(filepath.Join(runRoot, "run", "platform", executionRuntimeSupportName)); err != nil {
		t.Fatalf("runtime support was not retained: %v", err)
	}
	if info, err := os.Stat(filepath.Join(runRoot, "run", "result")); err != nil || !info.IsDir() {
		t.Fatalf("result directory was not retained: %v", err)
	}
}

func TestSubmitRejectsRegistrationWindowSpecialBitBeforeNomadAndRetainsTree(t *testing.T) {
	fixture := newPreparedArtifactFixture(t)
	service, stagingRoot, _ := newWorkstreamCTestService(t, fixture)
	policyPayload := buildAdmissionPolicyStaticScriptArchive(t, map[string][]byte{
		staticScriptEntrypointName: []byte(benignPolicyFixtureText()),
	})
	service.arsClient = newResolvedPlanDependencyClient(t, resolvedPlanArtifactHandler(t, fixture, policyPayload, nil))

	nomadCalls := 0
	service.nomadClient = newResolvedPlanNomadClient(t, http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		nomadCalls++
		t.Fatalf("registration failure must precede Nomad registration, got %s %q", request.Method, request.URL.Path)
	}))

	var mutation registrationWindowModeMutation
	hookCalls := 0
	if beforeStagingChildRegistrationStatForTest != nil {
		t.Fatal("registration-window test hook is already installed")
	}
	beforeStagingChildRegistrationStatForTest = func(relativePath string, fd int, directory bool) {
		if relativePath == executionPayloadStageDirName+"/"+executionPayloadArchiveName && !directory {
			hookCalls++
			mutation.apply(fd, uint32(retainedResultBundleFileMode), unix.S_ISGID)
		}
	}
	t.Cleanup(func() { beforeStagingChildRegistrationStatForTest = nil })
	result, publicErr := service.Submit(context.Background(), fixture.prepareRequest())
	beforeStagingChildRegistrationStatForTest = nil
	if hookCalls != 1 || !mutation.called || mutation.err != nil {
		t.Fatalf("registration-window payload mutation calls=%d, called=%t, error=%v", hookCalls, mutation.called, mutation.err)
	}
	if uint32(mutation.after.Mode)&unix.S_ISGID == 0 {
		t.Skipf("filesystem did not retain setgid after successful descriptor chmod on staged payload")
	}
	if publicErr == nil || publicErr.Status != http.StatusInternalServerError || publicErr.Code != codeSubmissionFailed || publicErr.Message != "stage artifact payload failed" {
		t.Fatalf("unexpected public custody error: %+v", publicErr)
	}
	if result != (SubmitResult{}) {
		t.Fatalf("failed submit returned a result: %+v", result)
	}
	if nomadCalls != 0 {
		t.Fatalf("failed registration made %d Nomad calls", nomadCalls)
	}
	rootEntries, err := os.ReadDir(stagingRoot)
	if err != nil {
		t.Fatal(err)
	}
	if len(rootEntries) != 1 || !rootEntries[0].IsDir() || !strings.HasPrefix(rootEntries[0].Name(), "run-") {
		t.Fatalf("expected one retained run root without quarantine, got %v", rootEntries)
	}
	runRoot := filepath.Join(stagingRoot, rootEntries[0].Name())
	mutatedPath := filepath.Join(runRoot, executionPayloadStageDirName, executionPayloadArchiveName)
	mutation.assertRetained(t, mutatedPath, unix.S_IFREG, uint32(retainedResultBundleFileMode), unix.S_ISGID)
	if mutation.before.Size != int64(len(policyPayload)) {
		t.Fatalf("registration hook saw incomplete payload: size=%d want=%d", mutation.before.Size, len(policyPayload))
	}
	assertFileContent(t, mutatedPath, string(policyPayload))
}

func TestResolvedPlanCustodyRepairWideTreeSubmitHandoff(t *testing.T) {
	fixture := newPreparedArtifactFixture(t)
	service, stagingRoot, _ := newWorkstreamCTestService(t, fixture)
	policyPayload := buildAdmissionPolicyStaticScriptArchive(t, map[string][]byte{
		staticScriptEntrypointName: []byte(benignPolicyFixtureText()),
	})
	service.arsClient = newResolvedPlanDependencyClient(t, resolvedPlanArtifactHandler(t, fixture, policyPayload, nil))
	registrations := 0
	service.nomadClient = newResolvedPlanNomadClient(t, http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		registrations++
		if request.Method != http.MethodPost || request.URL.Path != "/v1/jobs" {
			t.Fatalf("unexpected Nomad registration %s %q", request.Method, request.URL.Path)
		}
		_, _ = w.Write([]byte(`{"EvalID":"eval-wide"}`))
	}))
	beforeStagingHandoffValidationForTest = func(custody *stagingCustody) {
		for index := 0; index < 1024; index++ {
			if err := custody.ensureDirectory(fmt.Sprintf("wide/dir-%04d", index), stableStageDirMode); err != nil {
				t.Fatalf("register wide staging child %d: %v", index, err)
			}
		}
	}
	defer func() { beforeStagingHandoffValidationForTest = nil }()
	result, publicErr := service.Submit(context.Background(), fixture.prepareRequest())
	if publicErr != nil || !result.Submitted || registrations != 1 {
		t.Fatalf("wide tree handoff did not dispatch once: result=%+v err=%+v calls=%d", result, publicErr, registrations)
	}
	if _, err := os.Lstat(filepath.Join(stagingRoot, result.RunID, "wide", "dir-1023")); err != nil {
		t.Fatalf("wide staged tree was not retained: %v", err)
	}
}

func TestResolvedPlanCustodyRepairMountNamesSubmitHandoff(t *testing.T) {
	fixture := newPreparedArtifactFixture(t)
	service, stagingRoot, _ := newWorkstreamCTestService(t, fixture)
	request := fixture.prepareRequest()
	request.Invocation.Mounts = []RuntimeMount{{
		Source:     MountSource{ArtifactDigest: fixture.discovery.Artifact.ArtifactDigest},
		TargetPath: "/execution/mounts/config",
		ReadOnly:   true,
	}}
	archive := buildAdmissionPolicyStaticScriptArchive(t, map[string][]byte{
		staticScriptEntrypointName: []byte(benignPolicyFixtureText()),
		"dir /a":                   []byte("space"),
		"dir/a":                    []byte("plain"),
	})
	service.arsClient = newResolvedPlanDependencyClient(t, resolvedPlanArtifactHandler(t, fixture, archive, nil))
	registrations := 0
	service.nomadClient = newResolvedPlanNomadClient(t, http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		registrations++
		if request.Method != http.MethodPost || request.URL.Path != "/v1/jobs" {
			t.Fatalf("unexpected Nomad registration %s %q", request.Method, request.URL.Path)
		}
		_, _ = w.Write([]byte(`{"EvalID":"eval-mount-names"}`))
	}))
	result, publicErr := service.Submit(context.Background(), request)
	if publicErr != nil || !result.Submitted || registrations != 1 {
		t.Fatalf("mount-name handoff did not dispatch once: result=%+v err=%+v calls=%d", result, publicErr, registrations)
	}
	contents := filepath.Join(stagingRoot, result.RunID, "mounts", "00", "contents")
	assertFileContent(t, filepath.Join(contents, "dir ", "a"), "space")
	assertFileContent(t, filepath.Join(contents, "dir", "a"), "plain")
}

func TestSubmitRejectsRootTopologyDriftBeforeStagingClaimAndNomad(t *testing.T) {
	fixture := newPreparedArtifactFixture(t)
	service, stagingRoot, _ := newWorkstreamCTestService(t, fixture)
	policyPayload := buildAdmissionPolicyStaticScriptArchive(t, map[string][]byte{
		staticScriptEntrypointName: []byte(benignPolicyFixtureText()),
	})
	service.arsClient = newResolvedPlanDependencyClient(t, resolvedPlanArtifactHandler(t, fixture, policyPayload, nil))
	nestedResults := filepath.Join(stagingRoot, "results-overlap")
	if err := os.Mkdir(nestedResults, 0o755); err != nil {
		t.Fatal(err)
	}
	service.cfg.Execution.ResultsRootDir = nestedResults
	nomadCalls := 0
	service.nomadClient = newResolvedPlanNomadClient(t, http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		nomadCalls++
		t.Fatalf("root-topology refusal reached Nomad: %s %s", request.Method, request.URL.Path)
	}))

	result, publicErr := service.Submit(context.Background(), fixture.prepareRequest())
	if publicErr == nil || publicErr.Code != codeSubmissionFailed || publicErr.Message != "claim execution staging root failed" {
		t.Fatalf("unexpected topology-refusal error: %+v", publicErr)
	}
	if result != (SubmitResult{}) || nomadCalls != 0 {
		t.Fatalf("topology refusal produced effects: result=%+v nomad_calls=%d", result, nomadCalls)
	}
	entries, err := os.ReadDir(stagingRoot)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "results-overlap" {
		t.Fatalf("topology refusal claimed a staging run: %v", entries)
	}
}

func TestResolvedSubmitLegacyEquivalencePreservesEnvironmentAndPlatformFields(t *testing.T) {
	owner := executionPlatformStateOwner{UID: os.Getuid(), GID: os.Getgid()}
	run := newRuntimeEnvironmentTestRun(map[string]string{
		"USER_DEFINED": "1",
	}, executionRuntimeProfile{}, stagedWorkloadTrustMaterial{}, owner, esconfig.ResolvedWorkloadVaultAuthPlan{
		Mode:        esconfig.WorkloadVaultAuthModeVaultIdentityJWT,
		Address:     "https://vault.internal:8200",
		AuthMount:   "jwt",
		AuthRole:    "execution",
		JWTAudience: "vault",
	})
	env := run.environment

	if env["USER_DEFINED"] != "1" {
		t.Fatal("expected invocation environment to be preserved")
	}
	if env["EXEC_RUN_ID"] != run.runID {
		t.Fatal("expected run ID injection")
	}
	if env[runtimeIdentityEndpointEnvKey] != run.layout.runtimeIdentity.endpointURI {
		t.Fatal("expected runtime identity endpoint injection")
	}
	if env["EXEC_WORKLOAD_VAULT_AUTH_MODE"] != string(esconfig.WorkloadVaultAuthModeVaultIdentityJWT) {
		t.Fatal("expected workload Vault auth mode injection")
	}
	if env["VAULT_ADDR"] != "https://vault.internal:8200" {
		t.Fatal("expected Vault address injection")
	}
	if env[platformStateOwnerUIDEnvKey] != fmt.Sprintf("%d", os.Getuid()) {
		t.Fatal("expected platform-state owner UID injection")
	}
	if env[platformStateOwnerGIDEnvKey] != fmt.Sprintf("%d", os.Getgid()) {
		t.Fatal("expected platform-state owner GID injection")
	}
	if env[platformStateOwnerSchemaEnvKey] != platformStateOwnerSchemaV1 {
		t.Fatal("expected platform-state owner schema injection")
	}
}

func TestResolvedSubmitLegacyEquivalenceInjectsWorkloadVaultTrustMaterial(t *testing.T) {
	run := newRuntimeEnvironmentTestRun(nil, executionRuntimeProfile{}, stagedWorkloadTrustMaterial{
		vaultCACert:       true,
		workloadTLSBundle: true,
	}, executionPlatformStateOwner{UID: os.Getuid(), GID: os.Getgid()}, esconfig.ResolvedWorkloadVaultAuthPlan{
		Mode:        esconfig.WorkloadVaultAuthModeVaultIdentityJWT,
		Address:     "https://vault.internal:8200",
		AuthMount:   "jwt",
		AuthRole:    "execution",
		JWTAudience: "vault",
	})
	env := run.environment

	if env["VAULT_CACERT"] != "/execution/run/platform/workload-vault-ca.pem" {
		t.Fatal("expected VAULT_CACERT injection")
	}
	if env["SSL_CERT_FILE"] != "/execution/run/platform/workload-ca-bundle.pem" {
		t.Fatal("expected SSL_CERT_FILE injection")
	}
}

func TestResolvedSubmitLegacyEquivalenceInjectsControlPlaneProfileMetadata(t *testing.T) {
	profile := executionRuntimeProfile{
		name: runtimeProfileControlPlaneNormalShell,
		env: map[string]string{
			"EXEC_CODEX_CLI_PATH":                      "/usr/local/bin/codex",
			"EXEC_CODEX_CREDENTIAL_SOURCE":             "workload_vault",
			"EXEC_CODEX_CREDENTIAL_VAULT_SECRET_PATH":  "proof-secrets/data/codex-runtime-profile",
			"EXEC_CODEX_CREDENTIAL_VAULT_SECRET_FIELD": "api_key",
		},
	}
	run := newRuntimeEnvironmentTestRun(nil, profile, stagedWorkloadTrustMaterial{}, executionPlatformStateOwner{UID: os.Getuid(), GID: os.Getgid()}, esconfig.ResolvedWorkloadVaultAuthPlan{
		Mode:        esconfig.WorkloadVaultAuthModeVaultIdentityJWT,
		Address:     "https://vault.internal:8200",
		AuthMount:   "jwt",
		AuthRole:    "execution",
		JWTAudience: "vault",
	})
	env := run.environment

	if env["EXEC_CODEX_CLI_PATH"] != "/usr/local/bin/codex" {
		t.Fatal("expected Codex CLI metadata")
	}
	if env["EXEC_CODEX_CREDENTIAL_SOURCE"] != "workload_vault" {
		t.Fatal("expected credential source metadata")
	}
	if env["EXEC_CODEX_CREDENTIAL_VAULT_SECRET_PATH"] != "proof-secrets/data/codex-runtime-profile" {
		t.Fatal("expected credential secret path metadata")
	}
	if env["EXEC_CODEX_CREDENTIAL_VAULT_SECRET_FIELD"] != "api_key" {
		t.Fatal("expected credential secret field metadata")
	}
}

func TestResolvedSubmitLegacyEquivalenceDefaultProfileJob(t *testing.T) {
	cfg := esconfig.Config{
		Nomad: esconfig.NomadConfig{
			Datacenter: "dc1",
		},
		Execution: esconfig.ExecutionConfig{
			BaseImage:                "alpine:3.20",
			RuntimeIdentityTmpfsSize: 2 << 20,
		},
	}
	cfg.RuntimeConfig.WorkloadZoneVaultConfigRef.Digest = testWorkloadZoneVaultConfigDigest
	stage := stagedExecutionInputs{
		layout: executionPackageLayout{
			payloadStageDir:    "/tmp/stage/payload",
			runStageDir:        "/tmp/stage/run",
			runtimePayloadRoot: executionRuntimePayloadRoot,
			runtimeRunRoot:     executionRuntimeRunRoot,
			runtimeWorkDir:     executionRuntimeWorkDir,
			runtimeResultDir:   executionRuntimeResultDir,
			runtimeEntrypoint:  executionRuntimeEntrypointPath,
			runtimeIdentity: runtimeIdentityHandoff{
				endpointURI: "unix:///run/es-runtime-identity/run-0123456789abcdef/public.sock",
			},
		},
	}

	jobSpec := buildNomadJobSpec(resolvedNomadJobProjection{
		jobID:          "exec-run-0123456789abcdef",
		runID:          "run-0123456789abcdef",
		layout:         stage.layout,
		runtimeCommand: newResolvedRuntimeCommand([]string{"--flag"}, 17),
		runtimeImage:   "alpine:3.20",
		environment:    map[string]string{"EXEC_RUN_ID": "run-0123456789abcdef"},
		networkMode:    "bridge",
		resources:      resolvedTaskResources{cpu: defaultSubmitCPU, memoryMB: defaultSubmitMemoryMB},
		runtimeMountInputs: resolvedRuntimeMountInputs{
			identityTmpfsSize: cfg.Execution.EffectiveRuntimeIdentityTmpfsSize(),
		},
		jobEnvelope: defaultResolvedJobEnvelope(),
		datacenters: []string{"dc1"},
		authorityMetadata: executionAuthorityMetadataProjection{
			runtimeProfileName:            runtimeProfileDefaultStaticScript,
			workloadZoneVaultConfigDigest: testWorkloadZoneVaultConfigDigest,
		},
	})

	job, ok := jobSpec["Job"].(map[string]any)
	if !ok {
		t.Fatal("expected top-level Nomad Job map")
	}
	meta, ok := job["Meta"].(map[string]any)
	if !ok || meta["run_id"] != "run-0123456789abcdef" {
		t.Fatal("expected run_id metadata in job spec")
	}
	if meta[executionAuthorityMetadataSchemaKey] != executionAuthorityMetadataSchemaVersion ||
		meta[executionAuthorityMetadataRuntimeProfileKey] != runtimeProfileDefaultStaticScript ||
		meta[executionAuthorityMetadataWorkloadZoneVaultConfigKey] != testWorkloadZoneVaultConfigDigest {
		t.Fatal("expected authority handoff metadata in job spec")
	}

	taskGroups, ok := job["TaskGroups"].([]any)
	if !ok || len(taskGroups) != 1 {
		t.Fatal("expected a single task group")
	}
	group, ok := taskGroups[0].(map[string]any)
	if !ok {
		t.Fatal("expected task group map")
	}
	tasks, ok := group["Tasks"].([]any)
	if !ok || len(tasks) != 1 {
		t.Fatal("expected a single task")
	}
	task, ok := tasks[0].(map[string]any)
	if !ok {
		t.Fatal("expected task map")
	}
	config, ok := task["Config"].(map[string]any)
	if !ok {
		t.Fatal("expected task config map")
	}
	if config["network_mode"] != "bridge" {
		t.Fatal("expected network access to select bridge mode")
	}
	if config["command"] != executionRuntimeSupportPath {
		t.Fatal("expected runtime-support command")
	}
	if config["image"] != "alpine:3.20" {
		t.Fatal("expected default runtime image")
	}
}

func TestResolvedSubmitLegacyEquivalenceUsesSelectedRuntimeProfileImage(t *testing.T) {
	cfg := esconfig.Config{
		Nomad: esconfig.NomadConfig{
			Datacenter: "dc1",
		},
	}
	stage := stagedExecutionInputs{
		layout: executionPackageLayout{
			payloadStageDir:    "/tmp/stage/payload",
			runStageDir:        "/tmp/stage/run",
			runtimePayloadRoot: executionRuntimePayloadRoot,
			runtimeRunRoot:     executionRuntimeRunRoot,
			runtimeWorkDir:     executionRuntimeWorkDir,
			runtimeResultDir:   executionRuntimeResultDir,
			runtimeEntrypoint:  executionRuntimeEntrypointPath,
			runtimeIdentity: runtimeIdentityHandoff{
				endpointURI: "unix:///run/es-runtime-identity/run-0123456789abcdef/public.sock",
			},
		},
	}

	profileEnvironment := map[string]string{
		codexCLIPathEnvKey:                    "/usr/local/bin/codex",
		codexCredentialSourceEnvKey:           codexCredentialSourceWorkloadVault,
		codexCredentialVaultSecretPathEnvKey:  "proof-secrets/data/codex-runtime-profile",
		codexCredentialVaultSecretFieldEnvKey: "api_key",
	}
	jobSpec := buildNomadJobSpec(resolvedNomadJobProjection{
		jobID:          "exec-run-0123456789abcdef",
		runID:          "run-0123456789abcdef",
		layout:         stage.layout,
		runtimeCommand: newResolvedRuntimeCommand(nil, 0),
		runtimeImage:   "execution-substrate/control-plane-normal-shell:test",
		environment:    copyStringMap(profileEnvironment),
		networkMode:    "bridge",
		resources:      resolvedTaskResources{cpu: defaultSubmitCPU, memoryMB: defaultSubmitMemoryMB},
		runtimeMountInputs: resolvedRuntimeMountInputs{
			identityTmpfsSize: cfg.Execution.EffectiveRuntimeIdentityTmpfsSize(),
		},
		jobEnvelope: defaultResolvedJobEnvelope(),
		datacenters: []string{"dc1"},
		authorityMetadata: executionAuthorityMetadataProjection{
			runtimeProfileName:            runtimeProfileControlPlaneNormalShell,
			workloadZoneVaultConfigDigest: testWorkloadZoneVaultConfigDigest,
		},
	})

	job := jobSpec["Job"].(map[string]any)
	metadata := job["Meta"].(map[string]any)
	taskGroups := job["TaskGroups"].([]any)
	group := taskGroups[0].(map[string]any)
	tasks := group["Tasks"].([]any)
	task := tasks[0].(map[string]any)
	config := task["Config"].(map[string]any)
	environment := task["Env"].(map[string]string)
	if metadata[executionAuthorityMetadataRuntimeProfileKey] != runtimeProfileControlPlaneNormalShell || config["image"] != "execution-substrate/control-plane-normal-shell:test" {
		t.Fatal("control-plane job fixture lost the selected profile or image")
	}
	if task["Driver"] != "docker" || task["User"] != "0:0" || config["command"] != executionRuntimeSupportPath || config["privileged"] != false || config["network_mode"] != "bridge" {
		t.Fatal("control-plane job fixture changed runtime or security selection")
	}
	securityOptions := config["security_opt"].([]string)
	if len(securityOptions) != 1 || securityOptions[0] != "no-new-privileges" || environment[codexCLIPathEnvKey] != "/usr/local/bin/codex" || environment[codexCredentialSourceEnvKey] != codexCredentialSourceWorkloadVault {
		t.Fatal("control-plane job fixture changed security options or profile environment")
	}
}

func TestResolvedSubmitLegacyEquivalenceKeepsRawSPIREPathHelperPrivate(t *testing.T) {
	cfg := esconfig.Config{
		Nomad: esconfig.NomadConfig{
			Datacenter: "dc1",
		},
		Execution: esconfig.ExecutionConfig{
			BaseImage:                  "alpine:3.20",
			SPIREWorkloadAPISocketPath: "/run/spire/sockets/agent.sock",
		},
	}
	stage := stagedExecutionInputs{
		layout: executionPackageLayout{
			payloadStageDir:    "/tmp/stage/payload",
			runStageDir:        "/tmp/stage/run",
			runtimePayloadRoot: executionRuntimePayloadRoot,
			runtimeRunRoot:     executionRuntimeRunRoot,
			runtimeWorkDir:     executionRuntimeWorkDir,
			runtimeResultDir:   executionRuntimeResultDir,
			runtimeEntrypoint:  executionRuntimeEntrypointPath,
			runtimeIdentity: runtimeIdentityHandoff{
				endpointEnvKey: runtimeIdentityEndpointEnvKey,
				endpointURI:    "unix:///run/es-runtime-identity/run-0123456789abcdef/public.sock",
			},
		},
	}
	run := newRuntimeEnvironmentTestRun(nil, executionRuntimeProfile{}, stagedWorkloadTrustMaterial{}, executionPlatformStateOwner{UID: os.Getuid(), GID: os.Getgid()}, esconfig.ResolvedWorkloadVaultAuthPlan{
		Mode:        esconfig.WorkloadVaultAuthModeVaultIdentityJWT,
		Address:     "https://vault.internal:8200",
		AuthMount:   "jwt",
		AuthRole:    "execution",
		JWTAudience: "vault",
	})
	env := run.environment

	jobSpec := buildNomadJobSpec(resolvedNomadJobProjection{
		jobID:          "exec-run-0123456789abcdef",
		runID:          "run-0123456789abcdef",
		layout:         stage.layout,
		runtimeCommand: newResolvedRuntimeCommand(nil, 0),
		runtimeImage:   "alpine:3.20",
		environment:    copyStringMap(env),
		networkMode:    "bridge",
		resources:      resolvedTaskResources{cpu: defaultSubmitCPU, memoryMB: defaultSubmitMemoryMB},
		runtimeMountInputs: resolvedRuntimeMountInputs{
			identityTmpfsSize: cfg.Execution.EffectiveRuntimeIdentityTmpfsSize(),
			spireSourceDir:    path.Dir(cfg.Execution.SPIREWorkloadAPISocketPath),
		},
		jobEnvelope: defaultResolvedJobEnvelope(),
		datacenters: []string{"dc1"},
		authorityMetadata: executionAuthorityMetadataProjection{
			runtimeProfileName:            runtimeProfileDefaultStaticScript,
			workloadZoneVaultConfigDigest: testWorkloadZoneVaultConfigDigest,
		},
	})

	job := jobSpec["Job"].(map[string]any)
	taskGroups := job["TaskGroups"].([]any)
	group := taskGroups[0].(map[string]any)
	tasks := group["Tasks"].([]any)
	task := tasks[0].(map[string]any)
	taskEnv := task["Env"].(map[string]string)
	for key, value := range taskEnv {
		if strings.Contains(value, cfg.Execution.SPIREWorkloadAPISocketPath) {
			t.Fatalf("workload environment key %q exposed the raw SPIRE path", key)
		}
		if strings.Contains(value, runtimeIdentitySPIRESocketName) {
			t.Fatalf("workload environment key %q exposed the helper-private SPIRE alias", key)
		}
	}

	config := task["Config"].(map[string]any)
	mounts := config["mounts"].([]any)
	spireMount := mounts[3].(map[string]any)
	if spireMount["source"] != path.Dir(cfg.Execution.SPIREWorkloadAPISocketPath) {
		t.Fatal("expected raw SPIRE source-directory mount")
	}
	if spireMount["target"] != path.Join(stage.layout.runtimeIdentity.internalDir(), runtimeIdentitySPIRESourceDir) {
		t.Fatal("expected helper-private SPIRE mount target")
	}
}

func newRuntimeEnvironmentTestRun(invocationEnvironment map[string]string, runtimeProfile executionRuntimeProfile, trust stagedWorkloadTrustMaterial, owner executionPlatformStateOwner, vaultPlan esconfig.ResolvedWorkloadVaultAuthPlan) resolvedRunProjection {
	profile := resolvedRuntimeProfile{
		name:  runtimeProfile.name,
		image: runtimeProfile.image,
	}
	vault := resolvedWorkloadVaultPlan{
		mode:        string(vaultPlan.Mode),
		address:     vaultPlan.Address,
		authMount:   vaultPlan.AuthMount,
		authRole:    vaultPlan.AuthRole,
		jwtAudience: vaultPlan.JWTAudience,
	}
	plan := newResolvedExecutionPlan(resolvedPlanFacts{
		runtimeProfile: profile,
		artifactDigest: "sha256:artifact",
		semanticEnvironment: resolvedSemanticRuntimeEnvironment(
			invocationEnvironment,
			runtimeProfile.env,
			"sha256:artifact",
			vault,
			trust,
		),
		authority: resolvedAuthorityPlan{
			runtimeProfileName: profile.name,
			codexCredential:    resolveCodexCredentialLocation(runtimeProfile.env),
			workloadVault:      vault,
			trustMaterial:      trust,
		},
	})
	host := newHostMaterializationContext("/tmp/es-stage", "/tmp/es-results", owner, "/run/spire/sockets", "dc1")
	return newResolvedRunProjection(plan, host, newExecutionLocatorFromRunID("run-0123456789abcdef"))
}
