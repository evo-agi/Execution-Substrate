package admission

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	esconfig "execution-substrate/es/config"
)

func testWorkloadGrantFacts() workloadGrantFacts {
	return workloadGrantFacts{
		evidence: workloadGrantEvidenceFacts{
			publisherPrincipal: "spiffe://execution.internal/operator/local",
			signerKeyID:        "ags-artifact-signer",
		},
		artifactType:            "static-script",
		runtimeProfile:          runtimeProfileDefaultStaticScript,
		runtimeProfileSupported: true,
		networkAccess:           true,
	}
}

func testWorkloadGrants(egressLane string) workloadGrants {
	return workloadGrants{rules: []workloadGrantRule{
		{id: "other", match: [4]string{"spiffe://execution.internal/service/control-plane", "ags-artifact-signer", "static-script", runtimeProfileDefaultStaticScript}, egressLane: esconfig.WorkloadEgressLaneUnrestricted},
		{id: "operator-default", match: testWorkloadGrantFacts().matchKey(), egressLane: egressLane},
	}}
}

func assertNetworkAccessNotGranted(t *testing.T, err *Error) {
	t.Helper()
	if err == nil || err.Status != http.StatusForbidden || err.Code != codeNetworkAccessNotGranted ||
		err.Message != "network access not granted by admission policy" {
		t.Fatalf("error = %+v, want 403 %s with the fixed message", err, codeNetworkAccessNotGranted)
	}
}

func TestWorkloadGrantDecisionFollowsTheNetworkGrantPolicy(t *testing.T) {
	if networkGrantPolicyID != "execution-substrate.admission.network-grant/v1" || codeNetworkAccessNotGranted != "network_access_not_granted" {
		t.Fatalf("policy ID %q and reason code %q differ from the contract", networkGrantPolicyID, codeNetworkAccessNotGranted)
	}
	unrestricted := esconfig.WorkloadEgressLaneUnrestricted

	t.Run("a matching rule with a lane gives the network", func(t *testing.T) {
		decision, err := testWorkloadGrants(unrestricted).decide(testWorkloadGrantFacts())
		if err != nil || decision != (workloadGrantDecision{ruleID: "operator-default", egressLane: unrestricted}) {
			t.Fatalf("decision = %+v, %+v", decision, err)
		}
	})
	t.Run("a run that requests no network gets none, with or without a rule", func(t *testing.T) {
		facts := testWorkloadGrantFacts()
		facts.networkAccess = false
		decision, err := testWorkloadGrants(unrestricted).decide(facts)
		if err != nil || decision != (workloadGrantDecision{ruleID: "operator-default"}) {
			t.Fatalf("decision with a rule = %+v, %+v", decision, err)
		}
		decision, err = workloadGrants{}.decide(facts)
		if err != nil || decision != (workloadGrantDecision{}) {
			t.Fatalf("decision without rules = %+v, %+v", decision, err)
		}
	})
	t.Run("a network run without a matching rule is refused", func(t *testing.T) {
		decision, err := workloadGrants{}.decide(testWorkloadGrantFacts())
		assertNetworkAccessNotGranted(t, err)
		if decision != (workloadGrantDecision{}) {
			t.Fatalf("a refused run carries decision %+v", decision)
		}
	})
	t.Run("a network run whose rule grants no lane is refused", func(t *testing.T) {
		_, err := testWorkloadGrants("").decide(testWorkloadGrantFacts())
		assertNetworkAccessNotGranted(t, err)
	})
	t.Run("matching is byte for byte on each of the four facts", func(t *testing.T) {
		for name, change := range map[string]func(*workloadGrantFacts){
			"publisher": func(f *workloadGrantFacts) {
				f.evidence.publisherPrincipal = "spiffe://execution.internal/operator/other"
			},
			"publisher case": func(f *workloadGrantFacts) {
				f.evidence.publisherPrincipal = "spiffe://execution.internal/Operator/local"
			},
			"publisher prefix": func(f *workloadGrantFacts) { f.evidence.publisherPrincipal = "spiffe://execution.internal/operator" },
			"publisher longer": func(f *workloadGrantFacts) {
				f.evidence.publisherPrincipal = "spiffe://execution.internal/operator/local/x"
			},
			"signer":            func(f *workloadGrantFacts) { f.evidence.signerKeyID = "other-signer" },
			"signer padded":     func(f *workloadGrantFacts) { f.evidence.signerKeyID = "ags-artifact-signer " },
			"artifact type":     func(f *workloadGrantFacts) { f.artifactType = "Static-Script" },
			"runtime profile":   func(f *workloadGrantFacts) { f.runtimeProfile = runtimeProfileControlPlaneNormalShell },
			"empty publisher":   func(f *workloadGrantFacts) { f.evidence.publisherPrincipal = "" },
			"invisible in type": func(f *workloadGrantFacts) { f.artifactType = "static​-script" },
			"publisher and signer": func(f *workloadGrantFacts) {
				f.evidence.publisherPrincipal, f.evidence.signerKeyID = "ags-artifact-signer", f.evidence.publisherPrincipal
			},
		} {
			facts := testWorkloadGrantFacts()
			change(&facts)
			if _, err := testWorkloadGrants(unrestricted).decide(facts); err == nil || err.Code != codeNetworkAccessNotGranted {
				t.Errorf("%s: decide = %+v, want a refusal", name, err)
			}
		}
	})
	t.Run("a profile ES does not support is left to the runtime-profile gate", func(t *testing.T) {
		facts := testWorkloadGrantFacts()
		facts.runtimeProfile, facts.runtimeProfileSupported = "unsupported/v1", false
		decision, err := workloadGrants{}.decide(facts)
		if err != nil || decision != (workloadGrantDecision{}) {
			t.Fatalf("decision = %+v, %+v", decision, err)
		}
	})
}

// The configuration builds a rule's key in the order admission builds a
// run's key, so a rule written for a run matches it and a rule with two
// facts swapped does not.
func TestWorkloadGrantRuleKeysAgreeWithRunFacts(t *testing.T) {
	facts := testWorkloadGrantFacts()
	rule := esconfig.WorkloadGrantRuleConfig{
		ID:                 "operator-default",
		PublisherPrincipal: facts.evidence.publisherPrincipal,
		SignerKeyID:        facts.evidence.signerKeyID,
		ArtifactType:       facts.artifactType,
		RuntimeProfile:     facts.runtimeProfile,
		EgressLane:         esconfig.WorkloadEgressLaneUnrestricted,
	}
	cfg := &esconfig.AdmissionPolicyConfig{WorkloadGrants: &esconfig.WorkloadGrantsConfig{Rules: []esconfig.WorkloadGrantRuleConfig{rule}}}
	decision, err := workloadGrantsFromConfig(cfg).decide(facts)
	if err != nil || decision.ruleID != "operator-default" || decision.egressLane != esconfig.WorkloadEgressLaneUnrestricted {
		t.Fatalf("decision = %+v, %+v", decision, err)
	}
	swapped := rule
	swapped.ArtifactType, swapped.RuntimeProfile = rule.RuntimeProfile, rule.ArtifactType
	cfg.WorkloadGrants.Rules = []esconfig.WorkloadGrantRuleConfig{swapped}
	if _, err := workloadGrantsFromConfig(cfg).decide(facts); err == nil {
		t.Fatal("a rule with two facts swapped matched")
	}
	if got := workloadGrantsFromConfig(nil); len(got.rules) != 0 {
		t.Fatalf("no configuration gave rules %+v", got.rules)
	}
	if got := workloadGrantsFromConfig(&esconfig.AdmissionPolicyConfig{}); len(got.rules) != 0 {
		t.Fatalf("no grants gave rules %+v", got.rules)
	}
}

// The names a rule may give as runtime_profile are the names admission
// matches on, and the profile names admission reports as supported are
// exactly those the runtime-profile gate resolves.
func TestWorkloadGrantRuntimeProfileAgreesWithTheRuntimeProfileGate(t *testing.T) {
	if esconfig.WorkloadGrantRuntimeProfileDefault != runtimeProfileDefaultStaticScript ||
		esconfig.WorkloadGrantRuntimeProfileControlPlaneNormalShell != runtimeProfileControlPlaneNormalShell {
		t.Fatalf("config profile names %q and %q differ from admission's %q and %q",
			esconfig.WorkloadGrantRuntimeProfileDefault, esconfig.WorkloadGrantRuntimeProfileControlPlaneNormalShell,
			runtimeProfileDefaultStaticScript, runtimeProfileControlPlaneNormalShell)
	}
	execution := esconfig.ExecutionConfig{BaseImage: "alpine:3.20"}
	execution.RuntimeProfiles.ControlPlaneNormalShell.Enabled = true
	artifact := preparedArtifact{manifest: Manifest{ArtifactType: "static-script"}, networkAccess: true}
	for _, requested := range []string{
		"", " ", runtimeProfileControlPlaneNormalShell, " " + runtimeProfileControlPlaneNormalShell + "\t",
		runtimeProfileDefaultStaticScript, "unsupported/v1", "Control-Plane-Normal-Shell/v1",
	} {
		req := PrepareRequest{Invocation: ArtifactInvocation{Annotations: map[string]string{runtimeProfileAnnotationKey: requested}}}
		name, supported := workloadGrantRuntimeProfile(req)
		resolved, err := resolveExecutionRuntimeProfile(execution, req, artifact)
		if supported != (err == nil) {
			t.Errorf("profile %q: grants report supported=%t, the gate reports %+v", requested, supported, err)
		}
		if supported && name != resolved.name {
			t.Errorf("profile %q: grants match on %q, the gate resolves %q", requested, name, resolved.name)
		}
	}
	if name, supported := workloadGrantRuntimeProfile(PrepareRequest{}); !supported || name != runtimeProfileDefaultStaticScript {
		t.Fatalf("a request without annotations matches on %q (%t)", name, supported)
	}
}

// workloadGrantsTestService is the shared test service with the grants it
// was built with replaced.
func workloadGrantsTestService(t *testing.T, fixture preparedArtifactFixture, grants *esconfig.WorkloadGrantsConfig) (*Service, string, string) {
	t.Helper()
	service, stagingRoot, resultsRoot := newWorkstreamCTestService(t, fixture)
	if grants == nil {
		service.cfg.AdmissionPolicy = nil
	} else {
		service.cfg.AdmissionPolicy = &esconfig.AdmissionPolicyConfig{WorkloadGrants: grants}
	}
	return service, stagingRoot, resultsRoot
}

func TestNetworkRunWithoutAGrantIsRefusedOnPrepareAndSubmitBeforeAnyEffect(t *testing.T) {
	fixture, payload := signedStaticScriptFixture(t)
	reaches := true
	noLane := &esconfig.WorkloadGrantsConfig{
		EgressLanes: []esconfig.WorkloadEgressLaneConfig{{Name: esconfig.WorkloadEgressLaneUnrestricted, ReachesWorkloadVault: &reaches}},
		Rules: []esconfig.WorkloadGrantRuleConfig{{
			ID:                 "no-network",
			PublisherPrincipal: fixture.evidence.Claims.Package.Publication.Invoker.Principal,
			SignerKeyID:        fixture.keyID,
			ArtifactType:       "static-script",
			RuntimeProfile:     runtimeProfileDefaultStaticScript,
		}},
	}
	other := esconfig.Config{}
	grantNetworkTo(&other, "spiffe://execution.internal/service/control-plane", fixture.keyID, "static-script")

	for name, grants := range map[string]*esconfig.WorkloadGrantsConfig{
		"no grants":              nil,
		"a rule without a lane":  noLane,
		"a rule for another run": other.AdmissionPolicy.WorkloadGrants,
	} {
		for _, operation := range []string{"prepare", "submit"} {
			t.Run(name+"/"+operation, func(t *testing.T) {
				service, stagingRoot, resultsRoot := workloadGrantsTestService(t, fixture, grants)
				handler := newSignedPayloadHandler(t, fixture, payload)
				service.arsClient = newResolvedPlanDependencyClient(t, handler)
				nomad := &nomadRegistrationLog{}
				service.nomadClient = newCountingNomadClient(t, nomad)
				request := fixture.prepareRequest()
				var err *Error
				if operation == "submit" {
					request.Mode = ExecutionModeAsync
					var result SubmitResult
					result, err = service.Submit(context.Background(), request)
					if result.Submitted || result.RunID != "" {
						t.Fatalf("a refused run got receipt %+v", result)
					}
				} else {
					var result PrepareResult
					result, err = service.Prepare(context.Background(), request)
					if result.Success {
						t.Fatalf("a refused run prepared: %+v", result)
					}
				}
				assertNetworkAccessNotGranted(t, err)
				// The grant policies run before the content policies, so a
				// refused run fetches no payload.
				if reads := handler.log.count("/v1/blobs/" + fixture.discovery.Payload.Digest + ":bytes"); reads != 0 {
					t.Fatalf("a refused run read its payload %d times", reads)
				}
				assertNoRunEffects(t, nomad, stagingRoot, resultsRoot)
			})
		}
	}
}

func TestNetworkRunWithAGrantIsAdmittedOnPrepareAndSubmit(t *testing.T) {
	fixture, payload := signedStaticScriptFixture(t)
	granted := esconfig.Config{}
	grantFixtureNetwork(&granted, fixture)
	service, stagingRoot, _ := workloadGrantsTestService(t, fixture, granted.AdmissionPolicy.WorkloadGrants)
	service.arsClient = newResolvedPlanDependencyClient(t, newSignedPayloadHandler(t, fixture, payload))
	nomad := &nomadRegistrationLog{}
	service.nomadClient = newCountingNomadClient(t, nomad)

	prepared, err := service.Prepare(context.Background(), fixture.prepareRequest())
	if err != nil || !prepared.Success {
		t.Fatalf("prepare = %+v, %+v", prepared, err)
	}
	request := fixture.prepareRequest()
	request.Mode = ExecutionModeAsync
	result, err := service.Submit(context.Background(), request)
	if err != nil || !result.Submitted || nomad.count() != 1 {
		t.Fatalf("submit = %+v, %+v, nomad=%d", result, err, nomad.count())
	}
	if _, statErr := os.Stat(filepath.Join(stagingRoot, result.RunID)); statErr != nil {
		t.Fatalf("admitted run was not staged: %v", statErr)
	}

	// Every delivery that can cause an effect reads the grants ES runs with
	// at that time: a grant removed after :prepare refuses the next :submit.
	service.cfg.AdmissionPolicy = nil
	_, err = service.Submit(context.Background(), request)
	assertNetworkAccessNotGranted(t, err)
	if nomad.count() != 1 {
		t.Fatalf("a submit after the grant was removed reached Nomad: %d registrations", nomad.count())
	}
}

func TestRunWithoutNetworkNeedsNoGrant(t *testing.T) {
	fixture := newPreparedArtifactFixture(t)
	fixture.evidence.Claims.Admission.Execution.Access.NetworkAccess = false
	payload := buildAdmissionPolicyStaticScriptArchive(t, map[string][]byte{
		staticScriptEntrypointName: []byte(benignPolicyFixtureText()),
	})
	fixture = fixture.withPayload(t, payload)
	service, _, _ := workloadGrantsTestService(t, fixture, nil)
	service.arsClient = newResolvedPlanDependencyClient(t, newSignedPayloadHandler(t, fixture, payload))
	nomad := &nomadRegistrationLog{}
	service.nomadClient = newCountingNomadClient(t, nomad)

	if prepared, err := service.Prepare(context.Background(), fixture.prepareRequest()); err != nil || !prepared.Success {
		t.Fatalf("prepare = %+v, %+v", prepared, err)
	}
	request := fixture.prepareRequest()
	request.Mode = ExecutionModeAsync
	if result, err := service.Submit(context.Background(), request); err != nil || !result.Submitted || nomad.count() != 1 {
		t.Fatalf("submit = %+v, %+v, nomad=%d", result, err, nomad.count())
	}
}

// The reliable operational path admits only runs that request no network,
// which no grant refuses, so grants take no part in its commissioned
// content: adding or removing grants leaves that content and its digest as
// they were.
func TestWorkloadGrantsLeaveTheOperationalAdmissionContentUnchanged(t *testing.T) {
	fixture := newPreparedArtifactFixture(t)
	service, _, _ := workloadGrantsTestService(t, fixture, nil)
	service.trustModelVerified = true
	service.trustModelOwner = service
	content := func() ([32]byte, bool) {
		service.mu.Lock()
		defer service.mu.Unlock()
		_, digest, ok := service.operationalAdmissionContent()
		return digest, ok
	}
	without, ok := content()
	if !ok {
		t.Fatal("control: the service without grants cannot be commissioned")
	}
	grantFixtureNetwork(&service.cfg, fixture)
	with, ok := content()
	if !ok || with != without {
		t.Fatalf("grants changed the operational content: ok=%t", ok)
	}
}

// Grant code decides in grant terms only: runtime realization alone maps a
// lane or an identity name to scheduler and container values.
func TestWorkloadGrantCodeNamesNoSchedulerOrContainerTerm(t *testing.T) {
	for _, file := range []string{"workload_grants.go", filepath.Join("..", "config", "workload_grants.go")} {
		data, err := os.ReadFile(file)
		if err != nil {
			t.Fatalf("read %s: %v", file, err)
		}
		text := strings.ToLower(string(data))
		for _, term := range []string{"nomad", "docker", "bridge", "network_mode", "networkmode", "execution-substrate.workload-identity"} {
			if strings.Contains(text, term) {
				t.Errorf("%s names %q", file, term)
			}
		}
	}
}
