package admission

import (
	"context"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"

	"execution-substrate/es/admission/internal/grantcaller"
	esconfig "execution-substrate/es/config"
	"execution-substrate/internal/callerauth"
)

func testWorkloadGrantFacts() workloadGrantFacts {
	return workloadGrantFacts{
		evidence: workloadGrantEvidenceFacts{
			publisherPrincipal: "spiffe://execution.internal/operator/local",
			signerKeyID:        "ags-artifact-signer",
		},
		caller:         grantCaller(testGrantCaller),
		artifactType:   "static-script",
		runtimeProfile: runtimeProfileDefaultStaticScript,
		networkAccess:  true,
	}
}

func testWorkloadGrants(egressLane string) workloadGrants {
	return workloadGrants{rules: []workloadGrantRule{
		{id: "other", match: [5]string{"spiffe://execution.internal/service/control-plane", "spiffe://execution.internal/service/control-plane", "ags-artifact-signer", "static-script", runtimeProfileDefaultStaticScript}, egressLane: esconfig.WorkloadEgressLaneUnrestricted},
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
	t.Run("matching is byte for byte on each of the five facts", func(t *testing.T) {
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
			"caller": func(f *workloadGrantFacts) {
				f.caller = grantCaller("spiffe://execution.internal/service/control-plane")
			},
			"caller sub-path": func(f *workloadGrantFacts) { f.caller = grantCaller(testGrantCaller + "/x") },
			"caller case":     func(f *workloadGrantFacts) { f.caller = grantCaller("spiffe://execution.internal/Operator/local") },
			"no caller":       func(f *workloadGrantFacts) { f.caller = grantcaller.Caller{} },
			"publisher and caller": func(f *workloadGrantFacts) {
				f.evidence.publisherPrincipal, f.caller = "spiffe://execution.internal/service/control-plane", grantCaller("spiffe://execution.internal/operator/local")
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
}

// The configuration builds a rule's key in the order admission builds a
// run's key, so a rule written for a run matches it and a rule with two
// facts swapped does not.
func TestWorkloadGrantRuleKeysAgreeWithRunFacts(t *testing.T) {
	facts := testWorkloadGrantFacts()
	rule := esconfig.WorkloadGrantRuleConfig{
		ID:                 "operator-default",
		PublisherPrincipal: facts.evidence.publisherPrincipal,
		CallerPrincipal:    facts.caller.Principal(),
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

// The grant decision takes the effective runtime profile from the
// runtime-profile gate, so every profile the gate resolves gets a grant
// decision on that name, and a request the gate refuses gets the gate's own
// refusal. The candidate names come from the source, every string literal of
// the package's production files, so a profile name added to the gate later
// is among them. (Red-team of ES PR #73, RT73-2: a separate list of profile
// names in the grant code would let a profile added to the gate alone run
// with the network and no grant.)
func TestEveryRuntimeProfileTheGateResolvesHasAGrantDecision(t *testing.T) {
	if esconfig.WorkloadGrantRuntimeProfileDefault != runtimeProfileDefaultStaticScript ||
		esconfig.WorkloadGrantRuntimeProfileControlPlaneNormalShell != runtimeProfileControlPlaneNormalShell {
		t.Fatalf("config profile names %q and %q differ from admission's %q and %q",
			esconfig.WorkloadGrantRuntimeProfileDefault, esconfig.WorkloadGrantRuntimeProfileControlPlaneNormalShell,
			runtimeProfileDefaultStaticScript, runtimeProfileControlPlaneNormalShell)
	}
	candidates := map[string]struct{}{"": {}, " " + runtimeProfileControlPlaneNormalShell + "\t": {}, "Control-Plane-Normal-Shell/v1": {}}
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	production := 0
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		parsed, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		production++
		ast.Inspect(parsed, func(node ast.Node) bool {
			if literal, ok := node.(*ast.BasicLit); ok && literal.Kind == token.STRING {
				if value, err := strconv.Unquote(literal.Value); err == nil {
					candidates[value] = struct{}{}
				}
			}
			return true
		})
	}
	if production < 10 || len(candidates) < 100 {
		t.Fatalf("read %d production files and %d string literals: the scan no longer sees the package", production, len(candidates))
	}
	for _, mustSee := range []string{runtimeProfileControlPlaneNormalShell, runtimeProfileDefaultStaticScript} {
		if _, ok := candidates[mustSee]; !ok {
			t.Fatalf("the scan does not see the profile name %q", mustSee)
		}
	}

	const publisher, signer = "spiffe://execution.internal/operator/local", "ags-artifact-signer"
	resolvedWithNetwork := 0
	for _, enabled := range []bool{true, false} {
		for _, artifactType := range []string{"static-script", "archive"} {
			for _, network := range []bool{true, false} {
				execution := esconfig.ExecutionConfig{BaseImage: "alpine:3.20"}
				execution.RuntimeProfiles.ControlPlaneNormalShell.Enabled = enabled
				artifact := preparedArtifact{
					manifest:      Manifest{ArtifactType: artifactType},
					networkAccess: network,
					grantFacts:    workloadGrantEvidenceFacts{publisherPrincipal: publisher, signerKeyID: signer},
				}
				for candidate := range candidates {
					req := PrepareRequest{Invocation: ArtifactInvocation{Annotations: map[string]string{runtimeProfileAnnotationKey: candidate}}}
					ungranted := &Service{cfg: esconfig.Config{Execution: execution}}
					decision, grantErr := ungranted.decideWorkloadGrants(testCallerContext(), req, artifact)
					resolved, resolveErr := resolveExecutionRuntimeProfile(execution, req, artifact)
					if resolveErr != nil {
						// The gate refuses: no grant decision, and the
						// grant step returns the gate's own 400.
						if grantErr == nil || *grantErr != *resolveErr || decision != (workloadGrantDecision{}) || resolveErr.Code != codeUnsupportedRuntimeProfile {
							t.Errorf("profile %q (enabled=%t, %s, network=%t): grant decision %+v, %+v; gate %+v",
								candidate, enabled, artifactType, network, decision, grantErr, resolveErr)
						}
						continue
					}
					if !network {
						if grantErr != nil {
							t.Errorf("profile %q: a run without network was refused: %+v", candidate, grantErr)
						}
						continue
					}
					resolvedWithNetwork++
					if grantErr == nil || grantErr.Code != codeNetworkAccessNotGranted {
						t.Errorf("profile %q resolves to %q and a network run without a grant gets %+v: it would get the network without a grant",
							candidate, resolved.name, grantErr)
					}
					granted := &Service{cfg: esconfig.Config{Execution: execution}}
					grantNetworkTo(&granted.cfg, publisher, signer, artifactType)
					for i := range granted.cfg.AdmissionPolicy.WorkloadGrants.Rules {
						granted.cfg.AdmissionPolicy.WorkloadGrants.Rules[i].RuntimeProfile = resolved.name
						granted.cfg.AdmissionPolicy.WorkloadGrants.Rules[i].ID = "rule-" + strconv.Itoa(i)
					}
					granted.cfg.AdmissionPolicy.WorkloadGrants.Rules = granted.cfg.AdmissionPolicy.WorkloadGrants.Rules[:1]
					if decision, err := granted.decideWorkloadGrants(testCallerContext(), req, artifact); err != nil || decision.egressLane != esconfig.WorkloadEgressLaneUnrestricted {
						t.Errorf("profile %q: a grant on the resolved name %q gave %+v, %+v", candidate, resolved.name, decision, err)
					}
				}
			}
		}
	}
	if resolvedWithNetwork == 0 {
		t.Fatal("no candidate resolved for a network run: the test no longer exercises the gate")
	}
}

// A request the runtime-profile gate refuses gets the gate's
// 400 unsupported_runtime_profile on :prepare and :submit, with or without a
// grant, as it does without grants: the grant policies do not answer for a
// profile selection ES refuses (audit 10, F5).
func TestARequestTheRuntimeProfileGateRefusesGetsItsRefusalNotAGrantDenial(t *testing.T) {
	fixture, payload := signedStaticScriptFixture(t)
	granted := esconfig.Config{}
	grantFixtureNetwork(&granted, fixture)
	for name, grants := range map[string]*esconfig.WorkloadGrantsConfig{
		"no grants":  nil,
		"with grant": granted.AdmissionPolicy.WorkloadGrants,
	} {
		for profile, want := range map[string]string{
			runtimeProfileControlPlaneNormalShell: "runtime profile control-plane-normal-shell/v1 is not enabled",
			"unsupported/v1":                      `unsupported runtime profile "unsupported/v1"`,
		} {
			for _, operation := range []string{"prepare", "submit"} {
				t.Run(name+"/"+profile+"/"+operation, func(t *testing.T) {
					service, stagingRoot, resultsRoot := workloadGrantsTestService(t, fixture, grants)
					service.cfg.Execution.RuntimeProfiles.ControlPlaneNormalShell.Enabled = false
					service.arsClient = newResolvedPlanDependencyClient(t, newSignedPayloadHandler(t, fixture, payload))
					nomad := &nomadRegistrationLog{}
					service.nomadClient = newCountingNomadClient(t, nomad)
					request := fixture.prepareRequest()
					request.Invocation.Annotations = map[string]string{runtimeProfileAnnotationKey: profile}
					var err *Error
					if operation == "submit" {
						request.Mode = ExecutionModeAsync
						_, err = service.Submit(testCallerContext(), request)
					} else {
						_, err = service.Prepare(testCallerContext(), request)
					}
					if err == nil || err.Status != http.StatusBadRequest || err.Code != codeUnsupportedRuntimeProfile || err.Message != want {
						t.Fatalf("error = %+v, want 400 %s %q", err, codeUnsupportedRuntimeProfile, want)
					}
					assertNoRunEffects(t, nomad, stagingRoot, resultsRoot)
				})
			}
		}
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

// Signed network_access=true is the publisher's request and only a request:
// a validly signed run that asks for the network gets none unless a rule
// names its publisher, its ES caller and the rest of its facts, and grants a
// lane. The ES caller comes from the authenticated connection alone, so a
// run with no authenticated caller matches no rule, and one caller's grant
// does not serve another caller of the same artifact.
func TestNetworkRunWithoutAGrantIsRefusedOnPrepareAndSubmitBeforeAnyEffect(t *testing.T) {
	fixture, payload := signedStaticScriptFixture(t)
	if !fixture.evidence.Claims.Admission.Execution.Access.NetworkAccess {
		t.Fatal("the fixture's signed evidence does not request the network")
	}
	publisher := fixture.evidence.Claims.Package.Publication.Invoker.Principal
	reaches := true
	noLane := &esconfig.WorkloadGrantsConfig{
		EgressLanes: []esconfig.WorkloadEgressLaneConfig{{Name: esconfig.WorkloadEgressLaneUnrestricted, ReachesWorkloadVault: &reaches}},
		Rules: []esconfig.WorkloadGrantRuleConfig{{
			ID:                 "no-network",
			PublisherPrincipal: publisher,
			CallerPrincipal:    testGrantCaller,
			SignerKeyID:        fixture.keyID,
			ArtifactType:       "static-script",
			RuntimeProfile:     runtimeProfileDefaultStaticScript,
		}},
	}
	otherPublisher := esconfig.Config{}
	grantNetworkTo(&otherPublisher, "spiffe://execution.internal/service/control-plane", fixture.keyID, "static-script")
	otherCaller := esconfig.Config{}
	grantNetworkToCaller(&otherCaller, publisher, "spiffe://execution.internal/service/control-plane", fixture.keyID, "static-script")
	granted := esconfig.Config{}
	grantFixtureNetwork(&granted, fixture)

	for name, test := range map[string]struct {
		grants *esconfig.WorkloadGrantsConfig
		ctx    context.Context
	}{
		"no grants":                    {nil, testCallerContext()},
		"a rule without a lane":        {noLane, testCallerContext()},
		"a rule for another publisher": {otherPublisher.AdmissionPolicy.WorkloadGrants, testCallerContext()},
		"a rule for another ES caller": {otherCaller.AdmissionPolicy.WorkloadGrants, testCallerContext()},
		"a caller below the rule's":    {granted.AdmissionPolicy.WorkloadGrants, callerContext(context.Background(), testGrantCaller+"/sub")},
		"no authenticated caller":      {granted.AdmissionPolicy.WorkloadGrants, context.Background()},
		"a zero authenticated caller":  {granted.AdmissionPolicy.WorkloadGrants, WithAuthenticatedCaller(context.Background(), callerauth.ConnectionCaller{})},
	} {
		for _, operation := range []string{"prepare", "submit"} {
			t.Run(name+"/"+operation, func(t *testing.T) {
				service, stagingRoot, resultsRoot := workloadGrantsTestService(t, fixture, test.grants)
				handler := newSignedPayloadHandler(t, fixture, payload)
				service.arsClient = newResolvedPlanDependencyClient(t, handler)
				nomad := &nomadRegistrationLog{}
				service.nomadClient = newCountingNomadClient(t, nomad)
				request := fixture.prepareRequest()
				var err *Error
				if operation == "submit" {
					request.Mode = ExecutionModeAsync
					var result SubmitResult
					result, err = service.Submit(test.ctx, request)
					if result.Submitted || result.RunID != "" {
						t.Fatalf("a refused run got receipt %+v", result)
					}
				} else {
					var result PrepareResult
					result, err = service.Prepare(test.ctx, request)
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

	prepared, err := service.Prepare(testCallerContext(), fixture.prepareRequest())
	if err != nil || !prepared.Success {
		t.Fatalf("prepare = %+v, %+v", prepared, err)
	}
	request := fixture.prepareRequest()
	request.Mode = ExecutionModeAsync
	result, err := service.Submit(testCallerContext(), request)
	if err != nil || !result.Submitted || nomad.count() != 1 {
		t.Fatalf("submit = %+v, %+v, nomad=%d", result, err, nomad.count())
	}
	if _, statErr := os.Stat(filepath.Join(stagingRoot, result.RunID)); statErr != nil {
		t.Fatalf("admitted run was not staged: %v", statErr)
	}

	// Every delivery that can cause an effect reads the grants ES runs with
	// at that time: a grant removed after :prepare refuses the next :submit.
	service.cfg.AdmissionPolicy = nil
	_, err = service.Submit(testCallerContext(), request)
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

	if prepared, err := service.Prepare(testCallerContext(), fixture.prepareRequest()); err != nil || !prepared.Success {
		t.Fatalf("prepare = %+v, %+v", prepared, err)
	}
	request := fixture.prepareRequest()
	request.Mode = ExecutionModeAsync
	if result, err := service.Submit(testCallerContext(), request); err != nil || !result.Submitted || nomad.count() != 1 {
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

// The grant facts are the trimmed publisher principal and seal key ID: the
// signed canonical claims trim the principal, and the verifier compares the
// trimmed key ID, so evidence with surrounding white space on either value
// is the same signed statement and matches the grant for the trimmed values
// (audit 10, F7).
func TestPaddedPublisherPrincipalAndSealKeyMatchTheGrantForTheTrimmedValues(t *testing.T) {
	fixture, payload := signedStaticScriptFixture(t)
	granted := esconfig.Config{}
	grantFixtureNetwork(&granted, fixture)
	principal := fixture.evidence.Claims.Package.Publication.Invoker.Principal
	fixture.evidence.Claims.Package.Publication.Invoker.Principal = " \t" + principal + "\n "
	fixture = fixture.resealed(t)
	fixture.evidence.Seal.KeyID = "  " + fixture.keyID + "\t"
	fixture.discovery.Evidence.Digest = digestBytes(servedJSONDocument(t, fixture.evidence))
	if fixture.evidence.Claims.Package.Publication.Invoker.Principal == principal || fixture.evidence.Seal.KeyID == fixture.keyID {
		t.Fatal("control: the served evidence is not padded")
	}

	for _, operation := range []string{"prepare", "submit"} {
		t.Run(operation, func(t *testing.T) {
			service, _, _ := workloadGrantsTestService(t, fixture, granted.AdmissionPolicy.WorkloadGrants)
			// The TrustModel's signer list compares the seal's key ID as
			// written, so this TrustModel names the padded form too.
			service.trustModel.SignerPolicy.AllowedSigners = append(service.trustModel.SignerPolicy.AllowedSigners, fixture.evidence.Seal.KeyID)
			service.arsClient = newResolvedPlanDependencyClient(t, newSignedPayloadHandler(t, fixture, payload))
			nomad := &nomadRegistrationLog{}
			service.nomadClient = newCountingNomadClient(t, nomad)
			request := fixture.prepareRequest()
			if operation == "submit" {
				request.Mode = ExecutionModeAsync
				if result, err := service.Submit(testCallerContext(), request); err != nil || !result.Submitted || nomad.count() != 1 {
					t.Fatalf("submit = %+v, %+v, nomad=%d", result, err, nomad.count())
				}
				return
			}
			if prepared, err := service.Prepare(testCallerContext(), request); err != nil || !prepared.Success {
				t.Fatalf("prepare = %+v, %+v", prepared, err)
			}
		})
	}
}

// The publisher principal is read only to match a grant: it never becomes
// ES request or response grammar, and it reaches no output of an admitted or
// refused run (.docs/execution_lifecycle/contracts.md, section 5B). The guard
// test bounds where the value is read; this test checks where it goes, with
// a canary principal: the prepare result, the submit receipt, the scheduler
// job, every staged and result file, and the refusal of an ungranted run.
// (Red-team of ES PR #73, RT73-5.)
func TestPublisherPrincipalReachesNoOutputOfARun(t *testing.T) {
	const canary = "canary-7f3a9d"
	fixture, payload := signedStaticScriptFixture(t)
	fixture.evidence.Claims.Package.Publication.Invoker.Principal = "spiffe://execution.internal/operator/" + canary
	fixture = fixture.resealed(t)
	granted := esconfig.Config{}
	grantFixtureNetwork(&granted, fixture)
	service, stagingRoot, resultsRoot := workloadGrantsTestService(t, fixture, granted.AdmissionPolicy.WorkloadGrants)
	service.arsClient = newResolvedPlanDependencyClient(t, newSignedPayloadHandler(t, fixture, payload))
	var mu sync.Mutex
	job := ""
	service.nomadClient = newResolvedPlanNomadClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		job += string(body)
		mu.Unlock()
		_, _ = w.Write([]byte(`{"EvalID":"eval-canary"}`))
	}))

	prepared, err := service.Prepare(testCallerContext(), fixture.prepareRequest())
	if err != nil || !prepared.Success {
		t.Fatalf("prepare = %+v, %+v", prepared, err)
	}
	if strings.Contains(fmt.Sprintf("%+v", prepared), canary) {
		t.Errorf("the prepare result carries the publisher principal")
	}
	request := fixture.prepareRequest()
	request.Mode = ExecutionModeAsync
	result, err := service.Submit(testCallerContext(), request)
	if err != nil || !result.Submitted {
		t.Fatalf("submit = %+v, %+v", result, err)
	}
	if strings.Contains(fmt.Sprintf("%+v", result), canary) {
		t.Errorf("the submit receipt carries the publisher principal")
	}
	mu.Lock()
	if job == "" || !strings.Contains(job, result.RunID) {
		t.Errorf("control: the scheduler job was not captured")
	}
	if strings.Contains(job, canary) {
		t.Errorf("the scheduler job carries the publisher principal")
	}
	mu.Unlock()
	files := 0
	for _, root := range []string{stagingRoot, resultsRoot} {
		walkErr := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
			if err != nil || entry.IsDir() {
				return err
			}
			files++
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			if strings.Contains(string(data), canary) {
				t.Errorf("%s carries the publisher principal", path)
			}
			return nil
		})
		if walkErr != nil {
			t.Fatal(walkErr)
		}
	}
	if files == 0 {
		t.Errorf("control: the admitted run staged no file")
	}

	service.cfg.AdmissionPolicy = nil
	_, err = service.Submit(testCallerContext(), request)
	assertNetworkAccessNotGranted(t, err)
	if strings.Contains(fmt.Sprintf("%+v", *err), canary) {
		t.Errorf("the refusal carries the publisher principal")
	}
}

// A private reliable submit delivery matches workload grants on the caller
// its claim is bound to, in place of any caller its context carried, and a
// bound caller that callerauth would not accept leaves it with none.
func TestPrivateDeliveryMatchesGrantsOnTheCallerItIsBoundTo(t *testing.T) {
	controlPlane := "spiffe://execution.internal/service/control-plane"
	for name, test := range map[string]struct {
		ctx   context.Context
		bound string
		want  string
	}{
		"bound caller, no context caller":     {context.Background(), testGrantCaller, testGrantCaller},
		"bound caller replaces another":       {callerContext(context.Background(), controlPlane), testGrantCaller, testGrantCaller},
		"foreign bound caller clears context": {testCallerContext(), "spiffe://synthetic.test/ns/admission", ""},
		"bound caller without a path":         {testCallerContext(), "spiffe://execution.internal/", ""},
		"padded bound caller":                 {testCallerContext(), " " + testGrantCaller, ""},
		"bound caller in another case":        {testCallerContext(), "SPIFFE://execution.internal/operator/local", ""},
		"empty bound caller":                  {testCallerContext(), "", ""},
		"workload bound caller":               {testCallerContext(), "spiffe://execution.internal/workload/codex-agent", ""},
		"workload bound caller in other case": {testCallerContext(), "spiffe://execution.internal/Workload/codex-agent", ""},
	} {
		// A URI the delivery parser refuses makes no caller fact; the zero
		// fact stands for it, and carries no caller either.
		fact, _ := newSyntheticCallerFact(test.bound)
		if got := AuthenticatedCallerPrincipal(withDeliveryCaller(test.ctx, fact)); got != test.want {
			t.Errorf("%s: grant caller %q, want %q", name, got, test.want)
		}
	}

	// End to end: the fixture's run requests the network and its grant names
	// testGrantCaller. A synthetic replay bound to that caller is admitted; one
	// bound to another caller is not, though its context names testGrantCaller.
	for _, test := range []struct {
		bound    string
		admitted bool
	}{
		{testGrantCaller, true},
		{controlPlane, false},
	} {
		service, raw, _, keys, image := privateReplayServiceFixture(t)
		caller, err := newSyntheticCallerFact(test.bound)
		if err != nil {
			t.Fatal(err)
		}
		catalog, err := newPrivateSyntheticKeyCatalog(keys)
		if err != nil {
			t.Fatal(err)
		}
		custody, _ := openPrivateReplayTestCustody(t)
		_, err = service.admitPrivateSyntheticReplay(testCallerContext(), custody, raw, caller, catalog, image)
		_ = custody.Close()
		if test.admitted && err != nil {
			t.Fatalf("delivery bound to %s: %v", test.bound, err)
		}
		if !test.admitted && err == nil {
			t.Fatalf("delivery bound to %s got the network from a grant for %s", test.bound, testGrantCaller)
		}
	}
}

// Section 5B: the grant policies run before the content policies, so a
// refused run fetches no payload for policy inspection. A caller that no
// grant names cannot get past that order by naming a runtime profile the
// gate refuses: the grant step returns the gate's own 400 then, before any
// payload read, and the answer does not depend on the owner's content
// policy. (Red-team 2 of ES PR #73, RT73B-2: before the repair, such a
// request skipped the grant decision, ES read the payload, and with an
// owner literal-deny entry the caller saw the content policy's answer.)
func TestARunNoGrantNamesReachesNoContentPolicyWhateverItsRuntimeProfile(t *testing.T) {
	const ungranted = "spiffe://execution.internal/user/mallory"
	fixture, payload := signedStaticScriptFixture(t)
	if !fixture.evidence.Claims.Admission.Execution.Access.NetworkAccess {
		t.Fatal("control: the fixture no longer requests the network")
	}
	granted := esconfig.Config{}
	grantFixtureNetwork(&granted, fixture) // names testGrantCaller only
	const literal = "policy-fixture-ok"    // a text the fixture payload holds
	payloadPath := "/v1/blobs/" + fixture.discovery.Payload.Digest + ":bytes"

	answer := func(t *testing.T, operation, annotation string, annotated, denyLiteral bool, caller string) (*Error, int) {
		t.Helper()
		service, stagingRoot, resultsRoot := workloadGrantsTestService(t, fixture, granted.AdmissionPolicy.WorkloadGrants)
		if denyLiteral {
			policy := *service.cfg.AdmissionPolicy
			policy.ConfiguredStaticScriptLiteralDeny = &esconfig.ConfiguredStaticScriptLiteralDenyPolicyConfig{
				Mode: esconfig.ConfiguredStaticScriptLiteralDenyModeEnforce,
				Entries: []esconfig.ConfiguredStaticScriptLiteralDenyEntryConfig{{
					ID: "owner-rule", InputClass: esconfig.ConfiguredStaticScriptLiteralDenyInputClassStaticScriptPayloadText, Literal: literal,
				}},
			}
			service.cfg.AdmissionPolicy = &policy
		}
		handler := newSignedPayloadHandler(t, fixture, payload)
		service.arsClient = newResolvedPlanDependencyClient(t, handler)
		nomad := &nomadRegistrationLog{}
		service.nomadClient = newCountingNomadClient(t, nomad)
		request := fixture.prepareRequest()
		if annotated {
			request.Invocation.Annotations = map[string]string{runtimeProfileAnnotationKey: annotation}
		}
		ctx := callerContext(context.Background(), caller)
		var err *Error
		if operation == "submit" {
			request.Mode = ExecutionModeAsync
			_, err = service.Submit(ctx, request)
		} else {
			_, err = service.Prepare(ctx, request)
		}
		if caller == ungranted {
			assertNoRunEffects(t, nomad, stagingRoot, resultsRoot)
		}
		return err, handler.log.count(payloadPath)
	}

	for _, operation := range []string{"prepare", "submit"} {
		// Control: the owner's entry does deny this payload, for the caller
		// the grant names. Without it the test would pass for no reason.
		if err, reads := answer(t, operation, "", false, true, testGrantCaller); err == nil || err.Code != codeConfiguredStaticScriptDenied || reads == 0 {
			t.Fatalf("control, %s: the granted caller's run should be denied by the owner's literal entry after a payload read, got %+v with %d reads", operation, err, reads)
		}
		for name, annotation := range map[string]string{
			"an unknown profile":                  "nothing/v1",
			"the profile that is not enabled":     runtimeProfileControlPlaneNormalShell,
			"a known profile in another case":     "Control-Plane-Normal-Shell/v1",
			"the default profile's name":          runtimeProfileDefaultStaticScript,
			"a profile name with a newline in it": "static-script/default\n",
		} {
			var codes [2]string
			for i, denyLiteral := range []bool{false, true} {
				err, reads := answer(t, operation, annotation, true, denyLiteral, ungranted)
				if err == nil {
					t.Fatalf("%s, %s: a caller no grant names was admitted to a run that requests the network", operation, name)
				}
				if reads != 0 {
					t.Errorf("%s, %s, owner literal entry=%t: ES read the payload %d time(s) for a run no grant names (answer %d %s)", operation, name, denyLiteral, reads, err.Status, err.Code)
				}
				if err.Status != http.StatusBadRequest || err.Code != codeUnsupportedRuntimeProfile {
					t.Errorf("%s, %s, owner literal entry=%t: answer %d %s, want the profile gate's 400 %s", operation, name, denyLiteral, err.Status, err.Code, codeUnsupportedRuntimeProfile)
				}
				codes[i] = err.Code
			}
			if codes[0] != codes[1] {
				t.Errorf("%s, %s: the answer to a caller no grant names depends on the owner's content policy: %s without the entry, %s with it", operation, name, codes[0], codes[1])
			}
		}
	}
}

// The grant caller is a grantcaller.Caller (final checks 22, 26 and 33 of ES
// PR #73). Its fields and its context key are unexported, so the Go compiler
// keeps every other package, es/admission included, from writing a caller
// into a Caller or into a context: a Caller comes only from
// grantcaller.FromConnection, which takes a callerauth.ConnectionCaller, or
// from grantcaller.FromDelivery, which takes the URI a private delivery's
// claim is bound to. Only callerauth can make a ConnectionCaller, and only
// from a TLS connection that ES's server accepted through
// callerauth.NewListener and handed it through its ConnContext hook, under a
// context key no other package can set; callerauth's typed guard
// (TestCallerIdentityIsReadOnlyByCallerauthByType) checks, by what each
// identifier refers to, which code refers to that listener, that hook and
// AuthenticateConnection. This test is the backstop for what the compiler
// cannot see on the grant side:
//   - WithAuthenticatedCaller takes a callerauth.ConnectionCaller;
//   - package grantcaller's exported surface is exactly Caller,
//     FromConnection(callerauth.ConnectionCaller), FromDelivery(string),
//     With, From and Caller.Principal; Caller has no exported field, and the
//     package declares no type alias;
//   - no Go package but es/admission imports grantcaller;
//   - in es/admission, FromDelivery is used once: called by
//     newSyntheticCallerFact with its own parameter, which it never changes;
//   - outside tests, newSyntheticCallerFact is used once: called by
//     operatePrivateHandoff with peer.String() for its spiffeid.ID
//     parameter peer, which the function never assigns, redeclares or takes
//     the address of. Synthetic replays get their caller fact from their own
//     caller, which today is only tests;
//   - no non-test Go file outside es/admission names
//     AuthenticatedCallerPrincipal, which reads the grant caller back.
//
// FromDelivery takes a string, so its one use is what keeps a value from a
// request out of a delivery's caller. The use checks count every identifier
// with those names, however the package is imported, so a reference cannot
// pass unseen; a lookalike that is not a use fails them too. Reflection,
// unsafe and cgo are outside what the test sees; a new import of any of them
// in a production file fails TestOperationalGuardImportInventoryIsExact.
// Edits to grantcaller itself are reviewed as part of the trust root. Moving
// one real caller to where another belongs is outside every check: a Caller
// copied from one variable to another still names a real connection's or
// delivery's caller, so any edit to how a request's or a delivery's caller is
// chosen is an auditor-reviewed change.
func TestOnlyAConnectionOrADeliveryMakesAGrantCaller(t *testing.T) {
	want := reflect.TypeOf(func(context.Context, callerauth.ConnectionCaller) context.Context { return nil })
	if got := reflect.TypeOf(WithAuthenticatedCaller); got != want {
		t.Fatalf("WithAuthenticatedCaller has the type %v, want %v", got, want)
	}

	signature := func(fields *ast.FieldList) string {
		if fields == nil {
			return ""
		}
		var parts []string
		for _, field := range fields.List {
			count := len(field.Names)
			if count == 0 {
				count = 1
			}
			for i := 0; i < count; i++ {
				parts = append(parts, types.ExprString(field.Type))
			}
		}
		return strings.Join(parts, ", ")
	}
	surface := map[string]string{}
	for _, parsed := range parseNonTestGoFiles(t, "internal/grantcaller") {
		for _, decl := range parsed.Decls {
			switch decl := decl.(type) {
			case *ast.FuncDecl:
				if !decl.Name.IsExported() {
					continue
				}
				name := decl.Name.Name
				if decl.Recv != nil {
					name = types.ExprString(decl.Recv.List[0].Type) + "." + name
				}
				surface[name] = "func(" + signature(decl.Type.Params) + ") (" + signature(decl.Type.Results) + ")"
			case *ast.GenDecl:
				for _, spec := range decl.Specs {
					switch spec := spec.(type) {
					case *ast.TypeSpec:
						if spec.Assign.IsValid() {
							t.Errorf("grantcaller declares the type alias %s", spec.Name.Name)
						}
						if !spec.Name.IsExported() {
							continue
						}
						surface[spec.Name.Name] = "type " + types.ExprString(spec.Type)
					case *ast.ValueSpec:
						for _, name := range spec.Names {
							if name.IsExported() {
								surface[name.Name] = "value"
							}
						}
					}
				}
			}
		}
	}
	wantSurface := map[string]string{
		"Caller":           "type struct{id callerauth.SPIFFEID}",
		"FromConnection":   "func(callerauth.ConnectionCaller) (Caller)",
		"FromDelivery":     "func(string) (Caller)",
		"With":             "func(context.Context, Caller) (context.Context)",
		"From":             "func(context.Context) (Caller)",
		"Caller.Principal": "func() (string)",
	}
	if !reflect.DeepEqual(surface, wantSurface) {
		t.Errorf("grantcaller's exported surface is %q, want %q", surface, wantSurface)
	}

	importers := map[string]bool{}
	walkErr := filepath.WalkDir("../..", func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			name := entry.Name()
			if path != "../.." && (strings.HasPrefix(name, ".") || strings.HasPrefix(name, "_") || name == "testdata" || name == "vendor") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		fset := token.NewFileSet()
		parsed, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			return err
		}
		for _, spec := range parsed.Imports {
			if spec.Path.Value == strconv.Quote("execution-substrate/es/admission/internal/grantcaller") {
				importers[filepath.ToSlash(filepath.Dir(path))] = true
			}
		}
		if filepath.ToSlash(filepath.Dir(path)) != "../../es/admission" {
			ast.Inspect(parsed, func(node ast.Node) bool {
				if ident, ok := node.(*ast.Ident); ok && ident.Name == "AuthenticatedCallerPrincipal" {
					t.Errorf("%s names AuthenticatedCallerPrincipal; only es/admission reads the grant caller back", fset.PositionFor(ident.Pos(), false))
				}
				return true
			})
		}
		return nil
	})
	if walkErr != nil {
		t.Fatal(walkErr)
	}
	if want := map[string]bool{"../../es/admission": true}; !reflect.DeepEqual(importers, want) {
		t.Errorf("packages that import grantcaller: %v, want only es/admission", importers)
	}

	// assigned reports whether body assigns, redeclares or takes the address
	// of name.
	assigned := func(body ast.Node, name string) bool {
		found := false
		is := func(expr ast.Expr) bool {
			ident, ok := expr.(*ast.Ident)
			return ok && ident.Name == name
		}
		ast.Inspect(body, func(node ast.Node) bool {
			switch node := node.(type) {
			case *ast.AssignStmt:
				for _, lhs := range node.Lhs {
					found = found || is(lhs)
				}
			case *ast.IncDecStmt:
				found = found || is(node.X)
			case *ast.RangeStmt:
				found = found || (node.Key != nil && is(node.Key)) || (node.Value != nil && is(node.Value))
			case *ast.UnaryExpr:
				found = found || (node.Op == token.AND && is(node.X))
			case *ast.ValueSpec:
				for _, ident := range node.Names {
					found = found || ident.Name == name
				}
			case *ast.FuncLit:
				for _, field := range node.Type.Params.List {
					for _, ident := range field.Names {
						found = found || ident.Name == name
					}
				}
			}
			return true
		})
		return found
	}
	var fromDeliveryUses, factUses int
	for _, parsed := range parseNonTestGoFiles(t, ".") {
		for _, decl := range parsed.Decls {
			function, ok := decl.(*ast.FuncDecl)
			if !ok {
				ast.Inspect(decl, func(node ast.Node) bool {
					if ident, ok := node.(*ast.Ident); ok && (ident.Name == "FromDelivery" || ident.Name == "newSyntheticCallerFact") {
						t.Errorf("a package-level declaration uses %s", ident.Name)
					}
					return true
				})
				continue
			}
			params := map[string]string{}
			var firstParam string
			for _, field := range function.Type.Params.List {
				for _, name := range field.Names {
					params[name.Name] = types.ExprString(field.Type)
					if firstParam == "" {
						firstParam = name.Name
					}
				}
			}
			callArgs := map[*ast.Ident][]ast.Expr{}
			ast.Inspect(function, func(node ast.Node) bool {
				switch node := node.(type) {
				case *ast.CallExpr:
					switch fun := node.Fun.(type) {
					case *ast.Ident:
						callArgs[fun] = node.Args
					case *ast.SelectorExpr:
						callArgs[fun.Sel] = node.Args
					}
				case *ast.Ident:
					if node == function.Name {
						return true
					}
					switch node.Name {
					case "FromDelivery":
						fromDeliveryUses++
						args, called := callArgs[node]
						ok := called && function.Name.Name == "newSyntheticCallerFact" && len(args) == 1 && function.Body != nil
						if ok {
							arg, isIdent := args[0].(*ast.Ident)
							ok = isIdent && arg.Name == firstParam && params[firstParam] == "string" && !assigned(function.Body, firstParam)
						}
						if !ok {
							t.Errorf("%s uses grantcaller.FromDelivery other than in newSyntheticCallerFact, with its own unchanged parameter", function.Name.Name)
						}
					case "newSyntheticCallerFact":
						factUses++
						args, called := callArgs[node]
						ok := called && function.Name.Name == "operatePrivateHandoff" && len(args) == 1 && function.Body != nil
						if ok {
							ok = false
							if inner, isCall := args[0].(*ast.CallExpr); isCall && len(inner.Args) == 0 {
								if selector, isSelector := inner.Fun.(*ast.SelectorExpr); isSelector && selector.Sel.Name == "String" {
									if peer, isIdent := selector.X.(*ast.Ident); isIdent {
										ok = params[peer.Name] == "spiffeid.ID" && !assigned(function.Body, peer.Name)
									}
								}
							}
						}
						if !ok {
							t.Errorf("%s makes a delivery caller fact other than from operatePrivateHandoff's unchanged authenticated peer", function.Name.Name)
						}
					}
				}
				return true
			})
		}
	}
	if fromDeliveryUses != 1 || factUses != 1 {
		t.Fatalf("control: grantcaller.FromDelivery used %d times and newSyntheticCallerFact %d times outside tests, want 1 each; the scan no longer reads the package", fromDeliveryUses, factUses)
	}
}

// parseNonTestGoFiles parses every non-test Go file directly in dir.
func parseNonTestGoFiles(t *testing.T, dir string) []*ast.File {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var files []*ast.File
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		parsed, err := parser.ParseFile(token.NewFileSet(), filepath.Join(dir, entry.Name()), nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, parsed)
	}
	return files
}
