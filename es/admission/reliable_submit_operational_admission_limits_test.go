package admission

// Tests of three documented limits of the operational handoff, written by the
// red-team of the combined change of PR #12 and its fix PR #13 (report
// 13-red-team.md, section 5, L1 to L3) and adopted unchanged in substance.
// Each pins the behaviour the owner document names in its limits (§8:
// CP-ROLLBACK, CP-RELEASE, and ordinary Submit reading trust only at
// startup). Each passes because the limit exists and fails with "LIMIT
// CHANGED" when a change closes or moves it. Such a change must update the
// owner document's limits and this test in the same commit, so a limit cannot
// close or widen without the documents saying so.

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"testing"

	"execution-substrate/es/admission/internal/reliablesubmit"
)

func operationalLimitPrepareRequest(t *testing.T, f *operationalFixture) PrepareRequest {
	t.Helper()
	var request struct {
		Invocation ArtifactInvocation `json:"invocation"`
	}
	if err := json.Unmarshal(f.raw, &request); err != nil {
		t.Fatal(err)
	}
	return PrepareRequest{SchemaVersion: "v1", Invocation: request.Invocation}
}

// Startup-only trust (L1). In ONE process the private
// path learns of an EGS revocation within one confirmation and stops, while
// ordinary Prepare keeps admitting the revoked artifact, and Initialize
// refuses to reload trust because the private state is commissioned. A
// never-commissioned process admits the revoked artifact until Initialize is
// called again, which production does only at startup (es/app/app.go).
func TestOperationalLimitStartupOnlyTrustOnTheOrdinaryPath(t *testing.T) {
	ctx := context.Background()
	f := makeOperationalFixture(t, "")
	request := operationalLimitPrepareRequest(t, f)
	if _, err := f.service.Prepare(ctx, request); err != nil {
		t.Fatalf("baseline ordinary Prepare refused: %+v", err)
	}
	artifact := operationalFixtureEvidence(t, f).Claims.Package.Identity.ArtifactDigest
	revoked := snapshotRuntimeTrustModel(*f.service.trustModel)
	revoked.ArtifactPolicy.RevokedArtifacts = append(revoked.ArtifactPolicy.RevokedArtifacts, artifact)
	f.egs.serve(revoked)

	f.service.confirmOperationalAdmission(ctx)
	if !f.service.operational.Inspect(f.service).Superseded {
		t.Fatal("private path did not latch supersession")
	}
	if out := f.submit(); out.kind != operationalUnavailable {
		t.Fatalf("private path admitted after the revocation: %s", operationalResultText(out))
	}
	result, perr := f.service.Prepare(ctx, request)
	t.Logf("same process, ordinary Prepare after EGS revoked %s: error=%v admitted=%t", artifact, perr, perr == nil)
	if perr != nil {
		t.Fatalf("LIMIT CHANGED (update the owner document §8 and this test): ordinary Prepare now refuses: %+v", perr)
	}
	_ = result
	if err := f.service.Initialize(ctx); err == nil {
		t.Fatal("Initialize reloaded trust in a commissioned process")
	} else {
		t.Logf("Initialize in the commissioned process: %v", err)
	}
	if _, perr := f.service.Prepare(ctx, request); perr != nil {
		t.Fatalf("ordinary Prepare refused after the refused Initialize: %+v", perr)
	}

	// A process that never commissioned the private path.
	plain, egs := operationalUncommissionedService(t, f, nil)
	if err := plain.Initialize(ctx); err != nil {
		t.Fatalf("plain Initialize: %v", err)
	}
	if _, perr := plain.Prepare(ctx, request); perr != nil {
		t.Fatalf("plain baseline Prepare refused: %+v", perr)
	}
	egs.serve(revoked)
	if _, perr := plain.Prepare(ctx, request); perr != nil {
		t.Fatalf("LIMIT CHANGED (update the owner document §8 and this test): plain Prepare refuses without a reload: %+v", perr)
	}
	t.Log("plain process admits the artifact EGS revoked, until Initialize runs again")
	if err := plain.Initialize(ctx); err != nil {
		t.Fatalf("plain re-Initialize: %v", err)
	}
	if _, perr := plain.Prepare(ctx, request); perr == nil || perr.Code != codeArtifactRevoked {
		t.Fatalf("after re-Initialize the revocation should apply: %+v", perr)
	} else {
		t.Logf("after re-Initialize: %s", perr.Code)
	}
}

// CP-ROLLBACK (L2). The signed trust payload has no sequence or
// expiry. A response recorded while the commissioned trust was published
// keeps confirming after EGS has revoked the claim's artifact, so the claim
// is staged and POSTed. Reaching the ES->EGS channel needs the EGS mTLS
// identity (config requires https with a client certificate), a stale EGS
// replica, or an EGS restarted from old configuration.
func TestOperationalLimitRollbackReplayConfirmsOldTrust(t *testing.T) {
	ctx := context.Background()
	f, _, _ := operationalSeedAt(t, reliablesubmit.OperationalAssign)
	response, err := f.service.egsClient.get(ctx, "/v1/trust-model")
	if err != nil {
		t.Fatal(err)
	}
	recorded, err := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if err != nil || response.StatusCode != http.StatusOK {
		t.Fatalf("record: %d %v", response.StatusCode, err)
	}
	revoked := snapshotRuntimeTrustModel(*f.service.trustModel)
	revoked.ArtifactPolicy.RevokedArtifacts = append(revoked.ArtifactPolicy.RevokedArtifacts,
		operationalFixtureEvidence(t, f).Claims.Package.Identity.ArtifactDigest)
	f.egs.serve(revoked)
	// The path to EGS now answers with the recorded response.
	f.service.egsClient = newResolvedPlanDependencyClient(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(recorded)
	}))
	out := f.service.handoffOperational(ctx, f.reopen(), f.domain.caller, f.raw)
	assertOperationalCompleted(t, f, out, "replayed old trust")
	t.Logf("artifact revoked at EGS was POSTed under a replayed confirmation: %s", operationalResultText(out))
}

type operationalLimitRefuseAll struct{}

func (operationalLimitRefuseAll) RequiredInputClasses(AdmissionPolicyContext) []AdmissionPolicyInputClass {
	return nil
}
func (operationalLimitRefuseAll) Evaluate(context.Context, AdmissionPolicyContext) AdmissionPolicyDecision {
	return AdmissionPolicyDecision{Allow: false, PolicyID: "red-team-new-release", ReasonCode: "denied"}
}

// CP-RELEASE (L3). A build whose compiled policy refuses what
// the old build allows presents the same digest (the configuration is the
// same), joins the old generation and fences nobody. The stricter proof
// evaluator stands in for the changed compiled behaviour: like it, it is
// outside the digest.
func TestOperationalLimitNewReleaseJoinsAndDoesNotFence(t *testing.T) {
	ctx := context.Background()
	f, _, _ := operationalSeedAt(t, reliablesubmit.OperationalAssign)
	before := operationalAdmissionRowAt(t, f)
	newer := operationalProofService(t, f, func(s *Service) {
		s.operationalProof = &operationalAdmissionProofHooks{stricter: operationalLimitRefuseAll{}}
	})
	if row := operationalAdmissionRowAt(t, f); row != before {
		t.Fatalf("the new build changed the row: %+v -> %+v", before, row)
	}
	refused := newer.handoffOperational(ctx, f.reopen(), f.domain.caller, f.raw)
	if refused.reason != reliablesubmit.OperationalDenied {
		t.Fatalf("new build did not deny: %s", operationalResultText(refused))
	}
	out := f.service.handoffOperational(ctx, f.reopen(), f.domain.caller, f.raw)
	assertOperationalCompleted(t, f, out, "old build after the new build joined")
	t.Logf("new build denied (%s); old build on the same generation sent the job (%s)", operationalResultText(refused), operationalResultText(out))
}
