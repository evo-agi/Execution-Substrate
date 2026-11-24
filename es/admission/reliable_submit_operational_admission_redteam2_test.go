package admission

// Red-team regression tests for the combined change of PR #12 and its fix
// PR #13 (bff8dda), written by the red-team (report 13-red-team.md, attacks
// A-1 to A-12 and A-14) and adopted as permanent tests. Each test is an attack
// that held: it passes when the property holds and fails if a later change
// reopens the road.

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	egsmodel "execution-substrate/egs/model"
	"execution-substrate/es/admission/internal/reliablesubmit"
)

// redTeamCombinedDistinctContent returns a configure function whose content
// differs from the fixture's and from every other index, and allows the
// fixture's claim.
func redTeamCombinedDistinctContent(i int) func(*Service) {
	return func(s *Service) {
		digit := "0123456789abcdef"[i%16 : i%16+1]
		s.trustModel.ArtifactPolicy.RevokedArtifacts = append(s.trustModel.ArtifactPolicy.RevokedArtifacts,
			"sha256:"+strings.Repeat(digit, 63)+"7")
	}
}

// ABA: the row goes g1 (A) -> g2 (B) -> g3 (A). A Service still holding the
// g1 view of content A carries the same digest as the stored row but another
// generation. It must stay fenced at every cut and at a fresh delivery; only
// the Service that holds g3 may complete the claim.
func TestRedTeamPR12CombinedGenerationABAKeepsOldViewFenced(t *testing.T) {
	ctx := context.Background()
	for _, fault := range []reliablesubmit.OperationalOperation{reliablesubmit.OperationalEstablish,
		reliablesubmit.OperationalAssign, reliablesubmit.OperationalIntent} {
		t.Run(map[reliablesubmit.OperationalOperation]string{reliablesubmit.OperationalEstablish: "established",
			reliablesubmit.OperationalAssign: "run assigned", reliablesubmit.OperationalIntent: "intent bound"}[fault], func(t *testing.T) {
			f, _, seeded := operationalSeedAt(t, fault)
			old := operationalInstalledView(f.service).Token()
			b := operationalProofService(t, f, operationalAllowingChange)
			c := operationalProofService(t, f, nil)
			row := operationalAdmissionRowAt(t, f)
			if row.Generation != 3 || row.State != 1 || !old.Names(f.domain.realm.installation, f.domain.realm.epoch, row.Digest) {
				t.Fatalf("the row did not return to the old content at generation 3: row=%+v", row)
			}
			if operationalInstalledView(c).Token() == old {
				t.Fatal("the g3 Service holds the g1 token")
			}
			// The g1 Service is confirmed and otherwise current.
			f.confirm()
			for name, svc := range map[string]*Service{"g1 view with equal digest": f.service, "g2 view": b} {
				out := svc.handoffOperational(ctx, f.reopen(), f.domain.caller, f.raw)
				assertOperationalRefusal(t, f, seeded, out, reliablesubmit.OperationalUnavailable)
				// A fresh delivery under another submit key stores nothing and
				// charges no reservation.
				fresh := svc.handoffOperational(ctx, f.reopen(), f.domain.caller, operationalRawWithKey(t, f, 0x41))
				if after := operationalPrestageStateAt(t, f); fresh.kind != operationalUnavailable || fresh.run != "" ||
					after.Claims != 1 || after.Grants != seeded.Grants {
					t.Fatalf("%s: fresh delivery acted: %s state=%+v seeded=%+v", name, operationalResultText(fresh), after, seeded)
				}
			}
			assertOperationalCompleted(t, f, c.handoffOperational(ctx, f.reopen(), f.domain.caller, f.raw), "the g3 Service")
		})
	}
}

// Eight fresh Services with eight different contents advance the same
// generation at once. Exactly one wins; every loser stays closed, installs no
// view and acts on nothing; the winner completes the claim with one POST.
// Two Services with the same content may both join the winning generation.
func TestRedTeamPR12CombinedConcurrentAdvanceHasOneWinner(t *testing.T) {
	ctx := context.Background()
	f, _, seeded := operationalSeedAt(t, reliablesubmit.OperationalAssign)
	const n = 8
	services := make([]*Service, n)
	for i := range services {
		services[i], _ = operationalUncommissionedService(t, f, redTeamCombinedDistinctContent(i))
	}
	twin, _ := operationalUncommissionedService(t, f, redTeamCombinedDistinctContent(0))
	start := make(chan struct{})
	errs := make([]error, n+1)
	var wg sync.WaitGroup
	for i, svc := range append(append([]*Service{}, services...), twin) {
		wg.Add(1)
		go func(i int, svc *Service) {
			defer wg.Done()
			<-start
			errs[i] = svc.advanceOperationalAdmission(ctx, f.domain, 1)
		}(i, svc)
	}
	close(start)
	wg.Wait()
	winners := 0
	winner := -1
	for i := 0; i < n; i++ {
		if errs[i] == nil {
			winners++
			winner = i
		}
	}
	if winners != 1 {
		t.Fatalf("%d of %d distinct advances of generation 1 succeeded: %v", winners, n, errs)
	}
	row := operationalAdmissionRowAt(t, f)
	if row.Generation != 2 || row.State != 1 ||
		!operationalInstalledView(services[winner]).Token().Names(f.domain.realm.installation, f.domain.realm.epoch, row.Digest) {
		t.Fatalf("row after the race: %+v", row)
	}
	if (errs[n] == nil) != (winner == 0) {
		t.Fatalf("the twin of Service 0 joined=%t while the winner is %d", errs[n] == nil, winner)
	}
	for i, svc := range services {
		if i == winner {
			continue
		}
		if operationalInstalledView(svc).Installed() {
			t.Fatalf("loser %d installed a view", i)
		}
		out := svc.handoffOperational(ctx, f.reopen(), f.domain.caller, f.raw)
		assertOperationalRefusal(t, f, seeded, out, reliablesubmit.OperationalUnavailable)
		// A loser cannot try again either: its row is gone and it cannot
		// advance a generation it did not read.
		if err := svc.advanceOperationalAdmission(ctx, f.domain, 1); err == nil {
			t.Fatalf("loser %d advanced a stale generation", i)
		}
	}
	assertOperationalCompleted(t, f, services[winner].handoffOperational(ctx, f.reopen(), f.domain.caller, f.raw), "the winner")
}

// A withdrawn domain cannot be enabled again with the content it held: not by
// commission, not by an advance of the same digest. Only new content enables
// it. The withdrawn Service and every Service still holding the old token stay
// closed afterwards.
func TestRedTeamPR12CombinedWithdrawnDomainNeedsNewContent(t *testing.T) {
	ctx := context.Background()
	f, _, seeded := operationalSeedAt(t, reliablesubmit.OperationalAssign)
	joined := operationalProofService(t, f, nil)
	if !f.service.withdrawOperationalEffects(ctx, f.domain) {
		t.Fatal("withdrawal was not confirmed")
	}
	if row := operationalAdmissionRowAt(t, f); row.State != 2 || row.Generation != 1 {
		t.Fatalf("row after withdrawal: %+v", row)
	}
	same, _ := operationalUncommissionedService(t, f, nil)
	if err := same.commissionOperationalAdmission(ctx, f.domain); err == nil {
		t.Fatal("commission of a withdrawn domain succeeded")
	}
	same2, _ := operationalUncommissionedService(t, f, nil)
	if err := same2.advanceOperationalAdmission(ctx, f.domain, 1); err == nil {
		t.Fatal("an advance with the withdrawn digest succeeded")
	}
	for _, svc := range []*Service{f.service, joined, same} {
		out := svc.handoffOperational(ctx, f.reopen(), f.domain.caller, f.raw)
		assertOperationalRefusal(t, f, seeded, out, reliablesubmit.OperationalUnavailable)
	}
	if f.service.advanceOperationalAdmission(ctx, f.domain, 1) == nil {
		t.Fatal("the withdrawn Service advanced")
	}
	next := operationalProofService(t, f, operationalAllowingChange)
	if row := operationalAdmissionRowAt(t, f); row.State != 1 || row.Generation != 2 {
		t.Fatalf("row after the advance: %+v", row)
	}
	for _, svc := range []*Service{f.service, joined} {
		out := svc.handoffOperational(ctx, f.reopen(), f.domain.caller, f.raw)
		assertOperationalRefusal(t, f, seeded, out, reliablesubmit.OperationalUnavailable)
	}
	assertOperationalCompleted(t, f, next.handoffOperational(ctx, f.reopen(), f.domain.caller, f.raw), "the new content")
}

// The admission row and the claim triggers refuse raw SQL that skips the Go
// operations: every transition other than withdraw and advance, deletion, a
// second row, and codec-5 progress or establishment while no row is enabled.
func TestRedTeamPR12CombinedAdmissionRowTriggersRefuseRawWrites(t *testing.T) {
	ctx := context.Background()
	f, _, _ := operationalSeedAt(t, reliablesubmit.OperationalAssign)
	other := operationalProofService(t, f, operationalAllowingChange) // row is generation 2 now
	exec := func(t *testing.T, query string, args ...any) error {
		t.Helper()
		tx, err := f.db.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback() }()
		_, err = tx.ExecContext(ctx, query, args...)
		return err
	}
	refused := func(t *testing.T, want, query string, args ...any) {
		t.Helper()
		err := exec(t, query, args...)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("raw write %q: error %v, want one containing %q", query, err, want)
		}
	}
	const admission = "reliable_submit_operational_admission"
	t.Run("transitions", func(t *testing.T) {
		before := operationalAdmissionRowAt(t, f)
		for name, query := range map[string]string{
			"re-enable without advance is not a transition from enabled": "UPDATE " + admission + " SET state=1, updated_at_unix_ns=updated_at_unix_ns+1",
			"skip a generation":            "UPDATE " + admission + " SET generation=generation+2, admission_digest=randomblob(32), updated_at_unix_ns=updated_at_unix_ns+1",
			"lower the generation":         "UPDATE " + admission + " SET generation=generation-1, admission_digest=randomblob(32), updated_at_unix_ns=updated_at_unix_ns+1",
			"same generation, new digest":  "UPDATE " + admission + " SET admission_digest=randomblob(32), updated_at_unix_ns=updated_at_unix_ns+1",
			"next generation, same digest": "UPDATE " + admission + " SET generation=generation+1, updated_at_unix_ns=updated_at_unix_ns+1",
			"advance into withdrawn":       "UPDATE " + admission + " SET generation=generation+1, admission_digest=randomblob(32), state=2, updated_at_unix_ns=updated_at_unix_ns+1",
		} {
			t.Run(name, func(t *testing.T) { refused(t, "invalid operational admission transition", query) })
		}
		refused(t, "immutable operational admission identity", "UPDATE "+admission+" SET installation=randomblob(32), updated_at_unix_ns=updated_at_unix_ns+1")
		refused(t, "immutable operational admission identity", "UPDATE "+admission+" SET epoch=epoch+1, updated_at_unix_ns=updated_at_unix_ns+1")
		refused(t, "operational admission time regression", "UPDATE "+admission+" SET state=2, updated_at_unix_ns=updated_at_unix_ns-1")
		refused(t, "operational admission deletion is forbidden", "DELETE FROM "+admission)
		refused(t, "invalid operational admission commission", "INSERT INTO "+admission+" VALUES (1, randomblob(32), 1, 1, randomblob(32), 1, 1)")
		refused(t, "invalid operational admission commission", "INSERT INTO "+admission+" VALUES (2, randomblob(32), 1, 1, randomblob(32), 1, 1)")
		if after := operationalAdmissionRowAt(t, f); after != before {
			t.Fatalf("a refused write changed the row: before=%+v after=%+v", before, after)
		}
		// Controls: the two transitions the Go operations use pass the trigger.
		if err := exec(t, "UPDATE "+admission+" SET state=2, updated_at_unix_ns=updated_at_unix_ns+1"); err != nil {
			t.Fatalf("withdraw transition refused: %v", err)
		}
		if err := exec(t, "UPDATE "+admission+" SET generation=generation+1, admission_digest=randomblob(32), updated_at_unix_ns=updated_at_unix_ns+1"); err != nil {
			t.Fatalf("advance transition refused: %v", err)
		}
	})
	progress := "UPDATE reliable_submit_claims SET revision=revision+1, latest_operation_kind=3, last_mutation_ref=randomblob(32), updated_at_unix_ns=updated_at_unix_ns+1"
	establish := "INSERT INTO reliable_submit_claims (codec_version, revision, latest_operation_kind) VALUES (5, 1, 1)"
	t.Run("claims while enabled pass the admission clause", func(t *testing.T) {
		for _, query := range []string{progress, establish} {
			if err := exec(t, query); err != nil && strings.Contains(err.Error(), "operational admission unavailable") {
				t.Fatalf("enabled row refused by the admission clause: %q: %v", query, err)
			}
		}
	})
	if !other.withdrawOperationalEffects(ctx, f.domain) {
		t.Fatal("withdrawal was not confirmed")
	}
	t.Run("claims while withdrawn", func(t *testing.T) {
		refused(t, "operational admission unavailable", progress)
		refused(t, "operational admission unavailable", establish)
		refused(t, "invalid operational admission transition", "UPDATE "+admission+" SET state=1, updated_at_unix_ns=updated_at_unix_ns+1")
		// Accept with receipt (kind 8) is not an admission cut.
		if err := exec(t, strings.Replace(progress, "latest_operation_kind=3", "latest_operation_kind=8", 1)); err != nil &&
			strings.Contains(err.Error(), "operational admission unavailable") {
			t.Fatalf("kind 8 refused by the admission clause: %v", err)
		}
	})
}

// An advance that commits between a writer's COMMIT and its release re-read,
// at the Service level. Nothing is released: no projection, no sender, no
// POST. Before staging, the generation that replaced the view completes the
// claim with exactly one POST. After staging the claim keeps its residue and
// never sends (owner document, "After staging the claim keeps its charged
// residue"); a marker that committed without its sender is never sent.
func TestRedTeamPR12CombinedAdvanceBetweenCommitAndRelease(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name                     string
		op                       reliablesubmit.OperationalOperation
		wantRevision             int
		completes, stamp, marker bool
	}{
		{"run assignment", reliablesubmit.OperationalAssign, 2, true, false, false},
		{"intent", reliablesubmit.OperationalIntent, 3, true, false, false},
		{"stamp", reliablesubmit.OperationalStamp, 4, false, true, false},
		{"first marker", reliablesubmit.OperationalMark, 5, false, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, _, _ := operationalSeedAt(t, reliablesubmit.OperationalEstablish)
			d := f.reopen()
			var next *Service
			observed := 0
			if err := d.custody.ConfigureOperationalReleaseProofForProof(func(op reliablesubmit.OperationalOperation) {
				if op == tc.op && next == nil {
					observed++
					next = operationalProofService(t, f, operationalAllowingChange)
				}
			}); err != nil {
				t.Fatal(err)
			}
			out := f.service.handoffOperational(ctx, d, d.caller, f.raw)
			state := operationalPrestageStateAt(t, f)
			if observed != 1 || next == nil {
				t.Fatalf("the advance did not run in the release window: observed=%d", observed)
			}
			if out.kind == operationalAccepted || out.run != "" || out.receipt.Valid() || state.Posts != 0 ||
				state.Revision != tc.wantRevision || state.Stamp != tc.stamp || state.Marker != tc.marker {
				t.Fatalf("release after the advance: %s state=%+v", operationalResultText(out), state)
			}
			// The fenced Service gains nothing by trying again.
			again := f.service.handoffOperational(ctx, f.reopen(), f.domain.caller, f.raw)
			if after := operationalPrestageStateAt(t, f); again.kind == operationalAccepted || after.Revision != state.Revision ||
				after.Posts != 0 || after.StageEntries != state.StageEntries {
				t.Fatalf("fenced retry: %s state=%+v", operationalResultText(again), after)
			}
			continued := next.handoffOperational(ctx, f.reopen(), f.domain.caller, f.raw)
			if tc.completes {
				assertOperationalCompleted(t, f, continued, "the replacing generation")
				return
			}
			if after := operationalPrestageStateAt(t, f); continued.kind == operationalAccepted || after.Posts != 0 ||
				after.Revision != state.Revision {
				t.Fatalf("a staged claim moved after the advance: %s state=%+v", operationalResultText(continued), after)
			}
		})
	}
}

// What EGS serves is compared by content, not by spelling. The same trust in
// another order and with padding confirms; any change of content, including
// one that only widens the allowed signers, latches supersession, and the
// latch survives EGS serving the commissioned trust again.
func TestRedTeamPR12CombinedConfirmationComparesContent(t *testing.T) {
	ctx := context.Background()
	evidenceOf := func(t *testing.T, f *operationalFixture) (string, string) {
		record := operationalFixtureEvidence(t, f)
		return record.Seal.KeyID, record.Claims.Package.Identity.ArtifactDigest
	}
	t.Run("respelled equal trust confirms", func(t *testing.T) {
		f := makeOperationalFixture(t, "")
		// The fixture's own trust, every entry padded and the lists reversed.
		served := snapshotRuntimeTrustModel(*f.service.trustModel)
		pad := func(values []string) []string {
			out := make([]string, 0, len(values))
			for i := len(values) - 1; i >= 0; i-- {
				out = append(out, "  "+values[i]+"\t")
			}
			return out
		}
		served.SignerPolicy.AllowedSigners = pad(served.SignerPolicy.AllowedSigners)
		served.SignerPolicy.RevokedSigners = pad(served.SignerPolicy.RevokedSigners)
		served.ArtifactPolicy.RevokedArtifacts = pad(served.ArtifactPolicy.RevokedArtifacts)
		f.egs.serve(served)
		f.service.confirmOperationalAdmission(ctx)
		if _, ok := f.service.currentOperationalAdmission(f.domain.realm); !ok {
			t.Fatal("respelled equal trust did not confirm")
		}
		assertOperationalCompleted(t, f, f.submit(), "after a respelled confirmation")
	})
	for name, change := range map[string]func(*testing.T, *operationalFixture, *egsmodel.RuntimeTrustPolicy){
		"an added allowed signer": func(_ *testing.T, _ *operationalFixture, trust *egsmodel.RuntimeTrustPolicy) {
			trust.SignerPolicy.AllowedSigners = append(trust.SignerPolicy.AllowedSigners, "red-team-extra-signer")
		},
		"an unrelated revocation": func(_ *testing.T, _ *operationalFixture, trust *egsmodel.RuntimeTrustPolicy) {
			trust.ArtifactPolicy.RevokedArtifacts = append(trust.ArtifactPolicy.RevokedArtifacts, "sha256:"+strings.Repeat("8", 64))
		},
		"the claim's artifact revoked": func(t *testing.T, f *operationalFixture, trust *egsmodel.RuntimeTrustPolicy) {
			_, artifact := evidenceOf(t, f)
			trust.ArtifactPolicy.RevokedArtifacts = append(trust.ArtifactPolicy.RevokedArtifacts, artifact)
		},
		"the claim's signer revoked": func(t *testing.T, f *operationalFixture, trust *egsmodel.RuntimeTrustPolicy) {
			signer, _ := evidenceOf(t, f)
			trust.SignerPolicy.RevokedSigners = append(trust.SignerPolicy.RevokedSigners, signer)
		},
	} {
		t.Run(name+" supersedes for good", func(t *testing.T) {
			f, _, seeded := operationalSeedAt(t, reliablesubmit.OperationalAssign)
			original := snapshotRuntimeTrustModel(*f.service.trustModel)
			changed := snapshotRuntimeTrustModel(original)
			change(t, f, &changed)
			f.egs.serve(changed)
			out := f.service.handoffOperational(ctx, f.reopen(), f.domain.caller, f.raw)
			assertOperationalRefusal(t, f, seeded, out, reliablesubmit.OperationalUnavailable)
			if st := f.service.operational.Inspect(f.service); !st.Superseded {
				t.Fatal("supersession was not latched")
			}
			f.egs.serve(original)
			out = f.service.handoffOperational(ctx, f.reopen(), f.domain.caller, f.raw)
			assertOperationalRefusal(t, f, seeded, out, reliablesubmit.OperationalUnavailable)
			fresh := f.service.handoffOperational(ctx, f.reopen(), f.domain.caller, operationalRawWithKey(t, f, 0x42))
			if after := operationalPrestageStateAt(t, f); fresh.kind != operationalUnavailable || after.Claims != 1 || after.Grants != seeded.Grants {
				t.Fatalf("superseded Service took a fresh delivery: %s state=%+v", operationalResultText(fresh), after)
			}
		})
	}
}

// Eight deliveries of the same claim at once in one process, each through its
// own custody handle: a fresh delivery (no claim yet) and retained claims at
// two cuts. Whatever each delivery answers, at most one POST is sent, and one
// more delivery afterwards ends with exactly one POST and the receipt.
func TestRedTeamPR12CombinedConcurrentSameClaimSendsOnce(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name string
		seed reliablesubmit.OperationalOperation
	}{{"fresh", 0}, {"established", reliablesubmit.OperationalEstablish}, {"run assigned", reliablesubmit.OperationalAssign}} {
		t.Run(tc.name, func(t *testing.T) {
			var f *operationalFixture
			if tc.seed == 0 {
				f = makeOperationalFixture(t, "")
			} else {
				f, _, _ = operationalSeedAt(t, tc.seed)
			}
			f.confirm()
			const n = 8
			domains := make([]*operationalDomain, n)
			for i := range domains {
				domains[i] = f.reopen()
			}
			results := make([]operationalHandoffResult, n)
			start := make(chan struct{})
			var wg sync.WaitGroup
			for i := range domains {
				wg.Add(1)
				go func(i int) {
					defer wg.Done()
					<-start
					results[i] = f.service.handoffOperational(ctx, domains[i], f.domain.caller, f.raw)
				}(i)
			}
			close(start)
			wg.Wait()
			raced := operationalPrestageStateAt(t, f)
			accepted := 0
			for _, r := range results {
				if r.kind == operationalAccepted {
					accepted++
				}
			}
			if raced.Posts > 1 || raced.Claims != 1 {
				t.Fatalf("concurrent deliveries: state=%+v", raced)
			}
			if accepted > 0 && (raced.Posts != 1 || !raced.Receipt) {
				t.Fatalf("accepted without the one POST and its receipt: state=%+v", raced)
			}
			out := f.service.handoffOperational(ctx, f.reopen(), f.domain.caller, f.raw)
			final := operationalPrestageStateAt(t, f)
			if out.kind != operationalAccepted || final.Posts != 1 || !final.Receipt || final.Claims != 1 {
				t.Fatalf("after the race: %s state=%+v", operationalResultText(out), final)
			}
			t.Logf("%d of %d concurrent deliveries accepted; POSTs after the race %d, at the end %d", accepted, n, raced.Posts, final.Posts)
		})
	}
}

// Two confirmations overlap. The first is slow and carries the commissioned
// trust; the second, sent later, carries changed trust and latches
// supersession. When the first returns, its equal answer must not reopen the
// state: supersession is for the life of the state, whatever order the answers
// arrive in.
func TestRedTeamPR12CombinedLateEqualConfirmationKeepsSupersession(t *testing.T) {
	ctx := context.Background()
	f := makeOperationalFixture(t, "")
	original := snapshotRuntimeTrustModel(*f.service.trustModel)
	changed := snapshotRuntimeTrustModel(original)
	changed.ArtifactPolicy.RevokedArtifacts = append(changed.ArtifactPolicy.RevokedArtifacts,
		operationalFixtureEvidence(t, f).Claims.Package.Identity.ArtifactDigest)
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	f.egs.observe(func() {
		first := false
		once.Do(func() { first = true })
		if first {
			close(entered)
			<-release
		}
	})
	slow := make(chan struct{})
	go func() {
		defer close(slow)
		f.service.confirmOperationalAdmission(ctx)
	}()
	<-entered // the slow request already holds the commissioned trust
	f.egs.serve(changed)
	f.service.confirmOperationalAdmission(ctx)
	if !f.service.operational.Inspect(f.service).Superseded {
		t.Fatal("the later confirmation did not latch supersession")
	}
	close(release)
	<-slow
	if st := f.service.operational.Inspect(f.service); !st.Superseded {
		t.Fatalf("a late equal answer cleared supersession: %+v", st)
	}
	f.egs.serve(original)
	if _, ok := f.service.currentOperationalAdmission(f.domain.realm); ok {
		t.Fatal("the superseded state is current again")
	}
	if out := f.submit(); out.kind != operationalUnavailable {
		t.Fatalf("superseded Service handed off: %s", operationalResultText(out))
	}
	if after := operationalPrestageStateAt(t, f); after.Posts != 0 {
		t.Fatalf("superseded Service POSTed: %+v", after)
	}
}

// The confirmation counts from the instant before the request was sent, so a
// slow EGS shortens the window and never lengthens it.
func TestRedTeamPR12CombinedSlowConfirmationCountsFromTheRequest(t *testing.T) {
	ctx := context.Background()
	f := makeOperationalFixture(t, "")
	var entered time.Time
	f.egs.observe(func() {
		entered = time.Now()
		time.Sleep(1500 * time.Millisecond)
	})
	before := time.Now()
	f.service.confirmOperationalAdmission(ctx)
	returned := time.Now()
	confirmed := f.service.operational.Inspect(f.service).Confirmed
	if confirmed.IsZero() || confirmed.Before(before) || confirmed.After(entered) || !returned.After(entered.Add(1400*time.Millisecond)) {
		t.Fatalf("confirmation time %v not in [%v, %v] (returned %v)", confirmed, before, entered, returned)
	}
}

// A fresh delivery whose artifact EGS has revoked since commissioning is
// refused after one confirmation: no claim row, no sealed original, no
// reservation.
func TestRedTeamPR12CombinedRevokedAtEGSRefusesFreshDelivery(t *testing.T) {
	f := makeOperationalFixture(t, "")
	// A confirmation inside the deadline already exists: only the one before
	// establishment can learn of the revocation.
	f.confirm()
	before := operationalPrestageStateAt(t, f)
	objects := operationalSealedObjects(t, f)
	trust := snapshotRuntimeTrustModel(*f.service.trustModel)
	trust.ArtifactPolicy.RevokedArtifacts = append(trust.ArtifactPolicy.RevokedArtifacts,
		operationalFixtureEvidence(t, f).Claims.Package.Identity.ArtifactDigest)
	f.egs.serve(trust)
	out := f.submit()
	if after := operationalPrestageStateAt(t, f); out.kind != operationalUnavailable || out.run != "" || after.Claims != before.Claims ||
		after.Grants != before.Grants || operationalSealedObjects(t, f) != objects || after.Posts != 0 {
		t.Fatalf("revoked fresh delivery acted: %s before=%+v after=%+v", operationalResultText(out), before, after)
	}
}

// The staging root is swapped under a domain that already holds it open,
// before a retained claim is continued: a symbolic link to the moved root, a
// new directory in its place, and a link to another directory. Every form is
// refused before a stage exists, nothing is created in either directory, and
// the claim is not poisoned: once the root is back, the claim completes.
func TestRedTeamPR12CombinedStagingRootSwapRefused(t *testing.T) {
	ctx := context.Background()
	for _, swap := range []string{"link to the moved root", "new directory in place", "link to another directory"} {
		t.Run(swap, func(t *testing.T) {
			f, _, seeded := operationalSeedAt(t, reliablesubmit.OperationalIntent)
			d := f.reopen()
			root := f.domain.realm.staging
			info, err := os.Stat(root)
			if err != nil {
				t.Fatal(err)
			}
			moved := root + ".moved"
			other := filepath.Join(t.TempDir(), "other-stage")
			if err := os.Mkdir(other, info.Mode().Perm()); err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(root, moved); err != nil {
				t.Fatal(err)
			}
			switch swap {
			case "link to the moved root":
				err = os.Symlink(moved, root)
			case "new directory in place":
				err = os.Mkdir(root, info.Mode().Perm())
			default:
				err = os.Symlink(other, root)
			}
			if err != nil {
				t.Fatal(err)
			}
			out := f.service.handoffOperational(ctx, d, d.caller, f.raw)
			for _, dir := range []string{moved, other} {
				if entries, err := os.ReadDir(dir); err != nil || len(entries) != 0 {
					t.Fatalf("%s holds %d entries after the swapped handoff (err %v): %s", dir, len(entries), err, operationalResultText(out))
				}
			}
			if after := operationalPrestageStateAt(t, f); out.kind == operationalAccepted || after.Posts != 0 || after.Stamp ||
				after.Revision != seeded.Revision {
				t.Fatalf("swapped staging root: %s state=%+v", operationalResultText(out), after)
			}
			if swap == "new directory in place" {
				if entries, err := os.ReadDir(root); err != nil || len(entries) != 0 {
					t.Fatalf("the replacement directory holds %d entries (err %v)", len(entries), err)
				}
			}
			if err := os.Remove(root); err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(moved, root); err != nil {
				t.Fatal(err)
			}
			assertOperationalCompleted(t, f, f.service.handoffOperational(ctx, f.reopen(), f.domain.caller, f.raw), "after the root came back")
		})
	}
}
