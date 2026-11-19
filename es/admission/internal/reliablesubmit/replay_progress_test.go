package reliablesubmit

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

type progressTestFixture struct {
	t       *testing.T
	custody *PrivateReplayProgressCustody
	root    string
	base    durableClaimRecord
	keys    PrivateReplayKeys
	payload []byte
	intent  []byte
	run     FixtureRunRef
	marker  FixtureFactRef
}

func newProgressTestFixture(t *testing.T, root string, base durableClaimRecord, keys PrivateReplayKeys) *progressTestFixture {
	t.Helper()
	f := &progressTestFixture{t: t, root: root, base: base, keys: keys,
		run: NewFixtureRunRef([32]byte{11}), marker: NewFixtureFactRef([32]byte{12})}
	f.payload = progressFixturePayload(t, base, keys)
	f.intent = progressVectorFields(t, f.payload[14:])[1]
	f.open()
	t.Cleanup(func() { _ = f.custody.Close() })
	return f
}

func progressFixture(t *testing.T) *progressTestFixture {
	t.Helper()
	base, _ := syntheticReplayRecordFixture(t)
	return newProgressTestFixture(t, fixtureReplayRoot(t), base, fixtureReplayKeys(t, 63))
}

func (f *progressTestFixture) open() {
	f.t.Helper()
	var err error
	f.custody, err = OpenPrivateReplayProgressCustody(context.Background(), f.root)
	if err != nil {
		f.t.Fatal(err)
	}
}

func (f *progressTestFixture) restart() {
	f.t.Helper()
	if err := f.custody.Close(); err != nil {
		f.t.Fatal(err)
	}
	f.open()
}

func (f *progressTestFixture) verify(view *ProgressOriginalView) (ProgressOriginalMatch, error) {
	fields, err := view.Fields()
	if err != nil || len(fields) != 10 {
		return ProgressOriginalMatch{}, errClaimStoreUnavailable
	}
	return NewProgressOriginalMatch(f.base.claim, f.base.plan, f.intent, sha256.Sum256(f.payload))
}

func (f *progressTestFixture) prepare(ctx context.Context, phase FixtureProgressPhase) (ProgressLookup, ProgressFrozen, ProgressPublication) {
	f.t.Helper()
	l, err := f.custody.LookupProgressOriginal(ctx, f.base.claim)
	if err != nil || !l.Absent() {
		f.t.Fatalf("initial lookup: %v", err)
	}
	input, err := NewProgressOriginalInput(f.payload)
	if err != nil {
		f.t.Fatal(err)
	}
	frozen, err := f.custody.FreezeProgressOriginal(ctx, l, phase, f.base.plan, f.keys, input)
	if err != nil {
		f.t.Fatal(err)
	}
	permit, err := f.custody.ReserveProgressSealUse(ctx, frozen)
	if err != nil {
		f.t.Fatal(err)
	}
	p, err := f.custody.PublishProgressOriginal(ctx, frozen, permit)
	if err != nil {
		f.t.Fatal(err)
	}
	return l, frozen, p
}

func (f *progressTestFixture) establish(phase FixtureProgressPhase) {
	f.t.Helper()
	ctx, stop := context.WithCancel(context.Background())
	defer stop()
	l, frozen, p := f.prepare(ctx, phase)
	a, status, err := f.custody.EstablishProgress(ctx, frozen, p)
	if err != nil || status != FixtureProgressCommitted {
		f.t.Fatalf("establish: %d %v", status, err)
	}
	var proof FixtureProgress
	status, err = f.custody.WithAuthenticatedProgressOriginal(ctx, l, f.keys, f.intent, a, f.verify, func(access *ProgressAccess) error {
		proof, err = f.custody.ReadFixtureProgress(ctx, access)
		return err
	})
	if err != nil || status != FixtureProgressCommitted || proof.Phase() != phase || proof.Revision() != 1 {
		f.t.Fatalf("establishment proof: %d %d %d %v", status, proof.Phase(), proof.Revision(), err)
	}
}

func (f *progressTestFixture) use(verify func(*ProgressOriginalView) (ProgressOriginalMatch, error),
	fn func(context.Context, *ProgressAccess) error) (FixtureProgressDisposition, error) {
	f.t.Helper()
	ctx, stop := context.WithCancel(context.Background())
	defer stop()
	l, err := f.custody.LookupProgressOriginal(ctx, f.base.claim)
	if err != nil {
		return FixtureProgressRefused, err
	}
	return f.custody.WithAuthenticatedProgressOriginal(ctx, l, f.keys, f.intent, ProgressAttempt{}, verify, func(access *ProgressAccess) error {
		return fn(ctx, access)
	})
}

func (f *progressTestFixture) apply(rev int64, m byte, command FixtureProgressCommand) (FixtureProgressDisposition, FixtureProgress, error) {
	var state FixtureProgressDisposition
	var p FixtureProgress
	outer, err := f.use(f.verify, func(ctx context.Context, access *ProgressAccess) error {
		var opErr error
		state, p, opErr = f.custody.ApplyFixtureProgress(ctx, access, rev, NewFixtureMutationRef([32]byte{m}), command)
		return opErr
	})
	if outer != FixtureProgressCurrent {
		return outer, FixtureProgress{}, err
	}
	return state, p, err
}

func (f *progressTestFixture) record() durableClaimRecord {
	f.t.Helper()
	r, err := f.custody.custody.store.loadClaim(context.Background(), loadClaimQuery{claim: f.base.claim})
	if err != nil {
		f.t.Fatal(err)
	}
	return r
}

func (f *progressTestFixture) object(r durableClaimRecord) []byte {
	f.t.Helper()
	b, err := os.ReadFile(filepath.Join(f.root, r.replay.ref))
	if err != nil {
		f.t.Fatal(err)
	}
	return b
}

func (f *progressTestFixture) step(rev int64, m byte, cmd FixtureProgressCommand, phase FixtureProgressPhase) durableClaimRecord {
	f.t.Helper()
	before := f.record()
	file := f.object(before)
	state, p, err := f.apply(rev, m, cmd)
	if err != nil || state != FixtureProgressCommitted || p.Revision() != rev+1 || p.Phase() != phase {
		f.t.Fatalf("step %d: status=%d revision=%d phase=%d error=%v", m, state, p.Revision(), p.Phase(), err)
	}
	after := f.record()
	if !before.sameProgressOriginal(after) || !bytes.Equal(file, f.object(after)) || int64(after.revision) != rev+1 {
		f.t.Fatal("progress rewrote original or advanced wrong revision")
	}
	return after
}

func (f *progressTestFixture) reject(rev int64, m byte, cmd FixtureProgressCommand) {
	f.t.Helper()
	before := f.record()
	state, p, err := f.apply(rev, m, cmd)
	if err == nil || state != FixtureProgressRefused || p.Revision() != 0 || !before.equal(f.record()) {
		f.t.Fatalf("invalid transition changed or disclosed state: %d %d %v", state, p.Revision(), err)
	}
}

func (f *progressTestFixture) assignAndIntent(phase FixtureProgressPhase) {
	f.t.Helper()
	f.establish(phase)
	f.step(1, 1, FixtureAssignRun{Run: f.run}, FixtureAssigned)
	f.step(2, 2, FixtureRecordIntent{Fact: NewFixtureFactRef([32]byte{13})}, FixtureAssigned)
}

func (f *progressTestFixture) markerCommand() FixtureRecordMarker {
	return FixtureRecordMarker{Run: f.run, Marker: f.marker}
}

func (f *progressTestFixture) reconciliation(kind FixtureReconciliationKind, fact byte) FixtureRecordReconciliation {
	return FixtureRecordReconciliation{Run: f.run, Kind: kind, Fact: NewFixtureFactRef([32]byte{fact})}
}

func (f *progressTestFixture) terminal(fact byte) FixtureTerminalEvidence {
	f.t.Helper()
	evidence, err := NewFixtureNotAcceptedEvidence(f.base.claim, f.run, f.marker, NewFixtureFactRef([32]byte{fact}))
	if err != nil {
		f.t.Fatal(err)
	}
	return evidence
}

func (f *progressTestFixture) acceptedEvidence(fact byte, receipt FixtureReceiptRef) FixtureTerminalEvidence {
	f.t.Helper()
	evidence, err := NewFixtureAcceptedEvidence(f.base.claim, f.run, f.marker, NewFixtureFactRef([32]byte{fact}), receipt)
	if err != nil {
		f.t.Fatal(err)
	}
	return evidence
}

func TestPrivateReplayProgressTransitions(t *testing.T) {
	t.Run("FixtureNoMarkerThenFirstMarkerAfterRestart", func(t *testing.T) {
		f := progressFixture(t)
		f.assignAndIntent(FixturePendingBeforeAssignment)
		baseline := f.step(3, 3, f.reconciliation(FixtureNoMarker, 14), FixtureAssigned)
		f.restart()
		staging := FixtureRecordStaging{Fact: NewFixtureFactRef([32]byte{15})}
		f.step(4, 4, staging, FixtureAssigned)
		next := f.step(5, 5, f.markerCommand(), FixtureAssigned)
		if !baseline.effects.reconciliation.equal(next.effects.reconciliation) || !next.effects.staging.present() {
			t.Fatal("historical no-marker observation or staging changed")
		}
		f.reject(6, 6, f.markerCommand())
		f.reject(6, 7, f.reconciliation(FixtureNoMarker, 14))
	})
	for _, tc := range []struct {
		name   string
		kind   FixtureReconciliationKind
		before FixtureProgressPhase
		accept bool
	}{
		{"NonterminalReconciliationThenPositiveAcceptedAfterRestart", FixtureReconciledPending, FixturePendingAfterAssignment, true},
		{"NonterminalReconciliationThenPositiveNotAcceptedAfterRestart", FixtureReconciledAmbiguous, FixtureAmbiguousAfterAssignment, false},
		{"NonterminalInconsistentThenPositiveAccepted", FixtureReconciledInconsistent, FixtureAmbiguousAfterAssignment, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := progressFixture(t)
			f.assignAndIntent(FixtureAmbiguousBeforeAssignment)
			f.step(3, 3, f.markerCommand(), FixtureAssigned)
			past := f.step(4, 4, f.reconciliation(tc.kind, 14), tc.before)
			f.restart()
			receipt := NewFixtureReceiptRef([32]byte{24})
			cmd := FixtureProgressCommand(FixtureReject{Evidence: f.terminal(23)})
			after := FixtureProvablyNotAccepted
			if tc.accept {
				cmd, after = FixtureAccept{Evidence: f.acceptedEvidence(23, receipt), Receipt: receipt}, FixtureAccepted
			}
			next := f.step(5, 5, cmd, after)
			if !past.effects.reconciliation.equal(next.effects.reconciliation) {
				t.Fatal("terminal changed earlier reconciliation")
			}
			f.restart()
			s, p, err := f.apply(5, 5, cmd)
			got, present := p.Receipt()
			if err != nil || s != FixtureProgressExactReplay || p.Revision() != 6 || present != tc.accept || (present && !got.Equal(receipt)) {
				t.Fatalf("terminal replay: %d %d %t %v", s, p.Revision(), present, err)
			}
		})
	}
	t.Run("HistoricalReconciliationProviderProgress", func(t *testing.T) {
		for _, kind := range []FixtureProviderKind{FixtureProviderPending, FixtureProviderAmbiguous, FixtureProviderCallUncertain} {
			f := progressFixture(t)
			f.assignAndIntent(FixturePendingBeforeAssignment)
			old := f.step(3, 3, f.reconciliation(FixtureNoMarker, 14), FixtureAssigned)
			f.step(4, 4, f.markerCommand(), FixtureAssigned)
			want := FixtureAmbiguousAfterAssignment
			if kind == FixtureProviderPending {
				want = FixturePendingAfterAssignment
			}
			provider := FixtureRecordProvider{Run: f.run, Kind: kind, Fact: NewFixtureFactRef([32]byte{20})}
			next := f.step(5, 5, provider, want)
			if !old.effects.reconciliation.equal(next.effects.reconciliation) {
				t.Fatal("current provider progress replaced historical no-marker tuple")
			}
			f.step(6, 6, FixtureReject{Evidence: f.terminal(22)}, FixtureProvablyNotAccepted)
		}
	})
	t.Run("TerminalReconciliationAndContradictions", func(t *testing.T) {
		f := progressFixture(t)
		f.assignAndIntent(FixturePendingBeforeAssignment)
		f.reject(3, 3, FixtureReject{Evidence: f.terminal(23)})
		f.reject(3, 4, f.reconciliation(FixtureReconciledPending, 15))
		f.step(3, 5, f.markerCommand(), FixtureAssigned)
		f.reject(4, 6, f.reconciliation(FixtureReconciledAccepted, 16))
		receipt := NewFixtureReceiptRef([32]byte{25})
		f.step(4, 7, FixtureAccept{Evidence: f.acceptedEvidence(23, receipt), Receipt: receipt}, FixtureAccepted)
		f.step(5, 8, f.reconciliation(FixtureReconciledAccepted, 17), FixtureAccepted)
		f.reject(6, 9, FixtureReject{Evidence: f.terminal(26)})
		f.reject(6, 10, FixtureAssignRun{Run: NewFixtureRunRef([32]byte{99})})

		g := progressFixture(t)
		g.assignAndIntent(FixturePendingBeforeAssignment)
		g.step(3, 3, g.markerCommand(), FixtureAssigned)
		negative := g.reconciliation(FixtureReconciledNotAccepted, 24)
		g.reject(4, 4, negative)
		negative.Negative = g.terminal(24)
		g.step(4, 5, negative, FixtureProvablyNotAccepted)
		g.reject(5, 6, FixtureAccept{Evidence: g.acceptedEvidence(24, receipt), Receipt: receipt})
	})
	t.Run("CopiedForeignEscapedCanceledAndClosedAccess", func(t *testing.T) {
		f := progressFixture(t)
		f.establish(FixturePendingBeforeAssignment)
		other := progressFixture(t)
		var escaped *ProgressAccess
		var escapedContext context.Context
		var escapedView *ProgressOriginalView
		verify := func(view *ProgressOriginalView) (ProgressOriginalMatch, error) {
			escapedView = view
			return f.verify(view)
		}
		_, err := f.use(verify, func(ctx context.Context, access *ProgressAccess) error {
			escaped, escapedContext = access, ctx
			copied := *access
			for _, candidate := range []struct {
				issuer *PrivateReplayProgressCustody
				access *ProgressAccess
				ctx    context.Context
			}{{f.custody, &copied, ctx}, {other.custody, access, ctx}, {f.custody, access, context.Background()}} {
				if _, err := candidate.issuer.ReadFixtureProgress(candidate.ctx, candidate.access); err == nil {
					t.Fatal("unqualified access accepted")
				}
			}
			if _, err := escapedView.Fields(); err == nil {
				t.Fatal("original view escaped verifier")
			}
			if p, err := f.custody.ReadFixtureProgress(ctx, access); err != nil || p.Revision() != 1 {
				t.Fatalf("legitimate use: %v", err)
			}
			if _, err := f.custody.ReadFixtureProgress(ctx, access); err == nil {
				t.Fatal("access used twice")
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.custody.ReadFixtureProgress(escapedContext, escaped); err == nil {
			t.Fatal("access escaped invocation")
		}
		_, _ = f.use(f.verify, func(ctx context.Context, access *ProgressAccess) error {
			if err := f.custody.Close(); err != nil {
				t.Fatal(err)
			}
			if _, err := f.custody.ReadFixtureProgress(ctx, access); err == nil {
				t.Fatal("closed issuer permitted access")
			}
			return nil
		})
	})
	t.Run("StrictStorageClassesAndProtectedOriginal", func(t *testing.T) {
		f := progressFixture(t)
		f.assignAndIntent(FixtureAmbiguousBeforeAssignment)
		store := f.custody.custody.store
		before := f.record()
		sealedBytes := f.object(before)
		for _, tc := range []struct{ label, field, value string }{
			{"UnsupportedCodec", "codec_version", "5"},
			{"CodecNarrowingAlias", "codec_version", "65540"},
			{"WrongScope", "replay_scope", "1"},
			{"WrongWrapper", "envelope_wrapper_format", "1"},
			{"NonGeneratedPhysicalID", "claim_rowid", "-1"},
			{"PhaseNarrowingAlias", "phase_tag", "259"},
			{"ProviderNarrowingAlias", "provider_observation_kind", "256"},
			{"TextRevision", "revision", "CAST(revision AS TEXT)"},
			{"TextCaller", "caller_ref", "CAST(caller_ref AS TEXT)"},
			{"EmptyAbsentReceipt", "receipt_ref", "x''"},
			{"DisagreeingIntentTuple", "effect_intent_ref", "NULL"},
			{"ForbiddenTombstoneOperation", "latest_operation_kind", "10"},
		} {
			t.Run(tc.label, func(t *testing.T) {
				fields := strings.Split("claim_rowid, "+sqliteClaimColumns+", "+sqliteReplayColumns, ",")
				found := false
				for i, field := range fields {
					if strings.TrimSpace(field) == tc.field {
						fields[i], found = tc.value, true
					}
				}
				if !found {
					t.Fatalf("column %s was omitted", tc.field)
				}
				query := "SELECT " + strings.Join(fields, ",") + " FROM reliable_submit_claims WHERE claim_rowid=?"
				r, err := scanSQLiteClaim(store.db.QueryRow(query, before.progressRowID))
				if err == nil || r.progressRowID != 0 {
					t.Fatalf("malformed storage hydrated: %v", err)
				}
			})
		}
		for _, stmt := range []string{
			"DELETE FROM reliable_submit_claims",
			"INSERT OR REPLACE INTO reliable_submit_claims SELECT * FROM reliable_submit_claims",
			"UPDATE reliable_submit_claims SET envelope_sha256=randomblob(32)",
			"UPDATE reliable_submit_claims SET claim_rowid=claim_rowid+1",
		} {
			if _, err := store.db.Exec(stmt); err == nil {
				t.Fatal("physical guard permitted replacement, deletion or immutable rewrite")
			}
		}
		if _, err := store.establishClaim(context.Background(), establishClaimCommand{record: before}); !errors.Is(err, errClaimStoreUnsupported) {
			t.Fatalf("legacy establish exposed progress: %v", err)
		}
		if _, err := f.custody.custody.LoadSyntheticClaim(context.Background(), before.claim); err == nil {
			t.Fatal("legacy scope selector accepted progress")
		}
		if !before.equal(f.record()) || !bytes.Equal(sealedBytes, f.object(before)) {
			t.Fatal("refusals changed the row or file")
		}
	})
	t.Run("RetainedRetiredOriginalThenRevocation", func(t *testing.T) {
		f := progressFixture(t)
		f.establish(FixturePendingBeforeAssignment)
		store := f.custody.custody.store
		for _, id := range []string{f.keys.bindingID, f.keys.envelopeID} {
			if err := store.transitionReplayKeyState(context.Background(), id, replayKeyStateRetired); err != nil {
				t.Fatal(err)
			}
		}
		f.step(1, 1, FixtureAssignRun{Run: f.run}, FixtureAssigned)
		if err := store.transitionReplayKeyState(context.Background(), f.keys.envelopeID, replayKeyStateRevoked); err != nil {
			t.Fatal(err)
		}
		state, p, err := f.apply(2, 2, FixtureRecordIntent{Fact: NewFixtureFactRef([32]byte{13})})
		if err == nil || state != FixtureProgressRefused || p.Revision() != 0 || f.record().revision != 2 {
			t.Fatalf("revoked key advanced or disclosed progress: %d %d %v", state, p.Revision(), err)
		}
	})
}

func TestPrivateReplayProgressConcurrencyAndCommitOutcome(t *testing.T) {
	makeReady := func(t *testing.T) *progressTestFixture {
		f := progressFixture(t)
		f.assignAndIntent(FixturePendingBeforeAssignment)
		f.step(3, 3, f.reconciliation(FixtureNoMarker, 14), FixtureAssigned)
		return f
	}
	type observation struct {
		state FixtureProgressDisposition
		p     FixtureProgress
		err   error
	}
	read := func(f *progressTestFixture) observation {
		var p FixtureProgress
		state, err := f.use(f.verify, func(ctx context.Context, access *ProgressAccess) error {
			var err error
			p, err = f.custody.ReadFixtureProgress(ctx, access)
			return err
		})
		return observation{state, p, err}
	}
	t.Run("UnknownMarkerCommitDoesNotRetryWithinInvocation", func(t *testing.T) {
		f := makeReady(t)
		s := f.custody.custody.store
		writes := 0
		s.claimCommit = func(ctx context.Context, conn *sql.Conn) error {
			writes++
			if err := commit(ctx, conn); err != nil {
				t.Fatalf("real write COMMIT: %v", err)
			}
			s.pooledReadTest = &sqlitePooledReadTestHooks{commit: func(ctx context.Context, conn *sql.Conn) error {
				if err := commit(ctx, conn); err != nil {
					t.Fatalf("real recovery read COMMIT: %v", err)
				}
				return errors.New("lost recovery read COMMIT response")
			}}
			return errors.New("lost write COMMIT response")
		}
		state, p, err := f.apply(4, 7, f.markerCommand())
		s.claimCommit, s.pooledReadTest = nil, nil
		if state != FixtureProgressWriteUnknown || p.Revision() != 0 || !errors.Is(err, errClaimStoreCommitUnknown) || writes != 1 {
			t.Fatalf("unknown: %d %d writes=%d err=%v", state, p.Revision(), writes, err)
		}
		f.restart()
		if r := f.record(); r.revision != 5 || !r.effects.dispatch.present() {
			t.Fatal("actual commit did not persist")
		}
	})
	t.Run("IndistinguishableRestartHistoriesHaveSameFixtureEligibility", func(t *testing.T) {
		a := makeReady(t)
		path := a.custody.custody.store.path
		before := a.record()
		errInjected := errors.New("commit dispatch response missing before driver commit")
		writes := 0
		store := a.custody.custody.store
		recoveryReads := 0
		store.claimCommit = func(context.Context, *sql.Conn) error {
			writes++
			store.pooledReadTest = &sqlitePooledReadTestHooks{commit: func(ctx context.Context, conn *sql.Conn) error {
				recoveryReads++
				if err := commit(ctx, conn); err != nil {
					t.Fatal(err)
				}
				return errors.New("lost independent recovery read response")
			}}
			return errInjected
		}
		unknown, p, err := a.apply(4, 7, a.markerCommand())
		store.claimCommit, store.pooledReadTest = nil, nil
		if unknown != FixtureProgressWriteUnknown || p.Revision() != 0 || !errors.Is(err, errClaimStoreCommitUnknown) || writes != 1 || recoveryReads != 1 {
			t.Fatalf("modeled uncertainty: %d %d %d %v", unknown, p.Revision(), writes, err)
		}
		if err := a.custody.Close(); err != nil {
			t.Fatal(err)
		}
		rootB := fixtureReplayRoot(t)
		for _, name := range []string{filepath.Base(path), before.replay.ref} {
			raw, err := os.ReadFile(filepath.Join(a.root, name))
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(rootB, name), raw, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		b := newProgressTestFixture(t, rootB, a.base, a.keys)
		a.open()
		if !before.equal(a.record()) || !a.record().equal(b.record()) || !bytes.Equal(a.object(before), b.object(before)) {
			t.Fatal("restart histories did not retain identical complete evidence")
		}
		t.Run("CurrentReplayDoesNotConfirmPriorUnknown", func(t *testing.T) {
			for _, f := range []*progressTestFixture{a, b} {
				o := read(f)
				if o.err != nil || o.state != FixtureProgressCurrent || o.p.Revision() != 4 || !before.equal(f.record()) {
					t.Fatalf("read claimed write knowledge: %d %d %v", o.state, o.p.Revision(), o.err)
				}
			}
		})
		t.Run("ExplicitLaterFixtureCommandDoesNotConfirmPriorUnknown", func(t *testing.T) {
			for _, f := range []*progressTestFixture{a, b} {
				store := f.custody.custody.store
				later := 0
				store.claimCommit = func(ctx context.Context, conn *sql.Conn) error {
					later++
					return commit(ctx, conn)
				}
				f.step(4, 9, f.markerCommand(), FixtureAssigned)
				store.claimCommit = nil
				if later != 1 || unknown != FixtureProgressWriteUnknown || !f.record().effects.dispatch.present() {
					t.Fatal("later explicit command reused prior attempt or differed by history")
				}
			}
		})
	})
	t.Run("ExistingMarkerExactReplayOnly", func(t *testing.T) {
		f := makeReady(t)
		f.step(4, 7, f.markerCommand(), FixtureAssigned)
		state, p, err := f.apply(4, 7, f.markerCommand())
		if err != nil || state != FixtureProgressExactReplay || p.Revision() != 5 {
			t.Fatalf("exact marker replay: %d %d %v", state, p.Revision(), err)
		}
		wrong := f.markerCommand()
		wrong.Marker = NewFixtureFactRef([32]byte{99})
		state, p, err = f.apply(4, 7, wrong)
		if err != nil || state != FixtureProgressConflict || p.Revision() != 0 {
			t.Fatalf("changed mutation: %d %d %v", state, p.Revision(), err)
		}
		f.reject(5, 8, f.markerCommand())
	})
	t.Run("StaleMarkerAndLateReconciliationReplay", func(t *testing.T) {
		f := makeReady(t)
		f.step(4, 7, f.markerCommand(), FixtureAssigned)
		for _, c := range []struct {
			rev int64
			m   byte
			cmd FixtureProgressCommand
		}{{4, 8, f.markerCommand()}, {3, 3, f.reconciliation(FixtureNoMarker, 14)}} {
			state, p, err := f.apply(c.rev, c.m, c.cmd)
			if err != nil || state != FixtureProgressStale || p.Revision() != 0 {
				t.Fatalf("stale input: %d %d %v", state, p.Revision(), err)
			}
		}
	})
	t.Run("WrongOriginalOrRunCannotAdvance", func(t *testing.T) {
		f := makeReady(t)
		other := f.markerCommand()
		other.Run = NewFixtureRunRef([32]byte{99})
		f.reject(4, 6, other)
		state, err := f.use(func(*ProgressOriginalView) (ProgressOriginalMatch, error) {
			return NewProgressOriginalMatch(f.base.claim, f.base.plan, f.intent, sha256.Sum256([]byte("different original")))
		}, func(context.Context, *ProgressAccess) error {
			t.Fatal("invalid original match granted access")
			return nil
		})
		if err == nil || state != FixtureProgressRefused || f.record().revision != 4 {
			t.Fatalf("wrong original: %d %v", state, err)
		}
	})
	t.Run("FullExactRecordConfirmsOnlyOwnWrite", func(t *testing.T) {
		f := makeReady(t)
		s := f.custody.custody.store
		attempts := 0
		s.claimCommit = func(ctx context.Context, conn *sql.Conn) error {
			attempts++
			if err := commit(ctx, conn); err != nil {
				t.Fatal(err)
			}
			return errors.New("response lost after actual COMMIT")
		}
		state, p, err := f.apply(4, 7, f.markerCommand())
		s.claimCommit = nil
		if err != nil || state != FixtureProgressOwnCommitConfirmed || p.Revision() != 5 || attempts != 1 {
			t.Fatalf("own confirmation: %d %d %d %v", state, p.Revision(), attempts, err)
		}
		f.restart()
		if o := read(f); o.err != nil || o.state != FixtureProgressCurrent || o.p.Revision() != 5 {
			t.Fatalf("restarted read: %+v", o)
		}
	})
	t.Run("AdvanceBetweenAuthenticationAndUse", func(t *testing.T) {
		f := makeReady(t)
		second := newProgressTestFixture(t, f.root, f.base, f.keys)
		var observed FixtureProgress
		report, err := f.use(func(v *ProgressOriginalView) (ProgressOriginalMatch, error) {
			second.step(4, 7, second.markerCommand(), FixtureAssigned)
			return f.verify(v)
		}, func(ctx context.Context, access *ProgressAccess) error {
			var err error
			observed, err = f.custody.ReadFixtureProgress(ctx, access)
			return err
		})
		if err != nil || report != FixtureProgressCurrent || observed.Revision() != 5 {
			t.Fatalf("read did not observe authenticated advancement: %d %d %v", report, observed.Revision(), err)
		}
	})
	t.Run("AdvancedWinnerCannotConfirmEarlierWrite", func(t *testing.T) {
		f := makeReady(t)
		second := newProgressTestFixture(t, f.root, f.base, f.keys)
		s := f.custody.custody.store
		s.claimCommit = func(ctx context.Context, conn *sql.Conn) error {
			if err := commit(ctx, conn); err != nil {
				t.Fatal(err)
			}
			second.step(5, 8, FixtureRecordProvider{Run: f.run, Kind: FixtureProviderPending, Fact: NewFixtureFactRef([32]byte{18})}, FixturePendingAfterAssignment)
			return errors.New("response lost while separate invocation advanced")
		}
		state, p, err := f.apply(4, 7, f.markerCommand())
		s.claimCommit = nil
		if state != FixtureProgressWriteUnknown || p.Revision() != 0 || !errors.Is(err, errClaimStoreCommitUnknown) || f.record().revision != 6 {
			t.Fatalf("advanced winner: %d %d %v", state, p.Revision(), err)
		}
	})
	for _, tc := range []struct {
		name string
		m    byte
		want FixtureProgressDisposition
		rev  int64
	}{{"AuthenticatedEquivalentWinner", 7, FixtureProgressExactReplay, 5}, {"KnownCASLossIsStale", 8, FixtureProgressStale, 0}} {
		t.Run(tc.name, func(t *testing.T) {
			f := makeReady(t)
			second := newProgressTestFixture(t, f.root, f.base, f.keys)
			s := f.custody.custody.store
			cas, commits := 0, 0
			s.progressBeforeCASTest = func() {
				cas++
				second.step(4, 7, second.markerCommand(), FixtureAssigned)
			}
			s.claimCommit = func(ctx context.Context, conn *sql.Conn) error {
				commits++
				return commit(ctx, conn)
			}
			state, p, err := f.apply(4, tc.m, f.markerCommand())
			s.progressBeforeCASTest, s.claimCommit = nil, nil
			if err != nil || state != tc.want || p.Revision() != tc.rev || cas != 1 || commits != 0 {
				t.Fatalf("CAS loss reported wrong disposition or retried: %d %d %d %d %v", state, p.Revision(), cas, commits, err)
			}
			if r := f.record(); r.revision != 5 || !r.effects.dispatch.present() {
				t.Fatal("loser rewrote winner")
			}
		})
	}
	t.Run("CanceledKnownCommitRetainsDisposition", func(t *testing.T) {
		f := makeReady(t)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		l, err := f.custody.LookupProgressOriginal(ctx, f.base.claim)
		if err != nil {
			t.Fatal(err)
		}
		s := f.custody.custody.store
		s.claimCommit = func(ctx context.Context, conn *sql.Conn) error {
			err := commit(ctx, conn)
			cancel()
			return err
		}
		var p FixtureProgress
		var status FixtureProgressDisposition
		_, err = f.custody.WithAuthenticatedProgressOriginal(ctx, l, f.keys, f.intent, ProgressAttempt{}, f.verify, func(access *ProgressAccess) error {
			status, p, err = f.custody.ApplyFixtureProgress(ctx, access, 4, NewFixtureMutationRef([32]byte{9}), f.markerCommand())
			return err
		})
		s.claimCommit = nil
		if err == nil || status != FixtureProgressCommitted || p.Revision() != 0 || f.record().revision != 5 {
			t.Fatalf("known COMMIT projection after cancel: %d %d %v", status, p.Revision(), err)
		}
	})
	t.Run("EstablishmentFullExpectedRecordAndOneUse", func(t *testing.T) {
		f := progressFixture(t)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		l, frozen, pub := f.prepare(ctx, FixturePendingBeforeAssignment)
		s := f.custody.custody.store
		s.claimCommit = func(ctx context.Context, conn *sql.Conn) error {
			if err := commit(ctx, conn); err != nil {
				t.Fatal(err)
			}
			return errors.New("lost establishment COMMIT response")
		}
		a, status, err := f.custody.EstablishProgress(ctx, frozen, pub)
		s.claimCommit = nil
		if !errors.Is(err, errClaimStoreCommitUnknown) || status != FixtureProgressWriteUnknown || !a.token.record.equal(f.record()) {
			t.Fatalf("establishment attempt did not retain full row: %d %v", status, err)
		}
		var invocationCount int
		check := func(access *ProgressAccess) error {
			invocationCount++
			p, err := f.custody.ReadFixtureProgress(ctx, access)
			if err != nil || p.Revision() != 1 {
				t.Fatalf("establishment confirmation projection: %d %v", p.Revision(), err)
			}
			return nil
		}
		status, err = f.custody.WithAuthenticatedProgressOriginal(ctx, l, f.keys, f.intent, a, f.verify, check)
		if err != nil || status != FixtureProgressOwnCommitConfirmed {
			t.Fatalf("establishment own confirmation: %d %v", status, err)
		}
		for _, c := range []context.Context{ctx, context.Background()} {
			status, err = f.custody.WithAuthenticatedProgressOriginal(c, l, f.keys, f.intent, a, f.verify, check)
			if err == nil || status != FixtureProgressRefused || invocationCount != 1 {
				t.Fatalf("spent or foreign proof exposed state: %d %v", status, err)
			}
		}
	})
	for _, tc := range []string{"MissingRecoveryRow", "WrongScopeRecoveryRow"} {
		t.Run(tc, func(t *testing.T) {
			f := progressFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			l, frozen, pub := f.prepare(ctx, FixturePendingBeforeAssignment)
			var createWinner func()
			if tc == "WrongScopeRecoveryRow" {
				legacy, err := OpenPrivateReplayCustody(ctx, f.root)
				if err != nil {
					t.Fatal(err)
				}
				defer legacy.Close()
				original, err := NewPrivateReplayFrozen(f.base.claim, f.base.plan, f.keys, fixtureReplayPayload(t, f.base, f.keys))
				if err != nil {
					t.Fatal(err)
				}
				permit, err := legacy.ReserveSealUse(ctx, original)
				if err != nil {
					t.Fatal(err)
				}
				sealed, err := legacy.PublishSealedSynthetic(ctx, original, permit)
				if err != nil {
					t.Fatal(err)
				}
				createWinner = func() {
					if _, created, err := legacy.EstablishSyntheticClaim(ctx, original, sealed); err != nil || !created {
						t.Fatalf("independent scope-1 winner: %v", err)
					}
				}
			}
			s := f.custody.custody.store
			attempts := 0
			s.claimCommit = func(ctx context.Context, c *sql.Conn) error {
				attempts++
				// Model a write response loss with no committed scope-2 row.
				if _, err := c.ExecContext(ctx, "ROLLBACK"); err != nil {
					t.Fatal(err)
				}
				if createWinner != nil {
					createWinner()
				}
				return errors.New("unconfirmed establishment COMMIT")
			}
			a, state, err := f.custody.EstablishProgress(ctx, frozen, pub)
			s.claimCommit = nil
			if !errors.Is(err, errClaimStoreCommitUnknown) || state != FixtureProgressWriteUnknown || attempts != 1 {
				t.Fatalf("unconfirmed establishment: %d %d %v", state, attempts, err)
			}
			state, err = f.custody.WithAuthenticatedProgressOriginal(ctx, l, f.keys, f.intent, a, f.verify, func(*ProgressAccess) error {
				t.Fatal("unconfirmed attempt with absent or wrong-scope row disclosed progress")
				return nil
			})
			if !errors.Is(err, errClaimStoreCommitUnknown) || state != FixtureProgressWriteUnknown || attempts != 1 {
				t.Fatalf("failed confirmation changed original disposition: %d %d %v", state, attempts, err)
			}
		})
	}
	for _, condition := range []string{"CanceledRecovery", "MissingOriginalDuringRecovery", "CorruptOriginalDuringRecovery", "WrongScopeOriginalDuringRecovery", "PrecommitCanceled"} {
		t.Run(condition, func(t *testing.T) {
			f := makeReady(t)
			before := f.record()
			object := f.object(before)
			path := filepath.Join(f.root, before.replay.ref)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			l, err := f.custody.LookupProgressOriginal(ctx, f.base.claim)
			if err != nil {
				t.Fatal(err)
			}
			store := f.custody.custody.store
			writes := 0
			if condition == "PrecommitCanceled" {
				store.progressBeforeCASTest = cancel
			}
			store.claimCommit = func(ctx context.Context, conn *sql.Conn) error {
				writes++
				if err := commit(ctx, conn); err != nil {
					t.Fatal(err)
				}
				switch condition {
				case "CanceledRecovery":
					cancel()
				case "MissingOriginalDuringRecovery":
					if err := os.Remove(path); err != nil {
						t.Fatal(err)
					}
				case "CorruptOriginalDuringRecovery":
					altered := bytes.Clone(object)
					altered[len(altered)-1] ^= 1
					if err := os.WriteFile(path, altered, 0o600); err != nil {
						t.Fatal(err)
					}
				case "WrongScopeOriginalDuringRecovery":
					_, wrongScope, _ := unclaimedReplaySealedFixture(t, f.base, f.keys)
					if err := os.WriteFile(path, wrongScope, 0o600); err != nil {
						t.Fatal(err)
					}
				}
				return errors.New("lost write COMMIT response")
			}
			var p FixtureProgress
			var status FixtureProgressDisposition
			_, err = f.custody.WithAuthenticatedProgressOriginal(ctx, l, f.keys, f.intent, ProgressAttempt{}, f.verify, func(access *ProgressAccess) error {
				status, p, err = f.custody.ApplyFixtureProgress(ctx, access, 4, NewFixtureMutationRef([32]byte{9}), f.markerCommand())
				return err
			})
			store.claimCommit, store.progressBeforeCASTest = nil, nil
			after := f.record()
			if condition == "PrecommitCanceled" {
				if status != FixtureProgressRefused || err == nil || writes != 0 || !before.equal(after) || p.Revision() != 0 {
					t.Fatalf("precommit cancellation: %d %d %v", status, writes, err)
				}
				return
			}
			if !errors.Is(err, errClaimStoreCommitUnknown) || status != FixtureProgressWriteUnknown || writes != 1 ||
				p.Revision() != 0 || after.revision != 5 || !before.sameProgressOriginal(after) {
				t.Fatalf("failed recovery: status=%d writes=%d err=%v", status, writes, err)
			}
		})
	}
}

// These test-only encoders are independent of the production TLV and domain
// encoders. The deeper semantic structures reuse the codec-3 fixture because
// scope 2 deliberately keeps those selected grammars.
func progressVectorFields(t *testing.T, body []byte) [][]byte {
	t.Helper()
	if len(body) < 2 {
		t.Fatal("fixture object too short")
	}
	count := int(binary.BigEndian.Uint16(body))
	body = body[2:]
	fields := make([][]byte, 0, count)
	for i := 0; i < count; i++ {
		if len(body) < 7 || body[2] != 1 || int(binary.BigEndian.Uint16(body)) != i+1 {
			t.Fatal("fixture field is not the expected consecutive present field")
		}
		n := int(binary.BigEndian.Uint32(body[3:]))
		if len(body) < n+7 {
			t.Fatal("fixture field length")
		}
		fields = append(fields, bytes.Clone(body[7:n+7]))
		body = body[n+7:]
	}
	if len(body) != 0 {
		t.Fatal("trailing fixture fields")
	}
	return fields
}

func progressVectorObject(fields ...[]byte) []byte {
	w := binary.BigEndian.AppendUint16(nil, uint16(len(fields)))
	for i, f := range fields {
		w = binary.BigEndian.AppendUint16(w, uint16(i+1))
		w = append(w, 1)
		w = binary.BigEndian.AppendUint32(w, uint32(len(f)))
		w = append(w, f...)
	}
	return w
}

func progressVectorPayload(fields [][]byte) []byte {
	body := progressVectorObject(fields...)
	header := append([]byte("ESRSPAY2"), 0, 2)
	header = binary.BigEndian.AppendUint32(header, uint32(len(body)))
	return append(header, body...)
}

func progressFixturePayload(t *testing.T, record durableClaimRecord, keys PrivateReplayKeys) []byte {
	t.Helper()
	fields := progressVectorFields(t, fixtureReplayPayload(t, record, keys)[14:])
	prov := progressVectorFields(t, fields[7])
	prov[0] = []byte("synthetic_progress_nonoperational_v1")
	fields[7] = progressVectorObject(prov...)
	formats := progressVectorFields(t, fields[8])
	formats[3], formats[4] = []byte{0, 2}, []byte{0, 2}
	fields[8] = progressVectorObject(formats...)
	fields[9] = []byte{2}
	return progressVectorPayload(fields)
}

func TestPrivateReplayProgressFormatVectors(t *testing.T) {
	t.Run("WrongRootMarker", func(t *testing.T) {
		root := fixtureReplayRoot(t)
		if err := os.WriteFile(filepath.Join(root, "synthetic-replay-v1.marker"), []byte("different fixture marker\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		c, err := OpenPrivateReplayProgressCustody(context.Background(), root)
		if err == nil || c != nil {
			t.Fatal("invalid marker opened a progress fixture")
		}
	})
	record, _ := syntheticReplayRecordFixture(t)
	keys := fixtureReplayKeys(t, 17)
	input := progressFixturePayload(t, record, keys)
	frozen, err := freezeReplayOriginal(progressReplayFormat, record.claim, record.plan, keys, input)
	if err != nil || !frozen.valid() {
		t.Fatalf("independent v2 payload did not freeze: %v", err)
	}
	fields := progressVectorFields(t, input[14:])
	tlv := func(id uint16, value []byte) []byte {
		part := binary.BigEndian.AppendUint16(nil, id)
		part = append(part, 1)
		part = binary.BigEndian.AppendUint32(part, uint32(len(value)))
		return append(part, value...)
	}
	mac := func(domain string, parts ...[]byte) []byte {
		h := hmac.New(sha256.New, keys.binding[:])
		h.Write([]byte(domain))
		for _, part := range parts {
			h.Write(part)
		}
		return h.Sum(nil)
	}
	intent := mac("ESRSINT2", tlv(2, fields[1]))
	info := mac("ESRSCTX2", tlv(6, fields[5]), tlv(7, fields[6]), tlv(8, fields[7]))
	join := progressVectorObject([]byte{0, 1}, []byte{0, 2}, []byte{2}, []byte{0, 1},
		[]byte(keys.bindingID), []byte(keys.envelopeID), frozen.objectID[:],
		record.claim.caller.ref.value, record.claim.submitKey.ref.value, record.plan.binding.ref.value,
		intent, info, binary.BigEndian.AppendUint32(nil, uint32(len(input))), binary.BigEndian.AppendUint32(nil, uint32(len(input)+28)))
	header := append([]byte("ESRSENV2"), 0, 2)
	header = binary.BigEndian.AppendUint32(header, uint32(len(join)+14))
	header = append(header, join...)
	aad := append([]byte("ESRSAAD2"), header...)
	h := sha256.New()
	for _, part := range [][]byte{[]byte("ESRSFRZ2"), keys.bindingFP[:], keys.envelopeFP[:], header, input} {
		h.Write(part)
	}
	if !bytes.Equal(header, frozen.header) || !bytes.Equal(aad, frozen.aad) ||
		!bytes.Equal(intent, frozen.intentMAC[:]) || !bytes.Equal(info, frozen.contextMAC[:]) ||
		!bytes.Equal(h.Sum(nil), frozen.digest[:]) {
		t.Fatal("codec-4 domains, framing, commitments or permit digest diverged from the independent encoding")
	}
	if _, err := parsePrivateReplayPayload(input); err == nil {
		t.Fatal("codec 3 accepted scope-2 payload")
	}
	if _, _, err := parsePrivateReplayHeader(header); err == nil {
		t.Fatal("codec 3 accepted scope-2 header")
	}
	block, err := aes.NewCipher(keys.envelope[:])
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	nonce := bytes.Repeat([]byte{0x72}, gcm.NonceSize()) // Test-only deterministic nonce.
	sealed := gcm.Seal(bytes.Clone(nonce), nonce, input, aad)
	file := append(bytes.Clone(header), sealed...)
	d := replayClaimDescriptor{scope: 2, intentFormat: 1, wrapperFormat: 2, payloadFormat: 2, algorithm: 1,
		ref: replayObjectRef(frozen.objectID), size: int64(len(file)), fileSHA: sha256.Sum256(file),
		bindingKeyID: keys.bindingID, envelopeKeyID: keys.envelopeID, bindingKeyFP: keys.bindingFP, envelopeKeyFP: keys.envelopeFP,
		intentMAC: frozen.intentMAC, contextMAC: frozen.contextMAC}
	got, err := verifyReplayFileBytes(file, record.claim, record.plan, keys, d)
	if err != nil || !bytes.Equal(got, input) {
		t.Fatalf("independently sealed vector: %v", err)
	}
	for _, name := range []string{"mixed scope", "file digest", "object substitution", "wrong version", "wrong envelope material"} {
		t.Run(name, func(t *testing.T) {
			bad := d
			wrong := keys
			switch name {
			case "mixed scope":
				bad.scope, bad.wrapperFormat, bad.payloadFormat = 1, 1, 1
			case "file digest":
				bad.fileSHA[0] ^= 1
			case "object substitution":
				bad.ref = replayObjectRef([32]byte{1})
			case "wrong version":
				bad.payloadFormat = 1
			case "wrong envelope material":
				wrong.envelope[0] ^= 1
			}
			if _, err := verifyReplayFileBytes(file, record.claim, record.plan, wrong, bad); err == nil {
				t.Fatal("corrupted or mixed vector authenticated")
			}
		})
	}
	for _, mutation := range []struct {
		name   string
		mutate func([]byte) []byte
	}{
		{"unknown nested format", func(raw []byte) []byte {
			f := progressVectorFields(t, raw[14:])
			k := progressVectorFields(t, f[8])
			k[4] = []byte{0, 3}
			f[8] = progressVectorObject(k...)
			return progressVectorPayload(f)
		}},
		{"wrong provenance", func(raw []byte) []byte {
			f := progressVectorFields(t, raw[14:])
			p := progressVectorFields(t, f[7])
			p[0] = []byte("synthetic_signed_dependencies_v1")
			f[7] = progressVectorObject(p...)
			return progressVectorPayload(f)
		}},
		{"mixed payload magic", func(raw []byte) []byte { raw[7] = '1'; return raw }},
		{"non-present identity", func(raw []byte) []byte { raw[18] = 0; return raw }},
		{"invalid presence byte", func(raw []byte) []byte { raw[18] = 2; return raw }},
		{"out-of-order first ID", func(raw []byte) []byte { raw[17] = 2; return raw }},
		{"overflow field length", func(raw []byte) []byte {
			binary.BigEndian.PutUint32(raw[19:23], ^uint32(0))
			return raw
		}},
		{"oversize top-level framing", func(raw []byte) []byte {
			return append(raw, make([]byte, 1<<20)...)
		}},
		{"trailing byte", func(raw []byte) []byte { return append(raw, 0) }},
	} {
		t.Run(mutation.name, func(t *testing.T) {
			if _, err := freezeReplayOriginal(progressReplayFormat, record.claim, record.plan, keys, mutation.mutate(bytes.Clone(input))); err == nil {
				t.Fatal("bad input froze")
			}
		})
	}
	t.Run("ParserDepthNodeAndAllocationLimits", func(t *testing.T) {
		encoded := progressVectorObject([]byte{0})
		for _, tc := range []struct {
			name       string
			budget     replayDecodeBudget
			object     int
			containers int
		}{
			{"object-depth", replayDecodeBudget{}, 6, 6},
			{"container-depth", replayDecodeBudget{}, 5, 9},
			{"node-count", replayDecodeBudget{nodes: 32768}, 1, 1},
		} {
			if _, err := parseReplayObject(encoded, 1, &tc.budget, tc.object, tc.containers); err == nil {
				t.Errorf("excess %s accepted", tc.name)
			}
		}
		budget := replayDecodeBudget{leafBytes: 1 << 20, elements: 8192}
		if budget.addLeaf(1) == nil || budget.addElements(1) == nil {
			t.Fatal("aggregate allocation limit was exceeded")
		}
	})
	create, err := newProgressInitialClaim(record.claim, record.plan, durablePhasePendingBeforeAssignment, d, record.createdAt)
	if err != nil {
		t.Fatal(err)
	}
	resolved, inapplicable, err := sqliteWitnessMasks(record.plan.Witness())
	if err != nil {
		t.Fatal(err)
	}
	wire := bytes.NewBufferString("ESRSEST2")
	put := func(v any) {
		if err := binary.Write(wire, binary.BigEndian, v); err != nil {
			t.Fatal(err)
		}
	}
	wire.Write(record.claim.caller.ref.value)
	wire.Write(record.claim.submitKey.ref.value)
	put(uint32(len(record.plan.binding.ref.value)))
	wire.Write(record.plan.binding.ref.value)
	put(uint16(resolved))
	put(uint16(inapplicable))
	put(byte(1))
	put(record.createdAt.UnixNano())
	put(uint16(4))
	put(byte(2))
	put(uint16(1))
	wire.Write(intent)
	wire.Write(info)
	put(uint16(2))
	put(uint16(2))
	put(uint16(1))
	wire.WriteString(d.ref)
	put(uint32(d.size))
	wire.Write(d.fileSHA[:])
	put(uint16(len(d.bindingKeyID)))
	wire.WriteString(d.bindingKeyID)
	wire.Write(d.bindingKeyFP[:])
	put(uint16(len(d.envelopeKeyID)))
	wire.WriteString(d.envelopeKeyID)
	wire.Write(d.envelopeKeyFP[:])
	prefix := append([]byte("es/reliable-submit/durable-operation-input/v1\x00"), 0, 1)
	prefix = binary.BigEndian.AppendUint64(prefix, 0)
	prefix = binary.BigEndian.AppendUint16(prefix, 10)
	prefix = binary.BigEndian.AppendUint32(prefix, uint32(wire.Len()))
	if expected := sha256.Sum256(append(prefix, wire.Bytes()...)); expected != create.latestOperation.binding.value {
		t.Fatal("scope-2 establishment operation preimage differs")
	}
}

func TestPrivateReplayProgressConfirmationEligibility(t *testing.T) {
	for _, route := range []string{"known-commit", "recoverable-unknown", "ordinary-current"} {
		for _, keyState := range []string{"active", "retired", "revoked-binding", "revoked-envelope"} {
			t.Run(route+"/"+keyState, func(t *testing.T) {
				f := progressFixture(t)
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				var lookup ProgressLookup
				var attempt ProgressAttempt
				entry := FixtureProgressCurrent
				if route == "ordinary-current" {
					f.establish(FixturePendingBeforeAssignment)
					var err error
					lookup, err = f.custody.LookupProgressOriginal(ctx, f.base.claim)
					if err != nil {
						t.Fatal(err)
					}
				} else {
					var frozen ProgressFrozen
					var published ProgressPublication
					lookup, frozen, published = f.prepare(ctx, FixturePendingBeforeAssignment)
					var err error
					commits := 0
					store := f.custody.custody.store
					if route == "recoverable-unknown" {
						store.claimCommit = func(callCtx context.Context, conn *sql.Conn) error {
							if err := commit(callCtx, conn); err != nil {
								return err
							}
							commits++
							return errors.New("audit observation seam: response lost after real COMMIT")
						}
					}
					attempt, entry, err = f.custody.EstablishProgress(ctx, frozen, published)
					store.claimCommit = nil
					if route == "known-commit" && (entry != FixtureProgressCommitted || err != nil) {
						t.Fatalf("precondition known commit: %d %v", entry, err)
					}
					if route == "recoverable-unknown" && (entry != FixtureProgressWriteUnknown || !errors.Is(err, errClaimStoreCommitUnknown) ||
						commits != 1 || attempt.token == nil || !attempt.token.recoverable || !attempt.token.record.equal(f.record())) {
						t.Fatalf("precondition one actual commit with recoverable lost response: %d %v, commits %d", entry, err, commits)
					}
				}
				before := f.record()
				sealed := f.object(before)
				other, err := OpenPrivateReplayProgressCustody(ctx, f.root)
				if err != nil {
					t.Fatal(err)
				}
				defer other.Close()
				store := other.custody.store
				calls := 0
				var projection FixtureProgress
				var readErr error
				got, err := f.custody.WithAuthenticatedProgressOriginal(ctx, lookup, f.keys, f.intent, attempt, f.verify,
					func(access *ProgressAccess) error {
						calls++
						// Entry into use follows original authentication. Each transition
						// commits on an independent handle before the read is entered.
						want := replayKeyStateActive
						observedKey := f.keys.envelopeID
						switch keyState {
						case "retired", "revoked-binding", "revoked-envelope":
							for _, id := range []string{f.keys.bindingID, f.keys.envelopeID} {
								if err := store.transitionReplayKeyState(ctx, id, replayKeyStateRetired); err != nil {
									t.Fatal(err)
								}
							}
							want = replayKeyStateRetired
							if strings.HasPrefix(keyState, "revoked-") {
								if keyState == "revoked-binding" {
									observedKey = f.keys.bindingID
								}
								if err := store.transitionReplayKeyState(ctx, observedKey, replayKeyStateRevoked); err != nil {
									t.Fatal(err)
								}
								want = replayKeyStateRevoked
							}
						}
						var actual int
						if err := f.custody.custody.store.db.QueryRowContext(ctx,
							"SELECT state FROM reliable_submit_key_registry WHERE key_id=?", observedKey).Scan(&actual); err != nil || actual != want {
							t.Fatalf("pre-entry registry snapshot: want %d got %d err %v", want, actual, err)
						}
						t.Logf("original authenticated, independent registry state %s visible before ReadFixtureProgress entry", keyState)
						projection, readErr = f.custody.ReadFixtureProgress(ctx, access)
						return readErr
					})
				wantDisposition := entry
				if route == "recoverable-unknown" && !strings.HasPrefix(keyState, "revoked-") {
					wantDisposition = FixtureProgressOwnCommitConfirmed
				}
				t.Logf("establishment/entry disposition=%d outer disposition=%d projected revision=%d phase=%d read error=%v outer error=%v",
					entry, got, projection.Revision(), projection.Phase(), readErr, err)
				if calls != 1 || !before.equal(f.record()) || !bytes.Equal(sealed, f.object(before)) {
					t.Fatal("unexpected callback count or claim/object mutation")
				}
				if strings.HasPrefix(keyState, "revoked-") {
					if got != wantDisposition || projection.Revision() != 0 || readErr == nil || err == nil {
						t.Errorf("revoked original must withhold read, retain disposition %d", wantDisposition)
					}
				} else if got != wantDisposition || err != nil || readErr != nil ||
					projection.Revision() != 1 || projection.Phase() != FixturePendingBeforeAssignment {
					t.Errorf("eligible original must return revision 1, disposition %d", wantDisposition)
				}
			})
		}
	}

	for _, name := range []string{"ReturnedCallback", "CanceledCallback"} {
		t.Run(name, func(t *testing.T) {
			f := progressFixture(t)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			lookup, frozen, publication := f.prepare(ctx, FixturePendingBeforeAssignment)
			attempt, entry, err := f.custody.EstablishProgress(ctx, frozen, publication)
			if entry != FixtureProgressCommitted || err != nil {
				t.Fatalf("establish before lifetime witness: %d %v", entry, err)
			}
			type readResult struct {
				progress FixtureProgress
				err      error
			}
			finished := make(chan readResult, 1)
			before := f.record()
			sealed := f.object(before)
			locked := false
			defer func() {
				if locked {
					f.custody.mu.Unlock()
				}
			}()
			entry, err = f.custody.WithAuthenticatedProgressOriginal(ctx, lookup, f.keys, f.intent, attempt, f.verify,
				func(access *ProgressAccess) error {
					f.custody.mu.Lock()
					locked = true
					go func() {
						progress, err := f.custody.ReadFixtureProgress(ctx, access)
						finished <- readResult{progress, err}
					}()
					for !access.state.used.Load() {
						if ctx.Err() != nil {
							t.Fatal("reader did not pass initial consumption")
						}
						runtime.Gosched()
					}
					t.Log("borrow consumed before release of issuer lock")
					if name == "CanceledCallback" {
						cancel()
						return ctx.Err()
					}
					return nil
				})
			// WithAuthenticatedProgressOriginal has ended the borrow while
			// the reader still cannot acquire the issuer lock.
			f.custody.mu.Unlock()
			locked = false
			if entry != FixtureProgressCommitted || (err != nil) != (name == "CanceledCallback") {
				t.Fatalf("known establishment result changed: %d %v", entry, err)
			}
			select {
			case result := <-finished:
				if result.err == nil || result.progress.Revision() != 0 {
					t.Errorf("in-flight closed borrow projected revision %d", result.progress.Revision())
				}
			case <-time.After(5 * time.Second):
				t.Fatal("reader did not finish after issuer lock release")
			}
			if !before.equal(f.record()) || !bytes.Equal(sealed, f.object(before)) {
				t.Fatal("lifetime refusal changed claim or seal")
			}
		})
	}
}

func TestPrivateReplayProgressReconciliationEligibility(t *testing.T) {
	for _, tc := range []struct {
		name       string
		kind       FixtureReconciliationKind
		phase      FixtureProgressPhase
		compatible FixtureProviderKind
		incompat   FixtureProviderKind
	}{
		{"pending", FixtureReconciledPending, FixturePendingAfterAssignment, FixtureProviderPending, FixtureProviderAmbiguous},
		{"ambiguous", FixtureReconciledAmbiguous, FixtureAmbiguousAfterAssignment, FixtureProviderAmbiguous, FixtureProviderPending},
		{"inconsistent", FixtureReconciledInconsistent, FixtureAmbiguousAfterAssignment, FixtureProviderCallUncertain, FixtureProviderPending},
	} {
		for _, later := range []string{"compatible-provider", "incompatible-provider", "accepted", "not-accepted"} {
			t.Run(fmt.Sprintf("%s/%s", tc.name, later), func(t *testing.T) {
				f := progressFixture(t)
				f.assignAndIntent(FixturePendingBeforeAssignment)
				f.step(3, 3, f.markerCommand(), FixtureAssigned)
				fact := f.reconciliation(tc.kind, 14)
				historical := f.step(4, 4, fact, tc.phase)
				sealed := f.object(historical)
				assertOutcome := func(rev int64, mutation byte, cmd FixtureProgressCommand, want FixtureProgressDisposition, projection int64, wantErr bool) {
					t.Helper()
					before := f.record()
					got, p, err := f.apply(rev, mutation, cmd)
					t.Logf("input predecessor=%d mutation=%d disposition=%d projection revision=%d phase=%d err=%v", rev, mutation, got, p.Revision(), p.Phase(), err)
					_, hasReceipt := p.Receipt()
					if got != want || p.Revision() != projection || (err != nil) != wantErr || (projection == 0 && hasReceipt) {
						t.Errorf("wanted disposition=%d projection=%d error=%t", want, projection, wantErr)
					}
					after := f.record()
					if !before.equal(after) || !historical.effects.reconciliation.equal(after.effects.reconciliation) ||
						!bytes.Equal(sealed, f.object(after)) {
						t.Fatal("no-write input changed durable state, history, or sealed bytes")
					}
				}
				assertOutcome(5, 71, fact, FixtureProgressNoChange, 5, false)
				assertOutcome(4, 4, fact, FixtureProgressExactReplay, 5, false)
				assertOutcome(4, 4, f.reconciliation(tc.kind, 15), FixtureProgressConflict, 0, false)
				switch later {
				case "accepted":
					f.step(5, 5, FixtureAccept{Evidence: f.acceptedEvidence(23, NewFixtureReceiptRef([32]byte{24})), Receipt: NewFixtureReceiptRef([32]byte{24})}, FixtureAccepted)
				case "not-accepted":
					f.step(5, 5, FixtureReject{Evidence: f.terminal(23)}, FixtureProvablyNotAccepted)
				default:
					kind := tc.compatible
					if later == "incompatible-provider" {
						kind = tc.incompat
					}
					phase := FixtureAmbiguousAfterAssignment
					if kind == FixtureProviderPending {
						phase = FixturePendingAfterAssignment
					}
					f.step(5, 5, FixtureRecordProvider{Run: f.run, Kind: kind, Fact: NewFixtureFactRef([32]byte{21})}, phase)
				}
				f.restart()
				assertOutcome(4, 4, fact, FixtureProgressStale, 0, false)
				if later == "compatible-provider" {
					assertOutcome(6, 72, fact, FixtureProgressNoChange, 6, false)
				} else {
					assertOutcome(6, 72, fact, FixtureProgressRefused, 0, true)
				}
			})
		}
	}

	for _, name := range []string{"NoMarker", "AcceptedCorroboration", "NegativeCorroboration", "NegativeWithoutProvider"} {
		t.Run(name, func(t *testing.T) {
			f := progressFixture(t)
			f.assignAndIntent(FixturePendingBeforeAssignment)
			cmd := f.reconciliation(FixtureNoMarker, 14)
			revision := int64(3)
			phase := FixtureAssigned
			if name != "NoMarker" {
				f.step(3, 3, f.markerCommand(), FixtureAssigned)
				revision = 4
				switch name {
				case "AcceptedCorroboration":
					receipt := NewFixtureReceiptRef([32]byte{24})
					f.step(4, 4, FixtureAccept{Evidence: f.acceptedEvidence(23, receipt), Receipt: receipt}, FixtureAccepted)
					cmd, phase, revision = f.reconciliation(FixtureReconciledAccepted, 14), FixtureAccepted, 5
				case "NegativeCorroboration":
					f.step(4, 4, FixtureReject{Evidence: f.terminal(23)}, FixtureProvablyNotAccepted)
					cmd, phase, revision = f.reconciliation(FixtureReconciledNotAccepted, 14), FixtureProvablyNotAccepted, 5
					cmd.Negative = f.terminal(14)
				case "NegativeWithoutProvider":
					cmd, phase = f.reconciliation(FixtureReconciledNotAccepted, 14), FixtureProvablyNotAccepted
					cmd.Negative = f.terminal(14)
				}
			}
			original := f.step(revision, 8, cmd, phase)
			if result, p, err := f.apply(revision, 8, cmd); err != nil || result != FixtureProgressExactReplay || p.Revision() != revision+1 {
				t.Fatalf("own terminal/no-marker replay refused: %d %d %v", result, p.Revision(), err)
			}
			if name == "NegativeWithoutProvider" {
				f.reject(revision+1, 9, cmd)
			} else if result, p, err := f.apply(revision+1, 9, cmd); err != nil || result != FixtureProgressNoChange || p.Revision() != revision+1 {
				t.Fatalf("currently eligible identical tuple refused: %d %d %v", result, p.Revision(), err)
			}
			if !original.equal(f.record()) {
				t.Fatal("no-write classification changed reconciliation")
			}
			if name == "NoMarker" {
				f.step(revision+1, 10, f.markerCommand(), FixtureAssigned)
				f.reject(revision+2, 11, cmd)
			}
		})
	}
}

// Model malformed values that cannot be constructed through the two fixtures'
// public-to-admission constructors.
func malformedFixtureTerminalEvidence(positive, negative FixtureTerminalEvidence, receipt FixtureReceiptRef) (FixtureTerminalEvidence, FixtureTerminalEvidence, FixtureTerminalEvidence) {
	badOutcome, missingReceipt, unexpectedReceipt := positive, positive, negative
	badOutcome.outcome = 99
	missingReceipt.receipt = FixtureReceiptRef{}
	unexpectedReceipt.receipt = receipt
	return badOutcome, missingReceipt, unexpectedReceipt
}

func TestPrivateReplayProgressTerminalEvidenceBinding(t *testing.T) {
	receipt := NewFixtureReceiptRef([32]byte{24})
	otherReceipt := NewFixtureReceiptRef([32]byte{25})
	for _, name := range []string{
		"SubstitutedReceipt", "PositiveAsReject", "PositiveAsNegativeReconciliation", "NegativeAsAccept",
		"ZeroEvidence", "InvalidOutcome", "MissingEvidenceReceipt", "ReceiptOnNegativeEvidence",
		"ZeroCommandReceipt", "WrongClaim", "WrongRun", "WrongMarker", "WrongNegativeFact",
	} {
		t.Run(name, func(t *testing.T) {
			f := progressFixture(t)
			f.assignAndIntent(FixturePendingBeforeAssignment)
			before := f.step(3, 3, f.markerCommand(), FixtureAssigned)
			sealed := f.object(before)
			positive, negative := f.acceptedEvidence(23, receipt), f.terminal(23)
			accept := FixtureAccept{Evidence: positive, Receipt: receipt}
			badOutcome, missingReceipt, unexpectedReceipt := malformedFixtureTerminalEvidence(positive, negative, receipt)
			var command FixtureProgressCommand = accept
			switch name {
			case "SubstitutedReceipt":
				command = FixtureAccept{Evidence: positive, Receipt: otherReceipt}
			case "PositiveAsReject":
				command = FixtureReject{Evidence: positive}
			case "PositiveAsNegativeReconciliation":
				cmd := f.reconciliation(FixtureReconciledNotAccepted, 23)
				cmd.Negative = positive
				command = cmd
			case "NegativeAsAccept":
				command = FixtureAccept{Evidence: negative, Receipt: receipt}
			case "ZeroEvidence":
				command = FixtureAccept{Receipt: receipt}
			case "InvalidOutcome":
				command = FixtureAccept{Evidence: badOutcome, Receipt: receipt}
			case "MissingEvidenceReceipt":
				command = FixtureAccept{Evidence: missingReceipt, Receipt: receipt}
			case "ReceiptOnNegativeEvidence":
				command = FixtureReject{Evidence: unexpectedReceipt}
			case "ZeroCommandReceipt":
				command = FixtureAccept{Evidence: positive}
			case "WrongNegativeFact":
				cmd := f.reconciliation(FixtureReconciledNotAccepted, 25)
				cmd.Negative = negative
				command = cmd
			default:
				claim, run, marker := f.base.claim, f.run, f.marker
				switch name {
				case "WrongClaim":
					claim = mustPrivateClaimID(t, claim.caller, mustPrivateSubmitKeyRef(t, bytes.Repeat([]byte{51}, 32)))
				case "WrongRun":
					run = NewFixtureRunRef([32]byte{51})
				case "WrongMarker":
					marker = NewFixtureFactRef([32]byte{51})
				}
				proof, err := NewFixtureAcceptedEvidence(claim, run, marker, NewFixtureFactRef([32]byte{23}), receipt)
				if err != nil {
					t.Fatal(err)
				}
				command = FixtureAccept{Evidence: proof, Receipt: receipt}
			}
			writes := 0
			store := f.custody.custody.store
			store.claimCommit = func(ctx context.Context, conn *sql.Conn) error {
				writes++
				return commit(ctx, conn)
			}
			state, projection, err := f.apply(4, 4, command)
			store.claimCommit = nil
			if err == nil || state != FixtureProgressRefused || projection.Revision() != 0 || writes != 0 {
				t.Errorf("invalid assertion: disposition=%d revision=%d writes=%d err=%v", state, projection.Revision(), writes, err)
			}
			if !before.equal(f.record()) || !bytes.Equal(sealed, f.object(before)) {
				t.Error("invalid evidence altered the original or durable row")
			}
		})
	}
	for _, accepted := range []bool{true, false} {
		t.Run(fmt.Sprintf("ValidTerminalAccepted%t", accepted), func(t *testing.T) {
			f := progressFixture(t)
			f.assignAndIntent(FixturePendingBeforeAssignment)
			f.step(3, 3, f.markerCommand(), FixtureAssigned)
			if _, err := NewFixtureAcceptedEvidence(f.base.claim, f.run, f.marker, NewFixtureFactRef([32]byte{23}), FixtureReceiptRef{}); err == nil {
				t.Fatal("accepted constructor accepted missing receipt")
			}
			if _, err := NewFixtureNotAcceptedEvidence(f.base.claim, f.run, f.marker, FixtureFactRef{}); err == nil {
				t.Fatal("negative constructor accepted missing fact")
			}
			var command FixtureProgressCommand = FixtureReject{Evidence: f.terminal(23)}
			phase := FixtureProvablyNotAccepted
			if accepted {
				command = FixtureAccept{Evidence: f.acceptedEvidence(23, receipt), Receipt: receipt}
				phase = FixtureAccepted
			}
			row := f.step(4, 4, command, phase)
			f.restart()
			state, p, err := f.apply(4, 4, command)
			got, present := p.Receipt()
			if err != nil || state != FixtureProgressExactReplay || p.Revision() != 5 || p.Phase() != phase ||
				present != accepted || (present && !got.Equal(receipt)) {
				t.Fatalf("valid terminal replay: %d %d %t %v", state, p.Revision(), present, err)
			}
			if accepted {
				f.reject(5, 5, FixtureReject{Evidence: f.terminal(24)})
			}
			f.reject(5, 6, FixtureAccept{Evidence: f.acceptedEvidence(24, otherReceipt), Receipt: otherReceipt})
			if !row.equal(f.record()) {
				t.Fatal("terminal replay or opposite decision changed immutable receipt or claim")
			}
		})
	}
}
