package reliablesubmit

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/binary"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

var (
	operationalStoreFixtureDigestB = [32]byte(bytes.Repeat([]byte{42}, 32))
	operationalStoreFixtureDigestC = [32]byte(bytes.Repeat([]byte{43}, 32))
)

// second opens another custody handle on the fixture's domain. It stands for
// another process: it has its own pool and shares nothing but the files.
func (f *operationalStoreFixture) second() *OperationalCustody {
	f.t.Helper()
	other, err := OpenProvisionedOperationalCustody(context.Background(), f.root)
	if err != nil {
		f.t.Fatal(err)
	}
	f.t.Cleanup(func() { _ = other.Close() })
	return other
}

func (f *operationalStoreFixture) advance(c *OperationalCustody, digest [32]byte, expected uint64) (OperationalAdmissionToken, error) {
	return c.AdvanceOperationalAdmission(context.Background(), operationalStoreFixtureInstallation,
		operationalStoreFixtureEpoch, digest, expected)
}

// admissionSnapshot renders every column of the stored admission row, or
// "absent". An operation that claims to write nothing must leave it equal.
func (f *operationalStoreFixture) admissionSnapshot() string {
	f.t.Helper()
	db := f.c.base.store.db
	var count int
	if err := db.QueryRow("SELECT count(*) FROM reliable_submit_operational_admission").Scan(&count); err != nil || count > 1 {
		f.t.Fatalf("admission rows=%d error=%v", count, err)
	}
	if count == 0 {
		return "absent"
	}
	var singleton, epoch, generation, state, updated int64
	var installation, digest []byte
	if err := db.QueryRow(`SELECT singleton, installation, epoch, generation, admission_digest, state, updated_at_unix_ns
FROM reliable_submit_operational_admission`).Scan(&singleton, &installation, &epoch, &generation, &digest, &state, &updated); err != nil {
		f.t.Fatal(err)
	}
	return fmt.Sprintf("singleton=%d installation=%x epoch=%d generation=%d digest=%x state=%d updated=%d",
		singleton, installation, epoch, generation, digest, state, updated)
}

func (f *operationalStoreFixture) count(query string) int {
	f.t.Helper()
	var n sql.NullInt64
	if err := f.c.base.store.db.QueryRow(query).Scan(&n); err != nil {
		f.t.Fatal(err)
	}
	return int(n.Int64)
}

func (f *operationalStoreFixture) revision() int64 {
	f.t.Helper()
	return int64(f.count("SELECT revision FROM reliable_submit_claims WHERE codec_version=5"))
}

// charged reports the reservations granted, the sealed objects present and
// the operational claims stored.
func (f *operationalStoreFixture) charged() [3]int {
	f.t.Helper()
	entries, err := os.ReadDir(filepath.Join(f.root, "objects", "v1"))
	if err != nil {
		f.t.Fatal(err)
	}
	return [3]int{f.count("SELECT sum(granted_count) FROM reliable_submit_seal_use"), len(entries),
		f.count("SELECT count(*) FROM reliable_submit_claims WHERE codec_version=5")}
}

func requireOperationalAdmissionRefused(t *testing.T, label string, token OperationalAdmissionToken, err error) {
	t.Helper()
	if !errors.Is(err, errOperationalAdmissionRefused) || token.Valid() {
		t.Fatalf("%s: want a refusal and no token, got valid=%t error=%v", label, token.Valid(), err)
	}
}

type operationalWrongToken struct {
	name  string
	token OperationalAdmissionToken
}

// operationalWrongTokens differ from the held token in exactly one field, plus
// the zero token.
func operationalWrongTokens(held OperationalAdmissionToken) []operationalWrongToken {
	edit := func(change func(*OperationalAdmissionToken)) OperationalAdmissionToken {
		out := held
		change(&out)
		return out
	}
	return []operationalWrongToken{
		{"zero token", OperationalAdmissionToken{}},
		{"other installation", edit(func(t *OperationalAdmissionToken) { t.installation[0] ^= 1 })},
		{"other epoch", edit(func(t *OperationalAdmissionToken) { t.epoch++ })},
		{"other generation", edit(func(t *OperationalAdmissionToken) { t.generation++ })},
		{"other digest", edit(func(t *OperationalAdmissionToken) { t.digest[0] ^= 1 })},
	}
}

// operationalCut is one first-effect cut after establishment. The pre-stage
// turn has no operation number: it reads under the writer lock and commits
// nothing.
type operationalForeignMatch struct {
	name  string
	match OperationalOriginalMatch
}

// operationalForeignMatches lists matches that are well formed and differ
// from the borrowed original in exactly one of the four things a match names:
// the claim, the plan binding, the plan witness and the payload digest.
func operationalForeignMatches(t *testing.T, a *OperationalAccess) []operationalForeignMatch {
	t.Helper()
	own := func() OperationalOriginalMatch {
		return OperationalOriginalMatch{claim: a.record.claim, plan: a.record.plan, digest: a.digest}
	}
	claim, binding, witness, digest := own(), own(), own(), own()
	claim.claim = mustPrivateClaimID(t, a.record.claim.caller, mustPrivateSubmitKeyRef(t, bytes.Repeat([]byte{77}, 32)))
	binding.plan = mustPrivateBoundPlan(t, mustPrivatePlanBinding(t, []byte("another-plan-binding")), a.record.plan.Witness())
	// The other witness marks the first category that allows it as explicitly
	// inapplicable; the fixture's witness resolves every category.
	entries := make([]EffectivePlanCategoryCompleteness, 0, len(allEffectivePlanCategories))
	changed := false
	for _, category := range allEffectivePlanCategories {
		entry, err := ResolvedCategory(category)
		if err != nil {
			t.Fatal(err)
		}
		if inapplicable, err := ExplicitlyInapplicableCategory(category); err == nil && !changed {
			entry, changed = inapplicable, true
		}
		entries = append(entries, entry)
	}
	other, err := NewEffectivePlanWitness(entries...)
	if err != nil || !changed {
		t.Fatalf("another complete witness: changed=%t error=%v", changed, err)
	}
	witness.plan = mustPrivateBoundPlan(t, a.record.plan.Binding(), other)
	digest.digest[0] ^= 1
	matches := []operationalForeignMatch{
		{"match for another claim", claim}, {"match for another plan binding", binding},
		{"match for another plan witness", witness}, {"match for another payload digest", digest},
	}
	for _, foreign := range matches {
		if !foreign.match.claim.Valid() || !foreign.match.plan.Valid() || a.matchesOriginal(foreign.match) {
			t.Fatalf("%s is not a valid match for another original", foreign.name)
		}
	}
	if !a.matchesOriginal(own()) {
		t.Fatal("the borrowed original does not match itself")
	}
	return matches
}

type operationalCut struct {
	name     string
	op       OperationalOperation
	revision int64
	success  OperationalDisposition
}

var operationalCuts = []operationalCut{
	{"Assign", OperationalAssign, 1, OperationalApplied},
	{"Intent", OperationalIntent, 2, OperationalApplied},
	{"Prestage", 0, 3, OperationalNoChange},
	{"Stamp", OperationalStamp, 3, OperationalApplied},
	{"Mark", OperationalMark, 4, OperationalMarkerDirect},
}

func (cut operationalCut) command(t *testing.T, a *OperationalAccess, p OperationalProjection) (OperationalCommand, OperationalMutation) {
	t.Helper()
	mutation := operationalTestMutation(t)
	var cmd OperationalCommand
	var err error
	switch cut.op {
	case OperationalAssign:
		cmd, err = NewAssignOperationalRun()
	case OperationalIntent:
		cmd, err = a.BindOperationalIntent(p, [32]byte{31})
	case OperationalStamp:
		raw := testOperationalStagePreimage(p)
		cmd, err = a.BindOperationalStage(p, [32]byte{32}, [32]byte{31}, raw, func() ([]byte, error) { return bytes.Clone(raw), nil })
	case OperationalMark:
		cmd = testOperationalMarker(t, a, p, mutation)
	default:
		t.Fatalf("cut %s has no command", cut.name)
	}
	if err != nil {
		t.Fatal(err)
	}
	return cmd, mutation
}

// attempt performs the cut once. senders counts first-marker callbacks.
func (cut operationalCut) attempt(t *testing.T, a *OperationalAccess, p OperationalProjection,
	qualify OperationalQualification, senders *int) (OperationalDisposition, OperationalProjection) {
	t.Helper()
	return cut.attemptWith(context.Background(), t, a, p, qualify, senders)
}

func (cut operationalCut) attemptWith(ctx context.Context, t *testing.T, a *OperationalAccess, p OperationalProjection,
	qualify OperationalQualification, senders *int) (OperationalDisposition, OperationalProjection) {
	t.Helper()
	if cut.op == 0 {
		return a.Prestage(ctx, p, qualify).Disposition(), OperationalProjection{}
	}
	cmd, mutation := cut.command(t, a, p)
	if marker, ok := cmd.(*OperationalMarkerCandidate); ok {
		return a.ApplyFirstMarker(ctx, p, mutation, marker, qualify, func(OperationalProjection) { *senders++ })
	}
	return a.Apply(ctx, p, mutation, cmd, qualify)
}

// operationalDriveTo applies, with the held token, the writes that precede a
// cut.
func operationalDriveTo(t *testing.T, a *OperationalAccess, p OperationalProjection, revision int64,
	held OperationalAdmissionToken) OperationalProjection {
	t.Helper()
	for _, cut := range operationalCuts {
		if cut.op == 0 || cut.revision < p.Revision() || cut.revision >= revision {
			continue
		}
		unused := 0
		status, next := cut.attempt(t, a, p, testOperationalQualificationWith(a, held), &unused)
		if status != cut.success || next.Revision() != cut.revision+1 {
			t.Fatalf("drive %s: disposition=%d revision=%d", cut.name, status, next.Revision())
		}
		p = next
	}
	if p.Revision() != revision {
		t.Fatalf("drive ended at revision %d, want %d", p.Revision(), revision)
	}
	return p
}

func TestOperationalAdmissionLifecycle(t *testing.T) {
	ctx := context.Background()
	inst, epoch, digestA := operationalStoreFixtureInstallation, operationalStoreFixtureEpoch, operationalStoreFixtureDigest
	digestB, digestC := operationalStoreFixtureDigestB, operationalStoreFixtureDigestC
	otherInst := inst
	otherInst[0] ^= 1
	token := func(generation uint64, digest [32]byte) OperationalAdmissionToken {
		return OperationalAdmissionToken{installation: inst, epoch: epoch, generation: generation, digest: digest}
	}

	t.Run("Commission", func(t *testing.T) {
		f := newUncommissionedOperationalStoreFixture(t, fixtureReplayRoot(t))
		if hint, ok := f.c.base.store.pooledOperationalAdmission(ctx); !ok || hint.Valid() || f.admissionSnapshot() != "absent" {
			t.Fatal("an uncommissioned domain presented a token")
		}
		if err := f.c.WithdrawOperationalAdmission(ctx, token(1, digestA)); !errors.Is(err, errOperationalAdmissionRefused) {
			t.Fatalf("withdrawal of an uncommissioned domain: %v", err)
		}
		early, err := f.advance(f.c, digestB, 1)
		requireOperationalAdmissionRefused(t, "advance of an uncommissioned domain", early, err)
		for _, c := range []struct {
			name         string
			installation [32]byte
			epoch        uint64
			digest       [32]byte
		}{
			{"zero installation", [32]byte{}, epoch, digestA},
			{"zero epoch", inst, 0, digestA},
			{"zero digest", inst, epoch, [32]byte{}},
			{"epoch above the stored range", inst, math.MaxInt64 + 1, digestA},
		} {
			got, err := f.c.CommissionOperationalAdmission(ctx, c.installation, c.epoch, c.digest)
			requireOperationalAdmissionRefused(t, c.name, got, err)
			if f.admissionSnapshot() != "absent" {
				t.Fatalf("%s wrote a row", c.name)
			}
		}
		first, err := f.c.CommissionOperationalAdmission(ctx, inst, epoch, digestA)
		if err != nil || first != token(1, digestA) {
			t.Fatalf("commission: %v", err)
		}
		created := f.admissionSnapshot()
		other := f.second()
		if adopted, err := other.CommissionOperationalAdmission(ctx, inst, epoch, digestA); err != nil || adopted != first ||
			f.admissionSnapshot() != created {
			t.Fatalf("a second process did not adopt the stored generation unchanged: %v", err)
		}
		for _, c := range []struct {
			name         string
			installation [32]byte
			epoch        uint64
			digest       [32]byte
		}{
			{"other digest", inst, epoch, digestB},
			{"other installation", otherInst, epoch, digestA},
			{"other epoch", inst, epoch + 1, digestA},
		} {
			got, err := other.CommissionOperationalAdmission(ctx, c.installation, c.epoch, c.digest)
			requireOperationalAdmissionRefused(t, c.name, got, err)
			if f.admissionSnapshot() != created {
				t.Fatalf("%s changed the row", c.name)
			}
		}
		// Commission never moves the generation: after an advance it adopts the
		// stored generation for the stored content and refuses the old content.
		second, err := f.advance(other, digestB, 1)
		if err != nil || second != token(2, digestB) {
			t.Fatalf("advance: %v", err)
		}
		advanced := f.admissionSnapshot()
		if adopted, err := f.c.CommissionOperationalAdmission(ctx, inst, epoch, digestB); err != nil || adopted != second ||
			f.admissionSnapshot() != advanced {
			t.Fatalf("commission did not adopt the advanced generation unchanged: %v", err)
		}
		got, err := f.c.CommissionOperationalAdmission(ctx, inst, epoch, digestA)
		requireOperationalAdmissionRefused(t, "superseded content", got, err)
		if err := other.WithdrawOperationalAdmission(ctx, second); err != nil {
			t.Fatal(err)
		}
		withdrawn := f.admissionSnapshot()
		got, err = f.c.CommissionOperationalAdmission(ctx, inst, epoch, digestB)
		requireOperationalAdmissionRefused(t, "commission of a withdrawn domain", got, err)
		if f.admissionSnapshot() != withdrawn {
			t.Fatal("a refused commission changed a withdrawn row")
		}
	})

	t.Run("Advance", func(t *testing.T) {
		f := newOperationalStoreFixture(t, fixtureReplayRoot(t))
		other := f.second()
		start := f.admissionSnapshot()
		for _, c := range []struct {
			name         string
			installation [32]byte
			epoch        uint64
			digest       [32]byte
			expected     uint64
		}{
			{"expected generation zero", inst, epoch, digestB, 0},
			{"expected generation ahead of the row", inst, epoch, digestB, 2},
			{"expected generation at the stored limit", inst, epoch, digestB, math.MaxInt64},
			{"same digest", inst, epoch, digestA, 1},
			{"zero digest", inst, epoch, [32]byte{}, 1},
			{"other installation", otherInst, epoch, digestB, 1},
			{"other epoch", inst, epoch + 1, digestB, 1},
		} {
			got, err := f.c.AdvanceOperationalAdmission(ctx, c.installation, c.epoch, c.digest, c.expected)
			requireOperationalAdmissionRefused(t, c.name, got, err)
			if f.admissionSnapshot() != start {
				t.Fatalf("%s changed the row", c.name)
			}
		}
		second, err := f.advance(f.c, digestB, 1)
		if err != nil || second != token(2, digestB) {
			t.Fatalf("advance: %v", err)
		}
		advanced := f.admissionSnapshot()
		if advanced == start {
			t.Fatal("advance wrote nothing")
		}
		if hint, ok := other.base.store.pooledOperationalAdmission(ctx); !ok || hint != second {
			t.Fatal("another process does not read the advanced token")
		}
		// The same call again is the retry after an unknown COMMIT outcome.
		if again, err := f.advance(other, digestB, 1); err != nil || again != second || f.admissionSnapshot() != advanced {
			t.Fatalf("advance is not idempotent by content: %v", err)
		}
		got, err := f.advance(other, digestC, 1)
		requireOperationalAdmissionRefused(t, "advance from a superseded generation", got, err)
		if f.admissionSnapshot() != advanced {
			t.Fatal("a stale advance changed the row")
		}
		// A retry cannot enable a domain that was withdrawn in between, and
		// the withdrawn content cannot be enabled again.
		if err := f.c.WithdrawOperationalAdmission(ctx, second); err != nil {
			t.Fatal(err)
		}
		withdrawn := f.admissionSnapshot()
		got, err = f.advance(other, digestB, 1)
		requireOperationalAdmissionRefused(t, "advance retry after a withdrawal", got, err)
		got, err = f.advance(other, digestB, 2)
		requireOperationalAdmissionRefused(t, "re-enabling the withdrawn content", got, err)
		if f.admissionSnapshot() != withdrawn {
			t.Fatal("a refused advance changed a withdrawn row")
		}
		if hint, ok := other.base.store.pooledOperationalAdmission(ctx); !ok || hint.Valid() {
			t.Fatal("a withdrawn domain presented a token")
		}
		third, err := f.advance(other, digestC, 2)
		if err != nil || third != token(3, digestC) {
			t.Fatalf("advance after withdrawal: %v", err)
		}
		if hint, ok := f.c.base.store.pooledOperationalAdmission(ctx); !ok || hint != third {
			t.Fatal("advance after withdrawal did not enable the next generation")
		}
	})

	t.Run("Withdraw", func(t *testing.T) {
		f := newOperationalStoreFixture(t, fixtureReplayRoot(t))
		other := f.second()
		start := f.admissionSnapshot()
		foreign := f.token
		foreign.installation = otherInst
		laterEpoch := f.token
		laterEpoch.epoch++
		for name, wrong := range map[string]OperationalAdmissionToken{
			"zero token": {}, "other installation": foreign, "other epoch": laterEpoch,
		} {
			if err := f.c.WithdrawOperationalAdmission(ctx, wrong); !errors.Is(err, errOperationalAdmissionRefused) || f.admissionSnapshot() != start {
				t.Fatalf("%s withdrew the domain: %v", name, err)
			}
		}
		second, err := f.advance(other, digestB, 1)
		if err != nil {
			t.Fatal(err)
		}
		// A process fenced at generation 1 can still stop the domain.
		if err := f.c.WithdrawOperationalAdmission(ctx, f.token); err != nil {
			t.Fatalf("withdrawal by a fenced process: %v", err)
		}
		withdrawn := f.admissionSnapshot()
		if !strings.Contains(withdrawn, "generation=2") || !strings.Contains(withdrawn, "state=2") {
			t.Fatalf("withdrawal did not keep the generation and set the state: %s", withdrawn)
		}
		for _, held := range []OperationalAdmissionToken{f.token, second} {
			if err := other.WithdrawOperationalAdmission(ctx, held); err != nil || f.admissionSnapshot() != withdrawn {
				t.Fatalf("withdrawal is not idempotent: %v", err)
			}
		}
	})

	t.Run("ClosedOrCanceled", func(t *testing.T) {
		f := newOperationalStoreFixture(t, fixtureReplayRoot(t))
		other := f.second()
		start := f.admissionSnapshot()
		canceled, cancel := context.WithCancel(ctx)
		cancel()
		if got, err := f.c.AdvanceOperationalAdmission(canceled, inst, epoch, digestB, 1); err == nil || got.Valid() {
			t.Fatal("a canceled advance returned a token")
		}
		if err := f.c.WithdrawOperationalAdmission(canceled, f.token); err == nil {
			t.Fatal("a canceled withdrawal reported success")
		}
		if f.admissionSnapshot() != start {
			t.Fatal("a canceled operation changed the row")
		}
		if err := other.Close(); err != nil {
			t.Fatal(err)
		}
		if got, err := other.CommissionOperationalAdmission(ctx, inst, epoch, digestA); !errors.Is(err, errClaimStoreUnavailable) || got.Valid() {
			t.Fatalf("a closed handle commissioned: %v", err)
		}
		if got, err := other.AdvanceOperationalAdmission(ctx, inst, epoch, digestB, 1); !errors.Is(err, errClaimStoreUnavailable) || got.Valid() {
			t.Fatalf("a closed handle advanced: %v", err)
		}
		if err := other.WithdrawOperationalAdmission(ctx, f.token); !errors.Is(err, errClaimStoreUnavailable) {
			t.Fatalf("a closed handle withdrew: %v", err)
		}
		if other.ConfigureOperationalReleaseProofForProof(func(OperationalOperation) {}) == nil {
			t.Fatal("a closed handle accepted a proof hook")
		}
		if f.admissionSnapshot() != start {
			t.Fatal("a closed handle changed the row")
		}
	})
}

func TestOperationalAdmissionSerializedWriters(t *testing.T) {
	ctx := context.Background()
	inst, epoch := operationalStoreFixtureInstallation, operationalStoreFixtureEpoch
	digests := make([][32]byte, 6)
	for i := range digests {
		digests[i] = [32]byte(bytes.Repeat([]byte{byte(60 + i)}, 32))
	}
	race := func(t *testing.T, f *operationalStoreFixture, call func(c *OperationalCustody, i int) (OperationalAdmissionToken, error)) ([]OperationalAdmissionToken, []error) {
		t.Helper()
		handles := []*OperationalCustody{f.c, f.second(), f.second()}
		tokens, errs := make([]OperationalAdmissionToken, len(digests)), make([]error, len(digests))
		var start, done sync.WaitGroup
		start.Add(1)
		for i := range digests {
			done.Add(1)
			go func() {
				defer done.Done()
				start.Wait()
				tokens[i], errs[i] = call(handles[i%len(handles)], i)
			}()
		}
		start.Done()
		done.Wait()
		return tokens, errs
	}
	winners := func(t *testing.T, tokens []OperationalAdmissionToken, errs []error) []int {
		t.Helper()
		var won []int
		for i := range tokens {
			switch {
			case errs[i] == nil && tokens[i].Valid():
				won = append(won, i)
			case errors.Is(errs[i], errOperationalAdmissionRefused) && !tokens[i].Valid():
			default:
				t.Fatalf("writer %d ended neither written nor refused: %v", i, errs[i])
			}
		}
		return won
	}

	t.Run("CommissionSameContent", func(t *testing.T) {
		f := newUncommissionedOperationalStoreFixture(t, fixtureReplayRoot(t))
		tokens, errs := race(t, f, func(c *OperationalCustody, _ int) (OperationalAdmissionToken, error) {
			return c.CommissionOperationalAdmission(ctx, inst, epoch, digests[0])
		})
		if won := winners(t, tokens, errs); len(won) != len(digests) {
			t.Fatalf("%d of %d equal commissions succeeded", len(won), len(digests))
		}
		for _, got := range tokens {
			if got != tokens[0] || got.generation != 1 {
				t.Fatal("equal commissions returned different tokens")
			}
		}
	})
	t.Run("CommissionDifferentContent", func(t *testing.T) {
		f := newUncommissionedOperationalStoreFixture(t, fixtureReplayRoot(t))
		tokens, errs := race(t, f, func(c *OperationalCustody, i int) (OperationalAdmissionToken, error) {
			return c.CommissionOperationalAdmission(ctx, inst, epoch, digests[i])
		})
		won := winners(t, tokens, errs)
		if len(won) != 1 || tokens[won[0]].generation != 1 || tokens[won[0]].digest != digests[won[0]] {
			t.Fatalf("different commissions: winners=%v", won)
		}
		if stored, ok := f.c.base.store.pooledOperationalAdmission(ctx); !ok || stored != tokens[won[0]] {
			t.Fatal("the stored row is not the single winner's")
		}
	})
	t.Run("AdvanceFromOneGeneration", func(t *testing.T) {
		f := newOperationalStoreFixture(t, fixtureReplayRoot(t))
		tokens, errs := race(t, f, func(c *OperationalCustody, i int) (OperationalAdmissionToken, error) {
			return f.advance(c, digests[i], 1)
		})
		won := winners(t, tokens, errs)
		if len(won) != 1 || tokens[won[0]].generation != 2 || tokens[won[0]].digest != digests[won[0]] {
			t.Fatalf("racing advances: winners=%v", won)
		}
		if stored, ok := f.c.base.store.pooledOperationalAdmission(ctx); !ok || stored != tokens[won[0]] {
			t.Fatal("the stored row is not the single winner's")
		}
	})
	// The three subtests above need the scheduler to overlap two writers, so
	// a missing writer turn does not fail them on every run. This one does
	// not depend on timing. Another process holds the writer lock with a
	// withdrawal it has not committed. Each call is one whose step writes
	// nothing, so only the writer turn itself can make it wait. With no
	// deadline it ends when the store's own busy timeout expires, and it must
	// end unavailable: an answer taken from the committed row would be a
	// decision made outside the writer turn.
	t.Run("NoWriteOutcomeWaitsForTheWriterTurn", func(t *testing.T) {
		f := newOperationalStoreFixture(t, fixtureReplayRoot(t))
		writer, err := f.second().base.store.checkedConn(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer writer.Close()
		if _, err := writer.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
			t.Fatal(err)
		}
		defer writer.ExecContext(ctx, "ROLLBACK")
		result, err := writer.ExecContext(ctx, `UPDATE reliable_submit_operational_admission
SET state=2, updated_at_unix_ns=updated_at_unix_ns+1 WHERE singleton=1 AND state=1`)
		if err != nil {
			t.Fatal(err)
		}
		if affected, err := result.RowsAffected(); err != nil || affected != 1 {
			t.Fatalf("the held writer's withdrawal touched %d rows: %v", affected, err)
		}
		committed := f.admissionSnapshot()
		if !strings.Contains(committed, "generation=1") || !strings.Contains(committed, "state=1") {
			t.Fatalf("the uncommitted withdrawal is visible: %s", committed)
		}
		foreign := f.token
		foreign.installation[0] ^= 1
		calls := []struct {
			name string
			run  func(c *OperationalCustody) (OperationalAdmissionToken, error)
		}{
			{"a commission that would adopt the stored row", func(c *OperationalCustody) (OperationalAdmissionToken, error) {
				return c.CommissionOperationalAdmission(ctx, inst, epoch, operationalStoreFixtureDigest)
			}},
			{"an advance from a generation that is not stored", func(c *OperationalCustody) (OperationalAdmissionToken, error) {
				return f.advance(c, digests[0], 7)
			}},
			{"a withdrawal for another installation", func(c *OperationalCustody) (OperationalAdmissionToken, error) {
				return OperationalAdmissionToken{}, c.WithdrawOperationalAdmission(ctx, foreign)
			}},
		}
		// The calls wait side by side only so that the busy timeout is paid
		// once. None depends on another: each has its own handle and pool.
		handles := []*OperationalCustody{f.c, f.second(), f.second()}
		tokens, errs := make([]OperationalAdmissionToken, len(calls)), make([]error, len(calls))
		var done sync.WaitGroup
		for i := range calls {
			done.Add(1)
			go func() {
				defer done.Done()
				tokens[i], errs[i] = calls[i].run(handles[i])
			}()
		}
		done.Wait()
		for i, call := range calls {
			if !errors.Is(errs[i], errClaimStoreUnavailable) || tokens[i].Valid() {
				t.Errorf("%s was decided while another writer held the turn: valid=%t error=%v", call.name, tokens[i].Valid(), errs[i])
			}
		}
		if got := f.admissionSnapshot(); got != committed {
			t.Fatalf("a waiting call changed the row: %s", got)
		}
		if t.Failed() {
			return
		}
		// Once the writer settles, each call is decided from the row it wrote.
		// The adoption is now refused, which is not what the committed row
		// would have answered while the withdrawal was pending.
		if _, err := writer.ExecContext(ctx, "COMMIT"); err != nil {
			t.Fatal(err)
		}
		withdrawn := f.admissionSnapshot()
		if !strings.Contains(withdrawn, "generation=1") || !strings.Contains(withdrawn, "state=2") {
			t.Fatalf("the writer's withdrawal was not stored: %s", withdrawn)
		}
		for i, call := range calls {
			got, err := call.run(handles[i])
			requireOperationalAdmissionRefused(t, call.name+" after the writer settled", got, err)
		}
		if got := f.admissionSnapshot(); got != withdrawn {
			t.Fatalf("a refused call changed the row: %s", got)
		}
	})
}

func TestOperationalAdmissionTriggers(t *testing.T) {
	inst, digestA := operationalStoreFixtureInstallation[:], operationalStoreFixtureDigest[:]
	otherInst := bytes.Repeat([]byte{99}, 32)
	const (
		insert = `INSERT INTO reliable_submit_operational_admission
(singleton, installation, epoch, generation, admission_digest, state, updated_at_unix_ns) VALUES (?,?,?,?,?,?,?)`
		commission = "invalid operational admission commission"
		identity   = "immutable operational admission identity"
		transition = "invalid operational admission transition"
		regression = "operational admission time regression"
		deletion   = "operational admission deletion is forbidden"
		check      = "CHECK constraint failed"
	)
	type statement struct {
		name, sql string
		args      []any
		message   string
	}
	run := func(t *testing.T, f *operationalStoreFixture, statements []statement) {
		t.Helper()
		before := f.admissionSnapshot()
		for _, s := range statements {
			_, err := f.c.base.store.db.Exec(s.sql, s.args...)
			if err == nil || !strings.Contains(err.Error(), s.message) {
				t.Errorf("%s: want %q, got %v", s.name, s.message, err)
			}
			if after := f.admissionSnapshot(); after != before {
				t.Fatalf("%s changed the row: %s", s.name, after)
			}
		}
	}

	t.Run("EmptyTable", func(t *testing.T) {
		f := newUncommissionedOperationalStoreFixture(t, fixtureReplayRoot(t))
		run(t, f, []statement{
			{"generation two at birth", insert, []any{1, inst, 1, 2, digestA, 1, 5}, commission},
			{"withdrawn at birth", insert, []any{1, inst, 1, 1, digestA, 2, 5}, commission},
			{"second singleton", insert, []any{2, inst, 1, 1, digestA, 1, 5}, commission},
			{"zero installation", insert, []any{1, make([]byte, 32), 1, 1, digestA, 1, 5}, check},
			{"short installation", insert, []any{1, inst[:31], 1, 1, digestA, 1, 5}, check},
			{"zero epoch", insert, []any{1, inst, 0, 1, digestA, 1, 5}, check},
			{"short digest", insert, []any{1, inst, 1, 1, digestA[:31], 1, 5}, check},
			{"zero time", insert, []any{1, inst, 1, 1, digestA, 1, 0}, check},
			{"text digest", insert, []any{1, inst, 1, 1, "digest", 1, 5}, "cannot store TEXT value in BLOB column"},
		})
		// Control: the one valid first row is accepted by the same statement.
		if _, err := f.c.base.store.db.Exec(insert, 1, inst, 1, 1, digestA, 1, 5); err != nil || f.admissionSnapshot() == "absent" {
			t.Fatalf("the valid first row was refused: %v", err)
		}
	})

	t.Run("EnabledRow", func(t *testing.T) {
		f := newOperationalStoreFixture(t, fixtureReplayRoot(t))
		if _, err := f.advance(f.c, operationalStoreFixtureDigestB, 1); err != nil {
			t.Fatal(err)
		}
		const where = " WHERE singleton=1"
		run(t, f, []statement{
			{"delete", "DELETE FROM reliable_submit_operational_admission", nil, deletion},
			{"second row", insert, []any{1, inst, 1, 1, digestA, 1, 5}, commission},
			{"replace the row", strings.Replace(insert, "INSERT INTO", "INSERT OR REPLACE INTO", 1), []any{1, otherInst, 1, 1, digestA, 1, 5}, commission},
			{"installation", "UPDATE reliable_submit_operational_admission SET installation=?" + where, []any{otherInst}, identity},
			{"epoch", "UPDATE reliable_submit_operational_admission SET epoch=epoch+1" + where, nil, identity},
			{"singleton", "UPDATE reliable_submit_operational_admission SET singleton=2" + where, nil, identity},
			{"generation back", "UPDATE reliable_submit_operational_admission SET generation=generation-1, admission_digest=?" + where, []any{digestA}, transition},
			{"generation skip", "UPDATE reliable_submit_operational_admission SET generation=generation+2, admission_digest=?" + where, []any{digestA}, transition},
			{"generation with the same digest", "UPDATE reliable_submit_operational_admission SET generation=generation+1" + where, nil, transition},
			{"digest at the same generation", "UPDATE reliable_submit_operational_admission SET admission_digest=?" + where, []any{digestA}, transition},
			{"withdraw while changing the digest", "UPDATE reliable_submit_operational_admission SET state=2, admission_digest=?" + where, []any{digestA}, transition},
			{"withdraw while advancing", "UPDATE reliable_submit_operational_admission SET state=2, generation=generation+1, admission_digest=?" + where, []any{digestA}, transition},
			{"time alone", "UPDATE reliable_submit_operational_admission SET updated_at_unix_ns=updated_at_unix_ns+1" + where, nil, transition},
			{"time back", "UPDATE reliable_submit_operational_admission SET state=2, updated_at_unix_ns=updated_at_unix_ns-1" + where, nil, regression},
			{"state out of range", "UPDATE reliable_submit_operational_admission SET state=3" + where, nil, transition},
			// The identity and the time are refused inside a statement that is
			// otherwise a selected transition, where no other rule applies.
			{"installation inside a valid advance", "UPDATE reliable_submit_operational_admission SET installation=?, generation=generation+1, admission_digest=?, state=1" + where, []any{otherInst, digestA}, identity},
			{"epoch inside a valid advance", "UPDATE reliable_submit_operational_admission SET epoch=epoch+1, generation=generation+1, admission_digest=?, state=1" + where, []any{digestA}, identity},
			{"installation inside a valid withdrawal", "UPDATE reliable_submit_operational_admission SET installation=?, state=2" + where, []any{otherInst}, identity},
			{"epoch inside a valid withdrawal", "UPDATE reliable_submit_operational_admission SET epoch=epoch+1, state=2" + where, nil, identity},
			{"time back inside a valid advance", "UPDATE reliable_submit_operational_admission SET generation=generation+1, admission_digest=?, state=1, updated_at_unix_ns=updated_at_unix_ns-1" + where, []any{digestA}, regression},
		})
		// A connection that has turned recursive triggers off. REPLACE then
		// removes the conflicting row without firing the delete trigger, so the
		// insert guard is the only rule between these statements and the row.
		ctx := context.Background()
		before := f.admissionSnapshot()
		raw, err := f.c.base.store.db.Conn(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := raw.ExecContext(ctx, "PRAGMA recursive_triggers=OFF"); err != nil {
			t.Fatal(err)
		}
		replace := strings.Replace(insert, "INSERT INTO", "INSERT OR REPLACE INTO", 1)
		for _, s := range []statement{
			{"replace with another installation, recursive triggers off", replace, []any{1, otherInst, 1, 1, digestA, 1, 5}, commission},
			{"replace back to generation one, recursive triggers off", replace, []any{1, inst, 1, 1, digestA, 1, 5}, commission},
		} {
			if _, err := raw.ExecContext(ctx, s.sql, s.args...); err == nil || !strings.Contains(err.Error(), s.message) {
				t.Errorf("%s: want %q, got %v", s.name, s.message, err)
			}
		}
		// Control: the delete guard did not fire on this connection, so it is
		// not what refused the two statements above.
		var recursive int
		if err := raw.QueryRowContext(ctx, "PRAGMA recursive_triggers").Scan(&recursive); err != nil || recursive != 0 {
			t.Fatalf("control: recursive triggers were not off on the raw connection: %d %v", recursive, err)
		}
		if err := raw.Close(); err != nil {
			t.Fatal(err)
		}
		if after := f.admissionSnapshot(); after != before {
			t.Fatalf("REPLACE without recursive triggers changed the row: %s", after)
		}
		// Controls: the two selected transitions are accepted by raw SQL too.
		db := f.c.base.store.db
		if _, err := db.Exec("UPDATE reliable_submit_operational_admission SET state=2" + where); err != nil {
			t.Fatalf("withdraw transition refused: %v", err)
		}
		run(t, f, []statement{
			{"enable at the same generation", "UPDATE reliable_submit_operational_admission SET state=1" + where, nil, transition},
			{"withdraw again by statement", "UPDATE reliable_submit_operational_admission SET state=2" + where, nil, transition},
			{"advance with the withdrawn digest", "UPDATE reliable_submit_operational_admission SET generation=generation+1, state=1" + where, nil, transition},
			{"advance into the withdrawn state", "UPDATE reliable_submit_operational_admission SET generation=generation+1, admission_digest=?, state=2" + where, []any{digestA}, transition},
			{"delete when withdrawn", "DELETE FROM reliable_submit_operational_admission", nil, deletion},
		})
		if _, err := db.Exec("UPDATE reliable_submit_operational_admission SET generation=generation+1, admission_digest=?, state=1"+where, digestA); err != nil {
			t.Fatalf("advance transition refused: %v", err)
		}
		if got := f.admissionSnapshot(); !strings.Contains(got, "generation=3") || !strings.Contains(got, "state=1") ||
			!strings.Contains(got, fmt.Sprintf("digest=%x", digestA)) {
			t.Fatalf("row after the control transitions: %s", got)
		}
	})
}

// operationalRawStep presents one command's row update to the store on a
// connection of its own. It repeats what a writer turn does after its checks
// and leaves out the Go comparison of the admission token, so the store
// trigger is the only admission check between the command and the row.
func operationalRawStep(t *testing.T, a *OperationalAccess, p OperationalProjection, cmd OperationalCommand, m OperationalMutation) error {
	t.Helper()
	ctx := context.Background()
	shape, err := a.operationalCommandShape(p, m, cmd)
	if err != nil {
		t.Fatal(err)
	}
	latest, err := deriveDurableOperationDescriptor(m.value, durableOperationKind(shape.op), claimRevision(p.revision), shape.parts...)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := a.issuer.base.store.checkedConn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := beginImmediate(ctx, conn); err != nil {
		t.Fatal(err)
	}
	committed := false
	defer rollbackIfOpen(ctx, conn, &committed)
	r, k := a.currentForTurn(ctx, conn, p.revision, true)
	if k != OperationalCurrent {
		t.Fatalf("raw step predecessor: %d", k)
	}
	at := normalizeClaimTime(time.Now())
	if r.updatedAt.After(at) {
		at = r.updatedAt
	}
	phase, facts, assigned, err := shape.transition(r, at)
	if err != nil {
		t.Fatal(err)
	}
	next, err := r.withPhaseAndOperation(phase, latest, at, assigned, facts, r.retention)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.ExecContext(ctx, sqliteUpdateOperationalSQL, operationalUpdateArgs(r, next)...); err != nil {
		return err
	}
	if err := commit(ctx, conn); err != nil {
		t.Fatal(err)
	}
	committed = true
	return nil
}

// These tests reach the claim triggers without the Go comparison in front of
// them: the store alone must refuse codec-5 first-effect progress on a domain
// that is not enabled.
func TestOperationalAdmissionClaimGuardsByRawSQL(t *testing.T) {
	ctx := context.Background()
	const refusal = "operational admission unavailable"
	rawInsert := func(t *testing.T, f *operationalStoreFixture) error {
		t.Helper()
		raw := operationalFixturePayload(t, f.base, f.keys, f.root)
		frozen, err := freezeReplayOriginal(operationalReplayFormat, f.base.claim, f.base.plan, f.keys, raw)
		if err != nil {
			t.Fatal(err)
		}
		grant, err := f.c.base.store.reserveReplaySealUse(ctx, f.keys, frozen.digest, false)
		if err != nil {
			t.Fatal(err)
		}
		sealed, err := f.c.base.publishReplayOriginal(ctx, frozen, PrivateReplaySealPermit{permit: grant})
		if err != nil {
			t.Fatal(err)
		}
		mutation, err := randomOperationalMutation()
		if err != nil {
			t.Fatal(err)
		}
		r, err := newOperationalRecord(f.base.claim, f.base.plan, sealed.descriptor, time.Now(), mutation)
		if err != nil {
			t.Fatal(err)
		}
		args, err := sqliteRecordArgs(r)
		if err != nil {
			t.Fatal(err)
		}
		_, err = f.c.base.store.db.Exec(sqliteInsertReplayClaimSQL, args...)
		return err
	}
	for _, state := range []string{"Uncommissioned", "Withdrawn", "Enabled"} {
		t.Run("Insert"+state, func(t *testing.T) {
			var f *operationalStoreFixture
			if state == "Uncommissioned" {
				f = newUncommissionedOperationalStoreFixture(t, fixtureReplayRoot(t))
			} else {
				f = newOperationalStoreFixture(t, fixtureReplayRoot(t))
			}
			if state == "Withdrawn" {
				if err := f.c.WithdrawOperationalAdmission(ctx, f.token); err != nil {
					t.Fatal(err)
				}
			}
			err := rawInsert(t, f)
			claims := f.count("SELECT count(*) FROM reliable_submit_claims WHERE codec_version=5")
			if state == "Enabled" {
				if err != nil || claims != 1 {
					t.Fatalf("control insert on an enabled domain: claims=%d error=%v", claims, err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), refusal) || claims != 0 {
				t.Fatalf("codec-5 insert: claims=%d error=%v", claims, err)
			}
		})
	}
	for _, cut := range operationalCuts {
		if cut.op == 0 {
			continue
		}
		for _, withdrawn := range []bool{false, true} {
			t.Run(fmt.Sprintf("Update%sWithdrawn-%t", cut.name, withdrawn), func(t *testing.T) {
				f := newOperationalStoreFixture(t, fixtureReplayRoot(t))
				other := f.second()
				if f.establish(f.base) != OperationalApplied {
					t.Fatal("establish")
				}
				if f.borrow(f.c, f.base, func(a *OperationalAccess, p OperationalProjection) {
					p = operationalDriveTo(t, a, p, cut.revision, f.token)
					if withdrawn {
						if err := other.WithdrawOperationalAdmission(ctx, f.token); err != nil {
							t.Fatal(err)
						}
					}
					cmd, mutation := cut.command(t, a, p)
					err := operationalRawStep(t, a, p, cmd, mutation)
					if !withdrawn {
						if err != nil || f.revision() != cut.revision+1 {
							t.Fatalf("control update on an enabled domain: revision=%d error=%v", f.revision(), err)
						}
						return
					}
					if err == nil || !strings.Contains(err.Error(), refusal) || f.revision() != cut.revision {
						t.Fatalf("operation kind %d on a withdrawn domain: revision=%d error=%v", cut.op, f.revision(), err)
					}
				}) != OperationalCurrent {
					t.Fatal("original borrow")
				}
			})
		}
	}
	t.Run("AcceptOnWithdrawnDomain", func(t *testing.T) {
		f := newOperationalStoreFixture(t, fixtureReplayRoot(t))
		other := f.second()
		if f.establish(f.base) != OperationalApplied {
			t.Fatal("establish")
		}
		if f.borrow(f.c, f.base, func(a *OperationalAccess, p OperationalProjection) {
			marked := operationalDriveTo(t, a, p, 5, f.token)
			if err := other.WithdrawOperationalAdmission(ctx, f.token); err != nil {
				t.Fatal(err)
			}
			project, realm := [32]byte{32}, [32]byte{31}
			preimage := binary.BigEndian.AppendUint64(a.evidenceInput(marked, project, realm), 74)
			eval := [16]byte{75}
			preimage = append(preimage, eval[:]...)
			proof, err := a.BindVerifiedOperationalObservation(marked, project, realm, preimage, replayHMAC(a.keys.binding, "ESOHEVD1", preimage))
			if err != nil {
				t.Fatal(err)
			}
			// Recording a positive fact for a marker that already exists is not
			// a first effect: neither the Go check nor the trigger gates it.
			status, accepted := a.Apply(ctx, marked, operationalTestMutation(t), proof, nil)
			if status != OperationalApplied || !accepted.Receipt().Valid() || f.revision() != 6 {
				t.Fatalf("accept on a withdrawn domain: disposition=%d revision=%d", status, f.revision())
			}
		}) != OperationalCurrent {
			t.Fatal("original borrow")
		}
	})
	for _, state := range []string{"Uncommissioned", "Withdrawn"} {
		t.Run("OtherCodecsOn"+state+"Domain", func(t *testing.T) {
			var f *operationalStoreFixture
			if state == "Uncommissioned" {
				f = newUncommissionedOperationalStoreFixture(t, fixtureReplayRoot(t))
			} else {
				f = newOperationalStoreFixture(t, fixtureReplayRoot(t))
				if err := f.c.WithdrawOperationalAdmission(ctx, f.token); err != nil {
					t.Fatal(err)
				}
			}
			// Codec 3: a synthetic claim is established.
			legacy, _ := syntheticReplayRecordFixture(t)
			legacyKeys := fixtureReplayKeys(t, 57)
			frozen, err := freezeReplayOriginal(syntheticReplayFormat, legacy.claim, legacy.plan, legacyKeys, fixtureReplayPayload(t, legacy, legacyKeys))
			if err != nil {
				t.Fatal(err)
			}
			permit, err := f.c.base.ReserveSealUse(ctx, frozen)
			if err != nil {
				t.Fatal(err)
			}
			publication, err := f.c.base.PublishSealedSynthetic(ctx, frozen, permit)
			if err != nil {
				t.Fatal(err)
			}
			if _, established, err := f.c.base.EstablishSyntheticClaim(ctx, frozen, publication); err != nil || !established {
				t.Fatalf("codec-3 establishment: %v", err)
			}
			// Codec 4: a progress claim is established, assigned and given an
			// intent, the same update kinds the operational clause refuses.
			base := legacy
			base.claim = mustPrivateClaimID(t, legacy.claim.caller, mustPrivateSubmitKeyRef(t, bytes.Repeat([]byte{66}, 32)))
			progress := newProgressTestFixture(t, f.root, base, fixtureReplayKeys(t, 63))
			progress.assignAndIntent(FixturePendingBeforeAssignment)
			if got := f.count("SELECT count(*) FROM reliable_submit_claims WHERE codec_version IN (3,4)"); got != 2 {
				t.Fatalf("codec 3 and 4 claims stored: %d", got)
			}
			if got := f.count("SELECT revision FROM reliable_submit_claims WHERE codec_version=4"); got != 3 {
				t.Fatalf("codec-4 revision: %d", got)
			}
		})
	}
}

func TestOperationalAdmissionTokenAtEveryCut(t *testing.T) {
	ctx := context.Background()
	t.Run("Establish", func(t *testing.T) {
		f := newOperationalStoreFixture(t, fixtureReplayRoot(t))
		other := f.second()
		raw := operationalFixturePayload(t, f.base, f.keys, f.root)
		attempt := func(token OperationalAdmissionToken) OperationalCheck {
			return f.c.EstablishOperational(ctx, f.base.claim, f.base.plan, f.keys, raw, token)
		}
		// A process that does not hold the stored token is refused before it
		// reserves capacity: nothing is charged, sealed or stored.
		refusedFree := func(label string, token OperationalAdmissionToken) {
			t.Helper()
			check := attempt(token)
			if check.Disposition() != OperationalRefused || check.Reason() != OperationalUnavailable || f.charged() != [3]int{} {
				t.Fatalf("%s: disposition=%d reason=%d charged=%v", label, check.Disposition(), check.Reason(), f.charged())
			}
		}
		for _, wrong := range operationalWrongTokens(f.token) {
			refusedFree(wrong.name, wrong.token)
		}
		if err := other.WithdrawOperationalAdmission(ctx, f.token); err != nil {
			t.Fatal(err)
		}
		refusedFree("withdrawn domain", f.token)
		next, err := f.advance(other, operationalStoreFixtureDigestB, 1)
		if err != nil {
			t.Fatal(err)
		}
		refusedFree("superseded generation", f.token)
		if check := attempt(next); check.Disposition() != OperationalApplied || f.charged() != [3]int{1, 1, 1} {
			t.Fatalf("control establishment with the stored token: disposition=%d charged=%v", check.Disposition(), f.charged())
		}
	})
	for _, cut := range operationalCuts {
		t.Run(cut.name, func(t *testing.T) {
			f := newOperationalStoreFixture(t, fixtureReplayRoot(t))
			other := f.second()
			if f.establish(f.base) != OperationalApplied {
				t.Fatal("establish")
			}
			senders := 0
			if f.borrow(f.c, f.base, func(a *OperationalAccess, p OperationalProjection) {
				p = operationalDriveTo(t, a, p, cut.revision, f.token)
				refused := func(label string, qualify OperationalQualification) {
					t.Helper()
					status, out := cut.attempt(t, a, p, qualify, &senders)
					if status != OperationalRefused || out.Revision() != 0 || f.revision() != cut.revision || senders != 0 {
						t.Fatalf("%s: disposition=%d projection=%d stored=%d senders=%d", label, status, out.Revision(), f.revision(), senders)
					}
				}
				refused("absent qualification", nil)
				for _, wrong := range operationalWrongTokens(f.token) {
					refused(wrong.name, testOperationalQualificationWith(a, wrong.token))
				}
				// A valid match that carries the stored token but describes another
				// original: the cut belongs to the borrowed original only.
				for _, foreign := range operationalForeignMatches(t, a) {
					refused(foreign.name, func(current OperationalAdmissionToken) (OperationalOriginalMatch, error) {
						if current != f.token {
							t.Errorf("%s: the cut did not present the stored token", foreign.name)
						}
						match := foreign.match
						match.admission = current
						return match, nil
					})
				}
				if err := other.WithdrawOperationalAdmission(ctx, f.token); err != nil {
					t.Fatal(err)
				}
				refused("withdrawn domain, held token", testOperationalQualificationWith(a, f.token))
				refused("withdrawn domain, echoed token", testOperationalQualification(a))
				next, err := f.advance(other, operationalStoreFixtureDigestB, 1)
				if err != nil {
					t.Fatal(err)
				}
				refused("superseded generation", testOperationalQualificationWith(a, f.token))
				// Control: the same cut passes with the stored token and nothing else changed.
				status, out := cut.attempt(t, a, p, testOperationalQualificationWith(a, next), &senders)
				wantRevision, wantSenders, wantProjection := cut.revision, 0, int64(0)
				if cut.op != 0 {
					wantRevision++
					wantProjection = wantRevision
				}
				if cut.op == OperationalMark {
					wantSenders = 1
				}
				if status != cut.success || out.Revision() != wantProjection || f.revision() != wantRevision || senders != wantSenders {
					t.Fatalf("control: disposition=%d projection=%d stored=%d senders=%d", status, out.Revision(), f.revision(), senders)
				}
			}) != OperationalCurrent {
				t.Fatal("original borrow")
			}
		})
	}
}

// An advance or a withdrawal that commits after a claim write's COMMIT and
// before its release leaves the write in place and releases nothing: no
// projection and no sender callback.
func TestOperationalAdmissionChangeBetweenCommitAndRelease(t *testing.T) {
	ctx := context.Background()
	for _, cut := range operationalCuts {
		if cut.op == 0 {
			continue
		}
		for _, change := range []string{"Advance", "Withdraw"} {
			t.Run(cut.name+change, func(t *testing.T) {
				f := newOperationalStoreFixture(t, fixtureReplayRoot(t))
				other := f.second()
				if f.establish(f.base) != OperationalApplied {
					t.Fatal("establish")
				}
				observed := 0
				var changeErr error
				if err := f.c.ConfigureOperationalReleaseProofForProof(func(op OperationalOperation) {
					if op != cut.op {
						return
					}
					observed++
					if change == "Advance" {
						_, changeErr = f.advance(other, operationalStoreFixtureDigestB, 1)
					} else {
						changeErr = other.WithdrawOperationalAdmission(ctx, f.token)
					}
				}); err != nil {
					t.Fatal(err)
				}
				senders := 0
				if f.borrow(f.c, f.base, func(a *OperationalAccess, p OperationalProjection) {
					p = operationalDriveTo(t, a, p, cut.revision, f.token)
					held := testOperationalQualificationWith(a, f.token)
					status, out := cut.attempt(t, a, p, held, &senders)
					if observed != 1 || changeErr != nil {
						t.Fatalf("the change did not run once between COMMIT and release: observed=%d error=%v", observed, changeErr)
					}
					if status != OperationalAppliedReleaseFailed || out.Revision() != 0 || senders != 0 || f.revision() != cut.revision+1 {
						t.Fatalf("disposition=%d projection=%d stored=%d senders=%d", status, out.Revision(), f.revision(), senders)
					}
					// The fenced process learns nothing by trying again.
					status, out = cut.attempt(t, a, p, held, &senders)
					if status != OperationalStale || out.Revision() != 0 || senders != 0 || f.revision() != cut.revision+1 || observed != 1 {
						t.Fatalf("retry: disposition=%d projection=%d stored=%d senders=%d", status, out.Revision(), f.revision(), senders)
					}
				}) != OperationalCurrent {
					t.Fatal("original borrow")
				}
			})
		}
	}
}

func TestOperationalAdmissionEstablishTurnIsTheAuthority(t *testing.T) {
	ctx := context.Background()
	f := newOperationalStoreFixture(t, fixtureReplayRoot(t))
	other := f.second()
	raw := operationalFixturePayload(t, f.base, f.keys, f.root)
	// The hint has passed when the reservation asks for its writer turn. An
	// advance by another process commits right there, before the turn begins.
	advances := 0
	var advanceErr error
	f.c.base.store.beginImmediateAttempt = func(ctx context.Context, conn *sql.Conn) error {
		if advances == 0 {
			advances++
			_, advanceErr = f.advance(other, operationalStoreFixtureDigestB, 1)
		}
		_, err := conn.ExecContext(ctx, "BEGIN IMMEDIATE")
		return err
	}
	check := f.c.EstablishOperational(ctx, f.base.claim, f.base.plan, f.keys, raw, f.token)
	f.c.base.store.beginImmediateAttempt = nil
	if advances != 1 || advanceErr != nil {
		t.Fatalf("the advance did not run after the hint: runs=%d error=%v", advances, advanceErr)
	}
	// The reservation was charged, so the hint passed; the establishment turn
	// read the advanced row and stored no claim.
	if got := f.charged(); check.Disposition() != OperationalRefused || check.Reason() != OperationalUnavailable ||
		got[0] != 1 || got[2] != 0 {
		t.Fatalf("disposition=%d reason=%d charged=%v", check.Disposition(), check.Reason(), got)
	}
}

type operationalAdmissionStatement struct {
	owner, verb, text string
}

// operationalAdmissionStatements lists every production string literal that
// names the admission table, with the declaration that contains it. It reads
// statement text, so a statement assembled from fragments is outside it; the
// table's triggers, not this inventory, are what make its installation and
// epoch immutable.
func operationalAdmissionStatements(t *testing.T, sources map[string]string) []operationalAdmissionStatement {
	t.Helper()
	var out []operationalAdmissionStatement
	fset := token.NewFileSet()
	names := make([]string, 0, len(sources))
	for name := range sources {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		file, err := parser.ParseFile(fset, name, sources[name], 0)
		if err != nil {
			t.Fatal(err)
		}
		collect := func(owner string, node ast.Node) {
			ast.Inspect(node, func(n ast.Node) bool {
				lit, ok := n.(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					return true
				}
				text, err := strconv.Unquote(lit.Value)
				if err != nil {
					t.Fatal(err)
				}
				if !strings.Contains(strings.ToLower(text), "operational_admission") {
					return true
				}
				verb := strings.ToUpper(strings.Fields(text)[0])
				out = append(out, operationalAdmissionStatement{owner: owner, verb: verb, text: text})
				return true
			})
		}
		for _, decl := range file.Decls {
			switch d := decl.(type) {
			case *ast.FuncDecl:
				collect(d.Name.Name, d)
			case *ast.GenDecl:
				for _, spec := range d.Specs {
					if value, ok := spec.(*ast.ValueSpec); ok && len(value.Names) > 0 {
						collect(value.Names[0].Name, value)
					} else {
						collect("", spec)
					}
				}
			}
		}
	}
	return out
}

// operationalAdmissionWriterViolations returns what breaks the rule "exactly
// three store functions contain a statement that writes the admission table,
// and no statement updates its singleton, installation or epoch".
func operationalAdmissionWriterViolations(statements []operationalAdmissionStatement) []string {
	want := map[string]string{
		"CommissionOperationalAdmission": "INSERT INTO reliable_submit_operational_admission",
		"AdvanceOperationalAdmission":    "UPDATE reliable_submit_operational_admission",
		"WithdrawOperationalAdmission":   "UPDATE reliable_submit_operational_admission",
	}
	seen := map[string]int{}
	var violations []string
	for _, s := range statements {
		words := operationalSQLWords(s.text)
		has := func(list ...string) bool {
			for _, word := range words {
				for _, wanted := range list {
					if word == wanted {
						return true
					}
				}
			}
			return false
		}
		switch {
		case s.owner == "sqliteMigration5SQL":
			// The schema text: the table, its triggers and the two claim clauses.
		case s.owner == "sqliteSelectOperationalAdmissionSQL":
			if s.verb != "SELECT" || has("INSERT", "UPDATE", "DELETE", "REPLACE", "DROP", "ALTER") {
				violations = append(violations, "the read statement writes: "+s.text)
			}
		case want[s.owner] != "":
			seen[s.owner]++
			if !strings.HasPrefix(s.text, want[s.owner]) || has("REPLACE", "DELETE", "DROP", "ALTER") {
				violations = append(violations, s.owner+" holds an unexpected statement: "+s.text)
			}
			if s.verb == "UPDATE" {
				// The assigned columns are the words between SET and WHERE.
				assigned, inSet, closed := map[string]bool{}, false, false
				for _, word := range words {
					switch {
					case word == "SET":
						inSet = true
					case word == "WHERE":
						inSet, closed = false, true
					case inSet:
						assigned[word] = true
					}
				}
				if !closed || assigned["INSTALLATION"] || assigned["EPOCH"] || assigned["SINGLETON"] {
					violations = append(violations, s.owner+" updates an identity column or has no WHERE: "+s.text)
				}
			}
		default:
			violations = append(violations, "unlisted declaration "+s.owner+" names the admission table: "+s.text)
		}
	}
	for owner := range want {
		if seen[owner] != 1 {
			violations = append(violations, fmt.Sprintf("%s holds %d admission statements, want 1", owner, seen[owner]))
		}
	}
	sort.Strings(violations)
	return violations
}

// operationalSQLWords splits statement text into upper-case identifier words.
func operationalSQLWords(text string) []string {
	return strings.FieldsFunc(strings.ToUpper(text), func(r rune) bool {
		return !(r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_')
	})
}

func TestOperationalAdmissionTableWriters(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil || len(files) == 0 {
		t.Fatalf("package sources: %v", err)
	}
	sources := map[string]string{}
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		raw, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		sources[name] = string(raw)
	}
	statements := operationalAdmissionStatements(t, sources)
	if violations := operationalAdmissionWriterViolations(statements); len(violations) != 0 {
		t.Fatalf("admission table writers:\n%s", strings.Join(violations, "\n"))
	}
	// Positive controls: each way of breaking the rule is reported.
	for name, extra := range map[string]string{
		"FourthWriter": "package reliablesubmit\nfunc reenable(db interface{ Exec(string) }) {\n\tdb.Exec(`UPDATE reliable_submit_operational_admission SET state=1`)\n}\n",
		"IdentityUpdate": "package reliablesubmit\nfunc WithdrawOperationalAdmission(db interface{ Exec(string) }) {\n" +
			"\tdb.Exec(`UPDATE reliable_submit_operational_admission SET epoch=epoch+1, state=2 WHERE singleton=1`)\n}\n",
		"DeleteStatement":  "package reliablesubmit\nconst forget = `DELETE FROM reliable_submit_operational_admission`\n",
		"ReadThatWrites":   "package reliablesubmit\nconst sqliteSelectOperationalAdmissionSQL = `SELECT 1; UPDATE reliable_submit_operational_admission SET state=1`\n",
		"ReplacingInsert":  "package reliablesubmit\nfunc CommissionOperationalAdmission(db interface{ Exec(string) }) {\n\tdb.Exec(`INSERT OR REPLACE INTO reliable_submit_operational_admission VALUES (1)`)\n}\n",
		"UppercaseMention": "package reliablesubmit\nvar other = \"update RELIABLE_SUBMIT_OPERATIONAL_ADMISSION set state=1\"\n",
	} {
		t.Run(name, func(t *testing.T) {
			mutated := map[string]string{"zz_control.go": extra}
			for k, v := range sources {
				mutated[k] = v
			}
			if len(operationalAdmissionWriterViolations(operationalAdmissionStatements(t, mutated))) == 0 {
				t.Fatal("the inventory accepted the control source")
			}
		})
	}
	t.Run("MissingWriter", func(t *testing.T) {
		var without []operationalAdmissionStatement
		for _, s := range statements {
			if s.owner != "AdvanceOperationalAdmission" {
				without = append(without, s)
			}
		}
		if len(operationalAdmissionWriterViolations(without)) == 0 {
			t.Fatal("the inventory accepted a missing writer")
		}
	})
}

// publishedOperationalMigration5 derives the migration-5 text published at
// 8058561 from the amended one by removing exactly what the amendment added:
// the admission table with its three triggers, and the two claim clauses.
func publishedOperationalMigration5(t *testing.T) string {
	t.Helper()
	text := sqliteMigration5SQL
	start := strings.Index(text, "CREATE TABLE reliable_submit_operational_admission (")
	end := strings.Index(text, "CREATE TRIGGER reliable_submit_claims_no_delete")
	if start < 0 || end <= start {
		t.Fatal("the admission table block was not found in migration 5")
	}
	text = text[:start] + text[end:]
	for _, clause := range []string{
		`  SELECT CASE WHEN NEW.codec_version = 5 AND NOT EXISTS (
    SELECT 1 FROM reliable_submit_operational_admission AS a WHERE a.state = 1)
    THEN RAISE(ABORT, 'operational admission unavailable') END;
`,
		`  SELECT CASE WHEN NEW.latest_operation_kind IS NOT 8 AND NOT EXISTS (
      SELECT 1 FROM reliable_submit_operational_admission AS a WHERE a.state = 1)
    THEN RAISE(ABORT, 'operational admission unavailable') END;
`,
	} {
		if strings.Count(text, clause) != 1 {
			t.Fatal("an admission claim clause was not found exactly once in migration 5")
		}
		text = strings.Replace(text, clause, "", 1)
	}
	if strings.Contains(text, "operational_admission") || strings.Contains(text, "operational admission") {
		t.Fatal("the derived text still names the admission table")
	}
	return text
}

// Migration 5 was amended before it merged. A database that holds the shape
// published at 8058561 is refused by every opener, and the refusal changes
// nothing in it.
func TestOperationalAdmissionPublishedSchema5ShapeRefused(t *testing.T) {
	const (
		publishedMigration5SHA256 = "c100749d5ff46ec303a2e0042b53675a2ec6625cc9c6b5f075d4828593acd294"
		publishedSchema5SHA256    = "e1239b294f35da571fdd687f91a92fb2163a3dad8650309c08cec3a9ce0409ed"
	)
	ctx := context.Background()
	published := publishedOperationalMigration5(t)
	if got := sqliteMigrationSHA256(published); got != publishedMigration5SHA256 {
		t.Fatalf("the derived text is not the published migration 5: %s", got)
	}
	if publishedSchema5SHA256 == sqliteSchema5SHA256 || publishedMigration5SHA256 == sqliteMigrationSHA256(sqliteMigration5SQL) {
		t.Fatal("the amended migration is indistinguishable from the published one")
	}
	build := func(t *testing.T, migration5 string) (string, string) {
		t.Helper()
		root := fixtureReplayRoot(t)
		path := filepath.Join(root, "reliable-submit.sqlite3")
		fixtureSchemaVersion(t, path, 4)
		db, err := sql.Open("sqlite", sqliteClaimStoreDSN(path, sqliteDefaultBusyTimeoutMS))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := db.ExecContext(ctx, migration5); err != nil {
			t.Fatal(err)
		}
		m := sqliteClaimStoreMigrations[4]
		if _, err := db.ExecContext(ctx, `INSERT INTO reliable_submit_migrations(version,name,applied_at_unix_ns,source_sha256) VALUES (?,?,?,?)`,
			m.version, m.name, int64(1720000000000000000), sqliteMigrationSHA256(migration5)); err != nil {
			t.Fatal(err)
		}
		if _, err := db.ExecContext(ctx, "PRAGMA user_version=5"); err != nil {
			t.Fatal(err)
		}
		if err := db.Close(); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, 0o600); err != nil {
			t.Fatal(err)
		}
		return root, path
	}
	physical := func(t *testing.T, path string) map[string]string {
		t.Helper()
		out := map[string]string{}
		for _, suffix := range []string{"", "-wal", "-shm", "-journal"} {
			raw, err := os.ReadFile(path + suffix)
			if os.IsNotExist(err) {
				out[suffix] = "absent"
				continue
			}
			if err != nil {
				t.Fatal(err)
			}
			out[suffix] = string(raw)
		}
		return out
	}

	root, path := build(t, published)
	witness := replayLogicalWitness(t, path, 0)
	if witness.version != 5 || witness.digest != publishedSchema5SHA256 || len(witness.ledger) != 5 || len(witness.claims) != 1 {
		t.Fatalf("the fixture is not the published schema 5: version=%d digest=%s ledger=%d claims=%d",
			witness.version, witness.digest, len(witness.ledger), len(witness.claims))
	}
	before := physical(t, path)
	if store, err := openSQLiteClaimStore(ctx, sqliteClaimStoreOptions{path: path}); store != nil || !errors.Is(err, errClaimStoreUnsupported) {
		t.Fatalf("the migrating opener accepted the published shape: %v", err)
	}
	// Each opener answers with its own refusal of a foreign schema: the three
	// that report the store's reason say the format is unsupported, and the
	// operational opener, which reports one reason for every failed open, says
	// unavailable. Any other error would be a failure of the fixture.
	if c, err := OpenPrivateReplayCustody(ctx, root); c != nil || !errors.Is(err, errClaimStoreUnsupported) {
		t.Fatalf("the fixture custody opener did not refuse the published shape as unsupported: %v", err)
	}
	if c, err := OpenPrivateReplayProgressCustody(ctx, root); c != nil || !errors.Is(err, errClaimStoreUnsupported) {
		t.Fatalf("the progress custody opener did not refuse the published shape as unsupported: %v", err)
	}
	if c, err := OpenProvisionedOperationalCustody(ctx, root); c != nil || !errors.Is(err, errClaimStoreUnavailable) {
		t.Fatalf("the operational custody opener did not refuse the published shape as unavailable: %v", err)
	}
	if after := physical(t, path); !reflect.DeepEqual(before, after) {
		t.Fatal("a refused open changed the database files")
	}
	if !reflect.DeepEqual(witness, replayLogicalWitness(t, path, 0)) {
		t.Fatal("a refused open changed the schema, ledger or rows")
	}

	// Control: the same construction with the amended text is the current
	// schema, and every opener accepts it.
	root, path = build(t, sqliteMigration5SQL)
	if current := replayLogicalWitness(t, path, 0); current.digest != sqliteSchema5SHA256 {
		t.Fatalf("the control fixture is not the current schema 5: %s", current.digest)
	}
	store, err := openSQLiteClaimStore(ctx, sqliteClaimStoreOptions{path: path})
	if err != nil {
		t.Fatalf("the migrating opener refused the current shape: %v", err)
	}
	if err := store.close(); err != nil {
		t.Fatal(err)
	}
	fixture, err := OpenPrivateReplayCustody(ctx, root)
	if err != nil {
		t.Fatalf("the fixture custody opener refused the current shape: %v", err)
	}
	if err := fixture.Close(); err != nil {
		t.Fatal(err)
	}
	progress, err := OpenPrivateReplayProgressCustody(ctx, root)
	if err != nil {
		t.Fatalf("the progress custody opener refused the current shape: %v", err)
	}
	if err := progress.Close(); err != nil {
		t.Fatal(err)
	}
	c, err := OpenProvisionedOperationalCustody(ctx, root)
	if err != nil {
		t.Fatalf("the operational custody opener refused the current shape: %v", err)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
}

type operationalAdmissionWriteCase struct {
	name string
	// empty starts from a domain that has no admission row.
	empty bool
	run   func(ctx context.Context, f *operationalStoreFixture) (OperationalAdmissionToken, error)
	// generation is the token a successful call returns; 0 for the
	// withdrawal, which returns none. stored is the row it leaves.
	generation uint64
	stored     string
}

func operationalAdmissionWriteCases() []operationalAdmissionWriteCase {
	return []operationalAdmissionWriteCase{
		{"commission", true, func(ctx context.Context, f *operationalStoreFixture) (OperationalAdmissionToken, error) {
			return f.c.CommissionOperationalAdmission(ctx, operationalStoreFixtureInstallation, operationalStoreFixtureEpoch, operationalStoreFixtureDigest)
		}, 1, fmt.Sprintf("generation=1 digest=%x state=1 ", operationalStoreFixtureDigest)},
		{"advance", false, func(ctx context.Context, f *operationalStoreFixture) (OperationalAdmissionToken, error) {
			return f.c.AdvanceOperationalAdmission(ctx, operationalStoreFixtureInstallation, operationalStoreFixtureEpoch,
				operationalStoreFixtureDigestB, 1)
		}, 2, fmt.Sprintf("generation=2 digest=%x state=1 ", operationalStoreFixtureDigestB)},
		{"withdrawal", false, func(ctx context.Context, f *operationalStoreFixture) (OperationalAdmissionToken, error) {
			return OperationalAdmissionToken{}, f.c.WithdrawOperationalAdmission(ctx, f.token)
		}, 0, fmt.Sprintf("generation=1 digest=%x state=2 ", operationalStoreFixtureDigest)},
	}
}

func (test operationalAdmissionWriteCase) fixture(t *testing.T) *operationalStoreFixture {
	t.Helper()
	if test.empty {
		return newUncommissionedOperationalStoreFixture(t, fixtureReplayRoot(t))
	}
	return newOperationalStoreFixture(t, fixtureReplayRoot(t))
}

// requireWritten runs the operation and requires success, the wanted token
// and the wanted stored row.
func (test operationalAdmissionWriteCase) requireWritten(t *testing.T, f *operationalStoreFixture, label string) string {
	t.Helper()
	token, err := test.run(context.Background(), f)
	snapshot := f.admissionSnapshot()
	if err != nil || token.Valid() != (test.generation != 0) || token.generation != test.generation || !strings.Contains(snapshot, test.stored) {
		t.Fatalf("%s: error=%v token generation=%d stored=%s", label, err, token.generation, snapshot)
	}
	return snapshot
}

// An admission write whose COMMIT answer is lost reports an unknown outcome,
// whether the row was written or not. The same call again converges on the
// wanted row, and it does not write a second time.
func TestOperationalAdmissionCommitAnswerLost(t *testing.T) {
	lost := errors.New("the COMMIT answer was lost")
	for _, test := range operationalAdmissionWriteCases() {
		for _, written := range []bool{true, false} {
			name := test.name + "/row not written"
			if written {
				name = test.name + "/row written"
			}
			t.Run(name, func(t *testing.T) {
				f := test.fixture(t)
				before := f.admissionSnapshot()
				attempts := 0
				f.c.admissionCommit = func(ctx context.Context, conn *sql.Conn) error {
					attempts++
					if written {
						if err := commit(ctx, conn); err != nil {
							t.Errorf("the real COMMIT failed: %v", err)
						}
					}
					return lost
				}
				token, err := test.run(context.Background(), f)
				f.c.admissionCommit = nil
				if !errors.Is(err, errClaimStoreCommitUnknown) || token.Valid() || attempts != 1 {
					t.Fatalf("lost answer: want the unknown-outcome error and no token, got valid=%t error=%v attempts=%d", token.Valid(), err, attempts)
				}
				after := f.admissionSnapshot()
				if written == (after == before) {
					t.Fatalf("stored row: written=%t before=%s after=%s", written, before, after)
				}
				if written && !strings.Contains(after, test.stored) {
					t.Fatalf("the committed row is not the wanted one: %s", after)
				}
				// Another handle on the same files sees the same row and converges
				// the same way as the caller that lost the answer.
				converged := test.requireWritten(t, f, "the same call again")
				if written && converged != after {
					t.Fatalf("the second call wrote again: %s then %s", after, converged)
				}
				if again := test.requireWritten(t, f, "a third call"); again != converged {
					t.Fatalf("a third call wrote: %s then %s", converged, again)
				}
			})
		}
	}
}

// operationalEndingContext reports its end through Err only. Its Done channel
// is nil, so neither database/sql nor the driver watches it, and the looks of
// the store's own code are the only instants at which its end can be seen.
// The first live looks see a live context and every later one an ended one.
type operationalEndingContext struct {
	context.Context
	live  int64
	looks atomic.Int64
}

func (c *operationalEndingContext) Err() error {
	if c.looks.Add(1) > c.live {
		return context.Canceled
	}
	return nil
}

// A context that ends after the written row was read back commits nothing:
// the writer turn looks at the context once more immediately before COMMIT,
// rolls back and reports the store as unavailable. A call that finds the
// wanted row writes nothing and takes the same looks as a writing call up to
// its step, so the next look of a writing call is the one before COMMIT.
func TestOperationalAdmissionWriteLooksAtTheContextBeforeCommit(t *testing.T) {
	for _, test := range operationalAdmissionWriteCases() {
		t.Run(test.name, func(t *testing.T) {
			settled := test.fixture(t)
			wanted := test.requireWritten(t, settled, "the call that writes")
			unchanged := &operationalEndingContext{Context: context.Background(), live: math.MaxInt64}
			if _, err := test.run(unchanged, settled); err != nil || settled.admissionSnapshot() != wanted || unchanged.looks.Load() == 0 {
				t.Fatalf("the call that finds the wanted row: error=%v looks=%d stored=%s", err, unchanged.looks.Load(), settled.admissionSnapshot())
			}
			prefix := unchanged.looks.Load()

			f := test.fixture(t)
			before := f.admissionSnapshot()
			var attempts, looksAtCommit int64
			var current *operationalEndingContext
			f.c.admissionCommit = func(ctx context.Context, conn *sql.Conn) error {
				attempts++
				looksAtCommit = current.looks.Load()
				return commit(ctx, conn)
			}
			defer func() { f.c.admissionCommit = nil }()
			// The context ends after the looks of the step: the write was made
			// and read back, and the look before COMMIT finds the context ended.
			current = &operationalEndingContext{Context: context.Background(), live: prefix}
			token, err := test.run(current, f)
			if !errors.Is(err, errClaimStoreUnavailable) || token.Valid() || attempts != 0 || current.looks.Load() != prefix+1 {
				t.Fatalf("context ended before COMMIT: want the unavailable error, no token and no COMMIT, got valid=%t error=%v attempts=%d looks=%d of %d",
					token.Valid(), err, attempts, current.looks.Load(), prefix+1)
			}
			if after := f.admissionSnapshot(); after != before {
				t.Fatalf("a call whose context ended before COMMIT changed the row: %s then %s", before, after)
			}
			// One live look more and the same call commits. The look before
			// COMMIT is therefore the only one between the step and COMMIT.
			current = &operationalEndingContext{Context: context.Background(), live: prefix + 1}
			token, err = test.run(current, f)
			after := f.admissionSnapshot()
			if err != nil || attempts != 1 || looksAtCommit != prefix+1 || token.generation != test.generation || !strings.Contains(after, test.stored) {
				t.Fatalf("one look more: error=%v attempts=%d looks at COMMIT=%d of %d token generation=%d stored=%s",
					err, attempts, looksAtCommit, prefix+1, token.generation, after)
			}
		})
	}
}

// The writer turn of a cut does the same. The context ends one look later in
// each attempt until the cut commits. The last attempt that commits nothing is
// stopped by the turn itself: its step had completed, it rolled back and it
// reports that nothing was applied, where an earlier end is a refusal of the
// step.
func TestOperationalHandoffCutLooksAtTheContextBeforeCommit(t *testing.T) {
	for _, cut := range operationalCuts {
		if cut.op == 0 {
			continue // the pre-stage turn writes nothing
		}
		t.Run(cut.name, func(t *testing.T) {
			f := newOperationalStoreFixture(t, fixtureReplayRoot(t))
			if f.establish(f.base) != OperationalApplied {
				t.Fatal("establish")
			}
			committed := false
			if f.borrow(f.c, f.base, func(a *OperationalAccess, p OperationalProjection) {
				p = operationalDriveTo(t, a, p, cut.revision, f.token)
				senders := 0
				previous := OperationalRefused
				for live := int64(0); live < 1000; live++ {
					ctx := &operationalEndingContext{Context: context.Background(), live: live}
					status, _ := cut.attemptWith(ctx, t, a, p, testOperationalQualificationWith(a, f.token), &senders)
					if f.revision() != cut.revision {
						if previous != OperationalDefinitelyNotApplied || f.revision() != cut.revision+1 {
							t.Fatalf("the cut committed with %d live looks, and with one fewer it answered %d (stored revision %d)",
								live, previous, f.revision())
						}
						committed = true
						return
					}
					if senders != 0 {
						t.Fatalf("an attempt that committed nothing reached the sender with %d live looks", live)
					}
					previous = status
				}
			}) != OperationalCurrent || !committed {
				t.Fatalf("borrow: committed=%t", committed)
			}
		})
	}
}

// A process whose clock is behind the time another process stored keeps the
// stored time. The row's time never goes back, so the trigger that forbids a
// regression is not reached and the write is not refused for the clock.
func TestOperationalAdmissionStoredTimeAheadOfTheClock(t *testing.T) {
	ctx := context.Background()
	f := newUncommissionedOperationalStoreFixture(t, fixtureReplayRoot(t))
	ahead := time.Now().Add(24 * time.Hour).UnixNano()
	if _, err := f.c.base.store.db.Exec(`INSERT INTO reliable_submit_operational_admission
(singleton, installation, epoch, generation, admission_digest, state, updated_at_unix_ns)
VALUES (1, ?, ?, 1, ?, 1, ?)`, operationalStoreFixtureInstallation[:], int64(operationalStoreFixtureEpoch), operationalStoreFixtureDigest[:], ahead); err != nil {
		t.Fatal(err)
	}
	want := func(label string, generation int, state int) {
		t.Helper()
		if got := f.admissionSnapshot(); !strings.Contains(got, fmt.Sprintf("generation=%d ", generation)) ||
			!strings.HasSuffix(got, fmt.Sprintf(" state=%d updated=%d", state, ahead)) {
			t.Fatalf("%s: stored row %s, want generation %d, state %d and the stored time %d", label, got, generation, state, ahead)
		}
	}
	token, err := f.c.CommissionOperationalAdmission(ctx, operationalStoreFixtureInstallation, operationalStoreFixtureEpoch, operationalStoreFixtureDigest)
	if err != nil || token.generation != 1 {
		t.Fatalf("adopting the seeded row: generation=%d error=%v", token.generation, err)
	}
	want("adopted", 1, 1)
	next, err := f.advance(f.c, operationalStoreFixtureDigestB, 1)
	if err != nil || next.generation != 2 {
		t.Fatalf("advance with a clock behind the stored time: generation=%d error=%v", next.generation, err)
	}
	want("advanced", 2, 1)
	if err := f.c.WithdrawOperationalAdmission(ctx, next); err != nil {
		t.Fatalf("withdrawal with a clock behind the stored time: %v", err)
	}
	want("withdrawn", 2, 2)
}

// The write verifies inside its transaction that the database still has the
// current schema. A database that has moved on is refused by all three
// operations, and nothing is written.
func TestOperationalAdmissionWriteRequiresCurrentStore(t *testing.T) {
	for _, test := range operationalAdmissionWriteCases() {
		t.Run(test.name, func(t *testing.T) {
			f := test.fixture(t)
			before := f.admissionSnapshot()
			version := func(value int) {
				t.Helper()
				if _, err := f.c.base.store.db.Exec(fmt.Sprintf("PRAGMA user_version=%d", value)); err != nil {
					t.Fatal(err)
				}
			}
			version(sqliteClaimStoreSchemaVersion + 1)
			token, err := test.run(context.Background(), f)
			if !errors.Is(err, errClaimStoreUnavailable) || token.Valid() {
				t.Fatalf("a newer schema version: want unavailable and no token, got valid=%t error=%v", token.Valid(), err)
			}
			if after := f.admissionSnapshot(); after != before {
				t.Fatalf("a refused write changed the row: %s then %s", before, after)
			}
			// Control: with the version restored the same call writes, so the
			// refusal above came from the version and nothing else.
			version(sqliteClaimStoreSchemaVersion)
			test.requireWritten(t, f, "control with the current version")
		})
	}
}

// Before COMMIT the write function reads the row back and requires it to
// equal what the step reported. A step that reports another row than the one
// it stored is refused and rolled back.
func TestOperationalAdmissionWriteReadsBackBeforeCommit(t *testing.T) {
	ctx := context.Background()
	f := newOperationalStoreFixture(t, fixtureReplayRoot(t))
	before := f.admissionSnapshot()
	withdraw := func(honest bool) (operationalAdmissionRow, error) {
		return f.c.operationalAdmissionWrite(ctx, func(conn *sql.Conn, row operationalAdmissionRow, now int64) (operationalAdmissionRow, bool, error) {
			result, err := conn.ExecContext(ctx, `UPDATE reliable_submit_operational_admission
SET state=2, updated_at_unix_ns=? WHERE singleton=1 AND state=1`, now)
			if err != nil {
				return operationalAdmissionRow{}, false, err
			}
			if affected, err := result.RowsAffected(); err != nil || affected != 1 {
				t.Errorf("the step's own write: affected=%d error=%v", affected, err)
			}
			row.updatedAt = now
			if honest {
				row.state = operationalAdmissionWithdrawn
			}
			return row, true, nil
		})
	}
	if row, err := withdraw(false); !errors.Is(err, errClaimStoreUnavailable) || row != (operationalAdmissionRow{}) {
		t.Fatalf("a step that misreports its write: row present=%t error=%v", row.present, err)
	}
	if after := f.admissionSnapshot(); after != before {
		t.Fatalf("the refused write was not rolled back: %s then %s", before, after)
	}
	row, err := withdraw(true)
	if err != nil || row.state != operationalAdmissionWithdrawn || !strings.Contains(f.admissionSnapshot(), " state=2 ") {
		t.Fatalf("control: state=%d error=%v stored=%s", row.state, err, f.admissionSnapshot())
	}
}
