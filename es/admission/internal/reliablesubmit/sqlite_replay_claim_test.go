package reliablesubmit

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
)

func syntheticReplayRecordFixture(t *testing.T) (durableClaimRecord, replayClaimDescriptor) {
	t.Helper()
	f := newDurableFixture(t)
	f.caller = mustPrivateCallerRef(t, bytes.Repeat([]byte{0x11}, 32))
	f.submitKey = mustPrivateSubmitKeyRef(t, bytes.Repeat([]byte{0x22}, 32))
	f.claim = mustPrivateClaimID(t, f.caller, f.submitKey)
	d := replayClaimDescriptor{
		scope: 1, intentFormat: 1, wrapperFormat: 1, payloadFormat: 1,
		algorithm: 1, ref: "objects/v1/" + strings.Repeat("a", 64), size: 100,
		bindingKeyID: "Binding-A", envelopeKeyID: "Envelope-A",
	}
	d.intentMAC[0] = 1
	d.contextMAC[0] = 2
	d.fileSHA[0] = 3
	d.bindingKeyFP[0] = 4
	d.envelopeKeyFP[0] = 5
	record, err := newReplayDurableClaimRecord(f.claim, f.plan, d, f.now)
	if err != nil {
		t.Fatalf("new synthetic record: %v", err)
	}
	return record, d
}

func registerSyntheticRecordKeys(t *testing.T, store *sqliteClaimStore, d replayClaimDescriptor) {
	t.Helper()
	for _, key := range []struct {
		id      string
		purpose int
		fp      [32]byte
	}{
		{d.bindingKeyID, 1, d.bindingKeyFP}, {d.envelopeKeyID, 2, d.envelopeKeyFP},
	} {
		if _, err := store.db.Exec(`INSERT INTO reliable_submit_key_registry(key_id,purpose,material_fingerprint,state) VALUES (?,?,?,1)`, key.id, key.purpose, key.fp[:]); err != nil {
			t.Fatal(err)
		}
	}
}

func TestSQLiteV3TargetedSameKeyClaimLoad(t *testing.T) {
	ctx := context.Background()
	store := mustOpenSQLiteClaimStore(t, sqliteTestPath(t, "state", "targeted.sqlite3"))
	defer store.close()
	record, d := syntheticReplayRecordFixture(t)
	registerSyntheticRecordKeys(t, store, d)
	first, err := store.establishClaim(ctx, establishClaimCommand{record: record})
	if err != nil || !first.created {
		t.Fatalf("first insert: %v", err)
	}
	again, err := store.establishClaim(ctx, establishClaimCommand{record: record})
	if err != nil || again.created || !again.record.equal(record) {
		t.Fatalf("same key conflict target: %v", err)
	}
	changedDescriptor := d
	changedDescriptor.ref = "objects/v1/" + strings.Repeat("b", 64)
	changed, err := newReplayDurableClaimRecord(record.claim, record.plan, changedDescriptor, record.createdAt)
	if err != nil {
		t.Fatal(err)
	}
	winner, err := store.establishClaim(ctx, establishClaimCommand{record: changed})
	if err != nil || winner.created || !winner.record.equal(record) {
		t.Fatalf("same-key changed proposal did not load original: %v", err)
	}
	otherCaller, err := NewCallerRef(bytes.Repeat([]byte{0x33}, 32))
	if err != nil {
		t.Fatal(err)
	}
	otherClaim, err := NewClaimID(otherCaller, record.claim.submitKey)
	if err != nil {
		t.Fatal(err)
	}
	other, err := newReplayDurableClaimRecord(otherClaim, record.plan, d, record.createdAt)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.establishClaim(ctx, establishClaimCommand{record: other}); err == nil {
		t.Fatal("unrelated envelope uniqueness conflict was ignored")
	}
	loaded, err := store.loadClaim(ctx, loadClaimQuery{claim: record.claim})
	if err != nil || !loaded.equal(record) {
		t.Fatalf("winner changed: %v", err)
	}
}

func TestSQLiteV3OrdinaryInsertLoadRetireAndIncrement(t *testing.T) {
	ctx := context.Background()
	store := mustOpenSQLiteClaimStore(t, sqliteTestPath(t, "state", "synthetic.sqlite3"))
	defer store.close()
	record, descriptor := syntheticReplayRecordFixture(t)
	for _, key := range []struct {
		id      string
		purpose int
		fp      [32]byte
	}{
		{descriptor.bindingKeyID, 1, descriptor.bindingKeyFP},
		{descriptor.envelopeKeyID, 2, descriptor.envelopeKeyFP},
	} {
		if _, err := store.db.ExecContext(ctx, `INSERT INTO reliable_submit_key_registry
(key_id,purpose,material_fingerprint,state) VALUES (?,?,?,1)`, key.id, key.purpose, key.fp[:]); err != nil {
			t.Fatal(err)
		}
	}
	created, err := store.establishClaim(ctx, establishClaimCommand{record: record})
	if err != nil {
		t.Fatalf("establish: %v", err)
	}
	if !created.created || !created.record.equal(record) {
		t.Fatal("created row mismatch")
	}
	loaded, err := store.loadClaim(ctx, loadClaimQuery{claim: record.claim})
	if err != nil || !loaded.equal(record) {
		t.Fatalf("load: %v", err)
	}
	if _, err := store.db.ExecContext(ctx, `INSERT INTO reliable_submit_seal_use(envelope_key_id,granted_count) VALUES (?,0)`, descriptor.envelopeKeyID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.ExecContext(ctx, `UPDATE reliable_submit_seal_use SET granted_count=granted_count+1 WHERE envelope_key_id=?`, descriptor.envelopeKeyID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.ExecContext(ctx, `UPDATE reliable_submit_key_registry SET state=2 WHERE key_id=?`, descriptor.envelopeKeyID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.ExecContext(ctx, `UPDATE reliable_submit_key_registry SET state=3 WHERE key_id=?`, descriptor.envelopeKeyID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.ExecContext(ctx, `UPDATE reliable_submit_key_registry SET state=1 WHERE key_id=?`, descriptor.envelopeKeyID); err == nil {
		t.Fatal("revocation reversed")
	}
}

func TestSQLiteV3SyntheticScopeCannotTransition(t *testing.T) {
	ctx := context.Background()
	store := mustOpenSQLiteClaimStore(t, sqliteTestPath(t, "state", "scope.sqlite3"))
	defer store.close()
	record, d := syntheticReplayRecordFixture(t)
	for _, key := range []struct {
		id      string
		purpose int
		fp      [32]byte
	}{
		{d.bindingKeyID, 1, d.bindingKeyFP}, {d.envelopeKeyID, 2, d.envelopeKeyFP},
	} {
		if _, err := store.db.ExecContext(ctx, `INSERT INTO reliable_submit_key_registry(key_id,purpose,material_fingerprint,state) VALUES (?,?,?,1)`, key.id, key.purpose, key.fp[:]); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := store.establishClaim(ctx, establishClaimCommand{record: record}); err != nil {
		t.Fatal(err)
	}
	args, err := sqliteRecordArgs(record)
	if err != nil {
		t.Fatal(err)
	}
	replaceSQL := strings.Replace(strings.Split(sqliteInsertReplayClaimSQL, " ON CONFLICT")[0], "INSERT INTO", "INSERT OR REPLACE INTO", 1)
	if _, err := store.db.ExecContext(ctx, replaceSQL, args...); err == nil {
		t.Fatal("complete colliding REPLACE bypassed immutable synthetic claim")
	}
	unchanged, err := store.loadClaim(ctx, loadClaimQuery{claim: record.claim})
	if err != nil || !unchanged.equal(record) {
		t.Fatal("REPLACE changed immutable claim")
	}
	for _, statement := range []string{
		`UPDATE reliable_submit_claims SET replay_scope=2`,
		`UPDATE reliable_submit_claims SET phase_tag=3`,
		`UPDATE reliable_submit_claims SET run_ref=x'01'`,
		`DELETE FROM reliable_submit_claims`,
		`INSERT OR REPLACE INTO reliable_submit_claims(caller_ref,submit_key_ref) VALUES (x'11',x'22')`,
	} {
		if _, err := store.db.ExecContext(ctx, statement); err == nil {
			t.Fatalf("synthetic mutation accepted: %s", statement)
		}
	}
	service := mustDurableService(t, store, fixedClaimClock{now: record.createdAt})
	_, err = service.exactReplayOrLoad(ctx, exactReplayRequest{claim: record.claim, binding: record.plan.Binding()})
	if !errors.Is(err, errClaimStoreUnsupported) {
		t.Fatalf("legacy service accepted synthetic row: %v", err)
	}
}
