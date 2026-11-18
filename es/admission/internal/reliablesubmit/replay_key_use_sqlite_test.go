package reliablesubmit

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"reflect"
	"sync"
	"testing"
)

func fixtureReplayKeys(t *testing.T, suffix byte) PrivateReplayKeys {
	t.Helper()
	keys, err := NewPrivateReplayKeys(fmt.Sprintf("Binding-%d", suffix),
		bytes.Repeat([]byte{suffix}, 32), fmt.Sprintf("Envelope-%d", suffix),
		bytes.Repeat([]byte{suffix + 64}, 32))
	if err != nil {
		t.Fatal(err)
	}
	return keys
}

func TestReplayKeyIdentityPurposeAndLifecycle(t *testing.T) {
	ctx := context.Background()
	store := mustOpenSQLiteClaimStore(t, sqliteTestPath(t, "state", "keys.sqlite3"))
	defer store.close()
	if _, err := NewPrivateReplayKeys("B", bytes.Repeat([]byte{1}, 32), "E", bytes.Repeat([]byte{1}, 32)); err == nil {
		t.Fatal("same material accepted across key purposes")
	}
	keys := fixtureReplayKeys(t, 1)
	digest := sha256.Sum256([]byte("synthetic frozen input"))
	permit, err := store.reserveReplaySealUse(ctx, keys, digest, false)
	if err != nil || permit == nil {
		t.Fatalf("reserve: %v", err)
	}
	if err := store.checkOriginalReplayKeys(ctx, keys, false); err != nil {
		t.Fatalf("active original: %v", err)
	}
	if err := store.transitionReplayKeyState(ctx, keys.envelopeID, replayKeyStateRetired); err != nil {
		t.Fatal(err)
	}
	if err := store.checkOriginalReplayKeys(ctx, keys, false); err != nil {
		t.Fatalf("retired original: %v", err)
	}
	if _, err := store.reserveReplaySealUse(ctx, keys, digest, false); err == nil {
		t.Fatal("retired key received grant")
	}
	if err := store.transitionReplayKeyState(ctx, keys.envelopeID, replayKeyStateRevoked); err != nil {
		t.Fatal(err)
	}
	if err := store.checkOriginalReplayKeys(ctx, keys, false); err == nil {
		t.Fatal("revoked original verified")
	}
	if err := store.transitionReplayKeyState(ctx, keys.envelopeID, replayKeyStateRetired); err == nil {
		t.Fatal("reversed key state")
	}
}

func TestReplaySealGrantLimitAndConcurrentReserve(t *testing.T) {
	t.Run("fixture_aggregate_32", func(t *testing.T) {
		ctx := context.Background()
		store := mustOpenSQLiteClaimStore(t, sqliteTestPath(t, "state", "grants.sqlite3"))
		defer store.close()
		keys := fixtureReplayKeys(t, 2)
		digest := sha256.Sum256([]byte("frozen"))
		var wg sync.WaitGroup
		results := make(chan *privateSealPermit, 32)
		errorsSeen := make(chan error, 32)
		for i := 0; i < 32; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				permit, err := store.reserveReplaySealUse(ctx, keys, digest, false)
				if err != nil {
					errorsSeen <- err
					return
				}
				results <- permit
			}()
		}
		wg.Wait()
		close(results)
		close(errorsSeen)
		for err := range errorsSeen {
			t.Errorf("concurrent reserve: %v", err)
		}
		seen := map[uint64]bool{}
		for permit := range results {
			if permit == nil || permit.sequence < 1 || permit.sequence > 32 || seen[permit.sequence] {
				t.Fatal("duplicate or invalid grant")
			}
			seen[permit.sequence] = true
		}
		if len(seen) != 32 {
			t.Fatalf("known grants=%d", len(seen))
		}
		if _, err := store.reserveReplaySealUse(ctx, keys, digest, false); !errors.Is(err, errClaimStoreUnsupported) {
			t.Fatalf("fixture ceiling: %v", err)
		}
	})
	t.Run("actual_key_2pow32_boundary", func(t *testing.T) {
		ctx := context.Background()
		path := sqliteTestPath(t, "state", "lifetime-reservation-only.sqlite3")
		store := mustOpenSQLiteClaimStore(t, path)
		keys := fixtureReplayKeys(t, 23)
		digest := sha256.Sum256([]byte("isolated lifetime grant"))
		tx, err := store.db.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback()
		for _, key := range []struct {
			id      string
			purpose int
			fp      [32]byte
		}{
			{keys.bindingID, 1, keys.bindingFP},
			{keys.envelopeID, 2, keys.envelopeFP},
		} {
			if _, err := tx.ExecContext(ctx, `INSERT INTO reliable_submit_key_registry(key_id,purpose,material_fingerprint,state) VALUES (?,?,?,1)`, key.id, key.purpose, key.fp[:]); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO reliable_submit_seal_use(envelope_key_id,granted_count) VALUES (?,0)`, keys.envelopeID); err != nil {
			t.Fatal(err)
		}
		var updateTrigger string
		if err := tx.QueryRowContext(ctx, `SELECT sql FROM sqlite_schema WHERE type='trigger' AND name='reliable_submit_seal_use_guard_update'`).Scan(&updateTrigger); err != nil || updateTrigger == "" {
			t.Fatalf("counter trigger unavailable: %v", err)
		}
		// Only this isolated fixture seeds the near-limit counter. Restore the
		// exact captured trigger before reopening and invoking real reservation.
		if _, err := tx.ExecContext(ctx, `DROP TRIGGER reliable_submit_seal_use_guard_update`); err != nil {
			t.Fatal(err)
		}
		if _, err := tx.ExecContext(ctx, `UPDATE reliable_submit_seal_use SET granted_count=? WHERE envelope_key_id=?`, int64(1<<32-1), keys.envelopeID); err != nil {
			t.Fatal(err)
		}
		if _, err := tx.ExecContext(ctx, updateTrigger); err != nil {
			t.Fatal(err)
		}
		if err := tx.Commit(); err != nil {
			t.Fatal(err)
		}
		if err := store.close(); err != nil {
			t.Fatal(err)
		}
		reopened := mustOpenSQLiteClaimStore(t, path) // complete schema shape is checked on open
		defer reopened.close()
		grant, err := reopened.reserveReplaySealUse(ctx, keys, digest, true)
		if err != nil || grant == nil || grant.sequence != 1<<32 {
			t.Fatalf("last actual-key grant: sequence=%v error=%v", grant, err)
		}
		if next, err := reopened.reserveReplaySealUse(ctx, keys, digest, true); next != nil || !errors.Is(err, errClaimStoreUnsupported) {
			t.Fatalf("actual-key ceiling allowed another grant: %v", err)
		}
		var count int64
		if err := reopened.db.QueryRowContext(ctx, `SELECT granted_count FROM reliable_submit_seal_use WHERE envelope_key_id=?`, keys.envelopeID).Scan(&count); err != nil || count != 1<<32 {
			t.Fatalf("counter after ceiling=%d error=%v", count, err)
		}
		var claims int
		if err := reopened.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM reliable_submit_claims`).Scan(&claims); err != nil || claims != 0 {
			t.Fatalf("reservation-only fixture claims=%d error=%v", claims, err)
		}
	})
}

func TestReplaySealFixtureAggregateBudgetAcrossKeys(t *testing.T) {
	ctx := context.Background()
	store := mustOpenSQLiteClaimStore(t, sqliteTestPath(t, "state", "aggregate.sqlite3"))
	defer store.close()
	digest := sha256.Sum256([]byte("frozen"))
	first := fixtureReplayKeys(t, 3)
	second := fixtureReplayKeys(t, 4)
	for i := 0; i < 16; i++ {
		if _, err := store.reserveReplaySealUse(ctx, first, digest, false); err != nil {
			t.Fatal(err)
		}
		if _, err := store.reserveReplaySealUse(ctx, second, digest, false); err != nil {
			t.Fatal(err)
		}
	}
	third := fixtureReplayKeys(t, 5)
	if _, err := store.reserveReplaySealUse(ctx, third, digest, false); !errors.Is(err, errClaimStoreUnsupported) {
		t.Fatalf("rotation bypassed aggregate: %v", err)
	}
}

func TestReplaySealGrantRetireBeforeUseBurns(t *testing.T) {
	ctx := context.Background()
	store := mustOpenSQLiteClaimStore(t, sqliteTestPath(t, "state", "retire.sqlite3"))
	defer store.close()
	keys := fixtureReplayKeys(t, 6)
	digest := sha256.Sum256([]byte("frozen"))
	permit, err := store.reserveReplaySealUse(ctx, keys, digest, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.transitionReplayKeyState(ctx, keys.envelopeID, replayKeyStateRetired); err != nil {
		t.Fatal(err)
	}
	if err := store.consumeReplaySealPermit(ctx, keys, digest, permit); err == nil {
		t.Fatal("retired grant consumed")
	}
	if permit.consume(store, keys.envelopeID, keys.envelopeFP, digest) {
		t.Fatal("burned grant reused")
	}
}

func TestReplaySealGrantCommitUnknownNoSeal(t *testing.T) {
	ctx := context.Background()
	path := sqliteTestPath(t, "state", "unknown-grant.sqlite3")
	store, err := openSQLiteClaimStore(ctx, sqliteClaimStoreOptions{path: path,
		sealGrantCommit: func(ctx context.Context, conn *sql.Conn) error {
			if err := commit(ctx, conn); err != nil {
				return err
			}
			return errClaimStoreCommitUnknown
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	keys := fixtureReplayKeys(t, 7)
	digest := sha256.Sum256([]byte("known frozen input"))
	permit, err := store.reserveReplaySealUse(ctx, keys, digest, false)
	if permit != nil || !errors.Is(err, errClaimStoreCommitUnknown) {
		t.Fatalf("uncertain grant produced permit: %v", err)
	}
	var count int64
	if err := store.db.QueryRowContext(ctx, `SELECT granted_count FROM reliable_submit_seal_use WHERE envelope_key_id=?`, keys.envelopeID).Scan(&count); err != nil || count != 1 {
		t.Fatalf("committed grant counter=%d err=%v", count, err)
	}
	if err := store.close(); err != nil {
		t.Fatal(err)
	}
	reopened := mustOpenSQLiteClaimStore(t, path)
	defer reopened.close()
	if err := reopened.db.QueryRowContext(ctx, `SELECT granted_count FROM reliable_submit_seal_use WHERE envelope_key_id=?`, keys.envelopeID).Scan(&count); err != nil || count != 1 {
		t.Fatalf("reopened grant count=%d err=%v", count, err)
	}
	next, err := reopened.reserveReplaySealUse(ctx, keys, digest, false)
	if err != nil || next == nil || next.sequence != 2 {
		t.Fatalf("unknown grant was refunded or reused: %v", err)
	}
}

func TestReplayGrantC1PreCommitConnectionQuarantine(t *testing.T) {
	ctx := context.Background()
	path := sqliteTestPath(t, "state", "precommit-grant.sqlite3")
	failBeforeCommit := true
	store, err := openSQLiteClaimStore(ctx, sqliteClaimStoreOptions{path: path,
		sealGrantCommit: func(ctx context.Context, conn *sql.Conn) error {
			if failBeforeCommit {
				return errClaimStoreCommitUnknown
			}
			return commit(ctx, conn)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer store.close()
	store.db.SetMaxOpenConns(1)
	store.db.SetMaxIdleConns(1)
	keys := fixtureReplayKeys(t, 32)
	digest := sha256.Sum256([]byte("precommit grant"))
	permit, err := store.reserveReplaySealUse(ctx, keys, digest, false)
	if permit != nil || !errors.Is(err, errClaimStoreCommitUnknown) {
		t.Fatalf("pre-COMMIT grant issued permit: %v", err)
	}
	if err := store.consumeReplaySealPermit(ctx, keys, digest, permit); !errors.Is(err, errClaimStoreUnavailable) {
		t.Fatalf("failed reservation enabled Seal: %v", err)
	}
	independentDB, independentConn := c1IndependentSQLiteConn(t, path)
	defer independentDB.Close()
	defer independentConn.Close()
	var committed int
	if err := independentConn.QueryRowContext(ctx, `SELECT COUNT(*) FROM reliable_submit_seal_use WHERE envelope_key_id=?`, keys.envelopeID).Scan(&committed); err != nil || committed != 0 {
		t.Fatalf("pre-COMMIT grant became durable: count=%d error=%v", committed, err)
	}
	if _, err := independentConn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		t.Fatalf("pre-COMMIT grant retained SQLite writer lock: %v", err)
	}
	if _, err := independentConn.ExecContext(ctx, "ROLLBACK"); err != nil {
		t.Fatal(err)
	}
	if stats := store.db.Stats(); stats.Idle != 0 || stats.OpenConnections != 0 {
		t.Fatalf("uncertain grant connection remained in the usable pool: idle=%d open=%d", stats.Idle, stats.OpenConnections)
	}
	failBeforeCommit = false
	later, err := store.reserveReplaySealUse(ctx, keys, digest, false)
	if err != nil || later == nil || later.sequence != 1 {
		t.Fatalf("later valid grant failed or budget advanced: permit=%v error=%v", later != nil, err)
	}
	var count, aggregate int64
	if err := independentConn.QueryRowContext(ctx, `SELECT granted_count FROM reliable_submit_seal_use WHERE envelope_key_id=?`, keys.envelopeID).Scan(&count); err != nil || count != 1 {
		t.Fatalf("durable grant count=%d error=%v", count, err)
	}
	if err := independentConn.QueryRowContext(ctx, `SELECT SUM(granted_count) FROM reliable_submit_seal_use`).Scan(&aggregate); err != nil || aggregate != 1 {
		t.Fatalf("durable aggregate budget=%d error=%v", aggregate, err)
	}
}

// The hook records only an identity number, never a driver connection usable
// outside Raw. It executes the real production BEGIN before losing its reply.
func d1LostBeginHook(t *testing.T, executed *bool, original *uintptr) func(context.Context, *sql.Conn) error {
	t.Helper()
	return func(ctx context.Context, conn *sql.Conn) error {
		if err := conn.Raw(func(raw any) error {
			value := reflect.ValueOf(raw)
			if value.Kind() != reflect.Pointer || value.IsNil() {
				return errClaimStoreInternal
			}
			*original = value.Pointer()
			return nil
		}); err != nil {
			return err
		}
		if _, err := conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
			return err
		}
		*executed = true
		return errors.New("synthetic lost BEGIN response")
	}
}

func d1DriverConnIdentity(t *testing.T, conn *sql.Conn) uintptr {
	t.Helper()
	var identity uintptr
	if err := conn.Raw(func(raw any) error {
		value := reflect.ValueOf(raw)
		if value.Kind() != reflect.Pointer || value.IsNil() {
			return errClaimStoreInternal
		}
		identity = value.Pointer()
		return nil
	}); err != nil || identity == 0 {
		t.Fatalf("driver connection identity unavailable: %v", err)
	}
	return identity
}

func TestReplayGrantD1BeginResponseLossQuarantine(t *testing.T) {
	ctx := context.Background()
	path := sqliteTestPath(t, "state", "d1-grant.sqlite3")
	store := mustOpenSQLiteClaimStore(t, path)
	defer store.close()
	store.db.SetMaxOpenConns(1)
	store.db.SetMaxIdleConns(1)
	keys := fixtureReplayKeys(t, 41)
	digest := sha256.Sum256([]byte("D1 frozen grant"))
	var executed bool
	var original uintptr
	store.beginImmediateAttempt = d1LostBeginHook(t, &executed, &original)
	permit, err := store.reserveReplaySealUse(ctx, keys, digest, false)
	if !executed || original == 0 || permit != nil || err == nil {
		t.Fatalf("BEGIN response loss was not exercised or authorized a grant: executed=%t permit=%t error=%v", executed, permit != nil, err)
	}
	if err := store.consumeReplaySealPermit(ctx, keys, digest, permit); !errors.Is(err, errClaimStoreUnavailable) {
		t.Fatalf("failed reservation enabled Seal: %v", err)
	}
	independentDB, independentConn := c1IndependentSQLiteConn(t, path)
	defer independentDB.Close()
	defer independentConn.Close()
	var durable int
	if err := independentConn.QueryRowContext(ctx, `SELECT COUNT(*) FROM reliable_submit_seal_use WHERE envelope_key_id=?`, keys.envelopeID).Scan(&durable); err != nil || durable != 0 {
		t.Fatalf("failed BEGIN changed durable grant: count=%d error=%v", durable, err)
	}
	if _, err := independentConn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		t.Fatalf("D1 grant writer lock retained after errored BEGIN: %v", err)
	}
	if _, err := independentConn.ExecContext(ctx, "ROLLBACK"); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(err, errClaimStoreUnavailable) {
		t.Fatalf("BEGIN uncertainty did not fail unavailable: %v", err)
	}
	if stats := store.db.Stats(); stats.Idle != 0 || stats.OpenConnections != 0 {
		t.Fatalf("D1 grant connection remained pooled: idle=%d open=%d", stats.Idle, stats.OpenConnections)
	}
	store.beginImmediateAttempt = nil
	conn, err := store.checkedConn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if nextIdentity := d1DriverConnIdentity(t, conn); nextIdentity == original {
		t.Fatal("errored BEGIN driver connection was reused")
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	later, err := store.reserveReplaySealUse(ctx, keys, digest, false)
	if err != nil || later == nil || later.sequence != 1 {
		t.Fatalf("later grant did not start at sequence 1: permit=%t error=%v", later != nil, err)
	}
	var count, aggregate int64
	if err := independentConn.QueryRowContext(ctx, `SELECT granted_count FROM reliable_submit_seal_use WHERE envelope_key_id=?`, keys.envelopeID).Scan(&count); err != nil || count != 1 {
		t.Fatalf("durable grant count=%d error=%v", count, err)
	}
	if err := independentConn.QueryRowContext(ctx, `SELECT SUM(granted_count) FROM reliable_submit_seal_use`).Scan(&aggregate); err != nil || aggregate != 1 {
		t.Fatalf("durable aggregate=%d error=%v", aggregate, err)
	}
}

func TestReplayKeyStateD1BeginResponseLossQuarantine(t *testing.T) {
	for _, target := range []struct {
		name  string
		state int
	}{
		{"retired", replayKeyStateRetired},
		{"revoked", replayKeyStateRevoked},
	} {
		t.Run(target.name, func(t *testing.T) {
			ctx := context.Background()
			path := sqliteTestPath(t, "state", "d1-key-state.sqlite3")
			store := mustOpenSQLiteClaimStore(t, path)
			defer store.close()
			store.db.SetMaxOpenConns(1)
			store.db.SetMaxIdleConns(1)
			keys := fixtureReplayKeys(t, 42)
			digest := sha256.Sum256([]byte("D1 key state"))
			if permit, err := store.reserveReplaySealUse(ctx, keys, digest, false); err != nil || permit == nil || permit.sequence != 1 {
				t.Fatalf("seed grant: permit=%t error=%v", permit != nil, err)
			}
			var executed bool
			var original uintptr
			store.beginImmediateAttempt = d1LostBeginHook(t, &executed, &original)
			err := store.transitionReplayKeyState(ctx, keys.envelopeID, target.state)
			if !executed || original == 0 || err == nil {
				t.Fatalf("BEGIN response loss was not exercised: executed=%t error=%v", executed, err)
			}
			independentDB, independentConn := c1IndependentSQLiteConn(t, path)
			defer independentDB.Close()
			defer independentConn.Close()
			var state, count int
			if err := independentConn.QueryRowContext(ctx, `SELECT state FROM reliable_submit_key_registry WHERE key_id=?`, keys.envelopeID).Scan(&state); err != nil || state != replayKeyStateActive {
				t.Fatalf("failed BEGIN changed durable key state: state=%d error=%v", state, err)
			}
			if err := independentConn.QueryRowContext(ctx, `SELECT granted_count FROM reliable_submit_seal_use WHERE envelope_key_id=?`, keys.envelopeID).Scan(&count); err != nil || count != 1 {
				t.Fatalf("failed state transition changed grant count: count=%d error=%v", count, err)
			}
			if _, err := independentConn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
				t.Fatalf("D1 key-state writer lock retained after errored BEGIN: %v", err)
			}
			if _, err := independentConn.ExecContext(ctx, "ROLLBACK"); err != nil {
				t.Fatal(err)
			}
			if !errors.Is(err, errClaimStoreUnavailable) {
				t.Fatalf("BEGIN uncertainty did not fail unavailable: %v", err)
			}
			if stats := store.db.Stats(); stats.Idle != 0 || stats.OpenConnections != 0 {
				t.Fatalf("D1 key-state connection remained pooled: idle=%d open=%d", stats.Idle, stats.OpenConnections)
			}
			store.beginImmediateAttempt = nil
			conn, err := store.checkedConn(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if nextIdentity := d1DriverConnIdentity(t, conn); nextIdentity == original {
				t.Fatal("errored BEGIN driver connection was reused")
			}
			if err := conn.Close(); err != nil {
				t.Fatal(err)
			}
			if err := store.transitionReplayKeyState(ctx, keys.envelopeID, target.state); err != nil {
				t.Fatalf("later valid state transition failed: %v", err)
			}
			if err := independentConn.QueryRowContext(ctx, `SELECT state FROM reliable_submit_key_registry WHERE key_id=?`, keys.envelopeID).Scan(&state); err != nil || state != target.state {
				t.Fatalf("later durable state=%d error=%v", state, err)
			}
			if err := independentConn.QueryRowContext(ctx, `SELECT granted_count FROM reliable_submit_seal_use WHERE envelope_key_id=?`, keys.envelopeID).Scan(&count); err != nil || count != 1 {
				t.Fatalf("state transition granted use: count=%d error=%v", count, err)
			}
		})
	}
}
