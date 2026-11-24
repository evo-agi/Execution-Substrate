package reliablesubmit

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"reflect"
	"runtime"
	"sync"
	"testing"
	"time"
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

type a1ReadFacts struct {
	bindingState  int
	envelopeState int
	grants        int64
	claims        int64
}

func a1ReadContext(t *testing.T) (context.Context, context.CancelFunc) {
	t.Helper()
	return context.WithTimeout(context.Background(), 12*time.Second)
}

func a1ReadFixture(t *testing.T) (*sqliteClaimStore, PrivateReplayKeys, [32]byte, *privateSealPermit) {
	t.Helper()
	store := mustOpenSQLiteClaimStore(t, sqliteTestPath(t, "state", "a1.sqlite3"))
	t.Cleanup(func() { _ = store.close() })
	t.Cleanup(func() { a1ReadClearHooks(store) })
	keys := fixtureReplayKeys(t, 71)
	digest := sha256.Sum256([]byte("A1 frozen synthetic input"))
	ctx, cancel := a1ReadContext(t)
	defer cancel()
	permit, err := store.reserveReplaySealUse(ctx, keys, digest, false)
	if err != nil || permit == nil {
		t.Fatalf("A1 setup grant: permit=%t error=%v", permit != nil, err)
	}
	return store, keys, digest, permit
}

func a1ReadClearHooks(store *sqliteClaimStore) {
	store.a1ReadBeginAttempt = nil
	store.a1ReadAfterBegin = nil
	store.a1ReadAfterFirstKey = nil
	store.a1ReadCommitAttempt = nil
	store.a1ReadRollbackAttempt = nil
	store.a1ReadDiscardAttempt = nil
}

// Read through a separately guarded, nonmigrating connection. The snapshot
// contains only logical state, never raw key material or WAL file bytes.
func a1ReadSnapshot(t *testing.T, store *sqliteClaimStore, keys PrivateReplayKeys) a1ReadFacts {
	t.Helper()
	db, err := sql.Open("sqlite", store.dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	ctx, cancel := a1ReadContext(t)
	defer cancel()
	conn, err := db.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := applyAndVerifySQLiteConnectionPragmas(ctx, conn); err != nil {
		t.Fatalf("independent pragmas: %v", err)
	}
	if err := verifySQLiteStoreCurrent(ctx, conn); err != nil {
		t.Fatalf("independent schema: %v", err)
	}
	var facts a1ReadFacts
	if err := conn.QueryRowContext(ctx, "SELECT state FROM reliable_submit_key_registry WHERE key_id=? COLLATE BINARY", keys.bindingID).Scan(&facts.bindingState); err != nil {
		t.Fatal(err)
	}
	if err := conn.QueryRowContext(ctx, "SELECT state FROM reliable_submit_key_registry WHERE key_id=? COLLATE BINARY", keys.envelopeID).Scan(&facts.envelopeState); err != nil {
		t.Fatal(err)
	}
	if err := conn.QueryRowContext(ctx, "SELECT granted_count FROM reliable_submit_seal_use WHERE envelope_key_id=? COLLATE BINARY", keys.envelopeID).Scan(&facts.grants); err != nil {
		t.Fatal(err)
	}
	if err := conn.QueryRowContext(ctx, "SELECT COUNT(*) FROM reliable_submit_claims").Scan(&facts.claims); err != nil {
		t.Fatal(err)
	}
	return facts
}

func a1ReadRetireIndependently(t *testing.T, store *sqliteClaimStore, keys PrivateReplayKeys) {
	t.Helper()
	db, err := sql.Open("sqlite", store.dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	ctx, cancel := a1ReadContext(t)
	defer cancel()
	conn, err := db.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := applyAndVerifySQLiteConnectionPragmas(ctx, conn); err != nil {
		t.Fatal(err)
	}
	if err := verifySQLiteStoreCurrent(ctx, conn); err != nil {
		t.Fatal(err)
	}
	result, err := conn.ExecContext(ctx, "UPDATE reliable_submit_key_registry SET state=? WHERE key_id=? COLLATE BINARY", replayKeyStateRetired, keys.envelopeID)
	if err != nil {
		t.Fatalf("independent retirement: %v", err)
	}
	if rows, err := result.RowsAffected(); err != nil || rows != 1 {
		t.Fatalf("independent retirement rows=%d error=%v", rows, err)
	}
}

func a1ReadProbePool(t *testing.T, store *sqliteClaimStore) (uintptr, error) {
	t.Helper()
	ctx, cancel := a1ReadContext(t)
	defer cancel()
	conn, err := store.db.Conn(ctx)
	if err != nil {
		return 0, err
	}
	defer conn.Close()
	identity := d1DriverConnIdentity(t, conn)
	_, err = conn.ExecContext(ctx, "BEGIN")
	if err == nil {
		if _, rollbackErr := conn.ExecContext(context.Background(), "ROLLBACK"); rollbackErr != nil {
			t.Errorf("probe rollback: %v", rollbackErr)
		}
	}
	return identity, err
}

func a1ReadAssertRecovery(t *testing.T, store *sqliteClaimStore, keys PrivateReplayKeys, digest [32]byte, before a1ReadFacts, discarded bool, original uintptr) {
	t.Helper()
	afterRead := a1ReadSnapshot(t, store, keys)
	if afterRead != before {
		t.Errorf("target read changed durable facts: before=%+v after=%+v", before, afterRead)
	}
	nextIdentity, probeErr := a1ReadProbePool(t, store)
	if probeErr != nil {
		t.Errorf("pooled transaction remained open: %v", probeErr)
	}
	if discarded && original != 0 && nextIdentity == original {
		t.Error("uncertain driver connection reused")
	}
	ctx, cancel := a1ReadContext(t)
	if err := store.checkOriginalReplayKeys(ctx, keys, false); err != nil {
		t.Errorf("fresh same-store existing read: %v", err)
	}
	cancel()
	ctx, cancel = a1ReadContext(t)
	permit, err := store.reserveReplaySealUse(ctx, keys, digest, false)
	if err != nil || permit == nil {
		t.Errorf("fresh same-store legitimate grant: permit=%t error=%v", permit != nil, err)
	}
	cancel()
	a1ReadRetireIndependently(t, store, keys)
	ctx, cancel = a1ReadContext(t)
	if err := store.checkOriginalReplayKeys(ctx, keys, false); err != nil {
		t.Errorf("later retired original unreadable on same store: %v", err)
	}
	cancel()
	ctx, cancel = a1ReadContext(t)
	if err := store.checkOriginalReplayKeys(ctx, keys, true); !errors.Is(err, errClaimStoreUnavailable) {
		t.Errorf("later retired key authorized new use: %v", err)
	}
	cancel()
	final := a1ReadSnapshot(t, store, keys)
	wantGrants := before.grants
	if permit != nil && err == nil {
		wantGrants++
	}
	if final.bindingState != replayKeyStateActive || final.envelopeState != replayKeyStateRetired || final.claims != before.claims || final.grants != wantGrants {
		t.Errorf("independent transition/follow-up facts=%+v want grants=%d", final, wantGrants)
	}
}

func TestReplayOriginalKeyReadCleanup(t *testing.T) {
	t.Run("key_lifecycle_and_invalid_precedence", func(t *testing.T) {
		store, keys, _, _ := a1ReadFixture(t)
		ctx, cancel := a1ReadContext(t)
		defer cancel()
		if err := store.checkOriginalReplayKeys(ctx, keys, true); err != nil {
			t.Fatalf("active pair: %v", err)
		}
		if err := store.transitionReplayKeyState(ctx, keys.envelopeID, replayKeyStateRetired); err != nil {
			t.Fatal(err)
		}
		if err := store.checkOriginalReplayKeys(ctx, keys, false); err != nil {
			t.Errorf("retired original read: %v", err)
		}
		if err := store.checkOriginalReplayKeys(ctx, keys, true); !errors.Is(err, errClaimStoreUnavailable) {
			t.Errorf("retired new use: %v", err)
		}
		if err := store.transitionReplayKeyState(ctx, keys.envelopeID, replayKeyStateRevoked); err != nil {
			t.Fatal(err)
		}
		if err := store.checkOriginalReplayKeys(ctx, keys, false); !errors.Is(err, errClaimStoreUnavailable) {
			t.Errorf("revoked original: %v", err)
		}
		missing := fixtureReplayKeys(t, 72)
		if err := store.checkOriginalReplayKeys(ctx, missing, false); !errors.Is(err, errClaimStoreUnavailable) {
			t.Errorf("missing original: %v", err)
		}
		mismatch, err := NewPrivateReplayKeys(keys.bindingID, bytes.Repeat([]byte{99}, 32), keys.envelopeID, keys.envelope[:])
		if err != nil {
			t.Fatal(err)
		}
		if err := store.checkOriginalReplayKeys(ctx, mismatch, false); !errors.Is(err, errClaimStoreUnavailable) {
			t.Errorf("mismatched original: %v", err)
		}
		canceled, stop := context.WithCancel(context.Background())
		stop()
		if err := store.checkOriginalReplayKeys(canceled, PrivateReplayKeys{}, false); !errors.Is(err, errClaimStoreUnsupported) {
			t.Errorf("invalid key precedence: %v", err)
		}
	})

	t.Run("paired_key_snapshot_then_fresh_transition", func(t *testing.T) {
		store, keys, _, _ := a1ReadFixture(t)
		before := a1ReadSnapshot(t, store, keys)
		reached := false
		store.a1ReadAfterFirstKey = func(*sql.Conn) error {
			reached = true
			a1ReadRetireIndependently(t, store, keys)
			return nil
		}
		ctx, cancel := a1ReadContext(t)
		err := store.checkOriginalReplayKeys(ctx, keys, true)
		cancel()
		a1ReadClearHooks(store)
		if !reached || err != nil {
			t.Errorf("paired snapshot: reached=%t error=%v", reached, err)
		}
		after := a1ReadSnapshot(t, store, keys)
		if after.bindingState != before.bindingState || after.envelopeState != replayKeyStateRetired || after.grants != before.grants || after.claims != before.claims {
			t.Errorf("committed transition facts=%+v", after)
		}
		ctx, cancel = a1ReadContext(t)
		if err := store.checkOriginalReplayKeys(ctx, keys, true); !errors.Is(err, errClaimStoreUnavailable) {
			t.Errorf("fresh transaction missed retirement: %v", err)
		}
		cancel()
	})

	t.Run("rollback_expired_nil_response_discards", func(t *testing.T) {
		store, keys, digest, _ := a1ReadFixture(t)
		before := a1ReadSnapshot(t, store, keys)
		var original, discardedIdentity uintptr
		var cleanupCtx context.Context
		var rollbackDeadline time.Time
		beginReached, beginSucceeded, afterBeginReached := false, false, false
		rollbackReached, rollbackExpired, rollbackSQLSucceeded := false, false, false
		rollbackHadDeadline, rollbackStartedLive := false, false
		discardCount := 0
		store.a1ReadBeginAttempt = func(ctx context.Context, conn *sql.Conn) error {
			beginReached = true
			original = d1DriverConnIdentity(t, conn)
			err := beginRead(ctx, conn)
			beginSucceeded = err == nil
			return err
		}
		store.a1ReadAfterBegin = func(*sql.Conn) error {
			afterBeginReached = true
			return errClaimStoreUnsupported // test-injected ordinary pre-COMMIT result
		}
		store.a1ReadRollbackAttempt = func(ctx context.Context, conn *sql.Conn) error {
			rollbackReached = true
			cleanupCtx = ctx
			rollbackDeadline, rollbackHadDeadline = ctx.Deadline()
			rollbackStartedLive = ctx.Err() == nil
			if !rollbackHadDeadline {
				return errClaimStoreInternal
			}
			<-ctx.Done() // actual private cleanup deadline, not a synthetic error
			rollbackExpired = errors.Is(ctx.Err(), context.DeadlineExceeded)
			testCtx, stop := context.WithTimeout(context.Background(), 5*time.Second)
			defer stop()
			_, err := conn.ExecContext(testCtx, "ROLLBACK") // same connection, live test-only context
			rollbackSQLSucceeded = err == nil
			return err // nil after real rollback models the late response
		}
		store.a1ReadDiscardAttempt = func(conn *sql.Conn) error {
			discardCount++
			discardedIdentity = d1DriverConnIdentity(t, conn)
			return discardUncertainSQLiteConn(conn)
		}
		callerCtx, stopCaller := a1ReadContext(t)
		err := store.checkOriginalReplayKeys(callerCtx, keys, false)
		callerLive := callerCtx.Err() == nil
		a1ReadClearHooks(store)
		stopCaller()
		if !beginReached || !beginSucceeded || !afterBeginReached || original == 0 || !rollbackReached ||
			!rollbackHadDeadline || !rollbackStartedLive || rollbackDeadline.IsZero() || !rollbackExpired || !rollbackSQLSucceeded || !callerLive {
			t.Fatalf("expiry setup: begin=%t/%t after_begin=%t original=%t rollback=%t deadline=%t/%t expired=%t sql=%t caller_live=%t",
				beginReached, beginSucceeded, afterBeginReached, original != 0, rollbackReached, rollbackHadDeadline, rollbackStartedLive,
				rollbackExpired, rollbackSQLSucceeded, callerLive)
		}
		if !errors.Is(cleanupCtx.Err(), context.DeadlineExceeded) {
			t.Fatalf("cleanup deadline was not retained: %v", cleanupCtx.Err())
		}
		if !errors.Is(err, errClaimStoreUnavailable) {
			t.Errorf("expired nil rollback response preserved ordinary result: %v", err)
		}
		if discardCount != 1 || discardedIdentity != original {
			t.Errorf("expired nil rollback did not discard exact connection: calls=%d same=%t", discardCount, discardedIdentity == original)
		}
		a1ReadAssertRecovery(t, store, keys, digest, before, true, original)
	})

	t.Run("rollback_timely_nil_response_preserves_result", func(t *testing.T) {
		store, keys, digest, _ := a1ReadFixture(t)
		before := a1ReadSnapshot(t, store, keys)
		var original uintptr
		var cleanupCtx context.Context
		var responseCtxErr error
		beginReached, beginSucceeded, afterBeginReached := false, false, false
		rollbackReached, rollbackHadDeadline, rollbackSQLSucceeded := false, false, false
		discardCount := 0
		store.a1ReadBeginAttempt = func(ctx context.Context, conn *sql.Conn) error {
			beginReached = true
			original = d1DriverConnIdentity(t, conn)
			err := beginRead(ctx, conn)
			beginSucceeded = err == nil
			return err
		}
		store.a1ReadAfterBegin = func(*sql.Conn) error {
			afterBeginReached = true
			return errClaimStoreUnsupported // same test-injected ordinary result
		}
		store.a1ReadRollbackAttempt = func(ctx context.Context, conn *sql.Conn) error {
			rollbackReached = true
			cleanupCtx = ctx
			_, rollbackHadDeadline = ctx.Deadline()
			_, err := conn.ExecContext(ctx, "ROLLBACK")
			rollbackSQLSucceeded = err == nil
			responseCtxErr = ctx.Err() // observe before the production cancel function runs
			return err
		}
		store.a1ReadDiscardAttempt = func(conn *sql.Conn) error {
			discardCount++
			return discardUncertainSQLiteConn(conn)
		}
		callerCtx, stopCaller := a1ReadContext(t)
		err := store.checkOriginalReplayKeys(callerCtx, keys, false)
		callerLive := callerCtx.Err() == nil
		a1ReadClearHooks(store)
		stopCaller()
		if !beginReached || !beginSucceeded || !afterBeginReached || original == 0 || !rollbackReached ||
			!rollbackHadDeadline || !rollbackSQLSucceeded || responseCtxErr != nil || !callerLive {
			t.Fatalf("timely setup: begin=%t/%t after_begin=%t original=%t rollback=%t deadline=%t sql=%t response_context=%v caller_live=%t",
				beginReached, beginSucceeded, afterBeginReached, original != 0, rollbackReached, rollbackHadDeadline,
				rollbackSQLSucceeded, responseCtxErr, callerLive)
		}
		if !errors.Is(cleanupCtx.Err(), context.Canceled) {
			t.Errorf("cleanup cancel function was not released by return: %v", cleanupCtx.Err())
		}
		if !errors.Is(err, errClaimStoreUnsupported) {
			t.Errorf("timely nil rollback did not preserve ordinary result: %v", err)
		}
		if discardCount != 0 {
			t.Errorf("timely confirmed rollback discarded connection: calls=%d", discardCount)
		}
		a1ReadAssertRecovery(t, store, keys, digest, before, false, original)
	})

	for _, fault := range []string{
		"already_canceled", "cancel_after_begin", "cancel_after_first_query",
		"begin_response_loss_model", "rollback_failure_model", "rollback_deadline_model",
		"commit_pre_dispatch_model", "commit_response_loss_model", "discard_response_rescue_model",
	} {
		t.Run(fault, func(t *testing.T) {
			store, keys, digest, _ := a1ReadFixture(t)
			before := a1ReadSnapshot(t, store, keys)
			requestKeys := keys
			if fault == "rollback_failure_model" || fault == "rollback_deadline_model" {
				requestKeys = fixtureReplayKeys(t, 72) // missing original yields early read refusal
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var original uintptr
			beginReached, realBeginSuccess, firstKeyReached := false, false, false
			rollbackCount, commitCount, discardCount := 0, 0, 0
			rollbackContextValid := false
			store.a1ReadBeginAttempt = func(ctx context.Context, conn *sql.Conn) error {
				beginReached = true
				original = d1DriverConnIdentity(t, conn)
				err := beginRead(ctx, conn)
				realBeginSuccess = err == nil
				if (fault == "begin_response_loss_model" || fault == "discard_response_rescue_model") && err == nil {
					return errClaimStoreUnavailable // synthetic lost response after real BEGIN
				}
				return err
			}
			store.a1ReadAfterBegin = func(*sql.Conn) error {
				if fault == "cancel_after_begin" {
					cancel()
				}
				return nil
			}
			store.a1ReadAfterFirstKey = func(*sql.Conn) error {
				firstKeyReached = true
				if fault == "cancel_after_first_query" {
					cancel()
				}
				return nil
			}
			store.a1ReadRollbackAttempt = func(cleanupCtx context.Context, conn *sql.Conn) error {
				rollbackCount++
				deadline, hasDeadline := cleanupCtx.Deadline()
				remaining := time.Until(deadline)
				rollbackContextValid = cleanupCtx.Err() == nil && hasDeadline && remaining > 4*time.Second && remaining <= 5*time.Second
				if fault == "rollback_failure_model" {
					return errClaimStoreUnavailable // synthetic pre-dispatch failure
				}
				if fault == "rollback_deadline_model" {
					return context.DeadlineExceeded // synthetic expired response
				}
				_, err := conn.ExecContext(cleanupCtx, "ROLLBACK")
				return err
			}
			store.a1ReadCommitAttempt = func(ctx context.Context, conn *sql.Conn) error {
				commitCount++
				if fault == "commit_pre_dispatch_model" {
					return errClaimStoreCommitUnknown // synthetic pre-dispatch response
				}
				err := commit(ctx, conn)
				if fault == "commit_response_loss_model" && err == nil {
					return errClaimStoreCommitUnknown // synthetic lost response after real COMMIT
				}
				return err
			}
			store.a1ReadDiscardAttempt = func(conn *sql.Conn) error {
				discardCount++
				if fault == "discard_response_rescue_model" {
					return errClaimStoreUnavailable // synthetic first response failure; real rescue is direct
				}
				return discardUncertainSQLiteConn(conn)
			}
			if fault == "already_canceled" {
				cancel()
			}
			err := store.checkOriginalReplayKeys(ctx, requestKeys, false)
			a1ReadClearHooks(store) // no fault may leak into healthy follow-up
			if !errors.Is(err, errClaimStoreUnavailable) {
				t.Errorf("fault %s result not unavailable: %v", fault, err)
			}
			if fault == "already_canceled" {
				if beginReached || rollbackCount != 0 || commitCount != 0 || discardCount != 0 {
					t.Errorf("pre-canceled read dispatched work: begin=%t rollback=%d commit=%d discard=%d", beginReached, rollbackCount, commitCount, discardCount)
				}
			} else if !beginReached || !realBeginSuccess {
				t.Errorf("real BEGIN not reached: reached=%t success=%t", beginReached, realBeginSuccess)
			}
			if fault == "cancel_after_first_query" && !firstKeyReached {
				t.Error("first real key query not reached")
			}
			switch fault {
			case "cancel_after_begin", "cancel_after_first_query":
				if rollbackCount != 1 || !rollbackContextValid || discardCount != 0 {
					t.Errorf("cancellation rollback: calls=%d live_five_second_context=%t discard=%d", rollbackCount, rollbackContextValid, discardCount)
				}
			case "rollback_failure_model", "rollback_deadline_model":
				if rollbackCount != 1 || !rollbackContextValid || discardCount != 1 {
					t.Errorf("failed rollback cleanup: calls=%d live_five_second_context=%t discard=%d", rollbackCount, rollbackContextValid, discardCount)
				}
			case "begin_response_loss_model", "discard_response_rescue_model":
				if rollbackCount != 0 || discardCount != 1 {
					t.Errorf("uncertain BEGIN cleanup: rollback=%d discard=%d", rollbackCount, discardCount)
				}
			case "commit_pre_dispatch_model", "commit_response_loss_model":
				if commitCount != 1 || rollbackCount != 0 || discardCount != 1 {
					t.Errorf("read COMMIT cleanup: commit=%d rollback=%d discard=%d", commitCount, rollbackCount, discardCount)
				}
			}
			if fault != "already_canceled" && fault != "cancel_after_begin" && fault != "cancel_after_first_query" {
				if stats := store.db.Stats(); stats.OpenConnections != 0 || stats.Idle != 0 {
					t.Errorf("uncertain connection returned to pool: open=%d idle=%d", stats.OpenConnections, stats.Idle)
				}
			}
			discarded := fault != "already_canceled" && fault != "cancel_after_begin" && fault != "cancel_after_first_query"
			a1ReadAssertRecovery(t, store, keys, digest, before, discarded, original)
		})
	}
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
			d1RetainDriverConn(t, raw)
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

// d1DriverConnIdentity returns the address of conn's driver connection. The
// address names that connection until the test ends, because
// d1RetainDriverConn keeps the connection object reachable until then.
func d1DriverConnIdentity(t *testing.T, conn *sql.Conn) uintptr {
	t.Helper()
	var identity uintptr
	if err := conn.Raw(func(raw any) error {
		value := reflect.ValueOf(raw)
		if value.Kind() != reflect.Pointer || value.IsNil() {
			return errClaimStoreInternal
		}
		identity = value.Pointer()
		d1RetainDriverConn(t, raw)
		return nil
	}); err != nil || identity == 0 {
		t.Fatalf("driver connection identity unavailable: %v", err)
	}
	return identity
}

// d1RetainDriverConn keeps a driver connection object reachable until t ends.
// The tests name a driver connection by its address, and Go may give the
// address of an object it has freed to a new object of the same size. Without
// this, a connection that the pool discarded could be freed after its address
// was recorded, the next connection could be allocated at that address, and a
// test that requires a fresh connection would fail although the connection is
// new. Two recorded addresses are therefore equal exactly when they name the
// same connection. The object is only kept; nothing calls it outside Raw.
func d1RetainDriverConn(t *testing.T, raw any) {
	t.Cleanup(func() { runtime.KeepAlive(raw) })
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
