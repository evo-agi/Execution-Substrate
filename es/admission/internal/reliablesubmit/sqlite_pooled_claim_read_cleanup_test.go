package reliablesubmit

import (
	"context"
	"database/sql"
	"errors"
	"reflect"
	"testing"
	"time"
)

// Only the specified response faults are synthetic. Lookup, transaction
// statements, checked pool reuse and the durable follow-up use real SQLite.
func TestSQLitePooledClaimReadCleanup(t *testing.T) {
	for _, tc := range []struct {
		name                  string
		want                  error
		begin, read, commit   int
		rollback, discard     int
		rescue, ordinaryClose int
	}{
		{"CancelAfterRealBegin", errClaimStoreUnavailable, 1, 0, 0, 1, 0, 0, 1},
		{"CancelAfterRealSelect", errClaimStoreUnavailable, 1, 1, 0, 1, 0, 0, 1},
		{"AmbiguousRealBegin", errClaimStoreUnavailable, 1, 0, 0, 0, 1, 0, 1},
		{"AmbiguousReadCommit", errClaimStoreUnavailable, 1, 1, 1, 0, 1, 0, 1},
		{"RollbackError", errClaimStoreUnavailable, 1, 0, 0, 1, 1, 0, 1},
		{"ExpiredRollbackNilResponse", errClaimStoreUnavailable, 1, 0, 0, 1, 1, 0, 1},
		{"TimelyRollback", errClaimStoreNotFound, 1, 0, 0, 1, 0, 0, 1},
		{"DiscardRescue", errClaimStoreUnavailable, 1, 0, 0, 1, 1, 1, 1},
		{"DoubleDiscardWithholds", errClaimStoreUnavailable, 1, 0, 0, 1, 1, 1, 0},
		{"PreDispatchCancellation", errClaimStoreUnavailable, 0, 0, 0, 0, 0, 0, 0},
		{"InvalidBeforeCancellation", errClaimStoreInternal, 0, 0, 0, 0, 0, 0, 0},
		{"OrdinaryNotFound", errClaimStoreNotFound, 1, 0, 0, 1, 0, 0, 1},
		{"OrdinaryCorrupt", errClaimStoreCorrupt, 1, 0, 0, 1, 0, 0, 1},
		{"OrdinaryRead", nil, 1, 1, 1, 0, 0, 0, 1},
		{"CanceledAfterKnownReadCommit", errClaimStoreUnavailable, 1, 1, 1, 0, 0, 0, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store, f, current, cas := legacyCASFixture(t)
			ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
			defer cancel()

			query := loadClaimQuery{claim: f.claim}
			var droppedGuard string
			switch tc.name {
			case "RollbackError", "ExpiredRollbackNilResponse", "TimelyRollback", "DiscardRescue", "DoubleDiscardWithholds", "OrdinaryNotFound":
				query.claim = mustPrivateClaimID(t, mustPrivateCallerRef(t, []byte("pooled-reader-absent")), f.submitKey)
			case "OrdinaryCorrupt":
				droppedGuard = pooledReadFixturePhase(t, store, 99, "")
			case "InvalidBeforeCancellation":
				query.claim = ClaimID{}
				cancel()
			case "PreDispatchCancellation":
				cancel()
			}
			fault := errors.New("injected pooled read boundary response")
			var began, read, committed, rolled, discarded, rescued, closed int
			var original uintptr
			var cleanup context.Context
			separateCleanup, expired, lateNil := false, false, false
			store.pooledReadTest = &sqlitePooledReadTestHooks{
				begin: func(ctx context.Context, conn *sql.Conn) error {
					began++
					original = d1DriverConnIdentity(t, conn)
					if err := beginRead(ctx, conn); err != nil {
						return err
					}
					if tc.name == "AmbiguousRealBegin" {
						return fault
					}
					return nil
				},
				afterBegin: func() {
					if tc.name == "CancelAfterRealBegin" {
						cancel()
					}
				},
				afterSelect: func() {
					read++
					if tc.name == "CancelAfterRealSelect" {
						cancel()
					}
				},
				commit: func(ctx context.Context, conn *sql.Conn) error {
					committed++
					if err := commit(ctx, conn); err != nil {
						return err
					}
					switch tc.name {
					case "AmbiguousReadCommit":
						return fault
					case "CanceledAfterKnownReadCommit":
						cancel()
					}
					return nil
				},
				rollback: func(clean context.Context, conn *sql.Conn) error {
					rolled++
					cleanup = clean
					deadline, bounded := clean.Deadline()
					separateCleanup = clean != ctx && bounded && clean.Err() == nil && time.Until(deadline) <= 5*time.Second
					switch tc.name {
					case "RollbackError", "DiscardRescue", "DoubleDiscardWithholds":
						return fault
					case "ExpiredRollbackNilResponse":
						if !separateCleanup {
							return fault // Old reader does not start an independent deadline.
						}
						<-clean.Done()
						expired = errors.Is(clean.Err(), context.DeadlineExceeded)
						live, stop := context.WithTimeout(context.Background(), 5*time.Second)
						defer stop()
						_, err := conn.ExecContext(live, "ROLLBACK")
						lateNil = err == nil
						return err
					}
					_, err := conn.ExecContext(clean, "ROLLBACK")
					return err
				},
				firstDiscard: func(conn *sql.Conn) error {
					discarded++
					if d1DriverConnIdentity(t, conn) != original {
						t.Error("discard did not own the dispatched driver connection")
					}
					if tc.name == "DiscardRescue" || tc.name == "DoubleDiscardWithholds" {
						return fault
					}
					return discardUncertainSQLiteConn(conn)
				},
				rescueResponse: func(err error) error {
					rescued++
					if err != nil {
						t.Errorf("real rescue response: %v", err)
					}
					if tc.name == "DoubleDiscardWithholds" {
						return fault // Model an unconfirmed response after real quarantine.
					}
					return err
				},
				beforePoolReturn: func() { closed++ },
			}
			got, err := store.loadClaim(ctx, query)
			store.pooledReadTest = nil
			if !errors.Is(err, tc.want) {
				t.Errorf("read disposition: got %v, want %v", err, tc.want)
			}
			if err == nil {
				if !got.equal(current) {
					t.Error("ordinary read did not return the existing record")
				}
			} else if !reflect.DeepEqual(got, durableClaimRecord{}) {
				t.Error("refusal returned a nonzero record")
			}
			if began != tc.begin || read != tc.read || committed != tc.commit ||
				rolled != tc.rollback || discarded != tc.discard || rescued != tc.rescue || closed != tc.ordinaryClose {
				t.Errorf("boundary counts: begin=%d select=%d commit=%d rollback=%d discard=%d rescue=%d return=%d",
					began, read, committed, rolled, discarded, rescued, closed)
			}
			if tc.rollback != 0 && (!separateCleanup || cleanup.Err() == nil) {
				t.Error("rollback did not get and release an independent bounded context")
			}
			if tc.name == "ExpiredRollbackNilResponse" && (!expired || !lateNil) {
				t.Error("did not observe real cleanup expiry followed by a successful real rollback response")
			}
			if tc.discard != 0 && tc.name != "DoubleDiscardWithholds" && store.db.Stats().Idle != 0 {
				t.Error("discarded connection could return to the idle pool")
			}
			if tc.name == "DoubleDiscardWithholds" {
				return // The contract withholds the wrapper and gives no healthy reuse guarantee.
			}
			if tc.name == "OrdinaryCorrupt" {
				pooledReadFixturePhase(t, store, int(current.phase.tag), droppedGuard)
			}
			independentDB, independent := c1IndependentSQLiteConn(t, store.path)
			defer independentDB.Close()
			defer independent.Close()
			durable, err := store.selectSQLiteClaim(context.Background(), independent, f.claim)
			if err != nil || !durable.equal(current) {
				t.Errorf("independent durable state after read: %v", err)
			}
			if _, err := independent.ExecContext(context.Background(), "BEGIN IMMEDIATE"); err != nil {
				t.Fatalf("independent writer: %v", err)
			}
			if _, err := independent.ExecContext(context.Background(), "ROLLBACK"); err != nil {
				t.Fatalf("independent writer rollback: %v", err)
			}
			follow, stop := context.WithTimeout(context.Background(), 5*time.Second)
			defer stop()
			later, err := store.loadClaim(follow, loadClaimQuery{claim: f.claim})
			if err != nil || !later.equal(current) {
				t.Errorf("fresh-context same-store read: %v", err)
				probe, probeErr := store.checkedConn(follow)
				if probeErr == nil {
					if _, probeErr = probe.ExecContext(follow, "BEGIN"); probeErr == nil {
						_, _ = probe.ExecContext(follow, "ROLLBACK")
					}
					_ = probe.Close()
					t.Logf("actual same-store direct BEGIN after follow-up: %v", probeErr)
				}
			}
			applied, err := store.compareAndSwapClaim(follow, cas)
			if err != nil || !applied.applied || !applied.record.equal(cas.next) {
				t.Errorf("fresh-context same-store CAS: %v", err)
			}
		})
	}
}

func pooledReadFixturePhase(t *testing.T, store *sqliteClaimStore, phase int, restore string) string {
	t.Helper()
	ctx := context.Background()
	conn, err := store.checkedConn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	var guard string
	if restore == "" {
		if err := conn.QueryRowContext(ctx, "SELECT sql FROM sqlite_schema WHERE name='reliable_submit_claims_guard_update'").Scan(&guard); err != nil {
			t.Fatal(err)
		}
		if _, err := conn.ExecContext(ctx, "DROP TRIGGER reliable_submit_claims_guard_update"); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := conn.ExecContext(ctx, "PRAGMA ignore_check_constraints=ON"); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.ExecContext(ctx, "UPDATE reliable_submit_claims SET phase_tag=?", phase); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.ExecContext(ctx, "PRAGMA ignore_check_constraints=OFF"); err != nil {
		t.Fatal(err)
	}
	if restore != "" {
		if _, err := conn.ExecContext(ctx, restore); err != nil {
			t.Fatal(err)
		}
	}
	return guard
}
