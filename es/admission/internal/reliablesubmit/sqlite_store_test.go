package reliablesubmit

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func mustOpenSQLiteClaimStore(t *testing.T, path string) *sqliteClaimStore {
	t.Helper()
	store, err := openSQLiteClaimStore(context.Background(), sqliteClaimStoreOptions{path: path})
	if err != nil {
		t.Fatalf("openSQLiteClaimStore: %v", err)
	}
	return store
}

func TestSQLiteClaimStoreConformance(t *testing.T) {
	runClaimStoreConformance(t, claimStoreConformanceFactory{
		name: "sqlite",
		open: func(t *testing.T) claimStoreConformanceHandle {
			t.Helper()
			path := sqliteTestPath(t, "state", "reliable-submit.sqlite3")
			store := mustOpenSQLiteClaimStore(t, path)
			return sqliteClaimStoreConformanceHandle(t, path, store)
		},
	})
}

func sqliteClaimStoreConformanceHandle(t *testing.T, path string, store *sqliteClaimStore) claimStoreConformanceHandle {
	t.Helper()
	return claimStoreConformanceHandle{
		store: store,
		close: func(t *testing.T) {
			t.Helper()
			if err := store.close(); err != nil {
				t.Fatalf("close claim store: %v", err)
			}
		},
		reopen: func(t *testing.T) claimStoreConformanceHandle {
			t.Helper()
			return sqliteClaimStoreConformanceHandle(t, path, mustOpenSQLiteClaimStore(t, path))
		},
	}
}

func TestSQLiteClaimStoreEstablishInsertTargetsCallerKeyConflictOnly(t *testing.T) {
	normalized := strings.Join(strings.Fields(sqliteInsertClaimSQL), " ")
	upper := strings.ToUpper(normalized)
	if strings.Contains(upper, "INSERT OR IGNORE") {
		t.Fatalf("establish insert must not use broad INSERT OR IGNORE")
	}
	if strings.Contains(upper, "REPLACE") {
		t.Fatalf("establish insert must not use replacement semantics")
	}
	if strings.Contains(normalized, "ON CONFLICT DO NOTHING") {
		t.Fatalf("establish insert must not use targetless DO NOTHING")
	}
	if strings.Count(normalized, "ON CONFLICT") != 1 {
		t.Fatalf("establish insert conflict handling is not singular")
	}
	if !strings.Contains(normalized, "ON CONFLICT(caller_ref, submit_key_ref) DO NOTHING") {
		t.Fatalf("establish insert must target only caller_ref and submit_key_ref")
	}
}

func TestSQLiteClaimStoreTargetedCallerKeyConflictLoadsExistingClaim(t *testing.T) {
	path := sqliteTestPath(t, "state", "reliable-submit.sqlite3")
	store := mustOpenSQLiteClaimStore(t, path)
	defer store.close()
	f := newDurableFixture(t)
	service := mustDurableService(t, store, fixedClaimClock{now: f.now})
	created := mustServiceEstablish(t, service, f)
	if created.kind != durableClaimOutcomeEstablished || !created.hasRecord {
		t.Fatalf("created outcome = %+v", created)
	}

	existing, err := store.establishClaim(context.Background(), establishClaimCommand{record: created.record})
	if err != nil {
		t.Fatalf("direct duplicate establish: %v", err)
	}
	if existing.created {
		t.Fatalf("duplicate caller/key was reported as a new claim")
	}
	if !existing.record.equal(created.record) {
		t.Fatalf("duplicate caller/key did not load the existing record")
	}
	assertSQLiteClaimUnchanged(t, store, created.record)
	assertSQLiteClaimRowCount(t, store.db, 1)

	replayed, err := service.establishOrLoadClaim(context.Background(), establishClaimRequest{
		claim:    f.claim,
		plan:     f.plan,
		mutation: f.nextMut,
	})
	if err != nil {
		t.Fatalf("service replay after duplicate: %v", err)
	}
	if replayed.kind != durableClaimOutcomeExactReplay || replayed.underlyingReplayKind != KindPendingBeforeAssignment {
		t.Fatalf("service replay outcome = %+v", replayed)
	}
	conflictPlan := mustPrivateBoundPlan(t, f.otherBind, f.witness)
	conflict, err := service.establishOrLoadClaim(context.Background(), establishClaimRequest{
		claim:    f.claim,
		plan:     conflictPlan,
		mutation: mustPrivateMutationRef(t, []byte("private-conflict-mutation")),
	})
	if err != nil {
		t.Fatalf("service conflict after duplicate: %v", err)
	}
	if conflict.kind != durableClaimOutcomeConflict || conflict.hasRecord {
		t.Fatalf("service conflict outcome = %+v", conflict)
	}
	assertSQLiteClaimUnchanged(t, store, created.record)
	assertSQLiteClaimRowCount(t, store.db, 1)
}

func TestSQLiteClaimStoreEmptyDBMigratesToV1AndReopenIsIdempotent(t *testing.T) {
	path := sqliteTestPath(t, "state", "reliable-submit.sqlite3")
	store := mustOpenSQLiteClaimStore(t, path)
	assertSQLitePragmaInt(t, store.db, "application_id", sqliteClaimStoreApplicationID)
	assertSQLitePragmaInt(t, store.db, "user_version", sqliteClaimStoreSchemaVersion)
	var migrationCount int
	if err := store.db.QueryRow(`SELECT count(*) FROM reliable_submit_migrations WHERE version = 1`).Scan(&migrationCount); err != nil {
		t.Fatalf("query migrations: %v", err)
	}
	if migrationCount != 1 {
		t.Fatalf("migration count = %d, want 1", migrationCount)
	}
	if err := store.close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	reopened := mustOpenSQLiteClaimStore(t, path)
	defer reopened.close()
	assertSQLitePragmaInt(t, reopened.db, "user_version", sqliteClaimStoreSchemaVersion)
}

func TestSQLiteClaimStoreRejectsForeignZeroVersionDatabaseWithoutClaiming(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup []string
	}{
		{name: "table", setup: []string{`CREATE TABLE foreign_claims(id INTEGER PRIMARY KEY)`}},
		{name: "view", setup: []string{`CREATE TABLE foreign_claims(id INTEGER PRIMARY KEY)`, `CREATE VIEW foreign_view AS SELECT id FROM foreign_claims`}},
		{name: "index", setup: []string{`CREATE TABLE foreign_claims(id INTEGER PRIMARY KEY, value TEXT)`, `CREATE INDEX foreign_index ON foreign_claims(value)`}},
		{name: "trigger", setup: []string{`CREATE TABLE foreign_claims(id INTEGER PRIMARY KEY, value TEXT)`, `CREATE TRIGGER foreign_trigger AFTER INSERT ON foreign_claims BEGIN UPDATE foreign_claims SET value = NEW.value WHERE id = NEW.id; END`}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := sqliteTestPath(t, "state", "foreign-"+tc.name+".sqlite3")
			db := mustRawSQLiteDB(t, path)
			for _, stmt := range tc.setup {
				if _, err := db.Exec(stmt); err != nil {
					t.Fatalf("create foreign schema: %v", err)
				}
			}
			assertSQLitePragmaInt(t, db, "application_id", 0)
			assertSQLitePragmaInt(t, db, "user_version", 0)
			if err := db.Close(); err != nil {
				t.Fatalf("close foreign db: %v", err)
			}

			_, err := openSQLiteClaimStore(context.Background(), sqliteClaimStoreOptions{path: path})
			if !errors.Is(err, errClaimStoreUnsupported) {
				t.Fatalf("foreign zero-version db error = %v", err)
			}

			reopened := mustRawSQLiteDB(t, path)
			defer reopened.Close()
			assertSQLitePragmaInt(t, reopened, "application_id", 0)
			assertSQLitePragmaInt(t, reopened, "user_version", 0)
			var reliableObjects int
			if err := reopened.QueryRow(`SELECT count(*) FROM sqlite_schema WHERE name LIKE 'reliable_submit_%'`).Scan(&reliableObjects); err != nil {
				t.Fatalf("query reliable objects: %v", err)
			}
			if reliableObjects != 0 {
				t.Fatalf("foreign database was claimed with %d reliable-submit objects", reliableObjects)
			}
		})
	}
}

func TestSQLiteClaimStoreRejectsWrongApplicationIDFutureVersionAndMigrationDrift(t *testing.T) {
	t.Run("wrong application id", func(t *testing.T) {
		path := sqliteTestPath(t, "state", "wrong-app.sqlite3")
		db := mustRawSQLiteDB(t, path)
		if _, err := db.Exec(`PRAGMA application_id = 1234`); err != nil {
			t.Fatalf("set application id: %v", err)
		}
		if err := db.Close(); err != nil {
			t.Fatalf("close raw db: %v", err)
		}
		_, err := openSQLiteClaimStore(context.Background(), sqliteClaimStoreOptions{path: path})
		if !errors.Is(err, errClaimStoreUnsupported) {
			t.Fatalf("wrong app id error = %v", err)
		}
	})

	t.Run("future user version", func(t *testing.T) {
		path := sqliteTestPath(t, "state", "future.sqlite3")
		db := mustRawSQLiteDB(t, path)
		if _, err := db.Exec(`PRAGMA application_id = 1163088467`); err != nil {
			t.Fatalf("set application id: %v", err)
		}
		if _, err := db.Exec(`PRAGMA user_version = 99`); err != nil {
			t.Fatalf("set user version: %v", err)
		}
		if err := db.Close(); err != nil {
			t.Fatalf("close raw db: %v", err)
		}
		_, err := openSQLiteClaimStore(context.Background(), sqliteClaimStoreOptions{path: path})
		if !errors.Is(err, errClaimStoreUnsupported) {
			t.Fatalf("future version error = %v", err)
		}
	})

	t.Run("migration drift", func(t *testing.T) {
		path := sqliteTestPath(t, "state", "drift.sqlite3")
		store := mustOpenSQLiteClaimStore(t, path)
		if _, err := store.db.Exec(`UPDATE reliable_submit_migrations SET source_sha256 = '0000000000000000000000000000000000000000000000000000000000000000' WHERE version = 1`); err != nil {
			t.Fatalf("mutate migration metadata: %v", err)
		}
		if err := store.close(); err != nil {
			t.Fatalf("close: %v", err)
		}
		_, err := openSQLiteClaimStore(context.Background(), sqliteClaimStoreOptions{path: path})
		if !errors.Is(err, errClaimStoreUnsupported) {
			t.Fatalf("migration drift error = %v", err)
		}
	})
}

func TestSQLiteClaimStoreTargetedConflictDoesNotSuppressInvalidCandidateConstraints(t *testing.T) {
	path := sqliteTestPath(t, "state", "reliable-submit.sqlite3")
	store := mustOpenSQLiteClaimStore(t, path)
	defer store.close()
	f := newDurableFixture(t)
	service := mustDurableService(t, store, fixedClaimClock{now: f.now})
	created := mustServiceEstablish(t, service, f)
	if created.kind != durableClaimOutcomeEstablished || !created.hasRecord {
		t.Fatalf("created outcome = %+v", created)
	}

	tests := []struct {
		name   string
		mutate func([]any)
	}{
		{
			name: "check constraint",
			mutate: func(args []any) {
				args[sqliteClaimArgPlanBinding] = []byte{}
			},
		},
		{
			name: "not null constraint",
			mutate: func(args []any) {
				args[sqliteClaimArgPlanBinding] = nil
			},
		},
		{
			name: "phase run receipt compatibility",
			mutate: func(args []any) {
				args[sqliteClaimArgPhaseTag] = int64(durablePhaseAccepted)
			},
		},
		{
			name: "witness mask validity",
			mutate: func(args []any) {
				args[sqliteClaimArgWitnessInapplicableMask] = int64(1)
			},
		},
		{
			name: "codec version",
			mutate: func(args []any) {
				args[sqliteClaimArgCodecVersion] = int64(durableClaimCodecVersion + 1)
			},
		},
		{
			name: "revision",
			mutate: func(args []any) {
				args[sqliteClaimArgRevision] = int64(0)
			},
		},
		{
			name: "retention",
			mutate: func(args []any) {
				args[sqliteClaimArgRetentionState] = int64(durableRetentionExpired)
			},
		},
		{
			name: "effect ordering",
			mutate: func(args []any) {
				args[sqliteClaimArgProviderObservationKind] = int64(durableProviderObservationPending)
				args[sqliteClaimArgProviderObservationRef] = factRefBytes(f.observation)
				args[sqliteClaimArgProviderObservationAt] = f.now.UnixNano()
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assertSQLiteTargetedInsertConstraintFailure(t, store, created.record, tc.name, tc.mutate)
		})
	}
}

func TestSQLiteClaimStoreEstablishRejectsInvalidDurableCandidateBeforeSQL(t *testing.T) {
	path := sqliteTestPath(t, "state", "reliable-submit.sqlite3")
	store := mustOpenSQLiteClaimStore(t, path)
	defer store.close()
	f := newDurableFixture(t)
	service := mustDurableService(t, store, fixedClaimClock{now: f.now})
	created := mustServiceEstablish(t, service, f)

	invalid := created.record.clone()
	invalid.codecVersion = durableClaimCodecVersion + 1
	result, err := store.establishClaim(context.Background(), establishClaimCommand{record: invalid})
	if !errors.Is(err, errClaimStoreCorrupt) {
		t.Fatalf("invalid durable candidate did not fail closed")
	}
	if result.created || result.record.claim.Valid() {
		t.Fatalf("invalid durable candidate returned an establish result")
	}
	assertSQLiteStoreErrorSanitized(t, "invalid durable candidate", err)
	assertSQLiteClaimUnchanged(t, store, created.record)
	assertSQLiteClaimRowCount(t, store.db, 1)
}

func TestSQLiteClaimStoreZeroRowConflictFailsClosedWhenExistingRowIsInvalid(t *testing.T) {
	path := sqliteTestPath(t, "state", "reliable-submit.sqlite3")
	store := mustOpenSQLiteClaimStore(t, path)
	defer store.close()
	f := newDurableFixture(t)
	original := mustPrivateRecord(t, mustPrivatePendingBefore(t, f), f)
	args, err := sqliteRecordArgs(original)
	if err != nil {
		t.Fatalf("sqliteRecordArgs: %v", err)
	}
	args[sqliteClaimArgCodecVersion] = int64(durableClaimCodecVersion + 1)
	if _, err := store.db.Exec(`PRAGMA ignore_check_constraints=ON`); err != nil {
		t.Fatalf("enable constraint bypass: %v", err)
	}
	if _, err := store.db.Exec(sqliteInsertClaimSQL, args...); err != nil {
		t.Fatalf("seed invalid existing row: %v", err)
	}
	if _, err := store.db.Exec(`PRAGMA ignore_check_constraints=OFF`); err != nil {
		t.Fatalf("disable constraint bypass: %v", err)
	}

	result, err := store.establishClaim(context.Background(), establishClaimCommand{record: original})
	if !errors.Is(err, errClaimStoreCorrupt) {
		t.Fatalf("invalid existing row did not fail closed")
	}
	if result.created || result.record.claim.Valid() {
		t.Fatalf("invalid existing row returned an establish result")
	}
	assertSQLiteStoreErrorSanitized(t, "invalid existing row", err)
	assertSQLiteClaimRowCount(t, store.db, 1)
}

func TestSQLiteClaimStoreDirectSQLConstraintsAndTriggers(t *testing.T) {
	path := sqliteTestPath(t, "state", "reliable-submit.sqlite3")
	store := mustOpenSQLiteClaimStore(t, path)
	defer store.close()
	f := newDurableFixture(t)
	service := mustDurableService(t, store, fixedClaimClock{now: f.now})
	created := mustServiceEstablish(t, service, f)

	if _, err := store.db.Exec(`DELETE FROM reliable_submit_claims`); err == nil || !strings.Contains(err.Error(), "deletion is forbidden") {
		t.Fatalf("delete trigger error = %v", err)
	}
	if _, err := store.db.Exec(`UPDATE reliable_submit_claims SET revision = revision + 2`); err == nil || !strings.Contains(err.Error(), "revision must increment") {
		t.Fatalf("revision trigger error = %v", err)
	}
	if _, err := store.db.Exec(`UPDATE reliable_submit_claims SET run_ref = ? WHERE caller_ref = ? AND submit_key_ref = ?`,
		[]byte("bad-run"),
		opaqueRefBytes(created.record.claim.caller.ref),
		opaqueRefBytes(created.record.claim.submitKey.ref),
	); err == nil {
		t.Fatalf("expected phase/run compatibility check failure")
	}

	pendingProvider := mustSQLiteRecordForEffects(t, f, mustPendingAfterAssignment(t, f), durableEffectFacts{
		intent:   newDurableEffectRefTime(f.intent, f.now),
		dispatch: newDurableEffectRefTime(f.dispatch, f.now),
		provider: durableProviderObservation{
			kind: durableProviderObservationPending,
			fact: newDurableEffectRefTime(f.observation, f.now),
		},
	})
	assertSQLiteInsertRejected(t, store.db, pendingProvider, "provider observation must progress phase", func(args []any) {
		setSQLiteClaimArgsIdentity(args, "provider-phase")
		args[sqliteClaimArgPhaseTag] = int64(durablePhaseEffectCapableAssigned)
	})

	noDispatchReconciliation := mustSQLiteRecordForEffects(t, f, mustPrivateAssigned(t, f), durableEffectFacts{
		intent: newDurableEffectRefTime(f.intent, f.now),
		reconciliation: durableReconciliationFact{
			kind: durableReconciliationNoDispatch,
			fact: newDurableEffectRefTime(f.reconcile, f.now),
		},
	})
	assertSQLiteInsertRejected(t, store.db, noDispatchReconciliation, "no-dispatch reconciliation rejects marker", func(args []any) {
		setSQLiteClaimArgsIdentity(args, "no-dispatch-marker")
		args[sqliteClaimArgDispatchRef] = factRefBytes(f.dispatch)
		args[sqliteClaimArgDispatchAt] = f.now.UnixNano()
	})

	pendingReconciliation := mustSQLiteRecordForEffects(t, f, mustPendingAfterAssignment(t, f), durableEffectFacts{
		intent:   newDurableEffectRefTime(f.intent, f.now),
		dispatch: newDurableEffectRefTime(f.dispatch, f.now),
		reconciliation: durableReconciliationFact{
			kind: durableReconciliationPending,
			fact: newDurableEffectRefTime(f.reconcile, f.now),
		},
	})
	assertSQLiteInsertRejected(t, store.db, pendingReconciliation, "pending reconciliation requires marker", func(args []any) {
		setSQLiteClaimArgsIdentity(args, "pending-reconcile-no-marker")
		args[sqliteClaimArgDispatchRef] = nil
		args[sqliteClaimArgDispatchAt] = nil
	})

	notAcceptedReconciliation := mustSQLiteRecordForEffects(t, f, mustNotAcceptedAfterAssignment(t, f), durableEffectFacts{
		intent:   newDurableEffectRefTime(f.intent, f.now),
		dispatch: newDurableEffectRefTime(f.dispatch, f.now),
		reconciliation: durableReconciliationFact{
			kind: durableReconciliationNotAccepted,
			fact: newDurableEffectRefTime(f.reconcile, f.now),
		},
	})
	args, err := sqliteRecordArgs(notAcceptedReconciliation)
	if err != nil {
		t.Fatalf("not accepted reconciliation args: %v", err)
	}
	setSQLiteClaimArgsIdentity(args, "not-accepted-reconcile")
	if _, err := store.db.Exec(sqliteInsertClaimSQL, args...); err != nil {
		t.Fatalf("valid not-accepted reconciliation insert: %v", err)
	}
}

const (
	sqliteClaimArgCallerRef               = 0
	sqliteClaimArgSubmitKeyRef            = 1
	sqliteClaimArgPlanBinding             = 2
	sqliteClaimArgWitnessInapplicableMask = 4
	sqliteClaimArgPhaseTag                = 5
	sqliteClaimArgRevision                = 8
	sqliteClaimArgDispatchRef             = 16
	sqliteClaimArgDispatchAt              = 17
	sqliteClaimArgProviderObservationKind = 18
	sqliteClaimArgProviderObservationRef  = 19
	sqliteClaimArgProviderObservationAt   = 20
	sqliteClaimArgRetentionState          = 25
	sqliteClaimArgCodecVersion            = 29
)

func setSQLiteClaimArgsIdentity(args []any, suffix string) {
	args[sqliteClaimArgCallerRef] = []byte("private-sql-caller-" + suffix)
	args[sqliteClaimArgSubmitKeyRef] = []byte("private-sql-key-" + suffix)
}

func assertSQLiteInsertRejected(t *testing.T, db *sql.DB, record durableClaimRecord, label string, mutate func([]any)) {
	t.Helper()
	args, err := sqliteRecordArgs(record)
	if err != nil {
		t.Fatalf("%s sqliteRecordArgs: %v", label, err)
	}
	mutate(args)
	if _, err := db.Exec(sqliteInsertClaimSQL, args...); err == nil {
		t.Fatalf("expected %s insert to fail", label)
	}
}

func mustSQLiteRecordForEffects(t *testing.T, f durableFixture, phase ClaimPhase, effects durableEffectFacts) durableClaimRecord {
	t.Helper()
	record, err := newDurableClaimRecord(newDurableClaimRecordInput{
		phase:        phase,
		revision:     initialClaimRevision,
		createdAt:    f.now,
		updatedAt:    f.now,
		assignedAt:   assignedAtForPhase(phase, f.now),
		effects:      effects,
		retention:    activeDurableRetention(),
		lastMutation: f.mutation,
	})
	if err != nil {
		t.Fatalf("new durable record for sqlite effects: %v", err)
	}
	return record
}

func mustPendingAfterAssignment(t *testing.T, f durableFixture) PendingAfterAssignment {
	t.Helper()
	pending, err := NewPendingAfterAssignment(mustPrivateAssigned(t, f))
	if err != nil {
		t.Fatalf("NewPendingAfterAssignment: %v", err)
	}
	return pending
}

func mustNotAcceptedAfterAssignment(t *testing.T, f durableFixture) ProvablyNotAcceptedAfterAssignment {
	t.Helper()
	notAccepted, err := NewProvablyNotAcceptedAfterAssignment(mustPrivateAssigned(t, f))
	if err != nil {
		t.Fatalf("NewProvablyNotAcceptedAfterAssignment: %v", err)
	}
	return notAccepted
}

func assertSQLiteTargetedInsertConstraintFailure(t *testing.T, store *sqliteClaimStore, original durableClaimRecord, label string, mutate func([]any)) {
	t.Helper()
	args, err := sqliteRecordArgs(original)
	if err != nil {
		t.Fatalf("%s sqliteRecordArgs: %v", label, err)
	}
	mutate(args)
	result, err := store.db.Exec(sqliteInsertClaimSQL, args...)
	if err == nil {
		rows, _ := result.RowsAffected()
		t.Fatalf("%s insert reached conflict disposition with %d rows affected", label, rows)
	}
	mapped := mapSQLiteError(err)
	if !errors.Is(mapped, errClaimStoreCorrupt) {
		t.Fatalf("%s mapped error did not fail closed", label)
	}
	assertSQLiteStoreErrorSanitized(t, label, mapped)
	assertSQLiteClaimUnchanged(t, store, original)
	assertSQLiteClaimRowCount(t, store.db, 1)
}

func assertSQLiteClaimUnchanged(t *testing.T, store *sqliteClaimStore, want durableClaimRecord) {
	t.Helper()
	loaded, err := store.loadClaim(context.Background(), loadClaimQuery{claim: want.claim})
	if err != nil {
		t.Fatalf("load expected claim: %v", err)
	}
	if !loaded.equal(want) {
		t.Fatalf("stored claim changed")
	}
}

func assertSQLiteClaimRowCount(t *testing.T, db *sql.DB, want int) {
	t.Helper()
	var got int
	if err := db.QueryRow(`SELECT count(*) FROM reliable_submit_claims`).Scan(&got); err != nil {
		t.Fatalf("query claim row count: %v", err)
	}
	if got != want {
		t.Fatalf("claim row count = %d, want %d", got, want)
	}
}

func assertSQLiteStoreErrorSanitized(t *testing.T, label string, err error) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s error is nil", label)
	}
	message := err.Error()
	for _, forbidden := range []string{
		"private-caller-reference",
		"private-submit-key-reference",
		"private-plan-binding",
		"private-plan-binding-other",
		"private-run-reference",
		"private-receipt-reference",
		"private-mutation-reference",
		"private-effect-intent",
		"private-staging-evidence",
		"private-dispatch-attempt",
		"private-provider-observation",
		"private-reconciliation",
		"caller_ref",
		"submit_key_ref",
		"reliable_submit_claims",
		"INSERT",
	} {
		if strings.Contains(message, forbidden) {
			t.Fatalf("%s error exposed forbidden diagnostic", label)
		}
	}
	lower := strings.ToLower(message)
	for _, forbidden := range []string{"sqlite", "constraint", "check failed", "not null"} {
		if strings.Contains(lower, forbidden) {
			t.Fatalf("%s error exposed raw storage diagnostic", label)
		}
	}
}

func assertSQLitePragmaInt(t *testing.T, db *sql.DB, name string, want int) {
	t.Helper()
	var got int
	if err := db.QueryRow(`PRAGMA ` + name).Scan(&got); err != nil {
		t.Fatalf("PRAGMA %s: %v", name, err)
	}
	if got != want {
		t.Fatalf("PRAGMA %s = %d, want %d", name, got, want)
	}
}

func mustRawSQLiteDB(t *testing.T, path string) *sql.DB {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("mkdir raw db parent: %v", err)
	}
	db, err := sql.Open("sqlite", sqliteClaimStoreDSN(path, sqliteDefaultBusyTimeoutMS))
	if err != nil {
		t.Fatalf("open raw sqlite: %v", err)
	}
	return db
}

func sqliteTestPath(t *testing.T, elem ...string) string {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("canonicalize temp dir: %v", err)
	}
	parts := append([]string{root}, elem...)
	return filepath.Join(parts...)
}
