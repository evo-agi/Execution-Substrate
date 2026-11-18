package reliablesubmit

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func fixtureSchemaVersion(t *testing.T, path string, version int) []any {
	t.Helper()
	if version == 0 {
		return nil
	}
	ctx := context.Background()
	db, err := sql.Open("sqlite", sqliteClaimStoreDSN(path, sqliteDefaultBusyTimeoutMS))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.ExecContext(ctx, fmt.Sprintf("PRAGMA application_id=%d", sqliteClaimStoreApplicationID)); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < version; i++ {
		migration := sqliteClaimStoreMigrations[i]
		if _, err := db.ExecContext(ctx, migration.sql); err != nil {
			t.Fatal(err)
		}
		if _, err := db.ExecContext(ctx, `INSERT INTO reliable_submit_migrations(version,name,applied_at_unix_ns,source_sha256) VALUES (?,?,?,?)`, migration.version, migration.name, int64(1720000000000000000), sqliteMigrationSHA256(migration.sql)); err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			if _, err := db.ExecContext(ctx, `INSERT INTO reliable_submit_claims(caller_ref,submit_key_ref,plan_binding,witness_resolved_mask,witness_inapplicable_mask,phase_tag,revision,created_at_unix_ns,updated_at_unix_ns,retention_state,unavailable_reason,last_mutation_ref,codec_version)
VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`, []byte("c"), []byte("k"), bytes.Repeat([]byte("b"), 257), int64(16383), int64(0), int64(1), int64(1), int64(1720000000000000000), int64(1720000000000000000), int64(1), "", []byte("m"), int64(1)); err != nil {
				t.Fatal(err)
			}
		}
	}
	if _, err := db.ExecContext(ctx, fmt.Sprintf("PRAGMA user_version=%d", version)); err != nil {
		t.Fatal(err)
	}
	return fixtureLegacyProjection(t, db, version)
}

func fixtureLegacyProjection(t *testing.T, db *sql.DB, version int) []any {
	t.Helper()
	columns := sqliteClaimColumns
	if version == 1 {
		columns = strings.Replace(columns, "latest_operation_kind,\nlatest_operation_input_digest,", "NULL AS latest_operation_kind,\nNULL AS latest_operation_input_digest,", 1)
	}
	row := db.QueryRow(`SELECT claim_rowid, ` + columns + ` FROM reliable_submit_claims WHERE caller_ref=x'63' AND submit_key_ref=x'6b'`)
	values := make([]any, 33)
	dest := make([]any, 33)
	for i := range dest {
		dest[i] = &values[i]
	}
	if err := row.Scan(dest...); err != nil {
		t.Fatal(err)
	}
	return values
}

func fixtureAssertMigrationOutcome(t *testing.T, path string, opening int, preimage []any, expected int) {
	t.Helper()
	db, err := sql.Open("sqlite", sqliteClaimStoreDSN(path, sqliteDefaultBusyTimeoutMS))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var version int
	if err := db.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	if version != expected {
		t.Fatalf("opening %d ended at schema %d, want %d", opening, version, expected)
	}
	if opening > 0 {
		actual := fixtureLegacyProjection(t, db, expected)
		if !reflect.DeepEqual(preimage, actual) {
			t.Fatal("legacy rowid or inherited 32-column content changed")
		}
	}
	if expected == 3 {
		var migrations int
		if err := db.QueryRow(`SELECT count(*) FROM reliable_submit_migrations`).Scan(&migrations); err != nil || migrations != 3 {
			t.Fatalf("incomplete ledger: %d %v", migrations, err)
		}
	}
}

func fixtureMigrationPath(t *testing.T, name string) string {
	t.Helper()
	return filepath.Join(t.TempDir(), name+".sqlite3")
}

func TestSQLiteV3BootstrapCommitUnknownReopenZeroOrThree(t *testing.T) {
	for _, scenario := range []struct {
		name              string
		afterActualCommit bool
	}{
		{"interrupted_before_commit", false}, {"lost_response_after_commit", true},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			path := fixtureMigrationPath(t, "bootstrap")
			store, err := openSQLiteClaimStore(context.Background(), sqliteClaimStoreOptions{path: path,
				migrationCommit: func(ctx context.Context, conn *sql.Conn) error {
					if scenario.afterActualCommit {
						if err := commit(ctx, conn); err != nil {
							return err
						}
					} else {
						if err := conn.Close(); err != nil {
							return err
						}
					}
					return errClaimStoreCommitUnknown
				},
			})
			if scenario.afterActualCommit {
				if err != nil || store == nil || !store.migrationRecoveredNew {
					t.Fatalf("recovered-new: %v", err)
				}
				if err := store.close(); err != nil {
					t.Fatal(err)
				}
				fixtureAssertMigrationOutcome(t, path, 0, nil, 3)
			} else {
				if store != nil {
					_ = store.close()
					t.Fatal("interrupted bootstrap returned store")
				}
				if !errors.Is(err, errClaimStoreMigrationRecoveredOld) {
					t.Fatalf("recovered old: %v", err)
				}
				fixtureAssertMigrationOutcome(t, path, 0, nil, 0)
			}
		})
	}
}

func TestSQLiteV3UpgradeFromOneCommitUnknownNoIntermediateTwo(t *testing.T) {
	for _, committed := range []bool{false, true} {
		t.Run(fmt.Sprint(committed), func(t *testing.T) {
			path := fixtureMigrationPath(t, "from-one")
			preimage := fixtureSchemaVersion(t, path, 1)
			store, err := openSQLiteClaimStore(context.Background(), sqliteClaimStoreOptions{path: path,
				migrationCommit: func(ctx context.Context, conn *sql.Conn) error {
					if committed {
						if err := commit(ctx, conn); err != nil {
							return err
						}
					} else {
						if err := conn.Close(); err != nil {
							return err
						}
					}
					return errClaimStoreCommitUnknown
				},
			})
			if committed {
				if err != nil || store == nil || !store.migrationRecoveredNew {
					t.Fatalf("recovered-new: %v", err)
				}
				if err := store.close(); err != nil {
					t.Fatal(err)
				}
				fixtureAssertMigrationOutcome(t, path, 1, preimage, 3)
			} else {
				if store != nil {
					_ = store.close()
					t.Fatal("interrupted upgrade returned store")
				}
				if !errors.Is(err, errClaimStoreMigrationRecoveredOld) {
					t.Fatalf("recovered old: %v", err)
				}
				fixtureAssertMigrationOutcome(t, path, 1, preimage, 1)
			}
		})
	}
}

func TestSQLiteV3UpgradeFromTwoCommitUnknownOldOrNew(t *testing.T) {
	for _, committed := range []bool{false, true} {
		t.Run(fmt.Sprint(committed), func(t *testing.T) {
			path := fixtureMigrationPath(t, "from-two")
			preimage := fixtureSchemaVersion(t, path, 2)
			store, err := openSQLiteClaimStore(context.Background(), sqliteClaimStoreOptions{path: path,
				migrationCommit: func(ctx context.Context, conn *sql.Conn) error {
					if committed {
						if err := commit(ctx, conn); err != nil {
							return err
						}
					} else {
						if err := conn.Close(); err != nil {
							return err
						}
					}
					return errClaimStoreCommitUnknown
				},
			})
			if committed {
				if err != nil || store == nil || !store.migrationRecoveredNew {
					t.Fatalf("recovered-new: %v", err)
				}
				if err := store.close(); err != nil {
					t.Fatal(err)
				}
				fixtureAssertMigrationOutcome(t, path, 2, preimage, 3)
			} else {
				if store != nil {
					_ = store.close()
					t.Fatal("interrupted upgrade returned store")
				}
				if !errors.Is(err, errClaimStoreMigrationRecoveredOld) {
					t.Fatalf("recovered old: %v", err)
				}
				fixtureAssertMigrationOutcome(t, path, 2, preimage, 2)
			}
		})
	}
}

func TestSQLiteV3PrecommitConfirmedRollback(t *testing.T) {
	for _, opening := range []int{0, 1, 2} {
		t.Run(fmt.Sprint(opening), func(t *testing.T) {
			path := fixtureMigrationPath(t, "precommit")
			preimage := fixtureSchemaVersion(t, path, opening)
			store, err := openSQLiteClaimStore(context.Background(), sqliteClaimStoreOptions{path: path,
				beforeMigrationCommit: func(context.Context, *sql.Conn) error { return errClaimStoreUnavailable },
			})
			if store != nil {
				_ = store.close()
				t.Fatal("precommit failure returned store")
			}
			if !errors.Is(err, errClaimStoreUnavailable) {
				t.Fatalf("precommit failure: %v", err)
			}
			fixtureAssertMigrationOutcome(t, path, opening, preimage, opening)
		})
	}
}

func TestSQLiteV3KnownCommitResponseLoss(t *testing.T) {
	for _, opening := range []int{0, 1, 2} {
		t.Run(fmt.Sprint(opening), func(t *testing.T) {
			path := fixtureMigrationPath(t, "known")
			preimage := fixtureSchemaVersion(t, path, opening)
			store, err := openSQLiteClaimStore(context.Background(), sqliteClaimStoreOptions{path: path})
			if err != nil || store == nil {
				t.Fatalf("known commit open: %v", err)
			}
			if store.migrationRecoveredNew {
				t.Fatal("known commit misreported as recovered")
			}
			if err := store.close(); err != nil {
				t.Fatal(err)
			}
			fixtureAssertMigrationOutcome(t, path, opening, preimage, 3)
		})
	}
}

func TestSQLiteV3ConformancePreservesLegacyRows(t *testing.T) {
	ctx := context.Background()
	path := fixtureMigrationPath(t, "legacy-conformance")
	legacy := mustOpenLegacyV2ClaimStore(t, path)
	f := newDurableFixture(t)
	f.caller = mustPrivateCallerRef(t, []byte("c"))
	f.submitKey = mustPrivateSubmitKeyRef(t, []byte("k"))
	f.claim = mustPrivateClaimID(t, f.caller, f.submitKey)
	f.binding = mustPrivatePlanBinding(t, bytes.Repeat([]byte("b"), 257))
	f.plan = mustPrivateBoundPlan(t, f.binding, f.witness)
	service := mustDurableService(t, legacy, fixedClaimClock{now: f.now})
	created := mustServiceEstablish(t, service, f)
	if !created.record.claim.Equal(f.claim) {
		t.Fatal("legacy establishment mismatch")
	}
	before := fixtureLegacyProjection(t, legacy.db, 2)
	if err := legacy.close(); err != nil {
		t.Fatal(err)
	}
	migrated := mustOpenSQLiteClaimStore(t, path)
	defer migrated.close()
	after := fixtureLegacyProjection(t, migrated.db, 3)
	if !reflect.DeepEqual(before, after) {
		t.Fatal("legacy rowid or inherited 32 columns changed")
	}
	loaded, err := migrated.loadClaim(ctx, loadClaimQuery{claim: f.claim})
	if err != nil || !loaded.equal(created.record) {
		t.Fatalf("legacy load: %v", err)
	}
	if len(opaqueRefBytes(loaded.claim.caller.ref)) != 1 || len(opaqueRefBytes(loaded.claim.submitKey.ref)) != 1 || len(opaqueRefBytes(loaded.plan.binding.ref)) != 257 {
		t.Fatal("legacy opaque domain narrowed")
	}
	service = mustDurableService(t, migrated, fixedClaimClock{now: f.now})
	assigned, err := service.assignRun(ctx, assignRunRequest{claim: f.claim, binding: f.binding, expectedRevision: created.record.revision, run: f.run, mutation: f.nextMut})
	if err != nil || assigned.kind != durableClaimOutcomeAssigned {
		t.Fatalf("legacy CAS after migration: %v", err)
	}
	replayed, err := service.assignRun(ctx, assignRunRequest{claim: f.claim, binding: f.binding, expectedRevision: created.record.revision, run: f.run, mutation: f.nextMut})
	if err != nil || replayed.kind != durableClaimOutcomeAssigned {
		t.Fatalf("legacy replay after migration: %v", err)
	}
	if _, err := newReplayDurableClaimRecord(f.claim, f.plan, replayClaimDescriptor{}, f.now); err == nil {
		t.Fatal("out-of-domain legacy row became a v3 original")
	}
}
