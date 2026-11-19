package reliablesubmit

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
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
	if expected == sqliteClaimStoreSchemaVersion {
		var migrations int
		if err := db.QueryRow(`SELECT count(*) FROM reliable_submit_migrations`).Scan(&migrations); err != nil || migrations != expected {
			t.Fatalf("incomplete ledger: %d %v", migrations, err)
		}
	}
}

func fixtureMigrationPath(t *testing.T, name string) string {
	t.Helper()
	return filepath.Join(t.TempDir(), name+".sqlite3")
}

func TestSQLiteV4BootstrapCommitUnknownReopenZeroOrFour(t *testing.T) {
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
				fixtureAssertMigrationOutcome(t, path, 0, nil, sqliteClaimStoreSchemaVersion)
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

func TestSQLiteV4UpgradeFromOneCommitUnknownNoIntermediate(t *testing.T) {
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
				fixtureAssertMigrationOutcome(t, path, 1, preimage, sqliteClaimStoreSchemaVersion)
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

func TestSQLiteV4UpgradeFromTwoCommitUnknownOldOrNew(t *testing.T) {
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
				fixtureAssertMigrationOutcome(t, path, 2, preimage, sqliteClaimStoreSchemaVersion)
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

func TestSQLiteV4PrecommitConfirmedRollback(t *testing.T) {
	for _, opening := range []int{0, 1, 2, 3} {
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

func TestSQLiteV4KnownCommitResponseLoss(t *testing.T) {
	for _, opening := range []int{0, 1, 2, 3} {
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
			fixtureAssertMigrationOutcome(t, path, opening, preimage, sqliteClaimStoreSchemaVersion)
		})
	}
}

func TestSQLiteV4ConformancePreservesLegacyRows(t *testing.T) {
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
	after := fixtureLegacyProjection(t, migrated.db, sqliteClaimStoreSchemaVersion)
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

type replayLogicalSnapshot struct {
	version, appID               int
	digest                       string
	claims, keys, grants, ledger [][]any
}

func replayLogicalWitness(t *testing.T, path string, legacyLedgerMax int) replayLogicalSnapshot {
	t.Helper()
	raw := openNonmigratingSQLiteFixture(t, path)
	defer raw.close()
	ctx := context.Background()
	conn, err := raw.checkedConn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	version, err := pragmaInt(ctx, conn, "user_version")
	if err != nil {
		t.Fatal(err)
	}
	appID, err := pragmaInt(ctx, conn, "application_id")
	if err != nil {
		t.Fatal(err)
	}
	got := replayLogicalSnapshot{version: version, appID: appID}
	if version == 0 {
		return got
	}
	got.digest, err = sqliteSchemaDigest(ctx, conn)
	if err != nil {
		t.Fatal(err)
	}
	query := func(stmt string, args ...any) [][]any {
		t.Helper()
		rows, err := conn.QueryContext(ctx, stmt, args...)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		names, err := rows.Columns()
		if err != nil {
			t.Fatal(err)
		}
		out := make([][]any, 0)
		for rows.Next() {
			row := make([]any, len(names))
			ptr := make([]any, len(names))
			for i := range row {
				ptr[i] = &row[i]
			}
			if err := rows.Scan(ptr...); err != nil {
				t.Fatal(err)
			}
			out = append(out, row)
		}
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
		return out
	}
	projection := sqliteClaimColumns
	if version == 1 {
		projection = strings.Replace(projection, "latest_operation_kind,\nlatest_operation_input_digest,", "NULL, NULL,", 1)
	}
	if version < 3 {
		projection += ", NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL"
	} else {
		projection += ", " + sqliteReplayColumns
	}
	got.claims = query("SELECT claim_rowid, " + projection + " FROM reliable_submit_claims ORDER BY claim_rowid")
	if version >= 3 {
		got.keys = query("SELECT rowid,* FROM reliable_submit_key_registry ORDER BY rowid")
		got.grants = query("SELECT rowid,* FROM reliable_submit_seal_use ORDER BY rowid")
	}
	if legacyLedgerMax > 0 {
		got.ledger = query("SELECT * FROM reliable_submit_migrations WHERE version<=? ORDER BY version", legacyLedgerMax)
	} else {
		got.ledger = query("SELECT * FROM reliable_submit_migrations ORDER BY version")
	}
	return got
}

func seedProgressMigrationV3(t *testing.T, path string) {
	t.Helper()
	record, _ := syntheticReplayRecordFixture(t)
	seedProgressMigrationV3WithOriginal(t, path, record)
}

func seedProgressMigrationV3WithOriginal(t *testing.T, path string, record durableClaimRecord) {
	t.Helper()
	ctx := context.Background()
	fixtureSchemaVersion(t, path, 2)
	raw := openNonmigratingSQLiteFixture(t, path)
	defer raw.close()
	raw.legacyV2Fixture = true
	f := newDurableFixture(t)
	service := mustDurableService(t, raw, fixedClaimClock{now: f.now})
	if created := mustServiceEstablish(t, service, f); created.kind != durableClaimOutcomeEstablished {
		t.Fatal("unable to seed historical codec-2 row")
	}
	if _, err := raw.db.Exec(sqliteMigration3SQL); err != nil {
		t.Fatal(err)
	}
	m := sqliteClaimStoreMigrations[2]
	if _, err := raw.db.Exec("INSERT INTO reliable_submit_migrations VALUES (?,?,?,?)", 3, m.name, f.now.UnixNano(), sqliteMigrationSHA256(m.sql)); err != nil {
		t.Fatal(err)
	}
	if _, err := raw.db.Exec("PRAGMA user_version=3"); err != nil {
		t.Fatal(err)
	}
	raw.legacyV2Fixture = false
	d := record.replay
	registerSyntheticRecordKeys(t, raw, d)
	active := fixtureReplayKeys(t, 67)
	if _, err := raw.db.Exec("INSERT INTO reliable_submit_key_registry VALUES (?,?,?,1),(?,?,?,1)",
		active.bindingID, 1, active.bindingFP[:], active.envelopeID, 2, active.envelopeFP[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := raw.db.Exec("INSERT INTO reliable_submit_seal_use VALUES (?,0)", active.envelopeID); err != nil {
		t.Fatal(err)
	}
	if got, err := raw.establishClaim(ctx, establishClaimCommand{record: record}); err != nil || !got.created {
		t.Fatalf("seed codec-3 row: %v", err)
	}
	if _, err := raw.db.Exec("INSERT INTO reliable_submit_seal_use VALUES (?,0)", d.envelopeKeyID); err != nil {
		t.Fatal(err)
	}
	if _, err := raw.db.Exec("UPDATE reliable_submit_seal_use SET granted_count=granted_count+1 WHERE envelope_key_id=?", d.envelopeKeyID); err != nil {
		t.Fatal(err)
	}
	for _, v := range []struct {
		id    string
		state int
	}{{d.bindingKeyID, replayKeyStateRetired}, {d.envelopeKeyID, replayKeyStateRevoked}} {
		if err := raw.transitionReplayKeyState(ctx, v.id, v.state); err != nil {
			t.Fatal(err)
		}
	}
}

func TestSQLiteV4MigrationPreservesFullState(t *testing.T) {
	for _, starting := range []int{0, 1, 2, 3} {
		for _, boundary := range []string{"KnownCommit", "Rollback", "LostCommitResponse"} {
			t.Run(fmt.Sprintf("%d/%s", starting, boundary), func(t *testing.T) {
				path := fixtureMigrationPath(t, "preserve")
				if starting == 3 {
					seedProgressMigrationV3(t, path)
				} else {
					fixtureSchemaVersion(t, path, starting)
				}
				before := replayLogicalWitness(t, path, starting)
				options := sqliteClaimStoreOptions{path: path}
				switch boundary {
				case "Rollback":
					options.beforeMigrationCommit = func(context.Context, *sql.Conn) error { return errClaimStoreUnavailable }
				case "LostCommitResponse":
					options.migrationCommit = func(ctx context.Context, conn *sql.Conn) error {
						if err := commit(ctx, conn); err != nil {
							return err
						}
						return errClaimStoreCommitUnknown
					}
				}
				store, err := openSQLiteClaimStore(context.Background(), options)
				if boundary == "Rollback" {
					if store != nil || !errors.Is(err, errClaimStoreUnavailable) {
						t.Fatalf("rollback failed closed: %v", err)
					}
					if after := replayLogicalWitness(t, path, starting); !reflect.DeepEqual(before, after) {
						t.Fatal("rollback changed complete logical witness")
					}
					return
				}
				if err != nil || store == nil {
					t.Fatalf("upgrade: %v", err)
				}
				if store.migrationRecoveredNew != (boundary == "LostCommitResponse") {
					t.Fatal("migration response was misclassified")
				}
				if err := store.close(); err != nil {
					t.Fatal(err)
				}
				after := replayLogicalWitness(t, path, starting)
				if after.version != 4 || after.appID != sqliteClaimStoreApplicationID || after.digest != sqliteSchema4SHA256 {
					t.Fatal("upgrade did not reach exactly schema 4")
				}
				if starting > 0 && !reflect.DeepEqual(before.claims, after.claims) {
					t.Fatal("old rowid, storage type or complete claim content changed")
				}
				if starting == 0 && len(after.claims) != 0 {
					t.Fatal("migration bootstrap created claim authority")
				}
				if starting == 3 && (!reflect.DeepEqual(before.grants, after.grants) || !reflect.DeepEqual(before.keys, after.keys)) {
					t.Fatal("key or reservation changed")
				}
				if starting > 0 && !reflect.DeepEqual(before.ledger, after.ledger) {
					t.Fatal("old ledger rows changed")
				}
			})
		}
	}
	t.Run("RefusesAuthenticatedIntermediateDuringRecovery", func(t *testing.T) {
		path := fixtureMigrationPath(t, "intermediate")
		fixtureSchemaVersion(t, path, 2)
		before := replayLogicalWitness(t, path, 0)
		store := openNonmigratingSQLiteFixture(t, path)
		store.migrationOpeningVersion = 1
		err := store.verifyMigrationRecovery(context.Background())
		_ = store.close()
		if !errors.Is(err, errClaimStoreUnavailable) || !reflect.DeepEqual(before, replayLogicalWitness(t, path, 0)) {
			t.Fatalf("intermediate shape acquired migration authority: %v", err)
		}
	})
	t.Run("RefusesMixedCurrentLedgerDuringRecovery", func(t *testing.T) {
		path := fixtureMigrationPath(t, "mixed")
		seedProgressMigrationV3(t, path)
		store, err := openSQLiteClaimStore(context.Background(), sqliteClaimStoreOptions{path: path})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := store.db.Exec("DELETE FROM reliable_submit_migrations WHERE version=4"); err != nil {
			t.Fatal(err)
		}
		before := replayLogicalWitness(t, path, 0)
		store.migrationOpeningVersion = 3
		err = store.verifyMigrationRecovery(context.Background())
		_ = store.close()
		if !errors.Is(err, errClaimStoreUnavailable) || !reflect.DeepEqual(before, replayLogicalWitness(t, path, 0)) {
			t.Fatalf("mixed ledger acquired migration authority: %v", err)
		}
	})
	t.Run("CanceledRecoveryAfterActualCommit", func(t *testing.T) {
		path := fixtureMigrationPath(t, "canceled")
		seedProgressMigrationV3(t, path)
		before := replayLogicalWitness(t, path, 3)
		ctx, stop := context.WithCancel(context.Background())
		defer stop()
		store, err := openSQLiteClaimStore(ctx, sqliteClaimStoreOptions{path: path, migrationCommit: func(ctx context.Context, conn *sql.Conn) error {
			if err := commit(ctx, conn); err != nil {
				t.Fatal(err)
			}
			stop()
			return errClaimStoreCommitUnknown
		}})
		if store != nil || !errors.Is(err, errClaimStoreUnavailable) {
			t.Fatalf("canceled recovery acquired store: %v", err)
		}
		after := replayLogicalWitness(t, path, 3)
		if after.version != 4 || after.digest != sqliteSchema4SHA256 ||
			!reflect.DeepEqual(before.claims, after.claims) || !reflect.DeepEqual(before.keys, after.keys) ||
			!reflect.DeepEqual(before.grants, after.grants) || !reflect.DeepEqual(before.ledger, after.ledger) {
			t.Fatal("canceled recovery changed the actual migrated state")
		}
	})
}

type migrationPreflightClock func()

func (f migrationPreflightClock) Now() time.Time {
	f()
	return time.Unix(1720000000, 0).UTC()
}

// Read every schema entry and the contents of each fixture table without the
// production digest or bootstrap predicate.
func migrationOpeningWitness(t *testing.T, db *sql.DB) map[string][][]any {
	t.Helper()
	query := func(statement string) [][]any {
		t.Helper()
		rows, err := db.Query(statement)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		columns, err := rows.Columns()
		if err != nil {
			t.Fatal(err)
		}
		var result [][]any
		for rows.Next() {
			row := make([]any, len(columns))
			dest := make([]any, len(columns))
			for i := range row {
				dest[i] = &row[i]
			}
			if err := rows.Scan(dest...); err != nil {
				t.Fatal(err)
			}
			result = append(result, row)
		}
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
		return result
	}
	schema := query("SELECT type,name,tbl_name,sql FROM sqlite_schema ORDER BY name COLLATE BINARY")
	out := map[string][][]any{
		"application_id": query("PRAGMA application_id"),
		"user_version":   query("PRAGMA user_version"),
		"schema":         schema,
	}
	for _, row := range schema {
		if row[0] == "table" {
			name := row[1].(string)
			out["table:"+name] = query(`SELECT rowid,* FROM "` + strings.ReplaceAll(name, `"`, `""`) + `" ORDER BY rowid`)
		}
	}
	return out
}

func TestSQLiteMigrationOpeningRevalidatedUnderLock(t *testing.T) {
	for _, tc := range []struct {
		name       string
		start      int
		statements []string
	}{
		{"FutureVersion", 3, []string{"PRAGMA user_version = 99"}},
		{"NonemptyBootstrap", 0, []string{"CREATE TABLE sqliteXforeign(v TEXT)", "INSERT INTO sqliteXforeign VALUES ('foreign')"}},
		{"ForeignApplication", 3, []string{"PRAGMA application_id = 1234"}},
		{"InvalidLedger", 3, []string{"UPDATE reliable_submit_migrations SET source_sha256 = printf('%064d',0) WHERE version=3"}},
		{"ChangedSchema", 3, []string{"DROP TRIGGER reliable_submit_claims_no_delete", "CREATE TRIGGER reliable_submit_claims_no_delete BEFORE DELETE ON reliable_submit_claims BEGIN SELECT 1; END"}},
		{"CompetingAuthenticHead", 3, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			path := fixtureMigrationPath(t, "revalidate")
			fixtureSchemaVersion(t, path, tc.start)
			other := mustRawSQLiteDB(t, path)
			defer other.Close()
			var committed map[string][][]any
			calls := 0
			beforeWrite := migrationPreflightClock(func() {
				calls++
				if tc.statements == nil {
					competitor, err := openSQLiteClaimStore(ctx, sqliteClaimStoreOptions{path: path})
					if err != nil {
						t.Fatalf("competing migration did not commit before writer acquisition: %v", err)
					}
					if err := competitor.close(); err != nil {
						t.Fatal(err)
					}
				} else {
					tx, err := other.BeginTx(ctx, nil)
					if err != nil {
						t.Fatal(err)
					}
					defer tx.Rollback()
					for _, stmt := range tc.statements {
						if _, err := tx.ExecContext(ctx, stmt); err != nil {
							t.Fatalf("independent writer setup: %v", err)
						}
					}
					if err := tx.Commit(); err != nil {
						t.Fatal(err)
					}
				}
				committed = migrationOpeningWitness(t, other)
				t.Log("independent writer committed before migration writer acquisition")
			})
			writes := 0
			store, err := openSQLiteClaimStore(ctx, sqliteClaimStoreOptions{path: path, clock: beforeWrite,
				beforeMigrationCommit: func(context.Context, *sql.Conn) error {
					writes++
					return nil
				}})
			if store != nil {
				defer store.close()
			}
			if calls != 1 || committed == nil {
				t.Fatal("opening did not reach the controlled writer boundary")
			}
			if tc.statements == nil {
				if store == nil || err != nil {
					t.Errorf("authenticated competing head must open with no migrations: %v", err)
				}
			} else if store != nil || err == nil {
				t.Errorf("disallowed lock-held state acquired migration authority: %v", err)
			}
			if after := migrationOpeningWitness(t, other); writes != 0 || !reflect.DeepEqual(committed, after) {
				t.Errorf("opener changed the independently committed state or reached migration COMMIT: writes=%d, version before=%v after=%v", writes, committed["user_version"], after["user_version"])
			}
		})
	}
	for _, version := range []int{0, 1, 2, 3, 4} {
		t.Run(fmt.Sprintf("Authentic%d", version), func(t *testing.T) {
			path := fixtureMigrationPath(t, "authentic")
			before := fixtureSchemaVersion(t, path, version)
			store, err := openSQLiteClaimStore(context.Background(), sqliteClaimStoreOptions{path: path})
			if err != nil {
				t.Fatal(err)
			}
			if err := store.close(); err != nil {
				t.Fatal(err)
			}
			fixtureAssertMigrationOutcome(t, path, version, before, 4)
		})
	}
}

func TestSQLiteMigrationPrecommitClosedWrapperRecovery(t *testing.T) {
	for _, version := range []int{0, 1, 2, 3} {
		for _, scenario := range []struct {
			name           string
			closeWrapper   bool
			cancelRecovery bool
			want           error
		}{
			{"ClosedWrapper", true, false, errClaimStoreMigrationRecoveredOld},
			{"OrdinaryRollback", false, false, errClaimStoreUnavailable},
			{"CanceledReadback", true, true, errClaimStoreUnavailable},
		} {
			t.Run(fmt.Sprintf("Schema%d/%s", version, scenario.name), func(t *testing.T) {
				root := fixtureReplayRoot(t)
				path := filepath.Join(root, "reliable-submit.sqlite3")
				var objectPath string
				var sealed []byte
				if version == 3 {
					record, _ := syntheticReplayRecordFixture(t)
					_, object, descriptor := unclaimedReplaySealedFixture(t, record, fixtureReplayKeys(t, 62))
					record, err := newReplayDurableClaimRecord(record.claim, record.plan, descriptor, record.createdAt)
					if err != nil {
						t.Fatal(err)
					}
					objectPath, sealed = filepath.Join(root, descriptor.ref), object
					if err := os.WriteFile(objectPath, sealed, 0o600); err != nil {
						t.Fatal(err)
					}
					seedProgressMigrationV3WithOriginal(t, path, record)
				} else {
					fixtureSchemaVersion(t, path, version)
				}
				witness := func() map[string][][]any {
					t.Helper()
					db := mustRawSQLiteDB(t, path)
					defer db.Close()
					return migrationOpeningWitness(t, db)
				}
				before := witness()
				if version == 3 && (len(before["table:reliable_submit_claims"]) < 2 ||
					len(before["table:reliable_submit_key_registry"]) < 4 ||
					len(before["table:reliable_submit_seal_use"]) < 2 ||
					len(before["table:reliable_submit_migrations"]) != 3) {
					t.Fatal("schema-3 opening witness did not include the populated fixtures")
				}
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				openings, precommit, commits := 0, 0, 0
				store, err := openSQLiteClaimStore(ctx, sqliteClaimStoreOptions{
					path:  path,
					clock: migrationPreflightClock(func() { openings++ }),
					beforeMigrationCommit: func(ctx context.Context, conn *sql.Conn) error {
						if err := verifySQLiteStoreCurrent(ctx, conn); err != nil {
							t.Fatalf("migration did not reach verified schema 4 inside the transaction: %v", err)
						}
						precommit++
						if scenario.closeWrapper {
							if err := conn.Close(); err != nil {
								t.Fatalf("could not return the actual connection wrapper: %v", err)
							}
							if err := conn.Raw(func(any) error { return nil }); !errors.Is(err, sql.ErrConnDone) {
								t.Fatalf("wrapper remained usable: %v", err)
							}
						}
						if scenario.cancelRecovery {
							cancel()
						}
						return errClaimStoreUnavailable
					},
					migrationCommit: func(context.Context, *sql.Conn) error {
						commits++
						return errClaimStoreCommitUnknown
					},
				})
				if store != nil {
					defer store.close()
					t.Error("pre-COMMIT refusal returned a usable store")
				}
				if openings != 1 || precommit != 1 || commits != 0 {
					t.Fatalf("wrong transaction boundary: migrations=%d pre-COMMIT checks=%d COMMIT attempts=%d", openings, precommit, commits)
				}
				if after := witness(); !reflect.DeepEqual(before, after) {
					t.Fatal("independent read observed a changed logical opening state")
				}
				if objectPath != "" {
					if got, err := os.ReadFile(objectPath); err != nil || !bytes.Equal(sealed, got) {
						t.Fatalf("sealed original changed: %v", err)
					}
				}
				t.Logf("verified schema 4 before COMMIT, one migration, zero COMMIT attempts, preserved opening schema %d and full logical state", version)
				if !errors.Is(err, scenario.want) {
					t.Errorf("pre-COMMIT classification = %v, want %v", err, scenario.want)
				}
			})
		}
	}
}
