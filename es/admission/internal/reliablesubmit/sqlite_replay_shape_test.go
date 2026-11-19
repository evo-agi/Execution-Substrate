package reliablesubmit

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestSQLiteV4PreviousSchema3BinaryRefusesWithoutMutation(t *testing.T) {
	probe := os.Getenv("ES_REPLAY_SCHEMA3_PROBE")
	if probe == "" {
		t.Fatal("authenticated schema-3 production-source probe is required")
	}
	root := fixtureReplayRoot(t)
	path := filepath.Join(root, "reliable-submit.sqlite3")
	legacy, _ := syntheticReplayRecordFixture(t)
	_, legacyObject, legacyDescriptor := unclaimedReplaySealedFixture(t, legacy, fixtureReplayKeys(t, 62))
	legacy, err := newReplayDurableClaimRecord(legacy.claim, legacy.plan, legacyDescriptor, legacy.createdAt)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, legacyDescriptor.ref), legacyObject, 0o600); err != nil {
		t.Fatal(err)
	}
	seedProgressMigrationV3WithOriginal(t, path, legacy)
	progressBase, _ := syntheticReplayRecordFixture(t)
	progressBase.claim = mustPrivateClaimID(t, progressBase.claim.caller, mustPrivateSubmitKeyRef(t, bytes.Repeat([]byte{64}, 32)))
	f := newProgressTestFixture(t, root, progressBase, fixtureReplayKeys(t, 63))
	f.assignAndIntent(FixturePendingBeforeAssignment)
	progress := f.record()
	progressObject := f.object(progress)
	if err := f.custody.Close(); err != nil {
		t.Fatal(err)
	}
	before := replayLogicalWitness(t, path, 0)
	if before.version != 4 || before.digest != sqliteSchema4SHA256 || len(before.claims) != 4 || len(before.ledger) != 4 {
		t.Fatal("schema-4 probe target must contain all four codecs")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, probe, "-test.run=^TestPreviousSchema3OpenerProbe$", "-test.v")
	cmd.Env = append(os.Environ(), "ES_REPLAY_SCHEMA3_TARGET="+path)
	output, err := cmd.CombinedOutput()
	if err != nil || !strings.Contains(string(output), "SCHEMA3_REFUSED_SCHEMA4") ||
		!strings.Contains(string(output), "--- PASS: TestPreviousSchema3OpenerProbe") {
		t.Fatalf("schema-3 probe result: %v\n%s", err, output)
	}
	after := replayLogicalWitness(t, path, 0)
	if !reflect.DeepEqual(before, after) || !bytes.Equal(legacyObject, f.object(legacy)) ||
		!bytes.Equal(progressObject, f.object(progress)) {
		t.Fatal("schema-3 refused open mutated logical evidence or sealed original")
	}
	t.Log("SCHEMA3_REFUSED_SCHEMA4 with complete equal logical witnesses and both sealed originals")
}

func TestSQLiteV3ReopenRejectsMixedSchemaLedger(t *testing.T) {
	ctx := context.Background()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	conn, err := db.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	for _, migration := range sqliteClaimStoreMigrations {
		if _, err := conn.ExecContext(ctx, migration.sql); err != nil {
			t.Fatal(err)
		}
		digest, err := sqliteSchemaDigest(ctx, conn)
		if err != nil {
			t.Fatal(err)
		}
		expected := []string{sqliteSchema1SHA256, sqliteSchema2SHA256, sqliteSchema3SHA256, sqliteSchema4SHA256}[migration.version-1]
		if digest != expected {
			t.Fatalf("version %d source shape changed", migration.version)
		}
	}
	path := filepath.Join(t.TempDir(), "state.sqlite3")
	store, err := openSQLiteClaimStore(ctx, sqliteClaimStoreOptions{path: path})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.close(); err != nil {
		t.Fatal(err)
	}
	raw, err := sql.Open("sqlite", sqliteClaimStoreDSN(path, sqliteDefaultBusyTimeoutMS))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(`DROP TRIGGER reliable_submit_claims_no_delete`); err != nil {
		t.Fatal(err)
	}
	if err := raw.Close(); err != nil {
		t.Fatal(err)
	}
	refused, err := openSQLiteClaimStore(ctx, sqliteClaimStoreOptions{path: path})
	if refused != nil {
		_ = refused.close()
		t.Fatal("opened mixed schema")
	}
	if !errors.Is(err, errClaimStoreUnsupported) {
		t.Fatalf("mixed schema result: %v", err)
	}
}

func TestSQLiteV3OldBinaryRefusesWithoutMutation(t *testing.T) {
	ctx := context.Background()
	probe := os.Getenv("ES_REPLAY_PB1_PROBE")
	if probe == "" {
		t.Fatal("old PB1 production-source probe is required")
	}
	path := filepath.Join(t.TempDir(), "future-schema.sqlite3")
	fixtureSchemaVersion(t, path, 3)
	store := openNonmigratingSQLiteFixture(t, path)
	record, d := syntheticReplayRecordFixture(t)
	registerSyntheticRecordKeys(t, store, d)
	if _, err := store.establishClaim(ctx, establishClaimCommand{record: record}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.ExecContext(ctx, `INSERT INTO reliable_submit_seal_use(envelope_key_id,granted_count) VALUES (?,0)`, d.envelopeKeyID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.ExecContext(ctx, `UPDATE reliable_submit_seal_use SET granted_count=granted_count+1 WHERE envelope_key_id=?`, d.envelopeKeyID); err != nil {
		t.Fatal(err)
	}
	readLogical := func(s *sqliteClaimStore) (string, int, int, int, int, int64) {
		t.Helper()
		conn, err := s.checkedConn(ctx)
		if err != nil {
			t.Fatal(err)
		}
		digest, err := sqliteSchemaDigest(ctx, conn)
		if err != nil {
			t.Fatal(err)
		}
		if err := conn.Close(); err != nil {
			t.Fatal(err)
		}
		var version, ledger, claims, keys int
		var grants int64
		for _, q := range []struct {
			sql  string
			dest any
		}{
			{`PRAGMA user_version`, &version},
			{`SELECT count(*) FROM reliable_submit_migrations`, &ledger},
			{`SELECT count(*) FROM reliable_submit_claims`, &claims},
			{`SELECT count(*) FROM reliable_submit_key_registry`, &keys},
			{`SELECT granted_count FROM reliable_submit_seal_use WHERE envelope_key_id='Envelope-A'`, &grants},
		} {
			if err := s.db.QueryRowContext(ctx, q.sql).Scan(q.dest); err != nil {
				t.Fatal(err)
			}
		}
		return digest, version, ledger, claims, keys, grants
	}
	beforeDigest, beforeVersion, beforeLedger, beforeClaims, beforeKeys, beforeGrants := readLogical(store)
	if err := store.close(); err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(ctx, probe, "-test.run=^TestOldPB1OpenerProbe$", "-test.v")
	cmd.Env = append(os.Environ(), "ES_REPLAY_PB1_TARGET="+path)
	output, err := cmd.Output()
	if err != nil || !strings.Contains(string(output), "PB1_REFUSED_UNSUPPORTED") || !strings.Contains(string(output), "PASS") {
		t.Fatal("authenticated PB1 production-source opener did not refuse schema 3")
	}
	reopened := openNonmigratingSQLiteFixture(t, path)
	defer reopened.close()
	afterDigest, afterVersion, afterLedger, afterClaims, afterKeys, afterGrants := readLogical(reopened)
	if beforeDigest != afterDigest || beforeVersion != afterVersion || beforeLedger != afterLedger || beforeClaims != afterClaims || beforeKeys != afterKeys || beforeGrants != afterGrants {
		t.Fatal("old opener changed schema, ledger, claim, key or counter state")
	}
	loaded, err := reopened.loadClaim(ctx, loadClaimQuery{claim: record.claim})
	if err != nil || !loaded.equal(record) {
		t.Fatal("old opener changed the synthetic claim")
	}
}

func openNonmigratingSQLiteFixture(t *testing.T, path string) *sqliteClaimStore {
	t.Helper()
	db, err := sql.Open("sqlite", sqliteClaimStoreDSN(path, sqliteDefaultBusyTimeoutMS))
	if err != nil {
		t.Fatal(err)
	}
	return &sqliteClaimStore{db: db, path: path}
}

func TestSQLiteLiteralInternalNamespaceQualification(t *testing.T) {
	for _, tc := range []struct {
		name       string
		version    int
		statements []string
	}{
		{"PristineCollisionTable", 0, []string{"CREATE TABLE sqliteXforeign(v TEXT)", "INSERT INTO sqliteXforeign VALUES ('sentinel'), ('retained')"}},
		{"PristineOrdinaryTable", 0, []string{"CREATE TABLE foreign_table(v TEXT)", "INSERT INTO foreign_table VALUES ('sentinel')"}},
		{"Schema3CollisionIndex", 3, []string{"CREATE INDEX SqLiTeXforeign ON reliable_submit_claims(revision)"}},
		{"Schema4CollisionView", 4, []string{"CREATE VIEW sQLitEXforeign AS SELECT revision FROM reliable_submit_claims"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := fixtureMigrationPath(t, "literal")
			fixtureSchemaVersion(t, path, tc.version)
			db := mustRawSQLiteDB(t, path)
			defer db.Close()
			for _, stmt := range tc.statements {
				if _, err := db.Exec(stmt); err != nil {
					t.Fatalf("ordinary SQLite name was not accepted by fixture engine: %v", err)
				}
			}
			before := migrationOpeningWitness(t, db)
			store, err := openSQLiteClaimStore(context.Background(), sqliteClaimStoreOptions{path: path})
			if store != nil {
				defer store.close()
			}
			if store != nil || !errors.Is(err, errClaimStoreUnsupported) {
				t.Errorf("extra object was not refused: %v", err)
			}
			if after := migrationOpeningWitness(t, db); !reflect.DeepEqual(before, after) {
				t.Errorf("refusal did not preserve complete logical state: version before=%v after=%v", before["user_version"], after["user_version"])
			}
		})
	}
}
