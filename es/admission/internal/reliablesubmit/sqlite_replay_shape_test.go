package reliablesubmit

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

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
		expected := []string{sqliteSchema1SHA256, sqliteSchema2SHA256, sqliteSchema3SHA256}[migration.version-1]
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
	store := mustOpenSQLiteClaimStore(t, path)
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
	reopened := mustOpenSQLiteClaimStore(t, path)
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
