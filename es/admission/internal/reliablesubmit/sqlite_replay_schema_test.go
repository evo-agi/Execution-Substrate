package reliablesubmit

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestSQLiteV3ReferenceAndKeyIDByteGrammar(t *testing.T) {
	store := mustOpenSQLiteClaimStore(t, sqliteTestPath(t, "state", "v3-id-grammar.sqlite3"))
	defer store.close()

	validFingerprint := bytes.Repeat([]byte{0x31}, 32)
	if _, err := store.db.Exec("INSERT INTO reliable_submit_key_registry (key_id, purpose, material_fingerprint, state) VALUES (?, 2, ?, 1)",
		"Envelope-A.1", validFingerprint); err != nil {
		t.Fatalf("valid registry ID: %v", err)
	}
	for _, tc := range []struct {
		name string
		id   string
	}{
		{"empty", ""},
		{"initial punctuation", ".bad"},
		{"embedded NUL", "Envelope\x00-A"},
		{"non-ASCII", "Envéloppe"},
		{"space", "Envelope A"},
		{"overlong", string(bytes.Repeat([]byte{'a'}, 65))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := store.db.Exec("INSERT INTO reliable_submit_key_registry (key_id, purpose, material_fingerprint, state) VALUES (?, 2, ?, 1)",
				tc.id, bytes.Repeat([]byte{byte(len(tc.name))}, 32)); err == nil {
				t.Fatal("invalid registry ID accepted")
			}
		})
	}
	record, d := syntheticReplayRecordFixture(t)
	registerSyntheticRecordKeys(t, store, d)
	args, err := sqliteRecordArgs(record)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name  string
		index int
		value any
	}{
		{"short caller codec3", 0, []byte("c")},
		{"short key codec3", 1, []byte("k")},
		{"long binding codec3", 2, bytes.Repeat([]byte("b"), 257)},
		{"NUL envelope ref", 39, "objects/v1/" + strings.Repeat("a", 63) + "\x00"},
		{"upper envelope ref", 39, "objects/v1/" + strings.Repeat("A", 64)},
		{"nonhex envelope ref", 39, "objects/v1/" + strings.Repeat("g", 64)},
		{"NUL binding ID", 42, "Binding\x00A"},
		{"NUL envelope ID", 44, "Envelope\x00A"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mutated := append([]any(nil), args...)
			mutated[tc.index] = tc.value
			if _, err := store.db.Exec(sqliteInsertReplayClaimSQL, mutated...); err == nil {
				t.Fatal("invalid complete codec3 row inserted")
			}
		})
	}
	var claims int
	if err := store.db.QueryRow(`SELECT count(*) FROM reliable_submit_claims`).Scan(&claims); err != nil || claims != 0 {
		t.Fatal("invalid rows left a claim")
	}
}

func TestSQLiteV3ReplaceCannotResetClaimKeyOrCounter(t *testing.T) {
	store := mustOpenSQLiteClaimStore(t, sqliteTestPath(t, "state", "v3-replace.sqlite3"))
	defer store.close()
	db := store.db
	keyID := "Envelope-A"
	fingerprint := bytes.Repeat([]byte{0x42}, 32)
	if _, err := db.Exec("INSERT INTO reliable_submit_key_registry (key_id, purpose, material_fingerprint, state) VALUES (?, 2, ?, 1)",
		keyID, fingerprint); err != nil {
		t.Fatalf("register key: %v", err)
	}
	if _, err := db.Exec("INSERT INTO reliable_submit_seal_use (envelope_key_id, granted_count) VALUES (?, 0)", keyID); err != nil {
		t.Fatalf("initialize counter: %v", err)
	}
	if _, err := db.Exec("UPDATE reliable_submit_seal_use SET granted_count=1 WHERE envelope_key_id=?", keyID); err != nil {
		t.Fatalf("positive counter increment: %v", err)
	}
	if _, err := db.Exec("INSERT OR REPLACE INTO reliable_submit_seal_use (envelope_key_id, granted_count) VALUES (?, 0)", keyID); err == nil {
		t.Fatal("REPLACE reset counter")
	}
	if _, err := db.Exec("UPDATE OR REPLACE reliable_submit_seal_use SET granted_count=0 WHERE envelope_key_id=?", keyID); err == nil {
		t.Fatal("UPDATE OR REPLACE reset counter")
	}
	var count int64
	if err := db.QueryRow("SELECT granted_count FROM reliable_submit_seal_use WHERE envelope_key_id=?", keyID).Scan(&count); err != nil {
		t.Fatalf("read counter: %v", err)
	}
	if count != 1 {
		t.Fatalf("counter = %d, want 1", count)
	}
	if _, err := db.Exec("INSERT OR REPLACE INTO reliable_submit_key_registry (key_id, purpose, material_fingerprint, state) VALUES (?, 2, ?, 1)",
		keyID, bytes.Repeat([]byte{0x43}, 32)); err == nil {
		t.Fatal("REPLACE changed registered material")
	}
	if _, err := db.Exec("UPDATE OR REPLACE reliable_submit_key_registry SET material_fingerprint=? WHERE key_id=?",
		bytes.Repeat([]byte{0x43}, 32), keyID); err == nil {
		t.Fatal("UPDATE OR REPLACE changed registered material")
	}
	var actual []byte
	if err := db.QueryRow("SELECT material_fingerprint FROM reliable_submit_key_registry WHERE key_id=?", keyID).Scan(&actual); err != nil {
		t.Fatalf("read registry: %v", err)
	}
	if !bytes.Equal(actual, fingerprint) {
		t.Fatal("registry material changed")
	}
	conn, err := db.Conn(context.Background())
	if err != nil {
		t.Fatalf("checked connection: %v", err)
	}
	defer conn.Close()
	var recursive int
	if err := conn.QueryRowContext(context.Background(), "PRAGMA recursive_triggers").Scan(&recursive); err != nil {
		t.Fatalf("recursive_triggers: %v", err)
	}
	if recursive != 1 {
		t.Fatalf("recursive_triggers = %d, want 1", recursive)
	}
}

func TestSQLiteV3ManagedConnectionRequiresRecursiveTriggers(t *testing.T) {
	ctx := context.Background()
	store := mustOpenSQLiteClaimStore(t, sqliteTestPath(t, "state", "recursive.sqlite3"))
	defer store.close()
	raw, err := store.db.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := raw.ExecContext(ctx, `PRAGMA recursive_triggers=OFF`); err != nil {
		t.Fatal(err)
	}
	if err := raw.Close(); err != nil {
		t.Fatal(err)
	}
	checked, err := store.checkedConn(ctx)
	if err != nil {
		t.Fatalf("managed connection did not establish policy: %v", err)
	}
	var recursive int
	if err := checked.QueryRowContext(ctx, `PRAGMA recursive_triggers`).Scan(&recursive); err != nil || recursive != 1 {
		t.Fatalf("managed recursive policy=%d err=%v", recursive, err)
	}
	if err := checked.Close(); err != nil {
		t.Fatal(err)
	}
	// An active transaction prevents the complete connection policy from
	// being established; the gate must fail instead of using that handle.
	blocked, err := store.db.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := blocked.ExecContext(ctx, `BEGIN`); err != nil {
		t.Fatal(err)
	}
	if err := applyAndVerifySQLiteConnectionPragmas(ctx, blocked); err == nil {
		t.Fatal("policy accepted an unestablishable transaction")
	}
	if _, err := blocked.ExecContext(ctx, `ROLLBACK`); err != nil {
		t.Fatal(err)
	}
	if err := blocked.Close(); err != nil {
		t.Fatal(err)
	}
}
