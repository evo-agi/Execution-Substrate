package reliablesubmit

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	_ "modernc.org/sqlite"
)

type sqliteClaimStore struct {
	db   *sql.DB
	path string
}

type sqliteClaimStoreOptions struct {
	path            string
	disallowedRoots []string
	busyTimeout     time.Duration
	maxOpenConns    int
	clock           claimClock
}

func openSQLiteClaimStore(ctx context.Context, opts sqliteClaimStoreOptions) (*sqliteClaimStore, error) {
	cleanPath, err := validateSQLiteStorePath(opts.path, opts.disallowedRoots)
	if err != nil {
		return nil, err
	}
	parent := filepath.Dir(cleanPath)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return nil, errClaimStoreUnavailable
	}
	if err := rejectSymlinkPath(cleanPath); err != nil {
		return nil, err
	}
	if err := rejectHardlinkedFile(cleanPath); err != nil {
		return nil, err
	}

	busyTimeoutMS := sqliteDefaultBusyTimeoutMS
	if opts.busyTimeout > 0 {
		busyTimeoutMS = int(opts.busyTimeout / time.Millisecond)
		if busyTimeoutMS <= 0 {
			busyTimeoutMS = 1
		}
	}
	maxOpenConns := opts.maxOpenConns
	if maxOpenConns <= 0 {
		maxOpenConns = sqliteDefaultMaxOpenConns
	}
	db, err := sql.Open("sqlite", sqliteClaimStoreDSN(cleanPath, busyTimeoutMS))
	if err != nil {
		return nil, errClaimStoreUnavailable
	}
	db.SetMaxOpenConns(maxOpenConns)
	db.SetMaxIdleConns(maxOpenConns)

	store := &sqliteClaimStore{db: db, path: cleanPath}
	if err := store.openGate(ctx, opts.clock); err != nil {
		_ = db.Close()
		return nil, err
	}
	if err := chmodSQLiteStoreFiles(cleanPath); err != nil {
		_ = db.Close()
		return nil, err
	}
	return store, nil
}

func (s *sqliteClaimStore) close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

func (s *sqliteClaimStore) establishClaim(ctx context.Context, cmd establishClaimCommand) (establishClaimStoreResult, error) {
	if err := cmd.record.validate(); err != nil {
		return establishClaimStoreResult{}, errClaimStoreCorrupt
	}
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return establishClaimStoreResult{}, mapSQLiteError(err)
	}
	defer conn.Close()
	if err := beginImmediate(ctx, conn); err != nil {
		return establishClaimStoreResult{}, err
	}
	committed := false
	defer rollbackIfOpen(ctx, conn, &committed)

	args, err := sqliteRecordArgs(cmd.record)
	if err != nil {
		return establishClaimStoreResult{}, err
	}
	result, err := conn.ExecContext(ctx, sqliteInsertClaimSQL, args...)
	if err != nil {
		return establishClaimStoreResult{}, mapSQLiteError(err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return establishClaimStoreResult{}, errClaimStoreInternal
	}
	if rows < 0 || rows > 1 {
		return establishClaimStoreResult{}, errClaimStoreInternal
	}
	loaded, err := selectSQLiteClaim(ctx, conn, cmd.record.claim)
	if err != nil {
		return establishClaimStoreResult{}, err
	}
	if err := commit(ctx, conn); err != nil {
		return establishClaimStoreResult{}, err
	}
	committed = true
	_ = chmodSQLiteStoreFiles(s.path)
	return establishClaimStoreResult{record: loaded, created: rows == 1}, nil
}

func (s *sqliteClaimStore) loadClaim(ctx context.Context, query loadClaimQuery) (durableClaimRecord, error) {
	if !query.claim.Valid() {
		return durableClaimRecord{}, errClaimStoreInternal
	}
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return durableClaimRecord{}, mapSQLiteError(err)
	}
	defer conn.Close()
	if err := beginRead(ctx, conn); err != nil {
		return durableClaimRecord{}, err
	}
	committed := false
	defer rollbackIfOpen(ctx, conn, &committed)
	record, err := selectSQLiteClaim(ctx, conn, query.claim)
	if err != nil {
		return durableClaimRecord{}, err
	}
	if err := commit(ctx, conn); err != nil {
		return durableClaimRecord{}, err
	}
	committed = true
	return record, nil
}

func (s *sqliteClaimStore) compareAndSwapClaim(ctx context.Context, cmd compareAndSwapClaimCommand) (compareAndSwapClaimStoreResult, error) {
	if !cmd.claim.Valid() || cmd.expectedRevision < initialClaimRevision {
		return compareAndSwapClaimStoreResult{}, errClaimStoreInternal
	}
	if err := cmd.next.validate(); err != nil {
		return compareAndSwapClaimStoreResult{}, errClaimStoreCorrupt
	}
	if !cmd.next.claim.Equal(cmd.claim) || cmd.next.revision != cmd.expectedRevision+1 {
		return compareAndSwapClaimStoreResult{}, errClaimStoreCorrupt
	}
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return compareAndSwapClaimStoreResult{}, mapSQLiteError(err)
	}
	defer conn.Close()
	if err := beginImmediate(ctx, conn); err != nil {
		return compareAndSwapClaimStoreResult{}, err
	}
	committed := false
	defer rollbackIfOpen(ctx, conn, &committed)

	args, err := sqliteRecordArgs(cmd.next)
	if err != nil {
		return compareAndSwapClaimStoreResult{}, err
	}
	args = append(args, opaqueRefBytes(cmd.claim.caller.ref), opaqueRefBytes(cmd.claim.submitKey.ref), int64(cmd.expectedRevision), int64(durableRetentionActive))
	result, err := conn.ExecContext(ctx, sqliteUpdateClaimSQL, args...)
	if err != nil {
		return compareAndSwapClaimStoreResult{}, mapSQLiteError(err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return compareAndSwapClaimStoreResult{}, errClaimStoreInternal
	}
	if rows == 1 {
		loaded, err := selectSQLiteClaim(ctx, conn, cmd.claim)
		if err != nil {
			return compareAndSwapClaimStoreResult{}, err
		}
		if err := commit(ctx, conn); err != nil {
			return compareAndSwapClaimStoreResult{}, err
		}
		committed = true
		_ = chmodSQLiteStoreFiles(s.path)
		return compareAndSwapClaimStoreResult{record: loaded, applied: true, found: true}, nil
	}
	current, err := selectSQLiteClaim(ctx, conn, cmd.claim)
	if err != nil {
		if isClaimStoreError(err, claimStoreErrorNotFound) {
			return compareAndSwapClaimStoreResult{found: false}, nil
		}
		return compareAndSwapClaimStoreResult{}, err
	}
	if err := commit(ctx, conn); err != nil {
		return compareAndSwapClaimStoreResult{}, err
	}
	committed = true
	return compareAndSwapClaimStoreResult{record: current, applied: false, found: true}, nil
}

func (s *sqliteClaimStore) openGate(ctx context.Context, clock claimClock) error {
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return mapSQLiteError(err)
	}
	defer conn.Close()
	if err := applyAndVerifySQLiteConnectionPragmas(ctx, conn); err != nil {
		return err
	}
	if err := sqliteQuickCheck(ctx, conn); err != nil {
		return err
	}
	applicationID, err := pragmaInt(ctx, conn, "application_id")
	if err != nil {
		return err
	}
	userVersion, err := pragmaInt(ctx, conn, "user_version")
	if err != nil {
		return err
	}
	if applicationID != 0 && applicationID != sqliteClaimStoreApplicationID {
		return errClaimStoreUnsupported
	}
	if userVersion > sqliteClaimStoreSchemaVersion {
		return errClaimStoreUnsupported
	}
	if applicationID == 0 && userVersion != 0 {
		return errClaimStoreCorrupt
	}
	if userVersion == 0 {
		if applicationID != 0 {
			return errClaimStoreCorrupt
		}
		if err := requireEmptySQLiteBootstrap(ctx, conn); err != nil {
			return err
		}
		return s.applyInitialMigration(ctx, conn, clock)
	}
	if applicationID != sqliteClaimStoreApplicationID {
		return errClaimStoreUnsupported
	}
	if userVersion < sqliteClaimStoreSchemaVersion {
		if err := verifySQLiteMigrationsUpTo(ctx, conn, userVersion); err != nil {
			return err
		}
		if err := s.applyMigrationsAfter(ctx, conn, clock, userVersion); err != nil {
			return err
		}
	}
	return verifySQLiteMigrations(ctx, conn)
}

func (s *sqliteClaimStore) applyInitialMigration(ctx context.Context, conn *sql.Conn, clock claimClock) error {
	if clock == nil {
		clock = systemClaimClock{}
	}
	now := normalizeClaimTime(clock.Now())
	if err := beginImmediate(ctx, conn); err != nil {
		return err
	}
	committed := false
	defer rollbackIfOpen(ctx, conn, &committed)
	if _, err := conn.ExecContext(ctx, fmt.Sprintf("PRAGMA application_id = %d", sqliteClaimStoreApplicationID)); err != nil {
		return mapSQLiteError(err)
	}
	for _, migration := range sqliteClaimStoreMigrations {
		if _, err := conn.ExecContext(ctx, migration.sql); err != nil {
			return mapSQLiteError(err)
		}
		if _, err := conn.ExecContext(ctx,
			`INSERT INTO reliable_submit_migrations(version, name, applied_at_unix_ns, source_sha256) VALUES (?, ?, ?, ?)`,
			migration.version, migration.name, now.UnixNano(), sqliteMigrationSHA256(migration.sql),
		); err != nil {
			return mapSQLiteError(err)
		}
	}
	if _, err := conn.ExecContext(ctx, fmt.Sprintf("PRAGMA user_version = %d", sqliteClaimStoreSchemaVersion)); err != nil {
		return mapSQLiteError(err)
	}
	if err := commit(ctx, conn); err != nil {
		return err
	}
	committed = true
	return nil
}

func (s *sqliteClaimStore) applyMigrationsAfter(ctx context.Context, conn *sql.Conn, clock claimClock, currentVersion int) error {
	if currentVersion < 0 || currentVersion >= sqliteClaimStoreSchemaVersion {
		return errClaimStoreUnsupported
	}
	if clock == nil {
		clock = systemClaimClock{}
	}
	now := normalizeClaimTime(clock.Now())
	if err := beginImmediate(ctx, conn); err != nil {
		return err
	}
	committed := false
	defer rollbackIfOpen(ctx, conn, &committed)
	for _, migration := range sqliteClaimStoreMigrations[currentVersion:] {
		if migration.version != currentVersion+1 {
			return errClaimStoreUnsupported
		}
		if _, err := conn.ExecContext(ctx, migration.sql); err != nil {
			return mapSQLiteError(err)
		}
		if _, err := conn.ExecContext(ctx,
			`INSERT INTO reliable_submit_migrations(version, name, applied_at_unix_ns, source_sha256) VALUES (?, ?, ?, ?)`,
			migration.version, migration.name, now.UnixNano(), sqliteMigrationSHA256(migration.sql),
		); err != nil {
			return mapSQLiteError(err)
		}
		currentVersion = migration.version
	}
	if _, err := conn.ExecContext(ctx, fmt.Sprintf("PRAGMA user_version = %d", sqliteClaimStoreSchemaVersion)); err != nil {
		return mapSQLiteError(err)
	}
	if err := commit(ctx, conn); err != nil {
		return err
	}
	committed = true
	return nil
}

func requireEmptySQLiteBootstrap(ctx context.Context, conn *sql.Conn) error {
	var count int
	if err := conn.QueryRowContext(ctx, `
SELECT count(*)
FROM sqlite_schema
WHERE name NOT LIKE 'sqlite_%'
`).Scan(&count); err != nil {
		return mapSQLiteError(err)
	}
	if count != 0 {
		return errClaimStoreUnsupported
	}
	return nil
}

func validateSQLiteStorePath(path string, disallowedRoots []string) (string, error) {
	if strings.TrimSpace(path) == "" || !filepath.IsAbs(path) {
		return "", errClaimStoreUnsupported
	}
	cleanPath := filepath.Clean(path)
	for _, root := range disallowedRoots {
		if strings.TrimSpace(root) == "" {
			continue
		}
		cleanRoot := filepath.Clean(root)
		if pathsOverlapForSQLiteStore(cleanPath, cleanRoot) {
			return "", errClaimStoreUnsupported
		}
	}
	return cleanPath, nil
}

func pathsOverlapForSQLiteStore(left string, right string) bool {
	if left == right {
		return true
	}
	rel, err := filepath.Rel(left, right)
	if err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return true
	}
	rel, err = filepath.Rel(right, left)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator))
}

func rejectSymlinkPath(path string) error {
	clean := filepath.Clean(path)
	if !filepath.IsAbs(clean) {
		return errClaimStoreUnsupported
	}
	current := string(os.PathSeparator)
	trimmed := strings.TrimPrefix(clean, string(os.PathSeparator))
	if trimmed == "" {
		return nil
	}
	for _, part := range strings.Split(trimmed, string(os.PathSeparator)) {
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err != nil {
			return errClaimStoreUnavailable
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return errClaimStoreUnsupported
		}
	}
	return nil
}

func rejectHardlinkedFile(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return errClaimStoreUnavailable
	}
	if !info.Mode().IsRegular() {
		return errClaimStoreUnsupported
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if ok && stat.Nlink > 1 {
		return errClaimStoreUnsupported
	}
	return nil
}

func sqliteClaimStoreDSN(path string, busyTimeoutMS int) string {
	uri := url.URL{Scheme: "file", Path: path}
	query := uri.Query()
	query.Add("_pragma", "busy_timeout("+strconv.Itoa(busyTimeoutMS)+")")
	query.Add("_pragma", "foreign_keys(ON)")
	query.Add("_pragma", "trusted_schema(OFF)")
	query.Add("_pragma", "synchronous(FULL)")
	query.Add("_pragma", "journal_mode(WAL)")
	query.Set("_txlock", "immediate")
	uri.RawQuery = query.Encode()
	return uri.String()
}

func applyAndVerifySQLiteConnectionPragmas(ctx context.Context, conn *sql.Conn) error {
	var journal string
	if err := conn.QueryRowContext(ctx, "PRAGMA journal_mode=WAL").Scan(&journal); err != nil {
		return mapSQLiteError(err)
	}
	if strings.ToLower(journal) != "wal" {
		return errClaimStoreUnsupported
	}
	if _, err := conn.ExecContext(ctx, "PRAGMA synchronous=FULL"); err != nil {
		return mapSQLiteError(err)
	}
	if _, err := conn.ExecContext(ctx, "PRAGMA foreign_keys=ON"); err != nil {
		return mapSQLiteError(err)
	}
	if _, err := conn.ExecContext(ctx, "PRAGMA trusted_schema=OFF"); err != nil {
		return mapSQLiteError(err)
	}
	foreignKeys, err := pragmaInt(ctx, conn, "foreign_keys")
	if err != nil {
		return err
	}
	if foreignKeys != 1 {
		return errClaimStoreUnsupported
	}
	trustedSchema, err := pragmaInt(ctx, conn, "trusted_schema")
	if err != nil {
		return err
	}
	if trustedSchema != 0 {
		return errClaimStoreUnsupported
	}
	return nil
}

func sqliteQuickCheck(ctx context.Context, conn *sql.Conn) error {
	var result string
	if err := conn.QueryRowContext(ctx, "PRAGMA quick_check").Scan(&result); err != nil {
		return mapSQLiteError(err)
	}
	if result != "ok" {
		return errClaimStoreCorrupt
	}
	return nil
}

func verifySQLiteMigrations(ctx context.Context, conn *sql.Conn) error {
	return verifySQLiteMigrationsUpTo(ctx, conn, sqliteClaimStoreSchemaVersion)
}

func verifySQLiteMigrationsUpTo(ctx context.Context, conn *sql.Conn, expectedVersion int) error {
	if expectedVersion <= 0 || expectedVersion > sqliteClaimStoreSchemaVersion {
		return errClaimStoreUnsupported
	}
	rows, err := conn.QueryContext(ctx, `SELECT version, name, source_sha256 FROM reliable_submit_migrations ORDER BY version`)
	if err != nil {
		return mapSQLiteError(err)
	}
	defer rows.Close()
	seen := 0
	for rows.Next() {
		var version int
		var name string
		var source string
		if err := rows.Scan(&version, &name, &source); err != nil {
			return mapSQLiteError(err)
		}
		if version != seen+1 || version > expectedVersion || version > len(sqliteClaimStoreMigrations) {
			return errClaimStoreUnsupported
		}
		expected := sqliteClaimStoreMigrations[version-1]
		if name != expected.name || source != sqliteMigrationSHA256(expected.sql) {
			return errClaimStoreUnsupported
		}
		seen = version
	}
	if err := rows.Err(); err != nil {
		return mapSQLiteError(err)
	}
	if seen != expectedVersion {
		return errClaimStoreUnsupported
	}
	return nil
}

func pragmaInt(ctx context.Context, conn *sql.Conn, name string) (int, error) {
	var value int
	if err := conn.QueryRowContext(ctx, "PRAGMA "+name).Scan(&value); err != nil {
		return 0, mapSQLiteError(err)
	}
	return value, nil
}

func beginImmediate(ctx context.Context, conn *sql.Conn) error {
	if _, err := conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		return mapSQLiteError(err)
	}
	return nil
}

func beginRead(ctx context.Context, conn *sql.Conn) error {
	if _, err := conn.ExecContext(ctx, "BEGIN"); err != nil {
		return mapSQLiteError(err)
	}
	return nil
}

func commit(ctx context.Context, conn *sql.Conn) error {
	if _, err := conn.ExecContext(ctx, "COMMIT"); err != nil {
		return errClaimStoreCommitUnknown
	}
	return nil
}

func rollbackIfOpen(ctx context.Context, conn *sql.Conn, committed *bool) {
	if committed != nil && *committed {
		return
	}
	_, _ = conn.ExecContext(ctx, "ROLLBACK")
}

func chmodSQLiteStoreFiles(path string) error {
	for _, candidate := range []string{path, path + "-wal", path + "-shm", path + "-journal"} {
		if _, err := os.Lstat(candidate); errors.Is(err, os.ErrNotExist) {
			continue
		} else if err != nil {
			return mapSQLiteFilesystemError(err)
		}
		if err := os.Chmod(candidate, 0o600); err != nil {
			return mapSQLiteFilesystemError(err)
		}
	}
	return nil
}

func mapSQLiteFilesystemError(err error) error {
	if err == nil {
		return nil
	}
	return errClaimStoreUnavailable
}

func mapSQLiteError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, sql.ErrNoRows) {
		return errClaimStoreNotFound
	}
	lower := strings.ToLower(err.Error())
	switch {
	case strings.Contains(lower, "database is locked"),
		strings.Contains(lower, "database table is locked"),
		strings.Contains(lower, "sqlite_busy"),
		strings.Contains(lower, "sqlite_locked"),
		strings.Contains(lower, "busy"):
		return errClaimStoreBusy
	case strings.Contains(lower, "not a database"),
		strings.Contains(lower, "malformed"),
		strings.Contains(lower, "corrupt"),
		strings.Contains(lower, "file is not a database"):
		return errClaimStoreCorrupt
	case strings.Contains(lower, "constraint"),
		strings.Contains(lower, "trigger"),
		strings.Contains(lower, "check failed"):
		return errClaimStoreCorrupt
	case strings.Contains(lower, "permission denied"),
		strings.Contains(lower, "readonly"),
		strings.Contains(lower, "unable to open"),
		strings.Contains(lower, "i/o error"):
		return errClaimStoreUnavailable
	default:
		return errClaimStoreInternal
	}
}

const sqliteClaimColumns = `
caller_ref,
submit_key_ref,
plan_binding,
witness_resolved_mask,
witness_inapplicable_mask,
phase_tag,
run_ref,
receipt_ref,
revision,
created_at_unix_ns,
updated_at_unix_ns,
assigned_at_unix_ns,
effect_intent_ref,
effect_intent_at_unix_ns,
staging_ref,
staging_at_unix_ns,
dispatch_ref,
dispatch_at_unix_ns,
provider_observation_kind,
provider_observation_ref,
provider_observation_at_unix_ns,
reconciliation_kind,
reconciliation_ref,
reconciliation_at_unix_ns,
expires_at_unix_ns,
retention_state,
unavailable_at_unix_ns,
unavailable_reason,
last_mutation_ref,
latest_operation_kind,
latest_operation_input_digest,
codec_version`

const sqliteInsertClaimSQL = `
INSERT INTO reliable_submit_claims (` + sqliteClaimColumns + `)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(caller_ref, submit_key_ref) DO NOTHING`

const sqliteUpdateClaimSQL = `
UPDATE reliable_submit_claims
SET caller_ref = ?,
    submit_key_ref = ?,
    plan_binding = ?,
    witness_resolved_mask = ?,
    witness_inapplicable_mask = ?,
    phase_tag = ?,
    run_ref = ?,
    receipt_ref = ?,
    revision = ?,
    created_at_unix_ns = ?,
    updated_at_unix_ns = ?,
    assigned_at_unix_ns = ?,
    effect_intent_ref = ?,
    effect_intent_at_unix_ns = ?,
    staging_ref = ?,
    staging_at_unix_ns = ?,
    dispatch_ref = ?,
    dispatch_at_unix_ns = ?,
    provider_observation_kind = ?,
    provider_observation_ref = ?,
    provider_observation_at_unix_ns = ?,
    reconciliation_kind = ?,
    reconciliation_ref = ?,
    reconciliation_at_unix_ns = ?,
    expires_at_unix_ns = ?,
    retention_state = ?,
    unavailable_at_unix_ns = ?,
    unavailable_reason = ?,
    last_mutation_ref = ?,
    latest_operation_kind = ?,
    latest_operation_input_digest = ?,
    codec_version = ?
WHERE caller_ref = ? AND submit_key_ref = ? AND revision = ? AND retention_state = ?`

func selectSQLiteClaim(ctx context.Context, conn *sql.Conn, claim ClaimID) (durableClaimRecord, error) {
	if !claim.Valid() {
		return durableClaimRecord{}, errClaimStoreInternal
	}
	row := conn.QueryRowContext(ctx,
		`SELECT `+sqliteClaimColumns+` FROM reliable_submit_claims WHERE caller_ref = ? AND submit_key_ref = ?`,
		opaqueRefBytes(claim.caller.ref), opaqueRefBytes(claim.submitKey.ref),
	)
	record, err := scanSQLiteClaim(row)
	if err != nil {
		return durableClaimRecord{}, err
	}
	return record, nil
}

type sqliteScanner interface {
	Scan(dest ...any) error
}

func scanSQLiteClaim(row sqliteScanner) (durableClaimRecord, error) {
	var data sqliteClaimRow
	if err := row.Scan(
		&data.callerRef,
		&data.submitKeyRef,
		&data.planBinding,
		&data.witnessResolvedMask,
		&data.witnessInapplicableMask,
		&data.phaseTag,
		&data.runRef,
		&data.receiptRef,
		&data.revision,
		&data.createdAtUnixNS,
		&data.updatedAtUnixNS,
		&data.assignedAtUnixNS,
		&data.effectIntentRef,
		&data.effectIntentAtUnixNS,
		&data.stagingRef,
		&data.stagingAtUnixNS,
		&data.dispatchRef,
		&data.dispatchAtUnixNS,
		&data.providerObservationKind,
		&data.providerObservationRef,
		&data.providerObservationAtUnixNS,
		&data.reconciliationKind,
		&data.reconciliationRef,
		&data.reconciliationAtUnixNS,
		&data.expiresAtUnixNS,
		&data.retentionState,
		&data.unavailableAtUnixNS,
		&data.unavailableReason,
		&data.lastMutationRef,
		&data.latestOperationKind,
		&data.latestOperationInputDigest,
		&data.codecVersion,
	); err != nil {
		if errors.Is(err, errInvalidDurableRecord) {
			return durableClaimRecord{}, errClaimStoreCorrupt
		}
		return durableClaimRecord{}, mapSQLiteError(err)
	}
	record, err := data.record()
	if err != nil {
		return durableClaimRecord{}, errClaimStoreCorrupt
	}
	return record, nil
}

type sqliteClaimRow struct {
	callerRef                   []byte
	submitKeyRef                []byte
	planBinding                 []byte
	witnessResolvedMask         int64
	witnessInapplicableMask     int64
	phaseTag                    int64
	runRef                      []byte
	receiptRef                  []byte
	revision                    int64
	createdAtUnixNS             int64
	updatedAtUnixNS             int64
	assignedAtUnixNS            sql.NullInt64
	effectIntentRef             []byte
	effectIntentAtUnixNS        sql.NullInt64
	stagingRef                  []byte
	stagingAtUnixNS             sql.NullInt64
	dispatchRef                 []byte
	dispatchAtUnixNS            sql.NullInt64
	providerObservationKind     int64
	providerObservationRef      []byte
	providerObservationAtUnixNS sql.NullInt64
	reconciliationKind          int64
	reconciliationRef           []byte
	reconciliationAtUnixNS      sql.NullInt64
	expiresAtUnixNS             sql.NullInt64
	retentionState              int64
	unavailableAtUnixNS         sql.NullInt64
	unavailableReason           string
	lastMutationRef             []byte
	latestOperationKind         sql.NullInt64
	latestOperationInputDigest  sqliteNullableBlob
	codecVersion                int64
}

type sqliteNullableBlob struct {
	valid bool
	bytes []byte
}

func (b *sqliteNullableBlob) Scan(value any) error {
	if value == nil {
		b.valid = false
		b.bytes = nil
		return nil
	}
	raw, ok := value.([]byte)
	if !ok {
		b.valid = false
		b.bytes = nil
		return errInvalidDurableRecord
	}
	b.valid = true
	b.bytes = append(b.bytes[:0], raw...)
	return nil
}

func (r sqliteClaimRow) record() (durableClaimRecord, error) {
	caller, err := NewCallerRef(r.callerRef)
	if err != nil {
		return durableClaimRecord{}, err
	}
	submitKey, err := NewSubmitKeyRef(r.submitKeyRef)
	if err != nil {
		return durableClaimRecord{}, err
	}
	claim, err := NewClaimID(caller, submitKey)
	if err != nil {
		return durableClaimRecord{}, err
	}
	binding, err := NewPlanBinding(r.planBinding)
	if err != nil {
		return durableClaimRecord{}, err
	}
	witness, err := witnessFromSQLiteMasks(r.witnessResolvedMask, r.witnessInapplicableMask)
	if err != nil {
		return durableClaimRecord{}, err
	}
	plan, err := NewBoundPlan(binding, witness)
	if err != nil {
		return durableClaimRecord{}, err
	}
	phase, err := r.phaseSnapshot()
	if err != nil {
		return durableClaimRecord{}, err
	}
	effects, err := r.effectFacts()
	if err != nil {
		return durableClaimRecord{}, err
	}
	mutation, err := newDurableMutationRef(r.lastMutationRef)
	if err != nil {
		return durableClaimRecord{}, err
	}
	latestOperation, err := sqliteLatestOperationDescriptor(uint16(r.codecVersion), mutation, r.latestOperationKind, r.latestOperationInputDigest)
	if err != nil {
		return durableClaimRecord{}, err
	}
	record := durableClaimRecord{
		codecVersion:    uint16(r.codecVersion),
		claim:           claim,
		plan:            plan,
		phase:           phase,
		revision:        claimRevision(r.revision),
		effects:         effects,
		createdAt:       time.Unix(0, r.createdAtUnixNS).UTC(),
		updatedAt:       time.Unix(0, r.updatedAtUnixNS).UTC(),
		assignedAt:      nullUnixNanoToClaimTime(r.assignedAtUnixNS),
		expiresAt:       nullUnixNanoToClaimTime(r.expiresAtUnixNS),
		latestOperation: latestOperation,
		retention: durableRetentionFact{
			state:         durableRetentionState(r.retentionState),
			unavailableAt: nullUnixNanoToClaimTime(r.unavailableAtUnixNS),
			reason:        r.unavailableReason,
		},
		lastMutation: mutation,
	}
	if err := record.validate(); err != nil {
		return durableClaimRecord{}, err
	}
	return record, nil
}

func sqliteLatestOperationDescriptor(codecVersion uint16, mutation durableMutationRef, kind sql.NullInt64, digest sqliteNullableBlob) (durableLatestOperationDescriptor, error) {
	switch codecVersion {
	case durableClaimCodecVersionLegacy:
		if kind.Valid || digest.valid {
			return durableLatestOperationDescriptor{}, errInvalidDurableRecord
		}
		return newLegacyDurableLatestOperationDescriptor(mutation)
	case durableClaimCodecVersion:
		if !kind.Valid || !digest.valid {
			return durableLatestOperationDescriptor{}, errInvalidDurableRecord
		}
		binding, err := newDurableOperationInputBinding(digest.bytes)
		if err != nil {
			return durableLatestOperationDescriptor{}, errInvalidDurableRecord
		}
		return newCompleteDurableLatestOperationDescriptor(mutation, durableOperationKind(kind.Int64), binding)
	default:
		return durableLatestOperationDescriptor{}, errInvalidDurableRecord
	}
}

func (r sqliteClaimRow) phaseSnapshot() (durablePhaseSnapshot, error) {
	snapshot := durablePhaseSnapshot{tag: durablePhaseTag(r.phaseTag)}
	if len(r.runRef) > 0 {
		run, err := NewRunRef(r.runRef)
		if err != nil {
			return durablePhaseSnapshot{}, err
		}
		snapshot.run = run
	}
	if len(r.receiptRef) > 0 {
		receipt, err := NewReceiptRef(r.receiptRef)
		if err != nil {
			return durablePhaseSnapshot{}, err
		}
		snapshot.receipt = receipt
	}
	if !snapshot.valid() {
		return durablePhaseSnapshot{}, errInvalidDurableRecord
	}
	return snapshot, nil
}

func (r sqliteClaimRow) effectFacts() (durableEffectFacts, error) {
	intent, err := sqliteEffectRefTime(r.effectIntentRef, r.effectIntentAtUnixNS)
	if err != nil {
		return durableEffectFacts{}, err
	}
	staging, err := sqliteEffectRefTime(r.stagingRef, r.stagingAtUnixNS)
	if err != nil {
		return durableEffectFacts{}, err
	}
	dispatch, err := sqliteEffectRefTime(r.dispatchRef, r.dispatchAtUnixNS)
	if err != nil {
		return durableEffectFacts{}, err
	}
	providerFact, err := sqliteEffectRefTime(r.providerObservationRef, r.providerObservationAtUnixNS)
	if err != nil {
		return durableEffectFacts{}, err
	}
	reconciliationFact, err := sqliteEffectRefTime(r.reconciliationRef, r.reconciliationAtUnixNS)
	if err != nil {
		return durableEffectFacts{}, err
	}
	return durableEffectFacts{
		intent:   intent,
		staging:  staging,
		dispatch: dispatch,
		provider: durableProviderObservation{
			kind: durableProviderObservationKind(r.providerObservationKind),
			fact: providerFact,
		},
		reconciliation: durableReconciliationFact{
			kind: durableReconciliationKind(r.reconciliationKind),
			fact: reconciliationFact,
		},
	}, nil
}

func sqliteEffectRefTime(ref []byte, at sql.NullInt64) (durableEffectRefTime, error) {
	if len(ref) == 0 && !at.Valid {
		return durableEffectRefTime{}, nil
	}
	if len(ref) == 0 || !at.Valid {
		return durableEffectRefTime{}, errInvalidDurableRecord
	}
	fact, err := newDurableFactRef(ref)
	if err != nil {
		return durableEffectRefTime{}, err
	}
	return durableEffectRefTime{ref: fact, at: someClaimTime(time.Unix(0, at.Int64))}, nil
}

func nullUnixNanoToClaimTime(value sql.NullInt64) optionalClaimTime {
	if !value.Valid {
		return noClaimTime()
	}
	return someClaimTime(time.Unix(0, value.Int64))
}

func sqliteRecordArgs(record durableClaimRecord) ([]any, error) {
	if err := record.validate(); err != nil {
		return nil, err
	}
	resolvedMask, inapplicableMask, err := sqliteWitnessMasks(record.plan.Witness())
	if err != nil {
		return nil, err
	}
	args := []any{
		opaqueRefBytes(record.claim.caller.ref),
		opaqueRefBytes(record.claim.submitKey.ref),
		opaqueRefBytes(record.plan.Binding().ref),
		resolvedMask,
		inapplicableMask,
		int64(record.phase.tag),
		optionalOpaqueSQL(record.phase.run.ref),
		optionalOpaqueSQL(record.phase.receipt.ref),
		int64(record.revision),
		normalizeClaimTime(record.createdAt).UnixNano(),
		normalizeClaimTime(record.updatedAt).UnixNano(),
		optionalTimeSQL(record.assignedAt),
		optionalFactSQL(record.effects.intent.ref),
		optionalTimeSQL(record.effects.intent.at),
		optionalFactSQL(record.effects.staging.ref),
		optionalTimeSQL(record.effects.staging.at),
		optionalFactSQL(record.effects.dispatch.ref),
		optionalTimeSQL(record.effects.dispatch.at),
		int64(record.effects.provider.kind),
		optionalFactSQL(record.effects.provider.fact.ref),
		optionalTimeSQL(record.effects.provider.fact.at),
		int64(record.effects.reconciliation.kind),
		optionalFactSQL(record.effects.reconciliation.fact.ref),
		optionalTimeSQL(record.effects.reconciliation.fact.at),
		optionalTimeSQL(record.expiresAt),
		int64(record.retention.state),
		optionalTimeSQL(record.retention.unavailableAt),
		record.retention.reason,
		mutationRefBytes(record.lastMutation),
		operationKindSQL(record.latestOperation),
		operationInputBindingSQL(record.latestOperation),
		int64(record.codecVersion),
	}
	return args, nil
}

func operationKindSQL(operation durableLatestOperationDescriptor) any {
	if !operation.kind.valid() {
		return nil
	}
	return int64(operation.kind)
}

func operationInputBindingSQL(operation durableLatestOperationDescriptor) any {
	if !operation.binding.valid {
		return nil
	}
	return operation.binding.bytes()
}

func optionalOpaqueSQL(ref opaqueRef) any {
	if !ref.valid() {
		return nil
	}
	return opaqueRefBytes(ref)
}

func optionalFactSQL(ref durableFactRef) any {
	if !ref.valid() {
		return nil
	}
	return factRefBytes(ref)
}

func optionalTimeSQL(value optionalClaimTime) any {
	if !value.valid {
		return nil
	}
	return value.unixNano()
}

func sqliteWitnessMasks(witness EffectivePlanWitness) (int64, int64, error) {
	if !witness.Valid() {
		return 0, 0, errInvalidDurableRecord
	}
	var resolved int64
	var inapplicable int64
	for _, category := range allEffectivePlanCategories {
		resolution, err := witness.Resolution(category)
		if err != nil {
			return 0, 0, err
		}
		bit := int64(1 << (int(category) - 1))
		switch resolution {
		case EffectivePlanResolved:
			resolved |= bit
		case EffectivePlanExplicitlyInapplicable:
			inapplicable |= bit
		default:
			return 0, 0, errInvalidDurableRecord
		}
	}
	return resolved, inapplicable, nil
}

func witnessFromSQLiteMasks(resolved int64, inapplicable int64) (EffectivePlanWitness, error) {
	if resolved < 0 || inapplicable < 0 ||
		(resolved&inapplicable) != 0 ||
		(resolved|inapplicable) != 16383 ||
		(inapplicable&7935) != 0 {
		return EffectivePlanWitness{}, errInvalidDurableRecord
	}
	entries := make([]EffectivePlanCategoryCompleteness, 0, len(allEffectivePlanCategories))
	for _, category := range allEffectivePlanCategories {
		bit := int64(1 << (int(category) - 1))
		switch {
		case resolved&bit != 0:
			entry, err := ResolvedCategory(category)
			if err != nil {
				return EffectivePlanWitness{}, err
			}
			entries = append(entries, entry)
		case inapplicable&bit != 0 && category == EffectivePlanCategoryOutputIdentity:
			entries = append(entries, OutputIdentityExplicitlyInapplicableForPermittedExecutionKind())
		case inapplicable&bit != 0:
			entry, err := ExplicitlyInapplicableCategory(category)
			if err != nil {
				return EffectivePlanWitness{}, err
			}
			entries = append(entries, entry)
		default:
			return EffectivePlanWitness{}, errInvalidDurableRecord
		}
	}
	return NewEffectivePlanWitness(entries...)
}
