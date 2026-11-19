package reliablesubmit

import (
	"context"
	"database/sql"
	"database/sql/driver"
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
	db                      *sql.DB
	path                    string
	dsn                     string
	legacyV2Fixture         bool // Set only by the historical schema-2 conformance fixture.
	migrationOpeningVersion int
	migrationRecoveredNew   bool
	migrationCommit         func(context.Context, *sql.Conn) error
	beforeMigrationCommit   func(context.Context, *sql.Conn) error
	claimCommit             func(context.Context, *sql.Conn) error
	sealGrantCommit         func(context.Context, *sql.Conn) error
	beginImmediateAttempt   func(context.Context, *sql.Conn) error // Test-only execute-then-error seam; never configured by the opener.
	casAfterBegin           func(context.Context, *sql.Conn) error // O2 test-only CAS phase seam; nil in production.
	casCommitAttempt        func(context.Context, *sql.Conn) error // O2 test-only CAS COMMIT response seam.
	casRollbackAttempt      func(context.Context, *sql.Conn) error // O2 test-only CAS ROLLBACK response seam.
	casDiscardAttempt       func(*sql.Conn) error                  // O2 test-only exact-discard response seam.
	a1ReadBeginAttempt      func(context.Context, *sql.Conn) error // A1 test-only read BEGIN response seam; nil in production.
	a1ReadAfterBegin        func(*sql.Conn) error                  // A1 test-only known-BEGIN observation seam.
	a1ReadAfterFirstKey     func(*sql.Conn) error                  // A1 test-only first-key observation seam.
	a1ReadCommitAttempt     func(context.Context, *sql.Conn) error // A1 test-only read COMMIT response seam.
	a1ReadRollbackAttempt   func(context.Context, *sql.Conn) error // A1 test-only read ROLLBACK response seam.
	a1ReadDiscardAttempt    func(*sql.Conn) error                  // A1 test-only first-discard response seam.
	pooledReadTest          *sqlitePooledReadTestHooks             // Nil outside pooled-reader tests.
	progressBeforeCASTest   func()                                 // Nil outside progress concurrency tests.
}

type sqliteClaimStoreOptions struct {
	path                  string
	disallowedRoots       []string
	busyTimeout           time.Duration
	maxOpenConns          int
	clock                 claimClock
	migrationCommit       func(context.Context, *sql.Conn) error
	beforeMigrationCommit func(context.Context, *sql.Conn) error
	claimCommit           func(context.Context, *sql.Conn) error
	sealGrantCommit       func(context.Context, *sql.Conn) error
}

// errSQLiteMigrationNeedsReadback transfers recovery to the unpublished opener.
var errSQLiteMigrationNeedsReadback = errors.New("SQLite migration requires readback")

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
	dsn := sqliteClaimStoreDSN(cleanPath, busyTimeoutMS)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, errClaimStoreUnavailable
	}
	db.SetMaxOpenConns(maxOpenConns)
	db.SetMaxIdleConns(maxOpenConns)

	store := &sqliteClaimStore{db: db, path: cleanPath, dsn: dsn,
		migrationCommit: opts.migrationCommit, beforeMigrationCommit: opts.beforeMigrationCommit,
		claimCommit: opts.claimCommit, sealGrantCommit: opts.sealGrantCommit}
	if err := store.openGate(ctx, opts.clock); err != nil {
		if !errors.Is(err, errSQLiteMigrationNeedsReadback) {
			_ = db.Close()
			return nil, err
		}
		// openGate has finished with its connection. Check closure of the
		// unpublished pool before observing the file through a fresh pool.
		if db.Close() != nil {
			return nil, errClaimStoreUnavailable
		}
		fresh, openErr := sql.Open("sqlite", dsn)
		if openErr != nil {
			return nil, errClaimStoreUnavailable
		}
		fresh.SetMaxOpenConns(maxOpenConns)
		fresh.SetMaxIdleConns(maxOpenConns)
		store.db = fresh
		verifyErr := store.verifyMigrationRecovery(ctx)
		if ctx.Err() != nil {
			verifyErr = errClaimStoreUnavailable
		}
		if verifyErr != nil {
			_ = fresh.Close()
			return nil, verifyErr
		}
	}
	if err := chmodSQLiteStoreFiles(cleanPath); err != nil {
		_ = store.db.Close()
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

// checkedConn is the only pool acquisition path. SQLite PRAGMAs are per
// connection, so a check made by the opener cannot authorize later work.
func (s *sqliteClaimStore) checkedConn(ctx context.Context) (*sql.Conn, error) {
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return nil, mapSQLiteError(err)
	}
	if err := applyAndVerifySQLiteConnectionPragmas(ctx, conn); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return conn, nil
}

// Returning ErrBadConn from Raw makes database/sql discard and physically
// close this driver connection before the high-level Conn can reach the pool.
// Raw does not retry the preceding COMMIT or ROLLBACK operation.
func discardUncertainSQLiteConn(conn *sql.Conn) error {
	if conn == nil || !errors.Is(conn.Raw(func(any) error { return driver.ErrBadConn }), driver.ErrBadConn) {
		return errClaimStoreUnavailable
	}
	return nil
}

func (s *sqliteClaimStore) establishClaim(ctx context.Context, cmd establishClaimCommand) (out establishClaimStoreResult, outErr error) {
	if err := cmd.record.validate(); err != nil {
		return establishClaimStoreResult{}, errClaimStoreCorrupt
	}
	if cmd.record.codecVersion == durableClaimCodecVersionProgress {
		return establishClaimStoreResult{}, errClaimStoreUnsupported
	}
	conn, err := s.checkedConn(ctx)
	if err != nil {
		return establishClaimStoreResult{}, err
	}
	defer conn.Close()
	if err := s.beginImmediate(ctx, conn); err != nil {
		return establishClaimStoreResult{}, err
	}
	commitAttempted := false
	defer func() {
		if !commitAttempted {
			if _, err := conn.ExecContext(context.Background(), "ROLLBACK"); err != nil {
				if discardUncertainSQLiteConn(conn) != nil {
					out, outErr = establishClaimStoreResult{}, errClaimStoreUnavailable
				} else {
					out, outErr = establishClaimStoreResult{}, errClaimStoreCommitUnknown
				}
			}
		}
	}()
	if cmd.record.codecVersion != durableClaimCodecVersionSynthetic {
		version, err := pragmaInt(ctx, conn, "user_version")
		if err != nil {
			return establishClaimStoreResult{}, err
		}
		if version == sqliteClaimStoreSchemaVersion {
			// The current schema permits legacy rows only through migration. A same-key
			// historical row can be classified by the service, but no new
			// codec-1/2 row may be inserted.
			loaded, err := s.selectSQLiteClaim(ctx, conn, cmd.record.claim)
			if isClaimStoreError(err, claimStoreErrorNotFound) {
				return establishClaimStoreResult{}, errClaimStoreUnsupported
			}
			if err != nil {
				return establishClaimStoreResult{}, err
			}
			if loaded.codecVersion >= durableClaimCodecVersionSynthetic {
				return establishClaimStoreResult{}, errClaimStoreUnsupported
			}
			commitAttempted = true
			if err := s.commitClaim(ctx, conn); err != nil {
				if discardUncertainSQLiteConn(conn) != nil {
					return establishClaimStoreResult{}, errClaimStoreUnavailable
				}
				return establishClaimStoreResult{}, err
			}
			_ = chmodSQLiteStoreFiles(s.path)
			return establishClaimStoreResult{record: loaded}, nil
		}
	}

	args, err := sqliteRecordArgs(cmd.record)
	if err != nil {
		return establishClaimStoreResult{}, err
	}
	if cmd.record.codecVersion == durableClaimCodecVersionSynthetic {
		var count int
		if err := conn.QueryRowContext(ctx, `SELECT count(*) FROM reliable_submit_claims WHERE codec_version IN (3,4)`).Scan(&count); err != nil {
			return establishClaimStoreResult{}, mapSQLiteError(err)
		}
		if count >= 4 {
			var existing int
			err := conn.QueryRowContext(ctx, `SELECT 1 FROM reliable_submit_claims WHERE caller_ref=? AND submit_key_ref=?`,
				opaqueRefBytes(cmd.record.claim.caller.ref), opaqueRefBytes(cmd.record.claim.submitKey.ref)).Scan(&existing)
			if errors.Is(err, sql.ErrNoRows) {
				return establishClaimStoreResult{}, errClaimStoreUnsupported
			}
			if err != nil {
				return establishClaimStoreResult{}, mapSQLiteError(err)
			}
		}
	}
	insertSQL := sqliteInsertClaimSQL
	if cmd.record.codecVersion == durableClaimCodecVersionSynthetic {
		insertSQL = sqliteInsertReplayClaimSQL
	}
	result, err := conn.ExecContext(ctx, insertSQL, args...)
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
	loaded, err := s.selectSQLiteClaim(ctx, conn, cmd.record.claim)
	if err != nil {
		return establishClaimStoreResult{}, err
	}
	if loaded.codecVersion == durableClaimCodecVersionProgress {
		return establishClaimStoreResult{}, errClaimStoreUnsupported
	}
	commitAttempted = true
	if err := s.commitClaim(ctx, conn); err != nil {
		if discardUncertainSQLiteConn(conn) != nil {
			return establishClaimStoreResult{}, errClaimStoreUnavailable
		}
		return establishClaimStoreResult{}, err
	}
	_ = chmodSQLiteStoreFiles(s.path)
	return establishClaimStoreResult{record: loaded, created: rows == 1}, nil
}

// These seams are local to the pooled reader. A rescue is always attempted
// through the real discard primitive before its response can be modeled.
type sqlitePooledReadTestHooks struct {
	begin, commit, rollback func(context.Context, *sql.Conn) error
	afterBegin, afterSelect func()
	firstDiscard            func(*sql.Conn) error
	rescueResponse          func(error) error
	beforePoolReturn        func()
}

func (s *sqliteClaimStore) loadClaim(ctx context.Context, query loadClaimQuery) (record durableClaimRecord, out error) {
	if !query.claim.Valid() {
		return durableClaimRecord{}, errClaimStoreInternal
	}
	if ctx.Err() != nil {
		return durableClaimRecord{}, errClaimStoreUnavailable
	}
	conn, err := s.checkedConn(ctx)
	if err != nil {
		if ctx.Err() != nil {
			return durableClaimRecord{}, errClaimStoreUnavailable
		}
		return durableClaimRecord{}, err
	}

	hooks := s.pooledReadTest
	mayReturn := true
	defer func() {
		if mayReturn {
			if hooks != nil && hooks.beforePoolReturn != nil {
				hooks.beforePoolReturn()
			}
			_ = conn.Close()
		}
	}()

	begin, end := beginRead, commit
	rollback := func(ctx context.Context, conn *sql.Conn) error {
		_, err := conn.ExecContext(ctx, "ROLLBACK")
		return err
	}
	firstDiscard := discardUncertainSQLiteConn
	if hooks != nil {
		if hooks.begin != nil {
			begin = hooks.begin
		}
		if hooks.commit != nil {
			end = hooks.commit
		}
		if hooks.rollback != nil {
			rollback = hooks.rollback
		}
		if hooks.firstDiscard != nil {
			firstDiscard = hooks.firstDiscard
		}
	}
	discard := func() {
		mayReturn = false
		if firstDiscard(conn) == nil {
			mayReturn = true
			return
		}
		rescue := discardUncertainSQLiteConn(conn)
		if hooks != nil && hooks.rescueResponse != nil {
			rescue = hooks.rescueResponse(rescue)
		}
		mayReturn = rescue == nil
	}

	if ctx.Err() != nil {
		return durableClaimRecord{}, errClaimStoreUnavailable
	}
	if err := begin(ctx, conn); err != nil {
		discard()
		return durableClaimRecord{}, errClaimStoreUnavailable
	}
	commitAttempted := false
	defer func() {
		if commitAttempted {
			return
		}
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		rollbackErr := rollback(cleanupCtx, conn)
		contextErr := cleanupCtx.Err()
		cancel()
		if rollbackErr != nil || contextErr != nil {
			discard()
			record, out = durableClaimRecord{}, errClaimStoreUnavailable
		} else if ctx.Err() != nil {
			record, out = durableClaimRecord{}, errClaimStoreUnavailable
		}
	}()
	if hooks != nil && hooks.afterBegin != nil {
		hooks.afterBegin()
	}
	record, err = s.selectSQLiteClaim(ctx, conn, query.claim)
	if err != nil {
		return durableClaimRecord{}, err
	}
	if hooks != nil && hooks.afterSelect != nil {
		hooks.afterSelect()
	}
	if ctx.Err() != nil {
		return durableClaimRecord{}, errClaimStoreUnavailable
	}
	commitAttempted = true
	if err := end(ctx, conn); err != nil {
		discard()
		return durableClaimRecord{}, errClaimStoreUnavailable
	}
	if ctx.Err() != nil {
		return durableClaimRecord{}, errClaimStoreUnavailable
	}
	return record, nil
}

// Private codec-3 classification uses an independent pool, including after
// claim COMMIT uncertainty. It verifies current state without running openGate
// or migrations and cannot reuse the discarded driver connection.
func (s *sqliteClaimStore) loadClaimFresh(ctx context.Context, query loadClaimQuery) (durableClaimRecord, error) {
	dsn := s.dsn
	if dsn == "" {
		dsn = sqliteClaimStoreDSN(s.path, sqliteDefaultBusyTimeoutMS)
	}
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return durableClaimRecord{}, errClaimStoreUnavailable
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(0)
	fresh := &sqliteClaimStore{db: db, path: s.path}
	conn, err := fresh.checkedConn(ctx)
	if err != nil {
		return durableClaimRecord{}, errClaimStoreUnavailable
	}
	defer conn.Close()
	if err := verifySQLiteStoreCurrent(ctx, conn); err != nil {
		return durableClaimRecord{}, errClaimStoreUnavailable
	}
	if err := beginRead(ctx, conn); err != nil {
		return durableClaimRecord{}, err
	}
	committed := false
	defer rollbackIfOpen(ctx, conn, &committed)
	record, err := s.selectSQLiteClaim(ctx, conn, query.claim)
	if err != nil {
		return durableClaimRecord{}, err
	}
	if err := commit(ctx, conn); err != nil {
		return durableClaimRecord{}, err
	}
	committed = true
	return record, nil
}

func (s *sqliteClaimStore) compareAndSwapClaim(ctx context.Context, cmd compareAndSwapClaimCommand) (out compareAndSwapClaimStoreResult, outErr error) {
	if !cmd.claim.Valid() || cmd.expectedRevision < initialClaimRevision {
		return compareAndSwapClaimStoreResult{}, errClaimStoreInternal
	}
	if err := cmd.next.validate(); err != nil {
		return compareAndSwapClaimStoreResult{}, errClaimStoreCorrupt
	}
	if !cmd.next.claim.Equal(cmd.claim) || cmd.next.revision != cmd.expectedRevision+1 {
		return compareAndSwapClaimStoreResult{}, errClaimStoreCorrupt
	}
	if cmd.next.codecVersion >= durableClaimCodecVersionSynthetic {
		return compareAndSwapClaimStoreResult{}, errClaimStoreUnsupported
	}
	conn, err := s.checkedConn(ctx)
	if err != nil {
		return compareAndSwapClaimStoreResult{}, err
	}
	returnToPool := true
	defer func() {
		if returnToPool {
			_ = conn.Close()
		}
	}()
	if err := beginImmediate(ctx, conn); err != nil {
		return compareAndSwapClaimStoreResult{}, err
	}
	commitAttempted := false
	defer func() {
		if commitAttempted {
			return
		}
		// This cleanup is deliberately independent of the caller's context.
		// A failed rollback overrides even a CAS-miss nil result.
		if err := s.rollbackLegacyCAS(context.Background(), conn); err != nil {
			returnToPool = false // Never return an unconfirmed transaction ordinarily.
			_ = s.discardLegacyCAS(conn)
			out, outErr = compareAndSwapClaimStoreResult{}, errClaimStoreUnavailable
		}
	}()
	if s.casAfterBegin != nil {
		if err := s.casAfterBegin(ctx, conn); err != nil {
			return compareAndSwapClaimStoreResult{}, err
		}
	}

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
		loaded, err := s.selectSQLiteClaim(ctx, conn, cmd.claim)
		if err != nil {
			return compareAndSwapClaimStoreResult{}, err
		}
		commitAttempted = true
		if err := s.commitLegacyCAS(ctx, conn); err != nil {
			returnToPool = false
			if s.discardLegacyCAS(conn) != nil {
				return compareAndSwapClaimStoreResult{}, errClaimStoreUnavailable
			}
			return compareAndSwapClaimStoreResult{}, errClaimStoreCommitUnknown
		}
		_ = chmodSQLiteStoreFiles(s.path)
		return compareAndSwapClaimStoreResult{record: loaded, applied: true, found: true}, nil
	}
	current, err := s.selectSQLiteClaim(ctx, conn, cmd.claim)
	if err != nil {
		if isClaimStoreError(err, claimStoreErrorNotFound) {
			return compareAndSwapClaimStoreResult{found: false}, nil
		}
		return compareAndSwapClaimStoreResult{}, err
	}
	if current.codecVersion == durableClaimCodecVersionProgress {
		return compareAndSwapClaimStoreResult{}, errClaimStoreUnsupported
	}
	commitAttempted = true
	if err := s.commitLegacyCAS(ctx, conn); err != nil {
		returnToPool = false
		if s.discardLegacyCAS(conn) != nil {
			return compareAndSwapClaimStoreResult{}, errClaimStoreUnavailable
		}
		return compareAndSwapClaimStoreResult{}, errClaimStoreCommitUnknown
	}
	return compareAndSwapClaimStoreResult{record: current, applied: false, found: true}, nil
}

// These finite seams belong only to historical CAS. Nil production paths
// execute the existing pinned SQLite operations and exact-connection discard.
func (s *sqliteClaimStore) rollbackLegacyCAS(ctx context.Context, conn *sql.Conn) error {
	if s.casRollbackAttempt != nil {
		return s.casRollbackAttempt(ctx, conn)
	}
	_, err := conn.ExecContext(ctx, "ROLLBACK")
	return err
}

func (s *sqliteClaimStore) commitLegacyCAS(ctx context.Context, conn *sql.Conn) error {
	if s.casCommitAttempt != nil {
		return s.casCommitAttempt(ctx, conn)
	}
	return commit(ctx, conn)
}

func (s *sqliteClaimStore) discardLegacyCAS(conn *sql.Conn) error {
	attempt := discardUncertainSQLiteConn
	if s.casDiscardAttempt != nil {
		attempt = s.casDiscardAttempt
	}
	if err := attempt(conn); err != nil {
		// The test seam can lose the disposal response before performing Raw.
		// A direct rescue still fails the operation; never grant success from it.
		_ = discardUncertainSQLiteConn(conn)
		return err
	}
	return nil
}

func (s *sqliteClaimStore) openGate(ctx context.Context, clock claimClock) error {
	conn, err := s.checkedConn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	version, err := verifySQLiteOpening(ctx, conn)
	if err != nil || version == sqliteClaimStoreSchemaVersion {
		return err
	}
	return s.migrateSQLite(ctx, conn, clock)
}

func verifySQLiteOpening(ctx context.Context, conn *sql.Conn) (int, error) {
	if err := sqliteQuickCheck(ctx, conn); err != nil {
		return 0, err
	}
	applicationID, err := pragmaInt(ctx, conn, "application_id")
	if err != nil {
		return 0, err
	}
	version, err := pragmaInt(ctx, conn, "user_version")
	if err != nil {
		return 0, err
	}
	if (applicationID != 0 && applicationID != sqliteClaimStoreApplicationID) ||
		version < 0 || version > sqliteClaimStoreSchemaVersion {
		return 0, errClaimStoreUnsupported
	}
	if version == 0 {
		if applicationID != 0 {
			return 0, errClaimStoreCorrupt
		}
		return 0, requireEmptySQLiteBootstrap(ctx, conn)
	}
	if applicationID == 0 {
		return 0, errClaimStoreCorrupt
	}
	if err := verifySQLiteMigrationsUpTo(ctx, conn, version); err != nil {
		return 0, err
	}
	if err := verifySQLiteSchemaShape(ctx, conn, version); err != nil {
		return 0, err
	}
	return version, nil
}

func verifySQLiteStoreCurrent(ctx context.Context, conn *sql.Conn) error {
	if err := sqliteQuickCheck(ctx, conn); err != nil {
		return err
	}
	appID, err := pragmaInt(ctx, conn, "application_id")
	if err != nil {
		return err
	}
	version, err := pragmaInt(ctx, conn, "user_version")
	if err != nil {
		return err
	}
	if appID != sqliteClaimStoreApplicationID || version != sqliteClaimStoreSchemaVersion {
		return errClaimStoreUnsupported
	}
	if err := verifySQLiteMigrations(ctx, conn); err != nil {
		return err
	}
	return verifySQLiteSchemaShape(ctx, conn, sqliteClaimStoreSchemaVersion)
}

// verifyMigrationRecovery classifies the authenticated opening or current
// schema without migrating. A current observation supplies no attribution
// to the transaction whose cleanup or COMMIT response was unconfirmed.
func (s *sqliteClaimStore) verifyMigrationRecovery(ctx context.Context) error {
	conn, err := s.checkedConn(ctx)
	if err != nil {
		return errClaimStoreUnavailable
	}
	defer conn.Close()
	if err := sqliteQuickCheck(ctx, conn); err != nil {
		return errClaimStoreUnavailable
	}
	appID, err := pragmaInt(ctx, conn, "application_id")
	if err != nil {
		return errClaimStoreUnavailable
	}
	version, err := pragmaInt(ctx, conn, "user_version")
	if err != nil {
		return errClaimStoreUnavailable
	}
	if appID == sqliteClaimStoreApplicationID && version == sqliteClaimStoreSchemaVersion {
		if verifySQLiteStoreCurrent(ctx, conn) != nil {
			return errClaimStoreUnavailable
		}
		s.migrationRecoveredNew = true
		return nil
	}
	if version != s.migrationOpeningVersion {
		return errClaimStoreUnavailable
	}
	if version == 0 {
		if appID != 0 || requireEmptySQLiteBootstrap(ctx, conn) != nil {
			return errClaimStoreUnavailable
		}
		return errClaimStoreMigrationRecoveredOld
	}
	if appID != sqliteClaimStoreApplicationID ||
		verifySQLiteMigrationsUpTo(ctx, conn, version) != nil ||
		verifySQLiteSchemaShape(ctx, conn, version) != nil {
		return errClaimStoreUnavailable
	}
	return errClaimStoreMigrationRecoveredOld
}

func (s *sqliteClaimStore) migrateSQLite(ctx context.Context, conn *sql.Conn, clock claimClock) (out error) {
	if clock == nil {
		clock = systemClaimClock{}
	}
	now := normalizeClaimTime(clock.Now())
	if err := beginImmediate(ctx, conn); err != nil {
		return err
	}
	commitAttempted := false
	migrationStarted := false
	defer func() {
		if commitAttempted {
			return
		}
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_, err := conn.ExecContext(cleanup, "ROLLBACK")
		cleanupErr := cleanup.Err()
		cancel()
		if err != nil || cleanupErr != nil {
			out = errClaimStoreUnavailable
			// A closed wrapper can hand off to its unpublished pool, which
			// still owns disposition. A live wrapper needs confirmed discard.
			if returned := errors.Is(err, sql.ErrConnDone) || discardUncertainSQLiteConn(conn) == nil; returned && migrationStarted {
				out = errSQLiteMigrationNeedsReadback
			}
		} else if out == nil && ctx.Err() != nil {
			out = errClaimStoreUnavailable
		}
	}()

	// Only this lock-held observation can authorize migration or identify
	// its opening state for a later nonmigrating recovery read.
	currentVersion, err := verifySQLiteOpening(ctx, conn)
	if err != nil || currentVersion == sqliteClaimStoreSchemaVersion {
		return err
	}
	if ctx.Err() != nil {
		return errClaimStoreUnavailable
	}
	s.migrationOpeningVersion = currentVersion
	migrationStarted = true
	if currentVersion == 0 {
		if _, err := conn.ExecContext(ctx, fmt.Sprintf("PRAGMA application_id = %d", sqliteClaimStoreApplicationID)); err != nil {
			return mapSQLiteError(err)
		}
	}
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
	if err := verifySQLiteStoreCurrent(ctx, conn); err != nil {
		return err
	}
	if s.beforeMigrationCommit != nil {
		if err := s.beforeMigrationCommit(ctx, conn); err != nil {
			return errClaimStoreUnavailable
		}
	}
	if ctx.Err() != nil {
		return errClaimStoreUnavailable
	}
	commitAttempted = true
	if err := s.commitMigration(ctx, conn); err != nil {
		// The opener closes the whole unpublished pool before recovery.
		// The response hook can already have returned this wrapper.
		return errSQLiteMigrationNeedsReadback
	}
	return nil
}

func requireEmptySQLiteBootstrap(ctx context.Context, conn *sql.Conn) error {
	var count int
	if err := conn.QueryRowContext(ctx, `
SELECT count(*)
FROM sqlite_schema
WHERE `+sqliteUserSchemaPredicate).Scan(&count); err != nil {
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
	query.Add("_pragma", "recursive_triggers(ON)")
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
	if _, err := conn.ExecContext(ctx, "PRAGMA recursive_triggers=ON"); err != nil {
		return errClaimStoreUnsupported
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
	recursiveTriggers, err := pragmaInt(ctx, conn, "recursive_triggers")
	if err != nil || recursiveTriggers != 1 {
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
	return guardedBeginImmediate(ctx, conn, nil)
}

func (s *sqliteClaimStore) beginImmediate(ctx context.Context, conn *sql.Conn) error {
	return guardedBeginImmediate(ctx, conn, s.beginImmediateAttempt)
}

// Own the exact connection before dispatch: a returned BEGIN error may follow
// a successful SQLite step. Only a known-successful result transfers cleanup
// to the caller's transaction lifecycle. The fault hook is used only by tests.
func guardedBeginImmediate(ctx context.Context, conn *sql.Conn, attempt func(context.Context, *sql.Conn) error) (out error) {
	knownBegun := false
	defer func() {
		if !knownBegun {
			// Raw uses no request context and synchronously removes the driver
			// connection from the pool. Error classification is retained only
			// after disposal; it never proves that BEGIN did not execute.
			if discardUncertainSQLiteConn(conn) != nil {
				out = errClaimStoreUnavailable
			}
		}
	}()
	if attempt == nil {
		attempt = func(ctx context.Context, conn *sql.Conn) error {
			_, err := conn.ExecContext(ctx, "BEGIN IMMEDIATE")
			return err
		}
	}
	if err := attempt(ctx, conn); err != nil {
		mapped := mapSQLiteError(err)
		if errors.Is(mapped, errClaimStoreInternal) {
			return errClaimStoreUnavailable
		}
		return mapped
	}
	knownBegun = true
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

func (s *sqliteClaimStore) commitMigration(ctx context.Context, conn *sql.Conn) error {
	if s.migrationCommit != nil {
		return s.migrationCommit(ctx, conn)
	}
	return commit(ctx, conn)
}

func (s *sqliteClaimStore) commitClaim(ctx context.Context, conn *sql.Conn) error {
	if s.claimCommit != nil {
		return s.claimCommit(ctx, conn)
	}
	return commit(ctx, conn)
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

const sqliteReplayColumns = `
replay_scope,
intent_format,
intent_commitment,
context_commitment,
envelope_wrapper_format,
envelope_payload_format,
envelope_algorithm,
envelope_ref,
envelope_size,
envelope_sha256,
binding_key_id,
binding_key_fingerprint,
envelope_key_id,
envelope_key_fingerprint`

const sqliteInsertClaimSQL = `
INSERT INTO reliable_submit_claims (` + sqliteClaimColumns + `)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(caller_ref, submit_key_ref) DO NOTHING`

var sqliteInsertReplayClaimSQL = `INSERT INTO reliable_submit_claims (` +
	sqliteClaimColumns + `, ` + sqliteReplayColumns + `) VALUES (` +
	strings.TrimSuffix(strings.Repeat("?,", 46), ",") +
	`) ON CONFLICT(caller_ref, submit_key_ref) DO NOTHING`

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
WHERE caller_ref = ? AND submit_key_ref = ? AND revision = ? AND retention_state = ? AND codec_version != 4`

func (s *sqliteClaimStore) selectSQLiteClaim(ctx context.Context, conn *sql.Conn, claim ClaimID) (durableClaimRecord, error) {
	if !claim.Valid() {
		return durableClaimRecord{}, errClaimStoreInternal
	}
	projection := sqliteClaimColumns + `, ` + sqliteReplayColumns
	if s.legacyV2Fixture {
		// The authentic schema-2 test fixture has no custody columns. Its
		// unchanged legacy row decoder receives fourteen absent values.
		projection = sqliteClaimColumns + `, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL`
	}
	row := conn.QueryRowContext(ctx,
		`SELECT claim_rowid, `+projection+` FROM reliable_submit_claims WHERE caller_ref = ? AND submit_key_ref = ?`,
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
		sqliteInteger{&data.rowID},
		sqliteBlob{&data.callerRef},
		sqliteBlob{&data.submitKeyRef},
		sqliteBlob{&data.planBinding},
		sqliteInteger{&data.witnessResolvedMask},
		sqliteInteger{&data.witnessInapplicableMask},
		sqliteInteger{&data.phaseTag},
		sqliteBlob{&data.runRef},
		sqliteBlob{&data.receiptRef},
		sqliteInteger{&data.revision},
		sqliteInteger{&data.createdAtUnixNS},
		sqliteInteger{&data.updatedAtUnixNS},
		sqliteOptionalInteger{&data.assignedAtUnixNS},
		sqliteBlob{&data.effectIntentRef},
		sqliteOptionalInteger{&data.effectIntentAtUnixNS},
		sqliteBlob{&data.stagingRef},
		sqliteOptionalInteger{&data.stagingAtUnixNS},
		sqliteBlob{&data.dispatchRef},
		sqliteOptionalInteger{&data.dispatchAtUnixNS},
		sqliteInteger{&data.providerObservationKind},
		sqliteBlob{&data.providerObservationRef},
		sqliteOptionalInteger{&data.providerObservationAtUnixNS},
		sqliteInteger{&data.reconciliationKind},
		sqliteBlob{&data.reconciliationRef},
		sqliteOptionalInteger{&data.reconciliationAtUnixNS},
		sqliteOptionalInteger{&data.expiresAtUnixNS},
		sqliteInteger{&data.retentionState},
		sqliteOptionalInteger{&data.unavailableAtUnixNS},
		sqliteText{&data.unavailableReason},
		sqliteBlob{&data.lastMutationRef},
		sqliteOptionalInteger{&data.latestOperationKind},
		&data.latestOperationInputDigest,
		sqliteInteger{&data.codecVersion},
		sqliteOptionalInteger{&data.replayScope},
		sqliteOptionalInteger{&data.intentFormat},
		&data.intentCommitment,
		&data.contextCommitment,
		sqliteOptionalInteger{&data.wrapperFormat},
		sqliteOptionalInteger{&data.payloadFormat},
		sqliteOptionalInteger{&data.envelopeAlgorithm},
		sqliteOptionalText{&data.envelopeRef},
		sqliteOptionalInteger{&data.envelopeSize},
		&data.envelopeSHA,
		sqliteOptionalText{&data.bindingKeyID},
		&data.bindingKeyFP,
		sqliteOptionalText{&data.envelopeKeyID},
		&data.envelopeKeyFP,
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
	rowID                       int64
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
	replayScope                 sql.NullInt64
	intentFormat                sql.NullInt64
	intentCommitment            sqliteNullableBlob
	contextCommitment           sqliteNullableBlob
	wrapperFormat               sql.NullInt64
	payloadFormat               sql.NullInt64
	envelopeAlgorithm           sql.NullInt64
	envelopeRef                 sql.NullString
	envelopeSize                sql.NullInt64
	envelopeSHA                 sqliteNullableBlob
	bindingKeyID                sql.NullString
	bindingKeyFP                sqliteNullableBlob
	envelopeKeyID               sql.NullString
	envelopeKeyFP               sqliteNullableBlob
}

type sqliteInteger struct{ value *int64 }
type sqliteOptionalInteger struct{ value *sql.NullInt64 }
type sqliteText struct{ value *string }
type sqliteOptionalText struct{ value *sql.NullString }
type sqliteBlob struct{ value *[]byte }

func (s sqliteInteger) Scan(raw any) error {
	value, ok := raw.(int64)
	if !ok {
		return errInvalidDurableRecord
	}
	*s.value = value
	return nil
}

func (s sqliteOptionalInteger) Scan(raw any) error {
	if raw == nil {
		*s.value = sql.NullInt64{}
		return nil
	}
	value, ok := raw.(int64)
	if !ok {
		return errInvalidDurableRecord
	}
	*s.value = sql.NullInt64{Int64: value, Valid: true}
	return nil
}

func (s sqliteText) Scan(raw any) error {
	value, ok := raw.(string)
	if !ok {
		return errInvalidDurableRecord
	}
	*s.value = value
	return nil
}

func (s sqliteOptionalText) Scan(raw any) error {
	if raw == nil {
		*s.value = sql.NullString{}
		return nil
	}
	value, ok := raw.(string)
	if !ok {
		return errInvalidDurableRecord
	}
	*s.value = sql.NullString{String: value, Valid: true}
	return nil
}

func (s sqliteBlob) Scan(raw any) error {
	if raw == nil {
		*s.value = nil
		return nil
	}
	value, ok := raw.([]byte)
	if !ok {
		return errInvalidDurableRecord
	}
	*s.value = append([]byte{}, value...)
	return nil
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
	if r.codecVersion < 1 || r.codecVersion > int64(durableClaimCodecVersionProgress) ||
		r.phaseTag < 1 || r.phaseTag > int64(durablePhaseProvablyNotAcceptedAfterAssignment) ||
		r.retentionState < 1 || r.retentionState > int64(durableRetentionTombstoned) ||
		r.providerObservationKind < 0 || r.providerObservationKind > int64(durableProviderObservationCallUncertain) ||
		r.reconciliationKind < 0 || r.reconciliationKind > int64(durableReconciliationInconsistent) {
		return durableClaimRecord{}, errInvalidDurableRecord
	}
	var rowID int64
	if r.codecVersion == int64(durableClaimCodecVersionProgress) {
		if r.rowID <= 0 {
			return durableClaimRecord{}, errInvalidDurableRecord
		}
		rowID = r.rowID
		for _, value := range [][]byte{r.runRef, r.receiptRef, r.effectIntentRef, r.stagingRef,
			r.dispatchRef, r.providerObservationRef, r.reconciliationRef} {
			if value != nil && len(value) != 32 {
				return durableClaimRecord{}, errInvalidDurableRecord
			}
		}
	}
	replay, err := r.replayDescriptor()
	if err != nil {
		return durableClaimRecord{}, err
	}
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
		progressRowID:   rowID,
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
		replay:       replay,
	}
	if err := record.validate(); err != nil {
		return durableClaimRecord{}, err
	}
	return record, nil
}

func (r sqliteClaimRow) replayDescriptor() (replayClaimDescriptor, error) {
	values := []bool{r.replayScope.Valid, r.intentFormat.Valid,
		r.intentCommitment.valid, r.contextCommitment.valid,
		r.wrapperFormat.Valid, r.payloadFormat.Valid, r.envelopeAlgorithm.Valid,
		r.envelopeRef.Valid, r.envelopeSize.Valid, r.envelopeSHA.valid,
		r.bindingKeyID.Valid, r.bindingKeyFP.valid, r.envelopeKeyID.Valid,
		r.envelopeKeyFP.valid}
	if r.codecVersion < int64(durableClaimCodecVersionSynthetic) {
		for _, present := range values {
			if present {
				return replayClaimDescriptor{}, errInvalidDurableRecord
			}
		}
		return replayClaimDescriptor{}, nil
	}
	for _, present := range values {
		if !present {
			return replayClaimDescriptor{}, errInvalidDurableRecord
		}
	}
	for _, raw := range [][]byte{r.intentCommitment.bytes, r.contextCommitment.bytes,
		r.envelopeSHA.bytes, r.bindingKeyFP.bytes, r.envelopeKeyFP.bytes} {
		if len(raw) != 32 {
			return replayClaimDescriptor{}, errInvalidDurableRecord
		}
	}
	d := replayClaimDescriptor{
		scope: r.replayScope.Int64, intentFormat: r.intentFormat.Int64,
		wrapperFormat: r.wrapperFormat.Int64, payloadFormat: r.payloadFormat.Int64,
		algorithm: r.envelopeAlgorithm.Int64, ref: r.envelopeRef.String,
		size: r.envelopeSize.Int64, bindingKeyID: r.bindingKeyID.String,
		envelopeKeyID: r.envelopeKeyID.String,
	}
	copy(d.intentMAC[:], r.intentCommitment.bytes)
	copy(d.contextMAC[:], r.contextCommitment.bytes)
	copy(d.fileSHA[:], r.envelopeSHA.bytes)
	copy(d.bindingKeyFP[:], r.bindingKeyFP.bytes)
	copy(d.envelopeKeyFP[:], r.envelopeKeyFP.bytes)
	if !d.validForScope(r.codecVersion - 2) {
		return replayClaimDescriptor{}, errInvalidDurableRecord
	}
	return d, nil
}

func sqliteLatestOperationDescriptor(codecVersion uint16, mutation durableMutationRef, kind sql.NullInt64, digest sqliteNullableBlob) (durableLatestOperationDescriptor, error) {
	switch codecVersion {
	case durableClaimCodecVersionLegacy:
		if kind.Valid || digest.valid {
			return durableLatestOperationDescriptor{}, errInvalidDurableRecord
		}
		return newLegacyDurableLatestOperationDescriptor(mutation)
	case durableClaimCodecVersion, durableClaimCodecVersionSynthetic, durableClaimCodecVersionProgress:
		if !kind.Valid || !digest.valid || kind.Int64 < 1 || kind.Int64 > int64(durableOperationTombstoneOrExpire) {
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
	if record.codecVersion >= durableClaimCodecVersionSynthetic {
		d := record.replay
		args = append(args, d.scope, d.intentFormat,
			append([]byte(nil), d.intentMAC[:]...), append([]byte(nil), d.contextMAC[:]...),
			d.wrapperFormat, d.payloadFormat, d.algorithm, d.ref, d.size,
			append([]byte(nil), d.fileSHA[:]...), d.bindingKeyID,
			append([]byte(nil), d.bindingKeyFP[:]...), d.envelopeKeyID,
			append([]byte(nil), d.envelopeKeyFP[:]...))
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

// progressWriteReply retains the actual SQL outcome independently of whether
// the authenticated user of the result can still project its record.
type progressWriteReply struct {
	record      durableClaimRecord
	applied     bool
	occupied    bool
	unknown     bool
	recoverable bool
}

func (s *sqliteClaimStore) progressWrite(ctx context.Context,
	step func(*sql.Conn) (progressWriteReply, error)) (out progressWriteReply, outErr error) {
	if ctx.Err() != nil {
		return out, errClaimStoreUnavailable
	}
	conn, err := s.checkedConn(ctx)
	if err != nil {
		return out, errClaimStoreUnavailable
	}
	mayReturn := true
	defer func() {
		if mayReturn {
			_ = conn.Close()
		}
	}()
	discard := func() bool {
		mayReturn = false
		if discardUncertainSQLiteConn(conn) == nil || discardUncertainSQLiteConn(conn) == nil {
			mayReturn = true
		}
		return mayReturn
	}
	if ctx.Err() != nil {
		return out, errClaimStoreUnavailable
	}
	if _, err := conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		discard()
		return out, errClaimStoreUnavailable
	}
	commitAttempted := false
	defer func() {
		if commitAttempted {
			return
		}
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_, err := conn.ExecContext(cleanup, "ROLLBACK")
		cleanupErr := cleanup.Err()
		cancel()
		if err != nil || cleanupErr != nil {
			discard()
			out, outErr = progressWriteReply{}, errClaimStoreUnavailable
		}
	}()
	out, err = step(conn)
	if err != nil || !out.applied {
		return out, err
	}
	if ctx.Err() != nil {
		return progressWriteReply{}, errClaimStoreUnavailable
	}
	commitAttempted = true
	if err := s.commitClaim(ctx, conn); err != nil {
		out.applied = false
		out.unknown = true
		out.recoverable = discard()
		return out, errClaimStoreCommitUnknown
	}
	_ = chmodSQLiteStoreFiles(s.path)
	return out, nil
}

func (s *sqliteClaimStore) establishProgressRow(ctx context.Context, record durableClaimRecord) (progressWriteReply, error) {
	if record.codecVersion != durableClaimCodecVersionProgress || record.revision != initialClaimRevision ||
		record.progressRowID != 0 || record.validate() != nil {
		return progressWriteReply{}, errClaimStoreUnsupported
	}
	return s.progressWrite(ctx, func(conn *sql.Conn) (progressWriteReply, error) {
		found, err := s.selectSQLiteClaim(ctx, conn, record.claim)
		if err == nil {
			if found.codecVersion != durableClaimCodecVersionProgress {
				return progressWriteReply{}, errClaimStoreUnsupported
			}
			return progressWriteReply{record: found, occupied: true}, nil
		}
		if !errors.Is(err, errClaimStoreNotFound) {
			return progressWriteReply{}, err
		}
		var count int
		if err := conn.QueryRowContext(ctx, "SELECT count(*) FROM reliable_submit_claims WHERE codec_version IN (3,4)").Scan(&count); err != nil {
			return progressWriteReply{}, mapSQLiteError(err)
		}
		if count >= 4 {
			return progressWriteReply{}, errClaimStoreUnsupported
		}
		args, err := sqliteRecordArgs(record)
		if err != nil {
			return progressWriteReply{}, err
		}
		res, err := conn.ExecContext(ctx, sqliteInsertReplayClaimSQL, args...)
		if err != nil {
			return progressWriteReply{}, mapSQLiteError(err)
		}
		changed, err := res.RowsAffected()
		if err != nil || changed != 1 {
			return progressWriteReply{}, errClaimStoreCorrupt
		}
		id, err := res.LastInsertId()
		if err != nil || id <= 0 {
			return progressWriteReply{}, errClaimStoreCorrupt
		}
		record.progressRowID = id
		observed, err := s.selectSQLiteClaim(ctx, conn, record.claim)
		if err != nil || !observed.equal(record) {
			return progressWriteReply{}, errClaimStoreCorrupt
		}
		return progressWriteReply{record: record, applied: true}, nil
	})
}

const sqliteUpdateProgressSQL = `
UPDATE reliable_submit_claims
SET phase_tag=?, run_ref=?, receipt_ref=?, revision=?, updated_at_unix_ns=?,
    assigned_at_unix_ns=?, effect_intent_ref=?, effect_intent_at_unix_ns=?,
    staging_ref=?, staging_at_unix_ns=?, dispatch_ref=?, dispatch_at_unix_ns=?,
    provider_observation_kind=?, provider_observation_ref=?, provider_observation_at_unix_ns=?,
    reconciliation_kind=?, reconciliation_ref=?, reconciliation_at_unix_ns=?,
    last_mutation_ref=?, latest_operation_kind=?, latest_operation_input_digest=?
WHERE claim_rowid=? AND codec_version=4 AND revision=? AND retention_state=1`

func (s *sqliteClaimStore) compareAndSwapProgress(ctx context.Context, before, next durableClaimRecord, keys PrivateReplayKeys) (progressWriteReply, error) {
	if !next.sameProgressOriginal(before) || next.validate() != nil || next.revision <= before.revision ||
		next.revision-1 != before.revision || !progressKeysMatch(before.replay, keys) {
		return progressWriteReply{}, errClaimStoreUnsupported
	}
	return s.progressWrite(ctx, func(conn *sql.Conn) (progressWriteReply, error) {
		current, err := s.selectSQLiteClaim(ctx, conn, before.claim)
		if err != nil || !before.sameProgressOriginal(current) {
			return progressWriteReply{}, errClaimStoreUnavailable
		}
		if err := s.registerOrCompareReplayKey(ctx, conn, keys.bindingID, 1, keys.bindingFP, false); err != nil {
			return progressWriteReply{}, err
		}
		if err := s.registerOrCompareReplayKey(ctx, conn, keys.envelopeID, 2, keys.envelopeFP, false); err != nil {
			return progressWriteReply{}, err
		}
		if current.revision != before.revision {
			return progressWriteReply{record: current, occupied: true}, nil
		}
		if !current.equal(before) {
			return progressWriteReply{}, errClaimStoreCorrupt
		}
		f := next.effects
		res, err := conn.ExecContext(ctx, sqliteUpdateProgressSQL,
			int64(next.phase.tag), optionalOpaqueSQL(next.phase.run.ref), optionalOpaqueSQL(next.phase.receipt.ref),
			int64(next.revision), next.updatedAt.UnixNano(), optionalTimeSQL(next.assignedAt),
			optionalFactSQL(f.intent.ref), optionalTimeSQL(f.intent.at), optionalFactSQL(f.staging.ref), optionalTimeSQL(f.staging.at),
			optionalFactSQL(f.dispatch.ref), optionalTimeSQL(f.dispatch.at),
			int64(f.provider.kind), optionalFactSQL(f.provider.fact.ref), optionalTimeSQL(f.provider.fact.at),
			int64(f.reconciliation.kind), optionalFactSQL(f.reconciliation.fact.ref), optionalTimeSQL(f.reconciliation.fact.at),
			mutationRefBytes(next.lastMutation), operationKindSQL(next.latestOperation), operationInputBindingSQL(next.latestOperation),
			before.progressRowID, int64(before.revision))
		if err != nil {
			return progressWriteReply{}, mapSQLiteError(err)
		}
		changed, err := res.RowsAffected()
		if err != nil || changed != 1 {
			return progressWriteReply{}, errClaimStoreCorrupt
		}
		actual, err := s.selectSQLiteClaim(ctx, conn, before.claim)
		if err != nil || !actual.equal(next) {
			return progressWriteReply{}, errClaimStoreCorrupt
		}
		return progressWriteReply{record: next, applied: true}, nil
	})
}
