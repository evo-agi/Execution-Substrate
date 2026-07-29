package reliablesubmit

import (
	"bufio"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestSQLiteClaimStorePathAndPermissionPosture(t *testing.T) {
	t.Run("reject symlink parent", func(t *testing.T) {
		root := t.TempDir()
		realParent := filepath.Join(root, "real")
		if err := os.Mkdir(realParent, 0o700); err != nil {
			t.Fatalf("mkdir real parent: %v", err)
		}
		linkParent := filepath.Join(root, "link")
		if err := os.Symlink(realParent, linkParent); err != nil {
			t.Skipf("symlink unsupported: %v", err)
		}
		_, err := openSQLiteClaimStore(context.Background(), sqliteClaimStoreOptions{path: filepath.Join(linkParent, "reliable-submit.sqlite3")})
		if !errors.Is(err, errClaimStoreUnsupported) {
			t.Fatalf("symlink parent error = %v", err)
		}
	})

	t.Run("reject symlink db path", func(t *testing.T) {
		root := t.TempDir()
		target := filepath.Join(root, "target.sqlite3")
		link := filepath.Join(root, "link.sqlite3")
		if err := os.WriteFile(target, []byte("not used"), 0o600); err != nil {
			t.Fatalf("write target: %v", err)
		}
		if err := os.Symlink(target, link); err != nil {
			t.Skipf("symlink unsupported: %v", err)
		}
		_, err := openSQLiteClaimStore(context.Background(), sqliteClaimStoreOptions{path: link})
		if !errors.Is(err, errClaimStoreUnsupported) {
			t.Fatalf("symlink db error = %v", err)
		}
	})

	t.Run("reject hardlinked db path", func(t *testing.T) {
		root, err := filepath.EvalSymlinks(t.TempDir())
		if err != nil {
			t.Fatalf("canonicalize temp dir: %v", err)
		}
		path := filepath.Join(root, "state", "reliable-submit.sqlite3")
		store := mustOpenSQLiteClaimStore(t, path)
		if err := store.close(); err != nil {
			t.Fatalf("close: %v", err)
		}
		link := filepath.Join(root, "linked.sqlite3")
		if err := os.Link(path, link); err != nil {
			t.Skipf("hardlink unsupported: %v", err)
		}
		_, err = openSQLiteClaimStore(context.Background(), sqliteClaimStoreOptions{path: path})
		if !errors.Is(err, errClaimStoreUnsupported) {
			t.Fatalf("hardlink error = %v", err)
		}
	})

	t.Run("reject staging results overlap by supplied contract roots", func(t *testing.T) {
		root := t.TempDir()
		staging := filepath.Join(root, "stage")
		results := filepath.Join(root, "results")
		path := filepath.Join(staging, "reliable-submit.sqlite3")
		_, err := openSQLiteClaimStore(context.Background(), sqliteClaimStoreOptions{
			path:            path,
			disallowedRoots: []string{staging, results},
		})
		if !errors.Is(err, errClaimStoreUnsupported) {
			t.Fatalf("overlap error = %v", err)
		}
	})

	t.Run("restrictive directory database and sidecar modes", func(t *testing.T) {
		path := sqliteTestPath(t, "state", "reliable-submit.sqlite3")
		store := mustOpenSQLiteClaimStore(t, path)
		defer store.close()
		f := newDurableFixture(t)
		service := mustDurableService(t, store, fixedClaimClock{now: f.now})
		_ = mustServiceEstablish(t, service, f)
		checkModeExactly(t, filepath.Dir(path), 0o700)
		checkModeExactly(t, path, 0o600)
		checkExistingSidecarMode(t, path+"-wal", 0o600)
		checkExistingSidecarMode(t, path+"-shm", 0o600)
	})
}

func TestSQLiteClaimStoreMalformedAndInvalidCodecFailClosed(t *testing.T) {
	t.Run("not a database", func(t *testing.T) {
		path := sqliteTestPath(t, "state", "not-a-db.sqlite3")
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.WriteFile(path, []byte("not sqlite"), 0o600); err != nil {
			t.Fatalf("write not sqlite: %v", err)
		}
		_, err := openSQLiteClaimStore(context.Background(), sqliteClaimStoreOptions{path: path})
		if !errors.Is(err, errClaimStoreCorrupt) {
			t.Fatalf("not-a-database error = %v", err)
		}
	})

	t.Run("invalid codec row", func(t *testing.T) {
		path := sqliteTestPath(t, "state", "invalid-codec.sqlite3")
		store := mustOpenSQLiteClaimStore(t, path)
		defer store.close()
		f := newDurableFixture(t)
		record := mustPrivateRecord(t, mustPrivatePendingBefore(t, f), f)
		args, err := sqliteRecordArgs(record)
		if err != nil {
			t.Fatalf("sqliteRecordArgs: %v", err)
		}
		args[len(args)-1] = int64(durableClaimCodecVersion + 1)
		if _, err := store.db.Exec(`DROP TRIGGER reliable_submit_claims_guard_insert_v2`); err != nil {
			t.Fatalf("drop insert guard for corruption seed: %v", err)
		}
		if _, err := store.db.Exec(`PRAGMA ignore_check_constraints=ON`); err != nil {
			t.Fatalf("ignore constraints: %v", err)
		}
		if _, err := store.db.Exec(sqliteInsertClaimSQL, args...); err != nil {
			t.Fatalf("insert invalid codec row: %v", err)
		}
		_, err = store.loadClaim(context.Background(), loadClaimQuery{claim: f.claim})
		if !errors.Is(err, errClaimStoreCorrupt) {
			t.Fatalf("invalid codec load error = %v", err)
		}
	})
}

func TestSQLiteClaimStoreTwoHandlesBusyTimeoutAndHelperProcessContention(t *testing.T) {
	path := sqliteTestPath(t, "state", "reliable-submit.sqlite3")
	first := mustOpenSQLiteClaimStore(t, path)
	defer first.close()
	second, err := openSQLiteClaimStore(context.Background(), sqliteClaimStoreOptions{
		path:        path,
		busyTimeout: 25 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("open second handle: %v", err)
	}
	defer second.close()
	f := newDurableFixture(t)
	service := mustDurableService(t, first, fixedClaimClock{now: f.now})
	created := mustServiceEstablish(t, service, f)
	loaded, err := second.loadClaim(context.Background(), loadClaimQuery{claim: f.claim})
	if err != nil {
		t.Fatalf("second handle load: %v", err)
	}
	if !loaded.equal(created.record) {
		t.Fatalf("second handle loaded different record")
	}

	cmd := exec.Command(os.Args[0], "-test.run=TestSQLiteClaimStoreLockHelperProcess", "--")
	cmd.Env = append(os.Environ(),
		"RELIABLE_SUBMIT_SQLITE_LOCK_HELPER=1",
		"RELIABLE_SUBMIT_SQLITE_LOCK_PATH="+path,
	)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("helper stdout: %v", err)
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start helper: %v", err)
	}
	scanner := bufio.NewScanner(stdout)
	if !scanner.Scan() || scanner.Text() != "locked" {
		_ = cmd.Process.Kill()
		t.Fatalf("helper did not report lock; text=%q err=%v", scanner.Text(), scanner.Err())
	}
	other := newDurableFixture(t)
	other.caller = mustPrivateCallerRef(t, []byte("private-caller-reference-two"))
	other.claim = mustPrivateClaimID(t, other.caller, other.submitKey)
	other.plan = mustPrivateBoundPlan(t, other.binding, other.witness)
	busyService := mustDurableService(t, second, fixedClaimClock{now: other.now})
	_, err = busyService.establishOrLoadClaim(context.Background(), establishClaimRequest{
		claim:    other.claim,
		plan:     other.plan,
		mutation: other.mutation,
	})
	if !errors.Is(err, errClaimStoreBusy) {
		_ = cmd.Process.Kill()
		t.Fatalf("busy contention error = %v", err)
	}
	if err := cmd.Wait(); err != nil {
		t.Fatalf("helper wait: %v", err)
	}
}

func TestSQLiteClaimStoreLockHelperProcess(t *testing.T) {
	if os.Getenv("RELIABLE_SUBMIT_SQLITE_LOCK_HELPER") != "1" {
		t.Skip("helper process only")
	}
	path := os.Getenv("RELIABLE_SUBMIT_SQLITE_LOCK_PATH")
	db, err := sql.Open("sqlite", sqliteClaimStoreDSN(path, sqliteDefaultBusyTimeoutMS))
	if err != nil {
		t.Fatalf("open helper db: %v", err)
	}
	defer db.Close()
	conn, err := db.Conn(context.Background())
	if err != nil {
		t.Fatalf("helper conn: %v", err)
	}
	defer conn.Close()
	if err := beginImmediate(context.Background(), conn); err != nil {
		t.Fatalf("helper begin immediate: %v", err)
	}
	fmt.Println("locked")
	time.Sleep(300 * time.Millisecond)
	if _, err := conn.ExecContext(context.Background(), "ROLLBACK"); err != nil {
		t.Fatalf("helper rollback: %v", err)
	}
}

func TestSQLiteClaimStoreRollbackLeavesNoPartialMutation(t *testing.T) {
	path := sqliteTestPath(t, "state", "reliable-submit.sqlite3")
	store := mustOpenSQLiteClaimStore(t, path)
	defer store.close()
	f := newDurableFixture(t)
	record := mustPrivateRecord(t, mustPrivatePendingBefore(t, f), f)
	args, err := sqliteRecordArgs(record)
	if err != nil {
		t.Fatalf("sqliteRecordArgs: %v", err)
	}
	conn, err := store.db.Conn(context.Background())
	if err != nil {
		t.Fatalf("conn: %v", err)
	}
	defer conn.Close()
	if err := beginImmediate(context.Background(), conn); err != nil {
		t.Fatalf("begin: %v", err)
	}
	if _, err := conn.ExecContext(context.Background(), sqliteInsertClaimSQL, args...); err != nil {
		t.Fatalf("insert in tx: %v", err)
	}
	if _, err := conn.ExecContext(context.Background(), "ROLLBACK"); err != nil {
		t.Fatalf("rollback: %v", err)
	}
	_, err = store.loadClaim(context.Background(), loadClaimQuery{claim: f.claim})
	if !errors.Is(err, errClaimStoreNotFound) {
		t.Fatalf("load after rollback error = %v", err)
	}
}

func TestSQLiteRollbackJournalObservation(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("journal file observation is platform-specific")
	}
	path := sqliteTestPath(t, "rollback.sqlite3")
	db := mustRawSQLiteDB(t, path)
	defer db.Close()
	if _, err := db.Exec(`PRAGMA journal_mode=DELETE`); err != nil {
		t.Fatalf("set delete journal: %v", err)
	}
	if _, err := db.Exec(`CREATE TABLE t (id INTEGER PRIMARY KEY, value TEXT NOT NULL)`); err != nil {
		t.Fatalf("create table: %v", err)
	}
	conn, err := db.Conn(context.Background())
	if err != nil {
		t.Fatalf("conn: %v", err)
	}
	defer conn.Close()
	if _, err := conn.ExecContext(context.Background(), `BEGIN IMMEDIATE`); err != nil {
		t.Fatalf("begin: %v", err)
	}
	if _, err := conn.ExecContext(context.Background(), `INSERT INTO t(value) VALUES ('held')`); err != nil {
		t.Fatalf("insert: %v", err)
	}
	if _, err := os.Lstat(path + "-journal"); err != nil {
		_, _ = conn.ExecContext(context.Background(), `ROLLBACK`)
		t.Fatalf("rollback journal not observed: %v", err)
	}
	if _, err := conn.ExecContext(context.Background(), `ROLLBACK`); err != nil {
		t.Fatalf("rollback: %v", err)
	}
}

func checkModeExactly(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", filepath.Base(path), err)
	}
	if got := info.Mode().Perm(); got != want {
		t.Fatalf("%s mode = %o, want %o", filepath.Base(path), got, want)
	}
}

func checkExistingSidecarMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected SQLite sidecar %s to exist", filepath.Base(path))
	}
	if err != nil {
		t.Fatalf("stat sidecar: %v", err)
	}
	if got := info.Mode().Perm(); got != want {
		t.Fatalf("%s mode = %o, want %o", filepath.Base(path), got, want)
	}
}

func TestSQLitePhysicalErrorsDoNotExposePrivateValues(t *testing.T) {
	path := sqliteTestPath(t, "state", "reliable-submit.sqlite3")
	store := mustOpenSQLiteClaimStore(t, path)
	defer store.close()
	f := newDurableFixture(t)
	_, err := store.loadClaim(context.Background(), loadClaimQuery{claim: f.claim})
	if err == nil {
		t.Fatalf("expected missing claim error")
	}
	for _, forbidden := range []string{"private-caller-reference", "private-submit-key-reference", path} {
		if strings.Contains(err.Error(), forbidden) {
			t.Fatalf("error leaked private value %q: %v", forbidden, err)
		}
	}
}

func TestSQLiteFilesystemErrorsDoNotExposePrivatePaths(t *testing.T) {
	root := t.TempDir()
	sentinel := "private-path-sentinel"
	privatePath := filepath.Join(root, sentinel, "reliable-submit.sqlite3")

	_, err := openSQLiteClaimStore(context.Background(), sqliteClaimStoreOptions{
		path:            privatePath,
		disallowedRoots: []string{filepath.Dir(privatePath)},
	})
	assertStoreErrorPrivatePathSafe(t, err, errClaimStoreUnsupported, root, sentinel, privatePath)

	parentFile := filepath.Join(root, sentinel+"-parent-file")
	if err := os.WriteFile(parentFile, []byte("not a directory"), 0o600); err != nil {
		t.Fatalf("write parent file: %v", err)
	}
	fileChildPath := filepath.Join(parentFile, "reliable-submit.sqlite3")
	_, err = openSQLiteClaimStore(context.Background(), sqliteClaimStoreOptions{path: fileChildPath})
	assertStoreErrorPrivatePathSafe(t, err, errClaimStoreUnavailable, root, sentinel, fileChildPath)

	realParent := filepath.Join(root, sentinel+"-real")
	if err := os.Mkdir(realParent, 0o700); err != nil {
		t.Fatalf("mkdir real parent: %v", err)
	}
	linkParent := filepath.Join(root, sentinel+"-link")
	if err := os.Symlink(realParent, linkParent); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	linkPath := filepath.Join(linkParent, "reliable-submit.sqlite3")
	_, err = openSQLiteClaimStore(context.Background(), sqliteClaimStoreOptions{path: linkPath})
	assertStoreErrorPrivatePathSafe(t, err, errClaimStoreUnsupported, root, sentinel, linkPath)

	blocked := filepath.Join(root, sentinel+"-blocked")
	if err := os.Mkdir(blocked, 0o700); err != nil {
		t.Fatalf("mkdir blocked: %v", err)
	}
	if err := os.Chmod(blocked, 0); err != nil {
		t.Fatalf("chmod blocked: %v", err)
	}
	defer os.Chmod(blocked, 0o700)
	chmodPath := filepath.Join(blocked, "reliable-submit.sqlite3")
	err = chmodSQLiteStoreFiles(chmodPath)
	if err != nil {
		assertStoreErrorPrivatePathSafe(t, err, errClaimStoreUnavailable, root, sentinel, chmodPath)
	}
}

func assertStoreErrorPrivatePathSafe(t *testing.T, err error, want error, forbidden ...string) {
	t.Helper()
	if !errors.Is(err, want) {
		t.Fatalf("store error = %v, want %v", err, want)
	}
	for _, rendered := range []string{err.Error(), fmt.Sprint(err), fmt.Sprintf("%+v", err)} {
		for _, private := range forbidden {
			if private != "" && strings.Contains(rendered, private) {
				t.Fatalf("store error leaked private path %q through %q", private, rendered)
			}
		}
	}
	for cause := errors.Unwrap(err); cause != nil; cause = errors.Unwrap(cause) {
		for _, private := range forbidden {
			if private != "" && strings.Contains(cause.Error(), private) {
				t.Fatalf("store error unwrap leaked private path %q through %q", private, cause.Error())
			}
		}
	}
}
