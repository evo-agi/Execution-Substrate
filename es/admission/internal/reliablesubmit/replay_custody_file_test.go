package reliablesubmit

import (
	"bufio"
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"errors"
	"fmt"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func fixtureReplayObject(t *testing.T, values ...[]byte) []byte {
	t.Helper()
	fields := make([]replayField, len(values))
	for i, value := range values {
		fields[i] = replayField{id: uint16(i + 1), state: 1, value: value}
	}
	out, err := encodeReplayObject(fields)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// This is a source-order assertion. The dynamic publication case below proves
// the retained file is empty, but does not hook or observe cipher.GCM.Seal.
func a1ReadAssertPreSealSource(t *testing.T) {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "replay_custody_file.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var publish *ast.FuncDecl
	wrappers := map[string]int{"PublishSealedSynthetic": 0, "PublishProgressOriginal": 0}
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok {
			continue
		}
		if fn.Name.Name == "publishReplayOriginal" {
			publish = fn
		}
		if _, isWrapper := wrappers[fn.Name.Name]; !isWrapper {
			continue
		}
		ast.Inspect(fn.Body, func(node ast.Node) bool {
			if call, ok := node.(*ast.CallExpr); ok {
				if target, ok := call.Fun.(*ast.SelectorExpr); ok && target.Sel.Name == "publishReplayOriginal" {
					wrappers[fn.Name.Name]++
				}
			}
			return true
		})
	}
	if publish == nil || wrappers["PublishSealedSynthetic"] != 1 || wrappers["PublishProgressOriginal"] != 1 {
		t.Fatal("publication source function missing")
	}
	var checkPos, sealPos token.Pos
	ast.Inspect(publish.Body, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		var rendered bytes.Buffer
		if err := format.Node(&rendered, fset, call.Fun); err != nil {
			t.Fatal(err)
		}
		switch rendered.String() {
		case "c.store.consumeReplaySealPermit":
			checkPos = call.Pos()
		case "gcm.Seal":
			sealPos = call.Pos()
		}
		return true
	})
	if checkPos == token.NoPos || sealPos == token.NoPos || checkPos >= sealPos {
		t.Fatal("key-use check does not precede Seal in publication source")
	}
	guardedReturn := false
	for _, stmt := range publish.Body.List {
		if branch, ok := stmt.(*ast.IfStmt); ok && branch.Init != nil && branch.Pos() <= checkPos && checkPos < branch.End() {
			if len(branch.Body.List) != 1 {
				t.Fatal("pre-Seal key-check error has no direct refusal return")
			}
			_, guardedReturn = branch.Body.List[0].(*ast.ReturnStmt)
			if !guardedReturn {
				t.Fatal("pre-Seal key-check error has no direct refusal return")
			}
			break
		}
	}
	if !guardedReturn {
		t.Fatal("pre-Seal key-check refusal guard missing")
	}
}

func a1ReadCustodyFixture(t *testing.T) (*PrivateReplayCustody, durableClaimRecord, PrivateReplayKeys, PrivateReplayFrozen, string) {
	t.Helper()
	record, _ := syntheticReplayRecordFixture(t)
	keys := fixtureReplayKeys(t, 74)
	root := fixtureReplayRoot(t)
	ctx, cancel := a1ReadContext(t)
	defer cancel()
	custody, err := OpenPrivateReplayCustody(ctx, root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = custody.Close() })
	t.Cleanup(func() { a1ReadClearHooks(custody.store) })
	frozen, err := NewPrivateReplayFrozen(record.claim, record.plan, keys, fixtureReplayPayload(t, record, keys))
	if err != nil {
		t.Fatal(err)
	}
	return custody, record, keys, frozen, root
}

func TestReplayOriginalKeyReadCallerRefusal(t *testing.T) {
	t.Run("publication_pre_seal_retains_inert_file_and_burns_permit", func(t *testing.T) {
		a1ReadAssertPreSealSource(t)
		custody, record, keys, frozen, root := a1ReadCustodyFixture(t)
		ctx, cancel := a1ReadContext(t)
		grant, err := custody.ReserveSealUse(ctx, frozen)
		cancel()
		if err != nil || grant.permit == nil {
			t.Fatalf("setup grant: %v", err)
		}
		before := a1ReadSnapshot(t, custody.store, keys)
		requestCtx, stop := context.WithCancel(context.Background())
		defer stop()
		reached := false
		custody.store.a1ReadAfterBegin = func(*sql.Conn) error {
			reached = true
			stop()
			return nil
		}
		publication, err := custody.PublishSealedSynthetic(requestCtx, frozen, grant)
		a1ReadClearHooks(custody.store)
		if !reached || !errors.Is(err, errClaimStoreUnavailable) || publication.descriptor.valid() {
			t.Errorf("pre-Seal refusal: reached=%t valid=%t error=%v", reached, publication.descriptor.valid(), err)
		}
		if !grant.permit.used || grant.permit.consume(custody.store, keys.envelopeID, keys.envelopeFP, frozen.digest) {
			t.Error("failed publication restored consumed permit")
		}
		path := filepath.Join(root, "objects", "v1", fmt.Sprintf("%x", frozen.objectID))
		empty, err := os.ReadFile(path)
		if err != nil || len(empty) != 0 {
			t.Errorf("inert candidate file not retained empty: size=%d error=%v", len(empty), err)
		}
		if after := a1ReadSnapshot(t, custody.store, keys); after != before {
			t.Errorf("failed publication changed durable facts: before=%+v after=%+v", before, after)
		}
		fresh, err := NewPrivateReplayFrozen(record.claim, record.plan, keys, fixtureReplayPayload(t, record, keys))
		if err != nil || fresh.objectID == frozen.objectID {
			t.Fatalf("new object identity unavailable: %v", err)
		}
		ctx, cancel = a1ReadContext(t)
		newGrant, err := custody.ReserveSealUse(ctx, fresh)
		if err != nil || newGrant.permit == nil {
			t.Errorf("fresh legitimate grant unavailable: %v", err)
		} else {
			next, publishErr := custody.PublishSealedSynthetic(ctx, fresh, newGrant)
			if publishErr != nil || !next.descriptor.valid() {
				t.Errorf("new publication failed: valid=%t error=%v", next.descriptor.valid(), publishErr)
			}
		}
		cancel()
	})

	t.Run("establish_preclaim_refuses_and_retains_published_bytes", func(t *testing.T) {
		custody, _, keys, frozen, root := a1ReadCustodyFixture(t)
		ctx, cancel := a1ReadContext(t)
		grant, err := custody.ReserveSealUse(ctx, frozen)
		if err != nil {
			t.Fatal(err)
		}
		publication, err := custody.PublishSealedSynthetic(ctx, frozen, grant)
		cancel()
		if err != nil || !publication.descriptor.valid() {
			t.Fatalf("setup publication: %v", err)
		}
		path := filepath.Join(root, filepath.FromSlash(publication.descriptor.ref))
		original, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		before := a1ReadSnapshot(t, custody.store, keys)
		requestCtx, stop := context.WithCancel(context.Background())
		defer stop()
		reached := false
		custody.store.a1ReadAfterBegin = func(*sql.Conn) error {
			reached = true
			stop()
			return nil
		}
		_, created, err := custody.EstablishSyntheticClaim(requestCtx, frozen, publication)
		a1ReadClearHooks(custody.store)
		if !reached || created || !errors.Is(err, errClaimStoreUnavailable) {
			t.Errorf("preclaim refusal: reached=%t created=%t error=%v", reached, created, err)
		}
		if after := a1ReadSnapshot(t, custody.store, keys); after != before {
			t.Errorf("failed preclaim changed durable facts: before=%+v after=%+v", before, after)
		}
		current, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(current, original) {
			t.Errorf("preclaim changed published bytes: error=%v", err)
		}
		ctx, cancel = a1ReadContext(t)
		_, created, err = custody.EstablishSyntheticClaim(ctx, frozen, publication)
		cancel()
		if err != nil || !created {
			t.Errorf("fresh same-store establishment failed: created=%t error=%v", created, err)
		}
	})

	t.Run("authenticated_existing_claim_refuses_zero_callback_then_recovers", func(t *testing.T) {
		custody, record, keys, frozen, root := a1ReadCustodyFixture(t)
		ctx, cancel := a1ReadContext(t)
		grant, err := custody.ReserveSealUse(ctx, frozen)
		if err != nil {
			t.Fatal(err)
		}
		publication, err := custody.PublishSealedSynthetic(ctx, frozen, grant)
		if err != nil {
			t.Fatal(err)
		}
		_, created, err := custody.EstablishSyntheticClaim(ctx, frozen, publication)
		cancel()
		if err != nil || !created {
			t.Fatalf("setup claim: created=%t error=%v", created, err)
		}
		path := filepath.Join(root, filepath.FromSlash(publication.descriptor.ref))
		original, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		before := a1ReadSnapshot(t, custody.store, keys)
		requestCtx, stop := context.WithCancel(context.Background())
		defer stop()
		reached, callbacks := false, 0
		custody.store.a1ReadAfterBegin = func(*sql.Conn) error {
			reached = true
			stop()
			return nil
		}
		err = custody.WithAuthenticatedClaim(requestCtx, record.claim, keys, func(AuthenticatedClaimMeta, []byte) error {
			callbacks++
			return nil
		})
		a1ReadClearHooks(custody.store)
		if !reached || !errors.Is(err, errClaimStoreUnavailable) || callbacks != 0 {
			t.Errorf("authenticated read refusal: reached=%t callbacks=%d error=%v", reached, callbacks, err)
		}
		if after := a1ReadSnapshot(t, custody.store, keys); after != before {
			t.Errorf("failed authenticated read changed durable facts: before=%+v after=%+v", before, after)
		}
		current, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(current, original) {
			t.Errorf("failed authenticated read changed sealed bytes: error=%v", err)
		}
		ctx, cancel = a1ReadContext(t)
		err = custody.WithAuthenticatedClaim(ctx, record.claim, keys, func(AuthenticatedClaimMeta, []byte) error {
			callbacks++
			return nil
		})
		cancel()
		if err != nil || callbacks != 1 {
			t.Errorf("fresh same-store authenticated read failed: callbacks=%d error=%v", callbacks, err)
		}
	})
}

func fixtureReplayObjectAbsent(t *testing.T, absent map[int]bool, values ...[]byte) []byte {
	t.Helper()
	fields := make([]replayField, len(values))
	for i, value := range values {
		fields[i] = replayField{id: uint16(i + 1), state: 1, value: value}
		if absent[i+1] {
			fields[i].state = 0
			fields[i].value = nil
		}
	}
	out, err := encodeReplayObject(fields)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func fixtureReplayPayload(t *testing.T, record durableClaimRecord, keys PrivateReplayKeys) []byte {
	t.Helper()
	emptySequence := []byte{0, 0}
	zeroDescriptor := make([]byte, 41)
	resolved, inapplicable, err := sqliteWitnessMasks(record.plan.Witness())
	if err != nil {
		t.Fatal(err)
	}
	binding := make([]byte, 2+len(record.plan.binding.ref.value))
	binary.BigEndian.PutUint16(binding[:2], uint16(len(record.plan.binding.ref.value)))
	copy(binding[2:], record.plan.binding.ref.value)
	materialIDs := fixtureReplayObject(t, zeroDescriptor, zeroDescriptor, emptySequence, zeroDescriptor, zeroDescriptor)
	assessment := fixtureReplayObject(t, binding, replayU16(uint16(resolved)), replayU16(uint16(inapplicable)), materialIDs)
	identity := fixtureReplayObject(t, record.claim.caller.ref.value, record.claim.submitKey.ref.value)
	keyGroup := fixtureReplayObject(t, replayU16(1), []byte(keys.bindingID), []byte(keys.envelopeID), replayU16(1), replayU16(1), replayU16(1))
	original := fixtureReplayObjectAbsent(t, map[int]bool{4: true, 8: true, 9: true, 10: true, 11: true, 12: true, 13: true, 14: true, 15: true},
		[]byte("execution-substrate.reliable-submit-request/v1"), []byte("execution-substrate.reliable-submit/v1"), []byte{1}, nil,
		[]byte("artifact"), []byte("derivation"), []byte("output"), nil, nil, nil, nil, nil, nil, nil, nil)
	authorityValues := make([][]byte, 14)
	for i := range authorityValues {
		authorityValues[i] = []byte("x")
	}
	for _, i := range []int{1, 12, 13} {
		authorityValues[i] = []byte{0}
	}
	plan := fixtureReplayObject(t,
		fixtureReplayObject(t, []byte("v1"), []byte("v1")),
		fixtureReplayObject(t, []byte("async"), replayU32(1)),
		fixtureReplayObject(t, replayU32(1), replayU32(1)),
		fixtureReplayObject(t, []byte("profile"), []byte("image")),
		fixtureReplayObject(t, []byte("artifact"), []byte("payload")),
		fixtureReplayObject(t, []byte("derivation"), []byte("output")),
		fixtureReplayObject(t, []byte("/bin/true"), emptySequence),
		emptySequence, emptySequence, []byte{0}, fixtureReplayObject(t, authorityValues...),
		[]byte("support"), make([]byte, 8),
		fixtureReplayObject(t, []byte("service"), []byte("group"), replayU32(1), []byte("task"), []byte("driver"), []byte("user"), []byte{0}, emptySequence, replayU32(0), []byte("restart"), make([]byte, 8), make([]byte, 8), replayU32(0), []byte{0}, make([]byte, 8), []byte("constant"), make([]byte, 8)),
	)
	material := fixtureReplayObjectAbsent(t, map[int]bool{4: true, 5: true}, []byte{1}, []byte{2}, emptySequence, nil, nil)
	image := fixtureReplayObject(t, []byte("image"), bytes.Repeat([]byte{3}, 32), []byte("synthetic issuer"), []byte{1}, []byte("dc"))
	placement := fixtureReplayObject(t, []byte("/staging"), []byte("/results"), []byte("/spire"), []byte("dc"), replayU32(1), replayU32(1))
	provenance := fixtureReplayObject(t, []byte("synthetic_signed_dependencies_v1"), []byte("artifact"), []byte("payload"), []byte("support"), emptySequence, fixtureReplayObject(t, []byte{0}, []byte{0}))
	values := [][]byte{
		identity, original, plan, material, assessment, image,
		placement, provenance, keyGroup, {1},
	}
	object := fixtureReplayObject(t, values...)
	payload := make([]byte, 14+len(object))
	copy(payload, "ESRSPAY1")
	binary.BigEndian.PutUint16(payload[8:10], 1)
	binary.BigEndian.PutUint32(payload[10:14], uint32(len(object)))
	copy(payload[14:], object)
	return payload
}

func unclaimedReplaySealedFixture(t *testing.T, record durableClaimRecord, keys PrivateReplayKeys) (PrivateReplayFrozen, []byte, replayClaimDescriptor) {
	t.Helper()
	frozen, err := NewPrivateReplayFrozen(record.claim, record.plan, keys, fixtureReplayPayload(t, record, keys))
	if err != nil {
		t.Fatal(err)
	}
	block, err := aes.NewCipher(keys.envelope[:])
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCMWithRandomNonce(block)
	if err != nil {
		t.Fatal(err)
	}
	combined := gcm.Seal(nil, nil, frozen.plaintext, frozen.aad)
	sealed := append(append([]byte(nil), frozen.header...), combined...)
	descriptor := replayClaimDescriptor{
		scope: 1, intentFormat: 1, wrapperFormat: 1, payloadFormat: 1, algorithm: 1,
		ref: replayObjectRef(frozen.objectID), size: int64(len(sealed)), fileSHA: sha256.Sum256(sealed),
		bindingKeyID: keys.bindingID, bindingKeyFP: keys.bindingFP,
		envelopeKeyID: keys.envelopeID, envelopeKeyFP: keys.envelopeFP,
		intentMAC: frozen.intentMAC, contextMAC: frozen.contextMAC,
	}
	if !descriptor.valid() {
		t.Fatal("unclaimed synthetic descriptor invalid")
	}
	return frozen, sealed, descriptor
}

func fixtureReplayRoot(t *testing.T) string {
	t.Helper()
	parent := t.TempDir()
	parentFD, err := unix.Open(parent, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := unix.Mkdirat(parentFD, "synthetic", 0o700); err != nil {
		t.Fatal(err)
	}
	rootFD, err := unix.Openat(parentFD, "synthetic", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := unix.Mkdirat(rootFD, "objects", 0o700); err != nil {
		t.Fatal(err)
	}
	objectsFD, err := unix.Openat(rootFD, "objects", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := unix.Mkdirat(objectsFD, "v1", 0o700); err != nil {
		t.Fatal(err)
	}
	v1FD, err := unix.Openat(objectsFD, "v1", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	markerFD, err := unix.Openat(rootFD, "synthetic-replay-v1.marker", unix.O_CREAT|unix.O_EXCL|unix.O_WRONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	marker := []byte("synthetic_nonoperational_v1\n")
	if n, err := unix.Write(markerFD, marker); err != nil || n != len(marker) {
		t.Fatal("write synthetic marker")
	}
	if err := unix.Fsync(markerFD); err != nil {
		t.Fatal(err)
	}
	if err := unix.Close(markerFD); err != nil {
		t.Fatal(err)
	}
	for _, fd := range []int{v1FD, objectsFD, rootFD, parentFD} {
		if err := unix.Fsync(fd); err != nil {
			t.Fatal(err)
		}
	}
	visibleObjects, err := unix.Openat(rootFD, "objects", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	visible, err := unix.Openat(visibleObjects, "v1", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	var heldStat, visibleStat unix.Stat_t
	if unix.Fstat(v1FD, &heldStat) != nil || unix.Fstat(visible, &visibleStat) != nil || heldStat.Dev != visibleStat.Dev || heldStat.Ino != visibleStat.Ino {
		t.Fatal("synthetic directory identity changed")
	}
	if err := unix.Close(visible); err != nil {
		t.Fatal(err)
	}
	if err := unix.Close(visibleObjects); err != nil {
		t.Fatal(err)
	}
	for _, fd := range []int{v1FD, objectsFD, rootFD, parentFD} {
		if err := unix.Close(fd); err != nil {
			t.Fatal(err)
		}
	}
	return filepath.Join(parent, "synthetic")
}

// This handle has its own database/sql pool and verifies the existing schema
// without invoking the migrating store opener.
func c1IndependentSQLiteConn(t *testing.T, path string) (*sql.DB, *sql.Conn) {
	t.Helper()
	ctx := context.Background()
	db, err := sql.Open("sqlite", sqliteClaimStoreDSN(path, 100))
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	conn, err := db.Conn(ctx)
	if err != nil {
		_ = db.Close()
		t.Fatal(err)
	}
	if err := applyAndVerifySQLiteConnectionPragmas(ctx, conn); err != nil {
		_ = conn.Close()
		_ = db.Close()
		t.Fatalf("independent connection pragmas: %v", err)
	}
	if err := verifySQLiteStoreCurrent(ctx, conn); err != nil {
		_ = conn.Close()
		_ = db.Close()
		t.Fatalf("independent nonmigrating verification: %v", err)
	}
	return db, conn
}

func TestReplayClaimC1UncertainConnectionQuarantine(t *testing.T) {
	ctx := context.Background()
	record, _ := syntheticReplayRecordFixture(t)
	keys := fixtureReplayKeys(t, 31)
	root := fixtureReplayRoot(t)
	custody, err := OpenPrivateReplayCustody(ctx, root)
	if err != nil {
		t.Fatal(err)
	}
	defer custody.Close()
	custody.store.db.SetMaxOpenConns(1)
	custody.store.db.SetMaxIdleConns(1)
	frozen, err := NewPrivateReplayFrozen(record.claim, record.plan, keys, fixtureReplayPayload(t, record, keys))
	if err != nil {
		t.Fatal(err)
	}
	grant, err := custody.ReserveSealUse(ctx, frozen)
	if err != nil {
		t.Fatal(err)
	}
	publication, err := custody.PublishSealedSynthetic(ctx, frozen, grant)
	if err != nil {
		t.Fatal(err)
	}
	unclaimedPath := filepath.Join(root, filepath.FromSlash(publication.descriptor.ref))
	unclaimedBytes, err := os.ReadFile(unclaimedPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := custody.InjectClaimCommitFaultForTesting(PrivateReplayClaimConnectionClosedBeforeCommit); err != nil {
		t.Fatal(err)
	}
	attempt, created, err := custody.EstablishSyntheticClaim(ctx, frozen, publication)
	if !errors.Is(err, errClaimStoreCommitUnknown) || created || attempt.expected.validate() != nil {
		t.Fatalf("pre-COMMIT failure was reported as successful: created=%t error=%v", created, err)
	}
	independentDB, independentConn := c1IndependentSQLiteConn(t, custody.store.path)
	defer independentDB.Close()
	defer independentConn.Close()
	var committed int
	if err := independentConn.QueryRowContext(ctx, `SELECT COUNT(*) FROM reliable_submit_claims WHERE caller_ref=? AND submit_key_ref=?`,
		opaqueRefBytes(record.claim.caller.ref), opaqueRefBytes(record.claim.submitKey.ref)).Scan(&committed); err != nil || committed != 0 {
		t.Fatalf("pre-COMMIT attempt became durable: count=%d error=%v", committed, err)
	}
	if _, err := independentConn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		t.Fatalf("pre-COMMIT connection retained SQLite writer lock: %v", err)
	}
	if _, err := independentConn.ExecContext(ctx, "ROLLBACK"); err != nil {
		t.Fatal(err)
	}
	if stats := custody.store.db.Stats(); stats.Idle != 0 || stats.OpenConnections != 0 {
		t.Fatalf("uncertain claim connection remained in the usable pool: idle=%d open=%d", stats.Idle, stats.OpenConnections)
	}
	held, err := custody.store.db.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	readCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	lookup, err := custody.LoadSyntheticClaim(readCtx, record.claim)
	if err != nil || lookup.Found() {
		t.Fatalf("fresh classification of absent pre-COMMIT claim: found=%t error=%v", lookup.Found(), err)
	}
	called := false
	if err := custody.WithAuthenticatedClaim(readCtx, record.claim, keys, func(AuthenticatedClaimMeta, []byte) error {
		called = true
		return nil
	}); !errors.Is(err, errClaimStoreNotFound) || called {
		t.Fatalf("unclaimed file gained read authority: called=%t error=%v", called, err)
	}
	cancel()
	if err := held.Close(); err != nil {
		t.Fatal(err)
	}
	if visible, err := os.ReadFile(unclaimedPath); err != nil || !bytes.Equal(visible, unclaimedBytes) {
		t.Fatalf("unclaimed file was changed or removed: %v", err)
	}
	custody.store.claimCommit = nil
	later, err := NewPrivateReplayFrozen(record.claim, record.plan, keys, fixtureReplayPayload(t, record, keys))
	if err != nil {
		t.Fatal(err)
	}
	laterGrant, err := custody.ReserveSealUse(ctx, later)
	if err != nil || laterGrant.permit == nil {
		t.Fatalf("later valid grant failed: %v", err)
	}
	laterPublication, err := custody.PublishSealedSynthetic(ctx, later, laterGrant)
	if err != nil || laterPublication.descriptor.ref == publication.descriptor.ref {
		t.Fatalf("later publication failed or adopted unclaimed file: %v", err)
	}
	_, laterCreated, err := custody.EstablishSyntheticClaim(ctx, later, laterPublication)
	if err != nil || !laterCreated {
		t.Fatalf("later valid claim failed: created=%t error=%v", laterCreated, err)
	}
	if visible, err := os.ReadFile(unclaimedPath); err != nil || !bytes.Equal(visible, unclaimedBytes) {
		t.Fatalf("earlier unclaimed file changed after later claim: %v", err)
	}
}

func TestReplayClaimC1CommittedResponseLossUsesFreshConnection(t *testing.T) {
	ctx := context.Background()
	record, _ := syntheticReplayRecordFixture(t)
	keys := fixtureReplayKeys(t, 33)
	root := fixtureReplayRoot(t)
	custody, err := OpenPrivateReplayCustody(ctx, root)
	if err != nil {
		t.Fatal(err)
	}
	defer custody.Close()
	custody.store.db.SetMaxOpenConns(1)
	custody.store.db.SetMaxIdleConns(1)
	frozen, err := NewPrivateReplayFrozen(record.claim, record.plan, keys, fixtureReplayPayload(t, record, keys))
	if err != nil {
		t.Fatal(err)
	}
	grant, err := custody.ReserveSealUse(ctx, frozen)
	if err != nil {
		t.Fatal(err)
	}
	publication, err := custody.PublishSealedSynthetic(ctx, frozen, grant)
	if err != nil {
		t.Fatal(err)
	}
	if err := custody.InjectClaimCommitFaultForTesting(PrivateReplayClaimCommitResponseLost); err != nil {
		t.Fatal(err)
	}
	attempt, created, err := custody.EstablishSyntheticClaim(ctx, frozen, publication)
	if !errors.Is(err, errClaimStoreCommitUnknown) || created {
		t.Fatalf("lost COMMIT response reported known success: created=%t error=%v", created, err)
	}
	if stats := custody.store.db.Stats(); stats.Idle != 0 || stats.OpenConnections != 0 {
		t.Fatalf("completed uncertain connection remained pooled: idle=%d open=%d", stats.Idle, stats.OpenConnections)
	}
	independentDB, independentConn := c1IndependentSQLiteConn(t, custody.store.path)
	defer independentDB.Close()
	defer independentConn.Close()
	var committed int
	if err := independentConn.QueryRowContext(ctx, `SELECT COUNT(*) FROM reliable_submit_claims WHERE caller_ref=? AND submit_key_ref=?`,
		opaqueRefBytes(record.claim.caller.ref), opaqueRefBytes(record.claim.submitKey.ref)).Scan(&committed); err != nil || committed != 1 {
		t.Fatalf("completed claim not durable: count=%d error=%v", committed, err)
	}
	held, err := custody.store.db.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	readCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	lookup, err := custody.LoadSyntheticClaim(readCtx, record.claim)
	cancel()
	if err := held.Close(); err != nil {
		t.Fatal(err)
	}
	if err != nil || !lookup.Found() {
		t.Fatalf("completed claim was not classified through fresh connection: found=%t error=%v", lookup.Found(), err)
	}
	called := false
	if err := custody.WithAuthenticatedClaim(ctx, record.claim, keys, func(meta AuthenticatedClaimMeta, plain []byte) error {
		called = true
		if !meta.MatchesAttempt(attempt) || !bytes.Equal(plain, frozen.plaintext) {
			t.Fatal("completed claim lost original attempt association")
		}
		return nil
	}); err != nil || !called {
		t.Fatalf("completed claim was not authenticated: called=%t error=%v", called, err)
	}
}

func TestReplayClaimD1BeginResponseLossQuarantine(t *testing.T) {
	ctx := context.Background()
	record, _ := syntheticReplayRecordFixture(t)
	keys := fixtureReplayKeys(t, 43)
	root := fixtureReplayRoot(t)
	custody, err := OpenPrivateReplayCustody(ctx, root)
	if err != nil {
		t.Fatal(err)
	}
	defer custody.Close()
	custody.store.db.SetMaxOpenConns(1)
	custody.store.db.SetMaxIdleConns(1)
	frozen, err := NewPrivateReplayFrozen(record.claim, record.plan, keys, fixtureReplayPayload(t, record, keys))
	if err != nil {
		t.Fatal(err)
	}
	grant, err := custody.ReserveSealUse(ctx, frozen)
	if err != nil {
		t.Fatal(err)
	}
	publication, err := custody.PublishSealedSynthetic(ctx, frozen, grant)
	if err != nil {
		t.Fatal(err)
	}
	unclaimedPath := filepath.Join(root, filepath.FromSlash(publication.descriptor.ref))
	unclaimedBytes, err := os.ReadFile(unclaimedPath)
	if err != nil {
		t.Fatal(err)
	}
	var executed bool
	var original uintptr
	custody.store.beginImmediateAttempt = d1LostBeginHook(t, &executed, &original)
	attempt, created, err := custody.EstablishSyntheticClaim(ctx, frozen, publication)
	if !executed || original == 0 || err == nil || created || attempt.expected.validate() != nil {
		t.Fatalf("BEGIN response loss was not exercised or authorized a claim: executed=%t created=%t error=%v", executed, created, err)
	}
	independentDB, independentConn := c1IndependentSQLiteConn(t, custody.store.path)
	defer independentDB.Close()
	defer independentConn.Close()
	var durable int
	if err := independentConn.QueryRowContext(ctx, `SELECT COUNT(*) FROM reliable_submit_claims WHERE caller_ref=? AND submit_key_ref=?`,
		opaqueRefBytes(record.claim.caller.ref), opaqueRefBytes(record.claim.submitKey.ref)).Scan(&durable); err != nil || durable != 0 {
		t.Fatalf("failed BEGIN changed durable claim: count=%d error=%v", durable, err)
	}
	if _, err := independentConn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		t.Fatalf("D1 claim writer lock retained after errored BEGIN: %v", err)
	}
	if _, err := independentConn.ExecContext(ctx, "ROLLBACK"); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(err, errClaimStoreUnavailable) {
		t.Fatalf("BEGIN uncertainty did not fail unavailable: %v", err)
	}
	if stats := custody.store.db.Stats(); stats.Idle != 0 || stats.OpenConnections != 0 {
		t.Fatalf("D1 claim connection remained pooled: idle=%d open=%d", stats.Idle, stats.OpenConnections)
	}
	custody.store.beginImmediateAttempt = nil
	conn, err := custody.store.checkedConn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if nextIdentity := d1DriverConnIdentity(t, conn); nextIdentity == original {
		t.Fatal("errored BEGIN driver connection was reused")
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	called := false
	if err := custody.WithAuthenticatedClaim(ctx, record.claim, keys, func(AuthenticatedClaimMeta, []byte) error {
		called = true
		return nil
	}); !errors.Is(err, errClaimStoreNotFound) || called {
		t.Fatalf("unclaimed file gained read authority: called=%t error=%v", called, err)
	}
	if visible, err := os.ReadFile(unclaimedPath); err != nil || !bytes.Equal(visible, unclaimedBytes) {
		t.Fatalf("unclaimed file changed: %v", err)
	}
	later, err := NewPrivateReplayFrozen(record.claim, record.plan, keys, fixtureReplayPayload(t, record, keys))
	if err != nil {
		t.Fatal(err)
	}
	laterGrant, err := custody.ReserveSealUse(ctx, later)
	if err != nil || laterGrant.permit == nil {
		t.Fatalf("later grant failed: %v", err)
	}
	laterPublication, err := custody.PublishSealedSynthetic(ctx, later, laterGrant)
	if err != nil || laterPublication.descriptor.ref == publication.descriptor.ref {
		t.Fatalf("later publication failed or adopted unclaimed file: %v", err)
	}
	_, laterCreated, err := custody.EstablishSyntheticClaim(ctx, later, laterPublication)
	if err != nil || !laterCreated {
		t.Fatalf("later valid claim failed: created=%t error=%v", laterCreated, err)
	}
	if visible, err := os.ReadFile(unclaimedPath); err != nil || !bytes.Equal(visible, unclaimedBytes) {
		t.Fatalf("unclaimed file changed after later claim: %v", err)
	}
}

func TestReplayPublicationFaultAndIdentity(t *testing.T) {
	ctx := context.Background()
	t.Run("successful_publication_and_checked_read", func(t *testing.T) {
		record, _ := syntheticReplayRecordFixture(t)
		keys := fixtureReplayKeys(t, 17)
		root := fixtureReplayRoot(t)
		custody, err := OpenPrivateReplayCustody(ctx, root)
		if err != nil {
			t.Fatal(err)
		}
		defer custody.Close()
		frozen, err := NewPrivateReplayFrozen(record.claim, record.plan, keys, fixtureReplayPayload(t, record, keys))
		if err != nil {
			t.Fatal(err)
		}
		grant, err := custody.ReserveSealUse(ctx, frozen)
		if err != nil {
			t.Fatal(err)
		}
		publication, err := custody.PublishSealedSynthetic(ctx, frozen, grant)
		if err != nil {
			t.Fatal(err)
		}
		if !publication.descriptor.valid() {
			t.Fatal("invalid published descriptor")
		}
		attempt, created, err := custody.EstablishSyntheticClaim(ctx, frozen, publication)
		if err != nil || !created {
			t.Fatalf("establish created=%v error=%v", created, err)
		}
		called := false
		if err := custody.WithAuthenticatedClaim(ctx, record.claim, keys, func(meta AuthenticatedClaimMeta, plaintext []byte) error {
			called = true
			if !meta.MatchesAttempt(attempt) || !bytes.Equal(plaintext, frozen.plaintext) {
				t.Fatal("checked reader mismatch")
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		if !called {
			t.Fatal("admission callback not called")
		}
		object := filepath.Join(root, filepath.FromSlash(publication.descriptor.ref))
		original, err := os.ReadFile(object)
		if err != nil {
			t.Fatal(err)
		}
		_, header, err := parsePrivateReplayHeader(original)
		if err != nil {
			t.Fatal(err)
		}
		const gcmRandomNonceBytes = 12
		nonceStart := len(header)
		nonceEnd := nonceStart + gcmRandomNonceBytes
		if nonceStart != len(frozen.header) || nonceEnd > len(original) {
			t.Fatal("published object nonce bounds invalid")
		}
		originalCopy := append([]byte(nil), original...)
		tampered := append([]byte(nil), original...)
		tampered[nonceStart] ^= 0x01
		if tampered[nonceStart] == original[nonceStart] || len(tampered) != len(original) || !bytes.Equal(original, originalCopy) {
			t.Fatal("nonce mutation did not preserve original object")
		}
		changedAt, changedCount := -1, 0
		for i := range original {
			if original[i] != tampered[i] {
				changedAt = i
				changedCount++
			}
		}
		if changedCount != 1 || changedAt != nonceStart || changedAt >= nonceEnd {
			t.Fatal("nonce mutation changed unexpected bytes")
		}
		file, err := os.OpenFile(object, os.O_RDWR, 0)
		if err != nil {
			t.Fatal(err)
		}
		if n, err := file.WriteAt(tampered[nonceStart:nonceStart+1], int64(nonceStart)); err != nil || n != 1 {
			t.Fatalf("nonce mutation write failed: %v", err)
		}
		if err := file.Sync(); err != nil {
			t.Fatal(err)
		}
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
		onDisk, err := os.ReadFile(object)
		if err != nil {
			t.Fatal(err)
		}
		if len(onDisk) != len(original) || !bytes.Equal(onDisk, tampered) || !bytes.Equal(original, originalCopy) {
			t.Fatal("published object mutation did not match one-byte nonce flip")
		}
		called = false
		if err := custody.WithAuthenticatedClaim(ctx, record.claim, keys, func(AuthenticatedClaimMeta, []byte) error { called = true; return nil }); !errors.Is(err, errReplayFormat) {
			if err == nil {
				t.Fatal("tampered object verified")
			}
			t.Fatalf("tampered object refusal category: %v", err)
		}
		if called {
			t.Fatal("callback saw unauthenticated bytes")
		}
	})
	t.Run("issuing_store_same_store_positive", func(t *testing.T) {
		record, _ := syntheticReplayRecordFixture(t)
		keys := fixtureReplayKeys(t, 24)
		root := fixtureReplayRoot(t)
		custody, err := OpenPrivateReplayCustody(ctx, root)
		if err != nil {
			t.Fatal(err)
		}
		defer custody.Close()
		frozen, err := NewPrivateReplayFrozen(record.claim, record.plan, keys, fixtureReplayPayload(t, record, keys))
		if err != nil {
			t.Fatal(err)
		}
		grant, err := custody.ReserveSealUse(ctx, frozen)
		if err != nil || grant.permit == nil {
			t.Fatalf("same-store reservation: %v", err)
		}
		publication, err := custody.PublishSealedSynthetic(ctx, frozen, grant)
		if err != nil || !publication.descriptor.valid() {
			t.Fatalf("same-store publication: %v", err)
		}
		_, created, err := custody.EstablishSyntheticClaim(ctx, frozen, publication)
		if err != nil || !created {
			t.Fatalf("same-store claim created=%v error=%v", created, err)
		}
		called := false
		if err := custody.WithAuthenticatedClaim(ctx, record.claim, keys, func(_ AuthenticatedClaimMeta, plaintext []byte) error {
			called = true
			if !bytes.Equal(plaintext, frozen.plaintext) {
				t.Fatal("same-store plaintext changed")
			}
			return nil
		}); err != nil || !called {
			t.Fatalf("same-store checked read called=%v error=%v", called, err)
		}
		var count int64
		if err := custody.store.db.QueryRowContext(ctx, `SELECT granted_count FROM reliable_submit_seal_use WHERE envelope_key_id=?`, keys.envelopeID).Scan(&count); err != nil || count != 1 {
			t.Fatalf("same-store grant count=%d error=%v", count, err)
		}
	})
	t.Run("foreign_issuing_store_refused_and_burned", func(t *testing.T) {
		record, _ := syntheticReplayRecordFixture(t)
		keys := fixtureReplayKeys(t, 25)
		frozen, err := NewPrivateReplayFrozen(record.claim, record.plan, keys, fixtureReplayPayload(t, record, keys))
		if err != nil {
			t.Fatal(err)
		}
		rootA, rootB := fixtureReplayRoot(t), fixtureReplayRoot(t)
		if rootA == rootB {
			t.Fatal("synthetic state roots were not independent")
		}
		custodyA, err := OpenPrivateReplayCustody(ctx, rootA)
		if err != nil {
			t.Fatal(err)
		}
		defer custodyA.Close()
		custodyB, err := OpenPrivateReplayCustody(ctx, rootB)
		if err != nil {
			t.Fatal(err)
		}
		defer custodyB.Close()
		if custodyA.store == custodyB.store {
			t.Fatal("synthetic SQLite stores were not independent")
		}
		for i := 0; i < 32; i++ {
			grant, err := custodyB.ReserveSealUse(ctx, frozen)
			if err != nil || grant.permit == nil {
				t.Fatalf("B reservation %d: %v", i+1, err)
			}
			grant.permit.burn() // Capacity is durable and is not refunded.
		}
		assertCount := func(custody *PrivateReplayCustody, want int64) {
			t.Helper()
			var count int64
			if err := custody.store.db.QueryRowContext(ctx, `SELECT granted_count FROM reliable_submit_seal_use WHERE envelope_key_id=?`, keys.envelopeID).Scan(&count); err != nil || count != want {
				t.Fatalf("grant count=%d want=%d error=%v", count, want, err)
			}
			var claims int
			if err := custody.store.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM reliable_submit_claims WHERE codec_version=3`).Scan(&claims); err != nil || claims != 0 {
				t.Fatalf("codec-3 claims=%d error=%v", claims, err)
			}
		}
		assertCount(custodyB, 32)
		grantA, err := custodyA.ReserveSealUse(ctx, frozen)
		if err != nil || grantA.permit == nil {
			t.Fatalf("A reservation: %v", err)
		}
		assertCount(custodyA, 1)
		publication, err := custodyB.PublishSealedSynthetic(ctx, frozen, grantA)
		if !errors.Is(err, errClaimStoreUnavailable) || publication.descriptor.valid() {
			t.Fatalf("foreign permit yielded B publication: %v", err)
		}
		assertCount(custodyB, 32)
		assertCount(custodyA, 1)
		objectDir := filepath.Join(rootB, "objects", "v1")
		entries, err := os.ReadDir(objectDir)
		if err != nil || len(entries) != 0 {
			t.Fatalf("foreign issuer was supposed to refuse before allocation: names=%d error=%v", len(entries), err)
		}
		lookup, err := custodyB.LoadSyntheticClaim(ctx, record.claim)
		if err != nil || lookup.Found() {
			t.Fatalf("foreign permit associated a B claim: %v", err)
		}
		called := false
		if err := custodyB.WithAuthenticatedClaim(ctx, record.claim, keys, func(AuthenticatedClaimMeta, []byte) error {
			called = true
			return nil
		}); err == nil || called {
			t.Fatal("foreign permit reached authenticated callback")
		}
		publication, err = custodyA.PublishSealedSynthetic(ctx, frozen, grantA)
		if !errors.Is(err, errClaimStoreUnavailable) || publication.descriptor.valid() {
			t.Fatalf("foreign attempt did not burn A's permit: %v", err)
		}
		if nextB, err := custodyB.ReserveSealUse(ctx, frozen); nextB.permit != nil || !errors.Is(err, errClaimStoreUnsupported) {
			t.Fatalf("B exhausted budget issued a fresh permit: %v", err)
		}
		assertCount(custodyB, 32)
		assertCount(custodyA, 1)
	})
	for _, scenario := range []struct {
		name       string
		fault      replayPublicationFault
		wantSize   int64
		wantReopen int
	}{
		{"short_write_then_failure", replayPublicationWriteShortThenFail, 1, 0},
		{"failed_write", replayPublicationWriteFail, 0, 0},
		{"readback_mismatch", replayPublicationReadbackMismatch, -1, 0},
		{"readback_failure", replayPublicationReadbackFail, -1, 0},
		{"file_fsync_failure", replayPublicationFileSyncFail, -1, 0},
		{"parent_fsync_failure", replayPublicationParentSyncFail, -1, 0},
		{"final_close_failure_once", replayPublicationFinalCloseFail, -1, 0},
		{"reopen_failure", replayPublicationReopenFail, -1, 1},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			record, _ := syntheticReplayRecordFixture(t)
			keys := fixtureReplayKeys(t, 21)
			root := fixtureReplayRoot(t)
			custody, err := OpenPrivateReplayCustody(ctx, root)
			if err != nil {
				t.Fatal(err)
			}
			defer custody.Close()
			frozen, err := NewPrivateReplayFrozen(record.claim, record.plan, keys, fixtureReplayPayload(t, record, keys))
			if err != nil {
				t.Fatal(err)
			}
			grant, err := custody.ReserveSealUse(ctx, frozen)
			if err != nil {
				t.Fatal(err)
			}
			custody.testPublicationFault = scenario.fault
			publication, err := custody.PublishSealedSynthetic(ctx, frozen, grant)
			if !errors.Is(err, errClaimStoreUnavailable) || publication.descriptor.valid() {
				t.Fatalf("fault yielded publication: %v", err)
			}
			if custody.testPublicationCloseAttempts != 1 || custody.testPublicationReopenAttempts != scenario.wantReopen {
				t.Fatalf("close/reopen attempts=%d/%d", custody.testPublicationCloseAttempts, custody.testPublicationReopenAttempts)
			}
			if scenario.wantSize >= 0 {
				info, err := os.Stat(filepath.Join(root, filepath.FromSlash(replayObjectRef(frozen.objectID))))
				if err != nil || info.Size() != scenario.wantSize {
					t.Fatalf("partial publication size: %v", err)
				}
			}
			lookup, err := custody.LoadSyntheticClaim(ctx, record.claim)
			if err != nil || lookup.Found() {
				t.Fatalf("fault associated a claim: %v", err)
			}
			var claims int
			if err := custody.store.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM reliable_submit_claims WHERE codec_version=3`).Scan(&claims); err != nil || claims != 0 {
				t.Fatalf("fault claim count=%d error=%v", claims, err)
			}
			called := false
			if err := custody.WithAuthenticatedClaim(ctx, record.claim, keys, func(AuthenticatedClaimMeta, []byte) error { called = true; return nil }); err == nil || called {
				t.Fatal("fault reached authenticated callback")
			}
		})
	}
}

func TestReplayCustodyAEADAndSwapRefusal(t *testing.T) {
	ctx := context.Background()
	t.Run("committed_positive_and_visible_replacement_refusal", func(t *testing.T) {
		record, _ := syntheticReplayRecordFixture(t)
		keys := fixtureReplayKeys(t, 18)
		root := fixtureReplayRoot(t)
		custody, err := OpenPrivateReplayCustody(ctx, root)
		if err != nil {
			t.Fatal(err)
		}
		defer custody.Close()
		frozen, err := NewPrivateReplayFrozen(record.claim, record.plan, keys, fixtureReplayPayload(t, record, keys))
		if err != nil {
			t.Fatal(err)
		}
		grant, err := custody.ReserveSealUse(ctx, frozen)
		if err != nil {
			t.Fatal(err)
		}
		publication, err := custody.PublishSealedSynthetic(ctx, frozen, grant)
		if err != nil {
			t.Fatal(err)
		}
		_, created, err := custody.EstablishSyntheticClaim(ctx, frozen, publication)
		if err != nil || !created {
			t.Fatalf("establish: %v", err)
		}
		if _, err := custody.PublishSealedSynthetic(ctx, frozen, grant); !errors.Is(err, errClaimStoreUnavailable) {
			t.Fatalf("reused permit: %v", err)
		}
		object := filepath.Join(root, filepath.FromSlash(publication.descriptor.ref))
		replacement := filepath.Join(root, "objects", "v1", "replacement")
		if err := os.Rename(object, replacement); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(object, []byte("forged"), 0o600); err != nil {
			t.Fatal(err)
		}
		called := false
		if err := custody.WithAuthenticatedClaim(ctx, record.claim, keys, func(AuthenticatedClaimMeta, []byte) error { called = true; return nil }); err == nil || called {
			t.Fatal("replacement reached authenticated callback")
		}
	})
	// These prospective bytes have no file or claim. Adjusting only the outer
	// SHA after a mutation proves the AEAD or association check itself refuses.
	record, _ := syntheticReplayRecordFixture(t)
	keys := fixtureReplayKeys(t, 22)
	frozen, sealed, descriptor := unclaimedReplaySealedFixture(t, record, keys)
	t.Run("unclaimed_exact_positive_control", func(t *testing.T) {
		plain, err := verifyReplayFileBytes(sealed, record.claim, record.plan, keys, descriptor)
		if err != nil || !bytes.Equal(plain, frozen.plaintext) {
			t.Fatalf("prospective authenticated bytes refused: %v", err)
		}
	})
	for _, scenario := range []struct {
		name   string
		offset int
	}{
		{"nonce_mutation", len(frozen.header)},
		{"ciphertext_mutation", len(frozen.header) + 12},
		{"tag_mutation", len(sealed) - 1},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			changed := append([]byte(nil), sealed...)
			changed[scenario.offset] ^= 0x80
			modified := descriptor
			modified.fileSHA = sha256.Sum256(changed)
			if _, err := verifyReplayFileBytes(changed, record.claim, record.plan, keys, modified); !errors.Is(err, errClaimStoreUnavailable) {
				t.Fatalf("mutated AEAD component did not reach authenticated refusal: %v", err)
			}
		})
	}
	t.Run("authenticated_header_aad_mutation", func(t *testing.T) {
		changed := append([]byte(nil), sealed...)
		fields, _, err := parsePrivateReplayHeader(changed)
		if err != nil {
			t.Fatal(err)
		}
		fields[10].value[0] ^= 0x80 // field 11 is the intent commitment in AAD
		modified := descriptor
		copy(modified.intentMAC[:], fields[10].value)
		modified.fileSHA = sha256.Sum256(changed)
		if _, err := verifyReplayFileBytes(changed, record.claim, record.plan, keys, modified); !errors.Is(err, errClaimStoreUnavailable) {
			t.Fatalf("changed AAD was refused before AEAD: %v", err)
		}
	})
	t.Run("wrong_envelope_key", func(t *testing.T) {
		wrong, err := NewPrivateReplayKeys(keys.bindingID, keys.binding[:], keys.envelopeID, bytes.Repeat([]byte{0xd7}, 32))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := verifyReplayFileBytes(sealed, record.claim, record.plan, wrong, descriptor); !errors.Is(err, errClaimStoreUnavailable) {
			t.Fatalf("wrong envelope key reached plaintext: %v", err)
		}
	})
	t.Run("wrong_caller_claim_association", func(t *testing.T) {
		caller, err := NewCallerRef(bytes.Repeat([]byte{0x66}, 32))
		if err != nil {
			t.Fatal(err)
		}
		other, err := NewClaimID(caller, record.claim.submitKey)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := verifyReplayFileBytes(sealed, other, record.plan, keys, descriptor); !errors.Is(err, errReplayFormat) {
			t.Fatalf("wrong caller claim reached plaintext: %v", err)
		}
	})
}

func TestReplayCustodyAssociationCopies(t *testing.T) {
	record, _ := syntheticReplayRecordFixture(t)
	keys := fixtureReplayKeys(t, 19)
	plain := fixtureReplayPayload(t, record, keys)
	frozen, err := NewPrivateReplayFrozen(record.claim, record.plan, keys, plain)
	if err != nil {
		t.Fatal(err)
	}
	want := append([]byte(nil), frozen.plaintext...)
	plain[15] ^= 0xff
	if !bytes.Equal(frozen.plaintext, want) || !frozen.valid() {
		t.Fatal("frozen payload borrowed caller storage")
	}
	changed := frozen
	changed.header = append([]byte(nil), frozen.header...)
	changed.header[len(changed.header)-1] ^= 1
	if changed.valid() {
		t.Fatal("changed header retained association")
	}
	changed = frozen
	changed.plaintext = append([]byte(nil), frozen.plaintext...)
	changed.plaintext[len(changed.plaintext)-1] ^= 1
	if changed.valid() {
		t.Fatal("changed plaintext retained association")
	}
}

func TestReplayVisibleParentReplacementRefused(t *testing.T) {
	ctx := context.Background()
	root := fixtureReplayRoot(t)
	custody, err := OpenPrivateReplayCustody(ctx, root)
	if err != nil {
		t.Fatal(err)
	}
	defer custody.Close()
	parent := filepath.Join(root, "objects", "v1")
	if err := os.Rename(parent, parent+"-detached"); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	record, _ := syntheticReplayRecordFixture(t)
	keys := fixtureReplayKeys(t, 20)
	frozen, err := NewPrivateReplayFrozen(record.claim, record.plan, keys, fixtureReplayPayload(t, record, keys))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := custody.ReserveSealUse(ctx, frozen); err == nil {
		t.Fatal("detached parent received grant")
	}
	if _, err := custody.LoadSyntheticClaim(ctx, record.claim); err == nil {
		t.Fatal("detached parent allowed lookup")
	}
}

func TestReplayExistingStateModeNotRepaired(t *testing.T) {
	for _, special := range []uint16{0o1000, 0o2000, 0o4000} {
		dir := unix.Stat_t{Uid: uint32(os.Getuid()), Gid: uint32(os.Getgid())}
		dir.Mode = probeMode(dir.Mode, uint32(unix.S_IFDIR)|0o700|uint32(special))
		if replayDirectoryQualified(dir) {
			t.Fatal("special directory mode accepted")
		}
		file := unix.Stat_t{Uid: uint32(os.Getuid()), Gid: uint32(os.Getgid()), Nlink: 1}
		file.Mode = probeMode(file.Mode, uint32(unix.S_IFREG)|0o600|uint32(special))
		if replayFileQualified(file) {
			t.Fatal("special file mode accepted")
		}
	}
	root := fixtureReplayRoot(t)
	path := filepath.Join(root, "reliable-submit.sqlite3")
	if err := os.WriteFile(path, []byte("synthetic wrong-mode state"), 0o640); err != nil {
		t.Fatal(err)
	}
	if custody, err := OpenPrivateReplayCustody(context.Background(), root); err == nil {
		_ = custody.Close()
		t.Fatal("wrong-mode state adopted")
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o640 {
		t.Fatal("existing state mode was repaired")
	}
}

// Each case runs in a child test process because the original blocking open
// cannot be interrupted by canceling a Go context. The parent owns the bound.
func TestReplayObjectFIFORefusal(t *testing.T) {
	const childScenario = "ES_PR8_REPLAY_FIFO_CHILD_SCENARIO"
	if scenario := os.Getenv(childScenario); scenario != "" {
		runReplayObjectFIFOChild(t, scenario)
		return
	}
	for _, scenario := range []string{"marker", "preclaim", "claimed"} {
		t.Run(scenario, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestReplayObjectFIFORefusal$", "-test.v")
			cmd.Env = append(os.Environ(), childScenario+"="+scenario)
			output, err := cmd.CombinedOutput()
			ready := []byte("PR8_FIFO_READY " + scenario + "\n")
			done := []byte("PR8_FIFO_DONE " + scenario + "\n")
			if !bytes.Contains(output, ready) {
				t.Fatalf("FIFO helper did not reach the guarded open: error=%v output_sha256=%x", err, sha256.Sum256(output))
			}
			if ctx.Err() != nil {
				t.Fatalf("FIFO helper blocked after readiness: scenario=%s deadline=%v", scenario, ctx.Err())
			}
			if err != nil || !bytes.Contains(output, done) {
				t.Fatalf("FIFO helper failed after readiness: error=%v output_sha256=%x", err, sha256.Sum256(output))
			}
		})
	}
}

func runReplayObjectFIFOChild(t *testing.T, scenario string) {
	t.Helper()
	ctx := context.Background()
	if scenario == "marker" {
		root := fixtureReplayRoot(t)
		marker := filepath.Join(root, "synthetic-replay-v1.marker")
		if err := os.Remove(marker); err != nil {
			t.Fatal(err)
		}
		makeReplayFIFO(t, marker)
		fmt.Printf("PR8_FIFO_READY %s\n", scenario)
		custody, err := OpenPrivateReplayCustody(ctx, root)
		if custody != nil {
			_ = custody.Close()
			t.Fatal("FIFO marker returned custody")
		}
		if !errors.Is(err, errClaimStoreUnsupported) {
			t.Fatalf("FIFO marker refusal category: %v", err)
		}
		fmt.Printf("PR8_FIFO_DONE %s\n", scenario)
		return
	}
	if scenario != "preclaim" && scenario != "claimed" {
		t.Fatalf("unknown FIFO scenario %q", scenario)
	}
	record, _ := syntheticReplayRecordFixture(t)
	keys := fixtureReplayKeys(t, 29)
	root := fixtureReplayRoot(t)
	custody, err := OpenPrivateReplayCustody(ctx, root)
	if err != nil {
		t.Fatal(err)
	}
	defer custody.Close()
	frozen, err := NewPrivateReplayFrozen(record.claim, record.plan, keys, fixtureReplayPayload(t, record, keys))
	if err != nil {
		t.Fatal(err)
	}
	grant, err := custody.ReserveSealUse(ctx, frozen)
	if err != nil {
		t.Fatal(err)
	}
	publication, err := custody.PublishSealedSynthetic(ctx, frozen, grant)
	if err != nil || !publication.descriptor.valid() {
		t.Fatalf("valid publication failed: %v", err)
	}
	if scenario == "claimed" {
		_, created, err := custody.EstablishSyntheticClaim(ctx, frozen, publication)
		if err != nil || !created {
			t.Fatalf("valid claim created=%v error=%v", created, err)
		}
		called := false
		if err := custody.WithAuthenticatedClaim(ctx, record.claim, keys, func(AuthenticatedClaimMeta, []byte) error {
			called = true
			return nil
		}); err != nil || !called {
			t.Fatalf("valid pre-replacement read called=%v error=%v", called, err)
		}
	}
	object := filepath.Join(root, filepath.FromSlash(publication.descriptor.ref))
	if err := os.Rename(object, object+".original"); err != nil {
		t.Fatal(err)
	}
	makeReplayFIFO(t, object)
	fmt.Printf("PR8_FIFO_READY %s\n", scenario)
	if scenario == "preclaim" {
		_, created, err := custody.EstablishSyntheticClaim(ctx, frozen, publication)
		if created || !errors.Is(err, errClaimStoreUnavailable) {
			t.Fatalf("FIFO preclaim created=%v error=%v", created, err)
		}
		var count int64
		if err := custody.store.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM reliable_submit_claims WHERE codec_version=3`).Scan(&count); err != nil || count != 0 {
			t.Fatalf("FIFO preclaim row count=%d error=%v", count, err)
		}
		called := false
		if err := custody.WithAuthenticatedClaim(ctx, record.claim, keys, func(AuthenticatedClaimMeta, []byte) error {
			called = true
			return nil
		}); !errors.Is(err, errClaimStoreNotFound) || called {
			t.Fatalf("FIFO preclaim callback=%v error=%v", called, err)
		}
	} else {
		called := false
		if err := custody.WithAuthenticatedClaim(ctx, record.claim, keys, func(AuthenticatedClaimMeta, []byte) error {
			called = true
			return nil
		}); !errors.Is(err, errClaimStoreUnavailable) || called {
			t.Fatalf("FIFO claimed callback=%v error=%v", called, err)
		}
		var count int64
		if err := custody.store.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM reliable_submit_claims WHERE codec_version=3`).Scan(&count); err != nil || count != 1 {
			t.Fatalf("FIFO claimed row count=%d error=%v", count, err)
		}
	}
	fmt.Printf("PR8_FIFO_DONE %s\n", scenario)
}

func makeReplayFIFO(t *testing.T, path string) {
	t.Helper()
	if err := unix.Mkfifo(path, 0o600); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeNamedPipe == 0 || info.Mode().Perm() != 0o600 {
		t.Fatalf("FIFO fixture did not qualify: %v", err)
	}
}

func TestReplayReadOnlyCandidateOpenContract(t *testing.T) {
	const directChild = "ES_PR8_REPLAY_FIFO_DIRECT_CHILD"
	if os.Getenv(directChild) == "1" {
		root := t.TempDir()
		makeReplayFIFO(t, filepath.Join(root, "fifo"))
		rootFD, err := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			t.Fatal(err)
		}
		defer unix.Close(rootFD)
		fmt.Println("PR8_DIRECT_READY")
		fd, err := openReplayReadOnlyCandidate(rootFD, "fifo")
		if err != nil {
			t.Fatalf("nonblocking FIFO open failed: %v", err)
		}
		var held unix.Stat_t
		statErr := unix.Fstat(fd, &held)
		closeErr := unix.Close(fd)
		if statErr != nil || closeErr != nil || replayFileQualified(held) {
			t.Fatalf("FIFO descriptor was accepted or not closed: stat=%v close=%v", statErr, closeErr)
		}
		fmt.Println("PR8_DIRECT_DONE")
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestReplayReadOnlyCandidateOpenContract$", "-test.v")
	cmd.Env = append(os.Environ(), directChild+"=1")
	output, err := cmd.CombinedOutput()
	if !bytes.Contains(output, []byte("PR8_DIRECT_READY\n")) {
		t.Fatalf("direct FIFO helper did not reach open: error=%v output_sha256=%x", err, sha256.Sum256(output))
	}
	if ctx.Err() != nil {
		t.Fatalf("direct FIFO helper blocked after readiness: %v", ctx.Err())
	}
	if err != nil || !bytes.Contains(output, []byte("PR8_DIRECT_DONE\n")) {
		t.Fatalf("direct FIFO helper failed: error=%v output_sha256=%x", err, sha256.Sum256(output))
	}

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "replay_custody_file.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	functions := make(map[string]*ast.FuncDecl)
	for _, declaration := range file.Decls {
		if fn, ok := declaration.(*ast.FuncDecl); ok {
			functions[fn.Name.Name] = fn
		}
	}
	nodeText := func(node ast.Node) string {
		var rendered bytes.Buffer
		if err := format.Node(&rendered, fset, node); err != nil {
			t.Fatal(err)
		}
		return strings.Join(strings.Fields(rendered.String()), "")
	}
	helper := functions["openReplayReadOnlyCandidate"]
	if helper == nil || nodeText(helper) != strings.Join(strings.Fields(`
		func openReplayReadOnlyCandidate(dirFD int, name string) (int, error) {
			return unix.Openat(dirFD, name, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		}`), "") {
		t.Fatal("read-only candidate helper flags or body changed")
	}
	expected := []struct {
		name   string
		helper []string
		direct []string
	}{
		{"OpenPrivateReplayCustody", nil, nil},
		{"openReplayCustody", []string{`openReplayReadOnlyCandidate(rootFD,"synthetic-replay-v1.marker")`}, []string{
			`unix.Openat(rootFD,"objects",unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC,0)`,
			`unix.Openat(objectsFD,"v1",unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC,0)`,
		}},
		{"PublishSealedSynthetic", nil, nil},
		{"PublishProgressOriginal", nil, nil},
		{"publishReplayOriginal", []string{`openReplayReadOnlyCandidate(c.parentFD,visibleName)`}, nil},
		{"allocateReplayObject", nil, []string{
			`unix.Openat(c.parentFD,name,unix.O_CREAT|unix.O_EXCL|unix.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC,0o600)`,
		}},
		{"checkPublishedRef", []string{
			`openReplayReadOnlyCandidate(c.parentFD,basename)`,
			`openReplayReadOnlyCandidate(c.parentFD,basename)`,
		}, nil},
	}
	for _, want := range expected {
		fn := functions[want.name]
		if fn == nil {
			t.Fatalf("missing custody function %s", want.name)
		}
		var helperCalls, directCalls []string
		ast.Inspect(fn.Body, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			switch nodeText(call.Fun) {
			case "openReplayReadOnlyCandidate":
				helperCalls = append(helperCalls, nodeText(call))
			case "unix.Openat":
				directCalls = append(directCalls, nodeText(call))
			}
			return true
		})
		if !slices.Equal(helperCalls, want.helper) || !slices.Equal(directCalls, want.direct) {
			t.Fatalf("custody open inventory changed in %s: helper=%v direct=%v", want.name, helperCalls, directCalls)
		}
	}
}

func allocatorFrozenFixture(t *testing.T, scope byte) PrivateReplayFrozen {
	t.Helper()
	record, _ := syntheticReplayRecordFixture(t)
	keys := fixtureReplayKeys(t, 17)
	format, _ := replayFormatForScope(int64(scope))
	raw := fixtureReplayPayload(t, record, keys)
	if scope == 2 {
		raw = progressFixturePayload(t, record, keys)
	}
	frozen, err := freezeReplayOriginal(format, record.claim, record.plan, keys, raw)
	if err != nil {
		t.Fatal(err)
	}
	return frozen
}

func allocatorPublisher(t *testing.T, ctx context.Context, c *PrivateReplayCustody, scope byte) func() error {
	t.Helper()
	frozen := allocatorFrozenFixture(t, scope)
	var publish func() (PrivateReplayPublication, error)
	if scope == 1 {
		permit, err := c.ReserveSealUse(ctx, frozen)
		if err != nil {
			t.Fatal(err)
		}
		publish = func() (PrivateReplayPublication, error) { return c.PublishSealedSynthetic(ctx, frozen, permit) }
	} else {
		progress := &PrivateReplayProgressCustody{custody: c}
		progress.self = progress
		l, err := progress.LookupProgressOriginal(ctx, frozen.claim)
		if err != nil || !l.Absent() {
			t.Fatalf("scope-2 allocator fixture lookup: %v", err)
		}
		input, err := NewProgressOriginalInput(frozen.plaintext)
		if err != nil {
			t.Fatal(err)
		}
		f, err := progress.FreezeProgressOriginal(ctx, l, FixturePendingBeforeAssignment, frozen.plan, frozen.keys, input)
		if err != nil {
			t.Fatal(err)
		}
		frozen = f.frozen
		permit, err := progress.ReserveProgressSealUse(ctx, f)
		if err != nil {
			t.Fatal(err)
		}
		publish = func() (PrivateReplayPublication, error) {
			p, err := progress.PublishProgressOriginal(ctx, f, permit)
			return p.sealed, err
		}
	}
	return func() error {
		p, err := publish()
		if err == nil {
			if _, err := c.checkPublishedRef(ctx, frozen.claim, frozen.plan, frozen.keys, p.descriptor); err != nil {
				return fmt.Errorf("publication verification: %w", err)
			}
			if p.descriptor.scope != int64(scope) {
				t.Error("publication scope differs from selected wire")
			}
		}
		return err
	}
}

func TestPrivateReplaySharedObjectAllocation(t *testing.T) {
	for _, tc := range []struct {
		name    string
		process bool
	}{
		{"CrossSelectorFinalSlotTwoHandles", false},
		{"CrossSelectorFinalSlotHelperProcess", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, stop := context.WithTimeout(context.Background(), 15*time.Second)
			defer stop()
			root := fixtureReplayRoot(t)
			for i := 0; i < 31; i++ {
				path := filepath.Join(root, "objects", "v1", fmt.Sprintf("inert-%d", i))
				if err := os.WriteFile(path, nil, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			a, err := OpenPrivateReplayCustody(ctx, root)
			if err != nil {
				t.Fatal(err)
			}
			defer a.Close()
			first := allocatorPublisher(t, ctx, a, 1)
			outcomes := make(chan error, 2)
			if tc.process {
				program, err := os.Executable()
				if err != nil {
					t.Fatal(err)
				}
				cmd := exec.CommandContext(ctx, program, "-test.run=^TestPrivateReplayObjectAllocatorHelperProcess$", "-test.v")
				cmd.Env = append(os.Environ(), "ES_SHARED_ALLOCATOR_FIXTURE="+root)
				childIn, err := cmd.StdinPipe()
				if err != nil {
					t.Fatal(err)
				}
				childOut, err := cmd.StdoutPipe()
				if err != nil {
					t.Fatal(err)
				}
				if err := cmd.Start(); err != nil {
					t.Fatal(err)
				}
				scanner := bufio.NewScanner(childOut)
				ready := false
				for scanner.Scan() {
					if scanner.Text() == "SHARED_ALLOCATOR_READY" {
						ready = true
						break
					}
				}
				if !ready {
					_ = childIn.Close()
					_ = cmd.Wait()
					t.Fatal("independent publisher did not reach the contention barrier")
				}
				go func() { outcomes <- first() }()
				_, writeErr := fmt.Fprintln(childIn, "go")
				_ = childIn.Close()
				found := ""
				for scanner.Scan() {
					switch scanner.Text() {
					case "SHARED_ALLOCATOR_WON", "SHARED_ALLOCATOR_FULL":
						found = scanner.Text()
					}
				}
				if err := cmd.Wait(); err != nil || writeErr != nil || scanner.Err() != nil || found == "" {
					t.Fatalf("independent allocator result: witness=%q process=%v barrier=%v", found, err, writeErr)
				}
				t.Log("independent process reached SHARED_ALLOCATOR_READY and " + found)
				if found == "SHARED_ALLOCATOR_FULL" {
					outcomes <- errClaimStoreUnsupported
				} else {
					outcomes <- nil
				}
			} else {
				b, err := OpenPrivateReplayCustody(ctx, root)
				if err != nil {
					t.Fatal(err)
				}
				defer b.Close()
				second := allocatorPublisher(t, ctx, b, 2)
				gate := make(chan struct{})
				for _, publish := range []func() error{first, second} {
					go func() { <-gate; outcomes <- publish() }()
				}
				close(gate)
			}
			var won, full int
			for i := 0; i < 2; i++ {
				err := <-outcomes
				switch {
				case err == nil:
					won++
				case errors.Is(err, errClaimStoreUnsupported):
					full++
				default:
					t.Errorf("shared publication: %v", err)
				}
			}
			files, err := os.ReadDir(filepath.Join(root, "objects", "v1"))
			if err != nil || won != 1 || full != 1 || len(files) != 32 {
				t.Fatalf("shared bound won=%d refused=%d names=%d: %v", won, full, len(files), err)
			}
			var reserved, claims int
			if err := a.store.db.QueryRow("SELECT sum(granted_count) FROM reliable_submit_seal_use").Scan(&reserved); err != nil || reserved != 2 {
				t.Fatalf("durable reservations changed: %d, %v", reserved, err)
			}
			if err := a.store.db.QueryRow("SELECT count(*) FROM reliable_submit_claims").Scan(&claims); err != nil || claims != 0 {
				t.Fatalf("publication made a claim: %d, %v", claims, err)
			}
		})
	}
	for _, fault := range []string{"CancelAfterExclusiveCreate", "AmbiguousBegin", "AmbiguousRollbackAfterExclusiveCreate", "ExpiredRollbackNilResponse", "DiscardRescue", "DoubleDiscardWithholds"} {
		t.Run(fault, func(t *testing.T) {
			ctx, stop := context.WithTimeout(context.Background(), 15*time.Second)
			defer stop()
			root := fixtureReplayRoot(t)
			c, err := OpenPrivateReplayCustody(ctx, root)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			frozen := allocatorFrozenFixture(t, 1)
			grant, err := c.ReserveSealUse(ctx, frozen)
			if err != nil {
				t.Fatal(err)
			}
			injected := errors.New("modeled allocator response failure")
			createFD := -1
			var original uintptr
			var calls, rescue, release int
			expired := false
			c.allocatorTest = &replayAllocatorTestHooks{
				begin: func(ctx context.Context, conn *sql.Conn) error {
					original = d1DriverConnIdentity(t, conn)
					if _, err := conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
						return err
					}
					if fault == "AmbiguousBegin" {
						return injected
					}
					return nil
				},
				afterCreate: func(fd int) {
					createFD = fd
					if fault == "CancelAfterExclusiveCreate" {
						stop()
					}
				},
				rollback: func(ctx context.Context, conn *sql.Conn) error {
					if ctx.Err() != nil {
						t.Error("rollback inherited cancellation")
					}
					if fault == "AmbiguousRollbackAfterExclusiveCreate" || fault == "DiscardRescue" || fault == "DoubleDiscardWithholds" {
						return injected
					}
					if fault == "ExpiredRollbackNilResponse" {
						<-ctx.Done()
						expired = errors.Is(ctx.Err(), context.DeadlineExceeded)
						ctx = context.Background()
					}
					_, err := conn.ExecContext(ctx, "ROLLBACK")
					return err
				},
				firstDiscard: func(conn *sql.Conn) error {
					calls++
					if d1DriverConnIdentity(t, conn) != original {
						t.Error("discard driver mismatch")
					}
					if fault == "DiscardRescue" || fault == "DoubleDiscardWithholds" {
						return injected
					}
					return discardUncertainSQLiteConn(conn)
				},
				rescueResponse: func(err error) error {
					rescue++
					if err != nil {
						t.Error(err)
					}
					if fault == "DoubleDiscardWithholds" {
						return injected
					}
					return err
				},
				beforePoolReturn: func() { release++ },
			}
			p, err := c.PublishSealedSynthetic(ctx, frozen, grant)
			c.allocatorTest = nil
			if !errors.Is(err, errClaimStoreUnavailable) || p.descriptor.ref != "" || !grant.permit.used {
				t.Fatalf("failed allocation returned authority: %v", err)
			}
			name := filepath.Join(root, replayObjectRef(frozen.objectID))
			info, err := os.Lstat(name)
			if fault == "AmbiguousBegin" {
				if !errors.Is(err, os.ErrNotExist) || createFD != -1 {
					t.Error("uncertain BEGIN reached create")
				}
			} else {
				if err != nil || info.Size() != 0 || info.Mode().Perm() != 0o600 {
					t.Fatalf("expected retained empty object: %v", err)
				}
				var closed unix.Stat_t
				if !errors.Is(unix.Fstat(createFD, &closed), unix.EBADF) {
					t.Error("owned allocation descriptor was not closed")
				}
			}
			if fault == "ExpiredRollbackNilResponse" && !expired {
				t.Error("did not observe real deadline")
			}
			wantDiscard := 1
			if fault == "CancelAfterExclusiveCreate" {
				wantDiscard = 0
			}
			wantRescue := 0
			if fault == "DiscardRescue" || fault == "DoubleDiscardWithholds" {
				wantRescue = 1
			}
			wantRelease := 1
			if fault == "DoubleDiscardWithholds" {
				wantRelease = 0
			}
			if calls != wantDiscard || rescue != wantRescue || release != wantRelease {
				t.Errorf("discard/rescue/release %d/%d/%d", calls, rescue, release)
			}
			if fault != "DoubleDiscardWithholds" {
				assertLegacyCASIndependentWriter(t, c.store.path)
				var reserved, claims int
				err := c.store.db.QueryRow("SELECT sum(granted_count), (SELECT count(*) FROM reliable_submit_claims) FROM reliable_submit_seal_use").Scan(&reserved, &claims)
				if err != nil || reserved != 1 || claims != 0 {
					t.Fatalf("failed allocation durable state %d/%d: %v", reserved, claims, err)
				}
			}
		})
	}
	t.Run("NormalPublishersVerify", func(t *testing.T) {
		ctx, stop := context.WithCancel(context.Background())
		defer stop()
		c, err := OpenPrivateReplayCustody(ctx, fixtureReplayRoot(t))
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		for _, scope := range []byte{1, 2} {
			if err := allocatorPublisher(t, ctx, c, scope)(); err != nil {
				t.Fatalf("scope %d: %v", scope, err)
			}
		}
	})
}

func TestPrivateReplayObjectAllocatorHelperProcess(t *testing.T) {
	root := os.Getenv("ES_SHARED_ALLOCATOR_FIXTURE")
	if root == "" {
		t.Skip("allocator helper control, executed by TestPrivateReplaySharedObjectAllocation")
	}
	ctx, stop := context.WithTimeout(context.Background(), 12*time.Second)
	defer stop()
	c, err := OpenPrivateReplayCustody(ctx, root)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	publish := allocatorPublisher(t, ctx, c, 2)
	fmt.Println("SHARED_ALLOCATOR_READY")
	if line, err := bufio.NewReader(os.Stdin).ReadString('\n'); err != nil || line != "go\n" {
		t.Fatal("missing parent barrier")
	}
	switch err := publish(); {
	case err == nil:
		fmt.Println("SHARED_ALLOCATOR_WON")
	case errors.Is(err, errClaimStoreUnsupported):
		fmt.Println("SHARED_ALLOCATOR_FULL")
	default:
		t.Fatal(err)
	}
}

func TestPrivateReplayScope1PublicationPreflight(t *testing.T) {
	for _, path := range []string{"ClosedCustody", "InvalidFrozen", "NoPermit", "WrongScope", "QualifiedForeignIssuer", "AllocationCollision"} {
		t.Run(path, func(t *testing.T) {
			ctx := context.Background()
			record, _ := syntheticReplayRecordFixture(t)
			keys := fixtureReplayKeys(t, 25)
			frozen, err := NewPrivateReplayFrozen(record.claim, record.plan, keys, fixtureReplayPayload(t, record, keys))
			if err != nil {
				t.Fatal(err)
			}
			root := fixtureReplayRoot(t)
			issuer, err := OpenPrivateReplayCustody(ctx, root)
			if err != nil {
				t.Fatal(err)
			}
			defer issuer.Close()
			grant, err := issuer.ReserveSealUse(ctx, frozen)
			if err != nil {
				t.Fatal(err)
			}
			caller, supplied, permit := issuer, frozen, grant
			callerRoot := root
			var orphan string
			switch path {
			case "ClosedCustody", "QualifiedForeignIssuer":
				callerRoot = fixtureReplayRoot(t)
				caller, err = OpenPrivateReplayCustody(ctx, callerRoot)
				if err != nil {
					t.Fatal(err)
				}
				defer caller.Close()
				if path == "ClosedCustody" {
					if err := caller.Close(); err != nil {
						t.Fatal(err)
					}
				}
			case "InvalidFrozen":
				supplied.digest[0] ^= 1
			case "NoPermit":
				permit = PrivateReplaySealPermit{}
			case "WrongScope":
				supplied.format = progressReplayFormat
			case "AllocationCollision":
				orphan = filepath.Join(root, replayObjectRef(frozen.objectID))
				if err := os.WriteFile(orphan, []byte("retained"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			rejected, err := caller.PublishSealedSynthetic(ctx, supplied, permit)
			if err == nil || rejected.descriptor.valid() {
				t.Fatal("ineligible publication reached Seal or returned a descriptor")
			}
			names, err := os.ReadDir(filepath.Join(callerRoot, "objects", "v1"))
			wantNames := 0
			if orphan != "" {
				wantNames = 1
				if contents, err := os.ReadFile(orphan); err != nil || string(contents) != "retained" {
					t.Fatal("allocation collision adopted or rewrote an existing object")
				}
			}
			if err != nil || len(names) != wantNames {
				t.Fatalf("refused publication allocated a name: %d %v", len(names), err)
			}
			burned := path == "QualifiedForeignIssuer" || path == "AllocationCollision"
			if grant.permit.used != burned {
				t.Errorf("refusal permit burn=%t want %t", grant.permit.used, burned)
			}
			publication, err := issuer.PublishSealedSynthetic(ctx, frozen, grant)
			if burned {
				if err == nil || publication.descriptor.valid() {
					t.Fatal("qualified failure refunded its permit")
				}
			} else if err != nil || !publication.descriptor.valid() {
				t.Errorf("issuer lost its eligible first publication: %v", err)
			} else if again, err := issuer.PublishSealedSynthetic(ctx, frozen, grant); err == nil || again.descriptor.valid() {
				t.Fatal("a consumed permit published twice")
			}
			var reserved int
			if err := issuer.store.db.QueryRow("SELECT sum(granted_count) FROM reliable_submit_seal_use").Scan(&reserved); err != nil || reserved != 1 {
				t.Fatalf("permit trial altered durable reservations: %d %v", reserved, err)
			}
		})
	}
}

func probeMode[T ~uint16 | ~uint32](_ T, v uint32) T { return T(v) }
