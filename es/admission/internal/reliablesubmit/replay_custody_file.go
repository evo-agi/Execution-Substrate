package reliablesubmit

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// PrivateReplayCustody exists only for the explicitly synthetic, unwired
// fixture. The held root/parent descriptors are not an effect authority.
type PrivateReplayCustody struct {
	privateReplayRedacted
	store       *sqliteClaimStore
	rootFD      int
	objectsFD   int
	parentFD    int
	rootPath    string
	rootStat    unix.Stat_t
	objectsStat unix.Stat_t
	parentStat  unix.Stat_t
	closed      bool
	// The finite fault selector is package-private and used only by synthetic
	// publication tests. Zero is the only production value.
	testPublicationFault          replayPublicationFault
	testPublicationCloseAttempts  int
	testPublicationReopenAttempts int
	allocatorTest                 *replayAllocatorTestHooks
}

type replayPublicationFault uint8

const (
	replayPublicationWriteShortThenFail replayPublicationFault = iota + 1
	replayPublicationWriteFail
	replayPublicationReadbackMismatch
	replayPublicationReadbackFail
	replayPublicationFileSyncFail
	replayPublicationParentSyncFail
	replayPublicationFinalCloseFail
	replayPublicationReopenFail
)

// replayPublicationOwnedFD clears ownership before close(2). A close error
// never licenses another close of the same numeric descriptor.
type replayPublicationOwnedFD struct {
	fd      int
	custody *PrivateReplayCustody
}

func (o *replayPublicationOwnedFD) close(final bool) error {
	if o.fd < 0 {
		return nil
	}
	fd := o.fd
	o.fd = -1
	if o.custody.testPublicationFault != 0 {
		o.custody.testPublicationCloseAttempts++
	}
	err := unix.Close(fd)
	if final && o.custody.testPublicationFault == replayPublicationFinalCloseFail && err == nil {
		return errClaimStoreUnavailable
	}
	return err
}

type PrivateReplaySealPermit struct {
	privateReplayRedacted
	permit *privateSealPermit
}

type PrivateReplayPublication struct {
	privateReplayRedacted
	descriptor replayClaimDescriptor
}

type PrivateReplayAttempt struct {
	privateReplayRedacted
	expected durableClaimRecord
}

// PrivateReplayClaimCommitFault is a finite synthetic-fixture test seam. It
// cannot establish a claim, return a Seal permit, or grant an effect.
type PrivateReplayClaimCommitFault uint8

const (
	PrivateReplayClaimCommitResponseLost PrivateReplayClaimCommitFault = iota + 1
	PrivateReplayClaimConnectionClosedBeforeCommit
)

func (c *PrivateReplayCustody) InjectClaimCommitFaultForTesting(fault PrivateReplayClaimCommitFault) error {
	if c == nil || c.closed || c.store == nil || c.store.claimCommit != nil ||
		(fault != PrivateReplayClaimCommitResponseLost && fault != PrivateReplayClaimConnectionClosedBeforeCommit) {
		return errClaimStoreUnsupported
	}
	c.store.claimCommit = func(ctx context.Context, conn *sql.Conn) error {
		if fault == PrivateReplayClaimCommitResponseLost {
			if err := commit(ctx, conn); err != nil {
				return err
			}
		}
		// The caller discards the still-held driver connection before any
		// classifier can read. This pre-COMMIT fault never reaches COMMIT.
		return errClaimStoreCommitUnknown
	}
	return nil
}

type AuthenticatedClaimMeta struct {
	privateReplayRedacted
	record durableClaimRecord
}

func ErrPrivateReplayClaimCommitUnknown() error { return errClaimStoreCommitUnknown }

type PrivateReplayClaimLookup struct {
	privateReplayRedacted
	found      bool
	bindingID  string
	envelopeID string
}

func (l PrivateReplayClaimLookup) Found() bool { return l.found }
func (l PrivateReplayClaimLookup) OriginalKeyIDs() (string, string, bool) {
	if !l.found {
		return "", "", false
	}
	return l.bindingID, l.envelopeID, true
}

func (m AuthenticatedClaimMeta) MatchesAttempt(attempt PrivateReplayAttempt) bool {
	return m.record.validate() == nil && attempt.expected.validate() == nil &&
		subtle.ConstantTimeCompare(m.record.plan.binding.ref.value, attempt.expected.plan.binding.ref.value) == 1 &&
		m.record.equal(attempt.expected)
}

func (m AuthenticatedClaimMeta) MatchesClaimAndPlan(claim ClaimID, plan BoundPlan) bool {
	return m.record.validate() == nil && m.record.codecVersion == durableClaimCodecVersionSynthetic &&
		m.record.claim.Equal(claim) &&
		subtle.ConstantTimeCompare(m.record.plan.binding.ref.value, plan.binding.ref.value) == 1 &&
		witnessEqual(m.record.plan.Witness(), plan.Witness())
}

func OpenPrivateReplayCustody(ctx context.Context, root string) (*PrivateReplayCustody, error) {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root || rejectSymlinkPath(root) != nil {
		return nil, errClaimStoreUnsupported
	}
	rootFD, err := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, errClaimStoreUnavailable
	}
	closeRoot := true
	defer func() {
		if closeRoot {
			_ = unix.Close(rootFD)
		}
	}()
	var rootStat unix.Stat_t
	if unix.Fstat(rootFD, &rootStat) != nil || !replayDirectoryQualified(rootStat) {
		return nil, errClaimStoreUnsupported
	}
	// The fixture marker is created only with a new synthetic state root. It
	// refuses silent adoption of an unrelated owner-owned database directory.
	markerFD, err := openReplayReadOnlyCandidate(rootFD, "synthetic-replay-v1.marker")
	if err != nil {
		return nil, errClaimStoreUnsupported
	}
	var markerStat unix.Stat_t
	if unix.Fstat(markerFD, &markerStat) != nil || !replayFileQualified(markerStat) || markerStat.Size != int64(len("synthetic_nonoperational_v1\n")) {
		_ = unix.Close(markerFD)
		return nil, errClaimStoreUnsupported
	}
	marker, readErr := readReplayFD(markerFD, int(markerStat.Size))
	markerCloseErr := unix.Close(markerFD)
	if readErr != nil || markerCloseErr != nil || string(marker) != "synthetic_nonoperational_v1\n" {
		return nil, errClaimStoreUnsupported
	}
	objectsFD, err := unix.Openat(rootFD, "objects", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, errClaimStoreUnsupported
	}
	closeObjects := true
	defer func() {
		if closeObjects {
			_ = unix.Close(objectsFD)
		}
	}()
	var objectsStat unix.Stat_t
	if unix.Fstat(objectsFD, &objectsStat) != nil || !replayDirectoryQualified(objectsStat) {
		return nil, errClaimStoreUnsupported
	}
	parentFD, err := unix.Openat(objectsFD, "v1", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, errClaimStoreUnsupported
	}
	closeParent := true
	defer func() {
		if closeParent {
			_ = unix.Close(parentFD)
		}
	}()
	var parentStat unix.Stat_t
	if unix.Fstat(parentFD, &parentStat) != nil || !replayDirectoryQualified(parentStat) {
		return nil, errClaimStoreUnsupported
	}
	if unix.Fsync(rootFD) != nil || unix.Fsync(objectsFD) != nil || unix.Fsync(parentFD) != nil {
		return nil, errClaimStoreUnsupported
	}
	dbPath := filepath.Join(root, "reliable-submit.sqlite3")
	// The shared opener may initialize modes for files it creates. Existing
	// fixture files must already qualify; the private path never repairs them.
	if err := checkReplayDBFiles(dbPath); err != nil {
		return nil, err
	}
	store, err := openSQLiteClaimStore(ctx, sqliteClaimStoreOptions{path: dbPath})
	if err != nil {
		return nil, err
	}
	var visibleRoot unix.Stat_t
	if unix.Lstat(root, &visibleRoot) != nil || !sameReplayIdentity(rootStat, visibleRoot) {
		_ = store.close()
		return nil, errClaimStoreUnavailable
	}
	closeRoot, closeObjects, closeParent = false, false, false
	custody := &PrivateReplayCustody{store: store, rootFD: rootFD, objectsFD: objectsFD,
		parentFD: parentFD, rootPath: root, rootStat: rootStat, objectsStat: objectsStat, parentStat: parentStat}
	if err := custody.checkFixtureDBBudget(); err != nil {
		_ = custody.Close()
		return nil, err
	}
	return custody, nil
}

func replayDirectoryQualified(st unix.Stat_t) bool {
	return st.Mode&unix.S_IFMT == unix.S_IFDIR && st.Mode&0o7777 == 0o700 &&
		st.Uid == uint32(os.Getuid()) && st.Gid == uint32(os.Getgid())
}

func replayFileQualified(st unix.Stat_t) bool {
	return st.Mode&unix.S_IFMT == unix.S_IFREG && st.Mode&0o7777 == 0o600 &&
		st.Nlink == 1 && st.Uid == uint32(os.Getuid()) && st.Gid == uint32(os.Getgid())
}

func openReplayReadOnlyCandidate(dirFD int, name string) (int, error) {
	return unix.Openat(dirFD, name, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
}

func sameReplayIdentity(a, b unix.Stat_t) bool {
	return a.Dev == b.Dev && a.Ino == b.Ino && a.Uid == b.Uid &&
		a.Gid == b.Gid && a.Mode&0o7777 == b.Mode&0o7777
}

func (c *PrivateReplayCustody) checkParents() (out error) {
	if c == nil || c.closed {
		return errClaimStoreUnavailable
	}
	var root, objects, parent unix.Stat_t
	if unix.Fstat(c.rootFD, &root) != nil || unix.Fstat(c.objectsFD, &objects) != nil || unix.Fstat(c.parentFD, &parent) != nil ||
		!replayDirectoryQualified(root) || !replayDirectoryQualified(objects) || !replayDirectoryQualified(parent) ||
		!sameReplayIdentity(root, c.rootStat) || !sameReplayIdentity(objects, c.objectsStat) || !sameReplayIdentity(parent, c.parentStat) {
		return errClaimStoreUnavailable
	}
	// A relative object ref must still name the held directory chain in the
	// visible root. A detached held v1 descriptor cannot authorize a claim.
	visibleRoot, err := unix.Open(c.rootPath, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return errClaimStoreUnavailable
	}
	defer func() {
		if unix.Close(visibleRoot) != nil {
			out = errClaimStoreUnavailable
		}
	}()
	if unix.Fstat(visibleRoot, &root) != nil || !sameReplayIdentity(root, c.rootStat) {
		return errClaimStoreUnavailable
	}
	visibleObjects, err := unix.Openat(visibleRoot, "objects", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return errClaimStoreUnavailable
	}
	defer func() {
		if unix.Close(visibleObjects) != nil {
			out = errClaimStoreUnavailable
		}
	}()
	if unix.Fstat(visibleObjects, &objects) != nil || !sameReplayIdentity(objects, c.objectsStat) {
		return errClaimStoreUnavailable
	}
	visibleParent, err := unix.Openat(visibleObjects, "v1", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return errClaimStoreUnavailable
	}
	defer func() {
		if unix.Close(visibleParent) != nil {
			out = errClaimStoreUnavailable
		}
	}()
	if unix.Fstat(visibleParent, &parent) != nil || !sameReplayIdentity(parent, c.parentStat) {
		return errClaimStoreUnavailable
	}
	return nil
}

func (c *PrivateReplayCustody) Close() error {
	if c == nil || c.closed {
		return nil
	}
	c.closed = true
	err := c.store.close()
	if unix.Close(c.parentFD) != nil {
		err = errClaimStoreUnavailable
	}
	if unix.Close(c.objectsFD) != nil {
		err = errClaimStoreUnavailable
	}
	if unix.Close(c.rootFD) != nil {
		err = errClaimStoreUnavailable
	}
	return err
}

func (c *PrivateReplayCustody) LoadSyntheticClaim(ctx context.Context, claim ClaimID) (PrivateReplayClaimLookup, error) {
	if c.checkParents() != nil || c.checkFixtureDBBudget() != nil || !claim.Valid() {
		return PrivateReplayClaimLookup{}, errClaimStoreUnavailable
	}
	record, err := c.store.loadClaimFresh(ctx, loadClaimQuery{claim: claim})
	if c.checkFixtureDBBudget() != nil {
		return PrivateReplayClaimLookup{}, errClaimStoreUnavailable
	}
	if errors.Is(err, errClaimStoreNotFound) {
		return PrivateReplayClaimLookup{}, nil
	}
	if err != nil {
		return PrivateReplayClaimLookup{}, err
	}
	if record.codecVersion != durableClaimCodecVersionSynthetic {
		return PrivateReplayClaimLookup{}, errClaimStoreUnsupported
	}
	return PrivateReplayClaimLookup{found: true, bindingID: record.replay.bindingKeyID, envelopeID: record.replay.envelopeKeyID}, nil
}

func (c *PrivateReplayCustody) ReserveSealUse(ctx context.Context, frozen PrivateReplayFrozen) (PrivateReplaySealPermit, error) {
	if c.checkParents() != nil || frozen.format != syntheticReplayFormat || !frozen.valid() || c.checkFixtureDBBudget() != nil {
		return PrivateReplaySealPermit{}, errClaimStoreUnavailable
	}
	permit, err := c.store.reserveReplaySealUse(ctx, frozen.keys, frozen.digest, false)
	if err != nil {
		return PrivateReplaySealPermit{}, err
	}
	if c.checkFixtureDBBudget() != nil {
		permit.burn()
		return PrivateReplaySealPermit{}, errClaimStoreUnavailable
	}
	return PrivateReplaySealPermit{permit: permit}, nil
}

func (f PrivateReplayFrozen) valid() bool {
	format, ok := replayFormatForScope(int64(f.format.scope))
	if !ok || f.format != format {
		return false
	}
	if !f.claim.Valid() || !f.plan.Valid() || !f.keys.valid ||
		len(f.plaintext) < 14 || len(f.plaintext) > replayPayloadLimit ||
		len(f.header) < 16 || len(f.header) > replayHeaderLimit ||
		len(f.aad) != 8+len(f.header) || string(f.aad[:8]) != format.aadDomain ||
		subtle.ConstantTimeCompare(f.aad[8:], f.header) != 1 {
		return false
	}
	fields, err := format.parsePayload(f.plaintext)
	if err != nil || format.checkPayloadAssociations(fields, f.claim, f.plan, f.keys) != nil {
		return false
	}
	header, err := format.encodeHeader(f.claim, f.plan, f.keys, f.objectID, f.intentMAC, f.contextMAC, len(f.plaintext))
	if err != nil || subtle.ConstantTimeCompare(header, f.header) != 1 {
		return false
	}
	intentWire, _ := encodeReplayField(fields[1])
	contextWire := make([]byte, 0)
	for _, field := range fields[5:8] {
		encoded, _ := encodeReplayField(field)
		contextWire = append(contextWire, encoded...)
	}
	wantIntent := replayHMAC(f.keys.binding, format.intentDomain, intentWire)
	wantContext := replayHMAC(f.keys.binding, format.contextDomain, contextWire)
	wantDigest := format.frozenDigest(f.keys, f.header, f.plaintext)
	return subtle.ConstantTimeCompare(wantIntent[:], f.intentMAC[:]) == 1 &&
		subtle.ConstantTimeCompare(wantContext[:], f.contextMAC[:]) == 1 &&
		subtle.ConstantTimeCompare(wantDigest[:], f.digest[:]) == 1
}

func (c *PrivateReplayCustody) PublishSealedSynthetic(ctx context.Context, frozen PrivateReplayFrozen, grant PrivateReplaySealPermit) (PrivateReplayPublication, error) {
	if frozen.format != syntheticReplayFormat {
		return PrivateReplayPublication{}, errClaimStoreUnavailable
	}
	return c.publishReplayOriginal(ctx, frozen, grant)
}

func (c *PrivateReplayCustody) publishReplayOriginal(ctx context.Context, frozen PrivateReplayFrozen, grant PrivateReplaySealPermit) (PrivateReplayPublication, error) {
	qualified := c.checkParents() == nil && frozen.valid() && grant.permit != nil
	if !qualified && frozen.format == syntheticReplayFormat {
		return PrivateReplayPublication{}, errClaimStoreUnavailable
	}
	defer grant.permit.burn()
	if !qualified {
		return PrivateReplayPublication{}, errClaimStoreUnavailable
	}
	if !grant.permit.matchesAllocation(c.store, frozen) {
		return PrivateReplayPublication{}, errClaimStoreUnavailable
	}
	basename := hex.EncodeToString(frozen.objectID[:])
	fd, held, err := c.allocateReplayObject(ctx, basename)
	if err != nil {
		return PrivateReplayPublication{}, err
	}
	owned := replayPublicationOwnedFD{fd: fd, custody: c}
	defer func() {
		_ = owned.close(false)
	}()
	if err := c.store.consumeReplaySealPermit(ctx, frozen.keys, frozen.digest, grant.permit); err != nil {
		return PrivateReplayPublication{}, err
	}
	block, err := aes.NewCipher(frozen.keys.envelope[:])
	if err != nil {
		return PrivateReplayPublication{}, errClaimStoreUnavailable
	}
	gcm, err := cipher.NewGCMWithRandomNonce(block)
	if err != nil {
		return PrivateReplayPublication{}, errClaimStoreUnavailable
	}
	combined := gcm.Seal(nil, nil, frozen.plaintext, frozen.aad)
	if len(combined) != len(frozen.plaintext)+28 || len(frozen.header)+len(combined) > replaySealedLimit {
		return PrivateReplayPublication{}, errReplayFormat
	}
	file := make([]byte, 0, len(frozen.header)+len(combined))
	file = append(file, frozen.header...)
	file = append(file, combined...)
	written := 0
	for written < len(file) {
		var n int
		var writeErr error
		switch {
		case c.testPublicationFault == replayPublicationWriteShortThenFail && written == 0:
			n, writeErr = unix.Write(fd, file[:1])
		case c.testPublicationFault == replayPublicationWriteShortThenFail,
			c.testPublicationFault == replayPublicationWriteFail:
			writeErr = errClaimStoreUnavailable
		default:
			n, writeErr = unix.Write(fd, file[written:])
		}
		if writeErr != nil || n <= 0 {
			return PrivateReplayPublication{}, errClaimStoreUnavailable
		}
		written += n
	}
	if _, err := unix.Seek(fd, 0, 0); err != nil {
		return PrivateReplayPublication{}, errClaimStoreUnavailable
	}
	readback, err := readReplayFD(fd, len(file))
	if c.testPublicationFault == replayPublicationReadbackFail {
		err = errClaimStoreUnavailable
	}
	if c.testPublicationFault == replayPublicationReadbackMismatch && len(readback) > 0 {
		readback[0] ^= 1
	}
	if err != nil || subtle.ConstantTimeCompare(file, readback) != 1 {
		return PrivateReplayPublication{}, errClaimStoreUnavailable
	}
	var after unix.Stat_t
	if unix.Fstat(fd, &after) != nil || !replayFileQualified(after) || !sameReplayIdentity(held, after) || after.Size != int64(len(file)) {
		return PrivateReplayPublication{}, errClaimStoreUnavailable
	}
	scope := int64(frozen.format.scope)
	d := replayClaimDescriptor{scope: scope, intentFormat: 1, wrapperFormat: scope, payloadFormat: scope, algorithm: 1,
		ref: replayObjectRef(frozen.objectID), size: int64(len(file)), fileSHA: sha256.Sum256(file),
		bindingKeyID: frozen.keys.bindingID, bindingKeyFP: frozen.keys.bindingFP,
		envelopeKeyID: frozen.keys.envelopeID, envelopeKeyFP: frozen.keys.envelopeFP,
		intentMAC: frozen.intentMAC, contextMAC: frozen.contextMAC}
	if _, err := verifyReplayFileBytes(file, frozen.claim, frozen.plan, frozen.keys, d); err != nil {
		return PrivateReplayPublication{}, err
	}
	fileSyncErr := unix.Fsync(fd)
	if c.testPublicationFault == replayPublicationFileSyncFail && fileSyncErr == nil {
		fileSyncErr = errClaimStoreUnavailable
	}
	if fileSyncErr != nil {
		return PrivateReplayPublication{}, errClaimStoreUnavailable
	}
	parentSyncErr := unix.Fsync(c.parentFD)
	if c.testPublicationFault == replayPublicationParentSyncFail && parentSyncErr == nil {
		parentSyncErr = errClaimStoreUnavailable
	}
	if parentSyncErr != nil {
		return PrivateReplayPublication{}, errClaimStoreUnavailable
	}
	if err := owned.close(true); err != nil {
		return PrivateReplayPublication{}, errClaimStoreUnavailable
	}
	if c.testPublicationFault != 0 {
		c.testPublicationReopenAttempts++
	}
	visibleName := basename
	if c.testPublicationFault == replayPublicationReopenFail {
		// The isolated synthetic fixture has no such name; exercise the real
		// no-follow reopen failure after the sealed object's final close.
		visibleName += "-missing"
	}
	visibleFD, err := openReplayReadOnlyCandidate(c.parentFD, visibleName)
	if err != nil {
		return PrivateReplayPublication{}, errClaimStoreUnavailable
	}
	var visible unix.Stat_t
	if unix.Fstat(visibleFD, &visible) != nil || !replayFileQualified(visible) || !sameReplayIdentity(held, visible) || visible.Size != int64(len(file)) {
		_ = unix.Close(visibleFD)
		return PrivateReplayPublication{}, errClaimStoreUnavailable
	}
	visibleBytes, err := readReplayFD(visibleFD, len(file))
	closeErr := unix.Close(visibleFD)
	if err != nil || closeErr != nil || subtle.ConstantTimeCompare(file, visibleBytes) != 1 || c.checkParents() != nil {
		return PrivateReplayPublication{}, errClaimStoreUnavailable
	}
	if _, err := verifyReplayFileBytes(visibleBytes, frozen.claim, frozen.plan, frozen.keys, d); err != nil {
		return PrivateReplayPublication{}, err
	}
	return PrivateReplayPublication{descriptor: d}, nil
}

func readReplayFD(fd int, expected int) ([]byte, error) {
	if expected < 0 || expected > replaySealedLimit {
		return nil, errReplayFormat
	}
	buf := make([]byte, expected+1)
	used := 0
	for used < len(buf) {
		n, err := unix.Read(fd, buf[used:])
		if err != nil {
			return nil, errClaimStoreUnavailable
		}
		if n == 0 {
			break
		}
		used += n
	}
	if used != expected {
		return nil, errClaimStoreUnavailable
	}
	return buf[:used], nil
}

type replayAllocatorTestHooks struct {
	begin, rollback  func(context.Context, *sql.Conn) error
	afterCreate      func(int)
	firstDiscard     func(*sql.Conn) error
	rescueResponse   func(error) error
	beforePoolReturn func()
}

// matchesAllocation checks the prospective permit without spending it. The
// later locked consume is the only authority to grant a Seal.
func (p *privateSealPermit) matchesAllocation(issuer *sqliteClaimStore, frozen PrivateReplayFrozen) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return !p.used && p.issuer == issuer && p.keyID == frozen.keys.envelopeID && p.sequence > 0 &&
		subtle.ConstantTimeCompare(p.fingerprint[:], frozen.keys.envelopeFP[:]) == 1 &&
		subtle.ConstantTimeCompare(p.frozenDigest[:], frozen.digest[:]) == 1
}

func (c *PrivateReplayCustody) allocateReplayObject(ctx context.Context, name string) (int, unix.Stat_t, error) {
	if ctx.Err() != nil || c.checkParents() != nil || !replayObjectRefValid("objects/v1/"+name) {
		return -1, unix.Stat_t{}, errClaimStoreUnavailable
	}
	conn, err := c.store.checkedConn(ctx)
	if err != nil {
		return -1, unix.Stat_t{}, errClaimStoreUnavailable
	}
	hooks := c.allocatorTest
	closeConn := func() error {
		if hooks != nil && hooks.beforePoolReturn != nil {
			hooks.beforePoolReturn()
		}
		return conn.Close()
	}
	discard := func() {
		first := discardUncertainSQLiteConn
		if hooks != nil && hooks.firstDiscard != nil {
			first = hooks.firstDiscard
		}
		err := first(conn)
		if err != nil {
			err = discardUncertainSQLiteConn(conn)
			if hooks != nil && hooks.rescueResponse != nil {
				err = hooks.rescueResponse(err)
			}
		}
		if err == nil {
			_ = closeConn()
		}
	}
	if ctx.Err() != nil {
		_ = closeConn()
		return -1, unix.Stat_t{}, errClaimStoreUnavailable
	}
	begin := func(ctx context.Context, conn *sql.Conn) error {
		_, err := conn.ExecContext(ctx, "BEGIN IMMEDIATE")
		return err
	}
	rollback := func(ctx context.Context, conn *sql.Conn) error {
		_, err := conn.ExecContext(ctx, "ROLLBACK")
		return err
	}
	if hooks != nil {
		if hooks.begin != nil {
			begin = hooks.begin
		}
		if hooks.rollback != nil {
			rollback = hooks.rollback
		}
	}
	if err := begin(ctx, conn); err != nil {
		discard()
		return -1, unix.Stat_t{}, errClaimStoreUnavailable
	}

	owned := replayPublicationOwnedFD{fd: -1, custody: c}
	defer owned.close(false)
	create := func() error {
		if ctx.Err() != nil || c.checkParents() != nil {
			return errClaimStoreUnavailable
		}
		if err := c.checkObjectBudget(); err != nil {
			return err
		}
		if ctx.Err() != nil {
			return errClaimStoreUnavailable
		}
		fd, err := unix.Openat(c.parentFD, name, unix.O_CREAT|unix.O_EXCL|unix.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
		if err != nil {
			return errClaimStoreUnavailable
		}
		owned.fd = fd
		if hooks != nil && hooks.afterCreate != nil {
			hooks.afterCreate(fd)
		}
		if unix.Fchmod(fd, 0o600) != nil {
			return errClaimStoreUnavailable
		}
		return nil
	}
	created := create()
	held, qualifies := c.qualifiedEmptyReplayObject(owned.fd, name)
	clean, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	rollbackErr := rollback(clean, conn)
	cleanupErr := clean.Err()
	cancel()
	if rollbackErr != nil || cleanupErr != nil {
		discard()
		return -1, unix.Stat_t{}, errClaimStoreUnavailable
	}
	if closeConn() != nil || ctx.Err() != nil {
		return -1, unix.Stat_t{}, errClaimStoreUnavailable
	}
	if created != nil {
		return -1, unix.Stat_t{}, created
	}
	visible, stillQualified := c.qualifiedEmptyReplayObject(owned.fd, name)
	if !qualifies || !stillQualified || !sameReplayIdentity(held, visible) || ctx.Err() != nil {
		return -1, unix.Stat_t{}, errClaimStoreUnavailable
	}
	fd := owned.fd
	owned.fd = -1
	return fd, held, nil
}

func (c *PrivateReplayCustody) qualifiedEmptyReplayObject(fd int, name string) (held unix.Stat_t, ok bool) {
	var visible unix.Stat_t
	if fd < 0 || c.checkParents() != nil || unix.Fstat(fd, &held) != nil ||
		unix.Fstatat(c.parentFD, name, &visible, unix.AT_SYMLINK_NOFOLLOW) != nil {
		return held, false
	}
	return held, replayFileQualified(held) && replayFileQualified(visible) &&
		held.Size == 0 && visible.Size == 0 && sameReplayIdentity(held, visible)
}

func (c *PrivateReplayCustody) checkObjectBudget() error {
	// Counting names is only a first-proof resource bound. A name never grants
	// authority; only a matching committed claim and checked file can do so.
	var names int
	fd, err := unix.Openat(c.parentFD, ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return errClaimStoreUnavailable
	}
	file := os.NewFile(uintptr(fd), "synthetic-object-count")
	entries, err := file.Readdirnames(33)
	closeErr := file.Close()
	if err != nil && !errors.Is(err, io.EOF) {
		return errClaimStoreUnavailable
	}
	if closeErr != nil {
		return errClaimStoreUnavailable
	}
	names = len(entries)
	if names >= 32 {
		return errClaimStoreUnsupported
	}
	return nil
}

func (c *PrivateReplayCustody) checkFixtureDBBudget() error {
	if c == nil || c.store == nil {
		return errClaimStoreUnavailable
	}
	return checkReplayDBFiles(c.store.path)
}

func checkReplayDBFiles(path string) error {
	var total int64
	for _, candidate := range []string{path, path + "-wal", path + "-shm", path + "-journal"} {
		info, err := os.Lstat(candidate)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil || !info.Mode().IsRegular() {
			return errClaimStoreUnavailable
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok || st.Mode&0o7777 != 0o600 || st.Nlink != 1 || st.Uid != uint32(os.Getuid()) || st.Gid != uint32(os.Getgid()) {
			return errClaimStoreUnavailable
		}
		if info.Size() < 0 || info.Size() > 16<<20-total {
			return errClaimStoreUnavailable
		}
		total += info.Size()
	}
	return nil
}

func (c *PrivateReplayCustody) EstablishSyntheticClaim(ctx context.Context, frozen PrivateReplayFrozen, publication PrivateReplayPublication) (PrivateReplayAttempt, bool, error) {
	if c.checkParents() != nil || c.checkFixtureDBBudget() != nil || frozen.format != syntheticReplayFormat || !frozen.valid() || !publication.descriptor.valid() ||
		publication.descriptor.ref != replayObjectRef(frozen.objectID) ||
		publication.descriptor.bindingKeyID != frozen.keys.bindingID ||
		publication.descriptor.envelopeKeyID != frozen.keys.envelopeID ||
		subtle.ConstantTimeCompare(publication.descriptor.intentMAC[:], frozen.intentMAC[:]) != 1 ||
		subtle.ConstantTimeCompare(publication.descriptor.contextMAC[:], frozen.contextMAC[:]) != 1 ||
		subtle.ConstantTimeCompare(publication.descriptor.bindingKeyFP[:], frozen.keys.bindingFP[:]) != 1 ||
		subtle.ConstantTimeCompare(publication.descriptor.envelopeKeyFP[:], frozen.keys.envelopeFP[:]) != 1 {
		return PrivateReplayAttempt{}, false, errClaimStoreUnavailable
	}
	if err := c.store.checkOriginalReplayKeys(ctx, frozen.keys, true); err != nil {
		return PrivateReplayAttempt{}, false, err
	}
	if _, err := c.checkPublishedRef(ctx, frozen.claim, frozen.plan, frozen.keys, publication.descriptor); err != nil {
		return PrivateReplayAttempt{}, false, err
	}
	record, err := newReplayDurableClaimRecord(frozen.claim, frozen.plan, publication.descriptor, time.Now().UTC())
	if err != nil {
		return PrivateReplayAttempt{}, false, err
	}
	attempt := PrivateReplayAttempt{expected: record}
	result, err := c.store.establishClaim(ctx, establishClaimCommand{record: record})
	if err != nil {
		return attempt, false, err
	}
	if c.checkFixtureDBBudget() != nil {
		return attempt, false, errClaimStoreUnavailable
	}
	return attempt, result.created, nil
}

func (c *PrivateReplayCustody) WithAuthenticatedClaim(ctx context.Context, claim ClaimID, keys PrivateReplayKeys, callback func(AuthenticatedClaimMeta, []byte) error) error {
	if c.checkParents() != nil || c.checkFixtureDBBudget() != nil || !claim.Valid() || !keys.valid || callback == nil {
		return errClaimStoreUnavailable
	}
	record, err := c.store.loadClaimFresh(ctx, loadClaimQuery{claim: claim})
	if err != nil {
		return err
	}
	if record.codecVersion != durableClaimCodecVersionSynthetic || !record.replay.valid() {
		return errClaimStoreUnsupported
	}
	if record.replay.bindingKeyID != keys.bindingID || record.replay.envelopeKeyID != keys.envelopeID ||
		subtle.ConstantTimeCompare(record.replay.bindingKeyFP[:], keys.bindingFP[:]) != 1 ||
		subtle.ConstantTimeCompare(record.replay.envelopeKeyFP[:], keys.envelopeFP[:]) != 1 {
		return errClaimStoreUnavailable
	}
	if err := c.store.checkOriginalReplayKeys(ctx, keys, false); err != nil {
		return err
	}
	plaintext, err := c.checkPublishedRef(ctx, claim, record.plan, keys, record.replay)
	if err != nil {
		return err
	}
	if err := callback(AuthenticatedClaimMeta{record: record.clone()}, plaintext); err != nil {
		return errClaimStoreUnavailable
	}
	return nil
}

func (c *PrivateReplayCustody) checkPublishedRef(ctx context.Context, claim ClaimID, plan BoundPlan, keys PrivateReplayKeys, descriptor replayClaimDescriptor) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, errClaimStoreUnavailable
	}
	if c.checkParents() != nil || !descriptor.validForScope(descriptor.scope) {
		return nil, errClaimStoreUnavailable
	}
	basename := strings.TrimPrefix(descriptor.ref, "objects/v1/")
	if len(basename) != 64 {
		return nil, errReplayFormat
	}
	fd, err := openReplayReadOnlyCandidate(c.parentFD, basename)
	if err != nil {
		return nil, errClaimStoreUnavailable
	}
	var held unix.Stat_t
	if unix.Fstat(fd, &held) != nil || !replayFileQualified(held) || held.Size != descriptor.size {
		_ = unix.Close(fd)
		return nil, errClaimStoreUnavailable
	}
	file, err := readReplayFD(fd, int(descriptor.size))
	closeErr := unix.Close(fd)
	if err != nil || closeErr != nil || c.checkParents() != nil {
		return nil, errClaimStoreUnavailable
	}
	visibleFD, err := openReplayReadOnlyCandidate(c.parentFD, basename)
	if err != nil {
		return nil, errClaimStoreUnavailable
	}
	var visible unix.Stat_t
	if unix.Fstat(visibleFD, &visible) != nil || !replayFileQualified(visible) || !sameReplayIdentity(held, visible) || visible.Size != descriptor.size {
		_ = unix.Close(visibleFD)
		return nil, errClaimStoreUnavailable
	}
	if err := unix.Close(visibleFD); err != nil {
		return nil, errClaimStoreUnavailable
	}
	return verifyReplayFileBytes(file, claim, plan, keys, descriptor)
}

func verifyReplayFileBytes(file []byte, claim ClaimID, plan BoundPlan, keys PrivateReplayKeys, descriptor replayClaimDescriptor) ([]byte, error) {
	format, ok := replayFormatForScope(descriptor.scope)
	if !ok || !descriptor.validForScope(descriptor.scope) || int64(len(file)) != descriptor.size || len(file) > replaySealedLimit ||
		subtle.ConstantTimeCompare(sha256Sum(file), descriptor.fileSHA[:]) != 1 {
		return nil, errReplayFormat
	}
	fields, header, err := format.parseHeader(file)
	if err != nil {
		return nil, err
	}
	for _, id := range []int{1, 2, 4} {
		value, e := replayRequirePresent(fields, id, 2)
		want := uint16(1)
		if id == 2 {
			want = uint16(format.scope)
		}
		if e != nil || binary.BigEndian.Uint16(value) != want {
			return nil, errReplayFormat
		}
	}
	scope, e := replayRequirePresent(fields, 3, 1)
	if e != nil || scope[0] != format.scope {
		return nil, errReplayFormat
	}
	for id, want := range map[int]string{5: keys.bindingID, 6: keys.envelopeID} {
		value, e := replayRequirePresent(fields, id, -1)
		if e != nil || string(value) != want {
			return nil, errReplayFormat
		}
	}
	objectID, e := replayRequirePresent(fields, 7, 32)
	if e != nil || descriptor.ref != "objects/v1/"+hex.EncodeToString(objectID) {
		return nil, errReplayFormat
	}
	caller, e := replayRequirePresent(fields, 8, 32)
	if e != nil || subtle.ConstantTimeCompare(caller, claim.caller.ref.value) != 1 {
		return nil, errReplayFormat
	}
	submit, e := replayRequirePresent(fields, 9, 32)
	if e != nil || subtle.ConstantTimeCompare(submit, claim.submitKey.ref.value) != 1 {
		return nil, errReplayFormat
	}
	binding, e := replayRequirePresent(fields, 10, -1)
	if e != nil || len(binding) < 1 || len(binding) > 256 || subtle.ConstantTimeCompare(binding, plan.binding.ref.value) != 1 {
		return nil, errReplayFormat
	}
	intent, e := replayRequirePresent(fields, 11, 32)
	if e != nil || subtle.ConstantTimeCompare(intent, descriptor.intentMAC[:]) != 1 {
		return nil, errReplayFormat
	}
	contextMAC, e := replayRequirePresent(fields, 12, 32)
	if e != nil || subtle.ConstantTimeCompare(contextMAC, descriptor.contextMAC[:]) != 1 {
		return nil, errReplayFormat
	}
	plainLen, e := replayRequirePresent(fields, 13, 4)
	if e != nil {
		return nil, errReplayFormat
	}
	combinedLen, e := replayRequirePresent(fields, 14, 4)
	if e != nil {
		return nil, errReplayFormat
	}
	pl := binary.BigEndian.Uint32(plainLen)
	cl := binary.BigEndian.Uint32(combinedLen)
	if pl < 14 || pl > replayPayloadLimit || cl != pl+28 || int(cl) != len(file)-len(header) {
		return nil, errReplayFormat
	}
	aad := append([]byte(format.aadDomain), header...)
	block, err := aes.NewCipher(keys.envelope[:])
	if err != nil {
		return nil, errClaimStoreUnavailable
	}
	gcm, err := cipher.NewGCMWithRandomNonce(block)
	if err != nil {
		return nil, errClaimStoreUnavailable
	}
	plaintext, err := gcm.Open(nil, nil, file[len(header):], aad)
	if err != nil {
		return nil, errClaimStoreUnavailable
	}
	if len(plaintext) != int(pl) {
		return nil, errReplayFormat
	}
	payloadFields, err := format.parsePayload(plaintext)
	if err != nil {
		return nil, err
	}
	if err := format.checkPayloadAssociations(payloadFields, claim, plan, keys); err != nil {
		return nil, err
	}
	intentWire, _ := encodeReplayField(payloadFields[1])
	otherWire := make([]byte, 0)
	for _, field := range payloadFields[5:8] {
		encoded, _ := encodeReplayField(field)
		otherWire = append(otherWire, encoded...)
	}
	wantIntent := replayHMAC(keys.binding, format.intentDomain, intentWire)
	wantContext := replayHMAC(keys.binding, format.contextDomain, otherWire)
	if subtle.ConstantTimeCompare(wantIntent[:], intent) != 1 || subtle.ConstantTimeCompare(wantContext[:], contextMAC) != 1 {
		return nil, errReplayFormat
	}
	return plaintext, nil
}

func sha256Sum(raw []byte) []byte { sum := sha256.Sum256(raw); return sum[:] }

// PrivateReplayProgressCustody is the scope-2-only fixture selector. Its
// lifetime is distinct from a borrow of authenticated original evidence.
type PrivateReplayProgressCustody struct {
	privateReplayRedacted
	mu      sync.RWMutex
	self    *PrivateReplayProgressCustody
	custody *PrivateReplayCustody
}

type ProgressLookup struct {
	privateReplayRedacted
	issuer   *PrivateReplayProgressCustody
	owner    context.Context
	claim    ClaimID
	original durableClaimRecord
	found    bool
}

func (l ProgressLookup) Absent() bool {
	return l.issuer != nil && l.owner.Err() == nil && l.claim.Valid() && !l.found
}
func (l ProgressLookup) OriginalKeyIDs() (string, string, bool) {
	if l.issuer == nil || l.owner.Err() != nil || !l.found {
		return "", "", false
	}
	return l.original.replay.bindingKeyID, l.original.replay.envelopeKeyID, true
}

type ProgressOriginalInput struct {
	privateReplayRedacted
	encoded []byte
}

func NewProgressOriginalInput(assembled []byte) (ProgressOriginalInput, error) {
	if _, err := progressReplayFormat.parsePayload(assembled); err != nil {
		return ProgressOriginalInput{}, errReplayFormat
	}
	return ProgressOriginalInput{encoded: append([]byte(nil), assembled...)}, nil
}

type ProgressOriginalMatch struct {
	privateReplayRedacted
	claim       ClaimID
	plan        BoundPlan
	intent      []byte
	originalSHA [32]byte
}

func NewProgressOriginalMatch(claim ClaimID, plan BoundPlan, canonicalIntent []byte, reencodedSHA [32]byte) (ProgressOriginalMatch, error) {
	if !claim.Valid() || !plan.Valid() || len(canonicalIntent) < 2 || len(canonicalIntent) > 262144 {
		return ProgressOriginalMatch{}, errReplayFormat
	}
	return ProgressOriginalMatch{claim: claim.clone(), plan: plan.clone(), intent: append([]byte(nil), canonicalIntent...), originalSHA: reencodedSHA}, nil
}

type ProgressFrozen struct {
	privateReplayRedacted
	issuer  *PrivateReplayProgressCustody
	owner   context.Context
	initial durablePhaseTag
	frozen  PrivateReplayFrozen
}
type ProgressSealPermit struct {
	privateReplayRedacted
	issuer *PrivateReplayProgressCustody
	permit PrivateReplaySealPermit
}
type ProgressPublication struct {
	privateReplayRedacted
	issuer *PrivateReplayProgressCustody
	sealed PrivateReplayPublication
}
type ProgressAttempt struct {
	privateReplayRedacted
	token *progressAttemptState
}
type progressAttemptState struct {
	issuer      *PrivateReplayProgressCustody
	owner       context.Context
	record      durableClaimRecord
	disposition FixtureProgressDisposition
	recoverable bool
	used        atomic.Bool
}

type ProgressAccess struct {
	privateReplayRedacted
	state *progressAccessState
}
type progressAccessState struct {
	self      *ProgressAccess
	issuer    *PrivateReplayProgressCustody
	life      *progressOriginalLifetime
	original  durableClaimRecord
	confirmed durableClaimRecord
	keys      PrivateReplayKeys
	verify    func(*ProgressOriginalView) (ProgressOriginalMatch, error)
	used      atomic.Bool
}

func OpenPrivateReplayProgressCustody(ctx context.Context, root string) (*PrivateReplayProgressCustody, error) {
	rootCustody, err := OpenPrivateReplayCustody(ctx, root)
	if err != nil {
		return nil, err
	}
	out := &PrivateReplayProgressCustody{custody: rootCustody}
	out.self = out
	return out, nil
}

func (c *PrivateReplayProgressCustody) Close() error {
	if c == nil {
		return nil
	}
	if c.self != c {
		return errClaimStoreUnavailable
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.custody == nil {
		return nil
	}
	err := c.custody.Close()
	c.custody = nil
	return err
}

func (c *PrivateReplayProgressCustody) qualified(ctx context.Context) bool {
	return c.self == c && ctx.Err() == nil && c.custody != nil && c.custody.checkParents() == nil && c.custody.checkFixtureDBBudget() == nil
}

func (c *PrivateReplayProgressCustody) LookupProgressOriginal(ctx context.Context, claim ClaimID) (ProgressLookup, error) {
	if c == nil || c.self != c || !claim.Valid() || ctx.Done() == nil {
		return ProgressLookup{}, errClaimStoreUnavailable
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	if !c.qualified(ctx) {
		return ProgressLookup{}, errClaimStoreUnavailable
	}
	r, err := c.custody.store.loadClaim(ctx, loadClaimQuery{claim: claim})
	if errors.Is(err, errClaimStoreNotFound) {
		return ProgressLookup{issuer: c, owner: ctx, claim: claim.clone()}, nil
	}
	if err != nil || r.codecVersion != durableClaimCodecVersionProgress || !r.claim.Equal(claim) ||
		c.custody.checkFixtureDBBudget() != nil {
		return ProgressLookup{}, errClaimStoreUnavailable
	}
	return ProgressLookup{issuer: c, owner: ctx, claim: claim.clone(), original: r, found: true}, nil
}

func (c *PrivateReplayProgressCustody) FreezeProgressOriginal(ctx context.Context, miss ProgressLookup,
	initial FixtureProgressPhase, plan BoundPlan, keys PrivateReplayKeys, input ProgressOriginalInput) (ProgressFrozen, error) {
	if c == nil || miss.issuer != c || !miss.Absent() || !progressSameInvocation(ctx, miss.owner) ||
		(initial != FixturePendingBeforeAssignment && initial != FixtureAmbiguousBeforeAssignment) {
		return ProgressFrozen{}, errClaimStoreUnavailable
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	if !c.qualified(ctx) {
		return ProgressFrozen{}, errClaimStoreUnavailable
	}
	f, err := freezeReplayOriginal(progressReplayFormat, miss.claim, plan, keys, input.encoded)
	if err != nil {
		return ProgressFrozen{}, err
	}
	return ProgressFrozen{issuer: c, owner: ctx, initial: durablePhaseTag(initial), frozen: f}, nil
}

func progressSameInvocation(ctx context.Context, owner context.Context) bool {
	return owner != nil && owner.Done() != nil && ctx.Done() == owner.Done() && ctx.Err() == nil && owner.Err() == nil
}

func (c *PrivateReplayProgressCustody) ReserveProgressSealUse(ctx context.Context, f ProgressFrozen) (ProgressSealPermit, error) {
	if c == nil || f.issuer != c || !progressSameInvocation(ctx, f.owner) {
		return ProgressSealPermit{}, errClaimStoreUnavailable
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	if !c.qualified(ctx) || !f.frozen.valid() {
		return ProgressSealPermit{}, errClaimStoreUnavailable
	}
	p, err := c.custody.store.reserveReplaySealUse(ctx, f.frozen.keys, f.frozen.digest, false)
	if err != nil {
		return ProgressSealPermit{}, err
	}
	if ctx.Err() != nil || c.custody.checkFixtureDBBudget() != nil {
		p.burn()
		return ProgressSealPermit{}, errClaimStoreUnavailable
	}
	return ProgressSealPermit{issuer: c, permit: PrivateReplaySealPermit{permit: p}}, nil
}

func (c *PrivateReplayProgressCustody) PublishProgressOriginal(ctx context.Context, f ProgressFrozen, p ProgressSealPermit) (ProgressPublication, error) {
	if !progressSameInvocation(ctx, f.owner) || c == nil || f.issuer != c || p.issuer != c {
		p.permit.permit.burn()
		return ProgressPublication{}, errClaimStoreUnavailable
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	if !c.qualified(ctx) {
		p.permit.permit.burn()
		return ProgressPublication{}, errClaimStoreUnavailable
	}
	out, err := c.custody.publishReplayOriginal(ctx, f.frozen, p.permit)
	if err != nil {
		return ProgressPublication{}, err
	}
	return ProgressPublication{issuer: c, sealed: out}, nil
}

func (c *PrivateReplayProgressCustody) EstablishProgress(ctx context.Context, f ProgressFrozen, p ProgressPublication) (ProgressAttempt, FixtureProgressDisposition, error) {
	if c == nil || f.issuer != c || p.issuer != c || !progressSameInvocation(ctx, f.owner) {
		return ProgressAttempt{}, FixtureProgressRefused, errClaimStoreUnavailable
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	if !c.qualified(ctx) || !f.frozen.valid() {
		return ProgressAttempt{}, FixtureProgressRefused, errClaimStoreUnavailable
	}
	d := p.sealed.descriptor
	if !d.validForScope(2) || d.ref != replayObjectRef(f.frozen.objectID) || !progressKeysMatch(d, f.frozen.keys) ||
		subtle.ConstantTimeCompare(d.intentMAC[:], f.frozen.intentMAC[:]) != 1 ||
		subtle.ConstantTimeCompare(d.contextMAC[:], f.frozen.contextMAC[:]) != 1 {
		return ProgressAttempt{}, FixtureProgressRefused, errClaimStoreUnavailable
	}
	raw, err := c.custody.checkPublishedRef(ctx, f.frozen.claim, f.frozen.plan, f.frozen.keys, d)
	if err != nil || subtle.ConstantTimeCompare(raw, f.frozen.plaintext) != 1 {
		return ProgressAttempt{}, FixtureProgressRefused, errClaimStoreUnavailable
	}
	want, err := newProgressInitialClaim(f.frozen.claim, f.frozen.plan, f.initial, d, time.Now())
	if err != nil {
		return ProgressAttempt{}, FixtureProgressRefused, err
	}
	res, err := c.custody.store.establishProgressRow(ctx, want)
	state := FixtureProgressRefused
	switch {
	case res.unknown:
		state = FixtureProgressWriteUnknown
	case res.applied:
		state = FixtureProgressCommitted
	case res.occupied:
		return ProgressAttempt{}, FixtureProgressOccupied, nil
	default:
		return ProgressAttempt{}, state, err
	}
	attempt := ProgressAttempt{token: &progressAttemptState{issuer: c, owner: f.owner, record: res.record, disposition: state, recoverable: res.recoverable}}
	return attempt, state, err
}

func progressKeysMatch(d replayClaimDescriptor, k PrivateReplayKeys) bool {
	return k.valid && d.bindingKeyID == k.bindingID && d.envelopeKeyID == k.envelopeID &&
		subtle.ConstantTimeCompare(d.bindingKeyFP[:], k.bindingFP[:]) == 1 &&
		subtle.ConstantTimeCompare(d.envelopeKeyFP[:], k.envelopeFP[:]) == 1
}

func (c *PrivateReplayProgressCustody) loadOriginal(ctx context.Context, claim ClaimID, keys PrivateReplayKeys, expected durableClaimRecord, exact bool) (durableClaimRecord, []byte, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if !c.qualified(ctx) {
		return durableClaimRecord{}, nil, errClaimStoreUnavailable
	}
	record, err := c.custody.store.loadClaim(ctx, loadClaimQuery{claim: claim})
	if err != nil || !expected.sameProgressOriginal(record) || (exact && !expected.equal(record)) || !progressKeysMatch(record.replay, keys) {
		return durableClaimRecord{}, nil, errClaimStoreUnavailable
	}
	if err := c.custody.store.checkOriginalReplayKeys(ctx, keys, false); err != nil {
		return durableClaimRecord{}, nil, err
	}
	raw, err := c.custody.checkPublishedRef(ctx, claim, record.plan, keys, record.replay)
	if err != nil || ctx.Err() != nil || c.custody.checkFixtureDBBudget() != nil {
		return durableClaimRecord{}, nil, errClaimStoreUnavailable
	}
	return record, raw, nil
}

func verifyProgressOriginalMatch(ctx context.Context, raw []byte, r durableClaimRecord,
	verify func(*ProgressOriginalView) (ProgressOriginalMatch, error)) (ProgressOriginalMatch, error) {
	view, err := progressView(ctx, raw)
	if err != nil || verify == nil {
		return ProgressOriginalMatch{}, errClaimStoreUnavailable
	}
	defer view.life.closed.Store(true)
	m, err := verify(view)
	if err != nil || ctx.Err() != nil || !m.claim.Equal(r.claim) || !r.plan.EqualBinding(m.plan.Binding()) ||
		!witnessEqual(r.plan.Witness(), m.plan.Witness()) {
		return ProgressOriginalMatch{}, errClaimStoreUnavailable
	}
	digest := sha256.Sum256(raw)
	fields, err := progressReplayFormat.parsePayload(raw)
	if err != nil || subtle.ConstantTimeCompare(digest[:], m.originalSHA[:]) != 1 ||
		subtle.ConstantTimeCompare(fields[1].value, m.intent) != 1 {
		return ProgressOriginalMatch{}, errClaimStoreUnavailable
	}
	return m, nil
}

// WithAuthenticatedProgressOriginal exposes one synchronous, one-operation
// access. An establishment attempt may be confirmed only inside its owner.
func (c *PrivateReplayProgressCustody) WithAuthenticatedProgressOriginal(ctx context.Context, l ProgressLookup, k PrivateReplayKeys,
	incoming []byte, purpose ProgressAttempt, verify func(*ProgressOriginalView) (ProgressOriginalMatch, error),
	use func(*ProgressAccess) error) (FixtureProgressDisposition, error) {
	if c == nil || l.issuer != c || use == nil || !progressSameInvocation(ctx, l.owner) {
		if attempt := purpose.token; attempt != nil && c != nil && attempt.issuer == c &&
			l.issuer == c && l.claim.Equal(attempt.record.claim) && ctx.Done() == attempt.owner.Done() {
			return progressAuthenticationFailure(attempt.disposition, errClaimStoreUnavailable)
		}
		return FixtureProgressRefused, errClaimStoreUnavailable
	}
	original := l.original
	status := FixtureProgressCurrent
	confirmed := durableClaimRecord{}
	exact := false
	if attempt := purpose.token; attempt != nil {
		if attempt.issuer != c || !l.claim.Equal(attempt.record.claim) ||
			!progressSameInvocation(ctx, attempt.owner) || !attempt.used.CompareAndSwap(false, true) {
			return FixtureProgressRefused, errClaimStoreUnavailable
		}
		original, status = attempt.record, attempt.disposition
		exact = status == FixtureProgressWriteUnknown
		if exact && !attempt.recoverable {
			return status, errClaimStoreCommitUnknown
		}
		confirmed = attempt.record
	} else if !l.found {
		return FixtureProgressRefused, errClaimStoreUnavailable
	}
	r, raw, err := c.loadOriginal(ctx, l.claim, k, original, exact)
	if err != nil {
		return progressAuthenticationFailure(status, err)
	}
	m, err := verifyProgressOriginalMatch(ctx, raw, r, verify)
	if err != nil {
		return progressAuthenticationFailure(status, err)
	}
	c.mu.RLock()
	authorized := c.qualified(ctx)
	c.mu.RUnlock()
	if !authorized {
		return progressAuthenticationFailure(status, errClaimStoreUnavailable)
	}
	if subtle.ConstantTimeCompare(incoming, m.intent) != 1 {
		if exact {
			return FixtureProgressWriteUnknown, errClaimStoreCommitUnknown
		}
		return FixtureProgressConflict, errClaimStoreUnavailable
	}
	if exact {
		status = FixtureProgressOwnCommitConfirmed
	}
	life := &progressOriginalLifetime{ctx: ctx}
	access := &ProgressAccess{}
	access.state = &progressAccessState{self: access, issuer: c, life: life, original: r, confirmed: confirmed, keys: k, verify: verify}
	defer life.closed.Store(true)
	if err := use(access); err != nil {
		if exact {
			return FixtureProgressWriteUnknown, errClaimStoreCommitUnknown
		}
		return status, err
	}
	return status, nil
}

func progressAuthenticationFailure(status FixtureProgressDisposition, err error) (FixtureProgressDisposition, error) {
	switch status {
	case FixtureProgressCommitted:
		return status, err
	case FixtureProgressWriteUnknown:
		return status, errClaimStoreCommitUnknown
	default:
		return FixtureProgressRefused, err
	}
}

func (c *PrivateReplayProgressCustody) consumeProgressAccess(ctx context.Context, access *ProgressAccess) (*progressAccessState, error) {
	if c == nil || access == nil || access.state == nil {
		return nil, errClaimStoreUnavailable
	}
	state := access.state
	if state.self != access || state.issuer != c || !state.life.live() || !progressSameInvocation(ctx, state.life.ctx) ||
		!state.used.CompareAndSwap(false, true) {
		return nil, errClaimStoreUnavailable
	}
	return state, nil
}

func (c *PrivateReplayProgressCustody) ReadFixtureProgress(ctx context.Context, access *ProgressAccess) (FixtureProgress, error) {
	state, err := c.consumeProgressAccess(ctx, access)
	if err != nil {
		return FixtureProgress{}, err
	}
	if state.confirmed.progressRowID != 0 {
		c.mu.RLock()
		defer c.mu.RUnlock()
		if !state.life.live() || !c.qualified(ctx) || !progressKeysMatch(state.confirmed.replay, state.keys) {
			return FixtureProgress{}, errClaimStoreUnavailable
		}
		if err := c.custody.store.checkOriginalReplayKeys(ctx, state.keys, false); err != nil {
			return FixtureProgress{}, err
		}
		if !c.qualified(ctx) || !state.life.live() {
			return FixtureProgress{}, errClaimStoreUnavailable
		}
		return fixtureProgressProjection(state.confirmed), nil
	}
	r, err := state.reload(ctx)
	if err != nil {
		return FixtureProgress{}, err
	}
	return fixtureProgressProjection(r), nil
}

func (s *progressAccessState) reload(ctx context.Context) (durableClaimRecord, error) {
	c := s.issuer
	c.mu.RLock()
	defer c.mu.RUnlock()
	if !s.life.live() || !c.qualified(ctx) {
		return durableClaimRecord{}, errClaimStoreUnavailable
	}
	r, err := c.custody.store.loadClaim(ctx, loadClaimQuery{claim: s.original.claim})
	if err != nil || !s.original.sameProgressOriginal(r) || !progressKeysMatch(r.replay, s.keys) {
		return durableClaimRecord{}, errClaimStoreUnavailable
	}
	if err := c.custody.store.checkOriginalReplayKeys(ctx, s.keys, false); err != nil {
		return durableClaimRecord{}, err
	}
	if ctx.Err() != nil || !s.life.live() || c.custody.checkFixtureDBBudget() != nil {
		return durableClaimRecord{}, errClaimStoreUnavailable
	}
	return r, nil
}
