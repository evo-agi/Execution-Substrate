package admission

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	esconfig "execution-substrate/es/config"
	"golang.org/x/sys/unix"
)

const (
	retainedResultRecordFileName = "result.commit.v1"
	retainedResultRecordMaxBytes = 512
	retainedResultRecordDomain   = "es-retained-result-commit-v1"
)

// The key is service-private. The data/record subtree may be interfered with;
// the configured key and process memory are outside that selected interference.
type retainedResultAuthenticator struct {
	storeID string
	keyID   string
	key     [sha256.Size]byte
}

type retainedResultRecord struct {
	storeID string
	keyID   string
	runID   string
	root    custodyIdentity
	run     custodyIdentity
	final   custodyIdentity
	length  uint64
	digest  [sha256.Size]byte
}

func loadRetainedResultAuthenticator(cfg esconfig.ExecutionConfig) (*retainedResultAuthenticator, error) {
	if err := cfg.RetainedResultAuth.Validate("execution.retained_result_auth", cfg.StagingRootDir, cfg.ResultsRootDir); err != nil {
		return nil, err
	}
	keyPath := cfg.RetainedResultAuth.KeyFile
	parent, err := openQualifiedDirectoryExact(filepath.Dir(keyPath))
	if err != nil {
		return nil, fmt.Errorf("retained result authentication key is unavailable")
	}
	defer parent.close()
	parentIdentity := parent.identity
	if !custodyIdentityIsDirectory(parentIdentity) ||
		(parentIdentity.UID != os.Geteuid() && parentIdentity.UID != 0) ||
		os.FileMode(parentIdentity.Mode).Perm()&0o022 != 0 {
		return nil, fmt.Errorf("retained result authentication key parent is unsafe")
	}
	name := filepath.Base(keyPath)
	var visible unix.Stat_t
	if err := unix.Fstatat(parent.fd, name, &visible, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return nil, fmt.Errorf("retained result authentication key is unavailable")
	}
	if err := validateRetainedResultKeyStat(visible); err != nil {
		return nil, err
	}
	fd, err := platformOpenAtNoFollow(parent.fd, name, unix.O_RDONLY, 0, false)
	if err != nil {
		return nil, fmt.Errorf("retained result authentication key is unavailable")
	}
	file := os.NewFile(uintptr(fd), "retained result authentication key")
	if file == nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("retained result authentication key is unavailable")
	}
	defer file.Close()
	var before unix.Stat_t
	if err := unix.Fstat(fd, &before); err != nil ||
		!sameCustodyObject(custodyIdentityFromStat(visible), custodyIdentityFromStat(before)) {
		return nil, fmt.Errorf("retained result authentication key changed during opening")
	}
	if err := validateRetainedResultKeyStat(before); err != nil {
		return nil, err
	}
	data, err := io.ReadAll(io.LimitReader(file, sha256.Size+1))
	if err != nil || len(data) != sha256.Size {
		return nil, fmt.Errorf("retained result authentication key must contain exactly 32 raw bytes")
	}
	var after unix.Stat_t
	if err := unix.Fstat(fd, &after); err != nil || !platformStatSnapshotStable(before, after) {
		return nil, fmt.Errorf("retained result authentication key changed during reading")
	}
	var afterVisible unix.Stat_t
	if err := unix.Fstatat(parent.fd, name, &afterVisible, unix.AT_SYMLINK_NOFOLLOW); err != nil ||
		!sameCustodyObject(custodyIdentityFromStat(before), custodyIdentityFromStat(afterVisible)) ||
		parent.verifyVisible() != nil {
		return nil, fmt.Errorf("retained result authentication key path changed during reading")
	}
	result := &retainedResultAuthenticator{storeID: cfg.RetainedResultAuth.StoreID, keyID: cfg.RetainedResultAuth.KeyID}
	copy(result.key[:], data)
	return result, nil
}

func validateRetainedResultKeyStat(st unix.Stat_t) error {
	identity := custodyIdentityFromStat(st)
	mode := os.FileMode(identity.Mode).Perm()
	if !custodyIdentityIsRegular(identity) || identity.Links != 1 || identity.UID != os.Geteuid() ||
		(mode != 0o400 && mode != 0o600) || st.Size != sha256.Size {
		return fmt.Errorf("retained result authentication key has unsafe identity, access or length")
	}
	return nil
}

func (auth *retainedResultAuthenticator) encodeRecord(record retainedResultRecord) []byte {
	payload := fmt.Sprintf("%s\nstore_id=%s\nkey_id=%s\nrun_id=%s\nroot=%s\nrun_dir=%s\nfinal=%s\nlength=%016x\nsha256=%x\n",
		retainedResultRecordDomain, record.storeID, record.keyID, record.runID,
		formatRetainedResultIdentity(record.root), formatRetainedResultIdentity(record.run), formatRetainedResultIdentity(record.final),
		record.length, record.digest)
	mac := hmac.New(sha256.New, auth.key[:])
	_, _ = mac.Write([]byte(payload))
	return []byte(payload + "mac=" + hex.EncodeToString(mac.Sum(nil)) + "\n")
}

func formatRetainedResultIdentity(identity custodyIdentity) string {
	typeByte := byte('?')
	switch identity.Mode & unix.S_IFMT {
	case unix.S_IFDIR:
		typeByte = 'd'
	case unix.S_IFREG:
		typeByte = 'f'
	}
	return fmt.Sprintf("%016x:%016x:%c", identity.Device, identity.Inode, typeByte)
}

func (auth *retainedResultAuthenticator) verifyRecord(data []byte) (retainedResultRecord, error) {
	const trailerBytes = len("mac=") + sha256.Size*2 + len("\n")
	if auth == nil || len(data) <= trailerBytes || len(data) > retainedResultRecordMaxBytes {
		return retainedResultRecord{}, errors.New("retained result commitment is invalid")
	}
	payload := data[:len(data)-trailerBytes]
	trailer := data[len(data)-trailerBytes:]
	if !bytes.HasPrefix(trailer, []byte("mac=")) || trailer[len(trailer)-1] != '\n' {
		return retainedResultRecord{}, errors.New("retained result commitment is invalid")
	}
	provided, err := hex.DecodeString(string(trailer[len("mac=") : len(trailer)-1]))
	if err != nil || len(provided) != sha256.Size {
		return retainedResultRecord{}, errors.New("retained result commitment is invalid")
	}
	mac := hmac.New(sha256.New, auth.key[:])
	_, _ = mac.Write(payload)
	if !hmac.Equal(mac.Sum(nil), provided) {
		return retainedResultRecord{}, errors.New("retained result commitment is invalid")
	}
	// Parse only after authentication; the record is already bounded above.
	lines := strings.Split(string(payload), "\n")
	if len(lines) != 10 || lines[9] != "" || lines[0] != retainedResultRecordDomain {
		return retainedResultRecord{}, errors.New("retained result commitment encoding is invalid")
	}
	storeID, err := retainedResultLine(lines[1], "store_id=")
	if err != nil {
		return retainedResultRecord{}, err
	}
	keyID, err := retainedResultLine(lines[2], "key_id=")
	if err != nil {
		return retainedResultRecord{}, err
	}
	runID, err := retainedResultLine(lines[3], "run_id=")
	if err != nil {
		return retainedResultRecord{}, err
	}
	rootText, err := retainedResultLine(lines[4], "root=")
	if err != nil {
		return retainedResultRecord{}, err
	}
	runText, err := retainedResultLine(lines[5], "run_dir=")
	if err != nil {
		return retainedResultRecord{}, err
	}
	finalText, err := retainedResultLine(lines[6], "final=")
	if err != nil {
		return retainedResultRecord{}, err
	}
	lengthText, err := retainedResultLine(lines[7], "length=")
	if err != nil {
		return retainedResultRecord{}, err
	}
	digestText, err := retainedResultLine(lines[8], "sha256=")
	if err != nil {
		return retainedResultRecord{}, err
	}
	if storeID != auth.storeID || keyID != auth.keyID || !runIDPattern.MatchString(runID) {
		return retainedResultRecord{}, errors.New("retained result commitment context is invalid")
	}
	root, err := parseRetainedResultIdentity(rootText, 'd')
	if err != nil {
		return retainedResultRecord{}, err
	}
	run, err := parseRetainedResultIdentity(runText, 'd')
	if err != nil {
		return retainedResultRecord{}, err
	}
	final, err := parseRetainedResultIdentity(finalText, 'f')
	if err != nil {
		return retainedResultRecord{}, err
	}
	if len(lengthText) != 16 || !isLowerHex(lengthText) || len(digestText) != sha256.Size*2 || !isLowerHex(digestText) {
		return retainedResultRecord{}, errors.New("retained result commitment values are invalid")
	}
	length, err := strconv.ParseUint(lengthText, 16, 64)
	if err != nil || length > uint64(maximumInt()) {
		return retainedResultRecord{}, errors.New("retained result commitment length is invalid")
	}
	digestBytes, err := hex.DecodeString(digestText)
	if err != nil {
		return retainedResultRecord{}, errors.New("retained result commitment digest is invalid")
	}
	var digest [sha256.Size]byte
	copy(digest[:], digestBytes)
	record := retainedResultRecord{storeID: storeID, keyID: keyID, runID: runID, root: root, run: run, final: final, length: length, digest: digest}
	if !bytes.Equal(auth.encodeRecord(record), data) {
		return retainedResultRecord{}, errors.New("retained result commitment is noncanonical")
	}
	return record, nil
}

func retainedResultLine(line string, prefix string) (string, error) {
	if !strings.HasPrefix(line, prefix) {
		return "", errors.New("retained result commitment field is invalid")
	}
	return strings.TrimPrefix(line, prefix), nil
}

func parseRetainedResultIdentity(value string, wantType byte) (custodyIdentity, error) {
	parts := strings.Split(value, ":")
	if len(parts) != 3 || len(parts[0]) != 16 || len(parts[1]) != 16 || len(parts[2]) != 1 || parts[2][0] != wantType ||
		!isLowerHex(parts[0]) || !isLowerHex(parts[1]) {
		return custodyIdentity{}, errors.New("retained result commitment identity is invalid")
	}
	device, err := strconv.ParseUint(parts[0], 16, 64)
	if err != nil {
		return custodyIdentity{}, errors.New("retained result commitment device is invalid")
	}
	inode, err := strconv.ParseUint(parts[1], 16, 64)
	if err != nil {
		return custodyIdentity{}, errors.New("retained result commitment inode is invalid")
	}
	mode := uint32(unix.S_IFDIR)
	if wantType == 'f' {
		mode = unix.S_IFREG
	}
	return custodyIdentity{Device: device, Inode: inode, Mode: mode}, nil
}

func isLowerHex(value string) bool {
	for i := 0; i < len(value); i++ {
		if (value[i] < '0' || value[i] > '9') && (value[i] < 'a' || value[i] > 'f') {
			return false
		}
	}
	return true
}

func (directory *retainedResultDirectory) readRetainedResultRecordBytes() ([]byte, bool, error) {
	if err := directory.verifyVisible(); err != nil {
		return nil, false, err
	}
	var visible unix.Stat_t
	if err := unix.Fstatat(directory.runFD, retainedResultRecordFileName, &visible, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		if errors.Is(err, unix.ENOENT) {
			return nil, false, nil
		}
		return nil, false, err
	}
	if err := directory.validateRetainedResultStat(visible, retainedResultBundleFileMode); err != nil || visible.Size > retainedResultRecordMaxBytes {
		return nil, false, errors.New("retained result commitment file is invalid")
	}
	fd, err := platformOpenAtNoFollow(directory.runFD, retainedResultRecordFileName, unix.O_RDONLY, 0, true)
	if err != nil {
		return nil, false, err
	}
	file := os.NewFile(uintptr(fd), "retained result commitment")
	if file == nil {
		_ = unix.Close(fd)
		return nil, false, errors.New("open retained result commitment")
	}
	defer file.Close()
	var before unix.Stat_t
	if err := unix.Fstat(fd, &before); err != nil || !sameCustodyObject(custodyIdentityFromStat(visible), custodyIdentityFromStat(before)) ||
		directory.validateRetainedResultStat(before, retainedResultBundleFileMode) != nil || before.Size > retainedResultRecordMaxBytes {
		return nil, false, errors.New("retained result commitment identity changed")
	}
	data, err := io.ReadAll(io.LimitReader(file, before.Size+1))
	if err != nil || int64(len(data)) != before.Size {
		return nil, false, errors.New("retained result commitment length changed")
	}
	var after unix.Stat_t
	if err := unix.Fstat(fd, &after); err != nil || !platformStatSnapshotStable(before, after) {
		return nil, false, errors.New("retained result commitment changed while reading")
	}
	var afterVisible unix.Stat_t
	if err := unix.Fstatat(directory.runFD, retainedResultRecordFileName, &afterVisible, unix.AT_SYMLINK_NOFOLLOW); err != nil ||
		!sameCustodyObject(custodyIdentityFromStat(before), custodyIdentityFromStat(afterVisible)) {
		return nil, false, errors.New("retained result commitment path changed while reading")
	}
	return data, true, nil
}

func (directory *retainedResultDirectory) publishRetainedResultRecord(data []byte) error {
	if len(data) == 0 || len(data) > retainedResultRecordMaxBytes {
		return errors.New("retained result commitment length is invalid")
	}
	if err := directory.verifyBeforeEffect(); err != nil {
		return err
	}
	token, err := randomCustodyToken()
	if err != nil {
		return err
	}
	tempName := ".commit-" + token + ".tmp"
	fd, err := platformOpenAtNoFollow(directory.runFD, tempName, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL, uint32(retainedResultBundleFileMode), true)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), "retained result commitment temporary")
	if file == nil {
		_ = unix.Close(fd)
		return errors.New("open retained result commitment temporary")
	}
	defer file.Close()
	if err := directory.verifyBeforeEffect(); err != nil {
		return err
	}
	if err := unix.Fchown(fd, directory.owner.UID, directory.owner.GID); err != nil {
		return err
	}
	if err := directory.verifyBeforeEffect(); err != nil {
		return err
	}
	if err := unix.Fchmod(fd, uint32(retainedResultBundleFileMode)); err != nil {
		return err
	}
	if err := writeAllDescriptor(fd, data); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := directory.verifyBeforeEffect(); err != nil {
		return err
	}
	if err := platformRenameNoReplace(directory.runFD, tempName, directory.runFD, retainedResultRecordFileName); err != nil && !errors.Is(err, unix.EEXIST) {
		return err
	}
	observed, exists, err := directory.readRetainedResultRecordBytes()
	if err != nil || !exists || !bytes.Equal(observed, data) {
		return errors.New("retained result commitment does not match intended record")
	}
	return nil
}
