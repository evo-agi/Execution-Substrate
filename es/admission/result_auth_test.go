package admission

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"

	esconfig "execution-substrate/es/config"
	"golang.org/x/sys/unix"
)

func syntheticResultAuthenticator() *retainedResultAuthenticator {
	return &retainedResultAuthenticator{
		storeID: "test_store",
		keyID:   "test_key",
		key:     [32]byte{1, 2, 3, 4, 5, 6, 7, 8, 9},
	}
}

func TestRetainedResultAuthRecordRejectsNoncanonicalAndUnauthenticatedBytes(t *testing.T) {
	auth := syntheticResultAuthenticator()
	record := retainedResultRecord{
		storeID: "test_store",
		keyID:   "test_key",
		runID:   "run-0123456789abcdef",
		root:    custodyIdentity{Device: 1, Inode: 2, Mode: unix.S_IFDIR},
		run:     custodyIdentity{Device: 1, Inode: 3, Mode: unix.S_IFDIR},
		final:   custodyIdentity{Device: 1, Inode: 4, Mode: unix.S_IFREG},
		length:  17,
		digest:  sha256.Sum256([]byte("synthetic payload")),
	}
	encoded := auth.encodeRecord(record)
	if len(encoded) > retainedResultRecordMaxBytes {
		t.Fatalf("record exceeded bounded format: %d", len(encoded))
	}
	got, err := auth.verifyRecord(encoded)
	if err != nil || got != record {
		t.Fatalf("canonical record did not verify: got=%+v err=%v", got, err)
	}
	for _, test := range []struct {
		name string
		data []byte
	}{
		{"truncated", encoded[:len(encoded)-1]},
		{"trailing", append(bytes.Clone(encoded), '\n')},
		{"forged", bytes.Replace(bytes.Clone(encoded), []byte("length=0000000000000011"), []byte("length=0000000000000012"), 1)},
		{"unknown version", bytes.Replace(bytes.Clone(encoded), []byte("commit-v1"), []byte("commit-v2"), 1)},
		{"oversized", bytes.Repeat([]byte{'x'}, retainedResultRecordMaxBytes+1)},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := auth.verifyRecord(test.data); err == nil {
				t.Fatal("invalid completion record authenticated")
			}
		})
	}
	wrongKey := *auth
	wrongKey.key[0] ^= 1
	if _, err := wrongKey.verifyRecord(encoded); err == nil {
		t.Fatal("different key authenticated an existing record")
	}
	signedPayload := encoded[:bytes.LastIndex(encoded, []byte("mac="))]
	for _, test := range []struct {
		name    string
		payload []byte
	}{
		{"signed unknown version", bytes.Replace(bytes.Clone(signedPayload), []byte("commit-v1"), []byte("commit-v2"), 1)},
		{"signed uppercase digest", bytes.Replace(bytes.Clone(signedPayload), []byte("sha256="+hex.EncodeToString(record.digest[:])), []byte("sha256=A"+hex.EncodeToString(record.digest[:])[1:]), 1)},
		{"signed duplicate field", append(bytes.Clone(signedPayload), []byte("length=0000000000000011\n")...)},
	} {
		t.Run(test.name, func(t *testing.T) {
			mac := hmac.New(sha256.New, auth.key[:])
			_, _ = mac.Write(test.payload)
			signed := append(bytes.Clone(test.payload), []byte("mac="+hex.EncodeToString(mac.Sum(nil))+"\n")...)
			if _, err := auth.verifyRecord(signed); err == nil {
				t.Fatal("authenticated but noncanonical completion record was accepted")
			}
		})
	}
}

func TestRetainedResultAuthKeyLoadRejectsUnsafeFiles(t *testing.T) {
	root := physicalTestTempDir(t)
	stage := filepath.Join(root, "stage")
	results := filepath.Join(root, "results")
	keyDir := filepath.Join(root, "auth")
	for _, path := range []string{stage, results, keyDir} {
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	keyPath := filepath.Join(keyDir, "key")
	key := bytes.Repeat([]byte{0x53}, 32)
	if err := os.WriteFile(keyPath, key, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := esconfig.ExecutionConfig{
		StagingRootDir: stage,
		ResultsRootDir: results,
		RetainedResultAuth: esconfig.RetainedResultAuthConfig{
			StoreID: "test_store", KeyID: "test_key", KeyFile: keyPath,
		},
	}
	auth, err := loadRetainedResultAuthenticator(cfg)
	if err != nil || auth == nil || !bytes.Equal(auth.key[:], key) {
		t.Fatalf("safe synthetic key did not load: auth=%v err=%v", auth != nil, err)
	}
	if err := os.WriteFile(keyPath, bytes.Repeat([]byte{0x44}, 32), 0o600); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(auth.key[:], key) {
		t.Fatal("loaded key changed after provisioned file mutation")
	}
	if err := os.WriteFile(keyPath, key[:31], 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadRetainedResultAuthenticator(cfg); err == nil {
		t.Fatal("short key was accepted")
	}
	if err := os.WriteFile(keyPath, key, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(keyPath, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadRetainedResultAuthenticator(cfg); err == nil {
		t.Fatal("world-readable key was accepted")
	}
	if err := os.Remove(keyPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(root, "missing"), keyPath); err != nil {
		t.Fatal(err)
	}
	if _, err := loadRetainedResultAuthenticator(cfg); err == nil {
		t.Fatal("symlinked key was accepted")
	}
}

func TestRetainedResultReviewKeyLoaderPreservesSpaceBearingParent(t *testing.T) {
	root := physicalTestTempDir(t)
	stage := filepath.Join(root, "stage")
	results := filepath.Join(root, "results")
	exactParent := filepath.Join(root, "auth ")
	trimmedParent := filepath.Join(root, "auth")
	for _, path := range []string{stage, results, exactParent, trimmedParent} {
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	exactPath := filepath.Join(exactParent, "key")
	trimmedPath := filepath.Join(trimmedParent, "key")
	exactKey := bytes.Repeat([]byte{0x53}, sha256.Size)
	trimmedKey := bytes.Repeat([]byte{0x67}, sha256.Size)
	if err := os.WriteFile(trimmedPath, trimmedKey, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := esconfig.ExecutionConfig{
		StagingRootDir:     stage + " ",
		ResultsRootDir:     " " + results + " ",
		RetainedResultAuth: esconfig.RetainedResultAuthConfig{StoreID: "test_store", KeyID: "test_key", KeyFile: exactPath},
	}
	if auth, err := loadRetainedResultAuthenticator(cfg); err == nil || auth != nil || strings.Contains(err.Error(), exactPath) {
		t.Fatalf("absent exact key path substituted trimmed alternative: auth=%v err=%v", auth != nil, err)
	}
	if err := os.WriteFile(exactPath, exactKey, 0o600); err != nil {
		t.Fatal(err)
	}
	auth, err := loadRetainedResultAuthenticator(cfg)
	if err != nil || auth == nil || !bytes.Equal(auth.key[:], exactKey) || bytes.Equal(auth.key[:], trimmedKey) {
		t.Fatalf("loader did not use exact space-bearing parent: auth=%v err=%v", auth != nil, err)
	}
	for _, rootPath := range []string{stage, results} {
		cfg.RetainedResultAuth.KeyFile = filepath.Join(rootPath, "key")
		if auth, err := loadRetainedResultAuthenticator(cfg); err == nil || auth != nil || strings.Contains(err.Error(), cfg.RetainedResultAuth.KeyFile) {
			t.Fatalf("loader accepted key inside effective root: auth=%v err=%v", auth != nil, err)
		}
	}
}

func TestRetainedResultReviewKeyLoaderPreservesSpaceBearingAncestor(t *testing.T) {
	workspace := physicalTestTempDir(t)
	stage := filepath.Join(workspace, "stage")
	results := filepath.Join(workspace, "results")
	exactAncestor := filepath.Join(workspace, "auth ")
	otherAncestor := filepath.Join(workspace, "auth")
	for _, path := range []string{stage, results, otherAncestor, filepath.Join(otherAncestor, "keys")} {
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	exactPath := filepath.Join(exactAncestor, "keys", "key")
	otherPath := filepath.Join(otherAncestor, "keys", "key")
	exactKey := bytes.Repeat([]byte{0x53}, sha256.Size)
	otherKey := bytes.Repeat([]byte{0x67}, sha256.Size)
	if err := os.WriteFile(otherPath, otherKey, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := esconfig.ExecutionConfig{
		StagingRootDir: " " + stage + " ",
		ResultsRootDir: results + " ",
		RetainedResultAuth: esconfig.RetainedResultAuthConfig{
			StoreID: "test_store", KeyID: "test_key", KeyFile: exactPath,
		},
	}
	assertRefused := func(reason string) {
		t.Helper()
		auth, err := loadRetainedResultAuthenticator(cfg)
		if err == nil || auth != nil {
			t.Fatalf("%s accepted an unsafe or missing exact key", reason)
		}
		if strings.Contains(err.Error(), exactPath) || strings.Contains(err.Error(), otherPath) ||
			strings.Contains(err.Error(), string(exactKey)) || strings.Contains(err.Error(), string(otherKey)) {
			t.Fatalf("%s disclosed key material or path", reason)
		}
	}
	assertRefused("missing exact hierarchy")
	for _, path := range []string{exactAncestor, filepath.Join(exactAncestor, "keys")} {
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	assertRefused("missing exact key")
	if err := os.WriteFile(exactPath, exactKey, 0o600); err != nil {
		t.Fatal(err)
	}
	auth, err := loadRetainedResultAuthenticator(cfg)
	if err != nil || auth == nil || !bytes.Equal(auth.key[:], exactKey) || bytes.Equal(auth.key[:], otherKey) {
		t.Fatalf("exact nested key was not loaded: auth=%v err=%v", auth != nil, err)
	}
	if err := os.Remove(exactPath); err != nil {
		t.Fatal(err)
	}
	assertRefused("exact key removed")
	if err := os.Rename(exactAncestor, filepath.Join(workspace, "displaced-auth")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(otherAncestor, exactAncestor); err != nil {
		t.Fatal(err)
	}
	assertRefused("symlinked exact ancestor")
	otherAfter, err := os.ReadFile(otherPath)
	if err != nil || !bytes.Equal(otherAfter, otherKey) {
		t.Fatalf("loader changed alternative key fixture: err=%v", err)
	}
	if info, err := os.Lstat(exactAncestor); err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("loader changed symlink fixture: info=%v err=%v", info, err)
	}
}

func TestRetainedResultAuthPublicReaderRejectsIncompleteAndAlteredPairs(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(t *testing.T, service *Service, locator executionLocator)
	}{
		{"unmarked final", func(t *testing.T, s *Service, l executionLocator) {
			if err := os.Remove(filepath.Join(s.retainedResultRunDir(l), retainedResultRecordFileName)); err != nil {
				t.Fatal(err)
			}
		}},
		{"record only", func(t *testing.T, s *Service, l executionLocator) {
			if err := os.Remove(s.retainedResultBundlePath(l)); err != nil {
				t.Fatal(err)
			}
		}},
		{"forged record", func(t *testing.T, s *Service, l executionLocator) {
			path := filepath.Join(s.retainedResultRunDir(l), retainedResultRecordFileName)
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			data[len(data)-2] ^= 1
			if err := os.WriteFile(path, data, 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{"mutated final", func(t *testing.T, s *Service, l executionLocator) {
			path := s.retainedResultBundlePath(l)
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			data[0] ^= 1
			if err := os.WriteFile(path, data, 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{"replaced final with same bytes", func(t *testing.T, s *Service, l executionLocator) {
			path := s.retainedResultBundlePath(l)
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(path, path+".displaced"); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, data, 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{"wrong store", func(t *testing.T, s *Service, l executionLocator) {
			s.resultAuth.storeID = "other_store"
		}},
		{"wrong key identifier", func(t *testing.T, s *Service, l executionLocator) {
			s.resultAuth.keyID = "other_key"
		}},
		{"wrong key", func(t *testing.T, s *Service, l executionLocator) {
			s.resultAuth.key[0] ^= 1
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			service, locator, _ := newResultTestService(t)
			writeRetainedResultBundleBytes(t, service, locator, []byte("synthetic committed bytes"))
			test.mutate(t, service, locator)
			bundle, err := service.Result(context.Background(), locator.RunID)
			if err == nil || err.Status != http.StatusConflict || err.Code != codeResultUnavailable || len(bundle.Payload) != 0 {
				t.Fatalf("incomplete or altered pair was served: bundle=%q err=%+v", bundle.Payload, err)
			}
		})
	}
}

func TestRetainedResultReviewHeldFileRejectsLateMetadataChange(t *testing.T) {
	for _, test := range []struct {
		name      string
		change    func(t *testing.T, finalPath string)
		wantMode  os.FileMode
		wantLinks uint64
	}{
		{"mode", func(t *testing.T, finalPath string) {
			if err := os.Chmod(finalPath, 0o644); err != nil {
				t.Fatal(err)
			}
		}, 0o644, 1},
		{"hard_link", func(t *testing.T, finalPath string) {
			if err := os.Link(finalPath, finalPath+".extra"); err != nil {
				t.Fatal(err)
			}
		}, 0o600, 2},
	} {
		t.Run(test.name, func(t *testing.T) {
			service, locator, _ := newResultTestService(t)
			writeRetainedResultBundleBytes(t, service, locator, []byte("synthetic committed bytes"))
			finalPath := service.retainedResultBundlePath(locator)
			recordPath := filepath.Join(service.retainedResultRunDir(locator), retainedResultRecordFileName)
			recordBytes, err := os.ReadFile(recordPath)
			if err != nil {
				t.Fatal(err)
			}
			record, err := service.resultAuth.verifyRecord(recordBytes)
			if err != nil {
				t.Fatal(err)
			}
			directory, exists, err := openRetainedResultDirectory(service.cfg.Execution.ResultsRootDir, locator.RunID, executionPlatformStateOwner{UID: os.Getuid(), GID: os.Getgid()}, false)
			if err != nil || !exists {
				t.Fatalf("open retained directory: exists=%t err=%v", exists, err)
			}
			defer directory.close()
			payload, ok, err := directory.readRegularFileExpectedWithHook(resultBundleFileName, &record, func() error {
				test.change(t, finalPath)
				return nil
			})
			if err == nil || ok || len(payload) != 0 {
				t.Fatalf("late metadata change passed held read: ok=%t payload=%q err=%v", ok, payload, err)
			}
			bundle, publicErr := service.Result(context.Background(), locator.RunID)
			if publicErr == nil || publicErr.Status != http.StatusConflict || publicErr.Code != codeResultUnavailable || len(bundle.Payload) != 0 {
				t.Fatalf("late metadata change was publicly served: bundle=%q err=%+v", bundle.Payload, publicErr)
			}
			info, err := os.Lstat(finalPath)
			if err != nil || info.Mode().Perm() != test.wantMode {
				t.Fatalf("reader repaired or unlinked final: info=%v err=%v", info, err)
			}
			stat, ok := info.Sys().(*syscall.Stat_t)
			if !ok || uint64(stat.Nlink) != test.wantLinks {
				t.Fatalf("reader changed final link count: stat=%v", stat)
			}
			if after, err := os.ReadFile(recordPath); err != nil || !bytes.Equal(after, recordBytes) {
				t.Fatalf("reader changed completion record: err=%v", err)
			}
		})
	}
}

func TestRetainedResultAuthReaderNeedsVerifierEvenForExistingPair(t *testing.T) {
	service, locator, _ := newResultTestService(t)
	writeRetainedResultBundleBytes(t, service, locator, []byte("synthetic committed bytes"))
	// An exact struct copy of the unlocked Service models a restart with the
	// same retained state. Reflection keeps vet's copylocks check enabled for
	// every ordinary assignment.
	var restarted Service
	reflect.ValueOf(&restarted).Elem().Set(reflect.ValueOf(service).Elem())
	restarted.resultAuth = syntheticResultAuthenticator()
	bundle, err := restarted.Result(context.Background(), locator.RunID)
	if err != nil || string(bundle.Payload) != "synthetic committed bytes" {
		t.Fatalf("same-key restart could not read pair: bundle=%q err=%+v", bundle.Payload, err)
	}
	restarted.resultAuth = nil
	bundle, err = restarted.Result(context.Background(), locator.RunID)
	if err == nil || err.Status != http.StatusConflict || len(bundle.Payload) != 0 {
		t.Fatalf("missing verifier served pair: bundle=%q err=%+v", bundle.Payload, err)
	}
}

func TestRetainedResultAuthCrossRunRecordIsUnavailable(t *testing.T) {
	service, first, _ := newResultTestService(t)
	second := newExecutionLocatorFromRunID("run-fedcba9876543210")
	writeRetainedResultBundleBytes(t, service, first, []byte("shared bytes"))
	writeRetainedResultBundleBytes(t, service, second, []byte("shared bytes"))
	firstRecord, err := os.ReadFile(filepath.Join(service.retainedResultRunDir(first), retainedResultRecordFileName))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(service.retainedResultRunDir(second), retainedResultRecordFileName), firstRecord, 0o600); err != nil {
		t.Fatal(err)
	}
	bundle, resultErr := service.Result(context.Background(), second.RunID)
	if resultErr == nil || resultErr.Status != http.StatusConflict || len(bundle.Payload) != 0 {
		t.Fatalf("cross-run record replay was served: bundle=%q err=%+v", bundle.Payload, resultErr)
	}
}

func TestRetainedResultAuthPreexistingUnmarkedFinalIsNeverAdopted(t *testing.T) {
	service, locator, _ := newResultTestService(t)
	custody, _ := claimTestStagingCustody(t, service.cfg.Execution.StagingRootDir, locator.RunID)
	if err := custody.writeFile("run/result/summary.txt", []byte("stable result"), stableStageFileMode); err != nil {
		t.Fatal(err)
	}
	if err := custody.close(); err != nil {
		t.Fatal(err)
	}
	if retained, err := service.retainTerminalResult(locator); err != nil || !retained {
		t.Fatalf("first retention: %t %v", retained, err)
	}
	recordPath := filepath.Join(service.retainedResultRunDir(locator), retainedResultRecordFileName)
	if err := os.Remove(recordPath); err != nil {
		t.Fatal(err)
	}
	if retained, err := service.retainTerminalResult(locator); err == nil || retained {
		t.Fatalf("pre-existing unmarked final was adopted: retained=%t err=%v", retained, err)
	}
	if _, err := os.Lstat(recordPath); !os.IsNotExist(err) {
		t.Fatalf("unmarked final gained record: %v", err)
	}
	bundle, resultErr := service.Result(context.Background(), locator.RunID)
	if resultErr == nil || resultErr.Status != http.StatusConflict || len(bundle.Payload) != 0 {
		t.Fatalf("unmarked final was served: bundle=%q err=%+v", bundle.Payload, resultErr)
	}
}

func TestRetainedResultAuthRecordHasNoSecretOrKeyPath(t *testing.T) {
	service, locator, _ := newResultTestService(t)
	writeRetainedResultBundleBytes(t, service, locator, []byte("synthetic committed bytes"))
	data, err := os.ReadFile(filepath.Join(service.retainedResultRunDir(locator), retainedResultRecordFileName))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, service.resultAuth.key[:]) || strings.Contains(string(data), service.cfg.Execution.RetainedResultAuth.KeyFile) {
		t.Fatal("private record contains key material or key path")
	}
}
