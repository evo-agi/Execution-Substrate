// Package testutil holds helpers that only tests use: the repository root,
// reading and searching the repository's documents, and giving an example
// configuration fresh signing keys. Only test files import it, which a test
// of this package checks.
//
// go test runs the tests of a package in the package's directory. A test
// outside the repository root therefore names a repository file through
// Path or Read, which resolve a relative path against Root, and never by
// changing the working directory: the go test cache does not see a change
// of directory made while a test binary starts, so after a file changed it
// could replay a stale result. The tests of this package check that the
// packages which import it name no repository path relative to their own
// directory and start no command there, and that the repository root keeps
// only its docs tests: the tests of the scripts live in scripts/.
package testutil

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"testing"
)

// Root is the absolute path of the repository root.
var Root = mustRoot()

func mustRoot() string {
	_, sourceFile, _, ok := runtime.Caller(0)
	if !ok || sourceFile == "" || !filepath.IsAbs(sourceFile) {
		panic("testutil: cannot resolve an absolute path for its own source file")
	}
	root := filepath.Dir(filepath.Dir(filepath.Dir(sourceFile)))
	module, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if err != nil {
		panic("testutil: repository root " + root + " has no readable go.mod: " + err.Error())
	}
	if !strings.HasPrefix(string(module), "module execution-substrate\n") {
		panic("testutil: " + filepath.Join(root, "go.mod") + " is not the go.mod of module execution-substrate")
	}
	return root
}

// Path returns an absolute path. A relative path names a file of the
// repository.
func Path(path string) string {
	if filepath.IsAbs(path) {
		return path
	}
	return filepath.Join(Root, path)
}

// Read returns the content of a file. A relative path names a file of the
// repository.
func Read(t testing.TB, path string) string {
	t.Helper()
	data, err := os.ReadFile(Path(path))
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(data)
}

// Compact joins the words of a text with single spaces.
func Compact(text string) string {
	return strings.Join(strings.Fields(text), " ")
}

// Section returns the part of a document that starts at the first start
// and ends before the next end. An empty end means the end of the
// document.
func Section(t testing.TB, doc string, start string, end string) string {
	t.Helper()

	startIndex := strings.Index(doc, start)
	if startIndex == -1 {
		t.Fatalf("document section start %q not found", start)
	}
	section := doc[startIndex:]
	if end == "" {
		return section
	}
	endIndex := strings.Index(section, end)
	if endIndex == -1 {
		t.Fatalf("document section end %q not found after %q", end, start)
	}
	return section[:endIndex]
}

// CompactSection is Section followed by Compact.
func CompactSection(t testing.TB, doc string, start string, end string) string {
	t.Helper()
	return Compact(Section(t, doc, start, end))
}

// ContainsAll fails the test when text lacks any of the required phrases.
func ContainsAll(t testing.TB, label string, text string, required ...string) {
	t.Helper()

	for _, phrase := range required {
		if !strings.Contains(text, phrase) {
			t.Fatalf("%s missing %q", label, phrase)
		}
	}
}

// ContainsNone fails the test when text holds any of the forbidden phrases.
func ContainsNone(t testing.TB, label string, text string, forbidden ...string) {
	t.Helper()

	for _, phrase := range forbidden {
		if strings.Contains(text, phrase) {
			t.Fatalf("%s must not contain %q", label, phrase)
		}
	}
}

// testSigningKeys holds, for each running test, the key it generated for
// each key ID, so that every call of WithFreshSigningKeys in one test gives a
// key ID the same key.
var testSigningKeys sync.Map // testing.TB -> *testKeys

type testKeys struct {
	mu   sync.Mutex
	byID map[string]ed25519.PrivateKey
}

// WithFreshSigningKeys gives doc, a decoded AGS, EGS or ES configuration,
// signing keys generated for this test, and returns doc. It replaces the
// private and public key of "signer" and the public key of every entry of
// "verification", and keeps every key ID. Within one test a key ID always
// gets the same key: entries that share a key ID, as AGS's provenance key is
// shared by three ES entries, get the same new key, and a test that builds
// the same configuration twice gets the same bytes.
//
// The repository's example configurations carry known keys, which AGS, EGS
// and ES refuse (.docs/system_overview/contracts.md, section 3B), so a test
// that needs an example its service accepts calls this first.
func WithFreshSigningKeys(t testing.TB, doc map[string]any) map[string]any {
	t.Helper()
	stored, loaded := testSigningKeys.LoadOrStore(t, &testKeys{byID: map[string]ed25519.PrivateKey{}})
	if !loaded {
		t.Cleanup(func() { testSigningKeys.Delete(t) })
	}
	cache := stored.(*testKeys)
	cache.mu.Lock()
	defer cache.mu.Unlock()
	keys := cache.byID
	key := func(keyID any) ed25519.PrivateKey {
		id, ok := keyID.(string)
		if !ok || id == "" {
			t.Fatalf("WithFreshSigningKeys: an entry has no key_id")
		}
		if keys[id] == nil {
			_, private, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatalf("WithFreshSigningKeys: generate a key: %v", err)
			}
			keys[id] = private
		}
		return keys[id]
	}
	public := func(private ed25519.PrivateKey) string {
		return hex.EncodeToString(private.Public().(ed25519.PublicKey))
	}
	replaced := 0
	if signer, ok := doc["signer"].(map[string]any); ok {
		private := key(signer["key_id"])
		signer["private_key_hex"] = hex.EncodeToString(private.Seed())
		signer["public_key_hex"] = public(private)
		replaced++
	}
	if verification, ok := doc["verification"].(map[string]any); ok {
		names := make([]string, 0, len(verification))
		for name := range verification {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			entry, ok := verification[name].(map[string]any)
			if !ok {
				t.Fatalf("WithFreshSigningKeys: verification.%s is not an object", name)
			}
			entry["public_key_hex"] = public(key(entry["key_id"]))
			replaced++
		}
	}
	if replaced == 0 {
		t.Fatalf("WithFreshSigningKeys: the configuration has no signer and no verification keys")
	}
	return doc
}
