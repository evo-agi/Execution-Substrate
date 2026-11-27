package knownkeys_test

import (
	"encoding/hex"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"unicode/utf8"

	"execution-substrate/internal/knownkeys"
	"execution-substrate/internal/testutil"
)

// repositoryFiles lists the files of the repository as slash-separated paths
// relative to its root: git's tracked files when the root holds git
// metadata, and otherwise, as in a tree unpacked from a source archive, every
// file in the tree.
func repositoryFiles(t *testing.T) []string {
	t.Helper()
	if _, err := os.Lstat(filepath.Join(testutil.Root, ".git")); err == nil {
		cmd := exec.Command("git", "ls-files", "-z")
		cmd.Dir = testutil.Root
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("git ls-files: %v; the repository root has .git, so git must be able to list its files", err)
		}
		var files []string
		for _, file := range strings.Split(strings.TrimSuffix(string(out), "\x00"), "\x00") {
			if file != "" {
				files = append(files, file)
			}
		}
		return files
	}
	var files []string
	err := filepath.WalkDir(testutil.Root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.Type().IsRegular() {
			rel, err := filepath.Rel(testutil.Root, path)
			if err != nil {
				return err
			}
			files = append(files, filepath.ToSlash(rel))
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return files
}

// signingKeyValue finds a hex value given to a signing key field, in the
// spellings the repository uses: JSON and Python ("private_key_hex": "..."),
// Go struct literals (PrivateKeyHex: "...") and shell or Markdown
// (private_key_hex=...).
var signingKeyValue = regexp.MustCompile(`(?i)\b(private_?key_?hex|public_?key_?hex)\b["'` + "`" + `]?\s*[:=]\s*["'` + "`" + `]?([0-9a-f]{128}|[0-9a-f]{64})\b`)

// TestRepositoryShipsNoSigningKeyAServiceAccepts is the guard for each host
// having its own signing keys (.docs/system_overview/configuration.md,
// "Signing keys"). Every signing key value in a file outside the tests is a
// known key, one that AGS, EGS and ES refuse at startup
// (.docs/system_overview/contracts.md, section 3B). So no configuration the
// repository ships or a script writes can put a fixed key into a real
// install: a script that generates keys holds none, and an example's keys
// stop the service until the host gives it its own.
//
// Go test files may hold fixed keys: they reach no install. Every Go test
// that starts AGS, EGS or ES generates its keys.
func TestRepositoryShipsNoSigningKeyAServiceAccepts(t *testing.T) {
	files := repositoryFiles(t)
	examplesWithKeys := map[string]bool{}
	for _, file := range files {
		if strings.HasSuffix(file, "_test.go") {
			continue
		}
		data, err := os.ReadFile(testutil.Path(filepath.FromSlash(file)))
		if errors.Is(err, fs.ErrNotExist) {
			// A tracked file deleted in the working tree holds no key.
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		if !utf8.Valid(data) || strings.ContainsRune(string(data), 0) {
			continue
		}
		for _, match := range signingKeyValue.FindAllStringSubmatch(string(data), -1) {
			field, value := strings.ToLower(strings.ReplaceAll(match[1], "_", "")), match[2]
			key, err := hex.DecodeString(value)
			if err != nil {
				t.Fatal(err)
			}
			if field == "privatekeyhex" {
				err = knownkeys.CheckPrivate(match[1], key)
			} else {
				err = knownkeys.Check(match[1], key)
			}
			if err == nil {
				t.Errorf("%s: %s %s... is a signing key that AGS, EGS and ES would accept; the repository may ship only known keys outside Go tests, and an install generates its own", file, match[1], value[:8])
			}
			if strings.HasPrefix(file, ".examples/config/") {
				examplesWithKeys[file] = true
			}
		}
	}
	// The scan must see the keys it guards against: the example templates.
	for _, file := range []string{".examples/config/ags.json", ".examples/config/egs.json", ".examples/config/es.json"} {
		if !examplesWithKeys[file] {
			t.Errorf("the scan found no signing key in %s; the pattern no longer matches the repository's spelling", file)
		}
	}
}

// TestSupportedLocalSetupWritesNoFixedSigningKey: the supported-local setup
// script names no key value at all; the keys of each install come from
// scripts/internal/signingkeygen.
func TestSupportedLocalSetupWritesNoFixedSigningKey(t *testing.T) {
	setup := testutil.Read(t, filepath.Join("scripts", "72_supported_local_setup.sh"))
	if match := signingKeyValue.FindString(setup); match != "" {
		t.Fatalf("scripts/72_supported_local_setup.sh holds a signing key value: %.40s...", match)
	}
	for _, want := range []string{
		"generate_supported_local_signing_keys \"${PROOF_DIR}\"",
		"go run ./scripts/internal/signingkeygen \"${role}\"",
		"\"signer\": ags_signer,",
		"\"signer\": egs_signer,",
		"\"allowed_signers\": [ags_signer[\"key_id\"]]",
		"\"provenance\": verifier(ags_signer),",
		"\"trust_model\": verifier(egs_signer),",
	} {
		if !strings.Contains(setup, want) {
			t.Fatalf("scripts/72_supported_local_setup.sh no longer contains %q", want)
		}
	}
}
