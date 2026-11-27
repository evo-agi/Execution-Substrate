package knownkeys_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	agsconfig "execution-substrate/ags/config"
	egsconfig "execution-substrate/egs/config"
	"execution-substrate/internal/testutil"
)

// TestAGSAndEGSRefuseASignerConfigOtherUsersCanReadOrWrite: ags.json and
// egs.json hold the private signing keys, so AGS and EGS refuse to load one
// that other users can read or write, or that is not a regular file
// (.docs/system_overview/configuration.md, "Signing keys"; red-team RT75-4
// of ES PR #75).
func TestAGSAndEGSRefuseASignerConfigOtherUsersCanReadOrWrite(t *testing.T) {
	for _, c := range []struct {
		name string
		load func(string) error
	}{
		{"ags.json", func(p string) error { _, err := agsconfig.Load(p); return err }},
		{"egs.json", func(p string) error { _, err := egsconfig.Load(p); return err }},
	} {
		var doc map[string]any
		if err := json.Unmarshal([]byte(testutil.Read(t, filepath.Join(".examples", "config", c.name))), &doc); err != nil {
			t.Fatal(err)
		}
		data, err := json.Marshal(testutil.WithFreshSigningKeys(t, doc))
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(t.TempDir(), c.name)
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		// The two documented modes: 0600 for supported-local, and 0640 with
		// the service's group for Remote Alpha. 0400 and 0440 are tighter.
		for _, mode := range []os.FileMode{0o600, 0o640, 0o400, 0o440} {
			if err := os.Chmod(path, mode); err != nil {
				t.Fatal(err)
			}
			if err := c.load(path); err != nil {
				t.Errorf("%s with mode %04o refused: %v", c.name, mode, err)
			}
		}
		// Any bit for other users is refused: read, write or execute.
		for _, mode := range []os.FileMode{0o644, 0o604, 0o602, 0o601, 0o666, 0o646, 0o777} {
			if err := os.Chmod(path, mode); err != nil {
				t.Fatal(err)
			}
			if err := c.load(path); err == nil || !strings.Contains(err.Error(), "must be a regular file that other users cannot read or write") {
				t.Errorf("%s holds a private signing key and loads with mode %04o: %v", c.name, mode, err)
			}
		}
		// A link is judged by the file it names, as the check is on the
		// opened file: a link to a private config loads, and a link to one
		// other users can read does not.
		link := filepath.Join(t.TempDir(), "link-"+c.name)
		if err := os.Symlink(path, link); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := c.load(link); err != nil {
			t.Errorf("%s: a link to a config with mode 0600 is refused: %v", c.name, err)
		}
		if err := os.Chmod(path, 0o644); err != nil {
			t.Fatal(err)
		}
		if err := c.load(link); err == nil {
			t.Errorf("%s loads through a link to a file with mode 0644", c.name)
		}
		// A folder is not a config file, even one only its owner can enter,
		// which the other-users clause would let through.
		folder := filepath.Join(t.TempDir(), "private-folder")
		if err := os.Mkdir(folder, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(folder, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := c.load(folder); err == nil || !strings.Contains(err.Error(), "must be a regular file") {
			t.Errorf("%s: a folder with mode 0700: got %v, want the refusal of a file that is not a regular file", c.name, err)
		}
	}
}
