package scripts_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	agsconfig "execution-substrate/ags/config"
	egsconfig "execution-substrate/egs/config"
	"execution-substrate/internal/testutil"
)

// The ES binary deployment runs the config checks of ES, AGS and EGS, built
// from the same tree as the binaries it installs, before it installs
// anything (scripts/internal/remote_alpha_deploy_es_binaries.sh). Each check
// is a thin wrapper around its service's config.Load, as esconfigcheck is.

const agsConfigCheckMainBody = `{
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: agsconfigcheck <absolute path to ags.json>")
		os.Exit(2)
	}
	if _, err := config.Load(os.Args[1]); err != nil {
		fmt.Fprintf(os.Stderr, "ags config refused: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("ags config accepted")
}`

const egsConfigCheckMainBody = `{
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: egsconfigcheck <absolute path to egs.json>")
		os.Exit(2)
	}
	if _, err := config.Load(os.Args[1]); err != nil {
		fmt.Fprintf(os.Stderr, "egs config refused: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("egs config accepted")
}`

// TestAGSAndEGSConfigChecksOnlyCallConfigLoad holds agsconfigcheck and
// egsconfigcheck to the rules esconfigcheck follows: if one grew checks of
// its own, the deployment could pass a config its service refuses, or stop
// on one it accepts.
func TestAGSAndEGSConfigChecksOnlyCallConfigLoad(t *testing.T) {
	requireThinConfigCheck(t, "agsconfigcheck", "scripts/internal/agsconfigcheck/main.go", "execution-substrate/ags/config", agsConfigCheckMainBody)
	requireThinConfigCheck(t, "egsconfigcheck", "scripts/internal/egsconfigcheck/main.go", "execution-substrate/egs/config", egsConfigCheckMainBody)
}

// TestAGSAndEGSConfigChecksAgreeWithConfigLoad runs each built check on its
// example with fresh keys and on configs config.Load refuses, among them the
// example with the repository's published keys and a copy others can read,
// and requires the check's answer and reason to be config.Load's own.
func TestAGSAndEGSConfigChecksAgreeWithConfigLoad(t *testing.T) {
	for _, svc := range []struct {
		name string
		load func(string) error
	}{
		{"ags", func(path string) error { _, err := agsconfig.Load(path); return err }},
		{"egs", func(path string) error { _, err := egsconfig.Load(path); return err }},
	} {
		t.Run(svc.name, func(t *testing.T) {
			helper := buildConfigCheck(t, svc.name+"configcheck")
			published := testutil.Read(t, ".examples/config/"+svc.name+".json")
			var fresh map[string]any
			if err := json.Unmarshal([]byte(published), &fresh); err != nil {
				t.Fatal(err)
			}
			example, err := json.MarshalIndent(testutil.WithFreshSigningKeys(t, fresh), "", "  ")
			if err != nil {
				t.Fatal(err)
			}
			mutate := func(edit func(map[string]any)) []byte {
				var doc map[string]any
				if err := json.Unmarshal(example, &doc); err != nil {
					t.Fatal(err)
				}
				edit(doc)
				out, err := json.MarshalIndent(doc, "", "  ")
				if err != nil {
					t.Fatal(err)
				}
				return out
			}
			signer := func(doc map[string]any) map[string]any { return doc["signer"].(map[string]any) }
			cases := []struct {
				name string
				data []byte
				mode os.FileMode
			}{
				{"example with fresh keys", example, 0o600},
				{"example with fresh keys, group-readable", example, 0o640},
				{"unknown field", mutate(func(d map[string]any) { d["extra"] = true }), 0o600},
				{"trailing data", append(append([]byte{}, example...), []byte("{}")...), 0o600},
				{"a known signing key", mutate(func(d map[string]any) {
					signer(d)["private_key_hex"] = strings.Repeat("07", 32)
				}), 0o600},
				{"readable by others", example, 0o644},
				// A box still on the repository's published keys is refused
				// here, so the deployment stops until its keys are rotated.
				{"published signing keys", []byte(published), 0o600},
			}
			accepted := 0
			for _, tc := range cases {
				t.Run(tc.name, func(t *testing.T) {
					path := filepath.Join(t.TempDir(), svc.name+".json")
					if err := os.WriteFile(path, tc.data, 0o600); err != nil {
						t.Fatal(err)
					}
					if err := os.Chmod(path, tc.mode); err != nil {
						t.Fatal(err)
					}
					loadErr := svc.load(path)
					var stdout, stderr bytes.Buffer
					cmd := exec.Command(helper, path)
					cmd.Dir = t.TempDir()
					cmd.Stdout, cmd.Stderr = &stdout, &stderr
					runErr := cmd.Run()
					if loadErr == nil {
						accepted++
						if runErr != nil || stdout.String() != svc.name+" config accepted\n" || stderr.Len() != 0 {
							t.Fatalf("config.Load accepts it but the check said %v, stdout %q, stderr %q", runErr, stdout.String(), stderr.String())
						}
						return
					}
					var exitErr *exec.ExitError
					if !errors.As(runErr, &exitErr) || exitErr.ExitCode() != 1 {
						t.Fatalf("config.Load refuses it (%v) but the check exited with %v", loadErr, runErr)
					}
					if want := svc.name + " config refused: " + loadErr.Error() + "\n"; stderr.String() != want || stdout.Len() != 0 {
						t.Fatalf("the check said stdout %q, stderr %q; want stderr %q", stdout.String(), stderr.String(), want)
					}
				})
			}
			if accepted != 2 {
				t.Fatalf("config.Load accepted %d of the cases, want the 2 examples with fresh keys", accepted)
			}
		})
	}
}
