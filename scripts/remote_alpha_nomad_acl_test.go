package scripts_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const remoteAlphaObserverNomadToken = "7a6b5c4d-3e2f-4a1b-9c8d-7e6f5a4b3c2d"

// The Remote Alpha runtime image check reads node status from an
// ACL-enforcing Nomad with the read-only observer token named by
// NOMAD_TOKEN_FILE. The token reaches the nomad CLI only through its
// environment, and a token file that is a symbolic link is refused before
// the CLI runs.
func TestRemoteAlphaRuntimeImageNomadMetaUsesTheObserverToken(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	fakeBin := filepath.Join(tmpDir, "bin")
	if err := os.MkdirAll(fakeBin, 0o755); err != nil {
		t.Fatal(err)
	}
	calls := filepath.Join(tmpDir, "nomad-calls")
	writeExecutable(t, fakeBin, "nomad", `#!/bin/sh
printf 'call\n' >> "$FAKE_NOMAD_CALLS"
case "$*" in *"`+remoteAlphaObserverNomadToken+`"*) echo "token on the command line" >&2; exit 2 ;; esac
if [ "${NOMAD_TOKEN:-}" != "`+remoteAlphaObserverNomadToken+`" ]; then
  echo "Permission denied" >&2
  exit 1
fi
printf '[{"ID":"node-1","Status":"ready"}]\n'
`)
	tokenDir := filepath.Join(tmpDir, "nomad-acl")
	if err := os.Mkdir(tokenDir, 0o700); err != nil {
		t.Fatal(err)
	}
	tokenFile := filepath.Join(tokenDir, "observer-token")
	if err := os.WriteFile(tokenFile, []byte(remoteAlphaObserverNomadToken+"\n"), 0o400); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(tokenDir, "observer-link")
	if err := os.Symlink(tokenFile, link); err != nil {
		t.Fatal(err)
	}

	meta := func(tokenEnv string) string {
		t.Helper()
		env := envWithPath(fakeBin, "FAKE_NOMAD_CALLS="+calls, "NOMAD_TOKEN=", "NOMAD_TOKEN_FILE="+tokenEnv)
		output, err := runSourcedRuntimeImageHelper(t, env, "remote_alpha_runtime_image_nomad_meta")
		if err != nil {
			t.Fatalf("nomad meta failed: %v output=%s", err, output)
		}
		if strings.Contains(string(output), remoteAlphaObserverNomadToken) {
			t.Fatal("observer token entered the nomad summary")
		}
		return string(output)
	}
	callCount := func() int {
		data, err := os.ReadFile(calls)
		if os.IsNotExist(err) {
			return 0
		}
		if err != nil {
			t.Fatal(err)
		}
		return strings.Count(string(data), "call\n")
	}

	if got := meta(tokenFile); !strings.Contains(got, `"ready": true`) || !strings.Contains(got, `"ready_nodes": 1`) {
		t.Fatalf("node status with the observer token was not ready: %s", got)
	}
	if got := meta(""); !strings.Contains(got, "nomad node status did not succeed") {
		t.Fatalf("node status without a token was not refused by the ACL Nomad: %s", got)
	}
	before := callCount()
	if got := meta(link); !strings.Contains(got, "nomad observer token file is missing or invalid") {
		t.Fatalf("symbolic-link token file was accepted: %s", got)
	}
	if callCount() != before {
		t.Fatal("a symbolic-link token file reached the nomad CLI")
	}
}
