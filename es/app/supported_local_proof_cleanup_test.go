package app_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestSupportedLocalProofCleanupRemovesOnlyOwnedScratch(t *testing.T) {
	repoRoot := executionPlatformRepoRoot(t)
	parentDir := filepath.Join(t.TempDir(), "guest-tmp")
	if err := os.MkdirAll(parentDir, 0o755); err != nil {
		t.Fatalf("mkdir parent dir: %v", err)
	}

	staleOwned := filepath.Join(parentDir, "es-proof-stale-owned")
	writeOwnedProofScratch(t, staleOwned)
	if err := os.MkdirAll(staleOwned+".bootstrap", 0o755); err != nil {
		t.Fatalf("mkdir stale bootstrap dir: %v", err)
	}

	currentOwned := filepath.Join(parentDir, "es-proof-current-owned")
	writeOwnedProofScratch(t, currentOwned)
	if err := os.MkdirAll(currentOwned+".bootstrap", 0o755); err != nil {
		t.Fatalf("mkdir current bootstrap dir: %v", err)
	}

	foreignNamed := filepath.Join(parentDir, "es-proof-foreign")
	if err := os.MkdirAll(foreignNamed, 0o755); err != nil {
		t.Fatalf("mkdir foreign dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(foreignNamed, "note.txt"), []byte("not proof-owned\n"), 0o644); err != nil {
		t.Fatalf("write foreign note: %v", err)
	}

	orphanBootstrap := filepath.Join(parentDir, "es-proof-orphan.bootstrap")
	if err := os.MkdirAll(orphanBootstrap, 0o755); err != nil {
		t.Fatalf("mkdir orphan bootstrap dir: %v", err)
	}
	fakeBin := filepath.Join(t.TempDir(), "bin")
	if err := os.Mkdir(fakeBin, 0o700); err != nil {
		t.Fatal(err)
	}
	sudoLog := filepath.Join(t.TempDir(), "fake-sudo.log")
	fakeSudo := `#!/bin/sh
printf '%s\n' "$*" >> "$FAKE_SUDO_LOG"
[ "$1" = -n ] || exit 91
shift
if [ "$1" = true ]; then exit 0; fi
if [ "$1" = rm ] && [ "$2" = -rf ] && [ "$#" = 3 ]; then
  case "$3" in
    "$FAKE_PROOF_PARENT"/es-proof-stale-owned|"$FAKE_PROOF_PARENT"/es-proof-stale-owned.bootstrap|"$FAKE_PROOF_PARENT"/es-proof-orphan.bootstrap)
      exec /bin/rm -rf "$3" ;;
  esac
fi
exit 92
`
	if err := os.WriteFile(filepath.Join(fakeBin, "sudo"), []byte(fakeSudo), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fakeBin, "ss"), []byte("#!/bin/sh\nexit 1\n"), 0o700); err != nil {
		t.Fatal(err)
	}

	helperPath := filepath.Join(repoRoot, "scripts", "internal", "supported_local_proof_cleanup.sh")
	command := exec.Command("bash", helperPath, "cleanup-stale")
	command.Dir = repoRoot
	command.Env = auditControlledScriptEnv(t,
		"PATH="+fakeBin+string(os.PathListSeparator)+auditSafeScriptPath(t),
		"FAKE_SUDO_LOG="+sudoLog,
		"FAKE_PROOF_PARENT="+parentDir,
		"SUPPORTED_LOCAL_PROOF_PARENT="+parentDir,
		"SUPPORTED_LOCAL_PROOF_DIR="+currentOwned,
		"SUPPORTED_LOCAL_CLEANUP_RUN_BRINGUP_DOWN=0",
	)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("run cleanup helper: %v output=%s", err, string(output))
	}
	text := string(output)
	if !strings.Contains(text, staleOwned) {
		t.Fatalf("expected cleanup output to mention stale dir %s, got %s", staleOwned, text)
	}
	if !strings.Contains(text, currentOwned) {
		t.Fatalf("expected cleanup output to mention preserved current dir %s, got %s", currentOwned, text)
	}
	if !strings.Contains(text, orphanBootstrap) {
		t.Fatalf("expected cleanup output to mention orphan bootstrap dir %s, got %s", orphanBootstrap, text)
	}

	assertPathRemoved(t, staleOwned)
	assertPathRemoved(t, staleOwned+".bootstrap")
	assertPathPresent(t, currentOwned)
	assertPathPresent(t, currentOwned+".bootstrap")
	assertPathPresent(t, foreignNamed)
	assertPathRemoved(t, orphanBootstrap)
	transport, err := os.ReadFile(sudoLog)
	if err != nil || strings.Count(string(transport), "-n true\n") != 3 ||
		strings.Count(string(transport), "-n rm -rf ") != 3 ||
		strings.Contains(string(transport), currentOwned) || strings.Contains(string(transport), foreignNamed) {
		t.Fatalf("cleanup privilege fixture exceeded exact owned paths: err=%v calls=%q", err, transport)
	}
}

func writeOwnedProofScratch(t *testing.T, dir string) {
	t.Helper()

	for _, path := range []string{
		dir,
		filepath.Join(dir, "bringup-state"),
		filepath.Join(dir, "workdirs"),
	} {
		if err := os.MkdirAll(path, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", path, err)
		}
	}
	for name, contents := range map[string]string{
		"env.sh":                                "export BRINGUP_DIR=\"" + filepath.Join(dir, "bringup-state") + "\"\n",
		"managed-secrets.conf":                  "PROOF_VAULT_PORT=\"18460\"\n",
		"ars.json":                              "{}\n",
		"egs.json":                              "{}\n",
		"ags.json":                              "{}\n",
		"es.json":                               "{}\n",
		"workload-zone-vault-config-digest.txt": "sha256:test\n",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(contents), 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
}

func assertPathRemoved(t *testing.T, path string) {
	t.Helper()

	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("expected %s to be removed, got %v", path, err)
	}
}

func assertPathPresent(t *testing.T, path string) {
	t.Helper()

	if _, err := os.Stat(path); err != nil {
		t.Fatalf("expected %s to remain present: %v", path, err)
	}
}
