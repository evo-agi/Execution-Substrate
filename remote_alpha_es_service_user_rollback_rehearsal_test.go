package executionsubstrate_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func runESServiceUserRollbackRehearsalScript(t *testing.T, evidenceDir string) ([]byte, error) {
	t.Helper()

	scriptPath := filepath.Join(executionSubstrateRepoRoot, "scripts", "remote_alpha_es_service_user_rollback_rehearsal.sh")
	cmd := exec.Command("/bin/bash", scriptPath, "--evidence-dir", evidenceDir)
	cmd.Dir = executionSubstrateRepoRoot
	return cmd.CombinedOutput()
}

func copyRollbackRehearsalFixture(t *testing.T, name string) string {
	t.Helper()

	srcDir := filepath.Join(executionSubstrateRepoRoot, "testdata", "remote_alpha_es_service_user_rollback_rehearsal", name)
	dstDir := filepath.Join(t.TempDir(), name)
	if err := os.MkdirAll(dstDir, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", dstDir, err)
	}

	entries, err := os.ReadDir(srcDir)
	if err != nil {
		t.Fatalf("read fixture dir %s: %v", srcDir, err)
	}
	for _, entry := range entries {
		if entry.IsDir() {
			t.Fatalf("unexpected nested dir in fixture %s: %s", srcDir, entry.Name())
		}
		srcPath := filepath.Join(srcDir, entry.Name())
		dstPath := filepath.Join(dstDir, entry.Name())
		data, err := os.ReadFile(srcPath)
		if err != nil {
			t.Fatalf("read fixture file %s: %v", srcPath, err)
		}
		if err := os.WriteFile(dstPath, data, 0o644); err != nil {
			t.Fatalf("write fixture file %s: %v", dstPath, err)
		}
	}

	return dstDir
}

func readRollbackRehearsalArtifact(t *testing.T, evidenceDir string) map[string]any {
	t.Helper()
	return readJSONFile(t, filepath.Join(evidenceDir, "es-service-user-rollback-rehearsal.json"))
}

func TestRemoteAlphaESServiceUserRollbackRehearsalPassFixture(t *testing.T) {
	t.Parallel()

	evidenceDir := copyRollbackRehearsalFixture(t, "pass")
	output, err := runESServiceUserRollbackRehearsalScript(t, evidenceDir)
	if err != nil {
		t.Fatalf("rollback rehearsal script failed:\n%s", string(output))
	}

	payload := readRollbackRehearsalArtifact(t, evidenceDir)
	if got := payload["overall_classification"]; got != "pass" {
		t.Fatalf("expected overall pass, got %v\noutput=%s", got, string(output))
	}

	checks := nestedMap(t, payload, "checks")
	if got := nestedClassification(t, checks, "current_intended_dropin_bounded"); got != "pass" {
		t.Fatalf("expected bounded drop-in pass, got %s", got)
	}
	if got := nestedClassification(t, checks, "old_root_era_state_preserved"); got != "pass" {
		t.Fatalf("expected old-root preservation pass, got %s", got)
	}

	markdownPath := filepath.Join(evidenceDir, "es-service-user-rollback-rehearsal.md")
	markdown := mustRead(t, markdownPath)
	for _, required := range []string{
		"Overall classification: `pass`",
		"`current_intended_dropin_bounded`: `pass`",
		"Local evidence only; no SSH, sudo, live-host mutation, rollback execution, ES apply, governed proof, or PR/merge prep occurred.",
	} {
		if !strings.Contains(markdown, required) {
			t.Fatalf("markdown artifact missing %q\n%s", required, markdown)
		}
	}
}

func TestRemoteAlphaESServiceUserRollbackRehearsalWarningFixture(t *testing.T) {
	t.Parallel()

	evidenceDir := copyRollbackRehearsalFixture(t, "warning")
	output, err := runESServiceUserRollbackRehearsalScript(t, evidenceDir)
	if err != nil {
		t.Fatalf("warning fixture should not fail the script:\n%s", string(output))
	}

	payload := readRollbackRehearsalArtifact(t, evidenceDir)
	if got := payload["overall_classification"]; got != "warning" {
		t.Fatalf("expected overall warning, got %v\noutput=%s", got, string(output))
	}

	checks := nestedMap(t, payload, "checks")
	if got := nestedClassification(t, checks, "writable_state_backup_and_quarantine_referenced"); got != "warning" {
		t.Fatalf("expected writable-state quarantine warning, got %s", got)
	}
	if got := nestedClassification(t, checks, "old_root_era_state_preserved"); got != "warning" {
		t.Fatalf("expected old-root preservation warning, got %s", got)
	}
}

func TestRemoteAlphaESServiceUserRollbackRehearsalBlockerFixture(t *testing.T) {
	t.Parallel()

	evidenceDir := copyRollbackRehearsalFixture(t, "blocker")
	output, err := runESServiceUserRollbackRehearsalScript(t, evidenceDir)
	if err == nil {
		t.Fatalf("blocker fixture should fail the script\noutput=%s", string(output))
	}

	payload := readRollbackRehearsalArtifact(t, evidenceDir)
	if got := payload["overall_classification"]; got != "blocker" {
		t.Fatalf("expected overall blocker, got %v\noutput=%s", got, string(output))
	}

	checks := nestedMap(t, payload, "checks")
	if got := nestedClassification(t, checks, "no_recursive_chown_or_broad_deletion_required"); got != "blocker" {
		t.Fatalf("expected unsafe-instruction blocker, got %s", got)
	}
}

func TestRemoteAlphaESServiceUserRollbackRehearsalBlocksDropinDrift(t *testing.T) {
	t.Parallel()

	evidenceDir := copyRollbackRehearsalFixture(t, "pass")
	checkOnlyPath := filepath.Join(evidenceDir, "es-service-user-migration-check-only.json")
	payload := readJSONFile(t, checkOnlyPath)
	plan := jsonMap(t, payload["plan"])
	plan["planned_service_dropin_lines"] = []string{
		"[Service]",
		"User=es",
		"Group=es",
		"UMask=0027",
		"Environment=UNEXPECTED=1",
	}
	writeJSONFile(t, checkOnlyPath, payload)

	output, err := runESServiceUserRollbackRehearsalScript(t, evidenceDir)
	if err == nil {
		t.Fatalf("drop-in drift should fail the script\noutput=%s", string(output))
	}

	rehearsal := readRollbackRehearsalArtifact(t, evidenceDir)
	checks := nestedMap(t, rehearsal, "checks")
	if got := nestedClassification(t, checks, "current_intended_dropin_bounded"); got != "blocker" {
		t.Fatalf("expected current_intended_dropin_bounded blocker, got %s", got)
	}
}
