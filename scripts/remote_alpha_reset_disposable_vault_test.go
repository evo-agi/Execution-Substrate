package executionsubstrate_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestRemoteAlphaResetDisposableVaultStaticSafety(t *testing.T) {
	scriptPath := filepath.Join(executionSubstrateRepoRoot, "scripts", "remote_alpha_reset_disposable_vault.sh")
	if _, err := os.Stat(scriptPath); err != nil {
		t.Fatalf("reset helper missing: %v", err)
	}
	if got, forbidden := filepath.Base(scriptPath), "remote_alpha_operator.sh"; got == forbidden {
		t.Fatalf("reset helper must not be the future operator facade path %q", forbidden)
	}

	source := mustRead(t, scriptPath)
	assertContainsAll(t, "reset helper source", source,
		"set +x",
		"umask 077",
		`MODE="dry-run"`,
		`CONFIRMATION_PHRASE="RESET DISPOSABLE REMOTE ALPHA VAULT"`,
		"--execute-reset",
		"--unseal-only",
		"--post-unseal-check",
		`backup_path="${VAULT_RAFT_PATH}.remote-alpha-reset-backup-${timestamp}"`,
		`sudo mv -- "${VAULT_RAFT_PATH}" "${backup_path}"`,
		`sudo install -d -o "${vault_user}" -g "${vault_group}" -m 0700 -- "${VAULT_RAFT_PATH}"`,
		`""|"/"|"/var"|"/var/lib"|"/opt"|"/home"|"/etc"|"/usr"|"/tmp")`,
		`remote_alpha_vault_workload_auth_check.sh`,
		`sudo "${checker}"`,
	)

	for _, forbidden := range []string{
		"--root-token",
		"--unseal-key",
		"--client-token",
		"--vault-token",
		"--api-key",
		"--jwt-svid",
	} {
		if strings.Contains(source, forbidden) {
			t.Fatalf("reset helper must not accept secret-bearing flag %q", forbidden)
		}
	}

	assertContainsNone(t, "reset helper source", source,
		`rm -rf -- "${VAULT_RAFT_PATH}"`,
		"vault auth enable",
		"vault secrets enable",
		"vault policy write",
		"vault kv put",
		"vault write auth/",
		"vault write proof-secrets",
	)

	var initCommands []string
	var unsealCommands []string
	for _, line := range strings.Split(source, "\n") {
		trimmed := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(trimmed, "vault operator init"):
			initCommands = append(initCommands, trimmed)
		case strings.HasPrefix(trimmed, "vault operator unseal"):
			unsealCommands = append(unsealCommands, trimmed)
		}
	}
	if len(initCommands) == 0 {
		t.Fatal("reset helper has no static vault operator init invocation")
	}
	for _, command := range initCommands {
		if command != "vault operator init -key-shares=1 -key-threshold=1" {
			t.Fatalf("vault operator init must not carry key/token material, got %q", command)
		}
	}
	if len(unsealCommands) == 0 {
		t.Fatal("reset helper has no static vault operator unseal invocation")
	}
	for _, command := range unsealCommands {
		if command != "vault operator unseal" {
			t.Fatalf("vault operator unseal must not carry key/token material, got %q", command)
		}
	}
}

func TestRemoteAlphaResetDisposableVaultHelpDocumentsSafeModes(t *testing.T) {
	scriptPath := filepath.Join(executionSubstrateRepoRoot, "scripts", "remote_alpha_reset_disposable_vault.sh")
	cmd := exec.Command("/bin/bash", scriptPath, "--help")
	cmd.Dir = executionSubstrateRepoRoot
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("--help failed: %v\n%s", err, output)
	}

	help := compactText(string(output))
	assertContainsAll(t, "reset helper help", help,
		"Read-only checks only. This is the default.",
		"--execute-reset",
		"--unseal-only",
		"--post-unseal-check",
		"Repo-supported workload-auth checker path for --post-unseal-check.",
		"it must not be used as production Vault lifecycle automation",
	)
	assertContainsNone(t, "reset helper help", help,
		"--root-token",
		"--unseal-key",
		"--client-token",
		"--vault-token",
		"--api-key",
		"--jwt-svid",
	)
}

func TestRemoteAlphaResetDisposableVaultPrintsMacRefreshCommandOnly(t *testing.T) {
	scriptPath := filepath.Join(executionSubstrateRepoRoot, "scripts", "remote_alpha_reset_disposable_vault.sh")
	source := mustRead(t, scriptPath)
	section := docSection(t, source, "print_mac_refresh_command() {", "\n}\n\nwhile [[ $# -gt 0 ]]; do")

	assertContainsAll(t, "reset helper Mac refresh printer", section,
		"cat <<'EOF'",
		"After this script completes, run these commands on the Mac:",
		`cd "/Users/ds/Repositories/Infrastructure Manager"`,
		"PYTHONPATH=src python3 -m infra_manager.cli remote-alpha-live-refresh",
		`--profile-dir ".out/remote-alpha-m75q"`,
		"--ssh-alias host_to_remote_linux_m75q",
	)
}
