package executionsubstrate_test

import (
	"crypto/sha256"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func remoteAlphaOperatorScriptPath() string {
	return filepath.Join(executionSubstrateRepoRoot, "scripts", "remote_alpha_operator.sh")
}

func runRemoteAlphaOperator(args ...string) (string, error) {
	scriptPath := remoteAlphaOperatorScriptPath()
	cmd := exec.Command("/bin/bash", append([]string{scriptPath}, args...)...)
	cmd.Dir = executionSubstrateRepoRoot
	output, err := cmd.CombinedOutput()
	return string(output), err
}

func runRemoteAlphaOperatorWithEnv(env []string, args ...string) (string, error) {
	scriptPath := remoteAlphaOperatorScriptPath()
	cmd := exec.Command("/bin/bash", append([]string{scriptPath}, args...)...)
	cmd.Dir = executionSubstrateRepoRoot
	cmd.Env = env
	output, err := cmd.CombinedOutput()
	return string(output), err
}

func runRemoteAlphaOperatorWithPTY(t *testing.T, env []string, args ...string) (string, error) {
	t.Helper()
	scriptPath := remoteAlphaOperatorScriptPath()
	python := `
import os
import pty
import subprocess
import sys

repo_root = os.environ["ES_REPO_ROOT"]
cmd = sys.argv[1:]
master_fd, slave_fd = pty.openpty()
proc = subprocess.Popen(cmd, cwd=repo_root, stdin=slave_fd, stdout=slave_fd, stderr=slave_fd)
os.close(slave_fd)
chunks = []
while True:
    try:
        data = os.read(master_fd, 4096)
    except OSError:
        break
    if not data:
        break
    chunks.append(data)
os.close(master_fd)
status = proc.wait()
sys.stdout.buffer.write(b"".join(chunks))
sys.exit(status)
`
	commandArgs := append([]string{"-c", python, "/bin/bash", scriptPath}, args...)
	cmd := exec.Command("python3", commandArgs...)
	cmd.Dir = executionSubstrateRepoRoot
	cmd.Env = append(env, "ES_REPO_ROOT="+executionSubstrateRepoRoot)
	output, err := cmd.CombinedOutput()
	return string(output), err
}

func requireRemoteAlphaOperatorSuccess(t *testing.T, args ...string) string {
	t.Helper()
	output, err := runRemoteAlphaOperator(args...)
	if err != nil {
		t.Fatalf("remote_alpha_operator.sh %v failed: %v\n%s", args, err, output)
	}
	return output
}

func requireRemoteAlphaOperatorFailure(t *testing.T, args ...string) string {
	t.Helper()
	output, err := runRemoteAlphaOperator(args...)
	if err == nil {
		t.Fatalf("remote_alpha_operator.sh %v unexpectedly succeeded:\n%s", args, output)
	}
	return output
}

func remoteAlphaOperatorRouteArtifactPaths(extraDirs ...string) []string {
	dirs := append([]string{filepath.Join(".out", "remote-alpha-m75q")}, extraDirs...)
	names := []string{
		"es-writable-state-readiness.json",
		"es-writable-state-readiness-helper-staging-record.json",
	}
	var paths []string
	for _, dir := range dirs {
		paths = append(paths, filepath.Join(executionSubstrateRepoRoot, dir))
		for _, name := range names {
			paths = append(paths, filepath.Join(executionSubstrateRepoRoot, dir, name))
		}
	}
	return paths
}

func snapshotPathExistence(t *testing.T, paths ...string) map[string]bool {
	t.Helper()
	snapshot := make(map[string]bool, len(paths))
	for _, path := range paths {
		if _, err := os.Stat(path); err == nil {
			snapshot[path] = true
		} else if os.IsNotExist(err) {
			snapshot[path] = false
		} else {
			t.Fatalf("stat %s: %v", path, err)
		}
	}
	return snapshot
}

func assertNoNewPaths(t *testing.T, label string, before map[string]bool) {
	t.Helper()
	for path, existedBefore := range before {
		if existedBefore {
			continue
		}
		if _, err := os.Stat(path); err == nil {
			t.Fatalf("%s created generated artifact path %s", label, path)
		} else if !os.IsNotExist(err) {
			t.Fatalf("stat %s: %v", path, err)
		}
	}
}

func TestRemoteAlphaOperatorExistsExecutableAndHelpDocumentsP0kScope(t *testing.T) {
	scriptPath := remoteAlphaOperatorScriptPath()
	info, err := os.Stat(scriptPath)
	if err != nil {
		t.Fatalf("operator script missing: %v", err)
	}
	if info.Mode()&0o111 == 0 {
		t.Fatalf("operator script should be executable or intended executable, mode=%v", info.Mode())
	}

	help := requireRemoteAlphaOperatorSuccess(t, "--help")
	assertContainsAll(t, "operator help", help,
		"Remote Alpha operator facade",
		"P0q adds recovery-session vault-workload-auth-bootstrap --ssh-target <target> --execute-bootstrap --interactive-tty as a Mac-side staged bootstrap route",
		"P0r adds recovery-session runtime-identity-summary --ssh-target <target> --interactive-tty",
		"P0s adds recovery-session es-service-tls-status and es-service-tls-renew",
		"P0t adds recovery-session es-governance-tls-status and es-governance-tls-renew",
		"P0u adds recovery-session operator-healthcheck-tls-status and operator-healthcheck-tls-renew",
		"bounded proof/support helper",
		"evidence/projection only",
		"no authority source",
		"The human remains the operator",
		"bounded ES Remote Alpha operator facade/workflow",
		"minimize manual stitching, copying, and recovery sequencing; not eliminate prompts",
		"Explicit interactive modes are allowed only when named, bounded, visible, and secret-safe",
		"Noninteractive sudo is an ergonomic optimization, not a universal success criterion",
		"Outputs are evidence/projection/diagnostics only, never authority",
		"help",
		"inventory",
		"print-refresh-command",
		"print-support-bundle-command",
		"print-im-commands",
		"es-writable-state-readiness-check",
		"readiness-session",
		"recovery-session",
		"recovery-session vault-unseal-existing --host-local",
		"recovery-session vault-unseal-existing --ssh-target <user@host> --interactive-tty",
		"recovery-session vault-reset-disposable --ssh-target <user@host> --dry-run",
		"recovery-session vault-reset-disposable --ssh-target <user@host> --execute-reset --interactive-tty",
		"recovery-session vault-workload-auth-check --ssh-target <user@host> --interactive-tty",
		"recovery-session vault-workload-auth-bootstrap [--help|--plan|--inventory]",
		"recovery-session vault-workload-auth-bootstrap --ssh-target <user@host> --prepare-summary-path --interactive-tty",
		"recovery-session vault-workload-auth-bootstrap --ssh-target <user@host> --prepare-config-readability --interactive-tty",
		"recovery-session vault-workload-auth-bootstrap --ssh-target <user@host> --prepare-spire-bundle-read --interactive-tty",
		"recovery-session vault-workload-auth-bootstrap --ssh-target <user@host> --execute-bootstrap --prepare-summary-path --prepare-config-readability --prepare-spire-bundle-read --interactive-tty",
		"recovery-session vault-workload-auth-bootstrap --ssh-target <user@host> --execute-bootstrap --interactive-tty",
		"recovery-session runtime-identity-summary --ssh-target <user@host> --interactive-tty",
		"recovery-session es-service-tls-status --ssh-target <user@host> --interactive-tty",
		"recovery-session es-service-tls-renew --ssh-target <user@host> --interactive-tty --execute-renew",
		"recovery-session es-governance-tls-status --ssh-target <user@host> --interactive-tty",
		"recovery-session es-governance-tls-renew --ssh-target <user@host> --interactive-tty --execute-renew",
		"recovery-session operator-healthcheck-tls-status --ssh-target <user@host> --interactive-tty",
		"recovery-session operator-healthcheck-tls-renew --ssh-target <user@host> --interactive-tty --execute-renew",
		"Implemented through P0s, P0t, and P0u",
		"delegates only to scripts/remote_alpha_stage_es_writable_state_readiness_check.sh",
		"check-only/non-mutating",
		"requires --ssh-target",
		"runs the existing readiness route",
		"fresh output directory by default",
		"prints only non-secret artifact metadata",
		"safe/local recovery skeleton",
		"schema-aware local evidence-check",
		"host-local vault-unseal-existing",
		"Mac-side interactive TTY vault-unseal-existing",
		"Mac-side vault-reset-disposable dry-run planning",
		"Mac-side destructive vault-reset-disposable execute-reset",
		"Mac-side vault-workload-auth-check",
		"safe vault-workload-auth-bootstrap planning",
		"bounded vault-workload-auth-bootstrap summary-path, config-readability, and SPIRE bundle-read preparation",
		"Mac-side vault-workload-auth-bootstrap execution",
		"Mac-side runtime-identity-summary",
		"bounded es-service-tls status/renew",
		"bounded es-governance-tls status/renew",
		"bounded operator-healthcheck-tls status/renew",
		"fixed workload-auth public/internal helper pair",
		"fixed bootstrap public/internal helper pair",
		"fixed public runtime identity helper",
		"fixed TLS renewal public/internal helper pair",
		"helper's --dry-run mode",
		"helper's --execute-reset mode",
		"supports --plan, --inventory, --next-steps",
		"writes no operator summary",
		"preserves es-writable-state-readiness.json",
		"es-writable-state-readiness-helper-staging-record.json",
		"--profile-dir .out/remote-alpha-m75q",
		"--output-root .out/remote-alpha-m75q/support-bundles",
		"--ssh-alias host_to_remote_linux_m75q",
		"does not invoke IM refresh or support-bundle collection",
		"does not add ES Vault token brokerage, runtime identity generation, service-user, generic config/TLS deployment, binary deployment, writable-state ownership, or generic helper dispatch",
	)
}

func TestRemoteAlphaOperatorInventoryClassifiesImplementedFutureAndBlockedSurfaces(t *testing.T) {
	inventory := requireRemoteAlphaOperatorSuccess(t, "inventory")
	assertContainsAll(t, "operator inventory", inventory,
		"implemented through P0q plus P0r plus P0s plus P0t plus P0u",
		"help",
		"inventory",
		"print-refresh-command",
		"print-support-bundle-command",
		"print-im-commands",
		"es-writable-state-readiness-check",
		"readiness-session",
		"recovery-session",
		"delegates to existing readiness staged helper",
		"runs the existing readiness route",
		"check-only/non-mutating",
		"preserves es-writable-state-readiness.json and es-writable-state-readiness-helper-staging-record.json",
		"prints non-secret paths, byte counts, SHA-256 digests, schemas, blocker/warning counts, and sudo/checker status",
		"safe/local skeleton for recovery sequencing",
		"schema-aware local JSON evidence interpretation",
		"runs explicit vault-unseal-existing modes",
		"recovery-session vault-unseal-existing --host-local",
		"recovery-session vault-unseal-existing --ssh-target <target> --interactive-tty",
		"recovery-session vault-reset-disposable --ssh-target <target> --dry-run",
		"recovery-session vault-reset-disposable --ssh-target <target> --execute-reset --interactive-tty",
		"recovery-session vault-workload-auth-check --ssh-target <target> --interactive-tty",
		"recovery-session vault-workload-auth-bootstrap [--help|--plan|--inventory]",
		"recovery-session vault-workload-auth-bootstrap --ssh-target <target> --prepare-summary-path --interactive-tty",
		"bounded filesystem preparation route",
		"may trigger an OS sudo prompt",
		"recovery-session vault-workload-auth-bootstrap --ssh-target <target> --prepare-config-readability --interactive-tty",
		"fixed-path user ACLs",
		"recovery-session vault-workload-auth-bootstrap --ssh-target <target> --prepare-spire-bundle-read --interactive-tty",
		"fixed SPIRE server bundle-read command",
		"recovery-session vault-workload-auth-bootstrap --ssh-target <target> --execute-bootstrap --prepare-summary-path --prepare-config-readability --prepare-spire-bundle-read --interactive-tty",
		"prepare the bootstrap summary path, then config readability, then SPIRE bundle-read access",
		"recovery-session vault-workload-auth-bootstrap --ssh-target <target> --execute-bootstrap --interactive-tty",
		"recovery-session runtime-identity-summary --ssh-target <target> --interactive-tty",
		"recovery-session es-service-tls-status --ssh-target <target> --interactive-tty",
		"recovery-session es-service-tls-renew --ssh-target <target> --interactive-tty --execute-renew",
		"recovery-session es-governance-tls-status --ssh-target <target> --interactive-tty",
		"recovery-session es-governance-tls-renew --ssh-target <target> --interactive-tty --execute-renew",
		"recovery-session operator-healthcheck-tls-status --ssh-target <target> --interactive-tty",
		"recovery-session operator-healthcheck-tls-renew --ssh-target <target> --interactive-tty --execute-renew",
		"stages only scripts/remote_alpha_reset_disposable_vault.sh",
		"invokes only --unseal-only through ssh -tt",
		"invokes only --dry-run",
		"invokes only --execute-reset through ssh -tt",
		"scripts/remote_alpha_vault_workload_auth_check.sh",
		"scripts/internal/remote_alpha_vault_workload_auth_check.sh",
		"invokes only the staged public workload-auth helper through ssh -tt",
		"canonical summary remote at /var/tmp/execution-substrate-remote-alpha/vault-workload-auth-summary.json",
		"not workload-auth bootstrap",
		"not ES token brokerage",
		"safe local/print-only planning surface",
		"Mac-side staged bootstrap route",
		"invokes only the staged public bootstrap helper through ssh -tt",
		"not workload-auth success",
		"stages only scripts/remote_alpha_vault_workload_auth_bootstrap.sh and scripts/internal/remote_alpha_vault_workload_auth_bootstrap.sh",
		"canonical bootstrap summary remote at /var/tmp/execution-substrate-remote-alpha/vault-workload-auth-bootstrap-summary.json",
		"stages only scripts/remote_alpha_runtime_identity_helper_summary.sh",
		"canonical summary remote at /var/tmp/execution-substrate-remote-alpha/runtime-identity-helper-summary.json",
		"scripts/remote_alpha_es_service_tls_renew.sh",
		"scripts/internal/remote_alpha_es_service_tls_renew.sh",
		"canonical summary remote at /var/tmp/execution-substrate-remote-alpha/es-service-tls-renew-summary.json",
		"bounded internal ARS artifact-registry mTLS recovery only",
		"leaves the canonical summary remote at /var/tmp/execution-substrate-remote-alpha/es-governance-tls-renew-summary.json",
		"bounded ES -> EGS execution-governance trust-model mTLS material",
		"es-governance-tls status/renew is bounded ES -> EGS trust-model mTLS recovery only",
		"scripts/remote_alpha_operator_healthcheck_tls_renew.sh",
		"scripts/internal/remote_alpha_operator_healthcheck_tls_renew.sh",
		"canonical summary remote at /var/tmp/execution-substrate-remote-alpha/operator-healthcheck-tls-renew-summary.json",
		"operator-healthcheck-tls status/renew is bounded host-local operator healthcheck client TLS recovery only",
		"no transcript",
		"secret-sensitive",
		"destructive",
		"non-destructive",
		"vault-reset-disposable --execute-reset is destructive and must be run only when the operator intentionally wants to reset disposable Remote Alpha Vault state",
		"Vault service-user check/apply execution",
		"other staged ES helper delegation",
		"blocked/reopened",
		"vault-workload-auth-bootstrap execution",
		"bounded proof/support helper",
		"evidence/projection only",
		"no authority source",
		"implemented, future, and blocked entries are operator-workflow/evidence surfaces, not authority surfaces",
		"interactive operator involvement is expected where an explicit mode says so",
		"IM refresh and support-bundle steps remain separate IM evidence/provenance actions unless a later reviewed contract says otherwise",
		"vault-reset-disposable --dry-run is non-destructive planning only",
		"does not stop Vault, move raft storage, init or unseal Vault, run post-unseal checks, run IM, or collect support bundles",
		"vault-reset-disposable --execute-reset is destructive and must be run only when the operator intentionally wants to reset disposable Remote Alpha Vault state",
		"vault-workload-auth-check is separate post-reset evidence/projection only",
		"vault-workload-auth-bootstrap configures expected Vault objects only",
		"runtime-identity-summary is separate evidence/projection only",
		"not reset/unseal",
		"not readiness authority",
		"RESET DISPOSABLE REMOTE ALPHA VAULT",
		"must not make IM a remote reconciler, CP a Vault/runtime recovery authority, ES a Vault token broker, or Remote Alpha a deployment architecture",
	)
}

func TestRemoteAlphaOperatorPrintRefreshCommandIsInert(t *testing.T) {
	output := requireRemoteAlphaOperatorSuccess(t, "print-refresh-command")
	assertContainsAll(t, "print-refresh-command output", output,
		"Mac-side Infrastructure Manager live refresh command",
		"printed only",
		"cd \"/Users/ds/Repositories/Infrastructure Manager\"",
		"PYTHONPATH=src python3 -m infra_manager.cli remote-alpha-live-refresh \\",
		"--profile-dir \".out/remote-alpha-m75q\" \\",
		"--ssh-alias \"host_to_remote_linux_m75q\"",
	)
	assertContainsNone(t, "print-refresh-command output", output,
		"executed",
		"collected",
	)
}

func TestRemoteAlphaOperatorPrintSupportBundleCommandIsInert(t *testing.T) {
	output := requireRemoteAlphaOperatorSuccess(t, "print-support-bundle-command")
	assertContainsAll(t, "print-support-bundle-command output", output,
		"Mac-side Infrastructure Manager support-bundle command",
		"printed only",
		"cd \"/Users/ds/Repositories/Infrastructure Manager\"",
		"PYTHONPATH=src python3 -m infra_manager.cli remote-alpha-live-support-bundle \\",
		"--profile-dir \".out/remote-alpha-m75q\" \\",
		"--output-root \".out/remote-alpha-m75q/support-bundles\"",
	)
	assertContainsNone(t, "print-support-bundle-command output", output,
		"executed",
		"collected",
	)
}

func TestRemoteAlphaOperatorPrintIMCommandsPrintsBothCommands(t *testing.T) {
	output := requireRemoteAlphaOperatorSuccess(t, "print-im-commands")
	assertContainsAll(t, "print-im-commands output", output,
		"Mac-side Infrastructure Manager live refresh command",
		"remote-alpha-live-refresh",
		"--ssh-alias \"host_to_remote_linux_m75q\"",
		"Mac-side Infrastructure Manager support-bundle command",
		"remote-alpha-live-support-bundle",
		"--output-root \".out/remote-alpha-m75q/support-bundles\"",
	)
}

func TestRemoteAlphaOperatorCustomPrintOptionsOnlyAffectPrintedText(t *testing.T) {
	output := requireRemoteAlphaOperatorSuccess(t,
		"print-im-commands",
		"--profile-dir", "custom profiles/alpha",
		"--output-root", "custom bundles/alpha",
		"--ssh-alias", "custom_alias",
	)
	assertContainsAll(t, "custom print-im-commands output", output,
		"--profile-dir \"custom profiles/alpha\"",
		"--output-root \"custom bundles/alpha\"",
		"--ssh-alias \"custom_alias\"",
	)
	assertContainsNone(t, "custom print-im-commands output", output,
		"--profile-dir \".out/remote-alpha-m75q\"",
		"--output-root \".out/remote-alpha-m75q/support-bundles\"",
		"--ssh-alias \"host_to_remote_linux_m75q\"",
	)

	inventory := requireRemoteAlphaOperatorSuccess(t,
		"inventory",
		"--profile-dir", "custom profiles/alpha",
		"--output-root", "custom bundles/alpha",
		"--ssh-alias", "custom_alias",
	)
	assertContainsNone(t, "custom inventory output", inventory,
		"custom profiles/alpha",
		"custom bundles/alpha",
		"custom_alias",
	)
}

func TestRemoteAlphaOperatorRejectsSecretBearingFlagsBeforeNormalOutput(t *testing.T) {
	for _, flag := range []string{
		"--root-token",
		"--unseal-key",
		"--client-token",
		"--vault-token",
		"--api-key",
		"--jwt-svid",
		"--private-key",
		"--password",
		"--secret",
	} {
		t.Run(flag, func(t *testing.T) {
			output := requireRemoteAlphaOperatorFailure(t, "print-refresh-command", flag, "value")
			assertContainsAll(t, "secret flag refusal", output,
				"secret material must never be passed by CLI args/env/logs/reports/artifacts",
			)
			assertContainsNone(t, "secret flag refusal", output,
				"remote-alpha-live-refresh",
				"Remote Alpha operator inventory",
			)
		})
	}

	equalsOutput := requireRemoteAlphaOperatorFailure(t, "--api-key=dummy")
	assertContainsAll(t, "equals-form secret flag refusal", equalsOutput,
		"secret material must never be passed by CLI args/env/logs/reports/artifacts",
	)
	assertContainsNone(t, "equals-form secret flag refusal", equalsOutput,
		"Remote Alpha operator facade",
		"Remote Alpha operator inventory",
		"remote-alpha-live-refresh",
		"remote-alpha-live-support-bundle",
	)

	output := requireRemoteAlphaOperatorFailure(t, "print-refresh-command", "--vault-token-file", "path")
	assertContainsAll(t, "secret-like flag refusal", output,
		"secret material must never be passed by CLI args/env/logs/reports/artifacts",
	)
}

func TestRemoteAlphaOperatorBlockedSubcommandsRefuseWithoutRouting(t *testing.T) {
	for _, subcommand := range []string{
		"vault-reset-disposable",
		"vault-unseal",
		"vault-unseal-existing",
		"vault-workload-auth-check",
		"runtime-identity-summary",
		"vault-service-user-check",
		"runtime-security-check",
		"es-config-tls-prep",
		"es-binaries-check",
		"es-deploy-binaries",
		"es-writable-state-ownership",
		"es-service-user-migration",
	} {
		t.Run(subcommand, func(t *testing.T) {
			output := requireRemoteAlphaOperatorFailure(t, subcommand)
			assertContainsAll(t, "blocked subcommand refusal", output,
				subcommand,
				"not implemented as a top-level P0s/P0t/P0u route",
				"later audited slice",
				"No helper execution routing occurred.",
			)
		})
	}

	output := requireRemoteAlphaOperatorFailure(t, "vault-workload-auth-bootstrap")
	assertContainsAll(t, "bootstrap refusal", output,
		"vault-workload-auth-bootstrap",
		"blocked/reopened",
		"recovery-session vault-workload-auth-bootstrap --plan",
		"explicit P0q recovery-session execution route",
		"No helper execution routing occurred.",
	)
}

func TestRemoteAlphaOperatorWritableStateRouteHelpDocumentsScope(t *testing.T) {
	output := requireRemoteAlphaOperatorSuccess(t, "es-writable-state-readiness-check", "--help")
	assertContainsAll(t, "writable-state route help", output,
		"Remote Alpha operator route: es-writable-state-readiness-check",
		"Delegates only to scripts/remote_alpha_stage_es_writable_state_readiness_check.sh",
		"check-only/non-mutating",
		"requires --ssh-target",
		"supports explicit --interactive-sudo",
		"interactive sudo is operator-authorized and bounded to this route",
		"does not eliminate the operator",
		"removes manual staging and command stitching",
		"Artifacts remain evidence/projection only",
		"--mode alpha-compat|future-non-root-required",
		"--run-id <id>",
		"--output-dir <path>",
		"--readiness-output <path>",
		"--helper-staging-record-output <path>",
		"--provenance-output <path>",
		"--interactive-sudo",
		"--keep-staging-on-failure",
		"forbidden: --apply, --dry-run, arbitrary command strings, secret-like arguments",
		"Duplicate route flags are rejected before delegation",
		"preserves es-writable-state-readiness.json",
		"es-writable-state-readiness-helper-staging-record.json",
		"does not call Infrastructure Manager",
		"writes no operator summary",
	)
}

func TestRemoteAlphaOperatorReadinessSessionHelpDocumentsScope(t *testing.T) {
	output := requireRemoteAlphaOperatorSuccess(t, "readiness-session", "--help")
	assertContainsAll(t, "readiness-session help", output,
		"Remote Alpha operator workflow: readiness-session",
		"Runs the existing es-writable-state-readiness-check route",
		"bounded ES Remote Alpha operator facade/workflow",
		"human remains the operator",
		"minimizes manual stitching",
		"does not eliminate prompts",
		"explicit --interactive-sudo",
		"visible and secret-safe",
		"fresh run-specific output directory by default",
		"--ssh-target <target>",
		"--mode alpha-compat|future-non-root-required",
		"--output-dir <path>",
		"--run-id <id>",
		"--interactive-sudo",
		"--keep-staging-on-failure",
		"--ssh-alias <alias>",
		"--im-profile-dir <path>",
		"--support-output-root <path>",
		"for printed IM commands only",
		"forbidden: --apply, --dry-run, equals-form options, unknown flags, positional arguments, duplicate workflow flags, secret-like arguments",
		"verifies es-writable-state-readiness.json",
		"es-writable-state-readiness-helper-staging-record.json",
		"scans artifacts for secret-like content before reading JSON fields",
		"prints only non-secret metadata",
		"does not run Infrastructure Manager",
		"writes no operator summary",
		"IM follow-up commands are printed only as evidence/provenance actions",
		"not authority",
	)
}

func TestRemoteAlphaOperatorRecoverySessionHelpPlanInventoryAndNextStepsDocumentBoundaries(t *testing.T) {
	help := requireRemoteAlphaOperatorSuccess(t, "recovery-session", "--help")
	assertContainsAll(t, "recovery-session help", help,
		"Remote Alpha operator workflow: recovery-session",
		"P0u scope: safe/local recovery planning and evidence interpretation plus explicit vault-unseal-existing modes",
		"bounded Mac-side operator-healthcheck client TLS status/renew routing",
		"Secret-sensitive unseal key entry happens only in the visible terminal owned by the delegated helper, SSH, and Vault CLI",
		"Codex must not receive, type, log, relay, persist, or summarize the unseal key",
		"Outputs are evidence/projection/diagnostics only, never authority",
		"--plan",
		"--inventory",
		"--next-steps",
		"--evidence-check",
		"recovery-session vault-unseal-existing --host-local",
		"--vault-workload-auth-summary <path>",
		"--runtime-identity-summary <path>",
		"--vault-service-user-summary <path>",
		"--readiness-summary <path>",
		"--staging-record <path>",
		"--evidence-dir <path>",
		"--strict-known-schema",
		"Recognized schemas",
		"Unknown schemas are allowed by default",
		"Forbidden: --ssh-target, --interactive-sudo, --apply, --dry-run, --execute-reset, --execute-renew, --unseal-only, --post-unseal-check, --governed-smoke-command",
		"recovery-session vault-unseal-existing --ssh-target <user@host> --interactive-tty",
		"recovery-session vault-reset-disposable --ssh-target <user@host> --dry-run",
		"recovery-session vault-reset-disposable --ssh-target <user@host> --execute-reset --interactive-tty",
		"recovery-session vault-workload-auth-check --ssh-target <user@host> --interactive-tty",
		"recovery-session vault-workload-auth-bootstrap [--help|--plan|--inventory]",
		"recovery-session vault-workload-auth-bootstrap --ssh-target <user@host> --prepare-summary-path --interactive-tty",
		"recovery-session vault-workload-auth-bootstrap --ssh-target <user@host> --prepare-config-readability --interactive-tty",
		"recovery-session vault-workload-auth-bootstrap --ssh-target <user@host> --prepare-spire-bundle-read --interactive-tty",
		"recovery-session vault-workload-auth-bootstrap --ssh-target <user@host> --execute-bootstrap --prepare-summary-path --prepare-config-readability --prepare-spire-bundle-read --interactive-tty",
		"recovery-session vault-workload-auth-bootstrap --ssh-target <user@host> --execute-bootstrap --interactive-tty",
		"recovery-session runtime-identity-summary --ssh-target <user@host> --interactive-tty",
		"recovery-session operator-healthcheck-tls-status --ssh-target <user@host> --interactive-tty",
		"recovery-session operator-healthcheck-tls-renew --ssh-target <user@host> --interactive-tty --execute-renew",
		"recovery-session es-service-tls-status --ssh-target <user@host> --interactive-tty",
		"recovery-session es-service-tls-renew --ssh-target <user@host> --interactive-tty --execute-renew",
		"Mac-side dry-run planning only",
		"destructive Mac-side operator route",
		"stages only the reset helper",
		"invokes only --execute-reset",
		"Mac-side staged evidence route",
		"stages only the workload-auth public/internal helper pair",
		"leaves the canonical summary on the remote host",
		"does not bootstrap workload auth or broker Vault tokens",
		"safe local/print-only planning",
		"does not run SSH, sudo, Vault, workload-auth checks, reset/unseal, IM, support bundles, CP proof, runtime identity generation, or live bootstrap",
		"bounded remote filesystem preparation only",
		"may use an OS sudo prompt through the visible SSH TTY",
		"Mac-side staged bootstrap route",
		"stages only the bootstrap public/internal helper pair",
		"Vault bootstrap authority and proof secret values only in the visible remote helper prompt",
		"stages only the public runtime identity helper summary script",
		"does not claim runtime-profile readiness or submit readiness",
		"stages only the ES service TLS public/internal helper pair",
		"bounded to ARS/AGS/ES artifact-registry mTLS",
		"bounded to ES -> EGS trust-model mTLS",
		"exact confirmation phrase",
		"visible remote terminal",
		"non-destructive and does not stop Vault, move raft storage, init or unseal Vault, run post-unseal checks, run IM, or collect support bundles",
		"prints no full JSON",
		"creates no summary file",
		"writes no .out",
	)

	defaultOutput := requireRemoteAlphaOperatorSuccess(t, "recovery-session")
	assertContainsAll(t, "default recovery-session plan", defaultOutput,
		"Remote Alpha recovery-session plan",
		"P0u operator healthcheck TLS status/renew route added",
		"default behavior: print this plan/help and exit zero; no live tools run",
		"inventory/status - safe local planning and static inventory only",
		"evidence-check - local-only metadata check",
		"next-steps - print readiness-session and IM command text only",
		"vault-unseal-existing --host-local - implemented host-local operator mode for the Linux Remote Alpha host; secret-sensitive but non-destructive",
		"vault-unseal-existing --ssh-target <target> --interactive-tty - implemented Mac-side operator mode",
		"invokes only --unseal-only over ssh -tt",
		"vault-reset-disposable --ssh-target <target> --dry-run - implemented Mac-side dry-run planning mode",
		"invokes only --dry-run over SSH",
		"vault-reset-disposable --ssh-target <target> --execute-reset --interactive-tty - implemented destructive Mac-side operator mode",
		"invokes only --execute-reset over ssh -tt",
		"vault-workload-auth-check --ssh-target <target> --interactive-tty - implemented Mac-side staged evidence mode",
		"invokes only the staged public helper over ssh -tt",
		"leaves the canonical summary on the remote host",
		"vault-workload-auth-bootstrap [--help|--plan|--inventory] - implemented safe local/print-only planning mode",
		"no SSH, no sudo, no Vault, no root-token prompt, no proof secret creation, no workload-auth check, no JSON, no .out, no summary",
		"vault-workload-auth-bootstrap --ssh-target <target> --prepare-summary-path --interactive-tty - implemented bounded remote filesystem preparation mode",
		"may request OS sudo",
		"creates no final bootstrap summary",
		"vault-workload-auth-bootstrap --ssh-target <target> --prepare-config-readability --interactive-tty - implemented bounded remote filesystem preparation mode",
		"prints no config contents",
		"vault-workload-auth-bootstrap --ssh-target <target> --prepare-spire-bundle-read --interactive-tty - implemented bounded remote capability/filesystem preparation mode",
		"prints no SPIRE bundle contents",
		"vault-workload-auth-bootstrap --ssh-target <target> --execute-bootstrap --prepare-summary-path --prepare-config-readability --prepare-spire-bundle-read --interactive-tty - implemented combined preparation plus staged bootstrap mode",
		"summary preparation, config readability preparation, then SPIRE bundle-read preparation run before helper staging and before any Vault/root/proof prompt",
		"vault-workload-auth-bootstrap --ssh-target <target> --execute-bootstrap --interactive-tty - implemented Mac-side staged bootstrap mode",
		"runtime-identity-summary --ssh-target <target> --interactive-tty - implemented Mac-side staged runtime identity evidence mode",
		"es-service-tls-status --ssh-target <target> --interactive-tty - implemented Mac-side staged internal TLS evidence mode",
		"es-service-tls-renew --ssh-target <target> --interactive-tty --execute-renew - implemented Mac-side staged internal TLS recovery mode",
		"es-governance-tls-status --ssh-target <target> --interactive-tty - implemented Mac-side staged ES/EGS governance TLS evidence mode",
		"es-governance-tls-renew --ssh-target <target> --interactive-tty --execute-renew - implemented Mac-side staged ES/EGS governance TLS recovery mode",
		"operator-healthcheck-tls-status --ssh-target <target> --interactive-tty - implemented Mac-side staged host-local operator healthcheck TLS evidence mode",
		"operator-healthcheck-tls-renew --ssh-target <target> --interactive-tty --execute-renew - implemented Mac-side staged host-local operator healthcheck TLS recovery mode",
		"RESET DISPOSABLE REMOTE ALPHA VAULT",
		"visible remote helper/Vault terminal",
		"service-user check/apply - remains separate",
		"recovery-session does not execute IM",
		"not ES Vault token brokerage",
		"vault-reset-disposable --dry-run is non-destructive",
		"it does not stop Vault, move raft storage, init or unseal Vault, run post-unseal checks, run IM, or collect support bundles",
		"vault-workload-auth-check is evidence/projection only",
		"not workload-auth bootstrap",
		"not readiness authority",
		"vault-workload-auth-bootstrap configures expected Vault objects only",
		"not workload-auth success, not ES Vault token brokerage",
		"runtime-identity-summary is evidence/projection only",
		"not runtime-profile readiness, submit readiness, retained-result readiness, CP proof, production readiness, or runtime identity generation",
		"es-governance-tls status/renew is bounded ES -> EGS trust-model mTLS recovery only",
		"operator-healthcheck-tls status/renew is bounded host-local operator healthcheck client TLS recovery only",
		"no post-unseal/service-user/IM/support-bundle/CP-proof bundling is added in P0u",
		"vault-unseal-existing does not validate default noninteractive readiness",
	)

	plan := requireRemoteAlphaOperatorSuccess(t, "recovery-session", "--plan")
	assertContainsAll(t, "recovery-session plan", plan,
		"Remote Alpha recovery-session plan",
		"implemented safe/local or explicitly host-local",
		"vault-unseal-existing --host-local",
		"vault-reset-disposable --ssh-target <target> --dry-run",
		"vault-reset-disposable --ssh-target <target> --execute-reset --interactive-tty",
		"vault-workload-auth-check --ssh-target <target> --interactive-tty",
		"vault-workload-auth-bootstrap [--help|--plan|--inventory]",
		"vault-workload-auth-bootstrap --ssh-target <target> --prepare-summary-path --interactive-tty",
		"vault-workload-auth-bootstrap --ssh-target <target> --prepare-config-readability --interactive-tty",
		"vault-workload-auth-bootstrap --ssh-target <target> --prepare-spire-bundle-read --interactive-tty",
		"vault-workload-auth-bootstrap --ssh-target <target> --execute-bootstrap --prepare-summary-path --prepare-config-readability --prepare-spire-bundle-read --interactive-tty",
		"runtime-identity-summary --ssh-target <target> --interactive-tty",
		"es-service-tls-status --ssh-target <target> --interactive-tty",
		"es-service-tls-renew --ssh-target <target> --interactive-tty --execute-renew",
		"es-governance-tls-status --ssh-target <target> --interactive-tty",
		"es-governance-tls-renew --ssh-target <target> --interactive-tty --execute-renew",
		"operator-healthcheck-tls-status --ssh-target <target> --interactive-tty",
		"operator-healthcheck-tls-renew --ssh-target <target> --interactive-tty --execute-renew",
		"separate IM actions",
		"non-claims",
	)

	inventory := requireRemoteAlphaOperatorSuccess(t, "recovery-session", "--inventory")
	assertContainsAll(t, "recovery-session inventory", inventory,
		"Remote Alpha recovery-session static helper inventory",
		"safe/local inventory only",
		"no live host state inspection",
		"no helper execution",
		"scripts/remote_alpha_reset_disposable_vault.sh --unseal-only",
		"scripts/remote_alpha_reset_disposable_vault.sh --dry-run",
		"scripts/remote_alpha_reset_disposable_vault.sh --execute-reset",
		"scripts/remote_alpha_vault_workload_auth_check.sh",
		"scripts/internal/remote_alpha_vault_workload_auth_check.sh",
		"scripts/remote_alpha_runtime_identity_helper_summary.sh",
		"scripts/remote_alpha_es_service_tls_renew.sh --status",
		"scripts/remote_alpha_es_service_tls_renew.sh --scope execution-governance --status",
		"scripts/remote_alpha_operator_healthcheck_tls_renew.sh --status",
		"scripts/remote_alpha_migrate_vault_service_user.sh --check-only",
		"scripts/remote_alpha_operator.sh readiness-session",
		"recovery-session vault-unseal-existing --host-local",
		"recovery-session vault-unseal-existing --ssh-target <target> --interactive-tty",
		"recovery-session vault-reset-disposable --ssh-target <target> --dry-run",
		"recovery-session vault-reset-disposable --ssh-target <target> --execute-reset --interactive-tty",
		"recovery-session vault-workload-auth-check --ssh-target <target> --interactive-tty",
		"recovery-session vault-workload-auth-bootstrap [--help|--plan|--inventory]",
		"recovery-session vault-workload-auth-bootstrap --ssh-target <target> --prepare-summary-path --interactive-tty",
		"bounded remote filesystem preparation only",
		"recovery-session vault-workload-auth-bootstrap --ssh-target <target> --prepare-config-readability --interactive-tty",
		"fixed-path user ACLs",
		"recovery-session vault-workload-auth-bootstrap --ssh-target <target> --prepare-spire-bundle-read --interactive-tty",
		"fixed SPIRE server bundle-read access",
		"recovery-session vault-workload-auth-bootstrap --ssh-target <target> --execute-bootstrap --prepare-summary-path --prepare-config-readability --prepare-spire-bundle-read --interactive-tty",
		"prepares the summary path, then config readability, then SPIRE bundle-read access before staging",
		"recovery-session vault-workload-auth-bootstrap --ssh-target <target> --execute-bootstrap --interactive-tty",
		"recovery-session runtime-identity-summary --ssh-target <target> --interactive-tty",
		"recovery-session runtime-identity-summary --ssh-target <target> --interactive-tty",
		"recovery-session es-service-tls-status --ssh-target <target> --interactive-tty",
		"recovery-session es-service-tls-renew --ssh-target <target> --interactive-tty --execute-renew",
		"recovery-session es-governance-tls-status --ssh-target <target> --interactive-tty",
		"recovery-session es-governance-tls-renew --ssh-target <target> --interactive-tty --execute-renew",
		"recovery-session operator-healthcheck-tls-status --ssh-target <target> --interactive-tty",
		"recovery-session operator-healthcheck-tls-renew --ssh-target <target> --interactive-tty --execute-renew",
		"implemented host-local explicit operator mode",
		"implemented Mac-side explicit operator mode",
		"invokes only --unseal-only through ssh -tt",
		"invokes only --dry-run through SSH",
		"invokes only --execute-reset through ssh -tt",
		"invokes only the staged public helper through ssh -tt",
		"leaves /var/tmp/execution-substrate-remote-alpha/vault-workload-auth-summary.json on the remote host",
		"leaves /var/tmp/execution-substrate-remote-alpha/runtime-identity-helper-summary.json on the remote host",
		"leaves /var/tmp/execution-substrate-remote-alpha/es-service-tls-renew-summary.json on the remote host",
		"leaves /var/tmp/execution-substrate-remote-alpha/es-governance-tls-renew-summary.json on the remote host",
		"leaves /var/tmp/execution-substrate-remote-alpha/operator-healthcheck-tls-renew-summary.json on the remote host",
		"no summary copy-back",
		"safe local/print-only planning",
		"no SSH, no sudo, no Vault, no root-token prompt, no proof secret creation, no workload-auth check, no .out, no JSON, no summary",
		"leaves /var/tmp/execution-substrate-remote-alpha/vault-workload-auth-bootstrap-summary.json on the remote host",
		"leaves /var/tmp/execution-substrate-remote-alpha/runtime-identity-helper-summary.json on the remote host",
		"now also reachable through the P0r Mac-side staged evidence route",
		"does not stop Vault, move raft storage, init, unseal, run post-unseal checks, run IM, or collect support bundles",
		"secret-sensitive",
		"destructive",
		"non-destructive",
		"classifications present: safe/local, check-only, secret-sensitive, destructive, future, blocked/reopened",
		"live vault-workload-auth-bootstrap validation - not run in P0q",
	)

	nextSteps := requireRemoteAlphaOperatorSuccess(t,
		"recovery-session", "--next-steps",
		"--im-profile-dir", "profiles/alpha",
		"--support-output-root", "bundles/alpha",
		"--ssh-alias", "alpha_alias",
	)
	assertContainsAll(t, "recovery-session next steps", nextSteps,
		"Remote Alpha recovery-session next steps",
		"printed only; no execution",
		"bash scripts/remote_alpha_operator.sh readiness-session --ssh-target <user@host> --interactive-sudo",
		"Separate IM evidence/provenance actions",
		"not ES execution",
		"not authority",
		"remote-alpha-live-refresh",
		"--profile-dir \"profiles/alpha\"",
		"--ssh-alias \"alpha_alias\"",
		"remote-alpha-live-support-bundle",
		"--output-root \"bundles/alpha\"",
	)
}

func TestRemoteAlphaOperatorRecoverySessionVaultUnsealExistingHelpDocumentsHostLocalSecretPosture(t *testing.T) {
	help := requireRemoteAlphaOperatorSuccess(t, "recovery-session", "vault-unseal-existing", "--help")
	assertContainsAll(t, "vault-unseal-existing help", help,
		"Remote Alpha recovery-session mode: vault-unseal-existing",
		"P0j scope: explicit secret-sensitive non-destructive unseal-existing flow with host-local and Mac-side interactive TTY topologies",
		"Host-local mode must be run on the Remote Alpha host where Vault is installed and reachable",
		"Mac-side mode stages only scripts/remote_alpha_reset_disposable_vault.sh to the remote host and invokes only --unseal-only through ssh -tt",
		"No transcript, log, .out, report, support bundle, operator summary, IM refresh, workload-auth check, reset, or CP proof is created or run",
		"Delegates only to: scripts/remote_alpha_reset_disposable_vault.sh --unseal-only",
		"Human operator model",
		"The human remains the operator",
		"The operator enters any unseal key directly into the visible Vault/helper terminal prompt",
		"The operator facade does not prompt for, read, type, log, relay, persist, summarize, or accept unseal keys, root tokens, Vault tokens, API keys, passwords, or secret payloads",
		"Secret material must never be passed by CLI args, env files, logs, .out, reports, support bundles, retained bundles, or Codex output",
		"remote_alpha_operator.sh recovery-session vault-unseal-existing --host-local",
		"remote_alpha_operator.sh recovery-session vault-unseal-existing --ssh-target <user@host> --interactive-tty",
		"Allowed flags",
		"--host-local",
		"--ssh-target <target>",
		"--interactive-tty",
		"Topology rules",
		"--host-local and --ssh-target are mutually exclusive",
		"the SSH target must be a single target, not an option or shell command",
		"Forbidden in P0j",
		"--execute-reset",
		"--post-unseal-check",
		"--keep-staging-on-failure",
		"--interactive-sudo",
		"secret-like flags",
		"equals-form options",
		"Non-claims: not reset, not workload-auth bootstrap or check, not IM refresh/support-bundle, not CP proof, not default noninteractive readiness validation",
		"not ES Vault token brokerage",
		"not Remote Alpha deployment/provisioning/reconciliation architecture",
	)
}

func TestRemoteAlphaOperatorRecoverySessionVaultResetDisposableHelpDocumentsDryRunPosture(t *testing.T) {
	help := requireRemoteAlphaOperatorSuccess(t, "recovery-session", "vault-reset-disposable", "--help")
	assertContainsAll(t, "vault-reset-disposable help", help,
		"Remote Alpha recovery-session mode: vault-reset-disposable",
		"P0m scope: explicit Mac-side disposable Vault reset dry-run planning route plus destructive execute-reset operator route",
		"Dry-run stages only scripts/remote_alpha_reset_disposable_vault.sh to the remote host and invokes only --dry-run",
		"Execute-reset stages only scripts/remote_alpha_reset_disposable_vault.sh to the remote host and invokes only --execute-reset through ssh -tt",
		"Dry-run remains the prerequisite/planning route",
		"Live execute-reset must be run only when the operator intentionally wants to reset disposable Remote Alpha Vault state",
		"The helper supports --dry-run; the operator facade passes it explicitly",
		"No transcript, tee/script capture, log, .out, report, support bundle, operator summary, IM refresh, workload-auth check, post-unseal check, runtime identity summary, or CP proof is created or run",
		"Delegates only to: scripts/remote_alpha_reset_disposable_vault.sh --dry-run or scripts/remote_alpha_reset_disposable_vault.sh --execute-reset",
		"Non-destructive behavior",
		"This is planning/inspection only",
		"It does not stop Vault",
		"It does not move raft storage",
		"It does not run vault operator init",
		"It does not unseal Vault",
		"It does not run post-unseal checks",
		"It does not run Infrastructure Manager",
		"It does not collect support bundles",
		"Execute-reset is a destructive explicit operator route and requires --interactive-tty",
		"Destructive execute-reset behavior",
		"This is destructive for disposable Remote Alpha Vault state",
		"The existing exact confirmation phrase is RESET DISPOSABLE REMOTE ALPHA VAULT",
		"The operator types that phrase only in the visible remote helper/Vault terminal",
		"Vault init output, root token, unseal key, and Vault prompts are handled only by the human operator in the visible remote terminal",
		"The phrase and Vault secrets must never be passed by CLI args, env files, files, logs, .out, reports, support bundles, retained bundles, or Codex output",
		"The operator facade does not receive, parse, log, store, echo, summarize, or persist the phrase or secret material",
		"Artifacts and outputs remain evidence/projection/diagnostics only, never authority",
		"remote_alpha_operator.sh recovery-session vault-reset-disposable --ssh-target <user@host> --dry-run",
		"remote_alpha_operator.sh recovery-session vault-reset-disposable --ssh-target <user@host> --execute-reset --interactive-tty",
		"Allowed flags",
		"--ssh-target <target>",
		"--dry-run",
		"--execute-reset",
		"--interactive-tty",
		"Topology rules: Mac-side only",
		"exactly one of --dry-run or --execute-reset is required",
		"--execute-reset requires --interactive-tty",
		"--dry-run rejects --interactive-tty",
		"--host-local is not accepted",
		"Forbidden in P0m",
		"--unseal-only",
		"--post-unseal-check",
		"--host-local",
		"--keep-staging-on-failure",
		"workload-auth flags",
		"IM commands",
		"support-bundle commands",
		"runtime-identity flags",
		"secret-like flags",
		"equals-form options",
		"Non-claims: not workload-auth bootstrap or check, not IM refresh/support-bundle, not CP proof",
		"not ES Vault token brokerage",
		"not Remote Alpha deployment/provisioning/reconciliation architecture",
	)
}

func TestRemoteAlphaOperatorRecoverySessionVaultWorkloadAuthCheckHelpDocumentsMacSideEvidencePosture(t *testing.T) {
	help := requireRemoteAlphaOperatorSuccess(t, "recovery-session", "vault-workload-auth-check", "--help")
	assertContainsAll(t, "vault-workload-auth-check help", help,
		"Remote Alpha recovery-session mode: vault-workload-auth-check",
		"P0n scope: explicit Mac-side staged workload-auth evidence route, separate from reset/unseal",
		"stages only scripts/remote_alpha_vault_workload_auth_check.sh and scripts/internal/remote_alpha_vault_workload_auth_check.sh",
		"public/internal relative layout is preserved",
		"invokes only the staged public workload-auth helper through ssh -tt",
		"explicit interactive TTY path for root when required",
		"No transcript, tee/script capture, log, .out, report, support bundle, operator summary, IM refresh, runtime identity generation, reset/unseal, workload-auth bootstrap, ES token brokerage, or CP proof is created or run",
		"Canonical remote summary: /var/tmp/execution-substrate-remote-alpha/vault-workload-auth-summary.json",
		"Summary is evidence/projection only, not readiness authority",
		"Secret posture",
		"does not accept, parse, print, copy, log, relay, persist, summarize, or handle JWT-SVIDs, Vault client tokens, proof secret payloads, root tokens, unseal keys, API keys, private keys, passwords, or secret payloads",
		"does not print full summary JSON",
		"does not copy the summary back to Mac .out",
		"remote_alpha_operator.sh recovery-session vault-workload-auth-check --ssh-target <user@host> --interactive-tty",
		"Allowed flags",
		"--ssh-target <target>",
		"--interactive-tty",
		"Topology rules: Mac-side only",
		"--host-local is not accepted",
		"the SSH target must be a single target, not an option or shell command",
		"Forbidden in P0n",
		"--dry-run",
		"--execute-reset",
		"--unseal-only",
		"--post-unseal-check",
		"--interactive-sudo",
		"helper override flags",
		"Vault address/role/audience/path/proof-path overrides",
		"SPIFFE ID overrides",
		"config path overrides",
		"summary path overrides",
		"container probe image overrides",
		"SPIRE socket overrides",
		"secret-like flags",
		"equals-form options",
		"Non-claims: not reset/unseal, not workload-auth bootstrap, not ES Vault token brokerage, not IM refresh/support-bundle, not CP proof",
		"not Vault production readiness",
		"not governed execution proof",
		"not Remote Alpha deployment/provisioning/reconciliation architecture",
	)
}

func TestRemoteAlphaOperatorRecoverySessionRuntimeIdentitySummaryHelpDocumentsMacSideEvidencePosture(t *testing.T) {
	help := requireRemoteAlphaOperatorSuccess(t, "recovery-session", "runtime-identity-summary", "--help")
	assertContainsAll(t, "runtime-identity-summary help", help,
		"Remote Alpha recovery-session mode: runtime-identity-summary",
		"P0r scope: explicit Mac-side staged runtime identity evidence route",
		"separate from workload-auth bootstrap/check and reset/unseal",
		"stages only scripts/remote_alpha_runtime_identity_helper_summary.sh",
		"invokes only the staged runtime identity helper summary script through ssh -tt",
		"explicit interactive TTY path for root when required",
		"No transcript, tee/script capture, log, .out, report, support bundle, operator summary, IM refresh, workload-auth bootstrap/check, reset/unseal, runtime identity generation, ES token brokerage, Vault command, SPIRE live command by the operator facade, or CP proof is created or run by the facade",
		"Canonical remote summary: /var/tmp/execution-substrate-remote-alpha/runtime-identity-helper-summary.json",
		"Summary is evidence/projection only, not readiness authority",
		"Secret posture",
		"does not accept, parse, print, copy, log, relay, persist, summarize, or handle JWT-SVIDs, Vault tokens, root tokens, unseal keys, API keys, private keys, passwords, proof secrets, raw identity payloads, or secret material",
		"does not print full summary JSON",
		"does not copy the summary back to Mac .out",
		"remote_alpha_operator.sh recovery-session runtime-identity-summary --ssh-target <user@host> --interactive-tty",
		"Allowed flags",
		"--ssh-target <target>",
		"--interactive-tty",
		"Topology rules: Mac-side only",
		"--host-local is not accepted",
		"the SSH target must be a single target, not an option or shell command",
		"Forbidden in P0r",
		"--dry-run",
		"--check-only",
		"--execute-reset",
		"--unseal-only",
		"--post-unseal-check",
		"--execute-bootstrap",
		"--prepare-summary-path",
		"--prepare-config-readability",
		"--prepare-spire-bundle-read",
		"helper override flags",
		"output/summary path overrides",
		"runtime-support path overrides",
		"SPIRE socket overrides",
		"workload SPIFFE ID overrides",
		"audience overrides",
		"secret-like flags",
		"equals-form options",
		"Non-claims: not workload-auth bootstrap/check, not reset/unseal, not ES Vault token brokerage, not IM refresh/support-bundle, not CP proof",
		"not runtime-profile readiness",
		"not submit readiness",
		"not retained-result readiness",
		"not production readiness",
		"not governed execution proof",
		"not Remote Alpha deployment/provisioning/reconciliation architecture",
	)
}

func TestRemoteAlphaOperatorRecoverySessionEvidenceCheckNoPathsIsNonError(t *testing.T) {
	output := requireRemoteAlphaOperatorSuccess(t, "recovery-session", "--evidence-check")
	assertContainsAll(t, "recovery-session evidence-check no paths", output,
		"No recovery-session evidence paths supplied",
		"nothing to check",
		"local-only",
		"evidence/projection/diagnostics only",
		"never authority",
	)
}

func TestRemoteAlphaOperatorRecoverySessionEvidenceCheckRecognizesReadinessSummary(t *testing.T) {
	dir := t.TempDir()
	fixture := `{"schema_version":"execution-substrate.remote-alpha.es-writable-state-readiness.v1","operation_mode":"check_only","non_mutating":true,"checker_mode":"alpha-compat","overall_classification":"warning","blockers":["blocked detail"],"warnings":["warning detail"],"bounded_compatibility_edges":["edge-a","edge-b"],"internal_detail":"must not print"}`
	fixturePath := filepath.Join(dir, "es-writable-state-readiness.json")
	if err := os.WriteFile(fixturePath, []byte(fixture), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	sum := sha256.Sum256([]byte(fixture))

	output := requireRemoteAlphaOperatorSuccess(t,
		"recovery-session", "--evidence-check",
		"--readiness-summary", fixturePath,
	)
	assertContainsAll(t, "recovery-session evidence metadata", output,
		"Recovery-session evidence metadata",
		"local-only",
		"evidence/projection/diagnostics only",
		"classification: readiness-summary",
		"path: "+fixturePath,
		fmt.Sprintf("bytes: %d", len([]byte(fixture))),
		fmt.Sprintf("sha256: %x", sum),
		"schema_version: execution-substrate.remote-alpha.es-writable-state-readiness.v1",
		"schema_interpretation: readiness-summary",
		"operation_mode: check_only",
		"non_mutating: true",
		"checker_mode: alpha-compat",
		"overall_classification: warning",
		"blockers_count: 1",
		"warnings_count: 1",
		"bounded_compatibility_edges_count: 2",
	)
	assertContainsNone(t, "recovery-session evidence metadata", output,
		"internal_detail",
		"must not print",
		"{\"schema_version\"",
		"blocked detail",
		"warning detail",
	)
}

func TestRemoteAlphaOperatorRecoverySessionEvidenceCheckRecognizesReadinessStagingRecord(t *testing.T) {
	dir := t.TempDir()
	fixture := `{"schema_version":"execution-substrate.remote-alpha.es-writable-state-readiness-stage-provenance.v1","requested_checker_mode":"alpha-compat","sudo_mode":"interactive","staging_occurred":true,"checker_ran":true,"sudo_unavailable":false,"wrapper_exit_code":0,"checker_exit_code":0,"transient_staging_removed":true,"staging_retained_for_diagnostics":false,"staged_files":["wrapper","checker"],"internal_detail":"must not print"}`
	fixturePath := filepath.Join(dir, "es-writable-state-readiness-helper-staging-record.json")
	if err := os.WriteFile(fixturePath, []byte(fixture), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	output := requireRemoteAlphaOperatorSuccess(t,
		"recovery-session", "--evidence-check",
		"--staging-record", fixturePath,
	)
	assertContainsAll(t, "recovery-session staging metadata", output,
		"classification: staging-record",
		"schema_version: execution-substrate.remote-alpha.es-writable-state-readiness-stage-provenance.v1",
		"schema_interpretation: readiness-staging-record",
		"requested_checker_mode: alpha-compat",
		"sudo_mode: interactive",
		"staging_occurred: true",
		"checker_ran: true",
		"sudo_unavailable: false",
		"wrapper_exit_code: 0",
		"checker_exit_code: 0",
		"transient_staging_removed: true",
		"staging_retained_for_diagnostics: false",
		"staged_files_count: 2",
	)
	assertContainsNone(t, "recovery-session staging metadata", output,
		"internal_detail",
		"must not print",
		"wrapper\",",
		"checker\"",
	)
}

func TestRemoteAlphaOperatorRecoverySessionEvidenceCheckRecognizesVaultWorkloadAuthSummary(t *testing.T) {
	dir := t.TempDir()
	fixture := `{"schema_version":"execution-substrate.remote-alpha.vault-workload-auth-summary.v1","operation_mode":"check_only","collection_status":"collected","overall_classification":"pass","non_mutating":true,"blockers":[],"warnings":[],"requirements":["req-a","req-b"],"auth_smoke":{"jwt_fetch":{"status":"pass"},"vault_login":{"status":"pass"},"token_lookup":{"status":"pass"},"proof_read":{"status":"pass"},"proof_runtime_secret":{"status":"pass","field_present":true},"token_revoked":{"status":"pass"}},"internal_detail":"must not print"}`
	fixturePath := filepath.Join(dir, "vault-workload-auth-summary.json")
	if err := os.WriteFile(fixturePath, []byte(fixture), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	output := requireRemoteAlphaOperatorSuccess(t,
		"recovery-session", "--evidence-check",
		"--vault-workload-auth-summary", fixturePath,
	)
	assertContainsAll(t, "recovery-session vault workload auth metadata", output,
		"classification: vault-workload-auth-summary",
		"schema_version: execution-substrate.remote-alpha.vault-workload-auth-summary.v1",
		"schema_interpretation: vault-workload-auth-summary",
		"operation_mode: check_only",
		"collection_status: collected",
		"overall_classification: pass",
		"non_mutating: true",
		"blockers_count: 0",
		"warnings_count: 0",
		"requirements_count: 2",
		"auth_smoke.jwt_fetch_status: pass",
		"auth_smoke.vault_login_status: pass",
		"auth_smoke.token_lookup_status: pass",
		"auth_smoke.proof_read_status: pass",
		"auth_smoke.proof_runtime_secret_status: pass",
		"auth_smoke.proof_runtime_secret_field_present: true",
		"auth_smoke.token_revoked_status: pass",
	)
	assertContainsNone(t, "recovery-session vault workload auth metadata", output,
		"internal_detail",
		"must not print",
		"req-a",
		"req-b",
	)
}

func TestRemoteAlphaOperatorRecoverySessionEvidenceCheckRecognizesRuntimeIdentitySummary(t *testing.T) {
	dir := t.TempDir()
	fixture := `{"schema_version":"execution-substrate.remote-runtime-identity-helper-summary.v1alpha1","mode":"generate","overall_status":"pass","runtime_identity_helper_local_fetch":"pass","jwt_fetch_output_discarded":true,"helper_binary":{"exists":true},"spire_fetch_smoke":{"status":"pass","output_discarded":true},"checks":[true,false],"internal_detail":"must not print"}`
	fixturePath := filepath.Join(dir, "runtime-identity-helper-summary.json")
	if err := os.WriteFile(fixturePath, []byte(fixture), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	output := requireRemoteAlphaOperatorSuccess(t,
		"recovery-session", "--evidence-check",
		"--runtime-identity-summary", fixturePath,
	)
	assertContainsAll(t, "recovery-session runtime identity metadata", output,
		"classification: runtime-identity-summary",
		"schema_version: execution-substrate.remote-runtime-identity-helper-summary.v1alpha1",
		"schema_interpretation: runtime-identity-helper-summary",
		"mode: generate",
		"overall_status: pass",
		"runtime_identity_helper_local_fetch: pass",
		"jwt_fetch_output_discarded: true",
		"helper_binary.exists: true",
		"spire_fetch_smoke.status: pass",
		"spire_fetch_smoke.output_discarded: true",
		"checks_count: 2",
	)
	assertContainsNone(t, "recovery-session runtime identity metadata", output,
		"internal_detail",
		"must not print",
	)
}

func TestRemoteAlphaOperatorRecoverySessionEvidenceCheckRecognizesVaultServiceUserSummary(t *testing.T) {
	dir := t.TempDir()
	fixture := `{"schema_version":"execution-substrate.remote-alpha.vault-service-user-migration-summary.v1","operation_mode":"check_only","collection_status":"collected","non_mutating":true,"apply_ready":true,"sudo_unavailable":false,"blockers":[],"warnings":["warning detail"],"smoke":{"command_output":"must not print"}}`
	fixturePath := filepath.Join(dir, "vault-service-user-migration-check-only.json")
	if err := os.WriteFile(fixturePath, []byte(fixture), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	output := requireRemoteAlphaOperatorSuccess(t,
		"recovery-session", "--evidence-check",
		"--vault-service-user-summary", fixturePath,
	)
	assertContainsAll(t, "recovery-session service user metadata", output,
		"classification: vault-service-user-summary",
		"schema_version: execution-substrate.remote-alpha.vault-service-user-migration-summary.v1",
		"schema_interpretation: vault-service-user-migration-summary",
		"operation_mode: check_only",
		"collection_status: collected",
		"non_mutating: true",
		"apply_ready: true",
		"sudo_unavailable: false",
		"blockers_count: 0",
		"warnings_count: 1",
	)
	assertContainsNone(t, "recovery-session service user metadata", output,
		"command_output",
		"must not print",
		"warning detail",
	)
}

func TestRemoteAlphaOperatorRecoverySessionEvidenceCheckUnknownSchemaDefaultAndStrict(t *testing.T) {
	dir := t.TempDir()
	fixture := `{"schema_version":"execution-substrate.unknown.v1","operation_mode":"check_only","warnings":["do not print"],"internal_detail":"must not print"}`
	fixturePath := filepath.Join(dir, "unknown.json")
	if err := os.WriteFile(fixturePath, []byte(fixture), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	output := requireRemoteAlphaOperatorSuccess(t,
		"recovery-session", "--evidence-check",
		"--readiness-summary", fixturePath,
	)
	assertContainsAll(t, "recovery-session unknown schema default", output,
		"classification: readiness-summary",
		"path: "+fixturePath,
		"schema_version: execution-substrate.unknown.v1",
		"schema_interpretation: unknown",
	)
	assertContainsNone(t, "recovery-session unknown schema default", output,
		"operation_mode",
		"warnings_count",
		"internal_detail",
		"must not print",
		"do not print",
	)

	strictOutput := requireRemoteAlphaOperatorFailure(t,
		"recovery-session", "--evidence-check", "--strict-known-schema",
		"--readiness-summary", fixturePath,
	)
	assertContainsAll(t, "recovery-session unknown schema strict", strictOutput,
		"evidence-check failed for readiness-summary",
		"path: "+fixturePath,
		"error_classification: unknown_schema",
	)
	assertContainsNone(t, "recovery-session unknown schema strict", strictOutput,
		"operation_mode",
		"internal_detail",
		"must not print",
	)
}

func TestRemoteAlphaOperatorRecoverySessionEvidenceDirDiscoversExpectedFilesOnly(t *testing.T) {
	dir := t.TempDir()
	readinessFixture := `{"schema_version":"execution-substrate.remote-alpha.es-writable-state-readiness.v1","operation_mode":"check_only","non_mutating":true,"checker_mode":"alpha-compat","overall_classification":"pass","blockers":[],"warnings":[],"bounded_compatibility_edges":[]}`
	if err := os.WriteFile(filepath.Join(dir, "es-writable-state-readiness.json"), []byte(readinessFixture), 0o600); err != nil {
		t.Fatalf("write readiness fixture: %v", err)
	}
	vaultFixture := `{"schema_version":"execution-substrate.remote-alpha.vault-workload-auth-summary.v1","operation_mode":"check_only","collection_status":"collected","overall_classification":"pass","non_mutating":true,"blockers":[],"warnings":[],"auth_smoke":{"jwt_fetch":{"status":"pass"}}}`
	if err := os.WriteFile(filepath.Join(dir, "vault-workload-auth-summary.json"), []byte(vaultFixture), 0o600); err != nil {
		t.Fatalf("write vault fixture: %v", err)
	}
	nestedDir := filepath.Join(dir, "nested")
	if err := os.Mkdir(nestedDir, 0o700); err != nil {
		t.Fatalf("mkdir nested: %v", err)
	}
	nestedRuntime := filepath.Join(nestedDir, "runtime-identity-helper-summary.json")
	if err := os.WriteFile(nestedRuntime, []byte(`{"schema_version":"execution-substrate.remote-runtime-identity-helper-summary.v1alpha1"}`), 0o600); err != nil {
		t.Fatalf("write nested runtime fixture: %v", err)
	}

	output := requireRemoteAlphaOperatorSuccess(t,
		"recovery-session", "--evidence-check",
		"--evidence-dir", dir,
	)
	assertContainsAll(t, "recovery-session evidence dir", output,
		"evidence_dir: "+dir,
		"expected_filename: es-writable-state-readiness.json",
		"expected_filename: vault-workload-auth-summary.json",
		"classification: readiness-summary",
		"classification: vault-workload-auth-summary",
		"schema_interpretation: readiness-summary",
		"schema_interpretation: vault-workload-auth-summary",
		"expected_filename: runtime-identity-helper-summary.json",
		"status: not_supplied",
		"expected_filename: vault-service-user-migration-apply-summary.json",
	)
	assertContainsNone(t, "recovery-session evidence dir", output,
		nestedRuntime,
		"nested/runtime-identity-helper-summary.json",
	)
}

func TestRemoteAlphaOperatorRecoverySessionEvidenceCheckRejectsSecretLikeFixtureWithoutPrintingContents(t *testing.T) {
	dir := t.TempDir()
	fixture := `{"schema_version":"execution-substrate.test.v1","api_key":"DO_NOT_PRINT"}`
	fixturePath := filepath.Join(dir, "secret-like.json")
	if err := os.WriteFile(fixturePath, []byte(fixture), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	output := requireRemoteAlphaOperatorFailure(t,
		"recovery-session", "--evidence-check",
		"--vault-workload-auth-summary", fixturePath,
	)
	assertContainsAll(t, "recovery-session secret-like fixture refusal", output,
		"evidence-check failed for vault-workload-auth-summary",
		"path",
		fixturePath,
		"error_classification: secret_like_key",
	)
	assertContainsNone(t, "recovery-session secret-like fixture refusal", output,
		"api_key",
		"DO_NOT_PRINT",
		"{\"schema_version\"",
	)
}

func TestRemoteAlphaOperatorRecoverySessionEvidenceCheckRejectsMalformedJSON(t *testing.T) {
	dir := t.TempDir()
	fixture := `{"schema_version":`
	fixturePath := filepath.Join(dir, "malformed.json")
	if err := os.WriteFile(fixturePath, []byte(fixture), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	output := requireRemoteAlphaOperatorFailure(t,
		"recovery-session", "--evidence-check",
		"--runtime-identity-summary", fixturePath,
	)
	assertContainsAll(t, "recovery-session malformed fixture refusal", output,
		"evidence-check failed for runtime-identity-summary",
		fixturePath,
		"error_classification: malformed_json",
	)
	assertContainsNone(t, "recovery-session malformed fixture refusal", output,
		fixture,
		"schema_version",
	)
}

func TestRemoteAlphaOperatorRecoverySessionRejectsForbiddenFlagsAndUnsafeArgs(t *testing.T) {
	for _, tc := range []struct {
		name     string
		args     []string
		required []string
	}{
		{
			name:     "ssh target",
			args:     []string{"--ssh-target", "host"},
			required: []string{"recovery-session forbids --ssh-target outside explicit submodes", "safe/local/print-only/evidence-check plus explicit vault-unseal-existing, vault-reset-disposable, vault-workload-auth-check, vault-workload-auth-bootstrap, runtime-identity-summary, es-service-tls, es-governance-tls, and operator-healthcheck-tls submodes", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "interactive sudo",
			args:     []string{"--interactive-sudo"},
			required: []string{"recovery-session forbids --interactive-sudo", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "apply",
			args:     []string{"--apply"},
			required: []string{"recovery-session forbids --apply", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "dry run",
			args:     []string{"--dry-run"},
			required: []string{"recovery-session forbids --dry-run", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "execute reset",
			args:     []string{"--execute-reset"},
			required: []string{"recovery-session forbids --execute-reset", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "unseal only",
			args:     []string{"--unseal-only"},
			required: []string{"recovery-session forbids --unseal-only", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "post unseal check",
			args:     []string{"--post-unseal-check"},
			required: []string{"recovery-session forbids --post-unseal-check", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "governed smoke command",
			args:     []string{"--governed-smoke-command", "echo hi"},
			required: []string{"recovery-session forbids --governed-smoke-command", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "secret equals form",
			args:     []string{"--api-key=dummy"},
			required: []string{"secret material must never be passed by CLI args/env/logs/reports/artifacts"},
		},
		{
			name:     "unknown flag",
			args:     []string{"--unknown-flag"},
			required: []string{"unknown option for recovery-session: --unknown-flag", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "positional",
			args:     []string{"positional"},
			required: []string{"unexpected positional argument for recovery-session: positional", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "equals form",
			args:     []string{"--plan=true"},
			required: []string{"recovery-session does not accept equals-form options: --plan=true", "No recovery-session live helper or IM execution occurred."},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			output := requireRemoteAlphaOperatorFailure(t, append([]string{"recovery-session"}, tc.args...)...)
			assertContainsAll(t, "recovery-session refusal", output, tc.required...)
		})
	}
}

func TestRemoteAlphaOperatorRecoverySessionVaultUnsealExistingRejectsUnsafeArgsBeforeDelegation(t *testing.T) {
	for _, tc := range []struct {
		name     string
		args     []string
		required []string
	}{
		{
			name:     "missing topology",
			args:     []string{},
			required: []string{"recovery-session vault-unseal-existing requires --host-local or --ssh-target <target> --interactive-tty", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "missing interactive tty",
			args:     []string{"--ssh-target", "host"},
			required: []string{"recovery-session vault-unseal-existing --ssh-target requires --interactive-tty", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "missing ssh target",
			args:     []string{"--interactive-tty"},
			required: []string{"recovery-session vault-unseal-existing --interactive-tty requires --ssh-target <target>", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "host local plus ssh target",
			args:     []string{"--host-local", "--ssh-target", "host", "--interactive-tty"},
			required: []string{"recovery-session vault-unseal-existing requires exactly one topology", "--host-local or --ssh-target <target> --interactive-tty", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "execute reset",
			args:     []string{"--execute-reset"},
			required: []string{"recovery-session vault-unseal-existing forbids --execute-reset", "unseal-only, non-destructive, and does not combine checks", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "post unseal check",
			args:     []string{"--post-unseal-check"},
			required: []string{"recovery-session vault-unseal-existing forbids --post-unseal-check", "unseal-only, non-destructive, and does not combine checks", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "unseal only direct flag",
			args:     []string{"--unseal-only"},
			required: []string{"recovery-session vault-unseal-existing forbids --unseal-only", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "keep staging",
			args:     []string{"--keep-staging-on-failure"},
			required: []string{"recovery-session vault-unseal-existing forbids --keep-staging-on-failure", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "apply",
			args:     []string{"--apply"},
			required: []string{"recovery-session vault-unseal-existing forbids --apply", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "dry run",
			args:     []string{"--dry-run"},
			required: []string{"recovery-session vault-unseal-existing forbids --dry-run", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "interactive sudo",
			args:     []string{"--interactive-sudo"},
			required: []string{"recovery-session vault-unseal-existing forbids --interactive-sudo", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "governed smoke command",
			args:     []string{"--governed-smoke-command", "echo hi"},
			required: []string{"recovery-session vault-unseal-existing forbids --governed-smoke-command", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "unknown flag",
			args:     []string{"--unknown-flag"},
			required: []string{"unknown option for recovery-session vault-unseal-existing: --unknown-flag", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "equals form",
			args:     []string{"--host-local=true"},
			required: []string{"recovery-session vault-unseal-existing does not accept equals-form options: --host-local=true", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "positional",
			args:     []string{"unexpected"},
			required: []string{"unexpected positional argument for recovery-session vault-unseal-existing: unexpected", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "duplicate host local",
			args:     []string{"--host-local", "--host-local"},
			required: []string{"duplicate option for recovery-session: --host-local", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "duplicate ssh target",
			args:     []string{"--ssh-target", "a", "--ssh-target", "b", "--interactive-tty"},
			required: []string{"duplicate option for recovery-session: --ssh-target", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "duplicate interactive tty",
			args:     []string{"--ssh-target", "host", "--interactive-tty", "--interactive-tty"},
			required: []string{"duplicate option for recovery-session: --interactive-tty", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "ssh target option injection",
			args:     []string{"--ssh-target", "-oProxyCommand=sh", "--interactive-tty"},
			required: []string{"--ssh-target must be a single SSH target, not an option or shell command", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "ssh target shell command",
			args:     []string{"--ssh-target", "host;echo", "--interactive-tty"},
			required: []string{"--ssh-target must be a single SSH target, not an option or shell command", "No recovery-session live helper or IM execution occurred."},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			output := requireRemoteAlphaOperatorFailure(t, append([]string{"recovery-session", "vault-unseal-existing"}, tc.args...)...)
			assertContainsAll(t, "vault-unseal-existing refusal", output, tc.required...)
			assertContainsNone(t, "vault-unseal-existing refusal", output,
				"Running host-local Vault unseal-only helper",
				"remote_alpha_reset_disposable_vault.sh --unseal-only",
			)
		})
	}
}

func TestRemoteAlphaOperatorRecoverySessionVaultUnsealExistingRejectsSecretLikeArgsBeforeDelegation(t *testing.T) {
	for _, args := range [][]string{
		{"--api-key=dummy"},
		{"--api-key", "dummy"},
		{"--unseal-key", "dummy"},
		{"--unseal-key=dummy"},
		{"--root-token", "dummy"},
		{"--root-token=dummy"},
		{"--vault-token", "dummy"},
		{"--client-token", "dummy"},
		{"--jwt-svid", "dummy"},
		{"--private-key", "dummy"},
		{"--password", "dummy"},
		{"--secret", "dummy"},
	} {
		t.Run(strings.Join(args, "_"), func(t *testing.T) {
			output := requireRemoteAlphaOperatorFailure(t, append([]string{"recovery-session", "vault-unseal-existing"}, args...)...)
			assertContainsAll(t, "vault-unseal-existing secret flag refusal", output,
				"secret material must never be passed by CLI args/env/logs/reports/artifacts",
			)
			assertContainsNone(t, "vault-unseal-existing secret flag refusal", output,
				"Running host-local Vault unseal-only helper",
				"remote_alpha_reset_disposable_vault.sh --unseal-only",
			)
		})
	}
}

func TestRemoteAlphaOperatorRecoverySessionVaultResetDisposableRejectsUnsafeArgsBeforeDelegation(t *testing.T) {
	for _, tc := range []struct {
		name     string
		args     []string
		required []string
	}{
		{
			name:     "missing ssh target",
			args:     []string{},
			required: []string{"recovery-session vault-reset-disposable requires --ssh-target <target>", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "missing dry run",
			args:     []string{"--ssh-target", "host"},
			required: []string{"recovery-session vault-reset-disposable requires --dry-run or --execute-reset", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "execute reset missing ssh target",
			args:     []string{"--execute-reset"},
			required: []string{"recovery-session vault-reset-disposable requires --ssh-target <target>", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "execute reset missing interactive tty",
			args:     []string{"--ssh-target", "host", "--execute-reset"},
			required: []string{"recovery-session vault-reset-disposable --execute-reset requires --interactive-tty", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "execute reset plus dry run",
			args:     []string{"--ssh-target", "host", "--execute-reset", "--dry-run"},
			required: []string{"recovery-session vault-reset-disposable requires exactly one mode: --dry-run or --execute-reset", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "unseal only",
			args:     []string{"--unseal-only"},
			required: []string{"recovery-session vault-reset-disposable forbids --unseal-only", "does not combine reset, unseal, post-unseal checks", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "post unseal check",
			args:     []string{"--ssh-target", "host", "--execute-reset", "--post-unseal-check"},
			required: []string{"recovery-session vault-reset-disposable forbids --post-unseal-check", "does not combine reset, unseal, post-unseal checks", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "host local",
			args:     []string{"--ssh-target", "host", "--execute-reset", "--host-local"},
			required: []string{"recovery-session vault-reset-disposable forbids --host-local", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "interactive tty",
			args:     []string{"--ssh-target", "host", "--dry-run", "--interactive-tty"},
			required: []string{"recovery-session vault-reset-disposable forbids --interactive-tty", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "interactive sudo",
			args:     []string{"--interactive-sudo"},
			required: []string{"recovery-session vault-reset-disposable forbids --interactive-sudo", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "apply",
			args:     []string{"--apply"},
			required: []string{"recovery-session vault-reset-disposable forbids --apply", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "keep staging",
			args:     []string{"--keep-staging-on-failure"},
			required: []string{"recovery-session vault-reset-disposable forbids --keep-staging-on-failure", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "governed smoke command",
			args:     []string{"--governed-smoke-command", "echo hi"},
			required: []string{"recovery-session vault-reset-disposable forbids --governed-smoke-command", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "unknown flag",
			args:     []string{"--ssh-target", "host", "--dry-run", "--unknown-flag"},
			required: []string{"unknown option for recovery-session vault-reset-disposable: --unknown-flag", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "equals form",
			args:     []string{"--ssh-target=host", "--dry-run"},
			required: []string{"recovery-session vault-reset-disposable does not accept equals-form options: --ssh-target=host", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "positional",
			args:     []string{"--ssh-target", "host", "--dry-run", "unexpected"},
			required: []string{"unexpected positional argument for recovery-session vault-reset-disposable: unexpected", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "duplicate ssh target",
			args:     []string{"--ssh-target", "a", "--ssh-target", "b", "--dry-run"},
			required: []string{"duplicate option for recovery-session: --ssh-target", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "duplicate dry run",
			args:     []string{"--ssh-target", "host", "--dry-run", "--dry-run"},
			required: []string{"duplicate option for recovery-session: --dry-run", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "duplicate execute reset",
			args:     []string{"--ssh-target", "host", "--execute-reset", "--execute-reset", "--interactive-tty"},
			required: []string{"duplicate option for recovery-session: --execute-reset", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "duplicate interactive tty",
			args:     []string{"--ssh-target", "host", "--execute-reset", "--interactive-tty", "--interactive-tty"},
			required: []string{"duplicate option for recovery-session: --interactive-tty", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "ssh target option injection",
			args:     []string{"--ssh-target", "-oProxyCommand=sh", "--dry-run"},
			required: []string{"--ssh-target must be a single SSH target, not an option or shell command", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "ssh target shell command",
			args:     []string{"--ssh-target", "host;echo", "--dry-run"},
			required: []string{"--ssh-target must be a single SSH target, not an option or shell command", "No recovery-session live helper or IM execution occurred."},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			output := requireRemoteAlphaOperatorFailure(t, append([]string{"recovery-session", "vault-reset-disposable"}, tc.args...)...)
			assertContainsAll(t, "vault-reset-disposable refusal", output, tc.required...)
			assertContainsNone(t, "vault-reset-disposable refusal", output,
				"Running Mac-side disposable Vault reset dry-run planning route",
				"Running Mac-side disposable Vault execute-reset",
				"remote_alpha_reset_disposable_vault.sh --dry-run",
				"remote_alpha_reset_disposable_vault.sh --execute-reset",
			)
		})
	}
}

func TestRemoteAlphaOperatorRecoverySessionVaultResetDisposableRejectsSecretLikeArgsBeforeDelegation(t *testing.T) {
	for _, args := range [][]string{
		{"--api-key=dummy"},
		{"--api-key", "dummy"},
		{"--unseal-key", "dummy"},
		{"--unseal-key=dummy"},
		{"--root-token", "dummy"},
		{"--root-token=dummy"},
		{"--vault-token", "dummy"},
		{"--client-token", "dummy"},
		{"--jwt-svid", "dummy"},
		{"--private-key", "dummy"},
		{"--password", "dummy"},
		{"--secret", "dummy"},
	} {
		t.Run(strings.Join(args, "_"), func(t *testing.T) {
			output := requireRemoteAlphaOperatorFailure(t, append([]string{"recovery-session", "vault-reset-disposable"}, args...)...)
			assertContainsAll(t, "vault-reset-disposable secret flag refusal", output,
				"secret material must never be passed by CLI args/env/logs/reports/artifacts",
			)
			assertContainsNone(t, "vault-reset-disposable secret flag refusal", output,
				"Running Mac-side disposable Vault reset dry-run planning route",
				"Running Mac-side disposable Vault execute-reset",
				"remote_alpha_reset_disposable_vault.sh --dry-run",
				"remote_alpha_reset_disposable_vault.sh --execute-reset",
			)
		})
	}
}

func TestRemoteAlphaOperatorRecoverySessionVaultWorkloadAuthCheckRejectsUnsafeArgsBeforeDelegation(t *testing.T) {
	for _, tc := range []struct {
		name     string
		args     []string
		required []string
	}{
		{
			name:     "missing ssh target",
			args:     []string{},
			required: []string{"recovery-session vault-workload-auth-check requires --ssh-target <target>", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "missing interactive tty",
			args:     []string{"--ssh-target", "host"},
			required: []string{"recovery-session vault-workload-auth-check requires --interactive-tty", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "missing ssh target with tty",
			args:     []string{"--interactive-tty"},
			required: []string{"recovery-session vault-workload-auth-check requires --ssh-target <target>", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "host local",
			args:     []string{"--host-local"},
			required: []string{"recovery-session vault-workload-auth-check forbids --host-local", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "dry run",
			args:     []string{"--dry-run"},
			required: []string{"recovery-session vault-workload-auth-check forbids --dry-run", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "execute reset",
			args:     []string{"--execute-reset"},
			required: []string{"recovery-session vault-workload-auth-check forbids --execute-reset", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "unseal only",
			args:     []string{"--unseal-only"},
			required: []string{"recovery-session vault-workload-auth-check forbids --unseal-only", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "post unseal",
			args:     []string{"--post-unseal-check"},
			required: []string{"recovery-session vault-workload-auth-check forbids --post-unseal-check", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "governed smoke command",
			args:     []string{"--governed-smoke-command", "echo hi"},
			required: []string{"recovery-session vault-workload-auth-check forbids --governed-smoke-command", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "apply",
			args:     []string{"--apply"},
			required: []string{"recovery-session vault-workload-auth-check forbids --apply", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "interactive sudo",
			args:     []string{"--interactive-sudo"},
			required: []string{"recovery-session vault-workload-auth-check forbids --interactive-sudo", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "vault addr override",
			args:     []string{"--vault-addr", "https://vault"},
			required: []string{"forbids helper override flag --vault-addr", "canonical remote summary path", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "vault role override",
			args:     []string{"--vault-role", "role"},
			required: []string{"forbids helper override flag --vault-role", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "vault audience override",
			args:     []string{"--vault-audience", "aud"},
			required: []string{"forbids helper override flag --vault-audience", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "spiffe id override",
			args:     []string{"--spiffe-id", "spiffe://example/workload"},
			required: []string{"forbids helper override flag --spiffe-id", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "summary path override",
			args:     []string{"--summary-path", "/tmp/x"},
			required: []string{"forbids helper override flag --summary-path", "canonical remote summary path", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "config path override",
			args:     []string{"--config-path", "/tmp/config.json"},
			required: []string{"forbids helper override flag --config-path", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "unknown flag",
			args:     []string{"--ssh-target", "host", "--interactive-tty", "--unknown-flag"},
			required: []string{"unknown option for recovery-session vault-workload-auth-check: --unknown-flag", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "equals form",
			args:     []string{"--ssh-target=host", "--interactive-tty"},
			required: []string{"recovery-session vault-workload-auth-check does not accept equals-form options: --ssh-target=host", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "helper override equals form",
			args:     []string{"--vault-role=role"},
			required: []string{"forbids helper override flag --vault-role=role", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "positional",
			args:     []string{"--ssh-target", "host", "--interactive-tty", "unexpected"},
			required: []string{"unexpected positional argument for recovery-session vault-workload-auth-check: unexpected", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "duplicate ssh target",
			args:     []string{"--ssh-target", "a", "--ssh-target", "b", "--interactive-tty"},
			required: []string{"duplicate option for recovery-session: --ssh-target", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "duplicate interactive tty",
			args:     []string{"--ssh-target", "host", "--interactive-tty", "--interactive-tty"},
			required: []string{"duplicate option for recovery-session: --interactive-tty", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "ssh target option injection",
			args:     []string{"--ssh-target", "-oProxyCommand=sh", "--interactive-tty"},
			required: []string{"--ssh-target must be a single SSH target, not an option or shell command", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "ssh target shell command",
			args:     []string{"--ssh-target", "host;echo", "--interactive-tty"},
			required: []string{"--ssh-target must be a single SSH target, not an option or shell command", "No recovery-session live helper or IM execution occurred."},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			output := requireRemoteAlphaOperatorFailure(t, append([]string{"recovery-session", "vault-workload-auth-check"}, tc.args...)...)
			assertContainsAll(t, "vault-workload-auth-check refusal", output, tc.required...)
			assertContainsNone(t, "vault-workload-auth-check refusal", output,
				"Running Mac-side Vault workload-auth evidence check",
				"remote_alpha_vault_workload_auth_check.sh",
			)
		})
	}
}

func TestRemoteAlphaOperatorRecoverySessionVaultWorkloadAuthCheckRejectsSecretLikeArgsBeforeDelegation(t *testing.T) {
	for _, args := range [][]string{
		{"--api-key=dummy"},
		{"--api-key", "dummy"},
		{"--vault-token", "dummy"},
		{"--jwt-svid", "dummy"},
		{"--private-key", "dummy"},
		{"--root-token", "dummy"},
		{"--unseal-key", "dummy"},
		{"--client-token", "dummy"},
		{"--password", "dummy"},
		{"--secret", "dummy"},
	} {
		t.Run(strings.Join(args, "_"), func(t *testing.T) {
			output := requireRemoteAlphaOperatorFailure(t, append([]string{"recovery-session", "vault-workload-auth-check"}, args...)...)
			assertContainsAll(t, "vault-workload-auth-check secret flag refusal", output,
				"secret material must never be passed by CLI args/env/logs/reports/artifacts",
			)
			assertContainsNone(t, "vault-workload-auth-check secret flag refusal", output,
				"Running Mac-side Vault workload-auth evidence check",
				"remote_alpha_vault_workload_auth_check.sh",
			)
		})
	}
}

func TestRemoteAlphaOperatorRecoverySessionRuntimeIdentitySummaryRejectsUnsafeArgsBeforeDelegation(t *testing.T) {
	for _, tc := range []struct {
		name     string
		args     []string
		required []string
	}{
		{
			name:     "missing ssh target",
			args:     []string{},
			required: []string{"recovery-session runtime-identity-summary requires --ssh-target <target>", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "missing interactive tty",
			args:     []string{"--ssh-target", "host"},
			required: []string{"recovery-session runtime-identity-summary requires --interactive-tty", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "missing ssh target with tty",
			args:     []string{"--interactive-tty"},
			required: []string{"recovery-session runtime-identity-summary requires --ssh-target <target>", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "host local",
			args:     []string{"--host-local"},
			required: []string{"recovery-session runtime-identity-summary forbids --host-local", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "dry run",
			args:     []string{"--dry-run"},
			required: []string{"recovery-session runtime-identity-summary forbids --dry-run", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "check only",
			args:     []string{"--check-only"},
			required: []string{"recovery-session runtime-identity-summary forbids --check-only", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "execute reset",
			args:     []string{"--execute-reset"},
			required: []string{"recovery-session runtime-identity-summary forbids --execute-reset", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "execute bootstrap",
			args:     []string{"--execute-bootstrap"},
			required: []string{"recovery-session runtime-identity-summary forbids --execute-bootstrap", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "prepare summary path",
			args:     []string{"--prepare-summary-path"},
			required: []string{"recovery-session runtime-identity-summary forbids --prepare-summary-path", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "workload auth override",
			args:     []string{"--audience", "vault"},
			required: []string{"forbids helper override flag --audience", "canonical remote summary path", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "spire socket override",
			args:     []string{"--spire-agent-socket-path", "/tmp/socket"},
			required: []string{"forbids helper override flag --spire-agent-socket-path", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "unknown flag",
			args:     []string{"--ssh-target", "host", "--interactive-tty", "--unknown-flag"},
			required: []string{"unknown option for recovery-session runtime-identity-summary: --unknown-flag", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "equals form",
			args:     []string{"--ssh-target=host", "--interactive-tty"},
			required: []string{"recovery-session runtime-identity-summary does not accept equals-form options: --ssh-target=host", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "helper override equals form",
			args:     []string{"--runtime-support-path=/tmp/helper"},
			required: []string{"forbids helper override flag --runtime-support-path=/tmp/helper", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "positional",
			args:     []string{"--ssh-target", "host", "--interactive-tty", "unexpected"},
			required: []string{"unexpected positional argument for recovery-session runtime-identity-summary: unexpected", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "duplicate ssh target",
			args:     []string{"--ssh-target", "a", "--ssh-target", "b", "--interactive-tty"},
			required: []string{"duplicate option for recovery-session: --ssh-target", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "duplicate interactive tty",
			args:     []string{"--ssh-target", "host", "--interactive-tty", "--interactive-tty"},
			required: []string{"duplicate option for recovery-session: --interactive-tty", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "ssh target option injection",
			args:     []string{"--ssh-target", "-oProxyCommand=sh", "--interactive-tty"},
			required: []string{"--ssh-target must be a single SSH target, not an option or shell command", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "ssh target shell command",
			args:     []string{"--ssh-target", "host;echo", "--interactive-tty"},
			required: []string{"--ssh-target must be a single SSH target, not an option or shell command", "No recovery-session live helper or IM execution occurred."},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			output := requireRemoteAlphaOperatorFailure(t, append([]string{"recovery-session", "runtime-identity-summary"}, tc.args...)...)
			assertContainsAll(t, "runtime-identity-summary refusal", output, tc.required...)
			assertContainsNone(t, "runtime-identity-summary refusal", output,
				"Running Mac-side runtime identity helper summary",
				"remote_alpha_runtime_identity_helper_summary.sh",
			)
		})
	}
}

func TestRemoteAlphaOperatorRecoverySessionRuntimeIdentitySummaryRejectsSecretLikeArgsBeforeDelegation(t *testing.T) {
	for _, args := range [][]string{
		{"--api-key=dummy"},
		{"--api-key", "dummy"},
		{"--vault-token", "dummy"},
		{"--jwt-svid", "dummy"},
		{"--private-key", "dummy"},
		{"--root-token", "dummy"},
		{"--unseal-key", "dummy"},
		{"--client-token", "dummy"},
		{"--password", "dummy"},
		{"--secret", "dummy"},
	} {
		t.Run(strings.Join(args, "_"), func(t *testing.T) {
			output := requireRemoteAlphaOperatorFailure(t, append([]string{"recovery-session", "runtime-identity-summary"}, args...)...)
			assertContainsAll(t, "runtime-identity-summary secret flag refusal", output,
				"secret material must never be passed by CLI args/env/logs/reports/artifacts",
			)
			assertContainsNone(t, "runtime-identity-summary secret flag refusal", output,
				"Running Mac-side runtime identity helper summary",
				"remote_alpha_runtime_identity_helper_summary.sh",
			)
		})
	}
}

func TestRemoteAlphaOperatorRecoverySessionVaultWorkloadAuthBootstrapPrintsPlanInventoryAndHelp(t *testing.T) {
	for _, tc := range []struct {
		name     string
		args     []string
		required []string
	}{
		{
			name: "default plan",
			args: []string{"recovery-session", "vault-workload-auth-bootstrap"},
			required: []string{
				"Remote Alpha Vault workload-auth bootstrap plan (P0q safe modes plus staged execution)",
				"route mechanics partially passed",
				"vault.initialized=true",
				"vault.sealed=false",
				"vault.auth_mount=jwt",
				"vault.role=service_execution",
				"vault.audience=vault",
				"vault_workload_auth_smoke=fail",
				"auth_smoke.vault_login=fail",
				"Vault JWT login rejected or not configured",
				"auth mount: jwt",
				"JWT auth config: SPIRE JWT validation material selected for the workload trust domain and bound issuer",
				"role: service_execution",
				"role_type=jwt",
				"user_claim=sub",
				"bound_audiences=vault",
				"bound_subject=spiffe://execution.internal/workload",
				"policy such as runtime-identity-proof",
				"proof-secrets/data/runtime-identity-vault-login",
				"proof-secrets/data/codex-runtime-profile",
				"api_key present and non-empty; value never printed",
				"/etc/execution-substrate/vault/workload-zone-vault-config.json",
				"Implemented execution contract",
				"recovery-session vault-workload-auth-bootstrap --ssh-target <target> --prepare-summary-path --interactive-tty",
				"runs only bounded remote filesystem preparation",
				"may use visible OS sudo",
				"recovery-session vault-workload-auth-bootstrap --ssh-target <target> --prepare-config-readability --interactive-tty",
				"fixed-path user ACLs",
				"config contents are never printed",
				"recovery-session vault-workload-auth-bootstrap --ssh-target <target> --prepare-spire-bundle-read --interactive-tty",
				"fixed SPIRE server bundle-read access",
				"bundle output is discarded and never printed",
				"optional combined form may add --prepare-summary-path, --prepare-config-readability, and --prepare-spire-bundle-read",
				"recovery-session vault-workload-auth-bootstrap --ssh-target <target> --execute-bootstrap --interactive-tty",
				"stages only scripts/remote_alpha_vault_workload_auth_bootstrap.sh and scripts/internal/remote_alpha_vault_workload_auth_bootstrap.sh",
				"root token must never be accepted as a CLI arg, env var, file, .out, report, support bundle, retained bundle, or Codex output",
				"explicit visible or silent operator prompt",
				"no transcript capture, no tee, no script",
				"proof secret values must never be printed, copied, summarized, or logged",
				"must not claim workload-auth success",
				"vault-workload-auth-bootstrap-summary.json",
				"workload-auth check remains a separate command after bootstrap",
				"not ES Vault token brokerage",
				"not Remote Alpha deployment, provisioning, or reconciliation architecture",
			},
		},
		{
			name: "explicit plan",
			args: []string{"recovery-session", "vault-workload-auth-bootstrap", "--plan"},
			required: []string{
				"Remote Alpha Vault workload-auth bootstrap plan (P0q safe modes plus staged execution)",
				"conservative classification: Vault JWT login rejected or not configured",
				"bootstrap configures expected Vault objects only and must not claim workload-auth success",
			},
		},
		{
			name: "help",
			args: []string{"recovery-session", "vault-workload-auth-bootstrap", "--help"},
			required: []string{
				"Remote Alpha recovery-session mode: vault-workload-auth-bootstrap",
				"P0q scope: safe local/print-only planning plus bounded summary-path, config-readability, and SPIRE bundle-read preparation and Mac-side staged bootstrap execution",
				"Allowed flags:",
				"--help",
				"--plan",
				"--inventory",
				"--ssh-target <target>",
				"--execute-bootstrap",
				"--prepare-summary-path",
				"--prepare-config-readability",
				"--prepare-spire-bundle-read",
				"--interactive-tty",
				"Default behavior: print the bootstrap plan/help and exit zero.",
				"Topology rules:",
				"summary-path, config-readability, and SPIRE bundle-read preparation may prompt only for OS sudo",
				"Secret posture:",
				"not workload-auth success",
				"not ES Vault token brokerage",
			},
		},
		{
			name: "inventory",
			args: []string{"recovery-session", "vault-workload-auth-bootstrap", "--inventory"},
			required: []string{
				"Remote Alpha Vault workload-auth bootstrap inventory (P0q)",
				"static local inventory only",
				"recovery-session vault-workload-auth-bootstrap --help",
				"recovery-session vault-workload-auth-bootstrap --plan",
				"recovery-session vault-workload-auth-bootstrap --inventory",
				"recovery-session vault-workload-auth-bootstrap --ssh-target <target> --prepare-summary-path --interactive-tty",
				"run only the bounded remote filesystem preparation command",
				"recovery-session vault-workload-auth-bootstrap --ssh-target <target> --prepare-config-readability --interactive-tty",
				"fixed workload-zone config readability",
				"recovery-session vault-workload-auth-bootstrap --ssh-target <target> --prepare-spire-bundle-read --interactive-tty",
				"fixed SPIRE server bundle-read access",
				"recovery-session vault-workload-auth-bootstrap --ssh-target <target> --execute-bootstrap --prepare-summary-path --prepare-config-readability --prepare-spire-bundle-read --interactive-tty",
				"prepare the summary path, then config readability, then SPIRE bundle-read access before staging",
				"recovery-session vault-workload-auth-bootstrap --ssh-target <target> --execute-bootstrap --interactive-tty",
				"stage the dedicated bootstrap helper pair",
				"live validation - not performed",
				"workload-auth check execution, reset/unseal, IM, support bundle, CP proof, and runtime identity generation - not part of bootstrap",
				"role service_execution with role_type=jwt",
				"proof-secrets/data/runtime-identity-vault-login",
				"proof-secrets/data/codex-runtime-profile",
				"api_key field present and non-empty; proof secret value never printed",
				"preparation creates no final bootstrap summary and no Mac artifact",
				"execution writes only a remote non-secret summary; no Mac .out; no operator summary",
				"Vault owns token, secret, and lease authority",
				"SPIRE owns JWT-SVID issuance",
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			output := requireRemoteAlphaOperatorSuccess(t, tc.args...)
			assertContainsAll(t, "vault-workload-auth-bootstrap output", output, tc.required...)
			assertContainsNone(t, "vault-workload-auth-bootstrap output", output,
				"Running Mac-side Vault workload-auth evidence check",
				"wrote /var/tmp",
				"not available in P0q",
			)
		})
	}
}

func TestRemoteAlphaOperatorRecoverySessionVaultWorkloadAuthBootstrapRejectsUnsafeArgs(t *testing.T) {
	for _, tc := range []struct {
		name     string
		args     []string
		required []string
	}{
		{
			name:     "execute bootstrap",
			args:     []string{"--execute-bootstrap"},
			required: []string{"recovery-session vault-workload-auth-bootstrap --execute-bootstrap requires --ssh-target <target>", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "ssh target",
			args:     []string{"--ssh-target", "host"},
			required: []string{"recovery-session vault-workload-auth-bootstrap --ssh-target is valid only with --execute-bootstrap, --prepare-summary-path, --prepare-config-readability, or --prepare-spire-bundle-read", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "interactive tty",
			args:     []string{"--interactive-tty"},
			required: []string{"recovery-session vault-workload-auth-bootstrap --interactive-tty is valid only with --execute-bootstrap, --prepare-summary-path, --prepare-config-readability, or --prepare-spire-bundle-read", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "prepare summary path missing ssh target and tty",
			args:     []string{"--prepare-summary-path"},
			required: []string{"recovery-session vault-workload-auth-bootstrap --prepare-summary-path requires --ssh-target <target>", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "prepare summary path missing tty",
			args:     []string{"--ssh-target", "host", "--prepare-summary-path"},
			required: []string{"recovery-session vault-workload-auth-bootstrap --prepare-summary-path requires --interactive-tty", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "prepare summary path missing ssh target",
			args:     []string{"--interactive-tty", "--prepare-summary-path"},
			required: []string{"recovery-session vault-workload-auth-bootstrap --prepare-summary-path requires --ssh-target <target>", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "prepare config readability missing ssh target and tty",
			args:     []string{"--prepare-config-readability"},
			required: []string{"recovery-session vault-workload-auth-bootstrap --prepare-config-readability requires --ssh-target <target>", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "prepare config readability missing tty",
			args:     []string{"--ssh-target", "host", "--prepare-config-readability"},
			required: []string{"recovery-session vault-workload-auth-bootstrap --prepare-config-readability requires --interactive-tty", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "prepare config readability missing ssh target",
			args:     []string{"--interactive-tty", "--prepare-config-readability"},
			required: []string{"recovery-session vault-workload-auth-bootstrap --prepare-config-readability requires --ssh-target <target>", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "prepare spire bundle read missing ssh target and tty",
			args:     []string{"--prepare-spire-bundle-read"},
			required: []string{"recovery-session vault-workload-auth-bootstrap --prepare-spire-bundle-read requires --ssh-target <target>", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "prepare spire bundle read missing tty",
			args:     []string{"--ssh-target", "host", "--prepare-spire-bundle-read"},
			required: []string{"recovery-session vault-workload-auth-bootstrap --prepare-spire-bundle-read requires --interactive-tty", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "prepare spire bundle read missing ssh target",
			args:     []string{"--interactive-tty", "--prepare-spire-bundle-read"},
			required: []string{"recovery-session vault-workload-auth-bootstrap --prepare-spire-bundle-read requires --ssh-target <target>", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "host local",
			args:     []string{"--host-local"},
			required: []string{"recovery-session vault-workload-auth-bootstrap forbids --host-local", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "execute reset",
			args:     []string{"--execute-reset"},
			required: []string{"recovery-session vault-workload-auth-bootstrap forbids --execute-reset", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "dry run",
			args:     []string{"--dry-run"},
			required: []string{"recovery-session vault-workload-auth-bootstrap forbids --dry-run", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "unseal only",
			args:     []string{"--unseal-only"},
			required: []string{"recovery-session vault-workload-auth-bootstrap forbids --unseal-only", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "post unseal",
			args:     []string{"--post-unseal-check"},
			required: []string{"recovery-session vault-workload-auth-bootstrap forbids --post-unseal-check", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "apply",
			args:     []string{"--apply"},
			required: []string{"recovery-session vault-workload-auth-bootstrap forbids --apply", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "governed smoke",
			args:     []string{"--governed-smoke-command", "echo hi"},
			required: []string{"recovery-session vault-workload-auth-bootstrap forbids --governed-smoke-command", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "helper override",
			args:     []string{"--vault-role", "other"},
			required: []string{"forbids helper override flag --vault-role", "fixed documented bootstrap values", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "proof value",
			args:     []string{"--proof-secret-value", "dummy"},
			required: []string{"forbids proof secret value flag --proof-secret-value", "proof secret values must never be passed", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "unknown flag",
			args:     []string{"--unknown-flag"},
			required: []string{"unknown option for recovery-session vault-workload-auth-bootstrap: --unknown-flag", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "equals form",
			args:     []string{"--plan=true"},
			required: []string{"recovery-session vault-workload-auth-bootstrap does not accept equals-form options: --plan=true", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "positional",
			args:     []string{"unexpected"},
			required: []string{"unexpected positional argument for recovery-session vault-workload-auth-bootstrap: unexpected", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "duplicate mode",
			args:     []string{"--plan", "--inventory"},
			required: []string{"duplicate option for recovery-session: --inventory", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "duplicate prepare summary path",
			args:     []string{"--ssh-target", "host", "--prepare-summary-path", "--prepare-summary-path", "--interactive-tty"},
			required: []string{"duplicate option for recovery-session: --prepare-summary-path", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "duplicate prepare config readability",
			args:     []string{"--ssh-target", "host", "--prepare-config-readability", "--prepare-config-readability", "--interactive-tty"},
			required: []string{"duplicate option for recovery-session: --prepare-config-readability", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "duplicate prepare spire bundle read",
			args:     []string{"--ssh-target", "host", "--prepare-spire-bundle-read", "--prepare-spire-bundle-read", "--interactive-tty"},
			required: []string{"duplicate option for recovery-session: --prepare-spire-bundle-read", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "safe mode with prepare config readability",
			args:     []string{"--plan", "--prepare-config-readability"},
			required: []string{"safe modes are mutually exclusive with --execute-bootstrap, --prepare-summary-path, --prepare-config-readability, and --prepare-spire-bundle-read", "No recovery-session live helper or IM execution occurred."},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			output := requireRemoteAlphaOperatorFailure(t, append([]string{"recovery-session", "vault-workload-auth-bootstrap"}, tc.args...)...)
			assertContainsAll(t, "vault-workload-auth-bootstrap refusal", output, tc.required...)
			assertContainsNone(t, "vault-workload-auth-bootstrap refusal", output,
				"Remote Alpha Vault workload-auth bootstrap plan (P0o print-only)",
				"Remote Alpha Vault workload-auth bootstrap plan (P0q safe modes plus staged execution)",
				"Running Mac-side Vault workload-auth evidence check",
				"remote_alpha_vault_workload_auth_check.sh",
			)
		})
	}
}

func TestRemoteAlphaOperatorRecoverySessionVaultWorkloadAuthBootstrapRejectsSecretLikeArgsBeforePlanning(t *testing.T) {
	for _, args := range [][]string{
		{"--root-token", "dummy"},
		{"--unseal-key", "dummy"},
		{"--client-token", "dummy"},
		{"--vault-token", "dummy"},
		{"--api-key", "dummy"},
		{"--api-key=dummy"},
		{"--jwt-svid", "dummy"},
		{"--private-key", "dummy"},
		{"--password", "dummy"},
		{"--secret", "dummy"},
	} {
		t.Run(strings.Join(args, "_"), func(t *testing.T) {
			output := requireRemoteAlphaOperatorFailure(t, append([]string{"recovery-session", "vault-workload-auth-bootstrap"}, args...)...)
			assertContainsAll(t, "vault-workload-auth-bootstrap secret flag refusal", output,
				"secret material must never be passed by CLI args/env/logs/reports/artifacts",
			)
			assertContainsNone(t, "vault-workload-auth-bootstrap secret flag refusal", output,
				"Remote Alpha Vault workload-auth bootstrap plan (P0o print-only)",
				"Remote Alpha Vault workload-auth bootstrap plan (P0q safe modes plus staged execution)",
				"Remote Alpha Vault workload-auth bootstrap inventory",
			)
		})
	}
}

func TestRemoteAlphaOperatorRecoverySessionVaultResetDisposableExecuteResetRejectsSecretLikeArgsBeforeDelegation(t *testing.T) {
	for _, args := range [][]string{
		{"--api-key=dummy"},
		{"--root-token", "dummy"},
		{"--unseal-key", "dummy"},
		{"--vault-token", "dummy"},
		{"--client-token", "dummy"},
		{"--jwt-svid", "dummy"},
		{"--private-key", "dummy"},
		{"--password", "dummy"},
		{"--secret", "dummy"},
	} {
		t.Run(strings.Join(args, "_"), func(t *testing.T) {
			routeArgs := append([]string{
				"recovery-session", "vault-reset-disposable",
				"--ssh-target", "host",
				"--execute-reset",
				"--interactive-tty",
			}, args...)
			output := requireRemoteAlphaOperatorFailure(t, routeArgs...)
			assertContainsAll(t, "vault-reset-disposable execute secret flag refusal", output,
				"secret material must never be passed by CLI args/env/logs/reports/artifacts",
			)
			assertContainsNone(t, "vault-reset-disposable execute secret flag refusal", output,
				"Running Mac-side disposable Vault execute-reset",
				"remote_alpha_reset_disposable_vault.sh --execute-reset",
			)
		})
	}
}

type fakeRemoteAlphaUnsealHarness struct {
	localBin   string
	remoteBin  string
	remoteRoot string
	sshLogPath string
	scpLogPath string
	rmLogPath  string
	helperLog  string
}

func setupFakeRemoteAlphaUnsealHarness(t *testing.T) *fakeRemoteAlphaUnsealHarness {
	t.Helper()

	tmpDir := t.TempDir()
	h := &fakeRemoteAlphaUnsealHarness{
		localBin:   filepath.Join(tmpDir, "local-bin"),
		remoteBin:  filepath.Join(tmpDir, "remote-bin"),
		remoteRoot: filepath.Join(tmpDir, "remote-root"),
		sshLogPath: filepath.Join(tmpDir, "ssh.log"),
		scpLogPath: filepath.Join(tmpDir, "scp.log"),
		rmLogPath:  filepath.Join(tmpDir, "rm.log"),
		helperLog:  filepath.Join(tmpDir, "helper.log"),
	}
	for _, dir := range []string{h.localBin, h.remoteBin, h.remoteRoot} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", dir, err)
		}
	}

	writeExecutable(t, h.localBin, "ssh", fmt.Sprintf(`#!/usr/bin/env bash
set -euo pipefail
tty=false
while [[ "${1:-}" == "-tt" ]]; do
  tty=true
  shift
done
target="${1:-}"
shift || true
printf 'tty=%%s target=%%s args=%%s\n' "${tty}" "${target}" "$*" >> %q
export PATH="${FAKE_REMOTE_BIN}:${PATH}"
if [[ "${1:-}" == "/bin/bash" && "${2:-}" == "-s" ]]; then
  shift 2
  if [[ "${1:-}" == "--" ]]; then
    shift
  fi
  mapped_args=()
  for arg in "$@"; do
    if [[ "${arg}" == /* ]]; then
      mapped_args+=("${FAKE_REMOTE_ROOT}${arg}")
    else
      mapped_args+=("${arg}")
    fi
  done
  payload="$(mktemp)"
  cat >"${payload}"
  set +e
  /bin/bash "${payload}" "${mapped_args[@]}"
  status=$?
  set -e
  rm -f -- "${payload}"
  exit "${status}"
fi
if [[ "${1:-}" == "/bin/bash" && "${2:-}" == "-c" ]]; then
  command_string="${3:-}"
  remote_prefix="/tmp/execution-substrate-remote-alpha-vault-unseal-existing"
  mapped_prefix="${FAKE_REMOTE_ROOT}${remote_prefix}"
  mapped_command="${command_string//${remote_prefix}/${mapped_prefix}}"
  exec /bin/bash -c "${mapped_command}"
fi
if [[ "$#" -eq 1 && "${1:-}" == exec\ /bin/bash\ -c* ]]; then
  command_string="${1}"
  remote_prefix="/tmp/execution-substrate-remote-alpha-vault-unseal-existing"
  mapped_prefix="${FAKE_REMOTE_ROOT}${remote_prefix}"
  mapped_command="${command_string//${remote_prefix}/${mapped_prefix}}"
  exec /bin/bash -c "${mapped_command}"
fi
echo "unexpected fake ssh invocation: $*" >&2
exit 64
`, h.sshLogPath))

	writeExecutable(t, h.localBin, "scp", fmt.Sprintf(`#!/usr/bin/env bash
set -euo pipefail
if [[ "$#" -ne 2 ]]; then
  echo "unexpected fake scp args: $*" >&2
  exit 64
fi
src=$1
dest=$2
printf '%%s\t%%s\n' "${src}" "${dest}" >> %q
if [[ "${src}" == *:* || "${dest}" != *:* ]]; then
  echo "fake scp supports one local-to-remote helper upload" >&2
  exit 64
fi
remote_path="${dest#*:}"
mapped_dest="${FAKE_REMOTE_ROOT}${remote_path}"
mkdir -p -- "$(dirname "${mapped_dest}")"
cat >"${mapped_dest}" <<'REMOTE_ALPHA_FAKE_UNSEAL_HELPER'
#!/usr/bin/env bash
set -euo pipefail
printf '%%s\n' "$*" >> %q
REMOTE_ALPHA_FAKE_UNSEAL_HELPER
chmod 0700 "${mapped_dest}"
`, h.scpLogPath, h.helperLog))

	writeExecutable(t, h.remoteBin, "rm", fmt.Sprintf(`#!/usr/bin/env bash
set -euo pipefail
printf '%%s\n' "$*" >> %q
exec /bin/rm "$@"
`, h.rmLogPath))

	return h
}

func (h *fakeRemoteAlphaUnsealHarness) env() []string {
	return envWithPath(h.localBin,
		"FAKE_REMOTE_BIN="+h.remoteBin,
		"FAKE_REMOTE_ROOT="+h.remoteRoot,
	)
}

func TestRemoteAlphaOperatorRecoverySessionVaultUnsealExistingNoTTYFailsBeforeStaging(t *testing.T) {
	h := setupFakeRemoteAlphaUnsealHarness(t)
	output, err := runRemoteAlphaOperatorWithEnv(h.env(),
		"recovery-session", "vault-unseal-existing",
		"--ssh-target", "ds@m75q-test",
		"--interactive-tty",
	)
	if err == nil {
		t.Fatalf("expected no-TTY failure before staging, got success:\n%s", output)
	}
	assertContainsAll(t, "vault-unseal-existing no tty refusal", output,
		"requires visible local terminal",
		"no staging or SSH occurred",
		"No recovery-session live helper or IM execution occurred.",
	)
	if _, err := os.Stat(h.sshLogPath); !os.IsNotExist(err) {
		t.Fatalf("ssh should not run when local TTY guard fails: %v", err)
	}
	if _, err := os.Stat(h.scpLogPath); !os.IsNotExist(err) {
		t.Fatalf("scp should not run when local TTY guard fails: %v", err)
	}
}

func TestRemoteAlphaOperatorRecoverySessionVaultUnsealExistingMacSideStagesSingleHelperWithTTYAndCleanup(t *testing.T) {
	h := setupFakeRemoteAlphaUnsealHarness(t)
	before := snapshotPathExistence(t, remoteAlphaOperatorRouteArtifactPaths()...)

	output, err := runRemoteAlphaOperatorWithPTY(t, h.env(),
		"recovery-session", "vault-unseal-existing",
		"--ssh-target", "ds@m75q-test",
		"--interactive-tty",
	)
	if err != nil {
		t.Fatalf("Mac-side fake unseal route failed: %v\noutput=%s\nssh=%s\nscp=%s\nhelper=%s\nrm=%s",
			err, output, readIfExists(h.sshLogPath), readIfExists(h.scpLogPath), readIfExists(h.helperLog), readIfExists(h.rmLogPath))
	}

	assertContainsAll(t, "Mac-side fake unseal output", output,
		"Running Mac-side Vault unseal-existing through an explicit interactive SSH TTY.",
		"Staging only scripts/remote_alpha_reset_disposable_vault.sh and invoking only --unseal-only.",
		"The operator enters any unseal key directly into the visible SSH/Vault/helper prompt.",
		"staged helper cleanup was attempted",
		"Post-unseal evidence checks, IM refresh, support-bundle collection, and workload-auth checks are separate follow-up actions and were not executed here.",
	)

	scpLog := strings.TrimSpace(mustRead(t, h.scpLogPath))
	scpLines := strings.Split(scpLog, "\n")
	if len(scpLines) != 1 {
		t.Fatalf("expected exactly one staged file upload, got %q", scpLog)
	}
	assertContainsAll(t, "fake scp log", scpLog,
		filepath.Join(executionSubstrateRepoRoot, "scripts", "remote_alpha_reset_disposable_vault.sh"),
	)
	assertContainsNone(t, "fake scp log", scpLog,
		"remote_alpha_operator.sh",
		"scripts/internal",
		"bundle",
	)

	sshLog := mustRead(t, h.sshLogPath)
	if got := strings.Count(sshLog, "tty=true"); got != 1 {
		t.Fatalf("expected exactly one interactive ssh -tt invocation, got %d log=%q", got, sshLog)
	}
	assertContainsAll(t, "fake ssh log", sshLog,
		"tty=true target=ds@m75q-test",
	)
	assertContainsNone(t, "fake ssh log forbidden capture", sshLog,
		" tee ",
		"script ",
		"transcript",
	)

	helperLog := strings.TrimSpace(mustRead(t, h.helperLog))
	if helperLog != "--unseal-only" {
		t.Fatalf("expected staged helper to receive only --unseal-only, got %q", helperLog)
	}
	assertContainsNone(t, "fake helper log forbidden modes", helperLog,
		"--execute-reset",
		"--post-unseal-check",
		"workload-auth",
		"remote-alpha-live-refresh",
		"remote-alpha-live-support-bundle",
	)

	rmLog := mustRead(t, h.rmLogPath)
	assertContainsAll(t, "fake remote cleanup log", rmLog,
		"execution-substrate-remote-alpha-vault-unseal-existing",
	)
	if entries, err := os.ReadDir(filepath.Join(h.remoteRoot, "tmp", "execution-substrate-remote-alpha-vault-unseal-existing")); err == nil && len(entries) > 0 {
		t.Fatalf("expected remote staged helper directory to be cleaned, found %d entries", len(entries))
	}
	assertNoNewPaths(t, "Mac-side fake unseal route", before)
}

type fakeRemoteAlphaResetDryRunHarness struct {
	localBin   string
	remoteBin  string
	remoteRoot string
	sshLogPath string
	scpLogPath string
	rmLogPath  string
	helperLog  string
}

func setupFakeRemoteAlphaResetDryRunHarness(t *testing.T) *fakeRemoteAlphaResetDryRunHarness {
	t.Helper()

	tmpDir := t.TempDir()
	h := &fakeRemoteAlphaResetDryRunHarness{
		localBin:   filepath.Join(tmpDir, "local-bin"),
		remoteBin:  filepath.Join(tmpDir, "remote-bin"),
		remoteRoot: filepath.Join(tmpDir, "remote-root"),
		sshLogPath: filepath.Join(tmpDir, "ssh.log"),
		scpLogPath: filepath.Join(tmpDir, "scp.log"),
		rmLogPath:  filepath.Join(tmpDir, "rm.log"),
		helperLog:  filepath.Join(tmpDir, "helper.log"),
	}
	for _, dir := range []string{h.localBin, h.remoteBin, h.remoteRoot} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", dir, err)
		}
	}

	writeExecutable(t, h.localBin, "ssh", fmt.Sprintf(`#!/usr/bin/env bash
set -euo pipefail
tty=false
while [[ "${1:-}" == "-tt" ]]; do
  tty=true
  shift
done
target="${1:-}"
shift || true
printf 'tty=%%s target=%%s args=%%s\n' "${tty}" "${target}" "$*" >> %q
export PATH="${FAKE_REMOTE_BIN}:${PATH}"
if [[ "${1:-}" == "/bin/bash" && "${2:-}" == "-s" ]]; then
  shift 2
  if [[ "${1:-}" == "--" ]]; then
    shift
  fi
  mapped_args=()
  for arg in "$@"; do
    if [[ "${arg}" == /* ]]; then
      mapped_args+=("${FAKE_REMOTE_ROOT}${arg}")
    else
      mapped_args+=("${arg}")
    fi
  done
  payload="$(mktemp)"
  cat >"${payload}"
  set +e
  /bin/bash "${payload}" "${mapped_args[@]}"
  status=$?
  set -e
  rm -f -- "${payload}"
  exit "${status}"
fi
if [[ "$#" -eq 1 && "${1:-}" == exec\ /bin/bash\ -c* ]]; then
  command_string="${1}"
  dry_run_prefix="/tmp/execution-substrate-remote-alpha-vault-reset-disposable-dry-run"
  execute_prefix="/tmp/execution-substrate-remote-alpha-vault-reset-disposable-execute"
  mapped_command="${command_string//${dry_run_prefix}/${FAKE_REMOTE_ROOT}${dry_run_prefix}}"
  mapped_command="${mapped_command//${execute_prefix}/${FAKE_REMOTE_ROOT}${execute_prefix}}"
  exec /bin/bash -c "${mapped_command}"
fi
echo "unexpected fake ssh invocation: $*" >&2
exit 64
`, h.sshLogPath))

	writeExecutable(t, h.localBin, "scp", fmt.Sprintf(`#!/usr/bin/env bash
set -euo pipefail
if [[ "$#" -ne 2 ]]; then
  echo "unexpected fake scp args: $*" >&2
  exit 64
fi
src=$1
dest=$2
printf '%%s\t%%s\n' "${src}" "${dest}" >> %q
if [[ "${src}" == *:* || "${dest}" != *:* ]]; then
  echo "fake scp supports one local-to-remote helper upload" >&2
  exit 64
fi
remote_path="${dest#*:}"
mapped_dest="${FAKE_REMOTE_ROOT}${remote_path}"
mkdir -p -- "$(dirname "${mapped_dest}")"
cat >"${mapped_dest}" <<'REMOTE_ALPHA_FAKE_RESET_DRY_RUN_HELPER'
#!/usr/bin/env bash
set -euo pipefail
printf '%%s\n' "$*" >> %q
REMOTE_ALPHA_FAKE_RESET_DRY_RUN_HELPER
chmod 0700 "${mapped_dest}"
`, h.scpLogPath, h.helperLog))

	writeExecutable(t, h.remoteBin, "rm", fmt.Sprintf(`#!/usr/bin/env bash
set -euo pipefail
printf '%%s\n' "$*" >> %q
exec /bin/rm "$@"
`, h.rmLogPath))

	return h
}

func (h *fakeRemoteAlphaResetDryRunHarness) env() []string {
	return envWithPath(h.localBin,
		"FAKE_REMOTE_BIN="+h.remoteBin,
		"FAKE_REMOTE_ROOT="+h.remoteRoot,
	)
}

func TestRemoteAlphaOperatorRecoverySessionVaultResetDisposableMacSideDryRunStagesSingleHelperAndCleanup(t *testing.T) {
	h := setupFakeRemoteAlphaResetDryRunHarness(t)
	before := snapshotPathExistence(t, remoteAlphaOperatorRouteArtifactPaths()...)

	output, err := runRemoteAlphaOperatorWithEnv(h.env(),
		"recovery-session", "vault-reset-disposable",
		"--ssh-target", "ds@m75q-test",
		"--dry-run",
	)
	if err != nil {
		t.Fatalf("Mac-side fake reset dry-run route failed: %v\noutput=%s\nssh=%s\nscp=%s\nhelper=%s\nrm=%s",
			err, output, readIfExists(h.sshLogPath), readIfExists(h.scpLogPath), readIfExists(h.helperLog), readIfExists(h.rmLogPath))
	}

	assertContainsAll(t, "Mac-side fake reset dry-run output", output,
		"Running Mac-side disposable Vault reset dry-run planning route.",
		"Staging only scripts/remote_alpha_reset_disposable_vault.sh and invoking only --dry-run.",
		"This route is non-destructive",
		"does not stop Vault, move raft storage, init or unseal Vault, run post-unseal checks, run workload-auth checks, run IM, or collect support bundles",
		"No transcript, tee/script capture, .out, report, support bundle, operator summary, or generated JSON is created.",
		"staged helper cleanup was attempted",
		"Execute-reset is a separate destructive exact-phrase route; IM refresh and support-bundle collection were not executed here.",
	)

	scpLog := strings.TrimSpace(mustRead(t, h.scpLogPath))
	scpLines := strings.Split(scpLog, "\n")
	if len(scpLines) != 1 {
		t.Fatalf("expected exactly one staged file upload, got %q", scpLog)
	}
	assertContainsAll(t, "fake reset dry-run scp log", scpLog,
		filepath.Join(executionSubstrateRepoRoot, "scripts", "remote_alpha_reset_disposable_vault.sh"),
	)
	assertContainsNone(t, "fake reset dry-run scp log", scpLog,
		"remote_alpha_operator.sh",
		"scripts/internal",
		"bundle",
	)

	sshLog := mustRead(t, h.sshLogPath)
	if strings.Contains(sshLog, "tty=true") {
		t.Fatalf("dry-run route must not allocate an interactive TTY, log=%q", sshLog)
	}
	assertContainsAll(t, "fake reset dry-run ssh log", sshLog,
		"tty=false target=ds@m75q-test",
	)
	assertContainsNone(t, "fake reset dry-run ssh log forbidden capture", sshLog,
		" tee ",
		"script ",
		"transcript",
		".out",
	)

	helperLog := strings.TrimSpace(mustRead(t, h.helperLog))
	if helperLog != "--dry-run" {
		t.Fatalf("expected staged helper to receive only --dry-run, got %q", helperLog)
	}
	assertContainsNone(t, "fake reset dry-run helper log forbidden modes", helperLog,
		"--execute-reset",
		"--unseal-only",
		"--post-unseal-check",
		"workload-auth",
		"remote-alpha-live-refresh",
		"remote-alpha-live-support-bundle",
	)

	rmLog := mustRead(t, h.rmLogPath)
	assertContainsAll(t, "fake reset dry-run remote cleanup log", rmLog,
		"execution-substrate-remote-alpha-vault-reset-disposable-dry-run",
	)
	if entries, err := os.ReadDir(filepath.Join(h.remoteRoot, "tmp", "execution-substrate-remote-alpha-vault-reset-disposable-dry-run")); err == nil && len(entries) > 0 {
		t.Fatalf("expected remote reset dry-run staged helper directory to be cleaned, found %d entries", len(entries))
	}
	assertNoNewPaths(t, "Mac-side fake reset dry-run route", before)
}

func TestRemoteAlphaOperatorRecoverySessionVaultResetDisposableExecuteResetNoTTYFailsBeforeStaging(t *testing.T) {
	h := setupFakeRemoteAlphaResetDryRunHarness(t)
	output, err := runRemoteAlphaOperatorWithEnv(h.env(),
		"recovery-session", "vault-reset-disposable",
		"--ssh-target", "ds@m75q-test",
		"--execute-reset",
		"--interactive-tty",
	)
	if err == nil {
		t.Fatalf("expected no-TTY failure before execute-reset staging, got success:\n%s", output)
	}
	assertContainsAll(t, "vault-reset-disposable execute no tty refusal", output,
		"requires visible local terminal",
		"no staging or SSH occurred",
		"No recovery-session live helper or IM execution occurred.",
	)
	if _, err := os.Stat(h.sshLogPath); !os.IsNotExist(err) {
		t.Fatalf("ssh should not run when execute-reset local TTY guard fails: %v", err)
	}
	if _, err := os.Stat(h.scpLogPath); !os.IsNotExist(err) {
		t.Fatalf("scp should not run when execute-reset local TTY guard fails: %v", err)
	}
}

func TestRemoteAlphaOperatorRecoverySessionVaultResetDisposableExecuteResetStagesSingleHelperWithTTYAndCleanup(t *testing.T) {
	h := setupFakeRemoteAlphaResetDryRunHarness(t)
	before := snapshotPathExistence(t, remoteAlphaOperatorRouteArtifactPaths()...)

	output, err := runRemoteAlphaOperatorWithPTY(t, h.env(),
		"recovery-session", "vault-reset-disposable",
		"--ssh-target", "ds@m75q-test",
		"--execute-reset",
		"--interactive-tty",
	)
	if err != nil {
		t.Fatalf("Mac-side fake reset execute route failed: %v\noutput=%s\nssh=%s\nscp=%s\nhelper=%s\nrm=%s",
			err, output, readIfExists(h.sshLogPath), readIfExists(h.scpLogPath), readIfExists(h.helperLog), readIfExists(h.rmLogPath))
	}

	assertContainsAll(t, "Mac-side fake reset execute output", output,
		"Running Mac-side disposable Vault execute-reset through an explicit interactive SSH TTY.",
		"Staging only scripts/remote_alpha_reset_disposable_vault.sh and invoking only --execute-reset.",
		"destructive for disposable Remote Alpha Vault state",
		"The operator handles confirmation, Vault init output, root token, unseal key, and Vault prompts only in the visible SSH/Vault/helper terminal.",
		"The operator facade will not read, log, relay, persist, summarize, or capture the confirmation phrase or secret material.",
		"No transcript, tee/script capture, .out, report, support bundle, operator summary, generated JSON, post-unseal check, workload-auth check, runtime identity summary, IM refresh, or CP proof is created or run.",
		"staged helper cleanup was attempted",
		"Post-reset evidence checks, post-unseal checks, workload-auth checks, runtime identity summaries, IM refresh, support-bundle collection, and CP proof were not executed here.",
	)
	assertContainsNone(t, "Mac-side fake reset execute output must not print phrase", output,
		"RESET DISPOSABLE REMOTE ALPHA VAULT",
	)

	scpLog := strings.TrimSpace(mustRead(t, h.scpLogPath))
	scpLines := strings.Split(scpLog, "\n")
	if len(scpLines) != 1 {
		t.Fatalf("expected exactly one staged file upload, got %q", scpLog)
	}
	assertContainsAll(t, "fake reset execute scp log", scpLog,
		filepath.Join(executionSubstrateRepoRoot, "scripts", "remote_alpha_reset_disposable_vault.sh"),
	)
	assertContainsNone(t, "fake reset execute scp log", scpLog,
		"remote_alpha_operator.sh",
		"scripts/internal",
		"bundle",
	)

	sshLog := mustRead(t, h.sshLogPath)
	if got := strings.Count(sshLog, "tty=true"); got != 1 {
		t.Fatalf("expected exactly one interactive ssh -tt invocation, got %d log=%q", got, sshLog)
	}
	assertContainsAll(t, "fake reset execute ssh log", sshLog,
		"tty=true target=ds@m75q-test",
	)
	assertContainsNone(t, "fake reset execute ssh log forbidden capture", sshLog,
		" tee ",
		"script ",
		"transcript",
		".out",
	)

	helperLog := strings.TrimSpace(mustRead(t, h.helperLog))
	if helperLog != "--execute-reset" {
		t.Fatalf("expected staged helper to receive only --execute-reset, got %q", helperLog)
	}
	assertContainsNone(t, "fake reset execute helper log forbidden modes", helperLog,
		"--dry-run",
		"--unseal-only",
		"--post-unseal-check",
		"workload-auth",
		"remote-alpha-live-refresh",
		"remote-alpha-live-support-bundle",
	)

	rmLog := mustRead(t, h.rmLogPath)
	assertContainsAll(t, "fake reset execute remote cleanup log", rmLog,
		"execution-substrate-remote-alpha-vault-reset-disposable-execute",
	)
	if entries, err := os.ReadDir(filepath.Join(h.remoteRoot, "tmp", "execution-substrate-remote-alpha-vault-reset-disposable-execute")); err == nil && len(entries) > 0 {
		t.Fatalf("expected remote reset execute staged helper directory to be cleaned, found %d entries", len(entries))
	}
	assertNoNewPaths(t, "Mac-side fake reset execute route", before)
}

type fakeRemoteAlphaWorkloadAuthHarness struct {
	localBin   string
	remoteBin  string
	remoteRoot string
	sshLogPath string
	scpLogPath string
	rmLogPath  string
	sudoLog    string
	helperLog  string
}

func setupFakeRemoteAlphaWorkloadAuthHarness(t *testing.T) *fakeRemoteAlphaWorkloadAuthHarness {
	t.Helper()

	tmpDir := t.TempDir()
	h := &fakeRemoteAlphaWorkloadAuthHarness{
		localBin:   filepath.Join(tmpDir, "local-bin"),
		remoteBin:  filepath.Join(tmpDir, "remote-bin"),
		remoteRoot: filepath.Join(tmpDir, "remote-root"),
		sshLogPath: filepath.Join(tmpDir, "ssh.log"),
		scpLogPath: filepath.Join(tmpDir, "scp.log"),
		rmLogPath:  filepath.Join(tmpDir, "rm.log"),
		sudoLog:    filepath.Join(tmpDir, "sudo.log"),
		helperLog:  filepath.Join(tmpDir, "helper.log"),
	}
	for _, dir := range []string{h.localBin, h.remoteBin, h.remoteRoot} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", dir, err)
		}
	}

	writeExecutable(t, h.localBin, "ssh", fmt.Sprintf(`#!/usr/bin/env bash
set -euo pipefail
tty=false
while [[ "${1:-}" == "-tt" ]]; do
  tty=true
  shift
done
target="${1:-}"
shift || true
printf 'tty=%%s target=%%s args=%%s\n' "${tty}" "${target}" "$*" >> %q
export PATH="${FAKE_REMOTE_BIN}:${PATH}"
if [[ "${1:-}" == "/bin/bash" && "${2:-}" == "-s" ]]; then
  shift 2
  if [[ "${1:-}" == "--" ]]; then
    shift
  fi
  mapped_args=()
  for arg in "$@"; do
    if [[ "${arg}" == /* ]]; then
      mapped_args+=("${FAKE_REMOTE_ROOT}${arg}")
    else
      mapped_args+=("${arg}")
    fi
  done
  payload="$(mktemp)"
  cat >"${payload}"
  set +e
  /bin/bash "${payload}" "${mapped_args[@]}"
  status=$?
  set -e
  rm -f -- "${payload}"
  exit "${status}"
fi
if [[ "$#" -eq 1 && "${1:-}" == exec\ /bin/bash\ -c* ]]; then
  command_string="${1}"
  workload_prefix="/tmp/execution-substrate-remote-alpha-vault-workload-auth-check"
  mapped_command="${command_string//${workload_prefix}/${FAKE_REMOTE_ROOT}${workload_prefix}}"
  exec /bin/bash -c "${mapped_command}"
fi
echo "unexpected fake ssh invocation: $*" >&2
exit 64
`, h.sshLogPath))

	writeExecutable(t, h.localBin, "scp", fmt.Sprintf(`#!/usr/bin/env bash
set -euo pipefail
if [[ "$#" -ne 2 ]]; then
  echo "unexpected fake scp args: $*" >&2
  exit 64
fi
src=$1
dest=$2
printf '%%s\t%%s\n' "${src}" "${dest}" >> %q
if [[ "${src}" == *:* || "${dest}" != *:* ]]; then
  echo "fake scp supports one local-to-remote upload" >&2
  exit 64
fi
remote_path="${dest#*:}"
mapped_dest="${FAKE_REMOTE_ROOT}${remote_path}"
mkdir -p -- "$(dirname "${mapped_dest}")"
if [[ "${src}" == */scripts/internal/remote_alpha_vault_workload_auth_check.sh ]]; then
  cat >"${mapped_dest}" <<'REMOTE_ALPHA_FAKE_WORKLOAD_AUTH_INTERNAL'
# fake internal workload-auth helper staged for layout verification
REMOTE_ALPHA_FAKE_WORKLOAD_AUTH_INTERNAL
elif [[ "$(basename "${src}")" == "remote_alpha_vault_workload_auth_check.sh" ]]; then
  cat >"${mapped_dest}" <<'REMOTE_ALPHA_FAKE_WORKLOAD_AUTH_PUBLIC'
#!/usr/bin/env bash
set -euo pipefail
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
internal="${script_dir}/internal/remote_alpha_vault_workload_auth_check.sh"
if [[ ! -f "${internal}" ]]; then
  echo "missing internal helper: ${internal}" >&2
  exit 65
fi
printf 'public_args=%%s\n' "$*" >> %q
printf 'internal=%%s\n' "${internal}" >> %q
REMOTE_ALPHA_FAKE_WORKLOAD_AUTH_PUBLIC
else
  echo "unexpected fake scp source: ${src}" >&2
  exit 64
fi
chmod 0700 "${mapped_dest}"
`, h.scpLogPath, h.helperLog, h.helperLog))

	writeExecutable(t, h.remoteBin, "id", `#!/usr/bin/env bash
set -euo pipefail
if [[ "${1:-}" == "-u" ]]; then
  echo 1000
  exit 0
fi
exec /usr/bin/id "$@"
`)
	writeExecutable(t, h.remoteBin, "sudo", fmt.Sprintf(`#!/usr/bin/env bash
set -euo pipefail
printf 'sudo_args=%%s\n' "$*" >> %q
exec "$@"
`, h.sudoLog))
	writeExecutable(t, h.remoteBin, "rm", fmt.Sprintf(`#!/usr/bin/env bash
set -euo pipefail
printf '%%s\n' "$*" >> %q
exec /bin/rm "$@"
`, h.rmLogPath))

	return h
}

func (h *fakeRemoteAlphaWorkloadAuthHarness) env() []string {
	return envWithPath(h.localBin,
		"FAKE_REMOTE_BIN="+h.remoteBin,
		"FAKE_REMOTE_ROOT="+h.remoteRoot,
	)
}

func TestRemoteAlphaOperatorRecoverySessionVaultWorkloadAuthCheckNoTTYFailsBeforeStaging(t *testing.T) {
	h := setupFakeRemoteAlphaWorkloadAuthHarness(t)
	output, err := runRemoteAlphaOperatorWithEnv(h.env(),
		"recovery-session", "vault-workload-auth-check",
		"--ssh-target", "ds@m75q-test",
		"--interactive-tty",
	)
	if err == nil {
		t.Fatalf("expected no-TTY failure before workload-auth staging, got success:\n%s", output)
	}
	assertContainsAll(t, "vault-workload-auth-check no tty refusal", output,
		"requires visible local terminal",
		"no staging or SSH occurred",
		"No recovery-session live helper or IM execution occurred.",
	)
	if _, err := os.Stat(h.sshLogPath); !os.IsNotExist(err) {
		t.Fatalf("ssh should not run when workload-auth local TTY guard fails: %v", err)
	}
	if _, err := os.Stat(h.scpLogPath); !os.IsNotExist(err) {
		t.Fatalf("scp should not run when workload-auth local TTY guard fails: %v", err)
	}
}

func TestRemoteAlphaOperatorRecoverySessionVaultWorkloadAuthCheckStagesOnlyApprovedHelpersWithTTYAndCleanup(t *testing.T) {
	h := setupFakeRemoteAlphaWorkloadAuthHarness(t)
	before := snapshotPathExistence(t, remoteAlphaOperatorRouteArtifactPaths(filepath.Join(".out", "remote-alpha-m75q", "vault-workload-auth-summary.json"))...)

	output, err := runRemoteAlphaOperatorWithPTY(t, h.env(),
		"recovery-session", "vault-workload-auth-check",
		"--ssh-target", "ds@m75q-test",
		"--interactive-tty",
	)
	if err != nil {
		t.Fatalf("Mac-side fake workload-auth route failed: %v\noutput=%s\nssh=%s\nscp=%s\nsudo=%s\nhelper=%s\nrm=%s",
			err, output, readIfExists(h.sshLogPath), readIfExists(h.scpLogPath), readIfExists(h.sudoLog), readIfExists(h.helperLog), readIfExists(h.rmLogPath))
	}

	assertContainsAll(t, "Mac-side fake workload-auth output", output,
		"Running Mac-side Vault workload-auth evidence check through an explicit interactive SSH TTY.",
		"Staging only scripts/remote_alpha_vault_workload_auth_check.sh and scripts/internal/remote_alpha_vault_workload_auth_check.sh.",
		"Invoking only the staged public workload-auth helper; no helper override flags are accepted or passed.",
		"Canonical summary stays remote at /var/tmp/execution-substrate-remote-alpha/vault-workload-auth-summary.json.",
		"No transcript, tee/script capture, .out, report, support bundle, operator summary, generated JSON, reset/unseal, IM refresh, runtime identity generation, workload-auth bootstrap, ES token brokerage, or CP proof is created or run.",
		"staged helper cleanup was attempted",
		"Canonical remote summary path: /var/tmp/execution-substrate-remote-alpha/vault-workload-auth-summary.json",
		"did not copy it back to Mac .out",
		"did not print full summary JSON",
		"recovery-session --evidence-check --vault-workload-auth-summary <local-path-to-vault-workload-auth-summary.json>",
		"Separate IM evidence/provenance actions",
		"remote-alpha-live-refresh",
		"remote-alpha-live-support-bundle",
	)

	scpLog := strings.TrimSpace(mustRead(t, h.scpLogPath))
	scpLines := strings.Split(scpLog, "\n")
	if len(scpLines) != 2 {
		t.Fatalf("expected exactly two staged file uploads, got %q", scpLog)
	}
	assertContainsAll(t, "fake workload-auth scp log", scpLog,
		filepath.Join(executionSubstrateRepoRoot, "scripts", "remote_alpha_vault_workload_auth_check.sh"),
		filepath.Join(executionSubstrateRepoRoot, "scripts", "internal", "remote_alpha_vault_workload_auth_check.sh"),
		"/scripts/remote_alpha_vault_workload_auth_check.sh",
		"/scripts/internal/remote_alpha_vault_workload_auth_check.sh",
	)
	assertContainsNone(t, "fake workload-auth scp log", scpLog,
		"remote_alpha_operator.sh",
		"remote_alpha_reset_disposable_vault.sh",
		"remote_alpha_runtime_identity_helper_summary.sh",
		"remote_alpha_migrate_vault_service_user.sh",
		"remote_alpha_prepare_es_config_tls",
		"remote_alpha_deploy_es_binaries",
		"bundle",
	)

	sshLog := mustRead(t, h.sshLogPath)
	if got := strings.Count(sshLog, "tty=true"); got != 1 {
		t.Fatalf("expected exactly one interactive ssh -tt invocation, got %d log=%q", got, sshLog)
	}
	assertContainsAll(t, "fake workload-auth ssh log", sshLog,
		"tty=true target=ds@m75q-test",
	)
	assertContainsNone(t, "fake workload-auth ssh log forbidden capture", sshLog,
		" tee ",
		"script ",
		"transcript",
		"--execute-reset",
		"--unseal-only",
		"--post-unseal-check",
		"remote-alpha-live-refresh",
		"remote-alpha-live-support-bundle",
		"cp-proof",
	)

	sudoLog := strings.TrimSpace(mustRead(t, h.sudoLog))
	assertContainsAll(t, "fake workload-auth sudo log", sudoLog,
		"sudo_args=",
		"/scripts/remote_alpha_vault_workload_auth_check.sh",
	)
	assertContainsNone(t, "fake workload-auth sudo log forbidden args", sudoLog,
		"--vault-addr",
		"--vault-role",
		"--summary-path",
		"--execute-reset",
		"--unseal-only",
		"--post-unseal-check",
		"remote_alpha_reset_disposable_vault.sh",
	)

	helperLog := mustRead(t, h.helperLog)
	assertContainsAll(t, "fake workload-auth helper log", helperLog,
		"public_args=",
		"/scripts/internal/remote_alpha_vault_workload_auth_check.sh",
	)
	assertContainsNone(t, "fake workload-auth helper log forbidden args", helperLog,
		"--vault-addr",
		"--vault-role",
		"--vault-audience",
		"--spiffe-id",
		"--summary-path",
		"--config-path",
		"--execute-reset",
		"--unseal-only",
		"--post-unseal-check",
		"remote-alpha-live-refresh",
		"remote-alpha-live-support-bundle",
	)

	rmLog := mustRead(t, h.rmLogPath)
	assertContainsAll(t, "fake workload-auth remote cleanup log", rmLog,
		"execution-substrate-remote-alpha-vault-workload-auth-check",
	)
	if entries, err := os.ReadDir(filepath.Join(h.remoteRoot, "tmp", "execution-substrate-remote-alpha-vault-workload-auth-check")); err == nil && len(entries) > 0 {
		t.Fatalf("expected remote workload-auth staged helper directory to be cleaned, found %d entries", len(entries))
	}
	assertNoNewPaths(t, "Mac-side fake workload-auth route", before)
}

type fakeRemoteAlphaRuntimeIdentitySummaryHarness struct {
	localBin   string
	remoteBin  string
	remoteRoot string
	sshLogPath string
	scpLogPath string
	rmLogPath  string
	sudoLog    string
	helperLog  string
}

func setupFakeRemoteAlphaRuntimeIdentitySummaryHarness(t *testing.T) *fakeRemoteAlphaRuntimeIdentitySummaryHarness {
	t.Helper()

	tmpDir := t.TempDir()
	h := &fakeRemoteAlphaRuntimeIdentitySummaryHarness{
		localBin:   filepath.Join(tmpDir, "local-bin"),
		remoteBin:  filepath.Join(tmpDir, "remote-bin"),
		remoteRoot: filepath.Join(tmpDir, "remote-root"),
		sshLogPath: filepath.Join(tmpDir, "ssh.log"),
		scpLogPath: filepath.Join(tmpDir, "scp.log"),
		rmLogPath:  filepath.Join(tmpDir, "rm.log"),
		sudoLog:    filepath.Join(tmpDir, "sudo.log"),
		helperLog:  filepath.Join(tmpDir, "helper.log"),
	}
	for _, dir := range []string{h.localBin, h.remoteBin, h.remoteRoot} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", dir, err)
		}
	}

	writeExecutable(t, h.localBin, "ssh", fmt.Sprintf(`#!/usr/bin/env bash
set -euo pipefail
tty=false
while [[ "${1:-}" == "-tt" ]]; do
  tty=true
  shift
done
target="${1:-}"
shift || true
printf 'tty=%%s target=%%s args=%%s\n' "${tty}" "${target}" "$*" >> %q
export PATH="${FAKE_REMOTE_BIN}:${PATH}"
if [[ "${1:-}" == "/bin/bash" && "${2:-}" == "-s" ]]; then
  shift 2
  if [[ "${1:-}" == "--" ]]; then
    shift
  fi
  mapped_args=()
  for arg in "$@"; do
    if [[ "${arg}" == /* ]]; then
      mapped_args+=("${FAKE_REMOTE_ROOT}${arg}")
    else
      mapped_args+=("${arg}")
    fi
  done
  payload="$(mktemp)"
  cat >"${payload}"
  set +e
  /bin/bash "${payload}" "${mapped_args[@]}"
  status=$?
  set -e
  rm -f -- "${payload}"
  exit "${status}"
fi
if [[ "$#" -eq 1 && "${1:-}" == exec\ /bin/bash\ -c* ]]; then
  command_string="${1}"
  runtime_prefix="/tmp/execution-substrate-remote-alpha-runtime-identity-summary"
  mapped_command="${command_string//${runtime_prefix}/${FAKE_REMOTE_ROOT}${runtime_prefix}}"
  exec /bin/bash -c "${mapped_command}"
fi
echo "unexpected fake ssh invocation: $*" >&2
exit 64
`, h.sshLogPath))

	writeExecutable(t, h.localBin, "scp", fmt.Sprintf(`#!/usr/bin/env bash
set -euo pipefail
if [[ "$#" -ne 2 ]]; then
  echo "unexpected fake scp args: $*" >&2
  exit 64
fi
src=$1
dest=$2
printf '%%s\t%%s\n' "${src}" "${dest}" >> %q
if [[ "${src}" == *:* || "${dest}" != *:* ]]; then
  echo "fake scp supports one local-to-remote upload" >&2
  exit 64
fi
remote_path="${dest#*:}"
mapped_dest="${FAKE_REMOTE_ROOT}${remote_path}"
mkdir -p -- "$(dirname "${mapped_dest}")"
if [[ "$(basename "${src}")" == "remote_alpha_runtime_identity_helper_summary.sh" ]]; then
  cat >"${mapped_dest}" <<'REMOTE_ALPHA_FAKE_RUNTIME_IDENTITY_SUMMARY'
#!/usr/bin/env bash
set -euo pipefail
printf 'public_args=%%s\n' "$*" >> %q
printf 'Remote Alpha runtime identity helper summary finished.\n'
printf 'Remote summary path: /var/tmp/execution-substrate-remote-alpha/runtime-identity-helper-summary.json\n'
printf 'Runtime identity summary evidence only; workload-auth bootstrap/check, reset/unseal, IM refresh, support-bundle collection, CP proof, and runtime identity generation were not run.\n'
REMOTE_ALPHA_FAKE_RUNTIME_IDENTITY_SUMMARY
else
  echo "unexpected fake scp source: ${src}" >&2
  exit 64
fi
chmod 0700 "${mapped_dest}"
`, h.scpLogPath, h.helperLog))

	writeExecutable(t, h.remoteBin, "id", `#!/usr/bin/env bash
set -euo pipefail
if [[ "${1:-}" == "-u" ]]; then
  echo 1000
  exit 0
fi
exec /usr/bin/id "$@"
`)
	writeExecutable(t, h.remoteBin, "sudo", fmt.Sprintf(`#!/usr/bin/env bash
set -euo pipefail
printf 'sudo_args=%%s\n' "$*" >> %q
exec "$@"
`, h.sudoLog))
	writeExecutable(t, h.remoteBin, "rm", fmt.Sprintf(`#!/usr/bin/env bash
set -euo pipefail
printf '%%s\n' "$*" >> %q
exec /bin/rm "$@"
`, h.rmLogPath))

	return h
}

func (h *fakeRemoteAlphaRuntimeIdentitySummaryHarness) env() []string {
	return envWithPath(h.localBin,
		"FAKE_REMOTE_BIN="+h.remoteBin,
		"FAKE_REMOTE_ROOT="+h.remoteRoot,
	)
}

func TestRemoteAlphaOperatorRecoverySessionRuntimeIdentitySummaryNoTTYFailsBeforeStaging(t *testing.T) {
	h := setupFakeRemoteAlphaRuntimeIdentitySummaryHarness(t)
	output, err := runRemoteAlphaOperatorWithEnv(h.env(),
		"recovery-session", "runtime-identity-summary",
		"--ssh-target", "ds@m75q-test",
		"--interactive-tty",
	)
	if err == nil {
		t.Fatalf("expected no-TTY failure before runtime identity summary staging, got success:\n%s", output)
	}
	assertContainsAll(t, "runtime-identity-summary no tty refusal", output,
		"requires visible local terminal",
		"no staging or SSH occurred",
		"No recovery-session live helper or IM execution occurred.",
	)
	if _, err := os.Stat(h.sshLogPath); !os.IsNotExist(err) {
		t.Fatalf("ssh should not run when runtime identity summary local TTY guard fails: %v", err)
	}
	if _, err := os.Stat(h.scpLogPath); !os.IsNotExist(err) {
		t.Fatalf("scp should not run when runtime identity summary local TTY guard fails: %v", err)
	}
}

func TestRemoteAlphaOperatorRecoverySessionRuntimeIdentitySummaryStagesOnlyApprovedHelperWithTTYAndCleanup(t *testing.T) {
	h := setupFakeRemoteAlphaRuntimeIdentitySummaryHarness(t)
	before := snapshotPathExistence(t, remoteAlphaOperatorRouteArtifactPaths(filepath.Join(".out", "remote-alpha-m75q", "runtime-identity-helper-summary.json"))...)

	output, err := runRemoteAlphaOperatorWithPTY(t, h.env(),
		"recovery-session", "runtime-identity-summary",
		"--ssh-target", "ds@m75q-test",
		"--interactive-tty",
	)
	if err != nil {
		t.Fatalf("Mac-side fake runtime identity summary route failed: %v\noutput=%s\nssh=%s\nscp=%s\nsudo=%s\nhelper=%s\nrm=%s",
			err, output, readIfExists(h.sshLogPath), readIfExists(h.scpLogPath), readIfExists(h.sudoLog), readIfExists(h.helperLog), readIfExists(h.rmLogPath))
	}

	assertContainsAll(t, "Mac-side fake runtime identity output", output,
		"Running Mac-side runtime identity helper summary through an explicit interactive SSH TTY.",
		"Staging only scripts/remote_alpha_runtime_identity_helper_summary.sh.",
		"Invoking only the staged runtime identity helper summary script; no helper override flags are accepted or passed.",
		"Canonical summary stays remote at /var/tmp/execution-substrate-remote-alpha/runtime-identity-helper-summary.json.",
		"No transcript, tee/script capture, .out, report, support bundle, operator summary, operator-generated JSON, workload-auth bootstrap/check, reset/unseal, IM refresh, ES token brokerage, runtime identity generation, or CP proof is created or run by the facade.",
		"Remote Alpha runtime identity helper summary finished.",
		"Canonical remote summary path: /var/tmp/execution-substrate-remote-alpha/runtime-identity-helper-summary.json",
		"did not copy it back to Mac .out",
		"did not print full summary JSON",
		"evidence/projection only",
		"not runtime-profile readiness",
		"not submit readiness",
		"not retained-result readiness",
		"not governed execution proof",
		"recovery-session --evidence-check --runtime-identity-summary <local-path-to-runtime-identity-helper-summary.json>",
	)
	assertContainsNone(t, "Mac-side fake runtime identity output forbidden surfaces", output,
		"remote-alpha-live-refresh",
		"remote-alpha-live-support-bundle",
		"cp-proof",
		"root-token",
		"jwt-svid",
		"{\"schema_version\"",
	)

	scpLog := strings.TrimSpace(mustRead(t, h.scpLogPath))
	scpLines := strings.Split(scpLog, "\n")
	if len(scpLines) != 1 {
		t.Fatalf("expected exactly one staged file upload, got %q", scpLog)
	}
	assertContainsAll(t, "fake runtime identity scp log", scpLog,
		filepath.Join(executionSubstrateRepoRoot, "scripts", "remote_alpha_runtime_identity_helper_summary.sh"),
		"/scripts/remote_alpha_runtime_identity_helper_summary.sh",
	)
	assertContainsNone(t, "fake runtime identity scp log", scpLog,
		"remote_alpha_operator.sh",
		"scripts/internal",
		"remote_alpha_reset_disposable_vault.sh",
		"remote_alpha_vault_workload_auth_check.sh",
		"remote_alpha_vault_workload_auth_bootstrap.sh",
		"remote_alpha_migrate_vault_service_user.sh",
		"remote_alpha_prepare_es_config_tls",
		"remote_alpha_deploy_es_binaries",
		"bundle",
	)

	sshLog := mustRead(t, h.sshLogPath)
	if got := strings.Count(sshLog, "tty=true"); got != 1 {
		t.Fatalf("expected exactly one interactive ssh -tt invocation, got %d log=%q", got, sshLog)
	}
	assertContainsAll(t, "fake runtime identity ssh log", sshLog,
		"tty=true target=ds@m75q-test",
		"execution-substrate-remote-alpha-runtime-identity-summary",
		"exec /bin/bash -c",
	)
	assertContainsNone(t, "fake runtime identity ssh log forbidden capture", sshLog,
		" tee ",
		"script ",
		"transcript",
		"--execute-reset",
		"--unseal-only",
		"--post-unseal-check",
		"--execute-bootstrap",
		"remote-alpha-live-refresh",
		"remote-alpha-live-support-bundle",
		"cp-proof",
		".out",
	)

	sudoLog := strings.TrimSpace(mustRead(t, h.sudoLog))
	assertContainsAll(t, "fake runtime identity sudo log", sudoLog,
		"sudo_args=",
		"/scripts/remote_alpha_runtime_identity_helper_summary.sh",
	)
	assertContainsNone(t, "fake runtime identity sudo log forbidden args", sudoLog,
		"--dry-run",
		"--check-only",
		"--output",
		"--runtime-support-path",
		"--spire-agent-socket-path",
		"--audience",
		"remote_alpha_vault_workload_auth_check.sh",
		"remote_alpha_reset_disposable_vault.sh",
	)

	helperLog := strings.TrimSpace(mustRead(t, h.helperLog))
	if helperLog != "public_args=" {
		t.Fatalf("expected staged runtime identity helper to receive no args, got %q", helperLog)
	}

	rmLog := mustRead(t, h.rmLogPath)
	assertContainsAll(t, "fake runtime identity remote cleanup log", rmLog,
		"execution-substrate-remote-alpha-runtime-identity-summary",
	)
	if entries, err := os.ReadDir(filepath.Join(h.remoteRoot, "tmp", "execution-substrate-remote-alpha-runtime-identity-summary")); err == nil && len(entries) > 0 {
		t.Fatalf("expected remote runtime identity staged helper directory to be cleaned, found %d entries", len(entries))
	}
	assertNoNewPaths(t, "Mac-side fake runtime identity summary route", before)
}

type fakeRemoteAlphaESServiceTLSHarness struct {
	localBin   string
	remoteBin  string
	remoteRoot string
	sshLogPath string
	scpLogPath string
	rmLogPath  string
	sudoLog    string
	helperLog  string
}

func setupFakeRemoteAlphaESServiceTLSHarness(t *testing.T) *fakeRemoteAlphaESServiceTLSHarness {
	t.Helper()

	tmpDir := t.TempDir()
	h := &fakeRemoteAlphaESServiceTLSHarness{
		localBin:   filepath.Join(tmpDir, "local-bin"),
		remoteBin:  filepath.Join(tmpDir, "remote-bin"),
		remoteRoot: filepath.Join(tmpDir, "remote-root"),
		sshLogPath: filepath.Join(tmpDir, "ssh.log"),
		scpLogPath: filepath.Join(tmpDir, "scp.log"),
		rmLogPath:  filepath.Join(tmpDir, "rm.log"),
		sudoLog:    filepath.Join(tmpDir, "sudo.log"),
		helperLog:  filepath.Join(tmpDir, "helper.log"),
	}
	for _, dir := range []string{h.localBin, h.remoteBin, h.remoteRoot} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", dir, err)
		}
	}

	writeExecutable(t, h.localBin, "ssh", fmt.Sprintf(`#!/usr/bin/env bash
set -euo pipefail
tty=false
while [[ "${1:-}" == "-tt" ]]; do
  tty=true
  shift
done
target="${1:-}"
shift || true
printf 'tty=%%s target=%%s args=%%s\n' "${tty}" "${target}" "$*" >> %q
export PATH="${FAKE_REMOTE_BIN}:${PATH}"
if [[ "${1:-}" == "/bin/bash" && "${2:-}" == "-s" ]]; then
  shift 2
  if [[ "${1:-}" == "--" ]]; then
    shift
  fi
  mapped_args=()
  for arg in "$@"; do
    if [[ "${arg}" == /* ]]; then
      mapped_args+=("${FAKE_REMOTE_ROOT}${arg}")
    else
      mapped_args+=("${arg}")
    fi
  done
  payload="$(mktemp)"
  cat >"${payload}"
  set +e
  /bin/bash "${payload}" "${mapped_args[@]}"
  status=$?
  set -e
  rm -f -- "${payload}"
  exit "${status}"
fi
if [[ "$#" -eq 1 && "${1:-}" == exec\ /bin/bash\ -c* ]]; then
  command_string="${1}"
  tls_prefix="/tmp/execution-substrate-remote-alpha-es-service-tls-renew"
  mapped_command="${command_string//${tls_prefix}/${FAKE_REMOTE_ROOT}${tls_prefix}}"
  governance_tls_prefix="/tmp/execution-substrate-remote-alpha-es-governance-tls-renew"
  mapped_command="${mapped_command//${governance_tls_prefix}/${FAKE_REMOTE_ROOT}${governance_tls_prefix}}"
  operator_healthcheck_tls_prefix="/tmp/execution-substrate-remote-alpha-operator-healthcheck-tls-renew"
  mapped_command="${mapped_command//${operator_healthcheck_tls_prefix}/${FAKE_REMOTE_ROOT}${operator_healthcheck_tls_prefix}}"
  exec /bin/bash -c "${mapped_command}"
fi
echo "unexpected fake ssh invocation: $*" >&2
exit 64
`, h.sshLogPath))

	writeExecutable(t, h.localBin, "scp", fmt.Sprintf(`#!/usr/bin/env bash
set -euo pipefail
if [[ "$#" -ne 2 ]]; then
  echo "unexpected fake scp args: $*" >&2
  exit 64
fi
src=$1
dest=$2
printf '%%s\t%%s\n' "${src}" "${dest}" >> %q
if [[ "${src}" == *:* || "${dest}" != *:* ]]; then
  echo "fake scp supports one local-to-remote upload" >&2
  exit 64
fi
remote_path="${dest#*:}"
mapped_dest="${FAKE_REMOTE_ROOT}${remote_path}"
mkdir -p -- "$(dirname "${mapped_dest}")"
if [[ "${src}" == */scripts/internal/remote_alpha_es_service_tls_renew.sh ]]; then
  cat >"${mapped_dest}" <<'REMOTE_ALPHA_FAKE_ES_SERVICE_TLS_INTERNAL'
# fake ES service TLS internal helper staged for layout verification
REMOTE_ALPHA_FAKE_ES_SERVICE_TLS_INTERNAL
elif [[ "${src}" == */scripts/internal/remote_alpha_operator_healthcheck_tls_renew.sh ]]; then
  cat >"${mapped_dest}" <<'REMOTE_ALPHA_FAKE_OPERATOR_HEALTHCHECK_TLS_INTERNAL'
# fake operator healthcheck TLS internal helper staged for layout verification
REMOTE_ALPHA_FAKE_OPERATOR_HEALTHCHECK_TLS_INTERNAL
elif [[ "$(basename "${src}")" == "remote_alpha_operator_healthcheck_tls_renew.sh" ]]; then
  cat >"${mapped_dest}" <<'REMOTE_ALPHA_FAKE_OPERATOR_HEALTHCHECK_TLS_PUBLIC'
#!/usr/bin/env bash
set -euo pipefail
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
internal="${script_dir}/internal/remote_alpha_operator_healthcheck_tls_renew.sh"
if [[ ! -f "${internal}" ]]; then
  echo "missing internal helper: ${internal}" >&2
  exit 65
fi
printf 'public_args=%%s\n' "$*" >> %q
printf 'internal=%%s\n' "${internal}" >> %q
printf 'Remote Alpha operator healthcheck TLS helper finished.\n'
printf 'Remote summary path: /var/tmp/execution-substrate-remote-alpha/operator-healthcheck-tls-renew-summary.json\n'
printf 'IM refresh, support-bundle collection, CP proof, Vault, SPIRE, Nomad, reset/unseal, workload-auth, runtime identity, and ES restart were not run.\n'
REMOTE_ALPHA_FAKE_OPERATOR_HEALTHCHECK_TLS_PUBLIC
elif [[ "$(basename "${src}")" == "remote_alpha_es_service_tls_renew.sh" ]]; then
  cat >"${mapped_dest}" <<'REMOTE_ALPHA_FAKE_ES_SERVICE_TLS_PUBLIC'
#!/usr/bin/env bash
set -euo pipefail
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
internal="${script_dir}/internal/remote_alpha_es_service_tls_renew.sh"
if [[ ! -f "${internal}" ]]; then
  echo "missing internal helper: ${internal}" >&2
  exit 65
fi
printf 'public_args=%%s\n' "$*" >> %q
printf 'internal=%%s\n' "${internal}" >> %q
printf 'Remote Alpha ES service TLS helper finished.\n'
if [[ "$*" == *"execution-governance"* ]]; then
  printf 'Remote summary path: /var/tmp/execution-substrate-remote-alpha/es-governance-tls-renew-summary.json\n'
else
  printf 'Remote summary path: /var/tmp/execution-substrate-remote-alpha/es-service-tls-renew-summary.json\n'
fi
printf 'IM refresh, support-bundle collection, CP proof, Vault, SPIRE, Nomad, reset/unseal, workload-auth, and runtime identity were not run.\n'
REMOTE_ALPHA_FAKE_ES_SERVICE_TLS_PUBLIC
else
  echo "unexpected fake scp source: ${src}" >&2
  exit 64
fi
chmod 0700 "${mapped_dest}"
`, h.scpLogPath, h.helperLog, h.helperLog, h.helperLog, h.helperLog))

	writeExecutable(t, h.remoteBin, "id", `#!/usr/bin/env bash
set -euo pipefail
if [[ "${1:-}" == "-u" ]]; then
  echo 1000
  exit 0
fi
exec /usr/bin/id "$@"
`)
	writeExecutable(t, h.remoteBin, "sudo", fmt.Sprintf(`#!/usr/bin/env bash
set -euo pipefail
printf 'sudo_args=%%s\n' "$*" >> %q
exec "$@"
`, h.sudoLog))
	writeExecutable(t, h.remoteBin, "rm", fmt.Sprintf(`#!/usr/bin/env bash
set -euo pipefail
printf '%%s\n' "$*" >> %q
exec /bin/rm "$@"
`, h.rmLogPath))

	return h
}

func (h *fakeRemoteAlphaESServiceTLSHarness) env() []string {
	return envWithPath(h.localBin,
		"FAKE_REMOTE_BIN="+h.remoteBin,
		"FAKE_REMOTE_ROOT="+h.remoteRoot,
	)
}

func TestRemoteAlphaOperatorRecoverySessionESServiceTLSRejectsUnsafeArgsBeforeDelegation(t *testing.T) {
	for _, tc := range []struct {
		name     string
		args     []string
		required []string
	}{
		{
			name:     "status missing ssh target",
			args:     []string{"es-service-tls-status", "--interactive-tty"},
			required: []string{"recovery-session es-service-tls requires --ssh-target <target>", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "status missing tty",
			args:     []string{"es-service-tls-status", "--ssh-target", "host"},
			required: []string{"recovery-session es-service-tls requires --interactive-tty", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "status execute renew forbidden",
			args:     []string{"es-service-tls-status", "--ssh-target", "host", "--interactive-tty", "--execute-renew"},
			required: []string{"recovery-session es-service-tls-status forbids --execute-renew", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "renew missing execute renew",
			args:     []string{"es-service-tls-renew", "--ssh-target", "host", "--interactive-tty"},
			required: []string{"recovery-session es-service-tls-renew requires --execute-renew", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "renew missing ssh target",
			args:     []string{"es-service-tls-renew", "--execute-renew", "--interactive-tty"},
			required: []string{"recovery-session es-service-tls requires --ssh-target <target>", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "renew missing tty",
			args:     []string{"es-service-tls-renew", "--ssh-target", "host", "--execute-renew"},
			required: []string{"recovery-session es-service-tls requires --interactive-tty", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "helper override",
			args:     []string{"es-service-tls-status", "--ssh-target", "host", "--interactive-tty", "--summary-path", "/tmp/x"},
			required: []string{"forbids helper override flag --summary-path", "fixed documented ARS/AGS/ES TLS paths", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "forbidden status flag",
			args:     []string{"es-service-tls-status", "--ssh-target", "host", "--interactive-tty", "--status"},
			required: []string{"recovery-session es-service-tls forbids --status", "bounded ARS/AGS/ES internal TLS status/renew route", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "unknown flag",
			args:     []string{"es-service-tls-status", "--ssh-target", "host", "--interactive-tty", "--unknown-flag"},
			required: []string{"unknown option for recovery-session es-service-tls: --unknown-flag", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "equals form",
			args:     []string{"es-service-tls-status", "--ssh-target=host", "--interactive-tty"},
			required: []string{"recovery-session es-service-tls does not accept equals-form options: --ssh-target=host", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "duplicate interactive tty",
			args:     []string{"es-service-tls-status", "--ssh-target", "host", "--interactive-tty", "--interactive-tty"},
			required: []string{"duplicate option for recovery-session: --interactive-tty", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "ssh target option injection",
			args:     []string{"es-service-tls-status", "--ssh-target", "-oProxyCommand=sh", "--interactive-tty"},
			required: []string{"--ssh-target must be a single SSH target, not an option or shell command", "No recovery-session live helper or IM execution occurred."},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			output := requireRemoteAlphaOperatorFailure(t, append([]string{"recovery-session"}, tc.args...)...)
			assertContainsAll(t, "es-service-tls refusal", output, tc.required...)
			assertContainsNone(t, "es-service-tls refusal", output,
				"Running Mac-side ES service TLS",
				"remote_alpha_es_service_tls_renew.sh",
			)
		})
	}
}

func TestRemoteAlphaOperatorRecoverySessionESServiceTLSRejectsSecretLikeArgsBeforeDelegation(t *testing.T) {
	for _, args := range [][]string{
		{"--api-key=dummy"},
		{"--root-token", "dummy"},
		{"--unseal-key", "dummy"},
		{"--vault-token", "dummy"},
		{"--client-token", "dummy"},
		{"--jwt-svid", "dummy"},
		{"--private-key", "dummy"},
		{"--password", "dummy"},
		{"--secret", "dummy"},
	} {
		t.Run(strings.Join(args, "_"), func(t *testing.T) {
			routeArgs := append([]string{
				"recovery-session", "es-service-tls-renew",
				"--ssh-target", "host",
				"--interactive-tty",
				"--execute-renew",
			}, args...)
			output := requireRemoteAlphaOperatorFailure(t, routeArgs...)
			assertContainsAll(t, "es-service-tls secret flag refusal", output,
				"secret material must never be passed by CLI args/env/logs/reports/artifacts",
			)
			assertContainsNone(t, "es-service-tls secret flag refusal", output,
				"Running Mac-side ES service TLS",
				"remote_alpha_es_service_tls_renew.sh",
			)
		})
	}
}

func TestRemoteAlphaOperatorRecoverySessionESServiceTLSNoTTYFailsBeforeStaging(t *testing.T) {
	h := setupFakeRemoteAlphaESServiceTLSHarness(t)
	output, err := runRemoteAlphaOperatorWithEnv(h.env(),
		"recovery-session", "es-service-tls-status",
		"--ssh-target", "ds@m75q-test",
		"--interactive-tty",
	)
	if err == nil {
		t.Fatalf("expected no-TTY failure before ES service TLS staging, got success:\n%s", output)
	}
	assertContainsAll(t, "es-service-tls no tty refusal", output,
		"requires visible local terminal",
		"no staging or SSH occurred",
		"No recovery-session live helper or IM execution occurred.",
	)
	if _, err := os.Stat(h.sshLogPath); !os.IsNotExist(err) {
		t.Fatalf("ssh should not run when ES service TLS local TTY guard fails: %v", err)
	}
	if _, err := os.Stat(h.scpLogPath); !os.IsNotExist(err) {
		t.Fatalf("scp should not run when ES service TLS local TTY guard fails: %v", err)
	}
}

func TestRemoteAlphaOperatorRecoverySessionESServiceTLSStatusStagesOnlyFixedHelperPair(t *testing.T) {
	h := setupFakeRemoteAlphaESServiceTLSHarness(t)
	before := snapshotPathExistence(t, remoteAlphaOperatorRouteArtifactPaths(filepath.Join(".out", "remote-alpha-m75q", "es-service-tls-renew-summary.json"))...)

	output, err := runRemoteAlphaOperatorWithPTY(t, h.env(),
		"recovery-session", "es-service-tls-status",
		"--ssh-target", "ds@m75q-test",
		"--interactive-tty",
	)
	if err != nil {
		t.Fatalf("Mac-side fake ES service TLS status route failed: %v\noutput=%s\nssh=%s\nscp=%s\nsudo=%s\nhelper=%s\nrm=%s",
			err, output, readIfExists(h.sshLogPath), readIfExists(h.scpLogPath), readIfExists(h.sudoLog), readIfExists(h.helperLog), readIfExists(h.rmLogPath))
	}

	assertESServiceTLSFakeRoute(t, h, output, "--status")
	assertContainsAll(t, "Mac-side fake ES service TLS status output", output,
		"Running Mac-side ES service TLS status through an explicit interactive SSH TTY.",
		"Invoking only the staged public helper with --status",
		"Status mode is non-mutating",
		"Status mode is non-mutating and does not restart services.",
	)
	assertContainsNone(t, "Mac-side fake ES service TLS status output", output,
		"--execute-renew",
		"remote-alpha-live-refresh",
		"remote-alpha-live-support-bundle",
		"cp-proof",
		"BEGIN PRIVATE KEY",
		"BEGIN CERTIFICATE",
	)
	assertNoNewPaths(t, "Mac-side fake ES service TLS status route", before)
}

func TestRemoteAlphaOperatorRecoverySessionESServiceTLSRenewStagesOnlyFixedHelperPair(t *testing.T) {
	h := setupFakeRemoteAlphaESServiceTLSHarness(t)
	before := snapshotPathExistence(t, remoteAlphaOperatorRouteArtifactPaths(filepath.Join(".out", "remote-alpha-m75q", "es-service-tls-renew-summary.json"))...)

	output, err := runRemoteAlphaOperatorWithPTY(t, h.env(),
		"recovery-session", "es-service-tls-renew",
		"--ssh-target", "ds@m75q-test",
		"--interactive-tty",
		"--execute-renew",
	)
	if err != nil {
		t.Fatalf("Mac-side fake ES service TLS renew route failed: %v\noutput=%s\nssh=%s\nscp=%s\nsudo=%s\nhelper=%s\nrm=%s",
			err, output, readIfExists(h.sshLogPath), readIfExists(h.scpLogPath), readIfExists(h.sudoLog), readIfExists(h.helperLog), readIfExists(h.rmLogPath))
	}

	assertESServiceTLSFakeRoute(t, h, output, "--execute-renew")
	assertContainsAll(t, "Mac-side fake ES service TLS renew output", output,
		"Running Mac-side ES service TLS renewal through an explicit interactive SSH TTY.",
		"Invoking only the staged public helper with --execute-renew",
		"bounded to ARS/AGS/ES internal artifact-registry mTLS material",
		"restarted only ars.service, ags.service, and es.service",
	)
	assertContainsNone(t, "Mac-side fake ES service TLS renew output", output,
		"remote-alpha-live-refresh",
		"remote-alpha-live-support-bundle",
		"cp-proof",
		"BEGIN PRIVATE KEY",
		"BEGIN CERTIFICATE",
	)
	assertNoNewPaths(t, "Mac-side fake ES service TLS renew route", before)
}

func assertESServiceTLSFakeRoute(t *testing.T, h *fakeRemoteAlphaESServiceTLSHarness, output string, helperMode string) {
	t.Helper()
	assertContainsAll(t, "Mac-side fake ES service TLS output", output,
		"Staging only scripts/remote_alpha_es_service_tls_renew.sh and scripts/internal/remote_alpha_es_service_tls_renew.sh.",
		"Canonical summary stays remote at /var/tmp/execution-substrate-remote-alpha/es-service-tls-renew-summary.json.",
		"Remote Alpha ES service TLS helper finished.",
		"Canonical remote summary path: /var/tmp/execution-substrate-remote-alpha/es-service-tls-renew-summary.json",
		"did not copy it back to Mac .out",
		"did not print full summary JSON",
	)

	scpLog := strings.TrimSpace(mustRead(t, h.scpLogPath))
	scpLines := strings.Split(scpLog, "\n")
	if len(scpLines) != 2 {
		t.Fatalf("expected exactly two staged file uploads, got %q", scpLog)
	}
	assertContainsAll(t, "fake ES service TLS scp log", scpLog,
		filepath.Join(executionSubstrateRepoRoot, "scripts", "remote_alpha_es_service_tls_renew.sh"),
		filepath.Join(executionSubstrateRepoRoot, "scripts", "internal", "remote_alpha_es_service_tls_renew.sh"),
		"/scripts/remote_alpha_es_service_tls_renew.sh",
		"/scripts/internal/remote_alpha_es_service_tls_renew.sh",
	)
	assertContainsNone(t, "fake ES service TLS scp log", scpLog,
		"remote_alpha_operator.sh",
		"remote_alpha_reset_disposable_vault.sh",
		"remote_alpha_vault_workload_auth_check.sh",
		"remote_alpha_vault_workload_auth_bootstrap.sh",
		"remote_alpha_runtime_identity_helper_summary.sh",
		"remote_alpha_migrate_vault_service_user.sh",
		"remote_alpha_prepare_es_config_tls",
		"remote_alpha_deploy_es_binaries",
		"bundle",
	)

	sshLog := mustRead(t, h.sshLogPath)
	if got := strings.Count(sshLog, "tty=true"); got != 1 {
		t.Fatalf("expected exactly one interactive ssh -tt invocation, got %d log=%q", got, sshLog)
	}
	assertContainsAll(t, "fake ES service TLS ssh log", sshLog,
		"tty=true target=ds@m75q-test",
		"execution-substrate-remote-alpha-es-service-tls-renew",
		"exec /bin/bash -c",
	)
	assertContainsNone(t, "fake ES service TLS ssh log forbidden capture", sshLog,
		" tee ",
		"script ",
		"transcript",
		"remote-alpha-live-refresh",
		"remote-alpha-live-support-bundle",
		"cp-proof",
		".out",
	)

	sudoLog := strings.TrimSpace(mustRead(t, h.sudoLog))
	assertContainsAll(t, "fake ES service TLS sudo log", sudoLog,
		"sudo_args=",
		"/scripts/remote_alpha_es_service_tls_renew.sh",
		helperMode,
	)
	assertContainsNone(t, "fake ES service TLS sudo log forbidden args", sudoLog,
		"--summary-path",
		"--dry-run",
		"--check-only",
		"--ars-config-path",
		"--es-tls-dir",
		"remote_alpha_vault_workload_auth_check.sh",
		"remote_alpha_reset_disposable_vault.sh",
	)

	helperLog := strings.TrimSpace(mustRead(t, h.helperLog))
	assertContainsAll(t, "fake ES service TLS helper log", helperLog,
		"public_args="+helperMode,
		"/scripts/internal/remote_alpha_es_service_tls_renew.sh",
	)
	assertContainsNone(t, "fake ES service TLS helper log forbidden args", helperLog,
		"--summary-path",
		"--dry-run",
		"--check-only",
		"--root-token",
	)

	rmLog := mustRead(t, h.rmLogPath)
	assertContainsAll(t, "fake ES service TLS remote cleanup log", rmLog,
		"execution-substrate-remote-alpha-es-service-tls-renew",
	)
	if entries, err := os.ReadDir(filepath.Join(h.remoteRoot, "tmp", "execution-substrate-remote-alpha-es-service-tls-renew")); err == nil && len(entries) > 0 {
		t.Fatalf("expected remote ES service TLS staged helper directory to be cleaned, found %d entries", len(entries))
	}
}

func TestRemoteAlphaOperatorRecoverySessionESGovernanceTLSRejectsUnsafeArgsBeforeDelegation(t *testing.T) {
	for _, tc := range []struct {
		name     string
		args     []string
		required []string
	}{
		{
			name:     "status missing ssh target",
			args:     []string{"es-governance-tls-status", "--interactive-tty"},
			required: []string{"recovery-session es-governance-tls requires --ssh-target <target>", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "status missing tty",
			args:     []string{"es-governance-tls-status", "--ssh-target", "host"},
			required: []string{"recovery-session es-governance-tls requires --interactive-tty", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "status execute renew forbidden",
			args:     []string{"es-governance-tls-status", "--ssh-target", "host", "--interactive-tty", "--execute-renew"},
			required: []string{"recovery-session es-governance-tls-status forbids --execute-renew", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "renew missing execute renew",
			args:     []string{"es-governance-tls-renew", "--ssh-target", "host", "--interactive-tty"},
			required: []string{"recovery-session es-governance-tls-renew requires --execute-renew", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "renew missing ssh target",
			args:     []string{"es-governance-tls-renew", "--execute-renew", "--interactive-tty"},
			required: []string{"recovery-session es-governance-tls requires --ssh-target <target>", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "renew missing tty",
			args:     []string{"es-governance-tls-renew", "--ssh-target", "host", "--execute-renew"},
			required: []string{"recovery-session es-governance-tls requires --interactive-tty", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "helper override",
			args:     []string{"es-governance-tls-status", "--ssh-target", "host", "--interactive-tty", "--summary-path", "/tmp/x"},
			required: []string{"forbids helper override flag --summary-path", "fixed documented ES/EGS governance TLS paths", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "scope override",
			args:     []string{"es-governance-tls-status", "--ssh-target", "host", "--interactive-tty", "--scope", "artifact-registry"},
			required: []string{"forbids --scope", "fixed execution-governance scope", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "unknown flag",
			args:     []string{"es-governance-tls-status", "--ssh-target", "host", "--interactive-tty", "--unknown-flag"},
			required: []string{"unknown option for recovery-session es-governance-tls: --unknown-flag", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "equals form",
			args:     []string{"es-governance-tls-status", "--ssh-target=host", "--interactive-tty"},
			required: []string{"recovery-session es-governance-tls does not accept equals-form options: --ssh-target=host", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "ssh target option injection",
			args:     []string{"es-governance-tls-status", "--ssh-target", "-oProxyCommand=sh", "--interactive-tty"},
			required: []string{"--ssh-target must be a single SSH target, not an option or shell command", "No recovery-session live helper or IM execution occurred."},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			output := requireRemoteAlphaOperatorFailure(t, append([]string{"recovery-session"}, tc.args...)...)
			assertContainsAll(t, "es-governance-tls refusal", output, tc.required...)
			assertContainsNone(t, "es-governance-tls refusal", output,
				"Running Mac-side ES governance TLS",
				"remote_alpha_es_service_tls_renew.sh",
			)
		})
	}
}

func TestRemoteAlphaOperatorRecoverySessionESGovernanceTLSRejectsSecretLikeArgsBeforeDelegation(t *testing.T) {
	for _, args := range [][]string{
		{"--api-key=dummy"},
		{"--root-token", "dummy"},
		{"--unseal-key", "dummy"},
		{"--vault-token", "dummy"},
		{"--client-token", "dummy"},
		{"--jwt-svid", "dummy"},
		{"--private-key", "dummy"},
		{"--password", "dummy"},
		{"--secret", "dummy"},
	} {
		t.Run(strings.Join(args, "_"), func(t *testing.T) {
			routeArgs := append([]string{
				"recovery-session", "es-governance-tls-renew",
				"--ssh-target", "host",
				"--interactive-tty",
				"--execute-renew",
			}, args...)
			output := requireRemoteAlphaOperatorFailure(t, routeArgs...)
			assertContainsAll(t, "es-governance-tls secret flag refusal", output,
				"secret material must never be passed by CLI args/env/logs/reports/artifacts",
			)
			assertContainsNone(t, "es-governance-tls secret flag refusal", output,
				"Running Mac-side ES governance TLS",
				"remote_alpha_es_service_tls_renew.sh",
			)
		})
	}
}

func TestRemoteAlphaOperatorRecoverySessionESGovernanceTLSNoTTYFailsBeforeStaging(t *testing.T) {
	h := setupFakeRemoteAlphaESServiceTLSHarness(t)
	output, err := runRemoteAlphaOperatorWithEnv(h.env(),
		"recovery-session", "es-governance-tls-status",
		"--ssh-target", "ds@m75q-test",
		"--interactive-tty",
	)
	if err == nil {
		t.Fatalf("expected no-TTY failure before ES governance TLS staging, got success:\n%s", output)
	}
	assertContainsAll(t, "es-governance-tls no tty refusal", output,
		"requires visible local terminal",
		"no staging or SSH occurred",
		"No recovery-session live helper or IM execution occurred.",
	)
	if _, err := os.Stat(h.sshLogPath); !os.IsNotExist(err) {
		t.Fatalf("ssh should not run when ES governance TLS local TTY guard fails: %v", err)
	}
	if _, err := os.Stat(h.scpLogPath); !os.IsNotExist(err) {
		t.Fatalf("scp should not run when ES governance TLS local TTY guard fails: %v", err)
	}
}

func TestRemoteAlphaOperatorRecoverySessionESGovernanceTLSStatusStagesOnlyFixedHelperPair(t *testing.T) {
	h := setupFakeRemoteAlphaESServiceTLSHarness(t)
	before := snapshotPathExistence(t, remoteAlphaOperatorRouteArtifactPaths(filepath.Join(".out", "remote-alpha-m75q", "es-governance-tls-renew-summary.json"))...)

	output, err := runRemoteAlphaOperatorWithPTY(t, h.env(),
		"recovery-session", "es-governance-tls-status",
		"--ssh-target", "ds@m75q-test",
		"--interactive-tty",
	)
	if err != nil {
		t.Fatalf("Mac-side fake ES governance TLS status route failed: %v\noutput=%s\nssh=%s\nscp=%s\nsudo=%s\nhelper=%s\nrm=%s",
			err, output, readIfExists(h.sshLogPath), readIfExists(h.scpLogPath), readIfExists(h.sudoLog), readIfExists(h.helperLog), readIfExists(h.rmLogPath))
	}

	assertESGovernanceTLSFakeRoute(t, h, output, "--scope execution-governance --status")
	assertContainsAll(t, "Mac-side fake ES governance TLS status output", output,
		"Running Mac-side ES governance TLS status through an explicit interactive SSH TTY.",
		"Invoking only the staged public helper with --scope execution-governance --status",
		"Status mode is non-mutating",
		"Status mode is non-mutating and does not restart services.",
	)
	assertContainsNone(t, "Mac-side fake ES governance TLS status output", output,
		"--execute-renew",
		"remote-alpha-live-refresh",
		"remote-alpha-live-support-bundle",
		"cp-proof",
		"BEGIN PRIVATE KEY",
		"BEGIN CERTIFICATE",
	)
	assertNoNewPaths(t, "Mac-side fake ES governance TLS status route", before)
}

func TestRemoteAlphaOperatorRecoverySessionESGovernanceTLSRenewStagesOnlyFixedHelperPair(t *testing.T) {
	h := setupFakeRemoteAlphaESServiceTLSHarness(t)
	before := snapshotPathExistence(t, remoteAlphaOperatorRouteArtifactPaths(filepath.Join(".out", "remote-alpha-m75q", "es-governance-tls-renew-summary.json"))...)

	output, err := runRemoteAlphaOperatorWithPTY(t, h.env(),
		"recovery-session", "es-governance-tls-renew",
		"--ssh-target", "ds@m75q-test",
		"--interactive-tty",
		"--execute-renew",
	)
	if err != nil {
		t.Fatalf("Mac-side fake ES governance TLS renew route failed: %v\noutput=%s\nssh=%s\nscp=%s\nsudo=%s\nhelper=%s\nrm=%s",
			err, output, readIfExists(h.sshLogPath), readIfExists(h.scpLogPath), readIfExists(h.sudoLog), readIfExists(h.helperLog), readIfExists(h.rmLogPath))
	}

	assertESGovernanceTLSFakeRoute(t, h, output, "--scope execution-governance --execute-renew")
	assertContainsAll(t, "Mac-side fake ES governance TLS renew output", output,
		"Running Mac-side ES governance TLS renewal through an explicit interactive SSH TTY.",
		"Invoking only the staged public helper with --scope execution-governance --execute-renew",
		"bounded to ES/EGS execution-governance trust-model mTLS material",
		"restarted only egs.service and es.service",
	)
	assertContainsNone(t, "Mac-side fake ES governance TLS renew output", output,
		"remote-alpha-live-refresh",
		"remote-alpha-live-support-bundle",
		"cp-proof",
		"BEGIN PRIVATE KEY",
		"BEGIN CERTIFICATE",
	)
	assertNoNewPaths(t, "Mac-side fake ES governance TLS renew route", before)
}

func assertESGovernanceTLSFakeRoute(t *testing.T, h *fakeRemoteAlphaESServiceTLSHarness, output string, helperArgs string) {
	t.Helper()
	assertContainsAll(t, "Mac-side fake ES governance TLS output", output,
		"Staging only scripts/remote_alpha_es_service_tls_renew.sh and scripts/internal/remote_alpha_es_service_tls_renew.sh.",
		"Canonical summary stays remote at /var/tmp/execution-substrate-remote-alpha/es-governance-tls-renew-summary.json.",
		"Remote Alpha ES service TLS helper finished.",
		"Canonical remote summary path: /var/tmp/execution-substrate-remote-alpha/es-governance-tls-renew-summary.json",
		"did not copy it back to Mac .out",
		"did not print full summary JSON",
	)

	scpLog := strings.TrimSpace(mustRead(t, h.scpLogPath))
	scpLines := strings.Split(scpLog, "\n")
	if len(scpLines) != 2 {
		t.Fatalf("expected exactly two staged file uploads, got %q", scpLog)
	}
	assertContainsAll(t, "fake ES governance TLS scp log", scpLog,
		filepath.Join(executionSubstrateRepoRoot, "scripts", "remote_alpha_es_service_tls_renew.sh"),
		filepath.Join(executionSubstrateRepoRoot, "scripts", "internal", "remote_alpha_es_service_tls_renew.sh"),
		"/scripts/remote_alpha_es_service_tls_renew.sh",
		"/scripts/internal/remote_alpha_es_service_tls_renew.sh",
	)
	assertContainsNone(t, "fake ES governance TLS scp log", scpLog,
		"remote_alpha_operator.sh",
		"remote_alpha_reset_disposable_vault.sh",
		"remote_alpha_vault_workload_auth_check.sh",
		"remote_alpha_vault_workload_auth_bootstrap.sh",
		"remote_alpha_runtime_identity_helper_summary.sh",
		"remote_alpha_migrate_vault_service_user.sh",
		"remote_alpha_prepare_es_config_tls",
		"remote_alpha_deploy_es_binaries",
		"bundle",
	)

	sshLog := mustRead(t, h.sshLogPath)
	if got := strings.Count(sshLog, "tty=true"); got != 1 {
		t.Fatalf("expected exactly one interactive ssh -tt invocation, got %d log=%q", got, sshLog)
	}
	assertContainsAll(t, "fake ES governance TLS ssh log", sshLog,
		"tty=true target=ds@m75q-test",
		"execution-substrate-remote-alpha-es-governance-tls-renew",
		"exec /bin/bash -c",
	)
	assertContainsNone(t, "fake ES governance TLS ssh log forbidden capture", sshLog,
		" tee ",
		"script ",
		"transcript",
		"remote-alpha-live-refresh",
		"remote-alpha-live-support-bundle",
		"cp-proof",
		".out",
	)

	sudoLog := strings.TrimSpace(mustRead(t, h.sudoLog))
	assertContainsAll(t, "fake ES governance TLS sudo log", sudoLog,
		"sudo_args=",
		"/scripts/remote_alpha_es_service_tls_renew.sh",
		helperArgs,
	)
	assertContainsNone(t, "fake ES governance TLS sudo log forbidden args", sudoLog,
		"--summary-path",
		"--dry-run",
		"--check-only",
		"--egs-config-path",
		"--es-tls-dir",
		"remote_alpha_vault_workload_auth_check.sh",
		"remote_alpha_reset_disposable_vault.sh",
	)

	helperLog := strings.TrimSpace(mustRead(t, h.helperLog))
	assertContainsAll(t, "fake ES governance TLS helper log", helperLog,
		"public_args="+helperArgs,
		"/scripts/internal/remote_alpha_es_service_tls_renew.sh",
	)
	assertContainsNone(t, "fake ES governance TLS helper log forbidden args", helperLog,
		"--summary-path",
		"--dry-run",
		"--check-only",
		"--root-token",
	)

	rmLog := mustRead(t, h.rmLogPath)
	assertContainsAll(t, "fake ES governance TLS remote cleanup log", rmLog,
		"execution-substrate-remote-alpha-es-governance-tls-renew",
	)
	if entries, err := os.ReadDir(filepath.Join(h.remoteRoot, "tmp", "execution-substrate-remote-alpha-es-governance-tls-renew")); err == nil && len(entries) > 0 {
		t.Fatalf("expected remote ES governance TLS staged helper directory to be cleaned, found %d entries", len(entries))
	}
}

func TestRemoteAlphaOperatorRecoverySessionOperatorHealthcheckTLSRejectsUnsafeArgsBeforeDelegation(t *testing.T) {
	for _, tc := range []struct {
		name     string
		args     []string
		required []string
	}{
		{
			name:     "status missing ssh target",
			args:     []string{"operator-healthcheck-tls-status", "--interactive-tty"},
			required: []string{"recovery-session operator-healthcheck-tls requires --ssh-target <target>", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "status missing tty",
			args:     []string{"operator-healthcheck-tls-status", "--ssh-target", "host"},
			required: []string{"recovery-session operator-healthcheck-tls requires --interactive-tty", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "status execute renew forbidden",
			args:     []string{"operator-healthcheck-tls-status", "--ssh-target", "host", "--interactive-tty", "--execute-renew"},
			required: []string{"recovery-session operator-healthcheck-tls-status forbids --execute-renew", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "renew missing execute renew",
			args:     []string{"operator-healthcheck-tls-renew", "--ssh-target", "host", "--interactive-tty"},
			required: []string{"recovery-session operator-healthcheck-tls-renew requires --execute-renew", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "renew missing ssh target",
			args:     []string{"operator-healthcheck-tls-renew", "--execute-renew", "--interactive-tty"},
			required: []string{"recovery-session operator-healthcheck-tls requires --ssh-target <target>", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "renew missing tty",
			args:     []string{"operator-healthcheck-tls-renew", "--ssh-target", "host", "--execute-renew"},
			required: []string{"recovery-session operator-healthcheck-tls requires --interactive-tty", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "helper override",
			args:     []string{"operator-healthcheck-tls-status", "--ssh-target", "host", "--interactive-tty", "--summary-path", "/tmp/x"},
			required: []string{"forbids helper override flag --summary-path", "fixed documented operator healthcheck TLS paths", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "forbidden status flag",
			args:     []string{"operator-healthcheck-tls-status", "--ssh-target", "host", "--interactive-tty", "--status"},
			required: []string{"recovery-session operator-healthcheck-tls forbids --status", "bounded host-local operator healthcheck client TLS status/renew route", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "unknown flag",
			args:     []string{"operator-healthcheck-tls-status", "--ssh-target", "host", "--interactive-tty", "--unknown-flag"},
			required: []string{"unknown option for recovery-session operator-healthcheck-tls: --unknown-flag", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "equals form",
			args:     []string{"operator-healthcheck-tls-status", "--ssh-target=host", "--interactive-tty"},
			required: []string{"recovery-session operator-healthcheck-tls does not accept equals-form options: --ssh-target=host", "No recovery-session live helper or IM execution occurred."},
		},
		{
			name:     "ssh target option injection",
			args:     []string{"operator-healthcheck-tls-status", "--ssh-target", "-oProxyCommand=sh", "--interactive-tty"},
			required: []string{"--ssh-target must be a single SSH target, not an option or shell command", "No recovery-session live helper or IM execution occurred."},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			output := requireRemoteAlphaOperatorFailure(t, append([]string{"recovery-session"}, tc.args...)...)
			assertContainsAll(t, "operator-healthcheck-tls refusal", output, tc.required...)
			assertContainsNone(t, "operator-healthcheck-tls refusal", output,
				"Running Mac-side operator healthcheck TLS",
				"remote_alpha_operator_healthcheck_tls_renew.sh",
			)
		})
	}
}

func TestRemoteAlphaOperatorRecoverySessionOperatorHealthcheckTLSRejectsSecretLikeArgsBeforeDelegation(t *testing.T) {
	for _, args := range [][]string{
		{"--api-key=dummy"},
		{"--root-token", "dummy"},
		{"--unseal-key", "dummy"},
		{"--vault-token", "dummy"},
		{"--client-token", "dummy"},
		{"--jwt-svid", "dummy"},
		{"--private-key", "dummy"},
		{"--password", "dummy"},
		{"--secret", "dummy"},
	} {
		t.Run(strings.Join(args, "_"), func(t *testing.T) {
			routeArgs := append([]string{
				"recovery-session", "operator-healthcheck-tls-renew",
				"--ssh-target", "host",
				"--interactive-tty",
				"--execute-renew",
			}, args...)
			output := requireRemoteAlphaOperatorFailure(t, routeArgs...)
			assertContainsAll(t, "operator-healthcheck-tls secret flag refusal", output,
				"secret material must never be passed by CLI args/env/logs/reports/artifacts",
			)
			assertContainsNone(t, "operator-healthcheck-tls secret flag refusal", output,
				"Running Mac-side operator healthcheck TLS",
				"remote_alpha_operator_healthcheck_tls_renew.sh",
			)
		})
	}
}

func TestRemoteAlphaOperatorRecoverySessionOperatorHealthcheckTLSNoTTYFailsBeforeStaging(t *testing.T) {
	h := setupFakeRemoteAlphaESServiceTLSHarness(t)
	output, err := runRemoteAlphaOperatorWithEnv(h.env(),
		"recovery-session", "operator-healthcheck-tls-status",
		"--ssh-target", "ds@m75q-test",
		"--interactive-tty",
	)
	if err == nil {
		t.Fatalf("expected no-TTY failure before operator healthcheck TLS staging, got success:\n%s", output)
	}
	assertContainsAll(t, "operator-healthcheck-tls no tty refusal", output,
		"requires visible local terminal",
		"no staging or SSH occurred",
		"No recovery-session live helper or IM execution occurred.",
	)
	if _, err := os.Stat(h.sshLogPath); !os.IsNotExist(err) {
		t.Fatalf("ssh should not run when operator healthcheck TLS local TTY guard fails: %v", err)
	}
	if _, err := os.Stat(h.scpLogPath); !os.IsNotExist(err) {
		t.Fatalf("scp should not run when operator healthcheck TLS local TTY guard fails: %v", err)
	}
}

func TestRemoteAlphaOperatorRecoverySessionOperatorHealthcheckTLSStatusStagesOnlyFixedHelperPair(t *testing.T) {
	h := setupFakeRemoteAlphaESServiceTLSHarness(t)
	before := snapshotPathExistence(t, remoteAlphaOperatorRouteArtifactPaths(filepath.Join(".out", "remote-alpha-m75q", "operator-healthcheck-tls-renew-summary.json"))...)

	output, err := runRemoteAlphaOperatorWithPTY(t, h.env(),
		"recovery-session", "operator-healthcheck-tls-status",
		"--ssh-target", "ds@m75q-test",
		"--interactive-tty",
	)
	if err != nil {
		t.Fatalf("Mac-side fake operator healthcheck TLS status route failed: %v\noutput=%s\nssh=%s\nscp=%s\nsudo=%s\nhelper=%s\nrm=%s",
			err, output, readIfExists(h.sshLogPath), readIfExists(h.scpLogPath), readIfExists(h.sudoLog), readIfExists(h.helperLog), readIfExists(h.rmLogPath))
	}

	assertOperatorHealthcheckTLSFakeRoute(t, h, output, "--status")
	assertContainsAll(t, "Mac-side fake operator healthcheck TLS status output", output,
		"Running Mac-side operator healthcheck TLS status through an explicit interactive SSH TTY.",
		"Invoking only the staged public helper with --status",
		"Status mode is non-mutating",
		"Status mode is non-mutating and does not restart services.",
	)
	assertContainsNone(t, "Mac-side fake operator healthcheck TLS status output", output,
		"--execute-renew",
		"remote-alpha-live-refresh",
		"remote-alpha-live-support-bundle",
		"cp-proof",
		"BEGIN PRIVATE KEY",
		"BEGIN CERTIFICATE",
	)
	assertNoNewPaths(t, "Mac-side fake operator healthcheck TLS status route", before)
}

func TestRemoteAlphaOperatorRecoverySessionOperatorHealthcheckTLSRenewStagesOnlyFixedHelperPair(t *testing.T) {
	h := setupFakeRemoteAlphaESServiceTLSHarness(t)
	before := snapshotPathExistence(t, remoteAlphaOperatorRouteArtifactPaths(filepath.Join(".out", "remote-alpha-m75q", "operator-healthcheck-tls-renew-summary.json"))...)

	output, err := runRemoteAlphaOperatorWithPTY(t, h.env(),
		"recovery-session", "operator-healthcheck-tls-renew",
		"--ssh-target", "ds@m75q-test",
		"--interactive-tty",
		"--execute-renew",
	)
	if err != nil {
		t.Fatalf("Mac-side fake operator healthcheck TLS renew route failed: %v\noutput=%s\nssh=%s\nscp=%s\nsudo=%s\nhelper=%s\nrm=%s",
			err, output, readIfExists(h.sshLogPath), readIfExists(h.scpLogPath), readIfExists(h.sudoLog), readIfExists(h.helperLog), readIfExists(h.rmLogPath))
	}

	assertOperatorHealthcheckTLSFakeRoute(t, h, output, "--execute-renew")
	assertContainsAll(t, "Mac-side fake operator healthcheck TLS renew output", output,
		"Running Mac-side operator healthcheck TLS renewal through an explicit interactive SSH TTY.",
		"Invoking only the staged public helper with --execute-renew",
		"spiffe://execution.internal/operator/local",
		"did not restart ES",
	)
	assertContainsNone(t, "Mac-side fake operator healthcheck TLS renew output", output,
		"remote-alpha-live-refresh",
		"remote-alpha-live-support-bundle",
		"cp-proof",
		"BEGIN PRIVATE KEY",
		"BEGIN CERTIFICATE",
	)
	assertNoNewPaths(t, "Mac-side fake operator healthcheck TLS renew route", before)
}

func assertOperatorHealthcheckTLSFakeRoute(t *testing.T, h *fakeRemoteAlphaESServiceTLSHarness, output string, helperMode string) {
	t.Helper()
	assertContainsAll(t, "Mac-side fake operator healthcheck TLS output", output,
		"Staging only scripts/remote_alpha_operator_healthcheck_tls_renew.sh and scripts/internal/remote_alpha_operator_healthcheck_tls_renew.sh.",
		"Canonical summary stays remote at /var/tmp/execution-substrate-remote-alpha/operator-healthcheck-tls-renew-summary.json.",
		"Remote Alpha operator healthcheck TLS helper finished.",
		"Canonical remote summary path: /var/tmp/execution-substrate-remote-alpha/operator-healthcheck-tls-renew-summary.json",
		"did not copy it back to Mac .out",
		"did not print full summary JSON",
	)

	scpLog := strings.TrimSpace(mustRead(t, h.scpLogPath))
	scpLines := strings.Split(scpLog, "\n")
	if len(scpLines) != 2 {
		t.Fatalf("expected exactly two staged file uploads, got %q", scpLog)
	}
	assertContainsAll(t, "fake operator healthcheck TLS scp log", scpLog,
		filepath.Join(executionSubstrateRepoRoot, "scripts", "remote_alpha_operator_healthcheck_tls_renew.sh"),
		filepath.Join(executionSubstrateRepoRoot, "scripts", "internal", "remote_alpha_operator_healthcheck_tls_renew.sh"),
		"/scripts/remote_alpha_operator_healthcheck_tls_renew.sh",
		"/scripts/internal/remote_alpha_operator_healthcheck_tls_renew.sh",
	)
	assertContainsNone(t, "fake operator healthcheck TLS scp log", scpLog,
		"remote_alpha_operator.sh",
		"remote_alpha_reset_disposable_vault.sh",
		"remote_alpha_vault_workload_auth_check.sh",
		"remote_alpha_vault_workload_auth_bootstrap.sh",
		"remote_alpha_runtime_identity_helper_summary.sh",
		"remote_alpha_es_service_tls_renew.sh",
		"remote_alpha_migrate_vault_service_user.sh",
		"remote_alpha_prepare_es_config_tls",
		"remote_alpha_deploy_es_binaries",
		"bundle",
	)

	sshLog := mustRead(t, h.sshLogPath)
	if got := strings.Count(sshLog, "tty=true"); got != 1 {
		t.Fatalf("expected exactly one interactive ssh -tt invocation, got %d log=%q", got, sshLog)
	}
	assertContainsAll(t, "fake operator healthcheck TLS ssh log", sshLog,
		"tty=true target=ds@m75q-test",
		"execution-substrate-remote-alpha-operator-healthcheck-tls-renew",
		"exec /bin/bash -c",
	)
	assertContainsNone(t, "fake operator healthcheck TLS ssh log forbidden capture", sshLog,
		" tee ",
		"script ",
		"transcript",
		"remote-alpha-live-refresh",
		"remote-alpha-live-support-bundle",
		"cp-proof",
		".out",
	)

	sudoLog := strings.TrimSpace(mustRead(t, h.sudoLog))
	assertContainsAll(t, "fake operator healthcheck TLS sudo log", sudoLog,
		"sudo_args=",
		"/scripts/remote_alpha_operator_healthcheck_tls_renew.sh",
		helperMode,
	)
	assertContainsNone(t, "fake operator healthcheck TLS sudo log forbidden args", sudoLog,
		"--summary-path",
		"--dry-run",
		"--check-only",
		"--operator-cert-path",
		"--es-config-path",
		"remote_alpha_vault_workload_auth_check.sh",
		"remote_alpha_reset_disposable_vault.sh",
	)

	helperLog := strings.TrimSpace(mustRead(t, h.helperLog))
	assertContainsAll(t, "fake operator healthcheck TLS helper log", helperLog,
		"public_args="+helperMode,
		"/scripts/internal/remote_alpha_operator_healthcheck_tls_renew.sh",
	)
	assertContainsNone(t, "fake operator healthcheck TLS helper log forbidden args", helperLog,
		"--summary-path",
		"--dry-run",
		"--check-only",
		"--root-token",
	)

	rmLog := mustRead(t, h.rmLogPath)
	assertContainsAll(t, "fake operator healthcheck TLS remote cleanup log", rmLog,
		"execution-substrate-remote-alpha-operator-healthcheck-tls-renew",
	)
	if entries, err := os.ReadDir(filepath.Join(h.remoteRoot, "tmp", "execution-substrate-remote-alpha-operator-healthcheck-tls-renew")); err == nil && len(entries) > 0 {
		t.Fatalf("expected remote operator healthcheck TLS staged helper directory to be cleaned, found %d entries", len(entries))
	}
}

type fakeRemoteAlphaWorkloadAuthBootstrapHarness struct {
	localBin    string
	remoteBin   string
	remoteRoot  string
	sshLogPath  string
	scpLogPath  string
	rmLogPath   string
	sudoLogPath string
	spireLog    string
	helperLog   string
}

func setupFakeRemoteAlphaWorkloadAuthBootstrapHarness(t *testing.T) *fakeRemoteAlphaWorkloadAuthBootstrapHarness {
	t.Helper()

	tmpDir := t.TempDir()
	remoteRoot, err := os.MkdirTemp("/tmp", "es-ra-bootstrap-")
	if err != nil {
		t.Fatalf("mkdir short fake remote root: %v", err)
	}
	t.Cleanup(func() {
		_ = os.RemoveAll(remoteRoot)
	})
	h := &fakeRemoteAlphaWorkloadAuthBootstrapHarness{
		localBin:    filepath.Join(tmpDir, "local-bin"),
		remoteBin:   filepath.Join(tmpDir, "remote-bin"),
		remoteRoot:  remoteRoot,
		sshLogPath:  filepath.Join(tmpDir, "ssh.log"),
		scpLogPath:  filepath.Join(tmpDir, "scp.log"),
		rmLogPath:   filepath.Join(tmpDir, "rm.log"),
		sudoLogPath: filepath.Join(tmpDir, "sudo.log"),
		spireLog:    filepath.Join(tmpDir, "spire.log"),
		helperLog:   filepath.Join(tmpDir, "helper.log"),
	}
	for _, dir := range []string{h.localBin, h.remoteBin, h.remoteRoot} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", dir, err)
		}
	}

	writeExecutable(t, h.localBin, "ssh", fmt.Sprintf(`#!/usr/bin/env bash
set -euo pipefail
tty=false
while [[ "${1:-}" == "-tt" ]]; do
  tty=true
  shift
done
target="${1:-}"
shift || true
printf 'tty=%%s target=%%s args=%%s\n' "${tty}" "${target}" "$*" >> %q
export PATH="${FAKE_REMOTE_BIN}:${PATH}"
command_joined="$*"
if [[ "${command_joined}" == *"summary_path_prepare_status=pass"* ]]; then
  command_string="${command_joined}"
  summary_prefix="/var/tmp/execution-substrate-remote-alpha"
  mapped_command="${command_string//${summary_prefix}/${FAKE_REMOTE_ROOT}${summary_prefix}}"
  exec /bin/bash -c "${mapped_command}"
fi
if [[ "${command_joined}" == *"config_readability_prepare_status=pass"* ]]; then
  command_string="${command_joined}"
  config_prefix="/etc/execution-substrate"
  mapped_command="${command_string//${config_prefix}/${FAKE_REMOTE_ROOT}${config_prefix}}"
  exec /bin/bash -c "${mapped_command}"
fi
if [[ "${command_joined}" == *"spire_bundle_read_prepare_status=pass"* ]]; then
  command_string="${command_joined}"
  spire_prefix="/run/spire"
  mapped_command="${command_string//${spire_prefix}/${FAKE_REMOTE_ROOT}${spire_prefix}}"
  exec /bin/bash -c "${mapped_command}"
fi
if [[ "${1:-}" == "/bin/bash" && "${2:-}" == "-s" ]]; then
  shift 2
  if [[ "${1:-}" == "--" ]]; then
    shift
  fi
  mapped_args=()
  for arg in "$@"; do
    if [[ "${arg}" == /* ]]; then
      mapped_args+=("${FAKE_REMOTE_ROOT}${arg}")
    else
      mapped_args+=("${arg}")
    fi
  done
  payload="$(mktemp)"
  cat >"${payload}"
  set +e
  /bin/bash "${payload}" "${mapped_args[@]}"
  status=$?
  set -e
  rm -f -- "${payload}"
  exit "${status}"
fi
if [[ "$#" -eq 1 && "${1:-}" == exec\ /bin/bash\ -c* ]]; then
  command_string="${1}"
  bootstrap_prefix="/tmp/execution-substrate-remote-alpha-vault-workload-auth-bootstrap"
  mapped_command="${command_string//${bootstrap_prefix}/${FAKE_REMOTE_ROOT}${bootstrap_prefix}}"
  exec /bin/bash -c "${mapped_command}"
fi
echo "unexpected fake ssh invocation: $*" >&2
exit 64
`, h.sshLogPath))

	writeExecutable(t, h.localBin, "scp", fmt.Sprintf(`#!/usr/bin/env bash
set -euo pipefail
if [[ "$#" -ne 2 ]]; then
  echo "unexpected fake scp args: $*" >&2
  exit 64
fi
src=$1
dest=$2
printf '%%s\t%%s\n' "${src}" "${dest}" >> %q
if [[ "${src}" == *:* || "${dest}" != *:* ]]; then
  echo "fake scp supports one local-to-remote upload" >&2
  exit 64
fi
remote_path="${dest#*:}"
mapped_dest="${FAKE_REMOTE_ROOT}${remote_path}"
mkdir -p -- "$(dirname "${mapped_dest}")"
if [[ "${src}" == */scripts/internal/remote_alpha_vault_workload_auth_bootstrap.sh ]]; then
  cat >"${mapped_dest}" <<'REMOTE_ALPHA_FAKE_BOOTSTRAP_INTERNAL'
# fake internal bootstrap helper staged for layout verification
REMOTE_ALPHA_FAKE_BOOTSTRAP_INTERNAL
elif [[ "$(basename "${src}")" == "remote_alpha_vault_workload_auth_bootstrap.sh" ]]; then
  cat >"${mapped_dest}" <<'REMOTE_ALPHA_FAKE_BOOTSTRAP_PUBLIC'
#!/usr/bin/env bash
set -euo pipefail
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
internal="${script_dir}/internal/remote_alpha_vault_workload_auth_bootstrap.sh"
if [[ ! -f "${internal}" ]]; then
  echo "missing internal helper: ${internal}" >&2
  exit 65
fi
printf 'public_args=%%s\n' "$*" >> %q
printf 'internal=%%s\n' "${internal}" >> %q
printf 'Remote Alpha Vault workload-auth bootstrap helper finished.\n'
printf 'Remote summary path: /var/tmp/execution-substrate-remote-alpha/vault-workload-auth-bootstrap-summary.json\n'
printf 'Workload-auth check, reset/unseal, IM refresh, support-bundle collection, CP proof, and runtime identity generation were not run.\n'
printf 'Non-claims: not workload-auth success, not ES Vault token brokerage.\n'
REMOTE_ALPHA_FAKE_BOOTSTRAP_PUBLIC
else
  echo "unexpected fake scp source: ${src}" >&2
  exit 64
fi
chmod 0700 "${mapped_dest}"
`, h.scpLogPath, h.helperLog, h.helperLog))

	writeExecutable(t, h.remoteBin, "rm", fmt.Sprintf(`#!/usr/bin/env bash
set -euo pipefail
printf '%%s\n' "$*" >> %q
exec /bin/rm "$@"
	`, h.rmLogPath))

	writeExecutable(t, h.remoteBin, "setfacl", `#!/usr/bin/env bash
set -euo pipefail
exit 0
`)

	writeExecutable(t, h.remoteBin, "systemctl", `#!/usr/bin/env bash
set -euo pipefail
if [[ "$#" -eq 3 && "${1:-}" == "is-active" && "${2:-}" == "--quiet" && "${3:-}" == "spire-server" ]]; then
  exit "${REMOTE_ALPHA_FAKE_SYSTEMCTL_SPIRE_ACTIVE_STATUS:-0}"
fi
echo "unexpected fake systemctl args: $*" >&2
exit 64
`)

	writeExecutable(t, h.remoteBin, "spire-server", fmt.Sprintf(`#!/usr/bin/env bash
set -euo pipefail
printf 'args=%%s\n' "$*" >> %q
if [[ "$#" -ne 6 || "${1:-}" != "bundle" || "${2:-}" != "show" || "${3:-}" != "-format" || "${4:-}" != "spiffe" || "${5:-}" != "-socketPath" ]]; then
  echo "unexpected fake spire-server args: $*" >&2
  exit 64
fi
socket_path="${6:-}"
if [[ "${REMOTE_ALPHA_FAKE_SPIRE_SERVER_FORCE_FAIL:-false}" == "true" ]]; then
  echo "raw fake SPIRE stderr must not print" >&2
  exit 17
fi
if [[ ! -S "${socket_path}" || ! -r "${socket_path}" || ! -w "${socket_path}" ]]; then
  exit 13
fi
cat <<'JSON'
{"keys":[{"kty":"RSA","use":"jwt-svid","n":"FAKE-SPIRE-BUNDLE-MATERIAL-MUST-NOT-PRINT","e":"AQAB"}]}
JSON
`, h.spireLog))

	writeExecutable(t, h.remoteBin, "sudo", fmt.Sprintf(`#!/usr/bin/env bash
set -euo pipefail
printf '%%s\n' "$*" >> %q
cmd="${1:-}"
shift || true
if [[ "${cmd}" == "-n" ]]; then
  cmd="${1:-}"
  shift || true
fi
case "${cmd}" in
  -v)
    ;;
  install)
    mode=""
    dir=""
    while [[ "$#" -gt 0 ]]; do
      case "$1" in
        -d)
          shift
          ;;
        -m)
          mode="$2"
          shift 2
          ;;
        -o|-g)
          shift 2
          ;;
        --)
          shift
          dir="$1"
          shift
          ;;
        -*)
          echo "unexpected fake sudo install arg: $1" >&2
          exit 64
          ;;
        *)
          dir="$1"
          shift
          ;;
      esac
    done
    if [[ -z "${dir}" ]]; then
      echo "fake sudo install missing directory" >&2
      exit 64
    fi
    mkdir -p -- "${dir}"
    if [[ -n "${mode}" ]]; then
      chmod "${mode}" "${dir}"
    fi
    ;;
  chown)
    while [[ "$#" -gt 0 && "${1:-}" != "--" ]]; do
      shift
    done
    if [[ "${1:-}" == "--" ]]; then
      shift
    fi
    ;;
	  chmod)
	    mode="${1:-}"
	    shift || true
	    if [[ "${1:-}" == "--" ]]; then
	      shift
	    fi
	    exec /bin/chmod "${mode}" "$@"
	    ;;
	  test)
	    predicate="${1:-}"
	    path="${2:-}"
	    restore_path=""
	    restore_mode=""
	    if [[ -n "${FAKE_REMOTE_ROOT:-}" && "${path}" == "${FAKE_REMOTE_ROOT}/run/spire/server/"* ]]; then
	      server_dir="${FAKE_REMOTE_ROOT}/run/spire/server"
	      if [[ -d "${server_dir}" && ! -x "${server_dir}" ]]; then
	        restore_path="${server_dir}"
	        restore_mode="$(stat -f '%%Lp' "${server_dir}" 2>/dev/null || stat -c '%%a' "${server_dir}")"
	        /bin/chmod u+x "${server_dir}"
	      fi
	    fi
	    set +e
	    /bin/test "${predicate}" "${path}"
	    status=$?
	    set -e
	    if [[ -n "${restore_path}" ]]; then
	      /bin/chmod "${restore_mode}" "${restore_path}"
	    fi
	    exit "${status}"
	    ;;
	  setfacl)
	    acl_spec=""
	    path=""
	    while [[ "$#" -gt 0 ]]; do
	      case "$1" in
	        -m)
	          acl_spec="$2"
	          shift 2
	          ;;
	        --)
	          shift
	          path="$1"
	          shift
	          ;;
	        -*)
	          echo "unexpected fake sudo setfacl arg: $1" >&2
	          exit 64
	          ;;
	        *)
	          path="$1"
	          shift
	          ;;
	      esac
	    done
	    if [[ -z "${path}" ]]; then
	      echo "fake sudo setfacl missing path" >&2
	      exit 64
	    fi
	    case "${acl_spec}" in
	      u:*:--x)
	        /bin/chmod u+x "${path}"
	        ;;
	      u:*:r--)
	        /bin/chmod u+r "${path}"
	        ;;
	      u:*:rw-)
	        /bin/chmod u+rw "${path}"
	        ;;
	      *)
	        echo "unexpected fake sudo setfacl acl: ${acl_spec}" >&2
	        exit 64
	        ;;
	    esac
	    ;;
	  *)
	    echo "unexpected fake sudo command: ${cmd}" >&2
	    exit 64
    ;;
esac
`, h.sudoLogPath))

	return h
}

func (h *fakeRemoteAlphaWorkloadAuthBootstrapHarness) env() []string {
	return envWithPath(h.localBin,
		"FAKE_REMOTE_BIN="+h.remoteBin,
		"FAKE_REMOTE_ROOT="+h.remoteRoot,
	)
}

func createFakeBootstrapSpireSocket(t *testing.T, h *fakeRemoteAlphaWorkloadAuthBootstrapHarness, mode os.FileMode) string {
	t.Helper()
	socketPath := filepath.Join(h.remoteRoot, "run", "spire", "server", "private", "api.sock")
	if err := os.MkdirAll(filepath.Dir(socketPath), 0o755); err != nil {
		t.Fatalf("mkdir fake SPIRE socket parent: %v", err)
	}
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listen on fake SPIRE socket: %v", err)
	}
	t.Cleanup(func() {
		_ = listener.Close()
		_ = os.Remove(socketPath)
	})
	if err := os.Chmod(socketPath, mode); err != nil {
		t.Fatalf("chmod fake SPIRE socket: %v", err)
	}
	return socketPath
}

func TestRemoteAlphaOperatorRecoverySessionVaultWorkloadAuthBootstrapNoTTYFailsBeforeStaging(t *testing.T) {
	h := setupFakeRemoteAlphaWorkloadAuthBootstrapHarness(t)
	output, err := runRemoteAlphaOperatorWithEnv(h.env(),
		"recovery-session", "vault-workload-auth-bootstrap",
		"--ssh-target", "ds@m75q-test",
		"--execute-bootstrap",
		"--interactive-tty",
	)
	if err == nil {
		t.Fatalf("expected no-TTY failure before workload-auth bootstrap staging, got success:\n%s", output)
	}
	assertContainsAll(t, "vault-workload-auth-bootstrap no tty refusal", output,
		"requires visible local terminal",
		"no staging or SSH occurred",
		"No recovery-session live helper or IM execution occurred.",
	)
	if _, err := os.Stat(h.sshLogPath); !os.IsNotExist(err) {
		t.Fatalf("ssh should not run when workload-auth bootstrap local TTY guard fails: %v", err)
	}
	if _, err := os.Stat(h.scpLogPath); !os.IsNotExist(err) {
		t.Fatalf("scp should not run when workload-auth bootstrap local TTY guard fails: %v", err)
	}
}

func TestRemoteAlphaOperatorRecoverySessionVaultWorkloadAuthBootstrapPrepareSummaryPathUsesBoundedRemoteCommand(t *testing.T) {
	h := setupFakeRemoteAlphaWorkloadAuthBootstrapHarness(t)
	before := snapshotPathExistence(t, remoteAlphaOperatorRouteArtifactPaths(filepath.Join(".out", "remote-alpha-m75q", "vault-workload-auth-bootstrap-summary.json"))...)

	summaryParent := filepath.Join(h.remoteRoot, "var", "tmp", "execution-substrate-remote-alpha")
	if err := os.MkdirAll(summaryParent, 0o755); err != nil {
		t.Fatalf("mkdir summary parent: %v", err)
	}
	if err := os.Chmod(summaryParent, 0o555); err != nil {
		t.Fatalf("chmod summary parent: %v", err)
	}

	output, err := runRemoteAlphaOperatorWithPTY(t, h.env(),
		"recovery-session", "vault-workload-auth-bootstrap",
		"--ssh-target", "ds@m75q-test",
		"--prepare-summary-path",
		"--interactive-tty",
	)
	if err != nil {
		t.Fatalf("Mac-side fake workload-auth bootstrap prepare route failed: %v\noutput=%s\nssh=%s\nsudo=%s\nscp=%s\nhelper=%s\nrm=%s",
			err, output, readIfExists(h.sshLogPath), readIfExists(h.sudoLogPath), readIfExists(h.scpLogPath), readIfExists(h.helperLog), readIfExists(h.rmLogPath))
	}

	assertContainsAll(t, "Mac-side fake workload-auth bootstrap prepare output", output,
		"Preparing Remote Alpha Vault workload-auth bootstrap summary path through an explicit interactive SSH TTY.",
		"OS/filesystem preparation only",
		"may request only an OS sudo password",
		"summary_path_prepare_status=pass",
		"summary_parent_policy=owner_writable_0750_when_sudo_needed",
		"summary_file_policy=existing_regular_file_owner_writable_0600_when_sudo_needed",
		"final_summary_created=false",
		"vault_run=false",
		"workload_auth_check_run=false",
		"reset_unseal_im_support_bundle_cp_runtime_identity_run=false",
	)
	assertContainsNone(t, "Mac-side fake workload-auth bootstrap prepare output forbidden surfaces", output,
		"Running Mac-side Vault workload-auth bootstrap through an explicit interactive SSH TTY.",
		"Remote Alpha Vault workload-auth bootstrap helper finished.",
		"root-token-for-fake-bootstrap",
		"proof-value-for-fake-bootstrap",
		"remote-alpha-live-refresh",
		"remote-alpha-live-support-bundle",
		"cp-proof",
		"runtime identity generation was run",
	)

	sshLog := mustRead(t, h.sshLogPath)
	if got := strings.Count(sshLog, "tty=true"); got != 1 {
		t.Fatalf("expected exactly one interactive ssh -tt invocation for prepare, got %d log=%q", got, sshLog)
	}
	assertContainsAll(t, "fake workload-auth bootstrap prepare ssh log", sshLog,
		"tty=true target=ds@m75q-test",
		"/bin/bash -c",
		"vault-workload-auth-bootstrap-summary.json",
	)
	assertContainsNone(t, "fake workload-auth bootstrap prepare ssh log forbidden capture", sshLog,
		"/bin/bash -s -- /var/tmp/execution-substrate-remote-alpha",
		"exec /bin/bash -c",
		"execution-substrate-remote-alpha-vault-workload-auth-bootstrap",
		" tee ",
		"script ",
		"transcript",
		"remote-alpha-live-refresh",
		"remote-alpha-live-support-bundle",
		"cp-proof",
		".out",
	)

	sudoLog := mustRead(t, h.sudoLogPath)
	assertContainsAll(t, "fake workload-auth bootstrap prepare sudo log", sudoLog,
		"-v -p Remote Alpha OS sudo password for summary path preparation: ",
		"-n install -d -m 0750",
		"execution-substrate-remote-alpha",
	)
	assertContainsNone(t, "fake workload-auth bootstrap prepare sudo log forbidden surfaces", sudoLog,
		"vault",
		"remote_alpha_vault_workload_auth_bootstrap.sh",
		"remote_alpha_vault_workload_auth_check.sh",
		"remote_alpha_reset_disposable_vault.sh",
		"tee ",
		"script ",
	)
	if _, err := os.Stat(h.scpLogPath); !os.IsNotExist(err) {
		t.Fatalf("scp should not run for prepare-summary-path-only route: %v log=%s", err, readIfExists(h.scpLogPath))
	}
	if _, err := os.Stat(h.helperLog); !os.IsNotExist(err) {
		t.Fatalf("bootstrap helper should not run for prepare-summary-path-only route: %v log=%s", err, readIfExists(h.helperLog))
	}
	rmLog := readIfExists(h.rmLogPath)
	assertContainsAll(t, "fake workload-auth bootstrap prepare rm log", rmLog,
		".vault-workload-auth-bootstrap-summary.prepare.",
	)
	assertContainsNone(t, "fake workload-auth bootstrap prepare rm log forbidden staging cleanup", rmLog,
		"execution-substrate-remote-alpha-vault-workload-auth-bootstrap",
		"remote_alpha_vault_workload_auth_bootstrap.sh",
	)
	if _, err := os.Stat(filepath.Join(summaryParent, "vault-workload-auth-bootstrap-summary.json")); !os.IsNotExist(err) {
		t.Fatalf("prepare-summary-path-only route should not create final summary: %v", err)
	}
	matches, err := filepath.Glob(filepath.Join(summaryParent, ".vault-workload-auth-bootstrap-summary.prepare.*"))
	if err != nil {
		t.Fatalf("glob prepare temp: %v", err)
	}
	if len(matches) != 0 {
		t.Fatalf("prepare-summary-path-only route left temp summary probes: %v", matches)
	}
	assertNoNewPaths(t, "Mac-side fake workload-auth bootstrap prepare route", before)
}

func TestRemoteAlphaOperatorRecoverySessionVaultWorkloadAuthBootstrapPrepareConfigReadabilityUsesBoundedRemoteCommand(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("fake unreadable config preparation requires a non-root test process")
	}

	h := setupFakeRemoteAlphaWorkloadAuthBootstrapHarness(t)
	before := snapshotPathExistence(t, remoteAlphaOperatorRouteArtifactPaths(filepath.Join(".out", "remote-alpha-m75q", "vault-workload-auth-bootstrap-summary.json"))...)

	configPath := filepath.Join(h.remoteRoot, "etc", "execution-substrate", "vault", "workload-zone-vault-config.json")
	if err := os.MkdirAll(filepath.Dir(configPath), 0o755); err != nil {
		t.Fatalf("mkdir config parent: %v", err)
	}
	const configContentSentinel = "config-content-sentinel"
	if err := os.WriteFile(configPath, []byte(`{"vault_config":{"address":"https://example.invalid","note":"`+configContentSentinel+`"}}`), 0o600); err != nil {
		t.Fatalf("write config fixture: %v", err)
	}
	if err := os.Chmod(configPath, 0o000); err != nil {
		t.Fatalf("chmod unreadable config fixture: %v", err)
	}
	if err := os.Chmod(filepath.Dir(configPath), 0o600); err != nil {
		t.Fatalf("chmod config parent fixture: %v", err)
	}
	t.Cleanup(func() {
		_ = os.Chmod(filepath.Dir(configPath), 0o700)
		_ = os.Chmod(configPath, 0o600)
	})

	output, err := runRemoteAlphaOperatorWithPTY(t, h.env(),
		"recovery-session", "vault-workload-auth-bootstrap",
		"--ssh-target", "ds@m75q-test",
		"--prepare-config-readability",
		"--interactive-tty",
	)
	if err != nil {
		t.Fatalf("Mac-side fake workload-auth bootstrap config prepare route failed: %v\noutput=%s\nssh=%s\nsudo=%s\nscp=%s\nhelper=%s\nrm=%s",
			err, output, readIfExists(h.sshLogPath), readIfExists(h.sudoLogPath), readIfExists(h.scpLogPath), readIfExists(h.helperLog), readIfExists(h.rmLogPath))
	}

	assertContainsAll(t, "Mac-side fake workload-auth bootstrap config prepare output", output,
		"Preparing Remote Alpha Vault workload-auth bootstrap config readability through an explicit interactive SSH TTY.",
		"OS/filesystem preparation only",
		"may request only an OS sudo password",
		"fixed-path user ACLs",
		"config_readability_prepare_status=pass",
		"workload-zone-vault-config.json",
		"config_readability_policy=fixed_path_user_acl_when_needed",
		"config_acl_applied=true",
		"config_contents_printed=false",
		"vault_run=false",
		"workload_auth_check_run=false",
		"reset_unseal_im_support_bundle_cp_runtime_identity_run=false",
	)
	assertContainsNone(t, "Mac-side fake workload-auth bootstrap config prepare output forbidden surfaces", output,
		configContentSentinel,
		"Running Mac-side Vault workload-auth bootstrap through an explicit interactive SSH TTY.",
		"Remote Alpha Vault workload-auth bootstrap helper finished.",
		"root-token-for-fake-bootstrap",
		"proof-value-for-fake-bootstrap",
		"remote-alpha-live-refresh",
		"remote-alpha-live-support-bundle",
		"cp-proof",
		"runtime identity generation was run",
	)

	sshLog := mustRead(t, h.sshLogPath)
	if got := strings.Count(sshLog, "tty=true"); got != 1 {
		t.Fatalf("expected exactly one interactive ssh -tt invocation for config prepare, got %d log=%q", got, sshLog)
	}
	assertContainsAll(t, "fake workload-auth bootstrap config prepare ssh log", sshLog,
		"tty=true target=ds@m75q-test",
		"/bin/bash -c",
		"workload-zone-vault-config.json",
	)
	assertContainsNone(t, "fake workload-auth bootstrap config prepare ssh log forbidden capture", sshLog,
		configContentSentinel,
		"/bin/bash -s -- /var/tmp/execution-substrate-remote-alpha",
		"exec /bin/bash -c",
		"execution-substrate-remote-alpha-vault-workload-auth-bootstrap",
		" tee ",
		"script ",
		"transcript",
		".out",
	)

	sudoLog := mustRead(t, h.sudoLogPath)
	assertContainsAll(t, "fake workload-auth bootstrap config prepare sudo log", sudoLog,
		"-v -p Remote Alpha OS sudo password for config readability preparation: ",
		"-n setfacl -m u:",
		":--x --",
		":r-- --",
		"workload-zone-vault-config.json",
	)
	assertContainsNone(t, "fake workload-auth bootstrap config prepare sudo log forbidden surfaces", sudoLog,
		configContentSentinel,
		"remote_alpha_vault_workload_auth_bootstrap.sh",
		"remote_alpha_vault_workload_auth_check.sh",
		"remote_alpha_reset_disposable_vault.sh",
		"chmod 777",
		"chown",
		"tee ",
		"script ",
	)
	if _, err := os.Stat(h.scpLogPath); !os.IsNotExist(err) {
		t.Fatalf("scp should not run for prepare-config-readability-only route: %v log=%s", err, readIfExists(h.scpLogPath))
	}
	if _, err := os.Stat(h.helperLog); !os.IsNotExist(err) {
		t.Fatalf("bootstrap helper should not run for prepare-config-readability-only route: %v log=%s", err, readIfExists(h.helperLog))
	}
	if rmLog := readIfExists(h.rmLogPath); rmLog != "" && rmLog != "<missing>" {
		t.Fatalf("prepare-config-readability-only route should not delete summaries or staging paths: %s", rmLog)
	}
	assertNoNewPaths(t, "Mac-side fake workload-auth bootstrap config prepare route", before)
}

func TestRemoteAlphaOperatorRecoverySessionVaultWorkloadAuthBootstrapPrepareSpireBundleReadUsesBoundedRemoteCommand(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("fake SPIRE socket ACL preparation requires a non-root test process")
	}

	h := setupFakeRemoteAlphaWorkloadAuthBootstrapHarness(t)
	before := snapshotPathExistence(t, remoteAlphaOperatorRouteArtifactPaths(filepath.Join(".out", "remote-alpha-m75q", "vault-workload-auth-bootstrap-summary.json"))...)

	socketPath := createFakeBootstrapSpireSocket(t, h, 0o000)
	if err := os.Chmod(filepath.Dir(socketPath), 0o700); err != nil {
		t.Fatalf("chmod fake SPIRE socket parent: %v", err)
	}
	t.Cleanup(func() {
		_ = os.Chmod(filepath.Dir(socketPath), 0o700)
		_ = os.Chmod(socketPath, 0o600)
	})

	output, err := runRemoteAlphaOperatorWithPTY(t, h.env(),
		"recovery-session", "vault-workload-auth-bootstrap",
		"--ssh-target", "ds@m75q-test",
		"--prepare-spire-bundle-read",
		"--interactive-tty",
	)
	if err != nil {
		t.Fatalf("Mac-side fake workload-auth bootstrap SPIRE prepare route failed: %v\noutput=%s\nssh=%s\nsudo=%s\nspire=%s\nscp=%s\nhelper=%s\nrm=%s",
			err, output, readIfExists(h.sshLogPath), readIfExists(h.sudoLogPath), readIfExists(h.spireLog), readIfExists(h.scpLogPath), readIfExists(h.helperLog), readIfExists(h.rmLogPath))
	}

	assertContainsAll(t, "Mac-side fake workload-auth bootstrap SPIRE prepare output", output,
		"Preparing Remote Alpha Vault workload-auth bootstrap SPIRE bundle-read access through an explicit interactive SSH TTY.",
		"OS/filesystem/capability preparation only",
		"may request only an OS sudo password",
		"fixed-path user ACLs",
		"spire_bundle_read_prepare_status=pass",
		"api.sock",
		"spire_bundle_read_policy=fixed_path_user_acl_when_needed",
		"spire_socket_access_classification=spire_socket_present_needs_acl",
		"spire_socket_acl_applied=true",
		"bundle_output_discarded=true",
		"bundle_contents_printed=false",
		"vault_run=false",
		"workload_auth_check_run=false",
		"reset_unseal_im_support_bundle_cp_runtime_identity_run=false",
	)
	assertContainsNone(t, "Mac-side fake workload-auth bootstrap SPIRE prepare output forbidden surfaces", output,
		"FAKE-SPIRE-BUNDLE-MATERIAL-MUST-NOT-PRINT",
		"Running Mac-side Vault workload-auth bootstrap through an explicit interactive SSH TTY.",
		"Remote Alpha Vault workload-auth bootstrap helper finished.",
		"root-token-for-fake-bootstrap",
		"proof-value-for-fake-bootstrap",
		"remote-alpha-live-refresh",
		"remote-alpha-live-support-bundle",
		"cp-proof",
		"runtime identity generation was run",
	)

	sshLog := mustRead(t, h.sshLogPath)
	if got := strings.Count(sshLog, "tty=true"); got != 1 {
		t.Fatalf("expected exactly one interactive ssh -tt invocation for SPIRE prepare, got %d log=%q", got, sshLog)
	}
	assertContainsAll(t, "fake workload-auth bootstrap SPIRE prepare ssh log", sshLog,
		"tty=true target=ds@m75q-test",
		"/bin/bash -c",
		"/run/spire/server/private/api.sock",
		"spire_bundle_read_prepare_status=pass",
	)
	assertContainsNone(t, "fake workload-auth bootstrap SPIRE prepare ssh log forbidden capture", sshLog,
		"FAKE-SPIRE-BUNDLE-MATERIAL-MUST-NOT-PRINT",
		"/bin/bash -s -- /var/tmp/execution-substrate-remote-alpha",
		"exec /bin/bash -c",
		"execution-substrate-remote-alpha-vault-workload-auth-bootstrap",
		" tee ",
		"script ",
		"transcript",
		".out",
	)

	sudoLog := mustRead(t, h.sudoLogPath)
	assertContainsAll(t, "fake workload-auth bootstrap SPIRE prepare sudo log", sudoLog,
		"-v -p Remote Alpha OS sudo password for SPIRE bundle-read preparation: ",
		"-n setfacl -m u:",
		":rw- --",
		"api.sock",
	)
	assertContainsNone(t, "fake workload-auth bootstrap SPIRE prepare sudo log forbidden surfaces", sudoLog,
		"FAKE-SPIRE-BUNDLE-MATERIAL-MUST-NOT-PRINT",
		"remote_alpha_vault_workload_auth_bootstrap.sh",
		"remote_alpha_vault_workload_auth_check.sh",
		"remote_alpha_reset_disposable_vault.sh",
		"chmod 777",
		"chown",
		"tee ",
		"script ",
	)
	spireLog := mustRead(t, h.spireLog)
	assertContainsAll(t, "fake workload-auth bootstrap SPIRE command log", spireLog,
		"bundle show -format spiffe -socketPath",
		"api.sock",
	)
	if _, err := os.Stat(h.scpLogPath); !os.IsNotExist(err) {
		t.Fatalf("scp should not run for prepare-spire-bundle-read-only route: %v log=%s", err, readIfExists(h.scpLogPath))
	}
	if _, err := os.Stat(h.helperLog); !os.IsNotExist(err) {
		t.Fatalf("bootstrap helper should not run for prepare-spire-bundle-read-only route: %v log=%s", err, readIfExists(h.helperLog))
	}
	if rmLog := readIfExists(h.rmLogPath); rmLog != "" && rmLog != "<missing>" {
		t.Fatalf("prepare-spire-bundle-read-only route should not delete summaries or staging paths: %s", rmLog)
	}
	assertNoNewPaths(t, "Mac-side fake workload-auth bootstrap SPIRE prepare route", before)
}

func TestRemoteAlphaOperatorRecoverySessionVaultWorkloadAuthBootstrapPrepareSpireBundleReadClassifiesTraversalAmbiguityWithSudoVisibleInspection(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("fake no-sudo traversal ambiguity requires a non-root test process")
	}

	h := setupFakeRemoteAlphaWorkloadAuthBootstrapHarness(t)
	socketPath := createFakeBootstrapSpireSocket(t, h, 0o600)
	spireServerDir := filepath.Dir(filepath.Dir(socketPath))
	if err := os.Chmod(spireServerDir, 0o000); err != nil {
		t.Fatalf("chmod fake SPIRE server dir: %v", err)
	}
	t.Cleanup(func() {
		_ = os.Chmod(spireServerDir, 0o700)
		_ = os.Chmod(socketPath, 0o600)
	})

	output, err := runRemoteAlphaOperatorWithPTY(t, h.env(),
		"recovery-session", "vault-workload-auth-bootstrap",
		"--ssh-target", "ds@m75q-test",
		"--prepare-spire-bundle-read",
		"--interactive-tty",
	)
	if err != nil {
		t.Fatalf("expected sudo-visible SPIRE path inspection to disambiguate traversal denial: %v\noutput=%s\nsudo=%s\nspire=%s",
			err, output, readIfExists(h.sudoLogPath), readIfExists(h.spireLog))
	}

	assertContainsAll(t, "SPIRE traversal ambiguity prepare output", output,
		"spire_bundle_read_prepare_status=pass",
		"spire_socket_access_classification=spire_socket_present_needs_acl",
		"spire_socket_acl_applied=true",
		"bundle_contents_printed=false",
		"vault_run=false",
		"workload_auth_check_run=false",
		"reset_unseal_im_support_bundle_cp_runtime_identity_run=false",
	)
	assertContainsNone(t, "SPIRE traversal ambiguity output forbidden classifications", output,
		"spire_socket_parent_missing",
		"FAKE-SPIRE-BUNDLE-MATERIAL-MUST-NOT-PRINT",
		"raw fake SPIRE stderr",
	)

	sudoLog := mustRead(t, h.sudoLogPath)
	assertContainsAll(t, "SPIRE traversal ambiguity sudo log", sudoLog,
		"-n test -d",
		"-n test -S",
		"-n setfacl -m u:",
		":--x --",
		"run/spire/server",
	)
	assertContainsNone(t, "SPIRE traversal ambiguity sudo log forbidden broad changes", sudoLog,
		"chmod 777",
		"chown",
		" o:",
		"g:",
		"workload-zone-vault-config.json",
		"remote_alpha_vault_workload_auth_bootstrap.sh",
	)
}

func TestRemoteAlphaOperatorRecoverySessionVaultWorkloadAuthBootstrapPrepareSpireBundleReadFailsForTrueMissingParentUnderSudoVisibleInspection(t *testing.T) {
	h := setupFakeRemoteAlphaWorkloadAuthBootstrapHarness(t)
	spireServerDir := filepath.Join(h.remoteRoot, "run", "spire", "server")
	if err := os.MkdirAll(spireServerDir, 0o755); err != nil {
		t.Fatalf("mkdir fake SPIRE server dir: %v", err)
	}

	output, err := runRemoteAlphaOperatorWithPTY(t, h.env(),
		"recovery-session", "vault-workload-auth-bootstrap",
		"--ssh-target", "ds@m75q-test",
		"--prepare-spire-bundle-read",
		"--interactive-tty",
	)
	if err == nil {
		t.Fatalf("expected missing SPIRE socket parent failure:\n%s", output)
	}

	assertContainsAll(t, "missing SPIRE parent prepare output", output,
		"spire_bundle_read_prepare_status=fail",
		"error_classification=spire_socket_parent_missing",
		"spire_server_socket_path=",
		"bundle_contents_printed=false",
		"vault_run=false",
		"workload_auth_check_run=false",
		"reset_unseal_im_support_bundle_cp_runtime_identity_run=false",
	)
	assertContainsNone(t, "missing SPIRE parent output forbidden", output,
		"FAKE-SPIRE-BUNDLE-MATERIAL-MUST-NOT-PRINT",
		"Remote Alpha Vault workload-auth bootstrap helper finished.",
	)
	if _, statErr := os.Stat(filepath.Join(spireServerDir, "private")); !os.IsNotExist(statErr) {
		t.Fatalf("SPIRE prep must not create missing parent, stat err=%v", statErr)
	}
	sudoLog := mustRead(t, h.sudoLogPath)
	assertContainsNone(t, "missing SPIRE parent sudo log forbidden ACL", sudoLog,
		"setfacl",
		"chmod 777",
		"chown",
	)
}

func TestRemoteAlphaOperatorRecoverySessionVaultWorkloadAuthBootstrapPrepareSpireBundleReadFailsForTrueMissingSocketUnderSudoVisibleInspection(t *testing.T) {
	h := setupFakeRemoteAlphaWorkloadAuthBootstrapHarness(t)
	spireParent := filepath.Join(h.remoteRoot, "run", "spire", "server", "private")
	if err := os.MkdirAll(spireParent, 0o755); err != nil {
		t.Fatalf("mkdir fake SPIRE socket parent: %v", err)
	}

	output, err := runRemoteAlphaOperatorWithPTY(t, h.env(),
		"recovery-session", "vault-workload-auth-bootstrap",
		"--ssh-target", "ds@m75q-test",
		"--prepare-spire-bundle-read",
		"--interactive-tty",
	)
	if err == nil {
		t.Fatalf("expected missing SPIRE socket failure:\n%s", output)
	}

	assertContainsAll(t, "missing SPIRE socket prepare output", output,
		"spire_bundle_read_prepare_status=fail",
		"error_classification=spire_socket_missing",
		"bundle_contents_printed=false",
		"vault_run=false",
		"workload_auth_check_run=false",
		"reset_unseal_im_support_bundle_cp_runtime_identity_run=false",
	)
	if _, statErr := os.Stat(filepath.Join(spireParent, "api.sock")); !os.IsNotExist(statErr) {
		t.Fatalf("SPIRE prep must not create missing socket, stat err=%v", statErr)
	}
	sudoLog := mustRead(t, h.sudoLogPath)
	assertContainsNone(t, "missing SPIRE socket sudo log forbidden ACL", sudoLog,
		"setfacl",
		"chmod 777",
		"chown",
	)
}

func TestRemoteAlphaOperatorRecoverySessionVaultWorkloadAuthBootstrapPrepareSpireBundleReadFailsForWrongSocketType(t *testing.T) {
	h := setupFakeRemoteAlphaWorkloadAuthBootstrapHarness(t)
	socketPath := filepath.Join(h.remoteRoot, "run", "spire", "server", "private", "api.sock")
	if err := os.MkdirAll(filepath.Dir(socketPath), 0o755); err != nil {
		t.Fatalf("mkdir fake SPIRE socket parent: %v", err)
	}
	if err := os.WriteFile(socketPath, []byte("not a socket"), 0o600); err != nil {
		t.Fatalf("write wrong-type SPIRE path fixture: %v", err)
	}

	output, err := runRemoteAlphaOperatorWithPTY(t, h.env(),
		"recovery-session", "vault-workload-auth-bootstrap",
		"--ssh-target", "ds@m75q-test",
		"--prepare-spire-bundle-read",
		"--interactive-tty",
	)
	if err == nil {
		t.Fatalf("expected wrong-type SPIRE socket failure:\n%s", output)
	}

	assertContainsAll(t, "wrong-type SPIRE socket prepare output", output,
		"spire_bundle_read_prepare_status=fail",
		"error_classification=spire_socket_not_socket",
		"bundle_contents_printed=false",
		"vault_run=false",
		"workload_auth_check_run=false",
		"reset_unseal_im_support_bundle_cp_runtime_identity_run=false",
	)
	sudoLog := mustRead(t, h.sudoLogPath)
	assertContainsNone(t, "wrong-type SPIRE socket sudo log forbidden ACL", sudoLog,
		"setfacl",
		"chmod 777",
		"chown",
	)
}

func TestRemoteAlphaOperatorRecoverySessionVaultWorkloadAuthBootstrapPrepareSpireBundleReadClassifiesInactiveServerBeforeAcl(t *testing.T) {
	h := setupFakeRemoteAlphaWorkloadAuthBootstrapHarness(t)

	output, err := runRemoteAlphaOperatorWithPTY(t, append(h.env(), "REMOTE_ALPHA_FAKE_SYSTEMCTL_SPIRE_ACTIVE_STATUS=3"),
		"recovery-session", "vault-workload-auth-bootstrap",
		"--ssh-target", "ds@m75q-test",
		"--prepare-spire-bundle-read",
		"--interactive-tty",
	)
	if err == nil {
		t.Fatalf("expected inactive SPIRE server failure:\n%s", output)
	}

	assertContainsAll(t, "inactive SPIRE server prepare output", output,
		"spire_bundle_read_prepare_status=fail",
		"error_classification=spire_server_inactive_or_unknown",
		"bundle_contents_printed=false",
		"vault_run=false",
		"workload_auth_check_run=false",
		"reset_unseal_im_support_bundle_cp_runtime_identity_run=false",
	)
	sudoLog := readIfExists(h.sudoLogPath)
	assertContainsNone(t, "inactive SPIRE server must not apply ACL", sudoLog,
		"setfacl",
		"chmod 777",
		"chown",
	)
}

func TestRemoteAlphaOperatorRecoverySessionVaultWorkloadAuthBootstrapPrepareSpireBundleReadClassifiesAccessibleBundleShowFailure(t *testing.T) {
	h := setupFakeRemoteAlphaWorkloadAuthBootstrapHarness(t)
	createFakeBootstrapSpireSocket(t, h, 0o600)

	output, err := runRemoteAlphaOperatorWithPTY(t, append(h.env(), "REMOTE_ALPHA_FAKE_SPIRE_SERVER_FORCE_FAIL=true"),
		"recovery-session", "vault-workload-auth-bootstrap",
		"--ssh-target", "ds@m75q-test",
		"--prepare-spire-bundle-read",
		"--interactive-tty",
	)
	if err == nil {
		t.Fatalf("expected SPIRE bundle show failure:\n%s", output)
	}

	assertContainsAll(t, "accessible SPIRE bundle show failure output", output,
		"spire_bundle_read_prepare_status=fail",
		"error_classification=spire_bundle_show_failed",
		"spire_socket_access_classification=spire_socket_present_accessible",
		"bundle_contents_printed=false",
		"vault_run=false",
		"workload_auth_check_run=false",
		"reset_unseal_im_support_bundle_cp_runtime_identity_run=false",
	)
	assertContainsNone(t, "accessible SPIRE bundle show failure output forbidden raw content", output,
		"raw fake SPIRE stderr",
		"FAKE-SPIRE-BUNDLE-MATERIAL-MUST-NOT-PRINT",
	)
	sudoLog := readIfExists(h.sudoLogPath)
	assertContainsNone(t, "accessible SPIRE bundle show failure must not apply ACL", sudoLog,
		"setfacl",
		"chmod 777",
		"chown",
	)
}

func TestRemoteAlphaOperatorRecoverySessionVaultWorkloadAuthBootstrapPrepareRunsBeforeHelperExecution(t *testing.T) {
	h := setupFakeRemoteAlphaWorkloadAuthBootstrapHarness(t)
	before := snapshotPathExistence(t, remoteAlphaOperatorRouteArtifactPaths(filepath.Join(".out", "remote-alpha-m75q", "vault-workload-auth-bootstrap-summary.json"))...)

	summaryParent := filepath.Join(h.remoteRoot, "var", "tmp", "execution-substrate-remote-alpha")
	if err := os.MkdirAll(summaryParent, 0o755); err != nil {
		t.Fatalf("mkdir summary parent: %v", err)
	}
	if err := os.Chmod(summaryParent, 0o555); err != nil {
		t.Fatalf("chmod summary parent: %v", err)
	}
	configPath := filepath.Join(h.remoteRoot, "etc", "execution-substrate", "vault", "workload-zone-vault-config.json")
	if err := os.MkdirAll(filepath.Dir(configPath), 0o755); err != nil {
		t.Fatalf("mkdir config parent: %v", err)
	}
	if err := os.WriteFile(configPath, []byte(`{"vault_config":{"address":"https://example.invalid"}}`), 0o644); err != nil {
		t.Fatalf("write config fixture: %v", err)
	}
	createFakeBootstrapSpireSocket(t, h, 0o600)

	output, err := runRemoteAlphaOperatorWithPTY(t, h.env(),
		"recovery-session", "vault-workload-auth-bootstrap",
		"--ssh-target", "ds@m75q-test",
		"--execute-bootstrap",
		"--prepare-summary-path",
		"--prepare-config-readability",
		"--prepare-spire-bundle-read",
		"--interactive-tty",
	)
	if err != nil {
		t.Fatalf("Mac-side fake workload-auth bootstrap combined prepare+execute route failed: %v\noutput=%s\nssh=%s\nscp=%s\nsudo=%s\nhelper=%s\nrm=%s",
			err, output, readIfExists(h.sshLogPath), readIfExists(h.scpLogPath), readIfExists(h.sudoLogPath), readIfExists(h.helperLog), readIfExists(h.rmLogPath))
	}

	assertContainsAll(t, "Mac-side fake workload-auth bootstrap combined output", output,
		"Preparing Remote Alpha Vault workload-auth bootstrap summary path through an explicit interactive SSH TTY.",
		"summary_path_prepare_status=pass",
		"Preparing Remote Alpha Vault workload-auth bootstrap config readability through an explicit interactive SSH TTY.",
		"config_readability_prepare_status=pass",
		"Preparing Remote Alpha Vault workload-auth bootstrap SPIRE bundle-read access through an explicit interactive SSH TTY.",
		"spire_bundle_read_prepare_status=pass",
		"Running Mac-side Vault workload-auth bootstrap through an explicit interactive SSH TTY.",
		"Staging only scripts/remote_alpha_vault_workload_auth_bootstrap.sh and scripts/internal/remote_alpha_vault_workload_auth_bootstrap.sh.",
		"Remote Alpha Vault workload-auth bootstrap helper finished.",
		"Workload-auth check remains a separate post-bootstrap command and was not run here.",
	)
	prepareOutputIndex := strings.Index(output, "Preparing Remote Alpha Vault workload-auth bootstrap summary path")
	configPrepareOutputIndex := strings.Index(output, "Preparing Remote Alpha Vault workload-auth bootstrap config readability")
	spirePrepareOutputIndex := strings.Index(output, "Preparing Remote Alpha Vault workload-auth bootstrap SPIRE bundle-read access")
	executeOutputIndex := strings.Index(output, "Running Mac-side Vault workload-auth bootstrap")
	if prepareOutputIndex < 0 || configPrepareOutputIndex < 0 || spirePrepareOutputIndex < 0 || executeOutputIndex < 0 || !(prepareOutputIndex < configPrepareOutputIndex && configPrepareOutputIndex < spirePrepareOutputIndex && spirePrepareOutputIndex < executeOutputIndex) {
		t.Fatalf("expected prepare output before execute output, got output=%s", output)
	}

	sshLog := mustRead(t, h.sshLogPath)
	prepareIndex := strings.Index(sshLog, "vault-workload-auth-bootstrap-summary.json")
	configPrepareIndex := strings.Index(sshLog, "workload-zone-vault-config.json")
	spirePrepareIndex := strings.Index(sshLog, "/run/spire/server/private/api.sock")
	stageIndex := strings.Index(sshLog, "execution-substrate-remote-alpha-vault-workload-auth-bootstrap")
	helperIndex := strings.Index(sshLog, "exec /bin/bash -c")
	if prepareIndex < 0 || configPrepareIndex < 0 || spirePrepareIndex < 0 || stageIndex < 0 || helperIndex < 0 {
		t.Fatalf("expected summary prepare, config prepare, SPIRE prepare, stage, and helper ssh invocations in log=%q", sshLog)
	}
	if !(prepareIndex < configPrepareIndex && configPrepareIndex < spirePrepareIndex && spirePrepareIndex < stageIndex && stageIndex < helperIndex) {
		t.Fatalf("expected summary prepare before config prepare before SPIRE prepare before stage before helper execution, log=%q", sshLog)
	}
	if got := strings.Count(sshLog, "tty=true"); got != 4 {
		t.Fatalf("expected four interactive ssh -tt invocations for summary prepare, config prepare, SPIRE prepare, and helper, got %d log=%q", got, sshLog)
	}
	assertContainsNone(t, "fake workload-auth bootstrap combined ssh log forbidden capture", sshLog,
		" tee ",
		"script ",
		"transcript",
		"--execute-reset",
		"--unseal-only",
		"--post-unseal-check",
		"remote-alpha-live-refresh",
		"remote-alpha-live-support-bundle",
		"cp-proof",
		".out",
	)

	scpLog := strings.TrimSpace(mustRead(t, h.scpLogPath))
	if scpLines := strings.Split(scpLog, "\n"); len(scpLines) != 2 {
		t.Fatalf("expected exactly two staged file uploads after prepare, got %q", scpLog)
	}
	helperLog := mustRead(t, h.helperLog)
	assertContainsAll(t, "fake workload-auth bootstrap combined helper log", helperLog,
		"public_args=",
		"/scripts/internal/remote_alpha_vault_workload_auth_bootstrap.sh",
	)
	assertContainsNone(t, "fake workload-auth bootstrap combined helper log forbidden args", helperLog,
		"--prepare-summary-path",
		"--vault-addr",
		"--vault-role",
		"--api-key",
		"--prepare-spire-bundle-read",
		"--proof-secret-value",
		"--execute-reset",
		"remote-alpha-live-refresh",
		"remote-alpha-live-support-bundle",
	)
	sudoLog := mustRead(t, h.sudoLogPath)
	assertContainsAll(t, "fake workload-auth bootstrap combined sudo log", sudoLog,
		"-v -p Remote Alpha OS sudo password for summary path preparation: ",
		"-n install -d -m 0750",
	)
	assertNoNewPaths(t, "Mac-side fake workload-auth bootstrap combined route", before)
}

func TestRemoteAlphaOperatorRecoverySessionVaultWorkloadAuthBootstrapStagesOnlyApprovedHelpersWithTTYAndCleanup(t *testing.T) {
	h := setupFakeRemoteAlphaWorkloadAuthBootstrapHarness(t)
	before := snapshotPathExistence(t, remoteAlphaOperatorRouteArtifactPaths(filepath.Join(".out", "remote-alpha-m75q", "vault-workload-auth-bootstrap-summary.json"))...)

	output, err := runRemoteAlphaOperatorWithPTY(t, h.env(),
		"recovery-session", "vault-workload-auth-bootstrap",
		"--ssh-target", "ds@m75q-test",
		"--execute-bootstrap",
		"--interactive-tty",
	)
	if err != nil {
		t.Fatalf("Mac-side fake workload-auth bootstrap route failed: %v\noutput=%s\nssh=%s\nscp=%s\nhelper=%s\nrm=%s",
			err, output, readIfExists(h.sshLogPath), readIfExists(h.scpLogPath), readIfExists(h.helperLog), readIfExists(h.rmLogPath))
	}

	assertContainsAll(t, "Mac-side fake workload-auth bootstrap output", output,
		"Running Mac-side Vault workload-auth bootstrap through an explicit interactive SSH TTY.",
		"Staging only scripts/remote_alpha_vault_workload_auth_bootstrap.sh and scripts/internal/remote_alpha_vault_workload_auth_bootstrap.sh.",
		"Invoking only the staged public bootstrap helper; no helper override flags are accepted or passed.",
		"The operator enters Vault bootstrap authority and any proof secret value only into the visible remote helper prompt.",
		"Canonical bootstrap summary stays remote at /var/tmp/execution-substrate-remote-alpha/vault-workload-auth-bootstrap-summary.json.",
		"No transcript, tee/script capture, .out, report, support bundle, operator summary, generated Mac artifact, workload-auth check, reset/unseal, IM refresh, runtime identity generation, ES token brokerage, or CP proof is created or run.",
		"staged helper cleanup was attempted",
		"Canonical remote bootstrap summary path: /var/tmp/execution-substrate-remote-alpha/vault-workload-auth-bootstrap-summary.json",
		"The summary remains on the remote host",
		"did not copy it back to Mac .out",
		"did not print full summary JSON",
		"Workload-auth check remains a separate post-bootstrap command and was not run here.",
	)
	assertContainsNone(t, "Mac-side fake workload-auth bootstrap output forbidden capture", output,
		"root-token-for-fake-bootstrap",
		"proof-value-for-fake-bootstrap",
		"remote-alpha-live-refresh",
		"remote-alpha-live-support-bundle",
		"cp-proof",
		"runtime identity generation was run",
	)

	scpLog := strings.TrimSpace(mustRead(t, h.scpLogPath))
	scpLines := strings.Split(scpLog, "\n")
	if len(scpLines) != 2 {
		t.Fatalf("expected exactly two staged file uploads, got %q", scpLog)
	}
	assertContainsAll(t, "fake workload-auth bootstrap scp log", scpLog,
		filepath.Join(executionSubstrateRepoRoot, "scripts", "remote_alpha_vault_workload_auth_bootstrap.sh"),
		filepath.Join(executionSubstrateRepoRoot, "scripts", "internal", "remote_alpha_vault_workload_auth_bootstrap.sh"),
		"/scripts/remote_alpha_vault_workload_auth_bootstrap.sh",
		"/scripts/internal/remote_alpha_vault_workload_auth_bootstrap.sh",
	)
	assertContainsNone(t, "fake workload-auth bootstrap scp log", scpLog,
		"remote_alpha_operator.sh",
		"remote_alpha_reset_disposable_vault.sh",
		"remote_alpha_vault_workload_auth_check.sh",
		"remote_alpha_runtime_identity_helper_summary.sh",
		"remote_alpha_migrate_vault_service_user.sh",
		"remote_alpha_prepare_es_config_tls",
		"remote_alpha_deploy_es_binaries",
		"bundle",
	)

	sshLog := mustRead(t, h.sshLogPath)
	if got := strings.Count(sshLog, "tty=true"); got != 1 {
		t.Fatalf("expected exactly one interactive ssh -tt invocation, got %d log=%q", got, sshLog)
	}
	assertContainsAll(t, "fake workload-auth bootstrap ssh log", sshLog,
		"tty=true target=ds@m75q-test",
	)
	assertContainsNone(t, "fake workload-auth bootstrap ssh log forbidden capture", sshLog,
		" tee ",
		"script ",
		"transcript",
		"--execute-reset",
		"--unseal-only",
		"--post-unseal-check",
		"remote-alpha-live-refresh",
		"remote-alpha-live-support-bundle",
		"cp-proof",
		".out",
	)

	helperLog := mustRead(t, h.helperLog)
	assertContainsAll(t, "fake workload-auth bootstrap helper log", helperLog,
		"public_args=",
		"/scripts/internal/remote_alpha_vault_workload_auth_bootstrap.sh",
	)
	assertContainsNone(t, "fake workload-auth bootstrap helper log forbidden args", helperLog,
		"--vault-addr",
		"--vault-role",
		"--vault-audience",
		"--spiffe-id",
		"--summary-path",
		"--config-path",
		"--root-token",
		"--vault-token",
		"--api-key",
		"--proof-secret-value",
		"--execute-reset",
		"--unseal-only",
		"--post-unseal-check",
		"remote-alpha-live-refresh",
		"remote-alpha-live-support-bundle",
	)

	rmLog := mustRead(t, h.rmLogPath)
	assertContainsAll(t, "fake workload-auth bootstrap remote cleanup log", rmLog,
		"execution-substrate-remote-alpha-vault-workload-auth-bootstrap",
	)
	if entries, err := os.ReadDir(filepath.Join(h.remoteRoot, "tmp", "execution-substrate-remote-alpha-vault-workload-auth-bootstrap")); err == nil && len(entries) > 0 {
		t.Fatalf("expected remote workload-auth bootstrap staged helper directory to be cleaned, found %d entries", len(entries))
	}
	assertNoNewPaths(t, "Mac-side fake workload-auth bootstrap route", before)
}

func TestRemoteAlphaOperatorRecoverySessionVaultResetDisposableSourceKeepsExecuteRouteNarrow(t *testing.T) {
	source := mustRead(t, remoteAlphaOperatorScriptPath())
	section := docSection(t, source, "recovery_session_vault_reset_disposable_require_command() {", "\nrecovery_session_vault_workload_auth_check_require_command() {")

	assertContainsAll(t, "vault-reset-disposable source section", section,
		"REMOTE_ALPHA_VAULT_RESET_HELPER",
		"REMOTE_ALPHA_VAULT_RESET_DRY_RUN_STAGE_ROOT",
		"REMOTE_ALPHA_VAULT_RESET_EXECUTE_STAGE_ROOT",
		"recovery_session_vault_reset_disposable_require_local_tty",
		"ssh -tt",
		`"${helper_path}" --execute-reset`,
		`"${helper_path}" --dry-run`,
		"staged helper cleanup was attempted",
	)
	assertContainsNone(t, "vault-reset-disposable source section", section,
		"scripts/internal/",
		`scp "${SCRIPT_DIR}/remote_alpha_operator.sh"`,
		"remote_alpha_vault_workload_auth_check.sh",
		"remote_alpha_runtime_identity_helper_summary.sh",
		"remote_alpha_migrate_vault_service_user.sh",
		"remote_alpha_prepare_es_config_tls.sh",
		"remote_alpha_deploy_es_binaries.sh",
		"remote_alpha_prepare_es_writable_state_ownership.sh",
		"remote-alpha-live-refresh",
		"remote-alpha-live-support-bundle",
		"print_refresh_command",
		"print_support_bundle_command",
		"--workload-auth",
		"--runtime-identity",
		"operator_summary",
		"summary_path",
		"support_output_root",
	)
}

func TestRemoteAlphaOperatorRecoverySessionVaultWorkloadAuthCheckSourceKeepsRouteNarrow(t *testing.T) {
	source := mustRead(t, remoteAlphaOperatorScriptPath())
	section := docSection(t, source, "recovery_session_vault_workload_auth_check_require_command() {", "\nrecovery_session_runtime_identity_summary_require_command() {")

	assertContainsAll(t, "vault-workload-auth-check source section", section,
		"REMOTE_ALPHA_VAULT_WORKLOAD_AUTH_PUBLIC_HELPER",
		"REMOTE_ALPHA_VAULT_WORKLOAD_AUTH_INTERNAL_HELPER",
		"REMOTE_ALPHA_VAULT_WORKLOAD_AUTH_STAGE_ROOT",
		"REMOTE_ALPHA_VAULT_WORKLOAD_AUTH_REMOTE_SUMMARY",
		"recovery_session_vault_workload_auth_check_require_local_tty",
		`scp "${REMOTE_ALPHA_VAULT_WORKLOAD_AUTH_PUBLIC_HELPER}" "${ssh_target}:${remote_public_helper_path}"`,
		`scp "${REMOTE_ALPHA_VAULT_WORKLOAD_AUTH_INTERNAL_HELPER}" "${ssh_target}:${remote_internal_helper_path}"`,
		`ssh -tt "${ssh_target}"`,
		`sudo "${helper_path}"`,
		"remote_alpha_vault_workload_auth_check.sh",
		"scripts/internal/remote_alpha_vault_workload_auth_check.sh",
		"staged helper cleanup was attempted",
		"Canonical remote summary path",
	)
	assertContainsNone(t, "vault-workload-auth-check source section forbidden surfaces", section,
		`scp "${SCRIPT_DIR}/remote_alpha_operator.sh"`,
		"remote_alpha_reset_disposable_vault.sh",
		"remote_alpha_runtime_identity_helper_summary.sh",
		"remote_alpha_migrate_vault_service_user.sh",
		"remote_alpha_prepare_es_config_tls.sh",
		"remote_alpha_deploy_es_binaries.sh",
		"remote_alpha_prepare_es_writable_state_ownership.sh",
		"remote-alpha-live-refresh &&",
		"remote-alpha-live-support-bundle &&",
		`"${helper_path}" --execute-reset`,
		`"${helper_path}" --unseal-only`,
		`"${helper_path}" --post-unseal-check`,
		`"${helper_path}" --dry-run`,
		`"${helper_path}" --vault-addr`,
		`"${helper_path}" --vault-role`,
		`"${helper_path}" --vault-audience`,
		`"${helper_path}" --spiffe-id`,
		`"${helper_path}" --summary-path`,
		`"${helper_path}" --config-path`,
		"operator-summary",
		"readiness-session-summary",
		"recovery-session-summary",
		"tee ",
	)

	for _, forbidden := range []string{
		"remote_alpha_reset_disposable_vault.sh",
		"remote_alpha_runtime_identity_helper_summary.sh",
		"remote_alpha_migrate_vault_service_user.sh",
		"remote_alpha_prepare_es_config_tls",
		"remote_alpha_deploy_es_binaries",
		"remote_alpha_prepare_es_writable_state_ownership",
	} {
		if strings.Contains(section, forbidden) {
			t.Fatalf("vault-workload-auth-check source must not route unrelated helper %s", forbidden)
		}
	}
}

func TestRemoteAlphaOperatorRecoverySessionRuntimeIdentitySummarySourceKeepsRouteNarrow(t *testing.T) {
	source := mustRead(t, remoteAlphaOperatorScriptPath())
	section := docSection(t, source, "recovery_session_runtime_identity_summary_require_command() {", "\nrecovery_session_evidence_check() {")

	assertContainsAll(t, "runtime-identity-summary source section", section,
		"REMOTE_ALPHA_RUNTIME_IDENTITY_SUMMARY_HELPER",
		"REMOTE_ALPHA_RUNTIME_IDENTITY_SUMMARY_STAGE_ROOT",
		"REMOTE_ALPHA_RUNTIME_IDENTITY_SUMMARY_REMOTE_SUMMARY",
		"recovery_session_runtime_identity_summary_require_local_tty",
		`scp "${REMOTE_ALPHA_RUNTIME_IDENTITY_SUMMARY_HELPER}" "${ssh_target}:${remote_helper_path}"`,
		`ssh -tt "${ssh_target}"`,
		`sudo "${helper_path}"`,
		"remote_alpha_runtime_identity_helper_summary.sh",
		"staged helper cleanup was attempted",
		"Canonical remote summary path",
	)
	assertContainsNone(t, "runtime-identity-summary source section forbidden surfaces", section,
		`scp "${SCRIPT_DIR}/remote_alpha_operator.sh"`,
		"scripts/internal/",
		"remote_alpha_reset_disposable_vault.sh",
		"remote_alpha_vault_workload_auth_check.sh",
		"remote_alpha_vault_workload_auth_bootstrap.sh",
		"remote_alpha_migrate_vault_service_user.sh",
		"remote_alpha_prepare_es_config_tls.sh",
		"remote_alpha_deploy_es_binaries.sh",
		"remote_alpha_prepare_es_writable_state_ownership.sh",
		"remote-alpha-live-refresh",
		"remote-alpha-live-support-bundle",
		`"${helper_path}" --execute-reset`,
		`"${helper_path}" --unseal-only`,
		`"${helper_path}" --post-unseal-check`,
		`"${helper_path}" --dry-run`,
		`"${helper_path}" --check-only`,
		`"${helper_path}" --output`,
		`"${helper_path}" --runtime-support-path`,
		`"${helper_path}" --spire-agent-socket-path`,
		`"${helper_path}" --spire-server-socket-path`,
		`"${helper_path}" --workload-spiffe-id`,
		`"${helper_path}" --audience`,
		"operator-summary",
		"readiness-session-summary",
		"recovery-session-summary",
		"tee ",
	)
}

func TestRemoteAlphaOperatorRecoverySessionVaultWorkloadAuthBootstrapSourceKeepsRouteNarrow(t *testing.T) {
	source := mustRead(t, remoteAlphaOperatorScriptPath())
	section := docSection(t, source, "recovery_session_vault_workload_auth_bootstrap() {", "\nrecovery_session_vault_unseal_existing_require_command() {")

	assertContainsAll(t, "vault-workload-auth-bootstrap source section", section,
		"REMOTE_ALPHA_VAULT_WORKLOAD_AUTH_BOOTSTRAP_PUBLIC_HELPER",
		"REMOTE_ALPHA_VAULT_WORKLOAD_AUTH_BOOTSTRAP_INTERNAL_HELPER",
		"REMOTE_ALPHA_VAULT_WORKLOAD_AUTH_BOOTSTRAP_STAGE_ROOT",
		"REMOTE_ALPHA_VAULT_WORKLOAD_AUTH_BOOTSTRAP_REMOTE_SUMMARY_DIR",
		"REMOTE_ALPHA_VAULT_WORKLOAD_AUTH_BOOTSTRAP_REMOTE_SUMMARY",
		"REMOTE_ALPHA_VAULT_WORKLOAD_AUTH_BOOTSTRAP_CONFIG",
		"REMOTE_ALPHA_VAULT_WORKLOAD_AUTH_BOOTSTRAP_SPIRE_SERVER_SOCKET",
		"recovery_session_vault_workload_auth_bootstrap_plan",
		"recovery_session_vault_workload_auth_bootstrap_inventory",
		"recovery_session_vault_workload_auth_bootstrap_require_local_tty",
		"--execute-bootstrap",
		"--prepare-summary-path",
		"--prepare-config-readability",
		"--prepare-spire-bundle-read",
		"--ssh-target",
		"--interactive-tty",
		"--host-local",
		"--execute-reset",
		"--unseal-only",
		"--post-unseal-check",
		"--governed-smoke-command",
		"--proof-secret-value",
		"fixed documented bootstrap values",
		"proof secret values must never be passed",
		"recovery_session_vault_workload_auth_bootstrap_prepare_summary_path_remote",
		"summary_path_prepare_status=pass",
		`ssh -tt "${ssh_target}" "/bin/bash -c ${remote_prepare_command_quoted}"`,
		`sudo -v -p "Remote Alpha OS sudo password for summary path preparation: "`,
		`sudo -n "$@"`,
		"run_sudo install -d -m 0750",
		"final_summary_created=false",
		"recovery_session_vault_workload_auth_bootstrap_prepare_config_readability_remote",
		"config_readability_prepare_status=pass",
		`sudo -v -p "Remote Alpha OS sudo password for config readability preparation: "`,
		`run_sudo setfacl -m "u:${helper_user}:--x"`,
		`run_sudo setfacl -m "u:${helper_user}:r--"`,
		"config_contents_printed=false",
		"recovery_session_vault_workload_auth_bootstrap_prepare_spire_bundle_read_remote",
		"spire_bundle_read_prepare_status=pass",
		`sudo -v -p "Remote Alpha OS sudo password for SPIRE bundle-read preparation: "`,
		"require_spire_server_active_when_systemd_visible",
		"sudo_path_test",
		"require_sudo_visible_spire_path_shape",
		"helper_can_access_spire_socket",
		"spire_socket_present_accessible",
		"spire_socket_present_needs_acl",
		"spire_socket_parent_missing",
		"spire_socket_missing",
		"spire_socket_not_socket",
		"spire_server_inactive_or_unknown",
		"spire_server_command_missing",
		"spire_bundle_show_failed",
		`run_sudo setfacl -m "u:${helper_user}:rw-"`,
		"bundle_output_discarded=true",
		"bundle_contents_printed=false",
		`scp "${REMOTE_ALPHA_VAULT_WORKLOAD_AUTH_BOOTSTRAP_PUBLIC_HELPER}" "${ssh_target}:${remote_public_helper_path}"`,
		`scp "${REMOTE_ALPHA_VAULT_WORKLOAD_AUTH_BOOTSTRAP_INTERNAL_HELPER}" "${ssh_target}:${remote_internal_helper_path}"`,
		`ssh -tt "${ssh_target}"`,
		`"${helper_path}"`,
		"remote_alpha_vault_workload_auth_bootstrap.sh",
		"scripts/internal/remote_alpha_vault_workload_auth_bootstrap.sh",
		"staged helper cleanup was attempted",
		"Canonical remote bootstrap summary path",
	)
	assertContainsNone(t, "vault-workload-auth-bootstrap source forbidden execution surfaces", section,
		"recovery_session_vault_workload_auth_check_remote",
		"recovery_session_vault_workload_auth_check_run_remote",
		"recovery_session_vault_reset_disposable_remote",
		"recovery_session_vault_unseal_existing_remote",
		"recovery_session_vault_unseal_existing_run_remote",
		"recovery_session_vault_reset_disposable_run_remote",
		"REMOTE_ALPHA_VAULT_WORKLOAD_AUTH_PUBLIC_HELPER",
		"REMOTE_ALPHA_VAULT_WORKLOAD_AUTH_INTERNAL_HELPER",
		"REMOTE_ALPHA_VAULT_RESET_HELPER",
		"REMOTE_ALPHA_VAULT_WORKLOAD_AUTH_STAGE_ROOT",
		"REMOTE_ALPHA_VAULT_UNSEAL_STAGE_ROOT",
		"REMOTE_ALPHA_VAULT_RESET_DRY_RUN_STAGE_ROOT",
		"REMOTE_ALPHA_VAULT_RESET_EXECUTE_STAGE_ROOT",
		`sudo "${helper_path}"`,
		`exec "`,
		"print_refresh_command",
		"print_support_bundle_command",
		"remote-alpha-live-refresh",
		"remote-alpha-live-support-bundle",
		"remote_alpha_reset_disposable_vault.sh",
		"remote_alpha_vault_workload_auth_check.sh",
		"remote_alpha_runtime_identity_helper_summary.sh",
		"mktemp",
		"operator-summary",
		"recovery-session-summary",
		"tee ",
	)
}

func TestRemoteAlphaOperatorP0qBootstrapExecutionContractIsImplementedNarrowly(t *testing.T) {
	plans := compactText(mustRead(t, "PLANS.md"))
	remoteRaw := mustRead(t, ".docs/system_overview/remote_supported_host_alpha.md")
	remoteSection := compactDocSection(t, remoteRaw, "### P0q Vault Workload-Auth Bootstrap Execution Route", "### P0d Interactive Validation Evidence")
	source := mustRead(t, remoteAlphaOperatorScriptPath())
	sourceSection := docSection(t, source, "recovery_session_vault_workload_auth_bootstrap() {", "\nrecovery_session_vault_unseal_existing_require_command() {")

	assertContainsAll(t, "P0q bootstrap execution docs", plans,
		"The P0q implementation/self-audit/merge-readiness slice may implement exactly one dedicated secret-sensitive workload-auth bootstrap helper, exactly one Mac-side recovery-session execution route, one bounded preparation form for the bootstrap summary path, and one bounded preparation form for fixed workload-zone config readability, and one bounded preparation form for fixed SPIRE server bundle-read access",
		"`scripts/remote_alpha_operator.sh recovery-session vault-workload-auth-bootstrap --ssh-target <target> --execute-bootstrap --interactive-tty`",
		"`scripts/remote_alpha_operator.sh recovery-session vault-workload-auth-bootstrap --ssh-target <target> --prepare-summary-path --interactive-tty`",
		"`scripts/remote_alpha_operator.sh recovery-session vault-workload-auth-bootstrap --ssh-target <target> --prepare-config-readability --interactive-tty`",
		"`scripts/remote_alpha_operator.sh recovery-session vault-workload-auth-bootstrap --ssh-target <target> --prepare-spire-bundle-read --interactive-tty`",
		"`scripts/remote_alpha_vault_workload_auth_bootstrap.sh`",
		"`scripts/internal/remote_alpha_vault_workload_auth_bootstrap.sh`",
		"`--ssh-target <target> --execute-bootstrap --prepare-summary-path --prepare-config-readability --prepare-spire-bundle-read --interactive-tty`",
		"summary preparation runs first, config-readability preparation runs second, SPIRE bundle-read preparation runs third",
		"`--prepare-summary-path` follow-up is OS/filesystem preparation only",
		"`--prepare-config-readability` follow-up is OS/filesystem preparation only",
		"`--prepare-spire-bundle-read` follow-up is OS/filesystem/capability preparation only",
		"fixed-path user ACL",
		"`spire_socket_present_accessible`",
		"`spire_socket_present_needs_acl`",
		"`spire_socket_parent_missing`",
		"`spire_socket_missing`",
		"`spire_socket_not_socket`",
		"`spire_server_inactive_or_unknown`",
		"`spire_server_command_missing`",
		"`spire_bundle_show_failed`",
		"sudo-visible inspection shows",
		"do not create SPIRE parents or sockets",
		"config readability preflight before prompts and Vault writes",
		"SPIRE bundle-read preflight before prompts and Vault writes",
		"public JWT validation material for the workload SPIFFE ID trust domain",
		"safe source/shape labels, key counts, selected trust-domain labels, and a digest",
		"visible/silent remote helper TTY prompt",
		"in-process Vault API client",
		"must not use `VAULT_TOKEN`",
		"`vault login`",
		"`/var/tmp/execution-substrate-remote-alpha/vault-workload-auth-bootstrap-summary.json`",
		"`execution-substrate.remote-alpha.vault-workload-auth-bootstrap-summary.v1`",
		"P0q validation remains fake/static only",
	)
	assertContainsAll(t, "P0q bootstrap execution remote docs", remoteSection,
		"`Bounded slice rule`: P0q implements the dedicated secret-sensitive workload-auth bootstrap execution route and bounded summary-path preparation route plus bounded config-readability and SPIRE bundle-read preparation routes",
		"`scripts/remote_alpha_vault_workload_auth_bootstrap.sh`",
		"`scripts/internal/remote_alpha_vault_workload_auth_bootstrap.sh`",
		"Mac-side operator route:",
		"`scripts/remote_alpha_operator.sh recovery-session vault-workload-auth-bootstrap --ssh-target <target> --execute-bootstrap --interactive-tty`",
		"`scripts/remote_alpha_operator.sh recovery-session vault-workload-auth-bootstrap --ssh-target <target> --prepare-summary-path --interactive-tty`",
		"`scripts/remote_alpha_operator.sh recovery-session vault-workload-auth-bootstrap --ssh-target <target> --prepare-config-readability --interactive-tty`",
		"`scripts/remote_alpha_operator.sh recovery-session vault-workload-auth-bootstrap --ssh-target <target> --prepare-spire-bundle-read --interactive-tty`",
		"Combined form:",
		"Secret prompt model:",
		"The human remains the operator.",
		"ES remains a bounded Remote Alpha operator facade/workflow, not a Vault token broker.",
		"The helper prompts for Vault bootstrap authority and proof secret values only on the visible/silent remote TTY",
		"Summary-path preparation:",
		"Preparation is OS/filesystem setup only",
		"helper-user/group owned with mode `0750`",
		"creates no final bootstrap summary in standalone mode",
		"Config-readability preparation:",
		"fixed-path user ACLs",
		"does not print config contents",
		"SPIRE bundle-read preparation:",
		"fixed SPIRE server socket path",
		"`spire_socket_present_accessible`",
		"`spire_socket_present_needs_acl`",
		"`spire_socket_parent_missing`",
		"`spire_socket_missing`",
		"`spire_socket_not_socket`",
		"`spire_server_inactive_or_unknown`",
		"`spire_bundle_show_failed`",
		"sudo-visible inspection shows",
		"do not create SPIRE parents or sockets",
		"bundle output is discarded",
		"summary-path preparation, then config-readability preparation, then SPIRE bundle-read preparation, then helper staging/execution",
		"Vault API strategy:",
		"in-process HTTPS client",
		"must not use `VAULT_TOKEN`",
		"`vault login`",
		"Execution boundaries:",
		"must not run a workload-auth check",
		"must not run Infrastructure Manager refresh",
		"must not collect support bundles",
		"must not run CP proof",
		"must not run runtime identity summary or runtime identity generation",
		"must not claim workload-auth success",
		"Summary/evidence behavior:",
		"`/var/tmp/execution-substrate-remote-alpha/vault-workload-auth-bootstrap-summary.json`",
		"`execution-substrate.remote-alpha.vault-workload-auth-bootstrap-summary.v1`",
		"source labels, shape labels, counts, digests",
		"Allowed execution flags:",
		"`--execute-bootstrap`",
		"`--prepare-summary-path`",
		"`--prepare-config-readability`",
		"`--prepare-spire-bundle-read`",
		"Standalone `--prepare-summary-path` runs only the fixed bounded remote preparation command",
		"Standalone `--prepare-config-readability` runs only the fixed bounded remote preparation command",
		"Standalone `--prepare-spire-bundle-read` runs only the fixed bounded remote preparation command",
		"Forbidden execution flags and inputs include:",
		"`--root-token`",
		"`--vault-token`",
		"proof secret value flags",
		"P0q tests:",
		"fake bootstrap writes the Vault JWT auth config with the expected validation material and bound issuer shape",
		"fake workload-auth check JWT claims align with the bootstrap config labels",
		"fake SSH/SCP",
		"fake Vault API capture",
	)
	assertContainsAll(t, "P0q bootstrap execution operator source", sourceSection,
		"REMOTE_ALPHA_VAULT_WORKLOAD_AUTH_BOOTSTRAP_PUBLIC_HELPER",
		"REMOTE_ALPHA_VAULT_WORKLOAD_AUTH_BOOTSTRAP_INTERNAL_HELPER",
		"REMOTE_ALPHA_VAULT_WORKLOAD_AUTH_BOOTSTRAP_STAGE_ROOT",
		"REMOTE_ALPHA_VAULT_WORKLOAD_AUTH_BOOTSTRAP_REMOTE_SUMMARY_DIR",
		"REMOTE_ALPHA_VAULT_WORKLOAD_AUTH_BOOTSTRAP_REMOTE_SUMMARY",
		"--prepare-summary-path",
		"--prepare-config-readability",
		"--prepare-spire-bundle-read",
		"recovery_session_vault_workload_auth_bootstrap_prepare_summary_path_remote",
		"recovery_session_vault_workload_auth_bootstrap_prepare_config_readability_remote",
		"recovery_session_vault_workload_auth_bootstrap_prepare_spire_bundle_read_remote",
		`ssh -tt "${ssh_target}"`,
		`"${helper_path}"`,
	)
	assertContainsNone(t, "P0q bootstrap execution operator source forbidden bundle", sourceSection,
		"remote_alpha_vault_workload_auth_check.sh",
		"remote_alpha_reset_disposable_vault.sh",
		"remote_alpha_runtime_identity_helper_summary.sh",
		"remote-alpha-live-refresh",
		"remote-alpha-live-support-bundle",
		`sudo "${helper_path}"`,
	)

	for _, path := range []string{
		filepath.Join(executionSubstrateRepoRoot, "scripts", "remote_alpha_vault_workload_auth_bootstrap.sh"),
		filepath.Join(executionSubstrateRepoRoot, "scripts", "internal", "remote_alpha_vault_workload_auth_bootstrap.sh"),
	} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("stat %s: %v", path, err)
		}
	}
}

func TestRemoteAlphaOperatorRecoverySessionRejectsDuplicateAndMisplacedFlags(t *testing.T) {
	for _, tc := range []struct {
		name      string
		args      []string
		duplicate string
	}{
		{
			name:      "duplicate mode",
			args:      []string{"--plan", "--inventory"},
			duplicate: "--inventory",
		},
		{
			name:      "duplicate ssh alias",
			args:      []string{"--next-steps", "--ssh-alias", "a", "--ssh-alias", "b"},
			duplicate: "--ssh-alias",
		},
		{
			name:      "duplicate im profile dir",
			args:      []string{"--evidence-check", "--im-profile-dir", "a", "--im-profile-dir", "b"},
			duplicate: "--im-profile-dir",
		},
		{
			name:      "duplicate support output root",
			args:      []string{"--next-steps", "--support-output-root", "a", "--support-output-root", "b"},
			duplicate: "--support-output-root",
		},
		{
			name:      "duplicate vault summary",
			args:      []string{"--evidence-check", "--vault-workload-auth-summary", "a", "--vault-workload-auth-summary", "b"},
			duplicate: "--vault-workload-auth-summary",
		},
		{
			name:      "duplicate runtime summary",
			args:      []string{"--evidence-check", "--runtime-identity-summary", "a", "--runtime-identity-summary", "b"},
			duplicate: "--runtime-identity-summary",
		},
		{
			name:      "duplicate service-user summary",
			args:      []string{"--evidence-check", "--vault-service-user-summary", "a", "--vault-service-user-summary", "b"},
			duplicate: "--vault-service-user-summary",
		},
		{
			name:      "duplicate readiness summary",
			args:      []string{"--evidence-check", "--readiness-summary", "a", "--readiness-summary", "b"},
			duplicate: "--readiness-summary",
		},
		{
			name:      "duplicate staging record",
			args:      []string{"--evidence-check", "--staging-record", "a", "--staging-record", "b"},
			duplicate: "--staging-record",
		},
		{
			name:      "duplicate evidence dir",
			args:      []string{"--evidence-check", "--evidence-dir", "a", "--evidence-dir", "b"},
			duplicate: "--evidence-dir",
		},
		{
			name:      "duplicate strict known schema",
			args:      []string{"--evidence-check", "--strict-known-schema", "--strict-known-schema"},
			duplicate: "--strict-known-schema",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			output := requireRemoteAlphaOperatorFailure(t, append([]string{"recovery-session"}, tc.args...)...)
			assertContainsAll(t, "duplicate recovery-session flag refusal", output,
				"duplicate option for recovery-session: "+tc.duplicate,
				"No recovery-session live helper or IM execution occurred.",
			)
		})
	}

	output := requireRemoteAlphaOperatorFailure(t, "recovery-session", "--readiness-summary", "summary.json")
	assertContainsAll(t, "misplaced evidence path refusal", output,
		"recovery-session evidence path flags require --evidence-check",
		"No recovery-session live helper or IM execution occurred.",
	)
}

func TestRemoteAlphaOperatorWritableStateRouteRejectsUnsafeArgsBeforeRouting(t *testing.T) {
	docs := mustRead(t, ".docs/system_overview/remote_supported_host_alpha.md")
	assertContainsAll(t, "P0d writable-state route docs", docs,
		"`Bounded slice rule`: P0d implements exactly one Remote Alpha operator route",
		"`scripts/remote_alpha_operator.sh es-writable-state-readiness-check`",
		"Host-local execution is intentionally not enabled through the operator facade",
		"`--apply`",
		"`--dry-run`",
	)

	for _, tc := range []struct {
		name     string
		args     []string
		required []string
	}{
		{
			name: "missing ssh target",
			args: []string{},
			required: []string{
				"es-writable-state-readiness-check requires --ssh-target <target>",
				"No helper execution routing occurred.",
			},
		},
		{
			name: "apply forbidden",
			args: []string{"--apply"},
			required: []string{
				"es-writable-state-readiness-check forbids --apply",
				"check-only/non-mutating",
				"No helper execution routing occurred.",
			},
		},
		{
			name: "dry run forbidden",
			args: []string{"--dry-run"},
			required: []string{
				"es-writable-state-readiness-check forbids --dry-run",
				"helper does not expose a documented dry-run route",
				"No helper execution routing occurred.",
			},
		},
		{
			name: "unknown flag",
			args: []string{"--definitely-not-a-route-flag"},
			required: []string{
				"unknown option for es-writable-state-readiness-check: --definitely-not-a-route-flag",
				"No helper execution routing occurred.",
			},
		},
		{
			name: "unknown positional",
			args: []string{"unexpected-command"},
			required: []string{
				"unexpected positional argument for es-writable-state-readiness-check: unexpected-command",
				"No helper execution routing occurred.",
			},
		},
		{
			name: "invalid mode",
			args: []string{"--mode", "invalid"},
			required: []string{
				"unsupported --mode for es-writable-state-readiness-check: invalid",
				"No helper execution routing occurred.",
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			output := requireRemoteAlphaOperatorFailure(t, append([]string{"es-writable-state-readiness-check"}, tc.args...)...)
			assertContainsAll(t, "writable-state route refusal", output, tc.required...)
		})
	}
}

func TestRemoteAlphaOperatorWritableStateRouteRejectsDuplicateArgsBeforeRouting(t *testing.T) {
	for _, tc := range []struct {
		name         string
		args         []string
		duplicate    string
		artifactDirs []string
	}{
		{
			name:      "duplicate ssh target",
			args:      []string{"--ssh-target", "a", "--ssh-target", "b"},
			duplicate: "--ssh-target",
		},
		{
			name:      "duplicate mode",
			args:      []string{"--ssh-target", "host", "--mode", "alpha-compat", "--mode", "future-non-root-required"},
			duplicate: "--mode",
		},
		{
			name:      "duplicate run id",
			args:      []string{"--ssh-target", "host", "--run-id", "a", "--run-id", "b"},
			duplicate: "--run-id",
		},
		{
			name:         "duplicate output dir",
			args:         []string{"--ssh-target", "host", "--output-dir", ".out/a", "--output-dir", ".out/b"},
			duplicate:    "--output-dir",
			artifactDirs: []string{filepath.Join(".out", "a"), filepath.Join(".out", "b")},
		},
		{
			name:      "duplicate readiness output",
			args:      []string{"--ssh-target", "host", "--readiness-output", "a.json", "--readiness-output", "b.json"},
			duplicate: "--readiness-output",
		},
		{
			name:      "duplicate helper staging record output",
			args:      []string{"--ssh-target", "host", "--helper-staging-record-output", "a.json", "--helper-staging-record-output", "b.json"},
			duplicate: "--helper-staging-record-output",
		},
		{
			name:      "duplicate provenance output",
			args:      []string{"--ssh-target", "host", "--provenance-output", "a.json", "--provenance-output", "b.json"},
			duplicate: "--provenance-output",
		},
		{
			name:      "duplicate interactive sudo",
			args:      []string{"--ssh-target", "host", "--interactive-sudo", "--interactive-sudo"},
			duplicate: "--interactive-sudo",
		},
		{
			name:      "duplicate keep staging on failure",
			args:      []string{"--ssh-target", "host", "--keep-staging-on-failure", "--keep-staging-on-failure"},
			duplicate: "--keep-staging-on-failure",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			artifactPaths := remoteAlphaOperatorRouteArtifactPaths(tc.artifactDirs...)
			before := snapshotPathExistence(t, artifactPaths...)

			output := requireRemoteAlphaOperatorFailure(t, append([]string{"es-writable-state-readiness-check"}, tc.args...)...)
			assertContainsAll(t, "duplicate route flag refusal", output,
				"duplicate option for es-writable-state-readiness-check: "+tc.duplicate,
				"No helper execution routing occurred.",
			)
			assertContainsNone(t, "duplicate route flag refusal", output,
				"Remote Alpha operator route: es-writable-state-readiness-check",
				"scripts/remote_alpha_stage_es_writable_state_readiness_check.sh --ssh-target",
			)
			assertNoNewPaths(t, "duplicate route flag refusal", before)
		})
	}
}

func TestRemoteAlphaOperatorWritableStateRouteRejectsSecretLikeArgsBeforeRouting(t *testing.T) {
	for _, args := range [][]string{
		{"--api-key=dummy"},
		{"--api-key", "dummy"},
		{"--root-token", "dummy"},
		{"--unseal-key", "dummy"},
		{"--client-token", "dummy"},
		{"--vault-token", "dummy"},
		{"--jwt-svid", "dummy"},
		{"--private-key", "dummy"},
		{"--password", "dummy"},
		{"--secret", "dummy"},
	} {
		t.Run(strings.Join(args, "_"), func(t *testing.T) {
			output := requireRemoteAlphaOperatorFailure(t, append([]string{"es-writable-state-readiness-check"}, args...)...)
			assertContainsAll(t, "route secret flag refusal", output,
				"secret material must never be passed by CLI args/env/logs/reports/artifacts",
			)
			assertContainsNone(t, "route secret flag refusal", output,
				"Remote Alpha operator route: es-writable-state-readiness-check",
				"scripts/remote_alpha_stage_es_writable_state_readiness_check.sh --ssh-target",
			)
		})
	}
}

func TestRemoteAlphaOperatorReadinessSessionRejectsUnsafeArgsBeforeRouting(t *testing.T) {
	docs := mustRead(t, ".docs/system_overview/remote_supported_host_alpha.md")
	assertContainsAll(t, "P0f readiness-session docs", docs,
		"`Bounded slice rule`: P0f implements exactly one Remote Alpha operator",
		"`scripts/remote_alpha_operator.sh readiness-session`",
		"delegates only through the existing readiness route/helper path",
		"`--apply`",
		"`--dry-run`",
		"equals-form options",
		"secret-like arguments",
	)

	for _, tc := range []struct {
		name     string
		args     []string
		required []string
	}{
		{
			name: "missing ssh target",
			args: []string{},
			required: []string{
				"readiness-session requires --ssh-target <target>",
				"No readiness route execution occurred.",
			},
		},
		{
			name: "apply forbidden",
			args: []string{"--apply"},
			required: []string{
				"readiness-session forbids --apply",
				"check-only/non-mutating",
				"No readiness route execution occurred.",
			},
		},
		{
			name: "dry run forbidden",
			args: []string{"--dry-run"},
			required: []string{
				"readiness-session forbids --dry-run",
				"delegated route does not expose a documented dry-run mode",
				"No readiness route execution occurred.",
			},
		},
		{
			name: "invalid mode",
			args: []string{"--mode", "invalid"},
			required: []string{
				"unsupported --mode for readiness-session: invalid",
				"No readiness route execution occurred.",
			},
		},
		{
			name: "unknown flag",
			args: []string{"--unknown-flag"},
			required: []string{
				"unknown option for readiness-session: --unknown-flag",
				"No readiness route execution occurred.",
			},
		},
		{
			name: "positional",
			args: []string{"positional"},
			required: []string{
				"unexpected positional argument for readiness-session: positional",
				"No readiness route execution occurred.",
			},
		},
		{
			name: "missing run id",
			args: []string{"--run-id"},
			required: []string{
				"--run-id requires a value",
				"No readiness route execution occurred.",
			},
		},
		{
			name: "equals form",
			args: []string{"--mode=alpha-compat"},
			required: []string{
				"readiness-session does not accept equals-form options: --mode=alpha-compat",
				"No readiness route execution occurred.",
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			output := requireRemoteAlphaOperatorFailure(t, append([]string{"readiness-session"}, tc.args...)...)
			assertContainsAll(t, "readiness-session refusal", output, tc.required...)
		})
	}

	output := requireRemoteAlphaOperatorFailure(t, "--ssh-alias=alias", "readiness-session", "--ssh-target", "host")
	assertContainsAll(t, "readiness-session top-level equals-form refusal", output,
		"readiness-session does not accept top-level printed-command options before the subcommand: --ssh-alias",
		"No readiness route execution occurred.",
	)
	assertContainsNone(t, "readiness-session top-level equals-form refusal", output,
		"Readiness session artifact metadata",
		"remote-alpha-live-refresh",
		"remote-alpha-live-support-bundle",
	)
}

func TestRemoteAlphaOperatorReadinessSessionRejectsDuplicateArgsBeforeRouting(t *testing.T) {
	for _, tc := range []struct {
		name      string
		args      []string
		duplicate string
	}{
		{
			name:      "duplicate ssh target",
			args:      []string{"--ssh-target", "a", "--ssh-target", "b"},
			duplicate: "--ssh-target",
		},
		{
			name:      "duplicate mode",
			args:      []string{"--ssh-target", "host", "--mode", "alpha-compat", "--mode", "future-non-root-required"},
			duplicate: "--mode",
		},
		{
			name:      "duplicate output dir",
			args:      []string{"--ssh-target", "host", "--output-dir", ".out/a", "--output-dir", ".out/b"},
			duplicate: "--output-dir",
		},
		{
			name:      "duplicate run id",
			args:      []string{"--ssh-target", "host", "--run-id", "a", "--run-id", "b"},
			duplicate: "--run-id",
		},
		{
			name:      "duplicate interactive sudo",
			args:      []string{"--ssh-target", "host", "--interactive-sudo", "--interactive-sudo"},
			duplicate: "--interactive-sudo",
		},
		{
			name:      "duplicate keep staging",
			args:      []string{"--ssh-target", "host", "--keep-staging-on-failure", "--keep-staging-on-failure"},
			duplicate: "--keep-staging-on-failure",
		},
		{
			name:      "duplicate ssh alias",
			args:      []string{"--ssh-target", "host", "--ssh-alias", "a", "--ssh-alias", "b"},
			duplicate: "--ssh-alias",
		},
		{
			name:      "duplicate im profile dir",
			args:      []string{"--ssh-target", "host", "--im-profile-dir", "a", "--im-profile-dir", "b"},
			duplicate: "--im-profile-dir",
		},
		{
			name:      "duplicate support output root",
			args:      []string{"--ssh-target", "host", "--support-output-root", "a", "--support-output-root", "b"},
			duplicate: "--support-output-root",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			output := requireRemoteAlphaOperatorFailure(t, append([]string{"readiness-session"}, tc.args...)...)
			assertContainsAll(t, "duplicate readiness-session flag refusal", output,
				"duplicate option for readiness-session: "+tc.duplicate,
				"No readiness route execution occurred.",
			)
			assertContainsNone(t, "duplicate readiness-session flag refusal", output,
				"Readiness session artifact metadata",
				"remote-alpha-live-refresh",
				"remote-alpha-live-support-bundle",
			)
		})
	}
}

func TestRemoteAlphaOperatorReadinessSessionRejectsSecretLikeArgsBeforeRouting(t *testing.T) {
	for _, args := range [][]string{
		{"--api-key=dummy"},
		{"--api-key", "dummy"},
		{"--root-token", "dummy"},
		{"--unseal-key", "dummy"},
		{"--client-token", "dummy"},
		{"--vault-token", "dummy"},
		{"--jwt-svid", "dummy"},
		{"--private-key", "dummy"},
		{"--password", "dummy"},
		{"--secret", "dummy"},
	} {
		t.Run(strings.Join(args, "_"), func(t *testing.T) {
			output := requireRemoteAlphaOperatorFailure(t, append([]string{"readiness-session"}, args...)...)
			assertContainsAll(t, "readiness-session secret flag refusal", output,
				"secret material must never be passed by CLI args/env/logs/reports/artifacts",
			)
			assertContainsNone(t, "readiness-session secret flag refusal", output,
				"Readiness session artifact metadata",
				"remote-alpha-live-refresh",
				"remote-alpha-live-support-bundle",
			)
		})
	}
}

func TestRemoteAlphaOperatorUnknownSubcommandRefuses(t *testing.T) {
	output := requireRemoteAlphaOperatorFailure(t, "definitely-unknown")
	assertContainsAll(t, "unknown subcommand refusal", output,
		"unknown subcommand",
		"definitely-unknown",
		"not implemented in P0s",
		"later audited slice",
	)
}

func TestRemoteAlphaOperatorSourceLimitsP0kDelegationSurface(t *testing.T) {
	source := mustRead(t, remoteAlphaOperatorScriptPath())
	assertContainsAll(t, "operator source", source,
		"set -euo pipefail",
		"set +x",
		`SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"`,
		`REMOTE_ALPHA_ES_WRITABLE_STATE_READINESS_HELPER="${SCRIPT_DIR}/remote_alpha_stage_es_writable_state_readiness_check.sh"`,
		`REMOTE_ALPHA_VAULT_RESET_HELPER="${SCRIPT_DIR}/remote_alpha_reset_disposable_vault.sh"`,
		`REMOTE_ALPHA_VAULT_WORKLOAD_AUTH_PUBLIC_HELPER="${SCRIPT_DIR}/remote_alpha_vault_workload_auth_check.sh"`,
		`REMOTE_ALPHA_VAULT_WORKLOAD_AUTH_INTERNAL_HELPER="${SCRIPT_DIR}/internal/remote_alpha_vault_workload_auth_check.sh"`,
		`REMOTE_ALPHA_RUNTIME_IDENTITY_SUMMARY_HELPER="${SCRIPT_DIR}/remote_alpha_runtime_identity_helper_summary.sh"`,
		`REMOTE_ALPHA_ES_SERVICE_TLS_RENEW_PUBLIC_HELPER="${SCRIPT_DIR}/remote_alpha_es_service_tls_renew.sh"`,
		`REMOTE_ALPHA_ES_SERVICE_TLS_RENEW_INTERNAL_HELPER="${SCRIPT_DIR}/internal/remote_alpha_es_service_tls_renew.sh"`,
		`REMOTE_ALPHA_OPERATOR_HEALTHCHECK_TLS_RENEW_PUBLIC_HELPER="${SCRIPT_DIR}/remote_alpha_operator_healthcheck_tls_renew.sh"`,
		`REMOTE_ALPHA_OPERATOR_HEALTHCHECK_TLS_RENEW_INTERNAL_HELPER="${SCRIPT_DIR}/internal/remote_alpha_operator_healthcheck_tls_renew.sh"`,
		`REMOTE_ALPHA_ES_GOVERNANCE_TLS_RENEW_STAGE_ROOT="/tmp/execution-substrate-remote-alpha-es-governance-tls-renew"`,
		`REMOTE_ALPHA_OPERATOR_HEALTHCHECK_TLS_RENEW_STAGE_ROOT="/tmp/execution-substrate-remote-alpha-operator-healthcheck-tls-renew"`,
		`REMOTE_ALPHA_VAULT_UNSEAL_STAGE_ROOT="/tmp/execution-substrate-remote-alpha-vault-unseal-existing"`,
		`REMOTE_ALPHA_VAULT_RESET_DRY_RUN_STAGE_ROOT="/tmp/execution-substrate-remote-alpha-vault-reset-disposable-dry-run"`,
		`REMOTE_ALPHA_VAULT_WORKLOAD_AUTH_STAGE_ROOT="/tmp/execution-substrate-remote-alpha-vault-workload-auth-check"`,
		`REMOTE_ALPHA_RUNTIME_IDENTITY_SUMMARY_STAGE_ROOT="/tmp/execution-substrate-remote-alpha-runtime-identity-summary"`,
		`REMOTE_ALPHA_ES_SERVICE_TLS_RENEW_STAGE_ROOT="/tmp/execution-substrate-remote-alpha-es-service-tls-renew"`,
		`exec "${REMOTE_ALPHA_ES_WRITABLE_STATE_READINESS_HELPER}" "${helper_args[@]}"`,
		`exec "${REMOTE_ALPHA_VAULT_RESET_HELPER}" "--unseal-only"`,
		`scp "${REMOTE_ALPHA_VAULT_RESET_HELPER}" "${ssh_target}:${remote_helper_path}"`,
		`scp "${REMOTE_ALPHA_VAULT_WORKLOAD_AUTH_PUBLIC_HELPER}" "${ssh_target}:${remote_public_helper_path}"`,
		`scp "${REMOTE_ALPHA_VAULT_WORKLOAD_AUTH_INTERNAL_HELPER}" "${ssh_target}:${remote_internal_helper_path}"`,
		`scp "${REMOTE_ALPHA_RUNTIME_IDENTITY_SUMMARY_HELPER}" "${ssh_target}:${remote_helper_path}"`,
		`scp "${REMOTE_ALPHA_ES_SERVICE_TLS_RENEW_PUBLIC_HELPER}" "${ssh_target}:${remote_public_helper_path}"`,
		`scp "${REMOTE_ALPHA_ES_SERVICE_TLS_RENEW_INTERNAL_HELPER}" "${ssh_target}:${remote_internal_helper_path}"`,
		`scp "${REMOTE_ALPHA_OPERATOR_HEALTHCHECK_TLS_RENEW_PUBLIC_HELPER}" "${ssh_target}:${remote_public_helper_path}"`,
		`scp "${REMOTE_ALPHA_OPERATOR_HEALTHCHECK_TLS_RENEW_INTERNAL_HELPER}" "${ssh_target}:${remote_internal_helper_path}"`,
		`"${helper_path}" --unseal-only`,
		`"${helper_path}" --dry-run`,
		`recovery_session_vault_workload_auth_check`,
		`recovery_session_vault_workload_auth_check_remote`,
		`recovery_session_vault_workload_auth_bootstrap`,
		`recovery_session_runtime_identity_summary`,
		`recovery_session_runtime_identity_summary_remote`,
		`recovery_session_es_service_tls`,
		`recovery_session_es_service_tls_remote`,
		`recovery_session_es_governance_tls`,
		`recovery_session_es_governance_tls_remote`,
		`recovery_session_operator_healthcheck_tls`,
		`recovery_session_operator_healthcheck_tls_remote`,
		`ssh -tt "${ssh_target}"`,
		`es-writable-state-readiness-check)`,
		`route_es_writable_state_readiness_check ${subcommand_args[@]+"${subcommand_args[@]}"}`,
		`readiness-session)`,
		`readiness_session ${subcommand_args[@]+"${subcommand_args[@]}"}`,
		`"${SCRIPT_DIR}/remote_alpha_operator.sh" "${route_args[@]}"`,
		`recovery-session)`,
		`recovery_session ${subcommand_args[@]+"${subcommand_args[@]}"}`,
		`recovery_session_evidence_check`,
		`recovery_session_vault_unseal_existing`,
		`recovery_session_vault_unseal_existing_remote`,
		`recovery_session_vault_reset_disposable`,
		`recovery_session_vault_reset_disposable_remote`,
	)
	assertContainsNone(t, "operator source forbidden helper routing", source,
		`source "${`,
		". scripts/",
		"helper-name",
		"helper_name",
		"helper_path_from_user",
		"remote_alpha_stage_es_config_tls_prep.sh",
		"remote_alpha_deploy_es_binaries.sh",
		"remote_alpha_prepare_es_writable_state_ownership.sh",
		"remote_alpha_migrate_es_service_user.sh",
		"remote_alpha_stage_es_service_user",
		"remote_alpha_stage_es_binaries",
		"--summary-output",
		"operator-summary",
		"readiness-session-summary",
		"recovery-session-summary",
	)

	for _, helper := range []string{
		"remote_alpha_migrate_vault_service_user.sh",
	} {
		for lineNumber, line := range strings.Split(source, "\n") {
			if !strings.Contains(line, helper) {
				continue
			}
			trimmed := strings.TrimSpace(line)
			if !strings.HasPrefix(trimmed, "\"") {
				t.Fatalf("operator source line %d references %s outside static printed inventory: %s", lineNumber+1, helper, line)
			}
			if strings.Contains(trimmed, "exec ") || strings.Contains(trimmed, "$(") || strings.Contains(trimmed, "`") {
				t.Fatalf("operator source line %d appears to route helper %s: %s", lineNumber+1, helper, line)
			}
		}
	}

	unsealStart := strings.Index(source, "recovery_session_vault_unseal_existing_require_command() {")
	if unsealStart == -1 {
		t.Fatalf("operator source missing vault-unseal-existing function")
	}
	unsealEnd := strings.Index(source[unsealStart:], "\nrecovery_session_vault_reset_disposable_require_command() {")
	if unsealEnd == -1 {
		t.Fatalf("operator source missing end boundary for vault-unseal-existing function")
	}
	unsealFunction := source[unsealStart : unsealStart+unsealEnd]
	assertContainsAll(t, "vault-unseal-existing source", unsealFunction,
		`exec "${REMOTE_ALPHA_VAULT_RESET_HELPER}" "--unseal-only"`,
		`scp "${REMOTE_ALPHA_VAULT_RESET_HELPER}" "${ssh_target}:${remote_helper_path}"`,
		`"${helper_path}" --unseal-only`,
		`require_recovery_option_not_seen "$1" "${host_local_seen}"`,
		`require_recovery_option_not_seen "$1" "${ssh_target_seen}"`,
		`require_recovery_option_not_seen "$1" "${interactive_tty_seen}"`,
		`recovery_die "recovery-session vault-unseal-existing requires --host-local or --ssh-target`,
	)
	assertContainsNone(t, "vault-unseal-existing source forbidden execution surfaces", unsealFunction,
		`"--execute-reset"`,
		`"--post-unseal-check"`,
		"tee ",
		"script ",
		"transcript",
		".out",
		"operator-summary",
		"readiness-session-summary",
		"recovery-session-summary",
		"scripts/internal/",
		"remote_alpha_vault_workload_auth_check.sh",
		"remote_alpha_runtime_identity_helper_summary.sh",
		"remote_alpha_migrate_vault_service_user.sh",
		"remote-alpha-live-refresh",
		"remote-alpha-live-support-bundle",
	)

	resetStart := strings.Index(source, "recovery_session_vault_reset_disposable_require_command() {")
	if resetStart == -1 {
		t.Fatalf("operator source missing vault-reset-disposable function")
	}
	resetEnd := strings.Index(source[resetStart:], "\nrecovery_session_vault_workload_auth_check_require_command() {")
	if resetEnd == -1 {
		t.Fatalf("operator source missing end boundary for vault-reset-disposable function")
	}
	resetFunction := source[resetStart : resetStart+resetEnd]
	assertContainsAll(t, "vault-reset-disposable source", resetFunction,
		`REMOTE_ALPHA_VAULT_RESET_DRY_RUN_STAGE_ROOT`,
		`REMOTE_ALPHA_VAULT_RESET_EXECUTE_STAGE_ROOT`,
		`recovery_session_vault_reset_disposable_require_local_tty`,
		`scp "${REMOTE_ALPHA_VAULT_RESET_HELPER}" "${ssh_target}:${remote_helper_path}"`,
		`"${helper_path}" --dry-run`,
		`"${helper_path}" --execute-reset`,
		`ssh "${ssh_target}"`,
		`ssh -tt "${ssh_target}"`,
		`require_recovery_option_not_seen "$1" "${ssh_target_seen}"`,
		`require_recovery_option_not_seen "$1" "${dry_run_seen}"`,
		`require_recovery_option_not_seen "$1" "${execute_reset_seen}"`,
		`require_recovery_option_not_seen "$1" "${interactive_tty_seen}"`,
		`recovery_die "recovery-session vault-reset-disposable requires --ssh-target`,
		`recovery_die "recovery-session vault-reset-disposable requires --dry-run or --execute-reset"`,
		`recovery_die "recovery-session vault-reset-disposable --execute-reset requires --interactive-tty"`,
	)
	assertContainsNone(t, "vault-reset-disposable source forbidden execution surfaces", resetFunction,
		`"--unseal-only"`,
		`"--post-unseal-check"`,
		"operator-summary",
		"readiness-session-summary",
		"recovery-session-summary",
		"scripts/internal/",
		"remote_alpha_vault_workload_auth_check.sh",
		"remote_alpha_runtime_identity_helper_summary.sh",
		"remote_alpha_migrate_vault_service_user.sh",
		"remote-alpha-live-refresh",
		"remote-alpha-live-support-bundle",
	)

	liveCommand := regexp.MustCompile(`(^|[;&|()]|\bthen\b|\bdo\b)\s*(sudo|ssh|scp|vault|nomad|docker|spire|systemctl)(\s|$|[;&|()<>])`)
	for lineNumber, line := range strings.Split(source, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if liveCommand.MatchString(trimmed) {
			if strings.HasPrefix(trimmed, `ssh "${ssh_target}"`) || strings.HasPrefix(trimmed, `ssh -tt "${ssh_target}"`) || strings.HasPrefix(trimmed, `scp "${REMOTE_ALPHA_VAULT_RESET_HELPER}"`) || strings.HasPrefix(trimmed, `scp "${REMOTE_ALPHA_VAULT_WORKLOAD_AUTH_PUBLIC_HELPER}"`) || strings.HasPrefix(trimmed, `scp "${REMOTE_ALPHA_VAULT_WORKLOAD_AUTH_INTERNAL_HELPER}"`) || strings.HasPrefix(trimmed, `scp "${REMOTE_ALPHA_VAULT_WORKLOAD_AUTH_BOOTSTRAP_PUBLIC_HELPER}"`) || strings.HasPrefix(trimmed, `scp "${REMOTE_ALPHA_VAULT_WORKLOAD_AUTH_BOOTSTRAP_INTERNAL_HELPER}"`) || strings.HasPrefix(trimmed, `scp "${REMOTE_ALPHA_RUNTIME_IDENTITY_SUMMARY_HELPER}"`) || strings.HasPrefix(trimmed, `scp "${REMOTE_ALPHA_ES_SERVICE_TLS_RENEW_PUBLIC_HELPER}"`) || strings.HasPrefix(trimmed, `scp "${REMOTE_ALPHA_ES_SERVICE_TLS_RENEW_INTERNAL_HELPER}"`) || strings.HasPrefix(trimmed, `scp "${REMOTE_ALPHA_OPERATOR_HEALTHCHECK_TLS_RENEW_PUBLIC_HELPER}"`) || strings.HasPrefix(trimmed, `scp "${REMOTE_ALPHA_OPERATOR_HEALTHCHECK_TLS_RENEW_INTERNAL_HELPER}"`) {
				continue
			}
			if strings.HasPrefix(trimmed, `sudo -v -p "Remote Alpha OS sudo password for summary path preparation: "`) || strings.HasPrefix(trimmed, `sudo -v -p "Remote Alpha OS sudo password for config readability preparation: "`) || strings.HasPrefix(trimmed, `sudo -v -p "Remote Alpha OS sudo password for SPIRE bundle-read preparation: "`) || strings.HasPrefix(trimmed, `sudo -n "$@"`) || strings.HasPrefix(trimmed, `sudo -n test "${predicate}" "${path}"`) {
				continue
			}
			if strings.HasPrefix(trimmed, `systemctl is-active --quiet spire-server`) {
				continue
			}
			t.Fatalf("operator source line %d appears to invoke a live tool: %s", lineNumber+1, line)
		}
	}

	liveIMCommand := regexp.MustCompile(`^\s*(PYTHONPATH=.*infra_manager\.cli|python3\s+-m\s+infra_manager\.cli|infra_manager\.cli)(\s|$)`)
	for lineNumber, line := range strings.Split(source, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if liveIMCommand.MatchString(trimmed) {
			t.Fatalf("operator source line %d appears to invoke IM directly: %s", lineNumber+1, line)
		}
	}

	captureCommand := regexp.MustCompile(`(^|[;&|()]|\bthen\b|\bdo\b)\s*(tee|script)(\s|$|[;&|()<>])`)
	for lineNumber, line := range strings.Split(source, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if captureCommand.MatchString(trimmed) {
			t.Fatalf("operator source line %d appears to invoke transcript capture: %s", lineNumber+1, line)
		}
	}
}
