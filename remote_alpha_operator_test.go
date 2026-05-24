package executionsubstrate_test

import (
	"crypto/sha256"
	"fmt"
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

func TestRemoteAlphaOperatorExistsExecutableAndHelpDocumentsP0jScope(t *testing.T) {
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
		"P0j adds recovery-session vault-unseal-existing as an explicit Mac-side interactive TTY route while preserving the P0i host-local fallback",
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
		"supports --plan, --inventory, --next-steps",
		"writes no summary",
		"preserves es-writable-state-readiness.json",
		"es-writable-state-readiness-helper-staging-record.json",
		"--profile-dir .out/remote-alpha-m75q",
		"--output-root .out/remote-alpha-m75q/support-bundles",
		"--ssh-alias host_to_remote_linux_m75q",
		"does not invoke IM refresh or support-bundle collection",
		"does not add reset execution, Vault workload-auth, runtime identity, service-user, config/TLS, binary deployment, writable-state ownership, or generic helper dispatch",
	)
}

func TestRemoteAlphaOperatorInventoryClassifiesImplementedFutureAndBlockedSurfaces(t *testing.T) {
	inventory := requireRemoteAlphaOperatorSuccess(t, "inventory")
	assertContainsAll(t, "operator inventory", inventory,
		"implemented through P0j",
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
		"stages only scripts/remote_alpha_reset_disposable_vault.sh",
		"invokes only --unseal-only through ssh -tt",
		"no transcript",
		"secret-sensitive",
		"non-destructive",
		"future/not implemented",
		"Vault destructive reset execution",
		"workload-auth check",
		"runtime identity summary generation",
		"Vault service-user check/apply execution",
		"other staged ES helper delegation",
		"blocked/reopened",
		"vault-workload-auth-bootstrap",
		"bounded proof/support helper",
		"evidence/projection only",
		"no authority source",
		"implemented, future, and blocked entries are operator-workflow/evidence surfaces, not authority surfaces",
		"interactive operator involvement is expected where an explicit mode says so",
		"IM refresh and support-bundle steps remain separate IM evidence/provenance actions unless a later reviewed contract says otherwise",
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
				"not implemented in P0j",
				"later audited slice",
				"No helper execution routing occurred.",
			)
		})
	}

	output := requireRemoteAlphaOperatorFailure(t, "vault-workload-auth-bootstrap")
	assertContainsAll(t, "bootstrap refusal", output,
		"vault-workload-auth-bootstrap",
		"blocked/reopened",
		"not available in v1",
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
		"P0j scope: safe/local recovery planning and evidence interpretation plus explicit vault-unseal-existing host-local and Mac-side interactive TTY modes",
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
		"Forbidden: --ssh-target, --interactive-sudo, --apply, --dry-run, --execute-reset, --unseal-only, --post-unseal-check, --governed-smoke-command",
		"recovery-session vault-unseal-existing --ssh-target <user@host> --interactive-tty",
		"prints no full JSON",
		"creates no summary file",
		"writes no .out",
	)

	defaultOutput := requireRemoteAlphaOperatorSuccess(t, "recovery-session")
	assertContainsAll(t, "default recovery-session plan", defaultOutput,
		"Remote Alpha recovery-session plan",
		"default behavior: print this plan/help and exit zero; no live tools run",
		"inventory/status - safe local planning and static inventory only",
		"evidence-check - local-only metadata check",
		"next-steps - print readiness-session and IM command text only",
		"vault-unseal-existing --host-local - implemented host-local operator mode for the Linux Remote Alpha host; secret-sensitive but non-destructive",
		"vault-unseal-existing --ssh-target <target> --interactive-tty - implemented Mac-side operator mode",
		"invokes only --unseal-only over ssh -tt",
		"disposable reset - future destructive exact-phrase mode",
		"workload-auth check execution - future audited live check",
		"runtime identity summary generation - future audited evidence route",
		"service-user check/apply - remains separate",
		"recovery-session does not execute IM",
		"not ES Vault token brokerage",
		"no destructive reset/workload-auth/runtime-identity/service-user execution route is added in P0j",
		"vault-unseal-existing does not validate default noninteractive readiness",
	)

	plan := requireRemoteAlphaOperatorSuccess(t, "recovery-session", "--plan")
	assertContainsAll(t, "recovery-session plan", plan,
		"Remote Alpha recovery-session plan",
		"implemented safe/local or explicitly host-local",
		"vault-unseal-existing --host-local",
		"future explicit audited slices",
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
		"scripts/remote_alpha_reset_disposable_vault.sh --execute-reset",
		"scripts/remote_alpha_vault_workload_auth_check.sh",
		"scripts/remote_alpha_runtime_identity_helper_summary.sh",
		"scripts/remote_alpha_migrate_vault_service_user.sh --check-only",
		"scripts/remote_alpha_operator.sh readiness-session",
		"recovery-session vault-unseal-existing --host-local",
		"recovery-session vault-unseal-existing --ssh-target <target> --interactive-tty",
		"implemented host-local explicit operator mode",
		"implemented Mac-side explicit operator mode",
		"invokes only --unseal-only through ssh -tt",
		"secret-sensitive",
		"non-destructive",
		"classifications present: safe/local, check-only, secret-sensitive, destructive, future, blocked/reopened",
		"vault-workload-auth-bootstrap - blocked/reopened",
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
			required: []string{"recovery-session forbids --ssh-target", "safe/local/print-only/evidence-check plus explicit vault-unseal-existing submodes", "No recovery-session live helper or IM execution occurred."},
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
		"not implemented in P0j",
		"later audited slice",
	)
}

func TestRemoteAlphaOperatorSourceLimitsP0jDelegationSurface(t *testing.T) {
	source := mustRead(t, remoteAlphaOperatorScriptPath())
	assertContainsAll(t, "operator source", source,
		"set -euo pipefail",
		"set +x",
		`SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"`,
		`REMOTE_ALPHA_ES_WRITABLE_STATE_READINESS_HELPER="${SCRIPT_DIR}/remote_alpha_stage_es_writable_state_readiness_check.sh"`,
		`REMOTE_ALPHA_VAULT_RESET_HELPER="${SCRIPT_DIR}/remote_alpha_reset_disposable_vault.sh"`,
		`REMOTE_ALPHA_VAULT_UNSEAL_STAGE_ROOT="/tmp/execution-substrate-remote-alpha-vault-unseal-existing"`,
		`exec "${REMOTE_ALPHA_ES_WRITABLE_STATE_READINESS_HELPER}" "${helper_args[@]}"`,
		`exec "${REMOTE_ALPHA_VAULT_RESET_HELPER}" "--unseal-only"`,
		`scp "${REMOTE_ALPHA_VAULT_RESET_HELPER}" "${ssh_target}:${remote_helper_path}"`,
		`"${helper_path}" --unseal-only`,
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
	)
	assertContainsNone(t, "operator source forbidden helper routing", source,
		"scripts/internal/",
		"source ",
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
		"--summary-path",
		"--summary-output",
		"operator-summary",
		"readiness-session-summary",
		"recovery-session-summary",
	)

	for _, helper := range []string{
		"remote_alpha_runtime_identity_helper_summary.sh",
		"remote_alpha_vault_workload_auth_check.sh",
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
	unsealEnd := strings.Index(source[unsealStart:], "\nrecovery_session_evidence_check() {")
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

	liveCommand := regexp.MustCompile(`(^|[;&|()]|\bthen\b|\bdo\b)\s*(sudo|ssh|scp|vault|nomad|docker|spire|systemctl)(\s|$|[;&|()<>])`)
	for lineNumber, line := range strings.Split(source, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if liveCommand.MatchString(trimmed) {
			if strings.HasPrefix(trimmed, `ssh "${ssh_target}"`) || strings.HasPrefix(trimmed, `ssh -tt "${ssh_target}"`) || strings.HasPrefix(trimmed, `scp "${REMOTE_ALPHA_VAULT_RESET_HELPER}"`) {
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
}
