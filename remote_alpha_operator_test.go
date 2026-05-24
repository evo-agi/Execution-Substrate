package executionsubstrate_test

import (
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

func TestRemoteAlphaOperatorExistsExecutableAndHelpDocumentsP0fScope(t *testing.T) {
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
		"P0f adds one readiness-session workflow",
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
		"delegates only to scripts/remote_alpha_stage_es_writable_state_readiness_check.sh",
		"check-only/non-mutating",
		"requires --ssh-target",
		"runs the existing readiness route",
		"fresh output directory by default",
		"prints only non-secret artifact metadata",
		"preserves es-writable-state-readiness.json",
		"es-writable-state-readiness-helper-staging-record.json",
		"--profile-dir .out/remote-alpha-m75q",
		"--output-root .out/remote-alpha-m75q/support-bundles",
		"--ssh-alias host_to_remote_linux_m75q",
		"does not invoke IM refresh or support-bundle collection",
		"does not add reset/unseal, Vault workload-auth, runtime identity, service-user, config/TLS, binary deployment, writable-state ownership, or generic staging routes",
	)
}

func TestRemoteAlphaOperatorInventoryClassifiesImplementedFutureAndBlockedSurfaces(t *testing.T) {
	inventory := requireRemoteAlphaOperatorSuccess(t, "inventory")
	assertContainsAll(t, "operator inventory", inventory,
		"implemented through P0f",
		"help",
		"inventory",
		"print-refresh-command",
		"print-support-bundle-command",
		"print-im-commands",
		"es-writable-state-readiness-check",
		"readiness-session",
		"delegates to existing readiness staged helper",
		"runs the existing readiness route",
		"check-only/non-mutating",
		"preserves es-writable-state-readiness.json and es-writable-state-readiness-helper-staging-record.json",
		"prints non-secret paths, byte counts, SHA-256 digests, schemas, blocker/warning counts, and sudo/checker status",
		"future/not implemented",
		"Vault reset/unseal",
		"workload-auth check",
		"runtime identity summary",
		"Vault service-user check",
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
				"not implemented in P0f",
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
		"not implemented in P0f",
		"later audited slice",
	)
}

func TestRemoteAlphaOperatorSourceLimitsP0fDelegationSurface(t *testing.T) {
	source := mustRead(t, remoteAlphaOperatorScriptPath())
	assertContainsAll(t, "operator source", source,
		"set -euo pipefail",
		"set +x",
		`SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"`,
		`REMOTE_ALPHA_ES_WRITABLE_STATE_READINESS_HELPER="${SCRIPT_DIR}/remote_alpha_stage_es_writable_state_readiness_check.sh"`,
		`exec "${REMOTE_ALPHA_ES_WRITABLE_STATE_READINESS_HELPER}" "${helper_args[@]}"`,
		`es-writable-state-readiness-check)`,
		`route_es_writable_state_readiness_check ${subcommand_args[@]+"${subcommand_args[@]}"}`,
		`readiness-session)`,
		`readiness_session ${subcommand_args[@]+"${subcommand_args[@]}"}`,
		`"${SCRIPT_DIR}/remote_alpha_operator.sh" "${route_args[@]}"`,
	)
	assertContainsNone(t, "operator source forbidden helper routing", source,
		"scripts/internal/",
		"source ",
		". scripts/",
		"helper-name",
		"helper_name",
		"helper_path_from_user",
		"remote_alpha_reset_disposable_vault.sh",
		"remote_alpha_runtime_identity_helper_summary.sh",
		"remote_alpha_vault_workload_auth_check.sh",
		"remote_alpha_migrate_vault_service_user.sh",
		"remote_alpha_stage_es_config_tls_prep.sh",
		"remote_alpha_deploy_es_binaries.sh",
		"remote_alpha_prepare_es_writable_state_ownership.sh",
		"remote_alpha_migrate_es_service_user.sh",
		"--summary-path",
		"--summary-output",
		"operator-summary",
		"readiness-session-summary",
	)

	liveCommand := regexp.MustCompile(`(^|[;&|()]|\bthen\b|\bdo\b)\s*(sudo|ssh|scp|vault|nomad|docker|spire|systemctl)(\s|$|[;&|()<>])`)
	for lineNumber, line := range strings.Split(source, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if liveCommand.MatchString(trimmed) {
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
