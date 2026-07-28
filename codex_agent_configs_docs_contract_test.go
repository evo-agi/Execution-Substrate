package executionsubstrate_test

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

var codexAgentLocalAbsolutePathPatterns = []struct {
	label   string
	pattern *regexp.Regexp
}{
	{label: "local user absolute path", pattern: regexp.MustCompile(`(^|[^A-Za-z0-9])/(Users|home)/[^/\s]+(/|$)`)},
	{label: "local filesystem absolute path", pattern: regexp.MustCompile(`(^|[^A-Za-z0-9])/(var/folders|private|tmp|Volumes)(/|$)`)},
	{label: "Windows drive path", pattern: regexp.MustCompile(`(?i)(^|[^A-Za-z0-9])[A-Z]:\\`)},
	{label: "UNC path", pattern: regexp.MustCompile(`\\\\[^\\\s]+\\[^\\\s]+`)},
}

var codexAgentForbiddenPatterns = []struct {
	label   string
	pattern *regexp.Regexp
}{
	{label: "PEM block", pattern: regexp.MustCompile(`-----BEGIN(?: [A-Z ]+)?-----`)},
	{label: "private key marker", pattern: regexp.MustCompile(`BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY`)},
	{label: "certificate marker", pattern: regexp.MustCompile(`BEGIN CERTIFICATE`)},
	{label: "endpoint URL", pattern: regexp.MustCompile(`(?i)https?://|[a-z][a-z0-9+.-]*://`)},
	{label: "platform identifier", pattern: regexp.MustCompile(`(?i)\b(connector|tunnel|workspace|org)[_-][A-Za-z0-9]{6,}\b`)},
	{label: "token-shaped secret", pattern: regexp.MustCompile(`\bsk-[A-Za-z0-9_-]{20,}\b`)},
	{label: "secret environment assignment", pattern: regexp.MustCompile(`\b(OPENAI|ANTHROPIC|GITHUB|GH|VAULT|TOKEN|API_KEY|SECRET|PASSWORD)[A-Z0-9_]*\s*=`)},
	{label: "disallowed Codex override key", pattern: regexp.MustCompile(`(?m)^\s*(model|provider|auth|base_url|base-url|profile|telemetry|notification)\s*=`)},
	{label: "disallowed Codex override table", pattern: regexp.MustCompile(`(?m)^\s*\[(model|provider|auth|profile|telemetry|notification)[^\]]*\]\s*$`)},
	{label: "behavior-enabling flag", pattern: regexp.MustCompile(`(?i)allow_(push|auto_merge|real_write|real_codex_execution|shell_execution)\s*=\s*true`)},
}

func TestCodexAgentConfigsDocsContract(t *testing.T) {
	paths := assertCodexTreeAllowlist(t, []string{".codex/agents/es-boundary-auditor.toml"})

	requiredKeys := map[string]bool{
		"name":                   true,
		"description":            true,
		"developer_instructions": true,
	}
	requiredShared := []string{
		"Read-only by default",
		"Do not edit files unless the parent task explicitly authorizes edits",
		"Do not run live services",
		"remote commands",
		"Do not expose secrets",
		"project-scoped role definitions only",
		"not authority, credentials, approvals, execution capability",
		"not proof that every Codex surface can invoke custom agents by name",
		"source-grounded fact",
		"Codex-reported fact",
		"inference",
		"unresolved uncertainty",
		"repo-relative file paths and line references",
	}
	requiredClassifications := []string{
		"stable product boundary",
		"integration scaffolding",
		"blocked-seam evidence",
		"proof-harness containment",
		"compatibility edge",
		"future-design placeholder",
		"over-constrained candidate",
	}

	for _, path := range paths {
		raw := mustRead(t, path)
		keys := codexAgentParsedTopLevelKeys(t, raw)
		if unexpected := unapprovedCodexAgentTopLevelKeys(keys, requiredKeys); len(unexpected) > 0 {
			t.Fatalf("%s contains unapproved top-level keys or tables %v", path, unexpected)
		}
		if len(keys) != len(requiredKeys) {
			t.Fatalf("%s has unexpected top-level keys %v", path, keys)
		}
		assertContainsAll(t, path+" shared contract", raw, requiredShared...)
		assertContainsAll(t, path+" classifications", raw, requiredClassifications...)
		for _, forbidden := range codexAgentLocalAbsolutePathPatterns {
			if forbidden.pattern.MatchString(raw) {
				t.Fatalf("%s contains forbidden %s", path, forbidden.label)
			}
		}
		for _, forbidden := range codexAgentForbiddenPatterns {
			if forbidden.pattern.MatchString(raw) {
				t.Fatalf("%s contains forbidden %s", path, forbidden.label)
			}
		}
	}

	agent := mustRead(t, ".codex/agents/es-boundary-auditor.toml")
	assertContainsAll(t, "ES boundary auditor role", agent,
		"Workstream C admission, producer contract, prepare, submit, lifecycle, status, logs, result, cancel, and runtime-profile boundaries",
		"Current invariant",
		"operator-healthcheck TLS signer/custody",
		"Reopened redesign seam",
		"P0v operator-healthcheck TLS noninteractive status",
		"implemented read-only evidence/projection only",
		"not renewal",
		"not signer/custody resolution",
		"not ES runtime truth",
		"not MA/IM/CP/Bridge authority",
		"not permission to run live remote commands during an audit",
		"Remote Alpha proof and helper surfaces",
		"Temporary compatibility edge",
	)

	adr := mustRead(t, ".docs/system_overview/hybrid_integration_architecture_adr.md")
	assertContainsAll(t, "hybrid ADR repo-scoped Codex subagent note", compactText(adr),
		"Repo-Scoped Codex Subagent Role Definitions",
		"project-scoped role definitions only",
		"not authority, credentials, approvals, execution capability",
		"not proof that every Codex surface can invoke custom agents by name",
		"does not reopen accepted Workstream C admission/runtime boundaries",
		"does not resolve the operator-healthcheck TLS signer/custody seam",
	)
}

func TestCodexAgentParsedTopLevelKeysRejectTopLevelTables(t *testing.T) {
	raw := `name = "synthetic"
description = "Synthetic role."
developer_instructions = "Read-only."

[hooks]
pre_task = "blocked"
`
	keys := codexAgentParsedTopLevelKeys(t, raw)
	if !stringSliceContains(keys, "hooks") {
		t.Fatalf("parsed TOML keys did not expose top-level hooks table: %v", keys)
	}
	unexpected := unapprovedCodexAgentTopLevelKeys(keys, map[string]bool{
		"name":                   true,
		"description":            true,
		"developer_instructions": true,
	})
	if !stringSliceContains(unexpected, "hooks") {
		t.Fatalf("unapproved top-level keys did not include hooks table: %v", unexpected)
	}
}

func TestCodexAgentLocalAbsolutePathPatternCoverage(t *testing.T) {
	localPathSamples := []string{
		"/Users/alice/project",
		"/home/alice/project",
		"/var/folders/cache",
		"/private/tmp/file",
		"/tmp/file",
		"/Volumes/External/project",
		`C:\Users\alice\project`,
		`\\server\share\project`,
	}
	for _, sample := range localPathSamples {
		if !codexAgentLocalAbsolutePathDetected(sample) {
			t.Fatalf("local absolute path sample was not detected")
		}
	}

	apiRouteSamples := []string{"/v1/executions", "/execution/run/result"}
	for _, sample := range apiRouteSamples {
		if codexAgentLocalAbsolutePathDetected(sample) {
			t.Fatalf("API route sample was incorrectly detected as a local absolute path")
		}
	}
}

func assertCodexTreeAllowlist(t *testing.T, expectedPaths []string) []string {
	t.Helper()

	if _, err := os.Stat(".codex/config.toml"); !os.IsNotExist(err) {
		t.Fatalf(".codex/config.toml must not be added for role-only subagent configs")
	}
	if _, err := os.Stat(".codex/hooks"); !os.IsNotExist(err) {
		t.Fatalf(".codex/hooks must not be added for role-only subagent configs")
	}

	codexEntries, err := os.ReadDir(".codex")
	if err != nil {
		t.Fatalf("read .codex: %v", err)
	}
	var codexNames []string
	for _, entry := range codexEntries {
		codexNames = append(codexNames, entry.Name())
	}
	sort.Strings(codexNames)
	if got, want := strings.Join(codexNames, ","), "agents"; got != want {
		t.Fatalf(".codex contains unapproved entries: got %q want %q", got, want)
	}

	agentEntries, err := os.ReadDir(".codex/agents")
	if err != nil {
		t.Fatalf("read .codex/agents: %v", err)
	}
	var agentPaths []string
	var nestedDirs []string
	var nonTOMLFiles []string
	for _, entry := range agentEntries {
		rel := filepath.ToSlash(filepath.Join(".codex/agents", entry.Name()))
		if entry.IsDir() {
			nestedDirs = append(nestedDirs, rel)
			continue
		}
		if filepath.Ext(entry.Name()) != ".toml" {
			nonTOMLFiles = append(nonTOMLFiles, rel)
			continue
		}
		agentPaths = append(agentPaths, rel)
	}
	if len(nestedDirs) > 0 {
		t.Fatalf(".codex/agents contains nested directories: %v", nestedDirs)
	}
	if len(nonTOMLFiles) > 0 {
		t.Fatalf(".codex/agents contains non-TOML files: %v", nonTOMLFiles)
	}
	sort.Strings(agentPaths)
	sort.Strings(expectedPaths)
	if got, want := strings.Join(agentPaths, ","), strings.Join(expectedPaths, ","); got != want {
		t.Fatalf("unexpected Codex agent config set: got %q want %q", got, want)
	}
	return agentPaths
}

func codexAgentParsedTopLevelKeys(t *testing.T, raw string) []string {
	t.Helper()
	cmd := exec.Command("python3", "-c", "import json, sys, tomllib\nprint(json.dumps(sorted(tomllib.loads(sys.stdin.read()).keys())))\n")
	cmd.Stdin = strings.NewReader(raw)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Codex agent TOML parse failed: %v\n%s", err, string(output))
	}
	var keys []string
	if err := json.Unmarshal(output, &keys); err != nil {
		t.Fatalf("decode parsed Codex agent top-level keys: %v", err)
	}
	return keys
}

func unapprovedCodexAgentTopLevelKeys(keys []string, approved map[string]bool) []string {
	var unexpected []string
	for _, key := range keys {
		if !approved[key] {
			unexpected = append(unexpected, key)
		}
	}
	return unexpected
}

func codexAgentLocalAbsolutePathDetected(text string) bool {
	for _, pattern := range codexAgentLocalAbsolutePathPatterns {
		if pattern.pattern.MatchString(text) {
			return true
		}
	}
	return false
}

func stringSliceContains(values []string, needle string) bool {
	for _, value := range values {
		if value == needle {
			return true
		}
	}
	return false
}
