package executionsubstrate_test

import (
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
	"unicode"
)

// D2 re-derives Workstream D: the owner signs a standing policy that ES
// applies, EGS signs publisher admissions behind the owner's switch, and CGS
// is retired. These tests pin the contract that the later build steps
// implement, the Workstream D status line and exit criteria in PLANS.md that
// say when the workstream may close, and the rule that a working name is
// settled with the owner before code uses it.

const policyGovernanceContractPath = ".docs/system_overview/policy_governance_contract.md"

// TestPolicyGovernanceContractIsDocumented pins every sentence, list item and
// table row of the contract, in order (policyGovernanceContractText), and the
// cut-off subsection the contract cites, so that the contract cannot merge
// before the text it depends on.
func TestPolicyGovernanceContractIsDocumented(t *testing.T) {
	raw := mustRead(t, policyGovernanceContractPath)
	if !strings.HasPrefix(raw, "# Policy Governance Contract (D2)\n\n## 1. Purpose and status\n") {
		t.Fatal("the D2 contract must open with its title and section 1")
	}
	assertSectionIsExactly(t, "D2 contract", compactDocSection(t, raw, "## 1. Purpose and status", ""), policyGovernanceContractText)

	// Section 16 is what the build steps are held to: name the row count in
	// the failure, not only the first differing sentence.
	rows := 0
	for _, line := range strings.Split(markedDocSection(t, "D2 acceptance tests", raw, "## 16. Acceptance tests", "## 17. Delivery"), "\n") {
		if strings.HasPrefix(line, "| ") && !strings.HasPrefix(line, "| Rule |") {
			rows++
		}
	}
	if rows != 28 {
		t.Fatalf("section 16 of the D2 contract has %d acceptance rows, want 28: change the contract and this test together", rows)
	}

	// The contract cites the workload cut-off of section 11.7 (exit
	// criterion 3 and section 17), so it holds only once that text exists.
	handoff := mustRead(t, ".docs/system_overview/runtime_identity_handoff.md")
	posture := markedDocSection(t, "F1 posture", handoff, "### 11.7 SPIRE and Vault posture", "### 11.8 Adding per-run identities later")
	if !strings.Contains(posture, "\n#### Cutting off one named workload\n") {
		t.Fatal("the D2 contract cites the cut-off of one named workload in section 11.7 of runtime_identity_handoff.md, which is missing: merge that text first")
	}
}

var (
	workstreamDStatusLine = regexp.MustCompile(`(?m)^Workstream D status: (open|closed)\.$`)
	workstreamDCriterion  = regexp.MustCompile(`(?m)^- \[( |x)\] `)
)

func TestWorkstreamDStatusAndExitCriteria(t *testing.T) {
	plansRaw := mustRead(t, "PLANS.md")
	plans := markedDocSection(t, "PLANS.md Workstream D", plansRaw, "### Workstream D - Policy And Authorization Reset", "### Workstream E - Lookup And Config Indirection Reset")

	assertContainsAll(t, "PLANS.md Workstream D scope", compactText(plans),
		"Purpose: - Re-derive policy and authorization ownership. D2, below, is that re-derivation.",
		"Target files and packages: those that D2's build steps change (contract section 17): ES's admission, policy state and revocation route under `es/`; `egs/`; AGS's evidence under `ags/`; ARS's index under `ars/`; the owner's tool; the recovery, migration and log export scripts; and `cgs/`, which is deleted.",
		"Success condition: the exit criteria below.",
		"Dependencies: - Workstream A - Workstream C - The open security work on caller identities, network grants, declared env keys and mounts, and per-host signing keys (contract section 17) - Workstream F's cut-off of one named workload (exit criterion 3)",
		"D2 re-derives this workstream, as the project owner decided: CGS is retired, the owner signs a standing policy that ES applies, and EGS signs publisher admissions that ES requires only while the owner's signed switch is on.",
		"[`.docs/system_overview/policy_governance_contract.md`](.docs/system_overview/policy_governance_contract.md)",
	)
	assertContainsAll(t, "PLANS.md reopened-seam exit criteria", compactDocSection(t, plansRaw, "## Reopened-Seam Exit Criteria", "## Document Scope And Current Implementation"),
		"- Policy and authorization ownership is settled: Workstream D's exit criteria hold.",
	)

	statuses := workstreamDStatusLine.FindAllStringSubmatch(plans, -1)
	if len(statuses) != 1 {
		t.Fatalf("PLANS.md Workstream D must hold exactly one line \"Workstream D status: open.\" or \"Workstream D status: closed.\", found %d", len(statuses))
	}
	criteria := workstreamDCriterion.FindAllStringSubmatch(plans, -1)
	open := 0
	for _, criterion := range criteria {
		if criterion[1] == " " {
			open++
		}
	}
	switch statuses[0][1] {
	case "open":
		if open == 0 {
			t.Fatal("PLANS.md says Workstream D is open, but every exit criterion is ticked: close it in the change that rewrites README.md (build step 13)")
		}
	case "closed":
		if open != 0 {
			t.Fatalf("PLANS.md says Workstream D is closed, but %d exit criteria are not ticked", open)
		}
	}

	// The exit criteria name every gap the D2 review left open, so that the
	// repository, not a note outside it, says when Workstream D may close.
	required := []string{
		"CGS is retired [1].",
		"Revoking an artifact, a signer, a publisher key, a caller name or a workload identity name through ES's revocation route (contract section 7) has a runbook, run once on the supported host [4, 10].",
		"Cutting off one named workload passed WI-3's tests (`.docs/system_overview/runtime_identity_handoff.md`, section 11.7).",
		"Recovery from a lost Vault unseal key and from a full re-setup is built [12]; each CI rehearsal passed once, both scripts ran end to end on a throwaway machine once, and `rehearsal-due` is raised when a rehearsal is overdue.",
		"AGS's signing key is in Vault's transit engine, and no file on the host holds it, backups included [11].",
		"The owner's rules are signed and applied by ES, and no host file changes them [2, 4, 6, 7, 10].",
		"An older validly signed policy or EGS list cannot be confirmed as current (`CP-ROLLBACK`) [2, 4, 8].",
		"ES starts without EGS, and service certificates renew automatically [4, 9].",
		"ES loads no unused verifier key, and `es.json` holds no `verification.trust_model` [4, 7, 10].",
		"The policy log and the run log are copied off the host every hour while the owner's workstation is awake, through the export account and the log anchor that step 10 installs [5, 6, 10].",
		"A signed standing revision requires the evidence fields of contract section 12 [3, 4].",
		"Every acceptance test of contract section 16 and the class-kind test of section 15 exist and fail on a version without their rule [4 to 12].",
		"The supported host runs steps 1 to 12; the migration run's report is linked here.",
		"`README.md` and its diagram describe this design, rewritten in the change that closes Workstream D [13].",
	}
	if len(criteria) != len(required) {
		t.Fatalf("PLANS.md Workstream D has %d exit criteria, want %d: change this list and the contract together", len(criteria), len(required))
	}
	compactPlans := compactText(plans)
	for _, criterion := range required {
		if !strings.Contains(compactPlans, "] "+criterion) {
			t.Errorf("PLANS.md Workstream D exit criteria lack %q", criterion)
		}
	}

	record := workstreamRecord(t, "D")
	assertContainsAll(t, "Workstream D record points to D2", record,
		"- D2, the re-derivation the project owner decided, is `.docs/system_overview/policy_governance_contract.md`.",
		"D2 supersedes the limits below that keep a future EGS contract to signer and artifact trust (D1b and D1c): EGS v2 signs publisher admissions under the owner's standing policy, as a new versioned contract.",
		"D2 retires CGS, so the future CGS v2 authorize contract that D1b describes is not built.",
		"The EGS v1 and CGS v1 surfaces below stay current behavior until D2's build steps 7 and 1 remove them.",
		"- D2 settles the seams that the checkpoint below keeps reopened: the CGS authorize DTO and `id.conf` go with CGS, and EGS v2 is the new versioned contract. The \"D2\" that the checkpoint names is a slice label from before this contract; as it says, Workstream E planning did not wait for it.",
	)
}

// policyGovernanceNamesPredating lists the uses of a working name that
// predate the D2 contract, by path and count. Each is a shell variable that
// holds the owner of the ES service user's Nomad token, not the owner's tool.
// A new use anywhere else, or one more use here, fails the test.
var policyGovernanceNamesPredating = map[string]int{
	"scripts/01_bringup.sh":      4,
	"scripts/nomad_acl_setup.sh": 5,
}

// identifierWords splits text into lower-case words: at every character that
// is not a letter or a digit, inside a word at each change from a lower-case
// letter or a digit to a capital, and before the last capital of a run of
// capitals that a lower-case letter follows. ESOwner, es_owner, es-owner and
// ES_OWNER all give the words "es" and "owner".
func identifierWords(text string) []string {
	var words []string
	runes := []rune(text)
	start := -1
	flush := func(end int) {
		if start >= 0 && end > start {
			words = append(words, strings.ToLower(string(runes[start:end])))
		}
		start = -1
	}
	for i, r := range runes {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) {
			flush(i)
			continue
		}
		if start < 0 {
			start = i
			continue
		}
		previous := runes[i-1]
		lowerToUpper := unicode.IsUpper(r) && (unicode.IsLower(previous) || unicode.IsDigit(previous))
		capitalRunEnds := unicode.IsUpper(r) && unicode.IsUpper(previous) && i+1 < len(runes) && unicode.IsLower(runes[i+1])
		if lowerToUpper || capitalRunEnds {
			flush(i)
			start = i
		}
	}
	flush(len(runes))
	return words
}

// namePattern is a working name as code could spell it: its words joined, in
// any letter case, with or without separators between them.
type namePattern struct {
	row    string
	joined string
}

// countNameUses counts the places in text where consecutive words join to
// the name, so that "UseEgs", "use-egs", "useegs" and "ES_USE_EGS" each count
// once for use_egs, and "rules_owner" does not count for es-owner.
func countNameUses(words []string, joined string) int {
	count := 0
	for i := range words {
		built := ""
		for j := i; j < len(words) && len(built) < len(joined); j++ {
			built += words[j]
			if !strings.HasPrefix(joined, built) {
				break
			}
			if built == joined {
				count++
				break
			}
		}
	}
	return count
}

// workingNamePatterns reads section 2 of the contract: each row names one
// or more working names, comma-separated, and a format name drops its
// "/v1" version.
func workingNamePatterns(t *testing.T) []namePattern {
	t.Helper()
	names := markedDocSection(t, "D2 names", mustRead(t, policyGovernanceContractPath), "## 2. Names", "## 3. Who vouches for what")
	var patterns []namePattern
	for _, line := range strings.Split(names, "\n") {
		if !strings.HasPrefix(line, "| ") || strings.HasPrefix(line, "| Working name") || strings.HasPrefix(line, "| ---") {
			continue
		}
		row := strings.TrimPrefix(strings.Split(line, " | ")[0], "| ")
		for _, name := range strings.Split(row, ", ") {
			name = strings.Trim(name, "`")
			if slash := strings.Index(name, "/"); slash >= 0 {
				name = name[:slash]
			}
			joined := strings.Join(identifierWords(name), "")
			if joined == "" {
				t.Fatalf("section 2 of the D2 contract has a row with an empty name: %q", line)
			}
			patterns = append(patterns, namePattern{row: row, joined: joined})
		}
	}
	if len(patterns) > 0 && !strings.Contains(compactText(names), "The names below are working names.") {
		t.Fatal("section 2 of the D2 contract lists names but no longer says they are working names")
	}
	return patterns
}

// workingNameUses walks root and counts, per file, the uses of the patterns
// in the file's path below root and in its content. It skips .git, .docs,
// testdata and node_modules, Markdown files, Go test files and binary files.
func workingNameUses(t *testing.T, root string, patterns []namePattern) map[string]map[string]int {
	t.Helper()
	uses := map[string]map[string]int{}
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			switch entry.Name() {
			case ".git", ".docs", "testdata", "node_modules":
				return filepath.SkipDir
			}
			return nil
		}
		if !entry.Type().IsRegular() || strings.HasSuffix(path, "_test.go") || strings.EqualFold(filepath.Ext(path), ".md") {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if bytes.IndexByte(data, 0) >= 0 {
			return nil
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		relative = filepath.ToSlash(relative)
		pathWords := identifierWords(relative)
		contentWords := identifierWords(string(data))
		for _, pattern := range patterns {
			if n := countNameUses(pathWords, pattern.joined) + countNameUses(contentWords, pattern.joined); n > 0 {
				if uses[relative] == nil {
					uses[relative] = map[string]int{}
				}
				uses[relative][pattern.row] += n
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}
	return uses
}

func TestPolicyGovernanceWorkingNamesStayOutOfCode(t *testing.T) {
	patterns := workingNamePatterns(t)
	uses := workingNameUses(t, ".", patterns)

	paths := make([]string, 0, len(uses))
	for path := range uses {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	for _, path := range paths {
		for row, n := range uses[path] {
			if row == "`es-owner`" && n == policyGovernanceNamesPredating[path] {
				continue
			}
			t.Errorf("%s uses the working name %s %d time(s), in its path or content, in some letter case or spelling: settle the name with the owner first, then remove its row from section 2 of the D2 contract and update section 1's status in the same change", path, row, n)
		}
	}
	for path, want := range policyGovernanceNamesPredating {
		if got := uses[path]["`es-owner`"]; got != want {
			t.Errorf("policyGovernanceNamesPredating expects %d use(s) in %s, found %d: update the list to what predates the contract, never upward", want, path, got)
		}
	}
}

// TestPolicyGovernanceWorkingNamesGuardCatchesEverySpelling proves the guard
// against the spellings and places a build step would use first: a command
// directory, a script without an extension, a Go package, Go fields, JSON
// keys, upper-case environment names, Dockerfiles and nftables files.
func TestPolicyGovernanceWorkingNamesGuardCatchesEverySpelling(t *testing.T) {
	patterns := workingNamePatterns(t)
	probes := []struct {
		path    string
		content string
		row     string
	}{
		{"cmd/es-owner/main.go", "package main\n", "`es-owner`"},
		{"cmd/esowner/main.go", "package main\n", "`es-owner`"},
		{"scripts/es-resetup", "#!/bin/sh\n", "`es-recover-vault`, `es-resetup`"},
		{"es/policy/policy.go", "package standingpolicy\n", "standing policy"},
		{"es/policy/switch.go", "package policy\n\ntype Policy struct{ UseEgs bool `json:\"useEgs\"` }\n", "`use_egs`"},
		{"es/policy/env.go", "package policy\n\nconst env = \"ES_USE_EGS\"\n", "`use_egs`"},
		{"examples/policy.json", "{\"use-egs\": true}\n", "`use_egs`"},
		{"scripts/owner.sh", "es_owner=1\n", "`es-owner`"},
		{"es/policy/owner.go", "package policy\n\ntype ESOwner struct{}\n", "`es-owner`"},
		{"es/policy/due.go", "package policy\n\nvar RehearsalDue bool\n", "`rehearsal-due`"},
		{"es/policy/log.go", "package policy\n\ntype PolicyLog struct{}\n", "policy log"},
		{"es/policy/runs.go", "package policy\n\nvar runLog []string\n", "run log"},
		{"es/policy/anchor.go", "package loganchor\n", "log anchor"},
		{"es/policy/list.go", "package admissionlist\n", "admission list"},
		{"es/policy/class.go", "package policy\n\nconst kind = \"open-class\"\n", "open class, closed class"},
		{"deploy/Dockerfile", "RUN useradd es-log-reader\n", "`es-log-reader`"},
		{"deploy/host.nft", "# es-log-reader\n", "`es-log-reader`"},
		{"scripts/standing_policy/run", "#!/bin/sh\n", "standing policy"},
		{"scripts/export.py", "FORMAT = \"es-policy-log-export/v1\"\n", "`es-policy-log-export/v1`"},
		{"scripts/vault.sh", "es_recover_vault\n", "`es-recover-vault`, `es-resetup`"},
	}
	for _, probe := range probes {
		root := t.TempDir()
		full := filepath.Join(root, filepath.FromSlash(probe.path))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(probe.content), 0o644); err != nil {
			t.Fatal(err)
		}
		if uses := workingNameUses(t, root, patterns); uses[probe.path][probe.row] == 0 {
			t.Errorf("the working-names guard missed %s in %s (%q)", probe.row, probe.path, probe.content)
		}
	}

	// Words that merely end or start like a name are not a use.
	quiet := []string{"rules_owner := 1", "does_owner", "openclassic", "policy_logic", "run_logs", "useEgress"}
	for _, text := range quiet {
		for _, pattern := range patterns {
			if n := countNameUses(identifierWords(text), pattern.joined); n != 0 {
				t.Errorf("the working-names guard counts %q as a use of %s", text, pattern.row)
			}
		}
	}
}
