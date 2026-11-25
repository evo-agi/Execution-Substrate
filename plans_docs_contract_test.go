package executionsubstrate_test

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// plansRecordPath is the closed dated record of PLANS.md. On 2026-11-24 the
// Status entries, the selection history of 2026-11-17 and 2026-11-18 and the
// records of the superseded P0n and P0r facade routes moved there, unreworded
// (only relative link targets gained a ../../ prefix), so that PLANS.md opens
// with the current plan. The record is historical evidence and holds no
// current authority. Checks of that text read this file.
const plansRecordPath = ".docs/history/plans-record.md"

// The files in standingRulesDir hold standing rules that moved out of
// PLANS.md unreworded, so that PLANS.md holds intent and order. They keep
// PLANS.md's rank in the AGENTS.md authority hierarchy. Checks of those
// rules read these files.
const (
	standingRulesDir           = ".docs/standing_rules/"
	standingAdmissionRulesPath = standingRulesDir + "execution_admission_and_custody.md"
	standingRouteRulesPath     = standingRulesDir + "remote_alpha_operator_routes.md"
)

// plansAndStandingRules returns PLANS.md and the standing rule files that
// moved out of it, compacted and joined, for checks that a phrase appears in
// none of them: a refused phrase must not come back in the rules either.
func plansAndStandingRules(t *testing.T) string {
	t.Helper()
	return compactText(mustRead(t, "PLANS.md")) + " " +
		compactText(mustRead(t, standingAdmissionRulesPath)) + " " +
		compactText(mustRead(t, standingRouteRulesPath))
}

// plansRecordSHA256 pins the record. It is closed: no entry is added to it,
// so an edit to it changes this value in the same reviewed change.
const plansRecordSHA256 = "0b13566795d1233f91c293f4b5ea79134af73013d75fea2e7f74f7df57ed0561"

// plansMaxBytes caps PLANS.md a little above its size once the record and
// then the standing rules moved out (145,045 bytes). PLANS.md holds intent
// and order, is edited in place to stay current, and must not regrow into a
// log or a rule book. Raising the cap is a deliberate, reviewed change;
// prefer putting a standing rule in the file that owns it.
const plansMaxBytes = 150000

// plansOpeningSections are the first top-level sections of PLANS.md, in
// order: the plan an agent needs before any change comes first.
var plansOpeningSections = []string{
	"## Current Planning Objective",
	"## Ordered Execution Plan",
	"## Current Decision Rules",
	"## Reopened-Seam Exit Criteria",
}

// plansGuardedFiles are the files the status-entry guard reads: PLANS.md and
// the standing rule files that moved out of it, which are edited in place in
// the same way.
var plansGuardedFiles = []string{"PLANS.md", standingAdmissionRulesPath, standingRouteRulesPath}

// plansDatedLineExceptions are the dated lines that PLANS.md held, inside
// sections that stayed current, keyed by the file that holds them now. They
// may stay or go, but no new one may be added, and an exception that is gone
// must leave this list.
var plansDatedLineExceptions = map[string][]string{
	standingAdmissionRulesPath: {"**2026-11-13 Review-22 development-source disposition:**"},
}

var (
	atxHeading      = regexp.MustCompile(`^ {0,3}(#{1,6})(?:[ \t]+(.*?))?(?:[ \t]+#+)?[ \t]*$`)
	setextUnderline = regexp.MustCompile(`^ {0,3}(=+|-+)[ \t]*$`)
	fenceLine       = regexp.MustCompile("^ {0,3}(`{3,}|~{3,})(.*)$")
	blockStart      = regexp.MustCompile(`^ {0,3}([-+*]\s|\d+[.)]\s|>|\||#)`)
	isoDate         = `\d{4}-\d{2}-\d{2}`
	monthName       = `(?:jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)[a-z]*\.?`
	anyDate         = regexp.MustCompile(`(?i)\b(?:` + isoDate + `|\d{1,2} ` + monthName + `,? \d{4}|` + monthName + ` \d{1,2},? \d{4})\b`)
	datedLineStart  = regexp.MustCompile(`(?i)^ {0,3}(?:[-+*] |\d+[.)] )?(?:\*\*|__|\*|_)?(?:` + isoDate + `|\d{1,2} ` + monthName + `,? \d{4}|` + monthName + ` \d{1,2},? \d{4})`)
	statusHeading   = regexp.MustCompile(`(?i)^status\b|\bstatus$|\b(?:current|recent|latest|project|plan|work)\s+status\b|\bstatus\s+(?:update|updates|log|logs|entry|entries|report|reports|note|notes)\b`)
)

// markdownHeadingTitles returns the titles of the CommonMark ATX and setext
// headings in doc, outside fenced code, each with its level as "#" marks. As
// in CommonMark, a fence closes only on a line of the opening character at
// least as long as the opening run, with nothing after it, and an unclosed
// fence runs to the end of the document.
func markdownHeadingTitles(doc string) []string {
	var headings []string
	fence := ""
	previous := ""
	for _, line := range strings.Split(doc, "\n") {
		match := fenceLine.FindStringSubmatch(line)
		if fence != "" {
			if match != nil && match[1][0] == fence[0] && len(match[1]) >= len(fence) && strings.TrimSpace(match[2]) == "" {
				fence = ""
			}
			continue
		}
		if match != nil && !(match[1][0] == '`' && strings.Contains(match[2], "`")) {
			fence = match[1]
			previous = ""
			continue
		}
		if match := atxHeading.FindStringSubmatch(line); match != nil {
			headings = append(headings, match[1]+" "+strings.TrimSpace(match[2]))
			previous = ""
			continue
		}
		if match := setextUnderline.FindStringSubmatch(line); match != nil && strings.TrimSpace(previous) != "" && !blockStart.MatchString(previous) {
			level := "#"
			if strings.HasPrefix(match[1], "-") {
				level = "##"
			}
			headings = append(headings, level+" "+strings.TrimSpace(previous))
			previous = ""
			continue
		}
		previous = line
	}
	return headings
}

func TestPlansOpensWithTheCurrentPlan(t *testing.T) {
	plans := mustRead(t, "PLANS.md")
	var topLevel []string
	for _, heading := range markdownHeadingTitles(plans) {
		if strings.HasPrefix(heading, "## ") {
			topLevel = append(topLevel, heading)
		}
	}
	if len(topLevel) < len(plansOpeningSections) {
		t.Fatalf("PLANS.md has %d top-level sections, want at least %d", len(topLevel), len(plansOpeningSections))
	}
	for i, want := range plansOpeningSections {
		if topLevel[i] != want {
			t.Errorf("PLANS.md top-level section %d is %q, want %q", i+1, topLevel[i], want)
		}
	}
	intro := plans[:strings.Index(plans, plansOpeningSections[0])]
	assertContainsAll(t, "PLANS.md introduction", compactText(intro),
		"This file holds the current plan, its intent and order:",
		"Put a standing rule in the file that owns it, not here.",
		"[`execution_admission_and_custody.md`]("+standingAdmissionRulesPath+") holds the Workstream C admission and custody rules",
		"[`remote_alpha_operator_routes.md`]("+standingRouteRulesPath+") holds the Remote Alpha operator route rules P0i to P0v",
		"Do not add dated status entries",
		"Cite this file by section heading, never by line number",
		"("+plansRecordPath+")",
		"The record is closed and is historical evidence only: it holds no current authority, and where it differs from this file or from an owning `.docs/` contract, they win.",
	)
}

// TestPlansHoldsNoDatedStatusEntries keeps the status log from coming back:
// no status-log heading, no heading that carries a date, and no line that
// opens with a date beyond the pinned exceptions.
func TestPlansHoldsNoDatedStatusEntries(t *testing.T) {
	for path := range plansDatedLineExceptions {
		found := false
		for _, guarded := range plansGuardedFiles {
			found = found || guarded == path
		}
		if !found {
			t.Errorf("plansDatedLineExceptions names %s, which the guard does not read", path)
		}
	}
	for _, path := range plansGuardedFiles {
		doc := mustRead(t, path)
		for _, heading := range markdownHeadingTitles(doc) {
			title := strings.TrimSpace(strings.TrimLeft(heading, "#"))
			if statusHeading.MatchString(title) {
				t.Errorf("%s has a status heading %q: edit the section that states a fact, and say what a change did in its pull request description", path, heading)
			}
			if anyDate.MatchString(title) {
				t.Errorf("%s heading %q carries a date: it holds current plans and rules, not dated entries", path, heading)
			}
		}

		exceptions := map[string]int{}
		for _, line := range plansDatedLineExceptions[path] {
			exceptions[line] = 0
		}
		for i, line := range strings.Split(doc, "\n") {
			if !datedLineStart.MatchString(line) {
				continue
			}
			if _, ok := exceptions[strings.TrimSpace(line)]; ok {
				exceptions[strings.TrimSpace(line)]++
				continue
			}
			t.Errorf("%s:%d opens with a date (%q): it holds current plans and rules, not dated entries", path, i+1, line)
		}
		for line, seen := range exceptions {
			if seen != 1 {
				t.Errorf("pinned dated line %q appears %d times in %s, want exactly 1: remove it from plansDatedLineExceptions once it is gone", line, seen, path)
			}
		}
	}
}

func TestPlansStaysWithinItsSizeCap(t *testing.T) {
	if size := len(mustRead(t, "PLANS.md")); size > plansMaxBytes {
		t.Fatalf("PLANS.md is %d bytes, over its cap of %d: keep it current by editing in place, and move settled detail into its owning .docs/ contract", size, plansMaxBytes)
	}
}

func TestPlansRecordIsClosed(t *testing.T) {
	record := mustRead(t, plansRecordPath)
	sum := sha256.Sum256([]byte(record))
	if got := hex.EncodeToString(sum[:]); got != plansRecordSHA256 {
		t.Fatalf("%s has SHA-256 %s, want %s: the record is closed; add nothing to it", plansRecordPath, got, plansRecordSHA256)
	}
	assertContainsAll(t, "plan record header", compactText(record),
		"This is the closed dated record of `PLANS.md`.",
		"`16cbf739eea8c6a673aef8048aefb69cebd5121b`",
		"Nothing in it was reworded. The one change is that each relative link target gained a `../../` prefix",
		"It is historical evidence and holds no current authority. Where it differs from `PLANS.md` or from an owning `.docs/` contract, they win.",
		"The record is closed. Do not add entries",
		"in the order they stood at the top of `PLANS.md`",
	)

	// Nothing that moved is still in PLANS.md under the same heading.
	plansHeadings := map[string]bool{}
	for _, heading := range markdownHeadingTitles(mustRead(t, "PLANS.md")) {
		plansHeadings[heading] = true
	}
	moved := 0
	for _, heading := range markdownHeadingTitles(record) {
		if !strings.HasPrefix(heading, "## ") && !strings.HasPrefix(heading, "### ") {
			continue
		}
		moved++
		if plansHeadings[heading] {
			t.Errorf("heading %q is in both PLANS.md and %s", heading, plansRecordPath)
		}
	}
	if moved < 30 {
		t.Fatalf("%s has %d section headings, want the 30 or more that moved", plansRecordPath, moved)
	}
}

func TestPlansRecordIsNamedWhereAgentsStart(t *testing.T) {
	assertContainsAll(t, "AGENTS.md plan record rule", compactText(mustRead(t, "AGENTS.md")),
		"`"+plansRecordPath+"`, the closed dated record that moved out of `PLANS.md`, is historical evidence and holds no current authority: where it differs from `PLANS.md` or from an owning `.docs/` contract, they win.",
		"do not add a dated status entry to `PLANS.md` or to its closed record",
	)
	assertContainsAll(t, "README plan record reference", mustRead(t, "README.md"),
		"[.docs/history/plans-record.md](.docs/history/plans-record.md)",
		"historical evidence with no current authority",
	)
}

// TestStandingRulesKeepPlansAuthority pins where the standing rules that
// moved out of PLANS.md live, and that they keep its rank: AGENTS.md says so,
// and only AGENTS.md (TestAuthorityOrderIsStatedOnlyInAgents keeps the rank
// out of every other document); PLANS.md and the owning contract point at
// each file, and no section is held in two places.
func TestStandingRulesKeepPlansAuthority(t *testing.T) {
	assertContainsAll(t, "AGENTS.md standing rules", compactText(mustRead(t, "AGENTS.md")),
		"The files in `"+standingRulesDir+"` hold standing rules that moved unreworded out of `PLANS.md`: `execution_admission_and_custody.md` holds the Workstream C admission and custody rules, and `remote_alpha_operator_routes.md` holds the Remote Alpha operator route rules P0i to P0v. They keep `PLANS.md`'s authority, second in the list above: only their location changed, and the rules above apply to them as they apply to `PLANS.md`.",
		"consult the `"+standingRulesDir+"` file that holds the rules of the surface you change",
		"update the `"+standingRulesDir+"` file in place when a standing rule it holds changed, also without a dated status entry",
	)
	if lines := authorityHierarchyLines(t); lines[1] != "2. `PLANS.md` for allowed redesign work, active workstreams, priorities, and reopened seams" {
		t.Fatalf("the second entry of the AGENTS.md authority order is %q; the standing rules share that rank, so it must stay", lines[1])
	}
	readme := mustRead(t, "README.md")

	files := repositoryTextFiles(t)
	var inFolder []string
	for name := range files {
		if strings.HasPrefix(name, standingRulesDir) {
			inFolder = append(inFolder, name)
		}
	}
	sort.Strings(inFolder)
	if want := []string{standingAdmissionRulesPath, standingRouteRulesPath}; strings.Join(inFolder, " ") != strings.Join(want, " ") {
		t.Fatalf("%s holds %q, want %q: a new standing rule file is named in AGENTS.md section 3 first", standingRulesDir, inFolder, want)
	}

	plans := mustRead(t, "PLANS.md")
	plansHeadings := map[string]bool{}
	for _, heading := range markdownHeadingTitles(plans) {
		plansHeadings[heading] = true
	}
	for _, rule := range []struct {
		path, owner, pointer, ownerPointer, ownerNamed string
		sections                                       int
	}{
		{
			standingAdmissionRulesPath, ".docs/execution_lifecycle/contracts.md", "### Workstream C admission and custody rules",
			"The standing Workstream C admission and custody rules are in `" + standingAdmissionRulesPath + "`. This file holds the detailed lifecycle contract for them.",
			"The detailed lifecycle contract for these rules is `.docs/execution_lifecycle/contracts.md`.",
			1,
		},
		{
			standingRouteRulesPath, ".docs/system_overview/remote_supported_host_alpha.md", "### Remote Alpha operator facade route rules (P0i to P0v)",
			"The standing route rules for P0i to P0v are in `" + standingRouteRulesPath + "`. The sections below hold the detailed route contracts.",
			"The detailed route contracts are in `.docs/system_overview/remote_supported_host_alpha.md`.",
			3,
		},
	} {
		text := mustRead(t, rule.path)
		assertContainsAll(t, rule.path+" header", compactText(text),
			"They moved here unreworded from the `PLANS.md` section",
			rule.ownerNamed,
			"Edit a rule here in place when it changes. Do not add dated status entries",
			"Cite this file by section heading, never by line number.",
		)

		if !plansHeadings[rule.pointer] {
			t.Fatalf("PLANS.md lacks the pointer section %q", rule.pointer)
		}
		pointer := plans[strings.Index(plans, rule.pointer)+len(rule.pointer):]
		if next := strings.Index(pointer, "\n#"); next >= 0 {
			pointer = pointer[:next]
		}
		assertContainsAll(t, "PLANS.md pointer to "+rule.path, compactText(pointer),
			"["+"`"+rule.path+"`"+"]("+rule.path+")",
		)

		sections := 0
		for _, heading := range markdownHeadingTitles(text) {
			if !strings.HasPrefix(heading, "### ") {
				continue
			}
			sections++
			if plansHeadings[heading] {
				t.Errorf("heading %q is in both PLANS.md and %s", heading, rule.path)
			}
		}
		if sections != rule.sections {
			t.Errorf("%s has %d sections, want the %d that moved", rule.path, sections, rule.sections)
		}

		assertContainsAll(t, rule.owner+" pointer to "+rule.path, compactText(mustRead(t, rule.owner)),
			rule.ownerPointer,
		)
		if !strings.Contains(readme, "]("+rule.path+")") {
			t.Errorf("README.md does not link %s", rule.path)
		}
	}
}

// TestStandingRulesPinEachOtherwiseUncheckedRule pins the standing rule
// paragraphs that no other test reads. Deleting any one of them failed no
// test, before and after the move out of PLANS.md (audit 08, finding A08-1).
// Each row names one paragraph by its rule and pins phrases that state it.
// Every phrase must occur exactly once in its file, so deleting the paragraph
// fails this test. When a rule changes, edit its phrases here with it.
func TestStandingRulesPinEachOtherwiseUncheckedRule(t *testing.T) {
	for _, rule := range []struct {
		path, name string
		phrases    []string
	}{
		{standingAdmissionRulesPath, "Stage A slice scope", []string{
			"The independently accepted R9.28 owner is bounded artifact-design evidence, not repository adoption or runtime qualification.",
			"It adds no active import, public route, configuration, job, process, endpoint, issuer, ledger, receipt consumption, or production evidence intake.",
		}},
		{standingAdmissionRulesPath, "B1 current invariant", []string{
			"**Current invariant:** real artifact, capability, target, runtime-profile, policy and trust admission remain authoritative",
			"The strict legacy decoder rejects a structural `reliable_submit` body, even when a schema string alone is supplied.",
			"mode defaults to async, timeout to zero, and omitted CPU/memory to 10/128.",
		}},
		{standingAdmissionRulesPath, "Review-09 proof-artifact collection", []string{
			"The selected repair collects only explicitly classified top-level proof evidence, records a deterministic relative-path and SHA-256 manifest, uses a private `0700` host proof directory",
			"The proof collector is evidence projection, not ES, Nomad, Vault, SPIRE, result-auth, or cleanup authority.",
		}},
		{standingAdmissionRulesPath, "B2 provider response limits", []string{
			"Submit registration, projected-allocation list, and allocation-detail JSON use the existing 256 KiB transport boundary and one compatible JSON document",
			"B2 therefore selects neither a universal provider-response limit nor a public Logs byte/oversize policy.",
		}},
		{standingAdmissionRulesPath, "B2 preparedAdmission redaction and assurance", []string{
			"`preparedAdmission` carries the private formatter marker as its first anonymous field",
			"non-purging cancellation is enforced by a private construction that has no purge option.",
		}},
		{standingRouteRulesPath, "P0q bootstrap effects", []string{
			"P0q bootstrap configures expected Vault objects only.",
			"It must not claim workload-auth success, runtime-profile readiness, submit readiness, Vault production readiness, governed execution proof, IM authority, CP recovery authority, ES Vault token brokerage, or Remote Alpha production/deployment/provisioning/reconciliation architecture. The workload-auth check remains a separate post-bootstrap command.",
		}},
		{standingRouteRulesPath, "P0s/P0t failure witness", []string{
			"the fixed root bootstrap is the sole owner of an optional, at-most-one, source-bound P0s/P0t failure witness on its existing controlling terminal.",
			"The output is one fixed ASCII line of at most 512 bytes",
		}},
		{standingRouteRulesPath, "P0s/P0t collector scope tables", []string{
			"the root-run Python collector has only two immutable, source-controlled scope tables and no renewal mode, path override, arbitrary command, shell, backup, generation, install, restart, or post-renewal probe.",
			"A collector lifecycle failure is incomplete and publishes no generation.",
		}},
		{standingRouteRulesPath, "P0s/P0t related configuration states", []string{
			"a related configuration used for a fixed disjointness or exclusion check has a proved state.",
			"never an empty-object pass.",
		}},
		{standingRouteRulesPath, "P0s/P0t protected status directories", []string{
			"must each be real root:root `0755` directories with no symlink, unsafe access, or unresolved ACL/equivalent state.",
			"The collector never creates a missing protected directory; host preparation is separate.",
		}},
		{standingRouteRulesPath, "P0s/P0t legacy summaries", []string{
			"are historical only: no read as current status, migration, copy, overwrite, symlink, fallback, renewal, or rollback authority.",
			"The blocked candidate is design evidence and is not the implementation base.",
		}},
		{standingRouteRulesPath, "P0t diagnostic Mac facade", []string{
			"the new Mac facade form accepts only the existing validated `--ssh-target` and visible `--interactive-tty` for live use, plus a diagnostic-only local `--verify-only`.",
			"there is no nonroot cleanup, transcript capture, password relay, NOPASSWD change, automatic retry, or status package copy-back.",
		}},
		{standingRouteRulesPath, "P0u summary contents", []string{
			"P0u summaries are evidence/projection only.",
			"They must not include private key PEM bodies, full certificate PEM bodies, Vault tokens",
		}},
		{standingRouteRulesPath, "P0u authority bounds", []string{
			"P0u remains bounded ES Remote Alpha proof/support workflow glue only. It is not generic TLS deployment, not Infrastructure Manager reconciliation",
		}},
		{standingRouteRulesPath, "P0v cross-repo consumers", []string{
			"Bridge/MA/CP/IM consumers must not wrap missing ES prerequisites into ES status truth.",
			"P0v does not renew, mutate cert/profile/key/trust/env/state, run live proof, or widen any cross-repo authority boundary.",
		}},
	} {
		text := compactText(mustRead(t, rule.path))
		for _, phrase := range rule.phrases {
			if n := strings.Count(text, phrase); n != 1 {
				t.Errorf("%s rule %q: phrase occurs %d times, want exactly once: %q", rule.path, rule.name, n, phrase)
			}
		}
	}
}

var (
	plansCitedFile          = `(?:PLANS\.md|AGENTS\.md|standing_rules/[A-Za-z0-9_]+\.md)`
	plansCitedFileName      = regexp.MustCompile(plansCitedFile)
	plansInlineLineCitation = regexp.MustCompile(plansCitedFile + "`?" + `(?::|#L)\d`)
	plansWordLineCitation   = regexp.MustCompile(`(?i)` + plansCitedFile + `[^|\n]{0,40}?\blines?\s+\d`)
	numericCell             = regexp.MustCompile("^`?L?\\d+(?:\\s*[-–]\\s*L?\\d+)?`?(?:\\s*,\\s*`?L?\\d+(?:\\s*[-–]\\s*L?\\d+)?`?)*$")
	lineRange               = regexp.MustCompile(`\d\s*[-–]\s*L?\d`)
)

// plansLineCitations returns the lines of text that cite PLANS.md, AGENTS.md
// or a standing rule file by line number: the file name followed by a colon and a
// number, by "#L" and a number, or (within 40 characters) by "line" or
// "lines" and a number; or a table row whose cell names one of those files
// and a later cell holds only line numbers and ranges, at least one of them
// a range.
func plansLineCitations(text string) []int {
	var lines []int
	for i, line := range strings.Split(text, "\n") {
		cited := plansInlineLineCitation.MatchString(line) || plansWordLineCitation.MatchString(line)
		if !cited && strings.HasPrefix(strings.TrimSpace(line), "|") {
			cells := strings.Split(strings.Trim(strings.TrimSpace(line), "|"), "|")
			for at, cell := range cells {
				if !plansCitedFileName.MatchString(cell) {
					continue
				}
				for _, later := range cells[at+1:] {
					if later = strings.TrimSpace(later); numericCell.MatchString(later) && lineRange.MatchString(later) {
						cited = true
					}
				}
			}
		}
		if cited {
			lines = append(lines, i+1)
		}
	}
	return lines
}

// TestPlansIsCitedBySectionNotLine refuses line-number citations of
// PLANS.md, of AGENTS.md and of the standing rule files in every text file
// of the repository: their lines move with every edit.
func TestPlansIsCitedBySectionNotLine(t *testing.T) {
	files := repositoryTextFiles(t)
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	markdown := 0
	for _, name := range names {
		if strings.HasSuffix(name, ".md") {
			markdown++
		}
		for _, line := range plansLineCitations(string(files[name])) {
			t.Errorf("%s:%d cites PLANS.md, AGENTS.md or a standing rule file by line number; cite its section heading instead", name, line)
		}
	}
	if markdown < 40 {
		t.Fatalf("checked %d Markdown files, want the repository's 40 or more", markdown)
	}
}

// TestPlansGuardsFindEachKindOfProblem shows that the checks above find each
// form they are meant to refuse, and nothing in ordinary text.
func TestPlansGuardsFindEachKindOfProblem(t *testing.T) {
	for _, tc := range []struct {
		doc         string
		wantHeading string
	}{
		{"## Status\n", "## Status"},
		{"  ## Current Status\n", "## Current Status"},
		{"Status\n------\n", "## Status"},
		{"Plan\n===\n", "# Plan"},
		{"### PR #56 follow-up (25 Nov 2026) ###\n", "### PR #56 follow-up (25 Nov 2026)"},
		{"```\ncode\n```\n## Status\n", "## Status"},
		{"````\ncode\n`````\n## Status\n", "## Status"},
		{"````\n```\n````\n## Status\n", "## Status"},
		{"``` info `x`\n## Status\n", "## Status"},
	} {
		got := markdownHeadingTitles(tc.doc)
		if len(got) != 1 || got[0] != tc.wantHeading {
			t.Errorf("markdownHeadingTitles(%q) = %q, want [%q]", tc.doc, got, tc.wantHeading)
		}
	}
	for _, text := range []string{
		"- item\n---\n",
		"| a |\n---\n",
		"```\n## Status\n```\n",
		"    ## indented code\n",
		"````\n```\n## Status\n````\n",
		"~~~\n```\n## Status\n~~~\n",
		"```\n``` not a close\n## Status\n```\n",
		"```\n## Status, in an unclosed fence\n",
	} {
		if got := markdownHeadingTitles(text); len(got) != 0 {
			t.Errorf("markdownHeadingTitles(%q) = %q, want none", text, got)
		}
	}

	for _, title := range []string{"Status", "Current Status", "Status updates", "Recent status", "Plan status"} {
		if !statusHeading.MatchString(title) {
			t.Errorf("status heading %q is not refused", title)
		}
	}
	for _, title := range []string{"Remote Alpha TLS status, renewal and diagnostic routes (P0s to P0v)", "Document Scope And Current Implementation"} {
		if statusHeading.MatchString(title) {
			t.Errorf("heading %q is refused as a status heading", title)
		}
	}
	for _, title := range []string{"Fix (2026-11-25)", "Follow-up 25 Nov 2026", "Follow-up November 25, 2026"} {
		if !anyDate.MatchString(title) {
			t.Errorf("dated heading %q is not refused", title)
		}
	}

	for _, line := range []string{"2026-11-25: PR #56 changed submit.", "**2026-11-25 status:** PR #56.", "- 2026-11-25 PR #56", "__25 Nov 2026__ PR #56"} {
		if !datedLineStart.MatchString(line) {
			t.Errorf("dated line %q is not refused", line)
		}
	}
	for _, line := range []string{"ES retains every staging root since 2026-11-13.", "2026 targets", "Review-22 2026-11-13"} {
		if datedLineStart.MatchString(line) {
			t.Errorf("ordinary line %q is refused", line)
		}
	}

	// The refused examples spell the file names through {P}, {A} and {S}, so
	// that this file does not itself hold the citations the repository-wide
	// check refuses.
	for _, example := range []string{
		"See {P}:12.",
		"See `{P}`:12-20.",
		"[plan]({P}#L12)",
		"See `{P}` lines 12-20.",
		"See {P} line 4.",
		"| `{P}` | `329-421` | Why |",
		"| ES `{P}` | 12, 40-44 |",
		"// see {P}:12",
		"See `.docs/{S}`:12.",
		"See .docs/{S} lines 12-20.",
		"| `.docs/{S}` | 12-20 |",
		"ES `{A}:153-159`",
		"| `{A}` | `21-36`, `38-65` | Why |",
		"See {A} lines 21-36.",
	} {
		text := strings.ReplaceAll(example, "{P}", "PLANS"+".md")
		text = strings.ReplaceAll(text, "{A}", "AGENTS"+".md")
		text = strings.ReplaceAll(text, "{S}", "standing_rules/remote_alpha_operator_routes"+".md")
		if got := plansLineCitations(text); len(got) != 1 {
			t.Errorf("plansLineCitations(%q) = %v, want one citation", text, got)
		}
	}
	for _, text := range []string{
		"See PLANS.md, section Primary Program Orientation.",
		"| `PLANS.md` | [§ Primary Program Orientation](PLANS.md#primary-program-orientation) | Why |",
		"| A1 | claim | ES `PLANS.md` § Primary Program Orientation | 2026 |",
		"update `PLANS.md` when redesign scope changes",
		"| `AGENTS.md` | Sections 3 to 5, 7 and 10 to 12, cited by section because its lines move | Why |",
		"ES `AGENTS.md` section 12; ES `.docs/system_overview/capability_probing.md:1-16`",
	} {
		if got := plansLineCitations(text); len(got) != 0 {
			t.Errorf("plansLineCitations(%q) = %v, want none", text, got)
		}
	}
}
