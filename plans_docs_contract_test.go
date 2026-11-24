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

// plansRecordSHA256 pins the record. It is closed: no entry is added to it,
// so an edit to it changes this value in the same reviewed change.
const plansRecordSHA256 = "0b13566795d1233f91c293f4b5ea79134af73013d75fea2e7f74f7df57ed0561"

// plansMaxBytes caps PLANS.md a little above its size once the record moved
// out (312,592 bytes). PLANS.md is edited in place to stay current and must
// not regrow into a log. Raising the cap is a deliberate, reviewed change;
// prefer moving settled detail into the .docs/ contract that owns it.
const plansMaxBytes = 320000

// plansOpeningSections are the first top-level sections of PLANS.md, in
// order: the plan an agent needs before any change comes first.
var plansOpeningSections = []string{
	"## Current Planning Objective",
	"## Ordered Execution Plan",
	"## Current Decision Rules",
	"## Reopened-Seam Exit Criteria",
}

// plansDatedLineExceptions are the dated lines PLANS.md held before the
// record moved out, inside sections that stay current. They may stay or go,
// but no new one may be added, and an exception that is gone must leave this
// list.
var plansDatedLineExceptions = []string{
	"**2026-11-13 Review-22 development-source disposition:**",
}

var (
	atxHeading      = regexp.MustCompile(`^ {0,3}(#{1,6})(?:[ \t]+(.*?))?(?:[ \t]+#+)?[ \t]*$`)
	setextUnderline = regexp.MustCompile(`^ {0,3}(=+|-+)[ \t]*$`)
	fenceLine       = regexp.MustCompile("^ {0,3}(```|~~~)")
	blockStart      = regexp.MustCompile(`^ {0,3}([-+*]\s|\d+[.)]\s|>|\||#)`)
	isoDate         = `\d{4}-\d{2}-\d{2}`
	monthName       = `(?:jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)[a-z]*\.?`
	anyDate         = regexp.MustCompile(`(?i)\b(?:` + isoDate + `|\d{1,2} ` + monthName + `,? \d{4}|` + monthName + ` \d{1,2},? \d{4})\b`)
	datedLineStart  = regexp.MustCompile(`(?i)^ {0,3}(?:[-+*] |\d+[.)] )?(?:\*\*|__|\*|_)?(?:` + isoDate + `|\d{1,2} ` + monthName + `,? \d{4}|` + monthName + ` \d{1,2},? \d{4})`)
	statusHeading   = regexp.MustCompile(`(?i)^status\b|\bstatus$|\b(?:current|recent|latest|project|plan|work)\s+status\b|\bstatus\s+(?:update|updates|log|logs|entry|entries|report|reports|note|notes)\b`)
)

// markdownHeadingTitles returns the titles of the CommonMark ATX and setext
// headings in doc, outside fenced code, each with its level as "#" marks.
func markdownHeadingTitles(doc string) []string {
	var headings []string
	inFence := false
	previous := ""
	for _, line := range strings.Split(doc, "\n") {
		if fenceLine.MatchString(line) {
			inFence = !inFence
			previous = ""
			continue
		}
		if inFence {
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
	plans := mustRead(t, "PLANS.md")
	for _, heading := range markdownHeadingTitles(plans) {
		title := strings.TrimSpace(strings.TrimLeft(heading, "#"))
		if statusHeading.MatchString(title) {
			t.Errorf("PLANS.md has a status heading %q: edit the section that states a fact, and say what a change did in its pull request description", heading)
		}
		if anyDate.MatchString(title) {
			t.Errorf("PLANS.md heading %q carries a date: PLANS.md holds the current plan, not dated entries", heading)
		}
	}

	exceptions := map[string]int{}
	for _, line := range plansDatedLineExceptions {
		exceptions[line] = 0
	}
	for i, line := range strings.Split(plans, "\n") {
		if !datedLineStart.MatchString(line) {
			continue
		}
		if _, ok := exceptions[strings.TrimSpace(line)]; ok {
			exceptions[strings.TrimSpace(line)]++
			continue
		}
		t.Errorf("PLANS.md:%d opens with a date (%q): PLANS.md holds the current plan, not dated entries", i+1, line)
	}
	for line, seen := range exceptions {
		if seen != 1 {
			t.Errorf("pinned dated line %q appears %d times in PLANS.md, want exactly 1: remove it from plansDatedLineExceptions once it is gone", line, seen)
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

var (
	plansInlineLineCitation = regexp.MustCompile(`PLANS\.md` + "`?" + `(?::|#L)\d`)
	plansWordLineCitation   = regexp.MustCompile(`(?i)PLANS\.md[^|\n]{0,40}?\blines?\s+\d`)
	numericCell             = regexp.MustCompile("^`?L?\\d+(?:\\s*[-–]\\s*L?\\d+)?`?(?:\\s*,\\s*`?L?\\d+(?:\\s*[-–]\\s*L?\\d+)?`?)*$")
	lineRange               = regexp.MustCompile(`\d\s*[-–]\s*L?\d`)
)

// plansLineCitations returns the lines of text that cite PLANS.md by line
// number: the file name followed by a colon and a number, by "#L" and a
// number, or (within 40 characters) by "line" or "lines" and a number; or a
// table row whose cell names PLANS.md and a later cell holds only line
// numbers and ranges, at least one of them a range.
func plansLineCitations(text string) []int {
	var lines []int
	for i, line := range strings.Split(text, "\n") {
		cited := plansInlineLineCitation.MatchString(line) || plansWordLineCitation.MatchString(line)
		if !cited && strings.HasPrefix(strings.TrimSpace(line), "|") {
			cells := strings.Split(strings.Trim(strings.TrimSpace(line), "|"), "|")
			for at, cell := range cells {
				if !strings.Contains(cell, "PLANS.md") {
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
// PLANS.md in every text file of the repository: its lines move with every
// edit.
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
			t.Errorf("%s:%d cites PLANS.md by line number; cite its section heading instead", name, line)
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
	} {
		got := markdownHeadingTitles(tc.doc)
		if len(got) != 1 || got[0] != tc.wantHeading {
			t.Errorf("markdownHeadingTitles(%q) = %q, want [%q]", tc.doc, got, tc.wantHeading)
		}
	}
	for _, text := range []string{"- item\n---\n", "| a |\n---\n", "```\n## Status\n```\n", "    ## indented code\n"} {
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

	// The refused examples spell the file name through {P}, so that this
	// file does not itself hold the citations the repository-wide check
	// refuses.
	for _, example := range []string{
		"See {P}:12.",
		"See `{P}`:12-20.",
		"[plan]({P}#L12)",
		"See `{P}` lines 12-20.",
		"See {P} line 4.",
		"| `{P}` | `329-421` | Why |",
		"| ES `{P}` | 12, 40-44 |",
		"// see {P}:12",
	} {
		text := strings.ReplaceAll(example, "{P}", "PLANS"+".md")
		if got := plansLineCitations(text); len(got) != 1 {
			t.Errorf("plansLineCitations(%q) = %v, want one citation", text, got)
		}
	}
	for _, text := range []string{
		"See PLANS.md, section Primary Program Orientation.",
		"| `PLANS.md` | [§ Primary Program Orientation](PLANS.md#primary-program-orientation) | Why |",
		"| A1 | claim | ES `PLANS.md` § Primary Program Orientation | 2026 |",
		"update `PLANS.md` when redesign scope changes",
	} {
		if got := plansLineCitations(text); len(got) != 0 {
			t.Errorf("plansLineCitations(%q) = %v, want none", text, got)
		}
	}
}
