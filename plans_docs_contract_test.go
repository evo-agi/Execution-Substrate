package executionsubstrate_test

import (
	"crypto/sha256"
	"encoding/hex"
	"io/fs"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"execution-substrate/internal/testutil"
)

// plansRecordPath is the closed dated record of PLANS.md. On 2026-11-24 the
// Status entries, the selection history of 2026-11-17 and 2026-11-18 and the
// records of the superseded P0n and P0r facade routes moved there verbatim,
// so that PLANS.md opens with the current plan. Checks of that text read
// this file.
const plansRecordPath = ".docs/history/plans-record.md"

// plansRecordSHA256 pins the record. It is closed: no entry is added to it,
// so an edit to it changes this value in the same reviewed change.
const plansRecordSHA256 = "33ecb75bb5f197dd44d30fef1a4255dcde30220fcedde8929d9f60ee02a08e1c"

// plansMaxBytes caps PLANS.md a little above its size once the record moved
// out (312,475 bytes). PLANS.md is edited in place to stay current and must
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

func markdownHeadings(doc string) []string {
	var headings []string
	inFence := false
	for _, line := range strings.Split(doc, "\n") {
		if strings.HasPrefix(line, "```") {
			inFence = !inFence
			continue
		}
		if inFence {
			continue
		}
		if regexp.MustCompile(`^#{1,6} `).MatchString(line) {
			headings = append(headings, strings.TrimRight(line, " "))
		}
	}
	return headings
}

func TestPlansOpensWithTheCurrentPlan(t *testing.T) {
	plans := mustRead(t, "PLANS.md")
	var topLevel []string
	for _, heading := range markdownHeadings(plans) {
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
		"The record is closed and keeps the standing it had here.",
	)
}

// TestPlansHoldsNoDatedStatusEntries keeps the status log from coming back:
// no Status section and no heading that carries a date.
func TestPlansHoldsNoDatedStatusEntries(t *testing.T) {
	dated := regexp.MustCompile(`\b\d{4}-\d{2}-\d{2}\b`)
	for _, heading := range markdownHeadings(mustRead(t, "PLANS.md")) {
		title := strings.ToLower(strings.TrimSpace(strings.TrimLeft(heading, "#")))
		if title == "status" || strings.HasPrefix(title, "status ") {
			t.Errorf("PLANS.md has a status section %q: edit the section that states a fact, and say what a change did in its pull request description", heading)
		}
		if dated.MatchString(heading) {
			t.Errorf("PLANS.md heading %q carries a date: PLANS.md holds the current plan, not dated entries", heading)
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
		"Nothing in it was reworded.",
		"The record is closed. Do not add entries",
	)

	// Nothing that moved is still in PLANS.md under the same heading.
	plansHeadings := map[string]bool{}
	for _, heading := range markdownHeadings(mustRead(t, "PLANS.md")) {
		plansHeadings[heading] = true
	}
	moved := 0
	for _, heading := range markdownHeadings(record) {
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
		"`PLANS.md`'s closed dated record, `"+plansRecordPath+"`, keeps the standing its entries had in `PLANS.md`, but it is not part of the read-first path",
		"do not add a dated status entry to `PLANS.md` or to its closed record",
	)
	assertContainsAll(t, "README plan record reference", mustRead(t, "README.md"),
		"[.docs/history/plans-record.md](.docs/history/plans-record.md)",
	)
}

// TestPlansIsCitedBySectionNotLine refuses line-number citations of
// PLANS.md in the repository's Markdown: its lines move with every edit.
func TestPlansIsCitedBySectionNotLine(t *testing.T) {
	lineCitation := regexp.MustCompile(`PLANS\.md(:|#L)[0-9]`)
	checked := 0
	err := filepath.WalkDir(testutil.Root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			if name := entry.Name(); name == ".git" || name == ".out" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".md") {
			return nil
		}
		rel, err := filepath.Rel(testutil.Root, path)
		if err != nil {
			return err
		}
		checked++
		for i, line := range strings.Split(mustRead(t, filepath.ToSlash(rel)), "\n") {
			if lineCitation.MatchString(line) {
				t.Errorf("%s:%d cites PLANS.md by line number; cite its section heading instead", filepath.ToSlash(rel), i+1)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if checked < 40 {
		t.Fatalf("checked %d Markdown files, want the repository's 40 or more", checked)
	}
}
