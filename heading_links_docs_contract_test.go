package executionsubstrate_test

import (
	"fmt"
	"net/url"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
	"unicode"
)

// githubHeadingSlug returns the anchor GitHub gives a Markdown heading title:
// link syntax keeps only its text, code-span backticks go, the rest is lower
// case, every character that is not a letter, a digit, a space, a hyphen or
// an underscore is dropped, and each space becomes a hyphen. So
// "4A. Producer Contract Declaration" becomes "4a-producer-contract-declaration"
// and "v1 — Tranche A" becomes "v1--tranche-a".
func githubHeadingSlug(title string) string {
	title = markdownLinkText.ReplaceAllString(title, "$1")
	title = strings.ToLower(strings.ReplaceAll(title, "`", ""))
	var slug strings.Builder
	for _, r := range title {
		switch {
		case r == ' ':
			slug.WriteByte('-')
		case r == '-' || r == '_' || unicode.IsLetter(r) || unicode.IsDigit(r):
			slug.WriteRune(r)
		}
	}
	return slug.String()
}

var markdownLinkText = regexp.MustCompile(`\[([^\]]*)\]\([^)]*\)`)

// githubHeadingAnchors returns the anchors of every heading in a Markdown
// document, as GitHub numbers repeats: the second heading with a slug gets
// "-1", the third "-2", and so on.
func githubHeadingAnchors(doc string) map[string]bool {
	anchors := map[string]bool{}
	seen := map[string]int{}
	for _, heading := range markdownHeadingTitles(doc) {
		slug := githubHeadingSlug(strings.TrimSpace(strings.TrimLeft(heading, "#")))
		anchor := slug
		if n, ok := seen[slug]; ok {
			anchor = slug + "-" + strconv.Itoa(n+1)
			seen[slug] = n + 1
		} else {
			seen[slug] = 0
		}
		anchors[anchor] = true
	}
	return anchors
}

// TestMarkdownHeadingLinksResolve requires the fragment of every relative
// link to a Markdown file of the repository, and of every same-file "#"
// link, to name a heading of that file. Documents cite one another by section
// heading because lines move; a renamed heading must take its links with it.
func TestMarkdownHeadingLinksResolve(t *testing.T) {
	files := repositoryTextFiles(t)
	names := make([]string, 0, len(files))
	for name := range files {
		if strings.HasSuffix(name, ".md") {
			names = append(names, name)
		}
	}
	sort.Strings(names)

	anchors := map[string]map[string]bool{}
	checked := 0
	var broken []string
	for _, name := range names {
		for _, target := range markdownLinkTargets(string(files[name])) {
			hash := strings.Index(target, "#")
			if hash < 0 || markdownURLScheme.MatchString(target) {
				continue
			}
			targetPath, fragment := target[:hash], target[hash+1:]
			if query := strings.Index(targetPath, "?"); query >= 0 {
				targetPath = targetPath[:query]
			}
			resolved := name
			if targetPath != "" {
				decoded, err := url.PathUnescape(targetPath)
				if err != nil {
					continue // TestMarkdownRelativeLinksResolve reports it.
				}
				resolved = path.Clean(path.Join(path.Dir(name), decoded))
			}
			if !strings.HasSuffix(resolved, ".md") {
				continue
			}
			content, ok := files[resolved]
			if !ok {
				continue // outside the repository or missing: TestMarkdownRelativeLinksResolve reports it.
			}
			if anchors[resolved] == nil {
				anchors[resolved] = githubHeadingAnchors(string(content))
			}
			checked++
			decodedFragment, err := url.PathUnescape(fragment)
			if err != nil || !anchors[resolved][decodedFragment] {
				broken = append(broken, name+": "+target+" (no heading with that anchor in "+resolved+")")
			}
		}
	}
	if checked < 90 {
		t.Fatalf("checked %d links to a Markdown heading, want the repository's 90 or more; the link or heading pattern no longer matches", checked)
	}
	if len(broken) > 0 {
		t.Fatalf("Markdown links whose heading anchor does not exist:\n%s", strings.Join(broken, "\n"))
	}
}

func TestGithubHeadingAnchorsFollowGithubRules(t *testing.T) {
	for title, want := range map[string]string{
		"Primary Program Orientation":                     "primary-program-orientation",
		"4A. Producer Contract Declaration":               "4a-producer-contract-declaration",
		"5. `submit-ready` meaning":                       "5-submit-ready-meaning",
		"Remote Alpha access contract v1 — Tranche A":     "remote-alpha-access-contract-v1--tranche-a",
		"Example: Runtime Identity":                       "example-runtime-identity",
		"Current-State Facts To Preserve During Redesign": "current-state-facts-to-preserve-during-redesign",
		"The [`AGENTS.md`](AGENTS.md) rules":              "the-agentsmd-rules",
		"es_execution_admission_model":                    "es_execution_admission_model",
	} {
		if got := githubHeadingSlug(title); got != want {
			t.Errorf("githubHeadingSlug(%q) = %q, want %q", title, got, want)
		}
	}
	got := githubHeadingAnchors("# Plan\n\n## Purpose\n\n```\n## Not a heading\n```\n\n### Purpose\n\nPurpose\n-------\n")
	want := map[string]bool{"plan": true, "purpose": true, "purpose-1": true, "purpose-2": true}
	if len(got) != len(want) {
		t.Fatalf("githubHeadingAnchors = %v, want %v", got, want)
	}
	for anchor := range want {
		if !got[anchor] {
			t.Errorf("githubHeadingAnchors lacks %q (got %v)", anchor, got)
		}
	}
}

// claimLedgerPath is the commercialization claim ledger. It cites this
// repository by section and the Control Plane and Infrastructure Manager
// repositories by line, each citation prefixed with the repository's short
// name.
const claimLedgerPath = ".docs/commercialization/claim-ledger.md"

// claimLedgerESCitation is one citation of this repository in a line of the
// claim ledger: from "ES" to the next ";", the end of the table cell, the
// start of a Control Plane or Infrastructure Manager citation ("CP `" or
// "IM `"), or the end of the line.
var claimLedgerESCitation = regexp.MustCompile("\\bES\\s[^;|]*?(?:;|\\||\\b(?:CP|IM)\\s+`|$)")

// claimLedgerLineSpan is a code span that cites by line: a path that ends in
// ":<line>" or "#L<line>", or only a line number or range such as `51-82`.
var claimLedgerLineSpan = regexp.MustCompile("`(?:[^`\\n]*(?::|#L)\\d[^`\\n]*|L?\\d+(?:\\s*[-–]\\s*L?\\d+)?)`")

// claimLedgerLineCitations returns every code span in a line of the claim
// ledger that cites this repository by line, in order: each span of each ES
// citation of the line, repeats included.
func claimLedgerLineCitations(line string) []string {
	var found []string
	for _, citation := range claimLedgerESCitation.FindAllString(line, -1) {
		found = append(found, claimLedgerLineSpan.FindAllString(citation, -1)...)
	}
	return found
}

// claimLedgerBaselineCellCitesLines reports whether a cell of the claim
// ledger's Execution Substrate source baseline table cites by line: it holds
// only line numbers and ranges, it holds a digit range anywhere, or it holds a
// code span that cites by line.
func claimLedgerBaselineCellCitesLines(cell string) bool {
	cell = strings.TrimSpace(cell)
	return numericCell.MatchString(cell) || lineRange.MatchString(cell) || claimLedgerLineSpan.MatchString(cell)
}

// The Execution Substrate source baseline table of the claim ledger lies
// between these two headings.
const (
	claimLedgerBaselineStart = "### Execution Substrate"
	claimLedgerBaselineEnd   = "### Control Plane"
)

// claimLedgerLineProblems returns one message for each place in a claim
// ledger that cites this repository by line: each line-citing code span of
// each ES citation, on every line, and each cell of the Execution Substrate
// source baseline table that cites by line. A ledger without that table is a
// problem too. TestClaimLedgerCitesThisRepositoryBySection runs it on the
// real ledger and on small synthetic ones.
func claimLedgerLineProblems(ledger string) []string {
	var problems []string
	lines := strings.Split(ledger, "\n")
	for i, line := range lines {
		for _, span := range claimLedgerLineCitations(line) {
			problems = append(problems, fmt.Sprintf("line %d cites this repository by line (%s); link the section heading instead", i+1, span))
		}
	}
	inBaseline, sawBaseline := false, false
	for i, line := range lines {
		switch strings.TrimSpace(line) {
		case claimLedgerBaselineStart:
			inBaseline, sawBaseline = true, true
			continue
		case claimLedgerBaselineEnd:
			inBaseline = false
			continue
		}
		if !inBaseline || !strings.HasPrefix(strings.TrimSpace(line), "|") {
			continue
		}
		for _, cell := range strings.Split(strings.Trim(strings.TrimSpace(line), "|"), "|") {
			if claimLedgerBaselineCellCitesLines(cell) {
				problems = append(problems, fmt.Sprintf("line %d: a source baseline cell cites this repository by line (%s)", i+1, strings.TrimSpace(cell)))
			}
		}
	}
	if !sawBaseline {
		problems = append(problems, fmt.Sprintf("no source baseline table under %q", claimLedgerBaselineStart))
	}
	return problems
}

// TestClaimLedgerCitesThisRepositoryBySection keeps the claim ledger's
// citations of this repository on section headings: its lines move.
// TestMarkdownHeadingLinksResolve checks that each linked heading exists.
func TestClaimLedgerCitesThisRepositoryBySection(t *testing.T) {
	ledger := mustRead(t, claimLedgerPath)
	for _, problem := range claimLedgerLineProblems(ledger) {
		t.Errorf("%s: %s", claimLedgerPath, problem)
	}
	assertContainsAll(t, "claim ledger citation rule", compactText(ledger),
		"References into this repository cite sections, not lines, because lines move with every edit.",
		"They were mapped from the 53 line ranges this ledger cited when it was written, at commit `6300b9591f2f5443a2bd61e05134fd5a425ad3bf`: each range is linked to the whole sections that contain it, named by their current headings.",
		"Nine of the distinct ranges stopped inside a section, so their links are wider than the lines first cited, and a claim that cites one of them rests only on the part the range covered.",
		"The Infrastructure Manager ranges match its commit `3c9d21b03fa5756ca853ecaaf7b0314ade647fea`",
		"No Control Plane commit was recorded",
	)
	if links := strings.Count(ledger, "ES [`"); links < 50 {
		t.Errorf("%s has %d section links into this repository, want the 50 or more it cites", claimLedgerPath, links)
	}
}

// TestClaimLedgerLineGuardFindsEachCitation shows that the guard above finds
// every line citation it is meant to refuse, each one once, in any ES
// citation of a line, and nothing else. Each case lists exactly what must be
// found, so a guard that keeps only the first or the last citation of a line,
// stops at the first find, keeps one span per citation, or drops repeats
// fails here.
func TestClaimLedgerLineGuardFindsEachCitation(t *testing.T) {
	a, b, c := "ES [`a.md` § A](a.md#a)", "ES [`b.md` § B](b.md#b)", "ES [`c.md` § C](c.md#c)"
	for _, tc := range []struct {
		line string
		want []string
	}{
		// One ES citation.
		{"ES `.docs/mvp.md:40-68`", []string{"`.docs/mvp.md:40-68`"}},
		{"ES `README.md:1`", []string{"`README.md:1`"}},
		{"| ES `.docs/execution_lifecycle/contracts.md:77-158`; CP x |", []string{"`.docs/execution_lifecycle/contracts.md:77-158`"}},
		{"ES `.docs/mvp.md#L40`", []string{"`.docs/mvp.md#L40`"}},
		{a + ", `51-82`", []string{"`51-82`"}},
		{a + ", `51–82`", []string{"`51–82`"}},
		{a + ", `L70`", []string{"`L70`"}},
		{a + ", `70`", []string{"`70`"}},
		{"| ES [`x.md` § A](x.md#a) and [§ B](x.md#b), `L70` |", []string{"`L70`"}},
		{a + " (CP compatibility), `160-228`; CP `README.md:1-12`", []string{"`160-228`"}},
		{a + ", `51-82`, `L70`", []string{"`51-82`", "`L70`"}},
		// Three ES citations on one line, in each of the forms that end one.
		{a + ", `51-82`; " + b + "; " + c, []string{"`51-82`"}},
		{a + "; " + b + ", `51-82`; " + c, []string{"`51-82`"}},
		{a + "; " + b + "; " + c + ", `51-82`", []string{"`51-82`"}},
		{"| " + a + ", `51-82` | " + b + " | " + c + " |", []string{"`51-82`"}},
		{"| " + a + " | " + b + ", `51-82` | " + c + " |", []string{"`51-82`"}},
		{"| " + a + " | " + b + " | " + c + ", `51-82` |", []string{"`51-82`"}},
		{a + ", `51-82` CP `x.md:1` " + b + "; " + c, []string{"`51-82`"}},
		{a + ", `51-82`; " + b + "; " + c + ", `90-95`", []string{"`51-82`", "`90-95`"}},
		{a + ", `51-82`; " + b + ", `51-82`; " + c + ", `51-82`", []string{"`51-82`", "`51-82`", "`51-82`"}},
		{a + ", `51-82`, `L70`; " + b + ", `README.md:3`; " + c + ", `90–95`", []string{"`51-82`", "`L70`", "`README.md:3`", "`90–95`"}},
		// Nothing to find.
		{"CP `README.md:1-12`", nil},
		{"IM `.docs/commands.md:545-631`, `118-149`", nil},
		{"ES [`.docs/mvp.md` § Explicit non-claims](../mvp.md#explicit-non-claims)", nil},
		{"ES `AGENTS.md` section 12", nil},
		{a + "; CP `README.md:1-12`, `118-149`", nil},
		{"| " + a + " | IM `.docs/commands.md:545-631`, `296` |", nil},
		{a + " and IM `.docs/commands.md:545-631`, `296`", nil},
		{a + "; " + b + "; " + c, nil},
	} {
		if got := claimLedgerLineCitations(tc.line); strings.Join(got, " ") != strings.Join(tc.want, " ") || len(got) != len(tc.want) {
			t.Errorf("claimLedgerLineCitations(%q) = %q, want %q", tc.line, got, tc.want)
		}
	}

	for _, cell := range []string{"`229`", " 229 ", "Lines `1-229`", "Lines 1-229", "1-229", "`L12`, `L40-L68`", "`README.md:12`", "`.docs/mvp.md#L40`"} {
		if !claimLedgerBaselineCellCitesLines(cell) {
			t.Errorf("the source baseline check misses the cell %q", cell)
		}
	}
	for _, cell := range []string{
		"The whole file",
		"Sections 1, 2, 3, 4 and 8",
		"Sections 3 to 5, 7 and 10 to 12, cited by section because its lines move",
		"[§ Primary Program Orientation](../../PLANS.md#primary-program-orientation)",
		"`.docs/system_overview/boundaries.md`",
	} {
		if claimLedgerBaselineCellCitesLines(cell) {
			t.Errorf("the source baseline check refuses the cell %q", cell)
		}
	}

	// The whole check on small ledgers: every line is scanned, every row of
	// the baseline table and only that table, and a missing table is found.
	clean := strings.Join([]string{
		"# Ledger",
		"| C1 | claim | " + a + "; CP `README.md:1-12` |",
		claimLedgerBaselineStart,
		"| Source | Sections inspected | Why |",
		"| --- | --- | --- |",
		"| `x.md` | The whole file | reason |",
		claimLedgerBaselineEnd,
		"| `README.md` | `1-12` | CP lines may stay |",
	}, "\n")
	if got := claimLedgerLineProblems(clean); len(got) != 0 {
		t.Errorf("claimLedgerLineProblems finds %q in a clean ledger", got)
	}
	dirty := strings.Join([]string{
		"| C0 | claim | " + b + ", `1-2` |",
		"| C1 | claim | " + a + ", `51-82`; " + b + ", `README.md:3` |",
		"| C2 | claim | " + a + "; " + b + "; " + c + ", `L70` |",
		claimLedgerBaselineStart,
		"| Source | Sections inspected | Why |",
		"| --- | --- | --- |",
		"| `x.md` | `229` | reason |",
		"| `y.md` | The whole file | reason |",
		"| `z.md` | Lines 1-229 | reason |",
		"| `w.md` | `L12` | `1-12` |",
		claimLedgerBaselineEnd,
		"| `README.md` | `1-12` | CP lines may stay |",
		"| C3 | claim | " + c + ", `90-95` |",
	}, "\n")
	want := []string{
		"line 1 cites this repository by line (`1-2`); link the section heading instead",
		"line 2 cites this repository by line (`51-82`); link the section heading instead",
		"line 2 cites this repository by line (`README.md:3`); link the section heading instead",
		"line 3 cites this repository by line (`L70`); link the section heading instead",
		"line 13 cites this repository by line (`90-95`); link the section heading instead",
		"line 7: a source baseline cell cites this repository by line (`229`)",
		"line 9: a source baseline cell cites this repository by line (Lines 1-229)",
		"line 10: a source baseline cell cites this repository by line (`L12`)",
		"line 10: a source baseline cell cites this repository by line (`1-12`)",
	}
	if got := claimLedgerLineProblems(dirty); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("claimLedgerLineProblems on a ledger with eight line citations = %q, want %q", got, want)
	}
	if got := claimLedgerLineProblems("# Ledger\n| C1 | claim | " + a + " |\n"); len(got) != 1 || !strings.Contains(got[0], "no source baseline table") {
		t.Errorf("claimLedgerLineProblems on a ledger without a baseline table = %q, want the missing table", got)
	}
}
