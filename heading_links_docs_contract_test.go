package executionsubstrate_test

import (
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

// claimLedgerLineCitations returns the code spans in a line of the claim
// ledger that cite this repository by line.
func claimLedgerLineCitations(line string) []string {
	var found []string
	for _, citation := range claimLedgerESCitation.FindAllString(line, -1) {
		found = append(found, claimLedgerLineSpan.FindAllString(citation, -1)...)
	}
	return found
}

// TestClaimLedgerCitesThisRepositoryBySection keeps the claim ledger's
// citations of this repository on section headings: its lines move.
// TestMarkdownHeadingLinksResolve checks that each linked heading exists.
func TestClaimLedgerCitesThisRepositoryBySection(t *testing.T) {
	ledger := mustRead(t, claimLedgerPath)
	for i, line := range strings.Split(ledger, "\n") {
		for _, match := range claimLedgerLineCitations(line) {
			t.Errorf("%s:%d cites this repository by line (%s); link the section heading instead", claimLedgerPath, i+1, match)
		}
	}
	baseline := docSection(t, ledger, "### Execution Substrate", "### Control Plane")
	for _, line := range strings.Split(baseline, "\n") {
		if !strings.HasPrefix(line, "|") {
			continue
		}
		for _, cell := range strings.Split(strings.Trim(line, "|"), "|") {
			if cell = strings.TrimSpace(cell); numericCell.MatchString(cell) || lineRange.MatchString(cell) || claimLedgerLineSpan.MatchString(cell) {
				t.Errorf("%s source baseline cites this repository by line: %q", claimLedgerPath, line)
			}
		}
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

	for _, line := range []string{
		"ES `.docs/mvp.md:40-68`",
		"ES `README.md:1`",
		"| ES `.docs/execution_lifecycle/contracts.md:77-158`; CP x |",
		"ES `.docs/mvp.md#L40`",
		"ES [`x.md` § A](x.md#a), `51-82`",
		"| ES [`x.md` § A](x.md#a) and [§ B](x.md#b), `L70` |",
		"ES [`x.md` § A](x.md#a) (CP compatibility), `160-228`; CP `README.md:1-12`",
	} {
		if len(claimLedgerLineCitations(line)) == 0 {
			t.Errorf("claimLedgerLineCitations misses %q", line)
		}
	}
	for _, line := range []string{
		"CP `README.md:1-12`",
		"IM `.docs/commands.md:545-631`, `118-149`",
		"ES [`.docs/mvp.md` § Explicit non-claims](../mvp.md#explicit-non-claims)",
		"ES `AGENTS.md` section 12",
		"ES [`x.md` § A](x.md#a); CP `README.md:1-12`, `118-149`",
		"| ES [`x.md` § A](x.md#a) | IM `.docs/commands.md:545-631`, `296` |",
		"ES [`x.md` § A](x.md#a) and IM `.docs/commands.md:545-631`, `296`",
	} {
		if found := claimLedgerLineCitations(line); len(found) > 0 {
			t.Errorf("claimLedgerLineCitations refuses %q (%q)", line, found)
		}
	}
	for _, cell := range []string{"`229`", "Lines `1-229`", "1-229", "`L12`, `L40-L68`"} {
		if !numericCell.MatchString(cell) && !lineRange.MatchString(cell) && !claimLedgerLineSpan.MatchString(cell) {
			t.Errorf("the source baseline check misses the cell %q", cell)
		}
	}
}
