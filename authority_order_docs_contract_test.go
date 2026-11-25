package executionsubstrate_test

import (
	"sort"
	"strings"
	"testing"
)

// authorityOrderCopyPhrases are the forms in which documents restated the
// AGENTS.md authority order, or a file's rank in it, until 2026-11-25: a
// numbered copy of the order in twelve docs, an inline copy in four, and rank
// sentences in the standing rule files, their owning contracts, PLANS.md and
// README.md. AGENTS.md section 3 is the one place that states the order;
// every other document says what it governs. Each of the five lines of the
// order, without its number, is refused too.
var authorityOrderCopyPhrases = []string{
	"Authority for this document",
	"Authority follows the repository",
	"repo-wide authority hierarchy",
	"repository hierarchy in `AGENTS.md`",
	"`AGENTS.md` for agent operating rules",
	"`PLANS.md` for allowed redesign work",
	"for factual implemented behavior",
	"`AGENTS.md` section 3",
	"`PLANS.md`'s rank",
	"ranks it second",
	"ranks that file with",
	"keep this file's authority",
	"keep the authority they had",
	"and keep its authority",
}

// authorityOrderPhrases returns the refused phrases: the fixed forms above
// and each line of the order as AGENTS.md states it now, without its number.
func authorityOrderPhrases(t *testing.T) []string {
	t.Helper()
	phrases := append([]string{}, authorityOrderCopyPhrases...)
	for _, line := range authorityHierarchyLines(t) {
		phrases = append(phrases, strings.TrimSpace(line[strings.Index(line, ".")+1:]))
	}
	return phrases
}

// authorityOrderCopies returns the refused phrases that text holds.
func authorityOrderCopies(text string, phrases []string) []string {
	text = compactText(text)
	var found []string
	for _, phrase := range phrases {
		if strings.Contains(text, phrase) {
			found = append(found, phrase)
		}
	}
	return found
}

// TestAuthorityOrderIsStatedOnlyInAgents keeps the authority order in one
// place. AGENTS.md section 3 states it and says that it is the only place
// that does. No other Markdown file of the repository may restate the order,
// its own rank or another file's rank. The closed plan record is historical
// evidence, pinned by its SHA-256, and is not read.
func TestAuthorityOrderIsStatedOnlyInAgents(t *testing.T) {
	agents := compactText(mustRead(t, "AGENTS.md"))
	assertContainsAll(t, "AGENTS.md authority order rule", agents,
		"This section is the one place that states the authority order and the rank of a file in it. Other documents say what they govern; they do not restate the order, their own rank, or another file's rank.",
	)
	// The numbered forms of the order must still be AGENTS.md's own wording,
	// so that the phrases refused below track the order as it stands.
	for _, phrase := range []string{
		"`AGENTS.md` for agent operating rules",
		"`PLANS.md` for allowed redesign work",
		"for factual implemented behavior",
	} {
		if !strings.Contains(agents, phrase) {
			t.Errorf("AGENTS.md no longer states %q; update authorityOrderCopyPhrases with the order's wording", phrase)
		}
	}

	phrases := authorityOrderPhrases(t)
	files := repositoryTextFiles(t)
	names := make([]string, 0, len(files))
	for name := range files {
		if strings.HasSuffix(name, ".md") && name != "AGENTS.md" && name != plansRecordPath {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	if len(names) < 40 {
		t.Fatalf("checked %d Markdown files, want the repository's 40 or more", len(names))
	}
	for _, name := range names {
		for _, phrase := range authorityOrderCopies(string(files[name]), phrases) {
			t.Errorf("%s restates the authority order or a file's rank in it (%q); AGENTS.md section 3 is the one place that states it, so say what the document governs instead", name, phrase)
		}
	}
}

// TestAuthorityOrderGuardFindsEachFormOfCopy shows that the check above
// finds each form a copy took, and nothing in ordinary text.
func TestAuthorityOrderGuardFindsEachFormOfCopy(t *testing.T) {
	phrases := authorityOrderPhrases(t)
	for _, copied := range []string{
		"Authority for this document follows the repo-wide authority hierarchy:\n\n1. ...",
		"Authority follows the repository order:\n\n1. ...",
		"3. `.docs/system_overview/*` for architecture, contracts, boundaries, and change-governance rules",
		"4. `.docs/execution_lifecycle/*` for lifecycle design, contract, and implementation guidance",
		"5. current Go code and tests for factual implemented behavior",
		"Authority follows the repository hierarchy in `AGENTS.md`: `PLANS.md`,\n`.docs/system_overview/*`, and then current code/tests.",
		"The rules at `PLANS.md`'s rank are in the rule file.",
		"`AGENTS.md` section\n3 ranks that file with `PLANS.md`.",
		"They keep the authority they had in `PLANS.md`.",
		"They keep this file's authority.",
		"`AGENTS.md` ranks it second in authority.",
		"- `.docs/standing_rules/` for the standing rules that moved out of `PLANS.md` and keep its authority:",
	} {
		if len(authorityOrderCopies(copied, phrases)) == 0 {
			t.Errorf("copy %q is not refused", copied)
		}
	}
	for _, ordinary := range []string{
		"This document records the bounded Workstream A decision.",
		"If this document disagrees with current code and tests on implemented behavior, the code and tests win and this document must be realigned.",
		"Some architecture-defining seams remain intentionally reopened in `PLANS.md`.",
		"1. [AGENTS.md](AGENTS.md) for repository operating rules",
		"| `AGENTS.md` | Sections 3 to 5, 7 and 10 to 12, cited by section because its lines move | Authority hierarchy, classification vocabulary |",
		"The standing route rules for P0i to P0v are in `.docs/standing_rules/remote_alpha_operator_routes.md`.",
	} {
		if got := authorityOrderCopies(ordinary, phrases); len(got) != 0 {
			t.Errorf("ordinary text %q is refused for %q", ordinary, got)
		}
	}
}
