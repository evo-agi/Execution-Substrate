package executionsubstrate_test

import (
	"regexp"
	"sort"
	"strings"
	"testing"
)

// The authority order, a file's rank in it, and which source wins when two
// disagree are stated in one place: AGENTS.md section 3. Every other
// Markdown file says what it governs and which document owns a topic, and
// nothing about which file or source ranks above, controls or wins over
// another. Until 2026-11-25 sixteen docs restated the order and a test
// required them to; the checks below keep such statements out by meaning,
// not only in the wordings that were removed.

// authorityMarkdownLink matches a Markdown link or image.
var authorityMarkdownLink = regexp.MustCompile(`!?\[([^\]]*)\]\(([^)]*)\)`)

// normalizeAuthorityText reads text the way the checks compare it: a link as
// its text, followed by its target in parentheses when the text does not
// already name the target's file; without backticks or emphasis; "§" as
// "section"; lower case; whitespace collapsed.
func normalizeAuthorityText(text string) string {
	text = authorityMarkdownLink.ReplaceAllStringFunc(text, func(link string) string {
		parts := authorityMarkdownLink.FindStringSubmatch(link)
		label, target := parts[1], strings.SplitN(parts[2], "#", 2)[0]
		base := target[strings.LastIndex(target, "/")+1:]
		if base == "" || strings.Contains(strings.ToLower(label), strings.ToLower(base)) {
			return label
		}
		return label + " (" + target + ")"
	})
	text = strings.NewReplacer("`", "", "**", "", "__", "", "§", " section ", " ", " ").Replace(text)
	return compactText(strings.ToLower(text))
}

var (
	authorityUnitStart     = regexp.MustCompile(`^\s*(?:[-*+]\s|\d+[.)]\s|#|\|)`)
	authoritySentenceBreak = regexp.MustCompile(`[.!?]\s+`)
)

// authoritySentences splits a Markdown document into normalized sentences.
// A blank line, a heading, a list item and a table row each start a new
// unit; each table cell is its own unit; a unit is cut after ".", "!" or
// "?" followed by a space. A semicolon does not cut, so a rank stated after
// one is still read with the file named before it.
func authoritySentences(doc string) []string {
	var units []string
	var current []string
	flush := func() {
		if len(current) > 0 {
			units = append(units, strings.Join(current, " "))
			current = nil
		}
	}
	for _, line := range strings.Split(doc, "\n") {
		trimmed := strings.TrimSpace(line)
		switch {
		case trimmed == "":
			flush()
		case strings.HasPrefix(trimmed, "|"):
			flush()
			units = append(units, strings.Split(strings.Trim(trimmed, "|"), "|")...)
		case authorityUnitStart.MatchString(line):
			flush()
			current = append(current, trimmed)
		default:
			current = append(current, trimmed)
		}
	}
	flush()

	var sentences []string
	for _, unit := range units {
		unit = normalizeAuthorityText(unit)
		for unit != "" {
			cut := authoritySentenceBreak.FindStringIndex(unit)
			if cut == nil {
				sentences = append(sentences, unit)
				break
			}
			sentences = append(sentences, strings.TrimSpace(unit[:cut[0]+1]))
			unit = unit[cut[1]:]
		}
	}
	return sentences
}

// authorityOrderFile matches a file or source of the authority order, or a
// document speaking of itself, in normalized text.
var authorityOrderFile = regexp.MustCompile(`agents\.md|plans\.md|standing_rules|system_overview|execution_lifecycle|readme|plans-record|\.docs/|\bthis (?:file|document|doc|record|contract|page)\b|\bcode (?:and|or) tests\b|\bcode/tests\b|\bgo code\b|\b(?:the|those|these) docs\b`)

// authorityOrderMember matches the members of the order itself; a sentence
// that names two of them beside the word "authority" lists the order.
var authorityOrderMember = regexp.MustCompile(`agents\.md|plans\.md|standing_rules|system_overview|execution_lifecycle|\bcode (?:and|or) tests\b|\bcode/tests\b|\bgo code\b`)

// authorityRule is one way a sentence states a rank. A sentence is refused
// when it names a file of the order (authorityOrderFile) and a rule matches.
type authorityRule struct {
	name  string
	match func(sentence string) bool
}

func authorityPattern(name, pattern string) authorityRule {
	re := regexp.MustCompile(pattern)
	return authorityRule{name: name, match: re.MatchString}
}

var authorityRankRules = []authorityRule{
	authorityPattern("ranks", `\b(?:out)?rank(?:s|ed|ing)?\b`),
	authorityPattern("authority order", `\bauthority (?:order|hierarchy)\b`),
	authorityPattern("authority follows", `\bauthority (?:follows|for this)\b`),
	authorityPattern("held authority", `\b(?:same|no|no current|its|their|keeps?|kept) authority\b|'s authority\b`),
	authorityPattern("wins", `\bwins?\b`),
	authorityPattern("controls", `\bcontrols\b|\bcontrolled by\b|\bcontrol (?:this|that|the) (?:file|document|doc)`),
	authorityPattern("precedence", `\b(?:precedence|prevails?|defers? to|overrides?|supersedes?|prefer (?:the )?code)\b`),
	authorityPattern("place in the order", `\b(?:first|second|third|fourth|fifth|last) in (?:authority|rank|the order)\b`),
	authorityPattern("section 3 pointer", `agents\.md,? section 3\b`),
	{name: "authority beside two members of the order", match: func(sentence string) bool {
		if !strings.Contains(sentence, "authority") {
			return false
		}
		seen := map[string]bool{}
		for _, member := range authorityOrderMember.FindAllString(sentence, -1) {
			seen[member] = true
		}
		return len(seen) >= 2
	}},
}

// authorityCopyVariants are shorter wordings of order lines that docs
// carried; they are refused anywhere in a document, like the order lines.
var authorityCopyVariants = []authorityRule{
	authorityPattern("order line 2, shorter wording", `plans\.md for allowed redesign work`),
	authorityPattern("order line 5, shorter wording", `for factual implemented behavior`),
}

// authorityOrderLineRules returns one rule per line of the order as
// AGENTS.md states it now, without its number, refused anywhere in a
// document.
func authorityOrderLineRules(t *testing.T) []authorityRule {
	t.Helper()
	var rules []authorityRule
	for i, line := range authorityHierarchyLines(t) {
		text := normalizeAuthorityText(strings.TrimSpace(line[strings.Index(line, ".")+1:]))
		rules = append(rules, authorityRule{
			name:  "order line " + string(rune('1'+i)),
			match: func(doc string) bool { return strings.Contains(doc, text) },
		})
	}
	return rules
}

// authorityStatement is one refused statement: the rule and the sentence
// (or, for a copy of an order line, the rule alone).
type authorityStatement struct {
	rule, sentence string
}

// authorityStatements returns every statement of a rank or copy of the
// order in doc.
func authorityStatements(t *testing.T, doc string) []authorityStatement {
	t.Helper()
	var found []authorityStatement
	whole := normalizeAuthorityText(doc)
	for _, rule := range append(authorityOrderLineRules(t), authorityCopyVariants...) {
		if rule.match(whole) {
			found = append(found, authorityStatement{rule: rule.name})
		}
	}
	for _, sentence := range authoritySentences(doc) {
		if !authorityOrderFile.MatchString(sentence) {
			continue
		}
		for _, rule := range authorityRankRules {
			if rule.match(sentence) {
				found = append(found, authorityStatement{rule: rule.name, sentence: sentence})
			}
		}
	}
	return found
}

// authorityAllowedSentences are the sentences outside AGENTS.md that the
// rules above match but that state no rank, by file and normalized text.
// Each says what a document governs or owns, or uses a rule word in another
// sense. An entry that no longer matches a sentence fails the test, so the
// list stays exact.
var authorityAllowedSentences = map[string][]string{
	// What a disposition grants, not a rank between the two files it names.
	".docs/system_overview/capability_probing.md": {
		"the development-source disposition in .docs/standing_rules/execution_admission_and_custody.md and .docs/execution_lifecycle/contracts.md grants no startup or workload authority.",
	},
}

// TestAuthorityOrderIsStatedOnlyInAgents keeps the authority order, a
// file's rank and which source wins in AGENTS.md section 3. It reads every
// git-listed Markdown file except AGENTS.md and the closed plan record,
// which is historical evidence pinned by its SHA-256.
func TestAuthorityOrderIsStatedOnlyInAgents(t *testing.T) {
	assertContainsAll(t, "AGENTS.md authority order rule", compactText(mustRead(t, "AGENTS.md")),
		"This section is the one place that states the authority order, the rank of a file in it, and which source wins when two disagree.",
		"Other documents say what they govern and which document owns a topic; they do not restate the order or say that one file or source ranks above, controls, or wins over another.",
		// The two ranks that docs stated for themselves until 2026-11-25 and
		// that now live only here.
		"The Remote Alpha route design records directly under `.docs/` (the `remote_alpha_operator_healthcheck_*.md` files) rank after `.docs/system_overview/*`.",
		"If docs and code disagree on factual behavior, code and tests win for current behavior, and the docs must be realigned.",
	)

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

	used := map[string]bool{}
	for _, name := range names {
		allowed := map[string]bool{}
		for _, sentence := range authorityAllowedSentences[name] {
			allowed[sentence] = true
		}
		for _, statement := range authorityStatements(t, string(files[name])) {
			if statement.sentence != "" && allowed[statement.sentence] {
				used[name+"\x00"+statement.sentence] = true
				continue
			}
			if statement.sentence == "" {
				t.Errorf("%s copies the authority order (%s); AGENTS.md section 3 is the one place that states it", name, statement.rule)
			} else {
				t.Errorf("%s states a rank (%s): %q; AGENTS.md section 3 is the one place that does, so say what the document governs instead", name, statement.rule, statement.sentence)
			}
		}
	}
	for name, sentences := range authorityAllowedSentences {
		for _, sentence := range sentences {
			if !used[name+"\x00"+sentence] {
				t.Errorf("authorityAllowedSentences lists %s %q, which no longer matches a rule there; remove the entry", name, sentence)
			}
		}
	}
}

// TestAuthorityOrderGuardFindsEachFormOfRank shows that each rule refuses an
// example that no other rule refuses, that every form audit 02 probed is
// refused, and that ordinary sentences pass.
func TestAuthorityOrderGuardFindsEachFormOfRank(t *testing.T) {
	ruleNames := func(text string) []string {
		var names []string
		for _, statement := range authorityStatements(t, text) {
			names = append(names, statement.rule)
		}
		sort.Strings(names)
		return names
	}

	only := map[string]string{
		"ranks":              "This document ranks below `PLANS.md`.",
		"authority order":    "See `AGENTS.md` for the authority hierarchy.",
		"authority follows":  "Authority for this document: see the list.",
		"held authority":     "These rules carry the same authority as `PLANS.md`.",
		"wins":               "Where they differ, `PLANS.md` wins.",
		"controls":           "If they differ, `PLANS.md` controls.",
		"precedence":         "`PLANS.md` takes precedence here.",
		"place in the order": "`PLANS.md` is second in the order after the other file.",
		"section 3 pointer":  "Read [`AGENTS.md`](../../AGENTS.md) §3 first.",
		"authority beside two members of the order": "Authority, highest first: AGENTS.md, then PLANS.md.",
		"order line 2, shorter wording":             "2. `PLANS.md` for allowed redesign work and reopened seams",
		"order line 5, shorter wording":             "then current code/tests for factual implemented behavior",
	}
	var fixed []authorityRule
	for _, rules := range [][]authorityRule{authorityRankRules, authorityCopyVariants} {
		fixed = append(fixed, rules...)
	}
	ruled := map[string]bool{}
	for _, rule := range fixed {
		ruled[rule.name] = true
		example, ok := only[rule.name]
		if !ok {
			t.Errorf("rule %q has no example that only it refuses", rule.name)
			continue
		}
		if got := ruleNames(example); strings.Join(got, ",") != rule.name {
			t.Errorf("example %q is refused by %q, want only %q", example, got, rule.name)
		}
	}
	// A rule that is deleted leaves its example here; that fails too.
	for name := range only {
		if !ruled[name] {
			t.Errorf("example for rule %q names no rule; restore the rule or remove the example", name)
		}
	}
	for i, line := range authorityHierarchyLines(t) {
		want := "order line " + string(rune('1'+i))
		got := ruleNames("A doc that lists it:\n\n" + line + "\n")
		found := false
		for _, name := range got {
			found = found || name == want
		}
		if !found {
			t.Errorf("a copy of %q is refused by %q, want %q among them", line, got, want)
		}
	}

	// Audit 02 probes P1 to P14: each must be refused.
	for _, probe := range []string{
		"The authority order is in `AGENTS.md` §3.",
		"Authority follows AGENTS.md section 3.",
		"See [`AGENTS.md`](../../AGENTS.md) section 3 for the authority order.",
		"authority for this document follows the repo order:",
		"1. [`AGENTS.md`](../../AGENTS.md) for agent operating rules\n2. [`PLANS.md`](../../PLANS.md) for allowed redesign work",
		"Authority, highest first: AGENTS.md, PLANS.md, system overview docs, lifecycle docs, then code and tests.",
		"This document ranks below `PLANS.md` and above the lifecycle docs.",
		"These rules carry the same authority as `PLANS.md`.",
		"`PLANS.md` is second in authority after `AGENTS.md`.",
		"**Authority:** `AGENTS.md`, then `PLANS.md`, then `.docs/system_overview/*`.",
		"Route-specific `.docs/` design records rank after `.docs/system_overview/*`.",
		"Authority follows the [repository](../AGENTS.md) hierarchy: `PLANS.md`, then `.docs/system_overview/*`.",
		"If this file and `PLANS.md` differ on scope, `PLANS.md` controls.",
		"it holds no current authority, and where it differs from this file or from an owning `.docs/` contract, they win.",
		// Forms this PR removed.
		"If this document disagrees with current code and tests on implemented behavior, the code and tests win and this document must be realigned.",
		"When existing prose disagrees with code or tests, prefer code and tests over this document.",
		"- Code and tests outrank stale prose.",
		"Where this README and those docs disagree, the docs win.",
		"The standing rules at `PLANS.md`'s rank are in the rule file.",
		"They keep this file's authority (`AGENTS.md` section 3).",
		"- [the closed record](.docs/history/plans-record.md); it is historical evidence with no current authority, so read it only when needed",
		"For architecture and contracts, defer to the docs below.",
	} {
		if len(ruleNames(probe)) == 0 {
			t.Errorf("probe %q is not refused", probe)
		}
	}

	for _, ordinary := range []string{
		"This document records the bounded Workstream A decision.",
		"This file is authoritative for current endpoint, response, error, and lookup semantics.",
		"Some architecture-defining seams remain intentionally reopened in `PLANS.md`.",
		"1. [AGENTS.md](AGENTS.md) for repository operating rules",
		"| `AGENTS.md` | Sections 3 to 5, 7 and 10 to 12, cited by section because its lines move | Authority hierarchy, classification vocabulary |",
		"The standing route rules for P0i to P0v are in `.docs/standing_rules/remote_alpha_operator_routes.md`.",
		"See `.docs/system_overview/contracts.md` section 3A for the caller authentication contract.",
		"Nomad access control is described in `.docs/system_overview/configuration.md`.",
	} {
		if got := ruleNames(ordinary); len(got) != 0 {
			t.Errorf("ordinary text %q is refused by %q", ordinary, got)
		}
	}
}
