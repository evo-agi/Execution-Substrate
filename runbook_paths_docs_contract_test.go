package executionsubstrate_test

import (
	"bytes"
	"net/url"
	"os"
	"path"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// externalMarkdownLinkTargets lists the only relative Markdown link targets
// that may leave this repository. Each key is the target resolved against the
// repository root; such targets are never checked on disk, because what sits
// next to a checkout differs between machines.
var externalMarkdownLinkTargets = map[string]string{
	"../Control Plane/.docs/long-running-operator-mode-contract.md": "the retired Control Plane repository's contract, which Control Plane-era docs link to in a sibling checkout; that repository is not part of this one, and cleaning up Control Plane leftovers needs an explicit decision",
}

var (
	markdownFence    = regexp.MustCompile("(?ms)^ {0,3}(```|~~~).*?^ {0,3}(```|~~~)[^\n]*$")
	markdownCodeSpan = regexp.MustCompile("`[^`\n]*`")
	// An inline link or image: ](target) or ](<target>), optionally with a
	// title in double quotes, single quotes or parentheses.
	markdownInlineLink = regexp.MustCompile(`\]\(\s*(?:<([^<>\n]*)>|([^)\s<>]+))(?:\s+(?:"[^"\n]*"|'[^'\n]*'|\([^()\n]*\)))?\s*\)`)
	// A reference definition, [label]: target. A label that starts with "^"
	// is a footnote, whose text is not a link target.
	markdownReferenceDefinition = regexp.MustCompile(`(?m)^ {0,3}\[[^\]^\n][^\]\n]*\]:[ \t]*(?:<([^<>\n]*)>|(\S+))`)
	// An href or src attribute in an HTML tag.
	markdownHTMLLink  = regexp.MustCompile(`(?i)<[a-z][a-z0-9-]*\s[^>]*?\b(?:href|src)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'>]+))`)
	markdownURLScheme = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9+.-]*:`)
	// A runbook path: segments of word characters, dots and dashes, with
	// single spaces allowed inside a segment (the runbook names contain
	// spaces), ending in ".md".
	runbookPathMention = regexp.MustCompile(`\.runbooks/(?:[A-Za-z0-9_.-]+(?: [A-Za-z0-9_.-]+)*/)*[A-Za-z0-9_.-]+(?: [A-Za-z0-9_.-]+)*\.md`)
)

// markdownLinkTargets returns every link target in a Markdown text: inline
// links and images, reference definitions, and HTML href and src attributes.
// Targets inside fenced code blocks and code spans are not links and are left
// out.
func markdownLinkTargets(markdown string) []string {
	text := markdownFence.ReplaceAllString(markdown, "")
	text = markdownCodeSpan.ReplaceAllString(text, "x")
	var targets []string
	for _, pattern := range []*regexp.Regexp{markdownInlineLink, markdownReferenceDefinition, markdownHTMLLink} {
		for _, match := range pattern.FindAllStringSubmatch(text, -1) {
			for _, group := range match[1:] {
				if group != "" {
					targets = append(targets, group)
					break
				}
			}
		}
	}
	return targets
}

// repositoryTextFiles returns the files of the repository (see
// repositoryFiles) that exist in the tree as regular files and contain no
// NUL byte, with their contents.
func repositoryTextFiles(t *testing.T) map[string][]byte {
	t.Helper()
	paths, tracked := repositoryFiles(t)
	files := map[string][]byte{}
	for _, filePath := range paths {
		info, err := os.Lstat(filePath)
		if os.IsNotExist(err) {
			continue
		} else if err != nil {
			t.Fatalf("stat repository path %s: %v", filePath, err)
		}
		if !info.Mode().IsRegular() {
			continue
		}
		data, err := os.ReadFile(filePath)
		if err != nil {
			t.Fatalf("read repository path %s: %v", filePath, err)
		}
		if bytes.IndexByte(data, 0) >= 0 {
			continue
		}
		files[filePath] = data
	}
	if len(files) == 0 {
		t.Fatalf("the repository's file list (tracked by git: %v) has no readable text file", tracked)
	}
	return files
}

// TestMarkdownRelativeLinksResolve requires every relative link in a
// Markdown file of the repository (in any form markdownLinkTargets reads) to
// name a file or directory in this repository, apart from the named external
// targets above.
func TestMarkdownRelativeLinksResolve(t *testing.T) {
	files := repositoryTextFiles(t)
	names := make([]string, 0, len(files))
	for name := range files {
		if strings.HasSuffix(name, ".md") {
			names = append(names, name)
		}
	}
	sort.Strings(names)

	checked := 0
	usedExternal := map[string]bool{}
	var broken []string
	for _, name := range names {
		for _, target := range markdownLinkTargets(string(files[name])) {
			if markdownURLScheme.MatchString(target) || strings.HasPrefix(target, "#") {
				continue
			}
			targetPath := target
			if index := strings.IndexAny(targetPath, "#?"); index >= 0 {
				targetPath = targetPath[:index]
			}
			if targetPath == "" {
				continue
			}
			decoded, err := url.PathUnescape(targetPath)
			if err != nil {
				broken = append(broken, name+": "+target+" (cannot decode: "+err.Error()+")")
				continue
			}
			checked++
			resolved := path.Clean(path.Join(path.Dir(name), decoded))
			if resolved == ".." || strings.HasPrefix(resolved, "../") || path.IsAbs(decoded) {
				if _, ok := externalMarkdownLinkTargets[resolved]; ok {
					usedExternal[resolved] = true
					continue
				}
				broken = append(broken, name+": "+target+" (leaves the repository)")
				continue
			}
			if _, err := os.Stat(resolved); err != nil {
				broken = append(broken, name+": "+target+" (no "+resolved+")")
			}
		}
	}
	if checked == 0 {
		t.Fatal("found no relative Markdown links; the link pattern no longer matches")
	}
	if len(broken) > 0 {
		t.Fatalf("relative Markdown links that do not resolve in this repository:\n%s", strings.Join(broken, "\n"))
	}
	for target := range externalMarkdownLinkTargets {
		if !usedExternal[target] {
			t.Errorf("external link target %q is allowed but no longer linked; remove it from externalMarkdownLinkTargets", target)
		}
	}
}

// TestRunbookPathMentionsExist requires every .runbooks/…/*.md path written
// in a file of the repository (scripts, Go code, docs) to exist, so that a
// rename or a careless merge cannot leave a script printing a runbook path
// that is gone. A mention must sit on one line: a path wrapped across two
// lines, or built from parts at run time, is not seen.
func TestRunbookPathMentionsExist(t *testing.T) {
	files := repositoryTextFiles(t)
	names := make([]string, 0, len(files))
	for name := range files {
		if name != "runbook_paths_docs_contract_test.go" {
			names = append(names, name)
		}
	}
	sort.Strings(names)

	mentions := 0
	scriptMentions := 0
	var missing []string
	for _, name := range names {
		for _, mention := range runbookPathMention.FindAllString(string(files[name]), -1) {
			mentions++
			if strings.HasPrefix(name, "scripts/") {
				scriptMentions++
			}
			if _, err := os.Stat(mention); err != nil {
				missing = append(missing, name+": "+mention)
			}
		}
	}
	if mentions == 0 || scriptMentions == 0 {
		t.Fatalf("found %d runbook path mentions, %d in scripts/; the path pattern no longer matches", mentions, scriptMentions)
	}
	if len(missing) > 0 {
		t.Fatalf("runbook paths named in repository files that do not exist:\n%s", strings.Join(missing, "\n"))
	}
}

// TestMarkdownLinkTargetsReadsEveryLinkForm pins the link forms that
// TestMarkdownRelativeLinksResolve checks, so that narrowing a pattern fails
// here instead of quietly checking fewer links.
func TestMarkdownLinkTargetsReadsEveryLinkForm(t *testing.T) {
	cases := []struct {
		markdown string
		want     []string
	}{
		{"[a](plain.md)", []string{"plain.md"}},
		{"![a](image.png)", []string{"image.png"}},
		{"[a](Name%20With%20Spaces.md#part)", []string{"Name%20With%20Spaces.md#part"}},
		{"[a](<name with spaces.md>)", []string{"name with spaces.md"}},
		{`[a](double.md "title")`, []string{"double.md"}},
		{"[a](single.md 'title')", []string{"single.md"}},
		{"[a](paren.md (title))", []string{"paren.md"}},
		{"[a](https://example.com/x.md)", []string{"https://example.com/x.md"}},
		{"[ref]: reference.md", []string{"reference.md"}},
		{"   [ref]: <reference with spaces.md> \"title\"", []string{"reference with spaces.md"}},
		{"[^1]: A footnote, not a link.", nil},
		{`<a href="html-double.md">a</a>`, []string{"html-double.md"}},
		{"<img alt='x' src='html-single.png'>", []string{"html-single.png"}},
		{"<a class=x href=html-bare.md>a</a>", []string{"html-bare.md"}},
		{"`[a](in-code-span.md)`", nil},
		{"```\n[a](in-fence.md)\n```", nil},
	}
	for _, tc := range cases {
		got := markdownLinkTargets(tc.markdown)
		if strings.Join(got, "\n") != strings.Join(tc.want, "\n") {
			t.Errorf("markdownLinkTargets(%q) = %q, want %q", tc.markdown, got, tc.want)
		}
	}
}
