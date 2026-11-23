package executionsubstrate_test

import (
	"bytes"
	"net/url"
	"os"
	"os/exec"
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
	markdownFence      = regexp.MustCompile("(?ms)^ {0,3}(```|~~~).*?^ {0,3}(```|~~~)[^\n]*$")
	markdownCodeSpan   = regexp.MustCompile("`[^`\n]*`")
	markdownInlineLink = regexp.MustCompile(`\]\(\s*<?([^)\s>]+)>?(?:\s+"[^"]*")?\s*\)`)
	markdownURLScheme  = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9+.-]*:`)
	// A runbook path: segments of word characters, dots and dashes, with
	// single spaces allowed inside a segment (the runbook names contain
	// spaces), ending in ".md".
	runbookPathMention = regexp.MustCompile(`\.runbooks/(?:[A-Za-z0-9_.-]+(?: [A-Za-z0-9_.-]+)*/)*[A-Za-z0-9_.-]+(?: [A-Za-z0-9_.-]+)*\.md`)
)

// trackedTextFiles returns the tracked files that exist in the worktree and
// contain no NUL byte, with their contents.
func trackedTextFiles(t *testing.T) map[string][]byte {
	t.Helper()
	output, err := exec.Command("git", "ls-files", "-z").Output()
	if err != nil {
		t.Fatalf("git ls-files inventory failed: %v", err)
	}
	files := map[string][]byte{}
	for _, trackedPath := range strings.Split(strings.TrimSuffix(string(output), "\x00"), "\x00") {
		if trackedPath == "" {
			continue
		}
		info, err := os.Lstat(trackedPath)
		if os.IsNotExist(err) {
			continue
		} else if err != nil {
			t.Fatalf("stat tracked path %s: %v", trackedPath, err)
		}
		if !info.Mode().IsRegular() {
			continue
		}
		data, err := os.ReadFile(trackedPath)
		if err != nil {
			t.Fatalf("read tracked path %s: %v", trackedPath, err)
		}
		if bytes.IndexByte(data, 0) >= 0 {
			continue
		}
		files[trackedPath] = data
	}
	if len(files) == 0 {
		t.Fatal("git ls-files listed no readable tracked files")
	}
	return files
}

// TestMarkdownRelativeLinksResolve requires every relative link in a tracked
// Markdown file to name a file or directory in this repository, apart from
// the named external targets above.
func TestMarkdownRelativeLinksResolve(t *testing.T) {
	files := trackedTextFiles(t)
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
		text := markdownFence.ReplaceAllString(string(files[name]), "")
		text = markdownCodeSpan.ReplaceAllString(text, "x")
		for _, match := range markdownInlineLink.FindAllStringSubmatch(text, -1) {
			target := match[1]
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
// in a tracked file (scripts, Go code, docs) to exist, so that a rename or a
// careless merge cannot leave a script printing a runbook path that is gone.
func TestRunbookPathMentionsExist(t *testing.T) {
	files := trackedTextFiles(t)
	names := make([]string, 0, len(files))
	for name := range files {
		if name != "runbook_paths_contract_test.go" {
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
		t.Fatalf("runbook paths named in tracked files that do not exist:\n%s", strings.Join(missing, "\n"))
	}
}
