package executionsubstrate_test

import (
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

var intentionalGeneratedArtifacts = map[string]string{
	".examples/control_plane_normal_shell_runtime/dist/control_plane_normal_shell_runtime.tar.gz": "non-authoritative fixture",
	".examples/execution_loop/artifacts/static-script-success.tar.gz":                             "non-authoritative fixture",
	".examples/runtime_identity_reference/dist/runtime_identity_reference.tar.gz":                 "non-authoritative fixture",
	".out/Dockerfile": "temporary compatibility edge; generated projection",
}

// repositoryFiles lists the files of this repository as slash-separated
// paths relative to its root, which is this package's directory, and reports
// whether the list is git's list of tracked files.
//
// When the root holds git metadata (a .git directory, or the .git file of a
// worktree or submodule), the list is `git ls-files`. If git cannot read
// that metadata, the test fails rather than guess at another list.
//
// When the root holds no .git, as in a tree exported with git archive or
// unpacked from a source archive, nothing records which files are tracked.
// The list is then every file in the tree except the byproducts that
// isGeneratedArtifactByproduct names and intentionalGeneratedArtifacts does
// not allow. .gitignore keeps those byproducts untracked, and local tools
// leave them in a source tree (.DS_Store, __pycache__, build/).
func repositoryFiles(t *testing.T) (files []string, tracked bool) {
	t.Helper()
	files, tracked, err := repositoryFilesIn(".")
	if err != nil {
		t.Fatal(err)
	}
	return files, tracked
}

// repositoryFilesIn is repositoryFiles for the tree at root.
func repositoryFilesIn(root string) ([]string, bool, error) {
	if _, err := os.Lstat(filepath.Join(root, ".git")); err == nil {
		cmd := exec.Command("git", "ls-files", "-z")
		cmd.Dir = root
		output, err := cmd.Output()
		if err != nil {
			return nil, true, fmt.Errorf("git ls-files inventory failed: %v; the repository root has .git, so the tests check its tracked files and git must be able to list them", err)
		}
		var files []string
		for _, trackedPath := range strings.Split(strings.TrimSuffix(string(output), "\x00"), "\x00") {
			if trackedPath != "" {
				files = append(files, trackedPath)
			}
		}
		return files, true, nil
	} else if !os.IsNotExist(err) {
		return nil, false, fmt.Errorf("check the repository root for git metadata: %v", err)
	}

	var files []string
	err := filepath.WalkDir(root, func(walkPath string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		relative, err := filepath.Rel(root, walkPath)
		if err != nil {
			return err
		}
		relative = filepath.ToSlash(relative)
		if _, intentional := intentionalGeneratedArtifacts[relative]; !intentional && isGeneratedArtifactByproduct(relative) {
			return nil
		}
		files = append(files, relative)
		return nil
	})
	if err != nil {
		return nil, false, fmt.Errorf("list the files of the source tree %s, which has no .git: %v", root, err)
	}
	sort.Strings(files)
	return files, false, nil
}

func TestTrackedGeneratedArtifactHygiene(t *testing.T) {
	files, tracked := repositoryFiles(t)
	if !tracked {
		t.Skip("needs git metadata: this source tree has no .git, so files the repository tracks cannot be told apart from byproducts that local tools leave here and .gitignore keeps untracked; the check runs in every git checkout, CI included")
	}

	var unexpected []string
	for _, trackedPath := range files {
		if _, err := os.Lstat(trackedPath); os.IsNotExist(err) {
			continue
		} else if err != nil {
			t.Fatalf("stat tracked path %s: %v", trackedPath, err)
		}
		if _, ok := intentionalGeneratedArtifacts[trackedPath]; ok {
			continue
		}
		if isGeneratedArtifactByproduct(trackedPath) {
			unexpected = append(unexpected, trackedPath)
		}
	}

	if len(unexpected) > 0 {
		t.Fatalf("unexpected tracked generated artifacts; either remove them or document and allowlist them in .docs/system_overview/artifact_hygiene.md: %s", strings.Join(unexpected, ", "))
	}
}

func TestArtifactHygieneDocumentationClassifiesIntentionalFixtures(t *testing.T) {
	doc := compactText(mustRead(t, ".docs/system_overview/artifact_hygiene.md"))

	for trackedPath := range intentionalGeneratedArtifacts {
		if _, err := os.Lstat(trackedPath); err != nil {
			t.Fatalf("intentional generated artifact %s is missing: %v", trackedPath, err)
		}
	}

	assertContainsAll(t, "artifact hygiene doc", doc,
		"Generated Artifact Hygiene",
		"Generated or proof artifacts are evidence/projection/diagnostics only.",
		"not hidden runtime authority",
		".examples/execution_loop/artifacts/static-script-success.tar.gz",
		".examples/control_plane_normal_shell_runtime/dist/control_plane_normal_shell_runtime.tar.gz",
		".examples/runtime_identity_reference/dist/runtime_identity_reference.tar.gz",
		".out/Dockerfile",
		"non-authoritative fixture",
		"temporary compatibility edge; generated projection",
		"scripts/generate_control_plane_dockerfile.sh",
	)
}

func isGeneratedArtifactByproduct(trackedPath string) bool {
	base := path.Base(trackedPath)
	switch {
	case base == ".DS_Store":
		return true
	case strings.HasPrefix(base, "._"):
		return true
	case strings.HasSuffix(base, ".pyc") || strings.HasSuffix(base, ".pyo"):
		return true
	case strings.HasSuffix(base, ".tar.gz") || strings.HasSuffix(base, ".zip"):
		return true
	case strings.HasSuffix(base, ".egg-info"):
		return true
	case strings.HasPrefix(trackedPath, ".out/"):
		return true
	}

	for _, segment := range strings.Split(trackedPath, "/") {
		switch segment {
		case "__pycache__", "build", "dist":
			return true
		}
		if strings.HasSuffix(segment, ".egg-info") {
			return true
		}
	}

	return false
}

// TestRepositoryFilesUsesGitWhenTheRootHasGitMetadata pins how
// repositoryFiles lists the repository: git's tracked files when the root
// has .git, every file but the disallowed byproducts when it has none, and a
// failure, not a guess, when .git is there but git cannot read it.
func TestRepositoryFilesUsesGitWhenTheRootHasGitMetadata(t *testing.T) {
	names := []string{
		".DS_Store",
		".examples/runtime_identity_reference/dist/runtime_identity_reference.tar.gz",
		".out/Dockerfile",
		".out/build.log",
		"README.md",
		"build/copy.md",
		"docs/a.md",
		"pkg/__pycache__/m.pyc",
		"release.zip",
	}
	writeTree := func(t *testing.T) string {
		t.Helper()
		root := t.TempDir()
		for _, name := range names {
			file := filepath.Join(root, filepath.FromSlash(name))
			if err := os.MkdirAll(filepath.Dir(file), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(file, []byte(name+"\n"), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		return root
	}
	git := func(t *testing.T, root string, args ...string) {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = root
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, output)
		}
	}

	t.Run("source tree without .git", func(t *testing.T) {
		got, tracked, err := repositoryFilesIn(writeTree(t))
		if err != nil {
			t.Fatal(err)
		}
		want := []string{
			".examples/runtime_identity_reference/dist/runtime_identity_reference.tar.gz",
			".out/Dockerfile",
			"README.md",
			"docs/a.md",
		}
		if tracked || strings.Join(got, "\n") != strings.Join(want, "\n") {
			t.Fatalf("repositoryFilesIn() = %q, tracked %v; want %q, tracked false", got, tracked, want)
		}
	})

	t.Run("git checkout lists only tracked files", func(t *testing.T) {
		root := writeTree(t)
		git(t, root, "init", "-q")
		git(t, root, "add", "README.md", "build/copy.md", "docs/a.md")
		got, tracked, err := repositoryFilesIn(root)
		if err != nil {
			t.Fatal(err)
		}
		want := []string{"README.md", "build/copy.md", "docs/a.md"}
		if !tracked || strings.Join(got, "\n") != strings.Join(want, "\n") {
			t.Fatalf("repositoryFilesIn() = %q, tracked %v; want %q, tracked true", got, tracked, want)
		}
	})

	t.Run("git metadata that git cannot read fails", func(t *testing.T) {
		root := writeTree(t)
		if err := os.WriteFile(filepath.Join(root, ".git"), []byte("not a gitdir\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		got, _, err := repositoryFilesIn(root)
		if err == nil {
			t.Fatalf("repositoryFilesIn() = %q with an unreadable .git, want an error", got)
		}
	})
}
