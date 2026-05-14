package executionsubstrate_test

import (
	"os"
	"os/exec"
	"path"
	"strings"
	"testing"
)

var intentionalGeneratedArtifacts = map[string]string{
	".examples/control_plane_normal_shell_runtime/dist/control_plane_normal_shell_runtime.tar.gz": "non-authoritative fixture",
	".examples/execution_loop/artifacts/static-script-success.tar.gz":                             "non-authoritative fixture",
	".examples/runtime_identity_reference/dist/runtime_identity_reference.tar.gz":                 "non-authoritative fixture",
	".out/Dockerfile": "temporary compatibility edge; generated projection",
}

func TestTrackedGeneratedArtifactHygiene(t *testing.T) {
	cmd := exec.Command("git", "ls-files", "-z")
	output, err := cmd.Output()
	if err != nil {
		t.Fatalf("git ls-files inventory failed: %v", err)
	}

	var unexpected []string
	for _, trackedPath := range strings.Split(strings.TrimSuffix(string(output), "\x00"), "\x00") {
		if trackedPath == "" {
			continue
		}
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
