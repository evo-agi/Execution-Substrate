package scripts_test

// Audit 22 of PR #53, I22-5: ES binary staging builds its local upload tree
// inside `if ! remote_alpha_deploy_es_binaries_stage_make_local_upload_tree`,
// where Bash ignores set -e, the same pattern as the operator's staging
// functions. Each step of the upload tree and the payload tree now returns on
// failure, so a failed step stops the tree there.

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRemoteAlphaStageESBinariesLocalUploadTreeStopsAtTheFirstFailedStep(t *testing.T) {
	t.Parallel()

	t.Run("failed copy", func(t *testing.T) {
		t.Parallel()
		tmp := t.TempDir()
		emptyRepo := filepath.Join(tmp, "repo") // holds no helper to copy
		if err := os.Mkdir(emptyRepo, 0o755); err != nil {
			t.Fatal(err)
		}
		ran := filepath.Join(tmp, "payload-step-ran")
		output, err := runSourcedESBinaryDeploymentHelper(t, envWithPath(t.TempDir()), fmt.Sprintf(`
REPO_ROOT=%q
remote_alpha_deploy_es_binaries_stage_make_local_payload_tree() { : >%q; }
if remote_alpha_deploy_es_binaries_stage_make_local_upload_tree %q; then echo "tree assembled"; else echo "tree refused"; fi
`, emptyRepo, ran, filepath.Join(tmp, "upload")))
		if err != nil || !strings.Contains(string(output), "tree refused") {
			t.Fatalf("upload tree did not stop at a failed copy: %v\n%s", err, output)
		}
		if _, err := os.Stat(ran); !os.IsNotExist(err) {
			t.Fatalf("upload tree went on to the payload step after a failed copy: %v", err)
		}
	})

	for _, tc := range []struct {
		name      string
		toolchain string // exit status of the toolchain check
		failBuild string // the go build target that fails, if any
		wantBuild []string
	}{
		{"failed toolchain check", "1", "", nil},
		{"failed first build", "0", "./cmd/es", []string{"./cmd/es"}},
		{"failed second build", "0", "./cmd/es-runtime-support", []string{"./cmd/es", "./cmd/es-runtime-support"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			tmp := t.TempDir()
			fakeBin := filepath.Join(tmp, "bin")
			goLog := filepath.Join(tmp, "go.log")
			if err := os.Mkdir(fakeBin, 0o755); err != nil {
				t.Fatal(err)
			}
			writeExecutable(t, fakeBin, "go", fmt.Sprintf(`#!/usr/bin/env bash
target="${!#}"
printf '%%s\n' "${target}" >> %q
[[ "${target}" != %q ]]
`, goLog, tc.failBuild))
			payload := filepath.Join(tmp, "payload")
			output, err := runSourcedESBinaryDeploymentHelper(t, envWithPath(fakeBin), fmt.Sprintf(`
remote_alpha_deploy_es_binaries_require_supported_go_toolchain() { return %s; }
if remote_alpha_deploy_es_binaries_stage_make_local_payload_tree %q; then echo "payload built"; else echo "payload refused"; fi
`, tc.toolchain, payload))
			if err != nil || !strings.Contains(string(output), "payload refused") {
				t.Fatalf("payload tree did not stop: %v\n%s", err, output)
			}
			var builds []string
			if log := strings.TrimSpace(readIfExists(goLog)); log != "<missing>" && log != "" {
				builds = strings.Split(log, "\n")
			}
			if strings.Join(builds, " ") != strings.Join(tc.wantBuild, " ") {
				t.Fatalf("payload tree ran builds %q, want %q", builds, tc.wantBuild)
			}
			if _, err := os.Stat(filepath.Join(payload, "build-provenance.json")); !os.IsNotExist(err) {
				t.Fatalf("payload tree wrote build provenance after a failed step: %v", err)
			}
		})
	}
}

// Every step of both trees but the last returns on failure itself.
func TestRemoteAlphaStageESBinariesLocalUploadTreeStepsReturnOnFailure(t *testing.T) {
	t.Parallel()
	helper := mustRead(t, filepath.Join(executionSubstrateRepoRoot, "scripts", "internal", "remote_alpha_deploy_es_binaries.sh"))
	if !strings.Contains(helper, "if ! remote_alpha_deploy_es_binaries_stage_make_local_upload_tree ") {
		t.Fatal("the upload tree is no longer built as `if ! ...`; recheck which steps need their own return")
	}
	for name, want := range map[string]int{
		"remote_alpha_deploy_es_binaries_stage_make_local_upload_tree":  3,
		"remote_alpha_deploy_es_binaries_stage_make_local_payload_tree": 4,
	} {
		start := "\n" + name + "() {\n"
		i := strings.Index(helper, start)
		if i < 0 {
			t.Fatalf("helper has no function %s", name)
		}
		body := helper[i+len(start):]
		body = body[:strings.Index(body, "\n}\n")]
		if j := strings.Index(body, "<<'PY'"); j >= 0 {
			body = body[:j]
		}
		steps := 0
		for _, line := range strings.Split(body, "\n") {
			trimmed := strings.TrimSpace(line)
			for _, prefix := range []string{"mkdir ", "cp ", "env GOTOOLCHAIN=local ", "remote_alpha_deploy_es_binaries_require_supported_go_toolchain"} {
				if !strings.HasPrefix(trimmed, prefix) {
					continue
				}
				steps++
				if !strings.HasSuffix(trimmed, " || return 1") {
					t.Errorf("%s does not return when this step fails: %s", name, trimmed)
				}
			}
		}
		if steps != want {
			t.Errorf("%s has %d steps before its last, want %d", name, steps, want)
		}
	}
}
