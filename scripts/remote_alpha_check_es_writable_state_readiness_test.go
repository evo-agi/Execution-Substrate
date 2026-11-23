package executionsubstrate_test

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const retiredRemoteAlphaStderr = "remote alpha existing-host ES writable-state and service-user migration routes are retired; no host inspection, staging, mutation, or evidence production occurred\n" +
	"provision a fresh host through a separately selected setup contract, or select a separately governed existing-host migration contract\n"

type retiredRemoteAlphaRoute struct {
	name         string
	internalPath string
	publicPath   string
	functionName string
	internalMode os.FileMode
}

var retiredRemoteAlphaRoutes = []retiredRemoteAlphaRoute{
	{name: "writable-state-readiness", internalPath: "scripts/internal/remote_alpha_check_es_writable_state_readiness.sh", publicPath: "scripts/remote_alpha_check_es_writable_state_readiness.sh", functionName: "remote_alpha_check_es_writable_state_readiness_main", internalMode: 0o644},
	{name: "readiness-staging", internalPath: "scripts/internal/remote_alpha_stage_es_writable_state_readiness_check.sh", publicPath: "scripts/remote_alpha_stage_es_writable_state_readiness_check.sh", functionName: "remote_alpha_stage_es_writable_state_readiness_check_main", internalMode: 0o755},
	{name: "service-user-migration", internalPath: "scripts/internal/remote_alpha_migrate_es_service_user.sh", publicPath: "scripts/remote_alpha_migrate_es_service_user.sh", functionName: "remote_alpha_migrate_es_service_user_main", internalMode: 0o644},
	{name: "rollback-generation", internalPath: "scripts/internal/remote_alpha_es_service_user_rollback_rehearsal.sh", publicPath: "scripts/remote_alpha_es_service_user_rollback_rehearsal.sh", functionName: "remote_alpha_es_service_user_rollback_rehearsal_main", internalMode: 0o755},
	{name: "ownership-preparation", internalPath: "scripts/internal/remote_alpha_prepare_es_writable_state_ownership.sh", publicPath: "scripts/remote_alpha_prepare_es_writable_state_ownership.sh", functionName: "remote_alpha_prepare_es_writable_state_ownership_main", internalMode: 0o644},
	{name: "old-root-planning", internalPath: "scripts/internal/remote_alpha_plan_old_root_cleanup.sh", publicPath: "scripts/remote_alpha_plan_old_root_cleanup.sh", functionName: "remote_alpha_plan_old_root_cleanup_main", internalMode: 0o644},
}

func TestRetiredRemoteAlphaRoutesAreFixedForEveryArgumentShape(t *testing.T) {
	variants := [][]string{
		nil,
		{"--help"},
		{"--check-only"},
		{"--apply"},
		{"--malformed"},
		{"arbitrary", "additional", "arguments"},
	}
	for _, route := range retiredRemoteAlphaRoutes {
		for _, path := range []string{route.internalPath, route.publicPath} {
			for index, args := range variants {
				t.Run(fmt.Sprintf("%s/%s/%d", route.name, filepath.Base(path), index), func(t *testing.T) {
					assertRetiredRemoteAlphaRoute(t, path, args)
				})
			}
		}
	}
}

func TestRetiredRemoteAlphaInternalSourcesAreExactEffectFreeTombstones(t *testing.T) {
	for _, route := range retiredRemoteAlphaRoutes {
		t.Run(route.name, func(t *testing.T) {
			content, err := os.ReadFile(route.internalPath)
			if err != nil {
				t.Fatal(err)
			}
			want := retiredRemoteAlphaTombstoneSource(route.functionName)
			if string(content) != want {
				t.Fatalf("internal tombstone bytes differ\nwant:\n%s\ngot:\n%s", want, content)
			}
			info, err := os.Stat(route.internalPath)
			if err != nil {
				t.Fatal(err)
			}
			if info.Mode().Perm() != route.internalMode {
				t.Fatalf("mode = %04o, want %04o", info.Mode().Perm(), route.internalMode)
			}
		})
	}
}

func TestRetiredRemoteAlphaProtectedWrappersAndHistoricalFixturesRemainExact(t *testing.T) {
	want := map[string]struct {
		mode os.FileMode
		size int
		sha  string
	}{
		"scripts/remote_alpha_check_es_writable_state_readiness.sh":                                                     {0o644, 325, "8a6f6a24fc241e4f21a80523b5702f70242b0fefa24137fa9aef09ed9313b2d9"},
		"scripts/remote_alpha_es_service_user_rollback_rehearsal.sh":                                                    {0o755, 328, "d83664c34cf0b0f80f09ea5790343512ab5e9d0dd186ab1d2c5efa78eb7a4f7a"},
		"scripts/remote_alpha_migrate_es_service_user.sh":                                                               {0o644, 295, "095af1659a41922f7c53c727ee840d9794a2ff890533e200c97d47c0f6f433f7"},
		"scripts/remote_alpha_plan_old_root_cleanup.sh":                                                                 {0o644, 289, "e9772b2c281bf59476f06a1c52a010b9f8bcfe7d87595508fd556fa57d2aa660"},
		"scripts/remote_alpha_prepare_es_writable_state_ownership.sh":                                                   {0o644, 331, "790ea14659380c4559bbacffaa0e9f152b61b4931f7c69ba411652566dc5b4d4"},
		"scripts/remote_alpha_stage_es_writable_state_readiness_check.sh":                                               {0o755, 343, "1c2dbb77957a15734f684c898e78c5873e10fad2c900f4c16f347144f527e3d2"},
		"testdata/remote_alpha_es_service_user_rollback_rehearsal/blocker/es-service-user-migration-apply-summary.json": {0o644, 2013, "9d340920603b01e51b7e54d7f936ecd9674258301911468b3f729a39af5cbc16"},
		"testdata/remote_alpha_es_service_user_rollback_rehearsal/blocker/es-service-user-migration-check-only.json":    {0o644, 732, "5722b2f89094a1ea451871b9b39d07ae8814b6da242d1a326f53b9d82bde2b3e"},
		"testdata/remote_alpha_es_service_user_rollback_rehearsal/pass/es-service-user-migration-apply-summary.json":    {0o644, 2096, "56b2bad78a3b43aaeff9170b878ed87f558fe325160ad2e27c2d08a392a3c9dd"},
		"testdata/remote_alpha_es_service_user_rollback_rehearsal/pass/es-service-user-migration-check-only.json":       {0o644, 732, "5722b2f89094a1ea451871b9b39d07ae8814b6da242d1a326f53b9d82bde2b3e"},
		"testdata/remote_alpha_es_service_user_rollback_rehearsal/warning/es-service-user-migration-apply-summary.json": {0o644, 2096, "56b2bad78a3b43aaeff9170b878ed87f558fe325160ad2e27c2d08a392a3c9dd"},
		"testdata/remote_alpha_es_service_user_rollback_rehearsal/warning/es-service-user-migration-check-only.json":    {0o644, 732, "5722b2f89094a1ea451871b9b39d07ae8814b6da242d1a326f53b9d82bde2b3e"},
	}
	for path, expected := range want {
		content, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		gotSHA := fmt.Sprintf("%x", sha256.Sum256(content))
		if len(content) != expected.size || gotSHA != expected.sha || info.Mode().Perm() != expected.mode {
			t.Fatalf("protected path %s changed: mode=%04o size=%d sha=%s", path, info.Mode().Perm(), len(content), gotSHA)
		}
	}
}

func assertRetiredRemoteAlphaRoute(t *testing.T, path string, args []string) {
	t.Helper()
	work := t.TempDir()
	tmp := filepath.Join(work, "tmp")
	home := filepath.Join(work, "home")
	shimDir := filepath.Join(work, "shims")
	for _, dir := range []string{tmp, home, shimDir} {
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	sentinel := filepath.Join(work, "command-discovered")
	for _, name := range []string{"ssh", "scp", "sudo", "systemctl", "nomad", "docker", "vault", "spire-server", "spire-agent", "curl", "python", "python3", "mktemp", "stat", "find", "jq", "tee"} {
		body := "#!/bin/sh\nprintf '%s\\n' invoked >> '" + sentinel + "'\nexit 99\n"
		if err := os.WriteFile(filepath.Join(shimDir, name), []byte(body), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("/bin/bash", append([]string{absolute}, args...)...)
	cmd.Dir = home
	cmd.Env = []string{"PATH=" + shimDir + ":/usr/bin:/bin", "TMPDIR=" + tmp, "HOME=" + home}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err = cmd.Run()
	exitErr, ok := err.(*exec.ExitError)
	if !ok || exitErr.ExitCode() != 2 {
		t.Fatalf("exit = %v, want 2", err)
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want empty", stdout.String())
	}
	if stderr.String() != retiredRemoteAlphaStderr {
		t.Fatalf("stderr = %q, want %q", stderr.String(), retiredRemoteAlphaStderr)
	}
	if _, err := os.Lstat(sentinel); !os.IsNotExist(err) {
		t.Fatalf("dangerous command was discovered: %v", err)
	}
	for _, dir := range []string{tmp, home} {
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		if len(entries) != 0 {
			t.Fatalf("route created artifacts in %s: %v", dir, entries)
		}
	}
}

func retiredRemoteAlphaTombstoneSource(functionName string) string {
	return strings.Join([]string{
		"#!/usr/bin/env bash",
		"set -euo pipefail",
		"",
		functionName + "() {",
		"  printf '%s\\n' 'remote alpha existing-host ES writable-state and service-user migration routes are retired; no host inspection, staging, mutation, or evidence production occurred' >&2",
		"  printf '%s\\n' 'provision a fresh host through a separately selected setup contract, or select a separately governed existing-host migration contract' >&2",
		"  return 2",
		"}",
		"",
		"if [[ \"${BASH_SOURCE[0]}\" == \"$0\" ]]; then",
		"  " + functionName + " \"$@\"",
		"fi",
		"",
	}, "\n")
}

func nestedMap(t *testing.T, payload map[string]any, key string) map[string]any {
	t.Helper()
	value, ok := payload[key].(map[string]any)
	if !ok {
		t.Fatalf("%s is %T, want object", key, payload[key])
	}
	return value
}
