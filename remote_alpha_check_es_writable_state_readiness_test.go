package executionsubstrate_test

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"testing"
)

type fakeWritableStateStat struct {
	UID      int
	GID      int
	Mode     string
	FileType string
}

type fakeWritableStateAccount struct {
	Present   bool
	UID       int
	GID       int
	GroupName string
}

type readinessOwnedFixturePath struct {
	path      string
	mode      uint32
	directory bool
}

func readinessReadyRootPaths(stagingRoot, resultsRoot string) []readinessOwnedFixturePath {
	return []readinessOwnedFixturePath{
		{path: stagingRoot, mode: 0o750, directory: true},
		{path: resultsRoot, mode: 0o750, directory: true},
	}
}

func readinessStagedRunPaths(stagingRoot, runID string, marker bool) []readinessOwnedFixturePath {
	runRoot := filepath.Join(stagingRoot, runID)
	paths := []readinessOwnedFixturePath{
		{path: runRoot, mode: 0o750, directory: true},
		{path: filepath.Join(runRoot, "run", "platform"), mode: 0o750, directory: true},
		{path: filepath.Join(runRoot, "run", "work"), mode: 0o750, directory: true},
		{path: filepath.Join(runRoot, "run", "result"), mode: 0o750, directory: true},
	}
	if marker {
		paths = append(paths, readinessOwnedFixturePath{path: filepath.Join(runRoot, "run", "platform", "ownership-normalization.json"), mode: 0o600})
	}
	return paths
}

func readinessRetainedRunPaths(resultsRoot, runID string, marker bool, bundleMode uint32) []readinessOwnedFixturePath {
	runRoot := filepath.Join(resultsRoot, runID)
	paths := []readinessOwnedFixturePath{
		{path: runRoot, mode: 0o750, directory: true},
		{path: filepath.Join(runRoot, "result.tar.gz"), mode: bundleMode},
	}
	if marker {
		paths = append(paths, readinessOwnedFixturePath{path: filepath.Join(runRoot, "ownership-normalization.json"), mode: 0o600})
	}
	return paths
}

func establishReadinessFixtureOwnership(t *testing.T, fixtureRoot string, uid, gid int, paths ...readinessOwnedFixturePath) {
	t.Helper()
	if uid != os.Getuid() || gid != os.Getgid() {
		t.Fatalf("fixture ownership target %d:%d must be the current test identity", uid, gid)
	}
	for _, item := range paths {
		rel, err := filepath.Rel(fixtureRoot, item.path)
		if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
			t.Fatalf("fixture ownership path is outside test temporary root: %s", item.path)
		}
		before, err := os.Lstat(item.path)
		if err != nil {
			t.Fatalf("stat fixture ownership path %s: %v", item.path, err)
		}
		beforeStat, ok := before.Sys().(*syscall.Stat_t)
		if !ok || beforeStat.Uid != uint32(os.Geteuid()) {
			t.Fatalf("fixture ownership path %s is not owned by the current test user", item.path)
		}
		if item.directory != before.IsDir() || (!item.directory && !before.Mode().IsRegular()) {
			t.Fatalf("fixture ownership path %s has unexpected type %s", item.path, before.Mode())
		}
		if err := os.Chown(item.path, uid, gid); err != nil {
			t.Fatalf("set fixture ownership %s to fake es %d:%d: %v", item.path, uid, gid, err)
		}
		if err := os.Chmod(item.path, os.FileMode(item.mode)); err != nil {
			t.Fatalf("set fixture mode %s to %04o: %v", item.path, item.mode, err)
		}
		after, err := os.Lstat(item.path)
		if err != nil {
			t.Fatalf("verify fixture ownership path %s: %v", item.path, err)
		}
		afterStat, ok := after.Sys().(*syscall.Stat_t)
		if !ok || item.directory != after.IsDir() || (!item.directory && !after.Mode().IsRegular()) ||
			afterStat.Uid != uint32(uid) || afterStat.Gid != uint32(gid) || uint32(afterStat.Mode)&0o7777 != item.mode {
			t.Fatalf("fixture ownership path %s did not establish fake es %d:%d mode %04o", item.path, uid, gid, item.mode)
		}
	}
}

func runESWritableStateReadinessScript(t *testing.T, env []string, args ...string) ([]byte, error) {
	t.Helper()

	scriptPath := filepath.Join(executionSubstrateRepoRoot, "scripts", "remote_alpha_check_es_writable_state_readiness.sh")
	cmdArgs := append([]string{scriptPath}, args...)
	cmd := exec.Command("/bin/bash", cmdArgs...)
	cmd.Dir = executionSubstrateRepoRoot
	cmd.Env = env
	return cmd.CombinedOutput()
}

func writeWritableStateReadinessConfig(t *testing.T, path, stagingRoot, resultsRoot string) {
	t.Helper()

	payload := map[string]any{
		"execution": map[string]any{
			"staging_root_dir": stagingRoot,
			"results_root_dir": resultsRoot,
		},
	}
	data, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		t.Fatalf("marshal config: %v", err)
	}
	if err := os.WriteFile(path, append(data, '\n'), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
}

func parseWritableStateReadinessOutput(t *testing.T, output []byte) map[string]any {
	t.Helper()

	var payload map[string]any
	if err := json.Unmarshal(output, &payload); err != nil {
		t.Fatalf("decode checker output: %v\noutput=%s", err, string(output))
	}
	return payload
}

func nestedMap(t *testing.T, payload map[string]any, key string) map[string]any {
	t.Helper()
	value, ok := payload[key]
	if !ok {
		t.Fatalf("missing key %q", key)
	}
	result, ok := value.(map[string]any)
	if !ok {
		t.Fatalf("key %q was %T, want map[string]any", key, value)
	}
	return result
}

func nestedClassification(t *testing.T, payload map[string]any, key string) string {
	t.Helper()
	value := nestedMap(t, payload, key)["classification"]
	classification, ok := value.(string)
	if !ok {
		t.Fatalf("classification for %q was %T, want string", key, value)
	}
	return classification
}

func fakeWritableStateMutationScript(logPath, name string) string {
	return fmt.Sprintf(`#!/bin/sh
printf '%%s\n' %q >> %q
exit 97
`, name, logPath)
}

func writeWritableStateNormalizationMarker(t *testing.T, platformDir, runID string, overrides map[string]any) {
	t.Helper()

	payload := map[string]any{
		"schema_version":   "execution-substrate.es.runtime-ownership-normalization.v1",
		"status":           "normalized",
		"run_id":           runID,
		"target_uid":       os.Getuid(),
		"target_gid":       os.Getgid(),
		"paths_normalized": []string{"run/platform", "run/work", "run/result"},
		"completed_at":     "2026-04-25T12:00:00Z",
	}
	for key, value := range overrides {
		payload[key] = value
	}
	data, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		t.Fatalf("marshal marker: %v", err)
	}
	markerPath := filepath.Join(platformDir, "ownership-normalization.json")
	if err := os.WriteFile(markerPath, append(data, '\n'), 0o600); err != nil {
		t.Fatalf("write marker: %v", err)
	}
}

func setupFakeWritableStateReadinessCommands(
	t *testing.T,
	dir string,
	account fakeWritableStateAccount,
	statOverrides map[string]fakeWritableStateStat,
	mutationLogPath string,
) {
	t.Helper()

	groupName := account.GroupName
	if groupName == "" {
		groupName = "es"
	}

	writeExecutable(t, dir, "id", fmt.Sprintf(`#!/bin/sh
if [ "$1" = "-u" ] && [ "$2" = "es" ]; then
  if [ %q != "true" ]; then
    exit 1
  fi
  echo %d
  exit 0
fi
if [ "$1" = "-g" ] && [ "$2" = "es" ]; then
  if [ %q != "true" ]; then
    exit 1
  fi
  echo %d
  exit 0
fi
if [ "$1" = "-gn" ] && [ "$2" = "es" ]; then
  if [ %q != "true" ]; then
    exit 1
  fi
  echo %q
  exit 0
fi
exec /usr/bin/id "$@"
`, fmt.Sprintf("%t", account.Present), account.UID, fmt.Sprintf("%t", account.Present), account.GID, fmt.Sprintf("%t", account.Present), groupName))

	writeExecutable(t, dir, "getent", fmt.Sprintf(`#!/bin/sh
if [ "$1" = "passwd" ] && [ "$2" = "es" ]; then
  if [ %q != "true" ]; then
    exit 2
  fi
  echo "es:x:%d:%d::/nonexistent:/usr/sbin/nologin"
  exit 0
fi
if [ "$1" = "group" ] && [ "$2" = "es" ]; then
  if [ %q != "true" ]; then
    exit 2
  fi
  echo "%s:x:%d:"
  exit 0
fi
exit 2
`, fmt.Sprintf("%t", account.Present), account.UID, account.GID, fmt.Sprintf("%t", account.Present), groupName, account.GID))

	statLines := make([]string, 0, len(statOverrides))
	for path, override := range statOverrides {
		statLines = append(statLines, fmt.Sprintf(`if [ "$3" = %q ]; then
  printf '%%s\t%%s\t%%s\t%%s\n' %q %q %q %q
  exit 0
fi`, path, fmt.Sprintf("%d", override.UID), fmt.Sprintf("%d", override.GID), override.Mode, override.FileType))
	}
	sort.Strings(statLines)
	writeExecutable(t, dir, "stat", fmt.Sprintf(`#!/bin/sh
if [ "$1" != "-c" ] || [ "$#" -ne 3 ]; then
  exit 1
fi
%s
exit 1
`, strings.Join(statLines, "\n")))

	for _, name := range []string{"chown", "chmod", "useradd", "groupadd", "systemctl", "sudo", "rm"} {
		writeExecutable(t, dir, name, fakeWritableStateMutationScript(mutationLogPath, name))
	}
}

func TestRemoteAlphaESWritableStateReadinessIsNonMutating(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	fakeBin := filepath.Join(tmpDir, "bin")
	if err := os.MkdirAll(fakeBin, 0o755); err != nil {
		t.Fatalf("mkdir fake bin: %v", err)
	}

	stagingRoot := filepath.Join(tmpDir, "staging")
	resultsRoot := filepath.Join(tmpDir, "results")
	if err := os.MkdirAll(stagingRoot, 0o750); err != nil {
		t.Fatalf("mkdir staging root: %v", err)
	}
	if err := os.MkdirAll(resultsRoot, 0o750); err != nil {
		t.Fatalf("mkdir results root: %v", err)
	}

	establishReadinessFixtureOwnership(t, tmpDir, os.Getuid(), os.Getgid(), readinessReadyRootPaths(stagingRoot, resultsRoot)...)
	configPath := filepath.Join(tmpDir, "es.json")
	writeWritableStateReadinessConfig(t, configPath, stagingRoot, resultsRoot)

	mutationLogPath := filepath.Join(tmpDir, "mutations.log")
	setupFakeWritableStateReadinessCommands(t, fakeBin, fakeWritableStateAccount{
		Present:   true,
		UID:       os.Getuid(),
		GID:       os.Getgid(),
		GroupName: "es",
	}, nil, mutationLogPath)

	output, err := runESWritableStateReadinessScript(t, append(os.Environ(), "PATH="+fakeBin+":"+os.Getenv("PATH")), "--config-path", configPath)
	if err != nil {
		t.Fatalf("checker failed: %v\noutput=%s", err, string(output))
	}

	payload := parseWritableStateReadinessOutput(t, output)
	if payload["non_mutating"] != true {
		t.Fatalf("expected non_mutating=true, got %v", payload["non_mutating"])
	}
	if _, err := os.Stat(mutationLogPath); !os.IsNotExist(err) {
		t.Fatalf("mutation log should not exist, got %q", mutationLogPath)
	}
}

func TestRemoteAlphaESWritableStateReadinessMissingESAccountBlocksHostCheck(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	fakeBin := filepath.Join(tmpDir, "bin")
	if err := os.MkdirAll(fakeBin, 0o755); err != nil {
		t.Fatalf("mkdir fake bin: %v", err)
	}

	stagingRoot := filepath.Join(tmpDir, "staging")
	resultsRoot := filepath.Join(tmpDir, "results")
	if err := os.MkdirAll(stagingRoot, 0o750); err != nil {
		t.Fatalf("mkdir staging root: %v", err)
	}
	if err := os.MkdirAll(resultsRoot, 0o750); err != nil {
		t.Fatalf("mkdir results root: %v", err)
	}

	configPath := filepath.Join(tmpDir, "es.json")
	writeWritableStateReadinessConfig(t, configPath, stagingRoot, resultsRoot)

	setupFakeWritableStateReadinessCommands(t, fakeBin, fakeWritableStateAccount{}, nil, filepath.Join(tmpDir, "mutations.log"))

	output, err := runESWritableStateReadinessScript(
		t,
		append(os.Environ(), "PATH="+fakeBin+":"+os.Getenv("PATH")),
		"--config-path",
		configPath,
		"--mode",
		"future-non-root-required",
	)
	if err == nil {
		t.Fatalf("expected checker blocker for missing es account\noutput=%s", string(output))
	}

	payload := parseWritableStateReadinessOutput(t, output)
	if got := nestedClassification(t, payload, "es_account_status"); got != "blocker" {
		t.Fatalf("expected blocker es_account_status, got %q", got)
	}
	if got := payload["overall_classification"]; got != "blocker" {
		t.Fatalf("expected overall blocker, got %v", got)
	}
}

func TestRemoteAlphaESWritableStateReadinessPassesForESOwnedRoots(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	fakeBin := filepath.Join(tmpDir, "bin")
	if err := os.MkdirAll(fakeBin, 0o755); err != nil {
		t.Fatalf("mkdir fake bin: %v", err)
	}

	stagingRoot := filepath.Join(tmpDir, "staging")
	resultsRoot := filepath.Join(tmpDir, "results")
	if err := os.MkdirAll(stagingRoot, 0o750); err != nil {
		t.Fatalf("mkdir staging root: %v", err)
	}
	if err := os.MkdirAll(resultsRoot, 0o750); err != nil {
		t.Fatalf("mkdir results root: %v", err)
	}

	establishReadinessFixtureOwnership(t, tmpDir, os.Getuid(), os.Getgid(), readinessReadyRootPaths(stagingRoot, resultsRoot)...)
	configPath := filepath.Join(tmpDir, "es.json")
	writeWritableStateReadinessConfig(t, configPath, stagingRoot, resultsRoot)

	setupFakeWritableStateReadinessCommands(t, fakeBin, fakeWritableStateAccount{
		Present:   true,
		UID:       os.Getuid(),
		GID:       os.Getgid(),
		GroupName: "es",
	}, nil, filepath.Join(tmpDir, "mutations.log"))

	output, err := runESWritableStateReadinessScript(t, append(os.Environ(), "PATH="+fakeBin+":"+os.Getenv("PATH")), "--config-path", configPath)
	if err != nil {
		t.Fatalf("checker failed: %v\noutput=%s", err, string(output))
	}

	payload := parseWritableStateReadinessOutput(t, output)
	if got := nestedClassification(t, payload, "staging_root_status"); got != "pass" {
		t.Fatalf("expected pass staging_root_status, got %q", got)
	}
	if got := nestedClassification(t, payload, "results_root_status"); got != "pass" {
		t.Fatalf("expected pass results_root_status, got %q", got)
	}
}

func TestRemoteAlphaESWritableStateReadinessRootOwnedRootsBlockFutureNonRootES(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	fakeBin := filepath.Join(tmpDir, "bin")
	if err := os.MkdirAll(fakeBin, 0o755); err != nil {
		t.Fatalf("mkdir fake bin: %v", err)
	}

	stagingRoot := filepath.Join(tmpDir, "staging")
	resultsRoot := filepath.Join(tmpDir, "results")
	if err := os.MkdirAll(stagingRoot, 0o755); err != nil {
		t.Fatalf("mkdir staging root: %v", err)
	}
	if err := os.MkdirAll(resultsRoot, 0o755); err != nil {
		t.Fatalf("mkdir results root: %v", err)
	}

	configPath := filepath.Join(tmpDir, "es.json")
	writeWritableStateReadinessConfig(t, configPath, stagingRoot, resultsRoot)

	setupFakeWritableStateReadinessCommands(t, fakeBin, fakeWritableStateAccount{
		Present:   true,
		UID:       994,
		GID:       994,
		GroupName: "es",
	}, map[string]fakeWritableStateStat{
		stagingRoot: {UID: 0, GID: 0, Mode: "0755", FileType: "directory"},
		resultsRoot: {UID: 0, GID: 0, Mode: "0755", FileType: "directory"},
	}, filepath.Join(tmpDir, "mutations.log"))

	output, err := runESWritableStateReadinessScript(
		t,
		append(os.Environ(), "PATH="+fakeBin+":"+os.Getenv("PATH")),
		"--config-path",
		configPath,
		"--mode",
		"future-non-root-required",
	)
	if err == nil {
		t.Fatalf("expected blocker for non-es-owned roots\noutput=%s", string(output))
	}

	payload := parseWritableStateReadinessOutput(t, output)
	if got := nestedClassification(t, payload, "staging_root_status"); got != "blocker" {
		t.Fatalf("expected blocker staging_root_status, got %q", got)
	}
	if got := nestedClassification(t, payload, "results_root_status"); got != "blocker" {
		t.Fatalf("expected blocker results_root_status, got %q", got)
	}
}

func TestRemoteAlphaESWritableStateReadinessUnreadableRetainedResultBlocks(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	fakeBin := filepath.Join(tmpDir, "bin")
	if err := os.MkdirAll(fakeBin, 0o755); err != nil {
		t.Fatalf("mkdir fake bin: %v", err)
	}

	stagingRoot := filepath.Join(tmpDir, "staging")
	resultsRoot := filepath.Join(tmpDir, "results")
	if err := os.MkdirAll(stagingRoot, 0o750); err != nil {
		t.Fatalf("mkdir staging root: %v", err)
	}
	if err := os.MkdirAll(resultsRoot, 0o750); err != nil {
		t.Fatalf("mkdir results root: %v", err)
	}
	bundleDir := filepath.Join(resultsRoot, "run-123")
	if err := os.MkdirAll(bundleDir, 0o750); err != nil {
		t.Fatalf("mkdir bundle dir: %v", err)
	}
	bundlePath := filepath.Join(bundleDir, "result.tar.gz")
	if err := os.WriteFile(bundlePath, []byte("bundle"), 0o000); err != nil {
		t.Fatalf("write bundle: %v", err)
	}

	ownedPaths := append(readinessReadyRootPaths(stagingRoot, resultsRoot), readinessRetainedRunPaths(resultsRoot, "run-123", false, 0o000)...)
	establishReadinessFixtureOwnership(t, tmpDir, os.Getuid(), os.Getgid(), ownedPaths...)
	configPath := filepath.Join(tmpDir, "es.json")
	writeWritableStateReadinessConfig(t, configPath, stagingRoot, resultsRoot)

	setupFakeWritableStateReadinessCommands(t, fakeBin, fakeWritableStateAccount{
		Present:   true,
		UID:       os.Getuid(),
		GID:       os.Getgid(),
		GroupName: "es",
	}, nil, filepath.Join(tmpDir, "mutations.log"))

	output, err := runESWritableStateReadinessScript(
		t,
		append(os.Environ(), "PATH="+fakeBin+":"+os.Getenv("PATH")),
		"--config-path",
		configPath,
		"--mode",
		"future-non-root-required",
	)
	if err == nil {
		t.Fatalf("expected blocker for unreadable retained result\noutput=%s", string(output))
	}

	payload := parseWritableStateReadinessOutput(t, output)
	if got := nestedClassification(t, payload, "results_root_status"); got != "pass" {
		t.Fatalf("expected pass results_root_status, got %q", got)
	}
	if got := nestedClassification(t, payload, "retained_result_readiness_status"); got != "blocker" {
		t.Fatalf("expected blocker retained_result_readiness_status, got %q", got)
	}
}

func TestRemoteAlphaESWritableStateReadinessCompletedRunWithoutNormalizationEvidenceBlocks(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	fakeBin := filepath.Join(tmpDir, "bin")
	if err := os.MkdirAll(fakeBin, 0o755); err != nil {
		t.Fatalf("mkdir fake bin: %v", err)
	}

	stagingRoot := filepath.Join(tmpDir, "staging")
	resultsRoot := filepath.Join(tmpDir, "results")
	runID := "run-456"
	stageRunRoot := filepath.Join(stagingRoot, runID)
	runRoot := filepath.Join(stageRunRoot, "run")
	platformDir := filepath.Join(runRoot, "platform")
	workDir := filepath.Join(runRoot, "work")
	resultDir := filepath.Join(runRoot, "result")

	for _, path := range []string{stagingRoot, resultsRoot, stageRunRoot, runRoot, platformDir, workDir, resultDir} {
		if err := os.MkdirAll(path, 0o750); err != nil {
			t.Fatalf("mkdir %s: %v", path, err)
		}
	}
	if err := os.WriteFile(filepath.Join(resultDir, "output.txt"), []byte("hello"), 0o640); err != nil {
		t.Fatalf("write staged result: %v", err)
	}
	bundleDir := filepath.Join(resultsRoot, runID)
	if err := os.MkdirAll(bundleDir, 0o750); err != nil {
		t.Fatalf("mkdir bundle dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(bundleDir, "result.tar.gz"), []byte("bundle"), 0o600); err != nil {
		t.Fatalf("write retained bundle: %v", err)
	}
	ownedPaths := append(readinessReadyRootPaths(stagingRoot, resultsRoot), readinessStagedRunPaths(stagingRoot, runID, false)...)
	ownedPaths = append(ownedPaths, readinessRetainedRunPaths(resultsRoot, runID, false, 0o600)...)
	establishReadinessFixtureOwnership(t, tmpDir, os.Getuid(), os.Getgid(), ownedPaths...)
	if err := os.Chmod(workDir, 0o000); err != nil {
		t.Fatalf("chmod work dir: %v", err)
	}
	if err := os.Chmod(resultDir, 0o000); err != nil {
		t.Fatalf("chmod result dir: %v", err)
	}
	t.Cleanup(func() {
		_ = os.Chmod(workDir, 0o750)
		_ = os.Chmod(resultDir, 0o750)
	})

	configPath := filepath.Join(tmpDir, "es.json")
	writeWritableStateReadinessConfig(t, configPath, stagingRoot, resultsRoot)

	setupFakeWritableStateReadinessCommands(t, fakeBin, fakeWritableStateAccount{
		Present:   true,
		UID:       os.Getuid(),
		GID:       os.Getgid(),
		GroupName: "es",
	}, nil, filepath.Join(tmpDir, "mutations.log"))

	output, err := runESWritableStateReadinessScript(
		t,
		append(os.Environ(), "PATH="+fakeBin+":"+os.Getenv("PATH")),
		"--config-path",
		configPath,
		"--mode",
		"future-non-root-required",
	)
	if err == nil {
		t.Fatalf("expected blocker for completed run without normalization evidence\noutput=%s", string(output))
	}

	payload := parseWritableStateReadinessOutput(t, output)
	if got := nestedClassification(t, payload, "runtime_normalization_contract_status"); got != "blocker" {
		t.Fatalf("expected blocker runtime_normalization_contract_status, got %q", got)
	}
	if got := nestedClassification(t, payload, "cleanup_readiness_status"); got != "blocker" {
		t.Fatalf("expected blocker cleanup_readiness_status, got %q", got)
	}
}

func TestRemoteAlphaESWritableStateReadinessDefaultAlphaModeWarnsWhenMarkerMissing(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	fakeBin := filepath.Join(tmpDir, "bin")
	if err := os.MkdirAll(fakeBin, 0o755); err != nil {
		t.Fatalf("mkdir fake bin: %v", err)
	}

	stagingRoot := filepath.Join(tmpDir, "staging")
	resultsRoot := filepath.Join(tmpDir, "results")
	runID := "run-457-alpha"
	platformDir := filepath.Join(stagingRoot, runID, "run", "platform")
	workDir := filepath.Join(stagingRoot, runID, "run", "work")
	resultDir := filepath.Join(stagingRoot, runID, "run", "result")
	for _, path := range []string{platformDir, workDir, resultDir} {
		if err := os.MkdirAll(path, 0o750); err != nil {
			t.Fatalf("mkdir %s: %v", path, err)
		}
	}
	if err := os.MkdirAll(filepath.Join(resultsRoot, runID), 0o750); err != nil {
		t.Fatalf("mkdir bundle dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(resultsRoot, runID, "result.tar.gz"), []byte("bundle"), 0o600); err != nil {
		t.Fatalf("write retained bundle: %v", err)
	}

	ownedPaths := append(readinessReadyRootPaths(stagingRoot, resultsRoot), readinessStagedRunPaths(stagingRoot, runID, false)...)
	ownedPaths = append(ownedPaths, readinessRetainedRunPaths(resultsRoot, runID, false, 0o600)...)
	establishReadinessFixtureOwnership(t, tmpDir, os.Getuid(), os.Getgid(), ownedPaths...)
	configPath := filepath.Join(tmpDir, "es.json")
	writeWritableStateReadinessConfig(t, configPath, stagingRoot, resultsRoot)

	setupFakeWritableStateReadinessCommands(t, fakeBin, fakeWritableStateAccount{
		Present:   true,
		UID:       os.Getuid(),
		GID:       os.Getgid(),
		GroupName: "es",
	}, nil, filepath.Join(tmpDir, "mutations.log"))

	output, err := runESWritableStateReadinessScript(t, append(os.Environ(), "PATH="+fakeBin+":"+os.Getenv("PATH")), "--config-path", configPath)
	if err != nil {
		t.Fatalf("expected alpha-compatible warning, got err=%v\noutput=%s", err, string(output))
	}

	payload := parseWritableStateReadinessOutput(t, output)
	if payload["checker_mode"] != "alpha-compat" {
		t.Fatalf("expected checker_mode alpha-compat, got %v", payload["checker_mode"])
	}
	if payload["future_non_root_required"] != false {
		t.Fatalf("expected future_non_root_required=false, got %v", payload["future_non_root_required"])
	}
	if payload["future_non_root_ready"] != false {
		t.Fatalf("expected future_non_root_ready=false, got %v", payload["future_non_root_ready"])
	}
	if got := nestedClassification(t, payload, "runtime_normalization_contract_status"); got != "warning" {
		t.Fatalf("expected warning runtime_normalization_contract_status, got %q", got)
	}
	if got := nestedClassification(t, payload, "cleanup_readiness_status"); got != "warning" {
		t.Fatalf("expected warning cleanup_readiness_status, got %q", got)
	}
	if got := payload["overall_classification"]; got != "warning" {
		t.Fatalf("expected overall warning, got %v", got)
	}
}

func TestRemoteAlphaESWritableStateReadinessCompletedRunWithoutMarkerBlocksFutureNonRootReadiness(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	fakeBin := filepath.Join(tmpDir, "bin")
	if err := os.MkdirAll(fakeBin, 0o755); err != nil {
		t.Fatalf("mkdir fake bin: %v", err)
	}

	stagingRoot := filepath.Join(tmpDir, "staging")
	resultsRoot := filepath.Join(tmpDir, "results")
	runID := "run-457"
	platformDir := filepath.Join(stagingRoot, runID, "run", "platform")
	workDir := filepath.Join(stagingRoot, runID, "run", "work")
	resultDir := filepath.Join(stagingRoot, runID, "run", "result")
	for _, path := range []string{platformDir, workDir, resultDir} {
		if err := os.MkdirAll(path, 0o750); err != nil {
			t.Fatalf("mkdir %s: %v", path, err)
		}
	}
	if err := os.MkdirAll(filepath.Join(resultsRoot, runID), 0o750); err != nil {
		t.Fatalf("mkdir bundle dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(resultsRoot, runID, "result.tar.gz"), []byte("bundle"), 0o600); err != nil {
		t.Fatalf("write retained bundle: %v", err)
	}

	ownedPaths := append(readinessReadyRootPaths(stagingRoot, resultsRoot), readinessStagedRunPaths(stagingRoot, runID, false)...)
	ownedPaths = append(ownedPaths, readinessRetainedRunPaths(resultsRoot, runID, false, 0o600)...)
	establishReadinessFixtureOwnership(t, tmpDir, os.Getuid(), os.Getgid(), ownedPaths...)
	configPath := filepath.Join(tmpDir, "es.json")
	writeWritableStateReadinessConfig(t, configPath, stagingRoot, resultsRoot)

	setupFakeWritableStateReadinessCommands(t, fakeBin, fakeWritableStateAccount{
		Present:   true,
		UID:       os.Getuid(),
		GID:       os.Getgid(),
		GroupName: "es",
	}, nil, filepath.Join(tmpDir, "mutations.log"))

	output, err := runESWritableStateReadinessScript(
		t,
		append(os.Environ(), "PATH="+fakeBin+":"+os.Getenv("PATH")),
		"--config-path",
		configPath,
		"--mode",
		"future-non-root-required",
	)
	if err == nil {
		t.Fatalf("expected blocker for missing marker in future non-root readiness mode\noutput=%s", string(output))
	}

	payload := parseWritableStateReadinessOutput(t, output)
	if got := nestedClassification(t, payload, "runtime_normalization_contract_status"); got != "blocker" {
		t.Fatalf("expected blocker runtime_normalization_contract_status, got %q", got)
	}
	if got := nestedClassification(t, payload, "cleanup_readiness_status"); got != "blocker" {
		t.Fatalf("expected blocker cleanup_readiness_status, got %q", got)
	}
	if got := payload["overall_classification"]; got != "blocker" {
		t.Fatalf("expected overall blocker, got %v", got)
	}
}

func TestRemoteAlphaESWritableStateReadinessValidMarkerPasses(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	fakeBin := filepath.Join(tmpDir, "bin")
	if err := os.MkdirAll(fakeBin, 0o755); err != nil {
		t.Fatalf("mkdir fake bin: %v", err)
	}

	stagingRoot := filepath.Join(tmpDir, "staging")
	resultsRoot := filepath.Join(tmpDir, "results")
	runID := "run-458"
	platformDir := filepath.Join(stagingRoot, runID, "run", "platform")
	workDir := filepath.Join(stagingRoot, runID, "run", "work")
	resultDir := filepath.Join(stagingRoot, runID, "run", "result")
	for _, path := range []string{platformDir, workDir, resultDir} {
		if err := os.MkdirAll(path, 0o750); err != nil {
			t.Fatalf("mkdir %s: %v", path, err)
		}
	}
	if err := os.MkdirAll(filepath.Join(resultsRoot, runID), 0o750); err != nil {
		t.Fatalf("mkdir bundle dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(resultsRoot, runID, "result.tar.gz"), []byte("bundle"), 0o600); err != nil {
		t.Fatalf("write retained bundle: %v", err)
	}
	writeWritableStateNormalizationMarker(t, platformDir, runID, nil)

	ownedPaths := append(readinessReadyRootPaths(stagingRoot, resultsRoot), readinessStagedRunPaths(stagingRoot, runID, true)...)
	ownedPaths = append(ownedPaths, readinessRetainedRunPaths(resultsRoot, runID, false, 0o600)...)
	establishReadinessFixtureOwnership(t, tmpDir, os.Getuid(), os.Getgid(), ownedPaths...)
	configPath := filepath.Join(tmpDir, "es.json")
	writeWritableStateReadinessConfig(t, configPath, stagingRoot, resultsRoot)

	setupFakeWritableStateReadinessCommands(t, fakeBin, fakeWritableStateAccount{
		Present:   true,
		UID:       os.Getuid(),
		GID:       os.Getgid(),
		GroupName: "es",
	}, nil, filepath.Join(tmpDir, "mutations.log"))

	output, err := runESWritableStateReadinessScript(
		t,
		append(os.Environ(), "PATH="+fakeBin+":"+os.Getenv("PATH")),
		"--config-path",
		configPath,
		"--mode",
		"future-non-root-required",
	)
	if err != nil {
		t.Fatalf("expected valid marker pass, got err=%v\noutput=%s", err, string(output))
	}

	payload := parseWritableStateReadinessOutput(t, output)
	if got := nestedClassification(t, payload, "runtime_normalization_contract_status"); got != "pass" {
		t.Fatalf("expected pass runtime_normalization_contract_status, got %q", got)
	}
	if got := nestedClassification(t, payload, "cleanup_readiness_status"); got != "pass" {
		t.Fatalf("expected pass cleanup_readiness_status, got %q", got)
	}
	runtimeStatus := nestedMap(t, payload, "runtime_normalization_contract_status")
	observedRuns, ok := runtimeStatus["observed_runs"].([]any)
	if !ok || len(observedRuns) != 1 {
		t.Fatalf("expected one observed run, got %#v", runtimeStatus["observed_runs"])
	}
	runPayload, ok := observedRuns[0].(map[string]any)
	if !ok {
		t.Fatalf("observed run payload was %T", observedRuns[0])
	}
	markerPayload, ok := runPayload["marker"].(map[string]any)
	if !ok {
		t.Fatalf("marker payload was %T", runPayload["marker"])
	}
	if markerPayload["target_owner_status"] != "verified" {
		t.Fatalf("expected verified target owner, got %v", markerPayload["target_owner_status"])
	}
	if markerPayload["target_owner_verified"] != true {
		t.Fatalf("expected target_owner_verified=true, got %v", markerPayload["target_owner_verified"])
	}
}

func TestRemoteAlphaESWritableStateReadinessUsesPreservedRetainedEvidenceAfterCleanup(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	fakeBin := filepath.Join(tmpDir, "bin")
	if err := os.MkdirAll(fakeBin, 0o755); err != nil {
		t.Fatalf("mkdir fake bin: %v", err)
	}

	stagingRoot := filepath.Join(tmpDir, "staging")
	resultsRoot := filepath.Join(tmpDir, "results")
	runID := "run-458-cleaned"
	if err := os.MkdirAll(stagingRoot, 0o750); err != nil {
		t.Fatalf("mkdir staging root: %v", err)
	}
	retainedRunDir := filepath.Join(resultsRoot, runID)
	if err := os.MkdirAll(retainedRunDir, 0o750); err != nil {
		t.Fatalf("mkdir retained run dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(retainedRunDir, "result.tar.gz"), []byte("bundle"), 0o600); err != nil {
		t.Fatalf("write retained bundle: %v", err)
	}
	writeWritableStateNormalizationMarker(t, retainedRunDir, runID, nil)

	ownedPaths := append(readinessReadyRootPaths(stagingRoot, resultsRoot), readinessRetainedRunPaths(resultsRoot, runID, true, 0o600)...)
	establishReadinessFixtureOwnership(t, tmpDir, os.Getuid(), os.Getgid(), ownedPaths...)
	configPath := filepath.Join(tmpDir, "es.json")
	writeWritableStateReadinessConfig(t, configPath, stagingRoot, resultsRoot)

	setupFakeWritableStateReadinessCommands(t, fakeBin, fakeWritableStateAccount{
		Present:   true,
		UID:       os.Getuid(),
		GID:       os.Getgid(),
		GroupName: "es",
	}, nil, filepath.Join(tmpDir, "mutations.log"))

	output, err := runESWritableStateReadinessScript(
		t,
		append(os.Environ(), "PATH="+fakeBin+":"+os.Getenv("PATH")),
		"--config-path",
		configPath,
		"--mode",
		"future-non-root-required",
	)
	if err != nil {
		t.Fatalf("expected preserved retained evidence to pass, got err=%v\noutput=%s", err, string(output))
	}

	payload := parseWritableStateReadinessOutput(t, output)
	if got := nestedClassification(t, payload, "runtime_normalization_contract_status"); got != "pass" {
		t.Fatalf("expected pass runtime_normalization_contract_status, got %q", got)
	}
	runtimeStatus := nestedMap(t, payload, "runtime_normalization_contract_status")
	observedRuns, ok := runtimeStatus["observed_runs"].([]any)
	if !ok || len(observedRuns) != 1 {
		t.Fatalf("expected one observed run, got %#v", runtimeStatus["observed_runs"])
	}
	runPayload := observedRuns[0].(map[string]any)
	if runPayload["stage_root_present"] != false {
		t.Fatalf("expected cleaned stage root evidence, got %v", runPayload["stage_root_present"])
	}
	markerPayload := runPayload["marker"].(map[string]any)
	if markerPayload["evidence_source"] != "retained_result_preserved_marker" {
		t.Fatalf("expected preserved retained evidence source, got %v", markerPayload["evidence_source"])
	}
}

func TestRemoteAlphaESWritableStateReadinessInvalidPreservedRetainedEvidenceBlocks(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	fakeBin := filepath.Join(tmpDir, "bin")
	if err := os.MkdirAll(fakeBin, 0o755); err != nil {
		t.Fatalf("mkdir fake bin: %v", err)
	}

	stagingRoot := filepath.Join(tmpDir, "staging")
	resultsRoot := filepath.Join(tmpDir, "results")
	runID := "run-459-cleaned"
	if err := os.MkdirAll(stagingRoot, 0o750); err != nil {
		t.Fatalf("mkdir staging root: %v", err)
	}
	retainedRunDir := filepath.Join(resultsRoot, runID)
	if err := os.MkdirAll(retainedRunDir, 0o750); err != nil {
		t.Fatalf("mkdir retained run dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(retainedRunDir, "result.tar.gz"), []byte("bundle"), 0o600); err != nil {
		t.Fatalf("write retained bundle: %v", err)
	}
	writeWritableStateNormalizationMarker(t, retainedRunDir, runID, map[string]any{
		"completed_at": "not-a-timestamp",
	})

	ownedPaths := append(readinessReadyRootPaths(stagingRoot, resultsRoot), readinessRetainedRunPaths(resultsRoot, runID, true, 0o600)...)
	establishReadinessFixtureOwnership(t, tmpDir, os.Getuid(), os.Getgid(), ownedPaths...)
	configPath := filepath.Join(tmpDir, "es.json")
	writeWritableStateReadinessConfig(t, configPath, stagingRoot, resultsRoot)

	setupFakeWritableStateReadinessCommands(t, fakeBin, fakeWritableStateAccount{
		Present:   true,
		UID:       os.Getuid(),
		GID:       os.Getgid(),
		GroupName: "es",
	}, nil, filepath.Join(tmpDir, "mutations.log"))

	output, err := runESWritableStateReadinessScript(
		t,
		append(os.Environ(), "PATH="+fakeBin+":"+os.Getenv("PATH")),
		"--config-path",
		configPath,
		"--mode",
		"future-non-root-required",
	)
	if err == nil {
		t.Fatalf("expected blocker for invalid preserved retained evidence\noutput=%s", string(output))
	}

	payload := parseWritableStateReadinessOutput(t, output)
	if got := nestedClassification(t, payload, "runtime_normalization_contract_status"); got != "blocker" {
		t.Fatalf("expected blocker runtime_normalization_contract_status, got %q", got)
	}
}

func TestRemoteAlphaESWritableStateReadinessInvalidPresentMarkerBlocks(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	fakeBin := filepath.Join(tmpDir, "bin")
	if err := os.MkdirAll(fakeBin, 0o755); err != nil {
		t.Fatalf("mkdir fake bin: %v", err)
	}

	stagingRoot := filepath.Join(tmpDir, "staging")
	resultsRoot := filepath.Join(tmpDir, "results")
	runID := "run-459"
	platformDir := filepath.Join(stagingRoot, runID, "run", "platform")
	workDir := filepath.Join(stagingRoot, runID, "run", "work")
	resultDir := filepath.Join(stagingRoot, runID, "run", "result")
	for _, path := range []string{platformDir, workDir, resultDir} {
		if err := os.MkdirAll(path, 0o750); err != nil {
			t.Fatalf("mkdir %s: %v", path, err)
		}
	}
	if err := os.MkdirAll(filepath.Join(resultsRoot, runID), 0o750); err != nil {
		t.Fatalf("mkdir bundle dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(resultsRoot, runID, "result.tar.gz"), []byte("bundle"), 0o600); err != nil {
		t.Fatalf("write retained bundle: %v", err)
	}
	writeWritableStateNormalizationMarker(t, platformDir, runID, map[string]any{
		"completed_at": "not-a-timestamp",
	})

	ownedPaths := append(readinessReadyRootPaths(stagingRoot, resultsRoot), readinessStagedRunPaths(stagingRoot, runID, true)...)
	ownedPaths = append(ownedPaths, readinessRetainedRunPaths(resultsRoot, runID, false, 0o600)...)
	establishReadinessFixtureOwnership(t, tmpDir, os.Getuid(), os.Getgid(), ownedPaths...)
	configPath := filepath.Join(tmpDir, "es.json")
	writeWritableStateReadinessConfig(t, configPath, stagingRoot, resultsRoot)

	setupFakeWritableStateReadinessCommands(t, fakeBin, fakeWritableStateAccount{
		Present:   true,
		UID:       os.Getuid(),
		GID:       os.Getgid(),
		GroupName: "es",
	}, nil, filepath.Join(tmpDir, "mutations.log"))

	output, err := runESWritableStateReadinessScript(t, append(os.Environ(), "PATH="+fakeBin+":"+os.Getenv("PATH")), "--config-path", configPath)
	if err == nil {
		t.Fatalf("expected blocker for invalid present marker\noutput=%s", string(output))
	}

	payload := parseWritableStateReadinessOutput(t, output)
	if payload["checker_mode"] != "alpha-compat" {
		t.Fatalf("expected checker_mode alpha-compat, got %v", payload["checker_mode"])
	}
	if got := nestedClassification(t, payload, "runtime_normalization_contract_status"); got != "blocker" {
		t.Fatalf("expected blocker runtime_normalization_contract_status, got %q", got)
	}
	if got := nestedClassification(t, payload, "cleanup_readiness_status"); got != "blocker" {
		t.Fatalf("expected blocker cleanup_readiness_status, got %q", got)
	}
}

func TestRemoteAlphaESWritableStateReadinessTargetOwnerMismatchBlocks(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	fakeBin := filepath.Join(tmpDir, "bin")
	if err := os.MkdirAll(fakeBin, 0o755); err != nil {
		t.Fatalf("mkdir fake bin: %v", err)
	}

	stagingRoot := filepath.Join(tmpDir, "staging")
	resultsRoot := filepath.Join(tmpDir, "results")
	runID := "run-460"
	platformDir := filepath.Join(stagingRoot, runID, "run", "platform")
	workDir := filepath.Join(stagingRoot, runID, "run", "work")
	resultDir := filepath.Join(stagingRoot, runID, "run", "result")
	for _, path := range []string{platformDir, workDir, resultDir} {
		if err := os.MkdirAll(path, 0o750); err != nil {
			t.Fatalf("mkdir %s: %v", path, err)
		}
	}
	if err := os.MkdirAll(filepath.Join(resultsRoot, runID), 0o750); err != nil {
		t.Fatalf("mkdir bundle dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(resultsRoot, runID, "result.tar.gz"), []byte("bundle"), 0o600); err != nil {
		t.Fatalf("write retained bundle: %v", err)
	}
	writeWritableStateNormalizationMarker(t, platformDir, runID, map[string]any{
		"target_uid": os.Getuid() + 1,
	})
	fakeESUID, fakeESGID := os.Getuid(), os.Getgid()
	ownedPaths := append(readinessReadyRootPaths(stagingRoot, resultsRoot), readinessStagedRunPaths(stagingRoot, runID, true)...)
	ownedPaths = append(ownedPaths, readinessRetainedRunPaths(resultsRoot, runID, false, 0o600)...)
	establishReadinessFixtureOwnership(t, tmpDir, fakeESUID, fakeESGID, ownedPaths...)
	for _, root := range []string{stagingRoot, resultsRoot} {
		entries, err := os.ReadDir(root)
		if err != nil || len(entries) != 1 || entries[0].Name() != runID || !entries[0].IsDir() {
			t.Fatalf("expected only fixture run %s under %s, got %v, %v", runID, root, entries, err)
		}
	}
	markerBefore := readJSONFile(t, filepath.Join(platformDir, "ownership-normalization.json"))
	markerUID, uidOK := markerBefore["target_uid"].(float64)
	markerGID, gidOK := markerBefore["target_gid"].(float64)
	if !uidOK || !gidOK || int(markerUID) != fakeESUID+1 || int(markerUID) == fakeESUID || int(markerGID) != fakeESGID {
		t.Fatalf("fixture marker target must deliberately differ only in UID from fake es %d:%d, got %v:%v", fakeESUID, fakeESGID, markerBefore["target_uid"], markerBefore["target_gid"])
	}

	configPath := filepath.Join(tmpDir, "es.json")
	writeWritableStateReadinessConfig(t, configPath, stagingRoot, resultsRoot)

	mutationLogPath := filepath.Join(tmpDir, "mutations.log")
	setupFakeWritableStateReadinessCommands(t, fakeBin, fakeWritableStateAccount{
		Present:   true,
		UID:       fakeESUID,
		GID:       fakeESGID,
		GroupName: "es",
	}, nil, mutationLogPath)

	output, err := runESWritableStateReadinessScript(
		t,
		append(os.Environ(), "PATH="+fakeBin+":"+os.Getenv("PATH")),
		"--config-path",
		configPath,
		"--mode",
		"future-non-root-required",
	)
	if err == nil {
		t.Fatalf("expected blocker for target-owner mismatch\noutput=%s", string(output))
	}

	payload := parseWritableStateReadinessOutput(t, output)
	if got := nestedClassification(t, payload, "runtime_normalization_contract_status"); got != "blocker" {
		t.Fatalf("expected blocker runtime_normalization_contract_status, got %q", got)
	}
	runtimeStatus := nestedMap(t, payload, "runtime_normalization_contract_status")
	observedRuns, ok := runtimeStatus["observed_runs"].([]any)
	if !ok || len(observedRuns) != 1 {
		t.Fatalf("expected one observed run, got %#v", runtimeStatus["observed_runs"])
	}
	runPayload, ok := observedRuns[0].(map[string]any)
	if !ok {
		t.Fatalf("observed run payload was %T", observedRuns[0])
	}
	if runPayload["run_id"] != runID {
		t.Fatalf("expected observed run %s, got %v", runID, runPayload["run_id"])
	}
	markerPayload, ok := runPayload["marker"].(map[string]any)
	if !ok {
		t.Fatalf("marker payload was %T", runPayload["marker"])
	}
	if markerPayload["target_owner_status"] != "mismatch" {
		t.Fatalf("expected mismatch target owner status, got %v", markerPayload["target_owner_status"])
	}
	if markerPayload["target_owner_checked"] != true {
		t.Fatalf("expected target_owner_checked=true, got %v", markerPayload["target_owner_checked"])
	}
	issues, ok := markerPayload["issues"].([]any)
	if !ok || len(issues) != 1 || issues[0] != "normalization marker target_uid does not match expected es UID" {
		t.Fatalf("expected only the intended marker target UID mismatch, got %v", markerPayload["issues"])
	}
	verification := nestedMap(t, payload, "target_owner_verification")
	if verification["status"] != "mismatch" || verification["checked_against_expected_owner"] != true {
		t.Fatalf("expected checked target-owner mismatch, got %+v", verification)
	}
	if payload["overall_classification"] != "blocker" || payload["non_mutating"] != true {
		t.Fatalf("expected blocked non-mutating readiness result, got classification=%v non_mutating=%v", payload["overall_classification"], payload["non_mutating"])
	}
	if _, err := os.Stat(mutationLogPath); !os.IsNotExist(err) {
		t.Fatalf("readiness helper must not mutate fixture state: %v", err)
	}
}

func TestRemoteAlphaESWritableStateReadinessReportsMarkerEvidenceAsUnverifiedWithoutESOwner(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	fakeBin := filepath.Join(tmpDir, "bin")
	if err := os.MkdirAll(fakeBin, 0o755); err != nil {
		t.Fatalf("mkdir fake bin: %v", err)
	}

	stagingRoot := filepath.Join(tmpDir, "staging")
	resultsRoot := filepath.Join(tmpDir, "results")
	runID := "run-461"
	platformDir := filepath.Join(stagingRoot, runID, "run", "platform")
	workDir := filepath.Join(stagingRoot, runID, "run", "work")
	resultDir := filepath.Join(stagingRoot, runID, "run", "result")
	for _, path := range []string{platformDir, workDir, resultDir} {
		if err := os.MkdirAll(path, 0o750); err != nil {
			t.Fatalf("mkdir %s: %v", path, err)
		}
	}
	if err := os.MkdirAll(filepath.Join(resultsRoot, runID), 0o750); err != nil {
		t.Fatalf("mkdir bundle dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(resultsRoot, runID, "result.tar.gz"), []byte("bundle"), 0o600); err != nil {
		t.Fatalf("write retained bundle: %v", err)
	}
	writeWritableStateNormalizationMarker(t, platformDir, runID, nil)

	configPath := filepath.Join(tmpDir, "es.json")
	writeWritableStateReadinessConfig(t, configPath, stagingRoot, resultsRoot)

	setupFakeWritableStateReadinessCommands(t, fakeBin, fakeWritableStateAccount{}, nil, filepath.Join(tmpDir, "mutations.log"))

	output, err := runESWritableStateReadinessScript(t, append(os.Environ(), "PATH="+fakeBin+":"+os.Getenv("PATH")), "--config-path", configPath)
	if err != nil {
		t.Fatalf("expected alpha-compatible warning, got err=%v\noutput=%s", err, string(output))
	}

	payload := parseWritableStateReadinessOutput(t, output)
	if got := nestedClassification(t, payload, "runtime_normalization_contract_status"); got != "warning" {
		t.Fatalf("expected warning runtime_normalization_contract_status, got %q", got)
	}
	if got := nestedClassification(t, payload, "es_account_status"); got != "warning" {
		t.Fatalf("expected warning es_account_status, got %q", got)
	}
	if got := payload["overall_classification"]; got != "warning" {
		t.Fatalf("expected overall warning, got %v", got)
	}
	runtimeStatus := nestedMap(t, payload, "runtime_normalization_contract_status")
	observedRuns, ok := runtimeStatus["observed_runs"].([]any)
	if !ok || len(observedRuns) != 1 {
		t.Fatalf("expected one observed run, got %#v", runtimeStatus["observed_runs"])
	}
	runPayload, ok := observedRuns[0].(map[string]any)
	if !ok {
		t.Fatalf("observed run payload was %T", observedRuns[0])
	}
	markerPayload, ok := runPayload["marker"].(map[string]any)
	if !ok {
		t.Fatalf("marker payload was %T", runPayload["marker"])
	}
	if markerPayload["target_owner_status"] != "unverified" {
		t.Fatalf("expected unverified target owner status, got %v", markerPayload["target_owner_status"])
	}
	if markerPayload["target_owner_checked"] != false {
		t.Fatalf("expected target_owner_checked=false, got %v", markerPayload["target_owner_checked"])
	}
	if markerPayload["target_owner_verified"] != false {
		t.Fatalf("expected target_owner_verified=false, got %v", markerPayload["target_owner_verified"])
	}
}

func TestRemoteAlphaESWritableStateReadinessBlocksRootOwnerModelMismatchInFutureNonRootRequiredMode(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	fakeBin := filepath.Join(tmpDir, "bin")
	if err := os.MkdirAll(fakeBin, 0o755); err != nil {
		t.Fatalf("mkdir fake bin: %v", err)
	}

	stagingRoot := filepath.Join(tmpDir, "staging")
	resultsRoot := filepath.Join(tmpDir, "results")
	if err := os.MkdirAll(stagingRoot, 0o750); err != nil {
		t.Fatalf("mkdir staging root: %v", err)
	}
	if err := os.MkdirAll(resultsRoot, 0o750); err != nil {
		t.Fatalf("mkdir results root: %v", err)
	}

	configPath := filepath.Join(tmpDir, "es.json")
	writeWritableStateReadinessConfig(t, configPath, stagingRoot, resultsRoot)

	setupFakeWritableStateReadinessCommands(t, fakeBin, fakeWritableStateAccount{
		Present:   true,
		UID:       os.Getuid(),
		GID:       os.Getgid(),
		GroupName: "es",
	}, map[string]fakeWritableStateStat{
		stagingRoot: {UID: os.Getuid(), GID: os.Getgid(), Mode: "0750", FileType: "directory"},
		resultsRoot: {UID: os.Getuid(), GID: os.Getgid() + 1, Mode: "0750", FileType: "directory"},
	}, filepath.Join(tmpDir, "mutations.log"))

	output, err := runESWritableStateReadinessScript(
		t,
		append(os.Environ(), "PATH="+fakeBin+":"+os.Getenv("PATH")),
		"--config-path",
		configPath,
		"--mode",
		"future-non-root-required",
	)
	if err == nil {
		t.Fatalf("expected blocker for staging/results owner-model mismatch\noutput=%s", string(output))
	}

	payload := parseWritableStateReadinessOutput(t, output)
	if got := nestedClassification(t, payload, "target_owner_consistency_status"); got != "blocker" {
		t.Fatalf("expected blocker target_owner_consistency_status, got %q", got)
	}
	status := nestedMap(t, payload, "target_owner_consistency_status")
	if status["same_target_owner"] != false {
		t.Fatalf("expected same_target_owner=false, got %v", status["same_target_owner"])
	}
	if !strings.Contains(status["summary"].(string), "future non-root ES requires one shared target owner model") {
		t.Fatalf("expected actionable mismatch summary, got %v", status["summary"])
	}
}

func TestRemoteAlphaESWritableStateReadinessFutureModeBlocksStatOwnershipMismatch(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	fakeBin := filepath.Join(tmpDir, "bin")
	if err := os.MkdirAll(fakeBin, 0o755); err != nil {
		t.Fatalf("mkdir fake bin: %v", err)
	}

	stagingRoot := filepath.Join(tmpDir, "staging")
	resultsRoot := filepath.Join(tmpDir, "results")
	if err := os.MkdirAll(stagingRoot, 0o750); err != nil {
		t.Fatalf("mkdir staging root: %v", err)
	}
	if err := os.MkdirAll(resultsRoot, 0o750); err != nil {
		t.Fatalf("mkdir results root: %v", err)
	}

	configPath := filepath.Join(tmpDir, "es.json")
	writeWritableStateReadinessConfig(t, configPath, stagingRoot, resultsRoot)

	setupFakeWritableStateReadinessCommands(t, fakeBin, fakeWritableStateAccount{
		Present:   true,
		UID:       994,
		GID:       994,
		GroupName: "es",
	}, nil, filepath.Join(tmpDir, "mutations.log"))

	output, err := runESWritableStateReadinessScript(
		t,
		append(os.Environ(), "PATH="+fakeBin+":"+os.Getenv("PATH")),
		"--config-path",
		configPath,
		"--mode",
		"future-non-root-required",
	)
	if err == nil {
		t.Fatalf("expected blocker for stat ownership mismatch\noutput=%s", string(output))
	}

	payload := parseWritableStateReadinessOutput(t, output)
	if got := nestedClassification(t, payload, "staging_root_status"); got != "blocker" {
		t.Fatalf("expected blocker staging_root_status, got %q", got)
	}
}

func TestRemoteAlphaESWritableStateReadinessLabelsCompatibilityEdgesWithoutBlocking(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	fakeBin := filepath.Join(tmpDir, "bin")
	if err := os.MkdirAll(fakeBin, 0o755); err != nil {
		t.Fatalf("mkdir fake bin: %v", err)
	}

	stagingRoot := filepath.Join(tmpDir, "staging")
	resultsRoot := filepath.Join(tmpDir, "results")
	if err := os.MkdirAll(stagingRoot, 0o750); err != nil {
		t.Fatalf("mkdir staging root: %v", err)
	}
	if err := os.MkdirAll(resultsRoot, 0o750); err != nil {
		t.Fatalf("mkdir results root: %v", err)
	}

	establishReadinessFixtureOwnership(t, tmpDir, os.Getuid(), os.Getgid(), readinessReadyRootPaths(stagingRoot, resultsRoot)...)
	configPath := filepath.Join(tmpDir, "es.json")
	writeWritableStateReadinessConfig(t, configPath, stagingRoot, resultsRoot)

	setupFakeWritableStateReadinessCommands(t, fakeBin, fakeWritableStateAccount{
		Present:   true,
		UID:       os.Getuid(),
		GID:       os.Getgid(),
		GroupName: "es",
	}, nil, filepath.Join(tmpDir, "mutations.log"))

	output, err := runESWritableStateReadinessScript(t, append(os.Environ(), "PATH="+fakeBin+":"+os.Getenv("PATH")), "--config-path", configPath)
	if err != nil {
		t.Fatalf("checker failed: %v\noutput=%s", err, string(output))
	}

	payload := parseWritableStateReadinessOutput(t, output)
	edgesValue, ok := payload["bounded_compatibility_edges"]
	if !ok {
		t.Fatal("missing bounded_compatibility_edges")
	}
	edges, ok := edgesValue.([]any)
	if !ok {
		t.Fatalf("bounded_compatibility_edges was %T, want []any", edgesValue)
	}
	if len(edges) != 4 {
		t.Fatalf("expected 4 compatibility edges, got %d", len(edges))
	}
	for _, raw := range edges {
		edge, ok := raw.(map[string]any)
		if !ok {
			t.Fatalf("compatibility edge entry was %T, want map[string]any", raw)
		}
		if edge["classification"] != "warning" {
			t.Fatalf("expected warning compatibility edge, got %v", edge["classification"])
		}
	}
	if payload["overall_classification"] == "blocker" {
		t.Fatalf("compatibility edges should not block by themselves: output=%s", string(output))
	}
}

func TestRemoteAlphaESWritableStateReadinessJSONShapeStable(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	fakeBin := filepath.Join(tmpDir, "bin")
	if err := os.MkdirAll(fakeBin, 0o755); err != nil {
		t.Fatalf("mkdir fake bin: %v", err)
	}

	stagingRoot := filepath.Join(tmpDir, "staging")
	resultsRoot := filepath.Join(tmpDir, "results")
	if err := os.MkdirAll(stagingRoot, 0o750); err != nil {
		t.Fatalf("mkdir staging root: %v", err)
	}
	if err := os.MkdirAll(resultsRoot, 0o750); err != nil {
		t.Fatalf("mkdir results root: %v", err)
	}

	establishReadinessFixtureOwnership(t, tmpDir, os.Getuid(), os.Getgid(), readinessReadyRootPaths(stagingRoot, resultsRoot)...)
	configPath := filepath.Join(tmpDir, "es.json")
	writeWritableStateReadinessConfig(t, configPath, stagingRoot, resultsRoot)

	setupFakeWritableStateReadinessCommands(t, fakeBin, fakeWritableStateAccount{
		Present:   true,
		UID:       os.Getuid(),
		GID:       os.Getgid(),
		GroupName: "es",
	}, nil, filepath.Join(tmpDir, "mutations.log"))

	output, err := runESWritableStateReadinessScript(t, append(os.Environ(), "PATH="+fakeBin+":"+os.Getenv("PATH")), "--config-path", configPath)
	if err != nil {
		t.Fatalf("checker failed: %v\noutput=%s", err, string(output))
	}

	payload := parseWritableStateReadinessOutput(t, output)
	expectedKeys := []string{
		"blockers",
		"bounded_compatibility_edges",
		"checked_at",
		"checker_mode",
		"cleanup_readiness_status",
		"config_path",
		"config_status",
		"es_account_status",
		"future_non_root_ready",
		"future_non_root_required",
		"marker_presence_policy",
		"non_mutating",
		"operation_mode",
		"overall_classification",
		"results_root_status",
		"retained_result_readiness_status",
		"runtime_normalization_contract_status",
		"schema_version",
		"staging_root_status",
		"target_owner_consistency_status",
		"target_owner_verification",
		"warnings",
	}
	keys := make([]string, 0, len(payload))
	for key := range payload {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	if strings.Join(keys, ",") != strings.Join(expectedKeys, ",") {
		t.Fatalf("unexpected top-level keys:\n got=%v\nwant=%v", keys, expectedKeys)
	}
	if payload["schema_version"] != "execution-substrate.remote-alpha.es-writable-state-readiness.v1" {
		t.Fatalf("unexpected schema_version: %v", payload["schema_version"])
	}
	if payload["operation_mode"] != "check_only" {
		t.Fatalf("unexpected operation_mode: %v", payload["operation_mode"])
	}
	if payload["non_mutating"] != true {
		t.Fatalf("expected non_mutating=true, got %v", payload["non_mutating"])
	}
	if payload["checker_mode"] != "alpha-compat" {
		t.Fatalf("unexpected checker_mode: %v", payload["checker_mode"])
	}
	if payload["future_non_root_required"] != false {
		t.Fatalf("expected future_non_root_required=false, got %v", payload["future_non_root_required"])
	}
}
