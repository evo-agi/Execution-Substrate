package executionsubstrate_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

type fakeESServiceUserAccount struct {
	Present             bool
	UID                 int
	GID                 int
	GroupName           string
	SupplementaryGroups []string
	GroupEntryMembers   []string
}

type esServiceUserMigrationFixture struct {
	ESBinaryPath             string
	RuntimeSupportBinaryPath string
	SPIRESocketPath          string
	ConfigPath               string
	HealthEnvPath            string
	ServiceUnitPath          string
	ServiceDropInDir         string
	ServiceDropInPath        string
	TLSDir                   string
	StagingRoot              string
	ResultsRoot              string
	BackupRoot               esServiceUserTestBackupRoot
}

type esServiceUserTestBackupRoot struct {
	fixtureRoot string
	path        string
}

func newESServiceUserTestBackupRoot(t *testing.T, fixtureRoot string) esServiceUserTestBackupRoot {
	t.Helper()
	backup := esServiceUserTestBackupRoot{fixtureRoot: fixtureRoot, path: filepath.Join(fixtureRoot, "backups")}
	if err := os.Chmod(fixtureRoot, 0o700); err != nil {
		t.Fatalf("make test temporary root private: %v", err)
	}
	if err := os.Mkdir(backup.path, 0o700); err != nil {
		t.Fatalf("create fixture backup root: %v", err)
	}
	requireESServiceUserTestBackupRoot(t, backup)
	return backup
}

func requireESServiceUserTestBackupRoot(t *testing.T, backup esServiceUserTestBackupRoot) {
	t.Helper()
	if !filepath.IsAbs(backup.fixtureRoot) || !filepath.IsAbs(backup.path) {
		t.Fatal("fixture backup paths must be absolute")
	}
	rel, err := filepath.Rel(backup.fixtureRoot, backup.path)
	if err != nil || rel != "backups" {
		t.Fatal("fixture backup root must be a direct child of the test temporary root")
	}
	for _, path := range []string{backup.fixtureRoot, backup.path} {
		info, err := os.Lstat(path)
		if err != nil {
			t.Fatalf("stat fixture backup boundary: %v", err)
		}
		metadata, ok := info.Sys().(*syscall.Stat_t)
		if !ok || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || metadata.Uid != uint32(os.Geteuid()) || info.Mode().Perm() != 0o700 {
			t.Fatal("fixture backup boundary must be a nonsymlink current-user-owned mode-0700 directory")
		}
	}
}

func esServiceUserTestChildEnv(t *testing.T, backup esServiceUserTestBackupRoot, env []string) []string {
	t.Helper()
	requireESServiceUserTestBackupRoot(t, backup)
	mutationLogPath := filepath.Join(backup.fixtureRoot, "mutations.log")
	child := make([]string, 0, len(env)+2)
	for _, entry := range env {
		key, _, ok := strings.Cut(entry, "=")
		if !ok {
			t.Fatal("malformed fixture helper environment entry")
		}
		if key == "REMOTE_ALPHA_TEST_BACKUP_ROOT" {
			continue
		}
		if key == "REMOTE_ALPHA_TEST_MUTATION_LOG_PATH" {
			continue
		}
		child = append(child, entry)
	}
	child = append(child,
		"REMOTE_ALPHA_TEST_BACKUP_ROOT="+backup.path,
		"REMOTE_ALPHA_TEST_MUTATION_LOG_PATH="+mutationLogPath,
	)
	for key, want := range map[string]string{
		"REMOTE_ALPHA_TEST_BACKUP_ROOT":       backup.path,
		"REMOTE_ALPHA_TEST_MUTATION_LOG_PATH": mutationLogPath,
	} {
		count := 0
		for _, entry := range child {
			name, value, _ := strings.Cut(entry, "=")
			if name == key {
				count++
				if value != want {
					t.Fatalf("fixture helper environment has a wrong %s value", key)
				}
			}
		}
		if count != 1 {
			t.Fatalf("fixture helper environment must contain exactly one %s", key)
		}
	}
	return child
}

func requireNoESServiceUserTestMutationLog(t *testing.T, backup esServiceUserTestBackupRoot) {
	t.Helper()
	path := filepath.Join(backup.fixtureRoot, "mutations.log")
	if _, err := os.Lstat(path); err == nil {
		t.Fatal("fixture mutation command log must remain absent")
	} else if !os.IsNotExist(err) {
		t.Fatalf("cannot verify fixture mutation command log absence: %v", err)
	}
}

func requireESServiceUserTestBackupEntries(t *testing.T, backup esServiceUserTestBackupRoot, want int, entryMode os.FileMode) string {
	t.Helper()
	requireESServiceUserTestBackupRoot(t, backup)
	if want != 0 && want != 1 {
		t.Fatal("fixture backup count must be zero or one")
	}
	entries, err := os.ReadDir(backup.path)
	if err != nil {
		t.Fatalf("read fixture backup root: %v", err)
	}
	if len(entries) != want {
		t.Fatalf("fixture backup root contains %d entries, want %d", len(entries), want)
	}
	if want == 0 {
		return ""
	}
	path := filepath.Join(backup.path, entries[0].Name())
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("stat fixture backup: %v", err)
	}
	metadata, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || metadata.Uid != uint32(os.Geteuid()) || info.Mode().Perm() != entryMode {
		t.Fatalf("fixture backup entry must be a current-user-owned nonsymlink mode-%04o directory", entryMode)
	}
	return path
}

func requireESServiceUserTestReportedBackup(t *testing.T, backup esServiceUserTestBackupRoot, reported string, entryMode os.FileMode) string {
	t.Helper()
	actual := requireESServiceUserTestBackupEntries(t, backup, 1, entryMode)
	if reported != actual || strings.HasPrefix(reported, "/var/tmp/execution-substrate-remote-alpha") {
		t.Fatal("reported backup path escaped the fixture-owned backup root")
	}
	return actual
}

func requireESServiceUserTestBackupArtifact(t *testing.T, backupDir, reported, relative string, mode os.FileMode, directory bool) {
	t.Helper()
	if relative == "" || filepath.IsAbs(relative) || strings.HasPrefix(relative, "..") || reported != filepath.Join(backupDir, relative) {
		t.Fatal("reported backup artifact path escaped its fixture backup directory")
	}
	path := backupDir
	parts := strings.Split(relative, string(os.PathSeparator))
	for index, part := range parts {
		path = filepath.Join(path, part)
		info, err := os.Lstat(path)
		if err != nil {
			t.Fatalf("stat fixture backup artifact: %v", err)
		}
		metadata, ok := info.Sys().(*syscall.Stat_t)
		if !ok || info.Mode()&os.ModeSymlink != 0 || metadata.Uid != uint32(os.Geteuid()) {
			t.Fatal("fixture backup artifact must be current-user-owned and nonsymlink")
		}
		if index == len(parts)-1 {
			if info.IsDir() != directory || (!directory && !info.Mode().IsRegular()) || info.Mode().Perm() != mode {
				t.Fatalf("fixture backup artifact has unexpected type or mode; want %04o", mode)
			}
		} else if !info.IsDir() {
			t.Fatal("fixture backup artifact parent must be a directory")
		}
	}
}

func requireESServiceUserTestBackupField(t *testing.T, backup map[string]any, field string) string {
	t.Helper()
	value, ok := backup[field].(string)
	if !ok || value == "" {
		t.Fatalf("fixture backup report is missing %s", field)
	}
	return value
}

func requireESServiceUserMigrationBackupReport(t *testing.T, fixture esServiceUserMigrationFixture, summary map[string]any) {
	t.Helper()
	backup := nestedMap(t, summary, "backup")
	backupDir := requireESServiceUserTestReportedBackup(t, fixture.BackupRoot, requireESServiceUserTestBackupField(t, backup, "path"), 0o700)
	requireESServiceUserTestBackupArtifact(t, backupDir, requireESServiceUserTestBackupField(t, backup, "snapshot_path"), "pre-apply-snapshot.json", 0o644, false)
	requireESServiceUserTestBackupArtifact(t, backupDir, requireESServiceUserTestBackupField(t, backup, "config_backup_path"), "es.json", 0o600, false)
	requireESServiceUserTestBackupArtifact(t, backupDir, requireESServiceUserTestBackupField(t, backup, "service_unit_backup_dir"), "systemd", 0o755, true)
	requireESServiceUserTestBackupArtifact(t, backupDir, requireESServiceUserTestBackupField(t, backup, "dropin_backup_dir"), "dropins", 0o755, true)
	requireESServiceUserTestBackupArtifact(t, backupDir, filepath.Join(backupDir, "systemd", "es.service"), filepath.Join("systemd", "es.service"), 0o644, false)
}

func requireESServiceUserFixtureLiveRoots(t *testing.T, fixture esServiceUserMigrationFixture, uid, gid int, mode uint32) {
	t.Helper()
	for _, path := range []string{fixture.StagingRoot, fixture.ResultsRoot} {
		info, err := os.Lstat(path)
		if err != nil {
			t.Fatalf("stat fixture live root %s: %v", path, err)
		}
		if !info.IsDir() {
			t.Fatalf("fixture live root %s is not a directory: %s", path, info.Mode())
		}
		statInfo, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			t.Fatalf("fixture live root %s has no UID/GID stat metadata", path)
		}
		actualMode := uint32(statInfo.Mode) & 0o7777
		if statInfo.Uid != uint32(uid) || statInfo.Gid != uint32(gid) || actualMode != mode {
			t.Fatalf("fixture live root %s: got UID:GID %d:%d mode %04o; want %d:%d mode %04o", path, statInfo.Uid, statInfo.Gid, actualMode, uid, gid, mode)
		}
	}
}

func runSourcedESServiceUserMigrationHelper(t *testing.T, backup esServiceUserTestBackupRoot, wantBackups int, env []string, shellBody string) ([]byte, error) {
	t.Helper()
	requireESServiceUserTestBackupEntries(t, backup, 0, 0)
	helperPath := filepath.Join(executionSubstrateRepoRoot, "scripts", "internal", "remote_alpha_migrate_es_service_user.sh")
	script := fmt.Sprintf("set -euo pipefail\nsource %q\n%s\n", helperPath, shellBody)
	cmd := exec.Command("/bin/bash", "-c", script)
	cmd.Dir = executionSubstrateRepoRoot
	cmd.Env = esServiceUserTestChildEnv(t, backup, env)
	output, err := cmd.CombinedOutput()
	requireESServiceUserTestBackupEntries(t, backup, wantBackups, 0o700)
	return output, err
}

func esServiceUserMigrationExpectedSliceShell(f esServiceUserMigrationFixture) string {
	return fmt.Sprintf(`
remote_alpha_migrate_es_service_user_expected_binary_path=%q
remote_alpha_migrate_es_service_user_expected_config_path=%q
remote_alpha_migrate_es_service_user_expected_healthcheck_env_path=%q
remote_alpha_migrate_es_service_user_expected_service_unit_path=%q
remote_alpha_migrate_es_service_user_expected_service_dropin_dir=%q
remote_alpha_migrate_es_service_user_expected_service_dropin_path=%q
`, f.ESBinaryPath, f.ConfigPath, f.HealthEnvPath, f.ServiceUnitPath, f.ServiceDropInDir, f.ServiceDropInPath)
}

func setupESServiceUserMigrationFixture(t *testing.T, tmpDir string) esServiceUserMigrationFixture {
	t.Helper()

	fixture := esServiceUserMigrationFixture{
		ESBinaryPath:             filepath.Join(tmpDir, "bin", "es"),
		RuntimeSupportBinaryPath: filepath.Join(tmpDir, "bin", "es-runtime-support"),
		ConfigPath:               filepath.Join(tmpDir, "config", "es.json"),
		HealthEnvPath:            filepath.Join(tmpDir, "config", "healthcheck.env"),
		ServiceUnitPath:          filepath.Join(tmpDir, "systemd", "es.service"),
		ServiceDropInDir:         filepath.Join(tmpDir, "systemd", "es.service.d"),
		ServiceDropInPath:        filepath.Join(tmpDir, "systemd", "es.service.d", "10-account.conf"),
		TLSDir:                   filepath.Join(tmpDir, "tls"),
		StagingRoot:              filepath.Join(tmpDir, "state", "staging"),
		ResultsRoot:              filepath.Join(tmpDir, "state", "results"),
		BackupRoot:               newESServiceUserTestBackupRoot(t, tmpDir),
	}
	spireDir, err := os.MkdirTemp("/tmp", "es-spire-")
	if err != nil {
		t.Fatalf("mkdir temp spire dir: %v", err)
	}
	t.Cleanup(func() {
		_ = os.RemoveAll(spireDir)
	})
	fixture.SPIRESocketPath = filepath.Join(spireDir, "agent.sock")

	for _, dir := range []string{
		filepath.Dir(fixture.ESBinaryPath),
		filepath.Dir(fixture.ConfigPath),
		filepath.Dir(fixture.ServiceUnitPath),
		fixture.ServiceDropInDir,
		fixture.TLSDir,
		fixture.StagingRoot,
		fixture.ResultsRoot,
	} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", dir, err)
		}
	}

	fakeESUID, fakeESGID := os.Getuid(), os.Getgid()
	for _, root := range []string{fixture.StagingRoot, fixture.ResultsRoot} {
		if err := os.Chown(root, fakeESUID, fakeESGID); err != nil {
			t.Fatalf("set fixture live root %s owner to fake es identity %d:%d: %v", root, fakeESUID, fakeESGID, err)
		}
		if err := os.Chmod(root, 0o755); err != nil {
			t.Fatalf("set fixture live root %s mode 0755: %v", root, err)
		}
	}
	requireESServiceUserFixtureLiveRoots(t, fixture, fakeESUID, fakeESGID, 0o755)

	if err := os.WriteFile(fixture.ESBinaryPath, []byte("binary\n"), 0o755); err != nil {
		t.Fatalf("write ES binary: %v", err)
	}
	if err := os.WriteFile(fixture.RuntimeSupportBinaryPath, []byte("runtime-support\n"), 0o755); err != nil {
		t.Fatalf("write runtime support binary: %v", err)
	}
	if err := os.WriteFile(fixture.ServiceUnitPath, []byte("[Service]\nExecStart=/placeholder\n"), 0o644); err != nil {
		t.Fatalf("write service unit: %v", err)
	}
	listener, err := net.Listen("unix", fixture.SPIRESocketPath)
	if err != nil {
		t.Fatalf("listen on unix socket: %v", err)
	}
	t.Cleanup(func() {
		_ = listener.Close()
	})

	for _, name := range []string{
		"es-server-cert.pem",
		"es-server-key.pem",
		"server-client-ca.pem",
		"artifact-registry-client-cert.pem",
		"artifact-registry-client-key.pem",
		"artifact-registry-root-ca.pem",
		"execution-governance-client-cert.pem",
		"execution-governance-client-key.pem",
		"execution-governance-root-ca.pem",
		"operator-client-cert.pem",
		"operator-client-key.pem",
	} {
		if err := os.WriteFile(filepath.Join(fixture.TLSDir, name), []byte(name+"\n"), 0o600); err != nil {
			t.Fatalf("write tls file %s: %v", name, err)
		}
	}

	payload := map[string]any{
		"http": map[string]any{
			"bind_address": "127.0.0.1",
			"port":         8445,
		},
		"nomad": map[string]any{
			"base_url":        "http://127.0.0.1:4646",
			"datacenter":      "dc1",
			"timeout_seconds": 5,
		},
		"tls": map[string]any{
			"cert_file":      filepath.Join(fixture.TLSDir, "es-server-cert.pem"),
			"key_file":       filepath.Join(fixture.TLSDir, "es-server-key.pem"),
			"client_ca_file": filepath.Join(fixture.TLSDir, "server-client-ca.pem"),
		},
		"dependencies": map[string]any{
			"artifact_registry": map[string]any{
				"client_cert_file": filepath.Join(fixture.TLSDir, "artifact-registry-client-cert.pem"),
				"client_key_file":  filepath.Join(fixture.TLSDir, "artifact-registry-client-key.pem"),
				"root_ca_file":     filepath.Join(fixture.TLSDir, "artifact-registry-root-ca.pem"),
			},
			"execution_governance": map[string]any{
				"client_cert_file": filepath.Join(fixture.TLSDir, "execution-governance-client-cert.pem"),
				"client_key_file":  filepath.Join(fixture.TLSDir, "execution-governance-client-key.pem"),
				"root_ca_file":     filepath.Join(fixture.TLSDir, "execution-governance-root-ca.pem"),
			},
		},
		"execution": map[string]any{
			"staging_root_dir":               fixture.StagingRoot,
			"results_root_dir":               fixture.ResultsRoot,
			"runtime_support_binary":         fixture.RuntimeSupportBinaryPath,
			"spire_workload_api_socket_path": fixture.SPIRESocketPath,
		},
	}
	data, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		t.Fatalf("marshal config: %v", err)
	}
	if err := os.WriteFile(fixture.ConfigPath, append(data, '\n'), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	healthEnv := fmt.Sprintf("CA_CERT=%s\nOPERATOR_CERT=%s\nOPERATOR_KEY=%s\n",
		filepath.Join(fixture.TLSDir, "server-client-ca.pem"),
		filepath.Join(fixture.TLSDir, "operator-client-cert.pem"),
		filepath.Join(fixture.TLSDir, "operator-client-key.pem"),
	)
	if err := os.WriteFile(fixture.HealthEnvPath, []byte(healthEnv), 0o600); err != nil {
		t.Fatalf("write healthcheck env: %v", err)
	}

	return fixture
}

func updateESServiceUserFixtureNomadConfig(t *testing.T, fixture esServiceUserMigrationFixture, baseURL, datacenter string, timeoutSeconds int) {
	t.Helper()

	payload := readJSONFile(t, fixture.ConfigPath)
	payload["nomad"] = map[string]any{
		"base_url":        baseURL,
		"datacenter":      datacenter,
		"timeout_seconds": timeoutSeconds,
	}
	writeJSONFile(t, fixture.ConfigPath, payload)
}

func writeNormalizedESServiceUserRun(t *testing.T, fixture esServiceUserMigrationFixture, uid, gid int) {
	t.Helper()

	runID := "run-0001"
	runRoot := filepath.Join(fixture.StagingRoot, runID)
	platformDir := filepath.Join(runRoot, "run", "platform")
	workDir := filepath.Join(runRoot, "run", "work")
	resultDir := filepath.Join(runRoot, "run", "result")
	resultsRunDir := filepath.Join(fixture.ResultsRoot, runID)
	for _, dir := range []string{platformDir, workDir, resultDir, resultsRunDir} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatalf("mkdir %s: %v", dir, err)
		}
	}

	marker := map[string]any{
		"schema_version":   "execution-substrate.es.runtime-ownership-normalization.v1",
		"status":           "normalized",
		"run_id":           runID,
		"target_uid":       uid,
		"target_gid":       gid,
		"paths_normalized": []string{"run/platform", "run/work", "run/result"},
		"completed_at":     "2026-04-26T12:00:00Z",
	}
	data, err := json.MarshalIndent(marker, "", "  ")
	if err != nil {
		t.Fatalf("marshal marker: %v", err)
	}
	if err := os.WriteFile(filepath.Join(platformDir, "ownership-normalization.json"), append(data, '\n'), 0o600); err != nil {
		t.Fatalf("write marker: %v", err)
	}
	if err := os.WriteFile(filepath.Join(resultsRunDir, "result.tar.gz"), []byte("result\n"), 0o600); err != nil {
		t.Fatalf("write retained result: %v", err)
	}
}

func setupRetainedResultWithoutMarker(t *testing.T, fixture esServiceUserMigrationFixture) {
	t.Helper()

	runID := "run-0001"
	runRoot := filepath.Join(fixture.StagingRoot, runID)
	for _, dir := range []string{
		filepath.Join(runRoot, "run", "platform"),
		filepath.Join(runRoot, "run", "work"),
		filepath.Join(runRoot, "run", "result"),
		filepath.Join(fixture.ResultsRoot, runID),
	} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatalf("mkdir %s: %v", dir, err)
		}
	}
	if err := os.WriteFile(filepath.Join(fixture.ResultsRoot, runID, "result.tar.gz"), []byte("result\n"), 0o600); err != nil {
		t.Fatalf("write retained result: %v", err)
	}
}

func parseMigrationCheckOnlyOutput(t *testing.T, output []byte) map[string]any {
	t.Helper()
	var payload map[string]any
	if err := json.Unmarshal(output, &payload); err != nil {
		t.Fatalf("decode migration helper output: %v\noutput=%s", err, string(output))
	}
	return payload
}

func sha256Path(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func setupFakeESServiceUserMigrationCommands(
	t *testing.T,
	dir string,
	account fakeESServiceUserAccount,
	fixture esServiceUserMigrationFixture,
	mutationLogPath string,
) {
	t.Helper()

	groupName := account.GroupName
	if groupName == "" {
		groupName = "es"
	}
	allGroups := append([]string{groupName}, account.SupplementaryGroups...)
	groupMembers := account.GroupEntryMembers
	groupMembersCSV := strings.Join(groupMembers, ",")

	writeExecutable(t, dir, "id", fmt.Sprintf(`#!/bin/sh
if [ "$1" = "-u" ] && [ $# -eq 1 ]; then
  echo 0
  exit 0
fi
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
if [ "$1" = "-nG" ] && [ "$2" = "es" ]; then
  if [ %q != "true" ]; then
    exit 1
  fi
  echo %q
  exit 0
fi
exec /usr/bin/id "$@"
`, fmt.Sprintf("%t", account.Present), account.UID, fmt.Sprintf("%t", account.Present), account.GID, fmt.Sprintf("%t", account.Present), groupName, fmt.Sprintf("%t", account.Present), strings.Join(allGroups, " ")))

	writeExecutable(t, dir, "getent", fmt.Sprintf(`#!/bin/sh
if [ "$1" = "group" ] && [ "$2" = "es" ]; then
  if [ %q != "true" ]; then
    exit 2
  fi
  echo "%s:x:%d:%s"
  exit 0
fi
if [ "$1" = "passwd" ] && [ $# -eq 2 ] && [ "$2" = "es" ]; then
  if [ %q != "true" ]; then
    exit 2
  fi
  echo "es:x:%d:%d::/nonexistent:/usr/sbin/nologin"
  exit 0
fi
if [ "$1" = "passwd" ] && [ $# -eq 1 ]; then
  cat <<'EOF'
root:x:0:0:root:/root:/bin/bash
EOF
  if [ %q = "true" ]; then
    echo "es:x:%d:%d::/nonexistent:/usr/sbin/nologin"
  fi
  exit 0
fi
exit 2
`, fmt.Sprintf("%t", account.Present), groupName, account.GID, groupMembersCSV, fmt.Sprintf("%t", account.Present), account.UID, account.GID, fmt.Sprintf("%t", account.Present), account.UID, account.GID))

	writeExecutable(t, dir, "systemctl", fmt.Sprintf(`#!/bin/sh
require_mutation_ok() {
  if [ -n "${REMOTE_ALPHA_TEST_BACKUP_SENTINEL_PATH:-}" ] && [ ! -f "${REMOTE_ALPHA_TEST_BACKUP_SENTINEL_PATH}" ]; then
    echo "mutation command ran before backup sentinel ${REMOTE_ALPHA_TEST_BACKUP_SENTINEL_PATH}" >&2
    exit 98
  fi
}

case "$1" in
  daemon-reload)
    require_mutation_ok
    if [ -n "${REMOTE_ALPHA_TEST_MUTATION_LOG_PATH:-}" ]; then
      printf '%%s\n' "systemctl daemon-reload" >> "${REMOTE_ALPHA_TEST_MUTATION_LOG_PATH}"
    fi
    exit 0
    ;;
  restart)
    require_mutation_ok
    if [ -n "${REMOTE_ALPHA_TEST_MUTATION_LOG_PATH:-}" ]; then
      printf '%%s\n' "systemctl restart" >> "${REMOTE_ALPHA_TEST_MUTATION_LOG_PATH}"
    fi
    exit 0
    ;;
  stop)
    require_mutation_ok
    if [ -n "${REMOTE_ALPHA_TEST_MUTATION_LOG_PATH:-}" ]; then
      printf '%%s\n' "systemctl stop" >> "${REMOTE_ALPHA_TEST_MUTATION_LOG_PATH}"
    fi
    exit 0
    ;;
  start)
    require_mutation_ok
    if [ -n "${REMOTE_ALPHA_TEST_MUTATION_LOG_PATH:-}" ]; then
      printf '%%s\n' "systemctl start" >> "${REMOTE_ALPHA_TEST_MUTATION_LOG_PATH}"
    fi
    exit 0
    ;;
  is-enabled)
    exit 0
    ;;
  show)
    user=""
    group=""
    if [ "${REMOTE_ALPHA_TEST_SYSTEMCTL_IGNORE_DROPIN:-false}" != "true" ] && [ -f %q ]; then
      if grep -q '^User=es$' %q; then
        user="es"
      fi
      if grep -q '^Group=es$' %q; then
        group="es"
      fi
    fi
    cat <<EOF
User=%s
Group=%s
ExecStart={ path=%s ; argv[]=%s -config %s ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }
FragmentPath=%s
ActiveState=%s
SubState=%s
EOF
    exit 0
    ;;
esac
exit 1
`, fixture.ServiceDropInPath, fixture.ServiceDropInPath, fixture.ServiceDropInPath, "${user}", "${group}", fixture.ESBinaryPath, fixture.ESBinaryPath, fixture.ConfigPath, fixture.ServiceUnitPath, "${REMOTE_ALPHA_TEST_SYSTEMCTL_ACTIVE_STATE:-active}", "${REMOTE_ALPHA_TEST_SYSTEMCTL_SUB_STATE:-running}"))

	writeExecutable(t, dir, "curl", `#!/bin/sh
url=""
for arg in "$@"; do
  case "$arg" in
    http://*|https://*)
      url="$arg"
      ;;
  esac
done
case "$url" in
  https://127.0.0.1:8445/health)
    if [ "${REMOTE_ALPHA_TEST_CURL_FAIL_HEALTH:-false}" = "true" ]; then
      echo "simulated health failure" >&2
      exit 1
    fi
    if [ "${REMOTE_ALPHA_TEST_CURL_INVALID_HEALTH_JSON:-false}" = "true" ]; then
      echo "not-json"
      exit 0
    fi
    cat <<'EOF'
{"status":"healthy","ready":true,"service":"execution","additional_properties":{"dependencies":{"artifact_registry":"healthy"}}}
EOF
    ;;
  https://127.0.0.1:8445/v1/executions:contract)
    if [ "${REMOTE_ALPHA_TEST_CURL_FAIL_CONTRACT:-false}" = "true" ]; then
      echo "simulated contract failure" >&2
      exit 1
    fi
    if [ "${REMOTE_ALPHA_TEST_CURL_INVALID_CONTRACT_JSON:-false}" = "true" ]; then
      echo "not-json"
      exit 0
    fi
    cat <<'EOF'
{"schema_version":"execution-substrate.producer-contract/v1","service":"execution","governed_execution":{"contract":"governed-execution-producer/v1","enabled":true}}
EOF
    ;;
  *)
    echo "unexpected curl url: $url" >&2
    exit 1
    ;;
esac
`)

	writeExecutable(t, dir, "install", `#!/usr/bin/env bash
set -euo pipefail
if [[ -n "${REMOTE_ALPHA_TEST_BACKUP_SENTINEL_PATH:-}" && ! -f "${REMOTE_ALPHA_TEST_BACKUP_SENTINEL_PATH}" ]]; then
  echo "install ran before backup sentinel ${REMOTE_ALPHA_TEST_BACKUP_SENTINEL_PATH}" >&2
  exit 98
fi
directory=false
mode="0755"
args=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    -d)
      directory=true
      shift
      ;;
    -m)
      mode="$2"
      shift 2
      ;;
    -o|-g)
      shift 2
      ;;
    *)
      args+=("$1")
      shift
      ;;
  esac
done
if [[ "$directory" == "true" ]]; then
  for dest in "${args[@]}"; do
    mkdir -p "$dest"
    /bin/chmod "$mode" "$dest"
    if [[ -n "${REMOTE_ALPHA_TEST_MUTATION_LOG_PATH:-}" ]]; then
      printf '%%s\n' "install -d $dest" >> "${REMOTE_ALPHA_TEST_MUTATION_LOG_PATH}"
    fi
  done
  exit 0
fi
if [[ "${#args[@]}" -ne 2 ]]; then
  echo "unexpected install args: ${args[*]}" >&2
  exit 64
fi
src="${args[0]}"
dest="${args[1]}"
mkdir -p "$(dirname "$dest")"
cp "$src" "$dest"
/bin/chmod "$mode" "$dest"
if [[ -n "${REMOTE_ALPHA_TEST_MUTATION_LOG_PATH:-}" ]]; then
  printf '%%s\n' "install $src $dest" >> "${REMOTE_ALPHA_TEST_MUTATION_LOG_PATH}"
fi
`)

	for _, name := range []string{"chown", "chmod", "useradd", "groupadd", "sudo", "rm"} {
		writeExecutable(t, dir, name, fmt.Sprintf(`#!/bin/sh
if [ -n "${REMOTE_ALPHA_TEST_MUTATION_LOG_PATH:-}" ]; then
  printf '%%s\n' %q >> "${REMOTE_ALPHA_TEST_MUTATION_LOG_PATH}"
fi
exit 97
`, name))
	}
}

func TestRemoteAlphaESServiceUserMigrationCheckOnlyIsDefaultAndNonMutating(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	fakeBin := filepath.Join(tmpDir, "bin")
	if err := os.MkdirAll(fakeBin, 0o755); err != nil {
		t.Fatalf("mkdir fake bin: %v", err)
	}
	fixture := setupESServiceUserMigrationFixture(t, tmpDir)
	writeNormalizedESServiceUserRun(t, fixture, os.Getuid(), os.Getgid())

	mutationLogPath := filepath.Join(tmpDir, "mutations.log")
	setupFakeESServiceUserMigrationCommands(t, fakeBin, fakeESServiceUserAccount{
		Present:   true,
		UID:       os.Getuid(),
		GID:       os.Getgid(),
		GroupName: "es",
	}, fixture, mutationLogPath)

	shellBody := esServiceUserMigrationExpectedSliceShell(fixture) + `
remote_alpha_migrate_es_service_user_main
`
	output, err := runSourcedESServiceUserMigrationHelper(t, fixture.BackupRoot, 0, envWithPath(fakeBin, "REMOTE_ALPHA_TEST_MUTATION_LOG_PATH="+mutationLogPath), shellBody)
	if err != nil {
		t.Fatalf("helper failed: %v\noutput=%s", err, string(output))
	}

	payload := parseMigrationCheckOnlyOutput(t, output)
	mode := nestedMap(t, payload, "mode")
	proof := nestedMap(t, payload, "proof")
	plan := nestedMap(t, payload, "plan")
	if mode["name"] != "check_only" || mode["non_mutating"] != true {
		t.Fatalf("unexpected mode payload: %+v", mode)
	}
	if proof["check_only_is_not_proof"] != true || proof["host_mutation_performed"] != false {
		t.Fatalf("unexpected proof payload: %+v", proof)
	}
	if plan["apply_ready"] != true {
		t.Fatalf("expected apply_ready=true, got %v", plan["apply_ready"])
	}
	if payload["overall_classification"] != "pass" {
		t.Fatalf("expected overall pass, got %v", payload["overall_classification"])
	}
	if _, err := os.Stat(mutationLogPath); !os.IsNotExist(err) {
		t.Fatalf("mutation log should not exist, got %q", mutationLogPath)
	}
	if _, err := os.Stat(fixture.ServiceDropInPath); !os.IsNotExist(err) {
		t.Fatalf("drop-in should not be written in default check-only mode")
	}
}

func TestRemoteAlphaESServiceUserMigrationMissingAccountBlocksApplyReadiness(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	fakeBin := filepath.Join(tmpDir, "bin")
	if err := os.MkdirAll(fakeBin, 0o755); err != nil {
		t.Fatalf("mkdir fake bin: %v", err)
	}
	fixture := setupESServiceUserMigrationFixture(t, tmpDir)
	writeNormalizedESServiceUserRun(t, fixture, os.Getuid(), os.Getgid())
	setupFakeESServiceUserMigrationCommands(t, fakeBin, fakeESServiceUserAccount{
		Present: false,
	}, fixture, filepath.Join(tmpDir, "mutations.log"))

	shellBody := esServiceUserMigrationExpectedSliceShell(fixture) + `
remote_alpha_migrate_es_service_user_main --check-only
`
	output, err := runSourcedESServiceUserMigrationHelper(t, fixture.BackupRoot, 0, envWithPath(fakeBin), shellBody)
	if err == nil {
		t.Fatalf("expected blocker exit for missing es account, got success\noutput=%s", output)
	}

	payload := parseMigrationCheckOnlyOutput(t, output)
	if nestedClassification(t, payload, "service_account_status") != "blocker" {
		t.Fatalf("expected service_account_status blocker, got %v", nestedMap(t, payload, "service_account_status"))
	}
	if nestedMap(t, payload, "plan")["apply_ready"] != false {
		t.Fatalf("expected apply_ready=false, got %v", nestedMap(t, payload, "plan")["apply_ready"])
	}
}

func TestRemoteAlphaESServiceUserMigrationBroadAccountBlocksApplyReadiness(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	fakeBin := filepath.Join(tmpDir, "bin")
	if err := os.MkdirAll(fakeBin, 0o755); err != nil {
		t.Fatalf("mkdir fake bin: %v", err)
	}
	fixture := setupESServiceUserMigrationFixture(t, tmpDir)
	writeNormalizedESServiceUserRun(t, fixture, os.Getuid(), os.Getgid())
	setupFakeESServiceUserMigrationCommands(t, fakeBin, fakeESServiceUserAccount{
		Present:             true,
		UID:                 os.Getuid(),
		GID:                 os.Getgid(),
		GroupName:           "es",
		SupplementaryGroups: []string{"docker"},
	}, fixture, filepath.Join(tmpDir, "mutations.log"))

	shellBody := esServiceUserMigrationExpectedSliceShell(fixture) + `
remote_alpha_migrate_es_service_user_main --check-only
`
	output, err := runSourcedESServiceUserMigrationHelper(t, fixture.BackupRoot, 0, envWithPath(fakeBin), shellBody)
	if err == nil {
		t.Fatalf("expected blocker exit for broad es account, got success\noutput=%s", output)
	}

	payload := parseMigrationCheckOnlyOutput(t, output)
	status := nestedMap(t, payload, "service_account_status")
	if status["classification"] != "blocker" {
		t.Fatalf("expected service_account_status blocker, got %+v", status)
	}
	if !strings.Contains(fmt.Sprint(status["summary"]), "supplementary groups") {
		t.Fatalf("expected supplementary groups blocker, got %+v", status)
	}
}

func TestRemoteAlphaESServiceUserMigrationConfigTLSUnreadableBlocks(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	fakeBin := filepath.Join(tmpDir, "bin")
	if err := os.MkdirAll(fakeBin, 0o755); err != nil {
		t.Fatalf("mkdir fake bin: %v", err)
	}
	fixture := setupESServiceUserMigrationFixture(t, tmpDir)
	writeNormalizedESServiceUserRun(t, fixture, os.Getuid(), os.Getgid())
	if err := os.Chmod(filepath.Join(fixture.TLSDir, "es-server-key.pem"), 0o000); err != nil {
		t.Fatalf("chmod unreadable tls key: %v", err)
	}
	setupFakeESServiceUserMigrationCommands(t, fakeBin, fakeESServiceUserAccount{
		Present:   true,
		UID:       os.Getuid(),
		GID:       os.Getgid(),
		GroupName: "es",
	}, fixture, filepath.Join(tmpDir, "mutations.log"))

	shellBody := esServiceUserMigrationExpectedSliceShell(fixture) + `
remote_alpha_migrate_es_service_user_main --check-only
`
	output, err := runSourcedESServiceUserMigrationHelper(t, fixture.BackupRoot, 0, envWithPath(fakeBin), shellBody)
	if err == nil {
		t.Fatalf("expected blocker exit for unreadable TLS path, got success\noutput=%s", output)
	}

	payload := parseMigrationCheckOnlyOutput(t, output)
	if nestedClassification(t, payload, "config_tls_readability_status") != "blocker" {
		t.Fatalf("expected config_tls_readability_status blocker, got %v", nestedMap(t, payload, "config_tls_readability_status"))
	}
}

func TestRemoteAlphaESServiceUserMigrationTargetStartupValidationBlocksOnUnreadableRuntimeSupportBinary(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	fakeBin := filepath.Join(tmpDir, "bin")
	if err := os.MkdirAll(fakeBin, 0o755); err != nil {
		t.Fatalf("mkdir fake bin: %v", err)
	}
	fixture := setupESServiceUserMigrationFixture(t, tmpDir)
	writeNormalizedESServiceUserRun(t, fixture, os.Getuid(), os.Getgid())

	blockedRuntimeSupportDir := filepath.Join(tmpDir, "blocked-runtime-support")
	blockedRuntimeSupportPath := filepath.Join(blockedRuntimeSupportDir, "es-runtime-support")
	if err := os.MkdirAll(blockedRuntimeSupportDir, 0o700); err != nil {
		t.Fatalf("mkdir blocked runtime support dir: %v", err)
	}
	if err := os.WriteFile(blockedRuntimeSupportPath, []byte("runtime-support\n"), 0o600); err != nil {
		t.Fatalf("write blocked runtime support binary: %v", err)
	}

	payload := readJSONFile(t, fixture.ConfigPath)
	execution := nestedMap(t, payload, "execution")
	execution["runtime_support_binary"] = blockedRuntimeSupportPath
	writeJSONFile(t, fixture.ConfigPath, payload)

	setupFakeESServiceUserMigrationCommands(t, fakeBin, fakeESServiceUserAccount{
		Present:   true,
		UID:       12345,
		GID:       12345,
		GroupName: "es",
	}, fixture, filepath.Join(tmpDir, "mutations.log"))

	shellBody := esServiceUserMigrationExpectedSliceShell(fixture) + `
remote_alpha_migrate_es_service_user_main --check-only
`
	output, err := runSourcedESServiceUserMigrationHelper(t, fixture.BackupRoot, 0, envWithPath(fakeBin), shellBody)
	if err == nil {
		t.Fatalf("expected blocker exit for target startup validation, got success\noutput=%s", output)
	}

	payloadOut := parseMigrationCheckOnlyOutput(t, output)
	if nestedClassification(t, payloadOut, "target_service_user_startup_validation_status") != "blocker" {
		t.Fatalf("expected target_service_user_startup_validation_status blocker, got %v", nestedMap(t, payloadOut, "target_service_user_startup_validation_status"))
	}
	if nestedMap(t, payloadOut, "plan")["apply_ready"] != false {
		t.Fatalf("expected apply_ready=false, got %v", nestedMap(t, payloadOut, "plan")["apply_ready"])
	}
}

func TestRemoteAlphaESServiceUserMigrationHelperPrivateSPIRERuntimeInputBlocksWhenMissing(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	fakeBin := filepath.Join(tmpDir, "bin")
	if err := os.MkdirAll(fakeBin, 0o755); err != nil {
		t.Fatalf("mkdir fake bin: %v", err)
	}
	fixture := setupESServiceUserMigrationFixture(t, tmpDir)
	writeNormalizedESServiceUserRun(t, fixture, os.Getuid(), os.Getgid())

	payload := readJSONFile(t, fixture.ConfigPath)
	execution := nestedMap(t, payload, "execution")
	execution["spire_workload_api_socket_path"] = filepath.Join(tmpDir, "missing-spire.sock")
	writeJSONFile(t, fixture.ConfigPath, payload)

	setupFakeESServiceUserMigrationCommands(t, fakeBin, fakeESServiceUserAccount{
		Present:   true,
		UID:       os.Getuid(),
		GID:       os.Getgid(),
		GroupName: "es",
	}, fixture, filepath.Join(tmpDir, "mutations.log"))

	shellBody := esServiceUserMigrationExpectedSliceShell(fixture) + `
remote_alpha_migrate_es_service_user_main --check-only
`
	output, err := runSourcedESServiceUserMigrationHelper(t, fixture.BackupRoot, 0, envWithPath(fakeBin), shellBody)
	if err == nil {
		t.Fatalf("expected blocker exit for missing helper-private SPIRE runtime input, got success\noutput=%s", output)
	}

	payloadOut := parseMigrationCheckOnlyOutput(t, output)
	status := nestedMap(t, payloadOut, "helper_private_spire_runtime_input_status")
	if status["classification"] != "blocker" {
		t.Fatalf("expected helper_private_spire_runtime_input_status blocker, got %+v", status)
	}
	if status["reason"] == "" {
		t.Fatalf("expected helper_private_spire_runtime_input_status reason, got %+v", status)
	}
}

func TestRemoteAlphaESServiceUserMigrationWritableStateNotManageableBlocks(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	fakeBin := filepath.Join(tmpDir, "bin")
	if err := os.MkdirAll(fakeBin, 0o755); err != nil {
		t.Fatalf("mkdir fake bin: %v", err)
	}
	fixture := setupESServiceUserMigrationFixture(t, tmpDir)
	writeNormalizedESServiceUserRun(t, fixture, os.Getuid(), os.Getgid())
	if err := os.Chmod(fixture.StagingRoot, 0o500); err != nil {
		t.Fatalf("chmod staging root: %v", err)
	}
	if err := os.Chmod(fixture.ResultsRoot, 0o500); err != nil {
		t.Fatalf("chmod results root: %v", err)
	}
	t.Cleanup(func() {
		_ = os.Chmod(fixture.StagingRoot, 0o700)
		_ = os.Chmod(fixture.ResultsRoot, 0o700)
	})
	setupFakeESServiceUserMigrationCommands(t, fakeBin, fakeESServiceUserAccount{
		Present:   true,
		UID:       os.Getuid(),
		GID:       os.Getgid(),
		GroupName: "es",
	}, fixture, filepath.Join(tmpDir, "mutations.log"))

	shellBody := esServiceUserMigrationExpectedSliceShell(fixture) + `
remote_alpha_migrate_es_service_user_main --check-only
`
	output, err := runSourcedESServiceUserMigrationHelper(t, fixture.BackupRoot, 0, envWithPath(fakeBin), shellBody)
	if err == nil {
		t.Fatalf("expected blocker exit for unmanageable writable-state roots, got success\noutput=%s", output)
	}

	payload := parseMigrationCheckOnlyOutput(t, output)
	if nestedClassification(t, payload, "writable_state_manageability_status") != "blocker" {
		t.Fatalf("expected writable_state_manageability_status blocker, got %v", nestedMap(t, payload, "writable_state_manageability_status"))
	}
}

func TestRemoteAlphaESServiceUserMigrationActiveRunsPresentBlocks(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	fakeBin := filepath.Join(tmpDir, "bin")
	if err := os.MkdirAll(fakeBin, 0o755); err != nil {
		t.Fatalf("mkdir fake bin: %v", err)
	}
	fixture := setupESServiceUserMigrationFixture(t, tmpDir)
	if err := os.MkdirAll(filepath.Join(fixture.StagingRoot, "run-live", "run"), 0o700); err != nil {
		t.Fatalf("mkdir active run: %v", err)
	}
	setupFakeESServiceUserMigrationCommands(t, fakeBin, fakeESServiceUserAccount{
		Present:   true,
		UID:       os.Getuid(),
		GID:       os.Getgid(),
		GroupName: "es",
	}, fixture, filepath.Join(tmpDir, "mutations.log"))

	shellBody := esServiceUserMigrationExpectedSliceShell(fixture) + `
remote_alpha_migrate_es_service_user_main --check-only
`
	output, err := runSourcedESServiceUserMigrationHelper(t, fixture.BackupRoot, 0, envWithPath(fakeBin), shellBody)
	if err == nil {
		t.Fatalf("expected blocker exit for active-or-unknown runs, got success\noutput=%s", output)
	}

	payload := parseMigrationCheckOnlyOutput(t, output)
	if nestedClassification(t, payload, "active_run_status") != "blocker" {
		t.Fatalf("expected active_run_status blocker, got %v", nestedMap(t, payload, "active_run_status"))
	}
}

func TestRemoteAlphaESServiceUserMigrationFutureCheckerBlockersBlock(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	fakeBin := filepath.Join(tmpDir, "bin")
	if err := os.MkdirAll(fakeBin, 0o755); err != nil {
		t.Fatalf("mkdir fake bin: %v", err)
	}
	fixture := setupESServiceUserMigrationFixture(t, tmpDir)
	setupRetainedResultWithoutMarker(t, fixture)
	setupFakeESServiceUserMigrationCommands(t, fakeBin, fakeESServiceUserAccount{
		Present:   true,
		UID:       os.Getuid(),
		GID:       os.Getgid(),
		GroupName: "es",
	}, fixture, filepath.Join(tmpDir, "mutations.log"))

	shellBody := esServiceUserMigrationExpectedSliceShell(fixture) + `
remote_alpha_migrate_es_service_user_main --check-only
`
	output, err := runSourcedESServiceUserMigrationHelper(t, fixture.BackupRoot, 0, envWithPath(fakeBin), shellBody)
	if err == nil {
		t.Fatalf("expected blocker exit for future checker blockers, got success\noutput=%s", output)
	}

	payload := parseMigrationCheckOnlyOutput(t, output)
	if nestedClassification(t, payload, "future_non_root_required_readiness_status") != "blocker" {
		t.Fatalf("expected future checker blocker, got %v", nestedMap(t, payload, "future_non_root_required_readiness_status"))
	}
	if nestedClassification(t, payload, "active_run_status") != "pass" {
		t.Fatalf("expected active_run_status pass so the future-checker blocker is isolated, got %v", nestedMap(t, payload, "active_run_status"))
	}
}

func TestRemoteAlphaESServiceUserMigrationCheckOnlyBlocksOnWritableStateOwnerModelMismatch(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	fakeBin := filepath.Join(tmpDir, "bin")
	if err := os.MkdirAll(fakeBin, 0o755); err != nil {
		t.Fatalf("mkdir fake bin: %v", err)
	}
	fixture := setupESServiceUserMigrationFixture(t, tmpDir)
	writeNormalizedESServiceUserRun(t, fixture, os.Getuid(), os.Getgid())
	setupFakeESServiceUserMigrationCommands(t, fakeBin, fakeESServiceUserAccount{
		Present:   true,
		UID:       os.Getuid(),
		GID:       os.Getgid(),
		GroupName: "es",
	}, fixture, filepath.Join(tmpDir, "mutations.log"))
	writeExecutable(t, fakeBin, "stat", fmt.Sprintf(`#!/bin/sh
if [ "$1" != "-c" ] || [ "$#" -ne 3 ]; then
  exit 1
fi
if [ "$3" = %q ]; then
  printf '%%s\t%%s\t%%s\t%%s\n' %q %q %q %q
  exit 0
fi
if [ "$3" = %q ]; then
  printf '%%s\t%%s\t%%s\t%%s\n' %q %q %q %q
  exit 0
fi
exit 1
`, fixture.StagingRoot, fmt.Sprintf("%d", os.Getuid()), fmt.Sprintf("%d", os.Getgid()), "0750", "directory", fixture.ResultsRoot, fmt.Sprintf("%d", os.Getuid()), fmt.Sprintf("%d", os.Getgid()+1), "0750", "directory"))

	shellBody := esServiceUserMigrationExpectedSliceShell(fixture) + `
remote_alpha_migrate_es_service_user_main --check-only
`
	output, err := runSourcedESServiceUserMigrationHelper(t, fixture.BackupRoot, 0, envWithPath(fakeBin), shellBody)
	if err == nil {
		t.Fatalf("expected blocker exit for staging/results owner-model mismatch, got success\noutput=%s", output)
	}

	payload := parseMigrationCheckOnlyOutput(t, output)
	if nestedClassification(t, payload, "future_non_root_required_readiness_status") != "blocker" {
		t.Fatalf("expected future checker blocker, got %v", nestedMap(t, payload, "future_non_root_required_readiness_status"))
	}
	report := nestedMap(t, nestedMap(t, payload, "future_non_root_required_readiness_status"), "report")
	if nestedClassification(t, report, "target_owner_consistency_status") != "blocker" {
		t.Fatalf("expected nested target_owner_consistency_status blocker, got %v", nestedMap(t, report, "target_owner_consistency_status"))
	}
}

func TestRemoteAlphaESServiceUserMigrationPlanKeepsCompatibilityEdges(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	fakeBin := filepath.Join(tmpDir, "bin")
	if err := os.MkdirAll(fakeBin, 0o755); err != nil {
		t.Fatalf("mkdir fake bin: %v", err)
	}
	fixture := setupESServiceUserMigrationFixture(t, tmpDir)
	writeNormalizedESServiceUserRun(t, fixture, os.Getuid(), os.Getgid())
	setupFakeESServiceUserMigrationCommands(t, fakeBin, fakeESServiceUserAccount{
		Present:   true,
		UID:       os.Getuid(),
		GID:       os.Getgid(),
		GroupName: "es",
	}, fixture, filepath.Join(tmpDir, "mutations.log"))

	shellBody := esServiceUserMigrationExpectedSliceShell(fixture) + `
remote_alpha_migrate_es_service_user_main --check-only
`
	output, err := runSourcedESServiceUserMigrationHelper(t, fixture.BackupRoot, 0, envWithPath(fakeBin), shellBody)
	if err != nil {
		t.Fatalf("helper failed: %v\noutput=%s", err, string(output))
	}

	payload := parseMigrationCheckOnlyOutput(t, output)
	edges, ok := payload["bounded_compatibility_edges"].([]any)
	if !ok {
		t.Fatalf("expected bounded_compatibility_edges array, got %T", payload["bounded_compatibility_edges"])
	}
	seen := map[string]bool{}
	for _, item := range edges {
		entry := jsonMap(t, item)
		name, _ := entry["name"].(string)
		seen[name] = entry["planned_unchanged"] == true
	}
	for _, required := range []string{
		"root_start_runtime_helper",
		"nomad_task_user_0_0",
		"helper_private_spire_traversal",
		"broad_root_selector_scope",
		"vault_workload_zone_handoff",
	} {
		if !seen[required] {
			t.Fatalf("expected bounded compatibility edge %q to be present and planned unchanged; got %+v", required, seen)
		}
	}
	plan := nestedMap(t, payload, "plan")
	if got := jsonStringSlice(t, plan["mutation_scope"]); len(got) != 1 || got[0] != "systemd_dropin_only" {
		t.Fatalf("unexpected mutation scope %v", got)
	}
}

func TestRemoteAlphaESServiceUserMigrationApplyCreatesBackupAndOnlyWritesDropIn(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	fakeBin := filepath.Join(tmpDir, "bin")
	if err := os.MkdirAll(fakeBin, 0o755); err != nil {
		t.Fatalf("mkdir fake bin: %v", err)
	}
	fixture := setupESServiceUserMigrationFixture(t, tmpDir)
	writeNormalizedESServiceUserRun(t, fixture, os.Getuid(), os.Getgid())

	summaryPath := filepath.Join(tmpDir, "apply-summary.json")
	mutationLogPath := filepath.Join(tmpDir, "mutations.log")
	backupSentinelPath := filepath.Join(tmpDir, "backup.sentinel")
	backupPathFile := filepath.Join(tmpDir, "backup-path.txt")
	setupFakeESServiceUserMigrationCommands(t, fakeBin, fakeESServiceUserAccount{
		Present:   true,
		UID:       os.Getuid(),
		GID:       os.Getgid(),
		GroupName: "es",
	}, fixture, mutationLogPath)

	configBefore := sha256Path(t, fixture.ConfigPath)
	shellBody := esServiceUserMigrationExpectedSliceShell(fixture) + fmt.Sprintf(`
remote_alpha_migrate_es_service_user_main --apply --summary-path %q
`, summaryPath)
	output, err := runSourcedESServiceUserMigrationHelper(t, fixture.BackupRoot, 1, envWithPath(fakeBin,
		"REMOTE_ALPHA_TEST_MUTATION_LOG_PATH="+mutationLogPath,
		"REMOTE_ALPHA_TEST_BACKUP_SENTINEL_PATH="+backupSentinelPath,
		"REMOTE_ALPHA_TEST_BACKUP_PATH_FILE="+backupPathFile,
	), shellBody)
	if err != nil {
		t.Fatalf("apply helper failed: %v\noutput=%s\nsummary=%s", err, string(output), mustRead(t, summaryPath))
	}
	if strings.TrimSpace(string(output)) != summaryPath {
		t.Fatalf("unexpected helper output %q", strings.TrimSpace(string(output)))
	}

	if got := mustRead(t, fixture.ServiceDropInPath); got != "[Service]\nUser=es\nGroup=es\nUMask=0027\n" {
		t.Fatalf("unexpected drop-in contents %q", got)
	}
	if configAfter := sha256Path(t, fixture.ConfigPath); configAfter != configBefore {
		t.Fatalf("ES config changed unexpectedly: before=%s after=%s", configBefore, configAfter)
	}
	logLines := strings.Split(strings.TrimSpace(mustRead(t, mutationLogPath)), "\n")
	if strings.Count(strings.Join(logLines, "\n"), "systemctl restart") != 1 {
		t.Fatalf("expected exactly one restart, got %q", logLines)
	}
	for _, forbidden := range []string{"chown", "chmod", "useradd", "groupadd", "sudo", "rm"} {
		for _, line := range logLines {
			if line == forbidden {
				t.Fatalf("forbidden mutation command %q was invoked: %q", forbidden, logLines)
			}
		}
	}

	summary := readJSONFile(t, summaryPath)
	requireESServiceUserMigrationBackupReport(t, fixture, summary)
	if nestedMap(t, summary, "result")["ok"] != true {
		t.Fatalf("expected successful apply summary, got %+v", nestedMap(t, summary, "result"))
	}
	changes := nestedMap(t, summary, "changes")
	changedPaths := jsonStringSlice(t, changes["changed_paths"])
	if len(changedPaths) != 1 || changedPaths[0] != fixture.ServiceDropInPath {
		t.Fatalf("expected only the bounded drop-in path to be changed, got %v", changedPaths)
	}
	backup := nestedMap(t, summary, "backup")
	if backup["path"] == "" || backup["snapshot_path"] == "" {
		t.Fatalf("expected backup paths in summary, got %+v", backup)
	}
	rollbackNotes := jsonStringSlice(t, backup["rollback_notes"])
	if len(rollbackNotes) == 0 {
		t.Fatalf("expected rollback notes, got %+v", backup)
	}
	proof := nestedMap(t, summary, "proof")
	if proof["governed_proof_run"] != false {
		t.Fatalf("expected governed_proof_run=false, got %+v", proof)
	}
	postValidation := nestedMap(t, summary, "post_apply_validation")
	if postValidation["classification"] != "pass" {
		t.Fatalf("expected post-apply validation pass, got %+v", postValidation)
	}
}

func TestRemoteAlphaESServiceUserMigrationApplyRequiresPostApplyUserAndGroup(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	fakeBin := filepath.Join(tmpDir, "bin")
	if err := os.MkdirAll(fakeBin, 0o755); err != nil {
		t.Fatalf("mkdir fake bin: %v", err)
	}
	fixture := setupESServiceUserMigrationFixture(t, tmpDir)
	writeNormalizedESServiceUserRun(t, fixture, os.Getuid(), os.Getgid())

	summaryPath := filepath.Join(tmpDir, "apply-summary.json")
	mutationLogPath := filepath.Join(tmpDir, "mutations.log")
	backupSentinelPath := filepath.Join(tmpDir, "backup.sentinel")
	setupFakeESServiceUserMigrationCommands(t, fakeBin, fakeESServiceUserAccount{
		Present:   true,
		UID:       os.Getuid(),
		GID:       os.Getgid(),
		GroupName: "es",
	}, fixture, mutationLogPath)

	shellBody := esServiceUserMigrationExpectedSliceShell(fixture) + fmt.Sprintf(`
remote_alpha_migrate_es_service_user_main --apply --summary-path %q
`, summaryPath)
	output, err := runSourcedESServiceUserMigrationHelper(t, fixture.BackupRoot, 1, envWithPath(fakeBin,
		"REMOTE_ALPHA_TEST_MUTATION_LOG_PATH="+mutationLogPath,
		"REMOTE_ALPHA_TEST_BACKUP_SENTINEL_PATH="+backupSentinelPath,
		"REMOTE_ALPHA_TEST_SYSTEMCTL_IGNORE_DROPIN=true",
	), shellBody)
	if err == nil {
		t.Fatalf("expected apply failure when post-apply service identity remains root(default), got success\noutput=%s", output)
	}

	summary := readJSONFile(t, summaryPath)
	requireESServiceUserMigrationBackupReport(t, fixture, summary)
	result := nestedMap(t, summary, "result")
	if result["status"] != "post_apply_validation_failed" {
		t.Fatalf("expected post_apply_validation_failed, got %+v", result)
	}
	postValidation := nestedMap(t, summary, "post_apply_validation")
	if postValidation["classification"] != "blocker" {
		t.Fatalf("expected post-apply validation blocker, got %+v", postValidation)
	}
	if !strings.Contains(fmt.Sprint(postValidation["summary"]), "effective user") && !strings.Contains(fmt.Sprint(postValidation["summary"]), "effective group") {
		t.Fatalf("expected post-apply validation to mention user/group mismatch, got %+v", postValidation)
	}
}
