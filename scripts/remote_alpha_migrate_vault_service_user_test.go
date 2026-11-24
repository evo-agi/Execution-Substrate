package scripts_test

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

type fakeVaultServiceUserAccount struct {
	Present             bool
	UID                 int
	GID                 int
	GroupName           string
	SupplementaryGroups []string
	GroupEntryMembers   []string
}

type vaultServiceUserMigrationFixture struct {
	VaultConfigPath   string
	ServiceUnitPath   string
	ServiceDropInDir  string
	ServiceDropInPath string
	TLSDir            string
	StorageDir        string
	LogDir            string
	LogPath           string
	AuditDir          string
	AuditPath         string
	ESConfigPath      string
	HealthEnvPath     string
	BackupRootDir     string
}

func runSourcedVaultServiceUserMigrationHelper(t *testing.T, env []string, shellBody string) ([]byte, error) {
	t.Helper()
	helperPath := filepath.Join(executionSubstrateRepoRoot, "scripts", "internal", "remote_alpha_migrate_vault_service_user.sh")
	script := fmt.Sprintf("set -euo pipefail\nsource %q\n%s\n", helperPath, shellBody)
	cmd := exec.Command("/bin/bash", "-c", script)
	cmd.Dir = executionSubstrateRepoRoot
	cmd.Env = env
	return cmd.CombinedOutput()
}

func setupVaultServiceUserMigrationFixture(t *testing.T, tmpDir string) vaultServiceUserMigrationFixture {
	t.Helper()

	fixture := vaultServiceUserMigrationFixture{
		VaultConfigPath:   filepath.Join(tmpDir, "vault", "vault.json"),
		ServiceUnitPath:   filepath.Join(tmpDir, "systemd", "vault.service"),
		ServiceDropInDir:  filepath.Join(tmpDir, "systemd", "vault.service.d"),
		ServiceDropInPath: filepath.Join(tmpDir, "systemd", "vault.service.d", "10-account.conf"),
		TLSDir:            filepath.Join(tmpDir, "vault", "tls"),
		StorageDir:        filepath.Join(tmpDir, "vault", "data"),
		LogDir:            filepath.Join(tmpDir, "vault", "logs"),
		LogPath:           filepath.Join(tmpDir, "vault", "logs", "vault.log"),
		AuditDir:          filepath.Join(tmpDir, "vault", "audit"),
		AuditPath:         filepath.Join(tmpDir, "vault", "audit", "audit.log"),
		ESConfigPath:      filepath.Join(tmpDir, "es", "es.json"),
		HealthEnvPath:     filepath.Join(tmpDir, "es", "healthcheck.env"),
		BackupRootDir:     filepath.Join(tmpDir, "backups"),
	}

	for _, dir := range []string{
		filepath.Dir(fixture.VaultConfigPath),
		filepath.Dir(fixture.ServiceUnitPath),
		fixture.TLSDir,
		fixture.StorageDir,
		fixture.LogDir,
		fixture.AuditDir,
		filepath.Dir(fixture.ESConfigPath),
		fixture.BackupRootDir,
	} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", dir, err)
		}
	}

	for _, name := range []string{"vault-server-cert.pem", "vault-server-key.pem", "vault-client-ca.pem"} {
		if err := os.WriteFile(filepath.Join(fixture.TLSDir, name), []byte(name+"\n"), 0o600); err != nil {
			t.Fatalf("write tls file %s: %v", name, err)
		}
	}
	if err := os.WriteFile(fixture.LogPath, []byte("vault log\n"), 0o640); err != nil {
		t.Fatalf("write log file: %v", err)
	}
	if err := os.WriteFile(fixture.AuditPath, []byte("audit log\n"), 0o640); err != nil {
		t.Fatalf("write audit file: %v", err)
	}
	if err := os.WriteFile(fixture.ServiceUnitPath, []byte("[Service]\nExecStart=/usr/bin/vault server -config=/placeholder\n"), 0o644); err != nil {
		t.Fatalf("write service unit: %v", err)
	}

	writeJSONFile(t, fixture.VaultConfigPath, map[string]any{
		"api_addr": "https://127.0.0.1:8200",
		"storage": []map[string]any{
			{
				"type": "raft",
				"path": fixture.StorageDir,
			},
		},
		"listener": []map[string]any{
			{
				"type":               "tcp",
				"address":            "127.0.0.1:8200",
				"tls_cert_file":      filepath.Join(fixture.TLSDir, "vault-server-cert.pem"),
				"tls_key_file":       filepath.Join(fixture.TLSDir, "vault-server-key.pem"),
				"tls_client_ca_file": filepath.Join(fixture.TLSDir, "vault-client-ca.pem"),
			},
		},
		"log_file": fixture.LogPath,
		"audit": []map[string]any{
			{
				"type": "file",
				"path": fixture.AuditPath,
			},
		},
	})

	writeJSONFile(t, fixture.ESConfigPath, map[string]any{
		"http": map[string]any{
			"bind_address": "127.0.0.1",
			"port":         8445,
		},
	})

	healthEnv := fmt.Sprintf(
		"CA_CERT=%s\nOPERATOR_CERT=%s\nOPERATOR_KEY=%s\n",
		filepath.Join(fixture.TLSDir, "vault-client-ca.pem"),
		filepath.Join(fixture.TLSDir, "vault-server-cert.pem"),
		filepath.Join(fixture.TLSDir, "vault-server-key.pem"),
	)
	if err := os.WriteFile(fixture.HealthEnvPath, []byte(healthEnv), 0o600); err != nil {
		t.Fatalf("write healthcheck env: %v", err)
	}

	return fixture
}

func setupFakeVaultServiceUserMigrationCommands(
	t *testing.T,
	dir string,
	account fakeVaultServiceUserAccount,
	fixture vaultServiceUserMigrationFixture,
	mutationLogPath string,
) {
	t.Helper()

	groupName := account.GroupName
	if groupName == "" {
		groupName = "vault"
	}
	allGroups := append([]string{groupName}, account.SupplementaryGroups...)
	groupMembersCSV := strings.Join(account.GroupEntryMembers, ",")

	writeExecutable(t, dir, "id", fmt.Sprintf(`#!/bin/sh
if [ "$1" = "-u" ] && [ $# -eq 1 ]; then
  echo "${REMOTE_ALPHA_TEST_CURRENT_EUID:-0}"
  exit 0
fi
if [ "$1" = "-u" ] && [ "$2" = "vault" ]; then
  if [ %q != "true" ]; then
    exit 1
  fi
  echo %d
  exit 0
fi
if [ "$1" = "-g" ] && [ "$2" = "vault" ]; then
  if [ %q != "true" ]; then
    exit 1
  fi
  echo %d
  exit 0
fi
if [ "$1" = "-gn" ] && [ "$2" = "vault" ]; then
  if [ %q != "true" ]; then
    exit 1
  fi
  echo %q
  exit 0
fi
if [ "$1" = "-nG" ] && [ "$2" = "vault" ]; then
  if [ %q != "true" ]; then
    exit 1
  fi
  echo %q
  exit 0
fi
exec /usr/bin/id "$@"
`, fmt.Sprintf("%t", account.Present), account.UID, fmt.Sprintf("%t", account.Present), account.GID, fmt.Sprintf("%t", account.Present), groupName, fmt.Sprintf("%t", account.Present), strings.Join(allGroups, " ")))

	writeExecutable(t, dir, "getent", fmt.Sprintf(`#!/bin/sh
if [ "$1" = "group" ] && [ "$2" = "vault" ]; then
  if [ %q != "true" ]; then
    exit 2
  fi
  echo "%s:x:%d:%s"
  exit 0
fi
if [ "$1" = "passwd" ] && [ $# -eq 1 ]; then
  cat <<'EOF'
root:x:0:0:root:/root:/bin/bash
EOF
  if [ %q = "true" ]; then
    echo "vault:x:%d:%d::/nonexistent:/usr/sbin/nologin"
  fi
  exit 0
fi
exit 2
`, fmt.Sprintf("%t", account.Present), groupName, account.GID, groupMembersCSV, fmt.Sprintf("%t", account.Present), account.UID, account.GID))

	writeExecutable(t, dir, "systemctl", fmt.Sprintf(`#!/bin/sh
require_backup_ok() {
  if [ -n "${REMOTE_ALPHA_TEST_BACKUP_SENTINEL_PATH:-}" ] && [ ! -f "${REMOTE_ALPHA_TEST_BACKUP_SENTINEL_PATH}" ]; then
    echo "mutation command ran before backup sentinel ${REMOTE_ALPHA_TEST_BACKUP_SENTINEL_PATH}" >&2
    exit 98
  fi
}

case "$1" in
  daemon-reload)
    require_backup_ok
    if [ -n "${REMOTE_ALPHA_TEST_MUTATION_LOG_PATH:-}" ]; then
      printf '%%s\n' "systemctl daemon-reload" >> "${REMOTE_ALPHA_TEST_MUTATION_LOG_PATH}"
    fi
    exit 0
    ;;
  restart)
    require_backup_ok
    if [ -n "${REMOTE_ALPHA_TEST_MUTATION_LOG_PATH:-}" ]; then
      printf '%%s\n' "systemctl restart $2" >> "${REMOTE_ALPHA_TEST_MUTATION_LOG_PATH}"
    fi
    exit 0
    ;;
  is-active|is-enabled)
    exit 0
    ;;
  show)
    service_name="$2"
    if [ "$service_name" != "vault" ] && [ "$service_name" != "vault.service" ]; then
      exit 1
    fi
    user=""
    group=""
    umask=""
    if [ "${REMOTE_ALPHA_TEST_SYSTEMCTL_IGNORE_DROPIN:-false}" != "true" ] && [ -f %q ]; then
      if grep -q '^User=vault$' %q; then
        user="vault"
      fi
      if grep -q '^Group=vault$' %q; then
        group="vault"
      fi
      if grep -q '^UMask=0027$' %q; then
        umask="0027"
      fi
    fi
    cat <<EOF
User=${user}
Group=${group}
UMask=${umask}
ExecStart={ path=/usr/bin/vault ; argv[]=/usr/bin/vault server -config=%s ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }
FragmentPath=%s
ActiveState=${REMOTE_ALPHA_TEST_VAULT_ACTIVE_STATE:-active}
SubState=${REMOTE_ALPHA_TEST_VAULT_SUB_STATE:-running}
EOF
    exit 0
    ;;
esac
exit 1
`, fixture.ServiceDropInPath, fixture.ServiceDropInPath, fixture.ServiceDropInPath, fixture.ServiceDropInPath, fixture.VaultConfigPath, fixture.ServiceUnitPath))

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
  https://127.0.0.1:8200/v1/sys/health)
    if [ "${REMOTE_ALPHA_TEST_CURL_FAIL_VAULT_HEALTH:-false}" = "true" ]; then
      echo "simulated vault health failure" >&2
      exit 1
    fi
    cat <<'EOF'
{"initialized":true,"sealed":false,"standby":false}
EOF
    ;;
  https://127.0.0.1:8445/health)
    if [ "${REMOTE_ALPHA_TEST_CURL_FAIL_ES_HEALTH:-false}" = "true" ]; then
      echo "simulated es health failure" >&2
      exit 1
    fi
    cat <<'EOF'
{"status":"healthy","ready":true,"service":"execution"}
EOF
    ;;
  https://127.0.0.1:8445/v1/executions:contract)
    if [ "${REMOTE_ALPHA_TEST_CURL_FAIL_CONTRACT:-false}" = "true" ]; then
      echo "simulated contract failure" >&2
      exit 1
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
owner=""
group=""
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

	for _, name := range []string{"chown", "chmod", "groupadd", "useradd"} {
		writeExecutable(t, dir, name, fmt.Sprintf(`#!/bin/sh
if [ -n "${REMOTE_ALPHA_TEST_BACKUP_SENTINEL_PATH:-}" ] && [ ! -f "${REMOTE_ALPHA_TEST_BACKUP_SENTINEL_PATH}" ]; then
  echo "%s ran before backup sentinel ${REMOTE_ALPHA_TEST_BACKUP_SENTINEL_PATH}" >&2
  exit 98
fi
if [ -n "${REMOTE_ALPHA_TEST_MUTATION_LOG_PATH:-}" ]; then
  printf '%%s\n' %q >> "${REMOTE_ALPHA_TEST_MUTATION_LOG_PATH}"
fi
exit 0
`, name, name))
	}
}

func TestRemoteAlphaVaultServiceUserMigrationCheckOnlyIsDefaultAndNonMutating(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	fakeBin := filepath.Join(tmpDir, "bin")
	if err := os.MkdirAll(fakeBin, 0o755); err != nil {
		t.Fatalf("mkdir fake bin: %v", err)
	}
	fixture := setupVaultServiceUserMigrationFixture(t, tmpDir)
	summaryPath := filepath.Join(tmpDir, "vault-service-user-migration-check-only.json")
	mutationLogPath := filepath.Join(tmpDir, "mutations.log")
	setupFakeVaultServiceUserMigrationCommands(t, fakeBin, fakeVaultServiceUserAccount{
		Present:   true,
		UID:       os.Getuid(),
		GID:       os.Getgid(),
		GroupName: "vault",
	}, fixture, mutationLogPath)

	shellBody := fmt.Sprintf(`
remote_alpha_migrate_vault_service_user_main --summary-path %q --es-config-path %q --healthcheck-env-path %q
`, summaryPath, fixture.ESConfigPath, fixture.HealthEnvPath)
	output, err := runSourcedVaultServiceUserMigrationHelper(t, envWithPath(fakeBin, "REMOTE_ALPHA_TEST_MUTATION_LOG_PATH="+mutationLogPath), shellBody)
	if err != nil {
		t.Fatalf("helper failed: %v\noutput=%s", err, string(output))
	}
	if strings.TrimSpace(string(output)) != summaryPath {
		t.Fatalf("unexpected helper output %q", strings.TrimSpace(string(output)))
	}

	summary := readJSONFile(t, summaryPath)
	mode := nestedMap(t, summary, "mode")
	plan := nestedMap(t, summary, "plan")
	proof := nestedMap(t, summary, "proof")
	if summary["collection_status"] != "collected" {
		t.Fatalf("expected collected collection_status, got %+v", summary["collection_status"])
	}
	if mode["name"] != "check_only" || mode["non_mutating"] != true {
		t.Fatalf("unexpected mode payload %+v", mode)
	}
	if plan["apply_ready"] != true {
		t.Fatalf("expected apply_ready=true, got %+v", plan)
	}
	if proof["host_mutation_performed"] != false {
		t.Fatalf("expected host_mutation_performed=false, got %+v", proof)
	}
	if summary["apply_performed"] != false {
		t.Fatalf("expected apply_performed=false, got %+v", summary["apply_performed"])
	}
	if summary["governed_smoke_performed"] != false {
		t.Fatalf("expected governed_smoke_performed=false, got %+v", summary["governed_smoke_performed"])
	}
	semantics := nestedMap(t, summary, "workload_zone_semantics")
	if semantics["workload_performs_vault_jwt_login"] != true {
		t.Fatalf("expected workload-side vault login to remain documented, got %+v", semantics)
	}
	if semantics["es_vault_token_brokerage"] != false {
		t.Fatalf("expected ES vault token brokerage to remain absent, got %+v", semantics)
	}
	nonAuthorityLabels := jsonStringSlice(t, summary["non_authority_labels"])
	if len(nonAuthorityLabels) == 0 {
		t.Fatalf("expected non-authority labels, got %+v", summary["non_authority_labels"])
	}
	if summary["overall_classification"] != "pass" {
		t.Fatalf("expected overall pass, got %v", summary["overall_classification"])
	}
	if _, err := os.Stat(mutationLogPath); !os.IsNotExist(err) {
		t.Fatalf("mutation log should not exist, got %q", mutationLogPath)
	}
	if _, err := os.Stat(fixture.ServiceDropInPath); !os.IsNotExist(err) {
		t.Fatalf("drop-in should not be written in check-only mode")
	}
}

func TestRemoteAlphaVaultServiceUserMigrationCheckOnlyWritesBlockedArtifactWhenNoninteractiveRootUnavailable(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	fakeBin := filepath.Join(tmpDir, "bin")
	if err := os.MkdirAll(fakeBin, 0o755); err != nil {
		t.Fatalf("mkdir fake bin: %v", err)
	}
	summaryPath := filepath.Join(tmpDir, "vault-service-user-migration-check-only.json")
	writeExecutable(t, fakeBin, "sudo", `#!/bin/sh
echo "sudo: a password is required" >&2
exit 1
`)

	shellBody := fmt.Sprintf(`
remote_alpha_migrate_vault_service_user_main --summary-path %q
`, summaryPath)
	output, err := runSourcedVaultServiceUserMigrationHelper(t, envWithPath(fakeBin,
		"REMOTE_ALPHA_TEST_CURRENT_EUID=1000",
	), shellBody)
	if err == nil {
		t.Fatalf("expected blocked check-only helper result when noninteractive root is unavailable\noutput=%s", output)
	}
	if strings.TrimSpace(string(output)) != summaryPath {
		t.Fatalf("unexpected helper output %q", strings.TrimSpace(string(output)))
	}

	summary := readJSONFile(t, summaryPath)
	if summary["collection_status"] != "preflight_blocked" {
		t.Fatalf("expected preflight_blocked collection_status, got %+v", summary["collection_status"])
	}
	if summary["apply_performed"] != false {
		t.Fatalf("expected apply_performed=false, got %+v", summary["apply_performed"])
	}
	if summary["governed_smoke_performed"] != false {
		t.Fatalf("expected governed_smoke_performed=false, got %+v", summary["governed_smoke_performed"])
	}
	plan := nestedMap(t, summary, "plan")
	if plan["apply_ready"] != false {
		t.Fatalf("expected blocked preflight apply_ready=false, got %+v", plan)
	}
	prerequisiteProbe := nestedMap(t, summary, "prerequisite_probe")
	if prerequisiteProbe["command"] != "sudo -n true" {
		t.Fatalf("expected prerequisite probe command to be recorded, got %+v", prerequisiteProbe)
	}
	if prerequisiteProbe["attempted"] != true {
		t.Fatalf("expected prerequisite probe attempted=true, got %+v", prerequisiteProbe)
	}
	if !strings.Contains(fmt.Sprint(prerequisiteProbe["detail"]), "sudo: a password is required") {
		t.Fatalf("expected blocked prerequisite detail to include sudo failure, got %+v", prerequisiteProbe)
	}
	blockers, ok := summary["blockers"].([]any)
	if !ok || len(blockers) == 0 {
		t.Fatalf("expected blockers in blocked artifact, got %+v", summary["blockers"])
	}
	skippedChecks, ok := summary["skipped_checks"].([]any)
	if !ok || len(skippedChecks) == 0 {
		t.Fatalf("expected skipped checks in blocked artifact, got %+v", summary["skipped_checks"])
	}
	nonAuthorityLabels := jsonStringSlice(t, summary["non_authority_labels"])
	if len(nonAuthorityLabels) == 0 {
		t.Fatalf("expected non-authority labels, got %+v", summary["non_authority_labels"])
	}
	if summary["overall_classification"] != "blocker" {
		t.Fatalf("expected blocker overall classification, got %+v", summary["overall_classification"])
	}
}

func TestRemoteAlphaVaultServiceUserMigrationApplyRequiresReadyPreflight(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	fakeBin := filepath.Join(tmpDir, "bin")
	if err := os.MkdirAll(fakeBin, 0o755); err != nil {
		t.Fatalf("mkdir fake bin: %v", err)
	}
	fixture := setupVaultServiceUserMigrationFixture(t, tmpDir)
	preflightPath := filepath.Join(tmpDir, "preflight.json")
	summaryPath := filepath.Join(tmpDir, "apply-summary.json")
	mutationLogPath := filepath.Join(tmpDir, "mutations.log")
	setupFakeVaultServiceUserMigrationCommands(t, fakeBin, fakeVaultServiceUserAccount{
		Present:   true,
		UID:       os.Getuid(),
		GID:       os.Getgid(),
		GroupName: "vault",
	}, fixture, mutationLogPath)

	writeJSONFile(t, preflightPath, map[string]any{
		"schema_version": "execution-substrate.remote-alpha.vault-service-user-migration-summary.v1",
		"mode": map[string]any{
			"name":         "check_only",
			"non_mutating": true,
		},
		"plan": map[string]any{
			"apply_ready": false,
		},
		"overall_classification": "blocker",
	})

	shellBody := fmt.Sprintf(`
remote_alpha_migrate_vault_service_user_main --apply --summary-path %q --preflight-path %q --es-config-path %q --healthcheck-env-path %q
`, summaryPath, preflightPath, fixture.ESConfigPath, fixture.HealthEnvPath)
	output, err := runSourcedVaultServiceUserMigrationHelper(t, envWithPath(fakeBin, "REMOTE_ALPHA_TEST_MUTATION_LOG_PATH="+mutationLogPath), shellBody)
	if err == nil {
		t.Fatalf("expected apply to fail when preflight is not ready\noutput=%s", output)
	}

	summary := readJSONFile(t, summaryPath)
	result := nestedMap(t, summary, "result")
	if result["status"] != "preflight_blocked" {
		t.Fatalf("expected preflight_blocked result, got %+v", result)
	}
	if _, err := os.Stat(mutationLogPath); !os.IsNotExist(err) {
		t.Fatalf("mutation log should not exist when apply is blocked, got %q", mutationLogPath)
	}
}

func TestRemoteAlphaVaultServiceUserMigrationApplyCreatesBackupRollbackAndHonestSkippedSmoke(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	fakeBin := filepath.Join(tmpDir, "bin")
	if err := os.MkdirAll(fakeBin, 0o755); err != nil {
		t.Fatalf("mkdir fake bin: %v", err)
	}
	fixture := setupVaultServiceUserMigrationFixture(t, tmpDir)
	summaryPath := filepath.Join(tmpDir, "vault-service-user-migration-apply-summary.json")
	preflightPath := filepath.Join(tmpDir, "vault-service-user-migration-check-only.json")
	mutationLogPath := filepath.Join(tmpDir, "mutations.log")
	backupSentinelPath := filepath.Join(tmpDir, "backup.sentinel")
	setupFakeVaultServiceUserMigrationCommands(t, fakeBin, fakeVaultServiceUserAccount{
		Present:   true,
		UID:       os.Getuid(),
		GID:       os.Getgid(),
		GroupName: "vault",
	}, fixture, mutationLogPath)

	shellBody := fmt.Sprintf(`
remote_alpha_migrate_vault_service_user_main --apply --summary-path %q --preflight-path %q --backup-root-dir %q --es-config-path %q --healthcheck-env-path %q
`, summaryPath, preflightPath, fixture.BackupRootDir, fixture.ESConfigPath, fixture.HealthEnvPath)
	output, err := runSourcedVaultServiceUserMigrationHelper(t, envWithPath(fakeBin,
		"REMOTE_ALPHA_TEST_MUTATION_LOG_PATH="+mutationLogPath,
		"REMOTE_ALPHA_TEST_BACKUP_SENTINEL_PATH="+backupSentinelPath,
	), shellBody)
	if err != nil {
		t.Fatalf("apply helper failed: %v\noutput=%s\nsummary=%s", err, string(output), mustRead(t, summaryPath))
	}
	if strings.TrimSpace(string(output)) != summaryPath {
		t.Fatalf("unexpected helper output %q", strings.TrimSpace(string(output)))
	}
	if got := mustRead(t, fixture.ServiceDropInPath); got != "[Service]\nUser=vault\nGroup=vault\nUMask=0027\n" {
		t.Fatalf("unexpected drop-in contents %q", got)
	}

	summary := readJSONFile(t, summaryPath)
	if nestedMap(t, summary, "result")["ok"] != true {
		t.Fatalf("expected successful apply summary, got %+v", nestedMap(t, summary, "result"))
	}
	backup := nestedMap(t, summary, "backup")
	if backup["path"] == "" || backup["snapshot_path"] == "" || backup["rollback_notes_path"] == "" {
		t.Fatalf("expected backup evidence paths, got %+v", backup)
	}
	rollbackNotes := jsonStringSlice(t, backup["rollback_notes"])
	if len(rollbackNotes) == 0 {
		t.Fatalf("expected rollback notes, got %+v", backup)
	}
	postChecks := nestedMap(t, summary, "post_apply_checks")
	for _, name := range []string{"vault_health", "es_health", "es_contract"} {
		check := jsonMap(t, postChecks[name])
		if check["status"] != "pass" {
			t.Fatalf("expected %s pass, got %+v", name, check)
		}
	}
	smoke := jsonMap(t, postChecks["governed_execution_smoke"])
	if smoke["status"] != "skipped" {
		t.Fatalf("expected governed smoke skipped, got %+v", smoke)
	}
	if smoke["passed"] == true {
		t.Fatalf("skipped smoke must not be reported as passed: %+v", smoke)
	}
	explicitNonClaims := jsonStringSlice(t, summary["explicit_non_claims"])
	if len(explicitNonClaims) == 0 {
		t.Fatalf("expected explicit non-claims, got %+v", summary["explicit_non_claims"])
	}
	summaryText := mustRead(t, summaryPath)
	if strings.Contains(summaryText, "full ES/runtime de-root") {
		t.Fatalf("summary must not overclaim full ES/runtime de-root: %s", summaryText)
	}
}

func TestRemoteAlphaVaultServiceUserMigrationApplyRepresentsPostApplyContractFailureHonestly(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	fakeBin := filepath.Join(tmpDir, "bin")
	if err := os.MkdirAll(fakeBin, 0o755); err != nil {
		t.Fatalf("mkdir fake bin: %v", err)
	}
	fixture := setupVaultServiceUserMigrationFixture(t, tmpDir)
	summaryPath := filepath.Join(tmpDir, "apply-summary.json")
	preflightPath := filepath.Join(tmpDir, "preflight.json")
	mutationLogPath := filepath.Join(tmpDir, "mutations.log")
	backupSentinelPath := filepath.Join(tmpDir, "backup.sentinel")
	setupFakeVaultServiceUserMigrationCommands(t, fakeBin, fakeVaultServiceUserAccount{
		Present:   true,
		UID:       os.Getuid(),
		GID:       os.Getgid(),
		GroupName: "vault",
	}, fixture, mutationLogPath)

	shellBody := fmt.Sprintf(`
remote_alpha_migrate_vault_service_user_main --apply --summary-path %q --preflight-path %q --backup-root-dir %q --es-config-path %q --healthcheck-env-path %q
`, summaryPath, preflightPath, fixture.BackupRootDir, fixture.ESConfigPath, fixture.HealthEnvPath)
	output, err := runSourcedVaultServiceUserMigrationHelper(t, envWithPath(fakeBin,
		"REMOTE_ALPHA_TEST_MUTATION_LOG_PATH="+mutationLogPath,
		"REMOTE_ALPHA_TEST_BACKUP_SENTINEL_PATH="+backupSentinelPath,
		"REMOTE_ALPHA_TEST_CURL_FAIL_CONTRACT=true",
	), shellBody)
	if err == nil {
		t.Fatalf("expected apply failure when ES contract check fails\noutput=%s", output)
	}

	summary := readJSONFile(t, summaryPath)
	result := nestedMap(t, summary, "result")
	if result["status"] != "post_apply_validation_failed" {
		t.Fatalf("expected post_apply_validation_failed, got %+v", result)
	}
	contractCheck := jsonMap(t, nestedMap(t, summary, "post_apply_checks")["es_contract"])
	if contractCheck["status"] != "fail" {
		t.Fatalf("expected failed contract check, got %+v", contractCheck)
	}
}

func TestRemoteAlphaVaultServiceUserMigrationValidateSummaryRejectsSecretLikeMaterial(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	summaryPath := filepath.Join(tmpDir, "summary.json")
	secretSummary := `{"schema_version":"execution-substrate.remote-alpha.vault-service-user-migration-summary.v1","jwt":"eyJhbGciOiJub25lIn0.eyJzdWIiOiJzcGlmZmU6Ly9leGVjdXRpb24uaW50ZXJuYWwvd29ya2xvYWQifQ.signature","token":"hvs.secretmaterial123456","private_key":"-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----"}`
	if err := os.WriteFile(summaryPath, []byte(secretSummary), 0o600); err != nil {
		t.Fatalf("write summary: %v", err)
	}

	output, err := runSourcedVaultServiceUserMigrationHelper(t, os.Environ(), fmt.Sprintf(
		"remote_alpha_migrate_vault_service_user_validate_summary_file %q",
		summaryPath,
	))
	if err == nil {
		t.Fatalf("expected validator to fail for secret-like material")
	}
	if !strings.Contains(string(output), "summary contains") {
		t.Fatalf("unexpected validator output %q", output)
	}
}
