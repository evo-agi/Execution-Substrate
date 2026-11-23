package scripts_test

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func runSourcedEGSHardeningHelper(t *testing.T, env []string, shellBody string) ([]byte, error) {
	t.Helper()
	helperPath := filepath.Join(executionSubstrateRepoRoot, "scripts", "internal", "remote_alpha_harden_egs_service.sh")
	script := fmt.Sprintf("set -euo pipefail\nsource %q\n%s\n", helperPath, shellBody)
	cmd := exec.Command("/bin/bash", "-c", script)
	cmd.Dir = executionSubstrateRepoRoot
	cmd.Env = env
	return cmd.CombinedOutput()
}

func setupFakeEGSHardeningCommands(t *testing.T, dir, egsUnitPath, egsConfigPath, egsBinaryPath, agsBinaryPath, agsConfigPath, arsBinaryPath, arsConfigPath, egsGroups, egsGroupEntry string, passwdEntries []string, ownerships map[string]string) {
	t.Helper()

	writeExecutable(t, dir, "id", fmt.Sprintf(`#!/bin/sh
if [ "$1" = "-u" ] && [ $# -eq 1 ]; then
  echo 0
  exit 0
fi
if [ "$1" = "-u" ] && [ "$2" = "egs" ]; then
  echo 993
  exit 0
fi
if [ "$1" = "-gn" ] && [ "$2" = "egs" ]; then
  echo egs
  exit 0
fi
if [ "$1" = "-nG" ] && [ "$2" = "egs" ]; then
  echo %q
  exit 0
fi
if [ "$1" = "-nG" ] && [ "$2" = "ds" ]; then
  echo "ds adm wheel"
  exit 0
fi
exec /usr/bin/id "$@"
`, egsGroups))
	writeExecutable(t, dir, "getent", `#!/bin/sh
if [ "$1" = "group" ] && [ "$2" = "egs" ]; then
  echo `+fmt.Sprintf("%q", egsGroupEntry)+`
  exit 0
fi
if [ "$1" = "passwd" ] && [ $# -eq 1 ]; then
  cat <<'EOF'
`+strings.Join(passwdEntries, "\n")+`
EOF
  exit 0
fi
exit 2
`)
	writeExecutable(t, dir, "groupadd", "#!/bin/sh\nexit 0\n")
	writeExecutable(t, dir, "useradd", "#!/bin/sh\nexit 0\n")
	writeExecutable(t, dir, "chown", "#!/bin/sh\nexit 0\n")
	writeExecutable(t, dir, "systemctl", fmt.Sprintf(`#!/bin/sh
case "$1" in
  daemon-reload|restart|enable)
    exit 0
    ;;
  is-active)
    exit 0
    ;;
  is-enabled)
    exit 0
    ;;
  show)
    service="$2"
    case "$service" in
      egs.service)
        cat <<'EOF'
User=egs
Group=egs
ExecStart={ path=%s ; argv[]=%s -config %s ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }
FragmentPath=%s
ActiveState=active
SubState=running
EOF
        ;;
      ags.service)
        cat <<'EOF'
User=ags
Group=ags
ExecStart={ path=%s ; argv[]=%s -config %s ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }
FragmentPath=/etc/systemd/system/ags.service
ActiveState=active
SubState=running
EOF
        ;;
      ars.service)
        cat <<'EOF'
User=ars
Group=ars
ExecStart={ path=%s ; argv[]=%s -config %s ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }
FragmentPath=/etc/systemd/system/ars.service
ActiveState=active
SubState=running
EOF
        ;;
      es.service)
        cat <<'EOF'
User=es
Group=es
ExecStart={ path=/tmp/fake-es ; argv[]=/tmp/fake-es ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }
FragmentPath=/etc/systemd/system/es.service
ActiveState=active
SubState=running
EOF
        ;;
      *)
        exit 1
        ;;
    esac
    exit 0
    ;;
esac
exit 1
`, egsBinaryPath, egsBinaryPath, egsConfigPath, egsUnitPath, agsBinaryPath, agsBinaryPath, agsConfigPath, arsBinaryPath, arsBinaryPath, arsConfigPath))
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
  https://127.0.0.1:8443/health)
    cat <<'EOF'
{"status":"healthy","ready":true,"service":"execution-governance","additional_properties":{"readiness":{"signer":"initialized","trust_model":"loaded"}}}
EOF
    ;;
  https://192.168.1.156:8444/health)
    cat <<'EOF'
{"status":"healthy","ready":true,"service":"artifact-governance","additional_properties":{"dependencies":{"artifact_registry":"healthy"}}}
EOF
    ;;
  https://192.168.1.156:8444/v1/artifacts:publish)
    cat <<'EOF'
{"published":true,"artifact_digest":"sha256:egs-posture-test-artifact"}
EOF
    ;;
  https://192.168.1.156:8445/health)
    cat <<'EOF'
{"status":"healthy","ready":true,"service":"execution","additional_properties":{"dependencies":{"artifact_registry":"healthy"}}}
EOF
    ;;
  https://192.168.1.156:8445/v1/executions:contract)
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
	writeExecutable(t, dir, "stat", fmt.Sprintf(`#!/bin/sh
if [ "$1" != "-c" ]; then
  echo "unexpected stat args: $*" >&2
  exit 1
fi
shift 2
for path in "$@"; do
  case "$path" in
%s
    *)
      echo "unknown stat path: $path" >&2
      exit 1
      ;;
  esac
done
`, formatFakeStatCases(ownerships)))
}

func egsHardeningExpectedSliceShell(binaryPath, configPath, healthcheckEnvPath, unitPath, dropInDir, dropInPath, sharedTLSDir, tlsDir, agsConfigPath, esConfigPath string) string {
	return fmt.Sprintf(`
remote_alpha_egs_hardening_expected_binary_path=%q
remote_alpha_egs_hardening_expected_config_path=%q
remote_alpha_egs_hardening_expected_healthcheck_env_path=%q
remote_alpha_egs_hardening_expected_service_unit_path=%q
remote_alpha_egs_hardening_expected_service_dropin_dir=%q
remote_alpha_egs_hardening_expected_service_dropin_path=%q
remote_alpha_egs_hardening_expected_shared_tls_dir=%q
remote_alpha_egs_hardening_expected_tls_dir=%q
remote_alpha_egs_hardening_expected_ags_config_path=%q
remote_alpha_egs_hardening_expected_es_config_path=%q
remote_alpha_egs_hardening_expected_bind_address=%q
remote_alpha_egs_hardening_expected_port=%q
`, binaryPath, configPath, healthcheckEnvPath, unitPath, dropInDir, dropInPath, sharedTLSDir, tlsDir, agsConfigPath, esConfigPath, "127.0.0.1", "8443")
}

func TestRemoteAlphaEGSHardeningPassWritesSummaryAndDropIn(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	fakeBin := filepath.Join(tmpDir, "bin")
	if err := os.MkdirAll(fakeBin, 0o755); err != nil {
		t.Fatalf("mkdir fake bin: %v", err)
	}

	egsBinaryPath := filepath.Join(tmpDir, "fake-egs")
	if err := os.WriteFile(egsBinaryPath, []byte("binary"), 0o755); err != nil {
		t.Fatalf("write egs binary: %v", err)
	}
	agsBinaryPath := filepath.Join(tmpDir, "fake-ags")
	if err := os.WriteFile(agsBinaryPath, []byte("binary"), 0o755); err != nil {
		t.Fatalf("write ags binary: %v", err)
	}
	arsBinaryPath := filepath.Join(tmpDir, "fake-ars")
	if err := os.WriteFile(arsBinaryPath, []byte("binary"), 0o755); err != nil {
		t.Fatalf("write ars binary: %v", err)
	}

	sourceTLSDir := filepath.Join(tmpDir, "tls")
	if err := os.MkdirAll(sourceTLSDir, 0o755); err != nil {
		t.Fatalf("mkdir source tls dir: %v", err)
	}
	for _, name := range []string{
		"egs-server-cert.pem",
		"egs-server-key.pem",
		"runtime-ca.pem",
		"combined-service-ca-bundle.pem",
		"operator-client-cert.pem",
		"operator-client-key.pem",
	} {
		if err := os.WriteFile(filepath.Join(sourceTLSDir, name), []byte(name+"\n"), 0o600); err != nil {
			t.Fatalf("write tls file %s: %v", name, err)
		}
	}

	egsConfigPath := filepath.Join(tmpDir, "egs.json")
	if err := os.WriteFile(egsConfigPath, []byte(fmt.Sprintf(`{
  "http": {
    "bind_address": "127.0.0.1",
    "port": 8443
  },
  "publication": {
    "update_revision": 1,
    "version": "v1"
  },
  "runtime_trust": {
    "artifact_policy": {
      "revoked_artifacts": []
    },
    "signer_policy": {
      "allowed_signers": [
        "ags-key-1"
      ],
      "revoked_signers": []
    }
  },
  "security": {
    "bootstrap_issuer_common_name": "Bootstrap Root CA Example"
  },
  "signer": {
    "algorithm": "ed25519",
    "key_id": "egs-key-1",
    "private_key_hex": "3333333333333333333333333333333333333333333333333333333333333333",
    "public_key_hex": "17cb79fb2b4120f2b1ec65e4198d6e08b28e813feb01e4a400839b85e18080ce"
  },
  "tls": {
    "cert_file": %q,
    "client_ca_file": %q,
    "key_file": %q
  }
}
`,
		filepath.Join(sourceTLSDir, "egs-server-cert.pem"),
		filepath.Join(sourceTLSDir, "runtime-ca.pem"),
		filepath.Join(sourceTLSDir, "egs-server-key.pem"),
	)), 0o600); err != nil {
		t.Fatalf("write egs config: %v", err)
	}

	agsConfigPath := filepath.Join(tmpDir, "ags.json")
	if err := os.WriteFile(agsConfigPath, []byte(`{
  "http": {
    "bind_address": "192.168.1.156",
    "port": 8444
  }
}
`), 0o600); err != nil {
		t.Fatalf("write ags config: %v", err)
	}

	arsConfigPath := filepath.Join(tmpDir, "ars.json")
	if err := os.WriteFile(arsConfigPath, []byte(`{
  "http": {
    "bind_address": "127.0.0.1",
    "port": 8442
  }
}
`), 0o600); err != nil {
		t.Fatalf("write ars config: %v", err)
	}

	esConfigPath := filepath.Join(tmpDir, "es.json")
	if err := os.WriteFile(esConfigPath, []byte(`{
  "http": {
    "bind_address": "192.168.1.156",
    "port": 8445
  }
}
`), 0o600); err != nil {
		t.Fatalf("write es config: %v", err)
	}

	healthcheckEnvPath := filepath.Join(tmpDir, "healthcheck.env")
	if err := os.WriteFile(healthcheckEnvPath, []byte(strings.Join([]string{
		"CA_CERT=" + filepath.Join(sourceTLSDir, "combined-service-ca-bundle.pem"),
		"OPERATOR_CERT=" + filepath.Join(sourceTLSDir, "operator-client-cert.pem"),
		"OPERATOR_KEY=" + filepath.Join(sourceTLSDir, "operator-client-key.pem"),
		"",
	}, "\n")), 0o600); err != nil {
		t.Fatalf("write healthcheck env: %v", err)
	}

	unitPath := filepath.Join(tmpDir, "egs.service")
	if err := os.WriteFile(unitPath, []byte(fmt.Sprintf(`[Unit]
Description=Execution Substrate Execution Governance Service

[Service]
ExecStart=%s -config %s
`, egsBinaryPath, egsConfigPath)), 0o644); err != nil {
		t.Fatalf("write unit file: %v", err)
	}

	dropInDir := filepath.Join(tmpDir, "egs.service.d")
	dropInPath := filepath.Join(dropInDir, "10-account.conf")
	dedicatedTLSDir := filepath.Join(tmpDir, "egs-tls")
	summaryPath := filepath.Join(tmpDir, "egs-service-hardening-summary.json")

	ownerships := map[string]string{
		egsConfigPath:   fmt.Sprintf("root:egs 640 %s", egsConfigPath),
		dedicatedTLSDir: fmt.Sprintf("root:egs 710 %s", dedicatedTLSDir),
		filepath.Join(dedicatedTLSDir, "egs-server-cert.pem"): fmt.Sprintf("root:egs 640 %s", filepath.Join(dedicatedTLSDir, "egs-server-cert.pem")),
		filepath.Join(dedicatedTLSDir, "egs-server-key.pem"):  fmt.Sprintf("root:egs 640 %s", filepath.Join(dedicatedTLSDir, "egs-server-key.pem")),
		filepath.Join(dedicatedTLSDir, "runtime-ca.pem"):      fmt.Sprintf("root:egs 640 %s", filepath.Join(dedicatedTLSDir, "runtime-ca.pem")),
	}

	setupFakeEGSHardeningCommands(
		t,
		fakeBin,
		unitPath,
		egsConfigPath,
		egsBinaryPath,
		agsBinaryPath,
		agsConfigPath,
		arsBinaryPath,
		arsConfigPath,
		"egs",
		"egs:x:993:",
		[]string{
			"egs:x:993:993::/nonexistent:/usr/sbin/nologin",
			"ds:x:1000:1000::/home/ds:/bin/zsh",
		},
		ownerships,
	)

	output, err := runSourcedEGSHardeningHelper(t, envWithPath(fakeBin,
		"REMOTE_ALPHA_SUMMARY_PATH="+summaryPath,
		"REMOTE_ALPHA_TEST_PASSWORDLESS_SUDO_FOR_DS=false",
	), egsHardeningExpectedSliceShell(egsBinaryPath, egsConfigPath, healthcheckEnvPath, unitPath, dropInDir, dropInPath, sourceTLSDir, dedicatedTLSDir, agsConfigPath, esConfigPath)+"remote_alpha_egs_hardening_main")
	if err != nil {
		t.Fatalf("EGS hardening helper failed: %v\n%s", err, output)
	}

	if got := strings.TrimSpace(string(output)); got != summaryPath {
		t.Fatalf("unexpected summary path output %q", got)
	}

	dropIn := mustRead(t, dropInPath)
	if !strings.Contains(dropIn, "User=egs") {
		t.Fatalf("drop-in missing User=egs: %q", dropIn)
	}
	if !strings.Contains(dropIn, "Group=egs") {
		t.Fatalf("drop-in missing Group=egs: %q", dropIn)
	}
	if !strings.Contains(dropIn, "UMask=0027") {
		t.Fatalf("drop-in missing UMask=0027: %q", dropIn)
	}

	rewrittenConfig := mustRead(t, egsConfigPath)
	if !strings.Contains(rewrittenConfig, filepath.Join(dedicatedTLSDir, "egs-server-cert.pem")) {
		t.Fatalf("egs config did not point at dedicated tls dir: %q", rewrittenConfig)
	}
	if !strings.Contains(rewrittenConfig, filepath.Join(dedicatedTLSDir, "egs-server-key.pem")) {
		t.Fatalf("egs config did not point at dedicated tls key: %q", rewrittenConfig)
	}
	if !strings.Contains(rewrittenConfig, filepath.Join(dedicatedTLSDir, "runtime-ca.pem")) {
		t.Fatalf("egs config did not point at dedicated tls client ca: %q", rewrittenConfig)
	}

	summary := readJSONFile(t, summaryPath)
	if got := summary["schema_version"]; got != "execution-substrate.remote-alpha.egs-service-hardening-summary.v2" {
		t.Fatalf("unexpected schema version %v", got)
	}

	slice := jsonMap(t, summary["slice"])
	if got := slice["classification"]; got != "hardening_slice" {
		t.Fatalf("unexpected slice classification %v", got)
	}
	if got := slice["not_a_new_happy_path_proof"]; got != true {
		t.Fatalf("expected hardening slice to avoid happy-path proof claim, got %v", got)
	}

	service := jsonMap(t, summary["service"])
	if got := service["user"]; got != "egs" {
		t.Fatalf("unexpected EGS service user %v", got)
	}
	if got := service["group"]; got != "egs" {
		t.Fatalf("unexpected EGS service group %v", got)
	}
	if got := service["binary_path"]; got != egsBinaryPath {
		t.Fatalf("unexpected binary path %v", got)
	}
	if got := service["config_path"]; got != egsConfigPath {
		t.Fatalf("unexpected config path %v", got)
	}

	dependencies := jsonMap(t, summary["dependencies"])
	signer := jsonMap(t, dependencies["signer"])
	if got := signer["material_location"]; got != egsConfigPath {
		t.Fatalf("unexpected signer material location %v", got)
	}
	runtimeTrust := jsonMap(t, dependencies["runtime_trust"])
	if got := runtimeTrust["material_location"]; got != egsConfigPath {
		t.Fatalf("unexpected runtime trust material location %v", got)
	}
	publication := jsonMap(t, dependencies["publication"])
	if got := publication["material_location"]; got != egsConfigPath {
		t.Fatalf("unexpected publication material location %v", got)
	}

	ownership := jsonMap(t, summary["ownership_model"])
	accountOwnership := jsonMap(t, ownership["account"])
	if got := accountOwnership["primary_group"]; got != "egs" {
		t.Fatalf("unexpected account primary group %v", got)
	}
	if got := accountOwnership["narrow_dedicated_account"]; got != true {
		t.Fatalf("unexpected account narrowness %v", got)
	}
	if got := jsonStringSlice(t, accountOwnership["supplementary_groups"]); len(got) != 0 {
		t.Fatalf("expected no supplementary groups, got %v", got)
	}
	if got := jsonStringSlice(t, accountOwnership["group_members"]); len(got) != 1 || got[0] != "egs" {
		t.Fatalf("expected only egs group member, got %v", got)
	}
	configOwnership := jsonMap(t, ownership["config_file"])
	if got := configOwnership["owner"]; got != "root:egs" {
		t.Fatalf("unexpected config ownership %v", got)
	}
	runtimeState := jsonMap(t, ownership["runtime_state"])
	if got := runtimeState["required"]; got != false {
		t.Fatalf("unexpected runtime state requirement %v", got)
	}

	validation := jsonMap(t, summary["validation"])
	localEGSHealth := jsonMap(t, validation["local_egs_health"])
	if got := localEGSHealth["status"]; got != "pass" {
		t.Fatalf("unexpected local EGS health status %v", got)
	}
	localAGSHealth := jsonMap(t, validation["local_ags_health"])
	if got := localAGSHealth["status"]; got != "pass" {
		t.Fatalf("unexpected local AGS health status %v", got)
	}
	localAGSPublish := jsonMap(t, validation["local_ags_publish_probe"])
	if got := localAGSPublish["status"]; got != "pass" {
		t.Fatalf("unexpected local AGS publish status %v", got)
	}
	localESHealth := jsonMap(t, validation["local_es_health"])
	if got := localESHealth["status"]; got != "pass" {
		t.Fatalf("unexpected local ES health status %v", got)
	}
	localESContract := jsonMap(t, validation["local_es_contract_probe"])
	if got := localESContract["status"]; got != "pass" {
		t.Fatalf("unexpected local ES contract status %v", got)
	}
	serviceAccountNarrowness := jsonMap(t, validation["service_account_narrowness"])
	if got := serviceAccountNarrowness["status"]; got != "pass" {
		t.Fatalf("unexpected service account narrowness status %v", got)
	}
	if got := serviceAccountNarrowness["primary_group"]; got != "egs" {
		t.Fatalf("unexpected service account primary group %v", got)
	}
	if got := serviceAccountNarrowness["narrow_dedicated_account"]; got != true {
		t.Fatalf("unexpected service account narrowness result %v", got)
	}
	if got := jsonStringSlice(t, serviceAccountNarrowness["supplementary_groups"]); len(got) != 0 {
		t.Fatalf("expected no supplementary groups in validation, got %v", got)
	}
	if got := jsonStringSlice(t, serviceAccountNarrowness["group_members"]); len(got) != 1 || got[0] != "egs" {
		t.Fatalf("expected only egs group member in validation, got %v", got)
	}
	if got := jsonStringSlice(t, serviceAccountNarrowness["unexpected_group_members"]); len(got) != 0 {
		t.Fatalf("expected no unexpected group members in validation, got %v", got)
	}
	ownershipValidation := jsonMap(t, validation["ownership"])
	if got := ownershipValidation["status"]; got != "pass" {
		t.Fatalf("unexpected ownership validation status %v", got)
	}
	agsPosture := jsonMap(t, validation["ags_service_posture"])
	if got := agsPosture["effective_user"]; got != "ags" {
		t.Fatalf("unexpected ags posture %v", got)
	}
	arsPosture := jsonMap(t, validation["ars_service_posture"])
	if got := arsPosture["effective_user"]; got != "ars" {
		t.Fatalf("unexpected ars posture %v", got)
	}
	if got := arsPosture["effective_group"]; got != "ars" {
		t.Fatalf("unexpected ars group posture %v", got)
	}
	esPosture := jsonMap(t, validation["es_service_posture"])
	if got := esPosture["effective_user"]; got != "es" {
		t.Fatalf("unexpected es posture %v", got)
	}
	if got := esPosture["effective_group"]; got != "es" {
		t.Fatalf("unexpected es group posture %v", got)
	}

	preserved := jsonMap(t, summary["preserved_remote_path"])
	if got := preserved["egs_loopback_only"]; got != true {
		t.Fatalf("unexpected egs_loopback_only value %v", got)
	}
	directHTTPS := jsonMap(t, preserved["direct_https_mtls"])
	if got := directHTTPS["status"]; got != "inferred" {
		t.Fatalf("unexpected direct_https_mtls status %v", got)
	}
	if got := directHTTPS["value"]; got != true {
		t.Fatalf("unexpected direct_https_mtls value %v", got)
	}
	noBridge := jsonMap(t, preserved["no_bridge"])
	if got := noBridge["status"]; got != "operator_assertion" {
		t.Fatalf("unexpected no_bridge status %v", got)
	}
	if got := noBridge["value"]; got != true {
		t.Fatalf("unexpected no_bridge value %v", got)
	}
	noSharedFilesystem := jsonMap(t, preserved["no_shared_filesystem"])
	if got := noSharedFilesystem["status"]; got != "operator_assertion" {
		t.Fatalf("unexpected no_shared_filesystem status %v", got)
	}
	if got := noSharedFilesystem["value"]; got != true {
		t.Fatalf("unexpected no_shared_filesystem value %v", got)
	}

	security := jsonMap(t, summary["security"])
	if got := security["ds_not_in_docker_group"]; got != "true" {
		t.Fatalf("unexpected ds_not_in_docker_group %v", got)
	}
	if got := security["passwordless_sudo_for_ds"]; got != "false" {
		t.Fatalf("unexpected passwordless_sudo_for_ds %v", got)
	}
	sharedUnixAccountModel := jsonMap(t, security["shared_unix_account_model_introduced"])
	if got := sharedUnixAccountModel["status"]; got != "derived" {
		t.Fatalf("unexpected shared_unix_account_model_introduced status %v", got)
	}
	if got := sharedUnixAccountModel["value"]; got != false {
		t.Fatalf("unexpected shared_unix_account_model_introduced value %v", got)
	}
	if got := jsonStringSlice(t, sharedUnixAccountModel["supplementary_groups"]); len(got) != 0 {
		t.Fatalf("expected no supplementary groups in shared_unix_account_model_introduced, got %v", got)
	}
	if got := jsonStringSlice(t, sharedUnixAccountModel["group_members"]); len(got) != 1 || got[0] != "egs" {
		t.Fatalf("expected only egs group member in shared_unix_account_model_introduced, got %v", got)
	}
	if got := jsonStringSlice(t, sharedUnixAccountModel["unexpected_group_members"]); len(got) != 0 {
		t.Fatalf("expected no unexpected group members in shared_unix_account_model_introduced, got %v", got)
	}

	notClaimed := jsonMap(t, summary["not_claimed"])
	if got := notClaimed["es_de_root"]; got != "not_claimed" {
		t.Fatalf("unexpected es_de_root claim %v", got)
	}
	if got := notClaimed["es_public_contract_changes"]; got != "not_claimed" {
		t.Fatalf("unexpected es_public_contract_changes claim %v", got)
	}
}

func TestRemoteAlphaEGSHardeningRejectsPreexistingBroadServiceAccount(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	fakeBin := filepath.Join(tmpDir, "bin")
	if err := os.MkdirAll(fakeBin, 0o755); err != nil {
		t.Fatalf("mkdir fake bin: %v", err)
	}

	egsBinaryPath := filepath.Join(tmpDir, "fake-egs")
	if err := os.WriteFile(egsBinaryPath, []byte("binary"), 0o755); err != nil {
		t.Fatalf("write egs binary: %v", err)
	}
	agsBinaryPath := filepath.Join(tmpDir, "fake-ags")
	if err := os.WriteFile(agsBinaryPath, []byte("binary"), 0o755); err != nil {
		t.Fatalf("write ags binary: %v", err)
	}
	arsBinaryPath := filepath.Join(tmpDir, "fake-ars")
	if err := os.WriteFile(arsBinaryPath, []byte("binary"), 0o755); err != nil {
		t.Fatalf("write ars binary: %v", err)
	}

	sourceTLSDir := filepath.Join(tmpDir, "tls")
	if err := os.MkdirAll(sourceTLSDir, 0o755); err != nil {
		t.Fatalf("mkdir source tls dir: %v", err)
	}
	for _, name := range []string{
		"egs-server-cert.pem",
		"egs-server-key.pem",
		"runtime-ca.pem",
		"combined-service-ca-bundle.pem",
		"operator-client-cert.pem",
		"operator-client-key.pem",
	} {
		if err := os.WriteFile(filepath.Join(sourceTLSDir, name), []byte(name+"\n"), 0o600); err != nil {
			t.Fatalf("write tls file %s: %v", name, err)
		}
	}

	egsConfigPath := filepath.Join(tmpDir, "egs.json")
	if err := os.WriteFile(egsConfigPath, []byte(fmt.Sprintf(`{
  "http": {
    "bind_address": "127.0.0.1",
    "port": 8443
  },
  "publication": {
    "update_revision": 1,
    "version": "v1"
  },
  "runtime_trust": {
    "artifact_policy": {
      "revoked_artifacts": []
    },
    "signer_policy": {
      "allowed_signers": [
        "ags-key-1"
      ],
      "revoked_signers": []
    }
  },
  "security": {
    "bootstrap_issuer_common_name": "Bootstrap Root CA Example"
  },
  "signer": {
    "algorithm": "ed25519",
    "key_id": "egs-key-1",
    "private_key_hex": "3333333333333333333333333333333333333333333333333333333333333333",
    "public_key_hex": "17cb79fb2b4120f2b1ec65e4198d6e08b28e813feb01e4a400839b85e18080ce"
  },
  "tls": {
    "cert_file": %q,
    "client_ca_file": %q,
    "key_file": %q
  }
}
`,
		filepath.Join(sourceTLSDir, "egs-server-cert.pem"),
		filepath.Join(sourceTLSDir, "runtime-ca.pem"),
		filepath.Join(sourceTLSDir, "egs-server-key.pem"),
	)), 0o600); err != nil {
		t.Fatalf("write egs config: %v", err)
	}

	agsConfigPath := filepath.Join(tmpDir, "ags.json")
	if err := os.WriteFile(agsConfigPath, []byte(`{
  "http": {
    "bind_address": "192.168.1.156",
    "port": 8444
  }
}
`), 0o600); err != nil {
		t.Fatalf("write ags config: %v", err)
	}

	arsConfigPath := filepath.Join(tmpDir, "ars.json")
	if err := os.WriteFile(arsConfigPath, []byte(`{
  "http": {
    "bind_address": "127.0.0.1",
    "port": 8442
  }
}
`), 0o600); err != nil {
		t.Fatalf("write ars config: %v", err)
	}

	esConfigPath := filepath.Join(tmpDir, "es.json")
	if err := os.WriteFile(esConfigPath, []byte(`{
  "http": {
    "bind_address": "192.168.1.156",
    "port": 8445
  }
}
`), 0o600); err != nil {
		t.Fatalf("write es config: %v", err)
	}

	healthcheckEnvPath := filepath.Join(tmpDir, "healthcheck.env")
	if err := os.WriteFile(healthcheckEnvPath, []byte(strings.Join([]string{
		"CA_CERT=" + filepath.Join(sourceTLSDir, "combined-service-ca-bundle.pem"),
		"OPERATOR_CERT=" + filepath.Join(sourceTLSDir, "operator-client-cert.pem"),
		"OPERATOR_KEY=" + filepath.Join(sourceTLSDir, "operator-client-key.pem"),
		"",
	}, "\n")), 0o600); err != nil {
		t.Fatalf("write healthcheck env: %v", err)
	}

	unitPath := filepath.Join(tmpDir, "egs.service")
	if err := os.WriteFile(unitPath, []byte(fmt.Sprintf(`[Unit]
Description=Execution Substrate Execution Governance Service

[Service]
ExecStart=%s -config %s
`, egsBinaryPath, egsConfigPath)), 0o644); err != nil {
		t.Fatalf("write unit file: %v", err)
	}

	dropInDir := filepath.Join(tmpDir, "egs.service.d")
	dropInPath := filepath.Join(dropInDir, "10-account.conf")
	dedicatedTLSDir := filepath.Join(tmpDir, "egs-tls")
	summaryPath := filepath.Join(tmpDir, "egs-service-hardening-summary.json")

	ownerships := map[string]string{
		egsConfigPath:   fmt.Sprintf("root:egs 640 %s", egsConfigPath),
		dedicatedTLSDir: fmt.Sprintf("root:egs 710 %s", dedicatedTLSDir),
		filepath.Join(dedicatedTLSDir, "egs-server-cert.pem"): fmt.Sprintf("root:egs 640 %s", filepath.Join(dedicatedTLSDir, "egs-server-cert.pem")),
		filepath.Join(dedicatedTLSDir, "egs-server-key.pem"):  fmt.Sprintf("root:egs 640 %s", filepath.Join(dedicatedTLSDir, "egs-server-key.pem")),
		filepath.Join(dedicatedTLSDir, "runtime-ca.pem"):      fmt.Sprintf("root:egs 640 %s", filepath.Join(dedicatedTLSDir, "runtime-ca.pem")),
	}

	setupFakeEGSHardeningCommands(
		t,
		fakeBin,
		unitPath,
		egsConfigPath,
		egsBinaryPath,
		agsBinaryPath,
		agsConfigPath,
		arsBinaryPath,
		arsConfigPath,
		"egs docker",
		"egs:x:993:",
		[]string{
			"egs:x:993:993::/nonexistent:/usr/sbin/nologin",
			"ds:x:1000:1000::/home/ds:/bin/zsh",
		},
		ownerships,
	)

	output, err := runSourcedEGSHardeningHelper(t, envWithPath(fakeBin,
		"REMOTE_ALPHA_SUMMARY_PATH="+summaryPath,
		"REMOTE_ALPHA_TEST_PASSWORDLESS_SUDO_FOR_DS=false",
	), egsHardeningExpectedSliceShell(egsBinaryPath, egsConfigPath, healthcheckEnvPath, unitPath, dropInDir, dropInPath, sourceTLSDir, dedicatedTLSDir, agsConfigPath, esConfigPath)+"remote_alpha_egs_hardening_main")
	if err == nil {
		t.Fatalf("expected broad pre-existing service account rejection, got success\n%s", output)
	}
	if !strings.Contains(string(output), "supplementary groups present: docker") {
		t.Fatalf("expected supplementary group rejection, got %q", output)
	}
}

func TestRemoteAlphaEGSHardeningRejectsPreexistingBroadServiceGroup(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	fakeBin := filepath.Join(tmpDir, "bin")
	if err := os.MkdirAll(fakeBin, 0o755); err != nil {
		t.Fatalf("mkdir fake bin: %v", err)
	}

	egsBinaryPath := filepath.Join(tmpDir, "fake-egs")
	if err := os.WriteFile(egsBinaryPath, []byte("binary"), 0o755); err != nil {
		t.Fatalf("write egs binary: %v", err)
	}
	agsBinaryPath := filepath.Join(tmpDir, "fake-ags")
	if err := os.WriteFile(agsBinaryPath, []byte("binary"), 0o755); err != nil {
		t.Fatalf("write ags binary: %v", err)
	}
	arsBinaryPath := filepath.Join(tmpDir, "fake-ars")
	if err := os.WriteFile(arsBinaryPath, []byte("binary"), 0o755); err != nil {
		t.Fatalf("write ars binary: %v", err)
	}

	sourceTLSDir := filepath.Join(tmpDir, "tls")
	if err := os.MkdirAll(sourceTLSDir, 0o755); err != nil {
		t.Fatalf("mkdir source tls dir: %v", err)
	}
	for _, name := range []string{
		"egs-server-cert.pem",
		"egs-server-key.pem",
		"runtime-ca.pem",
		"combined-service-ca-bundle.pem",
		"operator-client-cert.pem",
		"operator-client-key.pem",
	} {
		if err := os.WriteFile(filepath.Join(sourceTLSDir, name), []byte(name+"\n"), 0o600); err != nil {
			t.Fatalf("write tls file %s: %v", name, err)
		}
	}

	egsConfigPath := filepath.Join(tmpDir, "egs.json")
	if err := os.WriteFile(egsConfigPath, []byte(fmt.Sprintf(`{
  "http": {
    "bind_address": "127.0.0.1",
    "port": 8443
  },
  "publication": {
    "update_revision": 1,
    "version": "v1"
  },
  "runtime_trust": {
    "artifact_policy": {
      "revoked_artifacts": []
    },
    "signer_policy": {
      "allowed_signers": [
        "ags-key-1"
      ],
      "revoked_signers": []
    }
  },
  "security": {
    "bootstrap_issuer_common_name": "Bootstrap Root CA Example"
  },
  "signer": {
    "algorithm": "ed25519",
    "key_id": "egs-key-1",
    "private_key_hex": "3333333333333333333333333333333333333333333333333333333333333333",
    "public_key_hex": "17cb79fb2b4120f2b1ec65e4198d6e08b28e813feb01e4a400839b85e18080ce"
  },
  "tls": {
    "cert_file": %q,
    "client_ca_file": %q,
    "key_file": %q
  }
}
`,
		filepath.Join(sourceTLSDir, "egs-server-cert.pem"),
		filepath.Join(sourceTLSDir, "runtime-ca.pem"),
		filepath.Join(sourceTLSDir, "egs-server-key.pem"),
	)), 0o600); err != nil {
		t.Fatalf("write egs config: %v", err)
	}

	agsConfigPath := filepath.Join(tmpDir, "ags.json")
	if err := os.WriteFile(agsConfigPath, []byte(`{
  "http": {
    "bind_address": "192.168.1.156",
    "port": 8444
  }
}
`), 0o600); err != nil {
		t.Fatalf("write ags config: %v", err)
	}

	arsConfigPath := filepath.Join(tmpDir, "ars.json")
	if err := os.WriteFile(arsConfigPath, []byte(`{
  "http": {
    "bind_address": "127.0.0.1",
    "port": 8442
  }
}
`), 0o600); err != nil {
		t.Fatalf("write ars config: %v", err)
	}

	esConfigPath := filepath.Join(tmpDir, "es.json")
	if err := os.WriteFile(esConfigPath, []byte(`{
  "http": {
    "bind_address": "192.168.1.156",
    "port": 8445
  }
}
`), 0o600); err != nil {
		t.Fatalf("write es config: %v", err)
	}

	healthcheckEnvPath := filepath.Join(tmpDir, "healthcheck.env")
	if err := os.WriteFile(healthcheckEnvPath, []byte(strings.Join([]string{
		"CA_CERT=" + filepath.Join(sourceTLSDir, "combined-service-ca-bundle.pem"),
		"OPERATOR_CERT=" + filepath.Join(sourceTLSDir, "operator-client-cert.pem"),
		"OPERATOR_KEY=" + filepath.Join(sourceTLSDir, "operator-client-key.pem"),
		"",
	}, "\n")), 0o600); err != nil {
		t.Fatalf("write healthcheck env: %v", err)
	}

	unitPath := filepath.Join(tmpDir, "egs.service")
	if err := os.WriteFile(unitPath, []byte(fmt.Sprintf(`[Unit]
Description=Execution Substrate Execution Governance Service

[Service]
ExecStart=%s -config %s
`, egsBinaryPath, egsConfigPath)), 0o644); err != nil {
		t.Fatalf("write unit file: %v", err)
	}

	dropInDir := filepath.Join(tmpDir, "egs.service.d")
	dropInPath := filepath.Join(dropInDir, "10-account.conf")
	dedicatedTLSDir := filepath.Join(tmpDir, "egs-tls")
	summaryPath := filepath.Join(tmpDir, "egs-service-hardening-summary.json")

	ownerships := map[string]string{
		egsConfigPath:   fmt.Sprintf("root:egs 640 %s", egsConfigPath),
		dedicatedTLSDir: fmt.Sprintf("root:egs 710 %s", dedicatedTLSDir),
		filepath.Join(dedicatedTLSDir, "egs-server-cert.pem"): fmt.Sprintf("root:egs 640 %s", filepath.Join(dedicatedTLSDir, "egs-server-cert.pem")),
		filepath.Join(dedicatedTLSDir, "egs-server-key.pem"):  fmt.Sprintf("root:egs 640 %s", filepath.Join(dedicatedTLSDir, "egs-server-key.pem")),
		filepath.Join(dedicatedTLSDir, "runtime-ca.pem"):      fmt.Sprintf("root:egs 640 %s", filepath.Join(dedicatedTLSDir, "runtime-ca.pem")),
	}

	setupFakeEGSHardeningCommands(
		t,
		fakeBin,
		unitPath,
		egsConfigPath,
		egsBinaryPath,
		agsBinaryPath,
		agsConfigPath,
		arsBinaryPath,
		arsConfigPath,
		"egs",
		"egs:x:993:",
		[]string{
			"egs:x:993:993::/nonexistent:/usr/sbin/nologin",
			"intruder:x:994:993::/home/intruder:/bin/sh",
			"ds:x:1000:1000::/home/ds:/bin/zsh",
		},
		ownerships,
	)

	output, err := runSourcedEGSHardeningHelper(t, envWithPath(fakeBin,
		"REMOTE_ALPHA_SUMMARY_PATH="+summaryPath,
		"REMOTE_ALPHA_TEST_PASSWORDLESS_SUDO_FOR_DS=false",
	), egsHardeningExpectedSliceShell(egsBinaryPath, egsConfigPath, healthcheckEnvPath, unitPath, dropInDir, dropInPath, sourceTLSDir, dedicatedTLSDir, agsConfigPath, esConfigPath)+"remote_alpha_egs_hardening_main")
	if err == nil {
		t.Fatalf("expected broad pre-existing service group rejection, got success\n%s", output)
	}
	if !strings.Contains(string(output), "unexpected group members present: intruder") {
		t.Fatalf("expected unexpected group member rejection, got %q", output)
	}
}

func TestRemoteAlphaEGSHardeningRejectsSliceOverrideEnv(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name    string
		env     string
		snippet string
	}{
		{
			name:    "service name",
			env:     "REMOTE_ALPHA_SERVICE_NAME=es",
			snippet: "REMOTE_ALPHA_SERVICE_NAME",
		},
		{
			name:    "service user",
			env:     "REMOTE_ALPHA_SERVICE_USER=root",
			snippet: "REMOTE_ALPHA_SERVICE_USER",
		},
		{
			name:    "service group",
			env:     "REMOTE_ALPHA_SERVICE_GROUP=root",
			snippet: "REMOTE_ALPHA_SERVICE_GROUP",
		},
		{
			name:    "binary path",
			env:     "REMOTE_ALPHA_BINARY_PATH=/tmp/not-egs",
			snippet: "REMOTE_ALPHA_BINARY_PATH",
		},
		{
			name:    "config path",
			env:     "REMOTE_ALPHA_CONFIG_PATH=/tmp/not-egs.json",
			snippet: "REMOTE_ALPHA_CONFIG_PATH",
		},
		{
			name:    "healthcheck env path",
			env:     "REMOTE_ALPHA_HEALTHCHECK_ENV_PATH=/tmp/not-healthcheck.env",
			snippet: "REMOTE_ALPHA_HEALTHCHECK_ENV_PATH",
		},
		{
			name:    "service unit path",
			env:     "REMOTE_ALPHA_SERVICE_UNIT_PATH=/tmp/not-egs.service",
			snippet: "REMOTE_ALPHA_SERVICE_UNIT_PATH",
		},
		{
			name:    "service dropin dir",
			env:     "REMOTE_ALPHA_SERVICE_DROPIN_DIR=/tmp/not-egs.service.d",
			snippet: "REMOTE_ALPHA_SERVICE_DROPIN_DIR",
		},
		{
			name:    "service dropin path",
			env:     "REMOTE_ALPHA_SERVICE_DROPIN_PATH=/tmp/not-egs.service.d/50-not-egs.conf",
			snippet: "REMOTE_ALPHA_SERVICE_DROPIN_PATH",
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tmpDir := t.TempDir()
			fakeBin := filepath.Join(tmpDir, "bin")
			if err := os.MkdirAll(fakeBin, 0o755); err != nil {
				t.Fatalf("mkdir fake bin: %v", err)
			}

			output, err := runSourcedEGSHardeningHelper(t, envWithPath(fakeBin, tc.env), "remote_alpha_egs_hardening_main")
			if err == nil {
				t.Fatalf("expected slice override rejection for %s, got success\n%s", tc.name, output)
			}
			if !strings.Contains(string(output), tc.snippet) {
				t.Fatalf("expected output to mention %q, got %q", tc.snippet, output)
			}
		})
	}
}

func TestRemoteAlphaEGSHardeningRejectsSliceOverrideFlags(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name    string
		body    string
		snippet string
	}{
		{
			name:    "service name",
			body:    "remote_alpha_egs_hardening_main --service-name es",
			snippet: "--service-name",
		},
		{
			name:    "service user",
			body:    "remote_alpha_egs_hardening_main --service-user root",
			snippet: "--service-user",
		},
		{
			name:    "service group",
			body:    "remote_alpha_egs_hardening_main --service-group root",
			snippet: "--service-group",
		},
		{
			name:    "binary path",
			body:    "remote_alpha_egs_hardening_main --binary-path /tmp/not-egs",
			snippet: "--binary-path",
		},
		{
			name:    "config path",
			body:    "remote_alpha_egs_hardening_main --config-path /tmp/not-egs.json",
			snippet: "--config-path",
		},
		{
			name:    "healthcheck env path",
			body:    "remote_alpha_egs_hardening_main --healthcheck-env-path /tmp/not-healthcheck.env",
			snippet: "--healthcheck-env-path",
		},
		{
			name:    "service unit path",
			body:    "remote_alpha_egs_hardening_main --service-unit-path /tmp/not-egs.service",
			snippet: "--service-unit-path",
		},
		{
			name:    "service dropin dir",
			body:    "remote_alpha_egs_hardening_main --service-dropin-dir /tmp/not-egs.service.d",
			snippet: "--service-dropin-dir",
		},
		{
			name:    "service dropin path",
			body:    "remote_alpha_egs_hardening_main --service-dropin-path /tmp/not-egs.service.d/50-not-egs.conf",
			snippet: "--service-dropin-path",
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tmpDir := t.TempDir()
			fakeBin := filepath.Join(tmpDir, "bin")
			if err := os.MkdirAll(fakeBin, 0o755); err != nil {
				t.Fatalf("mkdir fake bin: %v", err)
			}

			output, err := runSourcedEGSHardeningHelper(t, envWithPath(fakeBin), tc.body)
			if err == nil {
				t.Fatalf("expected slice flag rejection for %s, got success\n%s", tc.name, output)
			}
			if !strings.Contains(string(output), tc.snippet) {
				t.Fatalf("expected output to mention %q, got %q", tc.snippet, output)
			}
		})
	}
}

func TestRemoteAlphaEGSHardeningRequiresRoot(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	fakeBin := filepath.Join(tmpDir, "bin")
	if err := os.MkdirAll(fakeBin, 0o755); err != nil {
		t.Fatalf("mkdir fake bin: %v", err)
	}

	writeExecutable(t, fakeBin, "id", `#!/bin/sh
if [ "$1" = "-u" ]; then
  echo 1000
  exit 0
fi
exec /usr/bin/id "$@"
`)

	output, err := runSourcedEGSHardeningHelper(t, envWithPath(fakeBin), "remote_alpha_egs_hardening_require_root")
	if err == nil {
		t.Fatalf("expected root requirement failure, got success\n%s", output)
	}
	if !strings.Contains(string(output), "must run as root") {
		t.Fatalf("expected root failure message, got %q", output)
	}
}
