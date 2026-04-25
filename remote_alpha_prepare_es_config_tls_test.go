package executionsubstrate_test

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func runSourcedESConfigTLSPrepHelper(t *testing.T, env []string, shellBody string) ([]byte, error) {
	t.Helper()
	helperPath := filepath.Join(executionSubstrateRepoRoot, "scripts", "internal", "remote_alpha_prepare_es_config_tls.sh")
	script := fmt.Sprintf("set -euo pipefail\nsource %q\n%s\n", helperPath, shellBody)
	cmd := exec.Command("/bin/bash", "-c", script)
	cmd.Dir = executionSubstrateRepoRoot
	cmd.Env = env
	return cmd.CombinedOutput()
}

func setupFakeESConfigTLSPrepCommands(t *testing.T, dir, esUnitPath, esConfigPath, esBinaryPath, agsBinaryPath, agsConfigPath, arsBinaryPath, arsConfigPath, egsBinaryPath, egsConfigPath, esGroups string, ownerships map[string]string) {
	t.Helper()

	writeExecutable(t, dir, "id", fmt.Sprintf(`#!/bin/sh
if [ "$1" = "-u" ] && [ $# -eq 1 ]; then
  echo 0
  exit 0
fi
if [ "$1" = "-u" ] && [ "$2" = "es" ]; then
  echo 994
  exit 0
fi
if [ "$1" = "-gn" ] && [ "$2" = "es" ]; then
  echo es
  exit 0
fi
if [ "$1" = "-nG" ] && [ "$2" = "es" ]; then
  echo %q
  exit 0
fi
if [ "$1" = "-nG" ] && [ "$2" = "ds" ]; then
  echo "ds adm wheel"
  exit 0
fi
exec /usr/bin/id "$@"
`, esGroups))
	writeExecutable(t, dir, "getent", `#!/bin/sh
if [ "$1" = "group" ] && [ "$2" = "es" ]; then
  echo "es:x:994:"
  exit 0
fi
if [ "$1" = "passwd" ]; then
  cat <<'EOF'
root:x:0:0:root:/root:/bin/bash
es:x:994:994::/nonexistent:/usr/sbin/nologin
EOF
  exit 0
fi
exit 2
`)
	writeExecutable(t, dir, "groupadd", "#!/bin/sh\nexit 0\n")
	writeExecutable(t, dir, "useradd", "#!/bin/sh\nexit 0\n")
	writeExecutable(t, dir, "chown", "#!/bin/sh\nexit 0\n")
	writeExecutable(t, dir, "chmod", "#!/bin/sh\nexit 0\n")
	writeExecutable(t, dir, "systemctl", fmt.Sprintf(`#!/bin/sh
case "$1" in
  restart)
    exit 0
    ;;
  is-enabled)
    exit 0
    ;;
  show)
    service="$2"
    case "$service" in
      es.service)
        cat <<'EOF'
User=
Group=
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
      egs.service)
        cat <<'EOF'
User=egs
Group=egs
ExecStart={ path=%s ; argv[]=%s -config %s ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }
FragmentPath=/etc/systemd/system/egs.service
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
`, esBinaryPath, esBinaryPath, esConfigPath, esUnitPath, agsBinaryPath, agsBinaryPath, agsConfigPath, arsBinaryPath, arsBinaryPath, arsConfigPath, egsBinaryPath, egsBinaryPath, egsConfigPath))
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

func esConfigTLSPrepExpectedSliceShell(binaryPath, configPath, healthcheckEnvPath, unitPath, tlsDir string) string {
	return fmt.Sprintf(`
remote_alpha_es_config_tls_prep_expected_binary_path=%q
remote_alpha_es_config_tls_prep_expected_config_path=%q
remote_alpha_es_config_tls_prep_expected_healthcheck_env_path=%q
remote_alpha_es_config_tls_prep_expected_service_unit_path=%q
remote_alpha_es_config_tls_prep_expected_tls_dir=%q
`, binaryPath, configPath, healthcheckEnvPath, unitPath, tlsDir)
}

func TestRemoteAlphaESConfigTLSPrepPassWritesSummaryAndRewritesConfig(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	fakeBin := filepath.Join(tmpDir, "bin")
	if err := os.MkdirAll(fakeBin, 0o755); err != nil {
		t.Fatalf("mkdir fake bin: %v", err)
	}

	esBinaryPath := filepath.Join(tmpDir, "fake-es")
	if err := os.WriteFile(esBinaryPath, []byte("binary"), 0o755); err != nil {
		t.Fatalf("write es binary: %v", err)
	}
	agsBinaryPath := filepath.Join(tmpDir, "fake-ags")
	if err := os.WriteFile(agsBinaryPath, []byte("binary"), 0o755); err != nil {
		t.Fatalf("write ags binary: %v", err)
	}
	arsBinaryPath := filepath.Join(tmpDir, "fake-ars")
	if err := os.WriteFile(arsBinaryPath, []byte("binary"), 0o755); err != nil {
		t.Fatalf("write ars binary: %v", err)
	}
	egsBinaryPath := filepath.Join(tmpDir, "fake-egs")
	if err := os.WriteFile(egsBinaryPath, []byte("binary"), 0o755); err != nil {
		t.Fatalf("write egs binary: %v", err)
	}

	sourceTLSDir := filepath.Join(tmpDir, "tls")
	if err := os.MkdirAll(sourceTLSDir, 0o755); err != nil {
		t.Fatalf("mkdir source tls dir: %v", err)
	}
	for _, name := range []string{
		"es-server-cert.pem",
		"es-server-key.pem",
		"es-client-cert.pem",
		"es-client-key.pem",
		"runtime-ca.pem",
		"combined-service-ca-bundle.pem",
		"operator-client-cert.pem",
		"operator-client-key.pem",
	} {
		if err := os.WriteFile(filepath.Join(sourceTLSDir, name), []byte(name+"\n"), 0o600); err != nil {
			t.Fatalf("write tls file %s: %v", name, err)
		}
	}

	esConfigPath := filepath.Join(tmpDir, "es.json")
	if err := os.WriteFile(esConfigPath, []byte(fmt.Sprintf(`{
  "authorization": {
    "allowed_spiffe_path_prefixes": [
      "operator"
    ]
  },
  "dependencies": {
    "artifact_registry": {
      "base_url": "https://127.0.0.1:8442",
      "client_cert_file": %q,
      "client_key_file": %q,
      "root_ca_file": %q,
      "server_name": "server.artifact-registry.internal",
      "timeout_seconds": 5
    },
    "execution_governance": {
      "base_url": "https://127.0.0.1:8443",
      "client_cert_file": %q,
      "client_key_file": %q,
      "root_ca_file": %q,
      "server_name": "server.execution-governance.internal",
      "timeout_seconds": 5
    }
  },
  "execution": {
    "base_image": "alpine:3.20",
    "results_root_dir": "/var/lib/execution-substrate/es-results",
    "runtime_support_binary": "/usr/local/bin/es-runtime-support",
    "spire_workload_api_socket_path": "/run/spire/sockets/agent.sock",
    "staging_root_dir": "/var/lib/execution-substrate/es-staging"
  },
  "http": {
    "bind_address": "192.168.1.156",
    "port": 8445
  },
  "nomad": {
    "base_url": "http://127.0.0.1:4646",
    "datacenter": "dc1",
    "timeout_seconds": 5
  },
  "runtime_config": {
    "workload_zone_vault_config_ref": {
      "digest": "sha256:test-workload-zone-config"
    }
  },
  "security": {
    "bootstrap_issuer_common_name": "Bootstrap Root CA Example"
  },
  "tls": {
    "cert_file": %q,
    "client_ca_file": %q,
    "key_file": %q
  },
  "verification": {
    "derivation_attestation": {
      "algorithm": "ed25519",
      "key_id": "ags-key-1",
      "public_key_hex": "d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737"
    },
    "provenance": {
      "algorithm": "ed25519",
      "key_id": "ags-key-1",
      "public_key_hex": "d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737"
    },
    "trust_model": {
      "algorithm": "ed25519",
      "key_id": "egs-key-1",
      "public_key_hex": "17cb79fb2b4120f2b1ec65e4198d6e08b28e813feb01e4a400839b85e18080ce"
    },
    "workload_identity_binding": {
      "algorithm": "ed25519",
      "key_id": "ags-key-1",
      "public_key_hex": "d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737"
    }
  },
  "workload_vault_auth": {
    "default_mode": "vault_identity_jwt"
  }
}
`,
		filepath.Join(sourceTLSDir, "es-client-cert.pem"),
		filepath.Join(sourceTLSDir, "es-client-key.pem"),
		filepath.Join(sourceTLSDir, "runtime-ca.pem"),
		filepath.Join(sourceTLSDir, "es-client-cert.pem"),
		filepath.Join(sourceTLSDir, "es-client-key.pem"),
		filepath.Join(sourceTLSDir, "runtime-ca.pem"),
		filepath.Join(sourceTLSDir, "es-server-cert.pem"),
		filepath.Join(sourceTLSDir, "runtime-ca.pem"),
		filepath.Join(sourceTLSDir, "es-server-key.pem"),
	)), 0o600); err != nil {
		t.Fatalf("write es config: %v", err)
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

	egsConfigPath := filepath.Join(tmpDir, "egs.json")
	if err := os.WriteFile(egsConfigPath, []byte(`{
  "http": {
    "bind_address": "127.0.0.1",
    "port": 8443
  }
}
`), 0o600); err != nil {
		t.Fatalf("write egs config: %v", err)
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

	unitPath := filepath.Join(tmpDir, "es.service")
	if err := os.WriteFile(unitPath, []byte(fmt.Sprintf(`[Unit]
Description=Execution Substrate Execution Service

[Service]
ExecStart=%s -config %s
`, esBinaryPath, esConfigPath)), 0o644); err != nil {
		t.Fatalf("write unit file: %v", err)
	}

	dedicatedTLSDir := filepath.Join(tmpDir, "es-tls")
	summaryPath := filepath.Join(tmpDir, "es-config-tls-prep-summary.json")

	ownerships := map[string]string{
		esConfigPath:    fmt.Sprintf("root:es 640 %s", esConfigPath),
		dedicatedTLSDir: fmt.Sprintf("root:es 710 %s", dedicatedTLSDir),
		filepath.Join(dedicatedTLSDir, "es-server-cert.pem"):                   fmt.Sprintf("root:es 640 %s", filepath.Join(dedicatedTLSDir, "es-server-cert.pem")),
		filepath.Join(dedicatedTLSDir, "es-server-key.pem"):                    fmt.Sprintf("root:es 640 %s", filepath.Join(dedicatedTLSDir, "es-server-key.pem")),
		filepath.Join(dedicatedTLSDir, "server-client-ca.pem"):                 fmt.Sprintf("root:es 640 %s", filepath.Join(dedicatedTLSDir, "server-client-ca.pem")),
		filepath.Join(dedicatedTLSDir, "artifact-registry-client-cert.pem"):    fmt.Sprintf("root:es 640 %s", filepath.Join(dedicatedTLSDir, "artifact-registry-client-cert.pem")),
		filepath.Join(dedicatedTLSDir, "artifact-registry-client-key.pem"):     fmt.Sprintf("root:es 640 %s", filepath.Join(dedicatedTLSDir, "artifact-registry-client-key.pem")),
		filepath.Join(dedicatedTLSDir, "artifact-registry-root-ca.pem"):        fmt.Sprintf("root:es 640 %s", filepath.Join(dedicatedTLSDir, "artifact-registry-root-ca.pem")),
		filepath.Join(dedicatedTLSDir, "execution-governance-client-cert.pem"): fmt.Sprintf("root:es 640 %s", filepath.Join(dedicatedTLSDir, "execution-governance-client-cert.pem")),
		filepath.Join(dedicatedTLSDir, "execution-governance-client-key.pem"):  fmt.Sprintf("root:es 640 %s", filepath.Join(dedicatedTLSDir, "execution-governance-client-key.pem")),
		filepath.Join(dedicatedTLSDir, "execution-governance-root-ca.pem"):     fmt.Sprintf("root:es 640 %s", filepath.Join(dedicatedTLSDir, "execution-governance-root-ca.pem")),
	}

	setupFakeESConfigTLSPrepCommands(t, fakeBin, unitPath, esConfigPath, esBinaryPath, agsBinaryPath, agsConfigPath, arsBinaryPath, arsConfigPath, egsBinaryPath, egsConfigPath, "es", ownerships)

	output, err := runSourcedESConfigTLSPrepHelper(t, envWithPath(fakeBin,
		"REMOTE_ALPHA_SUMMARY_PATH="+summaryPath,
		"REMOTE_ALPHA_TEST_PASSWORDLESS_SUDO_FOR_DS=false",
	), esConfigTLSPrepExpectedSliceShell(esBinaryPath, esConfigPath, healthcheckEnvPath, unitPath, dedicatedTLSDir)+"remote_alpha_es_config_tls_prep_main")
	if err != nil {
		t.Fatalf("ES config/TLS prep helper failed: %v\n%s", err, output)
	}

	if got := strings.TrimSpace(string(output)); got != summaryPath {
		t.Fatalf("unexpected summary path output %q", got)
	}

	rewrittenConfig := mustRead(t, esConfigPath)
	for _, expected := range []string{
		filepath.Join(dedicatedTLSDir, "es-server-cert.pem"),
		filepath.Join(dedicatedTLSDir, "es-server-key.pem"),
		filepath.Join(dedicatedTLSDir, "server-client-ca.pem"),
		filepath.Join(dedicatedTLSDir, "artifact-registry-client-cert.pem"),
		filepath.Join(dedicatedTLSDir, "artifact-registry-client-key.pem"),
		filepath.Join(dedicatedTLSDir, "artifact-registry-root-ca.pem"),
		filepath.Join(dedicatedTLSDir, "execution-governance-client-cert.pem"),
		filepath.Join(dedicatedTLSDir, "execution-governance-client-key.pem"),
		filepath.Join(dedicatedTLSDir, "execution-governance-root-ca.pem"),
		"/var/lib/execution-substrate/es-staging",
		"/var/lib/execution-substrate/es-results",
		"/run/spire/sockets/agent.sock",
	} {
		if !strings.Contains(rewrittenConfig, expected) {
			t.Fatalf("rewritten config missing %q: %q", expected, rewrittenConfig)
		}
	}

	summary := readJSONFile(t, summaryPath)
	if got := summary["schema_version"]; got != "execution-substrate.remote-alpha.es-config-tls-prep-summary.v1" {
		t.Fatalf("unexpected schema version %v", got)
	}

	slice := jsonMap(t, summary["slice"])
	if got := slice["classification"]; got != "ownership_prep_slice" {
		t.Fatalf("unexpected slice classification %v", got)
	}
	if got := slice["not_a_new_happy_path_proof"]; got != true {
		t.Fatalf("expected prep slice to avoid happy-path proof claim, got %v", got)
	}

	service := jsonMap(t, summary["service"])
	if got := service["live_user"]; got != "root(default)" {
		t.Fatalf("unexpected ES live user %v", got)
	}
	if got := service["live_group"]; got != "root(default)" {
		t.Fatalf("unexpected ES live group %v", got)
	}
	if got := service["binary_path"]; got != esBinaryPath {
		t.Fatalf("unexpected binary path %v", got)
	}
	if got := service["config_path"]; got != esConfigPath {
		t.Fatalf("unexpected config path %v", got)
	}

	dependencies := jsonMap(t, summary["dependencies"])
	serverTLS := jsonMap(t, dependencies["server_tls"])
	if got := serverTLS["cert_file"]; got != filepath.Join(dedicatedTLSDir, "es-server-cert.pem") {
		t.Fatalf("unexpected server cert path %v", got)
	}
	artifactRegistry := jsonMap(t, dependencies["artifact_registry"])
	if got := artifactRegistry["client_cert_file"]; got != filepath.Join(dedicatedTLSDir, "artifact-registry-client-cert.pem") {
		t.Fatalf("unexpected artifact registry client cert %v", got)
	}
	executionGovernance := jsonMap(t, dependencies["execution_governance"])
	if got := executionGovernance["client_key_file"]; got != filepath.Join(dedicatedTLSDir, "execution-governance-client-key.pem") {
		t.Fatalf("unexpected execution governance client key %v", got)
	}
	localStatePaths := jsonMap(t, dependencies["local_state_paths"])
	if got := localStatePaths["staging_root_dir"]; got != "/var/lib/execution-substrate/es-staging" {
		t.Fatalf("unexpected staging root %v", got)
	}
	if got := localStatePaths["results_root_dir"]; got != "/var/lib/execution-substrate/es-results" {
		t.Fatalf("unexpected results root %v", got)
	}
	if got := localStatePaths["spire_workload_api_socket_path"]; got != "/run/spire/sockets/agent.sock" {
		t.Fatalf("unexpected spire socket path %v", got)
	}

	ownership := jsonMap(t, summary["ownership_model"])
	prepAccount := jsonMap(t, ownership["prep_account"])
	if got := prepAccount["primary_group"]; got != "es" {
		t.Fatalf("unexpected prep account primary group %v", got)
	}
	if got := prepAccount["narrow_dedicated_account"]; got != true {
		t.Fatalf("unexpected prep account narrowness %v", got)
	}
	if got := jsonStringSlice(t, prepAccount["supplementary_groups"]); len(got) != 0 {
		t.Fatalf("expected no supplementary groups, got %v", got)
	}
	configOwnership := jsonMap(t, ownership["config_file"])
	if got := configOwnership["owner"]; got != "root:es" {
		t.Fatalf("unexpected config ownership %v", got)
	}
	liveServicePosture := jsonMap(t, ownership["live_service_posture"])
	if got := liveServicePosture["unchanged_root_default"]; got != true {
		t.Fatalf("unexpected live service posture %v", got)
	}
	writableState := jsonMap(t, ownership["writable_state"])
	if got := writableState["changed"]; got != false {
		t.Fatalf("unexpected writable state change flag %v", got)
	}

	validation := jsonMap(t, summary["validation"])
	localESHealth := jsonMap(t, validation["local_es_health"])
	if got := localESHealth["status"]; got != "pass" {
		t.Fatalf("unexpected local ES health status %v", got)
	}
	localESContract := jsonMap(t, validation["local_es_contract_probe"])
	if got := localESContract["status"]; got != "pass" {
		t.Fatalf("unexpected local ES contract status %v", got)
	}
	prepAccountNarrowness := jsonMap(t, validation["prep_account_narrowness"])
	if got := prepAccountNarrowness["status"]; got != "pass" {
		t.Fatalf("unexpected prep account narrowness status %v", got)
	}
	ownershipValidation := jsonMap(t, validation["ownership"])
	if got := ownershipValidation["status"]; got != "pass" {
		t.Fatalf("unexpected ownership validation status %v", got)
	}
	rewriteScope := jsonMap(t, validation["config_rewrite_scope"])
	if got := rewriteScope["status"]; got != "pass" {
		t.Fatalf("unexpected rewrite scope status %v", got)
	}
	if got := jsonStringSlice(t, rewriteScope["unexpected_paths"]); len(got) != 0 {
		t.Fatalf("expected no unexpected rewrite paths, got %v", got)
	}
	esPosture := jsonMap(t, validation["es_service_posture"])
	if got := esPosture["effective_user"]; got != "root(default)" {
		t.Fatalf("unexpected es posture %v", got)
	}
	agsPosture := jsonMap(t, validation["ags_service_posture"])
	if got := agsPosture["effective_user"]; got != "ags" {
		t.Fatalf("unexpected ags posture %v", got)
	}
	arsPosture := jsonMap(t, validation["ars_service_posture"])
	if got := arsPosture["effective_user"]; got != "ars" {
		t.Fatalf("unexpected ars posture %v", got)
	}
	egsPosture := jsonMap(t, validation["egs_service_posture"])
	if got := egsPosture["effective_user"]; got != "egs" {
		t.Fatalf("unexpected egs posture %v", got)
	}

	preserved := jsonMap(t, summary["preserved_remote_path"])
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
	noSharedFilesystem := jsonMap(t, preserved["no_shared_filesystem"])
	if got := noSharedFilesystem["status"]; got != "operator_assertion" {
		t.Fatalf("unexpected no_shared_filesystem status %v", got)
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

	notClaimed := jsonMap(t, summary["not_claimed"])
	if got := notClaimed["es_de_root"]; got != "not_claimed" {
		t.Fatalf("unexpected es_de_root claim %v", got)
	}
	if got := notClaimed["staging_or_results_ownership_changes"]; got != "not_claimed" {
		t.Fatalf("unexpected staging/results claim %v", got)
	}
}

func TestRemoteAlphaESConfigTLSPrepRejectsPreexistingBroadPrepAccount(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	fakeBin := filepath.Join(tmpDir, "bin")
	if err := os.MkdirAll(fakeBin, 0o755); err != nil {
		t.Fatalf("mkdir fake bin: %v", err)
	}

	esBinaryPath := filepath.Join(tmpDir, "fake-es")
	if err := os.WriteFile(esBinaryPath, []byte("binary"), 0o755); err != nil {
		t.Fatalf("write es binary: %v", err)
	}
	agsBinaryPath := filepath.Join(tmpDir, "fake-ags")
	if err := os.WriteFile(agsBinaryPath, []byte("binary"), 0o755); err != nil {
		t.Fatalf("write ags binary: %v", err)
	}
	arsBinaryPath := filepath.Join(tmpDir, "fake-ars")
	if err := os.WriteFile(arsBinaryPath, []byte("binary"), 0o755); err != nil {
		t.Fatalf("write ars binary: %v", err)
	}
	egsBinaryPath := filepath.Join(tmpDir, "fake-egs")
	if err := os.WriteFile(egsBinaryPath, []byte("binary"), 0o755); err != nil {
		t.Fatalf("write egs binary: %v", err)
	}

	sourceTLSDir := filepath.Join(tmpDir, "tls")
	if err := os.MkdirAll(sourceTLSDir, 0o755); err != nil {
		t.Fatalf("mkdir source tls dir: %v", err)
	}
	for _, name := range []string{
		"es-server-cert.pem",
		"es-server-key.pem",
		"es-client-cert.pem",
		"es-client-key.pem",
		"runtime-ca.pem",
		"combined-service-ca-bundle.pem",
		"operator-client-cert.pem",
		"operator-client-key.pem",
	} {
		if err := os.WriteFile(filepath.Join(sourceTLSDir, name), []byte(name+"\n"), 0o600); err != nil {
			t.Fatalf("write tls file %s: %v", name, err)
		}
	}

	esConfigPath := filepath.Join(tmpDir, "es.json")
	if err := os.WriteFile(esConfigPath, []byte(fmt.Sprintf(`{
  "dependencies": {
    "artifact_registry": {
      "base_url": "https://127.0.0.1:8442",
      "client_cert_file": %q,
      "client_key_file": %q,
      "root_ca_file": %q
    },
    "execution_governance": {
      "base_url": "https://127.0.0.1:8443",
      "client_cert_file": %q,
      "client_key_file": %q,
      "root_ca_file": %q
    }
  },
  "execution": {
    "results_root_dir": "/var/lib/execution-substrate/es-results",
    "spire_workload_api_socket_path": "/run/spire/sockets/agent.sock",
    "staging_root_dir": "/var/lib/execution-substrate/es-staging"
  },
  "http": {
    "bind_address": "192.168.1.156",
    "port": 8445
  },
  "tls": {
    "cert_file": %q,
    "client_ca_file": %q,
    "key_file": %q
  }
}
`,
		filepath.Join(sourceTLSDir, "es-client-cert.pem"),
		filepath.Join(sourceTLSDir, "es-client-key.pem"),
		filepath.Join(sourceTLSDir, "runtime-ca.pem"),
		filepath.Join(sourceTLSDir, "es-client-cert.pem"),
		filepath.Join(sourceTLSDir, "es-client-key.pem"),
		filepath.Join(sourceTLSDir, "runtime-ca.pem"),
		filepath.Join(sourceTLSDir, "es-server-cert.pem"),
		filepath.Join(sourceTLSDir, "runtime-ca.pem"),
		filepath.Join(sourceTLSDir, "es-server-key.pem"),
	)), 0o600); err != nil {
		t.Fatalf("write es config: %v", err)
	}

	agsConfigPath := filepath.Join(tmpDir, "ags.json")
	if err := os.WriteFile(agsConfigPath, []byte(`{"http":{"bind_address":"192.168.1.156","port":8444}}`), 0o600); err != nil {
		t.Fatalf("write ags config: %v", err)
	}
	arsConfigPath := filepath.Join(tmpDir, "ars.json")
	if err := os.WriteFile(arsConfigPath, []byte(`{"http":{"bind_address":"127.0.0.1","port":8442}}`), 0o600); err != nil {
		t.Fatalf("write ars config: %v", err)
	}
	egsConfigPath := filepath.Join(tmpDir, "egs.json")
	if err := os.WriteFile(egsConfigPath, []byte(`{"http":{"bind_address":"127.0.0.1","port":8443}}`), 0o600); err != nil {
		t.Fatalf("write egs config: %v", err)
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
	unitPath := filepath.Join(tmpDir, "es.service")
	if err := os.WriteFile(unitPath, []byte(fmt.Sprintf("[Service]\nExecStart=%s -config %s\n", esBinaryPath, esConfigPath)), 0o644); err != nil {
		t.Fatalf("write unit file: %v", err)
	}

	dedicatedTLSDir := filepath.Join(tmpDir, "es-tls")
	summaryPath := filepath.Join(tmpDir, "es-config-tls-prep-summary.json")
	ownerships := map[string]string{
		esConfigPath:    fmt.Sprintf("root:es 640 %s", esConfigPath),
		dedicatedTLSDir: fmt.Sprintf("root:es 710 %s", dedicatedTLSDir),
		filepath.Join(dedicatedTLSDir, "es-server-cert.pem"):                   fmt.Sprintf("root:es 640 %s", filepath.Join(dedicatedTLSDir, "es-server-cert.pem")),
		filepath.Join(dedicatedTLSDir, "es-server-key.pem"):                    fmt.Sprintf("root:es 640 %s", filepath.Join(dedicatedTLSDir, "es-server-key.pem")),
		filepath.Join(dedicatedTLSDir, "server-client-ca.pem"):                 fmt.Sprintf("root:es 640 %s", filepath.Join(dedicatedTLSDir, "server-client-ca.pem")),
		filepath.Join(dedicatedTLSDir, "artifact-registry-client-cert.pem"):    fmt.Sprintf("root:es 640 %s", filepath.Join(dedicatedTLSDir, "artifact-registry-client-cert.pem")),
		filepath.Join(dedicatedTLSDir, "artifact-registry-client-key.pem"):     fmt.Sprintf("root:es 640 %s", filepath.Join(dedicatedTLSDir, "artifact-registry-client-key.pem")),
		filepath.Join(dedicatedTLSDir, "artifact-registry-root-ca.pem"):        fmt.Sprintf("root:es 640 %s", filepath.Join(dedicatedTLSDir, "artifact-registry-root-ca.pem")),
		filepath.Join(dedicatedTLSDir, "execution-governance-client-cert.pem"): fmt.Sprintf("root:es 640 %s", filepath.Join(dedicatedTLSDir, "execution-governance-client-cert.pem")),
		filepath.Join(dedicatedTLSDir, "execution-governance-client-key.pem"):  fmt.Sprintf("root:es 640 %s", filepath.Join(dedicatedTLSDir, "execution-governance-client-key.pem")),
		filepath.Join(dedicatedTLSDir, "execution-governance-root-ca.pem"):     fmt.Sprintf("root:es 640 %s", filepath.Join(dedicatedTLSDir, "execution-governance-root-ca.pem")),
	}

	setupFakeESConfigTLSPrepCommands(t, fakeBin, unitPath, esConfigPath, esBinaryPath, agsBinaryPath, agsConfigPath, arsBinaryPath, arsConfigPath, egsBinaryPath, egsConfigPath, "es docker", ownerships)

	output, err := runSourcedESConfigTLSPrepHelper(t, envWithPath(fakeBin,
		"REMOTE_ALPHA_SUMMARY_PATH="+summaryPath,
		"REMOTE_ALPHA_TEST_PASSWORDLESS_SUDO_FOR_DS=false",
	), esConfigTLSPrepExpectedSliceShell(esBinaryPath, esConfigPath, healthcheckEnvPath, unitPath, dedicatedTLSDir)+"remote_alpha_es_config_tls_prep_main")
	if err == nil {
		t.Fatalf("expected broad pre-existing prep account rejection, got success\n%s", output)
	}
	if !strings.Contains(string(output), "supplementary groups present: docker") {
		t.Fatalf("expected supplementary group rejection, got %q", output)
	}
}

func TestRemoteAlphaESConfigTLSPrepRejectsSliceOverrideEnv(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name    string
		env     string
		snippet string
	}{
		{
			name:    "service name",
			env:     "REMOTE_ALPHA_SERVICE_NAME=other",
			snippet: "REMOTE_ALPHA_SERVICE_NAME",
		},
		{
			name:    "prep user",
			env:     "REMOTE_ALPHA_PREP_USER=root",
			snippet: "REMOTE_ALPHA_PREP_USER",
		},
		{
			name:    "prep group",
			env:     "REMOTE_ALPHA_PREP_GROUP=root",
			snippet: "REMOTE_ALPHA_PREP_GROUP",
		},
		{
			name:    "binary path",
			env:     "REMOTE_ALPHA_BINARY_PATH=/tmp/not-es",
			snippet: "REMOTE_ALPHA_BINARY_PATH",
		},
		{
			name:    "config path",
			env:     "REMOTE_ALPHA_CONFIG_PATH=/tmp/not-es.json",
			snippet: "REMOTE_ALPHA_CONFIG_PATH",
		},
		{
			name:    "healthcheck env path",
			env:     "REMOTE_ALPHA_HEALTHCHECK_ENV_PATH=/tmp/not-healthcheck.env",
			snippet: "REMOTE_ALPHA_HEALTHCHECK_ENV_PATH",
		},
		{
			name:    "service unit path",
			env:     "REMOTE_ALPHA_SERVICE_UNIT_PATH=/tmp/not-es.service",
			snippet: "REMOTE_ALPHA_SERVICE_UNIT_PATH",
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

			output, err := runSourcedESConfigTLSPrepHelper(t, envWithPath(fakeBin, tc.env), "remote_alpha_es_config_tls_prep_main")
			if err == nil {
				t.Fatalf("expected slice override rejection for %s, got success\n%s", tc.name, output)
			}
			if !strings.Contains(string(output), tc.snippet) {
				t.Fatalf("expected output to mention %q, got %q", tc.snippet, output)
			}
		})
	}
}

func TestRemoteAlphaESConfigTLSPrepRejectsSliceOverrideFlags(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name    string
		body    string
		snippet string
	}{
		{
			name:    "service name",
			body:    "remote_alpha_es_config_tls_prep_main --service-name other",
			snippet: "--service-name",
		},
		{
			name:    "prep user",
			body:    "remote_alpha_es_config_tls_prep_main --prep-user root",
			snippet: "--prep-user",
		},
		{
			name:    "prep group",
			body:    "remote_alpha_es_config_tls_prep_main --prep-group root",
			snippet: "--prep-group",
		},
		{
			name:    "binary path",
			body:    "remote_alpha_es_config_tls_prep_main --binary-path /tmp/not-es",
			snippet: "--binary-path",
		},
		{
			name:    "config path",
			body:    "remote_alpha_es_config_tls_prep_main --config-path /tmp/not-es.json",
			snippet: "--config-path",
		},
		{
			name:    "healthcheck env path",
			body:    "remote_alpha_es_config_tls_prep_main --healthcheck-env-path /tmp/not-healthcheck.env",
			snippet: "--healthcheck-env-path",
		},
		{
			name:    "service unit path",
			body:    "remote_alpha_es_config_tls_prep_main --service-unit-path /tmp/not-es.service",
			snippet: "--service-unit-path",
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

			output, err := runSourcedESConfigTLSPrepHelper(t, envWithPath(fakeBin), tc.body)
			if err == nil {
				t.Fatalf("expected slice flag rejection for %s, got success\n%s", tc.name, output)
			}
			if !strings.Contains(string(output), tc.snippet) {
				t.Fatalf("expected output to mention %q, got %q", tc.snippet, output)
			}
		})
	}
}

func TestRemoteAlphaESConfigTLSPrepRequiresRoot(t *testing.T) {
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

	output, err := runSourcedESConfigTLSPrepHelper(t, envWithPath(fakeBin), "remote_alpha_es_config_tls_prep_require_root")
	if err == nil {
		t.Fatalf("expected root requirement failure, got success\n%s", output)
	}
	if !strings.Contains(string(output), "must run as root") {
		t.Fatalf("expected root failure message, got %q", output)
	}
}
