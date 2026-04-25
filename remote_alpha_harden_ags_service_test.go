package executionsubstrate_test

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func runSourcedAGSHardeningHelper(t *testing.T, env []string, shellBody string) ([]byte, error) {
	t.Helper()
	helperPath := filepath.Join(executionSubstrateRepoRoot, "scripts", "internal", "remote_alpha_harden_ags_service.sh")
	script := fmt.Sprintf("set -euo pipefail\nsource %q\n%s\n", helperPath, shellBody)
	cmd := exec.Command("/bin/bash", "-c", script)
	cmd.Dir = executionSubstrateRepoRoot
	cmd.Env = env
	return cmd.CombinedOutput()
}

func setupFakeAGSHardeningCommands(t *testing.T, dir string, unitPath, configPath, binaryPath string) {
	t.Helper()

	writeExecutable(t, dir, "id", fmt.Sprintf(`#!/bin/sh
if [ "$1" = "-u" ] && [ $# -eq 1 ]; then
  echo 0
  exit 0
fi
if [ "$1" = "-u" ] && [ "$2" = "ags" ]; then
  echo 991
  exit 0
fi
if [ "$1" = "-gn" ] && [ "$2" = "ags" ]; then
  echo ags
  exit 0
fi
if [ "$1" = "-nG" ] && [ "$2" = "ds" ]; then
  echo "ds adm wheel"
  exit 0
fi
exec /usr/bin/id "$@"
`))
	writeExecutable(t, dir, "getent", `#!/bin/sh
if [ "$1" = "group" ] && [ "$2" = "ags" ]; then
  echo "ags:x:991:"
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
      ags.service)
        cat <<'EOF'
User=ags
Group=ags
ExecStart={ path=%s ; argv[]=%s -config %s ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }
FragmentPath=%s
ActiveState=active
SubState=running
EOF
        ;;
      ars.service|egs.service|es.service)
        cat <<'EOF'
User=
Group=
ExecStart={ path=/tmp/fake-service ; argv[]=/tmp/fake-service ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }
FragmentPath=/etc/systemd/system/fake.service
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
`, binaryPath, binaryPath, configPath, unitPath))
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
  */health)
    cat <<'EOF'
{"status":"healthy","ready":true,"service":"artifact-governance","additional_properties":{"dependencies":{"artifact_registry":"healthy"}}}
EOF
    ;;
  */v1/artifacts:publish)
    cat <<'EOF'
{"published":true,"artifact_digest":"sha256:test-artifact"}
EOF
    ;;
  *)
    echo "unexpected curl url: $url" >&2
    exit 1
    ;;
esac
`)
}

func agsHardeningExpectedSliceShell(binaryPath, configPath, healthcheckEnvPath, unitPath, dropInDir, dropInPath string) string {
	return fmt.Sprintf(`
remote_alpha_ags_hardening_expected_binary_path=%q
remote_alpha_ags_hardening_expected_config_path=%q
remote_alpha_ags_hardening_expected_healthcheck_env_path=%q
remote_alpha_ags_hardening_expected_service_unit_path=%q
remote_alpha_ags_hardening_expected_service_dropin_dir=%q
remote_alpha_ags_hardening_expected_service_dropin_path=%q
`, binaryPath, configPath, healthcheckEnvPath, unitPath, dropInDir, dropInPath)
}

func TestRemoteAlphaAGSHardeningPassWritesSummaryAndDropIn(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	fakeBin := filepath.Join(tmpDir, "bin")
	if err := os.MkdirAll(fakeBin, 0o755); err != nil {
		t.Fatalf("mkdir fake bin: %v", err)
	}

	binaryPath := filepath.Join(tmpDir, "fake-ags")
	if err := os.WriteFile(binaryPath, []byte("binary"), 0o755); err != nil {
		t.Fatalf("write binary: %v", err)
	}

	tlsDir := filepath.Join(tmpDir, "tls")
	if err := os.MkdirAll(tlsDir, 0o755); err != nil {
		t.Fatalf("mkdir tls dir: %v", err)
	}
	for _, name := range []string{
		"ags-server-cert.pem",
		"ags-server-key.pem",
		"combined-service-ca-bundle.pem",
		"ags-client-cert.pem",
		"ags-client-key.pem",
		"runtime-ca.pem",
		"operator-client-cert.pem",
		"operator-client-key.pem",
	} {
		if err := os.WriteFile(filepath.Join(tlsDir, name), []byte(name+"\n"), 0o600); err != nil {
			t.Fatalf("write tls file %s: %v", name, err)
		}
	}

	configPath := filepath.Join(tmpDir, "ags.json")
	if err := os.WriteFile(configPath, []byte(fmt.Sprintf(`{
  "http": {
    "bind_address": "192.168.1.156",
    "port": 8444
  },
  "tls": {
    "cert_file": %q,
    "key_file": %q,
    "client_ca_file": %q
  },
  "dependencies": {
    "artifact_registry": {
      "base_url": "https://127.0.0.1:8442",
      "client_cert_file": %q,
      "client_key_file": %q,
      "root_ca_file": %q,
      "server_name": "server.artifact-registry.internal"
    }
  }
}
`,
		filepath.Join(tlsDir, "ags-server-cert.pem"),
		filepath.Join(tlsDir, "ags-server-key.pem"),
		filepath.Join(tlsDir, "combined-service-ca-bundle.pem"),
		filepath.Join(tlsDir, "ags-client-cert.pem"),
		filepath.Join(tlsDir, "ags-client-key.pem"),
		filepath.Join(tlsDir, "runtime-ca.pem"),
	)), 0o600); err != nil {
		t.Fatalf("write ags config: %v", err)
	}

	healthcheckEnvPath := filepath.Join(tmpDir, "healthcheck.env")
	if err := os.WriteFile(healthcheckEnvPath, []byte(strings.Join([]string{
		"CA_CERT=" + filepath.Join(tlsDir, "combined-service-ca-bundle.pem"),
		"OPERATOR_CERT=" + filepath.Join(tlsDir, "operator-client-cert.pem"),
		"OPERATOR_KEY=" + filepath.Join(tlsDir, "operator-client-key.pem"),
		"",
	}, "\n")), 0o600); err != nil {
		t.Fatalf("write healthcheck env: %v", err)
	}

	unitPath := filepath.Join(tmpDir, "ags.service")
	if err := os.WriteFile(unitPath, []byte(fmt.Sprintf(`[Unit]
Description=Execution Substrate Artifact Governance Service

[Service]
ExecStart=%s -config %s
`, binaryPath, configPath)), 0o644); err != nil {
		t.Fatalf("write unit file: %v", err)
	}

	dropInDir := filepath.Join(tmpDir, "ags.service.d")
	dropInPath := filepath.Join(dropInDir, "10-account.conf")
	summaryPath := filepath.Join(tmpDir, "ags-service-hardening-summary.json")

	setupFakeAGSHardeningCommands(t, fakeBin, unitPath, configPath, binaryPath)

	output, err := runSourcedAGSHardeningHelper(t, envWithPath(fakeBin,
		"REMOTE_ALPHA_SUMMARY_PATH="+summaryPath,
		"REMOTE_ALPHA_TEST_PASSWORDLESS_SUDO_FOR_DS=false",
	), agsHardeningExpectedSliceShell(binaryPath, configPath, healthcheckEnvPath, unitPath, dropInDir, dropInPath)+"remote_alpha_ags_hardening_main")
	if err != nil {
		t.Fatalf("AGS hardening helper failed: %v\n%s", err, output)
	}

	if got := strings.TrimSpace(string(output)); got != summaryPath {
		t.Fatalf("unexpected summary path output %q", got)
	}

	dropIn := mustRead(t, dropInPath)
	if !strings.Contains(dropIn, "User=ags") {
		t.Fatalf("drop-in missing User=ags: %q", dropIn)
	}
	if !strings.Contains(dropIn, "Group=ags") {
		t.Fatalf("drop-in missing Group=ags: %q", dropIn)
	}

	summary := readJSONFile(t, summaryPath)
	if got := summary["schema_version"]; got != "execution-substrate.remote-alpha.ags-service-hardening-summary.v1" {
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
	if got := service["user"]; got != "ags" {
		t.Fatalf("unexpected AGS service user %v", got)
	}
	if got := service["group"]; got != "ags" {
		t.Fatalf("unexpected AGS service group %v", got)
	}
	if got := service["binary_path"]; got != binaryPath {
		t.Fatalf("unexpected binary path %v", got)
	}
	if got := service["config_path"]; got != configPath {
		t.Fatalf("unexpected config path %v", got)
	}

	ownership := jsonMap(t, summary["ownership_model"])
	configOwnership := jsonMap(t, ownership["config_file"])
	if got := configOwnership["owner"]; got != "root:ags" {
		t.Fatalf("unexpected config ownership %v", got)
	}
	if got := configOwnership["mode"]; got != "0640" {
		t.Fatalf("unexpected config mode %v", got)
	}

	validation := jsonMap(t, summary["validation"])
	localHealth := jsonMap(t, validation["local_health"])
	if got := localHealth["status"]; got != "pass" {
		t.Fatalf("unexpected local health status %v", got)
	}
	localPublish := jsonMap(t, validation["local_publish_probe"])
	if got := localPublish["status"]; got != "pass" {
		t.Fatalf("unexpected local publish status %v", got)
	}
	arsPosture := jsonMap(t, validation["ars_service_posture"])
	if got := arsPosture["effective_user"]; got != "root(default)" {
		t.Fatalf("unexpected ars posture %v", got)
	}
	esPosture := jsonMap(t, validation["es_service_posture"])
	if got := esPosture["effective_user"]; got != "root(default)" {
		t.Fatalf("unexpected es posture %v", got)
	}
	if got := validation["mac_health_probe"]; got != "not_exercised" {
		t.Fatalf("unexpected mac health probe status %v", got)
	}

	preserved := jsonMap(t, summary["preserved_remote_path"])
	if got := preserved["direct_https_mtls"]; got != true {
		t.Fatalf("unexpected direct_https_mtls value %v", got)
	}
	if got := preserved["no_bridge"]; got != true {
		t.Fatalf("unexpected no_bridge value %v", got)
	}
	if got := preserved["no_shared_filesystem"]; got != true {
		t.Fatalf("unexpected no_shared_filesystem value %v", got)
	}

	security := jsonMap(t, summary["security"])
	if got := security["ds_not_in_docker_group"]; got != "true" {
		t.Fatalf("unexpected ds_not_in_docker_group %v", got)
	}
	if got := security["passwordless_sudo_for_ds"]; got != "false" {
		t.Fatalf("unexpected passwordless_sudo_for_ds %v", got)
	}
	if got := security["secret_material_in_summary"]; got != false {
		t.Fatalf("expected non-secret summary, got %v", got)
	}

	notClaimed := jsonMap(t, summary["not_claimed"])
	if got := notClaimed["es_runtime_hardening"]; got != "not_claimed" {
		t.Fatalf("unexpected es_runtime_hardening claim %v", got)
	}
	if got := notClaimed["spire_selector_model_changes"]; got != "not_claimed" {
		t.Fatalf("unexpected spire selector claim %v", got)
	}
}

func TestRemoteAlphaAGSHardeningRejectsSliceOverrideEnv(t *testing.T) {
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
			env:     "REMOTE_ALPHA_BINARY_PATH=/tmp/not-ags",
			snippet: "REMOTE_ALPHA_BINARY_PATH",
		},
		{
			name:    "config path",
			env:     "REMOTE_ALPHA_CONFIG_PATH=/tmp/not-ags.json",
			snippet: "REMOTE_ALPHA_CONFIG_PATH",
		},
		{
			name:    "healthcheck env path",
			env:     "REMOTE_ALPHA_HEALTHCHECK_ENV_PATH=/tmp/not-healthcheck.env",
			snippet: "REMOTE_ALPHA_HEALTHCHECK_ENV_PATH",
		},
		{
			name:    "service unit path",
			env:     "REMOTE_ALPHA_SERVICE_UNIT_PATH=/tmp/not-ags.service",
			snippet: "REMOTE_ALPHA_SERVICE_UNIT_PATH",
		},
		{
			name:    "service dropin dir",
			env:     "REMOTE_ALPHA_SERVICE_DROPIN_DIR=/tmp/not-ags.service.d",
			snippet: "REMOTE_ALPHA_SERVICE_DROPIN_DIR",
		},
		{
			name:    "service dropin path",
			env:     "REMOTE_ALPHA_SERVICE_DROPIN_PATH=/tmp/not-ags.service.d/50-not-ags.conf",
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

			output, err := runSourcedAGSHardeningHelper(t, envWithPath(fakeBin, tc.env), "remote_alpha_ags_hardening_main")
			if err == nil {
				t.Fatalf("expected slice override rejection for %s, got success\n%s", tc.name, output)
			}
			if !strings.Contains(string(output), tc.snippet) {
				t.Fatalf("expected output to mention %q, got %q", tc.snippet, output)
			}
		})
	}
}

func TestRemoteAlphaAGSHardeningRejectsSliceOverrideFlags(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name    string
		body    string
		snippet string
	}{
		{
			name:    "service name",
			body:    "remote_alpha_ags_hardening_main --service-name es",
			snippet: "--service-name",
		},
		{
			name:    "service user",
			body:    "remote_alpha_ags_hardening_main --service-user root",
			snippet: "--service-user",
		},
		{
			name:    "service group",
			body:    "remote_alpha_ags_hardening_main --service-group root",
			snippet: "--service-group",
		},
		{
			name:    "binary path",
			body:    "remote_alpha_ags_hardening_main --binary-path /tmp/not-ags",
			snippet: "--binary-path",
		},
		{
			name:    "config path",
			body:    "remote_alpha_ags_hardening_main --config-path /tmp/not-ags.json",
			snippet: "--config-path",
		},
		{
			name:    "healthcheck env path",
			body:    "remote_alpha_ags_hardening_main --healthcheck-env-path /tmp/not-healthcheck.env",
			snippet: "--healthcheck-env-path",
		},
		{
			name:    "service unit path",
			body:    "remote_alpha_ags_hardening_main --service-unit-path /tmp/not-ags.service",
			snippet: "--service-unit-path",
		},
		{
			name:    "service dropin dir",
			body:    "remote_alpha_ags_hardening_main --service-dropin-dir /tmp/not-ags.service.d",
			snippet: "--service-dropin-dir",
		},
		{
			name:    "service dropin path",
			body:    "remote_alpha_ags_hardening_main --service-dropin-path /tmp/not-ags.service.d/50-not-ags.conf",
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

			output, err := runSourcedAGSHardeningHelper(t, envWithPath(fakeBin), tc.body)
			if err == nil {
				t.Fatalf("expected slice flag rejection for %s, got success\n%s", tc.name, output)
			}
			if !strings.Contains(string(output), tc.snippet) {
				t.Fatalf("expected output to mention %q, got %q", tc.snippet, output)
			}
		})
	}
}

func TestRemoteAlphaAGSHardeningRequiresRoot(t *testing.T) {
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

	output, err := runSourcedAGSHardeningHelper(t, envWithPath(fakeBin), "remote_alpha_ags_hardening_require_root")
	if err == nil {
		t.Fatalf("expected root requirement failure, got success\n%s", output)
	}
	if !strings.Contains(string(output), "must run as root") {
		t.Fatalf("expected root failure message, got %q", output)
	}
}
