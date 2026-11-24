package scripts_test

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func runSourcedARSHardeningHelper(t *testing.T, env []string, shellBody string) ([]byte, error) {
	t.Helper()
	helperPath := filepath.Join(executionSubstrateRepoRoot, "scripts", "internal", "remote_alpha_harden_ars_service.sh")
	script := fmt.Sprintf("set -euo pipefail\nsource %q\n%s\n", helperPath, shellBody)
	cmd := exec.Command("/bin/bash", "-c", script)
	cmd.Dir = executionSubstrateRepoRoot
	cmd.Env = env
	return cmd.CombinedOutput()
}

func setupFakeARSHardeningCommands(t *testing.T, dir, arsUnitPath, arsConfigPath, arsBinaryPath, agsBinaryPath, agsConfigPath string, ownerships map[string]string) {
	t.Helper()

	writeExecutable(t, dir, "id", `#!/bin/sh
if [ "$1" = "-u" ] && [ $# -eq 1 ]; then
  echo 0
  exit 0
fi
if [ "$1" = "-u" ] && [ "$2" = "ars" ]; then
  # The state step sets owners for real, through descriptors, so the test's
  # ARS account is the user running the test.
  exec /usr/bin/id -u
fi
if [ "$1" = "-gn" ] && [ "$2" = "ars" ]; then
  echo ars
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
`)
	writeExecutable(t, dir, "getent", `#!/bin/sh
if [ "$1" = "group" ] && [ "$2" = "ars" ]; then
  echo "ars:x:$(/usr/bin/id -g):"
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
      ars.service)
        cat <<'EOF'
User=ars
Group=ars
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
      egs.service)
        cat <<'EOF'
User=egs
Group=egs
ExecStart={ path=/tmp/fake-egs ; argv[]=/tmp/fake-egs ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }
FragmentPath=/etc/systemd/system/egs.service
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
`, arsBinaryPath, arsBinaryPath, arsConfigPath, arsUnitPath, agsBinaryPath, agsBinaryPath, agsConfigPath))
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
  https://127.0.0.1:8442/health|https://server.artifact-registry.internal:8442/health)
    cat <<'EOF'
{"status":"healthy","ready":true,"service":"artifact-registry","additional_properties":{"dependencies":{"storage":"healthy","index":"healthy"}}}
EOF
    ;;
  https://192.168.1.156:8444/health)
    cat <<'EOF'
{"status":"healthy","ready":true,"service":"artifact-governance","additional_properties":{"dependencies":{"artifact_registry":"healthy"}}}
EOF
    ;;
  https://192.168.1.156:8444/v1/artifacts:publish)
    cat <<'EOF'
{"published":true,"artifact_digest":"sha256:ars-posture-test-artifact"}
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

func formatFakeStatCases(ownerships map[string]string) string {
	lines := make([]string, 0, len(ownerships))
	for path, value := range ownerships {
		lines = append(lines, fmt.Sprintf("    %q)\n      echo %q\n      ;;", path, value))
	}
	return strings.Join(lines, "\n")
}

func arsHardeningExpectedSliceShell(binaryPath, configPath, healthcheckEnvPath, unitPath, dropInDir, dropInPath, sharedTLSDir, tlsDir, agsConfigPath, storageRootDir, indexFile string) string {
	return fmt.Sprintf(`
remote_alpha_ars_hardening_expected_binary_path=%q
remote_alpha_ars_hardening_expected_config_path=%q
remote_alpha_ars_hardening_expected_healthcheck_env_path=%q
remote_alpha_ars_hardening_expected_service_unit_path=%q
remote_alpha_ars_hardening_expected_service_dropin_dir=%q
remote_alpha_ars_hardening_expected_service_dropin_path=%q
remote_alpha_ars_hardening_expected_shared_tls_dir=%q
remote_alpha_ars_hardening_expected_tls_dir=%q
remote_alpha_ars_hardening_expected_ags_config_path=%q
remote_alpha_ars_hardening_expected_bind_address=%q
remote_alpha_ars_hardening_expected_port=%q
remote_alpha_ars_hardening_expected_storage_root_dir=%q
remote_alpha_ars_hardening_expected_storage_index_file=%q
`, binaryPath, configPath, healthcheckEnvPath, unitPath, dropInDir, dropInPath, sharedTLSDir, tlsDir, agsConfigPath, "127.0.0.1", "8442", storageRootDir, indexFile)
}

func TestRemoteAlphaARSHardeningPassWritesSummaryAndDropIn(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	fakeBin := filepath.Join(tmpDir, "bin")
	if err := os.MkdirAll(fakeBin, 0o755); err != nil {
		t.Fatalf("mkdir fake bin: %v", err)
	}

	arsBinaryPath := filepath.Join(tmpDir, "fake-ars")
	if err := os.WriteFile(arsBinaryPath, []byte("binary"), 0o755); err != nil {
		t.Fatalf("write ars binary: %v", err)
	}
	agsBinaryPath := filepath.Join(tmpDir, "fake-ags")
	if err := os.WriteFile(agsBinaryPath, []byte("binary"), 0o755); err != nil {
		t.Fatalf("write ags binary: %v", err)
	}

	sourceTLSDir := filepath.Join(tmpDir, "tls")
	if err := os.MkdirAll(sourceTLSDir, 0o755); err != nil {
		t.Fatalf("mkdir source tls dir: %v", err)
	}
	for _, name := range []string{
		"ars-server-cert.pem",
		"ars-server-key.pem",
		"runtime-ca.pem",
		"combined-service-ca-bundle.pem",
		"operator-client-cert.pem",
		"operator-client-key.pem",
	} {
		if err := os.WriteFile(filepath.Join(sourceTLSDir, name), []byte(name+"\n"), 0o600); err != nil {
			t.Fatalf("write tls file %s: %v", name, err)
		}
	}

	stateRootDir := filepath.Join(tmpDir, "state")
	storageRootDir := filepath.Join(stateRootDir, "blobs")
	if err := os.MkdirAll(storageRootDir, 0o755); err != nil {
		t.Fatalf("mkdir storage root: %v", err)
	}
	indexFile := filepath.Join(stateRootDir, "index.json")
	if err := os.WriteFile(indexFile, []byte("{}\n"), 0o600); err != nil {
		t.Fatalf("write index file: %v", err)
	}

	arsConfigPath := filepath.Join(tmpDir, "ars.json")
	if err := os.WriteFile(arsConfigPath, []byte(fmt.Sprintf(`{
  "http": {
    "bind_address": "127.0.0.1",
    "port": 8442
	},
  "tls": {
    "cert_file": %q,
    "key_file": %q,
    "client_ca_file": %q
  },
  "storage": {
    "root_dir": %q,
    "index_file": %q
  }
}
`,
		filepath.Join(sourceTLSDir, "ars-server-cert.pem"),
		filepath.Join(sourceTLSDir, "ars-server-key.pem"),
		filepath.Join(sourceTLSDir, "runtime-ca.pem"),
		storageRootDir,
		indexFile,
	)), 0o600); err != nil {
		t.Fatalf("write ars config: %v", err)
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

	healthcheckEnvPath := filepath.Join(tmpDir, "healthcheck.env")
	if err := os.WriteFile(healthcheckEnvPath, []byte(strings.Join([]string{
		"CA_CERT=" + filepath.Join(sourceTLSDir, "combined-service-ca-bundle.pem"),
		"OPERATOR_CERT=" + filepath.Join(sourceTLSDir, "operator-client-cert.pem"),
		"OPERATOR_KEY=" + filepath.Join(sourceTLSDir, "operator-client-key.pem"),
		"",
	}, "\n")), 0o600); err != nil {
		t.Fatalf("write healthcheck env: %v", err)
	}

	unitPath := filepath.Join(tmpDir, "ars.service")
	if err := os.WriteFile(unitPath, []byte(fmt.Sprintf(`[Unit]
Description=Execution Substrate Artifact Registry Service

[Service]
ExecStart=%s -config %s
`, arsBinaryPath, arsConfigPath)), 0o644); err != nil {
		t.Fatalf("write unit file: %v", err)
	}

	dropInDir := filepath.Join(tmpDir, "ars.service.d")
	dropInPath := filepath.Join(dropInDir, "10-account.conf")
	dedicatedTLSDir := filepath.Join(tmpDir, "ars-tls")
	summaryPath := filepath.Join(tmpDir, "ars-service-hardening-summary.json")

	ownerships := map[string]string{
		arsConfigPath:   fmt.Sprintf("root:ars 640 %s", arsConfigPath),
		dedicatedTLSDir: fmt.Sprintf("root:ars 710 %s", dedicatedTLSDir),
		filepath.Join(dedicatedTLSDir, "ars-server-cert.pem"): fmt.Sprintf("root:ars 640 %s", filepath.Join(dedicatedTLSDir, "ars-server-cert.pem")),
		filepath.Join(dedicatedTLSDir, "ars-server-key.pem"):  fmt.Sprintf("root:ars 640 %s", filepath.Join(dedicatedTLSDir, "ars-server-key.pem")),
		filepath.Join(dedicatedTLSDir, "runtime-ca.pem"):      fmt.Sprintf("root:ars 640 %s", filepath.Join(dedicatedTLSDir, "runtime-ca.pem")),
		stateRootDir:   fmt.Sprintf("ars:ars 750 %s", stateRootDir),
		storageRootDir: fmt.Sprintf("ars:ars 750 %s", storageRootDir),
		indexFile:      fmt.Sprintf("ars:ars 600 %s", indexFile),
	}

	setupFakeARSHardeningCommands(t, fakeBin, unitPath, arsConfigPath, arsBinaryPath, agsBinaryPath, agsConfigPath, ownerships)

	output, err := runSourcedARSHardeningHelper(t, envWithPath(fakeBin,
		"REMOTE_ALPHA_SUMMARY_PATH="+summaryPath,
		"REMOTE_ALPHA_TEST_PASSWORDLESS_SUDO_FOR_DS=false",
	), arsHardeningExpectedSliceShell(arsBinaryPath, arsConfigPath, healthcheckEnvPath, unitPath, dropInDir, dropInPath, sourceTLSDir, dedicatedTLSDir, agsConfigPath, storageRootDir, indexFile)+"remote_alpha_ars_hardening_main")
	if err != nil {
		t.Fatalf("ARS hardening helper failed: %v\n%s", err, output)
	}

	if got := strings.TrimSpace(string(output)); got != summaryPath {
		t.Fatalf("unexpected summary path output %q", got)
	}

	dropIn := mustRead(t, dropInPath)
	if !strings.Contains(dropIn, "User=ars") {
		t.Fatalf("drop-in missing User=ars: %q", dropIn)
	}
	if !strings.Contains(dropIn, "Group=ars") {
		t.Fatalf("drop-in missing Group=ars: %q", dropIn)
	}
	if !strings.Contains(dropIn, "UMask=0027") {
		t.Fatalf("drop-in missing UMask=0027: %q", dropIn)
	}

	rewrittenConfig := mustRead(t, arsConfigPath)
	if !strings.Contains(rewrittenConfig, filepath.Join(dedicatedTLSDir, "ars-server-cert.pem")) {
		t.Fatalf("ars config did not point at dedicated tls dir: %q", rewrittenConfig)
	}
	if !strings.Contains(rewrittenConfig, filepath.Join(dedicatedTLSDir, "ars-server-key.pem")) {
		t.Fatalf("ars config did not point at dedicated tls key: %q", rewrittenConfig)
	}
	if !strings.Contains(rewrittenConfig, filepath.Join(dedicatedTLSDir, "runtime-ca.pem")) {
		t.Fatalf("ars config did not point at dedicated tls client ca: %q", rewrittenConfig)
	}

	summary := readJSONFile(t, summaryPath)
	if got := summary["schema_version"]; got != "execution-substrate.remote-alpha.ars-service-hardening-summary.v1" {
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
	if got := service["user"]; got != "ars" {
		t.Fatalf("unexpected ARS service user %v", got)
	}
	if got := service["group"]; got != "ars" {
		t.Fatalf("unexpected ARS service group %v", got)
	}
	if got := service["binary_path"]; got != arsBinaryPath {
		t.Fatalf("unexpected binary path %v", got)
	}
	if got := service["config_path"]; got != arsConfigPath {
		t.Fatalf("unexpected config path %v", got)
	}

	dependencies := jsonMap(t, summary["dependencies"])
	if got := dependencies["blob_root"]; got != storageRootDir {
		t.Fatalf("unexpected blob root %v", got)
	}
	if got := dependencies["index_file"]; got != indexFile {
		t.Fatalf("unexpected index file %v", got)
	}

	ownership := jsonMap(t, summary["ownership_model"])
	configOwnership := jsonMap(t, ownership["config_file"])
	if got := configOwnership["owner"]; got != "root:ars" {
		t.Fatalf("unexpected config ownership %v", got)
	}
	if !strings.Contains(mustRead(t, summaryPath), filepath.Join(dedicatedTLSDir, "runtime-ca.pem")) {
		t.Fatalf("summary did not record dedicated tls client ca path: %q", mustRead(t, summaryPath))
	}
	stateOwnership := jsonMap(t, ownership["state_root"])
	if got := stateOwnership["owner"]; got != "ars:ars" {
		t.Fatalf("unexpected state root ownership %v", got)
	}
	indexOwnership := jsonMap(t, ownership["index_file"])
	if got := indexOwnership["mode"]; got != "0600" {
		t.Fatalf("unexpected index mode %v", got)
	}

	validation := jsonMap(t, summary["validation"])
	localARSHealth := jsonMap(t, validation["local_ars_health"])
	if got := localARSHealth["status"]; got != "pass" {
		t.Fatalf("unexpected local ARS health status %v", got)
	}
	localAGSHealth := jsonMap(t, validation["local_ags_health"])
	if got := localAGSHealth["status"]; got != "pass" {
		t.Fatalf("unexpected local AGS health status %v", got)
	}
	localAGSPublish := jsonMap(t, validation["local_ags_publish_probe"])
	if got := localAGSPublish["status"]; got != "pass" {
		t.Fatalf("unexpected local AGS publish status %v", got)
	}
	stateValidation := jsonMap(t, validation["state_ownership"])
	if got := stateValidation["status"]; got != "pass" {
		t.Fatalf("unexpected state ownership validation status %v", got)
	}
	agsPosture := jsonMap(t, validation["ags_service_posture"])
	if got := agsPosture["effective_user"]; got != "ags" {
		t.Fatalf("unexpected ags posture %v", got)
	}
	if got := agsPosture["effective_group"]; got != "ags" {
		t.Fatalf("unexpected ags group posture %v", got)
	}
	egsPosture := jsonMap(t, validation["egs_service_posture"])
	if got := egsPosture["effective_user"]; got != "egs" {
		t.Fatalf("unexpected egs posture %v", got)
	}
	if got := egsPosture["effective_group"]; got != "egs" {
		t.Fatalf("unexpected egs group posture %v", got)
	}
	esPosture := jsonMap(t, validation["es_service_posture"])
	if got := esPosture["effective_user"]; got != "es" {
		t.Fatalf("unexpected es posture %v", got)
	}
	if got := esPosture["effective_group"]; got != "es" {
		t.Fatalf("unexpected es group posture %v", got)
	}

	preserved := jsonMap(t, summary["preserved_remote_path"])
	if got := preserved["ars_loopback_only"]; got != true {
		t.Fatalf("unexpected ars_loopback_only value %v", got)
	}
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

	notClaimed := jsonMap(t, summary["not_claimed"])
	if got := notClaimed["es_or_egs_hardening"]; got != "not_claimed" {
		t.Fatalf("unexpected es_or_egs_hardening claim %v", got)
	}
	if got := notClaimed["es_public_contract_changes"]; got != "not_claimed" {
		t.Fatalf("unexpected es_public_contract_changes claim %v", got)
	}
}

func TestRemoteAlphaARSHardeningRejectsSliceOverrideEnv(t *testing.T) {
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
			env:     "REMOTE_ALPHA_BINARY_PATH=/tmp/not-ars",
			snippet: "REMOTE_ALPHA_BINARY_PATH",
		},
		{
			name:    "config path",
			env:     "REMOTE_ALPHA_CONFIG_PATH=/tmp/not-ars.json",
			snippet: "REMOTE_ALPHA_CONFIG_PATH",
		},
		{
			name:    "healthcheck env path",
			env:     "REMOTE_ALPHA_HEALTHCHECK_ENV_PATH=/tmp/not-healthcheck.env",
			snippet: "REMOTE_ALPHA_HEALTHCHECK_ENV_PATH",
		},
		{
			name:    "service unit path",
			env:     "REMOTE_ALPHA_SERVICE_UNIT_PATH=/tmp/not-ars.service",
			snippet: "REMOTE_ALPHA_SERVICE_UNIT_PATH",
		},
		{
			name:    "service dropin dir",
			env:     "REMOTE_ALPHA_SERVICE_DROPIN_DIR=/tmp/not-ars.service.d",
			snippet: "REMOTE_ALPHA_SERVICE_DROPIN_DIR",
		},
		{
			name:    "service dropin path",
			env:     "REMOTE_ALPHA_SERVICE_DROPIN_PATH=/tmp/not-ars.service.d/50-not-ars.conf",
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

			output, err := runSourcedARSHardeningHelper(t, envWithPath(fakeBin, tc.env), "remote_alpha_ars_hardening_main")
			if err == nil {
				t.Fatalf("expected slice override rejection for %s, got success\n%s", tc.name, output)
			}
			if !strings.Contains(string(output), tc.snippet) {
				t.Fatalf("expected output to mention %q, got %q", tc.snippet, output)
			}
		})
	}
}

func TestRemoteAlphaARSHardeningRejectsSliceOverrideFlags(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name    string
		body    string
		snippet string
	}{
		{
			name:    "service name",
			body:    "remote_alpha_ars_hardening_main --service-name es",
			snippet: "--service-name",
		},
		{
			name:    "service user",
			body:    "remote_alpha_ars_hardening_main --service-user root",
			snippet: "--service-user",
		},
		{
			name:    "service group",
			body:    "remote_alpha_ars_hardening_main --service-group root",
			snippet: "--service-group",
		},
		{
			name:    "binary path",
			body:    "remote_alpha_ars_hardening_main --binary-path /tmp/not-ars",
			snippet: "--binary-path",
		},
		{
			name:    "config path",
			body:    "remote_alpha_ars_hardening_main --config-path /tmp/not-ars.json",
			snippet: "--config-path",
		},
		{
			name:    "healthcheck env path",
			body:    "remote_alpha_ars_hardening_main --healthcheck-env-path /tmp/not-healthcheck.env",
			snippet: "--healthcheck-env-path",
		},
		{
			name:    "service unit path",
			body:    "remote_alpha_ars_hardening_main --service-unit-path /tmp/not-ars.service",
			snippet: "--service-unit-path",
		},
		{
			name:    "service dropin dir",
			body:    "remote_alpha_ars_hardening_main --service-dropin-dir /tmp/not-ars.service.d",
			snippet: "--service-dropin-dir",
		},
		{
			name:    "service dropin path",
			body:    "remote_alpha_ars_hardening_main --service-dropin-path /tmp/not-ars.service.d/50-not-ars.conf",
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

			output, err := runSourcedARSHardeningHelper(t, envWithPath(fakeBin), tc.body)
			if err == nil {
				t.Fatalf("expected slice flag rejection for %s, got success\n%s", tc.name, output)
			}
			if !strings.Contains(string(output), tc.snippet) {
				t.Fatalf("expected output to mention %q, got %q", tc.snippet, output)
			}
		})
	}
}

func TestRemoteAlphaARSHardeningRequiresRoot(t *testing.T) {
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

	output, err := runSourcedARSHardeningHelper(t, envWithPath(fakeBin), "remote_alpha_ars_hardening_require_root")
	if err == nil {
		t.Fatalf("expected root requirement failure, got success\n%s", output)
	}
	if !strings.Contains(string(output), "must run as root") {
		t.Fatalf("expected root failure message, got %q", output)
	}
}
