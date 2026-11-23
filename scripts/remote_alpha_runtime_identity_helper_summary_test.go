package scripts_test

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestRemoteAlphaRuntimeIdentityHelperSummaryScriptSyntax(t *testing.T) {
	scriptPath := filepath.Join(executionSubstrateRepoRoot, "scripts", "remote_alpha_runtime_identity_helper_summary.sh")
	cmd := exec.Command("/bin/bash", "-n", scriptPath)
	cmd.Dir = executionSubstrateRepoRoot
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("bash -n failed: %v\n%s", err, output)
	}
}

func TestRemoteAlphaRuntimeIdentityHelperSummaryDryRun(t *testing.T) {
	tmpDir := t.TempDir()
	binDir := filepath.Join(tmpDir, "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatalf("mkdir fake bin: %v", err)
	}

	writeExecutable(t, binDir, "es-runtime-support", `#!/bin/sh
echo 'usage: es-runtime-support <supervisor|helper|exec-workload> [...]' >&2
exit 1
`)
	writeExecutable(t, binDir, "systemctl", `#!/bin/sh
if [ "$1" = "is-active" ]; then
  echo active
  exit 0
fi
exit 1
`)
	writeExecutable(t, binDir, "spire-agent", `#!/bin/sh
if [ "$1" = "healthcheck" ]; then
  echo "Agent is healthy."
  exit 0
fi
if [ "$1" = "api" ]; then
  echo "dry-run must not fetch JWT-SVID bodies" >&2
  exit 97
fi
exit 1
`)
	writeExecutable(t, binDir, "spire-server", `#!/bin/sh
if [ "$1" = "healthcheck" ]; then
  echo "Server is healthy."
  exit 0
fi
if [ "$1" = "entry" ] && [ "$2" = "show" ]; then
  cat <<'EOF'
Entry ID         : test-entry
SPIFFE ID        : spiffe://execution.internal/workload
Parent ID        : spiffe://execution.internal/spire-agent
Selector         : unix:uid:0
Selector         : unix:gid:0
EOF
  exit 0
fi
exit 1
`)
	writeExecutable(t, binDir, "docker", `#!/bin/sh
if [ "$1" = "info" ]; then
  echo '{}'
  exit 0
fi
exit 1
`)
	writeExecutable(t, binDir, "nomad", `#!/bin/sh
if [ "$1" = "node" ] && [ "$2" = "status" ] && [ "$3" = "-json" ]; then
  echo '[{"Status":"ready"}]'
  exit 0
fi
exit 1
`)

	outputPath := filepath.Join(tmpDir, "runtime-identity-helper-summary.json")
	scriptPath := filepath.Join(executionSubstrateRepoRoot, "scripts", "remote_alpha_runtime_identity_helper_summary.sh")
	cmd := exec.Command(
		"/bin/bash",
		scriptPath,
		"--dry-run",
		"--pretty",
		"--output", outputPath,
		"--runtime-support-path", filepath.Join(binDir, "es-runtime-support"),
		"--spire-agent-socket-path", filepath.Join(tmpDir, "agent.sock"),
		"--spire-server-socket-path", filepath.Join(tmpDir, "server.sock"),
	)
	cmd.Dir = executionSubstrateRepoRoot
	cmd.Env = append(os.Environ(), "PATH="+binDir+":"+os.Getenv("PATH"))
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("dry-run failed: %v\n%s", err, output)
	}
	if _, err := os.Stat(outputPath); !os.IsNotExist(err) {
		t.Fatalf("dry-run wrote output path %s", outputPath)
	}
	if strings.Contains(string(output), "eyJ") {
		t.Fatalf("dry-run output contains JWT-like material: %s", output)
	}

	var payload map[string]any
	if err := json.Unmarshal(output, &payload); err != nil {
		t.Fatalf("dry-run output was not JSON: %v\n%s", err, output)
	}
	if got, want := payload["schema"], "execution-substrate.remote-runtime-identity-helper-summary.v1alpha1"; got != want {
		t.Fatalf("schema = %v, want %s", got, want)
	}
	if got := payload["mode"]; got != "dry_run" {
		t.Fatalf("mode = %v, want dry_run", got)
	}
	if got := payload["runtime_identity_helper_local_fetch"]; got != "not_proven" {
		t.Fatalf("runtime_identity_helper_local_fetch = %v, want not_proven in dry-run", got)
	}
	health, ok := payload["health"].(map[string]any)
	if !ok {
		t.Fatalf("health missing or not an object: %#v", payload["health"])
	}
	if health["spire_server_health"] != true || health["spire_agent_health"] != true {
		t.Fatalf("SPIRE health was not reflected in dry-run payload: %#v", health)
	}
	if _, ok := payload["readiness_not_claimed"]; !ok {
		t.Fatalf("readiness_not_claimed missing from payload")
	}
	if _, ok := payload["redaction"]; !ok {
		t.Fatalf("redaction markers missing from payload")
	}
}

func TestRemoteAlphaRuntimeIdentityHelperSummaryGeneratorIsDocumented(t *testing.T) {
	remoteDoc := compactText(mustRead(t, ".docs/system_overview/remote_supported_host_alpha.md"))

	for _, required := range []string{
		"`scripts/remote_alpha_runtime_identity_helper_summary.sh`",
		"`/var/tmp/execution-substrate-remote-alpha/runtime-identity-helper-summary.json`",
		"`execution-substrate.remote-runtime-identity-helper-summary.v1alpha1`",
		"not CP run-control authority",
		"not ES submit authority",
		"not runtime-profile readiness",
		"not a replacement for the Milestone 3 proof",
		"skip the SPIRE JWT fetch smoke",
	} {
		if !strings.Contains(remoteDoc, required) {
			t.Fatalf("runtime identity helper generator docs missing %q", required)
		}
	}
}
