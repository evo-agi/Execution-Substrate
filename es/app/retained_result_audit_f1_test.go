package app_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

func auditSafeScriptPath(t *testing.T) string {
	t.Helper()
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Fatalf("resolve required production Python: %v", err)
	}
	return filepath.Dir(python) + string(os.PathListSeparator) + "/usr/bin:/bin"
}

func auditControlledScriptEnv(t *testing.T, overrides ...string) []string {
	t.Helper()
	values := map[string]string{
		"PATH":                    auditSafeScriptPath(t),
		"HOME":                    t.TempDir(),
		"TMPDIR":                  t.TempDir(),
		"LC_ALL":                  "C",
		"PYTHONDONTWRITEBYTECODE": "1",
	}
	for _, override := range overrides {
		key, value, found := strings.Cut(override, "=")
		if !found || key == "" {
			t.Fatalf("invalid synthetic environment assignment")
		}
		values[key] = value
	}
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	env := make([]string, 0, len(keys))
	for _, key := range keys {
		env = append(env, key+"="+values[key])
	}
	return env
}

func auditScriptSource(t *testing.T, scriptPath, body string, overrides ...string) ([]byte, error) {
	t.Helper()
	command := exec.Command("/bin/bash", "-c", "source \"$1\"; "+body, "bash", scriptPath)
	command.Env = auditControlledScriptEnv(t, overrides...)
	return command.CombinedOutput()
}

func TestRetainedResultAuditF1SetupAndWrapperRefuseUnsafeMetadataBeforeEffects(t *testing.T) {
	repoRoot := executionPlatformRepoRoot(t)
	workspace := t.TempDir()
	proofDir := filepath.Join(workspace, "proof")
	hostProofDir := filepath.Join(workspace, "host-proof")
	goodPath := filepath.Join(workspace, "external auth ", "keys", "key")
	setupScript := filepath.Join(repoRoot, "scripts", "72_supported_local_setup.sh")
	base := []string{
		"EXECUTION_SUBSTRATE_REPO_ROOT=" + repoRoot,
		"SUPPORTED_LOCAL_PROOF_DIR=" + proofDir,
		"SUPPORTED_LOCAL_RETAINED_RESULT_AUTH_STORE_ID=test_store",
		"SUPPORTED_LOCAL_RETAINED_RESULT_AUTH_KEY_ID=test_key",
		"SUPPORTED_LOCAL_RETAINED_RESULT_AUTH_KEY_FILE=" + goodPath,
	}
	if output, err := auditScriptSource(t, setupScript, "preflight_supported_local_setup_retained_result_auth", base...); err != nil {
		t.Fatalf("valid setup metadata refused: %v output=%s", err, output)
	}
	for _, test := range []struct{ name, variable, value string }{
		{"missing store", "SUPPORTED_LOCAL_RETAINED_RESULT_AUTH_STORE_ID", ""},
		{"invalid key ID", "SUPPORTED_LOCAL_RETAINED_RESULT_AUTH_KEY_ID", "Upper"},
		{"relative key", "SUPPORTED_LOCAL_RETAINED_RESULT_AUTH_KEY_FILE", "keys/key"},
		{"root parent", "SUPPORTED_LOCAL_RETAINED_RESULT_AUTH_KEY_FILE", "/key"},
		{"proof workspace", "SUPPORTED_LOCAL_RETAINED_RESULT_AUTH_KEY_FILE", filepath.Join(proofDir, "auth", "key")},
		{"staging", "SUPPORTED_LOCAL_RETAINED_RESULT_AUTH_KEY_FILE", filepath.Join(proofDir, "es-staging", "key")},
		{"results", "SUPPORTED_LOCAL_RETAINED_RESULT_AUTH_KEY_FILE", filepath.Join(proofDir, "es-results", "key")},
	} {
		t.Run("setup "+test.name, func(t *testing.T) {
			env := append(append([]string{}, base...), test.variable+"="+test.value)
			output, err := auditScriptSource(t, setupScript, "preflight_supported_local_setup_retained_result_auth", env...)
			if err == nil || strings.Contains(string(output), test.value) && test.value != "" {
				t.Fatalf("unsafe setup metadata accepted or disclosed: err=%v output=%s", err, output)
			}
			if _, err := os.Lstat(proofDir); !os.IsNotExist(err) {
				t.Fatalf("setup preflight changed proof workspace: %v", err)
			}
		})
	}
	// Enter the real setup dispatcher with a valid exact-Go version response.
	// The tripwire is the first post-auth path: an accidental fallthrough cannot
	// contact dependencies or create the proof workspace.
	fakeBin := filepath.Join(workspace, "fake-bin")
	if err := os.Mkdir(fakeBin, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fakeBin, "go"), []byte("#!/bin/sh\n[ \"$1\" = version ] || exit 97\nprintf 'go version go1.26.5 darwin/arm64\\n'\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	unsafeSetup := append(append([]string{}, base...), "SUPPORTED_LOCAL_RETAINED_RESULT_AUTH_STORE_ID=",
		"PATH="+fakeBin+string(os.PathListSeparator)+auditSafeScriptPath(t))
	setupBody := `require_command() { :; }
uname() { printf 'Linux\n'; }
detect_docker_bridge_gateway() { printf 'POST_AUTH_TRIPWIRE\n' >&2; return 97; }
generate_random_hex() { printf 'POST_AUTH_TRIPWIRE\n' >&2; return 97; }
setup`
	if output, err := auditScriptSource(t, setupScript, setupBody, unsafeSetup...); err == nil ||
		strings.Contains(string(output), "POST_AUTH_TRIPWIRE") {
		t.Fatalf("unsafe metadata passed real setup entry preflight: err=%v output=%s", err, output)
	}
	if _, err := os.Lstat(proofDir); !os.IsNotExist(err) {
		t.Fatalf("setup entry preflight changed proof workspace: %v", err)
	}

	proofScript := filepath.Join(repoRoot, "scripts", "73_supported_local_proof.sh")
	guestProof := "/tmp/es-proof-audit"
	guestBootstrap := guestProof + ".bootstrap"
	guestRepo := guestBootstrap + "/repo"
	wrapperBase := []string{
		"SUPPORTED_LOCAL_HOST_PROOF_DIR=" + hostProofDir,
		"SUPPORTED_LOCAL_GUEST_PROOF_DIR=" + guestProof,
		"SUPPORTED_LOCAL_GUEST_BOOTSTRAP_DIR=" + guestBootstrap,
		"SUPPORTED_LOCAL_GUEST_REPO_ROOT=" + guestRepo,
		"SUPPORTED_LOCAL_RETAINED_RESULT_AUTH_STORE_ID=test_store",
		"SUPPORTED_LOCAL_RETAINED_RESULT_AUTH_KEY_ID=test_key",
		"SUPPORTED_LOCAL_RETAINED_RESULT_AUTH_KEY_FILE=/opt/external auth /keys/key",
	}
	if output, err := auditScriptSource(t, proofScript, "preflight_supported_local_proof_retained_result_auth", wrapperBase...); err != nil {
		t.Fatalf("valid guest reference refused: %v output=%s", err, output)
	}
	for _, guestPath := range []string{guestProof + "/key", guestBootstrap + "/key", guestRepo + "/key", "/tmp/es-proof-stale/keys/key"} {
		env := append(append([]string{}, wrapperBase...), "SUPPORTED_LOCAL_RETAINED_RESULT_AUTH_KEY_FILE="+guestPath)
		output, err := auditScriptSource(t, proofScript, "preflight_supported_local_proof_retained_result_auth", env...)
		if err == nil || strings.Contains(string(output), guestPath) {
			t.Fatalf("guest cleanup-scope key accepted or disclosed: err=%v output=%s", err, output)
		}
	}
	unsafeWrapper := append(append([]string{}, wrapperBase...),
		"SUPPORTED_LOCAL_RETAINED_RESULT_AUTH_KEY_FILE="+guestBootstrap+"/keys/key",
		"PATH="+fakeBin+string(os.PathListSeparator)+auditSafeScriptPath(t))
	wrapperBody := `require_command() { :; }
mkdir() { printf 'POST_AUTH_TRIPWIRE\n' >&2; return 97; }
run`
	if output, err := auditScriptSource(t, proofScript, wrapperBody, unsafeWrapper...); err == nil ||
		strings.Contains(string(output), "POST_AUTH_TRIPWIRE") {
		t.Fatalf("unsafe metadata passed real proof entry preflight: err=%v output=%s", err, output)
	}
	if _, err := os.Lstat(hostProofDir); !os.IsNotExist(err) {
		t.Fatalf("wrapper preflight changed host proof workspace: %v", err)
	}
}

func TestRetainedResultAuditF1WrapperBuildsExactGuestMetadataArguments(t *testing.T) {
	repoRoot := executionPlatformRepoRoot(t)
	proofScript := filepath.Join(repoRoot, "scripts", "73_supported_local_proof.sh")
	guestPath := "/opt/external auth /keys/key"
	env := []string{
		"SUPPORTED_LOCAL_GUEST_PROOF_DIR=/tmp/es-proof-audit",
		"SUPPORTED_LOCAL_GUEST_BOOTSTRAP_DIR=/tmp/es-proof-audit.bootstrap",
		"SUPPORTED_LOCAL_GUEST_REPO_ROOT=/tmp/es-proof-audit.bootstrap/repo",
		"SUPPORTED_LOCAL_RETAINED_RESULT_AUTH_STORE_ID=stable_store",
		"SUPPORTED_LOCAL_RETAINED_RESULT_AUTH_KEY_ID=stable_key",
		"SUPPORTED_LOCAL_RETAINED_RESULT_AUTH_KEY_FILE=" + guestPath,
	}
	output, err := auditScriptSource(t, proofScript,
		"preflight_supported_local_proof_retained_result_auth; build_supported_local_guest_setup_command; printf '%s\\0' \"${SUPPORTED_LOCAL_GUEST_SETUP_CMD[@]}\"", env...)
	if err != nil {
		t.Fatalf("guest argument builder failed: %v output=%s", err, output)
	}
	arguments := strings.Split(strings.TrimSuffix(string(output), "\x00"), "\x00")
	for _, expected := range []string{
		"SUPPORTED_LOCAL_RETAINED_RESULT_AUTH_STORE_ID=stable_store",
		"SUPPORTED_LOCAL_RETAINED_RESULT_AUTH_KEY_ID=stable_key",
		"SUPPORTED_LOCAL_RETAINED_RESULT_AUTH_KEY_FILE=" + guestPath,
	} {
		found := false
		for _, argument := range arguments {
			if argument == expected {
				found = true
			}
		}
		if !found {
			t.Fatalf("exact guest metadata argument missing: %s", expected)
		}
	}
}

type review04ScriptFixture struct {
	repo        string
	bin         string
	proof       string
	hostProof   string
	precheckLog string
	effectLog   string
	env         map[string]string
}

func newReview04ScriptFixture(t *testing.T) review04ScriptFixture {
	t.Helper()
	root := t.TempDir()
	bin := filepath.Join(root, "bin")
	if err := os.Mkdir(bin, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "tmp"), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"bash", "env", "awk", "dirname", "pwd", "cat", "python3"} {
		path, err := exec.LookPath(name)
		if err != nil {
			t.Fatalf("resolve permitted fixture command %s: %v", name, err)
		}
		if err := os.Symlink(path, filepath.Join(bin, name)); err != nil {
			t.Fatal(err)
		}
	}
	for name, content := range map[string]string{
		"go": `#!/bin/sh
printf 'go\n' >> "$REVIEW04_PRECHECK_LOG"
if [ "${1-}" = version ]; then
  printf 'go version go1.26.5 darwin/arm64\n'
  exit 0
fi
printf 'go-operation\n' >> "$REVIEW04_EFFECT_LOG"
exit 97
`,
		"uname": `#!/bin/sh
if [ "${1-}" = -s ]; then
  printf 'uname\n' >> "$REVIEW04_PRECHECK_LOG"
  printf 'Linux\n'
  exit 0
fi
printf 'uname-operation\n' >> "$REVIEW04_EFFECT_LOG"
exit 97
`,
	} {
		if err := os.WriteFile(filepath.Join(bin, name), []byte(content), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	tripwire := []byte(`#!/bin/sh
printf 'operational:%s\n' "${0##*/}" >> "$REVIEW04_EFFECT_LOG"
exit 97
`)
	for _, name := range []string{
		"openssl", "curl", "tar", "vault", "docker", "nomad", "limactl",
		"mkdir", "tee", "rm", "sudo", "cp", "chmod", "chown", "kill", "systemctl",
	} {
		if err := os.WriteFile(filepath.Join(bin, name), tripwire, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	repo := executionPlatformRepoRoot(t)
	proof := filepath.Join(root, "proof")
	hostProof := filepath.Join(root, "host-proof")
	precheckLog := filepath.Join(root, "precheck.log")
	effectLog := filepath.Join(root, "operational.log")
	guestProof := "/tmp/es-proof-review04"
	return review04ScriptFixture{
		repo: repo, bin: bin, proof: proof, hostProof: hostProof,
		precheckLog: precheckLog, effectLog: effectLog,
		env: map[string]string{
			"PATH":                                          bin,
			"HOME":                                          root,
			"TMPDIR":                                        filepath.Join(root, "tmp"),
			"LC_ALL":                                        "C",
			"PYTHONDONTWRITEBYTECODE":                       "1",
			"EXECUTION_SUBSTRATE_REPO_ROOT":                 repo,
			"SUPPORTED_LOCAL_PROOF_ID":                      "review04-fixture",
			"SUPPORTED_LOCAL_PROOF_DIR":                     proof,
			"SUPPORTED_LOCAL_HOST_PROOF_DIR":                hostProof,
			"SUPPORTED_LOCAL_GUEST_PROOF_DIR":               guestProof,
			"SUPPORTED_LOCAL_GUEST_BOOTSTRAP_DIR":           guestProof + ".bootstrap",
			"SUPPORTED_LOCAL_GUEST_REPO_ROOT":               guestProof + ".bootstrap/repo",
			"SUPPORTED_LOCAL_REPO_ROOT_IN_GUEST":            "/opt/guest/repository",
			"SUPPORTED_LOCAL_RETAINED_RESULT_AUTH_STORE_ID": "test_store",
			"SUPPORTED_LOCAL_RETAINED_RESULT_AUTH_KEY_ID":   "test_key",
			"SUPPORTED_LOCAL_RETAINED_RESULT_AUTH_KEY_FILE": "/opt/external auth /keys/key",
			"REVIEW04_PRECHECK_LOG":                         precheckLog,
			"REVIEW04_EFFECT_LOG":                           effectLog,
		},
	}
}

func (fixture review04ScriptFixture) environment(t *testing.T) []string {
	t.Helper()
	values := make([]string, 0, len(fixture.env))
	for key, value := range fixture.env {
		values = append(values, key+"="+value)
	}
	return auditControlledScriptEnv(t, values...)
}

func (fixture review04ScriptFixture) scriptPath(name string) string {
	return filepath.Join(fixture.repo, "scripts", name)
}

func (fixture review04ScriptFixture) invoke(t *testing.T, script, mode, action string) (string, error) {
	t.Helper()
	path := fixture.scriptPath(script)
	var command *exec.Cmd
	switch mode {
	case "file":
		command = exec.Command(path, action)
	case "stdin":
		command = exec.Command("/bin/bash", "-s", "--", action)
		input, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		defer input.Close()
		command.Stdin = input
	case "source":
		function := "setup"
		if script == "73_supported_local_proof.sh" {
			function = "run"
		}
		command = exec.Command("/bin/bash", "-c",
			`source "$1"; declare -F "$2" >/dev/null; printf 'SOURCE_OK\n'`,
			"bash", path, function)
	default:
		t.Fatalf("unknown test invocation mode")
	}
	command.Dir = fixture.repo
	if script == "72_supported_local_setup.sh" && mode == "file" {
		withoutExplicitRoot := fixture
		withoutExplicitRoot.env = make(map[string]string, len(fixture.env))
		for key, value := range fixture.env {
			withoutExplicitRoot.env[key] = value
		}
		delete(withoutExplicitRoot.env, "EXECUTION_SUBSTRATE_REPO_ROOT")
		command.Env = withoutExplicitRoot.environment(t)
	} else {
		command.Env = fixture.environment(t)
	}
	output, err := command.CombinedOutput()
	return string(output), err
}

func (fixture review04ScriptFixture) assertNoOperationalEffects(t *testing.T) {
	t.Helper()
	for _, path := range []string{fixture.effectLog, fixture.proof, fixture.hostProof} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatalf("entrypoint reached operational effect or proof path: %v", err)
		}
	}
}

func TestRetainedResultReview04SetupInvocationModes(t *testing.T) {
	for _, test := range []struct{ script, mode string }{
		{"72_supported_local_setup.sh", "file"},
		{"72_supported_local_setup.sh", "stdin"},
		{"73_supported_local_proof.sh", "file"},
	} {
		t.Run(test.script+" "+test.mode+" help", func(t *testing.T) {
			fixture := newReview04ScriptFixture(t)
			output, err := fixture.invoke(t, test.script, test.mode, "--help")
			if err != nil || strings.Count(output, "Usage:") != 1 {
				t.Fatalf("real help dispatcher failed: err=%v output=%q", err, output)
			}
			fixture.assertNoOperationalEffects(t)
		})
	}
	for _, script := range []string{"72_supported_local_setup.sh", "73_supported_local_proof.sh"} {
		t.Run(script+" sourced", func(t *testing.T) {
			fixture := newReview04ScriptFixture(t)
			output, err := fixture.invoke(t, script, "source", "")
			if err != nil || output != "SOURCE_OK\n" {
				t.Fatalf("sourcing dispatched or hid production function: err=%v output=%q", err, output)
			}
			fixture.assertNoOperationalEffects(t)
		})
	}
	for _, test := range []struct{ script, mode string }{
		{"72_supported_local_setup.sh", "file"},
		{"72_supported_local_setup.sh", "stdin"},
		{"73_supported_local_proof.sh", "file"},
	} {
		t.Run(test.script+" "+test.mode+" unknown", func(t *testing.T) {
			fixture := newReview04ScriptFixture(t)
			output, err := fixture.invoke(t, test.script, test.mode, "unknown-action")
			if err == nil || strings.Count(output, "Usage:") != 1 {
				t.Fatalf("unknown action silently succeeded or missed dispatcher: err=%v output=%q", err, output)
			}
			fixture.assertNoOperationalEffects(t)
		})
	}
}

func TestRetainedResultReview04StdinSetupRejectsBeforeEffects(t *testing.T) {
	const refusal = "supported-local retained-result auth metadata or key placement is invalid\n"
	for _, test := range []struct{ mode, variable, value string }{
		{"file", "SUPPORTED_LOCAL_RETAINED_RESULT_AUTH_STORE_ID", ""},
		{"stdin", "SUPPORTED_LOCAL_RETAINED_RESULT_AUTH_STORE_ID", ""},
		{"file", "SUPPORTED_LOCAL_RETAINED_RESULT_AUTH_KEY_ID", "Upper"},
		{"stdin", "SUPPORTED_LOCAL_RETAINED_RESULT_AUTH_KEY_ID", "Upper"},
	} {
		t.Run(test.mode+" "+test.variable+" "+test.value, func(t *testing.T) {
			fixture := newReview04ScriptFixture(t)
			fixture.env[test.variable] = test.value
			output, err := fixture.invoke(t, "72_supported_local_setup.sh", test.mode, "setup")
			if err == nil || output != refusal {
				t.Fatalf("actual setup entrypoint missed metadata refusal: err=%v output=%q", err, output)
			}
			precheck, err := os.ReadFile(fixture.precheckLog)
			if err != nil || string(precheck) != "uname\ngo\n" {
				t.Fatalf("actual setup preflight order changed: err=%v precheck=%q", err, precheck)
			}
			fixture.assertNoOperationalEffects(t)
		})
	}
}

func TestRetainedResultReview04RootScopeRejectedBeforeEffects(t *testing.T) {
	const refusal = "supported-local retained-result auth metadata or key placement is invalid\n"
	t.Run("setup proof", func(t *testing.T) {
		fixture := newReview04ScriptFixture(t)
		fixture.env["SUPPORTED_LOCAL_PROOF_DIR"] = "/"
		output, err := fixture.invoke(t, "72_supported_local_setup.sh", "file", "setup")
		if err == nil || output != "SUPPORTED_LOCAL_PROOF_DIR is unsafe\n" {
			t.Fatalf("setup root proof scope was not refused: err=%v output=%q", err, output)
		}
		precheck, err := os.ReadFile(fixture.precheckLog)
		if err != nil || string(precheck) != "uname\n" {
			t.Fatalf("setup root proof scope passed its early boundary: err=%v precheck=%q", err, precheck)
		}
		fixture.assertNoOperationalEffects(t)
	})
	for _, variable := range []string{
		"SUPPORTED_LOCAL_GUEST_PROOF_DIR",
		"SUPPORTED_LOCAL_GUEST_BOOTSTRAP_DIR",
		"SUPPORTED_LOCAL_GUEST_REPO_ROOT",
		"SUPPORTED_LOCAL_REPO_ROOT_IN_GUEST",
		"SUPPORTED_LOCAL_HOST_PROOF_DIR",
	} {
		t.Run(variable, func(t *testing.T) {
			fixture := newReview04ScriptFixture(t)
			fixture.env[variable] = "/"
			output, err := fixture.invoke(t, "73_supported_local_proof.sh", "file", "run")
			if err == nil || output != refusal {
				t.Fatalf("actual wrapper entrypoint missed root-scope refusal: err=%v output=%q", err, output)
			}
			precheck, err := os.ReadFile(fixture.precheckLog)
			if err != nil || string(precheck) != "go\n" {
				t.Fatalf("actual wrapper preflight order changed: err=%v precheck=%q", err, precheck)
			}
			fixture.assertNoOperationalEffects(t)
		})
	}
}

func TestRetainedResultReview04ScopeContainment(t *testing.T) {
	const key = "/opt/external auth /keys/key"
	for _, test := range []struct {
		name, key, scope string
		valid            bool
	}{
		{"root scope", key, "/", false},
		{"equal", key, key, false},
		{"scope ancestor", key, "/opt/external auth /keys", false},
		{"scope descendant", key, key + "/child", false},
		{"space-bearing ancestor", key, "/opt/external auth ", false},
		{"different space-bearing component", key, "/opt/external auth/keys", true},
		{"sibling prefix", key, "/opt/external auth /keys2", true},
		{"file sibling prefix", key, key + "2", true},
		{"leading double slash", key, "//opt/proof", false},
		{"dot component", key, "/opt/./proof", false},
		{"parent component", key, "/opt/other/../proof", false},
		{"stale cleanup", "/tmp/es-proof-old/keys/key", "/opt/proof", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newReview04ScriptFixture(t)
			command := exec.Command("/bin/bash", "-c",
				`source "$1"; supported_local_validate_retained_result_auth "$2" "$3" "$4" "$5"`,
				"bash", fixture.scriptPath("internal/supported_local_retained_result_auth.sh"),
				"test_store", "test_key", test.key, test.scope)
			command.Dir = fixture.repo
			command.Env = fixture.environment(t)
			output, err := command.CombinedOutput()
			if test.valid {
				if err != nil || len(output) != 0 {
					t.Fatalf("valid disjoint path refused: err=%v output=%q", err, output)
				}
			} else if err == nil || string(output) != "supported-local retained-result auth metadata or key placement is invalid\n" {
				t.Fatalf("unsafe path admitted or disclosed: err=%v output=%q", err, output)
			}
			fixture.assertNoOperationalEffects(t)
		})
	}
}
