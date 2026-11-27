package admission

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	arscontract "execution-substrate/ars/contract"
	egscontract "execution-substrate/egs/contract"
	"execution-substrate/es/admission/internal/admissionstate"
	esconfig "execution-substrate/es/config"
	evidencev1 "execution-substrate/internal/contracts/evidence/v1"
	runtimeconfigv1 "execution-substrate/internal/contracts/runtimeconfig/v1"
	"execution-substrate/internal/observability"

	"golang.org/x/text/unicode/norm"
	"golang.org/x/text/unicode/rangetable"
)

const (
	codeInvalidRequest                  = "invalid_request"
	codeArtifactEvidenceNotFound        = "artifact_evidence_not_found"
	codeManifestNotFound                = "manifest_not_found"
	codeArtifactEvidenceInvalid         = "artifact_evidence_invalid"
	codeArtifactEvidenceUnavailable     = "artifact_evidence_unavailable"
	codeProvenanceNotFound              = "provenance_not_found"
	codeDerivationMetadataNotFound      = "derivation_metadata_not_found"
	codeDerivationAttestationNotFound   = "derivation_attestation_not_found"
	codeWorkloadIdentityBindingNotFound = "workload_identity_binding_not_found"
	codeProvenanceInvalid               = "provenance_invalid"
	codeDerivationAttestationInvalid    = "derivation_attestation_invalid"
	codeWorkloadIdentityBindingInvalid  = "workload_identity_binding_invalid"
	codeSignerNotAllowed                = "signer_not_allowed"
	codeSignerRevoked                   = "signer_revoked"
	codeArtifactRevoked                 = "artifact_revoked"
	codeWorkloadZoneVaultUnavailable    = "workload_zone_vault_unavailable"
	codeExecutionRuntimeUnavailable     = "execution_runtime_unavailable"
	codeUnsupportedExecutionMode        = "unsupported_execution_mode"
	codeUnsupportedArtifactType         = "unsupported_artifact_type"
	codeUnsupportedCapabilities         = "unsupported_capabilities"
	codeUnsupportedRuntimeProfile       = "unsupported_runtime_profile"
	codePayloadUnavailable              = "payload_unavailable"
	codeSubmissionFailed                = "submission_failed"
	codeInvalidRunID                    = "invalid_run_id"
	codeExecutionNotFound               = "execution_not_found"
	codeLogsUnavailable                 = "logs_unavailable"
	codeResultUnavailable               = "result_unavailable"
	codeResultNotFound                  = "result_not_found"
	codeMountConflict                   = "mount_conflict"
	codeMountArtifactInvalid            = "mount_artifact_invalid"
)

var (
	labeledSHA256DigestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	// reservedRuntimeEnvKeys, reservedRuntimeEnvPrefixes and
	// reservedRuntimeEnvSuffixes name the environment keys a caller may
	// never set, whatever the artifact declares. They are written in upper
	// case and matched against the
	// caller's key with ASCII letters folded to upper case, so http_proxy is
	// reserved with HTTPS_PROXY. They are a backstop, not the boundary: the
	// boundary is the artifact's signed environment allowlist, which admits
	// no caller key when it is empty (validateInvocationAgainstManifest). No
	// list can name every variable every program reads.
	reservedRuntimeEnvKeys = map[string]struct{}{
		// Keys ES sets or owns for the run's identity, platform and trust.
		"PROJECT_NAME":                {},
		"ENVIRONMENT":                 {},
		"PLATFORM":                    {},
		"GUID":                        {},
		"SERVICE_ID":                  {},
		"SESSION_ID":                  {},
		"PARENT_SESSION_ID":           {},
		"TRACEPARENT":                 {},
		"EXEC_SVID_PATH":              {},
		"VAULT_AGENT_TOKEN_PATH":      {},
		"VAULT_ADDR":                  {},
		"VAULT_CACERT":                {},
		"VAULT_NAMESPACE":             {},
		"SSL_CERT_FILE":               {},
		runtimeIdentityEndpointEnvKey: {},

		// The keys the GNU C library removes before it starts a set-user-ID
		// program (glibc 2.42, sysdeps/generic/unsecvars.h). Its LD_ keys are
		// covered by the LD_ prefix below.
		"GCONV_PATH":             {},
		"GETCONF_DIR":            {},
		"GLIBC_TUNABLES":         {},
		"HOSTALIASES":            {},
		"LOCALDOMAIN":            {},
		"LOCPATH":                {},
		"MALLOC_ARENA_MAX":       {},
		"MALLOC_ARENA_TEST":      {},
		"MALLOC_MMAP_MAX_":       {},
		"MALLOC_MMAP_THRESHOLD_": {},
		"MALLOC_PERTURB_":        {},
		"MALLOC_TOP_PAD_":        {},
		"MALLOC_TRACE":           {},
		"MALLOC_TRIM_THRESHOLD_": {},
		"NIS_PATH":               {},
		"NLSPATH":                {},
		"RESOLV_HOST_CONF":       {},
		"RES_OPTIONS":            {},
		"TMPDIR":                 {},
		"TZDIR":                  {},

		// The keys sudo 1.9.16p2 removes from the environment of every
		// command it runs (plugins/sudoers/env.c, initial_badenv_table, the
		// entries that apply on Linux; its wildcard entries are prefixes
		// below), and the entries sudo's development branch adds to that
		// table after 1.9.16p2: _JAVA_OPTIONS, CLASSPATH, NODE_OPTIONS and
		// NODE_PATH here, PYTHONSTARTUP, GIT_SSH_COMMAND and GIT_CONFIG_*
		// under the PYTHON and GIT_ prefixes below, and GCONV_PATH, which
		// the glibc list above already holds.
		"IFS":               {},
		"CDPATH":            {},
		"PATH_LOCALE":       {},
		"KRB5_KTNAME":       {},
		"TERMINFO":          {},
		"TERMINFO_DIRS":     {},
		"TERMPATH":          {},
		"TERMCAP":           {},
		"ENV":               {},
		"BASH_ENV":          {},
		"PS4":               {},
		"GLOBIGNORE":        {},
		"BASHOPTS":          {},
		"SHELLOPTS":         {},
		"JAVA_TOOL_OPTIONS": {},
		"_JAVA_OPTIONS":     {},
		"CLASSPATH":         {},
		"PERLIO_DEBUG":      {},
		"PERLLIB":           {},
		"PERL5LIB":          {},
		"PERL5OPT":          {},
		"PERL5DB":           {},
		"FPATH":             {},
		"NULLCMD":           {},
		"READNULLCMD":       {},
		"ZDOTDIR":           {},
		"TMPPREFIX":         {},
		"RUBYLIB":           {},
		"RUBYOPT":           {},
		"NODE_OPTIONS":      {},
		"NODE_PATH":         {},

		// Keys that decide which program a name runs and where programs read
		// per-user startup and configuration files (Python's user site
		// directory and its usercustomize module, Git, shells), and the Java
		// launcher's own options key.
		"PATH":             {},
		"HOME":             {},
		"JDK_JAVA_OPTIONS": {},

		// Keys that send the run's traffic through a host of the caller's
		// choosing, exempt hosts from a proxy, change which certificates the
		// run trusts, or write its TLS session keys to a file.
		"HTTP_PROXY":                   {},
		"HTTPS_PROXY":                  {},
		"ALL_PROXY":                    {},
		"FTP_PROXY":                    {},
		"NO_PROXY":                     {},
		"SSL_CERT_DIR":                 {},
		"REQUESTS_CA_BUNDLE":           {},
		"CURL_CA_BUNDLE":               {},
		"NODE_EXTRA_CA_CERTS":          {},
		"NODE_TLS_REJECT_UNAUTHORIZED": {},
		"SSLKEYLOGFILE":                {},

		// Keys of the same kinds that the lists above do not name and that
		// no prefix below covers (red-team report 19 and re-check 23 on PR
		// #74): a switch the repository's own Vault login code reads to skip
		// the TLS check (any key ending in INSECURE_SKIP_VERIFY is also
		// reserved, below); client configuration files; other proxies and
		// trust stores; Node.js keys that load or write files; other Java
		// virtual machines' option keys; Python environments and settings
		// modules; programs that other programs start by name; module paths
		// of R and Tcl; build and archive tool options and helper programs;
		// the Go toolchain keys that choose which toolchain, compiler or helper
		// command runs, including pkg-config and the Fortran compiler, where
		// modules, sources and build results come from or go, or how the
		// toolchain builds and fetches (every such key go help environment
		// lists, Go 1.26.5), and the two that change how ES's own Go supervisor
		// runs in the container; the GNU C compiler's keys that choose the
		// programs it runs, the headers and libraries it builds with, extra
		// options, or a file it writes with text the caller chooses: every such
		// key a GCC program reads that the GCC 14.2.0 manual names in any
		// section (gcc/doc/gcc.texi and the files it includes), not only in its
		// section on environment variables, among them MAKE, the program
		// lto-wrapper runs for a parallel link, CXX_MODULE_MAPPER, whose
		// "|program" form names a program cc1plus starts,
		// MSP430_GCC_INCLUDE_DIR, a header and linker-script directory of the
		// msp430 port, and VSB_DIR, which gcc's VxWorks 7 specs read for header
		// directories and to choose a library (the manual's spec-file example);
		// and LPATH and OBJCPLUS_INCLUDE_PATH, which gcc reads and the manual
		// leaves out; and the directory, domain and language list bash reads the
		// translations of $"..." strings from, which it expands as double-quoted
		// text, so a catalog the caller chooses could run commands in a script
		// that translates its messages. Upstream glibc's gettext skips a
		// LANGUAGE entry that holds a path only in set-user-ID programs
		// (intl/dcigettext.c, 2.39 and 2.42), so LANGUAGE=../x can name a
		// catalog outside the directory; the one Ubuntu build tested ignored
		// such entries, and a backstop does not rest on one build.
		"WORKLOAD_VAULT_INSECURE_SKIP_VERIFY": {},
		"WGETRC":                              {},
		"NETRC":                               {},
		"AWS_CONFIG_FILE":                     {},
		"AWS_SHARED_CREDENTIALS_FILE":         {},
		"AWS_CA_BUNDLE":                       {},
		"KUBECONFIG":                          {},
		"GNUPGHOME":                           {},
		"WS_PROXY":                            {},
		"WSS_PROXY":                           {},
		"RSYNC_PROXY":                         {},
		"SOCKS_PROXY":                         {},
		"NODE_REPL_EXTERNAL_MODULE":           {},
		"NODE_COMPILE_CACHE":                  {},
		"NODE_ICU_DATA":                       {},
		"NODE_V8_COVERAGE":                    {},
		"NODE_REDIRECT_WARNINGS":              {},
		"NODE_REPL_HISTORY":                   {},
		"OPENJ9_JAVA_OPTIONS":                 {},
		"IBM_JAVA_OPTIONS":                    {},
		"VIRTUAL_ENV":                         {},
		"DJANGO_SETTINGS_MODULE":              {},
		"SHELL":                               {},
		"PAGER":                               {},
		"MANPAGER":                            {},
		"EDITOR":                              {},
		"VISUAL":                              {},
		"BROWSER":                             {},
		"SUDO_ASKPASS":                        {},
		"R_PROFILE":                           {},
		"R_PROFILE_USER":                      {},
		"R_ENVIRON":                           {},
		"R_ENVIRON_USER":                      {},
		"R_LIBS":                              {},
		"R_LIBS_USER":                         {},
		"R_LIBS_SITE":                         {},
		"TCLLIBPATH":                          {},
		"MAKEFLAGS":                           {},
		"MFLAGS":                              {},
		"GNUMAKEFLAGS":                        {},
		"MAKEFILES":                           {},
		"TAR_OPTIONS":                         {},
		"LESSOPEN":                            {},
		"LESSCLOSE":                           {},
		"CC":                                  {},
		"CXX":                                 {},
		"CPP":                                 {},
		"LD":                                  {},
		"AR":                                  {},
		"AS":                                  {},
		"CFLAGS":                              {},
		"CXXFLAGS":                            {},
		"CPPFLAGS":                            {},
		"LDFLAGS":                             {},
		"RUSTFLAGS":                           {},
		"RUSTDOC":                             {},
		"RUSTDOCFLAGS":                        {},
		"GODEBUG":                             {},
		"GOTRACEBACK":                         {},
		"GOFLAGS":                             {},
		"GOENV":                               {},
		"GOTOOLCHAIN":                         {},
		"GOPROXY":                             {},
		"GONOPROXY":                           {},
		"GOPRIVATE":                           {},
		"GOINSECURE":                          {},
		"GOSUMDB":                             {},
		"GONOSUMDB":                           {},
		"GONOSUMCHECK":                        {},
		"GOROOT":                              {},
		"GOPATH":                              {},
		"GOBIN":                               {},
		"GOCACHE":                             {},
		"GOCACHEPROG":                         {},
		"GOMODCACHE":                          {},
		"GOWORK":                              {},
		"GOAUTH":                              {},
		"GOVCS":                               {},
		"GOEXPERIMENT":                        {},
		"GOTMPDIR":                            {},
		"GCCGO":                               {},
		"GCCGOTOOLDIR":                        {},
		"FC":                                  {},
		"GCC_EXEC_PREFIX":                     {},
		"COMPILER_PATH":                       {},
		"LIBRARY_PATH":                        {},
		"CPATH":                               {},
		"C_INCLUDE_PATH":                      {},
		"CPLUS_INCLUDE_PATH":                  {},
		"OBJC_INCLUDE_PATH":                   {},
		"GCC_COMPARE_DEBUG":                   {},
		"LPATH":                               {},
		"OBJCPLUS_INCLUDE_PATH":               {},
		"DEPENDENCIES_OUTPUT":                 {},
		"SUNPRO_DEPENDENCIES":                 {},
		"MAKE":                                {},
		"CXX_MODULE_MAPPER":                   {},
		"MSP430_GCC_INCLUDE_DIR":              {},
		"VSB_DIR":                             {},
		"TEXTDOMAINDIR":                       {},
		"TEXTDOMAIN":                          {},
		"LANGUAGE":                            {},
	}
	reservedRuntimeEnvPrefixes = []string{
		"EXEC_",
		"EXEC_WORKLOAD_VAULT_",
		// The dynamic loader's keys (glibc and musl), and sudo 1.9.16p2's
		// wildcard entries LD_*, _RLD* and KRB5_CONFIG*.
		"LD_",
		"_RLD",
		"KRB5_CONFIG",
		// CPython and Git read many keys under these prefixes to load code,
		// run commands or change TLS verification. They cover sudo
		// 1.9.16p2's PYTHONHOME, PYTHONPATH, PYTHONINSPECT and
		// PYTHONUSERBASE, and the later PYTHONSTARTUP, GIT_SSH_COMMAND and
		// GIT_CONFIG_*.
		"PYTHON",
		"GIT_",
		// Bash imports a function from a key of this form. Such a key is not
		// a valid caller key name in any case (it ends in %%).
		"BASH_FUNC_",
		// Whole families whose keys load code, name a program or a
		// configuration file, or change TLS trust, the address a client
		// talks to or its credentials (red-team report 19 on PR #74). A
		// family is reserved as a whole so that the list does not have to
		// keep up with each program's next key:
		// the Vault client, beyond the three keys ES sets;
		"VAULT_",
		// per-user configuration directories, which stand in for HOME;
		"XDG_",
		// OpenSSL's configuration file, modules and engines;
		"OPENSSL_",
		// npm settings, which npm reads in either letter case;
		"NPM_CONFIG_",
		// the scheduler's own task variables;
		"NOMAD_",
		// the agent CLI the control-plane image installs: its configuration
		// directory, and the address it sends requests and its credential to;
		"CODEX_",
		"OPENAI_",
		// Python's package installer and test runner;
		"PIP_",
		"PYTEST_",
		// Perl and Ruby, which the sudo list covers only in part, and Ruby's
		// gem and bundler settings;
		"PERL",
		"RUBY",
		"GEM_",
		"BUNDLE_",
		// Java's home and option keys, and the two common Java build tools;
		"JAVA_",
		"MAVEN_",
		"GRADLE_",
		// .NET runtime configuration, startup hooks and profilers;
		"DOTNET_",
		"CORECLR_",
		"COMPLUS_",
		// PHP's configuration file and scan directory, and Lua's start code
		// and module paths;
		"PHP",
		"LUA_",
		// Rust's build tool, toolchain installer and compiler wrappers;
		"CARGO_",
		"RUSTUP_",
		"RUSTC",
		// cgo's compiler and linker flags and their allow and deny lists, and
		// the pkg-config program a cgo build runs and the keys that choose
		// the .pc files that give it flags and libraries;
		"CGO_",
		"PKG_CONFIG",
		// client configuration that names helper programs, sockets or
		// trust: Docker, ssh, gRPC and curl.
		"DOCKER_",
		"SSH_",
		"GRPC_",
		"CURL_",
	}
	reservedRuntimeEnvSuffixes = []string{
		// Switches that turn off a client's TLS certificate check, named
		// after the InsecureSkipVerify field of Go's crypto/tls. The
		// repository's own Vault login code reads
		// WORKLOAD_VAULT_INSECURE_SKIP_VERIFY and the legacy reference
		// workload reads REFERENCE_VAULT_INSECURE_SKIP_VERIFY. A suffix, not
		// a list, so that the next workload's switch of the same name is
		// reserved too.
		"INSECURE_SKIP_VERIFY",
	}
)

type Error struct {
	Status  int
	Code    string
	Message string
}

func (e *Error) Error() string {
	return e.Message
}

type Service struct {
	cfg        esconfig.Config
	resultAuth *retainedResultAuthenticator

	workloadZoneVaultConfigRef runtimeconfigv1.WorkloadZoneVaultConfigRef
	arsClient                  *dependencyClient
	egsClient                  *dependencyClient

	trustModelVerifier       *ed25519Verifier
	provenanceVerifier       *ed25519Verifier
	nomadClient              *nomadClient
	admissionPolicyEvaluator AdmissionPolicyEvaluator

	mu         sync.RWMutex
	trustModel *egscontract.RuntimeTrustPolicy
	// Private operational authority is commissioned only by the unwired handoff.
	// trustModelVerified and trustModelOwner say that this Service loaded and
	// verified its trust model itself; Service.mu protects them.
	trustModelVerified bool
	trustModelOwner    *Service
	// operational is the handle of the admission state: the installed view,
	// the withdrawal and supersession latches and the confirmation time. The
	// state lives in the package admissionstate behind its own lock, and
	// NewService sets the handle once. A Service made without NewService holds
	// the zero handle, which is closed.
	operational      admissionstate.State
	operationalProof *operationalAdmissionProofHooks
}

type dependencyClient struct {
	dependencyName string
	baseURL        *url.URL
	client         *http.Client
}

type ed25519Verifier struct {
	algorithm string
	keyID     string
	publicKey ed25519.PublicKey
}

// TODO: ARS publishes richer health payloads today, but ES must not grow an
//
//	implicit shared health-schema dependency around those additional fields.
//	Revisit only if the platform adopts an explicit shared readiness contract.
//
// healthResponse is intentionally minimal. ES only depends on dependency
type healthResponse struct {
	Status string `json:"status"`
	Ready  bool   `json:"ready"`
}

type signedRuntimeTrustResponse struct {
	RuntimeTrust  egscontract.RuntimeTrustPolicy `json:"runtime_trust"`
	Algorithm     string                         `json:"algorithm"`
	KeyID         string                         `json:"key_id"`
	PayloadDigest string                         `json:"payload_digest"`
	Signature     string                         `json:"signature"`
	Publication   json.RawMessage                `json:"publication,omitempty"`
}

type artifactRegistryErrorResponse struct {
	Error string `json:"error"`
}

type discoveredArtifact struct {
	discovery arscontract.ArtifactDiscovery
	evidence  evidencev1.ArtifactEvidence
}

type preparedArtifact struct {
	privateExecutionValue
	manifest       Manifest
	payloadDigest  string
	targetPlatform string
	networkAccess  bool
	// Owned full signed record from the same successful artifact admission.
	provenanceRecord string
}

type preparedAdmission struct {
	privateExecutionValue
	admittedRequest             PrepareRequest
	result                      PrepareResult
	artifact                    preparedArtifact
	workloadVaultPlan           esconfig.ResolvedWorkloadVaultAuthPlan
	workloadZoneVaultConfigRef  runtimeconfigv1.WorkloadZoneVaultConfigRef
	trustModel                  egscontract.RuntimeTrustPolicy
	policyPayloadBytes          []byte
	policyPayloadBytesAvailable bool
}

type admissionIntent uint8

const (
	admissionIntentPrepare admissionIntent = iota
	admissionIntentSubmit
)

func NewService(cfg esconfig.Config) (*Service, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	workloadZoneVaultConfigRef := cfg.RuntimeConfig.WorkloadZoneVaultConfigRef.Normalized()
	arsClient, err := newDependencyClient(cfg.Dependencies.ArtifactRegistry, "artifact-registry")
	if err != nil {
		return nil, fmt.Errorf("build artifact registry client: %w", err)
	}
	egsClient, err := newDependencyClient(cfg.Dependencies.ExecutionGovernance, "execution-governance")
	if err != nil {
		return nil, fmt.Errorf("build execution governance client: %w", err)
	}

	trustModelVerifier, err := newEd25519Verifier(cfg.Verification.TrustModel)
	if err != nil {
		return nil, err
	}
	provenanceVerifier, err := newEd25519Verifier(cfg.Verification.Provenance)
	if err != nil {
		return nil, err
	}
	if _, err := newEd25519Verifier(cfg.Verification.DerivationAttestation); err != nil {
		return nil, err
	}
	if _, err := newEd25519Verifier(cfg.Verification.WorkloadIdentityBinding); err != nil {
		return nil, err
	}

	var nomadClient *nomadClient
	var resultAuth *retainedResultAuthenticator
	if cfg.SubmitConfigured() {
		resultAuth, err = loadRetainedResultAuthenticator(cfg.Execution)
		if err != nil {
			return nil, err
		}
		// The Nomad token is a startup prerequisite like the result key: a
		// missing or unsafe token file refuses startup before any execution
		// root is provisioned.
		nomadClient, err = newNomadClient(cfg.Nomad)
		if err != nil {
			return nil, fmt.Errorf("build nomad client: %w", err)
		}
		roots, err := provisionExecutionRoots(cfg.Execution.StagingRootDir, cfg.Execution.ResultsRootDir, nil)
		if err != nil {
			return nil, err
		}
		owner, err := roots.owner()
		if err != nil {
			_ = roots.close()
			return nil, err
		}
		if err := roots.probeCapabilities(owner); err != nil {
			_ = roots.close()
			return nil, fmt.Errorf("validate execution root capabilities: %w", err)
		}
		if err := roots.reobserve(); err != nil {
			_ = roots.close()
			return nil, fmt.Errorf("requalify execution roots after capability probes: %w", err)
		}
		if err := roots.close(); err != nil {
			return nil, fmt.Errorf("close qualified execution roots: %w", err)
		}
		if err := validateExecutionRuntimeInputs(cfg.Execution); err != nil {
			return nil, err
		}
	}

	service := &Service{
		cfg:                        cfg,
		resultAuth:                 resultAuth,
		workloadZoneVaultConfigRef: workloadZoneVaultConfigRef,
		arsClient:                  arsClient,
		egsClient:                  egsClient,
		trustModelVerifier:         trustModelVerifier,
		provenanceVerifier:         provenanceVerifier,
		nomadClient:                nomadClient,
		admissionPolicyEvaluator:   admissionPolicyEvaluatorFromConfig(cfg.AdmissionPolicy),
	}
	service.operational = admissionstate.New(service)
	return service, nil
}

func validateExecutionRuntimeInputs(cfg esconfig.ExecutionConfig) error {
	if err := validateSPIREWorkloadAPISocketPathConfigShape(cfg.SPIREWorkloadAPISocketPath); err != nil {
		return err
	}
	if err := validateBoundedRegularFile(cfg.RuntimeSupportBinary, maxRuntimeSupportBytes); err != nil {
		return fmt.Errorf("validate execution.runtime_support_binary: %w", err)
	}
	return nil
}

func validateSPIREWorkloadAPISocketPathConfigShape(path string) error {
	trimmed := strings.TrimSpace(path)
	if trimmed == "" {
		return fmt.Errorf("validate execution.spire_workload_api_socket_path: path is required")
	}
	if !filepath.IsAbs(trimmed) {
		return fmt.Errorf("validate execution.spire_workload_api_socket_path: path must be absolute")
	}
	return nil
}

func (s *Service) Initialize(ctx context.Context) error {
	if s.operational.Commissioned() {
		return fmt.Errorf("private operational authority is already commissioned or withdrawn")
	}
	normalized, err := s.fetchVerifiedTrustModel(ctx)
	if err != nil {
		return err
	}

	// Service.mu is held across this question and the write below. An install
	// holds it too, so no view is installed between the two.
	s.mu.Lock()
	if s.operational.Commissioned() {
		s.mu.Unlock()
		return fmt.Errorf("private operational authority was commissioned during trust load")
	}
	s.trustModel = &normalized
	s.trustModelVerified = true
	s.trustModelOwner = s
	s.mu.Unlock()

	return nil
}

// fetchVerifiedTrustModel requests the signed runtime trust model from EGS,
// verifies its envelope and returns the normalized policy. It reads and
// changes no Service state; Initialize and the private operational
// confirmation are its only callers.
func (s *Service) fetchVerifiedTrustModel(ctx context.Context) (egscontract.RuntimeTrustPolicy, error) {
	requestCtx, cancel := context.WithTimeout(ctx, s.egsClient.client.Timeout)
	defer cancel()

	response, err := s.egsClient.get(requestCtx, "/v1/trust-model")
	if err != nil {
		return egscontract.RuntimeTrustPolicy{}, fmt.Errorf("fetch trust model: %w", err)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return egscontract.RuntimeTrustPolicy{}, fmt.Errorf("fetch trust model: unexpected status %d", response.StatusCode)
	}

	var payload signedRuntimeTrustResponse
	if err := decodeBoundedJSONResponse(response, &payload); err != nil {
		return egscontract.RuntimeTrustPolicy{}, fmt.Errorf("decode trust model response: %w", err)
	}
	if err := payload.RuntimeTrust.Validate(); err != nil {
		return egscontract.RuntimeTrustPolicy{}, fmt.Errorf("validate trust model: %w", err)
	}

	canonical, err := payload.RuntimeTrust.CanonicalBytes()
	if err != nil {
		return egscontract.RuntimeTrustPolicy{}, fmt.Errorf("canonicalize trust model: %w", err)
	}
	if err := s.verifyTrustModelEnvelope(payload, canonical); err != nil {
		return egscontract.RuntimeTrustPolicy{}, fmt.Errorf("verify trust model: %w", err)
	}

	return payload.RuntimeTrust.Normalized(), nil
}

func (s *Service) Health(ctx context.Context) HealthSnapshot {
	// TODO: This milestone slice fetches TrustModel only at startup and does not
	// 		 treat live EGS reachability as a runtime readiness dependency afterward.
	// 		 If a later slice introduces background TrustModel refresh or LKG behavior,
	// 		 revisit ES /health semantics explicitly instead of expanding them by drift.
	type result struct {
		ok bool
	}

	arsCh := make(chan result, 1)

	go func() {
		arsCh <- result{ok: s.arsClient.checkReady(ctx)}
	}()

	arsResult := <-arsCh

	s.mu.RLock()
	loaded := s.trustModel != nil
	s.mu.RUnlock()

	return HealthSnapshot{
		ArtifactRegistryHealthy: arsResult.ok,
		TrustModelLoaded:        loaded,
	}
}

func (s *Service) Prepare(ctx context.Context, req PrepareRequest) (PrepareResult, *Error) {
	prepared, err := s.prepareAdmission(ctx, req, admissionIntentPrepare)
	if err != nil {
		return PrepareResult{}, err
	}
	if err := s.validateRuntimeProfileForPrepare(prepared.admittedRequest, prepared); err != nil {
		return PrepareResult{}, err
	}
	return prepared.result, nil
}

func (s *Service) prepareAdmission(ctx context.Context, req PrepareRequest, intent admissionIntent) (preparedAdmission, *Error) {
	req = snapshotAdmissionRequest(req)
	switch intent {
	case admissionIntentPrepare:
	case admissionIntentSubmit:
		if req.Mode == "" {
			req.Mode = ExecutionModeAsync
		}
		if req.Mode != ExecutionModeAsync {
			return preparedAdmission{}, &Error{
				Status:  http.StatusBadRequest,
				Code:    codeUnsupportedExecutionMode,
				Message: "only async submission is supported in this execution slice",
			}
		}
	default:
		panic("unknown private admission intent")
	}
	if err := validatePrepareRequest(&req); err != nil {
		return preparedAdmission{}, err
	}

	trustModel := s.currentTrustModel()
	if trustModel == nil {
		return preparedAdmission{}, &Error{
			Status:  http.StatusServiceUnavailable,
			Code:    "trust_model_unavailable",
			Message: "trust model is unavailable",
		}
	}

	artifact, err := s.prepareArtifact(ctx, req, *trustModel)
	if err != nil {
		return preparedAdmission{}, err
	}

	workloadVaultRef := s.workloadZoneVaultConfigRef
	workloadVaultConfig, err := s.fetchWorkloadZoneVaultConfig(ctx, workloadVaultRef)
	if err != nil {
		return preparedAdmission{}, err
	}

	plan, resolveErr := s.cfg.WorkloadVaultAuth.Resolve(workloadVaultConfig)
	if resolveErr != nil {
		return preparedAdmission{}, &Error{
			Status:  http.StatusServiceUnavailable,
			Code:    codeWorkloadZoneVaultUnavailable,
			Message: "workload-zone vault configuration is invalid",
		}
	}

	policyPayloadBytes, policyPayloadBytesAvailable, policyErr := s.enforceAdmissionPolicy(ctx, req, artifact)
	if policyErr != nil {
		return preparedAdmission{}, policyErr
	}

	return preparedAdmission{
		admittedRequest: snapshotAdmissionRequest(req),
		result: PrepareResult{
			Success: true,
		},
		artifact:                    artifact,
		workloadVaultPlan:           plan,
		workloadZoneVaultConfigRef:  workloadVaultRef,
		trustModel:                  snapshotRuntimeTrustModel(*trustModel),
		policyPayloadBytes:          policyPayloadBytes,
		policyPayloadBytesAvailable: policyPayloadBytesAvailable,
	}, nil
}

func (s *Service) prepareArtifact(ctx context.Context, req PrepareRequest, trustModel egscontract.RuntimeTrustPolicy) (preparedArtifact, *Error) {
	discovery, err := s.fetchArtifactDiscovery(ctx, req.Invocation.ArtifactDigest)
	if err != nil {
		return preparedArtifact{}, err
	}
	artifact, err := s.prepareArtifactFromDiscovery(req, trustModel, discovery)
	if err != nil {
		return preparedArtifact{}, err
	}
	// The successful ordinary resolution owns the exact typed record it used.
	// This carrier is inert for ordinary Submit and never enters its plan. A
	// record that cannot be represented leaves the carrier empty: ordinary
	// Prepare and Submit proceed, and the private builder refuses an empty one.
	if fullRecord, marshalErr := json.Marshal(discovery.evidence); marshalErr == nil {
		artifact.provenanceRecord = string(fullRecord)
	}
	return artifact, nil
}

func (s *Service) currentTrustModel() *egscontract.RuntimeTrustPolicy {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.trustModel == nil {
		return nil
	}
	snapshot := snapshotRuntimeTrustModel(*s.trustModel)
	return &snapshot
}

func (s *Service) fetchArtifactDiscovery(ctx context.Context, artifactDigest string) (discoveredArtifact, *Error) {
	discovery, err := s.fetchArtifactDiscoveryRecord(ctx, artifactDigest)
	if err != nil {
		return discoveredArtifact{}, err
	}
	evidence, err := s.fetchArtifactEvidenceBlob(ctx, artifactDigest, discovery.Evidence.Digest)
	if err != nil {
		return discoveredArtifact{}, err
	}
	return discoveredArtifact{
		discovery: discovery,
		evidence:  evidence,
	}, nil
}

func (s *Service) fetchArtifactDiscoveryRecord(ctx context.Context, artifactDigest string) (arscontract.ArtifactDiscovery, *Error) {
	response, err := s.arsClient.get(ctx, "/v1/artifacts/"+artifactDigest+"/discovery")
	if err != nil {
		return arscontract.ArtifactDiscovery{}, &Error{
			Status:  http.StatusServiceUnavailable,
			Code:    codeArtifactEvidenceUnavailable,
			Message: "artifact discovery read failed",
		}
	}
	defer response.Body.Close()

	switch response.StatusCode {
	case http.StatusOK:
		var payload arscontract.ArtifactDiscovery
		if err := decodeBoundedJSONResponse(response, &payload); err != nil {
			return arscontract.ArtifactDiscovery{}, &Error{
				Status:  http.StatusServiceUnavailable,
				Code:    codeArtifactEvidenceUnavailable,
				Message: "artifact discovery payload was invalid",
			}
		}
		return payload, nil
	case http.StatusNotFound:
		var payload artifactRegistryErrorResponse
		if err := decodeBoundedCompatibleJSONResponse(response, &payload); err == nil {
			switch strings.TrimSpace(payload.Error) {
			case "artifact not found", "artifact data not registered":
				return arscontract.ArtifactDiscovery{}, &Error{
					Status:  http.StatusNotFound,
					Code:    codeArtifactEvidenceNotFound,
					Message: "artifact evidence not found",
				}
			}
		}
		return arscontract.ArtifactDiscovery{}, &Error{
			Status:  http.StatusServiceUnavailable,
			Code:    codeArtifactEvidenceUnavailable,
			Message: "artifact evidence is unavailable",
		}
	default:
		return arscontract.ArtifactDiscovery{}, &Error{
			Status:  http.StatusServiceUnavailable,
			Code:    codeArtifactEvidenceUnavailable,
			Message: "artifact evidence is unavailable",
		}
	}
}

func (s *Service) fetchArtifactEvidenceBlob(ctx context.Context, artifactDigest string, evidenceDigest string) (evidencev1.ArtifactEvidence, *Error) {
	unavailable := func(message string) *Error {
		return &Error{
			Status:  http.StatusServiceUnavailable,
			Code:    codeArtifactEvidenceUnavailable,
			Message: message,
		}
	}
	evidenceBytes, fetchErr := s.fetchVerifiedARSBlob(ctx, evidenceDigest, arsBlobViewJSON, maxDependencyJSONResponseBytes)
	if fetchErr != nil {
		switch fetchErr.failure {
		case arsBlobRequestFailed:
			return evidencev1.ArtifactEvidence{}, unavailable("artifact evidence read failed")
		case arsBlobReadFailed:
			return evidencev1.ArtifactEvidence{}, unavailable("artifact evidence payload was invalid")
		case arsBlobDigestMismatch:
			return evidencev1.ArtifactEvidence{}, unavailable(artifactEvidenceDigestMismatchMessage)
		default:
			return evidencev1.ArtifactEvidence{}, unavailable("artifact evidence is unavailable")
		}
	}
	var payload evidencev1.ArtifactEvidence
	if err := decodeJSON(bytes.NewReader(evidenceBytes), &payload); err != nil {
		return evidencev1.ArtifactEvidence{}, unavailable("artifact evidence payload was invalid")
	}
	return payload, nil
}

func (s *Service) prepareArtifactFromDiscovery(req PrepareRequest, trustModel egscontract.RuntimeTrustPolicy, discovery discoveredArtifact) (preparedArtifact, *Error) {
	discoveryRecord := discovery.discovery
	evidence := discovery.evidence
	authorization := evidence.Claims.Admission.Authorization
	if discoveryRecord.Artifact.ArtifactDigest != req.Invocation.ArtifactDigest {
		return preparedArtifact{}, &Error{
			Status:  http.StatusBadRequest,
			Code:    codeInvalidRequest,
			Message: "artifact digest mismatch between request and artifact discovery",
		}
	}
	if evidence.Claims.Package.Identity.ArtifactDigest != req.Invocation.ArtifactDigest {
		return preparedArtifact{}, &Error{
			Status:  http.StatusBadRequest,
			Code:    codeInvalidRequest,
			Message: "artifact digest mismatch between request and artifact evidence",
		}
	}
	if authorization.Derivation.DerivationSpecDigest != req.Invocation.DerivationSpecDigest {
		return preparedArtifact{}, &Error{
			Status:  http.StatusBadRequest,
			Code:    codeInvalidRequest,
			Message: "derivation_spec_digest does not match artifact evidence",
		}
	}
	if authorization.Derivation.OutputID != req.Invocation.OutputID {
		return preparedArtifact{}, &Error{
			Status:  http.StatusBadRequest,
			Code:    codeInvalidRequest,
			Message: "output_id does not match artifact evidence",
		}
	}
	artifact, err := s.prepareArtifactFromEvidenceRecord(trustModel, discoveryRecord, evidence)
	if err != nil {
		return preparedArtifact{}, err
	}
	if err := validateInvocationAgainstManifest(req.Invocation, artifact.manifest); err != nil {
		return preparedArtifact{}, err
	}
	return artifact, nil
}

func (s *Service) prepareArtifactFromEvidenceRecord(trustModel egscontract.RuntimeTrustPolicy, discovery arscontract.ArtifactDiscovery, evidence evidencev1.ArtifactEvidence) (preparedArtifact, *Error) {
	artifactDigest := strings.TrimSpace(discovery.Artifact.ArtifactDigest)
	execution := evidence.Claims.Admission.Execution
	if evidence.Claims.Package.Identity.ArtifactDigest != artifactDigest {
		return preparedArtifact{}, &Error{
			Status:  http.StatusForbidden,
			Code:    codeArtifactEvidenceInvalid,
			Message: "artifact evidence does not match the requested artifact digest",
		}
	}
	if err := evidence.Validate(); err != nil {
		return preparedArtifact{}, &Error{
			Status:  http.StatusForbidden,
			Code:    codeArtifactEvidenceInvalid,
			Message: "artifact evidence is structurally invalid",
		}
	}
	if evidence.Claims.Package.Identity.PayloadDigest != strings.TrimSpace(discovery.Payload.Digest) {
		return preparedArtifact{}, &Error{
			Status:  http.StatusForbidden,
			Code:    codeArtifactEvidenceInvalid,
			Message: "artifact discovery payload reference does not match artifact evidence",
		}
	}
	if evidence.Claims.Package.Identity.ArtifactType != strings.TrimSpace(discovery.Artifact.ArtifactType) {
		return preparedArtifact{}, &Error{
			Status:  http.StatusForbidden,
			Code:    codeArtifactEvidenceInvalid,
			Message: "artifact discovery artifact type does not match artifact evidence",
		}
	}
	if evidence.Claims.Package.Identity.IntentDigest != strings.TrimSpace(discovery.Artifact.IntentDigest) {
		return preparedArtifact{}, &Error{
			Status:  http.StatusForbidden,
			Code:    codeArtifactEvidenceInvalid,
			Message: "artifact discovery intent digest does not match artifact evidence",
		}
	}
	if err := evidencev1.Verify(evidence, s.provenanceVerifier.keyID, s.provenanceVerifier.algorithm, s.provenanceVerifier.publicKey); err != nil {
		return preparedArtifact{}, &Error{
			Status:  http.StatusForbidden,
			Code:    codeArtifactEvidenceInvalid,
			Message: "artifact evidence signature verification failed",
		}
	}
	if err := enforceTrustModel(trustModel, evidence.Seal.KeyID, artifactDigest); err != nil {
		return preparedArtifact{}, err
	}
	return preparedArtifact{
		manifest:       manifestFromEvidence(evidence),
		payloadDigest:  strings.TrimSpace(discovery.Payload.Digest),
		targetPlatform: execution.Workload.TargetPlatform,
		networkAccess:  execution.Access.NetworkAccess,
	}, nil
}

func manifestFromEvidence(evidence evidencev1.ArtifactEvidence) Manifest {
	runtime := evidence.Claims.Admission.Execution.Runtime
	return Manifest{
		ArtifactDigest: evidence.Claims.Package.Identity.ArtifactDigest,
		ArtifactType:   evidence.Claims.Package.Identity.ArtifactType,
		IntentDigest:   evidence.Claims.Package.Identity.IntentDigest,
		RuntimeInterface: RuntimeInterface{
			EnvironmentVariables: append([]string(nil), runtime.EnvironmentVariables...),
			RequiredCapabilities: append([]string(nil), runtime.RequiredCapabilities...),
			MountTargets:         append([]string(nil), runtime.MountTargets...),
		},
	}
}

func (s *Service) fetchWorkloadZoneVaultConfig(ctx context.Context, ref runtimeconfigv1.WorkloadZoneVaultConfigRef) (runtimeconfigv1.WorkloadZoneVaultConfig, *Error) {
	unavailable := func(message string) *Error {
		return &Error{
			Status:  http.StatusServiceUnavailable,
			Code:    codeWorkloadZoneVaultUnavailable,
			Message: message,
		}
	}
	blobBytes, fetchErr := s.fetchVerifiedARSBlob(ctx, ref.Digest, arsBlobViewJSON, maxDependencyJSONResponseBytes)
	if fetchErr != nil {
		switch fetchErr.failure {
		case arsBlobRequestFailed:
			return runtimeconfigv1.WorkloadZoneVaultConfig{}, unavailable("artifact registry workload-zone vault blob read failed")
		case arsBlobReadFailed:
			return runtimeconfigv1.WorkloadZoneVaultConfig{}, unavailable("artifact registry workload-zone vault blob was invalid")
		case arsBlobDigestMismatch:
			return runtimeconfigv1.WorkloadZoneVaultConfig{}, unavailable(workloadZoneVaultBlobDigestMismatchMessage)
		default:
			return runtimeconfigv1.WorkloadZoneVaultConfig{}, unavailable("artifact registry workload-zone vault blob is unavailable")
		}
	}

	var payload runtimeconfigv1.WorkloadZoneVaultConfigBlob
	if err := decodeJSON(bytes.NewReader(blobBytes), &payload); err != nil {
		return runtimeconfigv1.WorkloadZoneVaultConfig{}, unavailable("artifact registry workload-zone vault blob was invalid")
	}
	if err := payload.Validate(); err != nil {
		return runtimeconfigv1.WorkloadZoneVaultConfig{}, &Error{
			Status:  http.StatusServiceUnavailable,
			Code:    codeWorkloadZoneVaultUnavailable,
			Message: "artifact registry workload-zone vault blob was invalid",
		}
	}
	return payload.Normalized().VaultConfig, nil
}

func (s *Service) verifyTrustModelEnvelope(payload signedRuntimeTrustResponse, canonical []byte) error {
	if strings.TrimSpace(payload.Algorithm) != s.trustModelVerifier.algorithm {
		return fmt.Errorf("trust model algorithm mismatch")
	}
	if strings.TrimSpace(payload.KeyID) != s.trustModelVerifier.keyID {
		return fmt.Errorf("trust model key_id mismatch")
	}
	expectedDigest := digestBytes(canonical)
	if payload.PayloadDigest != expectedDigest {
		return fmt.Errorf("trust model payload digest mismatch")
	}
	// publication metadata is intentionally outside the signed runtime trust
	// payload and is ignored for trust decisions here.
	if err := s.trustModelVerifier.verifyDetached(canonical, payload.KeyID, payload.Algorithm, payload.Signature); err != nil {
		return err
	}
	return nil
}

func enforceTrustModel(trustModel egscontract.RuntimeTrustPolicy, signerKeyID string, artifactDigest string) *Error {
	for _, allowed := range trustModel.SignerPolicy.AllowedSigners {
		if allowed == signerKeyID {
			goto allowed
		}
	}
	return &Error{
		Status:  http.StatusForbidden,
		Code:    codeSignerNotAllowed,
		Message: "provenance signer is not allowed by the TrustModel",
	}

allowed:
	for _, revoked := range trustModel.SignerPolicy.RevokedSigners {
		if revoked == signerKeyID {
			return &Error{
				Status:  http.StatusForbidden,
				Code:    codeSignerRevoked,
				Message: "provenance signer is revoked by the TrustModel",
			}
		}
	}
	for _, revokedArtifact := range trustModel.ArtifactPolicy.RevokedArtifacts {
		if revokedArtifact == artifactDigest {
			return &Error{
				Status:  http.StatusForbidden,
				Code:    codeArtifactRevoked,
				Message: "artifact is revoked by the TrustModel",
			}
		}
	}
	return nil
}

func validatePrepareRequest(req *PrepareRequest) *Error {
	if req == nil {
		return &Error{Status: http.StatusBadRequest, Code: codeInvalidRequest, Message: "request body is required"}
	}
	if strings.TrimSpace(req.SchemaVersion) == "" {
		req.SchemaVersion = "v1"
	}
	if strings.TrimSpace(req.Invocation.SchemaVersion) == "" {
		req.Invocation.SchemaVersion = "v1"
	}
	if req.Mode != "" && req.Mode != ExecutionModeAsync && req.Mode != ExecutionModeSync {
		return &Error{Status: http.StatusBadRequest, Code: codeInvalidRequest, Message: "mode must be sync or async"}
	}
	if req.TimeoutSeconds < 0 {
		return &Error{Status: http.StatusBadRequest, Code: codeInvalidRequest, Message: "timeout_seconds must be non-negative"}
	}
	if req.Resources != nil {
		if req.Resources.CPU <= 0 {
			return &Error{Status: http.StatusBadRequest, Code: codeInvalidRequest, Message: "resources.cpu must be greater than 0"}
		}
		if req.Resources.MemoryMB < nomadMinimumMemoryMB {
			return &Error{Status: http.StatusBadRequest, Code: codeInvalidRequest, Message: fmt.Sprintf("resources.memory_mb must be at least %d, the least memory Nomad registers a task with", nomadMinimumMemoryMB)}
		}
	}

	invocation := req.Invocation
	if !isLabeledSHA256Digest(invocation.ArtifactDigest) {
		return &Error{Status: http.StatusBadRequest, Code: codeInvalidRequest, Message: "invocation.artifact_digest must be a labeled sha256 digest"}
	}
	if !isLabeledSHA256Digest(invocation.DerivationSpecDigest) {
		return &Error{Status: http.StatusBadRequest, Code: codeInvalidRequest, Message: "invocation.derivation_spec_digest must be a labeled sha256 digest"}
	}
	if strings.TrimSpace(invocation.OutputID) == "" {
		return &Error{Status: http.StatusBadRequest, Code: codeInvalidRequest, Message: "invocation.output_id is required"}
	}
	return nil
}

// nomadPassesAsWritten reports whether Nomad hands s to the workload exactly
// as written. Nomad's client evaluates "${...}" and "%{...}" in every string of
// a task's driver configuration (the arguments and the mounts) as an HCL
// template, with the node's attributes and metadata, the task's environment
// and a set of functions, and rewrites the escapes "$${" and "%%{". It replaces
// "${name}" in every environment and meta value with a node attribute or an
// environment value. A NUL byte cannot reach a process at all. So a request
// string that ES places in a Nomad job holds none of these, or the workload
// would run with values that ES never admitted, or never start once ES has
// accepted it.
func nomadPassesAsWritten(s string) bool {
	return !strings.Contains(s, "${") && !strings.Contains(s, "%{") && strings.IndexByte(s, 0) < 0
}

const nomadEvaluatedText = `must not contain "${", "%{" or a NUL byte, which Nomad would not pass on as written`

// nomadKeepsDriverString reports whether Nomad's client leaves s, a string of a
// task's driver configuration (an argument or a mount target), unchanged on
// its way to the workload, apart from the templates nomadPassesAsWritten
// refuses. The client parses each such string with HCL, whose template
// scanner drops a byte order mark (U+FEFF) at its start, and holds the result
// as a cty string, which is rewritten to Unicode Normalization Form C. So s
// must not begin with U+FEFF and must be in NFC. ES judges NFC by its own
// tables, of Unicode version norm.Version. A Nomad built with tables of a
// later version could normalize a code point that ES's tables do not know, so
// s also holds only code points assigned in norm.Version. Unicode's
// normalization stability policy then keeps s unchanged by every later
// version. ES writes the job with encoding/json, which writes U+FFFD in place
// of each byte that is not valid UTF-8, so s must also be valid UTF-8. Nomad
// leaves environment keys and values and meta values as they are, so this
// applies to the driver configuration only.
func nomadKeepsDriverString(s string) bool {
	if !utf8.ValidString(s) || strings.HasPrefix(s, "\ufeff") || !norm.NFC.IsNormalString(s) {
		return false
	}
	for _, r := range s {
		if r >= utf8.RuneSelf && (nomadNormalizationAssigned == nil || !unicode.Is(nomadNormalizationAssigned, r)) {
			return false
		}
	}
	return true
}

// nomadNormalizationAssigned holds the code points assigned in the Unicode
// version of ES's normalization tables. If x/text has no table of assigned
// code points for that version it is nil, and nomadKeepsDriverString then
// refuses every string that is not ASCII.
var nomadNormalizationAssigned = rangetable.Assigned(norm.Version)

const nomadRewrittenText = "must be in Unicode Normalization Form C, use only code points assigned in Unicode " + norm.Version + " and not begin with a byte order mark, or Nomad would not pass it on as written"

// nomadMinimumMemoryMB is the least memory Nomad registers a task with
// (Nomad v2.1.1, structs.MinResources and Resources.MeetsMinResources). A
// request below it would be accepted, claimed and staged, and then refused by
// Nomad for good.
const nomadMinimumMemoryMB = 10

func validateInvocationAgainstManifest(invocation ArtifactInvocation, manifest Manifest) *Error {
	if manifest.ArtifactDigest != invocation.ArtifactDigest {
		return &Error{Status: http.StatusBadRequest, Code: codeInvalidRequest, Message: "artifact digest mismatch between request and manifest"}
	}
	if len(invocation.Argv) > 100 {
		return &Error{Status: http.StatusBadRequest, Code: codeInvalidRequest, Message: "invocation.argv exceeds the maximum supported count"}
	}
	if !nomadPassesAsWritten(invocation.OutputID) {
		return &Error{Status: http.StatusBadRequest, Code: codeInvalidRequest, Message: "invocation.output_id " + nomadEvaluatedText}
	}
	for _, arg := range invocation.Argv {
		if !nomadPassesAsWritten(arg) {
			return &Error{Status: http.StatusBadRequest, Code: codeInvalidRequest, Message: "invocation.argv " + nomadEvaluatedText}
		}
		if !nomadKeepsDriverString(arg) {
			return &Error{Status: http.StatusBadRequest, Code: codeInvalidRequest, Message: "invocation.argv " + nomadRewrittenText}
		}
	}
	// The artifact's signed runtime interface is the only source of what a
	// caller may set or mount. An empty or absent list admits nothing.
	allowedEnv := declaredStringSet(manifest.RuntimeInterface.EnvironmentVariables)
	for _, key := range sortedMapKeys(invocation.Env) {
		value := invocation.Env[key]
		if !nomadPassesAsWritten(key) || !nomadPassesAsWritten(value) {
			return &Error{Status: http.StatusBadRequest, Code: codeInvalidRequest, Message: "invocation.env " + nomadEvaluatedText}
		}
		if !isPortableEnvironmentKey(key) {
			return &Error{Status: http.StatusBadRequest, Code: codeInvalidRequest, Message: fmt.Sprintf("environment key must be ASCII letters, digits and underscores, not starting with a digit: %q", key)}
		}
		if isReservedRuntimeEnvKey(key) {
			return &Error{Status: http.StatusBadRequest, Code: codeInvalidRequest, Message: fmt.Sprintf("environment key is reserved for runtime identity or control-plane use: %s", key)}
		}
		if _, ok := allowedEnv[key]; !ok {
			return &Error{Status: http.StatusBadRequest, Code: codeInvalidRequest, Message: fmt.Sprintf("environment key is not allowed by the runtime interface: %s", key)}
		}
	}
	if err := validateRuntimeMounts(invocation.Mounts); err != nil {
		return err
	}
	allowedMountTargets := declaredStringSet(manifest.RuntimeInterface.MountTargets)
	for _, mount := range invocation.Mounts {
		if _, ok := allowedMountTargets[mount.TargetPath]; !ok {
			return &Error{Status: http.StatusBadRequest, Code: codeInvalidRequest, Message: fmt.Sprintf("mount target_path is not declared by the runtime interface: %s", mount.TargetPath)}
		}
	}
	return nil
}

// declaredStringSet returns the trimmed entries of a signed runtime-interface
// list, the form the evidence canonicalization signs.
func declaredStringSet(values []string) map[string]struct{} {
	set := make(map[string]struct{}, len(values))
	for _, value := range values {
		set[strings.TrimSpace(value)] = struct{}{}
	}
	return set
}

func sortedMapKeys(values map[string]string) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

// isPortableEnvironmentKey reports whether key is a portable environment
// variable name: an ASCII letter or underscore, then ASCII letters, digits
// and underscores. A key outside that form could carry an equals sign, which
// ends the name in the environment string the container receives, so
// "VAULT_ADDR=x" would set VAULT_ADDR past the reserved-key check.
func isPortableEnvironmentKey(key string) bool {
	if key == "" {
		return false
	}
	for index := 0; index < len(key); index++ {
		c := key[index]
		switch {
		case c == '_', 'A' <= c && c <= 'Z', 'a' <= c && c <= 'z':
		case '0' <= c && c <= '9' && index > 0:
		default:
			return false
		}
	}
	return true
}

func newDependencyClient(cfg esconfig.DependencyConfig, dependencyName string) (*dependencyClient, error) {
	certificate, err := tls.LoadX509KeyPair(cfg.ClientCertFile, cfg.ClientKeyFile)
	if err != nil {
		return nil, fmt.Errorf("load client certificate: %w", err)
	}

	rootPEM, err := os.ReadFile(cfg.RootCAFile)
	if err != nil {
		return nil, fmt.Errorf("read root ca: %w", err)
	}
	rootCAs := x509.NewCertPool()
	if !rootCAs.AppendCertsFromPEM(rootPEM) {
		return nil, fmt.Errorf("append root ca: no valid certificates found")
	}

	baseURL, err := url.Parse(cfg.BaseURL)
	if err != nil {
		return nil, fmt.Errorf("parse base url: %w", err)
	}

	tlsConfig := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		RootCAs:      rootCAs,
		ServerName:   cfg.ServerName,
		Certificates: []tls.Certificate{certificate},
	}

	transport := &http.Transport{
		TLSClientConfig: tlsConfig,
	}

	return &dependencyClient{
		dependencyName: strings.TrimSpace(dependencyName),
		baseURL:        baseURL,
		client: &http.Client{
			Timeout:   time.Duration(cfg.TimeoutSeconds) * time.Second,
			Transport: observability.WrapRoundTripper("execution", strings.TrimSpace(dependencyName), true, transport),
			// A redirect is the dependency's answer, never an instruction:
			// following one would let a compromised ARS or EGS make ES send
			// requests to any origin it can reach, including over cleartext.
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}, nil
}

func (c *dependencyClient) get(ctx context.Context, endpoint string) (*http.Response, error) {
	requestURL := c.baseURL.ResolveReference(&url.URL{Path: path.Clean(endpoint)})
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL.String(), nil)
	if err != nil {
		return nil, err
	}
	return c.client.Do(request)
}

func (c *dependencyClient) checkReady(ctx context.Context) bool {
	requestCtx, cancel := context.WithTimeout(ctx, c.client.Timeout)
	defer cancel()

	response, err := c.get(requestCtx, "/health")
	if err != nil {
		return false
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return false
	}

	var payload healthResponse
	// Dependency health payloads have historically been extension-tolerant.
	// Bound their acquisition without silently converting that compatibility
	// behavior into the strict decoding used by admission-owned contracts.
	if err := decodeBoundedCompatibleJSONResponse(response, &payload); err != nil {
		return false
	}
	return payload.Status == "healthy" && payload.Ready
}

func newEd25519Verifier(cfg esconfig.SignerVerifierConfig) (*ed25519Verifier, error) {
	publicKeyBytes, err := hex.DecodeString(strings.TrimSpace(cfg.PublicKeyHex))
	if err != nil {
		return nil, fmt.Errorf("decode %s public key: %w", cfg.KeyID, err)
	}
	return &ed25519Verifier{
		algorithm: "ed25519",
		keyID:     strings.TrimSpace(cfg.KeyID),
		publicKey: ed25519.PublicKey(publicKeyBytes),
	}, nil
}

func (v *ed25519Verifier) verifyDetached(canonical []byte, keyID string, algorithm string, signatureB64 string) error {
	if strings.TrimSpace(keyID) != v.keyID {
		return fmt.Errorf("unexpected signing key id")
	}
	if strings.TrimSpace(algorithm) != v.algorithm {
		return fmt.Errorf("unexpected signing algorithm")
	}
	signature, err := base64.StdEncoding.DecodeString(strings.TrimSpace(signatureB64))
	if err != nil {
		return fmt.Errorf("decode signature: %w", err)
	}
	if !ed25519.Verify(v.publicKey, canonical, signature) {
		return fmt.Errorf("signature verification failed")
	}
	return nil
}

func decodeJSON(reader io.Reader, target any) error {
	decoder := json.NewDecoder(reader)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); err != io.EOF {
		return fmt.Errorf("trailing data after first JSON document")
	}
	return nil
}

func decodeBoundedJSONResponse(response *http.Response, target any) error {
	payload, err := readBoundedResponseBody(response, maxDependencyJSONResponseBytes)
	if err != nil {
		return err
	}
	return decodeJSON(bytes.NewReader(payload), target)
}

func decodeBoundedCompatibleJSONResponse(response *http.Response, target any) error {
	payload, err := readBoundedResponseBody(response, maxDependencyJSONResponseBytes)
	if err != nil {
		return err
	}
	return json.NewDecoder(bytes.NewReader(payload)).Decode(target)
}

func decodeCompatibleJSONDocument(reader io.Reader, target any) error {
	decoder := json.NewDecoder(reader)
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); err != io.EOF {
		return fmt.Errorf("trailing data after first JSON document")
	}
	return nil
}

func decodeBoundedCompatibleJSONDocumentResponse(response *http.Response, target any) error {
	payload, err := readBoundedResponseBody(response, maxDependencyJSONResponseBytes)
	if err != nil {
		return err
	}
	return decodeCompatibleJSONDocument(bytes.NewReader(payload), target)
}

func digestBytes(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func isLabeledSHA256Digest(value string) bool {
	return labeledSHA256DigestPattern.MatchString(strings.TrimSpace(value))
}

func isReservedRuntimeEnvKey(key string) bool {
	normalized := asciiUpper(strings.TrimSpace(key))
	if normalized == "" {
		return false
	}
	if _, ok := reservedRuntimeEnvKeys[normalized]; ok {
		return true
	}
	for _, prefix := range reservedRuntimeEnvPrefixes {
		if strings.HasPrefix(normalized, prefix) {
			return true
		}
	}
	for _, suffix := range reservedRuntimeEnvSuffixes {
		if strings.HasSuffix(normalized, suffix) {
			return true
		}
	}
	return false
}

// asciiUpper folds only the ASCII letters a to z. Unicode case mapping would
// fold look-alike letters such as U+017F into ASCII ones, and no program reads
// a variable through such a fold.
func asciiUpper(value string) string {
	folded := []byte(value)
	for index, c := range folded {
		if 'a' <= c && c <= 'z' {
			folded[index] = c - ('a' - 'A')
		}
	}
	return string(folded)
}
