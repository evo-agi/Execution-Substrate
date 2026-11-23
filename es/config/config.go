package config

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	runtimeconfigv1 "execution-substrate/internal/contracts/runtimeconfig/v1"
)

type Config struct {
	HTTP              HTTPConfig              `json:"http"`
	TLS               TLSConfig               `json:"tls"`
	Security          SecurityConfig          `json:"security"`
	Authorization     AuthorizationConfig     `json:"authorization"`
	Dependencies      DependenciesConfig      `json:"dependencies"`
	AdmissionPolicy   *AdmissionPolicyConfig  `json:"admission_policy,omitempty"`
	RuntimeConfig     RuntimeConfigConfig     `json:"runtime_config"`
	Verification      VerificationConfig      `json:"verification"`
	WorkloadVaultAuth WorkloadVaultAuthConfig `json:"workload_vault_auth"`
	Nomad             NomadConfig             `json:"nomad,omitempty"`
	Execution         ExecutionConfig         `json:"execution,omitempty"`
}

type HTTPConfig struct {
	BindAddress            string `json:"bind_address"`
	Port                   int    `json:"port"`
	ReadTimeoutSeconds     int    `json:"read_timeout_seconds"`
	WriteTimeoutSeconds    int    `json:"write_timeout_seconds"`
	ShutdownTimeoutSeconds int    `json:"shutdown_timeout_seconds"`
}

type TLSConfig struct {
	CertFile     string `json:"cert_file"`
	KeyFile      string `json:"key_file"`
	ClientCAFile string `json:"client_ca_file"`
}

type SecurityConfig struct {
	BootstrapIssuerCommonName string `json:"bootstrap_issuer_common_name"`
}

type AuthorizationConfig struct {
	AllowedSPIFFEPathPrefixes []string `json:"allowed_spiffe_path_prefixes"`
}

type DependenciesConfig struct {
	ArtifactRegistry    DependencyConfig `json:"artifact_registry"`
	ExecutionGovernance DependencyConfig `json:"execution_governance"`
}

type RuntimeConfigConfig struct {
	WorkloadZoneVaultConfigRef runtimeconfigv1.WorkloadZoneVaultConfigRef `json:"workload_zone_vault_config_ref"`
}

type DependencyConfig struct {
	BaseURL        string `json:"base_url"`
	ServerName     string `json:"server_name"`
	ClientCertFile string `json:"client_cert_file"`
	ClientKeyFile  string `json:"client_key_file"`
	RootCAFile     string `json:"root_ca_file"`
	TimeoutSeconds int    `json:"timeout_seconds"`
}

type AdmissionPolicyConfig struct {
	ConfiguredStaticScriptLiteralDeny *ConfiguredStaticScriptLiteralDenyPolicyConfig `json:"configured_static_script_literal_deny,omitempty"`
}

type ConfiguredStaticScriptLiteralDenyPolicyMode string

const (
	ConfiguredStaticScriptLiteralDenyModeDisabled ConfiguredStaticScriptLiteralDenyPolicyMode = "disabled"
	ConfiguredStaticScriptLiteralDenyModeEnforce  ConfiguredStaticScriptLiteralDenyPolicyMode = "enforce"
)

type ConfiguredStaticScriptLiteralDenyInputClass string

const (
	ConfiguredStaticScriptLiteralDenyInputClassStaticScriptPayloadText ConfiguredStaticScriptLiteralDenyInputClass = "static_script_payload_text"
)

const (
	MaxConfiguredStaticScriptLiteralDenyEntries      = 32
	MaxConfiguredStaticScriptLiteralDenyLiteralBytes = 256
	MaxConfiguredStaticScriptLiteralDenyEntryIDBytes = 64
)

type ConfiguredStaticScriptLiteralDenyPolicyConfig struct {
	Mode    ConfiguredStaticScriptLiteralDenyPolicyMode    `json:"mode"`
	Entries []ConfiguredStaticScriptLiteralDenyEntryConfig `json:"entries,omitempty"`
}

type ConfiguredStaticScriptLiteralDenyEntryConfig struct {
	ID         string                                      `json:"id"`
	InputClass ConfiguredStaticScriptLiteralDenyInputClass `json:"input_class"`
	Literal    string                                      `json:"literal"`
}

type NomadConfig struct {
	BaseURL        string `json:"base_url"`
	Datacenter     string `json:"datacenter"`
	TimeoutSeconds int    `json:"timeout_seconds"`
	// TokenFile names the file that holds ES's Nomad ACL client token (the
	// token's SecretID). ES reads it once at startup and sends it on every
	// Nomad request. The token itself never appears in this config.
	TokenFile string `json:"token_file"`
}

type ExecutionConfig struct {
	StagingRootDir             string                   `json:"staging_root_dir"`
	ResultsRootDir             string                   `json:"results_root_dir"`
	RetainedResultAuth         RetainedResultAuthConfig `json:"retained_result_auth"`
	BaseImage                  string                   `json:"base_image"`
	RuntimeIdentityTmpfsSize   int64                    `json:"runtime_identity_tmpfs_size,omitempty"`
	RuntimeSupportBinary       string                   `json:"runtime_support_binary,omitempty"`
	SPIREWorkloadAPISocketPath string                   `json:"spire_workload_api_socket_path,omitempty"`
	RuntimeProfiles            RuntimeProfilesConfig    `json:"runtime_profiles,omitempty"`
}

type RetainedResultAuthConfig struct {
	StoreID string `json:"store_id"`
	KeyID   string `json:"key_id"`
	KeyFile string `json:"key_file"`
}

type RuntimeProfilesConfig struct {
	ControlPlaneNormalShell ControlPlaneNormalShellProfileConfig `json:"control_plane_normal_shell,omitempty"`
}

type ControlPlaneNormalShellProfileConfig struct {
	Enabled                    bool   `json:"enabled"`
	Image                      string `json:"image,omitempty"`
	CodexCLIPath               string `json:"codex_cli_path,omitempty"`
	CredentialVaultSecretPath  string `json:"credential_vault_secret_path,omitempty"`
	CredentialVaultSecretField string `json:"credential_vault_secret_field,omitempty"`
}

const (
	defaultRuntimeIdentityTmpfsSizeBytes int64 = 1 << 20
	maxRuntimeIdentityTmpfsSizeBytes     int64 = 8 << 20
)

type VerificationConfig struct {
	TrustModel              SignerVerifierConfig `json:"trust_model"`
	Provenance              SignerVerifierConfig `json:"provenance"`
	DerivationAttestation   SignerVerifierConfig `json:"derivation_attestation"`
	WorkloadIdentityBinding SignerVerifierConfig `json:"workload_identity_binding"`
}

type SignerVerifierConfig struct {
	Algorithm    string `json:"algorithm"`
	KeyID        string `json:"key_id"`
	PublicKeyHex string `json:"public_key_hex"`
}

type WorkloadVaultAuthMode string

const (
	WorkloadVaultAuthModeVaultIdentityJWT WorkloadVaultAuthMode = "vault_identity_jwt"
)

type WorkloadVaultAuthConfig struct {
	DefaultMode WorkloadVaultAuthMode `json:"default_mode"`
}

type ResolvedWorkloadVaultAuthPlan struct {
	Mode        WorkloadVaultAuthMode
	Address     string
	AuthMount   string
	AuthRole    string
	JWTAudience string
	CABundlePEM string
}

func Load(path string) (Config, error) {
	if strings.TrimSpace(path) == "" {
		return Config{}, fmt.Errorf("config path is required")
	}

	file, err := os.Open(path)
	if err != nil {
		return Config{}, fmt.Errorf("open config: %w", err)
	}
	defer file.Close()

	var cfg Config
	decoder := json.NewDecoder(file)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&cfg); err != nil {
		return Config{}, fmt.Errorf("decode config: %w", err)
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); err != io.EOF {
		return Config{}, fmt.Errorf("decode config: trailing data after first JSON document")
	}

	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}

	return cfg, nil
}

func (c Config) Validate() error {
	if strings.TrimSpace(c.HTTP.BindAddress) == "" {
		return fmt.Errorf("http.bind_address is required")
	}
	if c.HTTP.Port < 0 || c.HTTP.Port > 65535 {
		return fmt.Errorf("http.port must be between 0 and 65535")
	}
	if c.HTTP.ReadTimeoutSeconds <= 0 {
		return fmt.Errorf("http.read_timeout_seconds must be greater than 0")
	}
	if c.HTTP.WriteTimeoutSeconds <= 0 {
		return fmt.Errorf("http.write_timeout_seconds must be greater than 0")
	}
	if c.HTTP.ShutdownTimeoutSeconds <= 0 {
		return fmt.Errorf("http.shutdown_timeout_seconds must be greater than 0")
	}

	if strings.TrimSpace(c.TLS.CertFile) == "" {
		return fmt.Errorf("tls.cert_file is required")
	}
	if strings.TrimSpace(c.TLS.KeyFile) == "" {
		return fmt.Errorf("tls.key_file is required")
	}
	if strings.TrimSpace(c.TLS.ClientCAFile) == "" {
		return fmt.Errorf("tls.client_ca_file is required")
	}

	if strings.TrimSpace(c.Security.BootstrapIssuerCommonName) == "" {
		return fmt.Errorf("security.bootstrap_issuer_common_name is required")
	}
	if err := c.Authorization.Validate("authorization"); err != nil {
		return err
	}

	if err := c.Dependencies.ArtifactRegistry.Validate("dependencies.artifact_registry"); err != nil {
		return err
	}
	if err := c.Dependencies.ExecutionGovernance.Validate("dependencies.execution_governance"); err != nil {
		return err
	}
	if c.AdmissionPolicy != nil {
		if err := c.AdmissionPolicy.Validate(); err != nil {
			return err
		}
	}
	if err := c.RuntimeConfig.Validate(); err != nil {
		return err
	}

	if err := c.Verification.TrustModel.Validate("verification.trust_model"); err != nil {
		return err
	}
	if err := c.Verification.Provenance.Validate("verification.provenance"); err != nil {
		return err
	}
	if err := c.Verification.DerivationAttestation.Validate("verification.derivation_attestation"); err != nil {
		return err
	}
	if err := c.Verification.WorkloadIdentityBinding.Validate("verification.workload_identity_binding"); err != nil {
		return err
	}

	if err := c.WorkloadVaultAuth.Validate(); err != nil {
		return err
	}
	if c.SubmitConfigured() {
		if err := c.Nomad.Validate("nomad"); err != nil {
			return err
		}
		if err := c.Execution.Validate("execution"); err != nil {
			return err
		}
		if err := validateNomadTokenFilePlacement(c.Nomad.TokenFile, c.Execution); err != nil {
			return err
		}
	}

	return nil
}

func (c AuthorizationConfig) Validate(field string) error {
	prefixField := field + ".allowed_spiffe_path_prefixes"
	if len(c.AllowedSPIFFEPathPrefixes) == 0 {
		return fmt.Errorf("%s is required", prefixField)
	}
	for _, prefix := range c.AllowedSPIFFEPathPrefixes {
		if err := validateAllowedSPIFFEPathPrefix(prefixField, prefix); err != nil {
			return err
		}
	}
	return nil
}

func validateAllowedSPIFFEPathPrefix(field string, prefix string) error {
	if strings.TrimSpace(prefix) == "" {
		return fmt.Errorf("%s cannot contain empty values", field)
	}
	if prefix != strings.TrimSpace(prefix) {
		return fmt.Errorf("%s values must not contain leading or trailing whitespace", field)
	}

	segments := strings.Split(prefix, "/")
	for _, segment := range segments {
		switch segment {
		case "":
			return fmt.Errorf("%s values must not contain empty path segments", field)
		case ".", "..":
			return fmt.Errorf("%s values must not contain . or .. path segments", field)
		}
	}
	if len(segments) < 2 {
		return fmt.Errorf("%s values must contain at least two path segments", field)
	}
	return nil
}

func (c RuntimeConfigConfig) Validate() error {
	if err := c.WorkloadZoneVaultConfigRef.Validate(); err != nil {
		return fmt.Errorf("runtime_config.workload_zone_vault_config_ref: %w", err)
	}
	return nil
}

func (c DependencyConfig) Validate(field string) error {
	if strings.TrimSpace(c.BaseURL) == "" {
		return fmt.Errorf("%s.base_url is required", field)
	}
	parsed, err := url.Parse(c.BaseURL)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" {
		return fmt.Errorf("%s.base_url must be a valid absolute https URL", field)
	}
	if strings.TrimSpace(c.ServerName) == "" {
		return fmt.Errorf("%s.server_name is required", field)
	}
	if strings.TrimSpace(c.ClientCertFile) == "" {
		return fmt.Errorf("%s.client_cert_file is required", field)
	}
	if strings.TrimSpace(c.ClientKeyFile) == "" {
		return fmt.Errorf("%s.client_key_file is required", field)
	}
	if strings.TrimSpace(c.RootCAFile) == "" {
		return fmt.Errorf("%s.root_ca_file is required", field)
	}
	if c.TimeoutSeconds <= 0 {
		return fmt.Errorf("%s.timeout_seconds must be greater than 0", field)
	}
	return nil
}

func (c AdmissionPolicyConfig) Validate() error {
	if c.ConfiguredStaticScriptLiteralDeny != nil {
		if err := c.ConfiguredStaticScriptLiteralDeny.Validate("admission_policy.configured_static_script_literal_deny"); err != nil {
			return err
		}
	}
	return nil
}

func (c ConfiguredStaticScriptLiteralDenyPolicyConfig) Validate(field string) error {
	mode := strings.TrimSpace(string(c.Mode))
	if mode != string(c.Mode) {
		return fmt.Errorf("%s.mode must be disabled or enforce", field)
	}
	switch ConfiguredStaticScriptLiteralDenyPolicyMode(mode) {
	case ConfiguredStaticScriptLiteralDenyModeDisabled, ConfiguredStaticScriptLiteralDenyModeEnforce:
	default:
		return fmt.Errorf("%s.mode must be disabled or enforce", field)
	}

	if len(c.Entries) > MaxConfiguredStaticScriptLiteralDenyEntries {
		return fmt.Errorf("%s.entries must not contain more than %d entries", field, MaxConfiguredStaticScriptLiteralDenyEntries)
	}
	if ConfiguredStaticScriptLiteralDenyPolicyMode(mode) == ConfiguredStaticScriptLiteralDenyModeEnforce && len(c.Entries) == 0 {
		return fmt.Errorf("%s.entries is required when mode is enforce", field)
	}
	seenIDs := map[string]struct{}{}
	for i, entry := range c.Entries {
		if err := entry.Validate(fmt.Sprintf("%s.entries[%d]", field, i)); err != nil {
			return err
		}
		id := strings.TrimSpace(entry.ID)
		if _, ok := seenIDs[id]; ok {
			return fmt.Errorf("%s.entries[%d].id must be unique", field, i)
		}
		seenIDs[id] = struct{}{}
	}
	return nil
}

func (e ConfiguredStaticScriptLiteralDenyEntryConfig) Validate(field string) error {
	if err := validateConfiguredStaticScriptLiteralDenyEntryID(field+".id", e.ID); err != nil {
		return err
	}
	inputClass := strings.TrimSpace(string(e.InputClass))
	if inputClass != string(e.InputClass) {
		return fmt.Errorf("%s.input_class must be static_script_payload_text", field)
	}
	if ConfiguredStaticScriptLiteralDenyInputClass(inputClass) != ConfiguredStaticScriptLiteralDenyInputClassStaticScriptPayloadText {
		return fmt.Errorf("%s.input_class must be static_script_payload_text", field)
	}
	if e.Literal == "" || strings.TrimSpace(e.Literal) == "" {
		return fmt.Errorf("%s.literal must be non-empty printable text", field)
	}
	if len(e.Literal) > MaxConfiguredStaticScriptLiteralDenyLiteralBytes {
		return fmt.Errorf("%s.literal must not exceed %d bytes", field, MaxConfiguredStaticScriptLiteralDenyLiteralBytes)
	}
	if !utf8.ValidString(e.Literal) {
		return fmt.Errorf("%s.literal must be valid UTF-8 text", field)
	}
	for _, r := range e.Literal {
		if !isConfiguredStaticScriptLiteralDenyPrintableRune(r) {
			return fmt.Errorf("%s.literal must contain only printable non-control text", field)
		}
	}
	return nil
}

func isConfiguredStaticScriptLiteralDenyPrintableRune(r rune) bool {
	return unicode.IsPrint(r) && !unicode.Is(unicode.Cc, r) && !unicode.Is(unicode.Cf, r)
}

func validateConfiguredStaticScriptLiteralDenyEntryID(field string, id string) error {
	if id == "" {
		return fmt.Errorf("%s is required", field)
	}
	if id != strings.TrimSpace(id) {
		return fmt.Errorf("%s must not contain leading or trailing whitespace", field)
	}
	if len(id) > MaxConfiguredStaticScriptLiteralDenyEntryIDBytes {
		return fmt.Errorf("%s must not exceed %d bytes", field, MaxConfiguredStaticScriptLiteralDenyEntryIDBytes)
	}
	if !isConfiguredStaticScriptLiteralDenyEntryIDAlnum(id[0]) || !isConfiguredStaticScriptLiteralDenyEntryIDAlnum(id[len(id)-1]) {
		return fmt.Errorf("%s must start and end with an ASCII letter or digit", field)
	}
	for i := 0; i < len(id); i++ {
		b := id[i]
		if isConfiguredStaticScriptLiteralDenyEntryIDAlnum(b) || b == '.' || b == '_' || b == '-' {
			continue
		}
		return fmt.Errorf("%s may contain only ASCII letters, digits, dot, underscore, or hyphen", field)
	}
	return nil
}

func isConfiguredStaticScriptLiteralDenyEntryIDAlnum(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9')
}

func (c NomadConfig) Validate(field string) error {
	if strings.TrimSpace(c.BaseURL) == "" {
		return fmt.Errorf("%s.base_url is required", field)
	}
	parsed, err := url.Parse(c.BaseURL)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return fmt.Errorf("%s.base_url must be a valid absolute URL", field)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return fmt.Errorf("%s.base_url must use http or https", field)
	}
	if strings.TrimSpace(c.Datacenter) == "" {
		return fmt.Errorf("%s.datacenter is required", field)
	}
	if c.TimeoutSeconds <= 0 {
		return fmt.Errorf("%s.timeout_seconds must be greater than 0", field)
	}
	if c.TokenFile == "" || !filepath.IsAbs(c.TokenFile) || filepath.Clean(c.TokenFile) != c.TokenFile ||
		strings.TrimSpace(c.TokenFile) != c.TokenFile || strings.ContainsRune(c.TokenFile, 0) {
		return fmt.Errorf("%s.token_file must be a clean absolute path", field)
	}
	if filepath.Dir(c.TokenFile) == string(os.PathSeparator) {
		return fmt.Errorf("%s.token_file must have a non-root parent directory", field)
	}
	return nil
}

// validateNomadTokenFilePlacement keeps the Nomad token file outside ES's
// staging and results storage, where workload-visible or retained material
// lives, and outside the SPIRE Workload API socket's directory, which every
// workload gets as a bind mount.
func validateNomadTokenFilePlacement(tokenFile string, execution ExecutionConfig) error {
	if pathsOverlap(tokenFile, filepath.Clean(strings.TrimSpace(execution.StagingRootDir))) ||
		pathsOverlap(tokenFile, filepath.Clean(strings.TrimSpace(execution.ResultsRootDir))) {
		return fmt.Errorf("nomad.token_file must be outside staging and results storage")
	}
	if socketPath := strings.TrimSpace(execution.SPIREWorkloadAPISocketPath); socketPath != "" &&
		pathsOverlap(tokenFile, filepath.Dir(filepath.Clean(socketPath))) {
		return fmt.Errorf("nomad.token_file must be outside the directory of execution.spire_workload_api_socket_path, which workloads mount")
	}
	if tokenFile == execution.RetainedResultAuth.KeyFile {
		return fmt.Errorf("nomad.token_file must differ from execution.retained_result_auth.key_file")
	}
	return nil
}

func (c ExecutionConfig) Validate(field string) error {
	if strings.TrimSpace(c.StagingRootDir) == "" {
		return fmt.Errorf("%s.staging_root_dir is required", field)
	}
	if strings.TrimSpace(c.BaseImage) == "" {
		return fmt.Errorf("%s.base_image is required", field)
	}
	if strings.TrimSpace(c.ResultsRootDir) == "" {
		return fmt.Errorf("%s.results_root_dir is required", field)
	}
	if !filepath.IsAbs(strings.TrimSpace(c.StagingRootDir)) {
		return fmt.Errorf("%s.staging_root_dir must be an absolute path", field)
	}
	if !filepath.IsAbs(strings.TrimSpace(c.ResultsRootDir)) {
		return fmt.Errorf("%s.results_root_dir must be an absolute path", field)
	}
	if pathsOverlap(filepath.Clean(strings.TrimSpace(c.StagingRootDir)), filepath.Clean(strings.TrimSpace(c.ResultsRootDir))) {
		return fmt.Errorf("%s.results_root_dir must be separate from %s.staging_root_dir", field, field)
	}
	if strings.TrimSpace(c.RuntimeSupportBinary) == "" {
		return fmt.Errorf("%s.runtime_support_binary is required", field)
	}
	if !filepath.IsAbs(strings.TrimSpace(c.RuntimeSupportBinary)) {
		return fmt.Errorf("%s.runtime_support_binary must be an absolute path", field)
	}
	if strings.TrimSpace(c.SPIREWorkloadAPISocketPath) == "" {
		return fmt.Errorf("%s.spire_workload_api_socket_path is required", field)
	}
	if !filepath.IsAbs(strings.TrimSpace(c.SPIREWorkloadAPISocketPath)) {
		return fmt.Errorf("%s.spire_workload_api_socket_path must be an absolute path", field)
	}
	if c.RuntimeIdentityTmpfsSize < 0 {
		return fmt.Errorf("%s.runtime_identity_tmpfs_size must be greater than or equal to 0", field)
	}
	if c.RuntimeIdentityTmpfsSize > maxRuntimeIdentityTmpfsSizeBytes {
		return fmt.Errorf("%s.runtime_identity_tmpfs_size must not exceed %d bytes", field, maxRuntimeIdentityTmpfsSizeBytes)
	}
	if err := c.RuntimeProfiles.Validate(field + ".runtime_profiles"); err != nil {
		return err
	}
	if err := c.RetainedResultAuth.Validate(field+".retained_result_auth", c.StagingRootDir, c.ResultsRootDir); err != nil {
		return err
	}
	return nil
}

func (c RetainedResultAuthConfig) Validate(field string, stagingRoot string, resultsRoot string) error {
	if !validRetainedResultAuthIdentifier(c.StoreID) {
		return fmt.Errorf("%s.store_id must be a canonical 1-32 byte identifier", field)
	}
	if !validRetainedResultAuthIdentifier(c.KeyID) {
		return fmt.Errorf("%s.key_id must be a canonical 1-32 byte identifier", field)
	}
	if c.KeyFile == "" || !filepath.IsAbs(c.KeyFile) || filepath.Clean(c.KeyFile) != c.KeyFile ||
		strings.TrimSpace(c.KeyFile) != c.KeyFile || strings.ContainsRune(c.KeyFile, 0) {
		return fmt.Errorf("%s.key_file must be a clean absolute path", field)
	}
	if filepath.Dir(c.KeyFile) == string(os.PathSeparator) {
		return fmt.Errorf("%s.key_file must have a non-root parent directory", field)
	}
	if pathsOverlap(c.KeyFile, filepath.Clean(strings.TrimSpace(stagingRoot))) ||
		pathsOverlap(c.KeyFile, filepath.Clean(strings.TrimSpace(resultsRoot))) {
		return fmt.Errorf("%s.key_file must be outside staging and results storage", field)
	}
	return nil
}

func validRetainedResultAuthIdentifier(value string) bool {
	if len(value) < 1 || len(value) > 32 || value[0] < 'a' || value[0] > 'z' {
		return false
	}
	for i := 1; i < len(value); i++ {
		c := value[i]
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '_' && c != '-' {
			return false
		}
	}
	return true
}

func (c RuntimeProfilesConfig) Validate(field string) error {
	if err := c.ControlPlaneNormalShell.Validate(field + ".control_plane_normal_shell"); err != nil {
		return err
	}
	return nil
}

func (c ControlPlaneNormalShellProfileConfig) Validate(field string) error {
	if !c.Enabled {
		return nil
	}
	if strings.TrimSpace(c.Image) == "" {
		return fmt.Errorf("%s.image is required when enabled", field)
	}
	if strings.TrimSpace(c.CodexCLIPath) == "" {
		return fmt.Errorf("%s.codex_cli_path is required when enabled", field)
	}
	if !filepath.IsAbs(strings.TrimSpace(c.CodexCLIPath)) {
		return fmt.Errorf("%s.codex_cli_path must be an absolute container path", field)
	}
	if strings.TrimSpace(c.CredentialVaultSecretPath) == "" {
		return fmt.Errorf("%s.credential_vault_secret_path is required when enabled", field)
	}
	if strings.HasPrefix(strings.TrimSpace(c.CredentialVaultSecretPath), "/") {
		return fmt.Errorf("%s.credential_vault_secret_path must be a Vault API path without a leading slash", field)
	}
	if strings.Contains(strings.TrimSpace(c.CredentialVaultSecretPath), "..") {
		return fmt.Errorf("%s.credential_vault_secret_path must not contain path traversal segments", field)
	}
	if strings.TrimSpace(c.CredentialVaultSecretField) == "" {
		return fmt.Errorf("%s.credential_vault_secret_field is required when enabled", field)
	}
	return nil
}

func pathsOverlap(left string, right string) bool {
	if left == right {
		return true
	}
	relative, err := filepath.Rel(left, right)
	if err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return true
	}
	relative, err = filepath.Rel(right, left)
	if err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return true
	}
	return false
}

func (c ExecutionConfig) EffectiveRuntimeIdentityTmpfsSize() int64 {
	if c.RuntimeIdentityTmpfsSize <= 0 {
		return defaultRuntimeIdentityTmpfsSizeBytes
	}
	return c.RuntimeIdentityTmpfsSize
}

func (s SignerVerifierConfig) Validate(field string) error {
	if strings.TrimSpace(s.Algorithm) != "ed25519" {
		return fmt.Errorf("%s.algorithm must be ed25519", field)
	}
	if strings.TrimSpace(s.KeyID) == "" {
		return fmt.Errorf("%s.key_id is required", field)
	}
	if strings.TrimSpace(s.PublicKeyHex) == "" {
		return fmt.Errorf("%s.public_key_hex is required", field)
	}
	decoded, err := hex.DecodeString(strings.TrimSpace(s.PublicKeyHex))
	if err != nil {
		return fmt.Errorf("%s.public_key_hex must be valid hex", field)
	}
	if len(decoded) != ed25519.PublicKeySize {
		return fmt.Errorf("%s.public_key_hex must be a %d-byte Ed25519 public key", field, ed25519.PublicKeySize)
	}
	return nil
}

func (c WorkloadVaultAuthConfig) Validate() error {
	if !isValidAuthMode(c.DefaultMode) {
		return fmt.Errorf("workload_vault_auth.default_mode must be vault_identity_jwt")
	}
	return nil
}

func isValidAuthMode(value WorkloadVaultAuthMode) bool {
	switch value {
	case WorkloadVaultAuthModeVaultIdentityJWT:
		return true
	default:
		return false
	}
}

func (c WorkloadVaultAuthConfig) Resolve(vault runtimeconfigv1.WorkloadZoneVaultConfig) (ResolvedWorkloadVaultAuthPlan, error) {
	normalized := vault.Normalized()
	if err := normalized.Validate(); err != nil {
		return ResolvedWorkloadVaultAuthPlan{}, err
	}

	return ResolvedWorkloadVaultAuthPlan{
		Mode:        c.DefaultMode,
		Address:     normalized.Address,
		AuthMount:   normalized.AuthMount,
		AuthRole:    normalized.AuthRole,
		JWTAudience: normalized.JWTAudience,
		CABundlePEM: normalized.CABundlePEM,
	}, nil
}

func (c Config) ReadTimeout() time.Duration {
	return time.Duration(c.HTTP.ReadTimeoutSeconds) * time.Second
}

func (c Config) WriteTimeout() time.Duration {
	return time.Duration(c.HTTP.WriteTimeoutSeconds) * time.Second
}

func (c Config) ShutdownTimeout() time.Duration {
	return time.Duration(c.HTTP.ShutdownTimeoutSeconds) * time.Second
}

func (c Config) SubmitConfigured() bool {
	return strings.TrimSpace(c.Nomad.BaseURL) != "" ||
		strings.TrimSpace(c.Nomad.Datacenter) != "" ||
		c.Nomad.TimeoutSeconds != 0 ||
		c.Nomad.TokenFile != "" ||
		strings.TrimSpace(c.Execution.StagingRootDir) != "" ||
		strings.TrimSpace(c.Execution.ResultsRootDir) != "" ||
		strings.TrimSpace(c.Execution.BaseImage) != "" ||
		strings.TrimSpace(c.Execution.RuntimeSupportBinary) != "" ||
		strings.TrimSpace(c.Execution.SPIREWorkloadAPISocketPath) != "" ||
		c.Execution.RuntimeProfiles.ControlPlaneNormalShell.Enabled
}
