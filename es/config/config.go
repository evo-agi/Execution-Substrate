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

	runtimeconfigv1 "execution-substrate/internal/contracts/runtimeconfig/v1"
)

type Config struct {
	HTTP              HTTPConfig              `json:"http"`
	TLS               TLSConfig               `json:"tls"`
	Security          SecurityConfig          `json:"security"`
	Authorization     AuthorizationConfig     `json:"authorization"`
	Dependencies      DependenciesConfig      `json:"dependencies"`
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

type NomadConfig struct {
	BaseURL        string `json:"base_url"`
	Datacenter     string `json:"datacenter"`
	TimeoutSeconds int    `json:"timeout_seconds"`
}

type ExecutionConfig struct {
	StagingRootDir             string                `json:"staging_root_dir"`
	ResultsRootDir             string                `json:"results_root_dir"`
	BaseImage                  string                `json:"base_image"`
	RuntimeIdentityTmpfsSize   int64                 `json:"runtime_identity_tmpfs_size,omitempty"`
	RuntimeSupportBinary       string                `json:"runtime_support_binary,omitempty"`
	SPIREWorkloadAPISocketPath string                `json:"spire_workload_api_socket_path,omitempty"`
	RuntimeProfiles            RuntimeProfilesConfig `json:"runtime_profiles,omitempty"`
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
	if len(c.Authorization.AllowedSPIFFEPathPrefixes) == 0 {
		return fmt.Errorf("authorization.allowed_spiffe_path_prefixes is required")
	}
	for _, prefix := range c.Authorization.AllowedSPIFFEPathPrefixes {
		if strings.TrimSpace(prefix) == "" {
			return fmt.Errorf("authorization.allowed_spiffe_path_prefixes cannot contain empty values")
		}
	}

	if err := c.Dependencies.ArtifactRegistry.Validate("dependencies.artifact_registry"); err != nil {
		return err
	}
	if err := c.Dependencies.ExecutionGovernance.Validate("dependencies.execution_governance"); err != nil {
		return err
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
	return nil
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
		strings.TrimSpace(c.Execution.StagingRootDir) != "" ||
		strings.TrimSpace(c.Execution.ResultsRootDir) != "" ||
		strings.TrimSpace(c.Execution.BaseImage) != "" ||
		strings.TrimSpace(c.Execution.RuntimeSupportBinary) != "" ||
		strings.TrimSpace(c.Execution.SPIREWorkloadAPISocketPath) != "" ||
		c.Execution.RuntimeProfiles.ControlPlaneNormalShell.Enabled
}
