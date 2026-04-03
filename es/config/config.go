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
)

type Config struct {
	HTTP              HTTPConfig              `json:"http"`
	TLS               TLSConfig               `json:"tls"`
	Security          SecurityConfig          `json:"security"`
	Dependencies      DependenciesConfig      `json:"dependencies"`
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

type DependenciesConfig struct {
	ArtifactCatalog     DependencyConfig `json:"artifact_catalog"`
	ArtifactRegistry    DependencyConfig `json:"artifact_registry"`
	ExecutionGovernance DependencyConfig `json:"execution_governance"`
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
	StagingRootDir           string `json:"staging_root_dir"`
	BaseImage                string `json:"base_image"`
	RuntimeIdentityTmpfsSize int64  `json:"runtime_identity_tmpfs_size,omitempty"`
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
	WorkloadVaultAuthModeCGSProofLegacy   WorkloadVaultAuthMode = "cgs_proof_legacy"
	WorkloadVaultAuthModeVaultIdentityJWT WorkloadVaultAuthMode = "vault_identity_jwt"
)

type WorkloadVaultAuthConfig struct {
	DefaultMode WorkloadVaultAuthMode       `json:"default_mode"`
	Selectors   []WorkloadVaultAuthSelector `json:"selectors"`
}

type WorkloadVaultAuthSelector struct {
	Mode               WorkloadVaultAuthMode `json:"mode"`
	ArtifactClass      string                `json:"artifact_class,omitempty"`
	WorkloadType       string                `json:"workload_type,omitempty"`
	ServiceName        string                `json:"service_name,omitempty"`
	WorkloadIdentityID string                `json:"workload_identity_id,omitempty"`
	VaultAuthRole      string                `json:"vault_auth_role,omitempty"`
	JWTAudience        string                `json:"jwt_audience,omitempty"`
}

type WorkloadIdentityAttributes struct {
	ArtifactClass      string
	WorkloadType       string
	ServiceName        string
	WorkloadIdentityID string
}

type VaultRuntimeFields struct {
	Address     string
	AuthMount   string
	AuthRole    string
	JWTAudience string
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

	if err := c.Dependencies.ArtifactCatalog.Validate("dependencies.artifact_catalog"); err != nil {
		return err
	}
	if err := c.Dependencies.ArtifactRegistry.Validate("dependencies.artifact_registry"); err != nil {
		return err
	}
	if err := c.Dependencies.ExecutionGovernance.Validate("dependencies.execution_governance"); err != nil {
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
	if !filepath.IsAbs(strings.TrimSpace(c.StagingRootDir)) {
		return fmt.Errorf("%s.staging_root_dir must be an absolute path", field)
	}
	if c.RuntimeIdentityTmpfsSize < 0 {
		return fmt.Errorf("%s.runtime_identity_tmpfs_size must be greater than or equal to 0", field)
	}
	if c.RuntimeIdentityTmpfsSize > maxRuntimeIdentityTmpfsSizeBytes {
		return fmt.Errorf("%s.runtime_identity_tmpfs_size must not exceed %d bytes", field, maxRuntimeIdentityTmpfsSizeBytes)
	}
	return nil
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
		return fmt.Errorf("workload_vault_auth.default_mode must be vault_identity_jwt or cgs_proof_legacy")
	}
	for i, selector := range c.Selectors {
		if err := selector.Validate(fmt.Sprintf("workload_vault_auth.selectors[%d]", i)); err != nil {
			return err
		}
	}
	return nil
}

func (s WorkloadVaultAuthSelector) Validate(field string) error {
	if !isValidAuthMode(s.Mode) {
		return fmt.Errorf("%s.mode must be vault_identity_jwt or cgs_proof_legacy", field)
	}
	return nil
}

func isValidAuthMode(value WorkloadVaultAuthMode) bool {
	switch value {
		case WorkloadVaultAuthModeVaultIdentityJWT, WorkloadVaultAuthModeCGSProofLegacy:
			return true
		default:
			return false
	}
}

func (c WorkloadVaultAuthConfig) Resolve(attrs WorkloadIdentityAttributes, vault VaultRuntimeFields) (ResolvedWorkloadVaultAuthPlan, error) {
	selected, err := c.selectRule(attrs)
	if err != nil {
		return ResolvedWorkloadVaultAuthPlan{}, err
	}

	mode := c.DefaultMode
	if selected != nil {
		mode = selected.Mode
	}
	if mode == WorkloadVaultAuthModeCGSProofLegacy {
		return ResolvedWorkloadVaultAuthPlan{
			Mode: mode,
		}, nil
	}

	address := strings.TrimSpace(vault.Address)
	if address == "" {
		return ResolvedWorkloadVaultAuthPlan{}, fmt.Errorf("workload-zone vault address is required")
	}
	parsedAddress, err := url.Parse(address)
	if err != nil || parsedAddress.Scheme != "https" || parsedAddress.Host == "" {
		return ResolvedWorkloadVaultAuthPlan{}, fmt.Errorf("workload-zone vault address must be a valid absolute https URL")
	}

	authMount := strings.TrimSpace(vault.AuthMount)
	if authMount == "" {
		return ResolvedWorkloadVaultAuthPlan{}, fmt.Errorf("workload-zone vault auth_mount is required")
	}

	authRole := strings.TrimSpace(vault.AuthRole)
	if selected != nil && strings.TrimSpace(selected.VaultAuthRole) != "" {
		authRole = strings.TrimSpace(selected.VaultAuthRole)
	}
	if authRole == "" {
		return ResolvedWorkloadVaultAuthPlan{}, fmt.Errorf("vault_identity_jwt auth plan requires an auth role")
	}

	jwtAudience := strings.TrimSpace(vault.JWTAudience)
	if selected != nil && strings.TrimSpace(selected.JWTAudience) != "" {
		jwtAudience = strings.TrimSpace(selected.JWTAudience)
	}
	if jwtAudience == "" {
		return ResolvedWorkloadVaultAuthPlan{}, fmt.Errorf("vault_identity_jwt auth plan requires a jwt audience")
	}

	return ResolvedWorkloadVaultAuthPlan{
		Mode:        mode,
		Address:     address,
		AuthMount:   authMount,
		AuthRole:    authRole,
		JWTAudience: jwtAudience,
	}, nil
}

func (c WorkloadVaultAuthConfig) selectRule(attrs WorkloadIdentityAttributes) (*WorkloadVaultAuthSelector, error) {
	matches := make([]WorkloadVaultAuthSelector, 0, len(c.Selectors))
	for _, selector := range c.Selectors {
		if selector.matches(attrs) {
			matches = append(matches, selector)
		}
	}
	if len(matches) == 0 {
		return nil, nil
	}

	best := matches[0]
	bestSpecificity := best.specificity()
	for _, candidate := range matches[1:] {
		specificity := candidate.specificity()
		if specificity > bestSpecificity {
			best = candidate
			bestSpecificity = specificity
			continue
		}
		if specificity == bestSpecificity {
			return nil, fmt.Errorf("workload_vault_auth selectors are ambiguous for workload identity %q", attrs.WorkloadIdentityID)
		}
	}

	return &best, nil
}

func (s WorkloadVaultAuthSelector) matches(attrs WorkloadIdentityAttributes) bool {
	if value := strings.TrimSpace(s.ArtifactClass); value != "" && value != strings.TrimSpace(attrs.ArtifactClass) {
		return false
	}
	if value := strings.TrimSpace(s.WorkloadType); value != "" && value != strings.TrimSpace(attrs.WorkloadType) {
		return false
	}
	if value := strings.TrimSpace(s.ServiceName); value != "" && value != strings.TrimSpace(attrs.ServiceName) {
		return false
	}
	if value := strings.TrimSpace(s.WorkloadIdentityID); value != "" && value != strings.TrimSpace(attrs.WorkloadIdentityID) {
		return false
	}
	return true
}

func (s WorkloadVaultAuthSelector) specificity() int {
	score := 0
	for _, value := range []string{s.ArtifactClass, s.WorkloadType, s.ServiceName, s.WorkloadIdentityID} {
		if strings.TrimSpace(value) != "" {
			score++
		}
	}
	return score
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
		strings.TrimSpace(c.Execution.BaseImage) != ""
}
