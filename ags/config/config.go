package config

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"
	"time"

	"execution-substrate/internal/callerallowlist"
	"execution-substrate/internal/knownkeys"
)

type Config struct {
	HTTP          HTTPConfig          `json:"http"`
	TLS           TLSConfig           `json:"tls"`
	Security      SecurityConfig      `json:"security"`
	Authorization AuthorizationConfig `json:"authorization"`
	Dependencies  DependenciesConfig  `json:"dependencies"`
	Signer        SignerConfig        `json:"signer"`
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
	ArtifactRegistry DependencyConfig `json:"artifact_registry"`
}

type DependencyConfig struct {
	BaseURL        string `json:"base_url"`
	ServerName     string `json:"server_name"`
	ClientCertFile string `json:"client_cert_file"`
	ClientKeyFile  string `json:"client_key_file"`
	RootCAFile     string `json:"root_ca_file"`
	TimeoutSeconds int    `json:"timeout_seconds"`
}

type SignerConfig struct {
	Algorithm     string `json:"algorithm"`
	KeyID         string `json:"key_id"`
	PrivateKeyHex string `json:"private_key_hex"`
	PublicKeyHex  string `json:"public_key_hex"`
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

	// This file holds the AGS private signing key, so only the account
	// that runs the service and root may read it
	// (.docs/system_overview/configuration.md, "Signing keys"). The check is
	// on the opened file, so it judges the file that is read.
	info, err := file.Stat()
	if err != nil {
		return Config{}, fmt.Errorf("inspect config: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o007 != 0 {
		return Config{}, fmt.Errorf("config holds the private signing key and must be a regular file that other users cannot read or write: mode %04o", info.Mode().Perm())
	}

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
	if err := callerallowlist.ValidatePrefixes("authorization.allowed_spiffe_path_prefixes", c.Authorization.AllowedSPIFFEPathPrefixes); err != nil {
		return err
	}

	if err := c.Dependencies.ArtifactRegistry.Validate("dependencies.artifact_registry"); err != nil {
		return err
	}
	if err := c.Signer.Validate(); err != nil {
		return err
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

func (s SignerConfig) Validate() error {
	if strings.TrimSpace(s.Algorithm) != "ed25519" {
		return fmt.Errorf("signer.algorithm must be ed25519")
	}
	if strings.TrimSpace(s.KeyID) == "" {
		return fmt.Errorf("signer.key_id is required")
	}
	if strings.TrimSpace(s.PrivateKeyHex) == "" {
		return fmt.Errorf("signer.private_key_hex is required")
	}
	privateKeyBytes, err := hex.DecodeString(strings.TrimSpace(s.PrivateKeyHex))
	if err != nil {
		return fmt.Errorf("signer.private_key_hex must be valid hex")
	}
	if len(privateKeyBytes) != ed25519.PrivateKeySize && len(privateKeyBytes) != ed25519.SeedSize {
		return fmt.Errorf("signer.private_key_hex must be a %d-byte seed or %d-byte private key", ed25519.SeedSize, ed25519.PrivateKeySize)
	}
	if strings.TrimSpace(s.PublicKeyHex) == "" {
		return fmt.Errorf("signer.public_key_hex is required")
	}
	publicKeyBytes, err := hex.DecodeString(strings.TrimSpace(s.PublicKeyHex))
	if err != nil {
		return fmt.Errorf("signer.public_key_hex must be valid hex")
	}
	if len(publicKeyBytes) != ed25519.PublicKeySize {
		return fmt.Errorf("signer.public_key_hex must be a %d-byte Ed25519 public key", ed25519.PublicKeySize)
	}
	// A known key would let anyone seal evidence as this AGS
	// (.docs/system_overview/contracts.md, section 3B).
	if err := knownkeys.CheckPrivate("signer.private_key_hex", privateKeyBytes); err != nil {
		return err
	}
	return knownkeys.Check("signer.public_key_hex", publicKeyBytes)
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
