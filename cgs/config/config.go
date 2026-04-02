package config

import (
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"
	"time"
)

type Config struct {
	HTTP         HTTPConfig         `json:"http"`
	TLS          TLSConfig          `json:"tls"`
	Policy       PolicyConfig       `json:"policy"`
	VaultRuntime VaultRuntimeConfig `json:"vault_runtime"`
	Security     SecurityConfig     `json:"security"`
	ActionProof  ActionProofConfig  `json:"action_proof"`
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

type PolicyConfig struct {
	IDConfPath string `json:"id_conf_path"`
}

type VaultRuntimeConfig struct {
	Address          string `json:"address"`
	AuthMount        string `json:"auth_mount"`
	AuthRole         string `json:"auth_role"`
	JWTAudience      string `json:"jwt_audience"`
	ExpectedSPIFFEID string `json:"expected_spiffe_id"`
	ClientCertFile   string `json:"client_cert_file"`
	ClientKeyFile    string `json:"client_key_file"`
	ClientCAFile     string `json:"client_ca_file"`
	TimeoutSeconds   int    `json:"timeout_seconds"`
}

type SecurityConfig struct {
	BootstrapIssuerCommonName string `json:"bootstrap_issuer_common_name"`
}

type ActionProofConfig struct {
	SecretKey    string `json:"secret_key"`
	HashFunction string `json:"hash_function"`
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

	if strings.TrimSpace(c.Policy.IDConfPath) == "" {
		return fmt.Errorf("policy.id_conf_path is required")
	}

	if err := c.VaultRuntime.Validate(); err != nil {
		return err
	}

	if strings.TrimSpace(c.Security.BootstrapIssuerCommonName) == "" {
		return fmt.Errorf("security.bootstrap_issuer_common_name is required")
	}

	if strings.TrimSpace(c.ActionProof.SecretKey) == "" {
		return fmt.Errorf("action_proof.secret_key is required")
	}

	switch strings.ToLower(strings.TrimSpace(c.ActionProof.HashFunction)) {
		case "sha256", "sha512":
		default:
			return fmt.Errorf("action_proof.hash_function must be sha256 or sha512")
	}

	return nil
}

func (v VaultRuntimeConfig) Validate() error {
	if strings.TrimSpace(v.Address) == "" {
		return fmt.Errorf("vault_runtime.address is required")
	}
	parsedAddress, err := url.Parse(v.Address)
	if err != nil || parsedAddress.Scheme == "" || parsedAddress.Host == "" {
		return fmt.Errorf("vault_runtime.address must be a valid absolute URL")
	}
	if strings.TrimSpace(v.AuthMount) == "" {
		return fmt.Errorf("vault_runtime.auth_mount is required")
	}
	if strings.TrimSpace(v.AuthRole) == "" {
		return fmt.Errorf("vault_runtime.auth_role is required")
	}
	if strings.TrimSpace(v.JWTAudience) == "" {
		return fmt.Errorf("vault_runtime.jwt_audience is required")
	}
	if strings.TrimSpace(v.ExpectedSPIFFEID) == "" {
		return fmt.Errorf("vault_runtime.expected_spiffe_id is required")
	}
	parsedSPIFFE, err := url.Parse(v.ExpectedSPIFFEID)
	if err != nil || parsedSPIFFE.Scheme != "spiffe" || parsedSPIFFE.Host == "" {
		return fmt.Errorf("vault_runtime.expected_spiffe_id must be a valid SPIFFE ID")
	}
	if strings.TrimSpace(v.ClientCertFile) == "" {
		return fmt.Errorf("vault_runtime.client_cert_file is required")
	}
	if strings.TrimSpace(v.ClientKeyFile) == "" {
		return fmt.Errorf("vault_runtime.client_key_file is required")
	}
	if strings.TrimSpace(v.ClientCAFile) == "" {
		return fmt.Errorf("vault_runtime.client_ca_file is required")
	}
	if v.TimeoutSeconds <= 0 {
		return fmt.Errorf("vault_runtime.timeout_seconds must be greater than 0")
	}

	return nil
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
