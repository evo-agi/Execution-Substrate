package config

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"execution-substrate/egs/contract"
	"execution-substrate/internal/knownkeys"
)

type Config struct {
	HTTP         HTTPConfig                   `json:"http"`
	TLS          TLSConfig                    `json:"tls"`
	Security     SecurityConfig               `json:"security"`
	Signer       SignerConfig                 `json:"signer"`
	RuntimeTrust contract.RuntimeTrustPolicy  `json:"runtime_trust"`
	Publication  contract.PublicationMetadata `json:"publication"`
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

	if err := c.Signer.Validate(); err != nil {
		return err
	}
	if err := c.RuntimeTrust.Validate(); err != nil {
		return err
	}
	if err := c.Publication.Validate(); err != nil {
		return err
	}

	return nil
}

func (s SignerConfig) Validate() error {
	if strings.TrimSpace(s.Algorithm) != "ed25519" {
		// TODO: EGS v1 supports only Ed25519 because that is the currently
		// 		 validated trust-model path. This is an explicit slice boundary, not a
		// 		 generic signing framework. Revisit only if a concrete second algorithm
		// 		 is required by a live contract.
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
	if strings.TrimSpace(s.PublicKeyHex) == "" {
		return fmt.Errorf("signer.public_key_hex is required")
	}
	publicKeyBytes, err := hex.DecodeString(strings.TrimSpace(s.PublicKeyHex))
	if err != nil {
		return fmt.Errorf("signer.public_key_hex must be valid hex")
	}
	// A known key would let anyone sign a trust policy as this EGS
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
