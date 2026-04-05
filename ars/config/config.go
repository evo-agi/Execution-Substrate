package config

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

type Config struct {
	HTTP          HTTPConfig          `json:"http"`
	TLS           TLSConfig           `json:"tls"`
	Security      SecurityConfig      `json:"security"`
	Authorization AuthorizationConfig `json:"authorization"`
	Storage       StorageConfig       `json:"storage"`
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

type StorageConfig struct {
	RootDir   string `json:"root_dir"`
	IndexFile string `json:"index_file"`
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

	if strings.TrimSpace(c.Storage.RootDir) == "" {
		return fmt.Errorf("storage.root_dir is required")
	}
	if strings.TrimSpace(c.Storage.IndexFile) == "" {
		return fmt.Errorf("storage.index_file is required")
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
