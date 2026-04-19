package runtimeconfig

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

var labeledSHA256DigestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// WorkloadZoneVaultConfigRef identifies the current workload-zone Vault config
// blob without making ACS or ARS the semantic owner of the config itself.
type WorkloadZoneVaultConfigRef struct {
	Digest string `json:"digest"`
}

func (r WorkloadZoneVaultConfigRef) Normalized() WorkloadZoneVaultConfigRef {
	return WorkloadZoneVaultConfigRef{
		Digest: strings.TrimSpace(r.Digest),
	}
}

func (r WorkloadZoneVaultConfigRef) Validate() error {
	normalized := r.Normalized()
	if normalized.Digest == "" {
		return fmt.Errorf("digest is required")
	}
	if !labeledSHA256DigestPattern.MatchString(normalized.Digest) {
		return fmt.Errorf("digest must be a labeled SHA-256 digest")
	}
	return nil
}

// WorkloadZoneVaultConfigBlob is the current stored blob shape for the named
// workload-zone Vault runtime config.
type WorkloadZoneVaultConfigBlob struct {
	VaultConfig WorkloadZoneVaultConfig `json:"vault_config"`
}

func (b WorkloadZoneVaultConfigBlob) Normalized() WorkloadZoneVaultConfigBlob {
	return WorkloadZoneVaultConfigBlob{
		VaultConfig: b.VaultConfig.Normalized(),
	}
}

func (b WorkloadZoneVaultConfigBlob) Validate() error {
	if err := b.VaultConfig.Validate(); err != nil {
		return fmt.Errorf("vault_config: %w", err)
	}
	return nil
}

// WorkloadZoneVaultConfig is the current runtime-config meaning ES consumes
// from the workload-zone Vault blob.
type WorkloadZoneVaultConfig struct {
	Address     string `json:"address"`
	AuthMount   string `json:"auth_mount"`
	AuthRole    string `json:"auth_role"`
	JWTAudience string `json:"jwt_audience"`
	CABundlePEM string `json:"ca_bundle_pem,omitempty"`
}

func (c WorkloadZoneVaultConfig) Normalized() WorkloadZoneVaultConfig {
	return WorkloadZoneVaultConfig{
		Address:     strings.TrimSpace(c.Address),
		AuthMount:   strings.TrimSpace(c.AuthMount),
		AuthRole:    strings.TrimSpace(c.AuthRole),
		JWTAudience: strings.TrimSpace(c.JWTAudience),
		CABundlePEM: strings.TrimSpace(c.CABundlePEM),
	}
}

func (c WorkloadZoneVaultConfig) Validate() error {
	normalized := c.Normalized()
	if normalized.Address == "" {
		return fmt.Errorf("workload-zone vault address is required")
	}
	parsed, err := url.Parse(normalized.Address)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" {
		return fmt.Errorf("workload-zone vault address must be a valid absolute https URL")
	}
	if normalized.AuthMount == "" {
		return fmt.Errorf("workload-zone vault auth mount is required")
	}
	if normalized.AuthRole == "" {
		return fmt.Errorf("workload-zone vault auth role is required")
	}
	if normalized.JWTAudience == "" {
		return fmt.Errorf("workload-zone vault jwt audience is required")
	}
	if normalized.CABundlePEM != "" {
		if err := validatePEMCertificateBundle(normalized.CABundlePEM); err != nil {
			return fmt.Errorf("workload-zone vault ca_bundle_pem: %w", err)
		}
	}
	return nil
}

func validatePEMCertificateBundle(bundle string) error {
	remaining := []byte(strings.TrimSpace(bundle))
	certificates := 0
	for len(remaining) > 0 {
		var block *pem.Block
		block, remaining = pem.Decode(remaining)
		if block == nil {
			return fmt.Errorf("must contain only PEM certificate blocks")
		}
		if block.Type != "CERTIFICATE" {
			return fmt.Errorf("must contain only CERTIFICATE blocks")
		}
		if _, err := x509.ParseCertificate(block.Bytes); err != nil {
			return fmt.Errorf("invalid certificate block: %w", err)
		}
		certificates++
		remaining = []byte(strings.TrimSpace(string(remaining)))
	}
	if certificates == 0 {
		return fmt.Errorf("must contain at least one certificate")
	}
	return nil
}
