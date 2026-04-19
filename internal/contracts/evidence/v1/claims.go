package evidencev1

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

const Version = "v1"

type Claims struct {
	SchemaVersion string          `json:"schema_version"`
	Package       PackageClaims   `json:"package"`
	Admission     AdmissionClaims `json:"admission"`
}

func (c Claims) CanonicalBytes() ([]byte, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}

	type canonicalClaims struct {
		SchemaVersion string                   `json:"schema_version"`
		Package       canonicalPackageClaims   `json:"package"`
		Admission     canonicalAdmissionClaims `json:"admission"`
	}

	payload := canonicalClaims{
		SchemaVersion: Version,
		Package:       c.Package.canonicalize(),
		Admission:     c.Admission.canonicalize(),
	}
	return json.Marshal(payload)
}

func (c Claims) Validate() error {
	if strings.TrimSpace(c.SchemaVersion) != Version {
		return fmt.Errorf("artifact evidence claims schema_version must be %s", Version)
	}
	if err := c.Package.validate(); err != nil {
		return err
	}
	if err := c.Admission.validate(); err != nil {
		return err
	}
	return nil
}

func normalizePolicyDecisions(values []PolicyDecision) []PolicyDecision {
	if len(values) == 0 {
		return []PolicyDecision{}
	}
	normalized := append([]PolicyDecision(nil), values...)
	sort.Slice(normalized, func(i, j int) bool {
		leftRule := strings.TrimSpace(normalized[i].Rule)
		rightRule := strings.TrimSpace(normalized[j].Rule)
		if leftRule == rightRule {
			return strings.TrimSpace(normalized[i].Result) < strings.TrimSpace(normalized[j].Result)
		}
		return leftRule < rightRule
	})
	return normalized
}

func normalizeStringSet(values []string) []string {
	if len(values) == 0 {
		return []string{}
	}
	normalized := append([]string(nil), values...)
	for i := range normalized {
		normalized[i] = strings.TrimSpace(normalized[i])
	}
	sort.Strings(normalized)
	return normalized
}

func validateDigest(value string) error {
	if !strings.HasPrefix(value, "sha256:") {
		return fmt.Errorf("must be a labeled sha256 digest")
	}
	sum := strings.TrimPrefix(value, "sha256:")
	if len(sum) != 64 {
		return fmt.Errorf("must be a labeled sha256 digest")
	}
	if _, err := hex.DecodeString(sum); err != nil {
		return fmt.Errorf("must be a labeled sha256 digest")
	}
	return nil
}
