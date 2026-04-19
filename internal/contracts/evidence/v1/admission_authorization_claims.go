package evidencev1

import (
	"fmt"
	"strings"
)

type AuthorizationClaims struct {
	Derivation DerivationAuthorization `json:"derivation"`
}

type DerivationAuthorization struct {
	DerivationSpecDigest string `json:"derivation_spec_digest"`
	OutputID             string `json:"output_id"`
}

type canonicalAuthorizationClaims struct {
	Derivation canonicalDerivationAuthorization `json:"derivation"`
}

type canonicalDerivationAuthorization struct {
	DerivationSpecDigest string `json:"derivation_spec_digest"`
	OutputID             string `json:"output_id"`
}

func (a AuthorizationClaims) validate() error {
	requiredDigests := map[string]string{
		"claims.admission.authorization.derivation.derivation_spec_digest": a.Derivation.DerivationSpecDigest,
	}
	for field, digest := range requiredDigests {
		if err := validateDigest(strings.TrimSpace(digest)); err != nil {
			return fmt.Errorf("%s: %w", field, err)
		}
	}

	requiredStrings := map[string]string{
		"claims.admission.authorization.derivation.output_id": a.Derivation.OutputID,
	}
	for field, value := range requiredStrings {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("%s is required", field)
		}
	}

	return nil
}

func (a AuthorizationClaims) canonicalize() canonicalAuthorizationClaims {
	return canonicalAuthorizationClaims{
		Derivation: canonicalDerivationAuthorization{
			DerivationSpecDigest: strings.TrimSpace(a.Derivation.DerivationSpecDigest),
			OutputID:             strings.TrimSpace(a.Derivation.OutputID),
		},
	}
}
