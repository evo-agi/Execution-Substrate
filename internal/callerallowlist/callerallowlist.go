// Package callerallowlist is the SPIFFE path-prefix allowlist rule that ARS,
// AGS and ES apply after internal/callerauth has authenticated a caller: which
// configured prefixes are valid, and when a caller matches one.
//
// Each service owns its allowlist: which prefixes it configures and which
// routes they open. This package owns only the shape of a valid prefix and the
// match, so that the three services check prefixes the same way. The rule is
// in .docs/system_overview/contracts.md, section 3A.
package callerallowlist

import (
	"errors"
	"fmt"
	"strings"

	"execution-substrate/internal/callerauth"
)

// MinimumSegments is the fewest path segments a prefix may have. A
// one-segment prefix such as "service" would authorize every identity below
// it.
const MinimumSegments = 2

var (
	// ErrNotCanonical means the prefix is not the path of a SPIFFE ID that
	// callerauth accepts, so no authenticated caller could ever match it.
	ErrNotCanonical = errors.New("callerallowlist: a path prefix must be the path of a SPIFFE ID in trust domain " + callerauth.TrustDomain + ", without its leading slash: segments of A-Z, a-z, 0-9, \".\", \"-\" and \"_\", none of them \".\" or \"..\", joined by single slashes, with no scheme, white space, or leading or trailing slash")
	// ErrTooBroad means the prefix has fewer than MinimumSegments segments.
	ErrTooBroad = fmt.Errorf("callerallowlist: a path prefix must have at least %d path segments", MinimumSegments)
)

// ValidatePrefix accepts prefix only when it is exactly the path that
// callerauth gives an authenticated caller: when
// "spiffe://execution.internal/" followed by prefix is a SPIFFE ID that
// callerauth.ParseSPIFFEID accepts. The prefix must also have at least
// MinimumSegments segments. Both "operator/local" and "service/control-plane"
// are valid; "service", "/operator/local", "operator/local/",
// "operator//local", "operator/./local", " operator/local", "operator/lo cal"
// and "spiffe://execution.internal/operator/local" are not.
func ValidatePrefix(prefix string) error {
	if _, err := callerauth.ParseSPIFFEID("spiffe://" + callerauth.TrustDomain + "/" + prefix); err != nil {
		return ErrNotCanonical
	}
	if strings.Count(prefix, "/")+1 < MinimumSegments {
		return ErrTooBroad
	}
	return nil
}

// ValidatePrefixes checks the allowlist configured at field: it must hold at
// least one prefix, and every prefix must pass ValidatePrefix. Services call it
// when they load their configuration, so that a prefix no caller could match,
// or one that is too broad, stops the service at startup.
func ValidatePrefixes(field string, prefixes []string) error {
	if len(prefixes) == 0 {
		return fmt.Errorf("%s is required", field)
	}
	for i, prefix := range prefixes {
		if err := ValidatePrefix(prefix); err != nil {
			return fmt.Errorf("%s[%d]: %w", field, i, err)
		}
	}
	return nil
}

// Matches reports whether prefix authorizes the authenticated caller id: the
// prefix is valid and id's path equals it or continues it after a "/". So
// "operator/local" matches "operator/local" and "operator/local/a", but not
// "operator/local-evil". A prefix that fails ValidatePrefix matches nothing,
// even when it reaches a service without passing its configuration check.
func Matches(id callerauth.SPIFFEID, prefix string) bool {
	if ValidatePrefix(prefix) != nil {
		return false
	}
	path := id.Path()
	return path == prefix || strings.HasPrefix(path, prefix+"/")
}

// MatchesAny reports whether any of prefixes matches id.
func MatchesAny(id callerauth.SPIFFEID, prefixes []string) bool {
	for _, prefix := range prefixes {
		if Matches(id, prefix) {
			return true
		}
	}
	return false
}
