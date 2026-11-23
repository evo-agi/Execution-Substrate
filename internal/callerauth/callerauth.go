// Package callerauth authenticates the caller of a request to an ES service
// (ARS, AGS, EGS, CGS and ES). It reads the caller's SPIFFE ID from the
// verified TLS client certificate and refuses the request when that identity
// is missing, ambiguous, malformed or outside the ES trust domain, when the
// certificate is not an end-entity certificate, or when the certificate was
// issued by the configured bootstrap issuer.
//
// The package owns authentication only: who is calling. Which authenticated
// callers may use which route (authorization) stays with each service.
//
// The rules are the contract in .docs/system_overview/contracts.md, section
// "3A. Caller Authentication". The five services use this package and keep
// no copy of these rules.
package callerauth

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/http"
	"strings"

	"execution-substrate/internal/httpx"
)

// TrustDomain is the only SPIFFE trust domain whose identities the ES
// services accept from callers.
const TrustDomain = "execution.internal"

const (
	spiffeScheme = "spiffe://"

	// The refusal bodies are part of every service's public contract.
	unauthenticatedBody = "Authenticated caller identity required"
	bootstrapIssuerBody = "Bootstrap PKI callers are not accepted; use a SPIRE-issued identity"
)

// Each refusal reason has its own error. The HTTP response does not say
// which one applied: every one of them is answered with the same 401.
var (
	ErrNoVerifiedCertificate = errors.New("callerauth: no verified client certificate")
	ErrNotEndEntity          = errors.New("callerauth: client certificate is a CA certificate or may sign certificates or CRLs")
	ErrNoURISAN              = errors.New("callerauth: client certificate carries no URI SAN")
	ErrMultipleURISANs       = errors.New("callerauth: client certificate carries more than one URI SAN")
	ErrMalformedSPIFFEID     = errors.New("callerauth: URI SAN is not a conforming SPIFFE ID with a path")
	ErrForeignTrustDomain    = errors.New("callerauth: SPIFFE ID is outside trust domain " + TrustDomain)
)

// SPIFFEID is a SPIFFE ID in TrustDomain that passed ParseSPIFFEID. Its
// zero value is not a valid ID.
type SPIFFEID struct {
	path string
}

// ParseSPIFFEID accepts raw only when it is exactly a SPIFFE ID of the form
// spiffe://execution.internal/<segment>[/<segment>...], where every segment
// is one or more of the characters A-Z, a-z, 0-9, ".", "-" and "_" and is
// not "." or "..". Anything else is refused: another scheme or letter case
// of the scheme, user information, a port, a query, a fragment, percent
// encoding, an empty segment, a trailing slash, or no path at all. A
// well-formed ID in another trust domain returns ErrForeignTrustDomain;
// every other refusal returns ErrMalformedSPIFFEID.
//
// These are the SPIFFE ID rules of the SPIFFE standard, plus the
// requirement of a path, because the trust domain's own ID names no
// workload.
func ParseSPIFFEID(raw string) (SPIFFEID, error) {
	if !strings.HasPrefix(raw, spiffeScheme) {
		return SPIFFEID{}, ErrMalformedSPIFFEID
	}
	domain, path, hasPath := strings.Cut(raw[len(spiffeScheme):], "/")
	if !validTrustDomainName(domain) || !hasPath {
		return SPIFFEID{}, ErrMalformedSPIFFEID
	}
	for _, segment := range strings.Split(path, "/") {
		if !validPathSegment(segment) {
			return SPIFFEID{}, ErrMalformedSPIFFEID
		}
	}
	if domain != TrustDomain {
		return SPIFFEID{}, ErrForeignTrustDomain
	}
	return SPIFFEID{path: path}, nil
}

// String returns the ID in its only accepted form, for example
// "spiffe://execution.internal/operator/local".
func (id SPIFFEID) String() string {
	if id.path == "" {
		return ""
	}
	return spiffeScheme + TrustDomain + "/" + id.path
}

// Path returns the ID's path without its leading slash, for example
// "operator/local". The services' path-prefix authorization matches it.
func (id SPIFFEID) Path() string {
	return id.path
}

// Caller is an authenticated caller.
type Caller struct {
	id               SPIFFEID
	issuerCommonName string
}

// ID returns the caller's SPIFFE ID.
func (c Caller) ID() SPIFFEID {
	return c.id
}

// CallerFromConnectionState returns the caller identified by the verified
// client certificate of a TLS connection. It reads the leaf of the first
// verified chain; Go's TLS server puts the peer's leaf first in every
// verified chain. The leaf must be an end-entity certificate: not a CA, and
// with neither the keyCertSign nor the cRLSign key usage. It must carry
// exactly one URI SAN, and that URI must pass ParseSPIFFEID. Other SAN types
// (DNS names, IP addresses, e-mail addresses) are not read.
//
// It does not apply the bootstrap-issuer rule; Authenticator does.
func CallerFromConnectionState(state *tls.ConnectionState) (Caller, error) {
	if state == nil || len(state.VerifiedChains) == 0 || len(state.VerifiedChains[0]) == 0 {
		return Caller{}, ErrNoVerifiedCertificate
	}
	leaf := state.VerifiedChains[0][0]
	if leaf == nil {
		return Caller{}, ErrNoVerifiedCertificate
	}
	// X.509-SVID section 5.2: a validator refuses a leaf whose basic
	// constraints mark it as a CA, or whose key usage includes keyCertSign
	// or cRLSign. Go's verifier lets such a certificate stand as the client
	// certificate when it has no extended key usage, which CA certificates
	// usually lack.
	if leaf.IsCA || leaf.KeyUsage&(x509.KeyUsageCertSign|x509.KeyUsageCRLSign) != 0 {
		return Caller{}, ErrNotEndEntity
	}
	switch len(leaf.URIs) {
	case 0:
		return Caller{}, ErrNoURISAN
	case 1:
	default:
		return Caller{}, ErrMultipleURISANs
	}
	uri := leaf.URIs[0]
	if uri == nil {
		return Caller{}, ErrMalformedSPIFFEID
	}
	// The certificate parser keeps the URI parsed. Its String form must pass
	// the same strict text rule as any other SPIFFE ID; the rule refuses
	// every character that a user, port, query, fragment or percent
	// encoding would need.
	id, err := ParseSPIFFEID(uri.String())
	if err != nil {
		return Caller{}, err
	}
	return Caller{id: id, issuerCommonName: leaf.Issuer.CommonName}, nil
}

// Authenticator applies the caller authentication rules to requests. Make
// one with NewAuthenticator.
type Authenticator struct {
	bootstrapIssuerCommonName string
}

// NewAuthenticator returns an Authenticator that refuses callers whose
// client certificate names bootstrapIssuerCommonName as its issuer common
// name. Surrounding white space is ignored. Every service's startup
// configuration refuses an empty value; an Authenticator made with an empty
// value, and the zero Authenticator, refuse every request.
func NewAuthenticator(bootstrapIssuerCommonName string) Authenticator {
	return Authenticator{bootstrapIssuerCommonName: strings.TrimSpace(bootstrapIssuerCommonName)}
}

// Authenticate returns the authenticated caller of r and true. Otherwise it
// writes the refusal and returns false:
//
//   - 401 "Authenticated caller identity required" when r has no acceptable
//     caller identity (see CallerFromConnectionState), and when the
//     Authenticator has no bootstrap issuer;
//   - 403 "Bootstrap PKI callers are not accepted; use a SPIRE-issued
//     identity" when the client certificate's issuer common name is the
//     bootstrap issuer.
//
// Both bodies are plain text.
func (a Authenticator) Authenticate(w http.ResponseWriter, r *http.Request) (Caller, bool) {
	if a.bootstrapIssuerCommonName == "" {
		httpx.WriteText(w, http.StatusUnauthorized, unauthenticatedBody)
		return Caller{}, false
	}
	caller, err := CallerFromConnectionState(r.TLS)
	if err != nil {
		httpx.WriteText(w, http.StatusUnauthorized, unauthenticatedBody)
		return Caller{}, false
	}
	if caller.issuerCommonName == a.bootstrapIssuerCommonName {
		httpx.WriteText(w, http.StatusForbidden, bootstrapIssuerBody)
		return Caller{}, false
	}
	return caller, true
}

// validTrustDomainName reports whether name is a non-empty trust domain name
// of lowercase letters, digits, ".", "-" and "_".
func validTrustDomainName(name string) bool {
	if name == "" {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '.', c == '-', c == '_':
		default:
			return false
		}
	}
	return true
}

// validPathSegment reports whether segment is a non-empty SPIFFE ID path
// segment of letters, digits, ".", "-" and "_" that is not "." or "..".
func validPathSegment(segment string) bool {
	if segment == "" || segment == "." || segment == ".." {
		return false
	}
	for i := 0; i < len(segment); i++ {
		c := segment[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '.', c == '-', c == '_':
		default:
			return false
		}
	}
	return true
}
