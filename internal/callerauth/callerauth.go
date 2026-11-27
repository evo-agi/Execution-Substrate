// Package callerauth authenticates the caller of a request to an ES service
// (ARS, AGS, EGS, CGS and ES). It reads the caller's SPIFFE ID from the
// verified TLS client certificate and refuses the request when that identity
// is missing, ambiguous, malformed, outside the ES trust domain or a workload
// identity, when the verified chain is no longer (or not yet) within its
// validity period, when the certificate is not an end-entity certificate,
// when the certificate was issued by the configured bootstrap issuer, or
// when a namespace issuer binding ties the caller's path namespace and its
// issuing CA together and the certificate does not keep to it.
//
// The package owns authentication only: who is calling. Which authenticated
// callers may use which route (authorization) stays with each service.
//
// The rules are the contract in .docs/system_overview/contracts.md, section
// "3A. Caller Authentication". The five services use this package and keep
// no copy of these rules.
package callerauth

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

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
	ErrOutsideValidity       = errors.New("callerauth: no verified client certificate chain is within its validity period now")
	ErrNotEndEntity          = errors.New("callerauth: client certificate is a CA certificate or may sign certificates or CRLs")
	ErrNoURISAN              = errors.New("callerauth: client certificate carries no URI SAN")
	ErrMultipleURISANs       = errors.New("callerauth: client certificate carries more than one URI SAN")
	ErrMalformedSPIFFEID     = errors.New("callerauth: URI SAN is not a conforming SPIFFE ID with a path")
	ErrForeignTrustDomain    = errors.New("callerauth: SPIFFE ID is outside trust domain " + TrustDomain)
	ErrWorkloadIdentity      = errors.New("callerauth: SPIFFE ID is a workload identity, and workload identities are never callers")
	ErrIssuerNamespace       = errors.New("callerauth: the certificate's issuing CA and its path namespace do not keep to a namespace issuer binding")
)

// workloadPathSegment is the first path segment of every workload identity:
// the named identities spiffe://execution.internal/workload/<name>, the
// per-run identities reserved below them, and the shared ID
// spiffe://execution.internal/workload. Workload identities exist so that
// workloads can log in to the workload-zone Vault; no service accepts one as
// a caller. The rule is in .docs/system_overview/contracts.md, section 3A,
// and the identity layout in .docs/system_overview/runtime_identity_handoff.md,
// section 11.2.
const workloadPathSegment = "workload"

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
// well-formed ID in another trust domain returns ErrForeignTrustDomain. A
// well-formed ID in the trust domain whose first path segment is "workload",
// in any letter case, returns ErrWorkloadIdentity: workload identities are
// never callers. Every other refusal returns ErrMalformedSPIFFEID.
//
// These are the SPIFFE ID rules of the SPIFFE standard, plus the
// requirement of a path, because the trust domain's own ID names no
// workload, plus the refusal of workload identities. Callers use
// ParseSPIFFEID for caller identities only: an authenticated caller, an
// allowlist prefix, or a CGS principal.
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
	// Letter case is compared loosely on purpose: "Workload" is a different
	// SPIFFE ID, but no caller needs a path that differs from a workload
	// identity only in case, and refusing it leaves no letter-case variant
	// for a configuration to confuse with a workload identity. A different
	// word, such as "workloads", is a different identity and is not refused.
	if first, _, _ := strings.Cut(path, "/"); strings.EqualFold(first, workloadPathSegment) {
		return SPIFFEID{}, ErrWorkloadIdentity
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

// CallerFromConnectionState returns the caller identified, at time now, by
// the verified client certificate of a TLS connection. It reads the leaf of
// the first verified chain; Go's TLS server puts the peer's leaf first in
// every verified chain. At least one verified chain that starts with that
// leaf must have every certificate within its validity period at now: Go
// checks the chains once, at the handshake, and a connection can outlive
// them. The leaf must be an end-entity certificate: not a CA, and with
// neither the keyCertSign nor the cRLSign key usage. It must carry exactly
// one URI SAN, and that URI must pass ParseSPIFFEID. Other SAN types (DNS
// names, IP addresses, e-mail addresses) are not read.
//
// It does not apply the bootstrap-issuer rule; Authenticator does.
func CallerFromConnectionState(state *tls.ConnectionState, now time.Time) (Caller, error) {
	if state == nil || len(state.VerifiedChains) == 0 || len(state.VerifiedChains[0]) == 0 {
		return Caller{}, ErrNoVerifiedCertificate
	}
	leaf := state.VerifiedChains[0][0]
	if leaf == nil {
		return Caller{}, ErrNoVerifiedCertificate
	}
	if !verifiedChainValidAt(state.VerifiedChains, leaf, now) {
		return Caller{}, ErrOutsideValidity
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

// verifiedChainAnchors returns the SHA-256 of the last certificate of every
// verified chain of state that starts with its leaf: the trust anchors from
// the client CA pool that vouch for the caller.
func verifiedChainAnchors(state *tls.ConnectionState) [][sha256.Size]byte {
	if state == nil || len(state.VerifiedChains) == 0 || len(state.VerifiedChains[0]) == 0 || state.VerifiedChains[0][0] == nil {
		return nil
	}
	leaf := state.VerifiedChains[0][0]
	var anchors [][sha256.Size]byte
	for _, chain := range state.VerifiedChains {
		if len(chain) == 0 || (chain[0] != leaf && !chain[0].Equal(leaf)) || chain[len(chain)-1] == nil {
			continue
		}
		anchors = append(anchors, sha256.Sum256(chain[len(chain)-1].Raw))
	}
	return anchors
}

// NamespaceIssuer binds a SPIFFE ID path namespace to the one CA that may
// vouch for identities in it, and that CA to that namespace. A CA in a
// service's client CA pool otherwise vouches for any path in the trust
// domain: an X.509 URI name constraint can hold a CA to the trust domain
// but not to a path inside it. Make one with ParseNamespaceIssuer.
type NamespaceIssuer struct {
	pathPrefix string
	caSHA256   [sha256.Size]byte
}

// PathPrefix returns the bound namespace, for example "user".
func (n NamespaceIssuer) PathPrefix() string {
	return n.pathPrefix
}

// CASHA256 returns the SHA-256 of the bound CA certificate's DER encoding,
// as lower-case hex.
func (n NamespaceIssuer) CASHA256() string {
	return hex.EncodeToString(n.caSHA256[:])
}

// within reports whether path is the bound namespace or lies below it.
func (n NamespaceIssuer) within(path string) bool {
	return path == n.pathPrefix || strings.HasPrefix(path, n.pathPrefix+"/")
}

// ParseNamespaceIssuer accepts pathPrefix only when it is a SPIFFE ID path
// that ParseSPIFFEID would accept, written without a leading or trailing
// slash, for example "user" or "user/team" (so never a workload identity),
// and caSHA256 only when it is exactly 64 lower-case hexadecimal
// characters: the SHA-256 of the CA certificate's DER encoding.
func ParseNamespaceIssuer(pathPrefix, caSHA256 string) (NamespaceIssuer, error) {
	if _, err := ParseSPIFFEID(spiffeScheme + TrustDomain + "/" + pathPrefix); errors.Is(err, ErrWorkloadIdentity) {
		return NamespaceIssuer{}, fmt.Errorf("path_prefix %q names workload identities, which are never callers", pathPrefix)
	} else if err != nil {
		return NamespaceIssuer{}, fmt.Errorf("path_prefix %q is not a SPIFFE ID path such as \"user\"", pathPrefix)
	}
	if len(caSHA256) != 2*sha256.Size || strings.ToLower(caSHA256) != caSHA256 {
		return NamespaceIssuer{}, fmt.Errorf("issuer_certificate_sha256 %q is not 64 lower-case hexadecimal characters", caSHA256)
	}
	var digest [sha256.Size]byte
	if _, err := hex.Decode(digest[:], []byte(caSHA256)); err != nil {
		return NamespaceIssuer{}, fmt.Errorf("issuer_certificate_sha256 %q is not 64 lower-case hexadecimal characters", caSHA256)
	}
	return NamespaceIssuer{pathPrefix: pathPrefix, caSHA256: digest}, nil
}

// CheckNamespaceIssuers refuses a list in which an entry is not one that
// ParseNamespaceIssuer returned, two entries name the same CA, or one
// entry's namespace equals or lies within another's: each CA vouches for
// one namespace, and each path has at most one CA that may vouch for it.
func CheckNamespaceIssuers(issuers []NamespaceIssuer) error {
	for i, issuer := range issuers {
		if _, err := ParseNamespaceIssuer(issuer.pathPrefix, issuer.CASHA256()); err != nil {
			return fmt.Errorf("entry %d: %w", i, err)
		}
		for j := 0; j < i; j++ {
			other := issuers[j]
			if other.caSHA256 == issuer.caSHA256 {
				return fmt.Errorf("entries %d and %d bind the same CA", j, i)
			}
			if other.within(issuer.pathPrefix) || issuer.within(other.pathPrefix) {
				return fmt.Errorf("entries %d and %d bind overlapping namespaces %q and %q", j, i, other.pathPrefix, issuer.pathPrefix)
			}
		}
	}
	return nil
}

// NamespaceIssuerConfig is the configuration form of one NamespaceIssuer,
// as AGS and ES read it from security.namespace_issuers.
type NamespaceIssuerConfig struct {
	PathPrefix              string `json:"path_prefix"`
	IssuerCertificateSHA256 string `json:"issuer_certificate_sha256"`
}

// ParseNamespaceIssuers parses and checks a configured list. field names the
// list in error messages, for example "security.namespace_issuers".
func ParseNamespaceIssuers(field string, entries []NamespaceIssuerConfig) ([]NamespaceIssuer, error) {
	issuers := make([]NamespaceIssuer, 0, len(entries))
	for i, entry := range entries {
		issuer, err := ParseNamespaceIssuer(entry.PathPrefix, entry.IssuerCertificateSHA256)
		if err != nil {
			return nil, fmt.Errorf("%s[%d]: %w", field, i, err)
		}
		issuers = append(issuers, issuer)
	}
	if err := CheckNamespaceIssuers(issuers); err != nil {
		return nil, fmt.Errorf("%s: %w", field, err)
	}
	return issuers, nil
}

// namespaceIssuerError returns ErrIssuerNamespace unless the caller keeps to
// every binding of issuers: when a verified chain of its certificate ends at
// a bound CA, its path is in that CA's namespace, and when its path is in a
// bound namespace, every verified chain ends at that namespace's CA.
func namespaceIssuerError(caller Caller, state *tls.ConnectionState, issuers []NamespaceIssuer) error {
	if len(issuers) == 0 {
		return nil
	}
	anchors := verifiedChainAnchors(state)
	if len(anchors) == 0 {
		return ErrIssuerNamespace
	}
	for _, anchor := range anchors {
		for _, issuer := range issuers {
			if (anchor == issuer.caSHA256) != issuer.within(caller.id.path) {
				return ErrIssuerNamespace
			}
		}
	}
	return nil
}

// Authenticator applies the caller authentication rules to requests. Make
// one with NewAuthenticator.
type Authenticator struct {
	bootstrapIssuerCommonName string
	namespaceIssuers          []NamespaceIssuer
	// invalidNamespaceIssuers is set when WithNamespaceIssuers was given a
	// list that CheckNamespaceIssuers refuses; the Authenticator then
	// refuses every request.
	invalidNamespaceIssuers bool
	now                     func() time.Time
}

// NewAuthenticator returns an Authenticator that refuses callers whose
// client certificate names bootstrapIssuerCommonName as its issuer common
// name. Surrounding white space is ignored. Every service's startup
// configuration refuses an empty value; an Authenticator made with an empty
// value, and the zero Authenticator, refuse every request.
func NewAuthenticator(bootstrapIssuerCommonName string) Authenticator {
	return Authenticator{bootstrapIssuerCommonName: strings.TrimSpace(bootstrapIssuerCommonName), now: time.Now}
}

// WithNamespaceIssuers returns a copy of a that also applies issuers (see
// Authenticate). AGS and ES read them from security.namespace_issuers; with
// none, a behaves as before. A list that CheckNamespaceIssuers refuses makes
// the returned Authenticator refuse every request.
func (a Authenticator) WithNamespaceIssuers(issuers ...NamespaceIssuer) Authenticator {
	if err := CheckNamespaceIssuers(issuers); err != nil {
		a.namespaceIssuers = nil
		a.invalidNamespaceIssuers = true
		return a
	}
	a.namespaceIssuers = append([]NamespaceIssuer(nil), issuers...)
	a.invalidNamespaceIssuers = false
	return a
}

// Authenticate returns the authenticated caller of r and true. Otherwise it
// writes the refusal and returns false:
//
//   - 401 "Authenticated caller identity required" when r has no acceptable
//     caller identity at the time of the request (see
//     CallerFromConnectionState), and when the Authenticator has no
//     bootstrap issuer;
//   - 403 "Bootstrap PKI callers are not accepted; use a SPIRE-issued
//     identity" when the client certificate's issuer common name is the
//     bootstrap issuer;
//   - 401 "Authenticated caller identity required" when the caller does not
//     keep to a namespace issuer binding: a verified chain of its
//     certificate ends at a bound CA while its path is outside that CA's
//     namespace, or its path is in a bound namespace while a verified chain
//     ends at any other certificate (ErrIssuerNamespace), and when the
//     Authenticator was given namespace issuers that CheckNamespaceIssuers
//     refuses.
//
// Both bodies are plain text.
func (a Authenticator) Authenticate(w http.ResponseWriter, r *http.Request) (Caller, bool) {
	if a.bootstrapIssuerCommonName == "" || a.invalidNamespaceIssuers {
		httpx.WriteText(w, http.StatusUnauthorized, unauthenticatedBody)
		return Caller{}, false
	}
	now := time.Now
	if a.now != nil {
		now = a.now
	}
	caller, err := CallerFromConnectionState(r.TLS, now())
	if err != nil {
		httpx.WriteText(w, http.StatusUnauthorized, unauthenticatedBody)
		return Caller{}, false
	}
	if caller.issuerCommonName == a.bootstrapIssuerCommonName {
		httpx.WriteText(w, http.StatusForbidden, bootstrapIssuerBody)
		return Caller{}, false
	}
	if namespaceIssuerError(caller, r.TLS, a.namespaceIssuers) != nil {
		httpx.WriteText(w, http.StatusUnauthorized, unauthenticatedBody)
		return Caller{}, false
	}
	return caller, true
}

// verifiedChainValidAt reports whether one of chains starts with leaf and
// has every certificate within its validity period at now. Like Go's
// verifier, it counts a certificate as valid from its NotBefore through its
// NotAfter, both included.
func verifiedChainValidAt(chains [][]*x509.Certificate, leaf *x509.Certificate, now time.Time) bool {
	for _, chain := range chains {
		if len(chain) == 0 || (chain[0] != leaf && !chain[0].Equal(leaf)) {
			continue
		}
		valid := true
		for _, cert := range chain {
			if cert == nil || now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
				valid = false
				break
			}
		}
		if valid {
			return true
		}
	}
	return false
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
