// Package callerauthtest builds client certificates and TLS connection
// states for tests of the caller authentication rule in package callerauth.
// It is test support: only test files of this module import it, and no
// command or service links it.
//
// RefusedCallers is the shared list of caller credentials that every ES
// service must refuse with 401. Each service's own tests run the list
// against that service's handler, so one list pins the rule at all five
// call sites.
package callerauthtest

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// RuntimeIssuer is the issuer common name of the certificates that the
// tests treat as SPIRE-issued.
const RuntimeIssuer = "callerauthtest-runtime-ca"

var oidSubjectAltName = asn1.ObjectIdentifier{2, 5, 29, 17}

// Certificate returns a parsed leaf certificate issued by a fresh CA whose
// common name is issuerCommonName. The leaf carries the DNS name
// "client.callerauthtest" and the given URI SANs, written into the
// certificate exactly as given, in the given order. The certificate goes
// through x509.ParseCertificate, so its URIs are what Go's TLS stack would
// hand a server. The test fails when the parser refuses the certificate.
func Certificate(t testing.TB, issuerCommonName string, uris ...string) *x509.Certificate {
	t.Helper()
	cert, err := CertificateOrError(issuerCommonName, uris...)
	if err != nil {
		t.Fatalf("callerauthtest: certificate with URI SANs %q: %v", uris, err)
	}
	return cert
}

// CertificateOrError is Certificate for callers that expect the certificate
// parser to refuse a URI SAN.
func CertificateOrError(issuerCommonName string, uris ...string) (*x509.Certificate, error) {
	der, err := CertificateDER(issuerCommonName, uris...)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(der)
}

// CertificateDER returns the DER bytes of the certificate that Certificate
// parses.
func CertificateDER(issuerCommonName string, uris ...string) ([]byte, error) {
	return certificateDER(issuerCommonName, LeafProfile{}, uris)
}

// LeafProfile sets the basic constraints, key usage and validity period of
// the leaf that CertificateWithProfile builds. The zero value is the
// end-entity profile that Certificate uses: no basic constraints, the
// digitalSignature key usage, and valid from an hour ago to an hour from now.
type LeafProfile struct {
	// BasicConstraints writes a basic constraints extension; it says CA:FALSE
	// unless IsCA is set. SPIRE and the repository's scripts issue client
	// leaves with CA:FALSE.
	BasicConstraints bool
	// IsCA writes basic constraints that mark the leaf as a CA.
	IsCA bool
	// KeyUsage replaces the digitalSignature key usage when it is not zero.
	KeyUsage x509.KeyUsage
	// NotBefore and NotAfter replace the default validity period when they
	// are not zero.
	NotBefore, NotAfter time.Time
}

// CertificateWithProfile is Certificate with the leaf's basic constraints
// and key usage set by profile.
func CertificateWithProfile(t testing.TB, issuerCommonName string, profile LeafProfile, uris ...string) *x509.Certificate {
	t.Helper()
	der, err := certificateDER(issuerCommonName, profile, uris)
	if err == nil {
		var cert *x509.Certificate
		if cert, err = x509.ParseCertificate(der); err == nil {
			return cert
		}
	}
	t.Fatalf("callerauthtest: certificate with profile %+v and URI SANs %q: %v", profile, uris, err)
	return nil
}

func certificateDER(issuerCommonName string, profile LeafProfile, uris []string) ([]byte, error) {
	caPublic, caPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: issuerCommonName},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, caPublic, caPrivate)
	if err != nil {
		return nil, err
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		return nil, err
	}
	leafPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	san, err := subjectAltNameValue(uris)
	if err != nil {
		return nil, err
	}
	leafTemplate := &x509.Certificate{
		SerialNumber:    big.NewInt(2),
		Subject:         pkix.Name{CommonName: "client.callerauthtest"},
		NotBefore:       time.Now().Add(-time.Hour),
		NotAfter:        time.Now().Add(time.Hour),
		KeyUsage:        x509.KeyUsageDigitalSignature,
		ExtKeyUsage:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		ExtraExtensions: []pkix.Extension{{Id: oidSubjectAltName, Value: san}},
	}
	if profile.KeyUsage != 0 {
		leafTemplate.KeyUsage = profile.KeyUsage
	}
	if profile.BasicConstraints || profile.IsCA {
		leafTemplate.BasicConstraintsValid = true
		leafTemplate.IsCA = profile.IsCA
	}
	if !profile.NotBefore.IsZero() {
		leafTemplate.NotBefore = profile.NotBefore
	}
	if !profile.NotAfter.IsZero() {
		leafTemplate.NotAfter = profile.NotAfter
	}
	return x509.CreateCertificate(rand.Reader, leafTemplate, ca, leafPublic, caPrivate)
}

// subjectAltNameValue encodes a GeneralNames value with one DNS name and the
// given URIs as uniformResourceIdentifier entries, byte for byte.
func subjectAltNameValue(uris []string) ([]byte, error) {
	names := []asn1.RawValue{{Class: asn1.ClassContextSpecific, Tag: 2, Bytes: []byte("client.callerauthtest")}}
	for _, uri := range uris {
		names = append(names, asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 6, Bytes: []byte(uri)})
	}
	return asn1.Marshal(names)
}

// State returns a TLS connection state whose only verified chain holds cert
// as its leaf, as Go's TLS server reports a verified client certificate.
func State(cert *x509.Certificate) *tls.ConnectionState {
	return &tls.ConnectionState{
		HandshakeComplete: true,
		PeerCertificates:  []*x509.Certificate{cert},
		VerifiedChains:    [][]*x509.Certificate{{cert}},
	}
}

// RefusedCaller is one caller credential that every ES service must refuse
// with 401 "Authenticated caller identity required".
type RefusedCaller struct {
	// Name is the subtest name: ASCII letters, digits and "_" only.
	Name string
	// State builds the TLS state of the request; nil means a request
	// without TLS.
	State func(t testing.TB) *tls.ConnectionState
}

// SPIFFEID returns the SPIFFE ID of allowedPath in the ES trust domain.
func SPIFFEID(allowedPath string) string {
	return "spiffe://execution.internal/" + strings.Trim(allowedPath, "/")
}

// RefusedCallers returns the caller credentials that every service must
// refuse with 401, built around allowedPath: a path that the service under
// test authorizes. Every credential either carries allowedPath in some
// form or names it next to another identity, so a service that read the
// identity loosely would let the request through.
func RefusedCallers(allowedPath string) []RefusedCaller {
	path := strings.Trim(allowedPath, "/")
	id := SPIFFEID(path)
	last := path[strings.LastIndex(path, "/")+1:]
	parent := strings.TrimSuffix(strings.TrimSuffix(path, last), "/")

	withURIs := func(uris ...string) func(testing.TB) *tls.ConnectionState {
		return func(t testing.TB) *tls.ConnectionState {
			t.Helper()
			return State(Certificate(t, RuntimeIssuer, uris...))
		}
	}
	fixed := func(state *tls.ConnectionState) func(testing.TB) *tls.ConnectionState {
		return func(testing.TB) *tls.ConnectionState { return state }
	}
	withProfile := func(profile LeafProfile) func(testing.TB) *tls.ConnectionState {
		return func(t testing.TB) *tls.ConnectionState {
			t.Helper()
			return State(CertificateWithProfile(t, RuntimeIssuer, profile, id))
		}
	}

	cases := []RefusedCaller{
		// No verified certificate.
		{Name: "no_TLS", State: nil},
		{Name: "no_verified_chain", State: fixed(&tls.ConnectionState{HandshakeComplete: true})},
		{Name: "empty_verified_chain", State: fixed(&tls.ConnectionState{HandshakeComplete: true, VerifiedChains: [][]*x509.Certificate{{}}})},
		{Name: "nil_leaf", State: fixed(&tls.ConnectionState{HandshakeComplete: true, VerifiedChains: [][]*x509.Certificate{{nil}}})},
		{Name: "nil_URI_entry", State: fixed(State(&x509.Certificate{Issuer: pkix.Name{CommonName: RuntimeIssuer}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), URIs: []*url.URL{nil}}))},

		// Outside its validity period at the time of the request, even with
		// exactly the allowed identity: a connection can outlive the
		// certificates its handshake verified.
		{Name: "expired_leaf", State: withProfile(LeafProfile{NotBefore: time.Now().Add(-2 * time.Hour), NotAfter: time.Now().Add(-time.Minute)})},
		{Name: "not_yet_valid_leaf", State: withProfile(LeafProfile{NotBefore: time.Now().Add(time.Hour), NotAfter: time.Now().Add(2 * time.Hour)})},
		{Name: "expired_issuer_in_chain", State: func(t testing.TB) *tls.ConnectionState {
			t.Helper()
			leaf := Certificate(t, RuntimeIssuer, id)
			issuer := &x509.Certificate{Subject: pkix.Name{CommonName: RuntimeIssuer}, BasicConstraintsValid: true, IsCA: true, NotBefore: time.Now().Add(-2 * time.Hour), NotAfter: time.Now().Add(-time.Minute)}
			return &tls.ConnectionState{HandshakeComplete: true, PeerCertificates: []*x509.Certificate{leaf}, VerifiedChains: [][]*x509.Certificate{{leaf, issuer}}}
		}},

		// Not an end-entity certificate (X.509-SVID section 5.2), even with
		// exactly the allowed identity.
		{Name: "CA_leaf", State: withProfile(LeafProfile{IsCA: true})},
		{Name: "keyCertSign_leaf", State: withProfile(LeafProfile{KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign})},
		{Name: "cRLSign_leaf", State: withProfile(LeafProfile{KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCRLSign})},

		// No identity, or more than one.
		{Name: "no_URI_SAN", State: withURIs()},
		{Name: "two_URI_SANs_allowed_first", State: withURIs(id, "spiffe://execution.internal/service/other")},
		{Name: "two_URI_SANs_allowed_second", State: withURIs("spiffe://execution.internal/service/other", id)},
		{Name: "two_URI_SANs_foreign_first", State: withURIs("spiffe://other.internal/"+path, id)},
		{Name: "two_URI_SANs_same_ID_twice", State: withURIs(id, id)},
		{Name: "two_URI_SANs_second_not_SPIFFE", State: withURIs(id, "https://client.example/"+path)},

		// Outside the trust domain.
		{Name: "foreign_trust_domain", State: withURIs("spiffe://other.internal/" + path)},
		{Name: "trust_domain_as_prefix", State: withURIs("spiffe://execution.internal.evil/" + path)},
		{Name: "trust_domain_as_suffix", State: withURIs("spiffe://evil.execution.internal/" + path)},
		{Name: "trust_domain_with_port", State: withURIs("spiffe://execution.internal:8443/" + path)},
		{Name: "trust_domain_with_user", State: withURIs("spiffe://user@execution.internal/" + path)},
		{Name: "trust_domain_upper_case", State: withURIs("spiffe://EXECUTION.INTERNAL/" + path)},
		{Name: "other_scheme", State: withURIs("https://execution.internal/" + path)},

		// Not a conforming SPIFFE ID, or no workload path.
		{Name: "trust_domain_ID_only", State: withURIs("spiffe://execution.internal")},
		{Name: "root_path_only", State: withURIs("spiffe://execution.internal/")},
		{Name: "trailing_slash", State: withURIs(id + "/")},
		{Name: "leading_empty_segment", State: withURIs("spiffe://execution.internal//" + path)},
		{Name: "inner_empty_segment", State: withURIs("spiffe://execution.internal/" + parent + "//" + last)},
		{Name: "dot_segment", State: withURIs(id + "/.")},
		{Name: "dot_dot_segment", State: withURIs(id + "/..")},
		{Name: "dot_dot_back_into_path", State: withURIs(id + "/x/../" + last)},
		{Name: "query", State: withURIs(id + "?x=1")},
		{Name: "query_after_slash", State: withURIs(id + "/?x=1")},
		{Name: "empty_query", State: withURIs(id + "?")},
		{Name: "fragment", State: withURIs(id + "#x")},
		{Name: "fragment_after_slash", State: withURIs(id + "/#x")},
		{Name: "percent_encoded_slash", State: withURIs("spiffe://execution.internal/" + strings.ReplaceAll(path, "/", "%2F"))},
		{Name: "percent_encoded_letter", State: withURIs("spiffe://execution.internal/" + parent + "/%" + hexByte(last[0]) + last[1:])},
		{Name: "colon_in_segment", State: withURIs(id + "/a:b")},
		{Name: "at_in_segment", State: withURIs(id + "/a@b")},
		{Name: "tilde_in_segment", State: withURIs(id + "/a~b")},
		{Name: "plus_in_segment", State: withURIs(id + "/a+b")},
	}
	return cases
}

func hexByte(b byte) string {
	const digits = "0123456789ABCDEF"
	return string([]byte{digits[b>>4], digits[b&0x0f]})
}

const (
	// UnauthenticatedBody and BootstrapIssuerBody are the exact public
	// refusal bodies. They are repeated here, not taken from callerauth, so
	// that a change of either text fails the services' tests.
	UnauthenticatedBody = "Authenticated caller identity required"
	BootstrapIssuerBody = "Bootstrap PKI callers are not accepted; use a SPIRE-issued identity"
)

// Route is one route of a service that authenticates its caller.
type Route struct {
	// Name is the subtest name: ASCII letters, digits and "_" only.
	Name   string
	Method string
	Target string
	Body   string
	// AllowedPath is a caller path that the route authorizes.
	AllowedPath string
}

// Serve sends one request with the given TLS state to handler and returns
// the response. A handler panic fails the test.
func Serve(t testing.TB, handler http.Handler, method, target, body string, state *tls.ConnectionState) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(method, target, strings.NewReader(body))
	if body != "" {
		request.Header.Set("Content-Type", "application/json")
	}
	request.TLS = state
	recorder := httptest.NewRecorder()
	func() {
		defer func() {
			if p := recover(); p != nil {
				t.Fatalf("%s %s: handler panicked: %v", method, target, p)
			}
		}()
		handler.ServeHTTP(recorder, request)
	}()
	return recorder
}

// CheckRoute pins the caller authentication rule at one route. reached
// returns how many requests have gone past authentication into the
// service so far.
//
//   - A caller with one URI SAN, the SPIFFE ID of route.AllowedPath, from
//     RuntimeIssuer is neither refused with 401 nor with 403, and reaches
//     the service, with and without an explicit CA:FALSE basic constraint.
//   - The same identity from bootstrapIssuer gets 403 BootstrapIssuerBody.
//   - Every RefusedCallers credential gets 401 UnauthenticatedBody.
//
// Refused requests must not reach the service.
func CheckRoute(t *testing.T, handler http.Handler, route Route, bootstrapIssuer string, reached func() int) {
	t.Helper()
	t.Run(route.Name, func(t *testing.T) {
		for name, profile := range map[string]LeafProfile{
			"allowed_caller":          {},
			"allowed_caller_CA_false": {BasicConstraints: true, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment},
		} {
			t.Run(name, func(t *testing.T) {
				before := reached()
				state := State(CertificateWithProfile(t, RuntimeIssuer, profile, SPIFFEID(route.AllowedPath)))
				response := Serve(t, handler, route.Method, route.Target, route.Body, state)
				if response.Code == http.StatusUnauthorized || response.Code == http.StatusForbidden {
					t.Fatalf("allowed caller refused: %d %q", response.Code, response.Body.String())
				}
				if reached() == before {
					t.Fatalf("allowed caller did not reach the service: %d %q", response.Code, response.Body.String())
				}
			})
		}
		t.Run("bootstrap_issuer", func(t *testing.T) {
			before := reached()
			state := State(Certificate(t, bootstrapIssuer, SPIFFEID(route.AllowedPath)))
			response := Serve(t, handler, route.Method, route.Target, route.Body, state)
			expectRefusal(t, response, http.StatusForbidden, BootstrapIssuerBody)
			if reached() != before {
				t.Fatalf("bootstrap-issued caller reached the service")
			}
		})
		for _, tc := range RefusedCallers(route.AllowedPath) {
			t.Run(tc.Name, func(t *testing.T) {
				before := reached()
				var state *tls.ConnectionState
				if tc.State != nil {
					state = tc.State(t)
				}
				response := Serve(t, handler, route.Method, route.Target, route.Body, state)
				expectRefusal(t, response, http.StatusUnauthorized, UnauthenticatedBody)
				if reached() != before {
					t.Fatalf("refused caller reached the service")
				}
			})
		}
	})
}

func expectRefusal(t testing.TB, response *httptest.ResponseRecorder, status int, body string) {
	t.Helper()
	if response.Code != status || response.Body.String() != body {
		t.Fatalf("response %d %q, want %d %q", response.Code, response.Body.String(), status, body)
	}
	if got := response.Header().Get("Content-Type"); got != "text/plain; charset=utf-8" {
		t.Fatalf("Content-Type %q, want text/plain; charset=utf-8", got)
	}
}
