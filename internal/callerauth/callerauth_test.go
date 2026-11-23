package callerauth_test

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"

	"execution-substrate/internal/callerauth"
	"execution-substrate/internal/callerauth/callerauthtest"
)

const (
	unauthenticatedBody = "Authenticated caller identity required"
	bootstrapIssuerBody = "Bootstrap PKI callers are not accepted; use a SPIRE-issued identity"
	bootstrapIssuer     = "bootstrap-ca"
)

var acceptedIDs = []struct {
	raw  string
	path string
}{
	{raw: "spiffe://execution.internal/operator/local", path: "operator/local"},
	{raw: "spiffe://execution.internal/service/execution", path: "service/execution"},
	{raw: "spiffe://execution.internal/service/control-plane/provider", path: "service/control-plane/provider"},
	{raw: "spiffe://execution.internal/workload", path: "workload"},
	{raw: "spiffe://execution.internal/a", path: "a"},
	{raw: "spiffe://execution.internal/AZaz09.-_/x", path: "AZaz09.-_/x"},
	{raw: "spiffe://execution.internal/.../...", path: ".../..."},
	{raw: "spiffe://execution.internal/.a/a./..b/b..", path: ".a/a./..b/b.."},
}

var refusedIDs = []struct {
	raw  string
	want error
}{
	{raw: "", want: callerauth.ErrMalformedSPIFFEID},
	{raw: "spiffe:", want: callerauth.ErrMalformedSPIFFEID},
	{raw: "spiffe:/execution.internal/operator/local", want: callerauth.ErrMalformedSPIFFEID},
	{raw: "spiffe:execution.internal/operator/local", want: callerauth.ErrMalformedSPIFFEID},
	{raw: "SPIFFE://execution.internal/operator/local", want: callerauth.ErrMalformedSPIFFEID},
	{raw: "https://execution.internal/operator/local", want: callerauth.ErrMalformedSPIFFEID},
	{raw: " spiffe://execution.internal/operator/local", want: callerauth.ErrMalformedSPIFFEID},
	{raw: "spiffe://execution.internal/operator/local ", want: callerauth.ErrMalformedSPIFFEID},
	{raw: "spiffe://", want: callerauth.ErrMalformedSPIFFEID},
	{raw: "spiffe:///operator/local", want: callerauth.ErrMalformedSPIFFEID},
	{raw: "spiffe://execution.internal", want: callerauth.ErrMalformedSPIFFEID},
	{raw: "spiffe://execution.internal/", want: callerauth.ErrMalformedSPIFFEID},
	{raw: "spiffe://execution.internal//", want: callerauth.ErrMalformedSPIFFEID},
	{raw: "spiffe://execution.internal/operator/local/", want: callerauth.ErrMalformedSPIFFEID},
	{raw: "spiffe://execution.internal//operator/local", want: callerauth.ErrMalformedSPIFFEID},
	{raw: "spiffe://execution.internal/operator//local", want: callerauth.ErrMalformedSPIFFEID},
	{raw: "spiffe://execution.internal/.", want: callerauth.ErrMalformedSPIFFEID},
	{raw: "spiffe://execution.internal/..", want: callerauth.ErrMalformedSPIFFEID},
	{raw: "spiffe://execution.internal/operator/./local", want: callerauth.ErrMalformedSPIFFEID},
	{raw: "spiffe://execution.internal/operator/../operator/local", want: callerauth.ErrMalformedSPIFFEID},
	{raw: "spiffe://execution.internal/operator/local?", want: callerauth.ErrMalformedSPIFFEID},
	{raw: "spiffe://execution.internal/operator/local?x=1", want: callerauth.ErrMalformedSPIFFEID},
	{raw: "spiffe://execution.internal/operator/local#", want: callerauth.ErrMalformedSPIFFEID},
	{raw: "spiffe://execution.internal/operator/local#x", want: callerauth.ErrMalformedSPIFFEID},
	{raw: "spiffe://execution.internal/operator%2Flocal", want: callerauth.ErrMalformedSPIFFEID},
	{raw: "spiffe://execution.internal/operator/%6Cocal", want: callerauth.ErrMalformedSPIFFEID},
	{raw: "spiffe://execution.internal/operator/lo cal", want: callerauth.ErrMalformedSPIFFEID},
	{raw: "spiffe://execution.internal/operator/lo\x00cal", want: callerauth.ErrMalformedSPIFFEID},
	{raw: "spiffe://execution.internal/operator/löcal", want: callerauth.ErrMalformedSPIFFEID},
	{raw: "spiffe://execution.internal/operator\\local", want: callerauth.ErrMalformedSPIFFEID},
	{raw: "spiffe://execution.internal/operator/a:b", want: callerauth.ErrMalformedSPIFFEID},
	{raw: "spiffe://execution.internal/operator/a@b", want: callerauth.ErrMalformedSPIFFEID},
	{raw: "spiffe://execution.internal/operator/a~b", want: callerauth.ErrMalformedSPIFFEID},
	{raw: "spiffe://execution.internal/operator/a+b", want: callerauth.ErrMalformedSPIFFEID},
	{raw: "spiffe://execution.internal/operator/a;b", want: callerauth.ErrMalformedSPIFFEID},
	{raw: "spiffe://execution.internal/operator/a=b", want: callerauth.ErrMalformedSPIFFEID},
	{raw: "spiffe://execution.internal:443/operator/local", want: callerauth.ErrMalformedSPIFFEID},
	{raw: "spiffe://user@execution.internal/operator/local", want: callerauth.ErrMalformedSPIFFEID},
	{raw: "spiffe://EXECUTION.INTERNAL/operator/local", want: callerauth.ErrMalformedSPIFFEID},
	{raw: "spiffe://Execution.internal/operator/local", want: callerauth.ErrMalformedSPIFFEID},
	{raw: "spiffe://execution.internal?x/operator/local", want: callerauth.ErrMalformedSPIFFEID},
	{raw: "spiffe://other.internal", want: callerauth.ErrMalformedSPIFFEID},
	{raw: "spiffe://other.internal/", want: callerauth.ErrMalformedSPIFFEID},
	{raw: "spiffe://other.internal/operator/local/", want: callerauth.ErrMalformedSPIFFEID},
	{raw: "spiffe://other.internal/operator/local", want: callerauth.ErrForeignTrustDomain},
	{raw: "spiffe://execution.internal.evil/operator/local", want: callerauth.ErrForeignTrustDomain},
	{raw: "spiffe://evil.execution.internal/operator/local", want: callerauth.ErrForeignTrustDomain},
	{raw: "spiffe://execution.interna/operator/local", want: callerauth.ErrForeignTrustDomain},
	{raw: "spiffe://execution-internal/operator/local", want: callerauth.ErrForeignTrustDomain},
	{raw: "spiffe://execution_internal/operator/local", want: callerauth.ErrForeignTrustDomain},
	{raw: "spiffe://0/operator/local", want: callerauth.ErrForeignTrustDomain},
}

func TestTrustDomainIsTheESTrustDomain(t *testing.T) {
	if callerauth.TrustDomain != "execution.internal" {
		t.Fatalf("TrustDomain = %q, want execution.internal", callerauth.TrustDomain)
	}
}

func TestParseSPIFFEIDAcceptsConformingIDsInTheTrustDomain(t *testing.T) {
	for _, tc := range acceptedIDs {
		id, err := callerauth.ParseSPIFFEID(tc.raw)
		if err != nil {
			t.Errorf("ParseSPIFFEID(%q): %v", tc.raw, err)
			continue
		}
		if got := id.String(); got != tc.raw {
			t.Errorf("ParseSPIFFEID(%q).String() = %q, want the input", tc.raw, got)
		}
		if got := id.Path(); got != tc.path {
			t.Errorf("ParseSPIFFEID(%q).Path() = %q, want %q", tc.raw, got, tc.path)
		}
	}
}

func TestParseSPIFFEIDRefusesEverythingElse(t *testing.T) {
	for _, tc := range refusedIDs {
		id, err := callerauth.ParseSPIFFEID(tc.raw)
		if !errors.Is(err, tc.want) {
			t.Errorf("ParseSPIFFEID(%q) error = %v, want %v", tc.raw, err, tc.want)
		}
		if id != (callerauth.SPIFFEID{}) {
			t.Errorf("ParseSPIFFEID(%q) returned %q with an error", tc.raw, id)
		}
	}
}

func TestZeroSPIFFEIDIsEmpty(t *testing.T) {
	var id callerauth.SPIFFEID
	if id.String() != "" || id.Path() != "" {
		t.Fatalf("zero SPIFFEID = %q path %q, want both empty", id.String(), id.Path())
	}
}

// referenceAccepts applies the SPIFFE standard as the go-spiffe library
// implements it, plus this package's two additions: the trust domain must
// be TrustDomain and the ID must have a path.
func referenceAccepts(raw string) bool {
	id, err := spiffeid.FromString(raw)
	return err == nil && id.TrustDomain().Name() == callerauth.TrustDomain && id.Path() != ""
}

func TestParseSPIFFEIDAgreesWithTheSPIFFEReferenceParser(t *testing.T) {
	var corpus []string
	for _, tc := range acceptedIDs {
		corpus = append(corpus, tc.raw)
	}
	for _, tc := range refusedIDs {
		corpus = append(corpus, tc.raw)
	}
	accepted := 0
	for _, raw := range corpus {
		_, err := callerauth.ParseSPIFFEID(raw)
		if got, want := err == nil, referenceAccepts(raw); got != want {
			t.Errorf("ParseSPIFFEID(%q) accepted=%v, reference accepted=%v", raw, got, want)
		}
		if err == nil {
			accepted++
		}
	}
	if accepted != len(acceptedIDs) {
		t.Fatalf("corpus accepted %d IDs, want %d", accepted, len(acceptedIDs))
	}
}

func FuzzParseSPIFFEIDAgreesWithTheSPIFFEReferenceParser(f *testing.F) {
	for _, tc := range acceptedIDs {
		f.Add(tc.raw)
	}
	for _, tc := range refusedIDs {
		f.Add(tc.raw)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		id, err := callerauth.ParseSPIFFEID(raw)
		if got, want := err == nil, referenceAccepts(raw); got != want {
			t.Fatalf("ParseSPIFFEID(%q) accepted=%v, reference accepted=%v", raw, got, want)
		}
		if err == nil && (id.String() != raw || "spiffe://"+callerauth.TrustDomain+"/"+id.Path() != raw) {
			t.Fatalf("ParseSPIFFEID(%q) = %q path %q, want the input", raw, id.String(), id.Path())
		}
	})
}

func TestCallerFromConnectionStateRefusesEveryListedCredential(t *testing.T) {
	want := map[string]error{
		"no_TLS":                         callerauth.ErrNoVerifiedCertificate,
		"no_verified_chain":              callerauth.ErrNoVerifiedCertificate,
		"empty_verified_chain":           callerauth.ErrNoVerifiedCertificate,
		"nil_leaf":                       callerauth.ErrNoVerifiedCertificate,
		"expired_leaf":                   callerauth.ErrOutsideValidity,
		"not_yet_valid_leaf":             callerauth.ErrOutsideValidity,
		"expired_issuer_in_chain":        callerauth.ErrOutsideValidity,
		"CA_leaf":                        callerauth.ErrNotEndEntity,
		"keyCertSign_leaf":               callerauth.ErrNotEndEntity,
		"cRLSign_leaf":                   callerauth.ErrNotEndEntity,
		"nil_URI_entry":                  callerauth.ErrMalformedSPIFFEID,
		"no_URI_SAN":                     callerauth.ErrNoURISAN,
		"two_URI_SANs_allowed_first":     callerauth.ErrMultipleURISANs,
		"two_URI_SANs_allowed_second":    callerauth.ErrMultipleURISANs,
		"two_URI_SANs_foreign_first":     callerauth.ErrMultipleURISANs,
		"two_URI_SANs_same_ID_twice":     callerauth.ErrMultipleURISANs,
		"two_URI_SANs_second_not_SPIFFE": callerauth.ErrMultipleURISANs,
		"foreign_trust_domain":           callerauth.ErrForeignTrustDomain,
		"trust_domain_as_prefix":         callerauth.ErrForeignTrustDomain,
		"trust_domain_as_suffix":         callerauth.ErrForeignTrustDomain,
	}
	cases := callerauthtest.RefusedCallers("operator/local")
	if len(cases) < 30 {
		t.Fatalf("RefusedCallers returned %d cases, want at least 30", len(cases))
	}
	for _, tc := range cases {
		t.Run(tc.Name, func(t *testing.T) {
			var state *tls.ConnectionState
			if tc.State != nil {
				state = tc.State(t)
			}
			caller, err := callerauth.CallerFromConnectionState(state, time.Now())
			if err == nil {
				t.Fatalf("accepted caller %q", caller.ID())
			}
			expected, ok := want[tc.Name]
			if !ok {
				expected = callerauth.ErrMalformedSPIFFEID
			}
			if !errors.Is(err, expected) {
				t.Fatalf("error = %v, want %v", err, expected)
			}
			if caller != (callerauth.Caller{}) {
				t.Fatalf("returned caller %q with an error", caller.ID())
			}
		})
	}
}

func TestCallerFromConnectionStateAcceptsOneConformingURISAN(t *testing.T) {
	for _, tc := range acceptedIDs {
		cert := callerauthtest.Certificate(t, callerauthtest.RuntimeIssuer, tc.raw)
		caller, err := callerauth.CallerFromConnectionState(callerauthtest.State(cert), time.Now())
		if err != nil {
			t.Errorf("%q: %v", tc.raw, err)
			continue
		}
		if caller.ID().String() != tc.raw || caller.ID().Path() != tc.path {
			t.Errorf("%q: caller = %q path %q", tc.raw, caller.ID(), caller.ID().Path())
		}
	}
}

// The certificate parser lowercases the URI scheme and drops an empty
// fragment, so such a SAN names the same ID as without them. go-spiffe's
// x509svid.IDFromCert reads a certificate the same way. If a Go release
// changes either behaviour, this test fails and the contract text in
// .docs/system_overview/contracts.md section 3A has to be revisited.
// SPIRE SVIDs and the repository's client leaves carry an explicit CA:FALSE
// basic constraint and may use keyEncipherment; the end-entity rule accepts
// them. digitalSignature is an issuer rule (X.509-SVID section 4.3) that
// validators, go-spiffe included, do not check, so a leaf without it is
// accepted too.
func TestCallerFromConnectionStateAcceptsAnEndEntityLeafWithCAFalse(t *testing.T) {
	for _, usage := range []x509.KeyUsage{x509.KeyUsageDigitalSignature, x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment, x509.KeyUsageKeyEncipherment} {
		cert := callerauthtest.CertificateWithProfile(t, callerauthtest.RuntimeIssuer, callerauthtest.LeafProfile{BasicConstraints: true, KeyUsage: usage}, "spiffe://execution.internal/operator/local")
		if !cert.BasicConstraintsValid || cert.IsCA {
			t.Fatalf("fixture: basic constraints valid %v, CA %v", cert.BasicConstraintsValid, cert.IsCA)
		}
		caller, err := callerauth.CallerFromConnectionState(callerauthtest.State(cert), time.Now())
		if err != nil || caller.ID().Path() != "operator/local" {
			t.Fatalf("key usage %b: caller %q, error %v", cert.KeyUsage, caller.ID(), err)
		}
	}
}

func TestCallerFromConnectionStateReadsTheURIAsTheCertificateParserHandsItOver(t *testing.T) {
	for _, raw := range []string{
		"SPIFFE://execution.internal/operator/local",
		"Spiffe://execution.internal/operator/local",
		"spiffe://execution.internal/operator/local#",
	} {
		cert := callerauthtest.Certificate(t, callerauthtest.RuntimeIssuer, raw)
		caller, err := callerauth.CallerFromConnectionState(callerauthtest.State(cert), time.Now())
		if err != nil || caller.ID().String() != "spiffe://execution.internal/operator/local" {
			t.Errorf("%q: caller %q, error %v; want spiffe://execution.internal/operator/local", raw, caller.ID(), err)
		}
	}
}

// Over every certificate of the shared refusal list and every accepted ID,
// CallerFromConnectionState accepts exactly what go-spiffe's
// x509svid.IDFromCert accepts in the trust domain with a path.
// noBundles is an X.509 bundle source without bundles. x509svid.Verify reads
// the leaf's ID and applies the X.509-SVID leaf rules before it asks the
// source for a bundle, so errNoBundle from Verify means the leaf passed both.
type noBundles struct{}

var errNoBundle = errors.New("reference: no bundle")

func (noBundles) GetX509BundleForTrustDomain(spiffeid.TrustDomain) (*x509bundle.Bundle, error) {
	return nil, errNoBundle
}

// The reference is go-spiffe's x509svid.Verify up to the bundle lookup: the
// ID reader (IDFromCert) and the leaf rules (not a CA, no keyCertSign, no
// cRLSign). Chain verification is the TLS stack's job and is not compared.
// go-spiffe checks the validity period inside that chain verification, after
// the bundle lookup, so the comparison adds the leaf's validity period to the
// reference.
func TestCallerFromConnectionStateAgreesWithTheSPIFFEReferenceValidator(t *testing.T) {
	var certs []*x509.Certificate
	for _, tc := range callerauthtest.RefusedCallers("operator/local") {
		if tc.State == nil {
			continue
		}
		state := tc.State(t)
		if len(state.VerifiedChains) == 0 || len(state.VerifiedChains[0]) == 0 || state.VerifiedChains[0][0] == nil || len(state.VerifiedChains[0][0].Raw) == 0 {
			continue
		}
		certs = append(certs, state.VerifiedChains[0][0])
	}
	for _, tc := range acceptedIDs {
		certs = append(certs, callerauthtest.Certificate(t, callerauthtest.RuntimeIssuer, tc.raw))
	}
	if len(certs) < 35 {
		t.Fatalf("compared %d certificates, want at least 35", len(certs))
	}
	for _, cert := range certs {
		now := time.Now()
		_, err := callerauth.CallerFromConnectionState(callerauthtest.State(cert), now)
		ref, _, refErr := x509svid.Verify([]*x509.Certificate{cert}, noBundles{})
		want := errors.Is(refErr, errNoBundle) && ref.TrustDomain().Name() == callerauth.TrustDomain && ref.Path() != "" &&
			!now.Before(cert.NotBefore) && !now.After(cert.NotAfter)
		if got := err == nil; got != want {
			t.Errorf("URIs %q, CA %v, key usage %b: accepted=%v, reference accepted=%v (%v)", cert.URIs, cert.IsCA, cert.KeyUsage, got, want, refErr)
		}
	}
}

func TestCallerFromConnectionStateReadsTheLeafOfTheFirstVerifiedChain(t *testing.T) {
	good := callerauthtest.Certificate(t, callerauthtest.RuntimeIssuer, "spiffe://execution.internal/operator/local")
	bad := callerauthtest.Certificate(t, callerauthtest.RuntimeIssuer, "spiffe://other.internal/operator/local")
	ca := &x509.Certificate{Subject: pkix.Name{CommonName: callerauthtest.RuntimeIssuer}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}

	caller, err := callerauth.CallerFromConnectionState(&tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{good, ca}, {bad, ca}}}, time.Now())
	if err != nil || caller.ID().Path() != "operator/local" {
		t.Fatalf("first chain good: caller %q, error %v", caller.ID(), err)
	}
	if _, err := callerauth.CallerFromConnectionState(&tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{bad, ca}, {good, ca}}}, time.Now()); !errors.Is(err, callerauth.ErrForeignTrustDomain) {
		t.Fatalf("first chain foreign: error %v, want %v", err, callerauth.ErrForeignTrustDomain)
	}
	if _, err := callerauth.CallerFromConnectionState(&tls.ConnectionState{PeerCertificates: []*x509.Certificate{good}}, time.Now()); !errors.Is(err, callerauth.ErrNoVerifiedCertificate) {
		t.Fatalf("peer certificate without a verified chain: error %v, want %v", err, callerauth.ErrNoVerifiedCertificate)
	}
}

func request(state *tls.ConnectionState) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.TLS = state
	return r
}

func goodState(t *testing.T, issuer string) *tls.ConnectionState {
	t.Helper()
	return callerauthtest.State(callerauthtest.Certificate(t, issuer, "spiffe://execution.internal/operator/local"))
}

func assertRefused(t *testing.T, recorder *httptest.ResponseRecorder, ok bool, caller callerauth.Caller, status int, body string) {
	t.Helper()
	if ok || caller != (callerauth.Caller{}) {
		t.Fatalf("Authenticate accepted caller %q", caller.ID())
	}
	if recorder.Code != status || recorder.Body.String() != body {
		t.Fatalf("response %d %q, want %d %q", recorder.Code, recorder.Body.String(), status, body)
	}
	if got := recorder.Header().Get("Content-Type"); got != "text/plain; charset=utf-8" {
		t.Fatalf("Content-Type %q, want text/plain; charset=utf-8", got)
	}
}

func TestAuthenticateAcceptsAConformingCallerAndWritesNothing(t *testing.T) {
	auth := callerauth.NewAuthenticator(bootstrapIssuer)
	recorder := httptest.NewRecorder()
	caller, ok := auth.Authenticate(recorder, request(goodState(t, callerauthtest.RuntimeIssuer)))
	if !ok || caller.ID().String() != "spiffe://execution.internal/operator/local" || caller.ID().Path() != "operator/local" {
		t.Fatalf("Authenticate = %q, %v", caller.ID(), ok)
	}
	if recorder.Body.Len() != 0 || len(recorder.Header()) != 0 || recorder.Code != http.StatusOK {
		t.Fatalf("Authenticate wrote a response: %d %q %v", recorder.Code, recorder.Body.String(), recorder.Header())
	}
}

func TestAuthenticateRefusesEveryListedCredentialWith401(t *testing.T) {
	auth := callerauth.NewAuthenticator(bootstrapIssuer)
	for _, tc := range callerauthtest.RefusedCallers("operator/local") {
		t.Run(tc.Name, func(t *testing.T) {
			var state *tls.ConnectionState
			if tc.State != nil {
				state = tc.State(t)
			}
			recorder := httptest.NewRecorder()
			caller, ok := auth.Authenticate(recorder, request(state))
			assertRefused(t, recorder, ok, caller, http.StatusUnauthorized, unauthenticatedBody)
		})
	}
}

func TestAuthenticateRefusesTheBootstrapIssuerWith403(t *testing.T) {
	for _, configured := range []string{bootstrapIssuer, "  " + bootstrapIssuer + "\n"} {
		recorder := httptest.NewRecorder()
		caller, ok := callerauth.NewAuthenticator(configured).Authenticate(recorder, request(goodState(t, bootstrapIssuer)))
		assertRefused(t, recorder, ok, caller, http.StatusForbidden, bootstrapIssuerBody)
	}
}

func TestAuthenticateComparesTheIssuerExactly(t *testing.T) {
	auth := callerauth.NewAuthenticator(bootstrapIssuer)
	for _, issuer := range []string{"Bootstrap-CA", "bootstrap-ca ", "bootstrap", "bootstrap-ca-2"} {
		recorder := httptest.NewRecorder()
		if _, ok := auth.Authenticate(recorder, request(goodState(t, issuer))); !ok {
			t.Errorf("issuer %q: refused %d %q", issuer, recorder.Code, recorder.Body.String())
		}
	}
}

func TestAuthenticateChecksTheIdentityBeforeTheIssuer(t *testing.T) {
	recorder := httptest.NewRecorder()
	state := callerauthtest.State(callerauthtest.Certificate(t, bootstrapIssuer, "spiffe://other.internal/operator/local"))
	caller, ok := callerauth.NewAuthenticator(bootstrapIssuer).Authenticate(recorder, request(state))
	assertRefused(t, recorder, ok, caller, http.StatusUnauthorized, unauthenticatedBody)
}

func TestAuthenticatorWithoutABootstrapIssuerRefusesEveryRequest(t *testing.T) {
	for name, auth := range map[string]callerauth.Authenticator{
		"zero value":  {},
		"empty":       callerauth.NewAuthenticator(""),
		"white space": callerauth.NewAuthenticator(" \t\n"),
	} {
		for _, issuer := range []string{callerauthtest.RuntimeIssuer, ""} {
			recorder := httptest.NewRecorder()
			caller, ok := auth.Authenticate(recorder, request(goodState(t, issuer)))
			if ok {
				t.Fatalf("%s, issuer %q: accepted %q", name, issuer, caller.ID())
			}
			assertRefused(t, recorder, ok, caller, http.StatusUnauthorized, unauthenticatedBody)
		}
	}
}

// validityCA returns a CA certificate valid from notBefore to notAfter. The
// validity rule reads only the times, so the certificate is not signed.
func validityCA(notBefore, notAfter time.Time) *x509.Certificate {
	return &x509.Certificate{
		Subject:               pkix.Name{CommonName: callerauthtest.RuntimeIssuer},
		BasicConstraintsValid: true,
		IsCA:                  true,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
	}
}

// Go's TLS server verifies the client's chains once, at the handshake. The
// rule checks again at the time of every request: the leaf and every other
// certificate of a chain that starts with the leaf must be within their
// validity periods, NotBefore and NotAfter included, as Go's verifier counts
// them.
func TestCallerFromConnectionStateChecksTheValidityPeriodAtTheGivenTime(t *testing.T) {
	leaf := callerauthtest.Certificate(t, callerauthtest.RuntimeIssuer, "spiffe://execution.internal/operator/local")
	ca := validityCA(leaf.NotBefore.Add(-time.Hour), leaf.NotAfter.Add(time.Hour))
	state := &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{leaf, ca}}}
	for _, tc := range []struct {
		name string
		at   time.Time
		want error
	}{
		{name: "at NotBefore", at: leaf.NotBefore},
		{name: "inside", at: leaf.NotBefore.Add(time.Minute)},
		{name: "at NotAfter", at: leaf.NotAfter},
		{name: "just before NotBefore", at: leaf.NotBefore.Add(-time.Nanosecond), want: callerauth.ErrOutsideValidity},
		{name: "just after NotAfter", at: leaf.NotAfter.Add(time.Nanosecond), want: callerauth.ErrOutsideValidity},
	} {
		caller, err := callerauth.CallerFromConnectionState(state, tc.at)
		if tc.want == nil && (err != nil || caller.ID().Path() != "operator/local") {
			t.Errorf("%s: caller %q, error %v; want operator/local", tc.name, caller.ID(), err)
		}
		if tc.want != nil && (!errors.Is(err, tc.want) || caller != (callerauth.Caller{})) {
			t.Errorf("%s: caller %q, error %v; want %v", tc.name, caller.ID(), err, tc.want)
		}
	}

	inside := leaf.NotBefore.Add(time.Minute)
	for name, issuer := range map[string]*x509.Certificate{
		"expired issuer":       validityCA(inside.Add(-2*time.Hour), inside.Add(-time.Nanosecond)),
		"not yet valid issuer": validityCA(inside.Add(time.Nanosecond), inside.Add(2*time.Hour)),
	} {
		if _, err := callerauth.CallerFromConnectionState(&tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{leaf, issuer}}}, inside); !errors.Is(err, callerauth.ErrOutsideValidity) {
			t.Errorf("%s: error %v, want %v", name, err, callerauth.ErrOutsideValidity)
		}
	}
}

// A client chain can verify along more than one path, for example through a
// cross-signed intermediate. One chain that starts with the leaf and is
// still valid is enough; a valid chain that starts with another certificate
// is not.
func TestCallerFromConnectionStateAcceptsAnyStillValidChainOfTheLeaf(t *testing.T) {
	leaf := callerauthtest.Certificate(t, callerauthtest.RuntimeIssuer, "spiffe://execution.internal/operator/local")
	other := callerauthtest.Certificate(t, callerauthtest.RuntimeIssuer, "spiffe://execution.internal/operator/local")
	now := leaf.NotBefore.Add(time.Minute)
	expired := validityCA(now.Add(-2*time.Hour), now.Add(-time.Minute))
	valid := validityCA(now.Add(-time.Hour), now.Add(time.Hour))

	caller, err := callerauth.CallerFromConnectionState(&tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{leaf, expired}, {leaf, valid}}}, now)
	if err != nil || caller.ID().Path() != "operator/local" {
		t.Fatalf("expired first chain, valid second chain: caller %q, error %v", caller.ID(), err)
	}
	if _, err := callerauth.CallerFromConnectionState(&tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{leaf, expired}, {other, valid}}}, now); !errors.Is(err, callerauth.ErrOutsideValidity) {
		t.Fatalf("only another leaf's chain is valid: error %v, want %v", err, callerauth.ErrOutsideValidity)
	}
	if _, err := callerauth.CallerFromConnectionState(&tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{leaf, expired}, {leaf, nil}}}, now); !errors.Is(err, callerauth.ErrOutsideValidity) {
		t.Fatalf("second chain with a nil certificate: error %v, want %v", err, callerauth.ErrOutsideValidity)
	}
}

// Authenticate checks the validity period at the time it runs, on its own
// clock, so a caller whose certificate expires during a connection is
// refused from then on.
func TestAuthenticateRefusesACallerWhoseCertificateHasExpiredSinceTheHandshake(t *testing.T) {
	state := goodState(t, callerauthtest.RuntimeIssuer)
	leaf := state.VerifiedChains[0][0]
	now := leaf.NotBefore.Add(time.Minute)
	auth := callerauth.NewAuthenticator(bootstrapIssuer).WithClock(func() time.Time { return now })

	recorder := httptest.NewRecorder()
	if caller, ok := auth.Authenticate(recorder, request(state)); !ok || caller.ID().Path() != "operator/local" {
		t.Fatalf("inside the validity period: caller %q, ok %v, response %d %q", caller.ID(), ok, recorder.Code, recorder.Body.String())
	}
	now = leaf.NotAfter.Add(time.Second)
	recorder = httptest.NewRecorder()
	caller, ok := auth.Authenticate(recorder, request(state))
	assertRefused(t, recorder, ok, caller, http.StatusUnauthorized, unauthenticatedBody)

	now = leaf.NotBefore.Add(-time.Second)
	recorder = httptest.NewRecorder()
	caller, ok = auth.Authenticate(recorder, request(state))
	assertRefused(t, recorder, ok, caller, http.StatusUnauthorized, unauthenticatedBody)
}
