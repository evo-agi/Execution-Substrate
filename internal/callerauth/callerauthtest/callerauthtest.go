// Package callerauthtest builds client certificates, TLS connection states
// and real TLS connections for tests of the caller authentication rule in
// package callerauth. It is test support: only test files of this module
// import it, and no command or service links it.
//
// RefusedCallers is the shared list of caller credentials that every ES
// service must refuse with 401. Each service's own tests run the list
// against that service's handler, so one list pins the rule at all five
// call sites. CheckRoute runs it on the request's TLS state, for the
// services that call callerauth's Authenticate; CheckConnectionRoute runs it
// over real TLS connections, for ES, which calls AuthenticateConnection.
package callerauthtest

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"execution-substrate/internal/callerauth"
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
	credential, err := issueCredential(issuerCommonName, LeafProfile{}, uris)
	if err != nil {
		return nil, err
	}
	return credential.der, nil
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
	// IssuerNotBefore and IssuerNotAfter replace the validity period of the
	// CA that issues the leaf when they are not zero. By default the CA is
	// valid from an hour ago to an hour from now, and for the whole validity
	// period of the leaf.
	IssuerNotBefore, IssuerNotAfter time.Time
}

// CertificateWithProfile is Certificate with the leaf's basic constraints
// and key usage set by profile.
func CertificateWithProfile(t testing.TB, issuerCommonName string, profile LeafProfile, uris ...string) *x509.Certificate {
	t.Helper()
	return IssueCredential(t, issuerCommonName, profile, uris...).Leaf
}

// Credential is a client certificate with its private key and the CA
// certificate that issued it, for a real TLS handshake: a server that trusts
// CA verifies the chain at a time inside the validity period of both.
type Credential struct {
	// Leaf is the client certificate, as x509.ParseCertificate returns it.
	Leaf *x509.Certificate
	// CA is the certificate of the fresh CA that issued Leaf.
	CA *x509.Certificate

	der      []byte
	key      ed25519.PrivateKey
	verifyAt time.Time
}

// State returns a TLS connection state whose only verified chain holds the
// credential's leaf, as State does for a certificate.
func (c *Credential) State() *tls.ConnectionState {
	return State(c.Leaf)
}

// IssueCredential returns a client credential whose leaf is the certificate
// CertificateWithProfile describes. The test fails when the certificate
// parser refuses the leaf.
func IssueCredential(t testing.TB, issuerCommonName string, profile LeafProfile, uris ...string) *Credential {
	t.Helper()
	credential, err := IssueCredentialOrError(issuerCommonName, profile, uris...)
	if err != nil {
		t.Fatalf("callerauthtest: credential with profile %+v and URI SANs %q: %v", profile, uris, err)
	}
	return credential
}

// IssueCredentialOrError is IssueCredential for callers that handle the
// parser's refusal themselves.
func IssueCredentialOrError(issuerCommonName string, profile LeafProfile, uris ...string) (*Credential, error) {
	return issueCredential(issuerCommonName, profile, uris)
}

func issueCredential(issuerCommonName string, profile LeafProfile, uris []string) (*Credential, error) {
	now := time.Now()
	leafNotBefore, leafNotAfter := now.Add(-time.Hour), now.Add(time.Hour)
	if !profile.NotBefore.IsZero() {
		leafNotBefore = profile.NotBefore
	}
	if !profile.NotAfter.IsZero() {
		leafNotAfter = profile.NotAfter
	}
	caNotBefore, caNotAfter := now.Add(-time.Hour), now.Add(time.Hour)
	if leafNotBefore.Before(caNotBefore) {
		caNotBefore = leafNotBefore
	}
	if leafNotAfter.After(caNotAfter) {
		caNotAfter = leafNotAfter
	}
	if !profile.IssuerNotBefore.IsZero() {
		caNotBefore = profile.IssuerNotBefore
	}
	if !profile.IssuerNotAfter.IsZero() {
		caNotAfter = profile.IssuerNotAfter
	}

	caPublic, caPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: issuerCommonName},
		NotBefore:             caNotBefore,
		NotAfter:              caNotAfter,
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
	leafPublic, leafPrivate, err := ed25519.GenerateKey(rand.Reader)
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
		NotBefore:       leafNotBefore,
		NotAfter:        leafNotAfter,
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
	der, err := x509.CreateCertificate(rand.Reader, leafTemplate, ca, leafPublic, caPrivate)
	if err != nil {
		return nil, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}

	// The server verifies the chain in the middle of the time both
	// certificates are valid, so a leaf or CA that is expired or not yet
	// valid now still completes a handshake, as on a connection that has
	// outlived its certificates.
	from, until := leafNotBefore, leafNotAfter
	if caNotBefore.After(from) {
		from = caNotBefore
	}
	if caNotAfter.Before(until) {
		until = caNotAfter
	}
	if !from.Before(until) {
		return nil, errors.New("callerauthtest: the leaf and its CA are never valid at the same time")
	}
	return &Credential{Leaf: leaf, CA: ca, der: der, key: leafPrivate, verifyAt: from.Add(until.Sub(from) / 2)}, nil
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
	// Credential issues a client credential that a real TLS handshake
	// verifies and that the rule refuses for the same reason as State. It
	// is nil for the states that Go's TLS server never reports after a
	// handshake: no TLS, no verified chain, an empty chain, a nil leaf and
	// a nil URI SAN. CheckConnectionRoute has connection cases of its own
	// for those.
	Credential func(t testing.TB) *Credential
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

	issued := func(name string, profile LeafProfile, uris ...string) RefusedCaller {
		credential := func(t testing.TB) *Credential {
			t.Helper()
			return IssueCredential(t, RuntimeIssuer, profile, uris...)
		}
		state := func(t testing.TB) *tls.ConnectionState {
			t.Helper()
			return credential(t).State()
		}
		return RefusedCaller{Name: name, State: state, Credential: credential}
	}
	withURIs := func(name string, uris ...string) RefusedCaller {
		return issued(name, LeafProfile{}, uris...)
	}
	fixed := func(state *tls.ConnectionState) func(testing.TB) *tls.ConnectionState {
		return func(testing.TB) *tls.ConnectionState { return state }
	}
	withProfile := func(name string, profile LeafProfile) RefusedCaller {
		return issued(name, profile, id)
	}
	// The issuer expired a minute ago; the leaf is still valid. The
	// connection form completes its handshake half an hour ago, when both
	// were valid.
	expiredIssuer := issued("expired_issuer_in_chain", LeafProfile{IssuerNotBefore: time.Now().Add(-2 * time.Hour), IssuerNotAfter: time.Now().Add(-time.Minute)}, id)
	expiredIssuer.State = func(t testing.TB) *tls.ConnectionState {
		t.Helper()
		credential := expiredIssuer.Credential(t)
		return &tls.ConnectionState{HandshakeComplete: true, PeerCertificates: []*x509.Certificate{credential.Leaf}, VerifiedChains: [][]*x509.Certificate{{credential.Leaf, credential.CA}}}
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
		withProfile("expired_leaf", LeafProfile{NotBefore: time.Now().Add(-2 * time.Hour), NotAfter: time.Now().Add(-time.Minute)}),
		withProfile("not_yet_valid_leaf", LeafProfile{NotBefore: time.Now().Add(time.Hour), NotAfter: time.Now().Add(2 * time.Hour)}),
		expiredIssuer,

		// Not an end-entity certificate (X.509-SVID section 5.2), even with
		// exactly the allowed identity.
		withProfile("CA_leaf", LeafProfile{IsCA: true}),
		withProfile("keyCertSign_leaf", LeafProfile{KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign}),
		withProfile("cRLSign_leaf", LeafProfile{KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCRLSign}),

		// No identity, or more than one.
		withURIs("no_URI_SAN"),
		withURIs("two_URI_SANs_allowed_first", id, "spiffe://execution.internal/service/other"),
		withURIs("two_URI_SANs_allowed_second", "spiffe://execution.internal/service/other", id),
		withURIs("two_URI_SANs_foreign_first", "spiffe://other.internal/"+path, id),
		withURIs("two_URI_SANs_same_ID_twice", id, id),
		withURIs("two_URI_SANs_second_not_SPIFFE", id, "https://client.example/"+path),

		// Outside the trust domain.
		withURIs("foreign_trust_domain", "spiffe://other.internal/"+path),
		withURIs("trust_domain_as_prefix", "spiffe://execution.internal.evil/"+path),
		withURIs("trust_domain_as_suffix", "spiffe://evil.execution.internal/"+path),
		withURIs("trust_domain_with_port", "spiffe://execution.internal:8443/"+path),
		withURIs("trust_domain_with_user", "spiffe://user@execution.internal/"+path),
		withURIs("trust_domain_upper_case", "spiffe://EXECUTION.INTERNAL/"+path),
		withURIs("other_scheme", "https://execution.internal/"+path),

		// Workload identities are never callers, even one that carries the
		// allowed path below the workload segment.
		withURIs("workload_identity_shared", "spiffe://execution.internal/workload"),
		withURIs("workload_identity_named", "spiffe://execution.internal/workload/"+path),
		withURIs("workload_identity_per_run", "spiffe://execution.internal/workload/"+last+"/run/r1"),
		withURIs("workload_identity_upper_case", "spiffe://execution.internal/Workload/"+path),

		// Not a conforming SPIFFE ID, or no workload path.
		withURIs("trust_domain_ID_only", "spiffe://execution.internal"),
		withURIs("root_path_only", "spiffe://execution.internal/"),
		withURIs("trailing_slash", id+"/"),
		withURIs("leading_empty_segment", "spiffe://execution.internal//"+path),
		withURIs("inner_empty_segment", "spiffe://execution.internal/"+parent+"//"+last),
		withURIs("dot_segment", id+"/."),
		withURIs("dot_dot_segment", id+"/.."),
		withURIs("dot_dot_back_into_path", id+"/x/../"+last),
		withURIs("query", id+"?x=1"),
		withURIs("query_after_slash", id+"/?x=1"),
		withURIs("empty_query", id+"?"),
		withURIs("fragment", id+"#x"),
		withURIs("fragment_after_slash", id+"/#x"),
		withURIs("percent_encoded_slash", "spiffe://execution.internal/"+strings.ReplaceAll(path, "/", "%2F")),
		withURIs("percent_encoded_letter", "spiffe://execution.internal/"+parent+"/%"+hexByte(last[0])+last[1:]),
		withURIs("colon_in_segment", id+"/a:b"),
		withURIs("at_in_segment", id+"/a@b"),
		withURIs("tilde_in_segment", id+"/a~b"),
		withURIs("plus_in_segment", id+"/a+b"),
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
	request := newRequest(method, target, body)
	request.TLS = state
	return serve(t, handler, request)
}

// ServeConnection sends one request to handler over a TLS connection on which
// the client presented credential, or no certificate when credential is nil,
// and returns the response. The request reaches handler as ES's server hands
// it over: the server accepts connections through callerauth.NewListener and
// sets callerauth.ConnContext as its ConnContext hook, so the request's
// context carries the connection and r.TLS is nil. A handler panic fails the
// test, and so does a handshake the server refuses.
func ServeConnection(t testing.TB, handler http.Handler, method, target, body string, credential *Credential) *httptest.ResponseRecorder {
	t.Helper()
	conn, err := connect(credential, tls.VerifyClientCertIfGiven)
	if err != nil {
		t.Fatalf("%s %s: %v", method, target, err)
	}
	return serve(t, handler, requestOn(conn, method, target, body))
}

// ConnectionContext returns ctx as a service's server hands it to every
// request of a TLS connection on which the client presented credential: it
// completes a real TLS handshake in memory, in which the server trusts the
// credential's CA and verifies the client's chain, on a connection accepted
// through callerauth.NewListener, and passes that connection to
// callerauth.ConnContext, as http.Server does with its ConnContext hook. With
// a nil credential the client presents no certificate, so the connection has
// no verified chain.
func ConnectionContext(ctx context.Context, credential *Credential) (context.Context, error) {
	conn, err := connect(credential, tls.VerifyClientCertIfGiven)
	if err != nil {
		return nil, err
	}
	return callerauth.ConnContext(ctx, conn), nil
}

// connectionCallerBootstrapIssuer is the bootstrap issuer of the
// Authenticator that ConnectionCaller uses. No credential of this package
// names it unless a test asks for it.
const connectionCallerBootstrapIssuer = "callerauthtest-bootstrap-ca"

// ConnectionCaller returns what callerauth's AuthenticateConnection returns
// for a TLS connection on which the client presented a certificate from
// RuntimeIssuer whose only URI SAN is uri: the caller a service's API reads
// from such a connection. It returns an error when the rule refuses uri.
func ConnectionCaller(uri string) (callerauth.ConnectionCaller, error) {
	credential, err := IssueCredentialOrError(RuntimeIssuer, LeafProfile{}, uri)
	if err != nil {
		return callerauth.ConnectionCaller{}, err
	}
	ctx, err := ConnectionContext(context.Background(), credential)
	if err != nil {
		return callerauth.ConnectionCaller{}, err
	}
	request := httptest.NewRequest(http.MethodGet, "/", nil).WithContext(ctx)
	recorder := httptest.NewRecorder()
	caller, ok := callerauth.NewAuthenticator(connectionCallerBootstrapIssuer).AuthenticateConnection(recorder, request)
	if !ok {
		return callerauth.ConnectionCaller{}, fmt.Errorf("callerauthtest: caller %q refused: %d %q", uri, recorder.Code, recorder.Body.String())
	}
	return caller, nil
}

func newRequest(method, target, body string) *http.Request {
	request := httptest.NewRequest(method, target, strings.NewReader(body))
	if body != "" {
		request.Header.Set("Content-Type", "application/json")
	}
	return request
}

// requestOn returns a request that arrived on conn, as Go's HTTP server
// hands it to a handler whose server accepts connections through
// callerauth.NewListener and sets callerauth.ConnContext: r.TLS is nil.
func requestOn(conn net.Conn, method, target, body string) *http.Request {
	request := newRequest(method, target, body)
	request.TLS = nil
	return request.WithContext(callerauth.ConnContext(request.Context(), conn))
}

func serve(t testing.TB, handler http.Handler, request *http.Request) *httptest.ResponseRecorder {
	t.Helper()
	recorder := httptest.NewRecorder()
	func() {
		defer func() {
			if p := recover(); p != nil {
				t.Fatalf("%s %s: handler panicked: %v", request.Method, request.URL, p)
			}
		}()
		handler.ServeHTTP(recorder, request)
	}()
	return recorder
}

// serverName is the DNS name in the certificate that connect's server
// presents.
const serverName = "server.callerauthtest"

// connect completes a TLS handshake over an in-memory pipe, on a connection
// that callerauth.NewListener accepted as ES's listener does, for a client
// that presents credential, and returns that server-side connection. The
// server asks for a client certificate with clientAuth, trusts only the
// credential's CA, and verifies the chain at a time when the leaf and its CA
// are both valid. With a nil credential the client presents no certificate.
func connect(credential *Credential, clientAuth tls.ClientAuthType) (net.Conn, error) {
	serverPublic, serverPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	serverTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: serverName},
		DNSNames:              []string{serverName},
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	serverDER, err := x509.CreateCertificate(rand.Reader, serverTemplate, serverTemplate, serverPublic, serverPrivate)
	if err != nil {
		return nil, err
	}
	serverCert, err := x509.ParseCertificate(serverDER)
	if err != nil {
		return nil, err
	}
	roots := x509.NewCertPool()
	roots.AddCert(serverCert)
	serverConfig := &tls.Config{
		Certificates:           []tls.Certificate{{Certificate: [][]byte{serverDER}, PrivateKey: serverPrivate, Leaf: serverCert}},
		ClientAuth:             clientAuth,
		ClientCAs:              x509.NewCertPool(),
		MinVersion:             tls.VersionTLS12,
		SessionTicketsDisabled: true,
	}
	clientConfig := &tls.Config{RootCAs: roots, ServerName: serverName, MinVersion: tls.VersionTLS12}
	verifyAt := time.Now()
	if credential != nil {
		serverConfig.ClientCAs.AddCert(credential.CA)
		clientConfig.Certificates = []tls.Certificate{{Certificate: [][]byte{credential.der}, PrivateKey: credential.key, Leaf: credential.Leaf}}
		verifyAt = credential.verifyAt
	}
	serverConfig.Time = func() time.Time { return verifyAt }

	serverSide, clientSide := net.Pipe()
	deadline := time.Now().Add(30 * time.Second)
	if err := serverSide.SetDeadline(deadline); err != nil {
		return nil, err
	}
	if err := clientSide.SetDeadline(deadline); err != nil {
		return nil, err
	}
	listener, err := callerauth.NewListener(&pipeListener{conn: serverSide}, serverConfig)
	if err != nil {
		return nil, err
	}
	server, err := listener.Accept()
	if err != nil {
		return nil, err
	}
	client := tls.Client(clientSide, clientConfig)
	clientDone := make(chan error, 1)
	go func() {
		err := client.Handshake()
		if err == nil {
			_, err = client.Write([]byte{0})
		}
		clientDone <- err
	}()
	// The server's handshake runs inside the connection's first read, as it
	// does when Go's HTTP server reads the first request.
	_, serverErr := io.ReadFull(server, make([]byte, 1))
	if serverErr != nil {
		clientSide.Close()
	}
	clientErr := <-clientDone
	// The connection state stays readable after the pipe is closed.
	serverSide.Close()
	clientSide.Close()
	if serverErr != nil {
		return nil, fmt.Errorf("callerauthtest: the server refused the handshake: %w", serverErr)
	}
	if clientErr != nil {
		return nil, fmt.Errorf("callerauthtest: the client refused the handshake: %w", clientErr)
	}
	return server, nil
}

// pipeListener accepts its one connection once.
type pipeListener struct {
	conn net.Conn
}

func (l *pipeListener) Accept() (net.Conn, error) {
	if l.conn == nil {
		return nil, net.ErrClosed
	}
	conn := l.conn
	l.conn = nil
	return conn, nil
}

func (l *pipeListener) Close() error   { return nil }
func (l *pipeListener) Addr() net.Addr { return pipeAddr{} }

type pipeAddr struct{}

func (pipeAddr) Network() string { return "pipe" }
func (pipeAddr) String() string  { return "pipe" }

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

// connectionlessRefusedCallers are the RefusedCallers entries whose state
// no TLS handshake reports. CheckConnectionRoute covers them with its own
// connection cases: no connection, a connection without a client
// certificate, and a client certificate the server did not verify.
var connectionlessRefusedCallers = []string{"no_TLS", "no_verified_chain", "empty_verified_chain", "nil_leaf", "nil_URI_entry"}

// CheckConnectionRoute pins the caller authentication rule at one route of a
// service that reads its caller from the connection with callerauth's
// AuthenticateConnection (ES). Every request goes over a real TLS
// connection, as ServeConnection sends it. reached returns how many requests
// have gone past authentication into the service so far.
//
//   - A caller with one URI SAN, the SPIFFE ID of route.AllowedPath, from
//     RuntimeIssuer is neither refused with 401 nor with 403, and reaches
//     the service, with and without an explicit CA:FALSE basic constraint.
//   - The same identity from bootstrapIssuer gets 403 BootstrapIssuerBody.
//   - Every RefusedCallers credential gets 401 UnauthenticatedBody.
//   - So do: a request whose context holds no connection, with or without
//     r.TLS naming the allowed caller; a connection on which the client
//     presented no certificate; a connection whose client certificate, with
//     the allowed identity, the server asked for but did not verify; and a
//     connection that presented a refused credential while r.TLS names the
//     allowed caller. The route reads the connection, never r.TLS.
//
// Refused requests must not reach the service.
func CheckConnectionRoute(t *testing.T, handler http.Handler, route Route, bootstrapIssuer string, reached func() int) {
	t.Helper()
	t.Run(route.Name, func(t *testing.T) {
		refused := func(t *testing.T, request *http.Request, status int, body string) {
			t.Helper()
			before := reached()
			expectRefusal(t, serve(t, handler, request), status, body)
			if reached() != before {
				t.Fatalf("refused caller reached the service")
			}
		}
		over := func(t *testing.T, credential *Credential, clientAuth tls.ClientAuthType) *http.Request {
			t.Helper()
			conn, err := connect(credential, clientAuth)
			if err != nil {
				t.Fatal(err)
			}
			return requestOn(conn, route.Method, route.Target, route.Body)
		}
		allowed := func(t *testing.T, profile LeafProfile) *Credential {
			t.Helper()
			return IssueCredential(t, RuntimeIssuer, profile, SPIFFEID(route.AllowedPath))
		}
		for name, profile := range map[string]LeafProfile{
			"allowed_caller":          {},
			"allowed_caller_CA_false": {BasicConstraints: true, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment},
		} {
			t.Run(name, func(t *testing.T) {
				before := reached()
				response := serve(t, handler, over(t, allowed(t, profile), tls.VerifyClientCertIfGiven))
				if response.Code == http.StatusUnauthorized || response.Code == http.StatusForbidden {
					t.Fatalf("allowed caller refused: %d %q", response.Code, response.Body.String())
				}
				if reached() == before {
					t.Fatalf("allowed caller did not reach the service: %d %q", response.Code, response.Body.String())
				}
			})
		}
		t.Run("bootstrap_issuer", func(t *testing.T) {
			credential := IssueCredential(t, bootstrapIssuer, LeafProfile{}, SPIFFEID(route.AllowedPath))
			refused(t, over(t, credential, tls.VerifyClientCertIfGiven), http.StatusForbidden, BootstrapIssuerBody)
		})
		for _, tc := range RefusedCallers(route.AllowedPath) {
			if tc.Credential == nil {
				known := false
				for _, name := range connectionlessRefusedCallers {
					known = known || name == tc.Name
				}
				if !known {
					t.Errorf("RefusedCallers entry %s has no credential and is not one of the states no handshake reports", tc.Name)
				}
				continue
			}
			t.Run(tc.Name, func(t *testing.T) {
				refused(t, over(t, tc.Credential(t), tls.VerifyClientCertIfGiven), http.StatusUnauthorized, UnauthenticatedBody)
			})
		}
		t.Run("no_connection", func(t *testing.T) {
			refused(t, newRequest(route.Method, route.Target, route.Body), http.StatusUnauthorized, UnauthenticatedBody)
		})
		t.Run("request_TLS_without_connection", func(t *testing.T) {
			request := newRequest(route.Method, route.Target, route.Body)
			request.TLS = allowed(t, LeafProfile{}).State()
			refused(t, request, http.StatusUnauthorized, UnauthenticatedBody)
		})
		t.Run("no_client_certificate", func(t *testing.T) {
			refused(t, over(t, nil, tls.VerifyClientCertIfGiven), http.StatusUnauthorized, UnauthenticatedBody)
		})
		t.Run("unverified_client_certificate", func(t *testing.T) {
			refused(t, over(t, allowed(t, LeafProfile{}), tls.RequestClientCert), http.StatusUnauthorized, UnauthenticatedBody)
		})
		t.Run("request_TLS_differs_from_connection", func(t *testing.T) {
			request := over(t, IssueCredential(t, RuntimeIssuer, LeafProfile{}, "spiffe://other.internal/"+strings.Trim(route.AllowedPath, "/")), tls.VerifyClientCertIfGiven)
			request.TLS = allowed(t, LeafProfile{}).State()
			refused(t, request, http.StatusUnauthorized, UnauthenticatedBody)
		})
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
