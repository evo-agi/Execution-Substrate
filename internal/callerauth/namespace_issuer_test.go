package callerauth_test

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"execution-substrate/internal/callerauth"
)

func caSHA256(ca testCA) string {
	sum := sha256.Sum256(ca.der)
	return hex.EncodeToString(sum[:])
}

func newNamedRootCA(t *testing.T, name string) testCA {
	t.Helper()
	return issue(t, &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: name},
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}, newTestKey(t), nil)
}

func issueClientLeaf(t *testing.T, ca testCA, path string) testCA {
	t.Helper()
	return issue(t, &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: path},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		URIs:         []*url.URL{mustURL(t, callerauthSPIFFE(path))},
	}, newTestKey(t), &ca)
}

func callerauthSPIFFE(path string) string {
	return "spiffe://" + callerauth.TrustDomain + "/" + path
}

func mustNamespaceIssuer(t *testing.T, prefix string, ca testCA) callerauth.NamespaceIssuer {
	t.Helper()
	issuer, err := callerauth.ParseNamespaceIssuer(prefix, caSHA256(ca))
	if err != nil {
		t.Fatal(err)
	}
	return issuer
}

// serveWithPool is serveMutualTLS with a client CA pool of several roots
// and the given Authenticator.
func serveWithPool(t *testing.T, auth callerauth.Authenticator, roots []testCA, chain [][]byte, key *ecdsa.PrivateKey) (int, string) {
	t.Helper()
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		caller, ok := auth.Authenticate(w, r)
		if !ok {
			return
		}
		io.WriteString(w, caller.ID().String())
	}))
	pool := x509.NewCertPool()
	for _, root := range roots {
		pool.AddCert(root.cert)
	}
	server.TLS = &tls.Config{ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool, MinVersion: tls.VersionTLS12}
	server.StartTLS()
	defer server.Close()

	client := server.Client()
	client.Transport.(*http.Transport).TLSClientConfig.Certificates = []tls.Certificate{{Certificate: chain, PrivateKey: key}}
	response, err := client.Get(server.URL)
	if err != nil {
		t.Fatalf("handshake or request failed: %v", err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	return response.StatusCode, string(body)
}

func TestParseNamespaceIssuerAcceptsAPathAndADigest(t *testing.T) {
	digest := strings.Repeat("0a", 32)
	for _, prefix := range []string{"user", "user/team", "a.b-c_d"} {
		issuer, err := callerauth.ParseNamespaceIssuer(prefix, digest)
		if err != nil {
			t.Fatalf("%q: %v", prefix, err)
		}
		if issuer.PathPrefix() != prefix || issuer.CASHA256() != digest {
			t.Fatalf("%q: got %q %q", prefix, issuer.PathPrefix(), issuer.CASHA256())
		}
	}
}

func TestParseNamespaceIssuerRefusesEverythingElse(t *testing.T) {
	digest := strings.Repeat("0a", 32)
	for _, prefix := range []string{"", "/user", "user/", "user//team", ".", "..", "user/..", "us er", "user?x", "user%2f", "spiffe://execution.internal/user"} {
		if _, err := callerauth.ParseNamespaceIssuer(prefix, digest); err == nil {
			t.Errorf("path prefix %q accepted", prefix)
		}
	}
	for _, bad := range []string{"", strings.Repeat("0A", 32), strings.Repeat("0a", 31), strings.Repeat("0a", 33), strings.Repeat("zz", 32), " " + strings.Repeat("0a", 32)} {
		if _, err := callerauth.ParseNamespaceIssuer("user", bad); err == nil {
			t.Errorf("digest %q accepted", bad)
		}
	}
}

func TestCheckNamespaceIssuersRefusesSharedCAsAndOverlappingNamespaces(t *testing.T) {
	a := strings.Repeat("0a", 32)
	b := strings.Repeat("0b", 32)
	parse := func(prefix, digest string) callerauth.NamespaceIssuer {
		issuer, err := callerauth.ParseNamespaceIssuer(prefix, digest)
		if err != nil {
			t.Fatal(err)
		}
		return issuer
	}
	if err := callerauth.CheckNamespaceIssuers([]callerauth.NamespaceIssuer{parse("user", a), parse("robot", b)}); err != nil {
		t.Fatalf("two separate bindings refused: %v", err)
	}
	if err := callerauth.CheckNamespaceIssuers(nil); err != nil {
		t.Fatalf("no bindings refused: %v", err)
	}
	for name, list := range map[string][]callerauth.NamespaceIssuer{
		"one CA, two namespaces":   {parse("user", a), parse("robot", a)},
		"one namespace twice":      {parse("user", a), parse("user", b)},
		"a namespace inside one":   {parse("user", a), parse("user/team", b)},
		"a namespace around one":   {parse("user/team", a), parse("user", b)},
		"the zero NamespaceIssuer": {{}},
	} {
		if err := callerauth.CheckNamespaceIssuers(list); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// A prefix that only shares leading characters is a separate namespace.
	if err := callerauth.CheckNamespaceIssuers([]callerauth.NamespaceIssuer{parse("user", a), parse("users", b)}); err != nil {
		t.Fatalf("user and users refused: %v", err)
	}
}

func TestParseNamespaceIssuersNamesTheEntry(t *testing.T) {
	_, err := callerauth.ParseNamespaceIssuers("security.namespace_issuers", []callerauth.NamespaceIssuerConfig{
		{PathPrefix: "user", IssuerCertificateSHA256: strings.Repeat("0a", 32)},
		{PathPrefix: "/robot", IssuerCertificateSHA256: strings.Repeat("0b", 32)},
	})
	if err == nil || !strings.Contains(err.Error(), "security.namespace_issuers[1]") {
		t.Fatalf("error %v, want it to name security.namespace_issuers[1]", err)
	}
	_, err = callerauth.ParseNamespaceIssuers("security.namespace_issuers", []callerauth.NamespaceIssuerConfig{
		{PathPrefix: "user", IssuerCertificateSHA256: strings.Repeat("0a", 32)},
		{PathPrefix: "robot", IssuerCertificateSHA256: strings.Repeat("0a", 32)},
	})
	if err == nil || !strings.Contains(err.Error(), "same CA") {
		t.Fatalf("error %v, want the shared CA refused", err)
	}
	issuers, err := callerauth.ParseNamespaceIssuers("security.namespace_issuers", nil)
	if err != nil || len(issuers) != 0 {
		t.Fatalf("no entries: %v %v", issuers, err)
	}
}

// The binding behind a real TLS listener: the client CA pool holds an
// external CA and a user CA, as the Remote Alpha client CA files do once a
// user identity is allowed.
func TestAuthenticateKeepsEachCAToItsNamespace(t *testing.T) {
	external := newNamedRootCA(t, "external client CA")
	user := newNamedRootCA(t, "user CA")
	roots := []testCA{external, user}
	bound := callerauth.NewAuthenticator("callerauth-mtls-bootstrap").WithNamespaceIssuers(mustNamespaceIssuer(t, "user", user))
	unbound := callerauth.NewAuthenticator("callerauth-mtls-bootstrap")

	cases := []struct {
		name        string
		ca          testCA
		path        string
		auth        callerauth.Authenticator
		wantAllowed bool
	}{
		{"user CA, user path", user, "user/claude", bound, true},
		{"user CA, the namespace itself", user, "user", bound, true},
		{"user CA, operator path", user, "operator/local", bound, false},
		{"user CA, control plane path", user, "service/control-plane", bound, false},
		{"user CA, a path that only starts with the namespace", user, "users/claude", bound, false},
		{"external CA, operator path", external, "operator/local", bound, true},
		{"external CA, user path", external, "user/claude", bound, false},
		{"external CA, a path that only starts with the namespace", external, "users/claude", bound, true},
		// Without a binding the user CA vouches for any path: the gap the
		// binding closes.
		{"no binding, user CA, operator path", user, "operator/local", unbound, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			leaf := issueClientLeaf(t, tc.ca, tc.path)
			status, body := serveWithPool(t, tc.auth, roots, [][]byte{leaf.der}, leaf.key)
			if tc.wantAllowed {
				if status != http.StatusOK || body != callerauthSPIFFE(tc.path) {
					t.Fatalf("got %d %q, want 200 %q", status, body, callerauthSPIFFE(tc.path))
				}
				return
			}
			if status != http.StatusUnauthorized || body != "Authenticated caller identity required" {
				t.Fatalf("got %d %q, want the 401 refusal", status, body)
			}
		})
	}
}

func TestAuthenticatorWithInvalidNamespaceIssuersRefusesEveryRequest(t *testing.T) {
	external := newNamedRootCA(t, "external client CA")
	user := newNamedRootCA(t, "user CA")
	issuer := mustNamespaceIssuer(t, "user", user)
	other := mustNamespaceIssuer(t, "robot", user)
	auth := callerauth.NewAuthenticator("callerauth-mtls-bootstrap").WithNamespaceIssuers(issuer, other)
	leaf := issueClientLeaf(t, external, "operator/local")
	status, body := serveWithPool(t, auth, []testCA{external, user}, [][]byte{leaf.der}, leaf.key)
	if status != http.StatusUnauthorized || body != "Authenticated caller identity required" {
		t.Fatalf("got %d %q, want every request refused", status, body)
	}
	// A valid list given afterwards replaces the invalid one.
	auth = auth.WithNamespaceIssuers(issuer)
	if status, body := serveWithPool(t, auth, []testCA{external, user}, [][]byte{leaf.der}, leaf.key); status != http.StatusOK {
		t.Fatalf("got %d %q after a valid list", status, body)
	}
}

// Every verified chain counts: a leaf that also chains to another anchor
// does not get past the binding through the first chain alone.
func TestNamespaceIssuerRuleReadsEveryVerifiedChain(t *testing.T) {
	external := newNamedRootCA(t, "external client CA")
	user := newNamedRootCA(t, "user CA")
	issuers := []callerauth.NamespaceIssuer{mustNamespaceIssuer(t, "user", user)}
	leaf := issueClientLeaf(t, user, "user/claude")

	state := func(chains ...[]*x509.Certificate) *tls.ConnectionState {
		return &tls.ConnectionState{HandshakeComplete: true, PeerCertificates: []*x509.Certificate{leaf.cert}, VerifiedChains: chains}
	}
	caller, err := callerauth.CallerFromConnectionState(state([]*x509.Certificate{leaf.cert, user.cert}), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := callerauth.NamespaceIssuerError(caller, state([]*x509.Certificate{leaf.cert, user.cert}), issuers); err != nil {
		t.Fatalf("one chain to the user CA: %v", err)
	}
	two := state([]*x509.Certificate{leaf.cert, user.cert}, []*x509.Certificate{leaf.cert, external.cert})
	if err := callerauth.NamespaceIssuerError(caller, two, issuers); !errors.Is(err, callerauth.ErrIssuerNamespace) {
		t.Fatalf("a second chain to another anchor: %v, want ErrIssuerNamespace", err)
	}
	if err := callerauth.NamespaceIssuerError(caller, state(), issuers); !errors.Is(err, callerauth.ErrIssuerNamespace) {
		t.Fatalf("no verified chain: %v, want ErrIssuerNamespace", err)
	}
	if err := callerauth.NamespaceIssuerError(caller, two, nil); err != nil {
		t.Fatalf("no bindings: %v", err)
	}
}
