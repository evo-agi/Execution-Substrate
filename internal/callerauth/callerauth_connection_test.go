package callerauth_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	"execution-substrate/internal/callerauth"
	"execution-substrate/internal/callerauth/callerauthtest"
)

// These tests pin AuthenticateConnection, the path ES uses: the caller comes
// from the TLS connection that NewListener accepted and the server's
// ConnContext hook kept, never from the request.

// connectionRequest returns a request whose context carries a TLS connection
// on which the client presented credential, as callerauth.ConnContext keeps
// it for a server.
func connectionRequest(t *testing.T, credential *callerauthtest.Credential) *http.Request {
	t.Helper()
	ctx, err := callerauthtest.ConnectionContext(context.Background(), credential)
	if err != nil {
		t.Fatal(err)
	}
	return httptest.NewRequest(http.MethodGet, "/", nil).WithContext(ctx)
}

func assertConnectionRefused(t *testing.T, recorder *httptest.ResponseRecorder, ok bool, caller callerauth.ConnectionCaller, status int, body string) {
	t.Helper()
	if ok || caller != (callerauth.ConnectionCaller{}) {
		t.Fatalf("AuthenticateConnection accepted caller %q", caller.ID())
	}
	if recorder.Code != status || recorder.Body.String() != body {
		t.Fatalf("response %d %q, want %d %q", recorder.Code, recorder.Body.String(), status, body)
	}
	if got := recorder.Header().Get("Content-Type"); got != "text/plain; charset=utf-8" {
		t.Fatalf("Content-Type %q, want text/plain; charset=utf-8", got)
	}
}

// The caller is the identity the connection's handshake verified, even when
// r.TLS names another one.
func TestAuthenticateConnectionReadsTheCallerOfTheConnection(t *testing.T) {
	credential := callerauthtest.IssueCredential(t, callerauthtest.RuntimeIssuer, callerauthtest.LeafProfile{}, "spiffe://execution.internal/operator/local")
	r := connectionRequest(t, credential)
	r.TLS = goodStateFor(t, "spiffe://execution.internal/service/control-plane")
	recorder := httptest.NewRecorder()
	caller, ok := callerauth.NewAuthenticator(bootstrapIssuer).AuthenticateConnection(recorder, r)
	if !ok || caller.ID().String() != "spiffe://execution.internal/operator/local" {
		t.Fatalf("AuthenticateConnection = %q, %v; response %d %q", caller.ID(), ok, recorder.Code, recorder.Body.String())
	}
	if recorder.Body.Len() != 0 || len(recorder.Header()) != 0 || recorder.Code != http.StatusOK {
		t.Fatalf("AuthenticateConnection wrote a response: %d %q %v", recorder.Code, recorder.Body.String(), recorder.Header())
	}
}

// A request whose context holds no connection has no caller, whatever r.TLS
// holds: a request is a plain struct that any code can fill in.
func TestAuthenticateConnectionNeverReadsTheRequestTLSState(t *testing.T) {
	r := request(goodState(t, callerauthtest.RuntimeIssuer))
	recorder := httptest.NewRecorder()
	caller, ok := callerauth.NewAuthenticator(bootstrapIssuer).AuthenticateConnection(recorder, r)
	assertConnectionRefused(t, recorder, ok, caller, http.StatusUnauthorized, unauthenticatedBody)
}

// ConnContext keeps only a connection that NewListener accepted. Any other
// connection, a *tls.Conn included, leaves the context as it was, so its
// requests have no caller.
func TestConnContextKeepsOnlyConnectionsFromNewListener(t *testing.T) {
	plain, other := net.Pipe()
	defer plain.Close()
	defer other.Close()
	ctx := context.WithValue(context.Background(), struct{ name string }{"marker"}, 1)
	for name, conn := range map[string]net.Conn{
		"plain":         plain,
		"nil":           nil,
		"*tls.Conn":     tls.Server(plain, &tls.Config{}),
		"nil *tls.Conn": (*tls.Conn)(nil),
	} {
		if got := callerauth.ConnContext(ctx, conn); got != ctx {
			t.Fatalf("ConnContext changed the context for a %s connection", name)
		}
		r := httptest.NewRequest(http.MethodGet, "/", nil).WithContext(callerauth.ConnContext(ctx, conn))
		r.TLS = goodState(t, callerauthtest.RuntimeIssuer)
		recorder := httptest.NewRecorder()
		caller, ok := callerauth.NewAuthenticator(bootstrapIssuer).AuthenticateConnection(recorder, r)
		assertConnectionRefused(t, recorder, ok, caller, http.StatusUnauthorized, unauthenticatedBody)
	}
}

// acceptOne returns the server side of one TCP connection that listener
// accepted, and the client side, which has not started a handshake.
func acceptOne(t *testing.T, listener net.Listener) (net.Conn, net.Conn) {
	t.Helper()
	client, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close() })
	server, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { server.Close() })
	return server, client
}

func tcpListener(t *testing.T) net.Listener {
	t.Helper()
	inner, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { inner.Close() })
	return inner
}

// A connection that NewListener accepted hands out nothing but the net.Conn
// methods and CloseWrite: it is not a *tls.Conn, has no exported field, and
// has no method that returns its TLS state, its certificates or the
// connection beneath it, so Go's HTTP server records no TLS state on its
// requests, and Hijack hands a handler nothing more.
func TestNewListenerConnectionsHandOutNoTLSState(t *testing.T) {
	listener, err := callerauth.NewListener(tcpListener(t), &tls.Config{})
	if err != nil {
		t.Fatal(err)
	}
	server, _ := acceptOne(t, listener)
	if _, ok := server.(*tls.Conn); ok {
		t.Fatalf("the accepted connection is a *tls.Conn")
	}
	if _, ok := server.(interface{ ConnectionState() tls.ConnectionState }); ok {
		t.Fatalf("the accepted connection has ConnectionState")
	}
	if _, ok := server.(interface{ NetConn() net.Conn }); ok {
		t.Fatalf("the accepted connection has NetConn")
	}
	typ := reflect.TypeOf(server)
	var methods []string
	for i := 0; i < typ.NumMethod(); i++ {
		methods = append(methods, typ.Method(i).Name)
	}
	want := []string{"Close", "CloseWrite", "LocalAddr", "Read", "RemoteAddr", "SetDeadline", "SetReadDeadline", "SetWriteDeadline", "Write"}
	if !reflect.DeepEqual(methods, want) {
		t.Fatalf("the accepted connection has the methods %v, want %v", methods, want)
	}
	if typ.Kind() != reflect.Pointer || typ.Elem().Kind() != reflect.Struct {
		t.Fatalf("the accepted connection is a %v", typ)
	}
	for i := 0; i < typ.Elem().NumField(); i++ {
		if typ.Elem().Field(i).IsExported() {
			t.Fatalf("the accepted connection has the exported field %s", typ.Elem().Field(i).Name)
		}
	}
}

// NewListener refuses a configuration with a callback that sees the
// verified chains during the handshake, or with an ALPN protocol Go's HTTP
// server would not speak on its connections.
func TestNewListenerRefusesAConfigurationThatCouldChangeTheVerifiedChains(t *testing.T) {
	inner := tcpListener(t)
	for name, config := range map[string]*tls.Config{
		"nil":                   nil,
		"GetConfigForClient":    {GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) { return nil, nil }},
		"VerifyPeerCertificate": {VerifyPeerCertificate: func([][]byte, [][]*x509.Certificate) error { return nil }},
		"VerifyConnection":      {VerifyConnection: func(tls.ConnectionState) error { return nil }},
		"h2":                    {NextProtos: []string{"h2", "http/1.1"}},
	} {
		if listener, err := callerauth.NewListener(inner, config); err == nil || listener != nil {
			t.Errorf("%s: NewListener accepted the configuration", name)
		}
	}
	if listener, err := callerauth.NewListener(nil, &tls.Config{}); err == nil || listener != nil {
		t.Errorf("NewListener accepted no listener")
	}
	if _, err := callerauth.NewListener(inner, &tls.Config{NextProtos: []string{"http/1.1"}}); err != nil {
		t.Errorf("http/1.1: %v", err)
	}
}

// A connection whose handshake has not completed has no caller, even when
// ConnContext kept it.
func TestAuthenticateConnectionRefusesAConnectionBeforeItsHandshake(t *testing.T) {
	listener, err := callerauth.NewListener(tcpListener(t), &tls.Config{ClientAuth: tls.RequireAndVerifyClientCert})
	if err != nil {
		t.Fatal(err)
	}
	server, _ := acceptOne(t, listener)
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r = r.WithContext(callerauth.ConnContext(r.Context(), server))
	r.TLS = goodState(t, callerauthtest.RuntimeIssuer)
	recorder := httptest.NewRecorder()
	caller, ok := callerauth.NewAuthenticator(bootstrapIssuer).AuthenticateConnection(recorder, r)
	assertConnectionRefused(t, recorder, ok, caller, http.StatusUnauthorized, unauthenticatedBody)
}

// The shared list of refused callers, the bootstrap-issuer refusal and the
// connection cases of callerauthtest's connection check, over real TLS
// connections.
func TestAuthenticateConnectionAppliesTheSharedRuleOverRealConnections(t *testing.T) {
	reachedCount := 0
	auth := callerauth.NewAuthenticator(bootstrapIssuer)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := auth.AuthenticateConnection(w, r); ok {
			reachedCount++
		}
	})
	callerauthtest.CheckConnectionRoute(t, handler, callerauthtest.Route{Name: "connection", Method: http.MethodGet, Target: "/", AllowedPath: "operator/local"}, bootstrapIssuer, func() int { return reachedCount })
}

// AuthenticateConnection checks the validity period at the time it runs, so
// a caller whose certificate expires during a connection is refused from
// then on, as with Authenticate.
func TestAuthenticateConnectionRefusesACallerWhoseCertificateHasExpiredSinceTheHandshake(t *testing.T) {
	credential := callerauthtest.IssueCredential(t, callerauthtest.RuntimeIssuer, callerauthtest.LeafProfile{}, "spiffe://execution.internal/operator/local")
	r := connectionRequest(t, credential)
	now := credential.Leaf.NotBefore.Add(time.Minute)
	auth := callerauth.NewAuthenticator(bootstrapIssuer).WithClock(func() time.Time { return now })

	recorder := httptest.NewRecorder()
	if caller, ok := auth.AuthenticateConnection(recorder, r); !ok || caller.ID().Path() != "operator/local" {
		t.Fatalf("inside the validity period: caller %q, ok %v, response %d %q", caller.ID(), ok, recorder.Code, recorder.Body.String())
	}
	now = credential.Leaf.NotAfter.Add(time.Second)
	recorder = httptest.NewRecorder()
	caller, ok := auth.AuthenticateConnection(recorder, r)
	assertConnectionRefused(t, recorder, ok, caller, http.StatusUnauthorized, unauthenticatedBody)
}

func TestAuthenticatorWithoutABootstrapIssuerRefusesEveryConnection(t *testing.T) {
	credential := callerauthtest.IssueCredential(t, callerauthtest.RuntimeIssuer, callerauthtest.LeafProfile{}, "spiffe://execution.internal/operator/local")
	for name, auth := range map[string]callerauth.Authenticator{
		"zero value": {},
		"empty":      callerauth.NewAuthenticator(""),
	} {
		recorder := httptest.NewRecorder()
		caller, ok := auth.AuthenticateConnection(recorder, connectionRequest(t, credential))
		if ok {
			t.Fatalf("%s: accepted %q", name, caller.ID())
		}
		assertConnectionRefused(t, recorder, ok, caller, http.StatusUnauthorized, unauthenticatedBody)
	}
}

// A ConnectionCaller has no exported field, so no code outside callerauth
// can write an identity into one; the zero value is no caller.
func TestConnectionCallerHasNoExportedFieldAndItsZeroValueIsNoCaller(t *testing.T) {
	for _, value := range []any{callerauth.ConnectionCaller{}, callerauth.Caller{}} {
		typ := reflect.TypeOf(value)
		for i := 0; i < typ.NumField(); i++ {
			if typ.Field(i).IsExported() {
				t.Errorf("%v has the exported field %s", typ, typ.Field(i).Name)
			}
		}
	}
	var zero callerauth.ConnectionCaller
	if zero.ID() != (callerauth.SPIFFEID{}) || zero.ID().String() != "" {
		t.Fatalf("the zero ConnectionCaller has the ID %q", zero.ID())
	}
}

func goodStateFor(t *testing.T, uri string) *tls.ConnectionState {
	t.Helper()
	return callerauthtest.State(callerauthtest.Certificate(t, callerauthtest.RuntimeIssuer, uri))
}
