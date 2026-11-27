package callerauth

import (
	"crypto/tls"
	"time"
)

// WithClock returns a copy of a that reads the current time from now. Only
// this package's tests use it; the services always use the real clock.
func (a Authenticator) WithClock(now func() time.Time) Authenticator {
	a.now = now
	return a
}

// NamespaceIssuerError exposes the namespace issuer rule that Authenticate
// applies, so the tests can name the refusal.
func NamespaceIssuerError(caller Caller, state *tls.ConnectionState, issuers []NamespaceIssuer) error {
	return namespaceIssuerError(caller, state, issuers)
}
