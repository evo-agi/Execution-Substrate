// Package grantcaller holds the caller that ES admission's workload grants
// match on (.docs/execution_lifecycle/contracts.md, section 5B).
//
// A Caller has no exported field, so no code outside this package can write
// a caller into one, and the context key that carries it is unexported, so
// no code outside this package can put anything there. The Go compiler, not
// a test, enforces that every Caller comes from one of two constructors:
//
//   - FromConnection, which takes a callerauth.ConnectionCaller: the caller
//     that caller authentication read from the TLS connection a request
//     arrived on. Only callerauth can make one (see its package comment);
//   - FromDelivery, which takes the caller URI that a private reliable
//     submit delivery's claim is bound to. It is the only constructor that
//     takes a string, so the compiler cannot tell where that string came
//     from: ES admission calls it in one place, when it builds a delivery's
//     caller fact, and a guard test in es/admission pins that call site.
//
// The zero Caller is no caller: it matches no grant.
//
// The package has no reflection, no unsafe and no cgo, and performs no I/O.
package grantcaller

import (
	"context"

	"execution-substrate/internal/callerauth"
)

// Caller is the caller that workload grants match on.
type Caller struct {
	id callerauth.SPIFFEID
}

// FromConnection returns the caller that caller authentication read from
// the TLS connection a request arrived on. A zero
// callerauth.ConnectionCaller gives no caller.
func FromConnection(caller callerauth.ConnectionCaller) Caller {
	return canonical(caller.ID())
}

// FromDelivery returns the caller of a private reliable submit delivery:
// the caller URI its claim is bound to. A URI that callerauth would not
// accept, written in exactly that form, gives no caller, so the delivery
// matches no grant.
func FromDelivery(canonicalURI string) Caller {
	id, err := callerauth.ParseSPIFFEID(canonicalURI)
	if err != nil || id.String() != canonicalURI {
		return Caller{}
	}
	return Caller{id: id}
}

// canonical returns id as a Caller when callerauth accepts its text form
// exactly, and no caller otherwise (such as for the zero SPIFFEID).
func canonical(id callerauth.SPIFFEID) Caller {
	parsed, err := callerauth.ParseSPIFFEID(id.String())
	if err != nil || parsed.String() != id.String() {
		return Caller{}
	}
	return Caller{id: parsed}
}

// Principal returns the canonical SPIFFE ID of the caller, or the empty
// string for no caller.
func (c Caller) Principal() string {
	if c == (Caller{}) {
		return ""
	}
	return c.id.String()
}

type contextKey struct{}

// With returns ctx carrying caller in place of any caller ctx carried.
func With(ctx context.Context, caller Caller) context.Context {
	return context.WithValue(ctx, contextKey{}, caller)
}

// From returns the caller ctx carries, or no caller.
func From(ctx context.Context) Caller {
	caller, _ := ctx.Value(contextKey{}).(Caller)
	return caller
}
