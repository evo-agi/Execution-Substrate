package callerauth

import "time"

// WithClock returns a copy of a that reads the current time from now. Only
// this package's tests use it; the services always use the real clock.
func (a Authenticator) WithClock(now func() time.Time) Authenticator {
	a.now = now
	return a
}
