package grantcaller

import (
	"context"
	"testing"

	"execution-substrate/internal/callerauth"
	"execution-substrate/internal/callerauth/callerauthtest"
)

const operator = "spiffe://execution.internal/operator/local"

// connectionCaller returns the caller callerauth reads from a real TLS
// connection whose client certificate names uri.
func connectionCaller(t *testing.T, uri string) callerauth.ConnectionCaller {
	t.Helper()
	caller, err := callerauthtest.ConnectionCaller(uri)
	if err != nil {
		t.Fatal(err)
	}
	return caller
}

func TestFromConnectionKeepsTheAuthenticatedCaller(t *testing.T) {
	for _, uri := range []string{operator, operator + "/x", "spiffe://execution.internal/service/control-plane"} {
		if got := FromConnection(connectionCaller(t, uri)).Principal(); got != uri {
			t.Errorf("caller %q, want %q", got, uri)
		}
	}
	if got := FromConnection(callerauth.ConnectionCaller{}); got != (Caller{}) {
		t.Errorf("a zero callerauth.ConnectionCaller gives caller %q, want none", got.Principal())
	}
}

func TestFromDeliveryTakesOnlyACanonicalESCaller(t *testing.T) {
	for uri, want := range map[string]string{
		operator: operator,
		"spiffe://execution.internal/service/control-plane": "spiffe://execution.internal/service/control-plane",
		"spiffe://synthetic.test/ns/admission":              "",
		"spiffe://execution.internal/":                      "",
		" " + operator:                                      "",
		operator + " ":                                      "",
		"SPIFFE://execution.internal/operator/local":        "",
		"": "",
		"spiffe://execution.internal/workload/codex-agent": "",
		"spiffe://execution.internal/Workload/codex-agent": "",
		"spiffe://execution.internal/operator/local?x=1":   "",
		"spiffe://execution.internal/operator/%6Cocal":     "",
	} {
		if got := FromDelivery(uri).Principal(); got != want {
			t.Errorf("delivery bound to %q: caller %q, want %q", uri, got, want)
		}
	}
}

func TestAContextCarriesTheLastCallerPutThere(t *testing.T) {
	if got := From(context.Background()); got != (Caller{}) {
		t.Errorf("a context without a caller gives %q", got.Principal())
	}
	first := With(context.Background(), FromConnection(connectionCaller(t, operator)))
	if got := From(first).Principal(); got != operator {
		t.Errorf("caller %q, want %q", got, operator)
	}
	second := With(first, FromDelivery("spiffe://execution.internal/service/control-plane"))
	if got := From(second).Principal(); got != "spiffe://execution.internal/service/control-plane" {
		t.Errorf("caller %q after a delivery caller replaced it", got)
	}
	cleared := With(second, FromDelivery("spiffe://synthetic.test/ns/admission"))
	if got := From(cleared); got != (Caller{}) {
		t.Errorf("a delivery caller ES does not accept left caller %q in the context", got.Principal())
	}
	if got := From(context.WithValue(context.Background(), contextKey{}, operator)); got != (Caller{}) {
		t.Errorf("a string under the key gives caller %q, want none", got.Principal())
	}
}
