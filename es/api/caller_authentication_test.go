package api

import (
	"net/http"
	"testing"

	"execution-substrate/internal/callerauth/callerauthtest"
)

// ES reads its caller from the TLS connection its server accepted (callerauth's
// AuthenticateConnection), so every route is checked over real connections:
// the shared refusals, and a request whose TLS state names an allowed caller
// that its connection did not present.
func TestESRoutesApplyTheSharedCallerAuthenticationRule(t *testing.T) {
	var producerContractCalls, prepareCalls, submitCalls, statusCalls, logsCalls, resultCalls, cancelCalls int
	service := fakeLifecycleService{
		producerContractCalls: &producerContractCalls,
		prepareCalls:          &prepareCalls,
		submitCalls:           &submitCalls,
		statusCalls:           &statusCalls,
		logsCalls:             &logsCalls,
		resultCalls:           &resultCalls,
		cancelCalls:           &cancelCalls,
	}
	reached := func() int {
		return producerContractCalls + prepareCalls + submitCalls + statusCalls + logsCalls + resultCalls + cancelCalls
	}
	server := NewServer(service, "bootstrap-ca", []string{"service/control-plane"}, func() bool { return true })

	for _, route := range []callerauthtest.Route{
		{Name: "contract", Method: http.MethodGet, Target: "/v1/executions:contract"},
		{Name: "prepare", Method: http.MethodPost, Target: "/v1/executions:prepare", Body: "{}"},
		{Name: "submit", Method: http.MethodPost, Target: "/v1/executions:submit", Body: "{}"},
		{Name: "status", Method: http.MethodGet, Target: "/v1/executions/run-1/status"},
		{Name: "logs", Method: http.MethodGet, Target: "/v1/executions/run-1/logs"},
		{Name: "result", Method: http.MethodGet, Target: "/v1/executions/run-1/result"},
		{Name: "cancel", Method: http.MethodPost, Target: "/v1/executions/run-1:cancel"},
	} {
		for _, allowed := range []string{"service/control-plane", "service/control-plane/provider"} {
			route := route
			route.AllowedPath = allowed
			if allowed != "service/control-plane" {
				route.Name += "_subpath"
			}
			callerauthtest.CheckConnectionRoute(t, server.Handler(), route, "bootstrap-ca", reached)
		}
	}
}

// ES matches execution callers with the shared allowlist rule: a configured
// prefix that fails it matches nothing, even when a server is built with it
// directly instead of from a checked configuration. The old matcher trimmed
// slashes and took a one-segment prefix as a parent of every path below it.
func TestESAllowlistPrefixThatFailsTheSharedRuleMatchesNothing(t *testing.T) {
	var producerContractCalls int
	service := fakeLifecycleService{producerContractCalls: &producerContractCalls}
	server := NewServer(service, "bootstrap-ca", []string{"service", "/service/control-plane", "service/control-plane/"}, func() bool { return true })
	credential := callerauthtest.IssueCredential(t, callerauthtest.RuntimeIssuer, callerauthtest.LeafProfile{}, callerauthtest.SPIFFEID("service/control-plane"))
	response := callerauthtest.ServeConnection(t, server.Handler(), http.MethodGet, "/v1/executions:contract", "", credential)
	if response.Code != http.StatusForbidden || response.Body.String() != "Caller not authorized for this operation" {
		t.Fatalf("contract as service/control-plane: %d %q", response.Code, response.Body.String())
	}
	if producerContractCalls != 0 {
		t.Fatalf("the caller reached the service %d times", producerContractCalls)
	}
}
