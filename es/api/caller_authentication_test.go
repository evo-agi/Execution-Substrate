package api

import (
	"net/http"
	"testing"

	"execution-substrate/internal/callerauth/callerauthtest"
)

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
			callerauthtest.CheckRoute(t, server.Handler(), route, "bootstrap-ca", reached)
		}
	}
}
