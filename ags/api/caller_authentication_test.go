package api_test

import (
	"context"
	"net/http"
	"sync"
	"testing"

	"execution-substrate/ags/api"
	"execution-substrate/ags/publish"
	"execution-substrate/internal/callerauth/callerauthtest"
)

const testBootstrapIssuer = "bootstrap-ca"

type recordingPublisher struct {
	mu      sync.Mutex
	callers []publish.CallerIdentity
}

func (p *recordingPublisher) Health(context.Context) publish.HealthSnapshot {
	return publish.HealthSnapshot{}
}

func (p *recordingPublisher) Publish(_ context.Context, caller publish.CallerIdentity, _ publish.PublishRequest) (publish.PublishResult, *publish.Error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.callers = append(p.callers, caller)
	return publish.PublishResult{}, nil
}

func (p *recordingPublisher) count() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.callers)
}

func TestAGSPublishAppliesTheSharedCallerAuthenticationRule(t *testing.T) {
	publisher := &recordingPublisher{}
	server := api.NewServer(publisher, testBootstrapIssuer, []string{"operator/local"}, func() bool { return true })
	callerauthtest.CheckRoute(t, server.Handler(), callerauthtest.Route{
		Name:        "publish",
		Method:      http.MethodPost,
		Target:      "/v1/artifacts:publish",
		Body:        "{}",
		AllowedPath: "operator/local",
	}, testBootstrapIssuer, publisher.count)
}

// AGS binds publication to the caller: the publish service receives the
// caller's path and its full canonical SPIFFE ID.
func TestAGSPublishPassesTheAuthenticatedCallerToThePublishService(t *testing.T) {
	publisher := &recordingPublisher{}
	server := api.NewServer(publisher, testBootstrapIssuer, []string{"service/control-plane"}, func() bool { return true })
	state := callerauthtest.State(callerauthtest.Certificate(t, callerauthtest.RuntimeIssuer, "spiffe://execution.internal/service/control-plane/provider"))
	response := callerauthtest.Serve(t, server.Handler(), http.MethodPost, "/v1/artifacts:publish", "{}", state)
	if response.Code != http.StatusOK || publisher.count() != 1 {
		t.Fatalf("publish: %d %q, %d calls", response.Code, response.Body.String(), publisher.count())
	}
	want := publish.CallerIdentity{Path: "service/control-plane/provider", SPIFFEID: "spiffe://execution.internal/service/control-plane/provider"}
	if got := publisher.callers[0]; got != want {
		t.Fatalf("caller %+v, want %+v", got, want)
	}
}

func TestAGSAuthorizationStaysLocalAfterAuthentication(t *testing.T) {
	publisher := &recordingPublisher{}
	server := api.NewServer(publisher, testBootstrapIssuer, []string{"operator/local"}, func() bool { return true })
	for _, path := range []string{"operator", "operator/local-evil", "service/deployment"} {
		state := callerauthtest.State(callerauthtest.Certificate(t, callerauthtest.RuntimeIssuer, callerauthtest.SPIFFEID(path)))
		response := callerauthtest.Serve(t, server.Handler(), http.MethodPost, "/v1/artifacts:publish", "{}", state)
		if response.Code != http.StatusForbidden || response.Body.String() != "Caller not authorized for this operation" {
			t.Errorf("%s: %d %q", path, response.Code, response.Body.String())
		}
	}
	if publisher.count() != 0 {
		t.Fatalf("unauthorized callers reached the publish service %d times", publisher.count())
	}
}

// AGS matches publish callers with the shared allowlist rule: a configured
// prefix that fails it matches nothing, even when a server is built with it
// directly instead of from a checked configuration. The old matcher trimmed
// slashes and took a one-segment prefix as a parent of every path below it.
func TestAGSAllowlistPrefixThatFailsTheSharedRuleMatchesNothing(t *testing.T) {
	publisher := &recordingPublisher{}
	server := api.NewServer(publisher, testBootstrapIssuer, []string{"operator", "/operator/local", "operator/local/"}, func() bool { return true })
	state := callerauthtest.State(callerauthtest.Certificate(t, callerauthtest.RuntimeIssuer, callerauthtest.SPIFFEID("operator/local")))
	response := callerauthtest.Serve(t, server.Handler(), http.MethodPost, "/v1/artifacts:publish", "{}", state)
	if response.Code != http.StatusForbidden || response.Body.String() != "Caller not authorized for this operation" {
		t.Fatalf("publish as operator/local: %d %q", response.Code, response.Body.String())
	}
	if publisher.count() != 0 {
		t.Fatalf("the caller reached the publish service %d times", publisher.count())
	}
}

// AGS checks every configured prefix, so a caller that matches only a later
// one is allowed, by the shared rule's match (audit 11, mutant E16).
func TestAGSPublishAllowsACallerThatMatchesALaterPrefix(t *testing.T) {
	publisher := &recordingPublisher{}
	server := api.NewServer(publisher, testBootstrapIssuer, []string{"operator/local", "service/control-plane"}, func() bool { return true })
	for _, tc := range []struct {
		path string
		code int
	}{
		{path: "service/control-plane", code: http.StatusOK},
		{path: "service/control-plane/provider", code: http.StatusOK},
		{path: "service/control-plane-evil", code: http.StatusForbidden},
	} {
		state := callerauthtest.State(callerauthtest.Certificate(t, callerauthtest.RuntimeIssuer, callerauthtest.SPIFFEID(tc.path)))
		response := callerauthtest.Serve(t, server.Handler(), http.MethodPost, "/v1/artifacts:publish", "{}", state)
		if response.Code != tc.code {
			t.Errorf("%s: %d %q, want %d", tc.path, response.Code, response.Body.String(), tc.code)
		}
	}
	if publisher.count() != 2 {
		t.Fatalf("the publish service saw %d callers, want 2", publisher.count())
	}
}
