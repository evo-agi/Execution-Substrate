package admission

import (
	"context"
	"fmt"
	"sync"

	"execution-substrate/es/admission/internal/grantcaller"
	esconfig "execution-substrate/es/config"
	"execution-substrate/internal/callerauth"
	"execution-substrate/internal/callerauth/callerauthtest"
)

// testGrantCaller is the ES caller the test grants name: the caller the ES
// API would have authenticated for a test's :prepare or :submit.
const testGrantCaller = "spiffe://execution.internal/operator/local"

// connectionCallers caches authenticatedCaller's results: each one costs a
// TLS handshake, and a ConnectionCaller never changes.
var connectionCallers sync.Map

// authenticatedCaller returns the caller that ES's API reads from a TLS
// connection on which the client's verified certificate names caller. Tests
// build callers the way production does, from a real TLS connection that
// callerauth's ConnContext hook kept: the grant caller of a request has no
// other way in.
func authenticatedCaller(caller string) callerauth.ConnectionCaller {
	if cached, ok := connectionCallers.Load(caller); ok {
		return cached.(callerauth.ConnectionCaller)
	}
	authenticated, err := callerauthtest.ConnectionCaller(caller)
	if err != nil {
		panic(fmt.Sprintf("test caller %q: %v", caller, err))
	}
	connectionCallers.Store(caller, authenticated)
	return authenticated
}

// grantCaller returns caller as the grant caller of a connection that
// authenticated as caller.
func grantCaller(caller string) grantcaller.Caller {
	return grantcaller.FromConnection(authenticatedCaller(caller))
}

// callerContext returns a context that carries caller as the authenticated
// ES caller, as the ES API's WithAuthenticatedCaller does for a connection
// that authenticated as caller.
func callerContext(parent context.Context, caller string) context.Context {
	return WithAuthenticatedCaller(parent, authenticatedCaller(caller))
}

// testCallerContext is context.Background() with testGrantCaller as the
// authenticated ES caller.
func testCallerContext() context.Context {
	return callerContext(context.Background(), testGrantCaller)
}

// grantNetworkTo adds the workload grants that give the network, on both
// runtime profiles, to runs of artifactType artifacts that publisher
// published and keyID sealed, called by testGrantCaller. ES admits a run that
// requests the network only with such a grant
// (.docs/execution_lifecycle/contracts.md, section 5B), so every test fixture
// whose evidence requests the network needs one.
func grantNetworkTo(cfg *esconfig.Config, publisher string, keyID string, artifactType string) {
	grantNetworkToCaller(cfg, publisher, testGrantCaller, keyID, artifactType)
}

// grantNetworkToCaller is grantNetworkTo for another ES caller.
func grantNetworkToCaller(cfg *esconfig.Config, publisher string, caller string, keyID string, artifactType string) {
	if cfg.AdmissionPolicy == nil {
		cfg.AdmissionPolicy = &esconfig.AdmissionPolicyConfig{}
	} else {
		copied := *cfg.AdmissionPolicy
		cfg.AdmissionPolicy = &copied
	}
	grants := &esconfig.WorkloadGrantsConfig{}
	if cfg.AdmissionPolicy.WorkloadGrants != nil {
		grants.EgressLanes = append(grants.EgressLanes, cfg.AdmissionPolicy.WorkloadGrants.EgressLanes...)
		grants.Rules = append(grants.Rules, cfg.AdmissionPolicy.WorkloadGrants.Rules...)
	}
	if len(grants.EgressLanes) == 0 {
		reaches := true
		grants.EgressLanes = []esconfig.WorkloadEgressLaneConfig{{Name: esconfig.WorkloadEgressLaneUnrestricted, ReachesWorkloadVault: &reaches}}
	}
	for _, profile := range []string{runtimeProfileDefaultStaticScript, runtimeProfileControlPlaneNormalShell} {
		rule := esconfig.WorkloadGrantRuleConfig{
			ID:                 fmt.Sprintf("test-grant-%d", len(grants.Rules)+1),
			PublisherPrincipal: publisher,
			CallerPrincipal:    caller,
			SignerKeyID:        keyID,
			ArtifactType:       artifactType,
			RuntimeProfile:     profile,
			EgressLane:         esconfig.WorkloadEgressLaneUnrestricted,
		}
		present := false
		for _, existing := range grants.Rules {
			present = present || existing.MatchKey() == rule.MatchKey()
		}
		if !present {
			grants.Rules = append(grants.Rules, rule)
		}
	}
	cfg.AdmissionPolicy.WorkloadGrants = grants
}

// grantFixtureNetwork gives the network to runs of the fixture's artifact.
func grantFixtureNetwork(cfg *esconfig.Config, fixture preparedArtifactFixture) {
	grantNetworkTo(cfg, fixture.evidence.Claims.Package.Publication.Invoker.Principal, fixture.keyID,
		fixture.evidence.Claims.Package.Identity.ArtifactType)
}
