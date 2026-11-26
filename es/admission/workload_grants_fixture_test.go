package admission

import (
	"fmt"

	esconfig "execution-substrate/es/config"
)

// grantNetworkTo adds the workload grants that give the network, on both
// runtime profiles, to runs of artifactType artifacts that publisher
// published and keyID sealed. ES admits a run that requests the network only
// with such a grant (.docs/execution_lifecycle/contracts.md, section 5B), so
// every test fixture whose evidence requests the network needs one.
func grantNetworkTo(cfg *esconfig.Config, publisher string, keyID string, artifactType string) {
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
