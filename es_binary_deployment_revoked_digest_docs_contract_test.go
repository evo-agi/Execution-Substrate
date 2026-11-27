package executionsubstrate_test

import (
	"strings"
	"testing"
)

// TestESBinaryDeploymentDocsHoldTheRevokedDigestCheck holds what the docs say
// about the ES binary deployment's EGS config check of revoked digests, and
// about the one-time ES upgrade on a box that has already run it, together
// with the test those sentences name.
func TestESBinaryDeploymentDocsHoldTheRevokedDigestCheck(t *testing.T) {
	remote := compactText(mustRead(t, ".docs/system_overview/remote_supported_host_alpha.md"))
	configuration := compactText(mustRead(t, ".docs/system_overview/configuration.md"))

	assertContainsAll(t, "ES binary deployment, the EGS config check", remote,
		"It also stops a deployment on an `egs.json` whose `revoked_artifacts` holds a digest in any spelling but `sha256:` and 64 lower-case hex characters",
		"naming the entry: the deployment replaces ES and not EGS, so an older EGS that accepted the entry would keep serving it, the new ES would refuse that trust model and not start, and nothing would put the old ES back.",
		"`scripts/remote_alpha_deploy_es_binaries_revoked_digest_test.go` runs the deployment with the real `egsconfigcheck` to hold this.",
	)
	assertContainsAll(t, "ES upgrade, the box after the upgrade", remote,
		"That includes the box after this upgrade once a later commit is named: Nomad and `es.json` are `https`, but `es` and `es-runtime-support` are builds of the commit installed before, so `check` and `apply` refuse it and stop and change nothing. A later ES reaches the box through the ES binary deployment (\"Remote ES Binary Deployment Surface\").",
	)
	assertContainsAll(t, "EGS revoked_artifacts rule, on the box", configuration,
		"On the Remote Alpha box the ES binary deployment makes this check itself: its EGS config check refuses such an entry, and names it, before it installs anything (`.docs/system_overview/remote_supported_host_alpha.md`, \"Remote ES Binary Deployment Surface\").",
	)

	// The test the docs name has to exist and run the deployment with the
	// check built from this tree, not with the fixture's stand-in.
	named := mustRead(t, "scripts/remote_alpha_deploy_es_binaries_revoked_digest_test.go")
	for _, want := range []string{
		"func TestRemoteAlphaESBinaryDeploymentStopsOnARevokedDigestTheNewESRefuses(",
		`buildConfigCheck(t, "egsconfigcheck")`,
		"remote_alpha_deploy_es_binaries_main ",
	} {
		if !strings.Contains(named, want) {
			t.Fatalf("the test the docs name no longer holds %q", want)
		}
	}
}
