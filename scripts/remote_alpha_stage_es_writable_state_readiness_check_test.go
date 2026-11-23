package executionsubstrate_test

import "testing"

func TestRemoteAlphaWritableStateReadinessStagingRouteIsRetired(t *testing.T) {
	assertRetiredRemoteAlphaRoute(t, "scripts/remote_alpha_stage_es_writable_state_readiness_check.sh", []string{"--check-only"})
}
