package executionsubstrate_test

import "testing"

func TestRemoteAlphaOldRootPlanningRouteIsRetired(t *testing.T) {
	assertRetiredRemoteAlphaRoute(t, "scripts/remote_alpha_plan_old_root_cleanup.sh", []string{"--help"})
}
