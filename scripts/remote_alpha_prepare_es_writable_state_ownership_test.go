package scripts_test

import "testing"

func TestRemoteAlphaWritableStateOwnershipRouteIsRetired(t *testing.T) {
	assertRetiredRemoteAlphaRoute(t, "scripts/remote_alpha_prepare_es_writable_state_ownership.sh", []string{"--apply"})
}
