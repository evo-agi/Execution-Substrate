package executionsubstrate_test

import "testing"

func TestRemoteAlphaRollbackGenerationRouteIsRetired(t *testing.T) {
	assertRetiredRemoteAlphaRoute(t, "scripts/remote_alpha_es_service_user_rollback_rehearsal.sh", []string{"--apply"})
}
