package executionsubstrate_test

import "testing"

func TestRemoteAlphaESServiceUserMigrationPublicDelegationIsRetired(t *testing.T) {
	assertRetiredRemoteAlphaRoute(t, "scripts/remote_alpha_migrate_es_service_user.sh", []string{"arbitrary"})
}
