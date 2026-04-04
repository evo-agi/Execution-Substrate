package api

import "execution-platform/acs/catalog"

type LookupResponse struct {
	Success               bool                   `json:"success"`
	Digest                *string                `json:"digest,omitempty"`
	Assignment            *catalog.AssignmentKey `json:"assignment,omitempty"`
	CatalogSnapshotDigest *string                `json:"catalog_snapshot_digest,omitempty"`
	Error                 *string                `json:"error,omitempty"`
}

type WorkloadZoneVaultDiscoveryResponse struct {
	Success bool    `json:"success"`
	Digest  *string `json:"digest,omitempty"`
	Error   *string `json:"error,omitempty"`
}

type HealthResponse struct {
	Status                string                     `json:"status"`
	Ready                 bool                       `json:"ready"`
	Service               string                     `json:"service"`
	CacheEntries          int                        `json:"cache_entries"`
	CatalogSeedDigest     *string                    `json:"catalog_seed_digest,omitempty"`
	CatalogSnapshotDigest *string                    `json:"catalog_snapshot_digest,omitempty"`
	AdditionalProperties  HealthAdditionalProperties `json:"additional_properties"`
}

type HealthAdditionalProperties struct {
	Dependencies HealthDependencies `json:"dependencies"`
	Readiness    HealthReadiness    `json:"readiness"`
}

type HealthDependencies struct {
	Audit string `json:"audit"`
}

type HealthReadiness struct {
	CacheInitialized        string `json:"cache_initialized"`
	RequiredSeedAssignments string `json:"required_seed_assignments"`
	CatalogSeedDigest       string `json:"catalog_seed_digest"`
	CatalogSnapshotDigest   string `json:"catalog_snapshot_digest"`
}
