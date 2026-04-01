package catalog

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

type MemoryStore struct {
	lookup         map[string]string
	seedDigest     string
	snapshotDigest string
}

type seedDigestEntry struct {
	Digest     string        `json:"digest"`
	Assignment AssignmentKey `json:"assignment"`
}

type snapshotDigestEntry struct {
	Assignment AssignmentKey `json:"assignment"`
	Digest     string        `json:"digest"`
}

func NewMemoryStore(seed map[string]AssignmentKey) (*MemoryStore, error) {
	if len(seed) == 0 {
		return nil, fmt.Errorf("artifact catalog seed assignments are required before startup")
	}

	reversed := make(map[string]string, len(seed))

	for digest, assignment := range seed {
		if strings.TrimSpace(digest) == "" {
			return nil, fmt.Errorf("invalid digest in seed_artifact_digests: %q", digest)
		}

		if err := assignment.Validate(); err != nil {
			return nil, fmt.Errorf("invalid assignment in seed_artifact_digests for %s: %w", digest, err)
		}

		key, err := assignment.CanonicalJSON()
		if err != nil {
			return nil, fmt.Errorf("canonicalize assignment for %s: %w", digest, err)
		}

		if existing, ok := reversed[key]; ok {
			return nil, fmt.Errorf(
				"duplicate identity assignment in seed_artifact_digests: assignment=%s, existing_digest=%s, duplicate_digest=%s",
				key,
				existing,
				digest,
			)
		}

		reversed[key] = digest
	}

	required := RequiredWorkloadZoneVault().MustCanonicalJSON()
	if _, ok := reversed[required]; !ok {
		return nil, fmt.Errorf("artifact catalog is missing required seed assignments: [%s]", required)
	}

	store := &MemoryStore{
		lookup: reversed,
	}

	seedDigest, err := computeSeedDigest(seed)
	if err != nil {
		return nil, err
	}

	snapshotDigest, err := computeSnapshotDigest(reversed)
	if err != nil {
		return nil, err
	}

	store.seedDigest = seedDigest
	store.snapshotDigest = snapshotDigest

	return store, nil
}

func (s *MemoryStore) Lookup(assignment AssignmentKey) (string, bool, error) {
	key, err := assignment.CanonicalJSON()
	if err != nil {
		return "", false, err
	}

	digest, ok := s.lookup[key]
	return digest, ok, nil
}

func (s *MemoryStore) Ready() bool {
	return s != nil && len(s.lookup) > 0 && s.seedDigest != "" && s.snapshotDigest != ""
}

func (s *MemoryStore) EntryCount() int {
	if s == nil {
		return 0
	}

	return len(s.lookup)
}

func (s *MemoryStore) SeedDigest() string {
	if s == nil {
		return ""
	}

	return s.seedDigest
}

func (s *MemoryStore) SnapshotDigest() string {
	if s == nil {
		return ""
	}

	return s.snapshotDigest
}

func computeSeedDigest(seed map[string]AssignmentKey) (string, error) {
	// Seed digests are internal ACS state digests, not cross-service artifact digests.
	// We hash a sorted entry list instead of the Go map directly so identical input
	// always produces the same digest regardless of map iteration order.
	digests := make([]string, 0, len(seed))
	for digest := range seed {
		digests = append(digests, digest)
	}
	sort.Strings(digests)

	entries := make([]seedDigestEntry, 0, len(digests))
	for _, digest := range digests {
		entries = append(entries, seedDigestEntry{
			Digest:     digest,
			Assignment: seed[digest],
		})
	}

	return hashJSON(entries)
}

func computeSnapshotDigest(lookup map[string]string) (string, error) {
	// Snapshot digests intentionally reflect the normalized assignment->digest view
	// installed in memory. Sorting canonical assignment keys keeps the digest stable
	// across process runs and independent of map ordering.
	keys := make([]string, 0, len(lookup))
	for key := range lookup {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	entries := make([]snapshotDigestEntry, 0, len(keys))
	for _, key := range keys {
		var assignment AssignmentKey
		if err := json.Unmarshal([]byte(key), &assignment); err != nil {
			return "", fmt.Errorf("decode canonical assignment: %w", err)
		}

		entries = append(entries, snapshotDigestEntry{
			Assignment: assignment,
			Digest:     lookup[key],
		})
	}

	return hashJSON(entries)
}

func hashJSON(value any) (string, error) {
	payload, err := json.Marshal(value)
	if err != nil {
		return "", fmt.Errorf("marshal digest payload: %w", err)
	}

	sum := sha256.Sum256(payload)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}
