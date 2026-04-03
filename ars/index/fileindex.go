package index

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"execution-platform/ars/store"
)

type FileIndex struct {
	path    string
	entries map[string]Entry
	mu      sync.RWMutex
}

func Load(path string) (*FileIndex, error) {
	if strings.TrimSpace(path) == "" {
		return nil, fmt.Errorf("storage.index_file is required")
	}

	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open artifact index: %w", err)
	}
	defer file.Close()

	var entries map[string]Entry
	decoder := json.NewDecoder(file)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&entries); err != nil {
		return nil, fmt.Errorf("decode artifact index: %w", err)
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); err != io.EOF {
		return nil, fmt.Errorf("decode artifact index: trailing data after first JSON document")
	}

	if entries == nil {
		entries = map[string]Entry{}
	}

	for artifactDigest, entry := range entries {
		if err := validateEntry(artifactDigest, entry); err != nil {
			return nil, err
		}
	}

	return &FileIndex{
		path:    path,
		entries: entries,
	}, nil
}

func (f *FileIndex) Path() string {
	return f.path
}

func (f *FileIndex) Count() int {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return len(f.entries)
}

func (f *FileIndex) Lookup(artifactDigest string) (Entry, bool, error) {
	if err := store.ValidateDigest(artifactDigest); err != nil {
		return Entry{}, false, err
	}

	f.mu.RLock()
	defer f.mu.RUnlock()
	entry, found := f.entries[artifactDigest]
	return entry, found, nil
}

func (f *FileIndex) Register(entry Entry) (bool, error) {
	if strings.TrimSpace(entry.CreatedAt) == "" {
		entry.CreatedAt = time.Now().UTC().Format(time.RFC3339)
	}
	if err := validateEntry(entry.ArtifactDigest, entry); err != nil {
		return false, err
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	existing, found := f.entries[entry.ArtifactDigest]
	if found {
		if sameDigestTuple(existing, entry) {
			return false, nil
		}
		return false, ConflictError{ArtifactDigest: entry.ArtifactDigest}
	}

	next := make(map[string]Entry, len(f.entries)+1)
	for artifactDigest, storedEntry := range f.entries {
		next[artifactDigest] = storedEntry
	}
	next[entry.ArtifactDigest] = entry

	if err := persistEntries(f.path, next); err != nil {
		return false, err
	}

	f.entries = next
	return true, nil
}

func validateEntry(key string, entry Entry) error {
	if err := store.ValidateDigest(key); err != nil {
		return fmt.Errorf("validate artifact index key: %w", err)
	}
	if strings.TrimSpace(entry.ArtifactDigest) == "" {
		return fmt.Errorf("artifact index entry %s is missing artifact_digest", key)
	}
	if entry.ArtifactDigest != key {
		return fmt.Errorf("artifact index entry %s has mismatched artifact_digest", key)
	}

	if strings.TrimSpace(entry.DescriptorDigest) == "" {
		return fmt.Errorf("artifact index entry %s is missing descriptor_digest", key)
	}
	if err := store.ValidateDigest(entry.DescriptorDigest); err != nil {
		return fmt.Errorf("artifact index entry %s has invalid descriptor_digest: %w", key, err)
	}

	if strings.TrimSpace(entry.CreatedAt) == "" {
		return fmt.Errorf("artifact index entry %s is missing created_at", key)
	}

	return nil
}

func sameDigestTuple(left Entry, right Entry) bool {
	return left.ArtifactDigest == right.ArtifactDigest &&
		left.DescriptorDigest == right.DescriptorDigest
}

func persistEntries(path string, entries map[string]Entry) error {
	payload, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal artifact index: %w", err)
	}
	payload = append(payload, '\n')

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("create artifact index directory: %w", err)
	}

	tempFile, err := os.CreateTemp(filepath.Dir(path), ".artifact-index-*")
	if err != nil {
		return fmt.Errorf("create temp artifact index: %w", err)
	}

	tempPath := tempFile.Name()
	cleanupTemp := true
	defer func() {
		if cleanupTemp {
			_ = os.Remove(tempPath)
		}
	}()

	if _, err := tempFile.Write(payload); err != nil {
		tempFile.Close()
		return fmt.Errorf("write temp artifact index: %w", err)
	}
	if err := tempFile.Chmod(0o600); err != nil {
		tempFile.Close()
		return fmt.Errorf("chmod temp artifact index: %w", err)
	}
	if err := tempFile.Close(); err != nil {
		return fmt.Errorf("close temp artifact index: %w", err)
	}

	if err := os.Rename(tempPath, path); err != nil {
		return fmt.Errorf("commit artifact index: %w", err)
	}

	cleanupTemp = false
	return nil
}
