package catalog

type Store interface {
	Lookup(assignment AssignmentKey) (string, bool, error)
	Ready() bool
	EntryCount() int
	SeedDigest() string
	SnapshotDigest() string
}
