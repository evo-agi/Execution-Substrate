package admission

import "sort"

// currentLifecycleProjectionPolicy keeps the current bounded Nomad-backed
// lifecycle rules explicit in one place instead of letting them drift through
// ad hoc helpers.
type currentLifecycleProjectionPolicy struct{}

func (currentLifecycleProjectionPolicy) selectAllocation(entries []nomadAllocationListEntry) (nomadAllocationListEntry, bool) {
	if len(entries) == 0 {
		return nomadAllocationListEntry{}, false
	}

	// The current lifecycle slice treats the most recently modified allocation
	// as the one meaningful public projection target until a broader
	// retry/reschedule model exists.
	sort.SliceStable(entries, func(i, j int) bool {
		return entries[i].ModifyIndex > entries[j].ModifyIndex
	})
	return entries[0], true
}
