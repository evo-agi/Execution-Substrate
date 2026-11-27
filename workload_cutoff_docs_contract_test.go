package executionsubstrate_test

import "testing"

// WI-3 issues one identity per named workload. Before any of those
// identities goes live, the owner must be able to cut one of them off, and
// WI-3 must prove it with tests. This test pins that acceptance requirement
// in the F1 decision, so that dropping or weakening it is a visible change to
// the contract and not drift.
func TestWorkstreamFF1WorkloadCutOffIsRequiredOfWI3(t *testing.T) {
	decisionRaw := mustRead(t, ".docs/system_overview/runtime_identity_handoff.md")
	cutOff := compactDocSection(t, decisionRaw, "#### Cutting off one named workload", "### 11.8 Adding per-run identities later")
	delivery := compactDocSection(t, decisionRaw, "### 11.10 Delivery", "")

	assertContainsAll(t, "F1 cut-off owner", cutOff,
		"The owner can cut off one named workload without touching any other, and WI-3 proves it with tests.",
		"The owner does it with the setup scripts, because ES holds no SPIRE or Vault administrative access (section 11.3).",
	)

	assertContainsAll(t, "F1 cut-off outcomes", cutOff,
		"ES hands the identity to no run. The name leaves the configured list, and every grant rule that names it is removed, lane included, so a run whose profile needs a credential is refused with `403 workload_identity_not_granted` (section 11.5).",
		"SPIRE issues no new JWT-SVID for the name: its entry is deleted",
		"Its role `workload-<name>` is deleted, so no login succeeds, including one with a JWT-SVID issued before the cut-off that has not expired yet.",
		"A Vault token issued before the cut-off loses access to the name's secrets at once.",
		"If they show that such a token keeps access, WI-3 stops and brings the owner the choice between revoking each such token and accepting access until the role's `token_max_ttl` ends.",
		"A run that holds the identity when the cut-off starts is found by the container label of section 11.4 and cancelled through ES.",
		"Anything the workload could read is treated as seen, and the runbook says to rotate it where it was issued.",
		"The name is never registered again. The setup scripts keep a record of cut-off names and refuse to register one",
		"A full re-setup keeps that record.",
		"The Vault step runs first, so a cut-off that stops halfway leaves the workload without secrets.",
		"Readiness refuses `submit-ready` until every step is done",
	)

	assertContainsAll(t, "F1 cut-off tests and gate", cutOff,
		"WI-3's CI integration tests, with real SPIRE, Vault and Docker, register two names, cut one off with the setup scripts, and prove each outcome:",
		"a Vault token issued before the cut-off can no longer read `<name>/shared/`;",
		"registering the name again is refused;",
		"and the other name still logs in and reads its own secrets.",
		"No named identity goes live on a box before these tests pass.",
		"WI-3's box run also cuts off one throwaway name, with one of its runs in flight, and WI-3 adds the cut-off to the runbooks.",
	)

	assertContainsAll(t, "F1 delivery carries the cut-off", delivery,
		"and the cut-off of one named workload with its tests and runbook (section 11.7) |",
	)
}
