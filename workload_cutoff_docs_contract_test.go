package executionsubstrate_test

import (
	"strings"
	"testing"
)

// WI-3 issues one identity per named workload. Before any of those
// identities goes live, the owner must be able to cut one of them off, and
// WI-3 must prove it with tests. This test pins that acceptance requirement
// in the F1 decision and in the F1 record, every sentence of it, so that
// dropping or weakening any part is a visible change to the contract and not
// drift.
func TestWorkstreamFF1WorkloadCutOffIsRequiredOfWI3(t *testing.T) {
	decisionRaw := mustRead(t, ".docs/system_overview/runtime_identity_handoff.md")
	cutOff := compactDocSection(t, decisionRaw, "#### Cutting off one named workload", "### 11.8 Adding per-run identities later")
	posture := compactDocSection(t, decisionRaw, "### 11.7 SPIRE and Vault posture", "#### Cutting off one named workload")

	assertContainsAll(t, "F1 cut-off owner", cutOff,
		"The owner can cut off one named workload without touching any other, and WI-3 proves it with tests.",
		"The owner does it with the setup scripts, because ES holds no SPIRE or Vault administrative access (section 11.3).",
	)

	assertContainsAll(t, "F1 cut-off steps in order", cutOff,
		"A cut-off runs four steps, in this order: "+
			"1. Vault: the policy `workload-<name>` is deleted, then the role `workload-<name>`. "+
			"2. ES configuration: the name leaves the configured list, every grant rule that names it is removed, lane included, and the name joins the record of cut-off names. ES reads its configuration at startup, so this step restarts ES. "+
			"3. Runs in flight: each is cancelled through ES and followed to a terminal status. "+
			"4. SPIRE: the name's entry is deleted.",
	)

	assertContainsAll(t, "F1 cut-off outcomes", cutOff,
		"Cutting off a name has these outcomes: - ES hands the identity to no run.",
		"ES hands the identity to no run. A run whose profile needs a credential is refused with `403 workload_identity_not_granted` (section 11.5).",
		"Every delivery that can cause an effect evaluates the grants again with the configuration ES runs with (`.docs/execution_lifecycle/contracts.md`, section 5B), so after the restart a replay, or a prepared run not yet submitted, is refused too.",
		"A Vault token issued before the cut-off loses access to the name's secrets at once.",
		"Deleting the policy `workload-<name>` is expected to do this, because Vault looks up a token's policies on every request; WI-3's tests are the proof.",
		"If they show that such a token keeps access, WI-3 stops and brings the owner the choice between revoking each such token and accepting access until the role's `token_max_ttl` ends.",
		"With the role deleted, no Vault login succeeds for the name, including one with a JWT-SVID issued before the cut-off that has not expired yet.",
		"The policy goes before the role, so a cut-off that stops between the two still leaves every token without the name's secrets.",
		"A run in flight is one admitted with the identity and not yet terminal.",
		"Step 3 starts only after ES has restarted without the identity, so no new one can start.",
		"It finds every such run from the Nomad jobs whose task carries the container label of section 11.4, including jobs not yet placed; a job's ID is `exec-<run_id>`.",
		"It cancels each run through ES and reads its status until it is terminal.",
		"A run that is not terminal within the limit the WI-3 pull request sets is reported by its run ID, and the step fails.",
		"SPIRE issues no new JWT-SVID for the name once its agent has seen the deletion, so the runtime helper of a new run cannot obtain one (section 11.6).",
		"A JWT-SVID issued earlier stays valid until it expires, but it can no longer log in to Vault.",
		"The name's secrets under `<name>/shared/` stay in Vault: a cut-off removes access, not data.",
		"Anything the workload could read is treated as seen, and the runbook says to rotate it where it was issued.",
		"The name is never registered again.",
		"The record of cut-off names lives in ES deployment configuration, next to the configured list, not in Vault or SPIRE, so a Vault reset or a new SPIRE datastore does not lose it, and a full re-setup carries it over.",
		"ES startup refuses a configuration that lists a recorded name, the setup scripts refuse to register one, and readiness refuses `submit-ready` while SPIRE or Vault holds an entry, role or policy for one, including one made by hand.",
		"So an old grant, an old record or the old secrets under `<name>/shared/` never apply to a different workload.",
		"A cut-off that stops halfway leaves the workload without secrets, because the Vault step runs first.",
		"Readiness refuses `submit-ready` until every step is done, because until then the names registered in SPIRE and Vault differ from the names ES configuration lists.",
		"Every other name keeps working: its Vault role, policy and secrets, its SPIRE entry, its grants and its runs in flight are not touched.",
	)

	assertContainsAll(t, "F1 readiness counts leftover Vault objects", posture,
		"A Vault role or Vault policy left for an identity ES configuration does not list counts as a difference, the same as such an entry.",
	)

	assertContainsAll(t, "F1 cut-off proofs", cutOff,
		"WI-3's CI integration tests use real SPIRE, Vault, Nomad and Docker.",
		"They register two names, one a prefix of the other (such as `codex` and `codex-agent`), cut off the shorter one with the setup scripts, and prove each outcome:",
		"- ES refuses a run that needs the cut-off identity with `403 workload_identity_not_granted`, and ES configuration holds no grant rule that names it.",
		"- A Vault token issued before the cut-off can no longer read `<name>/shared/`, and the secrets are still in Vault.",
		"- A Vault login with a JWT-SVID issued before the cut-off fails.",
		"- A run in flight with the identity, started before the cut-off, is cancelled and reaches a terminal status.",
		"- Once the SPIRE agent has seen the deletion, a runtime helper cannot obtain a JWT-SVID for the name's ID.",
		"- A cut-off stopped after each of its four steps leaves a token issued before it unable to read `<name>/shared/`, and readiness refusing `submit-ready`.",
		"- Registering the name again is refused; an entry, role or policy made for it by hand makes readiness refuse `submit-ready`; and after a fresh setup from scratch with the same ES configuration, registering it is still refused.",
		"- Readiness reports `submit-ready` only once every step is done.",
		"- The other name still logs in and reads its own secrets, ES still admits a run for it, and a run of it in flight keeps running through the cut-off.",
	)

	assertContainsAll(t, "F1 cut-off gate", cutOff,
		"No named identity goes live on any host, the Remote Alpha box or a supported-local host, before these tests pass.",
		"WI-3's box run (section 11.10) also cuts off one throwaway name, with one of its runs in flight, and WI-3 adds the cut-off to the runbooks.",
	)

	// The cut-off belongs to the WI-3 row of the delivery table, not just
	// anywhere in it.
	wi3Row := ""
	for _, line := range strings.Split(decisionRaw, "\n") {
		if strings.HasPrefix(line, "| WI-3 | ") {
			wi3Row = line
		}
	}
	if !strings.Contains(wi3Row, "and the cut-off of one named workload with its tests and runbook (section 11.7) |") {
		t.Fatalf("the WI-3 delivery row must carry the cut-off, got %q", wi3Row)
	}

	// The F1 decision record, which keeps PLANS.md's authority, carries the
	// same gate, right after the F1 delivery bullet.
	assertContainsAll(t, "F1 record carries the cut-off", workstreamRecord(t, "F"),
		"WI-5 the durable format revision, before D3 makes those formats live state. "+
			"- WI-3 also delivers the owner's cut-off of one named workload, proved by CI integration tests with real SPIRE, Vault, Nomad and Docker and rehearsed in its box run. "+
			"No named identity goes live on any host, the Remote Alpha box or a supported-local host, before those tests pass (`.docs/system_overview/runtime_identity_handoff.md`, section 11.7).",
	)
}
