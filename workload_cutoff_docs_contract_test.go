package executionsubstrate_test

import (
	"strings"
	"testing"
)

// cutOffSentences is the whole of "Cutting off one named workload" in
// section 11.7 of the F1 decision, heading included, one entry per sentence
// or list marker, in order. The section must equal these entries joined by
// single spaces, so dropping, weakening, reordering or adding any part is a
// visible change to the contract and not drift.
var cutOffSentences = []string{
	"#### Cutting off one named workload",

	// Who and how.
	"The owner can cut off one named workload without touching any other, and WI-3 proves it with tests.",
	"The owner does it with the setup scripts, because ES holds no SPIRE or Vault administrative access (section 11.3).",

	// The four steps, in order. The record is written first.
	"A cut-off runs four steps, in this order:",
	"1. ES configuration: in one change, the name joins the record of cut-off names, leaves the configured list, and every grant rule that names it is removed, lane included.",
	"ES reads its configuration at startup, so this step restarts ES.",
	"2. Vault: the policy `workload-<name>` is deleted, then the role `workload-<name>`.",
	"3. Runs in flight: each is cancelled through ES and followed to a terminal status.",
	"4. SPIRE: the name's entry is deleted.",

	// Outcomes.
	"Cutting off a name has these outcomes:",
	"- ES hands the identity to no run.",
	"A run can hold an identity only with a lane, so only with network access, and the network policy runs first (`.docs/execution_lifecycle/contracts.md`, section 5B).",
	"So once the grant rule is gone, lane included, ES refuses a run that held the identity with `403 network_access_not_granted`.",
	"Every delivery that can cause an effect evaluates the grants again with the configuration ES runs with (section 5B), so after the restart a replay, or a prepared run not yet submitted, is refused too.",
	"- A Vault token issued before the cut-off loses access to the name's secrets at once.",
	"Deleting the policy `workload-<name>` is expected to do this, because Vault looks up a token's policies on every request;",
	"WI-3's tests are the proof.",
	"If they show that such a token keeps access, WI-3 stops and brings the owner the choice between revoking each such token and accepting access until the role's `token_max_ttl` ends.",
	"- With the role deleted, no Vault login succeeds for the name, including one with a JWT-SVID issued before the cut-off that has not expired yet.",
	"The policy goes before the role, so a cut-off that stops between the two still leaves every token without the name's secrets.",
	"- A run in flight is one admitted with the identity and not yet terminal.",
	"Step 3 starts only after ES has restarted without the identity, so no new one can start.",
	"It finds every such run from the Nomad jobs whose task carries the container label of section 11.4, including jobs not yet placed; a job's ID is `exec-<run_id>`.",
	"It cancels each run through ES and reads its status until it is terminal, then searches again until it finds none.",
	"A run that is not terminal within the limit the WI-3 pull request sets is reported by its run ID, and the step fails.",
	"- SPIRE issues no new JWT-SVID for the name once its agent has seen the deletion, so the runtime helper of a new run cannot obtain one (section 11.6).",
	"A JWT-SVID issued earlier stays valid until it expires, but it can no longer log in to Vault.",
	"- The name's secrets under `<name>/shared/` stay in Vault: a cut-off removes access, not data.",
	"Anything the workload could read is treated as seen, and the runbook says to rotate it where it was issued.",
	"- The name is never registered again.",
	"The record of cut-off names lives in ES deployment configuration, next to the configured list, not in Vault or SPIRE, so a Vault reset or a new SPIRE datastore does not lose it.",
	"A full re-setup needs that configuration anyway, to know which names to register, so it carries the record over.",
	"ES startup refuses a configuration that lists a recorded name, the setup scripts refuse to register one, and readiness refuses `submit-ready` while SPIRE or Vault holds an entry, role or policy for one, including one made by hand.",
	"So an old grant, an old record or the old secrets under `<name>/shared/` never apply to a different workload.",
	"- Restoring Vault or SPIRE from a backup taken before a cut-off brings back what the cut-off deleted, and a Vault restore also brings back the tokens issued before it.",
	"So the first thing the setup scripts do after such a restore is delete again the role, policy and entry of every recorded name, and readiness refuses `submit-ready` until they have.",
	"- The record is written in step 1, before anything is deleted, so from then on nothing registers the name again, not even a run of the setup scripts meant to repair a cut-off that stopped halfway.",
	"A cut-off that stops after step 1 leaves ES handing the identity to no run, and a token issued before the cut-off keeps the name's secrets until the Vault step runs.",
	"Once the Vault step is done, no token has them.",
	"Running the cut-off again finishes it.",
	"- Readiness refuses `submit-ready` until every step is done.",
	"ES does not start with a configuration that lists a recorded name, which covers step 1.",
	"Readiness refuses while a recorded name has a SPIRE entry, a Vault role or a Vault policy, which covers steps 2 and 4, and while a Nomad job whose task carries a recorded name's container label is not terminal, which covers step 3.",
	"- Every other name keeps working: its Vault role, policy and secrets, its SPIRE entry, its grants and its runs in flight are not touched.",

	// The CI proofs.
	"WI-3's CI integration tests use real SPIRE, Vault, Nomad and Docker.",
	"They register two names, one a prefix of the other (such as `codex` and `codex-agent`), cut off the shorter one with the setup scripts, and prove each outcome:",
	"- ES admits a run with the cut-off identity before the cut-off and refuses the same submission after it with `403 network_access_not_granted`, and ES configuration holds no grant rule that names the identity.",
	"- A Vault token issued before the cut-off can no longer read `<name>/shared/`, and the secrets are still in Vault.",
	"- A Vault login with a JWT-SVID issued before the cut-off fails.",
	"- A run in flight with the identity, started before the cut-off, is cancelled and reaches a terminal status.",
	"- Once the SPIRE agent has seen the deletion, a runtime helper cannot obtain a JWT-SVID for the name's ID.",
	"- A cut-off stopped after each of its four steps leaves readiness refusing `submit-ready`; from step 2 on, a token issued before the cut-off cannot read `<name>/shared/`; and running the cut-off again finishes it.",
	"- Registering the name again is refused; an entry, role or policy made for it by hand makes readiness refuse `submit-ready`; and after a fresh setup from scratch with the same ES configuration, registering it is still refused.",
	"- After Vault is restored from a snapshot taken before the cut-off, readiness refuses `submit-ready` until the setup scripts have deleted the name's role and policy again, and then a token issued before the cut-off cannot read `<name>/shared/`.",
	"- Readiness reports `submit-ready` only once every step is done, and refuses it while a run of the cut-off name is not yet terminal.",
	"- The other name still logs in and reads its own secrets;",
	"ES still admits a run for it, whose runtime helper obtains that name's JWT-SVID and which reads its own secrets; and a run of it in flight keeps running through the cut-off.",

	// The gate.
	"No named identity goes live on any host, the Remote Alpha box or a supported-local host, before these tests pass.",
	"WI-3's box run (section 11.10) also cuts off one throwaway name while one of its runs is in flight, and shows that run found by its label, cancelled and terminal, and readiness back at `submit-ready` once every step is done.",
	"WI-3 adds the cut-off to the runbooks.",
}

// assertSectionIsExactly fails unless text is exactly the sentences joined by
// single spaces. It names the first sentence that is missing, changed or out
// of order, and any text left after the last one.
func assertSectionIsExactly(t *testing.T, label string, text string, sentences []string) {
	t.Helper()

	rest := text
	for i, sentence := range sentences {
		if i > 0 {
			if !strings.HasPrefix(rest, " ") {
				t.Fatalf("%s: expected a space before sentence %d %q, got %q", label, i+1, sentence, clipForMessage(rest))
			}
			rest = rest[1:]
		}
		if !strings.HasPrefix(rest, sentence) {
			t.Fatalf("%s: sentence %d is missing, changed or out of order: want %q, got %q", label, i+1, sentence, clipForMessage(rest))
		}
		rest = rest[len(sentence):]
	}
	if rest != "" {
		t.Fatalf("%s: unexpected text after the last sentence: %q", label, clipForMessage(rest))
	}
}

func clipForMessage(text string) string {
	const limit = 200
	if len(text) > limit {
		return text[:limit] + "..."
	}
	return text
}

// WI-3 issues one identity per named workload. Before any of those
// identities goes live, the owner must be able to cut one of them off, and
// WI-3 must prove it with tests. This test pins that acceptance requirement
// in the F1 decision and in the F1 record, every sentence of it.
func TestWorkstreamFF1WorkloadCutOffIsRequiredOfWI3(t *testing.T) {
	decisionRaw := mustRead(t, ".docs/system_overview/runtime_identity_handoff.md")
	cutOff := compactDocSection(t, decisionRaw, "#### Cutting off one named workload", "### 11.8 Adding per-run identities later")
	posture := compactDocSection(t, decisionRaw, "### 11.7 SPIRE and Vault posture", "#### Cutting off one named workload")

	if strings.Count(decisionRaw, "#### Cutting off one named workload") != 1 {
		t.Fatalf("the F1 decision must hold exactly one cut-off subsection")
	}
	assertSectionIsExactly(t, "F1 cut-off", cutOff, cutOffSentences)

	// Readiness, which the cut-off relies on, sees a Vault object left
	// for a name ES configuration no longer lists.
	assertContainsAll(t, "F1 readiness counts leftover Vault objects", posture,
		"A Vault role or Vault policy left for an identity ES configuration does not list counts as a difference, the same as such an entry.",
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
