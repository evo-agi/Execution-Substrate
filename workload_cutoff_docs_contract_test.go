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
	"1. Record and ES configuration: the name joins the record of cut-off names, then leaves the configured list, and every grant rule that names it is removed, lane included.",
	"ES reads its configuration at startup, so this step ends by restarting ES.",
	"2. Vault: the policy `workload-<name>` is deleted, then the role `workload-<name>`.",
	"3. SPIRE: the name's entry is deleted.",
	"4. Runs in flight: each is cancelled through ES and followed to a terminal status.",

	// Only the step that cancels through ES waits for ES.
	"Steps 2 and 3 wait neither for ES to come back from its restart nor for it to start at all.",
	"Only step 4 waits for ES, because it cancels through ES.",

	// Outcomes.
	"Cutting off a name has these outcomes:",
	"- ES hands the identity to no run.",
	"A run can hold an identity only with a lane, so only with network access, and the network policy runs first (`.docs/execution_lifecycle/contracts.md`, section 5B).",
	"So once the grant rule is gone, lane included, ES refuses a run that held the identity with `403 network_access_not_granted`.",
	"Every delivery that can cause an effect evaluates the grants again with the configuration ES runs with (section 5B), so after the restart a replay, or a prepared run not yet submitted, is refused too.",
	"- A Vault token issued before the cut-off loses access to the name's secrets at once.",
	"Deleting the policy `workload-<name>` is expected to do this, because Vault looks up a token's policies on every request; WI-3's tests are the proof.",
	"If they show that such a token keeps access, WI-3 stops and brings the owner the choice between revoking each such token and accepting access until the role's `token_max_ttl` ends.",
	"- With the role deleted, no Vault login succeeds for the name, including one with a JWT-SVID issued before the cut-off that has not expired yet.",
	"The policy goes before the role, so a cut-off that stops between the two still leaves every token without the name's secrets, a token from a fresh login included.",
	"- SPIRE issues no new JWT-SVID for the name once its agent has seen the deletion, so the runtime helper of a run cannot obtain one (section 11.6).",
	"A JWT-SVID issued earlier stays valid until it expires, but it can no longer log in to Vault.",
	"- A run in flight is one admitted with the identity and not yet terminal.",
	"ES reports in its health the record it started with, and step 4 starts only once ES reports the new record, so no new run in flight can start.",
	"It finds every such run from the Nomad jobs whose task carries the container label of section 11.4, including jobs not yet placed; a job's ID is `exec-<run_id>`.",
	"It cancels each run through ES and reads its status until it is terminal, then searches again until it finds none.",
	"A run that is not terminal within the limit the WI-3 pull request sets is reported by its run ID, and the step fails.",
	"- The name's secrets under `<name>/shared/` stay in Vault: a cut-off removes access, not data.",
	"Anything the workload could read is treated as seen, and the runbook says to rotate it where it was issued.",
	"- The name is never registered again.",
	"The record of cut-off names is a file of its own on the host, next to ES's configuration and outside Vault and SPIRE, so a Vault reset or a new SPIRE datastore does not lose it.",
	"Only the cut-off writes it, and only by adding a name.",
	"ES reads it at startup and refuses to start when it is missing or unreadable, or when ES's configuration lists or grants a recorded name.",
	"The setup scripts refuse to register a recorded name, and readiness refuses `submit-ready` while SPIRE or Vault holds an entry, role or policy for one, including one made by hand.",
	"So an old grant, an old SPIRE entry or the old secrets under `<name>/shared/` never apply to a different workload.",
	"- Putting back or rewriting ES's configuration does not bring a name back.",
	"The ES upgrade's restore and rollback put back an older copy (`scripts/internal/remote_alpha_upgrade_es.py`), and the supported-local setup writes ES's configuration afresh.",
	"Every tool that puts back or writes ES's configuration leaves the record as it is, never puts back an older copy of it and never makes it shorter.",
	"It applies the record to what it writes: it removes every recorded name from the configured list and every grant rule that names one, and says so.",
	"It refuses, changing nothing, when it cannot read the record.",
	"- The record also survives the loss of the host.",
	"The cut-off runs from the owner's own computer and keeps a copy of the record there: it fetches the record after step 1 and fails, saying so, when it cannot write the copy.",
	"A setup from scratch on an empty host takes the owner's copy as an input and refuses to start without one; a host that never cut a name off is given an empty record.",
	"- Restoring Vault or SPIRE from a backup taken before a cut-off brings back what the cut-off deleted, and a Vault restore also brings back the tokens issued before it.",
	"So the setup scripts restore either one with workload traffic to Vault blocked at the host firewall, delete again the role, policy and entry of every recorded name, and only then unblock that traffic.",
	"Every restored token, and every token the restored role issues, is bound to the workload bridge subnet (`token_bound_cidrs`, section 11.7), so none of them can read anything before the re-deletion.",
	"A restore that cannot block that traffic does not start, and readiness refuses `submit-ready` until the re-deletion is done.",
	"- The record is written in step 1, before anything is deleted, so from then on nothing registers the name again, not even a run of the setup scripts meant to repair a cut-off that stopped halfway.",
	"Until ES restarts at the end of step 1, the running ES still hands the identity out; an ES that restarts before the configuration is written refuses to start.",
	"A cut-off that stops after step 1 leaves ES handing the identity to no new run, but the runs in flight keep their lane, and while the Vault role and the SPIRE entry remain, their runtime helper can obtain a new JWT-SVID and log in again.",
	"So they keep reading the name's secrets until step 2 is done, and keep running until step 4 is done.",
	"Once step 2 is done, no token has the secrets.",
	"Running the cut-off again finishes it.",
	"- Readiness refuses `submit-ready` until every step is done.",
	"It refuses while ES's configuration lists or grants a recorded name, or while ES reports a record other than the one on the host, which covers step 1.",
	"It refuses while a recorded name has a Vault role or a Vault policy, which covers step 2, or a SPIRE entry, which covers step 3, and while a Nomad job whose task carries a recorded name's container label is not terminal, which covers step 4.",
	"- Every other name keeps working: its Vault role, policy and secrets, its SPIRE entry, its grants and its runs in flight are not touched.",

	// The proofs WI-3's CI must give.
	"WI-3's CI integration tests use real SPIRE, Vault, Nomad and Docker.",
	"They register two names, one a prefix of the other (such as `codex` and `codex-agent`), cut off the shorter one with the setup scripts, and prove each outcome:",
	"- ES admits a run with the cut-off identity before the cut-off and refuses the same submission after it with `403 network_access_not_granted`, and ES configuration holds no grant rule that names the identity.",
	"- A run prepared before the cut-off and submitted after it is refused with `403 network_access_not_granted`.",
	"- ES refuses to start when its configuration lists or grants a recorded name, and when the record is missing or unreadable.",
	"- A Vault token issued before the cut-off can no longer read `<name>/shared/`, and the secrets are still in Vault.",
	"- A Vault login with a JWT-SVID issued before the cut-off fails.",
	"- Once the SPIRE agent has seen the deletion, a runtime helper cannot obtain a JWT-SVID for the name's ID.",
	"- A run in flight with the identity, started before the cut-off, is cancelled and reaches a terminal status; so does a job of the name not yet placed; and a run that does not reach a terminal status within the limit is reported by its run ID and fails the step.",
	"- A cut-off with a run in flight, stopped after each of its first three steps and between the policy and the role, leaves readiness refusing `submit-ready`.",
	"Stopped between the policy and the role, neither a token issued before the cut-off nor a token from a fresh login can read `<name>/shared/`; from step 2 on, a token issued before the cut-off cannot either.",
	"Running the cut-off again finishes it.",
	"- A cut-off whose ES restart fails still deletes the Vault policy and role and the SPIRE entry, and readiness refuses `submit-ready` until ES runs with the new record and step 4 is done.",
	"- Registering the name again is refused, and an entry, role or policy made for it by hand makes readiness refuse `submit-ready`.",
	"- After ES's configuration from before the cut-off is put back by the ES upgrade's restore, and again by its rollback, and after the supported-local setup writes it afresh, the name stays cut off: the configuration neither lists nor grants it, the record is unchanged, a run asking for the identity is refused, and registering the name is refused.",
	"A tool that cannot read the record refuses and changes nothing.",
	"- On an empty host, a setup from scratch given the owner's copy of the record refuses to register the name, and one given no copy refuses to start.",
	"- While Vault is restored from a snapshot taken before the cut-off, a workload container reaches no Vault until the setup scripts have deleted the name's role and policy again, and readiness refuses `submit-ready` until then; afterwards a token issued before the cut-off cannot read `<name>/shared/`.",
	"- After SPIRE is restored from a backup taken before the cut-off, readiness refuses `submit-ready` until the setup scripts have deleted the name's entry again, and then a runtime helper cannot obtain a JWT-SVID for the name's ID.",
	"- Readiness reports `submit-ready` only once every step is done, and refuses it while a run of the cut-off name is not yet terminal.",
	"- The other name still logs in and reads its own secrets; ES still admits a run for it, whose runtime helper obtains that name's JWT-SVID and which reads its own secrets; and a run of it in flight keeps running through the cut-off.",

	// The gate, the box run and the runbook.
	"No named identity goes live on any host, the Remote Alpha box or a supported-local host, before these tests pass.",
	"WI-3's box run (section 11.10) also cuts off one throwaway name while one of its runs is in flight, and shows that run found by its label, cancelled and terminal, and readiness back at `submit-ready` once every step is done.",
	"It then rolls ES back with the upgrade's rollback and shows the name still cut off.",
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
