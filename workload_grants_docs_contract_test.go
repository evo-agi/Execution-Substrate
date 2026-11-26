package executionsubstrate_test

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The F1 decision of Workstream F (named workload identities and workload
// grants) is written down before any code changes, in this order: PLANS.md,
// the runtime identity handoff decision, the workload grants contract, and
// the pages that point to them. These tests pin the decisions that later pull
// requests implement, so that a change to one of them is a visible change to
// the contract and not drift.

func TestWorkstreamFF1NamedWorkloadIdentityDecisionIsDocumented(t *testing.T) {
	decisionRaw := mustRead(t, ".docs/system_overview/runtime_identity_handoff.md")
	f1 := compactDocSection(t, decisionRaw, "## 11. F1 decision: named workload identities and workload grants", "### 11.10 Delivery")
	delivery := compactDocSection(t, decisionRaw, "### 11.10 Delivery", "")

	assertContainsAll(t, "F1 status", f1,
		"F1 is the next behavior-changing Workstream F slice.",
		"Until the pull request that lands a part merges, sections 1 to 10 and the other `.docs/` pages describe current behavior for that part, and this section is the target it implements.",
		"Each of those pull requests moves the matching current-behavior text to the new rule in the same change.",
	)

	assertContainsAll(t, "F1 names and SPIFFE ID layout", f1,
		"A workload identity name is a single SPIFFE path segment of 1 to 63 characters from `a-z`, `0-9` and `-`, starting with a letter or a digit.",
		"A named identity is `spiffe://execution.internal/workload/<name>`.",
		"`spiffe://execution.internal/workload/<name>/run/<run_id>` is reserved for per-run identities. F1 registers none. Every other path under `workload/` is reserved and unused.",
		"The shared ID `spiffe://execution.internal/workload` is retired when the identity part of F1 lands.",
		"The caller authentication contract refuses every caller whose path is `workload` or starts with `workload/`",
		"for ARS, AGS, EGS, CGS and ES alike, including the reserved per-run paths.",
	)

	assertContainsAll(t, "F1 owner picks the name", f1,
		"A rule matches exactly on four facts: the publisher principal (`claims.package.publication.invoker.principal`, which AGS takes from its authenticated caller), the evidence signer key ID (`seal.key_id`), the artifact type, and the effective runtime profile name.",
		"Publishers do not request a name. F1 adds no identity claim to signed evidence",
		"ES does not create SPIRE entries, Vault roles or Vault policies, and holds no SPIRE or Vault administrative access.",
		"ES startup refuses a grant that names an identity missing from the configured list.",
	)

	assertContainsAll(t, "F1 realization seam", f1,
		"Admission produces scheduler-neutral results only: an identity name or none, and an egress lane name or none.",
		"Runtime realization alone turns a name into the expected SPIFFE ID string, the container label `execution-substrate.workload-identity=<name>`, the Vault role `workload-<name>`, and the environment the helper and the workload receive.",
		"A guard test fails if grant or admission-policy code names Nomad, Docker or the container label.",
		"F1 adds no scheduler plug-in interface. Nomad remains the lifecycle authority",
	)

	assertContainsAll(t, "F1 runs without an identity and the helper check", f1,
		"no runtime helper endpoint, no `EXEC_WORKLOAD_IDENTITY_ENDPOINT`, no helper-private SPIRE socket mount, no runtime-identity tmpfs, and no workload-zone Vault environment.",
		"is refused at admission with `403 workload_identity_not_granted` when no identity is granted.",
		"ES startup refuses a rule that pairs an identity with a lane that does not.",
		"The helper refuses to serve the endpoint unless the JWT-SVID that SPIRE returns names exactly that ID. A mismatch is task-fatal before the workload starts.",
	)

	assertContainsAll(t, "F1 SPIRE and Vault posture", f1,
		"selectors `docker:label:execution-substrate.workload-identity:<name>` and `unix:uid:0`.",
		"The broad entry that gives `spiffe://execution.internal/workload` to every root process is removed in the same change.",
		"Readiness refuses `submit-ready` while any `workload` entry uses only `unix` selectors, lacks the label selector, or names an identity that ES configuration does not list.",
		"Each name gets a Vault JWT role and a Vault policy, both named `workload-<name>`, with `bound_subject` set to the name's exact SPIFFE ID and explicit `token_ttl`, `token_max_ttl` and `token_bound_cidrs`.",
		"A name's secrets live under `<name>/shared/` in the workload secret mount. `<name>/runs/` stays free for later per-run secrets.",
		"The workload-zone Vault runtime config moves to a version 2 blob without a single `auth_role`",
	)

	assertContainsAll(t, "F1 per-run path and non-changes", f1,
		"F1 keeps a path to per-run identities that adds pieces and removes no code:",
		"`EXEC_WORKLOAD_IDENTITY_ENDPOINT` stays the workload-visible discovery contract, and the raw SPIRE socket stays helper-private.",
		"The helper still starts as `0:0`, the Nomad task user is still `0:0`, and the workload still runs as fixed `10000:10000` with no supplemental groups.",
		"SPIRE issues JWT-SVIDs and Vault issues tokens, secrets and leases. ES brokers none of them.",
		"A `control-plane-normal-shell/v1` run always has an identity, so every field CP reads today stays present.",
	)

	for _, row := range []string{
		"| WI-1 | This decision in `PLANS.md` and `.docs/`, with doc-contract tests. No behavior change. |",
		"| WI-2 | Network grants:",
		"| WI-3a | The caller authentication contract refuses `workload` caller paths |",
		"| WI-3 | Named identities:",
		"| WI-4 | Egress lanes:",
		"| WI-5 | Durable replay and operational formats carry the identity name, the realized SPIFFE ID string and the lane name",
	} {
		assertContainsAll(t, "F1 delivery table", delivery, row)
	}
	assertContainsAll(t, "F1 delivery gates", delivery,
		"| Audit, red-team, a box run with scripted rollback, and the merge gate |",
		"before D3 makes those formats live state |",
	)
}

func TestWorkloadGrantsContractIsDocumented(t *testing.T) {
	lifecycleRaw := mustRead(t, ".docs/execution_lifecycle/contracts.md")
	grants := compactDocSection(t, lifecycleRaw, "## 5B. Workload grants contract", "## 6. Submit contract")

	assertContainsAll(t, "workload grants status", grants,
		"This contract is decided and not yet implemented. The network part lands with WI-2 and the identity part with WI-3",
		"The pull request that lands a part moves that text to this contract in the same change.",
	)

	assertContainsAll(t, "workload grants configuration", grants,
		"`admission_policy.workload_grants`",
		"Requests cannot carry grants, CP does not define or supply them, and IM remains readiness, provenance and diagnostics only.",
		"No setting turns grants off. A configuration without `workload_grants`, or with no rules, admits only runs that request no network and whose runtime profile needs no credential, and those runs receive no identity.",
		"A name is 1 to 63 characters from `a-z`, `0-9` and `-`, starting with a letter or a digit.",
		"Until WI-4, the only accepted lane is `unrestricted` with `reaches_workload_vault=true`, realized as the current `bridge` network mode under the host firewall",
		"four required match fields, compared byte for byte:",
		"`runtime_profile` (the effective profile name, `static-script/default` when the request names none)",
		"ES startup refuses: more than 32 rules; a duplicate rule ID; two rules with the same four match fields, so at most one rule matches a run;",
		"and a rule that grants an identity without a lane that reaches the workload-zone Vault.",
	)

	assertContainsAll(t, "workload grants evaluation", grants,
		"They run on `:prepare` and on `:submit` alike",
		"The effective lane is none when signed `network_access` is false, whatever the rule grants.",
		"is refused by `execution-substrate.admission.network-grant/v1` with `403`, reason code `network_access_not_granted` and safe message `network access not granted by admission policy`.",
		"is refused by `execution-substrate.admission.workload-identity-grant/v1` with `403`, reason code `workload_identity_not_granted` and safe message `workload identity not granted by admission policy`.",
		"The network policy runs first, so a run refused by both reports `network_access_not_granted`.",
		"A failure to read the workload-zone Vault config remains an unavailable dependency, not a grant denial.",
		"Every delivery that can cause an effect evaluates the grants again with the configuration ES runs with at that time, and refuses when a grant was removed or narrowed. Read-only receipt recovery does not evaluate them.",
	)

	assertContainsAll(t, "workload grants temporary edge and its removal condition", grants,
		"While any rule grants the lane `unrestricted`, readiness reports `workload_egress_unrestricted=true`. This is a `Temporary compatibility edge`",
		"WI-4 removes the value, and from then on ES startup refuses a configuration that uses it.",
	)

	assertContainsAll(t, "workload grants guardrails", grants,
		"Matching is exact. Grants do not add regex, glob, prefix matching, Boolean policy logic, OPA/Rego, a DSL, customer policy bundles, an external evaluator, request-supplied grants, CP-defined grants, user-defined reason codes or user-defined API messages.",
		"Grant and admission-policy code names no scheduler or container term",
		"A grant never gives a network to a run that did not request one.",
		"Grants are not a sandbox, an egress filter or a firewall.",
	)

	c6 := compactText(lifecycleRaw)
	assertContainsAll(t, "lifecycle C6 workload-grant follow-up", c6,
		"The C6 workload-grant follow-up, decided in Workstream F slice F1, adds two built-in ES admission policies that read owner grants from ES deployment/admin configuration",
	)
}

func TestWorkstreamFF1IsPlannedAndPointedTo(t *testing.T) {
	plansRaw := mustRead(t, "PLANS.md")
	workstreamF := compactDocSection(t, plansRaw, "### Workstream F - Runtime Identity Handoff Reset", "## Remote Alpha Hardening History and Current Retirement")
	f1 := compactDocSection(t, workstreamF, "F1 - Named Workload Identities And Workload Grants:", "Dependencies:")
	plans := compactText(plansRaw)

	assertContainsAll(t, "PLANS Workstream F F1", f1,
		"F1 is the next behavior-changing Workstream F slice, approved by the project owner and not yet implemented. The decision is section 11 of `.docs/system_overview/runtime_identity_handoff.md`; the workload grants it adds to C6 are section 5B of `.docs/execution_lifecycle/contracts.md`.",
		"`spiffe://execution.internal/workload/<name>`, with its own SPIRE entry (Docker label selector plus `unix:uid:0`) and its own Vault role and policy.",
		"The entry that gives `spiffe://execution.internal/workload` to every root process on the host is removed. ES picks the name from owner grant rules and holds no SPIRE or Vault administrative access; publishers request no name.",
		"Until lanes land, the only lane is `unrestricted`, a `Temporary compatibility edge` that readiness reports as `workload_egress_unrestricted=true`; its removal condition is WI-4.",
		"Workload identities are never callers, a run without an identity grant gets no identity handoff, admission decides in names only, and runtime realization alone maps names to Nomad and Docker values.",
		"`workload/<name>/run/<run_id>` is reserved so per-run identities can be added later without removing code.",
		"WI-5 the durable format revision, before D3 makes those formats live state.",
		"It does not mark full Workstream F complete.",
	)

	assertContainsAll(t, "PLANS C6 workload-grant follow-up and edges", plans,
		"The C6 workload-grant follow-up is part of Workstream F slice F1 and is not yet implemented: two built-in policies read exact-match owner grants from ES deployment/admin configuration, keep every absence listed for the configurable-input follow-up, and cannot be turned off.",
		"Workstream F slice F1 removes the broad root selector posture and the one shared Vault role with WI-3; it keeps the other three.",
		"Workstream F slice F1 is the separately documented redesign for the broad root selector posture and the per-workload Vault handoff.",
		"Workstream F slice F1 builds on this firewall rather than replacing it.",
	)

	contractsRaw := mustRead(t, ".docs/system_overview/contracts.md")
	callerAuth := compactDocSection(t, contractsRaw, "## 3A. Caller Authentication Contract", "## 4. Workload-Zone Vault Runtime-Config Contract")
	assertContainsAll(t, "caller authentication F1 rule", callerAuth,
		"Workstream F slice F1 adds one rule to this section when WI-3a lands",
		"a caller whose path is `workload` or starts with `workload/` has no caller identity, at every service.",
	)
	esContract := compactDocSection(t, contractsRaw, "## 7. ES Admission And Execution Contract", "## 8.")
	assertContainsAll(t, "ES network mapping F1 change", esContract,
		"From WI-2, a run that requests the network also needs an owner grant in ES configuration and is otherwise refused with `network_access_not_granted`. From WI-4, a granted run joins its egress lane's network instead of `bridge`.",
	)
	runtimeIdentity := compactDocSection(t, contractsRaw, "## 10. Runtime Identity Handoff Contract", "## 11. Temporary Compatibility Edges")
	assertContainsAll(t, "runtime identity contract F1 pointer", runtimeIdentity,
		"The next slice, F1, is decided and recorded in section 11 of `runtime_identity_handoff.md`",
		"It lands with WI-3. Until then this section describes current behavior.",
	)

	admissionModel := compactText(mustRead(t, ".docs/execution_lifecycle/es_execution_admission_model.md"))
	assertContainsAll(t, "admission model workload grants", admissionModel,
		"The workload-grant follow-up to C6 is decided in Workstream F slice F1",
		"These grants add no policy language: the guardrails for configurable inputs below apply to them unchanged.",
		"Do not let workload grants become prefix, glob or regex matching, Boolean rule logic, a publisher-requested identity, an identity claim in signed evidence, a switch that turns grants off, or a path for ES to create SPIRE entries, Vault roles or Vault policies.",
	)

	configuration := compactText(mustRead(t, ".docs/system_overview/configuration.md"))
	assertContainsAll(t, "configuration workload grants", configuration,
		"`admission_policy.workload_grants` is decided in Workstream F slice F1 and not yet implemented; ES refuses the key until WI-2 lands.",
		"Workstream F slice F1 is that replacement (`.docs/system_overview/runtime_identity_handoff.md`, section 11)",
	)

	remoteAlpha := compactText(mustRead(t, ".docs/system_overview/remote_supported_host_alpha.md"))
	assertContainsAll(t, "remote alpha F1 pointers", remoteAlpha,
		"F1 keeps its container rules as a second wall under the egress lanes",
		"replaces it with one entry per named workload, selected by a Docker container label and `unix:uid:0`, and one Vault role and policy per name.",
	)
}

// TestWorkloadGrantsDocsSayNotYetImplementedOnlyWhileTrue keeps the "not yet
// implemented" status lines honest. The pull request that implements a part
// adds its reason code to ES code; this test then fails until that pull
// request also moves the docs from "decided" to the current rule.
func TestWorkloadGrantsDocsSayNotYetImplementedOnlyWhileTrue(t *testing.T) {
	statusLine := "This contract is decided and not yet implemented."
	grants := compactDocSection(t, mustRead(t, ".docs/execution_lifecycle/contracts.md"), "## 5B. Workload grants contract", "## 6. Submit contract")
	if !strings.Contains(grants, statusLine) {
		return
	}

	markers := []string{
		"network_access_not_granted",
		"workload_identity_not_granted",
		"workload_grants",
		"execution-substrate.admission.network-grant/v1",
		"execution-substrate.admission.workload-identity-grant/v1",
	}
	found := map[string]string{}
	for _, root := range []string{"es", "internal", "cmd"} {
		err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if entry.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			for _, marker := range markers {
				if _, seen := found[marker]; !seen && strings.Contains(string(data), marker) {
					found[marker] = path
				}
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", root, err)
		}
	}
	for _, marker := range markers {
		if path, ok := found[marker]; ok {
			t.Errorf("%s names %q, but section 5B of .docs/execution_lifecycle/contracts.md still says %q: move the implemented part of the docs to the current rule in the same change", path, marker, statusLine)
		}
	}
}
