package executionsubstrate_test

import (
	"fmt"
	"io/fs"
	"path/filepath"
	"regexp"
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

	// What F1 changes is stated against the time before F1, so landing a
	// part of F1 leaves it true.
	assertContainsAll(t, "F1 starting point", f1,
		"Before F1: - every workload run received the same SPIFFE ID, `spiffe://execution.internal/workload`, and logged in to Vault with one shared role, so any workload could read any other workload's secrets;",
		"- the SPIRE registration for that ID matched any root process on the host (`unix:uid:0` plus `unix:gid:0`), inside a container or not;",
		"- the publisher's signed `network_access` alone decided whether a run got a network.",
	)

	assertContainsAll(t, "F1 names and SPIFFE ID layout", f1,
		"A workload identity name is a single SPIFFE path segment of 1 to 63 characters from `a-z`, `0-9` and `-`, starting with a letter or a digit.",
		"A named identity is `spiffe://execution.internal/workload/<name>`.",
		"`spiffe://execution.internal/workload/<name>/run/<run_id>` is reserved for per-run identities. F1 registers none. Every other path under `workload/` is reserved and unused.",
		"The shared ID `spiffe://execution.internal/workload` is retired when the identity part of F1 lands.",
		"The caller authentication contract refuses every caller whose path is `workload` or starts with `workload/`",
		"for ARS, AGS, EGS, CGS and ES alike, including the reserved per-run paths.",
		"This part is implemented: WI-3a landed it, and the refusal ignores letter case.",
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
		"Readiness refuses `submit-ready` while any `workload` entry uses only `unix` selectors or lacks the label selector, or while the registered names differ from the names ES configuration lists, in either direction: an entry that names an identity ES configuration does not list, and a listed identity with no registered entry, Vault role or Vault policy.",
		"Each name gets a Vault JWT role and a Vault policy, both named `workload-<name>`, with `bound_subject` set to the name's exact SPIFFE ID and explicit `token_ttl`, `token_max_ttl` and `token_bound_cidrs`.",
		"A name's secrets live under `<name>/shared/` in the workload secret mount. `<name>/runs/` stays free for later per-run secrets.",
		"The workload-zone Vault runtime config moves to a version 2 blob without a single `auth_role`",
	)

	assertContainsAll(t, "F1 per-run path and non-changes", f1,
		"F1 keeps a path to per-run identities that adds pieces and removes no code:",
		"`EXEC_WORKLOAD_IDENTITY_ENDPOINT` stays the workload-visible discovery contract, and the raw SPIRE socket stays helper-private.",
		"The helper still starts as `0:0`, the Nomad task user is still `0:0`, and the workload still runs as fixed `10000:10000` with no supplemental groups.",
		"SPIRE issues JWT-SVIDs and Vault issues tokens, secrets and leases. ES brokers none of them.",
		"The ES public execution request DTO, the response DTOs apart from their `authority_handoff` field, `GET /v1/executions:contract`, `outcome_evidence`, and M6 support-bundle inputs keep their shapes.",
		"`authority_handoff` stays non-secret evidence, and F1 changes its shape.",
		"so the identity pull request changes them only with a documented replacement handoff vocabulary and an explicit compatibility and versioning plan, for CP and IM consumers alike.",
		"For a run without an identity, including a `static-script/default` run whose grant names no identity, `identity_handoff.mode` is `none`, and the fields that describe an endpoint or a Vault login are absent: that run's response loses fields it carries today.",
		"A `control-plane-normal-shell/v1` run always has an identity, so it keeps every field it carries today.",
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
		"Until WI-4, the only accepted lane is `unrestricted` with `reaches_workload_vault=true`, realized as the current `bridge` network mode. On the Remote Supported Host Alpha box that network sits under the host firewall",
		"Supported-local hosts have no host firewall, so there `unrestricted` is the full `bridge` network, which reaches the local network and host services.",
		"four required match fields, compared byte for byte:",
		"`runtime_profile` (the effective profile name, `static-script/default` when the request names none)",
		"The publisher principal is the one `claims.package.publication` claim ES admission reads, and only as this match fact: it does not become ES request or response grammar, and no other publication claim reaches admission;",
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
		"Every delivery that can cause an effect evaluates the grants again with the configuration ES runs with at that time, and refuses when a grant was removed or narrowed. Read-only receipt recovery does not evaluate them. This settles, for workload grants only, the question that `.docs/execution_lifecycle/submit_idempotency_correlation_and_recovery.md` section 11 leaves open for mutable admission policy.",
	)

	assertContainsAll(t, "workload grants temporary edge and its removal condition", grants,
		"While any rule grants the lane `unrestricted`, readiness reports `workload_egress_unrestricted=true`. This is a `Temporary compatibility edge`",
		"a granted run reaches the internet without an egress filter of its own, through the host firewall on the Remote Supported Host Alpha box and through the full `bridge` network on supported-local hosts.",
		"WI-4 removes the value, and from then on ES startup refuses a configuration that uses it.",
	)

	assertContainsAll(t, "workload grants guardrails", grants,
		"Matching is exact. Grants do not add regex, glob, prefix matching, Boolean policy logic, OPA/Rego, a DSL, customer policy bundles, an external evaluator, request-supplied grants, CP-defined grants, user-defined reason codes or user-defined API messages.",
		"Grant and admission-policy code names no scheduler or container term",
		"A grant never gives a network to a run that did not request one.",
		"Grants are not a sandbox, an egress filter or a firewall. Until WI-4, a granted run's network is the current `bridge` network: under the host firewall on the Remote Supported Host Alpha box, and without one on supported-local hosts.",
	)

	idempotency := compactDocSection(t, mustRead(t, ".docs/execution_lifecycle/submit_idempotency_correlation_and_recovery.md"), "## 11. Replay, Authorization, And Admission", "## 12. Retention And Expiry")
	assertContainsAll(t, "idempotency contract points to the workload grants answer", idempotency,
		"Whether mutable admission policy is re-evaluated for read-only receipt recovery remains open.",
		"Workload grants settle this question for themselves only: read-only receipt recovery does not evaluate them, and every delivery that can cause an effect does (`.docs/execution_lifecycle/contracts.md`, section 5B). It stays open for every other mutable admission policy.",
	)

	c6 := compactText(lifecycleRaw)
	assertContainsAll(t, "lifecycle C6 workload-grant follow-up", c6,
		"The C6 workload-grant follow-up, decided in Workstream F slice F1, adds two built-in ES admission policies that read owner grants from ES deployment/admin configuration",
	)
}

func TestWorkstreamFF1IsPlannedAndPointedTo(t *testing.T) {
	plansRaw := mustRead(t, "PLANS.md")
	workstreamF := compactDocSection(t, plansRaw, "### Workstream F - Runtime Identity Handoff Reset", "## Host And Runtime Boundary Rules")
	f1 := compactDocSection(t, workstreamRecord(t, "F"), "F1 - Named Workload Identities And Workload Grants:", "")
	plans := compactText(plansRaw)

	assertContainsAll(t, "PLANS Workstream F points to its record and F1", workstreamF,
		"the F1 named workload identities and workload grants slice",
		"[`"+standingWorkstreamsPath+"` § Workstream F decision record]("+standingWorkstreamsPath+"#workstream-f-decision-record)",
	)
	assertContainsAll(t, "Workstream F record F1", f1,
		"F1 is the next behavior-changing Workstream F slice, approved by the project owner. Its caller refusal (WI-3a) is implemented; the rest is not yet implemented. The decision is section 11 of `.docs/system_overview/runtime_identity_handoff.md`; the workload grants it adds to C6 are section 5B of `.docs/execution_lifecycle/contracts.md`.",
		"It closes two gaps that existed before F1: every workload run shared one SPIFFE ID and one Vault role, so any workload could read any other workload's secrets; and the publisher's signed `network_access` alone decided network access.",
		"`spiffe://execution.internal/workload/<name>`, with its own SPIRE entry (Docker label selector plus `unix:uid:0`) and its own Vault role and policy.",
		"The entry that gives `spiffe://execution.internal/workload` to every root process on the host is removed. ES picks the name from owner grant rules and holds no SPIRE or Vault administrative access; publishers request no name.",
		"Until lanes land, the only lane is `unrestricted`, a `Temporary compatibility edge` that readiness reports as `workload_egress_unrestricted=true`; its removal condition is WI-4.",
		"Workload identities are never callers, a run without an identity grant gets no identity handoff, admission decides in names only, and runtime realization alone maps names to Nomad and Docker values.",
		"`workload/<name>/run/<run_id>` is reserved so per-run identities can be added later without removing code.",
		"WI-5 the durable format revision, before D3 makes those formats live state.",
		"It does not mark full Workstream F complete.",
	)

	assertContainsAll(t, "Workstream C record C6 workload-grant follow-up", workstreamRecord(t, "C"),
		"The C6 workload-grant follow-up is part of Workstream F slice F1 and is not yet implemented: two built-in policies read exact-match owner grants from ES deployment/admin configuration, keep every absence listed for the configurable-input follow-up, and cannot be turned off.",
	)
	assertContainsAll(t, "hardening tranche F1 edges", hostRuntimeSection(t, raHardeningHeading),
		"Workstream F slice F1 removes the broad root selector posture and the one shared Vault role with WI-3; it keeps the other three.",
	)
	assertContainsAll(t, "host network slice F1 firewall", hostRuntimeSection(t, raHostNetworkHeading),
		"Workstream F slice F1 builds on this firewall rather than replacing it.",
	)
	assertContainsAll(t, "PLANS privilege-boundary track F1 redesign", plans,
		"Workstream F slice F1 is the separately documented redesign for the broad root selector posture and the per-workload Vault handoff.",
	)

	contractsRaw := mustRead(t, ".docs/system_overview/contracts.md")
	sharedKernel := compactDocSection(t, contractsRaw, "## 3. Shared Cross-Service Kernel", "## 3A. Caller Authentication Contract")
	assertContainsAll(t, "shared kernel publication claim read by workload grants", sharedKernel,
		"`claims.package.publication` remains AGS-owned publish-time meaning carried inside the signed record; ES must not treat those publication claims as ES public admission grammar.",
		"From WI-2, workload grants (`.docs/execution_lifecycle/contracts.md`, section 5B) read one of them, `claims.package.publication.invoker.principal`, as an exact-match fact against ES configuration; that read adds nothing to ES request or response grammar, and no other publication claim reaches ES admission.",
	)
	callerAuth := compactDocSection(t, contractsRaw, "## 3A. Caller Authentication Contract", "## 4. Workload-Zone Vault Runtime-Config Contract")
	assertContainsAll(t, "caller authentication workload rule", callerAuth,
		"A caller whose path starts with the segment `workload`, in any letter case, has no caller identity, at every service.",
		"Workload identities exist so that workloads can log in to the workload-zone Vault; they are never callers, and a later design that lets a workload call a service must change this rule explicitly.",
		"A configured prefix whose first segment is `workload`, in any letter case, is refused at startup like any other prefix no caller could match, with its own message, and `id.conf` loading refuses a workload identity as a principal the same way.",
		"A path that only contains the word later, such as `service/workload`, or whose first segment is longer, such as `workloads`, is not affected.",
		"The comparison ignores letter case on purpose, so no configuration can name a workload identity in another letter case. It closes letter-case variants only: a different word, such as `workloads/x` or `work-load/x`, is a different SPIFFE ID and stays a valid path.",
	)
	// Every page that restates the caller identity or the allowlist-prefix
	// rule restates the workload exclusion too.
	esContractPrefixes := compactDocSection(t, contractsRaw, "## 7. ES Admission And Execution Contract", "## 8.")
	assertContainsAll(t, "ES section 7 restates the workload prefix refusal", esContractPrefixes,
		"no `.` or `..` segment, and no first segment `workload` in any letter case, and every segment uses only `A-Z`, `a-z`, `0-9`, `.`, `-`, and `_`.",
		"and so is a workload prefix such as `workload/codex-agent`.",
	)
	lifecycleCallerAuthorization := compactDocSection(t, mustRead(t, ".docs/execution_lifecycle/contracts.md"), "## 4. Caller authorization contract", "## 5.")
	assertContainsAll(t, "lifecycle caller authorization restates the workload exclusion", lifecycleCallerAuthorization,
		"that URI is a conforming SPIFFE ID with a path in the trust domain `execution.internal` whose first segment is not `workload` in any letter case.",
		"or a workload identity such as `spiffe://execution.internal/workload/codex-agent`, is `401` before allowlist matching.",
		"no `.` or `..` segment, and no first segment `workload` in any letter case,",
	)
	assertContainsAll(t, "PLANS restates the workload exclusion", plans,
		"exactly one URI SAN that is a conforming SPIFFE ID in the trust domain `execution.internal` and not a workload identity, identifies a caller;",
		"a prefix must be a canonical SPIFFE ID path of at least two segments whose first segment is not `workload` in any letter case, and a prefix that fails the rule matches nothing.",
	)
	assertContainsAll(t, "configuration lists the workload prefix refusal", compactText(mustRead(t, ".docs/system_overview/configuration.md")),
		"- A prefix whose first segment is `workload`, in any letter case, such as `workload/codex-agent`, is rejected: workload identities are never callers (`contracts.md` section 3A).",
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

// The parts of F1 land in separate pull requests. While a part has not
// landed, PLANS.md and .docs/ say so in status sentences; the pull request
// that lands a part puts one of its markers into ES Go code and moves its
// status sentences to the current rule in the same change. Every status
// sentence about F1 must be listed in f1StatusSentences with the parts it
// speaks for, so a reworded or added status sentence fails until it is
// classified.
var f1PartMarkers = map[string][]string{
	"network grants (WI-2)": {
		"network_access_not_granted",
		"execution-substrate.admission.network-grant/v1",
		"workload_grants",
	},
	"identity grants (WI-3)": {
		"workload_identity_not_granted",
		"execution-substrate.admission.workload-identity-grant/v1",
		"execution-substrate.workload-identity",
	},
	"caller refusal (WI-3a)": {
		"workload identities are never callers",
	},
}

var f1StatusSentences = []struct {
	file     string
	sentence string
	parts    []string
}{
	{standingWorkstreamsPath, "The C6 workload-grant follow-up is part of Workstream F slice F1 and is not yet implemented",
		[]string{"network grants (WI-2)", "identity grants (WI-3)"}},
	{standingWorkstreamsPath, "Its caller refusal (WI-3a) is implemented; the rest is not yet implemented.",
		[]string{"network grants (WI-2)", "identity grants (WI-3)"}},
	{".docs/execution_lifecycle/contracts.md", "They are not yet implemented: the network policy lands with WI-2 and the identity policy with WI-3.",
		[]string{"network grants (WI-2)", "identity grants (WI-3)"}},
	{".docs/execution_lifecycle/contracts.md", "This contract is decided and not yet implemented.",
		[]string{"network grants (WI-2)", "identity grants (WI-3)"}},
	{".docs/execution_lifecycle/contracts.md", "The network part lands with WI-2 and the identity part with WI-3",
		[]string{"network grants (WI-2)", "identity grants (WI-3)"}},
	{".docs/execution_lifecycle/es_execution_admission_model.md", "The workload-grant follow-up to C6 is decided in Workstream F slice F1 (`.docs/system_overview/runtime_identity_handoff.md`, section 11) and is not yet implemented.",
		[]string{"network grants (WI-2)", "identity grants (WI-3)"}},
	{".docs/execution_lifecycle/es_execution_admission_model.md", "(reason code `network_access_not_granted`, lands with WI-2)",
		[]string{"network grants (WI-2)"}},
	{".docs/execution_lifecycle/es_execution_admission_model.md", "(reason code `workload_identity_not_granted`, lands with WI-3)",
		[]string{"identity grants (WI-3)"}},
	{".docs/system_overview/configuration.md", "It lands with WI-3",
		[]string{"identity grants (WI-3)"}},
	{".docs/system_overview/configuration.md", "`admission_policy.workload_grants` is decided in Workstream F slice F1 and not yet implemented; ES refuses the key until WI-2 lands.",
		[]string{"network grants (WI-2)"}},
	{".docs/system_overview/contracts.md", "Workstream F slice F1 adds one rule to this section when WI-3a lands",
		[]string{"caller refusal (WI-3a)"}},
	{".docs/system_overview/contracts.md", "Until WI-3a lands, no allowlist or `id.conf`",
		[]string{"caller refusal (WI-3a)"}},
	{".docs/system_overview/contracts.md", "From WI-2, a run that requests the network also needs an owner grant",
		[]string{"network grants (WI-2)"}},
	{".docs/system_overview/contracts.md", "From WI-2, workload grants (`.docs/execution_lifecycle/contracts.md`, section 5B) read one of them",
		[]string{"network grants (WI-2)"}},
	{".docs/system_overview/contracts.md", "It lands with WI-3.",
		[]string{"identity grants (WI-3)"}},
	{".docs/system_overview/remote_supported_host_alpha.md", "It lands with WI-3, with a box run and scripted rollback.",
		[]string{"identity grants (WI-3)"}},
}

type f1StatusSentence struct {
	file     string
	sentence string
}

var (
	f1StatusPhrase = regexp.MustCompile(`not yet implemented|\b(?:[Ll]ands with|[Uu]ntil|[Ff]rom|[Ww]hen) WI-(?:2|3a|3)\b`)
	f1Term         = regexp.MustCompile(`WI-|\bF1\b|[Ww]orkload grant|workload_grants|[Ww]orkload identit`)
)

// scanF1StatusSentences returns every sentence of PLANS.md and .docs/ that
// says a part of F1 has not landed: a sentence with a status phrase in a
// Markdown paragraph, list item or table row that mentions F1. A sentence is
// read within its block.
func scanF1StatusSentences(t *testing.T) []f1StatusSentence {
	t.Helper()
	files := []string{"PLANS.md"}
	err := filepath.WalkDir(".docs", func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !entry.IsDir() && strings.HasSuffix(path, ".md") {
			files = append(files, filepath.ToSlash(path))
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk .docs: %v", err)
	}
	var found []f1StatusSentence
	for _, file := range files {
		for _, block := range markdownBlocks(mustRead(t, file)) {
			block = compactText(block)
			if !f1Term.MatchString(block) {
				continue
			}
			for _, sentence := range strings.SplitAfter(block, ". ") {
				sentence = strings.TrimSpace(sentence)
				if f1StatusPhrase.MatchString(sentence) {
					found = append(found, f1StatusSentence{file: file, sentence: sentence})
				}
			}
		}
	}
	return found
}

// markdownBlocks splits Markdown into paragraphs, list items, table rows and
// headings.
func markdownBlocks(doc string) []string {
	var blocks []string
	var current []string
	flush := func() {
		if len(current) > 0 {
			blocks = append(blocks, strings.Join(current, " "))
			current = nil
		}
	}
	for _, line := range strings.Split(doc, "\n") {
		trimmed := strings.TrimSpace(line)
		switch {
		case trimmed == "":
			flush()
		case strings.HasPrefix(trimmed, "#"), strings.HasPrefix(trimmed, "|"):
			flush()
			blocks = append(blocks, trimmed)
		case strings.HasPrefix(trimmed, "- "), strings.HasPrefix(trimmed, "* "), orderedListItem.MatchString(trimmed):
			flush()
			current = append(current, trimmed)
		default:
			current = append(current, trimmed)
		}
	}
	flush()
	return blocks
}

var orderedListItem = regexp.MustCompile(`^[0-9]+\. `)

// TestF1StatusSentencesAreAllClassified fails on a status sentence about F1
// that f1StatusSentences does not list, so a reworded or new one cannot
// escape TestF1StatusSentencesSayNotYetLandedOnlyWhileTrue.
func TestF1StatusSentencesAreAllClassified(t *testing.T) {
	for _, found := range scanF1StatusSentences(t) {
		classified := false
		for _, known := range f1StatusSentences {
			classified = classified || (known.file == found.file && strings.Contains(found.sentence, known.sentence))
		}
		if !classified {
			t.Errorf("%s: status sentence %q is not listed in f1StatusSentences with the parts of F1 it speaks for", found.file, found.sentence)
		}
	}
	for _, known := range f1StatusSentences {
		if len(known.parts) == 0 {
			t.Errorf("%s: status sentence %q names no part of F1", known.file, known.sentence)
		}
		for _, part := range known.parts {
			if len(f1PartMarkers[part]) == 0 {
				t.Errorf("%s: status sentence %q names the unknown part %q", known.file, known.sentence, part)
			}
		}
	}
}

// TestF1StatusSentencesSayNotYetLandedOnlyWhileTrue fails while a status
// sentence is still in its document and a marker of a part it speaks for is
// already in ES Go code: the pull request that lands a part moves that
// part's status sentences to the current rule in the same change.
func TestF1StatusSentencesSayNotYetLandedOnlyWhileTrue(t *testing.T) {
	landed := map[string]string{}
	for _, root := range []string{"es", "internal", "cmd"} {
		err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if entry.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			data := mustRead(t, path)
			for part, markers := range f1PartMarkers {
				for _, marker := range markers {
					if _, seen := landed[part]; !seen && strings.Contains(data, marker) {
						landed[part] = fmt.Sprintf("%s names %q", path, marker)
					}
				}
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", root, err)
		}
	}
	for _, known := range f1StatusSentences {
		if !strings.Contains(compactText(mustRead(t, known.file)), known.sentence) {
			continue
		}
		for _, part := range known.parts {
			if evidence, ok := landed[part]; ok {
				t.Errorf("%s still says %q, but the %s part has landed (%s): move that part's status sentences to the current rule in the same change", known.file, known.sentence, part, evidence)
			}
		}
	}
}
