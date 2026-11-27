package executionsubstrate_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	"execution-substrate/internal/testutil"
)

// mustRead, compactText, docSection, compactDocSection, assertContainsAll
// and assertContainsNone are the helpers of package testutil, under the
// names these tests use. The tests in scripts/ use them too.

func mustRead(t *testing.T, path string) string {
	t.Helper()
	return testutil.Read(t, path)
}

func compactText(text string) string {
	return testutil.Compact(text)
}

// remoteAlphaOperatorScriptPath is the path of the Remote Alpha operator
// script.
func remoteAlphaOperatorScriptPath() string {
	return testutil.Path("scripts/remote_alpha_operator.sh")
}

func authorityHierarchyLines(t *testing.T) []string {
	t.Helper()

	lines := make([]string, 0, 5)
	capture := false
	for _, line := range strings.Split(mustRead(t, "AGENTS.md"), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "## 3. Authority hierarchy" {
			capture = true
			continue
		}
		if !capture {
			continue
		}
		switch {
		case strings.HasPrefix(trimmed, "1. "),
			strings.HasPrefix(trimmed, "2. "),
			strings.HasPrefix(trimmed, "3. "),
			strings.HasPrefix(trimmed, "4. "),
			strings.HasPrefix(trimmed, "5. "):
			lines = append(lines, trimmed)
			if len(lines) == 5 {
				return lines
			}
		}
	}

	t.Fatalf("AGENTS.md authority hierarchy not found")
	return nil
}

func docSection(t *testing.T, doc string, start string, end string) string {
	t.Helper()
	return testutil.Section(t, doc, start, end)
}

func compactDocSection(t *testing.T, doc string, start string, end string) string {
	t.Helper()
	return testutil.CompactSection(t, doc, start, end)
}

func markedDocSection(t *testing.T, label string, doc string, start string, end string) string {
	t.Helper()

	if strings.Count(doc, start) != 1 {
		t.Fatalf("%s expected exactly one start marker %q", label, start)
	}
	startIndex := strings.Index(doc, start)

	var sectionEnd int
	if end == "" {
		sectionEnd = len(doc)
	} else {
		if strings.Count(doc, end) != 1 {
			t.Fatalf("%s expected exactly one end marker %q", label, end)
		}
		endIndex := strings.Index(doc, end)
		if endIndex <= startIndex {
			t.Fatalf("%s end marker %q must appear after start marker %q", label, end, start)
		}
		sectionEnd = endIndex
	}

	bodyStart := startIndex + len(start)
	if strings.TrimSpace(doc[bodyStart:sectionEnd]) == "" {
		t.Fatalf("%s selected subsection between %q and %q is empty", label, start, end)
	}
	if end == "" && strings.Contains(doc[bodyStart:sectionEnd], "\n## ") {
		t.Fatalf("%s unbounded subsection after %q consumed a later top-level section", label, start)
	}
	return doc[startIndex:sectionEnd]
}

func compactMarkedDocSection(t *testing.T, label string, doc string, start string, end string) string {
	t.Helper()
	return compactText(markedDocSection(t, label, doc, start, end))
}

func assertContainsAll(t *testing.T, label string, text string, required ...string) {
	t.Helper()
	testutil.ContainsAll(t, label, text, required...)
}

func assertContainsNone(t *testing.T, label string, text string, forbidden ...string) {
	t.Helper()
	testutil.ContainsNone(t, label, text, forbidden...)
}

var trancheB1ForbiddenDocumentationClaims = []string{
	"semantic plan is complete effect identity",
	"semantic plan is complete provider-effect identity",
	"semantic-plan equality implies provider-job equality",
	"semantic-plan equality implies dispatch equality",
	"semantic-plan equality implies replay equality",
	"semantic-plan equality implies restart equality",
	"semantic-plan equality implies safe-host substitution",
	"semantic-plan equality implies effect-binding equality",
	"host context is already canonically bound",
	"reliable keyed-submit runtime is wired",
	"reliable dispatch is implemented",
	"nomad ambiguity reconciliation is implemented",
	"planbinding exists",
	"`planbinding` exists",
	"canonical encoding exists",
	"coordinator adapter work is complete",
	"native linux validation is complete",
	"caller is concurrency-safe during unsynchronized copy",
	"caller mutation is safe after entry",
}

func trancheB1DocumentationContradiction(section string) string {
	normalized := strings.ToLower(compactText(section))
	for _, forbidden := range trancheB1ForbiddenDocumentationClaims {
		if strings.Contains(normalized, forbidden) {
			return forbidden
		}
	}
	return ""
}

func assertTrancheB1DocumentationSection(t *testing.T, label string, section string) {
	t.Helper()

	assertContainsAll(t, label, strings.ToLower(compactText(section)),
		"semantic truth only",
		"additional execution-shaping",
		"race-free",
		"caller data race",
		"not an es synchronization guarantee",
		"results root",
		"outside the semantic plan",
		"b1 binding",
		"tranche b2",
		"now completes",
		"reliable keyed-submit runtime remains unwired",
		"native linux runtime validation",
	)
	if contradiction := trancheB1DocumentationContradiction(section); contradiction != "" {
		t.Fatalf("%s contains contradictory B1 claim %q", label, contradiction)
	}
}

func assertContainsInOrder(t *testing.T, label string, text string, phrases ...string) {
	t.Helper()

	offset := 0
	for _, phrase := range phrases {
		index := strings.Index(text[offset:], phrase)
		if index < 0 {
			t.Fatalf("%s missing ordered phrase %q after offset %d", label, phrase, offset)
		}
		offset += index + len(phrase)
	}
}

const expectedTreeInventoryClause = "finite source inventories for expected-tree `ReadDir`, custody claim/materialization entry points, synchronized state, rejected A3 topology, and retired operator aliases"

const expectedTreeInventoryStatement = "Its accepted scope remains exactly: correcting the resolved-plan documentation truth and strengthening " + expectedTreeInventoryClause + "."

func hasExpectedTreeInventoryClause(section string) bool {
	normalized := compactText(section)
	normalized = strings.ReplaceAll(normalized, "expected- tree", "expected-tree")
	return strings.Contains(normalized, expectedTreeInventoryStatement)
}

func assertExpectedTreeInventoryClause(t *testing.T, section string) {
	t.Helper()
	if !hasExpectedTreeInventoryClause(section) {
		t.Fatalf("operator cutoff plan missing governed expected-tree inventory clause %q", expectedTreeInventoryClause)
	}
}

func TestExpectedTreeInventoryClauseLineWrapContract(t *testing.T) {
	for _, test := range []struct {
		name    string
		section string
		want    bool
	}{
		{
			name:    "canonical single line",
			section: expectedTreeInventoryStatement,
			want:    true,
		},
		{
			name: "ordinary markdown line wrap",
			section: "Its accepted scope remains exactly: correcting the resolved-plan documentation truth and strengthening finite source inventories for expected-\n" +
				"tree `ReadDir`, custody claim/materialization entry points, synchronized state, " +
				"rejected A3 topology, and retired operator aliases.",
			want: true,
		},
		{
			name:    "required semantic clause removed",
			section: "Its accepted scope remains exactly: correcting the resolved-plan documentation truth and strengthening custody claim/materialization entry points, synchronized state, rejected A3 topology, and retired operator aliases.",
			want:    false,
		},
		{
			name:    "materially contrary wording",
			section: "The remaining core repair excludes expected-tree `ReadDir` from its finite source inventories and covers only custody entry points.",
			want:    false,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := hasExpectedTreeInventoryClause(test.section); got != test.want {
				t.Fatalf("hasExpectedTreeInventoryClause() = %t, want %t", got, test.want)
			}
		})
	}
}

func TestResolvedExecutionPlanExtractionDocsContract(t *testing.T) {
	boundaries := compactText(mustRead(t, ".docs/system_overview/boundaries.md"))
	design := compactText(mustRead(t, ".docs/execution_lifecycle/design.md"))
	implementation := compactText(mustRead(t, ".docs/execution_lifecycle/implementation.md"))
	contracts := compactText(mustRead(t, ".docs/execution_lifecycle/contracts.md"))
	admission := compactText(mustRead(t, ".docs/execution_lifecycle/es_execution_admission_model.md"))
	recoveryRaw := mustRead(t, ".docs/execution_lifecycle/submit_idempotency_correlation_and_recovery.md")
	recovery := compactText(recoveryRaw)
	recoveryCurrent := compactDocSection(t, recoveryRaw, "## 2. Current Implementation Reality", "## 3. Dual Ambiguity Model")
	recoveryNonClaims := compactDocSection(t, recoveryRaw, "## 15. Explicit Non-Claims", "## 16. Required-Before-Implementation Gates")
	persistence := compactText(mustRead(t, ".docs/execution_lifecycle/reliable_submit_persistence_and_concurrency.md"))

	assertContainsAll(t, "resolved-plan tranche in the admission standing rules", compactText(mustRead(t, standingAdmissionRulesPath)),
		"one private `resolvedExecutionPlan`",
		"Successful return from that effectful read resolver is the freeze point",
		"The private `resolvedExecutionPlan` is admitted semantic truth",
		"Semantic-plan equality across qualified host contexts proves admitted-semantic equality only",
		"Every post-claim return closes descriptors and retains the visible run root",
	)
	assertContainsAll(t, "resolved-plan foundation limits in the paired-root custody standing rules", standingRuleSection(t, standingAdmissionRulesPath, pairedRootCustodyHeading),
		"does not select or implement canonical effective-plan encoding, `PlanBinding`, a complete effective-plan witness, durable material or replay-envelope custody",
	)
	assertContainsAll(t, "resolved-plan system boundary", boundaries,
		"Successful resolver return is the freeze point",
		"current legacy `Submit` may consume only narrow typed plan, material, run-projection, host-materialization, authority-handoff, and Nomad-job inputs",
		"Semantic-plan equality across qualified host contexts is admitted-semantic equality only",
		"does not implement or imply a public request/response change",
	)
	assertContainsAll(t, "resolved-plan lifecycle design", design,
		"resolved execution plan from the actual current ES admission and runtime-resolution path",
		"That plan is authoritative only for admitted semantics",
		"The semantic plan owns admitted execution semantics",
		"Plan equality across qualified host contexts proves admitted-semantic equality",
		"The separate private v1 `PlanBinding` producer consumes this source-grounded plan",
	)
	assertContainsAll(t, "resolved-plan implementation", implementation,
		"`es/admission/resolved_execution_plan.go`",
		"This successful return is the freeze point: no run ID, filesystem write, ownership mutation, or Nomad registration occurs before it",
		"Post-freeze mount materialization does not parse gzip or tar",
		"Once exclusive run-root creation succeeds, all Submit returns retain the visible root",
	)
	assertContainsAll(t, "resolved-plan lifecycle contract", contracts,
		"one private source-grounded semantic plan",
		"The private `resolvedExecutionPlan` is admitted semantic truth",
		"Semantic-plan equality across qualified host contexts is not provider-job, dispatch, replay, restart, safe-host-substitution, or provider-effect identity",
		"Once creation succeeds, every return closes descriptors and retains the visible root",
	)
	assertContainsAll(t, "resolved-plan admission model", admission,
		"Private resolved current-Submit plan",
		"Semantic-plan equality is not provider-effect/replay identity",
		"not canonical encoding, `PlanBinding`, a witness, durable custody, host-context binding/replay treatment, reliable runtime wiring, or public grammar",
	)
	assertContainsAll(t, "resolved-plan reliable target boundary", recovery,
		"Current legacy Submit now also consumes a separate private `resolvedExecutionPlan`",
		"No run ID, staging write, ownership mutation, or Nomad call precedes that freeze",
		"Current legacy `Service.Submit` already consumes the private source-grounded resolved-execution-plan extraction foundation",
		"not reliable-submit runtime wiring",
		"The earlier extraction foundation by itself selected no canonical binding or witness",
		"The separate private v1 producer now selects only an unwired encoding, commitment and completeness assessment",
	)
	assertContainsAll(t, "resolved-plan owning current section", recoveryCurrent,
		"source-grounded resolved-execution-plan extraction already implemented for current Submit",
		"Current legacy Submit now also consumes a separate private `resolvedExecutionPlan`",
		"No run ID, staging write, ownership mutation, or Nomad call precedes that freeze",
		"The current plan owns admitted semantic facts",
		"Current successful Submit always constructs `authority_handoff`",
	)
	assertContainsNone(t, "resolved-plan reliable target stale denial", recoveryCurrent+" "+recoveryNonClaims,
		"no source-grounded resolved effective-plan extraction implemented",
		"do not implement source-grounded resolved effective-plan extraction",
		"source-grounded resolved-plan extraction is absent",
		"source-grounded resolved-execution-plan extraction is absent",
		"source-grounded resolved-plan extraction is unimplemented",
		"source-grounded resolved-execution-plan extraction is unimplemented",
		"the resolved-execution-plan extraction foundation is absent",
		"the resolved-execution-plan extraction foundation is unimplemented",
	)
	assertContainsAll(t, "resolved-plan narrower reliable-submit non-claims", recoveryNonClaims,
		"does not by itself supply canonical encoding, a final `PlanBinding`, a completeness witness",
		"durable custody, reliable dispatch, ambiguity reconciliation",
		"or a Coordinator adapter",
		"private canonical effective-plan encoding, `PlanBinding` construction from admitted facts, and a complete fourteen-category witness exist only in the unwired package-private producer",
		"no public or operational durable replay-envelope custody",
		"no public reliable-submit runtime wiring",
		"no public replay DTO or recovery route",
		"no public reliable response field names",
		"no Nomad registration retry decision",
		"no Coordinator schema",
	)
	assertContainsAll(t, "resolved-plan persistence boundary", persistence,
		"separate private `resolved-execution-plan-extraction-foundation` now extracts the current legacy Submit plan from real admission/runtime resolution",
		"runtime consumption and original-key availability for the now-unwired private v1 binding",
		"durable material custody",
	)
}

func TestResolvedPlanDocumentationTruthAndFiniteInventoriesContract(t *testing.T) {
	plansRaw := mustRead(t, "PLANS.md")
	plans := compactText(plansRaw)
	admissionRaw := mustRead(t, ".docs/execution_lifecycle/es_execution_admission_model.md")
	admission := compactText(admissionRaw)
	remote := compactText(mustRead(t, ".docs/system_overview/remote_supported_host_alpha.md"))
	design := compactText(mustRead(t, ".docs/execution_lifecycle/design.md"))
	recovery := compactText(mustRead(t, ".docs/execution_lifecycle/submit_idempotency_correlation_and_recovery.md"))

	assertExpectedTreeInventoryClause(t, plansRaw)
	assertContainsAll(t, "resolved-plan finite-inventory completion plan", plans,
		"The resolved-plan documentation-truth and finite-source-inventory obligation is now complete",
		"`.docs/execution_lifecycle/es_execution_admission_model.md`",
		"`.docs/system_overview/remote_supported_host_alpha.md`",
		"changes no production custody or staging source",
		"begins no additional Tranche B behavior",
	)
	assertContainsAll(t, "resolved-plan truth closure", admission,
		"Resolved-plan truth and finite source inventories",
		"authoritative only for admitted semantics",
		"No other production plan consumer or resolver exists",
		"not lifecycle truth, scheduler truth, retained-result truth, a replay identity, a witness, a commitment, a `PlanBinding`, or hidden run truth",
		"`es/admission/staging_custody.go:validateExpectedDirectoryEntries` | `1`",
		"`es/admission/staging_custody.go:readDirectoryEntries` | `64`",
		"`es/admission/staging_custody.go:claimStagingCustodyFromQualifiedRoot` is the sole constructor on a production path",
		"The path-taking `claimStagingCustody` wrapper is test-only",
		"`es/admission/executionpackage.go:materializeExecutionInputs` is the only production function",
		"The remaining direct test-only callers of `claimStagingCustody` are exactly",
		"`lifecycle_test.go:TestDescriptorCloseRetainsSuccessfulRunRoot`",
		"`resolved_execution_plan_test.go:TestResolvedExecutionMaterialOwnsBytesBeforeHostMaterialization`",
		"`resolved_execution_plan_test.go:TestRuntimeSupportMaterialIdentityMatchesCapturedBytes`",
		"`staging_custody_test.go:TestStagingCustodyRefusesEveryPreExistingObjectWithoutChangingIt`",
		"`writablestate_readiness_test.go:newSyntheticNormalizedRunFixture`",
		"The direct test-only callers of `materializeExecutionInputs` are exactly",
		"`executionpackage_test.go:TestTrancheB2TrustMaterializationCauseUsesFixedPublicError`",
		"`executionpackage_test.go:(*Service).stageExecutionInputs`",
		"Synthetic source strings in guardrail mutation tests are validator fixtures, not executable package entry points",
		"`es/admission:Service.mu:sync.RWMutex`",
		"`es/app:App.mu:sync.RWMutex`",
		"`es/runtimehelper:helperServer.mu:sync.RWMutex`",
		"`.execution-substrate-namespace-lease-v1`",
		"`namespacelease`",
		"`mutationpoison`",
		"does not add an external current-schema package consumer",
		"resurrect the retired current-schema checker",
	)
	assertContainsAll(t, "retired operator finite inventory", remote,
		"The canonically recognized retirement inventory is finite and exact",
		"top-level evidence routes are `vault-workload-auth-check`, `runtime-identity-summary`, and `vault-service-user-check`",
		"there is no nested `recovery-session vault-service-user-check` alias",
		"`--evidence-check`, `--evidence-dir`, `--strict-known-schema`",
		"`--vault-workload-auth-summary`, `--runtime-identity-summary`, and `--vault-service-user-summary`",
		"`--readiness-summary` and `--staging-record`",
		"`es-writable-state-readiness-check` and `readiness-session`",
		"`reject_retired_operator_evidence_args` is the only live scanner",
		"`retired_operator_evidence_compatibility` is its only refusal handler",
		"`reject_secret_args` runs before either retirement classification",
	)
	assertContainsAll(t, "resolved-plan semantic authority qualification", design+" "+recovery,
		"authoritative only for admitted semantics",
	)
	assertContainsNone(t, "stale broad resolved-plan authority language", design+" "+recovery,
		"private authoritative resolved execution plan",
		"one authoritative private semantic plan",
	)
}

func TestTrancheB1SemanticOwnershipDocsContract(t *testing.T) {
	sections := []struct {
		label string
		path  string
		start string
		end   string
	}{
		{"admission standing rules B1 owning section", standingAdmissionRulesPath, "Tranche B1, `ES-B1-SEMANTIC-OWNERSHIP-COMMAND`", "The opened parent and root identities remain"},
		{"contracts B1 owning section", ".docs/execution_lifecycle/contracts.md", "### Request contract", "### Tranche A resource and filesystem custody contract"},
		{"design B1 owning section", ".docs/execution_lifecycle/design.md", "The `resolved-execution-plan-extraction-foundation` now derives", "Header-only reliable-submit opt-in is rejected"},
		{"admission-model B1 owning section", ".docs/execution_lifecycle/es_execution_admission_model.md", "- The selected `resolved-execution-plan-extraction-foundation`", "- C3 is the focused tests/docs guardrail slice"},
		{"implementation B1 owning section", ".docs/execution_lifecycle/implementation.md", "1. Reject submission if the Nomad client is unavailable", "Where IDs are created:"},
		{"recovery B1 owning section", ".docs/execution_lifecycle/submit_idempotency_correlation_and_recovery.md", "Current legacy Submit now also consumes a separate private", "Current private durable source implements"},
		{"boundaries B1 owning section", ".docs/system_overview/boundaries.md", "- ES now owns the separate", "- The Workstream F F0 runtime-identity handoff ownership decision"},
	}

	var current []string
	for _, section := range sections {
		text := docSection(t, mustRead(t, section.path), section.start, section.end)
		assertTrancheB1DocumentationSection(t, section.label, text)
		current = append(current, compactText(text))
	}
	combined := strings.Join(current, " ")
	assertContainsAll(t, "Tranche B1 semantic ownership", combined,
		"one private Prepare-versus-Submit intent",
		"distinct artifact/payload/derivation/output identities",
		"runtime-identity tmpfs size",
		"absolute SPIRE source",
		"Nomad datacenter",
		"one typed runtime command",
		"Current authority handoff is unconditionally applicable",
		"unmodified actual job tree",
		"pointer-owned token/template ledger",
		"finite package-local direct-call closure",
	)
	assertContainsAll(t, "Tranche B1 explicit nonclaims", combined,
		"canonical encoding",
		"host-context binding",
		"not whole-program",
		"prepared-admission redaction",
		"provider-body/lifecycle-log privacy work",
	)
}

func TestTrancheB1DocumentationNegativeGuardMutants(t *testing.T) {
	for _, test := range []struct {
		name    string
		mutant  string
		failure string
	}{
		{"complete effect identity", "The semantic plan is complete effect identity.", "semantic plan is complete effect identity"},
		{"reliable dispatch complete", "Reliable dispatch is implemented.", "reliable dispatch is implemented"},
		{"reliable runtime wired", "Reliable keyed-submit runtime is wired.", "reliable keyed-submit runtime is wired"},
		{"unsafe copy concurrency", "Caller is concurrency-safe during unsynchronized copy.", "caller is concurrency-safe during unsynchronized copy"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := trancheB1DocumentationContradiction(test.mutant); got != test.failure {
				t.Fatalf("contradiction = %q, want %q", got, test.failure)
			}
		})
	}
}

func trancheB2DocumentationContradiction(section string) string {
	normalized := strings.ToLower(compactText(section))
	for _, forbidden := range []string{
		"fetchjob is bounded to 256 kib",
		"successful authenticated public logs are bounded to 256 kib",
		"b2 provides reflection-safe redaction",
		"the control plane golden is a snapshot of cp",
		"reliable keyed-submit runtime is wired",
		"nomad ambiguity reconciliation is implemented",
	} {
		if strings.Contains(normalized, forbidden) {
			return forbidden
		}
	}
	return ""
}

func TestTrancheB2PrivacyIndependentAssuranceDocsContract(t *testing.T) {
	paths := []string{
		standingAdmissionRulesPath,
		".docs/system_overview/boundaries.md",
		".docs/system_overview/contracts.md",
		".docs/execution_lifecycle/design.md",
		".docs/execution_lifecycle/contracts.md",
		".docs/execution_lifecycle/implementation.md",
		".docs/execution_lifecycle/es_execution_admission_model.md",
		".docs/execution_lifecycle/submit_idempotency_correlation_and_recovery.md",
	}

	var sections []string
	for _, path := range paths {
		text := strings.ToLower(compactText(mustRead(t, path)))
		assertContainsAll(t, path+" B2 authority", text,
			"b2",
			"reliable keyed-submit runtime remains unwired",
			"native linux runtime validation",
		)
		assertContainsNone(t, path+" stale B2 state", text,
			"b2 privacy/public-message work remains pending",
			"b2 privacy work remains pending",
			"prepared-admission redaction remains pending",
			"provider-body/lifecycle-log privacy work remain pending",
		)
		if contradiction := trancheB2DocumentationContradiction(text); contradiction != "" {
			t.Fatalf("%s contains contradictory B2 claim %q", path, contradiction)
		}
		sections = append(sections, text)
	}

	combined := strings.Join(sections, " ")
	assertContainsAll(t, "Tranche B2 bounded contract", combined,
		"workload-zone vault configuration is invalid",
		"derive execution host context failed",
		"stage workload vault trust material failed",
		"derive execution platform state owner failed",
		"execution submission failed",
		"routes, http statuses, codes, dto fields",
		"es result retention failed run_id=%s",
		"validated public run id",
		"not process-wide log noninterference",
		"256 kib",
		"one-document",
		"unknown provider fields",
		"non-success",
		"fetchjob",
		"caller-environment aggregates",
		"successful authenticated public logs",
		"unbounded opaque",
		"universal provider-response",
		"workload-output limit",
		"preparedadmission",
		"ordinary formatting",
		"ordinary json",
		"reflection",
		"unsafe",
		"same-package",
		"secure-erasure",
		"source-distinct",
		"es profile-coverage evidence",
		"not a snapshot",
		"source-bounded",
		"not a general analyzer",
	)
	assertContainsAll(t, "Tranche B2 explicit nonclaims", combined,
		"canonical encoding",
		"planbinding",
		"host-context binding",
		"results-root",
		"durable custody",
		"reliable dispatch",
		"ambiguity reconciliation",
		"coordinator adapter",
		"staging reclamation",
	)
}

func TestTrancheB2DocumentationNegativeGuardMutants(t *testing.T) {
	for _, test := range []struct {
		name    string
		mutant  string
		failure string
	}{
		{"bounded fetchJob", "fetchJob is bounded to 256 KiB.", "fetchjob is bounded to 256 kib"},
		{"bounded public Logs", "Successful authenticated public Logs are bounded to 256 KiB.", "successful authenticated public logs are bounded to 256 kib"},
		{"reflection-safe private value", "B2 provides reflection-safe redaction.", "b2 provides reflection-safe redaction"},
		{"CP snapshot golden", "The Control Plane golden is a snapshot of CP.", "the control plane golden is a snapshot of cp"},
		{"reliable runtime wired", "Reliable keyed-submit runtime is wired.", "reliable keyed-submit runtime is wired"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := trancheB2DocumentationContradiction(test.mutant); got != test.failure {
				t.Fatalf("contradiction = %q, want %q", got, test.failure)
			}
		})
	}
}

func TestTrancheAFilesystemAndResourceCustodyDocsContract(t *testing.T) {
	admissionRules := compactText(mustRead(t, standingAdmissionRulesPath))
	contracts := compactText(mustRead(t, ".docs/execution_lifecycle/contracts.md"))
	design := compactText(mustRead(t, ".docs/execution_lifecycle/design.md"))
	implementation := compactText(mustRead(t, ".docs/execution_lifecycle/implementation.md"))
	configuration := compactText(mustRead(t, ".docs/system_overview/configuration.md"))
	runtimeConfig := compactText(mustRead(t, ".docs/system_overview/runtime_config_ownership.md"))
	publication := compactText(mustRead(t, ".docs/system_overview/artifact_publication_storage.md"))
	capabilities := compactText(mustRead(t, ".docs/system_overview/capability_probing.md"))
	writableState := compactText(mustRead(t, ".docs/system_overview/remote_alpha_beta_es_writable_state_ownership.md"))
	normalization := compactText(mustRead(t, ".docs/system_overview/remote_alpha_beta_es_runtime_ownership_normalization.md"))
	linuxQualification := compactDocSection(t, mustRead(t, ".docs/system_overview/supported_linux_host_qualification.md"), "### Tranche A filesystem-custody validation posture", "## 4. Explicit Disqualifiers")
	runbook := compactText(mustRead(t, ".runbooks/system/Governed Execution ES System Bring-Up.md"))

	assertContainsAll(t, "Tranche A plan limits and retained custody", admissionRules,
		"The selected Tranche A filesystem/resource-custody refinement",
		"opens a fresh independent directory description at position zero",
		"reads entries incrementally one at a time",
		"stops after at most the expected-child count plus one observed entry",
		"never materializes or sorts the complete untrusted directory inventory",
		"complete decompressed tar stream is additionally bounded to 16 MiB per mount and 64 MiB aggregate",
		"Once exclusive run-root creation succeeds, the visible root is retained on every return",
		"Automatic whole-run-root reclamation is not implemented",
		"Native Linux validation was not inherited as a pre-B gate",
		"fresh targeted independent audit with no repair defect",
	)
	assertContainsAll(t, "Tranche A lifecycle contract", contracts,
		"### Tranche A resource and filesystem custody contract",
		"reads at most effective-limit-plus-one",
		"no separate ES entry-count or resolved-name-length limit",
		"There is no claim marker, cleanup eligibility state, mutation/adoption reopening path",
		"bounded pre-handoff enumeration above is operation-local completeness validation only",
		"`openStagingTree` to reopen a retained root read-only",
		"Regular expected children require link count exactly one",
		"Expected directories require a positive link count",
		"A post-claim failure preserves its existing primary public error",
		"Incomplete exclusive leaves, unpublished result and normalization temporaries, and startup capability-probe fixtures remain when exact effect-time identity for deletion is unproved",
		"No scan, recursive cleanup, or later residue-reclamation owner is selected",
		"governed reclamation is an ES-owned `Reopened redesign seam`",
	)
	assertContainsAll(t, "Tranche A implementation accounting", implementation,
		"portable retained variable byte-content ceiling is 168,558,593 bytes",
		"168,820,737 bytes as the peak accounted content",
		"Exclusive `mkdirat` of `<staging_root>/<run_id>` is the first filesystem mutation",
		"Every post-claim return retains the visible run root",
		"Incomplete exclusive leaves, unpublished result or normalization temporaries, and startup capability-probe fixtures remain retained",
		"No pathname-based cleanup, scan, or whole-root reclamation is selected",
		"Result capture never reopens a staging root for deletion and never authorizes staging mutation",
		"opens a fresh independent no-follow open-file description at `\".\"`",
		"uses that fresh description directly as the enumeration stream",
		"unique edge-segment bytes plus expected nodes",
	)
	assertContainsAll(t, "Tranche A unconditional design retention", design,
		"Every post-claim Submit-created host staging root remains retained",
		"result-publication success, absence, conflict, or failure grant no staging deletion authority",
		"the current slice attempts no whole-run-root cleanup",
	)
	assertContainsAll(t, "Tranche A configuration", configuration,
		"probes staging for exclusive run-root creation and actual no-follow refusal",
		"separately probes results for exclusive temporary creation and no-replace publication",
		"each new run root is created exclusively, held by parent/root descriptors, and never adopted or reopened from a pre-existing path",
		"failed, partial, ambiguous, accepted, terminal, canceled, lost, unknown, and result-publication outcomes all retain `<staging_root>/<run_id>`",
		"ES does not quarantine, rename, scan, or recursively delete a run root",
		"existing final bundle is never owner- or mode-reconciled in place",
	)
	assertContainsAll(t, "Tranche A runtime-config consumer bounds", runtimeConfig,
		"enclosing workload-zone runtime-config JSON response to 256 KiB before strict decode",
		"combined workload bundle to 524,289 bytes",
		"168,820,737-byte peak ledger includes one temporary system-CA input and no redundant normalized copies",
	)
	assertContainsAll(t, "Tranche A artifact consumer bounds", publication,
		"explicit compatibility/security bounds without changing ARS ownership",
		"primary payload is 32 MiB",
		"governed mount payload transport is 8 MiB per mount and 32 MiB aggregate",
	)
	assertContainsAll(t, "Tranche A capability probing", capabilities,
		"## Example: Execution-root custody",
		"already qualified staging and results descriptors",
		"refuse symlink traversal on staging",
		"refuse the results no-replace publication primitive",
		"retain the exclusive startup probe fixtures when exact effect-time deletion identity cannot be proved; no pathname cleanup or recursion is selected",
		"There is no runtime `GOOS` branch, syscall fallback, or request-time probe",
		"Production run roots are retained after exclusive creation on every return",
		"Linux cross-compilation is compile evidence only",
		"linux/amd64 for an operational Remote Alpha claim",
		"linux/arm64 for an operational supported-local claim",
	)
	assertContainsAll(t, "Tranche A writable-state retirement", writableState,
		"Remote Alpha ES Writable-State Ownership — Retired Existing-Host Edge",
		"fixed exit-2 tombstones",
		"There is no root marker, reopening, adoption, cleanup eligibility, quarantine rename, scan, or recursive run-root deletion",
		"Governed staging reclamation is an ES-owned `Reopened redesign seam`",
	)
	assertContainsAll(t, "Tranche A normalization separation", normalization,
		"Remote Alpha ES Runtime Ownership Normalization — Historical Record",
		"It does not authorize staging deletion",
		"Every exclusively created run root is retained after claim",
		"No v2 schema, validator, fixture, or artifact exists for that retired ES writable-state/service-user migration family",
		"unrelated current EGS hardening v2 schema remains current",
	)
	assertContainsAll(t, "Tranche A operating qualification and local gate", linuxQualification,
		"### Tranche A filesystem-custody validation posture",
		"Historical Tranche A sequencing allowed a fresh read-only audit",
		"while native Linux remained pending",
		"does not impose a blanket native pre-commit gate on local source preservation or integration",
		"`.docs/standing_rules/execution_admission_and_custody.md` and `.docs/execution_lifecycle/contracts.md`",
		"governed Ubuntu 24.04 linux/amd64 for Remote Alpha and governed Ubuntu 24.04 linux/arm64 for supported-local",
		"`openat2` with beneath, no-magic-link, no-symlink, and no-cross-device resolution",
		"`renameat2(RENAME_NOREPLACE)` collision behavior",
		"exclusive run-root claim and descriptor-held identity custody",
		"an actual mount-crossing refusal",
		"Cross-compilation is compile evidence only and cannot replace those runtime observations",
		"C's selected native programme remains historical evidence for its exact source and environments",
		"report that operating claim as pending rather than supported by inference",
		"Neither the Remote Alpha amd64 nor supported-local arm64 claim is narrowed",
	)
	assertContainsNone(t, "obsolete Linux local gate", linuxQualification,
		"Before final combined ES audit and commit",
		"Until both claimed-architecture runtime executions pass",
	)
	assertContainsAll(t, "Tranche A runbook retained-state truth", runbook,
		"There is no staging only when failure preceded both run assignment and exclusive run-root creation",
		"may retain partial or complete staging without returning a receipt or run ID",
		"retained post-claim state may contain sensitive payload, trust, runtime-support, or mount material",
		"retained staging is not proof that Nomad accepted the job, and absence of staging is not proof that no provider effect occurred",
		"no current automatic whole-run-root reclamation path exists",
	)
	assertContainsNone(t, "removed whole-root cleanup vocabulary", plansAndStandingRules(t)+" "+contracts+" "+implementation+" "+configuration+" "+writableState+" "+normalization,
		".execution-substrate-stage-claim-v1",
		"no-replace quarantine rename is the cleanup commit point",
		"Only marker-bearing roots",
	)
	assertContainsNone(t, "removed terminal-success cleanup wording", design,
		"after ES observes terminal success, the current slice attempts result retention and then cleans that staging best-effort",
	)
}

func TestESExecutionAdmissionModelFinalAuditRepairContract(t *testing.T) {
	custody := standingRuleSection(t, standingAdmissionRulesPath, pairedRootCustodyHeading)
	configuration := compactText(mustRead(t, ".docs/system_overview/configuration.md"))
	capabilities := compactText(mustRead(t, ".docs/system_overview/capability_probing.md"))
	design := compactText(mustRead(t, ".docs/execution_lifecycle/design.md"))
	contracts := compactText(mustRead(t, ".docs/execution_lifecycle/contracts.md"))
	implementation := compactText(mustRead(t, ".docs/execution_lifecycle/implementation.md"))
	admissionModel := compactText(mustRead(t, ".docs/execution_lifecycle/es_execution_admission_model.md"))
	remoteAlpha := compactText(mustRead(t, ".docs/system_overview/remote_supported_host_alpha.md"))
	remoteGate := compactDocSection(t, mustRead(t, ".docs/system_overview/remote_supported_host_alpha.md"), "### Current Remote Alpha root-custody observation gate", "It is not the final commercial deployment target.")

	assertContainsAll(t, "current paired-root custody and acceptance scope", custody,
		"### Current paired-root custody and acceptance scope",
		"**Superseded CUST-1/CUST-2 gate history.**",
		"That pre-integration linkage is not a current local commit rule.",
		"Focused changed-interaction assessment, validation, and separately authorized commit were required there",
		"C's selected native observations remain historical evidence",
		"**Current invariant — staging non-mutation and retained-output independence.**",
		"**Bounded slice rule pending integrated review — paired-root qualification.**",
		"form one operation-local qualified root set",
		"Mountinfo record integrity is separate from root-coordinate eligibility.",
		"An `nsfs` root with the source-grounded namespace-object envelope `<kind>:[<canonical decimal inode>]` is retained as opaque",
		"`mnt`, `net`, `uts`, `ipc`, `pid`, `user`, `cgroup`, or `time`",
		"Opaque records still count toward byte/record limits, ID and parent/cycle integrity, stacking, and canonical descendant-mount checks.",
		"This recognition does not make `nsfs` a supported configured execution-root filesystem.",
		"Source coordinates derive from the selected record and canonical descriptor presentation, never configured spelling.",
		"The parser permits one unambiguous `/` top-of-tree self-parent terminal and parents hidden outside the process view",
		"Two missing roots under the same deepest existing object",
		"never turn a topology failure into Nomad fallback",
		"one invocation-local iterative compressed byte-radix ledger",
		"dependency behavior, not an ES resolved-name or entry-count policy",
	)
	assertContainsAll(t, "execution-root configuration contract and pending acceptance", configuration,
		"lexical separation is only an early non-mutating configuration check, not physical proof",
		"descriptor-held canonical objects and topology, not configured spelling",
		"classifies their source-grounded `kind:[decimal-inode]` roots as opaque, never as pathname coordinates",
		"a descriptor-selected opaque root fails before effects rather than using its mountpoint or configured spelling",
		"ambiguous dual-missing roots under one deepest existing lookup object fail closed",
		"a read never provisions a missing results root, and topology refusal never falls through to Nomad",
		"physical-separation implementation is candidate behavior",
		"Those gates were deferred until after local implementation; they were not passed or waived.",
	)
	assertContainsAll(t, "execution-root capability proof", capabilities,
		"Build-selected Linux and Darwin implementations qualify staging and results as one operation-local descriptor set",
		"Linux parses complete records before asking whether a root value can act as a pathname coordinate.",
		"Every accepted opaque record remains in snapshot count, ID/parent/cycle, stacking, and descendant-mount validation.",
		"Only canonical pathname roots are proof-eligible",
		"one unambiguous self-parent terminal at canonical mountpoint `/`",
		"startup behavior-probes the staging filesystem's exclusive claim/no-follow operations and the results filesystem's temporary/no-replace operations separately",
		"Local modeled records and ordinary filesystem tests do not prove mounted bind or casefold compatibility.",
		"deferred but not waived",
	)
	assertContainsAll(t, "lifecycle root and radix contract", design+" "+contracts+" "+implementation,
		"Missing suffixes are absence-checked intent, not canonical objects",
		"Pair proof does not grant deletion or repair authority",
		"Record validity is not coordinate eligibility",
		"Complete source-valid `nsfs` records with opaque namespace-object roots remain in snapshot integrity and descendant checks",
		"Its tagged root representation distinguishes canonical pathname roots from opaque `nsfs` namespace-object roots.",
		"A selected opaque root returns a dedicated refusal before device comparison or path arithmetic",
		"exact 32,768-header EOF boundary",
		"1-MiB hidden special-file processing limit is inherited dependency behavior",
		"The path-taking claim wrapper is test-only.",
	)
	assertContainsAll(t, "final-audit finite assurance inventory", admissionModel,
		"### 7.7 Final-audit finite repair inventories",
		"Its exact direct test call inventory is eight enclosing functions",
		"Production uses the distinct descriptor-taking constructor, verified by typed object identity rather than source text or a count-only oracle.",
		"The Linux mountinfo finite inventory also covers the tagged root-value class, filesystem type, and proof-eligibility branch.",
		"No fixture may drop an opaque record or rewrite its label as a path.",
		"Source tests use a test-local fail-closed accepted grammar",
		"Unknown executable syntax, command/arithmetic/process substitutions, redirections, and heredocs are rejected",
		"not a general Bash parser",
		"remain pending and are not replaced by local success",
	)
	assertContainsAll(t, "running Remote Alpha operational subject and gate", remoteGate,
		"one concrete currently running in-scope ES process",
		"process/start identity, mount namespace, configured roots, held descriptor identities",
		"root-value classification, and descendant-mount result",
		"retain unrelated valid opaque `nsfs` namespace-object records for complete analysis while refusing an opaque selected root",
		"must not filter away records or substitute mountpoint or configured spelling for source coordinates",
		"Real repaired-helper mounted-alias evidence remains required where the operational claim depends on it",
		"environment-bound operational qualification requirements",
		"not an independent blanket prerequisite to a separately authorized local",
		"No current deployment compatibility, supported-host claim, or rollout readiness is inferred here",
	)
	assertContainsNone(t, "obsolete Remote Alpha local gate", remoteGate,
		"The observation and real repaired-helper mounted alias fixtures remain pre-final-acceptance and pre-commit gates",
	)
	assertContainsAll(t, "bounded scanner prefix guard", remoteAlpha,
		"A separate prefix check requires those scanner calls to be the first two nontrivia statements of `parse_args`, in privacy-first order.",
	)
	assertContainsNone(t, "final-audit repair docs reject stale acceptance claims", plansAndStandingRules(t)+" "+configuration+" "+capabilities+" "+design+" "+contracts+" "+implementation+" "+admissionModel+" "+remoteAlpha,
		"the running-deployment observation is complete",
		"local modeled tests prove mounted bind compatibility",
		"local validation waives native Linux validation",
		"the repaired candidate is commit-ready",
	)
}

func TestGo1265ToolchainBaselineDocsAndBuildContract(t *testing.T) {
	goMod := mustRead(t, "go.mod")
	assertContainsAll(t, "go.mod Go 1.26.5 baseline", goMod,
		"\ngo 1.26.5\n",
		"github.com/go-jose/go-jose/v4 v4.0.4",
		"github.com/spiffe/go-spiffe/v2 v2.4.0",
		"google.golang.org/grpc v1.67.1",
		"modernc.org/sqlite v1.54.0",
		"modernc.org/libc v1.74.1",
	)
	if strings.Contains(goMod, "\ntoolchain ") {
		t.Fatalf("go.mod must not commit an explicit toolchain directive")
	}
	lowerGoMod := strings.ToLower(goMod)
	assertContainsNone(t, "go.mod forbidden database dependencies", lowerGoMod,
		"postgres",
		"pgx",
		"lib/pq",
		"mattn/go-sqlite3",
		"go.etcd.io/bbolt",
	)

	goSum := mustRead(t, "go.sum")
	if got := fmt.Sprintf("%x", sha256.Sum256([]byte(goSum))); got != "5c2e536bc93d89ce2a874a5203207b2bee6a859a90471c7abfbe4850fb00970e" {
		t.Fatalf("go.sum SHA-256 changed: got %s", got)
	}

	baselineDoc := mustRead(t, ".docs/system_overview/go_toolchain_baseline.md")
	currentStatus := compactDocSection(t, baselineDoc, "## 1. Current Status", "## 2. Module Policy")
	modulePolicy := compactDocSection(t, baselineDoc, "## 2. Module Policy", "## 3. Toolchain-Selection Policy")
	toolchainPolicy := compactDocSection(t, baselineDoc, "## 3. Toolchain-Selection Policy", "## 4. Supported Builds")
	supportedBuilds := compactDocSection(t, baselineDoc, "## 4. Supported Builds", "## 5. Setup And Docker Treatment")
	setupDocker := compactDocSection(t, baselineDoc, "## 5. Setup And Docker Treatment", "## 6. Offline Behavior")
	offline := compactDocSection(t, baselineDoc, "## 6. Offline Behavior", "## 7. Compatibility And Runtime Limits")
	runtimeLimits := compactDocSection(t, baselineDoc, "## 7. Compatibility And Runtime Limits", "## 8. Database Dependency Scope")
	databaseDependencyScope := compactDocSection(t, baselineDoc, "## 8. Database Dependency Scope", "## 9. Rollback")
	rollback := compactDocSection(t, baselineDoc, "## 9. Rollback", "## 10. Continuous Integration")
	continuousIntegration := compactDocSection(t, baselineDoc, "## 10. Continuous Integration", "## 11. Explicit Non-Claims")
	nonClaims := compactDocSection(t, baselineDoc, "## 11. Explicit Non-Claims", "")
	assertContainsAll(t, "Go baseline current status", currentStatus,
		"Go 1.26.5 is the current Execution Substrate minimum Go version",
		"supported scripted build/proof toolchain",
		"`modernc.org/sqlite v1.54.0`",
		"`modernc.org/libc v1.74.1`",
		"No PostgreSQL dependency",
	)
	assertContainsAll(t, "Go baseline module policy", modulePolicy,
		"go 1.26.5",
		"no explicit `toolchain` directive",
		"baseline remains exact Go 1.26.5",
		"Reliable-submit SQLite dependency changes are owned by the reliable-submit persistence tranche",
	)
	assertContainsAll(t, "Go baseline toolchain policy", toolchainPolicy,
		"`GOTOOLCHAIN=local`",
		"exactly `go1.26.5`",
		"must not rely on hidden automatic toolchain download",
		"older local Go toolchain fails closed",
		"newer local Go toolchain is not silently treated as the exact supported proof/build toolchain",
	)
	assertContainsAll(t, "Go baseline supported builds", supportedBuilds,
		"host development/build commands",
		"CGO-free linux/amd64 builds",
		"CGO-free linux/arm64 builds",
		"every command package under `cmd/...`",
		"`CGO_ENABLED=0 GOOS=linux GOARCH=amd64`",
	)
	assertContainsAll(t, "Go baseline setup and Docker", setupDocker,
		"exact official Go 1.26.5 archives",
		"SHA-256 verification",
		"fails closed for unsupported Linux architectures",
		"`golang:1.26.5-alpine3.24`",
		"`ENV GOTOOLCHAIN=local`",
		"must not be hand-edited",
	)
	assertContainsAll(t, "Go baseline offline behavior", offline,
		"Warm-cache `GOPROXY=off` builds are supported",
		"cold cache requires explicit prior dependency and toolchain availability",
		"introduces no vendoring claim",
	)
	assertContainsAll(t, "Go baseline runtime limits", runtimeLimits,
		"Linux cross-build success is not Linux runtime proof",
		"Process handling",
		"signal handling",
		"filesystem ownership",
		"TLS/SPIFFE behavior",
		"privilege-helper runtime behavior",
	)
	assertContainsAll(t, "Go baseline database dependency scope", databaseDependencyScope,
		"private reliable-submit SQLite source",
		"`modernc.org/sqlite v1.54.0`",
		"`es/admission/internal/reliablesubmit`",
		"not runtime wiring",
		"not runtime wiring, a public storage API, a PostgreSQL client decision, or an external database operations claim",
	)
	assertContainsAll(t, "Go baseline rollback", rollback,
		"Go baseline change",
		"Rollback of the reliable-submit SQLite source is a separate source/dependency rollback",
		"runtime-state migration",
	)
	assertContainsAll(t, "Go baseline continuous integration", continuousIntegration,
		"`.github/workflows/go.yml` runs on every pull request and on every push to `trunk_dev`",
		"GitHub-hosted `ubuntu-24.04` runner",
		"`GOTOOLCHAIN=local` and `GOFLAGS=-mod=readonly`",
		"restores no build or module cache",
		"`go mod download`, `go mod verify`, `go build ./...`, `go vet ./...`, and the tests of every package of the module",
		"One more step runs `GOOS=darwin GOARCH=arm64 go vet ./...`",
		"It type-checks the files that build only on macOS and runs no test",
		"Before the tests, the workflow installs Nomad 2.1.1, Vault 2.2.2 and SPIRE 1.14.4 from release downloads that it checks against reviewed SHA-256 values, and pulls the container images that the tests run by reviewed digest",
		"It reads the SPIRE value from `scripts/internal/spire_release.sha256`, the pin file that `scripts/72_supported_local_setup.sh` and `scripts/73_supported_local_proof.sh` check SPIRE against, so CI and those scripts accept the same SPIRE file",
		"So the `es/app` integration tests that start a Nomad agent with the Docker driver, and the supported-local setup test that runs Vault and SPIRE, run on that runner",
		"The job sets `AWS_EC2_METADATA_DISABLED=true`: the runner's EC2 metadata endpoint does not answer, and Nomad's AWS fingerprinter would otherwise fail the client of a test agent",
		"`.github/ci/environment-only-tests.txt` is the single statement of what the test step excludes and of which tests exclude themselves on that runner",
		"An entry names a test or subtest that cannot pass on that runner for host reasons",
		"`.github/ci/go_test_gate.py` skips those entries, each only in the package it names",
		"A `skips-itself` line names a test or subtest that skips itself on that runner",
		"The test step fails the run unless the tests that skipped themselves are exactly the tests that those lines name",
		"a test that skips itself on the runner needs a line, and a line cannot outlive its reason",
		"The log of the step names every test that skipped itself",
		"For every package the step also fails the run unless every top-level test that `go test` lists for the package, and that is not an entry, reported a verdict",
		"`go test` reads a test path as the start of a path, so the skip for a listed subtest also covers every test whose path starts with the path of that entry",
		"a skipped test leaves no trace in the output",
		"runs a package that has an entry for a subtest a second time, with a test binary that writes down every test that `-skip` drops",
		"It fails the run unless those tests are exactly the entries of that package",
		"For that one run `go test -overlay` builds the test binary with a copy of `src/testing/match.go` of the Go standard library, to which the gate adds the call that writes the name down",
		"The installed toolchain is not changed, and no other run uses the copy",
		"The gate makes the copy only from the file of the exact Go version that it names, so a change of the Go baseline has to review that file and change the gate in the same change",
		"That run needs a Go installation outside the module cache, as `actions/setup-go` makes one on the runner",
		"the `go` command does not let `-overlay` replace a file beneath `GOMODCACHE`, so with a toolchain that the `go` command downloaded itself the test step fails and shows that error",
		"A second blocking step judges every entry twice: in a run of its whole package with nothing skipped, and in a `go test` of its own",
		"It fails the run when an entry no longer fails on the runner in one of the two",
		"An entry fails there only if the testing package reported its failure",
		"A test that was running when the test binary stopped has reported none, so a test that ends the process without reporting, for example with `os.Exit` or `log.Fatal`, cannot be listed",
		"The run of a package has to come to its end",
		"When a listed test panics, the package runs again without it",
		"The step fails when a run stops and no listed test reported a failure as it stopped: a test that is not listed, or the time limit of `go test`, stopped it",
		"It also fails the run when the run of an entry for a subtest starts another test under the path of that entry",
		"Every `go test` of the gate that runs tests gives each test binary a time limit of 20 minutes instead of the default of 10 of `go test`",
		"A test binary that runs longer panics with the stacks of its goroutines inside the job's own limit of 90 minutes, so the log shows where it hung",
		"`.github/ci/go_test_gate_selftest.py` checks these behaviors on every run before the tests",
		"It also holds the workflow file by its SHA-256, so every edit of the workflow has to change that value in the same change",
		"A green run is validation evidence for the committed tree on that runner image",
		"It is not design authority",
		"It is not a macOS run, a race-detector run, a Linux runtime proof, a Remote Alpha proof, or a supported-local proof",
		"does not replace the exact-Go preflights of the supported scripts",
		"The Nomad, Vault and SPIRE that a test starts there are throwaway test instances, not a deployment",
		"It does not show that a test named in the list passes: on that runner those tests fail or skip themselves",
		"A second workflow, `.github/workflows/go-macos.yml`, runs on the same events on a GitHub-hosted `macos-26` runner",
		"a change that breaks them only on macOS passes the Linux run",
		"The runner runs the same major version of macOS as the operator's Mac, so the tests meet the tools that this version of macOS ships, such as `/bin/bash`, `stat`, `chmod` and `/usr/bin/openssl`",
		"runs the self-check and the two gate steps for the packages that `./scripts/...` names, with a list of its own: `.github/ci/environment-only-tests-macos.txt`, under the same rules",
		"`go_test_gate.py` takes that package pattern as an optional third argument; without it the gate covers every package of the module",
		"The macOS job has the same limit of 90 minutes as the Linux job, so a test binary that hangs there also reaches the gate's limit of 20 minutes inside the job",
		"The self-check holds that workflow file by its SHA-256 as well",
		"A green macOS run is validation evidence that the tests of those packages that its list does not name pass on that runner image",
		"It is not a run of the other packages on macOS, and not a run on the operator's Mac",
	)
	assertContainsNone(t, "Go baseline stale CI denial", baselineDoc,
		"no CI system introduced",
		"skips exactly those entries",
	)
	ciWorkflow := mustRead(t, ".github/workflows/go.yml")
	assertContainsAll(t, "Go CI workflow matches the documented baseline", ciWorkflow,
		"\n  pull_request:\n",
		"\n  push:\n    branches:\n      - trunk_dev\n",
		"runs-on: ubuntu-24.04",
		"timeout-minutes: 90\n",
		"GOTOOLCHAIN: local",
		"GOFLAGS: -mod=readonly",
		"go-version-file: go.mod",
		"cache: false",
		"ENVIRONMENT_ONLY_TESTS: .github/ci/environment-only-tests.txt",
		"AWS_EC2_METADATA_DISABLED: \"true\"",
		"fetch https://releases.hashicorp.com/nomad/2.1.1/nomad_2.1.1_linux_amd64.zip nomad.zip 073084f7690fdaea756ff1eff8b669b25c3a6c17778f19ae0c47606973ed3f39",
		"fetch https://releases.hashicorp.com/vault/2.2.2/vault_2.2.2_linux_amd64.zip vault.zip 5700edf139113609962fe371af7d2a53de8ecb720d545dc39b43de204515d3c4",
		"source scripts/internal/spire_release.sh\n          spire_sha256=\"$(spire_release_pinned_sha256 spire-1.14.4-linux-amd64-musl.tar.gz)\"\n          fetch https://github.com/spiffe/spire/releases/download/v1.14.4/spire-1.14.4-linux-amd64-musl.tar.gz spire.tar.gz \"$spire_sha256\"\n",
		"echo \"$3  $tools/download/$2\" | sha256sum --check --strict",
		"run: nomad version && vault version",
		"run: go mod download",
		"run: go mod verify",
		"run: go build ./...",
		"run: go vet ./...",
		"run: GOOS=darwin GOARCH=arm64 go vet ./...",
		"run: python3 -I -B .github/ci/go_test_gate_selftest.py",
		"run: python3 -I -B .github/ci/go_test_gate.py gate \"$ENVIRONMENT_ONLY_TESTS\"",
		"run: python3 -I -B .github/ci/go_test_gate.py still-failing \"$ENVIRONMENT_ONLY_TESTS\"",
	)
	macOSWorkflow := mustRead(t, ".github/workflows/go-macos.yml")
	assertContainsAll(t, "Go macOS CI workflow matches the documented baseline", macOSWorkflow,
		"\n  pull_request:\n",
		"\n  push:\n    branches:\n      - trunk_dev\n",
		"runs-on: macos-26",
		"timeout-minutes: 90\n",
		"GOTOOLCHAIN: local",
		"GOFLAGS: -mod=readonly",
		"go-version-file: go.mod",
		"cache: false",
		"ENVIRONMENT_ONLY_TESTS: .github/ci/environment-only-tests-macos.txt",
		"TESTED_PACKAGES: ./scripts/...",
		"run: go mod download",
		"run: go mod verify",
		"run: python3 -I -B .github/ci/go_test_gate_selftest.py",
		"run: python3 -I -B .github/ci/go_test_gate.py gate \"$ENVIRONMENT_ONLY_TESTS\" \"$TESTED_PACKAGES\"",
		"run: python3 -I -B .github/ci/go_test_gate.py still-failing \"$ENVIRONMENT_ONLY_TESTS\" \"$TESTED_PACKAGES\"",
	)
	// The SPIRE release files that CI and the supported-local scripts accept.
	// Each line is the line of the release's own checksum file, checked by
	// downloading the file and hashing it. A change of a pin, or a new version
	// or architecture, has to come to this test as well.
	const spireReleasePins = "4482db434af8a3d2f4c5aeaef8912b21311411a175ce7daeb49ea17b776bcbf5  spire-1.14.4-linux-amd64-musl.tar.gz\n" +
		"05dd598f80b39499fd2b1660ee419cbb2d204290abe9fa0a87256177836ce7f0  spire-1.14.4-linux-arm64-musl.tar.gz\n"
	if got := mustRead(t, "scripts/internal/spire_release.sha256"); got != spireReleasePins {
		t.Fatalf("scripts/internal/spire_release.sha256 changed; review each line against its release checksum file, then update this test: got %q", got)
	}
	// The CI self-check holds the workflow file by its SHA-256. This test
	// requires that value to be the hash of the file as it is, so an edit of
	// the workflow is also caught by go test on any host, and not only by the
	// workflow step that runs the self-check.
	ciWorkflowHold := fmt.Sprintf("WORKFLOW_SHA256 = \"%x\"\n", sha256.Sum256([]byte(ciWorkflow)))
	if !strings.Contains(mustRead(t, ".github/ci/go_test_gate_selftest.py"), "\n"+ciWorkflowHold) {
		t.Fatalf("the CI self-check does not hold .github/workflows/go.yml as it is; review the whole workflow, then set %s", strings.TrimSpace(ciWorkflowHold))
	}
	macOSWorkflowHold := fmt.Sprintf("MACOS_WORKFLOW_SHA256 = \"%x\"\n", sha256.Sum256([]byte(macOSWorkflow)))
	if !strings.Contains(mustRead(t, ".github/ci/go_test_gate_selftest.py"), "\n"+macOSWorkflowHold) {
		t.Fatalf("the CI self-check does not hold .github/workflows/go-macos.yml as it is; review the whole workflow, then set %s", strings.TrimSpace(macOSWorkflowHold))
	}
	// The observed run of the CI gate is written against one Go version and
	// one file of its standard library. A change of the Go baseline has to
	// come to this test, and so to these two values.
	assertContainsAll(t, "Go CI gate observed-run toolchain", mustRead(t, ".github/ci/go_test_gate.py"),
		"\nOBSERVED_GO_VERSION = \"go1.26.5\"\n",
		"\nMATCH_GO_SHA256 = \"f28418759ed48c72821b5ecc3700041b74151108557618f50d355ea98a1bbebe\"\n",
	)
	// The time limit of each test binary that the gate starts, which the
	// baseline doc states.
	assertContainsAll(t, "Go CI gate test binary time limit", mustRead(t, ".github/ci/go_test_gate.py"),
		"\nTIME_LIMIT = \"20m\"\n",
		"command = [\"go\", \"test\", \"-json\", \"-timeout=\" + TIME_LIMIT] + arguments\n",
	)
	for _, path := range []string{
		".github/ci/environment-only-tests.txt",
		".github/ci/environment-only-tests-macos.txt",
		".github/ci/go_test_gate.py",
		".github/ci/go_test_gate_selftest.py",
	} {
		if strings.TrimSpace(mustRead(t, path)) == "" {
			t.Fatalf("Go CI file %s is empty", path)
		}
	}
	assertContainsAll(t, "Go baseline non-claims", nonClaims,
		"no runtime behavior change",
		"no CI claim beyond section 10",
		"no vendoring",
		"no system-wide toolchain manager",
		"no Linux runtime proof",
		"no PostgreSQL dependency",
		"no external database service",
		"no deployment performed",
	)

	linuxSetup := mustRead(t, "scripts/70_linux_setup.sh")
	assertContainsAll(t, "Linux setup exact official Go install", linuxSetup,
		"GO_REQUIRED_VERSION=\"go1.26.5\"",
		"GO_DOWNLOAD_BASE_URL=\"https://go.dev/dl\"",
		"select_go_toolchain_archive()",
		"go1.26.5.linux-amd64.tar.gz",
		"5c2c3b16caefa1d968a94c1daca04a7ca301a496d9b086e17ad77bb81393f053",
		"go1.26.5.linux-arm64.tar.gz",
		"fe4789e92b1f33358680864bbe8704289e7bb5fc207d80623c308935bd696d49",
		"unsupported Linux architecture for Go ${GO_REQUIRED_VERSION}",
		"require_go_toolchain_archive_cleanup_trap_ownership()",
		"for signal in EXIT HUP INT TERM",
		"trap -p \"${signal}\"",
		"pre-existing ${signal} trap prevents Go archive installation",
		"standalone installer requires exclusive cleanup-trap ownership for the bounded Go archive installation step",
		"register_go_toolchain_archive_cleanup \"${archive_path}\"",
		"trap 'go_toolchain_archive_cleanup_exit \"$?\"' EXIT",
		"trap 'go_toolchain_archive_cleanup_signal HUP' HUP",
		"kill -s \"${signal}\" \"$$\"",
		"sudo rm -rf /usr/local/go",
		"env GOTOOLCHAIN=local go version",
	)
	assertContainsInOrder(t, "Linux setup archive selection before sudo", linuxSetup,
		"# Non-mutating Go archive selection must run before the first sudo invocation.",
		"select_go_toolchain_archive",
		"require_go_toolchain_archive_cleanup_trap_ownership",
		"sudo -v",
	)
	assertContainsInOrder(t, "Linux setup trap ownership before mktemp", linuxSetup,
		"if [[ -z \"${archive}\" || -z \"${expected_sha256}\" ]]",
		"require_go_toolchain_archive_cleanup_trap_ownership",
		"download_url=\"${GO_DOWNLOAD_BASE_URL}/${archive}\"",
		"archive_path=\"$(mktemp)\"",
		"register_go_toolchain_archive_cleanup \"${archive_path}\"",
	)
	assertContainsInOrder(t, "Linux setup cleanup trap after mktemp", linuxSetup,
		"archive_path=\"$(mktemp)\"",
		"register_go_toolchain_archive_cleanup \"${archive_path}\"",
	)
	assertContainsInOrder(t, "Linux setup digest before replacement", linuxSetup,
		"observed_sha256=\"$(sha256sum",
		"sudo rm -rf /usr/local/go",
	)
	assertContainsNone(t, "Linux setup distro Go package", linuxSetup, "golang-go")
	assertContainsNone(t, "Linux setup pre-existing trap composition", linuxSetup,
		"GO_TOOLCHAIN_PREVIOUS",
		"restore_go_toolchain_archive_cleanup_traps",
		"eval ",
	)

	supportedSetup := mustRead(t, "scripts/72_supported_local_setup.sh")
	assertContainsAll(t, "supported-local setup Go policy", supportedSetup,
		"GO_REQUIRED_VERSION=\"go1.26.5\"",
		"env GOTOOLCHAIN=local go version",
		"supported_local_setup_requires_local_go()",
		"prebuilt/no-local-Go: not applicable for this setup entry point.",
		"preflight_supported_local_setup_go_if_required",
		"target_arch=\"$(env GOTOOLCHAIN=local go env GOARCH)\"",
		"env GOTOOLCHAIN=local CGO_ENABLED=0 GOOS=linux GOARCH=\"${target_arch}\" go build",
		"env GOTOOLCHAIN=local go run",
	)
	assertContainsInOrder(t, "supported-local setup preflight before mutation", supportedSetup,
		"# Exact Go preflight for local-Go-required setup paths must precede proof/process/workspace mutation.",
		"preflight_supported_local_setup_go_if_required",
		"supported_local_setup_repair_test_sentinel",
		"stop_background_process",
	)

	supportedProof := mustRead(t, "scripts/73_supported_local_proof.sh")
	assertContainsAll(t, "supported-local proof Go policy", supportedProof,
		"GO_REQUIRED_VERSION=\"go1.26.5\"",
		"env GOTOOLCHAIN=local go version",
		"supported_local_proof_requires_local_go()",
		"prebuilt/no-local-Go: not applicable for this proof entry point.",
		"preflight_supported_local_proof_go_if_required",
		"env GOTOOLCHAIN=local CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build",
	)
	assertContainsInOrder(t, "supported-local proof preflight before mutation", supportedProof,
		"# Exact Go preflight for local-Go-required proof paths must precede proof/process/workspace mutation.",
		"preflight_supported_local_proof_go_if_required",
		"supported_local_proof_repair_test_sentinel",
		"create_private_host_proof_dir",
	)

	operatorScriptTests := mustRead(t, "es/app/operator_scripts_integration_test.go")
	assertContainsAll(t, "hermetic Go baseline executable tests", operatorScriptTests,
		"TestLinuxSetupGoToolchainInstallerHermeticPreflightAndCleanup",
		"fake command resolution prevents host fallthrough",
		"pre-existing cleanup traps reject without installer-invoked prior handler",
		"[]string{\"EXIT\", \"HUP\", \"INT\", \"TERM\"}",
		"runLinuxSetupPreexistingTrapOwnershipSeam",
		"rejected installer call must not run prior",
		"caller-owned EXIT trap runs only when the bounded child shell exits deliberately",
		"caller-owned %s",
		"markerBeforeDeliberatePath",
		"expected trap ownership seam to reject",
		"linuxSetupFakeCommandNames = []string{\"sudo\", \"apt-get\", \"curl\", \"sha256sum\", \"mktemp\", \"rm\", \"tar\", \"install\", \"tee\", \"env\", \"go\", \"uname\", \"systemctl\"}",
		"assertFakeCommandsResolve",
		"fake commands accept only exact bounded grammars",
		"fake commands reject malformed argv without mutation",
		"fake mutators reject traversal symlink and wrong contained paths",
		"fake tar rejects internal symlink effect paths without outside mutation",
		"fake tar rejects invalid extraction root and non-regular leaf without success ledger",
		"runFakeCommand",
		"TestLinuxSetupFakeCommandHelper",
		"LINUX_SETUP_FAKE_TEST_BINARY",
		"linuxSetupFakeRequireExactPath",
		"linuxSetupFakeCanonicalContainedPath",
		"linuxSetupFakeValidateTarExtractionRoot",
		"linuxSetupFakeValidateTarEffectPath",
		"linuxSetupFakePreflightTarDescendants",
		"linuxSetupFakeEnsureTarDirectory",
		"linuxSetupFakeWriteTarGoBinary",
		"linuxSetupFakeRejectExistingSymlinkInTarEffectChain",
		"linuxSetupFakeForbiddenHostPath",
		"assertEventExactCount",
		"assertEventPrefixCount",
		"assertFakeTarSuccessTree",
		"reject:",
		"direct invocation unsupported",
		"curl extra flag",
		"curl reordered flag",
		"curl wrong output",
		"curl wrong hostname",
		"curl query string",
		"env wrong gotoolchain",
		"direct go rejected",
		"uname combined flag",
		"systemctl unsupported",
		"symlink outside",
		"extraction root symlink",
		"extraction root regular file",
		"go binary directory",
		"go symlink",
		"go bin symlink",
		"go binary symlink",
		"pre-existing symlink in tar effect path rejected",
		"outside directory sentinel changed",
		"outside file sentinel changed",
		"assertNoFakeGoRegularMarker",
		"wrong contained",
		"relative path rejected",
		"forbidden host path rejected",
		"repository path rejected",
		"path escapes fake root",
		"ordinary no pre-existing trap success path installs and cleans archive",
		"root-file-sentinel",
		"leaf-directory-sentinel",
		"TestSupportedLocalSetupExactGoPreflightBeforeMutation",
		"TestSupportedLocalProofExactGoPreflightBeforeMutation",
		"newLinuxSetupFakeHarness",
		"newSupportedLocalFakeHarness",
	)
	assertContainsInOrder(t, "fake tar effect paths and effects complete before success ledger", operatorScriptTests,
		"goRoot := filepath.Join(expectedRoot, \"go\")",
		"goBinDir := filepath.Join(expectedRoot, \"go\", \"bin\")",
		"goBinary := filepath.Join(goBinDir, \"go\")",
		"linuxSetupFakeValidateTarExtractionRoot(expectedRoot)",
		"for _, effectPath := range []string{goRoot, goBinDir, goBinary}",
		"linuxSetupFakeValidateTarEffectPath(effectPath, effectPath, expectedRoot)",
		"linuxSetupFakePreflightTarDescendants(goRoot, goBinDir, goBinary, expectedRoot)",
		"linuxSetupFakeEnsureTarDirectory(goRoot, expectedRoot)",
		"linuxSetupFakeEnsureTarDirectory(goBinDir, expectedRoot)",
		"linuxSetupFakeWriteTarGoBinary(goBinary, expectedRoot)",
		"linuxSetupFakeRecord(eventPrefix+archivePath",
	)
	assertContainsInOrder(t, "fake tar extraction root is lstat-validated as a real directory", operatorScriptTests,
		"func linuxSetupFakeValidateTarExtractionRoot(expectedRoot string) error",
		"os.Lstat(expectedRoot)",
		"info.Mode()&os.ModeSymlink != 0",
		"!info.IsDir()",
		"linuxSetupFakeRequireExactPath(expectedRoot, expectedRoot)",
		"linuxSetupFakeCanonicalContainedPath(expectedRoot)",
	)
	assertContainsInOrder(t, "fake tar relative dot root chain still lstats root", operatorScriptTests,
		"if rel == \".\" {",
		"os.Lstat(cleanRoot)",
		"info.Mode()&os.ModeSymlink != 0",
	)
	assertContainsInOrder(t, "fake tar writes through bounded open after leaf validation", operatorScriptTests,
		"func linuxSetupFakeWriteTarGoBinary(path string, extractionRoot string) error",
		"linuxSetupFakeValidateTarEffectPath(path, path, extractionRoot)",
		"os.Lstat(path)",
		"info.Mode()&os.ModeSymlink != 0",
		"if err := linuxSetupFakeValidateTarEffectPath(path, path, extractionRoot); err != nil {\n\t\treturn err\n\t}\n\tfile, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)",
		"file.Write([]byte(\"fake go\\n\"))",
		"linuxSetupFakeValidateTarEffectPath(path, path, extractionRoot)",
	)

	remoteAlphaBuild := mustRead(t, "scripts/internal/remote_alpha_deploy_es_binaries.sh")
	assertContainsAll(t, "Remote Alpha Go build policy", remoteAlphaBuild,
		"remote_alpha_deploy_es_binaries_required_go_version=\"go1.26.5\"",
		"env GOTOOLCHAIN=local go version",
		"\"env\", \"GOTOOLCHAIN=local\", \"CGO_ENABLED=0\", \"GOOS=linux\", \"GOARCH=amd64\", \"go\", \"build\"",
		"env GOTOOLCHAIN=local CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o \"${payload_dir}/es\" ./cmd/es",
		"env GOTOOLCHAIN=local CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o payload/es ./cmd/es",
	)

	controlPlane := mustRead(t, "scripts/internal/control_plane.sh")
	assertContainsAll(t, "control-plane arch detection", controlPlane,
		"machine=\"$(uname -m)\"",
		"x86_64|amd64",
		"aarch64|arm64",
		"env GOTOOLCHAIN=local go env GOARCH",
	)

	generator := mustRead(t, "scripts/generate_control_plane_dockerfile.sh")
	assertContainsAll(t, "control-plane Dockerfile generator Go policy", generator,
		"FROM golang:1.26.5-alpine3.24 AS build",
		"ENV GOTOOLCHAIN=local",
		"CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH} go build",
	)

	generatedPath := filepath.Join(t.TempDir(), "Dockerfile")
	cmd := exec.Command("./scripts/generate_control_plane_dockerfile.sh", generatedPath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("generate Dockerfile: %v output=%s", err, string(output))
	}
	generatedDockerfile, err := os.ReadFile(generatedPath)
	if err != nil {
		t.Fatalf("read generated Dockerfile: %v", err)
	}
	trackedDockerfile, err := os.ReadFile(".out/Dockerfile")
	if err != nil {
		t.Fatalf("read tracked Dockerfile: %v", err)
	}
	if !bytes.Equal(generatedDockerfile, trackedDockerfile) {
		t.Fatalf("tracked .out/Dockerfile does not match scripts/generate_control_plane_dockerfile.sh")
	}
	assertContainsAll(t, "tracked generated Dockerfile", string(trackedDockerfile),
		"FROM golang:1.26.5-alpine3.24 AS build",
		"ENV GOTOOLCHAIN=local",
	)

	dependencyGate := compactDocSection(t, mustRead(t, ".docs/execution_lifecycle/reliable_submit_persistence_and_concurrency.md"), "## 14. Required Dependency-Selection Gate", "## 15. First Concrete Source Tranche")
	assertContainsAll(t, "reliable-submit dependency gate Go baseline", dependencyGate,
		"Go 1.26.5 compatibility",
		"CGO-free builds under `CGO_ENABLED=0`",
	)
	assertContainsNone(t, "reliable-submit dependency gate old Go baseline", dependencyGate, "Go 1.22 compatibility")
}

const (
	staleTargetMaxRelationSpan = 200
)

// This deliberately bounded grammar catches stale target-architecture
// relationships in either direction; it is not general semantic parsing.
// The closed grammar is section-scoped by its call sites, uses only the
// protected subject/target vocabularies below, recognizes is/remains/becomes
// and is-designated-as relationships, treats only direct is-not,
// is-no-longer, and no-longer-remains forms as negated, scans only within
// sentence units terminated by '.', '!', or '?', and caps relation spans.
var (
	staleTargetProtectedSubjectPattern = regexp.MustCompile(`(?i)\b(?:shape\s+a|(?:the\s+)?cp-authoritative(?:\s+product)?[-\s]+path)\b`)
	staleTargetPhrasePattern           = regexp.MustCompile(`(?i)\b(?:the\s+)?(?:enduring|permanent)\s+target\s+architecture\b`)
	staleTargetRelationshipVerbPattern = regexp.MustCompile(`(?i)\b(?:no\s+longer\s+remains|is(?:\s+(?:not|no\s+longer))?(?:\s+designated(?:\s+as)?)?|remains|becomes)\b`)
	staleTargetDirectNegationPattern   = regexp.MustCompile(`(?i)\b(?:is\s+(?:not|no\s+longer)(?:\s+designated(?:\s+as)?)?|no\s+longer\s+remains)\b`)
)

func staleTargetRelationshipUnits(text string) []string {
	compact := compactText(text)
	if compact == "" {
		return nil
	}

	var units []string
	start := 0
	for index, char := range compact {
		if char != '.' && char != '!' && char != '?' {
			continue
		}
		unit := strings.TrimSpace(compact[start : index+1])
		if unit != "" {
			units = append(units, unit)
		}
		start = index + 1
	}
	if tail := strings.TrimSpace(compact[start:]); tail != "" {
		units = append(units, tail)
	}
	return units
}

func staleTargetRelationshipIsAffirmative(relationText string) bool {
	for _, match := range staleTargetRelationshipVerbPattern.FindAllString(relationText, -1) {
		if !staleTargetDirectNegationPattern.MatchString(match) {
			return true
		}
	}
	return false
}

func staleTargetRelationshipMatch(text string) (string, string, bool) {
	for _, unit := range staleTargetRelationshipUnits(text) {
		subjects := staleTargetProtectedSubjectPattern.FindAllStringIndex(unit, -1)
		targets := staleTargetPhrasePattern.FindAllStringIndex(unit, -1)
		for _, subject := range subjects {
			for _, target := range targets {
				if subject[1] <= target[0] && target[0]-subject[1] <= staleTargetMaxRelationSpan {
					relation := unit[subject[1]:target[0]]
					if staleTargetRelationshipIsAffirmative(relation) {
						return "protected subject first", strings.TrimSpace(unit[subject[0]:target[1]]), true
					}
				}
				if target[1] <= subject[0] && subject[0]-target[1] <= staleTargetMaxRelationSpan {
					relation := unit[target[1]:subject[0]]
					if staleTargetRelationshipIsAffirmative(relation) {
						return "protected target first", strings.TrimSpace(unit[target[0]:subject[1]]), true
					}
				}
			}
		}
	}
	return "", "", false
}

func assertNoStaleTargetRelationship(t *testing.T, label string, text string) {
	t.Helper()

	relationship, match, found := staleTargetRelationshipMatch(text)
	if found {
		t.Fatalf("%s must not contain stale target relationship %s: %q", label, relationship, match)
	}
}

func assertStaleTargetRelationshipExamples(t *testing.T) {
	t.Helper()

	for _, tc := range []struct {
		name       string
		text       string
		wantReject bool
	}{
		{
			name:       "subject first shape a remains permanent target",
			text:       "Shape A remains the permanent target architecture.",
			wantReject: true,
		},
		{
			name:       "subject first shape a becomes enduring target",
			text:       "Shape A becomes the enduring target architecture.",
			wantReject: true,
		},
		{
			name:       "subject first cp authoritative path is enduring target",
			text:       "The CP-authoritative path is the enduring target architecture.",
			wantReject: true,
		},
		{
			name:       "subject first cp authoritative product path designated permanent target",
			text:       "The CP-authoritative product path is designated as the permanent target architecture.",
			wantReject: true,
		},
		{
			name:       "target first permanent target remains shape a",
			text:       "The permanent target architecture remains Shape A.",
			wantReject: true,
		},
		{
			name:       "target first enduring target is cp authoritative path",
			text:       "The enduring target architecture is the CP-authoritative path.",
			wantReject: true,
		},
		{
			name:       "target first permanent target becomes shape a",
			text:       "The permanent target architecture becomes Shape A.",
			wantReject: true,
		},
		{
			name:       "target first enduring target designated cp authoritative path",
			text:       "The enduring target architecture is designated as the CP-authoritative path.",
			wantReject: true,
		},
		{
			name:       "subject first shape a not permanent target",
			text:       "Shape A is not the permanent target architecture.",
			wantReject: false,
		},
		{
			name:       "subject first shape a no longer permanent target",
			text:       "Shape A is no longer the permanent target architecture.",
			wantReject: false,
		},
		{
			name:       "subject first cp authoritative path not enduring target",
			text:       "The CP-authoritative path is not the enduring target architecture.",
			wantReject: false,
		},
		{
			name:       "target first permanent target not shape a",
			text:       "The permanent target architecture is not Shape A.",
			wantReject: false,
		},
		{
			name:       "target first enduring target no longer cp authoritative path",
			text:       "The enduring target architecture is no longer the CP-authoritative path.",
			wantReject: false,
		},
		{
			name:       "subject first shape a no longer remains permanent target",
			text:       "Shape A no longer remains the permanent target architecture.",
			wantReject: false,
		},
		{
			name:       "subject first cp authoritative path no longer remains enduring target",
			text:       "The CP-authoritative path no longer remains the enduring target architecture.",
			wantReject: false,
		},
		{
			name:       "subject first cp authoritative product path no longer remains permanent target",
			text:       "The CP-authoritative product path no longer remains the permanent target architecture.",
			wantReject: false,
		},
		{
			name:       "target first permanent target no longer remains shape a",
			text:       "The permanent target architecture no longer remains Shape A.",
			wantReject: false,
		},
		{
			name:       "target first enduring target no longer remains cp authoritative path",
			text:       "The enduring target architecture no longer remains the CP-authoritative path.",
			wantReject: false,
		},
		{
			name:       "target first permanent target no longer remains cp authoritative product path",
			text:       "The permanent target architecture no longer remains the CP-authoritative product path.",
			wantReject: false,
		},
		{
			name:       "sentence terminal period boundary",
			text:       "Shape A remains only a historical label. The permanent target architecture is intentionally left open.",
			wantReject: false,
		},
		{
			name:       "sentence terminal exclamation boundary",
			text:       "Shape A remains only a historical label! The permanent target architecture is intentionally left open.",
			wantReject: false,
		},
		{
			name:       "sentence terminal question boundary",
			text:       "Shape A remains only a historical label? The permanent target architecture is intentionally left open.",
			wantReject: false,
		},
		{
			name:       "unrelated not does not negate affirmative stale relation",
			text:       "Shape A is, not merely was, the permanent target architecture.",
			wantReject: true,
		},
		{
			name:       "unrelated no longer does not negate affirmative stale relation",
			text:       "Shape A is no longer only historical and remains the permanent target architecture.",
			wantReject: true,
		},
		{
			name:       "historical former shape a",
			text:       "Shape A was the former target architecture.",
			wantReject: false,
		},
		{
			name:       "historical shape a migration discussion",
			text:       "Shape A appears only in a historical migration discussion.",
			wantReject: false,
		},
		{
			name:       "historical descriptions may mention shape a",
			text:       "Historical descriptions may say Shape A was a former target for migration context.",
			wantReject: false,
		},
		{
			name:       "cp authoritative current compatibility only",
			text:       "The CP-authoritative path is not the target and remains current demo or migration context only.",
			wantReject: false,
		},
		{
			name:       "bare vocabulary only",
			text:       "Shape A, CP, Control Plane, CP-authoritative, target architecture, historical, and migration are allowed vocabulary.",
			wantReject: false,
		},
	} {
		t.Run("stale target relationship/"+tc.name, func(t *testing.T) {
			_, match, gotReject := staleTargetRelationshipMatch(tc.text)
			if gotReject != tc.wantReject {
				t.Fatalf("stale relationship detection mismatch: got reject=%v match=%q, want reject=%v", gotReject, match, tc.wantReject)
			}
		})
	}
}

func markdownTableRowByFirstCell(t *testing.T, doc string, rowKey string) []string {
	t.Helper()

	var matches [][]string
	for _, line := range strings.Split(doc, "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "|") {
			continue
		}
		parts := strings.Split(strings.Trim(trimmed, "|"), "|")
		for i := range parts {
			parts[i] = strings.TrimSpace(parts[i])
		}
		if len(parts) > 0 && parts[0] == rowKey {
			matches = append(matches, parts)
		}
	}

	if len(matches) != 1 {
		t.Fatalf("expected exactly one %q table row, found %d", rowKey, len(matches))
	}
	return matches[0]
}

func compactTableRow(row []string) string {
	return compactText(strings.Join(row, " "))
}

func assertNoActiveShellDispatchArm(t *testing.T, label string, source string, route string) {
	t.Helper()

	for lineNumber, line := range strings.Split(source, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || !strings.Contains(trimmed, route) {
			continue
		}
		for _, marker := range []string{
			`"$1" == "` + route + `"`,
			`"$1" = "` + route + `"`,
			`"${1}" == "` + route + `"`,
			`"${1}" = "` + route + `"`,
			`"$subcommand" == "` + route + `"`,
			`"$subcommand" = "` + route + `"`,
			`"${subcommand}" == "` + route + `"`,
			`"${subcommand}" = "` + route + `"`,
			route + `)`,
			`"` + route + `")`,
			`'` + route + `')`,
			route + `|`,
			`|` + route,
		} {
			if strings.Contains(trimmed, marker) {
				t.Fatalf("%s must not contain active dispatch arm for %q at line %d: %s", label, route, lineNumber+1, trimmed)
			}
		}
	}
}

func assertOmitsLifecycleProjectionSchedulerDerivation(t *testing.T, label string, text string) {
	t.Helper()

	assertContainsNone(t, label, text,
		"ModifyIndex",
		"modify index",
		"modify-index",
		"nomad-index",
		"job modify index",
		"selected-allocation modify index",
		"max ModifyIndex",
		"backend ordering",
		"scheduler ordering",
	)
}

func TestSubmitIdempotencyCorrelationAndRecoveryDocsContract(t *testing.T) {
	targetPath := ".docs/execution_lifecycle/submit_idempotency_correlation_and_recovery.md"
	targetRaw := mustRead(t, targetPath)
	statusPurpose := compactDocSection(t, targetRaw, "## 1. Status And Purpose", "## 2. Current Implementation Reality")
	currentReality := compactDocSection(t, targetRaw, "## 2. Current Implementation Reality", "## 3. Dual Ambiguity Model")
	dualAmbiguity := compactDocSection(t, targetRaw, "## 3. Dual Ambiguity Model", "## 4. Authority And Identity Ownership")
	authorityIdentity := compactDocSection(t, targetRaw, "## 4. Authority And Identity Ownership", "## 5. Reliable Keyed-Submit Invariant")
	reliableInvariant := compactDocSection(t, targetRaw, "## 5. Reliable Keyed-Submit Invariant", "## run_id Phase And Disclosure Invariants")
	runIDPhase := compactDocSection(t, targetRaw, "## run_id Phase And Disclosure Invariants", "## Effective Execution Plan And Field Requiredness")
	effectivePlan := compactDocSection(t, targetRaw, "## Effective Execution Plan And Field Requiredness", "## 7. Narrow Durable Correlation Semantics")
	narrowRecord := compactDocSection(t, targetRaw, "## 7. Narrow Durable Correlation Semantics", "## 8. Ordering And Concurrency Invariants")
	ordering := compactDocSection(t, targetRaw, "## 8. Ordering And Concurrency Invariants", "## 9. ES-To-Nomad Reconciliation")
	nomadReconciliation := compactDocSection(t, targetRaw, "## 9. ES-To-Nomad Reconciliation", "## 10. Semantic Outcome Classes")
	outcomes := compactDocSection(t, targetRaw, "## 10. Semantic Outcome Classes", "## 11. Replay, Authorization, And Admission")
	replayAuth := compactDocSection(t, targetRaw, "## 11. Replay, Authorization, And Admission", "## 12. Retention And Expiry")
	retention := compactDocSection(t, targetRaw, "## 12. Retention And Expiry", "## 13. Compatibility And Opt-In Treatment")
	compatibility := compactDocSection(t, targetRaw, "## 13. Compatibility And Opt-In Treatment", "## 14. Safe Projection And Privacy")
	safeProjection := compactDocSection(t, targetRaw, "## 14. Safe Projection And Privacy", "## 15. Explicit Non-Claims")
	nonClaims := compactDocSection(t, targetRaw, "## 15. Explicit Non-Claims", "## 16. Required-Before-Implementation Gates")
	gates := compactDocSection(t, targetRaw, "## 16. Required-Before-Implementation Gates", "## 17. Open Seams")
	openSeams := compactDocSection(t, targetRaw, "## 17. Open Seams", "")

	assertContainsAll(t, "submit recovery target document status", statusPurpose,
		"TARGET-ONLY: public/operational submit idempotency, correlation, and recovery in this document remain target direction.",
		"CURRENT-UNCHANGED: current unkeyed submit remains the implemented behavior.",
		"does not implement runtime behavior",
		"does not select HTTP status mapping or public error strings",
		"does not add public response DTOs",
		"persistence and concurrency ADR",
		"selects local embedded SQLite as the first storage backend",
		"`modernc.org/sqlite v1.54.0` as the CGO-free driver",
		"private same-package durable-store source",
		"leaving runtime integration open",
		"selects the public opt-in/versioning posture and delegates the persistence/concurrency decision",
		"the existing submit route is retained",
		"the future reliable request is a submit-specific request family distinct from `PrepareRequest`",
		"producer-declaration preflight and an in-band structural request discriminator are both required",
		"header-only opt-in is rejected",
		"silent downgrade to current unkeyed submit is forbidden",
		"unavailable contract-adapter foundation",
		"No current public request field, public response DTO field, producer field, handler behavior, query route, Nomad behavior, runtime configuration, or runtime behavior is implemented by this document, the private store tranche, or the unavailable contract-adapter foundation",
	)
	assertContainsAll(t, "submit recovery current reality", currentReality,
		"top-level fields are `schema_version`, `invocation`, `mode`, `timeout_seconds`, and `resources`",
		"Current body decoding is strict",
		"adding a body field for reliable keyed submit would be a versioning event",
		"has no caller-provided submit idempotency key",
		"no exact replay contract",
		"no recovery lookup",
		"Current `validatePrepareRequest` defaults a blank `schema_version`",
		"A changed value in that existing `schema_version` field is not, by itself, the selected reliable-submit discriminator",
		"random public `run_id`",
		"`exec-<run_id>`",
		"Current `run_id` creation happens before execution-package staging",
		"Execution-package staging happens before Nomad registration",
		"bounded `202` `SubmitResult` only after ES has confirmed a Nomad registration response",
		"status, logs, cancel, and result lookup currently require `run_id`",
		"no broad durable run registry",
		"no ES-owned lifecycle store",
		"On every post-claim return, current submit closes held descriptors and retains the visible staged root",
		"implements latest-operation same-operation replay",
		"general mutation path derives and compares a complete private latest-operation descriptor",
		"Same mutation plus same operation kind and input binding replays the committed result without another CAS",
		"Same mutation plus different descriptor conflicts",
		"Migrated legacy/unbound rows preserve only the retained mutation reference",
		"fail closed for same-mutation replay",
		"persists no mutation history",
		"private store remains runtime-unwired",
		"no current public execution behavior is affected",
	)
	assertContainsAll(t, "submit recovery dual ambiguity", dualAmbiguity,
		"Caller-To-ES Ambiguity",
		"ES may accept a submission",
		"the caller or adapter may lose the response before receiving that `run_id`",
		"Current unkeyed submit gives that caller no public recovery key",
		"ES-To-Nomad Ambiguity",
		"Nomad may accept it",
		"transport error, timeout, malformed response, missing response, unreadable response",
		"does not prove rejection",
		"returns `submission_failed` when the Nomad response is not confirmed",
		"retains the complete staging root",
		"must not equate an uncertain Nomad response with proof that no job was accepted",
		"must also not automatically send a second Nomad registration",
		"Both ambiguity windows are ES-owned contract problems",
		"must not solve them by scraping Nomad",
		"treating trace IDs or request IDs as recovery authority",
	)
	assertContainsAll(t, "submit recovery authority ownership", authorityIdentity,
		"authenticated caller identity owns the initial namespace boundary",
		"Submit idempotency is not authorization, admission, or execution permission",
		"ES owns the reliable-submit protocol",
		"Nomad owns submitted execution lifecycle",
		"Coordinator owns its own semantic attempt and dispatch-command identities",
		"An adapter owns only ephemeral transport or session identity",
		"ES need not understand Coordinator work-item or attempt semantics",
	)
	assertContainsAll(t, "submit recovery reliable invariant", reliableInvariant,
		"Reliable keyed submit is explicitly opt-in",
		"One authenticated-caller namespace and submit idempotency key identifies one reliable-submit claim",
		"becomes capable of execution-producing staging or Nomad registration",
		"assigns exactly one immutable `run_id` before the first execution-producing effect",
		"Exact retry cannot create another stage package",
		"another Nomad job",
		"Concurrent exact retries converge",
		"exact redelivery of the latest already committed operation replays the committed result without new mutation or external effect",
		"Accepted replay returns the same accepted record and receipt",
		"Provably-not-accepted replay returns the same terminal record",
		"private source repair is complete for latest-operation replay",
		"public reliable-submit runtime enablement is still a later gate",
		"conflicting reuse",
		"before another execution-producing side effect",
		"different authenticated caller cannot probe",
		"A transport retry is not a new semantic execution",
		"A new semantic execution requires a new caller key",
		"final `run_id` generation algorithm remains open",
	)
	assertContainsAll(t, "submit recovery run_id phase and disclosure", runIDPhase,
		"## run_id Phase And Disclosure Invariants",
		"The target reliable-submit contract is state-specific",
		"rather than treating `run_id` as one broadly optional field",
		"Pre-claim rejection",
		"Not created",
		"does not allocate a `run_id`",
		"Optional non-effect-capable claim before run assignment",
		"no execution-producing staging or provider effect is permitted",
		"Effect-capable claim after run assignment",
		"Required and immutable",
		"exactly one ES-assigned immutable `run_id`",
		"\"at most one `run_id`\" is insufficient for this phase",
		"no second `run_id` may ever be assigned",
		"Pending before assignment",
		"No effect-producing operation may have begun",
		"Pending after assignment",
		"Recovery to the same authorized caller preserves and exposes that same `run_id`",
		"presence does not prove Nomad acceptance",
		"Ambiguous before assignment",
		"No provider effect may be inferred",
		"Ambiguous after assignment or possible provider effect",
		"the outcome remains ambiguous until ES-owned reconciliation",
		"Accepted",
		"The bounded submit receipt carries the same `run_id`",
		"Exact replay",
		"preserves the underlying claim phase",
		"never creates another `run_id` or execution-producing effect",
		"Recovered accepted",
		"carries the original `run_id`",
		"Provably not accepted after assignment",
		"must not be represented as an accepted execution",
		"the already assigned `run_id` remains internally bound to the claim",
		"the old semantic command does not silently reuse the same key",
		"Conflict",
		"The conflicting request creates no new `run_id`",
		"must not receive the existing claim's `run_id`",
		"Expired or unavailable correlation",
		"not evidence that no historical `run_id` or execution existed",
		"generic absence must not be modeled as \"no run existed.\"",
		"Unauthorized",
		"No existence or `run_id` disclosure",
		"Coordinator must not enter submitted, running, cancellation, logs, result, or other lifecycle-bearing progression without a correlated `run_id`",
		"unresolved submit/correlation state keyed by its own durable dispatch identity and the ES submit key",
		"An adapter acknowledgement is not a substitute for `run_id`",
		"`run_id` is an ES-owned external reference, not Coordinator semantic attempt identity",
		"one undifferentiated record with a broadly optional `run_id` field",
		"make invalid `run_id` and outcome combinations unrepresentable",
		"The exact model technique remains open",
	)
	assertContainsAll(t, "submit recovery effective execution plan", effectivePlan,
		"## Effective Execution Plan And Field Requiredness",
		"private canonical request and effective-plan binding",
		"one complete resolved effective execution plan before the first execution-producing staging or Nomad-registration effect",
		"covers effective values, not only sparse transport input or caller-controlled JSON",
		"user intent",
		"model planning",
		"standing policy",
		"Coordinator derivation",
		"ES-owned compatibility or default resolution",
		"selected runtime profile",
		"artifact or package metadata",
		"Origin does not change requiredness",
		"use the originally bound effective values",
		"Mutable defaults, current policy, runtime-profile revisions, environment changes, or service configuration must not silently alter the replayed execution",
		"immutable or versioned references sufficient to reproduce and conflict-check the effective plan",
		"Provider-generated volatile facts such as Nomad allocation IDs or EvalID are not part of the caller plan",
		"empty argument-addition list, environment-addition map, or mount list is a concrete bound value",
		"explicitly inapplicable rather than ambiguously omitted",
		"Absent sparse input may be valid for the legacy API",
		"Coordinator-managed reliable dispatch must be resolved and bound",
		"### Required Field And Fact Matrix",
		"Field or fact",
		"Authoritative/defaulting owner",
		"Allowed source or origin",
		"Phase where required",
		"Phase where forbidden or inapplicable",
		"Immutability point",
		"Replay-binding treatment",
		"Public/private treatment",
		"Validation authority",
		"Redaction or projection treatment",
		"Request schema or version",
		"Execution mode",
		"Timeout policy and effective timeout semantics",
		"Effective CPU",
		"Effective memory",
		"Runtime profile",
		"Artifact digest",
		"Derivation-spec digest",
		"Output identity",
		"Effective command and argument vector",
		"Environment additions",
		"Mounts",
		"Network posture",
		"Authority-handoff applicability",
		"Submit idempotency key",
		"Private request/effective-plan binding",
		"Assigned `run_id`",
		"Cancellation identity or cancellation-command correlation",
		"Retained-result reference",
		"Validation-evidence reference",
		"does not choose exact timeout, CPU, memory, runtime-profile value, final field layout, or final transport shape",
		"legacy ES transport may continue to accept compatibility defaults",
		"every execution-shaping value must still be concrete and bound before effect",
		"Schema or version, mode, timeout semantics, resources, runtime profile, artifact, derivation, output, effective command, environment, mounts, network, and authority-handoff applicability must be resolved before effect",
		"The reliable submit key is required before establishing the reliable claim",
		"The private effective-plan binding is required before the claim becomes effect-capable",
		"`run_id` follows the phase-requiredness table",
		"Cancellation identity is required only when a cancellation effect is requested",
		"Result and validation references are required only when those external facts exist",
		"Empty collections are concrete values",
		"Explicitly inapplicable values are distinct from unresolved values",
		"does not mean every ES field becomes a native first-class Coordinator database column",
		"Coordinator may retain an immutable execution-plan reference, safe binding, or typed boundary value",
		"ES remains validation and execution-admission authority",
		"Coordinator must not reimplement ES defaulting, admission, or runtime-profile semantics",
		"field-requiredness/effective-plan matrix are binding local-gate inputs",
		"later ES request, receipt, and error models and to Coordinator dispatch, command, and observation models",
		"must not begin until they can make the required and forbidden combinations unrepresentable or fail closed",
		"local dependency gate for those model tranches, not a prerequisite for unrelated project work",
	)
	assertContainsAll(t, "submit recovery narrow record", narrowRecord,
		"requires ES-owned durable recovery evidence sufficient to survive ES restart",
		"authenticated caller namespace",
		"opaque submit idempotency key or safe private representation",
		"private request binding",
		"assigned `run_id`",
		"bounded submission outcome class",
		"bounded original submit receipt or sufficient data to reproduce it",
		"retention and expiry information when selected",
		"must not become",
		"an allocation history",
		"a runtime status timeline",
		"a log index",
		"a result-content store",
		"cancellation-completion truth",
		"a runtime retry or reschedule policy store",
		"Coordinator desired state",
		"a Nomad mirror",
		"selects local embedded SQLite as the storage family",
		"preserves the current `CGO_ENABLED=0` build posture",
		"selects `modernc.org/sqlite v1.54.0`",
		"`modernc.org/libc v1.74.1`",
		"selects private same-package persistence hydration",
		"freezes revision/CAS plus provider-effect-intent ordering",
		"does not select the state-path config key, TTL, public request or receipt vocabulary, Nomad reconciliation mechanism, or runtime integration",
	)
	assertContainsAll(t, "submit recovery ordering", ordering,
		"Caller authentication and authorization occur before existence disclosure",
		"Request validation and conflict determination fail closed",
		"One authenticated-caller/key claim wins under concurrent first delivery",
		"A durable key claim and assigned `run_id` exist before any execution-producing staging or Nomad registration effect",
		"External I/O does not occur inside the narrow durable-state transaction",
		"Exact redelivery observes the existing claim",
		"Acknowledgement of the key claim is not Nomad acceptance",
		"A Nomad response is not semantic work acceptance",
		"Unknown remains unknown until reconciled",
		"No particular transaction API is prescribed",
	)
	assertContainsAll(t, "submit recovery Nomad reconciliation", nomadReconciliation,
		"ES may use its own stable assigned `run_id` and internal job locator to reconcile the submit effect",
		"Coordinator and adapters must not scrape Nomad",
		"Nomad metadata, allocation IDs, EvalID, trace IDs, and request IDs do not become caller recovery authority",
		"An uncertain Nomad response must not automatically trigger a second Nomad submission",
		"accepted, provably not accepted, still pending, or ambiguous",
		"Absence is not sufficient proof of no acceptance",
		"Stage or other recovery material required for reconciliation must not be destroyed merely because the immediate Nomad response was uncertain",
		"does not define the final Nomad query or reconciliation algorithm",
		"does not rely on undocumented Nomad re-registration behavior",
	)
	assertContainsAll(t, "submit recovery semantic outcomes", outcomes,
		"without selecting exact public JSON field names, HTTP status codes, route shapes, or error strings",
		"transport-neutral ES outcome projection",
		"does not encode HTTP status mapping",
		"accepted: one execution was accepted",
		"exact replay: return the same known outcome without another execution-producing effect",
		"conflict: the same caller/key was used for a non-equivalent request; perform no new effect",
		"pending: the keyed submission is still being processed or reconciled; perform no duplicate effect",
		"provably not accepted: ES has positive evidence that no execution-producing provider effect was accepted",
		"ambiguous: ES cannot yet prove accepted or not accepted",
		"caller must not automatically issue a new semantic execution",
		"expired or unavailable correlation",
		"not proof that no execution existed",
		"does not silently permit reuse",
		"unauthorized: deny without disclosing whether the correlation exists",
		"Exact public vocabulary and HTTP/public outcome mapping remain open",
	)
	assertContainsAll(t, "submit recovery replay auth", replayAuth,
		"Idempotency does not authorize execution",
		"First submission still passes authentication, authorization, admission, runtime-profile compatibility, and existing ES policy boundaries",
		"Replay and lookup remain caller-authorized operations",
		"Revoked or unauthorized callers do not gain access merely by knowing a key",
		"Exact replay cannot widen originally accepted execution effects",
		"returning a prior receipt from admitting a new execution",
		"Whether mutable admission policy is re-evaluated for read-only receipt recovery remains open",
	)
	assertContainsAll(t, "submit recovery retention", retention,
		"Retention must cover the supported duplicate-delivery and recovery window",
		"Deletion or expiry cannot be represented as proof that no prior execution existed",
		"Automatic key reuse after expiry is not allowed by inference",
		"A new semantic attempt uses a new key",
		"Exact TTL, tombstone, garbage-collection, and archival behavior remain open",
		"bounded and non-lifecycle",
	)
	assertContainsAll(t, "submit recovery compatibility", compatibility,
		"Current submit without the new key remains valid current behavior",
		"Current no-key submit does not gain reliable replay or recovery claims",
		"Reliable Coordinator-backed dispatch must use the future explicit opt-in",
		"`control-plane-normal-shell/v1` remains unchanged",
		"Current submit, status, logs, result, cancel, `authority_handoff`, and `outcome_evidence` compatibility remain unchanged",
		"`schema_version = \"execution-substrate.producer-contract/v1\"`",
		"`governed_execution.contract = \"governed-execution-producer/v1\"`",
		"one explicitly named and versioned reliable-submit producer sub-contract",
		"not a generic `capabilities` map",
		"two independent fail-closed gates",
		"require the exact reliable-submit sub-contract and enabled status",
		"The target reliable request uses the existing `POST /v1/executions:submit` route",
		"does not select a new route",
		"The reliable variant uses a submit-specific request family",
		"`execution-substrate.reliable-submit-request/v1`",
		"`reliable_submit`",
		"`submit_key`",
		"must not remain merely an optional semantic interpretation of `PrepareRequest`",
		"current server rejects a future reliable body carrying `reliable_submit` before calling current `Submit` behavior",
		"changed value in the existing `schema_version` field alone is not the selected discriminator",
		"Header-only reliable-submit opt-in is rejected",
		"this tranche selects no supplemental header",
		"absent, incompatible, disabled, or unavailable",
		"must stop before submit",
		"before execution-package staging",
		"before Nomad registration",
		"before any fallback to current unkeyed `Submit`",
		"Disabling the future reliable mode must fail closed",
		"not silently fall back to unkeyed submission",
		"Current `POST /v1/executions:prepare` remains the current bounded preflight surface",
		"does not select a reliable prepare variant",
		"claim creation during prepare",
		"`run_id` allocation during prepare",
		"prepare-to-submit claim transfer",
		"Current CP/demo and `control-plane-normal-shell/v1` compatibility remains unchanged",
		"Current CP and IM consumers may ignore the additive reliable-submit sub-declaration",
		"does not make CP or IM part of the target autonomous-development topology",
	)
	assertContainsAll(t, "submit recovery safe projection", safeProjection,
		"must not contain the raw submit idempotency key",
		"must not expose raw request bodies",
		"environment values",
		"credentials",
		"trust material",
		"local paths",
		"scheduler IDs",
		"allocation IDs",
		"EvalID",
		"trace IDs",
		"request IDs as recovery authority",
		"bounded submit correlation and receipt facts",
		"Existence must not leak across authenticated caller namespaces",
		"not Coordinator or runtime lifecycle truth",
	)
	assertContainsAll(t, "submit recovery non-claims", nonClaims,
		"no reliable submit runtime integration implemented",
		"no runtime behavior implemented",
		"no producer declaration field implemented",
		"no public request DTO implemented",
		"no public/runtime reliable-submit handler or route decoder is wired; the private admission-local `parseValidatedReliableSubmitRequest` and `decodeStrictReliableSubmitJSON` helpers remain unwired;",
		"no route implementation",
		"no public or runtime persistence integration",
		"no global state-path configuration or service-startup database construction",
		"no public or runtime schema, migration, backup, restore, or storage migration tooling exposed to operators",
		"no exact HTTP code selected",
		"no error string selected",
		"no public persistent receipt-store implementation",
		"no public reliable response field names",
		"no final `run_id` generation strategy",
		"no deterministic `run_id` decision",
		"no recovery query selected",
		"no supplemental header selected",
		"no reliable prepare selected",
		"no Nomad registration retry decision",
		"no Nomad behavior implemented",
		"no broad lifecycle store",
		"no scheduler",
		"no Coordinator schema",
		"no Bridge widening",
		"no gateway service",
		"no connector dependency",
		"no Development Program prerequisite",
		"no direct local Codex target path",
		"no CP target topology",
		"no general capability registry",
		"no silent unkeyed fallback",
		"no automatic merge or deployment behavior",
	)
	assertContainsNone(t, "submit recovery non-claims reject stale private persistence denial", nonClaims,
		"- no persistence;",
		"- no schema or migration;",
		"reliable submit is implemented end to end",
		"Reliable submit is implemented end to end",
		"no handler or decoder implemented",
	)
	assertContainsAll(t, "submit recovery gates", gates,
		"preserved public opt-in and versioning docs-contract coverage",
		"reliable request foundation and producer sub-contract target tests",
		"`reliable-submit-durable-same-operation-replay-repair`",
		"source-grounded resolved-plan extraction (satisfied by the private current-Submit foundation)",
		"narrow persistence and concurrency ADR decision",
		"ES-to-Nomad uncertain-outcome reconciliation decision",
		"retention and expiry decision",
		"security and privacy review",
		"request, receipt, and error model tests",
		"compatibility tests",
		"implementation provenance and independent audit",
	)
	assertContainsAll(t, "submit recovery open seams", openSeams,
		"exact public producer response schema identifier and final declaration",
		"recovery field names",
		"replay-only versus query route",
		"exact public outcome and error vocabulary",
		"exact reliable-submit state-path config key",
		"TTL, tombstone, and garbage collection",
		"plan snapshot versus immutable references",
		"Nomad reconciliation mechanism",
		"deterministic versus random assigned `run_id`",
		"bootstrap exception",
		"caller namespace refinement beyond authenticated identity",
		"later Coordinator consumer mapping",
	)
	custody := standingRuleSection(t, standingAdmissionRulesPath, pairedRootCustodyHeading)
	admissionRules := compactText(mustRead(t, standingAdmissionRulesPath))
	contractsSubmitTarget := compactDocSection(t, mustRead(t, ".docs/execution_lifecycle/contracts.md"), "### Target reliable keyed-submit contract", "## 7. Status contract")
	designPressure := compactDocSection(t, mustRead(t, ".docs/execution_lifecycle/design.md"), "## 9A. Submit Idempotency And Recovery Pressure", "## 10. Runtime identity and lifecycle interaction")
	implementationAbsenceRaw := markedDocSection(t, "implementation keyed recovery absence",
		mustRead(t, ".docs/execution_lifecycle/implementation.md"),
		"**Current keyed-recovery absence**", "## 8. Lifecycle projection implementation")
	implementationAbsence := compactText(implementationAbsenceRaw)
	admissionDecision := compactText(mustRead(t, ".docs/execution_lifecycle/es_execution_admission_model.md"))
	boundaries := compactText(mustRead(t, ".docs/system_overview/boundaries.md"))
	adrRecovery := compactDocSection(t, mustRead(t, ".docs/system_overview/hybrid_integration_architecture_adr.md"), "### Correlation And Recovery", "## Bridge <-> Codex Evidence Boundary")

	for _, doc := range []struct {
		label string
		text  string
	}{
		{label: "admission standing rules submit recovery tranche", text: admissionRules},
		{label: "contracts submit recovery target", text: contractsSubmitTarget},
		{label: "design submit recovery pressure", text: designPressure},
		{label: "implementation keyed recovery absence", text: implementationAbsence},
		{label: "admission model submit recovery pointer", text: admissionDecision},
		{label: "boundaries submit recovery ownership", text: boundaries},
		{label: "hybrid ADR correlation recovery seam", text: adrRecovery},
	} {
		assertContainsAll(t, doc.label, doc.text,
			"submit idempotency",
			"submit correlation",
			"recovery",
			"submit_idempotency_correlation_and_recovery.md",
		)
	}
	assertContainsAll(t, "paired-root custody standing rules submit recovery tranche", custody,
		"unwired",
		"`reliable-submit-durable-same-operation-replay-repair`",
		"source tranche is implemented inside the private durable source",
		"recognizes the current latest committed mutation before stale-revision and inactive-state refusal",
		"SQLite schema v2 persists the descriptor for codec-2 rows",
		"preserves migrated v1 rows as legacy/unbound",
		"caller-to-ES response loss",
		"ES-to-Nomad registration-response uncertainty",
		"prevent duplicate semantic execution from transport redelivery",
		"current no-key submit compatibility path",
		"`control-plane-normal-shell/v1`",
		"prohibition on a broad ES lifecycle store",
	)
	assertContainsAll(t, "admission standing rules submit recovery tranche", admissionRules,
		"ES-owned documentation seam",
		"The first source-bearing reliable-submit tranche initially added the admission-local pure Go model and tests",
		"The current source-bearing persistence tranche extends that same private package with a backend-neutral claim-store port",
		"durable semantic service",
		"private durable-record codec",
		"shared backend conformance tests",
		"same-package SQLite implementation",
		"`es/admission/internal/reliablesubmit`",
		"transport-neutral",
		"unwired",
		"Reliable submit is not implemented",
		"reliable_submit_persistence_and_concurrency.md",
		"narrow ES-owned submit-correlation store",
		"local embedded SQLite as the first concrete backend",
		"current `CGO_ENABLED=0` build posture",
		"`modernc.org/sqlite v1.54.0`",
		"`modernc.org/libc v1.74.1`",
		"private same-package durable-record codec",
		"revision/CAS semantics",
		"durable provider-effect intent before external I/O",
		"does not add global ES configuration, production runtime wiring",
		"public opt-in/versioning posture",
		"current outer producer-contract v1 identity",
		"one narrow versioned reliable-submit producer sub-contract",
		"keep `POST /v1/executions:submit` as the route",
		"submit-specific reliable request family distinct from `PrepareRequest`",
		"in-band structural reliable-submit discriminator",
		"producer-declaration preflight plus in-band request discrimination",
		"reject header-only opt-in",
		"forbid silent downgrade",
		"`control-plane-normal-shell/v1`",
	)
	providerEffectWarning := "Current non-confirmation returns the existing `submission_failed` behavior and retains the complete staging root; that is not a reliable proof that no provider effect was accepted"
	assertContainsAll(t, "implementation keyed recovery absence", implementationAbsence,
		"Current `Submit` has no submit idempotency key input",
		"no durable submit-correlation record",
		"Current `SubmitResult` has no replay or submit-correlation vocabulary",
		"Current code can be ambiguous at the caller-to-ES boundary",
		"Current code can also be ambiguous at the ES-to-Nomad boundary",
		providerEffectWarning,
		"not implemented here",
	)
	// Select a top-level list item from raw section text before whitespace
	// normalization. This narrow selector only accepts the current document's
	// column-zero list and indented, non-list continuation shape.
	type keyedRecoveryItem struct {
		raw  string
		text string
	}
	selectKeyedRecoveryItem := func(section, lead string) (keyedRecoveryItem, bool) {
		start, end, matches, offset := -1, -1, 0, 0
		active := false
		for _, part := range strings.SplitAfter(section, "\n") {
			line := strings.TrimSuffix(part, "\n")
			switch {
			case strings.HasPrefix(line, "- "):
				if active {
					end, active = offset, false
				}
				if strings.HasPrefix(line[2:], lead) {
					matches++
					start, end, active = offset, -1, true
				}
			case active && strings.TrimSpace(line) == "":
				end, active = offset, false
			case active && strings.HasPrefix(line, "  ") && !strings.HasPrefix(line, "  - "):
				// Wrapped text belongs to the selected item.
			case active:
				// An unindented paragraph or malformed continuation is not
				// silently absorbed into the provider item.
				return keyedRecoveryItem{}, false
			}
			offset += len(part)
		}
		if active {
			end = len(section)
		}
		if matches != 1 || start < 0 || end <= start {
			return keyedRecoveryItem{}, false
		}
		raw := section[start:end]
		return keyedRecoveryItem{raw: raw, text: compactText(raw)}, true
	}
	const providerLead = "Current code can also be ambiguous at the ES-to-Nomad boundary"
	const recipientLead = "Current `SubmitResult`"
	const callerLead = "Current code can be ambiguous at the caller-to-ES boundary"
	const providerUncertainty = "when ES sends a Nomad registration request but cannot confirm whether Nomad accepted it"
	hasProviderEffectWarning := func(section string) bool {
		provider, ok := selectKeyedRecoveryItem(section, providerLead)
		if !ok {
			return false
		}
		flat := compactText(section)
		return strings.Contains(flat, callerLead) && strings.Count(flat, providerEffectWarning) == 1 &&
			strings.Contains(provider.text, providerUncertainty) && strings.Contains(provider.text, providerEffectWarning)
	}
	// Every mutation below starts from the accepted actual raw section.
	if !hasProviderEffectWarning(implementationAbsenceRaw) {
		t.Fatal("actual provider bullet lost registration uncertainty or complete non-confirmation warning")
	}
	provider, providerOK := selectKeyedRecoveryItem(implementationAbsenceRaw, providerLead)
	recipient, recipientOK := selectKeyedRecoveryItem(implementationAbsenceRaw, recipientLead)
	const warningLines = "  Current non-confirmation returns the existing `submission_failed` behavior\n" +
		"  and retains the complete staging root; that is not a reliable proof that no\n" +
		"  provider effect was accepted.\n"
	if !providerOK || !recipientOK || strings.Count(provider.raw, warningLines) != 1 ||
		strings.Contains(recipient.text, providerEffectWarning) {
		t.Fatal("actual keyed-recovery item fixture does not match the owning paragraph")
	}
	t.Run("actual provider bullet", func(t *testing.T) {
		if !hasProviderEffectWarning(implementationAbsenceRaw) {
			t.Fatal("actual provider bullet did not satisfy its local warning predicate")
		}
	})
	t.Run("harmless continuation reflow", func(t *testing.T) {
		reflowedItem := strings.Replace(provider.raw,
			"not a reliable proof that no\n  provider effect was accepted.",
			"not a reliable proof\n    that no provider effect was accepted.", 1)
		if reflowedItem == provider.raw || compactText(reflowedItem) != provider.text {
			t.Fatal("continuation reflow fixture changed item meaning or did not change source layout")
		}
		reflowedSection := strings.Replace(implementationAbsenceRaw, provider.raw, reflowedItem, 1)
		if !hasProviderEffectWarning(reflowedSection) {
			t.Fatal("harmless provider continuation reflow was rejected")
		}
	})
	t.Run("removed provider warning", func(t *testing.T) {
		removed := strings.Replace(implementationAbsenceRaw, warningLines, "", 1)
		if removed == implementationAbsenceRaw || hasProviderEffectWarning(removed) {
			t.Fatal("removed provider warning fixture was unchanged or accepted")
		}
	})
	t.Run("reversed provider warning", func(t *testing.T) {
		reversed := strings.Replace(implementationAbsenceRaw,
			"not a reliable proof that no", "a reliable proof that no", 1)
		if reversed == implementationAbsenceRaw || hasProviderEffectWarning(reversed) {
			t.Fatal("reversed provider warning fixture was unchanged or accepted")
		}
	})
	providerWithoutWarning := strings.Replace(provider.raw, warningLines, "", 1)
	relocated := strings.Replace(implementationAbsenceRaw, provider.raw, providerWithoutWarning, 1)
	relocated = strings.Replace(relocated, recipient.raw, recipient.raw+warningLines, 1)
	t.Run("warning relocated into SubmitResult bullet", func(t *testing.T) {
		flat := compactText(relocated)
		movedProvider, providerFound := selectKeyedRecoveryItem(relocated, providerLead)
		movedRecipient, recipientFound := selectKeyedRecoveryItem(relocated, recipientLead)
		withoutWarning := func(section string) string {
			return compactText(strings.Replace(compactText(section), providerEffectWarning+".", "", 1))
		}
		if relocated == implementationAbsenceRaw || !providerFound || !recipientFound ||
			strings.Count(flat, providerEffectWarning) != 1 ||
			!strings.Contains(flat, callerLead) || !strings.Contains(flat, providerLead) ||
			strings.Contains(movedProvider.text, providerEffectWarning) ||
			!strings.Contains(movedRecipient.text, providerEffectWarning) ||
			withoutWarning(relocated) != withoutWarning(implementationAbsenceRaw) {
			t.Fatal("relocation fixture did not move the exact warning while preserving other section text")
		}
		if hasProviderEffectWarning(relocated) {
			t.Fatal("warning in unrelated SubmitResult bullet satisfied provider-bullet guard")
		}
	})
	t.Run("missing provider bullet with warning elsewhere", func(t *testing.T) {
		missing := strings.Replace(relocated, providerWithoutWarning, "", 1)
		if missing == relocated || strings.Count(compactText(missing), providerEffectWarning) != 1 ||
			hasProviderEffectWarning(missing) {
			t.Fatal("missing provider bullet fixture was unchanged or accepted")
		}
	})
	t.Run("duplicate provider bullet", func(t *testing.T) {
		duplicate := strings.Replace(implementationAbsenceRaw, provider.raw, provider.raw+providerWithoutWarning, 1)
		_, selected := selectKeyedRecoveryItem(duplicate, providerLead)
		if duplicate == implementationAbsenceRaw || strings.Count(compactText(duplicate), providerEffectWarning) != 1 ||
			strings.Count(duplicate, "- "+providerLead) != 2 || selected || hasProviderEffectWarning(duplicate) {
			t.Fatal("ambiguous provider bullets with one warning were accepted or fixture construction failed")
		}
	})
	t.Run("malformed provider continuation", func(t *testing.T) {
		malformed := strings.Replace(implementationAbsenceRaw,
			"  Current non-confirmation returns", "Current non-confirmation returns", 1)
		if malformed == implementationAbsenceRaw || hasProviderEffectWarning(malformed) {
			t.Fatal("malformed provider continuation fixture was unchanged or accepted")
		}
	})
	assertContainsAll(t, "hybrid ADR recovery non-compensation", adrRecovery,
		"not implemented by this ADR",
		"Reliable Coordinator-backed dispatch depends on a later implementation",
		"must not compensate by scraping Nomad",
		"using trace IDs or request IDs as recovery authority",
		"storing parallel runtime lifecycle truth",
		"adapter/session state as durable execution authority",
	)

	typesSource := mustRead(t, "es/admission/types.go")
	prepareRequest := docSection(t, typesSource, "type PrepareRequest struct {", "type ArtifactInvocation struct {")
	submitResult := docSection(t, typesSource, "type SubmitResult struct {", "// ExecutionStatusResult")
	assertContainsAll(t, "current PrepareRequest fields", prepareRequest,
		"SchemaVersion",
		"Invocation",
		"Mode",
		"TimeoutSeconds",
		"Resources",
	)
	assertContainsNone(t, "current PrepareRequest has no implemented submit recovery key", prepareRequest,
		"Idempotency",
		"Correlation",
		"Replay",
		"Dispatch",
		"SubmitKey",
	)
	assertContainsAll(t, "current SubmitResult fields", submitResult,
		"Success",
		"Submitted",
		"RunID",
		"Status",
		"AuthorityHandoff",
	)
	assertContainsNone(t, "current SubmitResult has no implemented submit recovery vocabulary", submitResult,
		"Replay",
		"Correlation",
		"Idempotency",
		"Conflict",
		"Pending",
		"Ambiguous",
		"Expired",
	)
}

func TestReliableSubmitPureModelDocsAndSourceContract(t *testing.T) {
	modelPath := "es/admission/internal/reliablesubmit/model.go"
	modelSource := mustRead(t, modelPath)
	modelCompact := compactText(modelSource)
	target := compactText(mustRead(t, ".docs/execution_lifecycle/submit_idempotency_correlation_and_recovery.md"))
	designPressure := compactDocSection(t, mustRead(t, ".docs/execution_lifecycle/design.md"), "## 9A. Submit Idempotency And Recovery Pressure", "## 10. Runtime identity and lifecycle interaction")
	implementationAbsence := compactDocSection(t, mustRead(t, ".docs/execution_lifecycle/implementation.md"), "**Current keyed-recovery absence**", "## 8. Lifecycle projection implementation")
	custody := standingRuleSection(t, standingAdmissionRulesPath, pairedRootCustodyHeading)
	admissionRules := compactText(mustRead(t, standingAdmissionRulesPath))

	assertContainsAll(t, "reliable submit pure model package placement", target,
		"The source-bearing reliable-submit package is now present as the admission-local internal Go package `es/admission/internal/reliablesubmit`",
		"Its pure model in `model.go` models local phase validity",
		"private persistence source in the same package adds a backend-neutral claim-store port",
		"durable semantic service",
		"durable-record codec",
		"shared conformance suite",
		"SQLite implementation",
		"It is not wired to current submit",
		"implements no public DTO",
		"producer declaration field",
		"staging behavior",
		"Nomad behavior",
		"recovery route",
		"runtime configuration",
		"runtime integration",
	)
	assertContainsAll(t, "reliable submit pure model local snapshot limitation", target,
		"validates one supplied current snapshot at a time",
		"reassignment with the same opaque `RunRef` as idempotent",
		"fail closed on reassignment with a different `RunRef`",
		"cannot enforce one globally winning caller/key assignment across stale copied pre-assignment values",
		"That authority belongs to the private persistence/concurrency layer with uniqueness rules and compare-and-swap transaction semantics",
		"Later transport and reconciliation code must consume rather than bypass this package",
		"must stop and revise the model instead of layering a second unused abstraction",
	)
	assertContainsAll(t, "reliable submit pure model design placement", designPressure,
		"`es/admission/internal/reliablesubmit`",
		"`modernc.org/sqlite v1.54.0`",
		"`modernc.org/libc v1.74.1`",
		"private same-package persistence hydration",
		"The private source remains unwired",
		"implements no config, production runtime wiring, public DTO, HTTP handler, producer declaration field, staging behavior, Nomad behavior, or runtime behavior",
		"does not select the state-path config key",
	)
	assertContainsAll(t, "reliable submit pure model implementation fact", implementationAbsence,
		"Current source includes the internal package `es/admission/internal/reliablesubmit`",
		"Its pure model in `model.go`",
		"same package now contains private durable-record, backend-neutral port, durable-service, shared conformance-test, and SQLite-store source",
		"That package is not wired to current `Submit`",
		"does not implement the producer sub-contract",
		"reliable request DTO",
		"staging",
		"Nomad reconciliation",
		"recovery lookup",
		"public error vocabulary",
		"runtime configuration",
		"runtime startup integration",
		"cannot enforce one winning assignment across stale or concurrent snapshots",
		"`reliable-submit-durable-same-operation-replay-repair` latest-operation-only",
		"same mutation reference with different kind or binding is mutation conflict",
		"an older operation after later progression is stale or superseded",
		"`reliable-submit-durable-same-operation-replay-repair`",
		"not reliable-submit config/store lifecycle wiring, producer enablement, or public runtime enablement",
		"Later reliable-submit tranches must consume this package or explicitly stop and revise it",
		"no second unused abstraction tranche may be layered on top without a concrete consumer",
	)
	assertContainsAll(t, "reliable submit pure model paired-root custody standing rules", custody,
		"unwired",
		"`reliable-submit-durable-same-operation-replay-repair`",
		"source tranche is implemented inside the private durable source",
		"SQLite schema v2 persists the descriptor for codec-2 rows",
		"preserves migrated v1 rows as legacy/unbound",
	)
	assertContainsAll(t, "reliable submit pure model admission standing rules", admissionRules,
		"The current source-bearing persistence tranche extends that same private package with a backend-neutral claim-store port",
		"durable semantic service",
		"private durable-record codec",
		"shared backend conformance tests",
		"same-package SQLite implementation",
		"`es/admission/internal/reliablesubmit`",
		"transport-neutral",
		"unwired",
		"Reliable submit is not implemented",
		"reliable_submit_persistence_and_concurrency.md",
		"narrow ES-owned submit-correlation store",
		"local embedded SQLite as the first concrete backend",
		"`modernc.org/sqlite v1.54.0`",
		"`modernc.org/libc v1.74.1`",
		"private same-package durable-record codec",
		"revision/CAS semantics",
		"provider-effect intent before external I/O",
	)

	assertContainsAll(t, "reliable submit pure model source package", modelCompact,
		"package reliablesubmit",
		"Package reliablesubmit contains the first pure ES reliable-submit model.",
		"validates phase shapes and one transition against one supplied current snapshot only",
		"cannot prevent two stale copied pre-assignment values",
		"later durable uniqueness and compare-and-swap layer",
	)
	assertContainsAll(t, "reliable submit pure model source identity and binding", modelSource,
		"type CallerRef struct",
		"type SubmitKeyRef struct",
		"type ClaimID struct",
		"type PlanBinding struct",
		"type EffectivePlanWitness struct",
		"type BoundPlan struct",
		"type RunRef struct",
		"type ReceiptRef struct",
	)
	assertContainsAll(t, "reliable submit pure model source phases", modelSource,
		"type PendingBeforeAssignment struct",
		"type AmbiguousBeforeAssignment struct",
		"type EffectCapableAssigned struct",
		"type PendingAfterAssignment struct",
		"type AmbiguousAfterAssignment struct",
		"type Accepted struct",
		"type ProvablyNotAcceptedAfterAssignment struct",
		"type RecoveredAccepted struct",
		"type ExactReplay struct",
		"type Conflict struct",
		"type Unauthorized struct",
		"type ExpiredUnavailable struct",
	)
	assertContainsAll(t, "reliable submit pure model source accepted payload", modelCompact,
		"type assignedCore struct { claimCore claimCore run RunRef }",
		"type Accepted struct { core assignedCore receipt ReceiptRef }",
		"func NewAccepted(phase ProviderOutcomeCandidatePhase, receipt ReceiptRef) (Accepted, error)",
	)
	assertContainsAll(t, "reliable submit pure model source accepted reference availability", modelCompact,
		"AcceptedSubmissionReferenceAvailable() bool",
		"func (a Accepted) AcceptedSubmissionReferenceAvailable() bool { return a.Valid() }",
		"func (r RecoveredAccepted) AcceptedSubmissionReferenceAvailable() bool { return r.Valid() }",
		"func (r ExactReplay) AcceptedSubmissionReferenceAvailable() bool",
		"return ok && phase.AcceptedSubmissionReferenceAvailable()",
		"func (p PendingBeforeAssignment) AcceptedSubmissionReferenceAvailable() bool { return false }",
		"func (a AmbiguousBeforeAssignment) AcceptedSubmissionReferenceAvailable() bool { return false }",
		"func (e EffectCapableAssigned) AcceptedSubmissionReferenceAvailable() bool { return false }",
		"func (p PendingAfterAssignment) AcceptedSubmissionReferenceAvailable() bool { return false }",
		"func (a AmbiguousAfterAssignment) AcceptedSubmissionReferenceAvailable() bool { return false }",
		"func (p ProvablyNotAcceptedAfterAssignment) AcceptedSubmissionReferenceAvailable() bool { return false }",
	)
	assertContainsAll(t, "reliable submit pure model preserves external progression docs", target,
		"Coordinator must not enter submitted, running, cancellation, logs, result, or other lifecycle-bearing progression without a correlated `run_id`",
		"later Coordinator consumer mapping",
	)
	assertContainsAll(t, "reliable submit pure model source conflict unauthorized privacy", modelCompact,
		"func (c Conflict) ClaimID() (ClaimID, bool) { return ClaimID{}, false }",
		"func (c Conflict) HasAssignedRunRef() bool { return false }",
		"func (c Conflict) ReceiptRef() (ReceiptRef, bool) { return ReceiptRef{}, false }",
		"func (u Unauthorized) ClaimID() (ClaimID, bool) { return ClaimID{}, false }",
		"func (u Unauthorized) HasAssignedRunRef() bool { return false }",
		"func (u Unauthorized) ReceiptRef() (ReceiptRef, bool) { return ReceiptRef{}, false }",
	)
	assertContainsAll(t, "reliable submit pure model source witness categories", modelSource,
		"EffectivePlanCategoryRequestSchemaOrVersion",
		"EffectivePlanCategoryExecutionMode",
		"EffectivePlanCategoryTimeoutSemantics",
		"EffectivePlanCategoryCPU",
		"EffectivePlanCategoryMemory",
		"EffectivePlanCategoryRuntimeProfile",
		"EffectivePlanCategoryArtifactIdentity",
		"EffectivePlanCategoryDerivationSpecIdentity",
		"EffectivePlanCategoryOutputIdentity",
		"EffectivePlanCategoryCommandAndArgv",
		"EffectivePlanCategoryEnvironmentAdditions",
		"EffectivePlanCategoryMounts",
		"EffectivePlanCategoryNetworkPosture",
		"EffectivePlanCategoryAuthorityHandoffApplicability",
		"const effectivePlanCategoryCount = int(EffectivePlanCategoryAuthorityHandoffApplicability)",
		"Empty argv additions, environment additions, and mounts are represented by the corresponding resolved categories",
	)
	assertContainsAll(t, "reliable submit pure model source witness requiredness", modelCompact,
		"func ExplicitlyInapplicableCategory(category EffectivePlanCategory) (EffectivePlanCategoryCompleteness, error)",
		"if category != EffectivePlanCategoryAuthorityHandoffApplicability { return EffectivePlanCategoryCompleteness{}, ErrInapplicableEffectivePlanCategory }",
		"func OutputIdentityExplicitlyInapplicableForPermittedExecutionKind() EffectivePlanCategoryCompleteness",
		"case EffectivePlanCategoryOutputIdentity: return category.outputInapplicablePermitted",
		"case EffectivePlanCategoryAuthorityHandoffApplicability: return true",
	)
	assertContainsNone(t, "reliable submit pure model source avoids optional state bag", modelSource,
		"type ClaimState struct",
		"type ReliableSubmitState struct",
		"type SubmitState struct",
		"*RunRef",
		"*ReceiptRef",
		"`json:",
		"`yaml:",
		"`db:",
		"`gorm:",
	)
	assertContainsNone(t, "reliable submit pure model source avoids current locator and runtime coupling", modelSource,
		"executionLocator",
		"runIDPattern",
		"exec-<run_id>",
		"JobID",
		"AllocationID",
		"EvalID",
		"TraceID",
		"RequestID",
		"work_item_id",
		"attempt_id",
		"repair_id",
		"dispatch_command_id",
		"DevelopmentProgram",
		"CoordinatorProgressionPermitted",
		"Coordinator",
		"Bridge",
		"Nomad",
		"nomad",
		"net/http",
		"database/sql",
	)

	submitSource := mustRead(t, "es/admission/submit.go")
	serviceSource := mustRead(t, "es/admission/service.go")
	serverSource := mustRead(t, "es/api/server.go")
	producerSource := mustRead(t, "es/admission/producercontract.go")
	typesSource := mustRead(t, "es/admission/types.go")
	locatorSource := mustRead(t, "es/admission/executionlocator.go")

	assertContainsNone(t, "current submit remains unwired from reliable-submit model", submitSource,
		"reliablesubmit",
		"internal/reliablesubmit",
	)
	assertContainsNone(t, "current prepare/service remains unwired from reliable-submit model", serviceSource,
		"reliablesubmit",
		"internal/reliablesubmit",
	)
	assertContainsNone(t, "current server remains without reliable-submit DTO handling", serverSource,
		"reliablesubmit",
		"ReliableSubmit",
		"reliable_submit",
	)
	assertContainsNone(t, "current producer declaration remains unchanged", producerSource,
		"reliablesubmit",
		"ReliableSubmit",
		"reliable_submit",
	)
	assertContainsNone(t, "current public DTOs remain unchanged", typesSource,
		"ReliableSubmit",
		"reliable_submit",
		"SubmitKey",
		"Idempotency",
	)
	assertContainsAll(t, "current locator remains separate current implementation", locatorSource,
		"runIDPattern",
		"executionLocator",
		"`^run-[0-9a-f]{16}$`",
		"jobID: \"exec-\" + runID",
	)
}

func TestReliableSubmitPublicOptInAndVersioningDocsContract(t *testing.T) {
	targetRaw := mustRead(t, ".docs/execution_lifecycle/submit_idempotency_correlation_and_recovery.md")
	statusPurpose := compactDocSection(t, targetRaw, "## 1. Status And Purpose", "## 2. Current Implementation Reality")
	currentReality := compactDocSection(t, targetRaw, "## 2. Current Implementation Reality", "## 3. Dual Ambiguity Model")
	compatibility := compactDocSection(t, targetRaw, "## 13. Compatibility And Opt-In Treatment", "## 14. Safe Projection And Privacy")
	nonClaims := compactDocSection(t, targetRaw, "## 15. Explicit Non-Claims", "## 16. Required-Before-Implementation Gates")
	gates := compactDocSection(t, targetRaw, "## 16. Required-Before-Implementation Gates", "## 17. Open Seams")
	openSeams := compactDocSection(t, targetRaw, "## 17. Open Seams", "")

	contractsRaw := mustRead(t, ".docs/execution_lifecycle/contracts.md")
	producerTarget := compactDocSection(t, contractsRaw, "### Target reliable-submit producer sub-contract selection", "### Error contract")
	submitTarget := compactDocSection(t, contractsRaw, "### Target reliable keyed-submit contract", "## 7. Status contract")
	designPressure := compactDocSection(t, mustRead(t, ".docs/execution_lifecycle/design.md"), "## 9A. Submit Idempotency And Recovery Pressure", "## 10. Runtime identity and lifecycle interaction")
	admissionSeams := compactDocSection(t, mustRead(t, ".docs/execution_lifecycle/es_execution_admission_model.md"), "### 4E. Reopened seams", "## 5. Guardrails for future edits")
	implementationAbsence := compactDocSection(t, mustRead(t, ".docs/execution_lifecycle/implementation.md"), "**Current keyed-recovery absence**", "## 8. Lifecycle projection implementation")
	boundaryOwnership := compactDocSection(t, mustRead(t, ".docs/system_overview/boundaries.md"), "## 8. ES boundary", "## 9. EGS boundary")
	boundaryCompatibility := boundaryOwnership
	admissionRules := compactText(mustRead(t, standingAdmissionRulesPath))

	assertContainsAll(t, "reliable submit current outer producer contract preserved", producerTarget,
		"`execution-substrate.producer-contract/v1`",
		"`governed-execution-producer/v1`",
		"The current producer declaration has no implemented reliable-submit sub-contract",
	)
	assertContainsAll(t, "reliable submit producer declaration remains narrow", producerTarget,
		"one explicitly named and versioned reliable-submit producer sub-contract",
		"The target reliable-submit producer sub-contract name is `reliable_submit`",
		"`execution-substrate.reliable-submit/v1`",
		"`execution-substrate.reliable-submit-request/v1`",
		"narrow and additive",
		"only the reliable-submit contract family/version supported",
		"whether reliable submit is enabled for this installation",
		"bounded safe unavailable or disabled reason",
		"minimum safe request-contract discriminator",
		"not a generic `capabilities` map",
		"feature registry",
		"plugin registry",
		"cross-service probing framework",
		"not sufficient opt-in",
		"the request body discriminator remains an independent fail-closed gate",
	)
	assertContainsAll(t, "reliable submit target status separates current and target", statusPurpose,
		"TARGET-ONLY",
		"CURRENT-UNCHANGED",
		"does not implement runtime behavior",
		"selects the public opt-in/versioning posture and delegates the persistence/concurrency decision",
		"unavailable contract-adapter foundation",
		"local embedded SQLite as the first storage backend",
		"`modernc.org/sqlite v1.54.0` as the CGO-free driver",
		"No current public request field, public response DTO field, producer field, handler behavior, query route, Nomad behavior, runtime configuration, or runtime behavior is implemented by this document, the private store tranche, or the unavailable contract-adapter foundation",
	)
	assertContainsAll(t, "reliable submit current implementation facts", currentReality,
		"current `PrepareRequest` body",
		"Current body decoding is strict",
		"Unknown request-body fields are rejected",
		"has no caller-provided submit idempotency key",
		"Current no-key submit has no exact replay contract",
		"Current no-key submit has no recovery lookup",
		"Current `validatePrepareRequest` defaults a blank `schema_version`",
		"A changed value in that existing `schema_version` field is not, by itself, the selected reliable-submit discriminator",
		"implements latest-operation same-operation replay",
		"general mutation path derives and compares a complete private latest-operation descriptor",
		"Same mutation plus same operation kind and input binding replays the committed result without another CAS",
		"Same mutation plus different descriptor conflicts",
		"no current public execution behavior is affected",
	)
	assertContainsAll(t, "reliable submit route and request-family selection", compatibility,
		"Current submit without the new key remains valid current behavior",
		"The target reliable request uses the existing `POST /v1/executions:submit` route",
		"does not select a new route",
		"The reliable variant uses a submit-specific request family",
		"must not remain merely an optional semantic interpretation of `PrepareRequest`",
		"`execution-substrate.reliable-submit-request/v1`",
		"`reliable_submit`",
		"`contract = \"execution-substrate.reliable-submit/v1\"`",
		"`submit_key`",
		"current server rejects a future reliable body carrying `reliable_submit` before calling current `Submit` behavior",
		"changed value in the existing `schema_version` field alone is not the selected discriminator",
	)
	assertContainsAll(t, "reliable submit two fail-closed gates", compatibility,
		"two independent fail-closed gates",
		"authenticate and read the producer declaration",
		"require the exact reliable-submit sub-contract and enabled status",
		"send a structurally distinct reliable-submit request variant",
		"The producer declaration alone is not execution authorization, admission, run existence, lifecycle truth, submit readiness, or proof that a specific request will be accepted",
		"The request discriminator alone does not replace producer compatibility negotiation",
	)
	assertContainsAll(t, "reliable submit header-only and downgrade rejection", compatibility,
		"Header-only reliable-submit opt-in is rejected",
		"current server may ignore an unknown header and execute the current unkeyed body",
		"this tranche selects no supplemental header",
		"absent, incompatible, disabled, or unavailable",
		"must stop before submit",
		"reject it before admission is treated as successful",
		"before effect-capable `run_id` assignment",
		"before execution-package staging",
		"before Nomad registration",
		"before any fallback to current unkeyed `Submit`",
		"not silently fall back to unkeyed submission",
	)
	assertContainsAll(t, "reliable submit legacy compatibility and prepare separation", compatibility,
		"Current no-key submit does not gain reliable replay or recovery claims",
		"Current `POST /v1/executions:prepare` remains the current bounded preflight surface",
		"does not select a reliable prepare variant",
		"claim creation during prepare",
		"`run_id` allocation during prepare",
		"persistence during prepare",
		"prepare-to-submit claim transfer",
		"Current CP/demo and `control-plane-normal-shell/v1` compatibility remains unchanged",
		"Current CP and IM consumers may ignore the additive reliable-submit sub-declaration",
		"future reliable clients must require it explicitly",
	)
	assertContainsAll(t, "reliable submit submit-contract target section", submitTarget,
		"`POST /v1/executions:submit` route for both the current legacy variant and the future reliable variant",
		"submit-specific request schema `execution-substrate.reliable-submit-request/v1`, distinct from `PrepareRequest`",
		"mandatory top-level structural discriminator `reliable_submit`",
		"Current strict `PrepareRequest` decoding rejects",
		"Header-only reliable opt-in is rejected",
		"before fallback to current unkeyed submit",
	)
	assertContainsAll(t, "reliable submit design pressure", designPressure,
		"two independent fail-closed gates",
		"future narrow reliable-submit producer sub-contract",
		"structurally distinct reliable request family or envelope",
		"existing `POST /v1/executions:submit` route",
		"in-band structural discriminator unknown to the current `PrepareRequest` decoder",
		"Header-only reliable-submit opt-in is rejected",
		"not authorization, admission, health, submit readiness, run authority, lifecycle truth, scheduler API, or a generic capability registry",
	)
	assertContainsAll(t, "reliable submit admission reopened seam", admissionSeams,
		"selects the shape class for the future reliable submit path",
		"existing `POST /v1/executions:submit` route",
		"additive narrow reliable-submit producer sub-contract",
		"producer preflight plus structural body discrimination",
		"submit-specific reliable request family distinct from `PrepareRequest`",
		"execution-substrate.reliable-submit-request/v1",
		"execution-substrate.reliable-submit/v1",
		"public receipt vocabulary",
		"error vocabulary and recovery route remain open",
	)
	assertContainsAll(t, "reliable submit implementation absence", implementationAbsence,
		"Current `Submit` has no submit idempotency key input",
		"Current `SubmitResult` has no replay or submit-correlation vocabulary",
		"Current `handleSubmit` still decodes the current `PrepareRequest` body",
		"no handler discrimination",
		"public reliable request DTO",
		"reliable runtime decoder",
		"reliable submit path",
		"No reliable-submit producer sub-contract field or DTO is implemented",
		"not implemented here",
		"no silent fallback to current unkeyed submit",
	)
	assertContainsAll(t, "reliable submit boundary ownership", boundaryOwnership,
		"ES also owns the future narrow reliable-submit producer sub-contract",
		"additive under the current governed-execution declaration",
		"not a general capability registry",
		"not a general capability registry, plugin registry, health check, submit-readiness proof, admission proof, run authority, lifecycle truth, or scheduler API",
	)
	assertContainsAll(t, "reliable submit boundary compatibility", boundaryCompatibility,
		"Reliable adapters and Coordinator consumers must require it before reliable submit, but they do not own it",
		"Future reliable keyed submit uses the existing `POST /v1/executions:submit` route",
		"distinct submit-specific reliable request family",
		"in-band structural discriminator that current strict decoding rejects",
		"Header-only opt-in is rejected",
		"must not fall back to current unkeyed submit",
		"Current CP/demo, IM, and `control-plane-normal-shell/v1` compatibility remain unchanged",
		"CP and IM may ignore the future additive reliable-submit sub-declaration",
		"does not make CP or IM part of the target autonomous-development topology",
	)
	assertContainsAll(t, "reliable submit admission standing rules tranche", admissionRules,
		"public opt-in/versioning posture",
		"current outer producer-contract v1 identity",
		"current governed-execution contract identity",
		"one narrow versioned reliable-submit producer sub-contract",
		"keep `POST /v1/executions:submit` as the route",
		"submit-specific reliable request family distinct from `PrepareRequest`",
		"in-band structural reliable-submit discriminator",
		"current strict decoding rejects",
		"producer-declaration preflight plus in-band request discrimination",
		"reject header-only opt-in",
		"forbid silent downgrade",
	)
	assertContainsAll(t, "reliable submit open decisions", openSeams,
		"exact public producer response schema identifier and final declaration",
		"recovery field names",
		"replay-only versus query route",
		"exact public outcome and error vocabulary",
		"exact reliable-submit state-path config key",
		"TTL, tombstone, and garbage collection",
		"Nomad reconciliation mechanism",
		"deterministic versus random assigned `run_id`",
	)
	assertContainsAll(t, "reliable submit non-claims", nonClaims,
		"no reliable submit runtime integration implemented",
		"no runtime behavior implemented",
		"no producer declaration field implemented",
		"no public request DTO implemented",
		"no public/runtime reliable-submit handler or route decoder is wired; the private admission-local `parseValidatedReliableSubmitRequest` and `decodeStrictReliableSubmitJSON` helpers remain unwired;",
		"no route implementation",
		"no public or runtime persistence integration",
		"no global state-path configuration or service-startup database construction",
		"no public or runtime schema, migration, backup, restore, or storage migration tooling exposed to operators",
		"no public reliable response field names",
		"no recovery query selected",
		"no supplemental header selected",
		"no reliable prepare selected",
		"no Nomad behavior implemented",
		"no Coordinator schema",
		"no Bridge widening",
		"no gateway service",
		"no CP target topology",
		"no general capability registry",
		"no silent unkeyed fallback",
	)
	assertContainsNone(t, "reliable submit non-claims reject stale private persistence denial", nonClaims,
		"- no persistence;",
		"- no schema or migration;",
		"reliable submit is implemented end to end",
		"Reliable submit is implemented end to end",
		"no handler or decoder implemented",
	)
	assertContainsAll(t, "reliable submit required next gates", gates,
		"preserved public opt-in and versioning docs-contract coverage",
		"reliable request foundation and producer sub-contract target tests",
		"`reliable-submit-durable-same-operation-replay-repair`",
		"source-grounded resolved-plan extraction (satisfied by the private current-Submit foundation)",
		"narrow persistence and concurrency ADR decision",
		"ES-to-Nomad uncertain-outcome reconciliation decision",
		"request, receipt, and error model tests",
	)

	httpxSource := mustRead(t, "internal/httpx/httpx.go")
	serverSource := mustRead(t, "es/api/server.go")
	serviceSource := mustRead(t, "es/admission/service.go")
	producerSource := mustRead(t, "es/admission/producercontract.go")
	typesSource := mustRead(t, "es/admission/types.go")

	assertContainsAll(t, "current strict decoder source", httpxSource,
		"decoder.DisallowUnknownFields()",
		"trailing data after first JSON document",
	)
	assertContainsAll(t, "current submit handler source", serverSource,
		"func (s *Server) handleSubmit",
		"request, ok := s.decodeAuthorizedExecutionRequest(w, r)",
		"result, err := s.service.Submit(r.Context(), request)",
	)
	assertContainsAll(t, "current schema version default source", serviceSource,
		"func validatePrepareRequest(req *PrepareRequest) *Error",
		"if strings.TrimSpace(req.SchemaVersion) == \"\"",
		"req.SchemaVersion = \"v1\"",
	)
	assertContainsAll(t, "current producer declaration source", producerSource,
		"producerContractSchemaVersion       = \"execution-substrate.producer-contract/v1\"",
		"governedExecutionProducerContract   = \"governed-execution-producer/v1\"",
		"GovernedExecution: governedExecution",
		"NonAuthority: []string",
	)
	assertContainsNone(t, "current producer declaration has no reliable-submit implementation", producerSource,
		"ReliableSubmit",
		"reliable_submit",
	)
	producerDeclaration := docSection(t, typesSource, "type ProducerContractDeclaration struct {", "type RuntimeInterface struct {")
	assertContainsAll(t, "current ProducerContractDeclaration fields", producerDeclaration,
		"SchemaVersion",
		"Service",
		"GovernedExecution",
		"NonAuthority",
	)
	assertContainsNone(t, "current ProducerContractDeclaration has no reliable-submit field", producerDeclaration,
		"Reliable",
		"Capability",
	)
}

func TestReliableSubmitContractAdapterFoundationDocsAndSourceContract(t *testing.T) {
	targetRaw := mustRead(t, ".docs/execution_lifecycle/submit_idempotency_correlation_and_recovery.md")
	statusPurpose := compactDocSection(t, targetRaw, "## 1. Status And Purpose", "## 2. Current Implementation Reality")
	currentReality := compactDocSection(t, targetRaw, "## 2. Current Implementation Reality", "## 3. Dual Ambiguity Model")
	authorityIdentity := compactDocSection(t, targetRaw, "## 4. Authority And Identity Ownership", "## 5. Reliable Keyed-Submit Invariant")
	effectivePlan := compactDocSection(t, targetRaw, "## Effective Execution Plan And Field Requiredness", "## 7. Narrow Durable Correlation Semantics")
	compatibility := compactDocSection(t, targetRaw, "## 13. Compatibility And Opt-In Treatment", "## 14. Safe Projection And Privacy")
	outcomes := compactDocSection(t, targetRaw, "## 10. Semantic Outcome Classes", "## 11. Replay, Authorization, And Admission")

	assertContainsAll(t, "reliable-submit foundation status", statusPurpose,
		"unavailable contract-adapter foundation",
		"private reliable request-family vocabulary",
		"submit-key syntax",
		"caller/key derivation",
		"composite `ClaimID` construction through the committed pure-model constructor",
		"ES-neutral outcome semantics",
		"separate private `resolved-execution-plan-extraction-foundation` resolves current legacy Submit from admitted facts before effect",
		"the codec-3 private synthetic composer is",
		"only new non-test caller",
		"still confers no effect permission",
		"No current public request field, public response DTO field, producer field, handler behavior, query route, Nomad behavior, runtime configuration, or runtime behavior",
	)
	assertContainsAll(t, "reliable-submit foundation current reality", currentReality,
		"admission-local private reliable-submit foundation helpers in package `admission`",
		"private reliable request-family shape and validation",
		"caller/key safe-reference derivation",
		"composite `ClaimID` construction through the committed pure-model constructor",
		"ES-neutral submission-outcome projection",
		"source-grounded resolved-execution-plan extraction already implemented for current Submit",
		"Current legacy Submit now also consumes a separate private `resolvedExecutionPlan`",
		"do not canonically encode or bind that plan",
		"construct its complete reliable witness",
		"durable replay-envelope custody",
		"orchestrate reliable runtime behavior",
		"not exported public DTOs",
		"not wired to handlers",
		"not called by current submit",
		"implements latest-operation same-operation replay",
		"general mutation path derives and compares a complete private latest-operation descriptor",
		"Same mutation plus same operation kind and input binding replays the committed result without another CAS",
		"Same mutation plus different descriptor conflicts",
		"Migrated legacy/unbound rows preserve only the retained mutation reference",
		"persists no mutation history",
		"private store remains runtime-unwired",
	)
	assertContainsNone(t, "reliable-submit foundation current reality rejects absolute extraction denial", currentReality,
		"no source-grounded resolved effective-plan extraction implemented",
		"do not implement source-grounded resolved effective-plan extraction",
		"source-grounded resolved-plan extraction is absent",
		"source-grounded resolved-execution-plan extraction is absent",
		"source-grounded resolved-plan extraction is unimplemented",
		"source-grounded resolved-execution-plan extraction is unimplemented",
	)
	assertContainsAll(t, "reliable-submit key and caller derivation docs", authorityIdentity,
		"base64url without padding",
		"exactly 43 ASCII characters",
		"decodes canonically to exactly 32 bytes",
		"cryptographically secure random generator",
		"server validates encoding, canonical form, and length only",
		"does not prove entropy",
		"exact canonical SPIFFE URI",
		"`caller_ref_bytes = SHA256(\"es/reliable-submit/caller-ref/v1\\0\" || canonical_spiffe_uri)`",
		"`submit_key_ref_bytes = SHA256(\"es/reliable-submit/submit-key-ref/v1\\0\" || caller_ref_bytes || raw_submit_key_bytes)`",
		"`reliablesubmit.NewClaimID(callerRef, submitKeyRef)`",
		"does not hash or invent a third claim-ID representation",
		"raw-key-bearing wire surrogate is function-local",
		"raw `submit_key` string may exist only during that decode/derive operation",
		"decoded key bytes are consumed only to derive `SubmitKeyRef`",
		"validated private request representation must retain only sanitized request facts plus safe private `CallerRef`, `SubmitKeyRef`, and `ClaimID` values",
		"not the raw `submit_key` string, decoded key bytes, or original raw-key-bearing wire request",
		"Full request objects remain unsafe as log payloads",
		"no secure-memory-erasure claim",
		"does not claim arbitrary invalid Go formatting operations",
		"invalid `%w` on non-error values",
		"Submit-key validation errors remain fixed bounded errors",
	)
	assertContainsAll(t, "reliable-submit request docs", compatibility,
		"`execution-substrate.reliable-submit-request/v1`",
		"`reliable_submit`",
		"`contract = \"execution-substrate.reliable-submit/v1\"`",
		"`submit_key`",
		"`schema_version`, `reliable_submit`, `invocation`, optional `mode`, optional `timeout_seconds`, and optional `resources`",
		"reuses lower-level `ArtifactInvocation`, `ExecutionMode`, and `ExecutionResources` values without modifying `PrepareRequest`",
		"Omitted `mode` resolves to `async`",
		"`sync` is rejected for reliable v1",
		"empty resources object is invalid",
		"foundation must not duplicate artifact, derivation, policy, runtime-profile, resource/admission, manifest, or trust validation",
	)
	assertContainsAll(t, "reliable-submit future effective-plan seam docs", effectivePlan,
		"The rejected self-validating plan binder remains absent",
		"implemented `resolved-execution-plan-extraction-foundation` derives one private semantic plan from actual current ES admission and runtime resolution",
		"That plan is authoritative only for admitted semantics",
		"the unwired private v1 `PlanBinding` producer consumes its actual frozen tuple rather than re-resolving the same categories",
		"Separate owned material contains all primary payload, runtime-support, compressed/parsed mount, Vault CA, and combined trust-bundle bytes",
		"The separate private v1 producer now selects only an unwired encoding, commitment and completeness assessment",
		"does not synthesize `PrepareRequest` or `Manifest` proof from the plan, create a parallel admission engine, change environment or mount admission, or infer authority-handoff inapplicability contrary to current Submit",
		"Environment and mount validation belong to the shared admission path, which the plan consumes and does not repeat",
		"a caller environment key must be a portable name, must not be reserved and must be in the artifact's signed environment allowlist",
		"an empty list admits nothing",
		"Current supported `Submit` constructs `authority_handoff`",
	)
	assertContainsAll(t, "reliable-submit neutral outcome docs", outcomes,
		"transport-neutral ES outcome projection",
		"phase-specific same-caller `RunRef` disclosure",
		"`ReceiptRef` presence",
		"whether exact retry of the same request is safe",
		"whether a new key is required",
		"whether an accepted submission reference is available",
		"does not encode HTTP status mapping",
		"does not encode HTTP status mapping, public error strings, CP or Coordinator progression, provider IDs, or raw private store state",
		"`open_for_later_transport_contract`",
		"no receipt",
		"no accepted-reference availability",
		"no public-transport decision",
		"HTTP/public outcome mapping remain open",
	)

	reliableInvariant := compactDocSection(t, targetRaw, "## 5. Reliable Keyed-Submit Invariant", "## run_id Phase And Disclosure Invariants")
	assertContainsAll(t, "reliable-submit target latest-operation replay invariant", reliableInvariant,
		"latest-operation-only",
		"current latest committed durable mutation descriptor",
		"mutation reference, closed private operation kind, and versioned safe operation-input binding",
		"older operation arriving after a later committed mutation is stale or superseded, not exact replay",
		"No historical mutation-result log is selected",
		"operation-input binding includes expected predecessor revision",
		"excludes mutation reference itself, raw requests, submit keys, caller URIs, environment values, credentials, filesystem paths, unrestricted provider IDs, trace/request/session/report IDs, logs, and result bodies",
		"Reuse of one mutation reference with a different operation kind or input binding is a mutation conflict",
		"Same payload with a new mutation reference is not exact replay",
		"without updating mutation identity merely to bless an already completed effect",
	)

	contractSource := mustRead(t, "es/admission/reliable_submit_contract.go")
	identitySource := mustRead(t, "es/admission/reliable_submit_identity.go")
	outcomeSource := mustRead(t, "es/admission/reliable_submit_outcome.go")
	for _, removedPlanPath := range []string{
		"es/admission/reliable_submit_plan.go",
		"es/admission/reliable_submit_plan_test.go",
	} {
		if _, err := os.Stat(removedPlanPath); !os.IsNotExist(err) {
			t.Fatalf("%s must be absent after reliable-submit scope reset, stat error: %v", removedPlanPath, err)
		}
	}

	assertContainsAll(t, "reliable-submit private request source", contractSource,
		"reliableSubmitRequestSchemaV1 = \"execution-substrate.reliable-submit-request/v1\"",
		"reliableSubmitContractV1      = \"execution-substrate.reliable-submit/v1\"",
		"reliableSubmitDiscriminator   = \"reliable_submit\"",
		"reliableSubmitContractField   = \"contract\"",
		"reliableSubmitKeyField        = \"submit_key\"",
		"type validatedReliableSubmitRequest struct",
		"type reliableSubmitWireMarker struct",
		"func parseValidatedReliableSubmitRequest",
		"func decodeStrictReliableSubmitJSON",
		"func decodeCanonicalReliableSubmitKey",
		"ArtifactInvocation",
		"ExecutionResources",
		"base64.RawURLEncoding",
		"deriveReliableSubmitClaimRefs(canonicalSPIFFEURI, rawSubmitKey)",
	)
	assertContainsNone(t, "reliable-submit private request source raw retention", contractSource,
		"type reliableSubmitRequest struct",
		"type reliableSubmitRequestMarker struct",
		"type reliableSubmitKey struct",
		"func (k reliableSubmitKey) MarshalJSON",
		"func (k reliableSubmitKey) MarshalText",
		"func (r validatedReliableSubmitRequest) MarshalJSON",
		"func (r validatedReliableSubmitRequest) MarshalText",
		"func (r validatedReliableSubmitRequest) String",
		"func (r validatedReliableSubmitRequest) GoString",
		"func (r validatedReliableSubmitRequest) Format",
		"func (r validatedReliableSubmitRequest) Error",
	)
	assertContainsAll(t, "reliable-submit private identity source", identitySource,
		"reliableSubmitCallerRefDomain",
		"es/reliable-submit/caller-ref/v1\\x00",
		"reliableSubmitSubmitKeyRefDomain",
		"es/reliable-submit/submit-key-ref/v1\\x00",
		"reliablesubmit.NewClaimID(callerRef, submitKeyRef)",
	)
	assertContainsAll(t, "reliable-submit private outcome source", outcomeSource,
		"type reliableSubmitOutcome struct",
		"acceptedSubmissionReferenceAvailable",
		"exactRetryOfSameRequestSafe",
		"newKeyRequired",
		"reliableSubmitRunRefDisclosureRequiredForSameAuthorizedCaller",
		"reliableSubmitRunRefDisclosureOpenForLaterTransportContract",
	)
	assertContainsNone(t, "reliable-submit private source forbidden dependencies", contractSource+identitySource+outcomeSource,
		"database/sql",
		"modernc.org/sqlite",
		"pgx",
		"postgres",
		"net/http",
		"http.Status",
		"StatusAccepted",
		"ProducerContract",
		"ReliableSubmitConfig",
	)
}

func TestReliableSubmitBindingProducerDocsContract(t *testing.T) {
	plansRaw := mustRead(t, plansRecordPath)
	plans := compactDocSection(t, plansRaw,
		"## Historical current-remote-base PB1 binding selection (2026-11-17)",
		"## Historical current-remote-base H/C/T foundation selection (2026-11-17)")
	assertContainsAll(t, "private binding selected plan", plans,
		"ES-PRIVATE-ADMISSION-BINDING-V1-20261115-01",
		"runtime-unwired",
		"accepted integration I",
		"signature-verified returned mount artifact digest",
		"signed payload digest",
		"without changing legacy admission rejection",
		"no production caller at PB1",
		"Reliable submit remains unavailable",
	)

	recoveryRaw := mustRead(t, ".docs/execution_lifecycle/submit_idempotency_correlation_and_recovery.md")
	current := compactDocSection(t, recoveryRaw, "## 2. Current Implementation Reality", "## 3. Dual Ambiguity Model")
	nonClaims := compactDocSection(t, recoveryRaw, "## 15. Explicit Non-Claims", "## 16. Required-Before-Implementation Gates")
	assertContainsNone(t, "private binding current absence denial", current+" "+nonClaims,
		"no canonical effective-plan encoding implemented",
		"no `PlanBinding` construction from admitted facts implemented",
		"no complete effective-plan witness construction in package `admission` implemented",
	)
	binding := compactDocSection(t, recoveryRaw,
		"### Private admission binding v1: current unwired producer and exact format",
		"## 7. Narrow Durable Correlation Semantics")
	assertContainsAll(t, "private binding current contract", binding,
		"buildReliableSubmitAdmissionBinding",
		"actual `resolvedExecution`",
		"fourteen-category witness",
		"always reports not-effect-ready",
		"Only the named private synthetic same-delivery composer calls",
		"requested/verified signed artifact equality",
		"existing governed mount parser",
		"The live resolver refuses a mount whose discovery record names another artifact than the requested source",
		"HMAC-SHA-256",
		"exactly 32 bytes",
		"[A-Za-z0-9][A-Za-z0-9._-]{0,63}",
		"ESRS-PB",
		"execution-substrate/reliable-effective-plan/v1",
		"header || mac",
		"64 MiB",
		"before sorting a map",
		"source-normalized",
		"present empty regular file",
		"Directory content is inapplicable",
		"Effective timeout in **seconds**",
		"**nanoseconds**",
		"value becoming omitted conflicts even if effective bindings match",
		"original intent",
		"No runtime function-value alias, handler, provider, store, or config uses it",
	)
	for _, category := range []string{
		"RequestSchemaOrVersion", "ExecutionMode", "TimeoutSemantics", "CPU", "Memory",
		"RuntimeProfile", "ArtifactIdentity", "DerivationSpecIdentity", "OutputIdentity",
		"CommandAndArgv", "EnvironmentAdditions", "Mounts", "NetworkPosture",
		"AuthorityHandoffApplicability",
	} {
		if strings.Count(binding, "`"+category+"`") != 1 {
			t.Fatalf("private binding category %s must have exactly one validation row", category)
		}
	}
	for _, tag := range []string{
		"`1` UTF-8 string", "`2` signed 64-bit", "`3` boolean", "`4` record",
		"`5` sequence", "`6` map", "`7` raw 32-byte SHA-256 digest", "`8` one-byte state",
	} {
		assertContainsAll(t, "private binding exact type tags", binding, tag)
	}
	table := docSection(t, recoveryRaw,
		"The eighteen top-level fields and complete nested record field IDs are:",
		"All scalar integer conversions must fit signed 64-bit range.")
	rows := strings.Split(table, "\n")
	last := -1
	for id := 1; id <= 18; id++ {
		marker := fmt.Sprintf("| `%d` ", id)
		matches := 0
		position := -1
		for index, row := range rows {
			if strings.HasPrefix(row, marker) {
				matches++
				position = index
			}
		}
		if matches != 1 {
			t.Fatalf("private binding top-level field %d is not unique", id)
		}
		if position <= last {
			t.Fatalf("private binding top-level field %d is out of order", id)
		}
		last = position
	}
	assertContainsAll(t, "private binding nested mount schema", table,
		"signature-verified returned artifact digest",
		"signed payload digest",
		"once-normalized name string",
		"full normalized mode integer",
	)
	producer := mustRead(t, "es/admission/reliable_submit_binding.go") + mustRead(t, "es/admission/reliable_submit_binding_encoding.go")
	assertContainsAll(t, "private binding producer source", producer,
		"func buildReliableSubmitAdmissionBinding",
		"type admissionBindingAssessment struct",
		"type privateBindingKey struct",
	)
}

func TestReliableSubmitPersistenceAndConcurrencyADRDocsContract(t *testing.T) {
	adrPath := ".docs/execution_lifecycle/reliable_submit_persistence_and_concurrency.md"
	adrRaw := mustRead(t, adrPath)

	statusPurpose := compactDocSection(t, adrRaw, "## 1. Status And Purpose", "## 2. Current Repository And Deployment Reality")
	currentReality := compactDocSection(t, adrRaw, "## 2. Current Repository And Deployment Reality", "## 3. Authority Boundary")
	authorityBoundary := compactDocSection(t, adrRaw, "## 3. Authority Boundary", "## 4. Storage-Family Decision")
	storageFamily := compactDocSection(t, adrRaw, "## 4. Storage-Family Decision", "## 5. Package And Hydration Boundary")
	packageHydration := compactDocSection(t, adrRaw, "## 5. Package And Hydration Boundary", "## 6. Minimum Durable Fact Model")
	phaseEffectFacts := compactMarkedDocSection(t, "reliable-submit persistence ADR phase/effect facts", adrRaw, "### Pure-Model Phase Versus Provider-Effect Facts", "Another subpackage")
	factModel := compactDocSection(t, adrRaw, "## 6. Minimum Durable Fact Model", "## 7. Revision And CAS Semantics")
	revisionCAS := compactDocSection(t, adrRaw, "## 7. Revision And CAS Semantics", "## 8. Provider-Effect Intent And Ordering")
	effectIntent := compactDocSection(t, adrRaw, "## 8. Provider-Effect Intent And Ordering", "## Validated No-Dispatch Evidence")
	validatedNoDispatch := compactDocSection(t, adrRaw, "## Validated No-Dispatch Evidence", "## 9. Operation Contract")
	operationContract := compactDocSection(t, adrRaw, "## 9. Operation Contract", "## 9A. Durable Latest-Operation Replay Repair ADR")
	latestOperationReplay := compactDocSection(t, adrRaw, "## 9A. Durable Latest-Operation Replay Repair ADR", "## 10. Crash-Window Matrix")
	crashMatrix := compactDocSection(t, adrRaw, "## 10. Crash-Window Matrix", "## 11. Retention And Tombstones")
	retention := compactDocSection(t, adrRaw, "## 11. Retention And Tombstones", "## 12. Security, Permissions, And Corruption")
	security := compactDocSection(t, adrRaw, "## 12. Security, Permissions, And Corruption", "## 13. Initial Deployment Topology")
	deployment := compactDocSection(t, adrRaw, "## 13. Initial Deployment Topology", "## 14. Required Dependency-Selection Gate")
	dependencyGate := compactDocSection(t, adrRaw, "## 14. Required Dependency-Selection Gate", "## 15. First Concrete Source Tranche")
	nextTranche := compactDocSection(t, adrRaw, "## 15. First Concrete Source Tranche", "## 16. Explicit Non-Claims And Open Decisions")
	privateCustody := compactDocSection(t, adrRaw, "## 15A. Private codec-3 synthetic custody, SQLite and recovery", "## 15B. Proposed private original replay and durable claim progress")
	nonClaimsOpen := compactDocSection(t, adrRaw, "## 16. Explicit Non-Claims And Open Decisions", "")
	assertContainsAll(t, "private codec-3 custody ADR", privateCustody,
		"synthetic_nonoperational_v1",
		"Only codec 3 requires caller_ref and submit_key_ref BLOB exactly 32",
		"For codec 1/2 all fourteen must be NULL",
		"4dafddbf477fd7f64ad88cf2b1e2b2becb378827e81cd6cc694456798c9a00be",
		"15ab48bde4d53bb252dc954a2aa3b1db12de7295111f23bb0264f74f153dba92",
		"sets and verifies recursive_triggers=ON",
		"a known successful COMMIT alone yields one process-local one-use permit",
		"fresh NONMIGRATING",
		"No production key loader or global rollback",
		"Binary custody encoding is the selected bounded private exception",
	)

	assertContainsAll(t, "O2 historical CAS physical proof", privateCustody,
		"historical codec-1/2 CAS path",
		"independent writer-lock release",
		"no reuse after discard",
		"A pre-dispatch COMMIT error must not be turned into a rollback shortcut",
		"codec-3 CAS stays refused",
	)
	assertContainsAll(t, "reliable-submit persistence ADR status", statusPurpose,
		"accepted architecture decision with bounded private codec-3 synthetic replay custody",
		"historical first tranche added private admission-local durable claim source and tests",
		"one backend-neutral claim-store port",
		"one durable semantic service",
		"one private durable-record codec",
		"one SQLite implementation using",
		"`modernc.org/sqlite v1.54.0`",
		"a shared backend conformance suite",
		"no configuration source",
		"no request or response DTO",
		"no HTTP handler",
		"no staging behavior",
		"no Nomad behavior",
		"no producer-contract field",
		"no runtime startup wiring",
		"Reliable submit remains unimplemented end to end",
		"`es/admission/internal/reliablesubmit`",
		"`reliable-submit-durable-same-operation-replay-repair`",
		"implemented the section 9A latest-operation contract",
		"Codec-1/2 rows retain their historical meaning",
		"valid v1 rows migrated as legacy/unbound codec-1 rows",
	)
	assertContainsAll(t, "reliable-submit persistence ADR current reality", currentReality,
		"admission-local and private",
		"unwired",
		"transport-neutral",
		"persistence-neutral",
		"effect-free",
		"private durable hydration",
		"remains unwired from submit, HTTP, Nomad, and runtime startup",
		"`modernc.org/sqlite v1.54.0`",
		"`modernc.org/libc v1.74.1`",
		"No PostgreSQL dependency is introduced",
		"`CGO_ENABLED=0 GOOS=linux GOARCH=amd64`",
		"must be preserved",
		"`execution.staging_root_dir`",
		"`execution.results_root_dir`",
		"creates only the staging and results roots",
		"`User=es`",
		"`Group=es`",
		"`UMask=0027`",
		"`es:es`",
		"in-process mutexes",
		"not a cross-process durable CAS substrate",
		"SQLite schema version 3 adds only private synthetic codec-3 custody",
		"Historical codec-2 rows still store the latest `lastMutation` reference",
		"migrated codec-1 rows retain",
		"generic nonempty opaque CallerRef, SubmitKeyRef and PlanBinding domains",
		"Only complete codec-3 rows require CallerRef/SubmitKeyRef of exactly 32 bytes",
		"No mutation history is stored",
	)
	assertContainsAll(t, "reliable-submit persistence ADR authority boundary", authorityBoundary,
		"narrow ES submit-correlation authority",
		"authenticated caller namespace binding",
		"safe private submit-key representation",
		"private effective-plan binding",
		"reliable-submit claim phase",
		"immutable ES-assigned `RunRef`",
		"bounded `ReceiptRef`",
		"monotonic revision",
		"retention, expiry, tombstone, ambiguity, and corruption posture",
		"must not become",
		"allocation history",
		"runtime status timeline",
		"log index",
		"result-content store",
		"cancellation-completion truth",
		"runtime retry or reschedule policy",
		"Coordinator work, attempt, dispatch, acceptance, or semantic state",
		"Git, CI, validation, or publication truth",
		"adapter, Bridge, or connector authority",
		"Nomad lifecycle mirror",
		"Nomad remains submitted-execution lifecycle authority",
		"Provider metadata, Nomad allocation IDs, EvalID, trace IDs, request IDs, adapter sessions, and Bridge records are not reliable-submit correlation authority",
	)
	assertContainsAll(t, "reliable-submit persistence ADR storage family", storageFamily,
		"selected embedded storage family",
		"local SQLite",
		"durable uniqueness",
		"immutable run assignment",
		"phase constraints",
		"revision CAS",
		"tombstones",
		"migration discipline",
		"local host storage only",
		"The selected Go SQLite driver is `modernc.org/sqlite v1.54.0`",
		"`modernc.org/libc v1.74.1`",
		"CGO-only SQLite driver is excluded",
		"`CGO_ENABLED=0`",
		"selects WAL",
		"`synchronous=FULL`",
		"`foreign_keys=ON`",
		"`trusted_schema=OFF`",
		"bounded `busy_timeout`",
		"immediate write-lock acquisition",
		"user-versioned forward-only embedded migrations",
		"fail-closed corruption and unsupported-version handling",
		"zero-version database only through a narrow empty-bootstrap gate",
		"requires no pre-existing non-`sqlite_%` schema object",
		"non-empty database with `application_id = 0` and `user_version = 0` is rejected as unsupported",
		"does not claim to identify every possible historical byte-level provenance",
		"Online backup/restore, managed backup, destructive restore, host replacement, and operator repair remain later operations contracts",
		"bbolt or another embedded key/value store: not selected",
		"handwritten JSON, append-only files, file directories, locks, and atomic replacement: not selected",
		"existing ES or ARS file/index patterns: not sufficient",
		"provider or Nomad metadata: rejected",
		"external database service: rejected",
	)
	assertContainsAll(t, "reliable-submit persistence ADR package and hydration", packageHydration,
		"The concrete store, backend-neutral port, durable semantic service, and private durable-record codec belong in the existing admission-local package",
		"`es/admission/internal/reliablesubmit`",
		"separate files from `model.go`",
		"not a public storage API, generic repository framework, ORM abstraction, database platform, generic SQL layer, or lowest-common-denominator CRUD interface",
		"pure model core remains I/O-free and database-free",
		"must not import SQLite",
		"`database/sql`",
		"filesystem packages",
		"time",
		"locks",
		"JSON codecs",
		"narrow private same-package codec",
		"No raw caller, submit-key, plan-binding, run, or receipt accessor is exported merely for storage",
		"No `Bytes`, `Raw`, `MarshalJSON`, SQL `Value`, SQL `Scan`, DTO, or database helper API",
		"must hydrate through the committed pure model invariants",
		"must not define a second persistence phase enum or independent phase algebra",
		"The private port expresses reliable-submit durable semantics only",
		"establish-or-load by `ClaimID`, load by `ClaimID`, and compare-and-swap by expected revision",
		"Backup is not part of the common port",
		"Pure-Model Phase Versus Provider-Effect Facts",
		"Provider-effect intent is an orthogonal durable fact",
		"not a pure-model phase",
		"Persistence hydration must reconstruct or validate an existing pure-model phase plus the orthogonal provider-effect evidence",
		"Another subpackage, including a child SQLite store package, may be reconsidered only through a later explicit encapsulation decision",
	)
	assertContainsAll(t, "reliable-submit persistence ADR phase/effect facts", phaseEffectFacts,
		"The committed `reliablesubmit` phase remains the authoritative claim-shape algebra",
		"Provider-effect intent is an orthogonal durable fact over an existing assigned claim phase",
		"It is not a pure-model phase",
		"Staging or materialization evidence is an orthogonal local-effect fact",
		"Provider-dispatch-attempt evidence is an orthogonal durable fact",
		"Provider-response and reconciliation evidence are orthogonal facts",
		"may constrain which pure-model transition is valid",
		"do not create a second model phase vocabulary",
		"must not introduce a provider-effect-intent phase, staging phase, provider-dispatch phase, provider-response phase",
		"Persistence hydration must reconstruct or validate an existing pure-model phase plus the orthogonal provider-effect evidence",
		"Same-package private access does not authorize bypassing constructors, normalization, or committed model invariants",
	)
	assertContainsAll(t, "reliable-submit persistence ADR fact model", factModel,
		"Authoritative stored facts",
		"store format version and schema/migration state",
		"authenticated caller namespace safe representation",
		"safe private submit-key representation scoped by caller namespace",
		"private effective-plan binding",
		"committed reliable-submit claim phase",
		"immutable `RunRef` after assignment",
		"bounded `ReceiptRef` after acceptance",
		"monotonic revision",
		"latest-operation descriptor for v2 rows",
		"latest mutation reference",
		"closed operation kind",
		"versioned safe operation-input binding digest",
		"provider-effect intent and ambiguity facts",
		"Private security material",
		"submit-key digest, HMAC, or equivalent safe representation",
		"private operation-input binding digest for the latest committed mutation",
		"External references",
		"ES-assigned `RunRef`",
		"Derived projections",
		"exact latest-operation replay view",
		"Forbidden lifecycle duplication",
		"allocation IDs, EvalID, scheduler job identity as recovery authority",
		"runtime status timeline",
		"logs",
		"result contents",
		"cancellation completion",
		"runtime retry or reschedule policy",
		"Coordinator semantic work or attempt state",
	)
	assertContainsAll(t, "reliable-submit persistence ADR revision CAS", revisionCAS,
		"one monotonic revision",
		"Every new mutation carries an expected predecessor revision",
		"Exact replay is latest-operation-only",
		"mutation reference, closed operation kind, and versioned operation-input binding before stale-revision rejection",
		"Different mutation references remain subject to revision, phase, and transition rules",
		"caller namespace plus safe submit-key representation is unique",
		"Concurrent first deliveries converge on one durable claim",
		"Historical codec-1/2 loads compare the same private binding",
		"private codec-3 synthetic adapter instead loads the verified winner by key",
		"compares canonical winner-original intent and field presence",
		"`RunRef` assignment is immutable",
		"assigned exactly once",
		"already assigned same `RunRef` is idempotent",
		"stale mutation",
		"rejected fail-closed",
		"store, not an in-process mutex, is mutation authority",
		"COMMIT outcome is uncertain",
		"must retry by loading the durable claim",
		"full latest-operation descriptor when present",
		"full expected-record equality",
		"not permission to create a second claim, assign a second run, or repeat an external provider effect",
	)
	assertContainsAll(t, "O2 historical CAS cleanup contract", revisionCAS,
		"O2 historical codec-1/2 CAS cleanup",
		"every `compareAndSwapClaim` pre-COMMIT exit",
		"context independent of the request",
		"cleanup failure overrides even a would-be nil-error return",
		"No rollback follows an attempted COMMIT",
		"before returning COMMIT-unknown or allowing a durable reload",
		"A high-level `sql.Conn.Close()` alone is not disposal proof",
		"A1 original-key read cleanup",
	)
	assertContainsAll(t, "A1 original-key read cleanup contract", revisionCAS,
		"A1 original-key read cleanup — Bounded slice rule refinement",
		"one read transaction on one checked connection",
		"Semantic BEGIN, SELECT and COMMIT use the caller's context",
		"read never registers a missing key",
		"Invalid keys retain unsupported precedence",
		"already-canceled request",
		"before dispatching read BEGIN",
		"nonnil result after BEGIN dispatch is potentially post-execution",
		"fixed unexported five-second budget",
		"Confirmed rollback permits ordinary connection release",
		"failed, expired or unconfirmed rollback",
		"marks COMMIT attempted before invoking COMMIT",
		"no post-attempt rollback or durable-claim reload",
		"no-ordinary-release decision precedes discard",
		"at most two attempts",
		"withhold that connection from ordinary",
		"one-use Seal permit",
		"inert empty/unclaimed file",
		"no-adoption and no-object-ID-reuse",
		"shared `beginRead`/`rollbackIfOpen` callers",
	)
	assertContainsAll(t, "reliable-submit persistence ADR effect intent", effectIntent,
		"committed pure-model claim phase from orthogonal provider-effect facts",
		"assigned but no provider effect may have started",
		"durable provider-effect intent committed",
		"staging or materialization evidence recorded when selected",
		"provider-dispatch-attempt fact committed",
		"provider request may have crossed the process boundary",
		"pending provider result",
		"ambiguous provider result",
		"accepted",
		"provably not accepted",
		"Effect intent must be committed durably before any external execution-producing I/O",
		"External I/O occurs outside the SQLite transaction",
		"Provider-effect intent alone is not evidence that a provider request was dispatched",
		"Staging or completed staging alone is not evidence that a provider request was dispatched",
		"provider-dispatch-attempt fact must commit durably before the provider request is sent",
		"Absence of the provider-dispatch-attempt fact becomes positive ES-owned evidence",
		"only through the complete Validated No-Dispatch Evidence predicate",
		"repair or reuse staging for the same claim and `RunRef`",
		"commit the provider-dispatch-attempt fact through expected-revision CAS",
		"first same-`RunRef` provider dispatch only after that marker commit is known successful",
		"No new claim or `RunRef` is created",
		"Once the provider-dispatch-attempt fact exists",
		"the request may have crossed the process boundary",
		"running ES-owned reconciliation or returning/recovering pending or ambiguous outcome",
		"must not automatically send a second Nomad submission",
		"Generic Nomad/job absence is not sufficient proof of non-acceptance",
		"Provider response, provider transport failure, response loss, or provider-call uncertainty evidence requires the committed provider-dispatch-attempt fact",
		"conservative dispatch-attempt marker may create an ambiguous window",
		"not hidden as exactly-once provider execution",
		"Accepted and recovered-accepted require the durable `RunRef` and bounded `ReceiptRef`",
		"positive ES-owned evidence",
	)
	assertContainsAll(t, "reliable-submit persistence ADR validated no-dispatch evidence", validatedNoDispatch,
		"Marker absence is positive ES-owned evidence",
		"only when every condition below holds",
		"exact same active durable claim was successfully loaded using its authenticated caller namespace and submit-key scope",
		"The durable record exists",
		"not missing, expired for active use, tombstoned as unavailable, corrupt, undecodable, or on an unsupported schema or migration state",
		"Private record decoding succeeded",
		"Hydration or validation against the committed pure-model invariants succeeded",
		"loaded `ClaimID`, private effective-plan binding, and `RunRef` match the operation being recovered",
		"Provider-effect intent is durably committed",
		"The provider-dispatch-attempt fact is absent",
		"Every relevant durable transaction outcome is known",
		"the effect-intent transaction, any attempted dispatch-marker transaction, and any preceding revision/CAS mutation",
		"No unresolved commit-uncertainty condition could explain the apparent absence of the marker",
		"implementation contract and stored record version both guarantee that every provider-I/O path commits the dispatch-attempt fact before provider I/O",
		"current record revision has been loaded and validated for the next CAS mutation",
		"Only after all conditions hold may ES repair or reuse staging for the same claim and `RunRef`",
		"commit the dispatch-attempt fact through expected-revision CAS",
		"perform the first provider dispatch for that same claim and `RunRef` after the marker commit is known successful",
		"Missing state is not valid marker absence",
		"Corrupt or undecodable state is not valid marker absence",
		"Unsupported migration or schema state is not valid marker absence",
		"Tombstone or expiry is not valid marker absence",
		"Unresolved commit uncertainty is not valid marker absence",
		"Process-local memory, trace IDs, request IDs, or generic provider absence are not valid no-dispatch evidence",
		"Failure of any condition makes reliable submit unavailable, ambiguous, or fail-closed",
		"Failure does not authorize dispatch or fallback to unkeyed submit",
		"Provider-dispatch-attempt fact implies provider-effect intent",
		"Provider-call response or call-uncertainty evidence implies a committed provider-dispatch-attempt fact",
		"Provider response or uncertainty evidence must not exist in an ordinary valid no-marker state",
		"`Accepted` requires the existing pure-model `RunRef` and `ReceiptRef` invariants",
		"Contradictory effect-fact combinations fail closed and require invariant, corruption, or unavailable handling rather than silent normalization",
		"SQLite schema adds check constraints and triggers for impossible row combinations, immutability, and monotonic physical facts",
		"service and pure model remain the transition authority",
	)
	assertContainsAll(t, "reliable-submit persistence ADR operation contract", operationContract,
		"private durable-operation contract implemented by the current durable source",
		"exact redelivery of the current latest durable operation replays the already committed result",
		"Older operations after later progression are stale or superseded",
		"accepted replay returns the same accepted record and receipt",
		"provably-not-accepted replay returns the same terminal record",
		"no new mutation or external effect occurs",
		"Resulting pure-model phase",
		"Durable effect facts established or changed",
		"Establish or load claim",
		"Compare binding",
		"Assign run",
		"Record provider-effect intent",
		"Begin or complete staging/materialization",
		"Record provider-dispatch attempt",
		"Record provider call observation or uncertainty",
		"Record reconciliation evidence",
		"Accept with receipt",
		"Record provably not accepted",
		"Exact replay or load",
		"Tombstone or expire",
		"Corruption or unavailable",
		"One SQLite transaction",
		"No external I/O",
		"Pending before assignment, ambiguous before assignment where permitted by the current durable request/model source, or existing hydrated pure-model phase",
		"Remains the existing assigned/effect-capable model phase",
		"Provider-effect intent committed; no staging, provider dispatch, provider response, or provider acceptance is proved",
		"no provider dispatch is proved",
		"Provider-dispatch-attempt fact committed; no provider acceptance is proved",
		"Provider request may be sent only after commit",
		"Same active durable claim with matching `ClaimID`, private effective-plan binding, and `RunRef`",
		"committed provider-effect intent; committed provider-dispatch-attempt fact",
		"provider pending, ambiguous, transport-failure, response-loss, or call-uncertainty evidence",
		"Missing dispatch-attempt fact",
		"provider absence alone",
		"attempt to record terminal accepted/provably-not-accepted through this observation path fails closed",
		"Only an existing or newly justified committed model transition among `PendingAfterAssignment` or `AmbiguousAfterAssignment`",
		"accepted and provably-not-accepted evidence use the dedicated terminal operations below",
		"Provider-call observation or uncertainty evidence recorded; no lifecycle timeline or provider history store; no new `ClaimID` or `RunRef`",
		"provider-call observation or uncertainty evidence cannot be recorded in a no-marker state",
		"Same active durable claim and `RunRef` plus expected revision/CAS",
		"Validated No-Dispatch Evidence or a committed provider-dispatch-attempt fact",
		"provider-response labeling in a no-marker state",
		"fails closed as invariant, corruption, or unavailable posture",
		"With validly absent dispatch-attempt fact: validated no-dispatch evidence, local staging/materialization recovery facts, or fail-closed inconsistency evidence only; no provider response or call uncertainty",
		"With dispatch-attempt fact: accepted, positive provably-not-accepted, still-pending, or ambiguous evidence",
		"reconciliation is separate from recording a provider-call response and introduces no second phase algebra",
		"External provider/staging I/O begins only after commit",
		"Different binding conflicts",
		"Unauthorized discloses nothing",
		"must not fall back to current unkeyed submit",
		"Current Same-Operation Replay Implementation Status",
		"previously committed latest-operation descriptor before stale-revision and inactive-state refusal",
		"Same mutation plus same closed operation kind and input binding returns the operation's committed result without another CAS",
		"Same mutation plus different kind or input binding returns mutation conflict",
		"Same mutation against a migrated legacy/unbound descriptor fails closed as unavailable",
		"private store remains runtime-unwired",
		"does not affect current public execution behavior",
		"completed prerequisite for later reliable-submit config or store lifecycle wiring, producer enablement, and public runtime enablement",
	)
	assertContainsAll(t, "reliable-submit latest-operation replay ADR", latestOperationReplay,
		"private source implemented and runtime-unwired",
		"The durable service, durable record, SQLite schema v2 migration, SQLite row scan/write/CAS, store tests, and shared conformance tests implement this ADR",
		"general mutation path derives a complete latest-operation descriptor",
		"exact latest-operation redelivery is implemented for terminal and nonterminal durable mutations",
		"SQLite schema version is v2",
		"persist the latest `lastMutation`, closed private operation kind, and operation-input binding digest for codec-2 rows",
		"migrated codec-1 rows retain only `lastMutation`",
		"no mutation history is retained",
		"Exact replay is guaranteed only for the current latest committed durable mutation on the claim",
		"No historical mutation-result log is introduced",
		"older operation arriving after a later committed mutation",
		"stale or superseded posture",
		"current later record must not be represented as the earlier operation's replay result",
		"latest mutation reference",
		"closed private operation kind",
		"versioned safe operation-input binding digest",
		"The three descriptor facts update atomically",
		"Mutation reference alone is not sufficient proof of same semantic command",
		"historical codec-1/2 durable service",
		"Same caller/key/binding loads existing claim without descriptor rewrite",
		"`establish_claim`",
		"`assign_run`",
		"`record_provider_effect_intent`",
		"`record_staging_evidence`",
		"`record_provider_dispatch_attempt`",
		"`record_provider_call_observation`",
		"`record_reconciliation_evidence`",
		"`accept_with_receipt`",
		"`record_provably_not_accepted`",
		"`tombstone_or_expire`",
		"`SHA256(\"es/reliable-submit/durable-operation-input/v1\\0\" || deterministic operation-specific safe encoding)`",
		"must include the expected predecessor revision",
		"every operation-specific safe opaque reference or immutable value that changes command meaning",
		"Semantic values must be normalized before sorting or duplicate detection",
		"expected predecessor revision, the closed operation kind, and every current request-carried safe receipt or evidence input that changes command meaning",
		"Claim identity and private plan binding are validated from the loaded claim",
		"existing durable-state fact is not made into a request-carried input",
		"no terminal operation row treats `RunRef` as a request-carried operation input",
		"immutable `RunRef` is validated from the hydrated existing assigned phase and durable record",
		"Terminal apply cannot proceed without the valid assigned-run context required by the committed pure model",
		"COMMIT-unknown full expected-record equality still includes the durable `RunRef` and the complete latest-operation descriptor",
		"This ADR selects no terminal request-shape expansion",
		"mutation reference itself",
		"service-generated timestamps",
		"raw requests",
		"submit keys",
		"caller URIs",
		"environment values",
		"credentials",
		"filesystem paths",
		"unrestricted provider IDs",
		"trace, request, session, and report IDs",
		"logs and result bodies",
		"Load the current record",
		"Validate schema and codec, then hydrate the pure phase",
		"Validate claim identity and private plan binding",
		"Derive and validate the incoming operation descriptor",
		"Compare mutation reference before stale-revision rejection",
		"same mutation plus same operation kind and input binding is exact latest-operation replay",
		"same mutation plus different operation kind or input binding is mutation conflict",
		"apply retention and inactive-state classification",
		"Validate expected revision",
		"On CAS loss, reload and repeat replay, conflict, stale, or superseded classification before returning stale",
		"COMMIT uncertainty",
		"full expected-record equality comparison, including the latest-operation descriptor",
		"before inactive-state refusal",
		"Corrupt, unsupported, or unhydratable state fails closed before replay",
		"Same assigned record and same `RunRef`",
		"Same record and same intent fact",
		"Same record and same staging fact",
		"Same record and same dispatch fact",
		"Pending or ambiguous phase justified by observation or call-uncertainty evidence",
		"Same semantic observation and same `RunRef`",
		"Same reconciliation fact and same `RunRef`",
		"Expected predecessor revision, accepted evidence reference where represented, and `ReceiptRef`",
		"Same accepted record and same `ReceiptRef`",
		"Expected predecessor revision and terminal not-accepted evidence reference",
		"Same terminal record",
		"Same inactive record",
		"Same payload with a new mutation reference is not exact replay",
		"must not update `lastMutation` merely to give a new identity to an already completed effect",
		"accepted exact replay returns the same accepted record and `ReceiptRef`",
		"provably-not-accepted exact replay returns the same terminal record",
		"same mutation with different receipt or evidence binding conflicts",
		"no public run or receipt disclosure policy is widened",
		"Concurrent exact duplicates may both load the same predecessor revision",
		"One CAS wins",
		"The loser reloads",
		"A SQLite schema migration is required",
		"logical v2 additions are the latest operation kind and latest operation input-binding digest",
		"operation kind and digest either both present or both absent for a migrated legacy row",
		"every newly created v2 row has a complete descriptor",
		"every successful v2 mutation updates mutation reference, operation kind, and fixed-length input digest together with revision `old+1`",
		"no descriptor-only update",
		"no revision update without the descriptor triple",
		"no delete or retention resurrection",
		"Existing v1 rows cannot be assigned invented operation semantics",
		"legacy/unbound migration posture",
		"preserve the existing v1 row",
		"retain the legacy mutation reference without treating it as a complete descriptor",
		"mark operation kind and input digest unavailable/unbound",
		"phase, durable effect facts, provider evidence, reports, logs, traces, request IDs, provider IDs, retained result material",
		"do not claim exact same-operation replay for that unbound latest mutation",
		"same-mutation replay attempt against an unbound legacy descriptor fails closed",
		"later valid distinct mutation may proceed through normal revision and phase rules",
		"no background rewrite, state deletion, or fabricated replay result is authorized",
		"unsupported future schema versions fail closed",
		"claimStore` port remains establish/load/CAS",
		"No PostgreSQL-specific type",
		"The current source repair updates the durable record and codec",
		"The durable service derives and compares operation descriptors",
		"Shared backend conformance covers the same semantics",
		"no reliable-submit state-path configuration or store lifecycle, producer enablement, public DTO, handler, staging, Nomad, or runtime behavior",
	)
	assertContainsNone(t, "reliable-submit latest-operation replay terminal request RunRef defect", latestOperationReplay,
		"Expected predecessor revision, `RunRef`, accepted evidence reference where represented, and `ReceiptRef`",
		"Expected predecessor revision, `RunRef`, and terminal not-accepted evidence reference",
	)
	assertContainsNone(t, "reliable-submit persistence ADR operation table old phase defect", operationContract,
		"provider-effect-intent phase that hydrates to a provider outcome candidate",
		"Resulting model phase",
		"Record provider response or reconciliation result",
	)
	assertContainsAll(t, "reliable-submit persistence ADR crash matrix", crashMatrix,
		"Could provider dispatch have occurred?",
		"Duplicate delivery or first-effect behavior",
		"Before claim persistence",
		"After claim before run assignment",
		"After run assignment before provider-effect intent",
		"After effect intent before staging",
		"During staging or local effect preparation",
		"After staging before dispatch-attempt commit",
		"After dispatch-attempt commit before provider call",
		"Provider call may have occurred before conclusive response",
		"Provider response uncertain or ambiguous result persisted",
		"After accepted receipt persistence before caller response",
		"During COMMIT uncertainty",
		"After expiry or tombstone",
		"dispatch-attempt fact is absent",
		"No only after the full Validated No-Dispatch Evidence predicate passes",
		"Staging and the first same-run provider dispatch remain permitted only after the full predicate passes",
		"Retry repairs or reuses same run-scoped material",
		"First same-run provider dispatch remains permitted only after the full predicate passes",
		"the marker is then committed through expected-revision CAS",
		"provider I/O occurs only after marker commit success",
		"Yes, conservatively, because crash cannot distinguish this window from one where the call crossed the boundary",
		"No automatic provider call or resubmit on restart",
		"Retry must not auto-register again",
		"no automatic provider resubmission",
		"ES-owned reconciliation is required",
		"generic provider absence is not proof",
		"call outcome or uncertainty evidence requires the marker",
		"Lost caller response is not a new execution",
		"latest-operation descriptor when present",
		"full expected-record equality",
	)
	assertContainsAll(t, "reliable-submit persistence ADR retention", retention,
		"Expiry cannot become generic absence",
		"Deletion cannot be represented as proof that no prior execution existed",
		"Automatic key reuse after expiry is not allowed by inference",
		"historical assignment truth",
		"tombstone",
		"Exact TTL, garbage collection, archival behavior, compaction, and operator repair remain open",
		"do not retain lifecycle timelines, logs, result contents, cancellation completion, or provider history",
	)
	assertContainsAll(t, "reliable-submit persistence ADR security", security,
		"Raw submit keys",
		"raw request bodies",
		"raw effective-plan material",
		"credentials",
		"trust material",
		"local paths",
		"scheduler IDs",
		"allocation IDs",
		"EvalID",
		"trace IDs",
		"request IDs",
		"must not be stored or logged as public recovery authority",
		"separate ES-owned state path",
		"must not reuse `execution.staging_root_dir` or `execution.results_root_dir` as the database path",
		"explicit configuration addition in a later tranche",
		"`es:es` directory ownership",
		"owner-only or equivalently restrictive database and sidecar file modes",
		"must not require root, supplemental groups, or broader deployment privileges",
		"must not include raw database diagnostics",
		"Corruption or malformed durable state fails reliable submit closed",
		"must not fall back to current unkeyed submit",
		"Backup and restore design remains a later gate",
	)
	assertContainsAll(t, "reliable-submit persistence ADR deployment", deployment,
		"first supported deployment may use one ES process on one host",
		"Correctness still derives from SQLite uniqueness, transaction isolation, and revision CAS",
		"does not import the Coordinator writer-session, writer-lease, operation-epoch, proof, or advisory-lock model",
		"Multi-host shared database, high availability, replication, remote database service operation, and active/active ES writers are non-claims",
	)
	assertContainsAll(t, "reliable-submit persistence ADR dependency gate", dependencyGate,
		"Go 1.26.5 compatibility",
		"CGO-free builds under `CGO_ENABLED=0`",
		"linux/amd64 and linux/arm64 support",
		"`database/sql` behavior or a documented replacement API decision",
		"license and redistribution posture",
		"exact direct and transitive version constraints",
		"static and cross-build behavior",
		"busy, locking, transaction, and isolation behavior",
		"backup and corruption APIs",
		"deterministic local/offline test and build posture",
		"sidecar file, journal, WAL, fsync, and permissions behavior",
		"must not select a CGO-only driver",
		"`modernc.org/sqlite v1.54.0` carries a BSD-3-Clause-style module `LICENSE`",
		"The bundled SQLite engine provenance is distinct from the Go wrapper/module license",
		"`SQLITE-LICENSE` states that SQLite deliverable code and documentation are public domain",
		"`modernc.org/libc v1.74.1` carries a BSD-3-Clause-style module `LICENSE`",
		"`LICENSE-3RD-PARTY.md` records additional third-party notices",
		"`golang.org/x/sys v0.46.0` carries the Go Authors BSD-3-Clause-style `LICENSE`",
		"`PATENTS` additional patent grant terms",
		"not legal advice or final packaging clearance",
		"complete transitive notice inventory and assembled distribution notice remain a later release/packaging gate",
	)
	assertContainsAll(t, "reliable-submit persistence ADR next source tranche", nextTranche,
		"same-package private durable-record codec",
		"`es/admission/internal/reliablesubmit`",
		"one private backend-neutral claim-store port",
		"one backend-neutral durable semantic service",
		"one shared backend conformance suite",
		"same-package SQLite store files",
		"separate from `model.go`",
		"`modernc.org/sqlite v1.54.0` as the selected CGO-free SQLite driver",
		"`modernc.org/libc v1.74.1` as the exact expected transitive coupling",
		"`go.mod` and `go.sum` updates",
		"schema v2 with v1-to-v2 migration preserving existing rows as legacy/unbound",
		"unique caller namespace plus safe submit-key claim constraint",
		"immutable run-assignment constraint",
		"revision CAS for every mutation",
		"provider-effect-intent persistence before external I/O",
		"hydration through the committed pure model",
		"crash, concurrency, corruption, permission, migration, and replay tests",
		"current latest-operation replay descriptor source and docs-contract alignment",
		"does not wire current submit, HTTP, DTOs, producer contract, staging, Nomad, lifecycle, result handling, Coordinator, Bridge, CP, IM, Git, CI, validation, publication",
		"global ES configuration, state-path startup wiring",
		"completed latest-operation source repair preserves the private",
		"establish/load/CAS `claimStore` port shape",
		"Later reliable-submit gates remain",
		"runtime consumption and original-key availability for the now-unwired private v1 binding",
		"state/store lifecycle and configuration",
		"Nomad reconciliation",
		"public runtime enablement",
		"not reinterpret the source repair as mutation-history support",
	)
	assertContainsAll(t, "reliable-submit persistence ADR non-claims and open decisions", nonClaimsOpen,
		"no end-to-end reliable submit is implemented in this tranche",
		"no global ES configuration source change is made in this tranche",
		"no current submit, HTTP, DTO, producer-contract, staging, Nomad, lifecycle",
		"no backup API is added to the common port",
		"no online backup/restore, managed backup, destructive restore, host replacement, or operator repair implementation is included",
		"no PostgreSQL dependency, source, schema, DSN, TLS, credential, advisory-lock, HA, replication, or migration implementation is included",
		"no live backend switching, dual write, automatic SQLite/PostgreSQL portability, export/import format, or existing-data migration guarantee is made",
		"no broad ES lifecycle store",
		"no provider metadata authority",
		"no unkeyed fallback for reliable submit",
		"no exported raw persistence accessors",
		"no second phase algebra",
		"no multi-host or HA claim",
		"no history-wide replay or mutation-history store",
		"no public replay DTO or public reliable-submit endpoint",
		"no PostgreSQL backend implementation",
		"exact reliable-submit state-path config key",
		"exact TTL, tombstone, garbage-collection, archival, and repair policy",
		"exact caller namespace source wiring at the authenticated request boundary",
		"operational replay-envelope/key custody, including production key epoch",
		"bounded codec-3 synthetic custody in section 15A does not answer those deployment gates",
		"exact Nomad reconciliation query and evidence rules",
		"exact public receipt, recovery, HTTP status, and error vocabulary",
		"exact runtime submit integration tranche",
		"A future PostgreSQL backend may implement the same private claim-store port and shared conformance suite",
		"separate contract and audit",
	)

	targetRaw := mustRead(t, ".docs/execution_lifecycle/submit_idempotency_correlation_and_recovery.md")
	targetStatus := compactDocSection(t, targetRaw, "## 1. Status And Purpose", "## 2. Current Implementation Reality")
	targetPrivate := compactDocSection(t, targetRaw, "### 6A. Private synthetic original custody and exact format", "### 6B. Proposed private original replay and durable claim progress")
	targetNarrowRecord := compactDocSection(t, targetRaw, "## 7. Narrow Durable Correlation Semantics", "## 8. Ordering And Concurrency Invariants")
	assertContainsAll(t, "private synthetic original contract", targetPrivate,
		"synthetic_nonoperational_v1",
		"actual resolver",
		"raw 43-character",
		"Neither raw key nor raw JSON is persisted",
		"Payload is ASCII ESRSPAY1",
		"Sealed file is a fixed 14-field header",
		"AAD is ASCII ESRSAAD1",
		"Commitment comparisons use a constant-time primitive",
		"Original intent, delivery, key bundle/permit",
		"fixed redacted formatting",
		"Private envelope publication and fsync precede claim establishment",
		"Reliable submit remains unavailable",
	)
	assertContainsAll(t, "reliable-submit target doc ADR pointer", targetStatus,
		"persistence and concurrency ADR",
		"selects local embedded SQLite as the first storage backend",
		"`modernc.org/sqlite v1.54.0` as the CGO-free driver",
		"private same-package durable-store source",
		"leaving runtime integration open",
		"No current public request field, public response DTO field, producer field, handler behavior, query route, Nomad behavior, runtime configuration, or runtime behavior is implemented by this document, the private store tranche, or the unavailable contract-adapter foundation",
		"backend-neutral claim-store port",
		"durable semantic service",
		"durable-record codec",
		"shared conformance suite",
		"SQLite implementation",
		"not wired to current submit",
		"target durable latest-operation replay repair contract",
	)
	assertContainsAll(t, "reliable-submit target doc persistence decision", targetNarrowRecord,
		"narrow submit-correlation record may semantically retain only what is necessary",
		"authenticated caller namespace",
		"opaque submit idempotency key or safe private representation",
		"private request binding",
		"assigned `run_id`",
		"bounded submission outcome class",
		"retention and expiry information",
		"latest mutation reference",
		"closed operation kind",
		"versioned input-binding digest",
	)

	custody := standingRuleSection(t, standingAdmissionRulesPath, pairedRootCustodyHeading)
	admissionRules := compactText(mustRead(t, standingAdmissionRulesPath))
	assertContainsAll(t, "paired-root custody standing rules reliable-submit persistence tranche", custody,
		"`reliable-submit-durable-same-operation-replay-repair`",
		"source tranche is implemented inside the private durable source",
		"derives a latest-operation descriptor",
		"recognizes the current latest committed mutation before stale-revision and inactive-state refusal",
		"same-mutation/different-kind-or-binding reuse",
		"keeps COMMIT-unknown recovery on stricter full-record equality including the descriptor",
		"SQLite schema v2 persists the descriptor for codec-2 rows",
		"preserves migrated v1 rows as legacy/unbound",
		"Historical mutation retention remains out of scope",
	)
	assertContainsAll(t, "admission standing rules reliable-submit persistence tranche", admissionRules,
		"reliable_submit_persistence_and_concurrency.md",
		"narrow ES-owned submit-correlation store",
		"local embedded SQLite as the first concrete backend",
		"current `CGO_ENABLED=0` build posture",
		"`modernc.org/sqlite v1.54.0`",
		"`modernc.org/libc v1.74.1`",
		"backend-neutral claim-store port",
		"durable semantic service",
		"private same-package durable-record codec",
		"same-package SQLite implementation",
		"revision/CAS semantics",
		"durable provider-effect intent before external I/O",
		"does not add global ES configuration, production runtime wiring, public DTOs, HTTP handler behavior, staging, Nomad, lifecycle",
		"does not promise live backend switching, dual write, automatic SQLite/PostgreSQL data portability",
	)

	designPressure := compactDocSection(t, mustRead(t, ".docs/execution_lifecycle/design.md"), "## 9A. Submit Idempotency And Recovery Pressure", "## 10. Runtime identity and lifecycle interaction")
	assertContainsAll(t, "design reliable-submit persistence ADR pointer", designPressure,
		"reliable_submit_persistence_and_concurrency.md",
		"local embedded SQLite as the first storage backend",
		"current `CGO_ENABLED=0` build posture",
		"`modernc.org/sqlite v1.54.0`",
		"`modernc.org/libc v1.74.1`",
		"private same-package persistence hydration",
		"revision/CAS semantics",
		"durable provider-effect intent before external I/O",
		"fail-closed corruption behavior",
		"private source implementation for the durable",
		"latest-operation replay repair contract",
		"current latest committed mutation descriptor",
		"Mutation-reference-only replay is rejected",
		"same mutation reference with different operation kind or input binding is a mutation conflict",
		"older operation arriving after a later committed mutation is stale or superseded",
		"no historical mutation-result log is selected",
		"Current source uses SQLite schema v3 for bounded synthetic codec-3 custody",
		"complete codec-2 descriptors",
		"codec-1 legacy/unbound rows",
		"without inventing old operation or original-intent semantics",
		"implements no config, production runtime wiring, public DTO, HTTP handler, producer declaration field, staging behavior, Nomad behavior, or runtime behavior",
	)

	implementationAbsence := compactDocSection(t, mustRead(t, ".docs/execution_lifecycle/implementation.md"), "**Current keyed-recovery absence**", "## 8. Lifecycle projection implementation")
	assertContainsAll(t, "implementation reliable-submit persistence ADR pointer", implementationAbsence,
		"reliable_submit_persistence_and_concurrency.md",
		"private durable-record, backend-neutral port, durable-service, shared conformance-test, and SQLite-store source",
		"selects local embedded SQLite as the first storage backend",
		"preserves the current `CGO_ENABLED=0` build posture",
		"selects `modernc.org/sqlite v1.54.0`",
		"`modernc.org/libc v1.74.1`",
		"selects private same-package persistence hydration inside `es/admission/internal/reliablesubmit`",
		"`reliable-submit-durable-same-operation-replay-repair` latest-operation-only",
		"persists a descriptor made of mutation reference",
		"closed private operation kind",
		"versioned safe input-binding digest",
		"same mutation reference with different kind or binding is mutation conflict",
		"older operation after later progression is stale or superseded",
		"versioned safe input-binding digest for codec-2 rows",
		"historical v1 migration source and metadata remain retained and verified",
		"valid v1 databases migrate through v2 to v3 in one grouped transaction",
		"Migrated codec-1 rows remain legacy/unbound",
		"migrated rows remain codec-1 legacy/unbound",
		"not reliable-submit config/store lifecycle wiring",
		"adds no config field, public producer/request/response source, staging behavior, Nomad behavior, runtime behavior, or public reliable-submit availability",
		"runtime behavior, or public reliable-submit availability",
		"Current `Submit` has no submit idempotency key input",
		"no durable submit-correlation record",
	)
	assertContainsNone(t, "implementation current schema truth rejects stale v1 wording", implementationAbsence,
		"current source still remains schema v1",
		"current source remains schema v1",
		"current SQLite store remains schema v1",
	)

	boundaries := compactDocSection(t, mustRead(t, ".docs/system_overview/boundaries.md"), "## 8. ES boundary", "## 9. EGS boundary")
	assertContainsAll(t, "system boundaries reliable-submit persistence ADR pointer", boundaries,
		"reliable_submit_persistence_and_concurrency.md",
		"narrow local SQLite submit-correlation store family",
		"current `CGO_ENABLED=0` build posture",
		"`modernc.org/sqlite v1.54.0`",
		"`modernc.org/libc v1.74.1`",
		"private same-package hydration",
		"revision/CAS",
		"durable provider-effect intent",
		"tombstone/no-reuse retention",
		"fail-closed corruption behavior",
		"historical latest-operation replay descriptor from SQLite schema v2",
		"Complete codec-2 rows persist `lastMutation`, closed private operation kind, and",
		"input-binding digest",
		"migrated codec-1 rows preserve only legacy",
		"without invented operation semantics",
		"adds private source only",
		"does not add global config or runtime wiring",
		"reuse staging or retained results as the database path",
		"import Coordinator writer-session authority",
		"make provider metadata a recovery source",
		"promise PostgreSQL implementation",
		"promise live backend switching",
		"promise automatic data migration",
	)

	buildScript := mustRead(t, "scripts/internal/remote_alpha_deploy_es_binaries.sh")
	assertContainsAll(t, "current Remote Alpha ES build contract", buildScript,
		"CGO_ENABLED=0",
		"GOOS=linux",
		"GOARCH=amd64",
		"go\", \"build\", \"-o\", os.fspath(es_path), \"./cmd/es\"",
		"go build -o \"${payload_dir}/es\" ./cmd/es",
	)
	configSource := mustRead(t, "es/config/config.go")
	executionConfig := docSection(t, configSource, "type ExecutionConfig struct {", "type VerificationConfig struct {")
	assertContainsAll(t, "current ExecutionConfig writable roots", executionConfig,
		"StagingRootDir",
		"ResultsRootDir",
		"BaseImage",
		"RuntimeSupportBinary",
	)
	assertContainsNone(t, "current ExecutionConfig has no reliable-submit store path", executionConfig,
		"ReliableSubmit",
		"SQLite",
		"Database",
		"StorePath",
	)

	serviceSource := mustRead(t, "es/admission/service.go")
	serviceStartup := docSection(t, serviceSource, "if cfg.SubmitConfigured() {", "validateExecutionRuntimeInputs(cfg.Execution)")
	assertContainsAll(t, "current startup provisions, qualifies, and probes the execution root pair", serviceStartup,
		"provisionExecutionRoots(cfg.Execution.StagingRootDir, cfg.Execution.ResultsRootDir, nil)",
		"owner, err := roots.owner()",
		"roots.probeCapabilities(owner)",
		"roots.reobserve()",
		"roots.close()",
	)
	assertContainsNone(t, "current startup omits stale single-root and reliable-submit behavior", serviceStartup,
		"probeStagingCustodyCapabilities",
		"openQualifiedDirectory",
		"ReliableSubmit",
		"SQLite",
		"database",
	)

	goMod := mustRead(t, "go.mod")
	goSum := mustRead(t, "go.sum")
	assertContainsAll(t, "go.mod has selected reliable-submit SQLite dependency", goMod,
		"modernc.org/sqlite v1.54.0",
		"modernc.org/libc v1.74.1",
	)
	assertContainsNone(t, "go.mod has no forbidden reliable-submit database dependency", goMod,
		"github.com/mattn/go-sqlite3",
		"go.etcd.io/bbolt",
		"bbolt",
		"pgx",
		"postgres",
	)
	assertContainsAll(t, "go.sum has selected reliable-submit SQLite dependency", goSum,
		"modernc.org/sqlite v1.54.0",
		"modernc.org/libc v1.74.1",
	)
	assertContainsNone(t, "go.sum has no forbidden reliable-submit database dependency", goSum,
		"github.com/mattn/go-sqlite3",
		"go.etcd.io/bbolt",
		"pgx",
		"postgres",
	)

	modelSource := mustRead(t, "es/admission/internal/reliablesubmit/model.go")
	assertContainsNone(t, "pure reliable-submit model remains I/O-free", modelSource,
		"database/sql",
		"modernc.org/sqlite",
		"github.com/mattn/go-sqlite3",
		"os.",
		"io.",
		"path/filepath",
		"sync.Mutex",
		"sync.RWMutex",
		"encoding/json",
		"MarshalJSON",
		"UnmarshalJSON",
		"`db:",
	)
	assertContainsNone(t, "pure reliable-submit model has no exported raw persistence accessors", modelSource,
		"func (c CallerRef) Bytes",
		"func (c CallerRef) Raw",
		"func (s SubmitKeyRef) Bytes",
		"func (s SubmitKeyRef) Raw",
		"func (p PlanBinding) Bytes",
		"func (p PlanBinding) Raw",
		"func (r RunRef) Bytes",
		"func (r RunRef) Raw",
		"func (r ReceiptRef) Bytes",
		"func (r ReceiptRef) Raw",
		"func (c ClaimID) Bytes",
		"func (c ClaimID) Raw",
	)

	durableServiceSource := mustRead(t, "es/admission/internal/reliablesubmit/durable_service.go")
	mutateFlow := docSection(t, durableServiceSource, "func (s *durableClaimService) mutate", "func (s *durableClaimService) classifyLoadedRecord")
	assertContainsInOrder(t, "current durable service operation replay precedes stale check", mutateFlow,
		"record, err := s.store.loadClaim",
		"_, classified, handled, err := s.validateLoadedRecordBinding(record, req.claim, req.binding)",
		"operation, err := deriveDurableOperationDescriptor",
		"classified, handled, err = s.classifyValidatedRecordForMutation(record, operation, req.successKind)",
		"if handled",
		"if record.revision != req.expectedRevision",
		"next, err := req.apply(record, now, operation)",
		"s.store.compareAndSwapClaim",
		"if result.found",
		"classifyLoadedRecordForMutation(result.record, req.claim, req.binding, operation, req.successKind)",
		"return outcomeForRecord(durableClaimOutcomeStale, result.record)",
	)
	assertContainsAll(t, "current durable service commit-unknown full equality", durableServiceSource,
		"func (s *durableClaimService) reloadAfterUnknown",
		"reloaded.lastMutation.equal(expected.lastMutation)",
		"reloaded.latestOperation.equal(expected.latestOperation)",
		"reloaded.revision == expected.revision",
		"reloaded.equal(expected)",
	)

	durableRecordSource := mustRead(t, "es/admission/internal/reliablesubmit/durable_record.go")
	durableRecordStruct := docSection(t, durableRecordSource, "type durableClaimRecord struct {", "type newDurableClaimRecordInput struct {")
	assertContainsAll(t, "current durable record stores latest-operation descriptor", durableRecordStruct,
		"revision",
		"retention",
		"lastMutation",
		"latestOperation durableLatestOperationDescriptor",
	)
	assertContainsNone(t, "current durable record has no mutation history or raw persistence accessor", durableRecordStruct,
		"operationKind",
		"inputBinding",
		"mutationHistory",
	)

	sqliteMigrationSource := mustRead(t, "es/admission/internal/reliablesubmit/sqlite_migrations.go")
	assertContainsAll(t, "current reliable-submit SQLite schema version", sqliteMigrationSource,
		"sqliteClaimStoreSchemaVersion = 5",
	)
	assertContainsAll(t, "current SQLite schema persists latest operation descriptor", sqliteMigrationSource,
		"revision INTEGER NOT NULL CHECK (revision > 0)",
		"last_mutation_ref BLOB NOT NULL CHECK (length(last_mutation_ref) > 0)",
		"latest_operation_kind INTEGER CHECK (latest_operation_kind IS NULL OR latest_operation_kind BETWEEN 1 AND 10)",
		"latest_operation_input_digest BLOB CHECK (latest_operation_input_digest IS NULL OR length(latest_operation_input_digest) = 32)",
		"codec_version INTEGER NOT NULL CHECK (codec_version IN (1, 2))",
		"codec_version = 1 AND latest_operation_kind IS NULL AND latest_operation_input_digest IS NULL",
		"codec_version = 2 AND latest_operation_kind IS NOT NULL AND latest_operation_input_digest IS NOT NULL",
		"new reliable submit rows require codec v2",
		"mutation reference must change with revision",
	)
	assertContainsAll(t, "v1 migration source remains present", sqliteMigrationSource,
		"codec_version INTEGER NOT NULL CHECK (codec_version = 1)",
	)
	assertContainsNone(t, "current SQLite schema has no mutation history", sqliteMigrationSource,
		"mutation_history",
	)

	storeSource := mustRead(t, "es/admission/internal/reliablesubmit/store.go")
	claimStoreInterface := docSection(t, storeSource, "type claimStore interface {", "type establishClaimCommand struct {")
	assertContainsAll(t, "current claimStore port remains establish load CAS", claimStoreInterface,
		"establishClaim(context.Context, establishClaimCommand)",
		"loadClaim(context.Context, loadClaimQuery)",
		"compareAndSwapClaim(context.Context, compareAndSwapClaimCommand)",
	)
	assertContainsNone(t, "current claimStore port has no backend-specific replay widening", claimStoreInterface,
		"SQLite",
		"Postgres",
		"SQLSTATE",
		"DSN",
		"mutationHistory",
	)

	reliableSubmitFiles, err := filepath.Glob("es/admission/internal/reliablesubmit/*.go")
	if err != nil {
		t.Fatalf("glob reliable-submit package files: %v", err)
	}
	if got, want := len(reliableSubmitFiles), 39; got != want {
		t.Fatalf("reliable-submit package inventory has %d files: %v", got, reliableSubmitFiles)
	}
	assertContainsAll(t, "reliable-submit package current file set", strings.Join(reliableSubmitFiles, " "),
		"es/admission/internal/reliablesubmit/model.go",
		"es/admission/internal/reliablesubmit/model_test.go",
		"es/admission/internal/reliablesubmit/guardrails_test.go",
		"es/admission/internal/reliablesubmit/clock.go",
		"es/admission/internal/reliablesubmit/durable_operation.go",
		"es/admission/internal/reliablesubmit/durable_operation_test.go",
		"es/admission/internal/reliablesubmit/durable_record.go",
		"es/admission/internal/reliablesubmit/store.go",
		"es/admission/internal/reliablesubmit/durable_service.go",
		"es/admission/internal/reliablesubmit/sqlite_migrations.go",
		"es/admission/internal/reliablesubmit/operational_handoff.go",
		"es/admission/internal/reliablesubmit/operational_handoff_test.go",
		"es/admission/internal/reliablesubmit/operational_admission.go",
		"es/admission/internal/reliablesubmit/operational_admission_test.go",
		"es/admission/internal/reliablesubmit/sqlite_operational_handoff_schema.go",
		"es/admission/internal/reliablesubmit/sqlite_store.go",
		"es/admission/internal/reliablesubmit/durable_record_test.go",
		"es/admission/internal/reliablesubmit/durable_service_test.go",
		"es/admission/internal/reliablesubmit/store_conformance_test.go",
		"es/admission/internal/reliablesubmit/sqlite_store_test.go",
		"es/admission/internal/reliablesubmit/sqlite_physical_test.go",
		"es/admission/internal/reliablesubmit/replay_custody_file.go",
		"es/admission/internal/reliablesubmit/replay_custody_file_test.go",
		"es/admission/internal/reliablesubmit/replay_custody_format.go",
		"es/admission/internal/reliablesubmit/replay_custody_format_test.go",
		"es/admission/internal/reliablesubmit/replay_custody_structure.go",
		"es/admission/internal/reliablesubmit/replay_key_use_sqlite.go",
		"es/admission/internal/reliablesubmit/replay_key_use_sqlite_test.go",
		"es/admission/internal/reliablesubmit/replay_progress_test.go",
		"es/admission/internal/reliablesubmit/sqlite_pooled_claim_read_cleanup_test.go",
		"es/admission/internal/reliablesubmit/sqlite_replay_claim.go",
		"es/admission/internal/reliablesubmit/sqlite_replay_claim_test.go",
		"es/admission/internal/reliablesubmit/sqlite_replay_migration_test.go",
		"es/admission/internal/reliablesubmit/sqlite_replay_progress_schema.go",
		"es/admission/internal/reliablesubmit/sqlite_replay_schema.go",
		"es/admission/internal/reliablesubmit/sqlite_replay_schema_test.go",
		"es/admission/internal/reliablesubmit/sqlite_replay_shape.go",
		"es/admission/internal/reliablesubmit/sqlite_replay_shape_test.go",
		"es/admission/internal/reliablesubmit/testtmpdir_main_test.go",
	)

	submitSource := mustRead(t, "es/admission/submit.go")
	serverSource := mustRead(t, "es/api/server.go")
	typesSource := mustRead(t, "es/admission/types.go")
	assertContainsNone(t, "current submit remains unwired from reliable-submit persistence", submitSource,
		"reliablesubmit",
		"ReliableSubmit",
		"SQLite",
	)
	assertContainsNone(t, "current server has no reliable-submit DTO handling", serverSource,
		"reliablesubmit",
		"ReliableSubmit",
		"reliable_submit",
	)
	prepareRequest := docSection(t, typesSource, "type PrepareRequest struct {", "type ArtifactInvocation struct {")
	assertContainsNone(t, "current PrepareRequest remains unkeyed", prepareRequest,
		"SubmitKey",
		"Idempotency",
		"ReliableSubmit",
	)
}

func TestHybridIntegrationArchitectureADRDocsContract(t *testing.T) {
	assertStaleTargetRelationshipExamples(t)

	adrRaw := mustRead(t, ".docs/system_overview/hybrid_integration_architecture_adr.md")
	adr := compactText(adrRaw)
	plansRaw := mustRead(t, "PLANS.md")
	plansPointer := compactDocSection(t, plansRaw, "## Cross-Repo Hybrid Integration ADR Pointer", "## Highest-Priority Backlog Entry")
	adrCurrentDecision := compactDocSection(t, adrRaw, "## Current Integration Decision And Target Reclassification", "## Preserved ES And NWP Boundaries")
	adrReopenedSeams := compactDocSection(t, adrRaw, "## Reopened Contract-Seam Inventory", "## Integration Point Map")
	adrComponentMap := compactDocSection(t, adrRaw, "## Component Map", "## Symphony Phase E Decision")
	adrDownstreamFollowupsRaw := docSection(t, adrRaw, "## Downstream Migration Follow-Ups", "")
	adrDownstreamFollowups := compactText(adrDownstreamFollowupsRaw)
	adrImmediateFollowups := compactMarkedDocSection(t,
		"hybrid integration ADR immediate active-contract follow-ups",
		adrDownstreamFollowupsRaw,
		"Immediate active-contract alignment follow-ups are",
		"Legacy/demo/helper record inventory:",
	)
	adrLegacyHelperInventory := compactMarkedDocSection(t,
		"hybrid integration ADR legacy/demo/helper inventory",
		adrDownstreamFollowupsRaw,
		"Legacy/demo/helper record inventory:",
		"",
	)
	nwpCoordinatorRow := compactTableRow(markdownTableRowByFirstCell(t, adrRaw, "NWP Coordinator"))

	assertContainsAll(t, "hybrid integration ADR", adr,
		"Status: accepted current-status and migration-boundary record; strategic target routing and component decomposition reopened; no integration behavior enabled.",
		"canonical cross-repository current-status and migration-boundary record",
		"not the complete target operating model",
		"does not enable real write, real Codex execution, remote maintenance, ES submit, CP diagnose, IM refresh, live proof, connector-triggered execution, worker dispatch, scheduler behavior, queue consumption, Coordinator provisioning, receipt provisioning, or publication",
		"Strategic target statements in this ADR are not implementation claims",
		"Current invariant",
		"Bounded slice rule",
		"Temporary compatibility edge",
		"Reopened redesign seam",
		"ES Workstream A and Workstream B remain gates that keep ES input contracts honest",
		"ES Workstream C admission/runtime boundaries remain the delivered ES milestone and a Current invariant",
		"`control-plane-normal-shell/v1` remains a bounded compatibility edge",
		"ES still owns no parallel scheduler or lifecycle store",
		"admission/runtime authority; lifecycle projection; runtime identity handoff; retained opaque results",
		"Current maintained MVP/demo workflow, progression, review, checkpoint, cancellation decision, intervention, and finalization authority",
		"not target autonomous-development architecture owner",
		"Bounded durable coding-work state; transition/global-stop apply; writer fencing; idempotency; CAS; event receipt; commit uncertainty; replay",
		"Guarded adapters and evidence/projection only",
		"Readiness, profile, provenance, and diagnostics",
		"Maintenance routes under maintenance-specific authority only",
		"Current policy and decision boundary for lease issuance where existing contracts require it",
		"Target issuer and delegation topology are reopened",
		"Bridge connector-safe source intake and no-mutation handoff are implemented and live-tested as Bridge-local evidence/projection",
		"They do not invoke Codex or mutate repos",
		"Local real Codex execution and local acceptance remain separate CLI-only and non-MCP-visible paths",
		"no Coordinator mutation",
		"NWP/autonomy does not redefine ES Workstream C or runtime authority",
		"CP compatibility remains bounded",
		"There is no TLS/noninteractive route widening in this ADR",
		"no ES admission/runtime, Workstream C, route, TLS, or noninteractive authority drift",
		"Economic or financial goals do not alter ES admission/security contracts",
		"No current unattended execution is claimed",
		"current Coordinator status is no longer an A2-P1 skeleton-only state and is not a state-store-port-only design",
		"internal durable SQLite writer issuance",
		"private atomic transition persistence",
		"guarded public transition delegation",
		"private atomic global-stop persistence",
		"guarded public global-stop delegation",
		"verification of already-persisted decision receipts",
		"fencing, idempotency, replay, CAS, rollback, one COMMIT attempt, commit uncertainty, and retry",
		"work-item production provisioning",
		"coding-work lease issuer",
		"executable authorization issuer",
		"decision-receipt provisioner",
		"worker",
		"scheduler",
		"queue consumer",
		"Codex invocation",
		"ES runtime",
		"CP workflow",
		"publication",
		"general orchestration",
		"CP-authoritative path is the current maintained MVP/demo compatibility path",
		"CP is absent from the target autonomous-development architecture",
		"No connector -> Bridge -> Coordinator -> ES product route is implemented or established by this ADR",
		"Future CP-less or Coordinator-centered routing remains a reopened target seam",
		"not be represented as a current CP replacement, ES admission authority, Bridge execution authority, or current Coordinator general orchestration",
		"ES Admission And Runtime Boundary Realignment remains parallel ES planning authority",
		"user is not expected to remain a routine per-task approval service",
		"does not make connector availability, a first-class Development Program, full append-only event sourcing, finite backlog, external-only authority issuance, or current IM/Maintenance Agent repository survival a prerequisite",
		"Reopened Contract-Seam Inventory",
		"current capability-gap inventory",
		"not a fixed global implementation sequence",
		"Authority Issuance",
		"lease and executable authorization issuance where current contracts require them",
		"executable authorization",
		"operator-decision receipt provisioning",
		"Coordinator Ingress",
		"work-source, backlog, and intent-to-work admission models",
		"work-item provisioning",
		"transition/global-stop command producers",
		"Worker / Runtime Handoff",
		"dispatch command/receipt",
		"guarded Codex invocation",
		"ES request construction and runtime handback",
		"Correlation And Recovery",
		"separate CP, Coordinator, Bridge, Connector, and ES identifiers",
		"duplicate and lost responses",
		"cancellation/global-stop propagation",
		"restart reconciliation",
		"review and finalization recovery",
		"Bridge <-> Codex",
		"no-mutation source intake and evidence recorder implemented/live-tested",
		"no repository write",
		"no shell execution",
		"no Codex invocation through connector",
		"no local acceptance",
		"Maintenance Agent current evidence and maintenance-route boundaries remain current facts",
		"target component survival and mandatory role are reopened",
		"must not become a hidden reconciler",
		"ES Workstream C guardrails",
		"Operator-healthcheck TLS signer/custody",
		"Harness Vs Product Classification",
		"Over-Constraint Policy",
		"what would allow this to change?",
		"Decision: SYMPHONY DEFERRED",
		"source/reference material only",
		"no experiment is currently authorized",
		"official specification is tracker-generic and language-neutral",
		"stock/reference implementation still owns scheduler/session/workspace behavior and has no Governed Execution ES admission backend",
		"Do not claim that the specification is Linear-only or inherently impossible to adapt",
		"Do not recommend installing, integrating, cloning, or running Symphony under this decision",
		"Coordinator current status: `Governed Execution Coordinator/.docs/architecture.md`; `Governed Execution Coordinator/.docs/authority-boundaries.md`",
		"Current CP MVP/demo workflow authority: `Control Plane/.docs/long-running-operator-mode-contract.md`",
		"Bridge/Symphony detailed decision: `Governed Execution OpenAI Bridge/docs/symphony-placement.md`",
		"ES admission/runtime: `Execution Substrate/PLANS.md`; `Execution Substrate/.docs/system_overview/boundaries.md`; `Execution Substrate/.docs/execution_lifecycle/contracts.md`",
		"Downstream Migration Follow-Ups",
		"does not claim cross-repository alignment is complete",
		"Governed Execution OpenAI Bridge/docs/hybrid-integration-architecture-adr.md",
		"Governed Execution OpenAI Bridge/tests/test_nwp_docs_boundaries.py",
		"Governed Execution Coordinator/.docs/architecture.md",
		"Governed Execution Coordinator/tests/test_finite_backlog.py",
		"must not be read as claiming their local contracts are already revised",
		"CP/IM/MA local hybrid ADRs or equivalent records remain legacy/demo/helper record inventory only",
		"not aligned target-architecture authorities and not prerequisites for defining the target",
		"no secret/raw material in ADR",
	)
	assertContainsAll(t, "hybrid integration ADR downstream follow-up scope", adrDownstreamFollowups,
		"immediate active-contract alignment follow-ups",
		"legacy/demo/helper record inventory",
		"Bridge and Coordinator remain the immediate downstream follow-ups",
		"active-contract reset",
		"Control Plane/.docs/hybrid-integration-architecture-adr.md",
		"current MVP/demo, compatibility, filming, freeze, reference, or retirement context only",
		"not part of the target autonomous-development architecture",
		"not an alignment prerequisite for defining that target",
		"Infrastructure Manager/.docs/hybrid-integration-architecture-adr.md",
		"Governed Execution Maintenance Agent/.docs/hybrid-integration-architecture-adr.md",
		"bounded helper/proof/topology-specific records",
		"retained, absorbed, re-derived, or retired",
		"current repository survival is not frozen",
		"not target-architecture authorities",
		"not claimed already aligned",
		"not a prerequisite for Coordinator or ES target work",
	)
	assertContainsAll(t, "hybrid integration ADR immediate active-contract follow-ups", adrImmediateFollowups,
		"Immediate active-contract alignment follow-ups",
		"active cross-repository architecture, authority, backlog, lease, ingress, or lifecycle statements",
		"Bridge and Coordinator remain the immediate downstream follow-ups",
		"active-contract reset",
		"Bridge follow-ups",
		"Governed Execution OpenAI Bridge/docs/hybrid-integration-architecture-adr.md",
		"Governed Execution OpenAI Bridge/tests/test_nwp_docs_boundaries.py",
		"Coordinator follow-ups",
		"Governed Execution Coordinator/.docs/architecture.md",
		"Governed Execution Coordinator/tests/test_finite_backlog.py",
		"must not be read as claiming their local contracts are already revised",
	)
	assertContainsNone(t, "hybrid integration ADR immediate active-contract follow-ups", adrImmediateFollowups,
		"Control Plane",
		"Control Plane/.docs/hybrid-integration-architecture-adr.md",
		"Infrastructure Manager",
		"Infrastructure Manager/.docs/hybrid-integration-architecture-adr.md",
		"Governed Execution Maintenance Agent",
		"Governed Execution Maintenance Agent/.docs/hybrid-integration-architecture-adr.md",
		"Maintenance Agent",
	)
	assertContainsAll(t, "hybrid integration ADR legacy/demo/helper inventory", adrLegacyHelperInventory,
		"Legacy/demo/helper record inventory",
		"Control Plane/.docs/hybrid-integration-architecture-adr.md",
		"current MVP/demo, compatibility, filming, freeze, reference, or retirement context only",
		"not part of the target autonomous-development architecture",
		"not an alignment prerequisite for defining that target",
		"Infrastructure Manager/.docs/hybrid-integration-architecture-adr.md",
		"Governed Execution Maintenance Agent/.docs/hybrid-integration-architecture-adr.md",
		"bounded helper/proof/topology-specific records",
		"retained, absorbed, re-derived, or retired",
		"current repository survival is not frozen",
		"not target-architecture authorities",
		"not claimed already aligned",
		"eventual cleanup, freeze, retirement, absorption, or re-derivation remains repository-scoped follow-up",
		"not a prerequisite for Coordinator or ES target work",
	)

	assertContainsAll(t, "PLANS hybrid integration pointer", plansPointer,
		"Cross-Repo Hybrid Integration ADR Pointer",
		"accepted Hybrid Integration Architecture ADR",
		"canonical cross-repository current-status and migration-boundary decision",
		"enables no integration behavior",
		"Phase D is complete",
		"Coordinator is parallel to CP as a bounded coding-work domain authority",
		"not a CP subordinate internally and not a product workflow by itself",
		"The connector -> Bridge -> Coordinator -> ES route without CP is not an established compatibility path, product workflow, or authorized integration implementation",
		"not an established compatibility path, product workflow, or authorized integration implementation",
		"does not freeze no-CP routing as proof-only target architecture",
		"current maintained MVP/demo compatibility path only",
		"CP is absent from the target autonomous-development architecture",
		"Strategic target direction is recorded here only as target direction",
		"model reasoning may become the cognitive engineering lead",
		"user is not expected to remain a routine per-task approval service",
		"Coordinator is intended to become a durable autonomy core while ES remains admission/runtime authority",
		"That target direction does not describe current implementation behavior",
		"does not make connector availability, a first-class Development Program, full append-only event sourcing, finite backlog, external-only authority issuance",
		"Phase E is complete with Symphony deferred",
		"Symphony is source/reference material only",
		"no Symphony experiment, installation, or integration is authorized",
		"Earlier planning identified four unresolved contract-seam themes",
		"Authority Issuance",
		"Coordinator Ingress",
		"Worker / Runtime Handoff",
		"Correlation And Recovery",
		"current capability-gap inventory only",
		"not a fixed package decomposition, global blocker, or mandatory next implementation sequence",
		"bounded durable SQLite mutation authority for coding-work state",
		"private atomic transition and global-stop persistence",
		"verification of already-persisted decision receipts",
		"does not own work-item production provisioning, lease issuance, executable authorization issuance, decision-receipt provisioning, a worker, scheduler, queue consumer",
		"Architecture/status alignment is the immediate documentation program",
		"next implementation selection is reopened contract-seam design, not end-to-end execution or a fixed global sequence",
		"ES Admission And Runtime Boundary Realignment remains the ES planning authority and is not displaced by Coordinator integration work",
		"required for any ES-owned admission/runtime change",
		"Bridge connector-safe source intake and no-mutation Codex handoff are implemented/live-tested as Bridge-local evidence/projection only",
		"They do not invoke Codex, run shell, mutate repositories, or alter ES admission, runtime, lifecycle, status, route, TLS, or noninteractive-route authority",
		"does not change ES priorities or ES route eligibility",
		"Contract design may proceed only within reopened seam boundaries above and must not authorize autonomous execution",
		"Current invariant: ES remains admission/runtime authority; CP remains workflow, progression, review, checkpoint, cancellation decision, intervention, and finalization authority inside the current maintained MVP/demo compatibility path",
		"Bounded slice rule: Bridge and Maintenance Agent may record or consume non-authoritative proposals",
		"Compatibility edge: `control-plane-normal-shell/v1` remains a bounded compatibility edge and is not changed by Coordinator integration planning",
		"Temporary compatibility edge: Remote Alpha helper/status/renewal routes remain proof/support containment",
		"Reopened redesign seam: operator-healthcheck TLS signer/custody remains blocked and source-insufficient",
		"Reopened target seam: work-source shape, backlog model, authority issuance/delegation, Coordinator ingress, worker/runtime handoff, correlation/recovery, package boundaries, and current component survival are reopened",
		"no-write, no-shell, no-Codex-invocation",
	)
	assertContainsAll(t, "ADR NWP Coordinator row", nwpCoordinatorRow,
		"Current bounded SQLite mutation authority exists",
		"Bounded durable coding-work state authority",
		"Apply transition and global-stop commands through writer-fenced SQLite mutation with idempotency, replay, CAS, receipts, uncertainty, and retry",
		"Target direction intends Coordinator to become durable autonomy core",
		"Not ES admission, runtime, lifecycle, status, route, TLS, noninteractive, Workstream C, CP workflow, worker, scheduler, queue, Codex invocation, provisioning, receipt provisioning, executable authorization, publication, or general orchestration authority",
		"Authority issuance/delegation seam; Coordinator ingress/work-source seam; worker/runtime handoff seam; correlation/recovery seam",
	)
	assertContainsNone(t, "hybrid integration ADR stale Coordinator status", adr,
		"Status: proposed / draft",
		"Symphony is optional candidate only",
		"A2-P1 skeleton exists locally",
		"P1 has a state-store port only",
		"no production storage backend",
		"no production store",
		"future durable local development-work state owner only",
		"CP product path is permanently settled by this ADR",
		"four packages are the required global implementation sequence",
		"Maintenance Agent is a mandatory target component",
	)
	assertContainsNone(t, "PLANS stale target relationships", plansPointer+" "+compactText(mustRead(t, standingAdmissionRulesPath)),
		"without CP is only a bounded coding-work proof candidate",
		"no-CP routing is only a proof candidate",
		"CP-less routing is proof-only",
		"Integration implementation is blocked by four missing contract packages",
		"contract design for the four missing packages",
		"four packages are the only authorized next sequence",
		"four packages are a fixed global sequence",
		"finite backlog admission",
		"finite immutable backlog",
		"finite backlog is the fixed target ingress",
		"Coordinator is permanently non-orchestration",
		"Coordinator non-orchestration is a permanent target constraint",
		"Coordinator must remain non-orchestration in the target",
		"IM is a mandatory target component",
		"IM is a permanent target component",
		"Maintenance Agent is a mandatory target component",
		"Maintenance Agent is a permanent target component",
		"current IM/Maintenance Agent repository survival is required",
	)
	assertNoStaleTargetRelationship(t, "PLANS stale target relationships", plansPointer+" "+compactText(mustRead(t, standingAdmissionRulesPath)))
	assertContainsNone(t, "ADR current decision stale target relationships", adrCurrentDecision,
		"CP-authoritative path is the enduring",
		"CP-authoritative path is the permanent",
		"target architecture is CP",
		"permanent CP target",
		"without CP is only a bounded coding-work proof candidate",
		"no-CP routing is only a proof candidate",
		"CP-less routing is proof-only",
		"current Coordinator general orchestration is permanently forbidden as target",
	)
	assertNoStaleTargetRelationship(t, "ADR current decision stale target relationships", adrCurrentDecision)
	assertContainsNone(t, "ADR reopened seam stale fixed sequence", adrReopenedSeams,
		"Missing Contract Packages",
		"Implementation is blocked by four missing contract packages",
		"four packages are the required global implementation sequence",
		"four packages are the only authorized next sequence",
		"four packages are a fixed global sequence",
		"finite backlog admission",
		"finite immutable backlog",
		"finite backlog is the fixed target ingress model",
		"finite backlog remains the target ingress model",
	)
	assertContainsNone(t, "ADR component map stale mandatory topology", adrComponentMap,
		"Enduring product workflow authority for Shape A",
		"Coordinator is permanently non-orchestration",
		"Coordinator non-orchestration is a permanent target constraint",
		"Coordinator must remain non-orchestration in the target",
		"IM is a mandatory target component",
		"IM is a permanent target component",
		"Maintenance Agent is a mandatory target component",
		"Maintenance Agent is a permanent target component",
		"current IM/Maintenance Agent repository survival is required",
		"current component survival is settled",
	)

	assertContainsNone(t, "hybrid integration ADR raw material", mustRead(t, ".docs/system_overview/hybrid_integration_architecture_adr.md"),
		"-----BEGIN",
		"BEGIN PRIVATE KEY",
		"BEGIN CERTIFICATE",
		"https://",
		"http://",
		"spiffe://",
		"/Users/",
		"/var/",
		"/tmp/",
		"Authorization:",
	)
}

func TestHybridIntegrationBridgeCodexRowPinsEvidenceBoundary(t *testing.T) {
	adrRaw := mustRead(t, ".docs/system_overview/hybrid_integration_architecture_adr.md")
	row := compactTableRow(markdownTableRowByFirstCell(t, adrRaw, "Bridge <-> Codex"))
	plans := compactDocSection(t, mustRead(t, "PLANS.md"), "## Cross-Repo Hybrid Integration ADR Pointer", "## Highest-Priority Backlog Entry")

	assertContainsAll(t, "Bridge <-> Codex integration row", row,
		"no-mutation source intake and evidence recorder implemented/live-tested",
		"source ledger evidence/projection",
		"no-mutation handoff packet recording",
		"implemented/live-tested",
		"exact retry reuse",
		"same-source conflict handling",
		"not Codex invocation",
		"repository mutation",
		"ES admission/runtime/lifecycle authority",
		"local runner/acceptance",
		"connector-triggered execution",
		"durable coordination",
		"A2 durable work-item state",
	)
	assertContainsNone(t, "Bridge <-> Codex integration row", row,
		"designed only",
		"first candidate only",
		"connector-triggered Codex implemented",
		"Bridge owns durable coordination",
	)

	assertContainsAll(t, "PLANS and ADR Bridge evidence agreement", plans,
		"Bridge connector-safe source intake and no-mutation Codex handoff are implemented/live-tested as Bridge-local evidence/projection only",
		"They do not invoke Codex, run shell, mutate repositories, or alter ES admission, runtime, lifecycle, status, route, TLS, or noninteractive-route authority",
		"next implementation selection is reopened contract-seam design, not end-to-end execution or a fixed global sequence",
		"already implemented Bridge source/handoff evidence slice must remain no-write, no-shell, no-Codex-invocation, non-authoritative for ES",
	)
	assertContainsNone(t, "PLANS and ADR Bridge evidence agreement", plans+" "+compactText(mustRead(t, standingAdmissionRulesPath)),
		"evaluate a future Bridge no-mutation Codex handoff packet/design",
		"The first implementation candidate after this ADR is Bridge no-mutation Codex handoff packet/design",
	)
}

func TestSupportedLocalCPConsumerRunbookPreservesControlPlaneBoundaries(t *testing.T) {
	readme := compactText(mustRead(t, "README.md"))
	runbook := compactText(mustRead(t, ".docs/supported_local_cp_consumer_runbook.md"))

	for _, required := range []string{
		"Control Plane long-running operator mode contract",
		"ES provider run ids",
		"not Control Plane orchestration truth",
		"ES retained results remain opaque output material",
		"semantic validation and any review, checkpoint, hold/resume/reject, or terminal run decision",
		"GET /v1/executions:contract",
		"governed-execution-producer/v1",
		"POST /v1/executions:prepare",
		"POST /v1/executions:submit",
		"GET /v1/executions/{run_id}/status",
		"GET /v1/executions/{run_id}/logs",
		"GET /v1/executions/{run_id}/result",
		"POST /v1/executions/{run_id}:cancel",
		"submit-ready: true",
		"not a registry guarantee",
		"The selected profile changes the runtime image and injects non-secret runtime metadata. It does not add ES-owned CP lifecycle, review, checkpoint, or finalization semantics.",
	} {
		if !strings.Contains(runbook, required) {
			t.Fatalf("supported-local CP consumer runbook missing %q", required)
		}
	}

	for _, required := range []string{
		"proves only admission-oriented service health",
		"ES must not widen this supported-local surface into CP orchestration",
	} {
		if !strings.Contains(readme, required) {
			t.Fatalf("README missing %q", required)
		}
	}
}

func TestPrimaryMilestoneRealignmentPreservesESOwnership(t *testing.T) {
	plans := compactText(mustRead(t, "PLANS.md"))
	architecture := compactText(mustRead(t, ".docs/system_overview/architecture.md"))
	boundaries := compactText(mustRead(t, ".docs/system_overview/boundaries.md"))
	contracts := compactText(mustRead(t, ".docs/system_overview/contracts.md"))
	lifecycle := compactText(mustRead(t, ".docs/execution_lifecycle/contracts.md"))
	runbook := compactText(mustRead(t, ".docs/supported_local_cp_consumer_runbook.md"))

	for _, required := range []string{
		"Execution Substrate is the primary program in this repository.",
		"ES Admission And Runtime Boundary Realignment",
		"Control Plane is an important first non-operator consumer",
		"Control Plane documents may describe how CP consumes accepted ES surfaces; they must not widen ES admission, lifecycle, runtime-profile, runtime-identity, result-retention, or readiness ownership.",
		"Workstream A and Workstream B are gates that keep ES input contracts honest; Workstream C is the delivered ES milestone.",
		"keeping the current `execution_substrate.runtime_profile` annotation and `control-plane-normal-shell/v1` profile as accepted bounded compatibility",
		"ES may expose a bounded lifecycle projection revision on status responses as an opaque same-run read-coordination fact derived from Nomad observation.",
	} {
		if !strings.Contains(plans, required) {
			t.Fatalf("PLANS missing %q", required)
		}
	}
	assertContainsAll(t, "PLANS lifecycle projection invariant", plans,
		"Callers may compare equality/change for the same run only.",
		"They must not parse or order it, infer scheduler or backend state from it",
		"or treat it as a Nomad identifier or index.",
	)
	assertOmitsLifecycleProjectionSchedulerDerivation(t, "PLANS and standing rules lifecycle projection authority", plansAndStandingRules(t))

	for _, required := range []string{
		"Execution Substrate is the primary governed execution system in this repository.",
		"Control Plane is a first non-operator consumer, not an owner of ES core contracts.",
	} {
		if !strings.Contains(architecture, required) {
			t.Fatalf("architecture doc missing %q", required)
		}
	}

	for _, required := range []string{
		"Control Plane is a consumer of accepted AGS and ES surfaces, not an owner of ES core contracts.",
		"Current CP compatibility for publish -> prepare -> submit -> status/logs/result/cancel is a retained consumer edge.",
	} {
		if !strings.Contains(boundaries, required) {
			t.Fatalf("boundaries doc missing %q", required)
		}
	}

	for _, required := range []string{
		"Stable semantic contracts for the ES Admission And Runtime Boundary Realignment package",
		"Compatibility edges to preserve during the next package unless a coordinated migration/versioning note says otherwise",
		"Implementation details and current slice constraints must not be promoted into stable cross-service semantics",
		"GET /v1/executions:contract",
		"lifecycle_projection",
	} {
		if !strings.Contains(contracts, required) {
			t.Fatalf("contracts doc missing %q", required)
		}
	}

	if !strings.Contains(lifecycle, "CP documents, probes, examples, and proof harnesses do not define ES lifecycle contracts.") {
		t.Fatalf("lifecycle contracts doc missing ES ownership authority note")
	}
	lifecycleStatusSection := compactDocSection(t, mustRead(t, ".docs/execution_lifecycle/contracts.md"), "## 7. Status contract", "### Authority handoff read surface")
	for _, required := range []string{
		"`lifecycle_projection.source` is `nomad`",
		"same-run read-coordination token",
		"opaque",
		"compare `lifecycle_projection.revision` values for the same `run_id`",
		"Callers must not parse or order `lifecycle_projection.revision`",
	} {
		if !strings.Contains(lifecycleStatusSection, required) {
			t.Fatalf("lifecycle contracts doc missing %q", required)
		}
	}
	assertOmitsLifecycleProjectionSchedulerDerivation(t, "lifecycle projection status contract section", lifecycleStatusSection)

	for _, doc := range []struct {
		label string
		text  string
	}{
		{label: "system contracts lifecycle projection authority", text: contracts},
		{label: "system boundaries lifecycle projection authority", text: boundaries},
		{label: "mvp lifecycle projection authority", text: compactText(mustRead(t, ".docs/mvp.md"))},
		{label: "execution admission decision lifecycle projection authority", text: compactText(mustRead(t, ".docs/execution_lifecycle/es_execution_admission_model.md"))},
		{label: "execution lifecycle design projection phase", text: compactDocSection(t, mustRead(t, ".docs/execution_lifecycle/design.md"), "### 5.3 Lifecycle projection phase", "### 5.4 Terminal result materialization phase")},
		{label: "execution lifecycle design invariants", text: compactDocSection(t, mustRead(t, ".docs/execution_lifecycle/design.md"), "## 6. Current lifecycle invariants", "## 7. Bounded slice rules")},
		{label: "execution lifecycle implementation authority", text: compactText(mustRead(t, ".docs/execution_lifecycle/implementation.md"))},
	} {
		assertOmitsLifecycleProjectionSchedulerDerivation(t, doc.label, doc.text)
	}

	if !strings.Contains(runbook, "This runbook documents how CP consumes an accepted ES-owned surface; it is not the source of truth for ES core contracts.") {
		t.Fatalf("CP consumer runbook missing ES ownership authority note")
	}
	if !strings.Contains(runbook, "Status responses include `lifecycle_projection.source` and") {
		t.Fatalf("CP consumer runbook missing lifecycle projection consumption note")
	}
	if !strings.Contains(runbook, "`GET /v1/executions:contract` is the current producer-side compatibility") {
		t.Fatalf("CP consumer runbook missing producer contract gate note")
	}
}

func TestWorkstreamASharedKernelDecisionIsDocumented(t *testing.T) {
	record := workstreamRecord(t, "A")
	sharedKernel := compactText(mustRead(t, ".docs/system_overview/shared_kernel.md"))
	contracts := compactText(mustRead(t, ".docs/system_overview/contracts.md"))
	boundaries := compactText(mustRead(t, ".docs/system_overview/boundaries.md"))
	lifecycle := compactText(mustRead(t, ".docs/execution_lifecycle/contracts.md"))
	artifactPublication := compactText(mustRead(t, ".docs/system_overview/artifact_publication_storage.md"))
	artifactHygiene := compactText(mustRead(t, ".docs/system_overview/artifact_hygiene.md"))

	for _, required := range []string{
		"Workstream A shared-contract and shared-kernel decision",
		"`internal/contracts/evidence/v1` is the only active shared artifact evidence kernel",
		"`internal/contracts/evidence/v1` is not a standalone service boundary",
		"`internal/contracts/evidence/v1` is not a cross-service semantic dumping ground.",
		"A field does not become shared-kernel-owned merely because it lives in or near a shared package.",
		"`claims.package.identity`",
		"`claims.package.publication`",
		"`claims.admission.authorization.derivation`",
		"`derivation_spec_digest` and `output_id`",
		"`claims.admission.execution`",
		"Do not absorb CP orchestration, review, checkpoint, finalization, task-attempt, proof-harness, or retained-result semantics into shared execution/runtime claims.",
		"Payload identity and artifact identity remain separate.",
		"`execution_substrate.runtime_profile`",
		"`control-plane-normal-shell/v1`",
		"Reason",
		"Scope",
		"Removal condition",
		"AGS publication claims, ARS discoverability/index shapes, ES public execution/lifecycle grammar, and the long-term workload-zone Vault runtime-config owner remain service-owned or reopened elsewhere",
		"generated evidence, support bundles, retained bundles, reports, traces, logs, summaries, proof artifacts",
		"This A0 decision preserves the current `control-plane-normal-shell/v1` compatibility edge.",
		"It does not change the runtime path, runtime-profile selection mechanism, or `static-script` overlay behavior.",
	} {
		if !strings.Contains(sharedKernel, required) {
			t.Fatalf("shared-kernel decision doc missing %q", required)
		}
	}

	for _, required := range []string{
		"The Workstream A shared-kernel decision is recorded in `.docs/system_overview/shared_kernel.md`.",
		"`internal/contracts/evidence/v1` remains the only active shared artifact evidence kernel for the current `AGS -> ARS -> ES` path, but it is not a standalone service boundary.",
		"Kernel-level shared meaning stays limited to package identity, narrow derivation request-binding authorization, narrow execution/runtime claims ES actually enforces, and evidence canonicalization plus `seal` verification.",
		"`internal/contracts/evidence/v1` is not a cross-service semantic dumping ground.",
		"generated evidence, `.out` workspaces, support bundles, retained bundles, reports, traces, logs, summaries, and proof artifacts do not become shared-kernel authority",
		"Workstream A0 preserves the current `execution_substrate.runtime_profile` annotation and bounded `control-plane-normal-shell/v1` compatibility edge.",
	} {
		if !strings.Contains(record, required) {
			t.Fatalf("Workstream A record missing Workstream A shared-kernel decision phrase %q", required)
		}
	}

	for _, required := range []string{
		"`shared_kernel.md`",
		"`claims.package.publication` remains AGS-owned publish-time meaning carried inside the signed record",
		"`claims.admission.authorization` is intentionally limited to `derivation_spec_digest` and `output_id`",
		"`claims.admission.execution` is intentionally limited to runtime env allowlist, declared mount targets, required capabilities, `target_platform`, and `network_access`",
		"`artifact_digest` and `payload_digest` remain separate facts.",
		"The repo now has one active shared artifact evidence kernel:",
		"The shared kernel is not a standalone service boundary and not a cross-service semantic dumping ground.",
		"not owners of broader system policy, publication semantics, discovery semantics, ES lifecycle grammar, CP orchestration semantics, or generated evidence/projection outputs.",
		"Generated evidence, `.out` workspaces, support bundles, retained bundles, reports, traces, logs, summaries, and proof artifacts are not shared-kernel authority.",
	} {
		if !strings.Contains(contracts, required) {
			t.Fatalf("system contracts doc missing shared-kernel phrase %q", required)
		}
	}

	for _, required := range []string{
		"`shared_kernel.md`",
		"`claims.package.identity`, narrow derivation request-binding authorization, the narrow execution/runtime claims ES actually enforces, and `seal` verification are the kernel-level shared surface.",
		"`claims.package.publication` remains AGS-owned publication meaning carried inside the signed record.",
		"ARS runtime-facing discovery, descriptor, and index shapes are ARS-owned discoverability contracts.",
		"The shared evidence package is not a cross-service semantic dumping ground.",
		"Package placement does not make AGS publication claims, ARS discoverability/index/support shapes, ES lifecycle/runtime-profile grammar, CP attempt semantics, or generated evidence/projection outputs shared-kernel owned.",
		"Generated evidence, `.out` workspaces, support bundles, retained bundles, reports, traces, logs, summaries, and proof artifacts remain evidence/projection/diagnostics only.",
	} {
		if !strings.Contains(boundaries, required) {
			t.Fatalf("system boundaries doc missing shared-kernel phrase %q", required)
		}
	}

	for _, required := range []string{
		"`invocation.derivation_spec_digest` and `invocation.output_id` are the only currently shared derivation authorization inputs ES compares against aggregate artifact evidence during `:prepare`.",
		"`:prepare` uses only the narrow shared execution/runtime claims ES currently enforces from aggregate artifact evidence: runtime env allowlist, declared mount targets, required capabilities, `target_platform`, and `network_access`.",
		"`:prepare` does not treat Control Plane orchestration, review, checkpoint, finalization, task-attempt, or proof-harness metadata as shared admission facts.",
	} {
		if !strings.Contains(lifecycle, required) {
			t.Fatalf("execution lifecycle contracts doc missing shared-kernel phrase %q", required)
		}
	}

	for _, required := range []string{
		"Workstream B consumes the Workstream A shared-kernel decision without widening it.",
		"`internal/contracts/evidence/v1` remains the narrow evidence-owned kernel, not a dumping ground for AGS publication, ARS discoverability, ES lifecycle, or CP orchestration meaning.",
		"generated evidence, retained result bundles, reports, traces, logs, summaries, support bundles, proof artifacts",
		"outside AGS/ARS/ES core semantics and outside shared kernel authority",
	} {
		if !strings.Contains(artifactPublication, required) {
			t.Fatalf("artifact publication/storage doc missing A0 boundary phrase %q", required)
		}
	}

	for _, required := range []string{
		"Generated or proof artifacts are evidence/projection/diagnostics only.",
		"not hidden runtime authority, scheduler authority, admission authority, policy truth, credential truth, shared-kernel authority",
		"This applies to `.out/`, proof workspaces, generated evidence, reports, traces, logs, summaries, support bundles, retained bundles, proof artifacts",
	} {
		if !strings.Contains(artifactHygiene, required) {
			t.Fatalf("artifact hygiene doc missing shared-kernel non-authority phrase %q", required)
		}
	}

	for _, forbidden := range []struct {
		label string
		text  string
		want  string
	}{
		{label: "shared kernel", text: sharedKernel, want: "`claims.package.publication` | `kernel-level shared contract`"},
		{label: "shared kernel", text: sharedKernel, want: "ARS blob, registration, discovery, descriptor, manifest routes, and index helpers | `kernel-level shared contract`"},
		{label: "shared kernel", text: sharedKernel, want: "ES public execution request, lifecycle, result, and `authority_handoff` surfaces | `kernel-level shared contract`"},
		{label: "shared kernel", text: sharedKernel, want: "Control Plane orchestration, review, checkpoint, finalization | `kernel-level shared contract`"},
		{label: "artifact hygiene", text: artifactHygiene, want: "Generated or proof artifacts are shared-kernel authority"},
	} {
		if strings.Contains(forbidden.text, forbidden.want) {
			t.Fatalf("%s must not promote forbidden shared-kernel ownership phrase %q", forbidden.label, forbidden.want)
		}
	}
}

func TestWorkstreamBArtifactPublicationStorageDecisionIsDocumented(t *testing.T) {
	record := workstreamRecord(t, "B")
	decisionRaw := mustRead(t, ".docs/system_overview/artifact_publication_storage.md")
	decision := compactText(decisionRaw)
	contractsRaw := mustRead(t, ".docs/system_overview/contracts.md")
	contracts := compactText(contractsRaw)
	boundariesRaw := mustRead(t, ".docs/system_overview/boundaries.md")
	boundaries := compactText(boundariesRaw)
	lifecycleRaw := mustRead(t, ".docs/execution_lifecycle/contracts.md")
	lifecycle := compactText(lifecycleRaw)
	designRaw := mustRead(t, ".docs/execution_lifecycle/design.md")
	design := compactText(designRaw)
	decisionCompatibility := compactDocSection(t, decisionRaw, "### 4C. Temporary compatibility edge metadata", "### 4D. Current relationship map")
	arsContractSection := compactDocSection(t, contractsRaw, "## 6. ARS Storage And Discoverability Contract", "## 7. ES Admission And Execution Contract")
	arsBoundarySection := compactDocSection(t, boundariesRaw, "## 6. ARS boundary", "## 7. AGS boundary")
	lifecyclePrepareSection := compactDocSection(t, lifecycleRaw, "## 5. Prepare contract", "## 6. Submit contract")
	designPreparationSection := compactDocSection(t, designRaw, "### 5.1 Preparation phase", "### 5.2 Submission phase")

	for _, required := range []string{
		"Workstream B artifact publication/storage/discoverability decision",
		"B1 is the focused code-facing guardrail slice over this decision.",
		"It adds tests that keep AGS publication output signed and evidence-producing, ARS discovery records runtime-facing, descriptor/manifest/index/support tuples secondary, payload and artifact identity distinct, `claims.package.identity` the identity surface ES consumes, Control Plane proof/example artifacts outside core semantics, and `control-plane-normal-shell/v1` compatibility unchanged.",
		"It makes no runtime implementation changes.",
		"AGS publish-time ownership",
		"ARS post-publication ownership",
		"ES consumer boundary",
		"`payload_digest` addresses payload bytes.",
		"`artifact_digest` is package-facing identity derived from `payload_digest`, `artifact_type`, and `intent_digest`.",
		"The current ARS discovery record is the canonical runtime-discoverable surface",
		"`POST /v1/artifacts:register` with required `discovery_digest` and optional `descriptor_digest`",
		"Descriptor support data remains optional and secondary.",
		"Reason",
		"Scope",
		"Affected contract or boundary",
		"Visibility",
		"Removal condition",
		"system-visible",
		"Descriptor read/support path",
		"Manifest read/support path",
		"descriptor `package.supporting[name=manifest]`",
		"The current discovery/register JSON shape is a `Bounded slice rule`, not a temporary compatibility edge.",
		"`ars/index.Entry` plus `KindDiscovery`, `KindDescriptor`, `KindEvidence`, and `KindManifest` remain `Implementation-only/current-slice detail`, not compatibility surfaces.",
		"`ars/index.Entry` plus `KindDiscovery`, `KindDescriptor`, `KindEvidence`, and `KindManifest`",
		"ES public grammar must not inherit AGS publish DTOs, ARS descriptor/index tuples, or Control Plane examples/probes",
		"AGS writes payload, aggregate evidence, discovery, descriptor, and manifest blobs to ARS",
	} {
		if !strings.Contains(decision, required) {
			t.Fatalf("artifact publication/storage decision doc missing %q", required)
		}
	}

	for _, required := range []string{
		"The Workstream B publication/storage/discoverability decision is recorded in `.docs/system_overview/artifact_publication_storage.md`.",
		"B1 is the focused code-facing guardrail slice over the same B0 boundary.",
		"It does not redesign AGS, ARS, or ES runtime behavior.",
		"The current ARS discovery record remains the canonical runtime-discoverable surface for the current slice.",
		"the secondary descriptor support path remains a temporary compatibility edge",
	} {
		if !strings.Contains(record, required) {
			t.Fatalf("Workstream B record missing Workstream B decision phrase %q", required)
		}
	}

	for _, required := range []string{
		"`artifact_publication_storage.md`",
		"Descriptor/manifest support data remain ARS-owned secondary publication detail",
		"ARS discovery, artifact evidence, and payload/blob reads on the current hot path",
	} {
		if !strings.Contains(contracts, required) {
			t.Fatalf("system contracts doc missing Workstream B phrase %q", required)
		}
	}

	for _, required := range []string{
		"`artifact_publication_storage.md`",
		"The current ARS discovery record is the canonical runtime-discoverable surface for the current slice",
		"but not descriptor/manifest support data on the current hot path",
	} {
		if !strings.Contains(boundaries, required) {
			t.Fatalf("system boundaries doc missing Workstream B phrase %q", required)
		}
	}

	for _, required := range []string{
		"`:prepare` treats the ARS discovery record as an upstream discoverability input, not as ES public execution grammar.",
		"`:prepare` does not require ARS descriptor or manifest support data on the current hot path.",
	} {
		if !strings.Contains(lifecycle, required) {
			t.Fatalf("execution lifecycle contracts doc missing Workstream B phrase %q", required)
		}
	}

	if !strings.Contains(design, "Descriptor/manifest support data remain secondary publication detail rather than current ES hot-path admission inputs.") {
		t.Fatalf("execution lifecycle design doc missing ES hot-path discoverability boundary note")
	}
	for _, section := range []struct {
		label string
		text  string
	}{
		{label: "execution lifecycle prepare contract section", text: lifecyclePrepareSection},
		{label: "execution lifecycle preparation design section", text: designPreparationSection},
	} {
		assertContainsAll(t, section.label, section.text,
			"`.docs/system_overview/artifact_publication_storage.md`",
			"Workstream B publication/storage/discoverability decision",
			"ARS discovery plus explicit evidence/payload references",
			"descriptor/manifest support paths as secondary compatibility support",
			"explicit separation between `artifact_digest` and `payload_digest`",
		)
	}

	if !strings.Contains(decisionCompatibility, "Descriptor read/support path") || !strings.Contains(decisionCompatibility, "Manifest read/support path") {
		t.Fatalf("artifact publication/storage decision doc missing explicit Workstream B compatibility-edge metadata section")
	}
	if !strings.Contains(arsContractSection, "Descriptor read/support path") || !strings.Contains(arsContractSection, "Manifest read/support path") {
		t.Fatalf("ARS contracts section missing descriptor/manifest compatibility-edge alignment")
	}
	if !strings.Contains(arsBoundarySection, "Descriptor read/support path") || !strings.Contains(arsBoundarySection, "Manifest read/support path") {
		t.Fatalf("ARS boundary section missing descriptor/manifest compatibility-edge alignment")
	}
}

func TestWorkstreamB1ArtifactBoundaryGuardrailPostureIsDocumented(t *testing.T) {
	record := workstreamRecord(t, "B")
	decision := compactText(mustRead(t, ".docs/system_overview/artifact_publication_storage.md"))

	assertContainsAll(t, "Workstream B record Workstream B1 guardrail posture", record,
		"B1 is the focused code-facing guardrail slice over the same B0 boundary.",
		"AGS publication output",
		"ARS runtime-facing discovery",
		"ES admission hot-path consumption",
		"payload/artifact/package identity separation",
		"CP proof/example non-authority",
		"`control-plane-normal-shell/v1` compatibility",
		"It does not redesign AGS, ARS, or ES runtime behavior.",
	)

	assertContainsAll(t, "artifact publication/storage B1 guardrail posture", decision,
		"## 6. Code-facing guardrail posture",
		"B1 guardrail tests are intentionally narrow.",
		"they must not make ES own AGS publication semantics",
		"make ES public DTOs depend on ARS descriptor/manifest/index/support tuple grammar",
		"collapse `payload_digest` and `artifact_digest`",
		"promote Control Plane proof/example artifacts into AGS/ARS/ES core semantics",
		"not themselves a migration plan for the reopened long-term discovery/index/publication-support seam",
	)
}

func TestWorkstreamBArtifactCompatibilityEdgesStayConsistent(t *testing.T) {
	decisionRaw := mustRead(t, ".docs/system_overview/artifact_publication_storage.md")
	contractsRaw := mustRead(t, ".docs/system_overview/contracts.md")
	boundariesRaw := mustRead(t, ".docs/system_overview/boundaries.md")

	decisionSurfaces := compactDocSection(t, decisionRaw, "### 4B. Publication, storage, and discoverability surfaces", "### 4C. Temporary compatibility edge metadata")
	decisionCompatibility := compactDocSection(t, decisionRaw, "### 4C. Temporary compatibility edge metadata", "### 4D. Current relationship map")
	arsContractSection := compactDocSection(t, contractsRaw, "## 6. ARS Storage And Discoverability Contract", "## 7. ES Admission And Execution Contract")
	arsContractCompatibility := compactDocSection(t, arsContractSection, "### Temporary compatibility edges", "### Reopened seams")
	arsBoundarySection := compactDocSection(t, boundariesRaw, "## 6. ARS boundary", "## 7. AGS boundary")
	arsBoundaryCompatibility := compactDocSection(t, arsBoundarySection, "**Temporary compatibility edges**", "**Reopened seams**")

	if strings.Contains(decisionSurfaces, "Artifact descriptor plus `/descriptor` read surface | support/secondary publication detail | `Temporary compatibility edge`") ||
		strings.Contains(decisionSurfaces, "Manifest support path plus `/manifest` read surface | support/secondary publication detail | `Temporary compatibility edge`") {
		if strings.Contains(arsContractCompatibility, "None on the current ARS artifact contract.") {
			t.Fatalf("ARS contracts section still claims no compatibility edges while Workstream B classifies descriptor/manifest support as compatibility-only")
		}
		if strings.Contains(arsBoundaryCompatibility, "None on the current ARS boundary.") {
			t.Fatalf("ARS boundary section still claims no compatibility edges while Workstream B classifies descriptor/manifest support as compatibility-only")
		}
	}

	for _, required := range []string{
		"Reason",
		"Scope",
		"Affected contract or boundary",
		"Visibility",
		"Removal condition",
		"Descriptor read/support path",
		"Manifest read/support path",
		"system-visible",
		"outside the ES hot path and outside ES public grammar",
		"`package.supporting[name=manifest]` reference",
		"`Bounded slice rule`, not a temporary compatibility edge",
		"`Implementation-only/current-slice detail`, not compatibility surfaces",
	} {
		if !strings.Contains(decisionCompatibility, required) {
			t.Fatalf("artifact publication/storage compatibility section missing %q", required)
		}
	}

	for _, required := range []string{
		"Descriptor read/support path",
		"Manifest read/support path",
		"system-visible compatibility edge",
		"not ES hot-path admission or ES public grammar",
		"artifact_publication_storage.md",
	} {
		if !strings.Contains(arsContractCompatibility, required) {
			t.Fatalf("ARS contracts compatibility section missing %q", required)
		}
		if !strings.Contains(arsBoundaryCompatibility, required) {
			t.Fatalf("ARS boundary compatibility section missing %q", required)
		}
	}

	for _, section := range []struct {
		label string
		text  string
	}{
		{label: "ARS contracts section", text: arsContractSection},
		{label: "ARS boundary section", text: arsBoundarySection},
	} {
		if !strings.Contains(section.text, "secondary publication detail") {
			t.Fatalf("%s must keep descriptor/manifest support secondary", section.label)
		}
		if strings.Contains(section.text, "descriptor/manifest support data are the canonical runtime-discoverable surface") {
			t.Fatalf("%s must not promote descriptor/manifest support into canonical runtime discoverability", section.label)
		}
		if strings.Contains(section.text, "descriptor/manifest support data define ES public grammar") {
			t.Fatalf("%s must not promote descriptor/manifest support into ES public grammar", section.label)
		}
	}
}

func TestWorkstreamB0ArtifactBoundaryGateIsDocumented(t *testing.T) {
	record := workstreamRecord(t, "B")
	decision := compactText(mustRead(t, ".docs/system_overview/artifact_publication_storage.md"))
	sharedKernel := compactText(mustRead(t, ".docs/system_overview/shared_kernel.md"))
	contracts := compactText(mustRead(t, ".docs/system_overview/contracts.md"))
	boundaries := compactText(mustRead(t, ".docs/system_overview/boundaries.md"))
	artifactHygiene := compactText(mustRead(t, ".docs/system_overview/artifact_hygiene.md"))

	for _, doc := range []struct {
		label string
		text  string
	}{
		{label: "Workstream B record Workstream B0 gate", text: record},
		{label: "artifact publication/storage decision", text: decision},
	} {
		assertContainsAll(t, doc.label, doc.text,
			"B0 is",
			"docs and docs-contract-test gate",
			"artifact publication, storage, discoverability, payload identity, artifact identity, and compatibility/support shapes",
			"no runtime implementation changes",
		)
	}

	assertContainsAll(t, "artifact publication/storage B0 ownership and identity", decision,
		"AGS owns publication semantics.",
		"ARS owns blob storage, discovery, index, descriptor, manifest, and support read semantics.",
		"Payload identity and artifact identity are explicit and not interchangeable.",
		"`payload_digest` identifies payload bytes or payload content identity.",
		"`artifact_digest` identifies artifact/package identity as currently derived and documented",
		"`claims.package.identity` is the shared-kernel identity surface ES consumes.",
		"Descriptor/manifest/index/support tuples are compatibility/support surfaces unless explicitly migrated.",
		"ES must consume artifacts through a designed discoverability surface, not by inheriting ARS support tuple grammar as ES public grammar.",
		"CP examples and proof harness artifacts do not define AGS/ARS/ES core semantics.",
		"Generated evidence, `.out`, support bundles, retained bundles, reports, traces, logs, summaries, and proof artifacts remain evidence/projection only.",
	)

	assertContainsAll(t, "shared kernel B0 identity", sharedKernel,
		"`claims.package.identity` is the shared-kernel identity surface ES consumes.",
		"`payload_digest` identifies payload bytes or payload content identity",
		"`artifact_digest` identifies artifact/package identity as currently derived and documented",
		"ARS route/index/descriptor/manifest/support tuple shapes are not themselves the shared kernel or ES public grammar.",
	)

	assertContainsAll(t, "contracts B0 boundary", contracts,
		"`claims.package.identity` is the shared-kernel identity surface ES consumes.",
		"`payload_digest` identifies payload bytes or payload content identity",
		"`artifact_digest` identifies artifact/package identity as currently derived and documented.",
		"Descriptor/manifest/index/support tuples are compatibility/support or implementation-only surfaces unless explicitly migrated.",
		"ES must consume artifacts through a designed discoverability surface, not by inheriting ARS support tuple grammar as ES public grammar.",
	)

	assertContainsAll(t, "boundaries B0 boundary", boundaries,
		"`claims.package.identity` is the shared-kernel identity surface ES consumes:",
		"`payload_digest` identifies payload bytes or payload content identity",
		"`artifact_digest` identifies artifact/package identity as currently derived and documented.",
		"Descriptor/manifest/index/support tuples are compatibility/support or implementation-only surfaces unless explicitly migrated",
		"ES reads artifacts through designed ARS discoverability outputs rather than inheriting ARS support tuple grammar as ES public grammar",
	)

	assertContainsAll(t, "artifact hygiene B0 non-authority", artifactHygiene,
		"CP examples and proof harness artifacts do not define AGS/ARS/ES core semantics.",
		"Generated evidence, `.out`, support bundles, retained bundles, reports, traces, logs, summaries, and proof artifacts remain evidence/projection only.",
	)

	for _, doc := range []struct {
		label string
		text  string
	}{
		{label: "artifact publication/storage decision", text: decision},
		{label: "shared kernel", text: sharedKernel},
		{label: "contracts", text: contracts},
		{label: "boundaries", text: boundaries},
		{label: "artifact hygiene", text: artifactHygiene},
	} {
		assertContainsNone(t, doc.label,
			doc.text,
			"ES owns AGS publication semantics",
			"ES public API owns ARS descriptor/manifest/index/support grammar",
			"`artifact_digest` and `payload_digest` are interchangeable",
			"CP examples and proof harness artifacts define AGS/ARS/ES core semantics",
			"Generated evidence, `.out`, support bundles, retained bundles, reports, traces, logs, summaries, and proof artifacts are authority",
		)
	}
}

func TestWorkstreamCESExecutionAdmissionModelDecisionIsDocumented(t *testing.T) {
	record := workstreamRecord(t, "C")
	decisionRaw := mustRead(t, ".docs/execution_lifecycle/es_execution_admission_model.md")
	decision := compactText(decisionRaw)
	contracts := compactText(mustRead(t, ".docs/system_overview/contracts.md"))
	boundaries := compactText(mustRead(t, ".docs/system_overview/boundaries.md"))
	lifecycleContracts := compactText(mustRead(t, ".docs/execution_lifecycle/contracts.md"))
	lifecycleDesign := compactText(mustRead(t, ".docs/execution_lifecycle/design.md"))
	publicSurfaceSection := compactDocSection(t, decisionRaw, "### 4A. Public execution surfaces", "### 4B. Admission, handoff, and projection ownership surfaces")
	compatibilitySection := compactDocSection(t, decisionRaw, "### 4C. Temporary compatibility edge metadata", "### 4D. Current relationship map")

	for _, required := range []string{
		"Workstream C ES public admission/execution model decision",
		"Workstream D policy/authorization redesign",
		"Workstream E runtime-config ownership redesign",
		"Workstream F runtime-identity redesign",
		"ES owns admission composition, prepare-time preflight, submit-time execution handoff, Nomad-backed lifecycle projection, retained opaque result-bundle ownership, and runtime handoff boundary enforcement.",
		"`internal/contracts/evidence/v1`",
		"`artifact_digest` as the payload locator by hidden equality",
		"`lifecycle_projection`",
		"`authority_handoff`",
		"`outcome_evidence`",
		"`GET /v1/executions:contract`",
		"`POST /v1/executions:prepare`",
		"`POST /v1/executions:submit`",
		"`GET /v1/executions/{run_id}/status`",
		"`GET /v1/executions/{run_id}/logs`",
		"`GET /v1/executions/{run_id}/result`",
		"`POST /v1/executions/{run_id}:cancel`",
		"Nomad remains authoritative for submitted execution lifecycle.",
		"runtime credential minting/brokerage/storage",
		"opaque output bundles",
	} {
		if !strings.Contains(decision, required) {
			t.Fatalf("workstream C execution-admission decision doc missing %q", required)
		}
	}

	for _, required := range []string{
		"`GET /v1/executions:contract` | `temporary compatibility edge`",
		"`POST /v1/executions:prepare` | `temporary compatibility edge`",
		"`POST /v1/executions:submit` | `stable contract`",
		"`GET /v1/executions/{run_id}/status` | `stable contract`",
		"`GET /v1/executions/{run_id}/logs` | `bounded slice rule`",
		"`GET /v1/executions/{run_id}/result` | `temporary compatibility edge`",
		"`POST /v1/executions/{run_id}:cancel` | `bounded slice rule`",
	} {
		if !strings.Contains(publicSurfaceSection, required) {
			t.Fatalf("workstream C public surface classification missing %q", required)
		}
	}

	for _, required := range []string{
		"The Workstream C ES public admission/execution model decision is recorded in `.docs/execution_lifecycle/es_execution_admission_model.md`.",
		"`GET /v1/executions:contract` and `POST /v1/executions:prepare` remain temporary compatibility edges",
		"Nomad remains authoritative for submitted execution lifecycle.",
		"caller auth/allowlist plus ARS discovery/evidence/payload refs",
		"`application/gzip` result bundles keyed by `run_id` remain explicit compatibility edges",
	} {
		if !strings.Contains(record, required) {
			t.Fatalf("Workstream C record missing Workstream C decision phrase %q", required)
		}
	}

	for _, required := range []string{
		"`.docs/execution_lifecycle/es_execution_admission_model.md`",
		"retained opaque result-bundle ownership",
		"`authority_handoff` read fact",
	} {
		if !strings.Contains(contracts, required) {
			t.Fatalf("system contracts doc missing Workstream C phrase %q", required)
		}
	}

	for _, required := range []string{
		"`.docs/execution_lifecycle/es_execution_admission_model.md`",
		"Runtime identity endpoint handoff and ES-owned subtree protection for the backing workspace",
		"Current CP compatibility for publish -> prepare -> submit -> status/logs/result/cancel is a retained consumer edge.",
	} {
		if !strings.Contains(boundaries, required) {
			t.Fatalf("system boundaries doc missing Workstream C phrase %q", required)
		}
	}

	for _, required := range []string{
		"`es_execution_admission_model.md`",
		"`authority_handoff` is additive and read-only.",
		"`POST /v1/executions:prepare` is an active milestone surface, not a declared long-term public execution API.",
	} {
		if !strings.Contains(lifecycleContracts, required) {
			t.Fatalf("execution lifecycle contracts doc missing Workstream C phrase %q", required)
		}
	}

	for _, required := range []string{
		"`es_execution_admission_model.md`",
		"`:submit` is the real execution-submission surface in the current slice.",
		"Terminal result retrieval is bounded to an ES-retained opaque bundle",
	} {
		if !strings.Contains(lifecycleDesign, required) {
			t.Fatalf("execution lifecycle design doc missing Workstream C phrase %q", required)
		}
	}

	for _, required := range []string{
		"Reason",
		"Scope",
		"Affected contract or boundary",
		"Visibility",
		"Removal condition",
		"Current CP governed execution consumer path",
		"`GET /v1/executions:contract` producer declaration",
		"`POST /v1/executions:prepare` bounded preflight surface",
		"`invocation.annotations[\"execution_substrate.runtime_profile\"]` plus `control-plane-normal-shell/v1` and the current `static-script` overlay",
		"Current `/execution/staged`, `/execution/run`, `/execution/run/result`, and run-scoped runtime-identity path conventions",
		"Current `authority_handoff` field names and evidence-source labels",
		"Current `outcome_evidence` JSON field layout and successful logs/result evidence headers",
		"Current `GET /v1/executions/{run_id}/result` route plus retained `application/gzip` bundles keyed by public `run_id`",
		"`system-visible`",
		"`local-runtime-only`",
	} {
		if !strings.Contains(compatibilitySection, required) {
			t.Fatalf("workstream C compatibility-edge section missing %q", required)
		}
	}
}

func TestWorkstreamC7CheckpointDocsContract(t *testing.T) {
	record := workstreamRecord(t, "C")
	checkpointRaw := mustRead(t, ".docs/execution_lifecycle/workstream_c7_checkpoint.md")
	checkpoint := compactText(checkpointRaw)
	decision := compactText(mustRead(t, ".docs/execution_lifecycle/es_execution_admission_model.md"))
	tlsDecision := compactText(mustRead(t, ".docs/remote_alpha_operator_healthcheck_tls_signing_custody_decision.md"))
	tlsResolution := compactText(mustRead(t, ".docs/remote_alpha_operator_healthcheck_tls_signing_custody_resolution.md"))
	remoteAlpha := compactText(mustRead(t, ".docs/system_overview/remote_supported_host_alpha.md"))
	runbook := compactText(mustRead(t, ".docs/supported_local_cp_consumer_runbook.md"))

	assertContainsAll(t, "Workstream C7 checkpoint status", checkpoint,
		"Workstream C7 consolidation checkpoint",
		"`Docs-only checkpoint`",
		"`No behavior/API/runtime change`",
		"C7 is a consolidation checkpoint, not a new route or runtime feature.",
		"No route/API behavior changed by C7.",
		"C7 adds no route, API shape, runtime profile, admission policy, scheduler behavior, signer option, renewal eligibility, CP diagnostic behavior, IM profile lineage behavior, or MA scheduling eligibility.",
	)
	assertContainsAll(t, "Workstream C7 A/B gates", checkpoint,
		"Workstream A shared-kernel gate is satisfied and remains narrow.",
		"`internal/contracts/evidence/v1` remains the only active shared artifact evidence kernel",
		"Workstream B artifact publication/storage gate is satisfied and remains evidence-owned.",
		"ES must consume artifacts through the designed ARS discoverability surface",
	)
	assertContainsAll(t, "Workstream C7 C0-C6 summary", checkpoint,
		"Workstream C0-C6 are present.",
		"C0: docs and docs-contract gate only",
		"C1: prepare/admission guardrail tests",
		"C2: submit and lifecycle-projection guardrails",
		"C3: retained-result and `authority_handoff` guardrails",
		"C4: runtime identity and Vault handoff guardrails",
		"C5: status/logs/result/cancel compatibility and non-authority guardrails.",
		"C6: ES Admission Policy Layer v0 and its configurable-input follow-up.",
	)
	assertContainsAll(t, "Workstream C7 compatibility edges", checkpoint,
		"`control-plane-normal-shell/v1`.",
		"`execution_substrate.runtime_profile`.",
		"`GET /v1/executions:contract` remains a narrow producer declaration, not health/readiness/run authority.",
		"`POST /v1/executions:prepare` remains bounded preflight, not hidden orchestration.",
		"`POST /v1/executions:submit` remains the ES handoff surface.",
		"Status remains a Nomad-backed projection, not an ES-owned lifecycle model.",
		"ES-retained opaque `application/gzip` result bundles by `run_id`.",
		"CP owns orchestration, review, checkpoint, and finalization.",
		"IM profile/readiness/provenance remain diagnostics only.",
	)
	assertContainsAll(t, "Workstream C7 reopened seams", checkpoint,
		"long-term ES request/submit DTOs",
		"long-term `:prepare` role",
		"admission policy model beyond C6 v0",
		"runtime-profile vocabulary",
		"execution locator/allocation projection",
		"`/execution/...` package layout",
		"retained-result route evolution",
		"runtime identity handoff owner",
		"workload-zone runtime-config owner",
		"ARS discovery/index long-term shape",
		"C7 records these reopened seams without settling them",
	)
	assertContainsAll(t, "Workstream C7 TLS closeout", checkpoint,
		"Remote Alpha TLS blocked decision reference:",
		"source-insufficient",
		"No signer/custody option is selected.",
		"operator-healthcheck TLS replacement remains blocked.",
		"`operator-healthcheck-tls-renew` remains blocked by `unsupported_signing_topology`.",
		"At this C7 checkpoint, P0v noninteractive status was design/static only.",
		"Later status alignment: a subsequent P0v tranche implements only the read-only",
		"no route from status evidence to renewal permission",
		"No CP diagnose rerun, IM refresh, ES route execution, renewal, replacement, or live proof occurred",
		"The TLS branch should not block Workstream C product work unless new source-grounded signer/custody evidence appears.",
	)
	assertContainsAll(t, "Workstream C7 next safe slices", checkpoint,
		"Producer Contract / Prepare Boundary Tests",
		"Runtime Profile Compatibility Matrix Cleanup",
		"Retained Result Bundle Contract Clarification",
		"Lifecycle Projection Authority Labels",
		"Artifact Identity / Discovery Seam",
		"CP Compatibility Fixture Alignment",
		"Stop conditions:",
		"Validation hints:",
	)
	assertContainsAll(t, "Workstream C record Workstream C7 pointer", record,
		"C7 is a docs/static-test-only consolidation checkpoint recorded in `.docs/execution_lifecycle/workstream_c7_checkpoint.md`.",
		"Workstream A/B gates are satisfied",
		"C0-C6 are present",
		"next behavior-changing C work must preserve CP compatibility and CP/IM non-authority boundaries",
		"It makes no behavior, API, route, runtime, TLS, CP diagnose, IM refresh, live proof, or route eligibility change.",
	)
	assertContainsAll(t, "Workstream C source decision still records C0-C6", decision,
		"C0 is the docs and docs-contract-test gate only",
		"C1 is the focused code-facing guardrail slice over",
		"C2 is the focused tests/docs guardrail slice over",
		"C3 is the focused tests/docs guardrail slice for retained-result",
		"C4 is the focused tests/docs guardrail slice for runtime identity and Vault handoff boundaries.",
		"C5 is the focused tests/docs guardrail slice for current status/logs/result/cancel compatibility and non-authority posture.",
		"C6 is ES Admission Policy Layer v0.",
	)
	assertContainsAll(t, "Remote Alpha TLS blocked decision remains blocked", tlsDecision,
		"Decision status for reusable P0u: blocked.",
		"No option is selected for reusable P0u.",
		"`operator-healthcheck-tls-renew` remains blocked by `unsupported_signing_topology`.",
		"P0v was design/static only at the time of this decision record.",
		"A later P0v tranche implements read-only status only with no fallback emitter",
	)
	assertContainsAll(t, "Remote Alpha TLS resolution remains blocked", tlsResolution,
		"Current reusable P0u resolution verdict: blocked.",
		"No current ES source satisfies the signer authority and custody evidence gate",
		"no reusable replacement, renewal, profile-lineage refresh, CP diagnose rerun, MA execution, Bridge projection, or live proof may proceed by inference",
	)
	assertContainsAll(t, "Remote Alpha TLS route matrix still blocked", remoteAlpha,
		"P0v implements the ES-owned noninteractive read-only operator-healthcheck TLS",
		"It preserves `operator-healthcheck-tls-renew` as blocked with `unsupported_signing_topology`",
		"`operator-healthcheck-tls-renew` | blocked/status-only",
	)
	assertContainsAll(t, "CP and IM non-authority labels remain preserved", runbook,
		"Control Plane owns orchestration, Temporal workflow state, review, checkpoint, finalization, intervention, and operator-facing control semantics.",
		"CP consumes accepted ES surfaces but does not define ES core contracts.",
		"IM readiness/profile/support-bundle/provenance artifacts remain evidence/projection/diagnostics only",
	)
	assertContainsNone(t, "Workstream C7 no TLS or authority widening claim", checkpoint,
		"operator-healthcheck TLS replacement is unblocked",
		"operator-healthcheck-tls-renew is eligible",
		"renewal is enabled",
		"source-grounded signer/custody evidence exists",
		"CP diagnose rerun occurred",
		"IM refresh occurred",
		"MA scheduled execution is eligible",
		"C7 implements",
		"C7 changes API",
		"C7 changes runtime",
	)
}

func TestWorkstreamCProducerContractPrepareBoundaryTestsAreDocumented(t *testing.T) {
	checkpoint := compactText(mustRead(t, ".docs/execution_lifecycle/workstream_c7_checkpoint.md"))
	decision := compactText(mustRead(t, ".docs/execution_lifecycle/es_execution_admission_model.md"))
	lifecycleContractsRaw := mustRead(t, ".docs/execution_lifecycle/contracts.md")
	lifecycleContract := compactText(lifecycleContractsRaw)
	producerSection := compactDocSection(t, lifecycleContractsRaw, "## 4A. Producer Contract Declaration", "## 5. Prepare contract")
	prepareSection := compactDocSection(t, lifecycleContractsRaw, "## 5. Prepare contract", "## 6. Submit contract")
	boundaries := compactText(mustRead(t, ".docs/system_overview/boundaries.md"))
	runbook := compactText(mustRead(t, ".docs/supported_local_cp_consumer_runbook.md"))

	assertContainsAll(t, "C7 next safe producer/prepare slice", checkpoint,
		"Producer Contract / Prepare Boundary Tests",
		"Why safe: strengthens existing C0-C1 guardrails around `GET /v1/executions:contract` and `POST /v1/executions:prepare` without changing runtime behavior.",
		"Stop conditions: a test requires new route behavior, run state, scheduler contact, CP workflow grammar, or changed public DTOs.",
	)

	assertContainsAll(t, "producer contract boundary contract", producerSection,
		"The declaration is read-only and non-secret.",
		"The declaration is not service health, submit readiness, artifact-specific admission proof, run existence proof, lifecycle state, lifecycle write coordination, credential possession, policy approval, or scheduler API.",
		"The current `non_authority` classifications include `not_service_health`, `not_submit_readiness`, `not_artifact_admission_proof`, `not_run_authority`, `not_run_existence_proof`, `not_lifecycle_truth`, `not_lifecycle_write_coordination`, `not_credential_truth`, `not_policy_truth`, and `not_scheduler_api`.",
		"The declaration must not expose Nomad job IDs, allocation IDs, task IDs, host paths, result filesystem paths, Vault tokens, Codex credential material, JWT-SVIDs, leases, or policy approval state.",
		"Consumers must still use `/health`, submit-readiness checks, and `:prepare` for service health, environment readiness, and artifact-specific admission proof.",
	)

	assertContainsAll(t, "prepare boundary contract", prepareSection,
		"`POST /v1/executions:prepare` returns bounded preflight success for a requested artifact execution without creating execution state.",
		"Unsupported or disabled profile selections fail during `:prepare` before any run ID exists.",
		"Successful `:prepare` returns bounded preflight success only, not execution state.",
		"No `run_id` is created.",
		"No Nomad job or eval ID is returned.",
		"No scheduler handoff occurs.",
		"No proto-execution state or durable ES execution record is created.",
		"No workload-vault plan, signer detail, or workload identity detail is returned.",
	)

	for _, doc := range []struct {
		label string
		text  string
	}{
		{label: "Workstream C decision producer/prepare separation", text: decision},
		{label: "execution lifecycle contracts producer/prepare separation", text: lifecycleContract},
		{label: "system boundaries producer/prepare separation", text: boundaries},
		{label: "CP consumer runbook producer/prepare separation", text: runbook},
	} {
		assertContainsAll(t, doc.label, doc.text,
			"`GET /v1/executions:contract` remains a narrow producer compatibility declaration, not health, submit readiness, run authority, or a general capability registry.",
			"`POST /v1/executions:prepare` remains bounded preflight and creates no run object or scheduler handoff.",
			"`POST /v1/executions:submit` remains the MVP execution handoff surface: async, bounded receipt, and Nomad submission through ES.",
			"Control Plane owns orchestration, Temporal workflow state, review, checkpoint, finalization, intervention, and operator-facing control semantics.",
			"IM readiness/profile/support-bundle/provenance artifacts remain evidence/projection/diagnostics only; they do not become ES or CP authority.",
			"Runtime identity and workload credential handoff remain non-secret and workload-side; ES must not become a Vault token broker or Codex credential broker.",
		)
	}
}

func TestWorkstreamC0ExecutionOwnershipGateIsDocumented(t *testing.T) {
	plans := compactText(mustRead(t, "PLANS.md"))
	record := workstreamRecord(t, "C")
	decision := compactText(mustRead(t, ".docs/execution_lifecycle/es_execution_admission_model.md"))
	contracts := compactText(mustRead(t, ".docs/system_overview/contracts.md"))
	boundaries := compactText(mustRead(t, ".docs/system_overview/boundaries.md"))
	lifecycleContracts := compactText(mustRead(t, ".docs/execution_lifecycle/contracts.md"))
	lifecycleDesign := compactText(mustRead(t, ".docs/execution_lifecycle/design.md"))
	runbook := compactText(mustRead(t, ".docs/supported_local_cp_consumer_runbook.md"))
	mvp := compactText(mustRead(t, ".docs/mvp.md"))

	for _, doc := range []struct {
		label string
		text  string
	}{
		{label: "Workstream C record C0 gate", text: record},
		{label: "Workstream C decision C0 gate", text: decision},
		{label: "system contracts C0 gate", text: contracts},
		{label: "lifecycle contracts C0 gate", text: lifecycleContracts},
		{label: "lifecycle design C0 gate", text: lifecycleDesign},
		{label: "CP consumer runbook C0 gate", text: runbook},
		{label: "MVP C0 gate", text: mvp},
	} {
		assertContainsAll(t, doc.label, doc.text,
			"C0 is the docs and docs-contract-test gate",
			"Workstream C implementation must not start until C0 docs and docs-contract tests pass.",
		)
	}

	for _, doc := range []struct {
		label string
		text  string
	}{
		{label: "PLANS C0 ownership", text: plans},
		{label: "Workstream C decision C0 ownership", text: decision},
		{label: "system contracts C0 ownership", text: contracts},
		{label: "system boundaries C0 ownership", text: boundaries},
		{label: "CP consumer runbook C0 ownership", text: runbook},
		{label: "MVP C0 ownership", text: mvp},
	} {
		assertContainsAll(t, doc.label, doc.text,
			"ES owns the public admission model, prepare model, submit model, Nomad-backed lifecycle projection, retained opaque result bundles, runtime-profile compatibility, runtime-boundary handoff semantics, and bounded runtime identity/workload credential handoff boundaries.",
		)
	}

	assertContainsAll(t, "Workstream C record C0 no implementation", record,
		"C0 makes no runtime implementation changes.",
	)
	assertContainsAll(t, "Workstream C decision C0 no implementation", decision,
		"C0 is the docs and docs-contract-test gate only. It makes no runtime implementation changes",
	)
	assertContainsAll(t, "system contracts C0 scope", contracts,
		"C0 makes no runtime implementation changes",
	)
}

func TestWorkstreamC0BoundarySurfaceAssertionsAreDocumented(t *testing.T) {
	decision := compactText(mustRead(t, ".docs/execution_lifecycle/es_execution_admission_model.md"))
	contracts := compactText(mustRead(t, ".docs/system_overview/contracts.md"))
	boundaries := compactText(mustRead(t, ".docs/system_overview/boundaries.md"))
	lifecycleContracts := compactText(mustRead(t, ".docs/execution_lifecycle/contracts.md"))
	lifecycleDesign := compactText(mustRead(t, ".docs/execution_lifecycle/design.md"))
	runbook := compactText(mustRead(t, ".docs/supported_local_cp_consumer_runbook.md"))
	mvp := compactText(mustRead(t, ".docs/mvp.md"))

	coreBoundaryPhrases := []string{
		"`GET /v1/executions:contract` remains a narrow producer compatibility declaration, not health, submit readiness, run authority, or a general capability registry.",
		"`POST /v1/executions:prepare` remains bounded preflight and creates no run object or scheduler handoff.",
		"`POST /v1/executions:submit` remains the MVP execution handoff surface: async, bounded receipt, and Nomad submission through ES.",
		"`lifecycle_projection` remains a Nomad-backed projection with `source=nomad` and an opaque read-coordination revision; it is not a Nomad scheduler id, ES lifecycle store, or write guard.",
		"`outcome_evidence` remains bounded evidence/projection; current labels are compatibility surfaces, not final scheduler/result/log/cancel vocabulary.",
		"`authority_handoff` remains bounded non-secret runtime handoff evidence; it never becomes a live credential, lease, approval, or scheduler truth.",
		"ES-retained result bundles remain opaque output artifacts owned by ES; CP may materialize, review, and finalize their contents semantically, but CP does not own the retained bundle as run-control state.",
		"`control-plane-normal-shell/v1` and `execution_substrate.runtime_profile` compatibility remain preserved unless an explicit migration/versioning plan exists.",
	}

	for _, doc := range []struct {
		label string
		text  string
	}{
		{label: "Workstream C decision boundary assertions", text: decision},
		{label: "execution lifecycle contracts boundary assertions", text: lifecycleContracts},
		{label: "execution lifecycle design boundary assertions", text: lifecycleDesign},
		{label: "CP consumer runbook boundary assertions", text: runbook},
	} {
		assertContainsAll(t, doc.label, doc.text, coreBoundaryPhrases...)
	}

	assertContainsAll(t, "system contracts boundary assertions", contracts, coreBoundaryPhrases...)
	assertContainsAll(t, "system boundaries boundary assertions", boundaries, coreBoundaryPhrases...)
	assertContainsAll(t, "MVP boundary assertions", mvp,
		"`GET /v1/executions:contract` producer declaration | `compatibility edge` | Keep this as the current read-only producer compatibility declaration and early gate. Do not promote it into health, submit readiness, run authority, or a general capability registry.",
		"`POST /v1/executions:prepare` | `compatibility edge` | Keep this as the current bounded preflight surface. It proves preflight success only and creates no run object or scheduler handoff.",
		"`POST /v1/executions:submit` | `stable contract` | Freeze this as the MVP execution handoff surface: async, bounded receipt, and Nomad submission through ES.",
		"`lifecycle_projection` | `stable contract` | Keep `source=nomad` and `revision` as an opaque same-run read-coordination token, not a scheduler id or write guard.",
		"`outcome_evidence` on status or cancel JSON and successful logs or result responses | `compatibility edge` | Keep the current evidence carriers and labels for the MVP, but do not treat the present vocabulary as the final scheduler, result, log, or cancellation model.",
		"`authority_handoff` on submit or status | `compatibility edge` | Keep this as bounded non-secret runtime handoff evidence only. It never becomes live credential, lease, approval, or scheduler truth.",
		"ES-retained result bundles remain opaque output artifacts owned by ES; CP may materialize, review, and finalize their contents semantically, but CP does not own the retained bundle as run-control state.",
		"`control-plane-normal-shell/v1` plus `execution_substrate.runtime_profile` compatibility | `compatibility edge` | Keep this as the accepted opt-in CP normal-shell runtime edge for the MVP. It is not a general package-kind redesign or a transfer of CP control semantics into ES.",
	)

	for _, doc := range []struct {
		label string
		text  string
	}{
		{label: "Workstream C decision runtime identity boundary", text: decision},
		{label: "execution lifecycle contracts runtime identity boundary", text: lifecycleContracts},
		{label: "execution lifecycle design runtime identity boundary", text: lifecycleDesign},
		{label: "system contracts runtime identity boundary", text: contracts},
		{label: "system boundaries runtime identity boundary", text: boundaries},
		{label: "CP consumer runbook runtime identity boundary", text: runbook},
	} {
		assertContainsAll(t, doc.label, doc.text,
			"Runtime identity and workload credential handoff remain non-secret and workload-side; ES must not become a Vault token broker or Codex credential broker.",
		)
	}
}

func TestWorkstreamC1PrepareAdmissionGuardrailPostureIsDocumented(t *testing.T) {
	record := workstreamRecord(t, "C")
	decision := compactText(mustRead(t, ".docs/execution_lifecycle/es_execution_admission_model.md"))
	postureSection := compactDocSection(t, mustRead(t, ".docs/execution_lifecycle/es_execution_admission_model.md"), "## 6. Code-facing guardrail posture", "")

	for _, doc := range []struct {
		label string
		text  string
	}{
		{label: "Workstream C record C1 guardrail posture", text: record},
		{label: "Workstream C decision C1 guardrail posture", text: decision},
	} {
		assertContainsAll(t, doc.label, doc.text,
			"C1 is the focused code-facing guardrail slice over",
			"bounded `:prepare` preflight non-effects",
			"ARS discovery/evidence/payload/package-identity consumption",
			"signed evidence",
			"narrow execution/runtime claim enforcement",
			"AGS/ARS support/CP grammar exclusion",
			"payload-digest versus package-identity mismatch separation",
			"current compatibility surfaces",
			"`authority_handoff`/`outcome_evidence` non-authority",
			"It does not redesign runtime behavior.",
		)
	}

	assertContainsAll(t, "Workstream C C1 code-facing guardrails", postureSection,
		"C1 guardrail tests are intentionally narrow.",
		"current ES route shapes",
		"request decoding",
		"admission composition",
		"evidence verification",
		"payload and package identity checks",
		"non-authority response vocabulary",
		"preserved compatibility edges",
		"must not make `:prepare` create run truth",
		"scheduler handoff",
		"provider run IDs",
		"retained results",
		"CP workflow state",
		"lifecycle-store mutation",
		"AGS publication fields",
		"ARS descriptor/manifest/index/support tuple fields",
		"CP attempt/review/checkpoint/finalization fields",
		"not a migration plan for the reopened long-term request",
		"runtime-profile",
		"lifecycle",
		"retained-result",
		"runtime-config",
		"runtime-identity seams",
	)
}

func TestWorkstreamC2SubmitLifecycleProjectionGuardrailPostureIsDocumented(t *testing.T) {
	record := workstreamRecord(t, "C")
	decisionRaw := mustRead(t, ".docs/execution_lifecycle/es_execution_admission_model.md")
	decision := compactText(decisionRaw)
	lifecycleContracts := compactText(mustRead(t, ".docs/execution_lifecycle/contracts.md"))
	lifecycleDesign := compactText(mustRead(t, ".docs/execution_lifecycle/design.md"))
	systemContracts := compactText(mustRead(t, ".docs/system_overview/contracts.md"))
	systemBoundaries := compactText(mustRead(t, ".docs/system_overview/boundaries.md"))
	artifactHygiene := compactText(mustRead(t, ".docs/system_overview/artifact_hygiene.md"))
	postureSection := compactDocSection(t, decisionRaw, "## 6. Code-facing guardrail posture", "")

	for _, doc := range []struct {
		label string
		text  string
	}{
		{label: "Workstream C record C2 posture", text: record},
		{label: "Workstream C decision C2 posture", text: decision},
		{label: "lifecycle contracts C2 posture", text: lifecycleContracts},
		{label: "lifecycle design C2 posture", text: lifecycleDesign},
		{label: "system contracts C2 posture", text: systemContracts},
		{label: "system boundaries C2 posture", text: systemBoundaries},
	} {
		assertContainsAll(t, doc.label, doc.text,
			"C2 is",
			"tests/docs guardrail slice",
			"submit",
			"lifecycle",
			"ES-owned async",
			"Nomad",
			"bounded",
			"`authority_handoff`",
			"`lifecycle_projection",
			"source=nomad",
			"opaque same-run read-coordination",
			"status/logs/result/cancel",
			"`control-plane-normal-shell/v1`",
			"does not redesign runtime behavior",
		)
	}

	assertContainsAll(t, "Workstream C record C2 CP grammar exclusions", record,
		"Control Plane attempt/review/checkpoint/finalization",
		"intervention",
		"approval",
		"hold/resume/reject",
		"Temporal",
		"workflow grammar",
	)
	assertContainsAll(t, "Workstream C C2 guardrail posture", postureSection,
		"C2 guardrail tests are also intentionally narrow.",
		"submit receipt shape",
		"ES-to-Nomad handoff",
		"Nomad-backed status/logs/result/cancel compatibility",
		"bounded `authority_handoff` evidence",
		"opaque `lifecycle_projection` read-coordination posture",
		"must not make submit create CP run-control truth",
		"review state",
		"checkpoint state",
		"finalization state",
		"intervention state",
		"Temporal workflow state",
		"CP workflow revisions",
		"retained-result identity",
		"scheduler IDs as public lifecycle authority",
		"write guards",
		"parallel ES lifecycle store",
	)
	assertContainsAll(t, "artifact hygiene C2 generated evidence non-authority", artifactHygiene,
		"Generated evidence, `.out`, reports, traces, logs, summaries, support bundles, retained bundles, proof artifacts, and maintenance summaries remain non-authoritative evidence/projection.",
	)
}

func TestWorkstreamC3RetainedResultAuthorityHandoffGuardrailPostureIsDocumented(t *testing.T) {
	record := workstreamRecord(t, "C")
	decisionRaw := mustRead(t, ".docs/execution_lifecycle/es_execution_admission_model.md")
	decision := compactText(decisionRaw)
	lifecycleContracts := compactText(mustRead(t, ".docs/execution_lifecycle/contracts.md"))
	lifecycleDesign := compactText(mustRead(t, ".docs/execution_lifecycle/design.md"))
	systemContracts := compactText(mustRead(t, ".docs/system_overview/contracts.md"))
	systemBoundaries := compactText(mustRead(t, ".docs/system_overview/boundaries.md"))
	runbook := compactText(mustRead(t, ".docs/supported_local_cp_consumer_runbook.md"))
	artifactHygiene := compactText(mustRead(t, ".docs/system_overview/artifact_hygiene.md"))
	postureSection := compactDocSection(t, decisionRaw, "## 6. Code-facing guardrail posture", "")

	for _, doc := range []struct {
		label string
		text  string
	}{
		{label: "Workstream C record C3 posture", text: record},
		{label: "Workstream C decision C3 posture", text: decision},
		{label: "lifecycle contracts C3 posture", text: lifecycleContracts},
		{label: "lifecycle design C3 posture", text: lifecycleDesign},
		{label: "system contracts C3 posture", text: systemContracts},
		{label: "system boundaries C3 posture", text: systemBoundaries},
	} {
		assertContainsAll(t, doc.label, doc.text,
			"C3 is the focused tests/docs guardrail slice for retained-result and `authority_handoff` boundaries.",
			"C3 is guardrail work, not runtime redesign.",
			"retained result bundles remain ES-owned opaque output artifacts",
			"CP may materialize, review, checkpoint, and finalize retained result contents semantically, but CP does not own the retained bundle as run-control state.",
			"Retained result references, paths, manifests, archives, `.out` copies, and materialized workspaces are evidence/projection or implementation detail, not orchestration authority.",
			"`GET /v1/executions/{run_id}/result` compatibility shape remains unchanged unless an explicit migration/versioning plan exists.",
			"`authority_handoff` remains bounded non-secret runtime handoff evidence only.",
			"`authority_handoff` never carries or implies live credentials, Vault tokens, Codex credentials, leases, approvals, operator authorization, CP workflow state, scheduler truth, or retained-result authority.",
			"Runtime identity/Vault handoff remains workload-side and non-secret; ES does not become a Vault token broker or Codex credential broker.",
			"`outcome_evidence` remains bounded evidence/projection; current labels remain compatibility surfaces.",
			"`control-plane-normal-shell/v1` and `execution_substrate.runtime_profile` compatibility remain preserved unless an explicit migration/versioning plan exists.",
		)
	}

	assertContainsAll(t, "Workstream C C3 guardrail posture", postureSection,
		"C3 guardrail tests are intentionally narrow.",
		"retained result ownership",
		"result-route compatibility shape",
		"public result and authority-handoff grammar exclusions",
		"bounded `outcome_evidence` label compatibility",
		"must not redesign retained results",
		"runtime identity",
		"Vault handoff",
		"Nomad integration",
		"Control Plane behavior",
	)
	assertContainsAll(t, "runbook C3 retained-result and authority posture", runbook,
		"Retained results are opaque tar.gz output material, not CP workflow truth, checkpoint truth, finalization truth, review authority, scheduler truth, or operator authority.",
		"`authority_handoff` never carries live credentials, Vault tokens, Codex credentials, leases, approvals, operator authorization, CP workflow state, scheduler truth, or retained-result authority.",
	)
	assertContainsAll(t, "artifact hygiene C3 generated evidence non-authority", artifactHygiene,
		"Generated evidence, `.out`, reports, traces, logs, summaries, support bundles, retained bundles, proof artifacts, and maintenance summaries remain non-authoritative evidence/projection.",
	)
}

func TestWorkstreamC4RuntimeIdentityVaultHandoffGuardrailPostureIsDocumented(t *testing.T) {
	record := workstreamRecord(t, "C")
	decisionRaw := mustRead(t, ".docs/execution_lifecycle/es_execution_admission_model.md")
	decision := compactText(decisionRaw)
	lifecycleContracts := compactText(mustRead(t, ".docs/execution_lifecycle/contracts.md"))
	lifecycleDesign := compactText(mustRead(t, ".docs/execution_lifecycle/design.md"))
	systemContracts := compactText(mustRead(t, ".docs/system_overview/contracts.md"))
	systemBoundaries := compactText(mustRead(t, ".docs/system_overview/boundaries.md"))
	runbook := compactText(mustRead(t, ".docs/supported_local_cp_consumer_runbook.md"))
	remoteAlpha := compactText(mustRead(t, ".docs/system_overview/remote_supported_host_alpha.md"))
	artifactHygiene := compactText(mustRead(t, ".docs/system_overview/artifact_hygiene.md"))
	postureSection := compactDocSection(t, decisionRaw, "## 6. Code-facing guardrail posture", "")

	for _, doc := range []struct {
		label string
		text  string
	}{
		{label: "Workstream C record C4 posture", text: record},
		{label: "Workstream C decision C4 posture", text: decision},
		{label: "lifecycle contracts C4 posture", text: lifecycleContracts},
		{label: "lifecycle design C4 posture", text: lifecycleDesign},
		{label: "system contracts C4 posture", text: systemContracts},
		{label: "system boundaries C4 posture", text: systemBoundaries},
		{label: "CP consumer runbook C4 posture", text: runbook},
	} {
		assertContainsAll(t, doc.label, doc.text,
			"C4 is the focused tests/docs guardrail slice for runtime identity and Vault handoff boundaries.",
			"C4 is guardrail work, not runtime redesign and not live helper execution.",
			"Runtime identity acquisition is workload-side or helper-mediated at runtime, not CP-owned and not IM-owned.",
			"ES may stage non-secret runtime identity and Vault configuration metadata, but ES must not mint, fetch, broker, parse, store, rotate, or validate Vault tokens.",
			"ES must not record or expose JWT-SVID bodies, SPIFFE JWTs, X.509 SVID bodies, private keys, API keys, proof secrets, root tokens, unseal keys, Vault client tokens, or secret payloads through public DTOs, lifecycle responses, retained-result metadata, summaries, logs, reports, `.out`, support bundles, or proof artifacts.",
			"`authority_handoff` may include non-secret credential-location and configuration metadata only.",
			"`authority_handoff` must not carry live credentials, leases, approvals, Vault tokens, Codex credentials, JWT-SVIDs, API keys, or scheduler truth.",
			"Workload-side Vault auth remains workload-side; Vault owns token, secret, and lease authority.",
			"SPIRE owns identity issuance and SVID material.",
			"ES must not expose raw SPIRE socket access to workloads as public ES grammar.",
			"`EXEC_WORKLOAD_IDENTITY_ENDPOINT` remains the workload-facing identity endpoint contract rather than raw SPIRE socket access.",
			"Runtime identity and Vault handoff evidence remains non-authoritative and redacted.",
			"CP may consume runtime identity/Vault handoff evidence, but CP does not own credential acquisition, Vault tokens, SPIRE identity issuance, or ES runtime handoff boundaries.",
			"IM and Maintenance Agent may report diagnostics/readiness/status, but do not own runtime identity or Vault authority.",
			"`control-plane-normal-shell/v1` and `execution_substrate.runtime_profile` compatibility remain preserved unless an explicit migration/versioning plan exists.",
			"Existing workload-auth Remote Alpha helpers remain bounded operator/support surfaces, not ES token brokerage or production Vault readiness.",
		)
	}

	assertContainsAll(t, "Workstream C C4 guardrail posture", postureSection,
		"C4 guardrail tests are intentionally narrow.",
		"runtime identity and Vault handoff public DTO exclusions",
		"non-secret `authority_handoff` credential-location/configuration metadata",
		"workload-zone Vault config as non-secret metadata",
		"`EXEC_WORKLOAD_IDENTITY_ENDPOINT` as the workload-facing endpoint contract",
		"Remote Alpha workload-auth evidence as evidence/projection only",
		"must not redesign runtime identity",
		"must not run live Vault, SPIRE, reset/unseal, workload-auth, renewal, CP proof, IM refresh, support-bundle, binary deployment, or remote mutation helpers",
	)
	assertContainsAll(t, "remote alpha C4 workload-auth evidence", remoteAlpha,
		"Existing workload-auth Remote Alpha helpers remain bounded operator/support surfaces, not ES token brokerage or production Vault readiness.",
		"Runtime identity and Vault handoff evidence remains non-authoritative and redacted.",
		"`readiness_not_claimed.*`: literal `not_claimed`",
	)
	assertContainsAll(t, "artifact hygiene C4 generated evidence non-authority", artifactHygiene,
		"Runtime identity and Vault handoff evidence in summaries, outcome evidence, retained result metadata, support bundles, logs, reports, `.out`, and proof artifacts remains non-authoritative and redacted.",
	)
}

func TestWorkstreamC5StatusLogsResultCancelCompatibilityGuardrailPostureIsDocumented(t *testing.T) {
	record := workstreamRecord(t, "C")
	decisionRaw := mustRead(t, ".docs/execution_lifecycle/es_execution_admission_model.md")
	decision := compactText(decisionRaw)
	lifecycleContractsRaw := mustRead(t, ".docs/execution_lifecycle/contracts.md")
	lifecycleContracts := compactText(lifecycleContractsRaw)
	lifecycleDesign := compactText(mustRead(t, ".docs/execution_lifecycle/design.md"))
	systemContracts := compactText(mustRead(t, ".docs/system_overview/contracts.md"))
	systemBoundaries := compactText(mustRead(t, ".docs/system_overview/boundaries.md"))
	runbook := compactText(mustRead(t, ".docs/supported_local_cp_consumer_runbook.md"))
	artifactHygiene := compactText(mustRead(t, ".docs/system_overview/artifact_hygiene.md"))
	postureSection := compactDocSection(t, decisionRaw, "## 6. Code-facing guardrail posture", "")

	for _, doc := range []struct {
		label string
		text  string
	}{
		{label: "Workstream C record C5 posture", text: record},
		{label: "Workstream C decision C5 posture", text: decision},
		{label: "lifecycle contracts C5 posture", text: lifecycleContracts},
		{label: "lifecycle design C5 posture", text: lifecycleDesign},
		{label: "system contracts C5 posture", text: systemContracts},
		{label: "system boundaries C5 posture", text: systemBoundaries},
		{label: "CP consumer runbook C5 posture", text: runbook},
	} {
		assertContainsAll(t, doc.label, doc.text,
			"C5 is the focused tests/docs guardrail slice for current status/logs/result/cancel compatibility and non-authority posture.",
			"C5 is guardrail work, not runtime redesign, live proof, or remote validation.",
			"Status remains Nomad-backed lifecycle projection and evidence, not CP workflow truth or ES lifecycle-store truth.",
			"Logs remain a bounded current compatibility/evidence surface, not final log architecture, CP run-control truth, or scheduler authority.",
			"Result remains opaque ES-retained output delivery, not CP checkpoint, finalization, or review state.",
			"Cancel remains a bounded ES/Nomad cancellation handoff, not CP intervention authority, operator approval authority, or Temporal workflow truth.",
			"Status/cancel JSON envelopes and successful logs/result headers",
			"live credential/security fields",
			"payload/output",
			"newly sanitized, interpreted, or promoted into authority.",
		)
	}

	assertContainsAll(t, "Workstream C C5 guardrail posture", postureSection,
		"C5 guardrail tests are intentionally narrow.",
		"status/logs/result/cancel response envelopes",
		"successful logs/result outcome-evidence headers",
		"bounded `outcome_evidence` label compatibility",
		"opaque `lifecycle_projection` read-coordination posture",
		"backend-ID non-authority",
		"non-secret `authority_handoff` posture",
		"raw logs/result payload opacity",
		"generated-artifact non-authority",
		"unchanged `control-plane-normal-shell/v1` compatibility",
		"must not redesign status, logs, result, cancel",
		"must not require new sanitization or interpretation of raw logs/result payloads",
		"must not run live proof, remote validation, Vault, SPIRE, reset/unseal, workload-auth, renewal, CP proof, IM refresh, support-bundle, binary deployment, or remote mutation helpers",
	)

	statusSection := compactDocSection(t, lifecycleContractsRaw, "## 7. Status contract", "### Authority handoff read surface")
	logsSection := compactDocSection(t, lifecycleContractsRaw, "## 8. Logs contract", "## 9. Result contract")
	resultSection := compactDocSection(t, lifecycleContractsRaw, "## 9. Result contract", "## 10. Cancel contract")
	cancelSection := compactDocSection(t, lifecycleContractsRaw, "## 10. Cancel contract", "## 11. Run-ID and scheduler lookup contract")

	assertContainsAll(t, "C5 status contract envelope", statusSection,
		"The status JSON envelope remains lifecycle projection and evidence only.",
		"must not add Control Plane run-control grammar",
		"Vault tokens, client/root tokens, unseal keys, JWT-SVIDs, X.509 SVIDs, private keys, API keys, proof secrets, secret payloads, lease IDs, or lease durations",
	)
	assertContainsAll(t, "C5 logs contract envelope", logsSection,
		"The successful response headers remain the logs envelope.",
		"The stdout body remains payload content under the existing compatibility contract",
		"ES does not sanitize, interpret, or promote raw log content into scheduler, CP run-control, credential, or policy authority.",
	)
	assertContainsAll(t, "C5 result contract envelope", resultSection,
		"The successful response headers remain the result envelope.",
		"The bundle body remains opaque output content under the existing compatibility contract",
		"ES does not sanitize, parse, or promote bundle contents into CP checkpoint, finalization, review, scheduler, credential, or policy authority.",
	)
	assertContainsAll(t, "C5 cancel contract envelope", cancelSection,
		"The cancel JSON envelope remains a bounded ES/Nomad handoff receipt.",
		"Control Plane intervention, approval, hold/resume/reject, Temporal, workflow, review, checkpoint, finalization",
		"operator-approval, scheduler authority, or live credential/security fields",
	)
	assertContainsAll(t, "C5 runbook consumption boundary", runbook,
		"Status/cancel JSON envelopes and successful logs/result headers are the compatibility envelopes CP may consume.",
		"Raw logs and result bundles remain payload/output content; CP owns any semantic interpretation above ES",
		"ES does not sanitize or promote that content into run-control authority.",
	)
	assertContainsAll(t, "artifact hygiene C5 generated evidence non-authority", artifactHygiene,
		"Status/logs/result/cancel evidence, generated `.out` files, reports, traces, raw logs, summaries, support bundles, retained bundles, proof artifacts, Remote Alpha summaries, and Maintenance Agent summaries remain non-authoritative evidence/projection.",
		"must not become CP run-control truth, ES lifecycle-store truth, scheduler authority, operator approval authority, credential authority, or the final scheduler/result/log/cancel vocabulary",
	)
}

func TestWorkstreamCLifecycleProjectionAuthorityLabelsAreDocumented(t *testing.T) {
	plans := compactText(mustRead(t, "PLANS.md"))
	checkpoint := compactText(mustRead(t, ".docs/execution_lifecycle/workstream_c7_checkpoint.md"))
	decisionRaw := mustRead(t, ".docs/execution_lifecycle/es_execution_admission_model.md")
	decision := compactText(decisionRaw)
	lifecycleContractsRaw := mustRead(t, ".docs/execution_lifecycle/contracts.md")
	lifecycleContracts := compactText(lifecycleContractsRaw)
	statusSection := compactDocSection(t, lifecycleContractsRaw, "## 7. Status contract", "### Authority handoff read surface")
	fullStatusSection := compactDocSection(t, lifecycleContractsRaw, "## 7. Status contract", "## 8. Logs contract")
	logsSection := compactDocSection(t, lifecycleContractsRaw, "## 8. Logs contract", "## 9. Result contract")
	resultSection := compactDocSection(t, lifecycleContractsRaw, "## 9. Result contract", "## 10. Cancel contract")
	cancelSection := compactDocSection(t, lifecycleContractsRaw, "## 10. Cancel contract", "## 11. Run-ID and scheduler lookup contract")
	systemContracts := compactText(mustRead(t, ".docs/system_overview/contracts.md"))
	systemBoundaries := compactText(mustRead(t, ".docs/system_overview/boundaries.md"))
	runbook := compactText(mustRead(t, ".docs/supported_local_cp_consumer_runbook.md"))

	assertContainsAll(t, "C7 lifecycle projection authority label slice", checkpoint,
		"Lifecycle Projection Authority Labels",
		"Why safe: sharpens existing status/cancel/logs/result non-authority labels while preserving the current Nomad-backed projection model.",
		"Risks: exposing scheduler identifiers, turning projection revision into a write precondition, or implying an ES-owned lifecycle store.",
		"Stop conditions: proposed labels require new Nomad fields, changed lifecycle JSON, changed cancel semantics, or live scheduler validation.",
	)
	assertContainsAll(t, "PLANS lifecycle projection authority labels", plans,
		"Nomad remains authoritative for submitted execution lifecycle; ES must not invent a parallel lifecycle store or scheduler authority.",
		"Callers may compare equality/change for the same run only.",
		"not a Control Plane workflow version or revision",
		"not proof of freshness outside the documented same-run status read model",
		"Control Plane owns orchestration, Temporal workflow state, review, checkpoint, finalization, intervention, and operator-facing control semantics.",
		"IM readiness/profile/support-bundle/provenance artifacts remain evidence/projection/diagnostics only; they do not become ES or CP authority.",
	)
	assertContainsAll(t, "status lifecycle projection authority labels", statusSection,
		"Status is a Nomad-backed projection.",
		"`lifecycle_projection.source` is `nomad`",
		"No alternate successful `lifecycle_projection.source` value is currently documented.",
		"Any future projection source must be recorded in `PLANS.md` and this lifecycle contract before it appears in public status JSON.",
		"`lifecycle_projection.revision` is an opaque same-run read-coordination token",
		"Callers must not parse or order `lifecycle_projection.revision`",
		"Nomad job/allocation identifier or index",
		"not a Control Plane workflow version or revision",
		"scheduler allocation id",
		"result-reference id",
		"proof of global freshness outside the documented same-run status read model",
		"The status JSON envelope remains lifecycle projection and evidence only.",
		"must not add Control Plane run-control grammar",
	)
	assertContainsAll(t, "status reopened seams stay open", fullStatusSection,
		"Lifecycle vocabulary beyond this current Nomad-backed projection",
		"execution locator/allocation projection",
		"retained-result route evolution",
		"runtime identity handoff ownership",
		"workload-zone runtime-config ownership",
		"ARS discovery/index long-term shape remain reopened seams",
	)
	assertContainsAll(t, "status result logs cancel relationship", lifecycleContracts,
		"Status remains Nomad-backed lifecycle projection and evidence, not CP workflow truth or ES lifecycle-store truth.",
		"Logs remain a bounded current compatibility/evidence surface, not final log architecture, CP run-control truth, or scheduler authority.",
		"Result remains opaque ES-retained output delivery, not CP checkpoint, finalization, or review state.",
		"Cancel remains a bounded ES/Nomad cancellation handoff, not CP intervention authority, operator approval authority, or Temporal workflow truth.",
	)
	assertContainsAll(t, "logs route remains separate", logsSection,
		"The successful response headers remain the logs envelope.",
		"The stdout body remains payload content under the existing compatibility contract",
		"ES does not sanitize, interpret, or promote raw log content into scheduler, CP run-control, credential, or policy authority.",
	)
	assertContainsAll(t, "result route remains separate", resultSection,
		"Result availability is evidence/projection for the ES-retained output surface.",
		"`result_not_found` means ES has no retained bundle for that `run_id`; it is not, by itself, Control Plane workflow failure, review failure, checkpoint failure, finalization failure, or Temporal run-control truth.",
		"Logs are not the result contract; stdout remains a separate narrow logs surface.",
		"ES does not add raw logs, proof payloads, support bundle payloads, retained-internal metadata, credentials, environment values, TLS/SPIFFE/Vault material",
	)
	assertContainsAll(t, "cancel remains bounded", cancelSection,
		"Cancel is a bounded Nomad stop request, not a wider cancellation model.",
		"The cancel JSON envelope remains a bounded ES/Nomad handoff receipt.",
		"Cancel does not create a richer cancellation state model.",
		"Cancel does not return proof that the workload has stopped.",
	)
	assertContainsAll(t, "decision lifecycle authority labels", decision,
		"The current documented projection source is `nomad`; any future projection source must be documented before it appears in public status JSON.",
		"`lifecycle_projection.revision` is not a Nomad allocation id, scheduler id, CP workflow version or revision, result-reference id, write guard, or proof of global freshness outside the documented same-run status read model.",
		"Lifecycle vocabulary beyond the current projection",
		"not settled lifecycle architecture",
	)
	assertContainsAll(t, "system contract lifecycle authority labels", systemContracts,
		"not a Control Plane workflow version or revision",
		"not proof of global freshness outside the documented same-run status read model",
	)
	assertContainsAll(t, "system boundary lifecycle authority labels", systemBoundaries,
		"CP workflow versions or revisions",
		"freshness proof outside the documented same-run read model",
	)
	assertContainsAll(t, "CP consumer lifecycle authority labels", runbook,
		"Status responses include `lifecycle_projection.source` and",
		"must treat the revision as opaque.",
		"not a CP workflow version or revision",
		"not proof of global freshness outside the documented same-run ES status read model",
		"CP may use these labels to tell whether ES served a Nomad-backed status projection, accepted Nomad stop request receipt, Nomad task stdout body, or opaque ES-retained result bundle.",
	)

	for _, doc := range []struct {
		label string
		text  string
	}{
		{label: "status authority labels", text: statusSection},
		{label: "decision authority labels", text: decision},
		{label: "system contract authority labels", text: systemContracts},
		{label: "system boundary authority labels", text: systemBoundaries},
		{label: "CP runbook authority labels", text: runbook},
	} {
		assertContainsNone(t, doc.label, doc.text,
			"`lifecycle_projection.revision` is a scheduler id",
			"`lifecycle_projection.revision` is a write guard",
			"`lifecycle_projection.revision` is a CP workflow version",
			"`lifecycle_projection.revision` proves global freshness",
			"status is CP workflow truth",
			"status is ES lifecycle-store truth",
		)
	}
}

func TestWorkstreamC6AdmissionPolicyLayerV0ContractIsDocumented(t *testing.T) {
	record := workstreamRecord(t, "C")
	decisionRaw := mustRead(t, ".docs/execution_lifecycle/es_execution_admission_model.md")
	decision := compactText(decisionRaw)
	lifecycleContracts := compactText(mustRead(t, ".docs/execution_lifecycle/contracts.md"))
	systemBoundaries := compactText(mustRead(t, ".docs/system_overview/boundaries.md"))
	artifactStorage := compactText(mustRead(t, ".docs/system_overview/artifact_publication_storage.md"))
	mvp := compactText(mustRead(t, ".docs/mvp.md"))

	assertContainsAll(t, "Workstream C record C6 admission policy posture", record,
		"C6 is the focused ES Admission Policy Layer v0 slice.",
		"It is a Workstream C admission extension, not the Workstream D CGS/EGS policy-language redesign.",
		"small ES-owned, replaceable policy-evaluation seam in the shared `:prepare`/`:submit` admission path",
		"one built-in selected-pattern static-script content policy to prove the seam",
		"ES remains the final admission-policy gate for ES-bound executions.",
		"Control Plane may later preflight or render ES policy decisions, but CP is not the final ES admission gate.",
		"IM remains readiness, provenance, and diagnostics only.",
		"only through the explicit ARS payload digest relationship already discovered and cross-checked by ES admission",
		"the ES-owned Admission Policy Layer v0 seam",
	)

	for _, doc := range []struct {
		label string
		text  string
	}{
		{label: "Workstream C6 decision metadata", text: decision},
		{label: "lifecycle contracts C6 metadata", text: lifecycleContracts},
	} {
		assertContainsAll(t, doc.label, doc.text,
			"ES Admission Policy Layer v0",
			"`execution-substrate.admission.selected-destructive-shell-command/v1`",
			"`destructive_shell_command_denied`",
			"`destructive shell command denied by admission policy`",
			"`admission_policy_input_unavailable`",
			"`admission policy input unavailable`",
			"Policy denial",
			"redacted",
		)
	}

	assertContainsAll(t, "Workstream C6 decision prepare and submit path", decision,
		"C6 adds a small ES-local, replaceable policy-evaluation seam in the shared `:prepare`/`:submit` admission path",
		"`POST /v1/executions:prepare` validates the request",
		"evaluates ES Admission Policy Layer v0",
		"It still creates no run object, staging root, scheduler handoff, or proto-execution state.",
		"`POST /v1/executions:submit` reuses the full prepare path",
		"Submit cannot bypass the admission policy path used by prepare",
		"Policy denial occurs before payload staging or Nomad submission.",
	)
	assertContainsAll(t, "lifecycle contracts C6 prepare and submit path", lifecycleContracts,
		"`:prepare` evaluates ES Admission Policy Layer v0 before success.",
		"No `run_id` is created.",
		"No scheduler handoff occurs.",
		"Submit reuses the same ES Admission Policy Layer v0 path as `:prepare`",
		"cannot bypass a policy that `:prepare` would deny.",
		"Policy denial happens before payload staging, mount staging, run ID creation, and Nomad submission.",
	)
	assertContainsAll(t, "system boundary C6 final authority", systemBoundaries,
		"ES Admission Policy Layer v0 is ES-owned final admission policy for ES-bound executions.",
		"does not make CP the final ES gate",
		"make IM policy/run/runtime authority",
	)
	assertContainsAll(t, "artifact storage C6 bounded payload relationship", artifactStorage,
		"ES Admission Policy Layer v0 may cause `:prepare` to read bounded static-script payload text",
		"explicit evidence/payload relationship",
		"does not treat `artifact_digest` as a payload locator",
	)
	assertContainsAll(t, "MVP C6 admission policy row", mvp,
		"ES Admission Policy Layer v0 | `stable contract`",
		"redacted denials and one bounded selected-pattern static-script content policy",
		"CP may preflight or render ES decisions later, but CP does not become the final ES gate; IM remains readiness/provenance/diagnostics only.",
	)
}

func TestWorkstreamC6ConfigurableAdmissionPolicyInputsAreDocumented(t *testing.T) {
	record := workstreamRecord(t, "C")
	decision := compactText(mustRead(t, ".docs/execution_lifecycle/es_execution_admission_model.md"))
	lifecycleContracts := compactText(mustRead(t, ".docs/execution_lifecycle/contracts.md"))
	configuration := compactText(mustRead(t, ".docs/system_overview/configuration.md"))
	mvp := compactText(mustRead(t, ".docs/mvp.md"))

	for _, doc := range []struct {
		label string
		text  string
	}{
		{label: "Workstream C record C6 configurable inputs", text: record},
		{label: "Workstream C6 decision configurable inputs", text: decision},
		{label: "lifecycle contracts C6 configurable inputs", text: lifecycleContracts},
	} {
		assertContainsAll(t, doc.label, doc.text,
			"configurable-input follow-up",
			"`execution-substrate.admission.configured-static-script-literal-deny/v1`",
			"`configured_static_script_content_denied`",
			"`static script content denied by admission policy`",
			"`disabled`",
			"`enforce`",
			"`static_script_payload_text`",
			"ES deployment/admin config",
			"CP does not define or supply",
			"IM remains readiness",
			"request",
			"OPA/Rego",
			"DSL",
			"CGS `id.conf` reuse",
			"external evaluator",
			"Denials remain redacted",
		)
	}

	assertContainsAll(t, "configuration C6 configurable input shape", configuration,
		"optional `admission_policy.configured_static_script_literal_deny` is ES deployment/admin configuration for one built-in ES admission policy only",
		"supported `mode` values are `disabled` and `enforce`",
		"the only supported `input_class` is `static_script_payload_text`",
		"current validation limits are at most 32 entries, at most 256 bytes per literal, and at most 64 bytes per entry ID",
		"not whitespace-only",
		"format/invisible",
		"regex-looking text is treated as literal text",
		"there is no regex, glob, shell expression, Boolean policy language, OPA/Rego, DSL, customer policy bundle, external evaluator service",
		"request-supplied policy entry",
		"CP-supplied policy input",
		"CGS `id.conf` reuse",
	)

	assertContainsAll(t, "MVP C6 configurable input non-claims", mvp,
		"configurable inputs for built-in ES admission policies as a broad policy engine",
		"evaluator injection hook",
		"OPA/Rego",
		"DSL",
		"regex engine",
		"customer-authored policy bundles",
		"external evaluator service",
		"CP-defined ES policy input",
		"request-supplied policy entries",
		"CGS `id.conf` reuse",
	)
}

func TestWorkstreamC6AdmissionPolicyNonClaimsAreDocumented(t *testing.T) {
	decision := compactText(mustRead(t, ".docs/execution_lifecycle/es_execution_admission_model.md"))
	lifecycleContracts := compactText(mustRead(t, ".docs/execution_lifecycle/contracts.md"))
	mvp := compactText(mustRead(t, ".docs/mvp.md"))

	nonClaims := []string{
		"not universal malware detection",
		"complete command sandboxing",
		"proof that all destructive behavior is impossible",
		"production endpoint security proof",
		"runtime identity or Vault proof",
		"IM support-bundle proof",
		"public/demo readiness proof",
		"independent audit proof",
		"cancel/failure/intervention proof",
		"CP-owned final ES policy",
		"IM-owned policy authority",
		"semantic understanding of all Control Plane prompts, workspaces, scripts",
	}
	for _, doc := range []struct {
		label string
		text  string
	}{
		{label: "Workstream C6 decision non-claims", text: decision},
		{label: "lifecycle contracts C6 non-claims", text: lifecycleContracts},
	} {
		assertContainsAll(t, doc.label, doc.text, nonClaims...)
	}
	assertContainsAll(t, "MVP C6 non-claims", mvp,
		"The current MVP does not claim:",
		"ES Admission Policy Layer v0 as universal malware detection",
		"complete command sandboxing",
		"proof that all destructive behavior is impossible",
		"production endpoint security proof",
		"runtime identity or Vault proof",
		"IM support-bundle proof",
		"public/demo readiness proof",
		"independent audit proof",
		"cancel/failure/intervention proof",
		"CP-owned final ES policy",
		"IM-owned policy authority",
		"semantic understanding of all Control Plane prompts, workspaces, scripts",
	)

	for _, doc := range []struct {
		label string
		text  string
	}{
		{label: "Workstream C6 decision overclaims", text: decision},
		{label: "lifecycle contracts C6 overclaims", text: lifecycleContracts},
		{label: "MVP C6 overclaims", text: mvp},
	} {
		assertContainsNone(t, doc.label, doc.text,
			"ES Admission Policy Layer v0 is universal malware detection",
			"ES Admission Policy Layer v0 proves all destructive behavior is impossible",
			"ES Admission Policy Layer v0 is production endpoint security proof",
			"Control Plane is the final ES admission gate",
			"IM owns ES admission policy",
			"ES understands all Control Plane prompts, workspaces, and scripts",
		)
	}
}

func TestWorkstreamC0ExternalAuthorityAndEvidenceNonOwnershipIsDocumented(t *testing.T) {
	plans := compactText(mustRead(t, "PLANS.md"))
	decision := compactText(mustRead(t, ".docs/execution_lifecycle/es_execution_admission_model.md"))
	contracts := compactText(mustRead(t, ".docs/system_overview/contracts.md"))
	boundaries := compactText(mustRead(t, ".docs/system_overview/boundaries.md"))
	lifecycleContracts := compactText(mustRead(t, ".docs/execution_lifecycle/contracts.md"))
	lifecycleDesign := compactText(mustRead(t, ".docs/execution_lifecycle/design.md"))
	runbook := compactText(mustRead(t, ".docs/supported_local_cp_consumer_runbook.md"))
	mvp := compactText(mustRead(t, ".docs/mvp.md"))
	artifactHygiene := compactText(mustRead(t, ".docs/system_overview/artifact_hygiene.md"))

	for _, doc := range []struct {
		label string
		text  string
	}{
		{label: "PLANS external authority", text: plans},
		{label: "Workstream C decision external authority", text: decision},
		{label: "system contracts external authority", text: contracts},
		{label: "system boundaries external authority", text: boundaries},
		{label: "lifecycle contracts external authority", text: lifecycleContracts},
		{label: "lifecycle design external authority", text: lifecycleDesign},
		{label: "CP consumer runbook external authority", text: runbook},
		{label: "MVP external authority", text: mvp},
	} {
		assertContainsAll(t, doc.label, doc.text,
			"Control Plane owns orchestration, Temporal workflow state, review, checkpoint, finalization, intervention, and operator-facing control semantics.",
			"CP consumes accepted ES surfaces but does not define ES core contracts.",
			"IM readiness/profile/support-bundle/provenance artifacts remain evidence/projection/diagnostics only; they do not become ES or CP authority.",
			"Maintenance Agent summaries remain scheduler/notifier/local-evidence outputs only and do not define ES route semantics.",
		)
	}

	for _, doc := range []struct {
		label string
		text  string
	}{
		{label: "Workstream C decision ES non-ownership", text: decision},
		{label: "system contracts ES non-ownership", text: contracts},
		{label: "system boundaries ES non-ownership", text: boundaries},
		{label: "lifecycle contracts ES non-ownership", text: lifecycleContracts},
	} {
		assertContainsAll(t, doc.label, doc.text,
			"ES must not absorb CP attempt/review/checkpoint/finalization semantics.",
			"ES must not become a Vault token broker, Codex credential broker, IM readiness authority, CP run-control authority, or maintenance-agent authority.",
		)
	}

	for _, doc := range []struct {
		label string
		text  string
	}{
		{label: "Workstream C decision generated evidence", text: decision},
		{label: "system contracts generated evidence", text: contracts},
		{label: "system boundaries generated evidence", text: boundaries},
		{label: "lifecycle design generated evidence", text: lifecycleDesign},
		{label: "artifact hygiene generated evidence", text: artifactHygiene},
	} {
		assertContainsAll(t, doc.label, doc.text,
			"Generated evidence, `.out`, reports, traces, logs, summaries, support bundles, retained bundles, proof artifacts, and maintenance summaries remain non-authoritative evidence/projection.",
		)
	}

	assertContainsAll(t, "artifact hygiene maintenance summaries", artifactHygiene,
		"Maintenance Agent summaries, if produced by an external scheduler/notifier or local-evidence summarizer, remain scheduler/notifier/local-evidence outputs only.",
		"They do not define ES route semantics, renewal semantics, runtime authority, IM readiness/provenance authority, CP run-control authority, or maintenance-agent authority inside this repository.",
	)
}

func TestWorkstreamDPolicyAuthorizationBoundaryClarificationIsDocumented(t *testing.T) {
	plansRaw := mustRead(t, "PLANS.md")
	contractsRaw := mustRead(t, ".docs/system_overview/contracts.md")
	boundariesRaw := mustRead(t, ".docs/system_overview/boundaries.md")
	architectureRaw := mustRead(t, ".docs/system_overview/architecture.md")
	configurationRaw := mustRead(t, ".docs/system_overview/configuration.md")
	admissionModelRaw := mustRead(t, ".docs/execution_lifecycle/es_execution_admission_model.md")
	implementationRaw := mustRead(t, ".docs/execution_lifecycle/implementation.md")
	lifecycleContractsRaw := mustRead(t, ".docs/execution_lifecycle/contracts.md")

	plans := compactText(plansRaw)
	architecture := compactText(architectureRaw)
	configuration := compactText(configurationRaw)
	admissionModel := compactText(admissionModelRaw)
	implementation := compactText(implementationRaw)
	lifecycleContracts := compactText(lifecycleContractsRaw)
	workstreamD := compactDocSection(t, plansRaw, "### Workstream D - Policy And Authorization Reset", "### Workstream E - Lookup And Config Indirection Reset")
	workstreamE := compactDocSection(t, plansRaw, "### Workstream E - Lookup And Config Indirection Reset", "### Workstream F - Runtime Identity Handoff Reset")
	workstreamF := compactDocSection(t, plansRaw, "### Workstream F - Runtime Identity Handoff Reset", "## Host And Runtime Boundary Rules")

	egsContractSection := compactDocSection(t, contractsRaw, "## 8. EGS Policy Contract", "## 9. CGS Authorization Contract")
	cgsContractSection := compactDocSection(t, contractsRaw, "## 9. CGS Authorization Contract", "## 10. Runtime Identity Handoff Contract")
	egsBoundarySection := compactDocSection(t, boundariesRaw, "## 9. EGS boundary", "## 10. CGS boundary")
	cgsBoundarySection := compactDocSection(t, boundariesRaw, "## 10. CGS boundary", "## 11. Cross-cutting packages that are not service boundaries")
	esBoundarySection := compactDocSection(t, boundariesRaw, "## 8. ES boundary", "## 9. EGS boundary")

	dIndex := strings.Index(plansRaw, "### Workstream D - Policy And Authorization Reset")
	eIndex := strings.Index(plansRaw, "### Workstream E - Lookup And Config Indirection Reset")
	fIndex := strings.Index(plansRaw, "### Workstream F - Runtime Identity Handoff Reset")
	if dIndex == -1 || eIndex == -1 || fIndex == -1 {
		t.Fatalf("expected Workstream D/E/F headings in PLANS")
	}
	if !(dIndex < eIndex && eIndex < fIndex) {
		t.Fatalf("expected Workstream D to remain ordered before E and F")
	}

	assertContainsAll(t, "PLANS Workstream D ordering", plans,
		"Workstream D - Policy And Authorization Reset",
		"Workstream E - Lookup And Config Indirection Reset",
		"Workstream F - Runtime Identity Handoff Reset",
	)
	assertContainsAll(t, "Workstream D section", workstreamD,
		"Dependencies: - Workstream A - Workstream C",
	)
	assertContainsAll(t, "Workstream E section", workstreamE,
		"Dependencies: - Workstream A - Workstream B - Workstream C - Workstream D",
	)
	assertContainsAll(t, "Workstream F section", workstreamF,
		"Dependencies: - Workstream C - Workstream D - Workstream E",
	)

	assertContainsAll(t, "EGS contracts section", egsContractSection,
		"Publish the signed runtime-trust payload that ES enforces at admission time for signer/artifact trust only.",
		"EGS owns runtime-trust publication and signing only.",
		"EGS publication metadata remains outside the signed `runtime_trust` payload.",
		"It does not carry authorization decisions, runtime auth-plan material, or ES runtime handoff facts.",
	)

	assertContainsAll(t, "CGS contracts section", cgsContractSection,
		"Provide a direct authorize-only decision boundary for credential-related access.",
		"ES is not a current CGS consumer in the active ES hot path.",
		"CGS is a direct authorize-only boundary.",
		"The authenticated caller identity must equal `workload.workload_identity_id`.",
		"`requested_capabilities` currently allows only `vault:read`.",
		"Current authorize responses include no secret material and no runtime auth-plan payload.",
		"`id.conf` is an active local policy input and current authorize-shape dependency",
		"final core authorization contract or final policy architecture.",
	)

	assertContainsAll(t, "EGS boundary section", egsBoundarySection,
		"Signed signer/artifact runtime-trust publication plus separate EGS-owned publication metadata",
		"publication metadata remaining separate and outside the signed payload",
		"Authorization decisions or runtime auth-plan shaping",
		"ES runtime handoff facts",
	)

	assertContainsAll(t, "CGS boundary section", cgsBoundarySection,
		"Direct authorize-only decisions for current requested capabilities",
		"Workload-bound caller/workload identity matching on the live request path",
		"CGS is active today, but it is not part of the current ES hot path",
		"caller/workload identity interpretation",
		"Runtime auth-plan shaping",
		"Credential material, Vault token material, or JWT-SVID material",
		"declared complete production policy grammar or final policy architecture",
	)
	assertContainsNone(t, "CGS boundary section", cgsBoundarySection,
		"workload vault configuration shapes",
	)

	assertContainsAll(t, "ES boundary section", esBoundarySection,
		"Composition across startup-owned runtime-config references, ARS, and EGS during prepare and submit, with CGS explicitly outside the current hot path",
		"CGS authorize decisions, policy-approval state, or runtime auth-plan truth as ES hot-path admission inputs, `authority_handoff` facts, `outcome_evidence`, or producer-contract truth",
		"`verification.derivation_attestation.*` and `verification.workload_identity_binding.*` config/startup verifier shapes are residue from earlier admission forms.",
	)

	assertContainsAll(t, "architecture policy flow", architecture,
		"EGS publishes signed runtime trust for signer and artifact trust only, plus separate EGS-owned publication metadata outside the signed payload.",
		"CGS provides a direct authorize-only surface backed by authenticated caller/workload identity matching and explicit `id.conf` subject records.",
		"CGS responses remain bounded to decision and audit facts; they do not become runtime auth plans or ES runtime handoff facts.",
		"CGS is active, but it is intentionally not part of the current ES hot path.",
		"This current split clarifies today’s boundary only. It does not settle Workstream E runtime-config ownership or Workstream F runtime-identity handoff ownership.",
	)

	assertContainsAll(t, "configuration residue note", configuration,
		"`verification.derivation_attestation.*` and `verification.workload_identity_binding.*` remain required because the current ES startup path still constructs those verifier shapes",
		"those two verifier config groups are current configuration/startup-verifier residue, not active shared-kernel authorization meaning, not CGS policy truth, and not a settlement of Workstream E runtime-config ownership or Workstream F runtime-identity handoff",
	)

	assertContainsAll(t, "admission model policy split", admissionModel,
		"ES admission composition remains CGS-independent in the current hot path.",
		"This decision does not settle Workstream E runtime-config ownership or Workstream F runtime-identity handoff ownership.",
		"CGS authorize remains outside the current hot path.",
	)

	assertContainsAll(t, "implementation residue and independence", implementation,
		"The current `verification.derivation_attestation` and `verification.workload_identity_binding` config groups remain startup verifier residue from earlier admission shapes.",
		"they do not add active shared-kernel authorization meaning, CGS policy meaning, Workstream E runtime-config ownership, or Workstream F runtime-identity ownership.",
		"CGS is not a current read dependency of `Prepare` or `Submit`",
		"`Prepare` does not call CGS or consume a CGS authorize response.",
		"`Submit` does not call CGS, and `authority_handoff` remains assembled from ES-selected runtime facts rather than CGS authorize output or policy-approval state.",
	)

	assertContainsAll(t, "lifecycle contracts producer non-authority", lifecycleContracts,
		"`not_policy_truth`",
		"The declaration must not expose Nomad job IDs, allocation IDs, task IDs, host paths, result filesystem paths, Vault tokens, Codex credential material, JWT-SVIDs, leases, or policy approval state.",
	)
}

func TestWorkstreamDVersioningGuardrailBeforeSemanticExpansionIsDocumented(t *testing.T) {
	contractsRaw := mustRead(t, ".docs/system_overview/contracts.md")
	boundariesRaw := mustRead(t, ".docs/system_overview/boundaries.md")
	architectureRaw := mustRead(t, ".docs/system_overview/architecture.md")
	configurationRaw := mustRead(t, ".docs/system_overview/configuration.md")
	admissionModelRaw := mustRead(t, ".docs/execution_lifecycle/es_execution_admission_model.md")

	recordD := workstreamRecord(t, "D")
	egsContractSection := compactDocSection(t, contractsRaw, "## 8. EGS Policy Contract", "## 9. CGS Authorization Contract")
	cgsContractSection := compactDocSection(t, contractsRaw, "## 9. CGS Authorization Contract", "## 10. Runtime Identity Handoff Contract")
	esBoundarySection := compactDocSection(t, boundariesRaw, "## 8. ES boundary", "## 9. EGS boundary")
	egsBoundarySection := compactDocSection(t, boundariesRaw, "## 9. EGS boundary", "## 10. CGS boundary")
	cgsBoundarySection := compactDocSection(t, boundariesRaw, "## 10. CGS boundary", "## 11. Cross-cutting packages that are not service boundaries")
	architecture := compactText(architectureRaw)
	configuration := compactText(configurationRaw)
	admissionModel := compactText(admissionModelRaw)

	assertContainsAll(t, "Workstream D record versioning direction", recordD,
		"CGS v1 compatibility surface",
		"EGS v1 compatibility surface",
		"Semantic expansion requires explicit versioning before implementation.",
		"`audit.policy_version` and EGS `publication.version` as service-owned audit/publication metadata, not transport/schema/API versioning.",
		"`id.conf` as current-CGS-v1 compatibility/config residue",
		"allow/deny plus opaque decision reference and expiry",
		"D1 does not settle Workstream E runtime-config ownership or Workstream F runtime-identity handoff.",
	)

	assertContainsAll(t, "EGS contracts versioning guardrail", egsContractSection,
		"`publication.version` and `publication.update_revision` are EGS-owned publication metadata. They are not trust-contract, schema, or API versioning for the current EGS surface.",
		"The current route plus wrapper/payload shape are the live EGS v1 compatibility surface.",
		"Semantic expansion of the EGS trust surface requires explicit wrapper/payload versioning before implementation; do not widen the current v1 surface in place.",
	)

	assertContainsAll(t, "CGS contracts versioning guardrail", cgsContractSection,
		"`audit.policy_version` inside `audit` is CGS audit/evaluation metadata. It is not transport, schema, or API versioning for the current authorize surface.",
		"The current request/response shape is the live CGS v1 compatibility surface.",
		"`id.conf` remains current-CGS-v1 compatibility/config residue even while it is active today.",
		"Semantic expansion of the CGS authorize surface requires explicit versioning before implementation; do not widen the current v1 surface in place.",
	)

	assertContainsAll(t, "EGS boundary versioning guardrail", egsBoundarySection,
		"The current route plus wrapper/payload shape are the live EGS v1 compatibility surface.",
		"`publication.version` and `publication.update_revision` are EGS publication metadata, not trust-contract/schema/API versioning for that surface.",
		"Semantic expansion of the EGS trust surface requires explicit wrapper/payload versioning before implementation; do not widen the current v1 surface in place.",
	)

	assertContainsAll(t, "CGS boundary versioning guardrail", cgsBoundarySection,
		"The current request/response shape is the live CGS v1 compatibility surface.",
		"`audit.policy_version` is CGS audit/evaluation metadata, not transport/schema/API versioning.",
		"`id.conf` remains current-CGS-v1 compatibility/config residue even while it is active today.",
		"Semantic expansion of the CGS authorize surface requires explicit versioning before implementation; do not widen the current v1 surface in place.",
	)

	assertContainsAll(t, "architecture D1 versioning guardrail", architecture,
		"The current `GET /v1/trust-model` and `POST /v1/credential/authorize` surfaces are v1 compatibility surfaces.",
		"`publication.version` and `audit.policy_version` are service-owned metadata, not trust-contract or transport/API versioning.",
		"D1 preserves that ES consumes no CGS facts.",
		"allow/deny plus opaque decision reference and expiry",
		"runtime auth plans, workload-vault fields, runtime-config refs, credential material, or identity-handoff facts.",
	)

	assertContainsAll(t, "configuration D1 residue note", configuration,
		"current-CGS-v1 compatibility/config residue for the current authorize surface",
		"not documented as transport/schema/API versioning or final repo-wide policy language",
	)

	assertContainsAll(t, "ES boundary D1 guardrail", esBoundarySection,
		"D1 keeps ES consuming no CGS facts.",
		"separately versioned bounded authorization fact such as allow/deny plus opaque decision reference and expiry",
		"`audit.policy_version`",
		"runtime auth-plan material",
		"workload-vault fields",
		"runtime-config refs",
		"identity-handoff facts",
	)

	assertContainsAll(t, "admission model D1 guardrail", admissionModel,
		"D1a preserves that ES consumes no CGS facts.",
		"any later ES-consumed authorization fact must be separately versioned and bounded",
		"current CGS v1 authorize shape, subject grammar, or audit fields.",
		"This decision does not settle Workstream E runtime-config ownership or Workstream F runtime-identity handoff ownership.",
	)
}

func TestWorkstreamD1bCGSV2AuthorizeContractDesignIsDocumented(t *testing.T) {
	contractsRaw := mustRead(t, ".docs/system_overview/contracts.md")
	boundariesRaw := mustRead(t, ".docs/system_overview/boundaries.md")
	architectureRaw := mustRead(t, ".docs/system_overview/architecture.md")
	configurationRaw := mustRead(t, ".docs/system_overview/configuration.md")
	admissionModelRaw := mustRead(t, ".docs/execution_lifecycle/es_execution_admission_model.md")

	recordD := workstreamRecord(t, "D")
	egsContractSection := compactDocSection(t, contractsRaw, "## 8. EGS Policy Contract", "## 9. CGS Authorization Contract")
	cgsContractSection := compactDocSection(t, contractsRaw, "## 9. CGS Authorization Contract", "## 10. Runtime Identity Handoff Contract")
	esBoundarySection := compactDocSection(t, boundariesRaw, "## 8. ES boundary", "## 9. EGS boundary")
	egsBoundarySection := compactDocSection(t, boundariesRaw, "## 9. EGS boundary", "## 10. CGS boundary")
	cgsBoundarySection := compactDocSection(t, boundariesRaw, "## 10. CGS boundary", "## 11. Cross-cutting packages that are not service boundaries")
	architecture := compactText(architectureRaw)
	configuration := compactText(configurationRaw)
	admissionModel := compactText(admissionModelRaw)

	assertContainsAll(t, "Workstream D1b design-only plan", recordD,
		"D1b is an accepted docs/tests-only slice on that seam",
		"keep the current `POST /v1/credential/authorize` route and wire shape as CGS v1 compatibility",
		"define any future CGS v2 authorize contract only at design level",
		"require explicit versioning before any behavior change lands",
		"allow/deny, an opaque decision reference, and expiry or another bounded freshness indicator if justified",
		"audit/evaluation metadata on that fact remains non-authoritative outside CGS",
		"runtime auth plans",
		"Vault token material",
		"JWT-SVIDs",
		"credential payloads",
		"scheduler facts",
		"ES lifecycle/admission facts",
		"runtime-config refs",
		"workload-zone Vault ownership facts",
		"identity-handoff facts",
		"Control Plane review/approval/checkpoint/finalization semantics",
		"does not rewrite its grammar or evaluation",
		"does not expand EGS beyond signer/artifact runtime-trust publication",
		"D1 does not settle Workstream E runtime-config ownership or Workstream F runtime-identity handoff.",
	)

	assertContainsAll(t, "CGS D1b contract design", cgsContractSection,
		"D1b is design-only and docs/tests-only.",
		"It does not implement CGS v2 or change the current `POST /v1/credential/authorize` route, DTO, wire shape, or `id.conf` evaluation behavior.",
		"The current `POST /v1/credential/authorize` request/response shape therefore remains the live CGS v1 compatibility surface until an explicitly versioned replacement exists.",
		"If a future CGS v2 authorize contract is implemented, it must be explicitly versioned before behavior changes land.",
		"allow/deny result",
		"opaque decision reference",
		"expiry or another bounded freshness indicator if justified",
		"audit/evaluation metadata that remains non-authoritative outside CGS",
		"runtime auth plans",
		"Vault token material",
		"JWT-SVIDs",
		"credential payloads",
		"scheduler facts",
		"ES lifecycle/admission facts",
		"runtime-config refs",
		"workload-zone Vault ownership facts",
		"identity-handoff facts",
		"Control Plane review/approval/checkpoint/finalization semantics",
		"ES remains a non-consumer in D1b.",
		"`id.conf` evaluation behavior",
		"D1b does not expand EGS beyond signer/artifact runtime-trust publication and does not settle Workstream E runtime-config ownership or Workstream F runtime-identity handoff.",
	)

	assertContainsAll(t, "CGS D1b boundary design", cgsBoundarySection,
		"Scheduler facts or ES lifecycle/admission facts",
		"Runtime-config refs or workload-zone Vault ownership facts",
		"Credential material, Vault token material, or JWT-SVID material",
		"Credential payloads",
		"Control Plane review/approval/checkpoint/finalization semantics",
		"D1b is design-only and docs/tests-only.",
		"The current `POST /v1/credential/authorize` shape remains CGS v1 compatibility",
		"any future CGS v2 authorize contract must be explicitly versioned before behavior changes land",
		"D1b keeps ES as a non-consumer.",
		"allow/deny, opaque decision reference, expiry or another bounded freshness indicator if justified",
		"audit/evaluation metadata that remains non-authoritative outside CGS",
		"D1b does not rewrite the current `id.conf` grammar or evaluation and does not expand EGS beyond signer/artifact runtime-trust publication.",
	)

	assertContainsAll(t, "architecture D1b design guardrail", architecture,
		"D1 preserves that ES consumes no CGS facts.",
		"D1b keeps any future CGS v2 authorize contract design-only.",
		"allow/deny, opaque decision reference, and expiry or another bounded freshness indicator if justified",
		"audit/evaluation metadata remaining non-authoritative outside CGS",
		"Vault token material",
		"JWT-SVIDs",
		"credential payloads",
		"scheduler facts",
		"ES lifecycle/admission facts",
		"workload-zone Vault ownership facts",
		"Control Plane review/approval/checkpoint/finalization semantics",
		"D1b does not expand EGS beyond signer/artifact runtime-trust publication.",
		"This current split clarifies today’s boundary only. It does not settle Workstream E runtime-config ownership or Workstream F runtime-identity handoff ownership.",
	)

	assertContainsAll(t, "configuration D1b id.conf residue note", configuration,
		"that checked-in file and `policy.id_conf_path` are current-CGS-v1 compatibility/config residue for the current authorize surface",
		"D1b does not rewrite the current `id.conf` grammar or evaluation and does not promote `id.conf` into repo-wide future policy language",
	)

	assertContainsAll(t, "ES boundary D1b non-consumer guardrail", esBoundarySection,
		"D1 keeps ES consuming no CGS facts.",
		"D1b keeps that future fact design-only.",
		"allow/deny, opaque decision reference, expiry or another bounded freshness indicator if justified",
		"audit/evaluation metadata that remains non-authoritative outside CGS",
		"JWT-SVIDs",
		"credential payloads",
		"scheduler facts",
		"ES lifecycle/admission facts",
		"workload-zone Vault ownership facts",
		"Control Plane review/approval/checkpoint/finalization semantics",
	)

	assertContainsAll(t, "admission model D1b design-only guardrail", admissionModel,
		"D1a preserves that ES consumes no CGS facts.",
		"D1b keeps any future CGS v2 authorize contract design-only.",
		"allow/deny, opaque decision reference, and expiry or another bounded freshness indicator if justified",
		"audit/evaluation metadata remaining non-authoritative outside CGS",
		"runtime auth plans",
		"scheduler facts",
		"ES lifecycle/admission facts",
		"runtime-config refs",
		"workload-zone Vault ownership facts",
		"identity-handoff facts",
		"Control Plane review/approval/checkpoint/finalization semantics",
		"This decision does not settle Workstream E runtime-config ownership or Workstream F runtime-identity handoff ownership.",
	)

	assertContainsAll(t, "EGS D1b non-expansion contract", egsContractSection,
		"D1b does not expand this EGS surface.",
		"EGS remains signer/artifact runtime-trust publication plus separate EGS-owned publication metadata only.",
	)

	assertContainsAll(t, "EGS D1b non-expansion boundary", egsBoundarySection,
		"D1b does not expand the EGS boundary.",
		"EGS remains signer/artifact runtime-trust publication plus separate EGS-owned publication metadata only.",
		"D1b keeps that surface design-stable at signer/artifact runtime trust only",
	)
}

func TestWorkstreamD1cEGSVersionedRuntimeTrustWrapperDesignIsDocumented(t *testing.T) {
	contractsRaw := mustRead(t, ".docs/system_overview/contracts.md")
	boundariesRaw := mustRead(t, ".docs/system_overview/boundaries.md")
	architectureRaw := mustRead(t, ".docs/system_overview/architecture.md")
	configurationRaw := mustRead(t, ".docs/system_overview/configuration.md")
	admissionModelRaw := mustRead(t, ".docs/execution_lifecycle/es_execution_admission_model.md")

	recordD := workstreamRecord(t, "D")
	egsContractSection := compactDocSection(t, contractsRaw, "## 8. EGS Policy Contract", "## 9. CGS Authorization Contract")
	esBoundarySection := compactDocSection(t, boundariesRaw, "## 8. ES boundary", "## 9. EGS boundary")
	egsBoundarySection := compactDocSection(t, boundariesRaw, "## 9. EGS boundary", "## 10. CGS boundary")
	architecture := compactText(architectureRaw)
	configuration := compactText(configurationRaw)
	admissionModel := compactText(admissionModelRaw)

	assertContainsAll(t, "Workstream D1c design-only plan", recordD,
		"D1c is an accepted docs/tests-only slice on that seam",
		"keep the current `GET /v1/trust-model` route plus wrapper/payload shape as EGS v1 compatibility",
		"define any future EGS versioned runtime-trust wrapper only at design level",
		"require explicit wrapper/payload/versioning before any semantic expansion lands",
		"EGS v1 publishing signed `runtime_trust` signer/artifact trust only",
		"EGS publication metadata remains outside the signed runtime-trust payload",
		"`publication.version` remains service-owned publication metadata rather than trust-contract/schema/API versioning",
		"signed runtime-trust payload facts, unsigned publication/discovery metadata, compatibility routing or API version, and non-authoritative service metadata",
		"CGS authorization decisions",
		"runtime auth plans",
		"Vault token material",
		"JWT-SVIDs",
		"credential payloads",
		"scheduler truth",
		"ES lifecycle/admission truth",
		"runtime-config refs",
		"workload-zone Vault ownership facts",
		"runtime identity handoff facts",
		"AGS/ARS artifact-publication authority",
		"ES consuming EGS only for signer/artifact runtime trust",
		"ES consuming no CGS facts",
		"does not reopen the accepted Workstream A/B/C decisions",
		"does not change the Workstream B AGS/ARS artifact publication/storage/discoverability decision or the Workstream C ES admission/runtime public model",
		"does not settle Workstream E runtime-config ownership or Workstream F runtime-identity handoff.",
	)

	assertContainsAll(t, "EGS D1c contract design", egsContractSection,
		"D1c is design-only and docs/tests-only.",
		"It does not implement EGS v2 or change the current `GET /v1/trust-model` route, wrapper, signed `runtime_trust` payload shape, or signing behavior.",
		"The current `GET /v1/trust-model` route plus wrapper/payload shape therefore remains the live EGS v1 compatibility surface until an explicitly versioned replacement exists.",
		"EGS publication metadata remains outside the signed `runtime_trust` payload.",
		"`publication.version` and `publication.update_revision` are EGS-owned metadata, not signed runtime-trust facts.",
		"`publication.version` and `publication.update_revision` are EGS-owned publication metadata. They are not trust-contract, schema, or API versioning for the current EGS surface.",
		"Future EGS semantic expansion requires explicit wrapper/payload/versioning before implementation.",
		"If a future EGS versioned trust wrapper is implemented, it must distinguish:",
		"signed runtime-trust payload facts",
		"unsigned publication/discovery metadata",
		"compatibility routing or API version",
		"non-authoritative service metadata",
		"That future wrapper must not carry:",
		"CGS authorization decisions",
		"Control Plane review/approval/checkpoint/finalization semantics",
		"runtime auth plans",
		"Vault token material",
		"JWT-SVIDs",
		"credential payloads",
		"scheduler truth",
		"ES lifecycle/admission truth",
		"runtime-config refs",
		"workload-zone Vault ownership facts",
		"runtime identity handoff facts",
		"AGS/ARS artifact-publication authority",
	)

	assertContainsAll(t, "EGS D1c boundary design", egsBoundarySection,
		"D1c keeps any future EGS versioned trust wrapper design-only.",
		"ES continues to consume EGS only for signed signer/artifact runtime trust, while EGS publication metadata remains unsigned service-owned metadata outside that payload.",
		"D1c is design-only and docs/tests-only.",
		"It does not implement EGS v2 or change the current `GET /v1/trust-model` route, wrapper, signed `runtime_trust` payload, or signing behavior.",
		"Any future EGS semantic expansion requires explicit wrapper/payload/versioning before implementation.",
		"Any future versioned EGS trust wrapper must distinguish signed runtime-trust payload facts, unsigned publication/discovery metadata, compatibility routing or API version, and non-authoritative service metadata.",
		"That future wrapper must not carry CGS authorization decisions, Control Plane review/approval/checkpoint/finalization semantics, runtime auth plans, Vault token material, JWT-SVIDs, credential payloads, scheduler truth, ES lifecycle/admission truth, runtime-config refs, workload-zone Vault ownership facts, runtime identity handoff facts, or AGS/ARS artifact-publication authority.",
	)

	assertContainsAll(t, "architecture D1c guardrail", architecture,
		"D1c keeps any future EGS versioned runtime-trust wrapper design-only.",
		"The current `GET /v1/trust-model` route plus wrapper/payload shape remain the EGS v1 compatibility surface until an explicitly versioned replacement exists.",
		"Any future EGS versioned trust wrapper must distinguish signed runtime-trust payload facts, unsigned publication/discovery metadata, compatibility routing or API version, and non-authoritative service metadata.",
		"That hypothetical future wrapper must not carry CGS authorization decisions, Control Plane review/approval/checkpoint/finalization semantics, runtime auth plans, Vault token material, JWT-SVIDs, credential payloads, scheduler truth, ES lifecycle/admission truth, runtime-config refs, workload-zone Vault ownership facts, runtime identity handoff facts, or AGS/ARS artifact-publication authority.",
		"D1c keeps ES consuming EGS only for signer/artifact runtime trust from the signed payload and keeps ES consuming no CGS facts.",
		"D1c does not change the accepted Workstream B artifact publication/storage/discoverability semantics, does not change the accepted Workstream C ES admission/runtime public model, and does not settle Workstream E runtime-config ownership or Workstream F runtime-identity handoff ownership.",
	)

	assertContainsAll(t, "configuration D1c metadata note", configuration,
		"`publication.version` and `publication.update_revision` configure EGS-owned publication metadata. They are not trust-contract/schema/API versioning for the current EGS v1 surface.",
		"`publication` config remains outside the signed `runtime_trust` payload.",
		"D1c is design-only and docs/tests-only; it does not introduce EGS v2 config, alter the signed runtime-trust payload shape, or change the current `GET /v1/trust-model` route/wrapper/payload compatibility surface.",
	)

	assertContainsAll(t, "ES boundary D1c guardrail", esBoundarySection,
		"D1 keeps ES consuming no CGS facts.",
		"D1c keeps ES consuming EGS only for signed signer/artifact runtime trust.",
		"EGS publication metadata remains outside the signed payload and outside ES hot-path admission facts.",
		"D1c keeps any future EGS versioned runtime-trust wrapper design-only and requires explicit wrapper/payload/versioning before implementation.",
		"D1c does not change the Workstream B AGS/ARS artifact publication/storage/discoverability decision, does not change the Workstream C ES admission/runtime public model, does not reopen the accepted Workstream A/B/C decisions, and does not settle Workstream E runtime-config ownership or Workstream F runtime-identity handoff.",
	)

	assertContainsAll(t, "admission model D1c guardrail", admissionModel,
		"D1c keeps any future EGS versioned runtime-trust wrapper design-only.",
		"ES continues to consume EGS only for signed signer/artifact runtime trust, and EGS publication metadata remains outside the signed payload and outside ES hot-path admission facts.",
		"Any future EGS semantic expansion must use explicit wrapper/payload/versioning before implementation and must not import CGS decisions, runtime-config ownership, runtime identity handoff, AGS/ARS artifact-publication authority, or Control Plane orchestration semantics into the EGS trust surface.",
		"D1c does not change the accepted Workstream B artifact publication/storage/discoverability semantics or the accepted Workstream C ES admission/runtime public model.",
		"This decision still does not settle Workstream E runtime-config ownership or Workstream F runtime-identity handoff ownership.",
	)
}

func TestWorkstreamD1dIDConfCompatibilityDowngradeIsDocumented(t *testing.T) {
	contractsRaw := mustRead(t, ".docs/system_overview/contracts.md")
	boundariesRaw := mustRead(t, ".docs/system_overview/boundaries.md")
	architectureRaw := mustRead(t, ".docs/system_overview/architecture.md")
	configurationRaw := mustRead(t, ".docs/system_overview/configuration.md")
	admissionModelRaw := mustRead(t, ".docs/execution_lifecycle/es_execution_admission_model.md")

	recordD := workstreamRecord(t, "D")
	cgsContractSection := compactDocSection(t, contractsRaw, "## 9. CGS Authorization Contract", "## 10. Runtime Identity Handoff Contract")
	esBoundarySection := compactDocSection(t, boundariesRaw, "## 8. ES boundary", "## 9. EGS boundary")
	cgsBoundarySection := compactDocSection(t, boundariesRaw, "## 10. CGS boundary", "## 11. Cross-cutting packages that are not service boundaries")
	architecture := compactText(architectureRaw)
	configuration := compactText(configurationRaw)
	admissionModel := compactText(admissionModelRaw)

	assertContainsAll(t, "Workstream D1d design-only plan", recordD,
		"D1d is an accepted docs/tests-only slice on that seam",
		"keep checked-in `cgs/policy/id.conf`, the current CGS v1 subject grammar, and `policy.id_conf_path` as current-CGS-v1 compatibility/config residue only",
		"`id.conf` is not a shared policy language",
		"not an ES admission policy input",
		"not an EGS trust input",
		"not a Control Plane review/approval/checkpoint/finalization policy input",
		"not an Infrastructure Manager readiness/profile/support-bundle authority input",
		"keeps the current CGS v1 subject grammar local to current CGS v1 evaluation",
		"keeps the checked-in `cgs/policy/id.conf` baseline as implementation/config residue rather than future product policy architecture",
		"keeps `policy.id_conf_path` as a CGS-local current-v1 configuration pointer rather than a repo-wide policy registry",
		"must not move `id.conf` into runtime-config ownership before Workstream E or fold it into runtime-identity handoff before Workstream F",
		"Future policy-input redesign requires explicit Workstream D follow-up and, if it changes CGS semantics, a versioned CGS contract.",
		"D1d does not change CGS v1 authorize behavior, does not implement CGS v2, and does not change EGS, ES admission, Workstream E runtime-config ownership, or Workstream F runtime-identity handoff.",
	)

	assertContainsAll(t, "Workstream D record checkpoint status", recordD,
		"D0-D1d completed the guardrail/design phase.",
		"Workstream D remains open;",
		"the long-term CGS authorize DTO, future CGS/EGS versioned contracts, and long-term `id.conf`/policy-input model remain reopened seams.",
		"Those remaining D seams are non-blocking follow-ups for Workstream E planning.",
		"No D2 behavior-changing slice is required before Workstream E planning.",
		"D1 does not settle Workstream E runtime-config ownership or Workstream F runtime-identity handoff.",
	)

	assertContainsAll(t, "CGS D1d contract seam", cgsContractSection,
		"`id.conf`, the current CGS v1 subject grammar, and `policy.id_conf_path` remain local to current CGS v1 evaluation only.",
		"They are not a shared policy language, not ES admission policy truth, not EGS trust truth, not Control Plane review/approval/checkpoint/finalization policy truth, and not Infrastructure Manager readiness/profile/support-bundle authority truth.",
		"`policy.id_conf_path` remains a CGS-local configuration pointer for current v1 only. It is not a repo-wide policy registry.",
		"`id.conf` must not move into runtime-config ownership before Workstream E and must not fold into runtime-identity handoff before Workstream F.",
		"The checked-in `cgs/policy/id.conf` baseline is implementation/config residue, not future product policy architecture.",
		"D1d is design-only and docs/tests-only.",
		"It does not change current `POST /v1/credential/authorize` behavior, does not implement CGS v2, and does not change the current `id.conf` grammar, `policy.id_conf_path`, or checked-in `cgs/policy/id.conf` baseline.",
		"Future policy-input redesign requires explicit Workstream D follow-up and, if it changes CGS semantics, a versioned CGS contract.",
	)

	assertContainsAll(t, "CGS D1d boundary seam", cgsBoundarySection,
		"D1d keeps `id.conf`, the current CGS v1 subject grammar, and `policy.id_conf_path` as CGS-local current-v1 compatibility/config residue rather than a shared policy language or repo-wide policy registry.",
		"D1d keeps those surfaces out of ES admission policy truth, EGS trust truth, Control Plane review/approval/checkpoint/finalization policy truth, and Infrastructure Manager readiness/profile/support-bundle authority truth.",
		"D1d keeps `id.conf` out of Workstream E runtime-config ownership and Workstream F runtime-identity handoff.",
		"D1d is design-only and docs/tests-only.",
		"It does not change current `POST /v1/credential/authorize` behavior, does not implement CGS v2, and does not change EGS trust semantics, ES admission behavior, Workstream E runtime-config ownership, or Workstream F runtime-identity handoff.",
	)

	assertContainsAll(t, "architecture D1d seam", architecture,
		"D1d keeps `id.conf`, the current CGS v1 subject grammar, and `policy.id_conf_path` as current-CGS-v1 compatibility/config residue local to CGS v1 evaluation only.",
		"They are not a shared policy language, not ES admission policy input, not EGS trust input, not Control Plane review/approval/checkpoint/finalization policy input, and not Infrastructure Manager readiness/profile/support-bundle authority input.",
		"D1d keeps `id.conf` out of Workstream E runtime-config ownership and Workstream F runtime-identity handoff.",
		"Future policy-input redesign requires explicit Workstream D follow-up and a versioned CGS contract if CGS semantics change.",
	)

	assertContainsAll(t, "configuration D1d seam", configuration,
		"`policy.id_conf_path` remains a CGS-local current-v1 configuration pointer only. It is not a repo-wide policy registry, runtime-config owner surface, or runtime-identity handoff input.",
		"the current `id.conf` grammar and checked-in baseline remain local to current CGS v1 evaluation only",
		"they are not ES admission policy truth",
		"they are not EGS trust truth",
		"they are not Control Plane review/approval/checkpoint/finalization policy truth",
		"they are not Infrastructure Manager readiness/profile/support-bundle authority truth",
		"D1d does not move `id.conf` into Workstream E runtime-config ownership or Workstream F runtime-identity handoff",
	)

	assertContainsAll(t, "ES boundary D1d non-consumer seam", esBoundarySection,
		"D1 keeps ES consuming no CGS facts.",
		"D1d keeps `id.conf`, the current CGS v1 subject grammar, and `policy.id_conf_path` outside the ES admission model.",
		"They remain CGS-local current-v1 compatibility/config residue, not ES admission policy truth, runtime-config ownership input, or runtime-identity handoff input.",
	)

	assertContainsAll(t, "admission model D1d seam", admissionModel,
		"D1d keeps `id.conf`, the current CGS v1 subject grammar, and `policy.id_conf_path` outside the ES admission model.",
		"They remain CGS-local current-v1 compatibility/config residue, not ES admission policy truth, runtime-config ownership input, or runtime-identity handoff input.",
		"D1d does not implement CGS v2, does not change EGS trust semantics, does not change ES admission behavior, and still does not settle Workstream E runtime-config ownership or Workstream F runtime-identity handoff ownership.",
	)
}

func TestWorkstreamERuntimeConfigOwnershipDecisionIsDocumented(t *testing.T) {
	plansRaw := mustRead(t, "PLANS.md")
	decisionRaw := mustRead(t, ".docs/system_overview/runtime_config_ownership.md")
	contractsRaw := mustRead(t, ".docs/system_overview/contracts.md")
	boundariesRaw := mustRead(t, ".docs/system_overview/boundaries.md")
	architectureRaw := mustRead(t, ".docs/system_overview/architecture.md")
	configurationRaw := mustRead(t, ".docs/system_overview/configuration.md")
	admissionModelRaw := mustRead(t, ".docs/execution_lifecycle/es_execution_admission_model.md")
	lifecycleContractsRaw := mustRead(t, ".docs/execution_lifecycle/contracts.md")
	implementationRaw := mustRead(t, ".docs/execution_lifecycle/implementation.md")

	decision := compactText(decisionRaw)
	architecture := compactText(architectureRaw)
	configuration := compactText(configurationRaw)
	admissionModel := compactText(admissionModelRaw)

	recordD := workstreamRecord(t, "D")
	recordE := workstreamRecord(t, "E")
	workstreamF := compactDocSection(t, plansRaw, "### Workstream F - Runtime Identity Handoff Reset", "## Host And Runtime Boundary Rules")
	runtimeConfigContract := compactDocSection(t, contractsRaw, "## 4. Workload-Zone Vault Runtime-Config Contract", "## 5. AGS Publication Contract")
	runtimeConfigBoundary := compactDocSection(t, boundariesRaw, "## 5. Workload-zone Vault runtime-config surface", "## 6. ARS boundary")
	esBoundary := compactDocSection(t, boundariesRaw, "## 8. ES boundary", "## 9. EGS boundary")
	prepareContract := compactDocSection(t, lifecycleContractsRaw, "## 5. Prepare contract", "## 6. Submit contract")
	authorityHandoffContract := compactDocSection(t, lifecycleContractsRaw, "### Authority handoff read surface", "### Error contract")
	implementationApp := compactDocSection(t, implementationRaw, "## 5. Application wiring", "## 6. Prepare path implementation")
	implementationPrepare := compactDocSection(t, implementationRaw, "## 6. Prepare path implementation", "## 7. Submit path implementation")

	assertContainsAll(t, "Workstream D record checkpoint remains open", recordD,
		"D0-D1d completed the guardrail/design phase.",
		"Workstream D remains open;",
		"No D2 behavior-changing slice is required before Workstream E planning.",
		"D1 does not settle Workstream E runtime-config ownership or Workstream F runtime-identity handoff.",
	)
	assertContainsAll(t, "Workstream E record E0 status", recordE,
		"The Workstream E runtime-config ownership decision is recorded in `.docs/system_overview/runtime_config_ownership.md`.",
		"E0 is docs/tests-only.",
		"Runtime-config semantics are owned by the runtime-config contract surface.",
		"The current typed shared schema for workload-zone Vault runtime config is `internal/contracts/runtimeconfig/v1`.",
		"ARS owns blob storage and read by digest only.",
		"ES is the current runtime-config consumer and lookup orchestrator during `:prepare` and `:submit`.",
		"ES startup config currently carries the required workload-zone Vault runtime-config reference. That placement is compatibility/config residue on a reopened ownership seam, not the declared final owner.",
		"The startup guarantee remains: the required typed runtime-config reference must be configured and validated before ES serves governed execution traffic.",
		"The digest-only ref shape is active as a temporary compatibility edge and bounded current surface",
		"There is no ACS hop in the runtime-config path.",
		"Runtime-config does not broker Vault tokens, JWT-SVIDs, secret payloads, leases, Codex credential material, or runtime identity handoff.",
		"`workload_vault_auth.default_mode` is current ES config residue and bounded current behavior, not a generalized runtime-auth-plan contract.",
		"`authority_handoff.runtime_config_refs` is non-secret handoff evidence only, not runtime-config authority or live credential truth.",
		"E0 preserves `GET /v1/executions:contract`, `POST /v1/executions:prepare`, `control-plane-normal-shell/v1`, CP compatibility, and M6 support-bundle inputs.",
		"E0 does not settle Workstream F runtime-identity handoff, does not reopen Workstreams A/B/C, does not mark full Workstream D complete, and does not mark full Workstream E complete.",
	)
	assertContainsAll(t, "PLANS Workstream F dependency", workstreamF,
		"Dependencies: - Workstream C - Workstream D - Workstream E",
	)

	assertContainsAll(t, "runtime-config ownership decision summary", decision,
		"E0 documents the current ownership model before any behavior-changing Workstream E implementation.",
		"Runtime-config semantics are owned by the runtime-config contract surface, not by ARS blob mechanics, ES startup placement, CGS, EGS publication metadata, IM profiles, support bundles, or CP orchestration.",
		"The current typed shared schema for workload-zone Vault runtime config is `internal/contracts/runtimeconfig/v1`.",
		"ARS owns blob storage and blob read by digest.",
		"ES is the current runtime-config consumer and lookup orchestrator during `:prepare` and `:submit`.",
		"That placement is compatibility/config residue on a reopened ownership seam, not the declared final owner.",
		"This is a reference-availability guarantee, not a new E0 guarantee that the ARS blob has been fetched before startup completes.",
		"The digest-only reference shape is active today as a temporary compatibility edge and bounded current surface.",
		"There is no ACS hop in the runtime-config path.",
		"Runtime-config does not broker Vault tokens, JWT-SVIDs, secret payloads, leases, Codex credential material, or runtime identity handoff.",
		"Optional workload-zone Vault CA trust material remains standard non-secret TLS/env-based trust configuration only.",
		"`workload_vault_auth.default_mode` is current ES config residue and bounded current behavior.",
		"`authority_handoff.runtime_config_refs` is non-secret handoff evidence only.",
		"E0 preserves ES public execution DTOs, `GET /v1/executions:contract`, `POST /v1/executions:prepare`, and `control-plane-normal-shell/v1`.",
		"E0 does not settle Workstream F runtime-identity handoff.",
		"E0 does not reopen Workstream A, Workstream B, or Workstream C. It does not mark full Workstream D complete and does not mark full Workstream E complete.",
	)

	dExclusions := compactDocSection(t, decisionRaw, "## 6. Required D exclusions", "## 7. Workstream F stop lines")
	assertContainsAll(t, "runtime-config ownership D exclusions", dExclusions,
		"CGS authorize output",
		"`id.conf`",
		"`policy.id_conf_path`",
		"`audit.policy_version`",
		"EGS `publication.version`",
		"EGS unsigned publication metadata",
		"AGS `policy_decisions`",
		"ES retained bundles",
		"ES `outcome_evidence`",
		"ES `authority_handoff`",
		"IM profiles",
		"support bundles",
		"logs, traces, reports, and `.out` artifacts",
		"CP review/approval/checkpoint/finalization state",
		"These exclusions preserve the accepted D0-D1d guardrails.",
	)

	fStopLines := compactDocSection(t, decisionRaw, "## 7. Workstream F stop lines", "## 8. Remaining Workstream E seams")
	assertContainsAll(t, "runtime-config ownership F stop lines", fStopLines,
		"runtime identity handoff ownership",
		"`EXEC_WORKLOAD_IDENTITY_ENDPOINT`",
		"SPIRE or Vault handoff implementation",
		"reserved runtime paths",
		"runtime helper behavior",
		"workload UID/GID or task-user semantics",
		"Vault JWT login protocol",
		"token, lease, or credential lifecycle semantics",
		"That remains Workstream F.",
	)

	assertContainsAll(t, "system contracts runtime-config E0 alignment", runtimeConfigContract,
		"`runtime_config_ownership.md`",
		"There is no ACS hop in the runtime-config path.",
		"Runtime-config semantics are owned by the runtime-config contract surface",
		"Runtime-config does not broker Vault tokens, JWT-SVIDs, secret payloads, leases, Codex credential material, or runtime identity handoff.",
		"ES is the current runtime-config consumer and lookup orchestrator during `:prepare` and `:submit`.",
		"ARS owns blob storage and retrieval by digest only. ARS does not own workload-zone Vault runtime-config semantics.",
		"ES startup-config placement of `runtime_config.workload_zone_vault_config_ref` is compatibility/config residue on a reopened ownership seam",
		"`workload_vault_auth.default_mode` is current ES config residue and bounded current behavior, not a generalized runtime-auth-plan contract.",
		"`authority_handoff.runtime_config_refs` is non-secret handoff evidence only, not runtime-config authority or live credential truth.",
	)

	assertContainsAll(t, "system boundaries runtime-config E0 alignment", runtimeConfigBoundary,
		"Runtime-config semantics for the current workload-zone Vault reference/blob surface",
		"ARS blob mechanics as semantic ownership of workload-zone Vault config",
		"Runtime-config authority from CGS authorize output, `id.conf`, `policy.id_conf_path`, `audit.policy_version`, EGS `publication.version`, EGS unsigned publication metadata, AGS `policy_decisions`, ES retained bundles, ES `outcome_evidence`, ES `authority_handoff`, IM profiles, support bundles, logs, traces, reports, `.out` artifacts, or CP review/approval/checkpoint/finalization state",
		"Vault tokens, JWT-SVIDs, secret payloads, leases, Codex credential material, or runtime identity handoff",
		"No ACS hop exists in the current runtime-config path",
		"ES startup-config placement of `runtime_config.workload_zone_vault_config_ref` is compatibility/config residue on a reopened ownership seam.",
		"The digest-only ref shape is an active temporary compatibility edge and bounded current surface.",
		"`workload_vault_auth.default_mode` is current ES config residue and bounded current behavior, not a generalized runtime-auth-plan contract.",
		"`authority_handoff.runtime_config_refs` is non-secret handoff evidence only, not runtime-config authority or live credential truth.",
	)

	assertContainsAll(t, "ES boundary runtime-config E0 alignment", esBoundary,
		"Current runtime-config consumer and lookup orchestration during prepare and submit",
		"`internal/contracts/runtimeconfig/v1`",
		"Runtime-config semantic ownership beyond ES's current consumer/lookup role",
		"`authority_handoff.runtime_config_refs` as runtime-config authority or live credential truth",
	)

	assertContainsAll(t, "architecture runtime-config E0 alignment", architecture,
		"`.docs/system_overview/runtime_config_ownership.md`: runtime-config semantics live in the runtime-config contract surface, ARS owns blob storage/read by digest only, and ES is the current consumer and lookup orchestrator.",
		"ES startup config currently carries the required workload-zone Vault runtime-config reference as compatibility/config residue on a reopened ownership seam",
		"does that runtime-config lookup directly, with no ACS hop",
		"`internal/contracts/runtimeconfig/v1` owns the typed semantics, ARS owns blob storage/read by digest",
		"ARS blob mechanics, ES startup placement, CGS, EGS publication metadata, IM profiles, support bundles, CP orchestration state, and evidence/report artifacts are not runtime-config authority.",
		"ES startup-config placement of `runtime_config.workload_zone_vault_config_ref`, the digest-only ref shape, and `workload_vault_auth.default_mode` are compatibility/config residue or bounded current surfaces for Workstream E",
	)

	assertContainsAll(t, "configuration runtime-config E0 alignment", configuration,
		"Runtime-config semantics live in the runtime-config contract surface; the current typed shared schema is `internal/contracts/runtimeconfig/v1`.",
		"ARS owns blob storage/read by digest only. ES is the current runtime-config consumer and lookup orchestrator during prepare and submit.",
		"There is no ACS hop in the runtime-config path.",
		"the required typed runtime-config reference must be configured and validated before ES serves governed execution traffic",
		"not a startup blob-fetch guarantee",
		"the digest-only ref shape is active as a temporary compatibility edge and bounded current surface",
		"optional `ca_bundle_pem` remains non-secret TLS trust material",
		"runtime-config does not broker Vault tokens, JWT-SVIDs, secret payloads, leases, Codex credential material, or runtime identity handoff",
		"`workload_vault_auth.default_mode` is current ES config residue and bounded current behavior, not a generalized runtime-auth-plan contract",
	)

	assertContainsAll(t, "admission model runtime-config E0 alignment", admissionModel,
		"`.docs/system_overview/runtime_config_ownership.md`",
		"`internal/contracts/runtimeconfig/v1` owns the typed semantics, ARS owns blob storage/read by digest only, and ES is the current consumer and lookup orchestrator during `:prepare` and `:submit`. There is no ACS hop.",
		"ES startup-config placement of the required runtime-config ref is compatibility/config residue on a reopened Workstream E ownership seam.",
		"The startup guarantee is that the typed ref is configured and validated before ES serves governed execution traffic",
		"`authority_handoff.runtime_config_refs` is non-secret handoff evidence only.",
		"Workload-zone Vault runtime-config lookup | `bounded slice rule`",
		"Current `authority_handoff.runtime_config_refs` digest evidence",
		"Do not treat ARS blob mechanics, ES startup placement, CGS authorize output, EGS publication metadata, IM profiles, support bundles, logs, traces, reports, retained bundles, `.out` artifacts, CP review/approval/checkpoint/finalization state, `authority_handoff`, or `outcome_evidence` as runtime-config authority.",
	)

	assertContainsAll(t, "execution lifecycle prepare runtime-config E0 alignment", prepareContract,
		"`.docs/system_overview/runtime_config_ownership.md`",
		"runtime-config semantics live in `internal/contracts/runtimeconfig/v1`, ARS owns blob storage/read by digest only, ES is the current consumer and lookup orchestrator, and no ACS hop exists.",
		"ES startup-config placement of the required runtime-config reference is compatibility/config residue on a reopened ownership seam",
		"`workload_vault_auth.default_mode` is current ES config residue and bounded current behavior, not a generalized runtime-auth-plan contract.",
	)
	assertContainsAll(t, "execution lifecycle authority handoff runtime-config E0 alignment", authorityHandoffContract,
		"`authority_handoff.runtime_config_refs` is non-secret handoff evidence only.",
		"`runtime_config_refs` inside `authority_handoff` identifies the selected workload-zone Vault config digest as evidence only.",
		"must not be used as runtime-config authority or live credential truth",
	)

	assertContainsAll(t, "execution implementation runtime-config E0 alignment", compactText(implementationApp+" "+implementationPrepare),
		"`.docs/system_overview/runtime_config_ownership.md`",
		"Runtime-config semantics live in `internal/contracts/runtimeconfig/v1`; ARS owns blob storage/read by digest only; ES is the current consumer and lookup orchestrator.",
		"That startup rule is a typed reference-availability guarantee, not a startup blob-fetch guarantee and not final runtime-config ownership by ES startup config.",
		"There is no ACS hop in this runtime-config path.",
		"CGS is not a current read dependency of `Prepare` or `Submit`",
		"`workload_vault_auth.default_mode` is current ES config residue and bounded current behavior, not a generalized runtime-auth-plan contract.",
	)

	assertContainsAll(t, "Workstream E record E0 global docs", recordE,
		"E0 preserves `GET /v1/executions:contract`, `POST /v1/executions:prepare`, `control-plane-normal-shell/v1`, CP compatibility, and M6 support-bundle inputs.",
	)
}

func TestWorkstreamERuntimeConfigOwnershipKeepsESCGSOutOfESInternal(t *testing.T) {
	forbidden := []string{
		"execution-substrate/cgs",
		"credential-governance",
		"/v1/credential/authorize",
		"id.conf",
		"id_conf_path",
	}

	for _, root := range []string{"es", "internal"} {
		if err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if info.IsDir() {
				return nil
			}
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			text := string(data)
			for _, phrase := range forbidden {
				if strings.Contains(text, phrase) {
					t.Fatalf("%s must not contain ES/internal CGS or id.conf dependency phrase %q", path, phrase)
				}
			}
			return nil
		}); err != nil {
			t.Fatalf("walk %s: %v", root, err)
		}
	}
}

func TestWorkstreamFRuntimeIdentityHandoffOwnershipDecisionIsDocumented(t *testing.T) {
	decisionRaw := mustRead(t, ".docs/system_overview/runtime_identity_handoff.md")
	contractsRaw := mustRead(t, ".docs/system_overview/contracts.md")
	boundariesRaw := mustRead(t, ".docs/system_overview/boundaries.md")
	architectureRaw := mustRead(t, ".docs/system_overview/architecture.md")
	configurationRaw := mustRead(t, ".docs/system_overview/configuration.md")
	admissionModelRaw := mustRead(t, ".docs/execution_lifecycle/es_execution_admission_model.md")
	lifecycleContractsRaw := mustRead(t, ".docs/execution_lifecycle/contracts.md")
	implementationRaw := mustRead(t, ".docs/execution_lifecycle/implementation.md")

	decision := compactText(decisionRaw)
	architecture := compactText(architectureRaw)
	configuration := compactText(configurationRaw)
	admissionModel := compactText(admissionModelRaw)
	recordF := workstreamRecord(t, "F")
	runtimeIdentityContract := compactDocSection(t, contractsRaw, "## 10. Runtime Identity Handoff Contract", "## 11. Temporary Compatibility Edges")
	esBoundary := compactDocSection(t, boundariesRaw, "## 8. ES boundary", "## 9. EGS boundary")
	lifecycleRuntimeIdentity := compactDocSection(t, lifecycleContractsRaw, "## 14. Runtime identity and lifecycle edge", "## 15. Bounded slice rules")
	authorityHandoffContract := compactDocSection(t, lifecycleContractsRaw, "### Authority handoff read surface", "### Error contract")
	implementationRuntimeIdentity := compactDocSection(t, implementationRaw, "## 9. Runtime identity and mount implementation", "## 10. Filesystem and local side effects")

	assertContainsAll(t, "Workstream F record F0 status", recordF,
		"F0 - Runtime Identity Handoff Ownership Decision",
		"F0 is docs/tests-only.",
		"The F0 decision is recorded in `.docs/system_overview/runtime_identity_handoff.md`.",
		"Runtime identity handoff is currently ES-selected and platform-delivered.",
		"ES owns handoff selection, env injection, reserved path layout, mounts, and Nomad job construction for the current slice.",
		"`EXEC_WORKLOAD_IDENTITY_ENDPOINT` is the bounded workload-visible discovery contract.",
		"It is not raw SPIRE socket exposure, Vault token brokerage, runtime-config authority, or a secret payload.",
		"The runtime supervisor/helper owns the in-task endpoint implementation, helper-private SPIRE traversal, readiness-before-workload, and root-to-workload privilege boundary",
		"SPIRE owns JWT-SVID issuance.",
		"Vault owns token, secret, and lease issuance after workload-side login.",
		"ES does not broker Vault tokens, Vault secrets, JWT-SVID payloads, leases, Codex credential material, or credential payloads.",
		"Current helper/root/Nomad task user/SPIRE traversal/reserved-path surfaces are bounded or compatibility-heavy, not final generalized architecture.",
		"Capability validation remains behavior-based and local to validation boundaries",
		"F0 does not change runtime-config ownership from E0/E1",
		"does not change CP compatibility or `control-plane-normal-shell/v1`",
		"does not change M6 support-bundle inputs",
		"F0 does not reopen Workstreams A/B/C, does not mark full Workstream D complete, does not mark full Workstream E complete, and does not mark full Workstream F complete.",
		"Full Workstream F remains open",
		"F0 does not claim full ES/runtime de-root, rootless Nomad client, production readiness, production Vault readiness, or generalized remote deployment architecture.",
	)

	assertContainsAll(t, "runtime-identity ownership decision summary", decision,
		"F0 documents the current ownership model before any behavior-changing Workstream F implementation.",
		"Runtime identity handoff is currently ES-selected and platform-delivered.",
		"ES owns handoff selection, environment injection, reserved path layout, mounts, and Nomad job construction for the current slice.",
		"`EXEC_WORKLOAD_IDENTITY_ENDPOINT` is the bounded workload-visible discovery contract.",
		"`EXEC_WORKLOAD_IDENTITY_ENDPOINT` is not raw SPIRE socket exposure, not Vault token brokerage, not runtime-config authority, and not a secret payload.",
		"The runtime supervisor/helper owns the in-task endpoint implementation, helper-private SPIRE traversal, readiness-before-workload, and the root-to-workload privilege boundary",
		"SPIRE owns JWT-SVID issuance.",
		"Vault owns token, secret, and lease issuance after workload-side login.",
		"ES does not broker Vault tokens, Vault secrets, JWT-SVID payloads, leases, Codex credential material, or credential payloads.",
		"Current helper/root/Nomad task user/SPIRE traversal/reserved-path surfaces are bounded or compatibility-heavy.",
		"Capability validation remains behavior-based and local to validation boundaries",
		"Workload-visible discovery is explicit while implementation remains platform-owned.",
		"F0 does not change runtime-config ownership from E0/E1",
		"F0 preserves ES public execution DTOs, `GET /v1/executions:contract`, `POST /v1/executions:prepare`, `control-plane-normal-shell/v1`, CP compatibility, and M6 support-bundle inputs.",
		"F0 does not claim full ES/runtime de-root, rootless Nomad client, production readiness, production Vault readiness, or generalized remote deployment architecture.",
		"F0 does not reopen Workstream A, Workstream B, or Workstream C. It does not mark full Workstream D complete, does not mark full Workstream E complete, and does not mark full Workstream F complete.",
	)

	assertContainsAll(t, "runtime-identity classified surfaces", decision,
		"| Runtime identity handoff overall | `Current invariant`, `Bounded slice rule` |",
		"| `EXEC_WORKLOAD_IDENTITY_ENDPOINT` | `Current invariant`, `Bounded slice rule` |",
		"| Raw SPIRE Workload API socket | `Security-sensitive secret-bearing surface`, `Temporary compatibility edge` |",
		"| Runtime supervisor/helper endpoint implementation | `Bounded slice rule`, `Implementation detail`, `Workstream F stop line` |",
		"| Helper start as `0:0`, Nomad task `User: \"0:0\"`, fixed workload `10000:10000`, no supplemental groups | `Temporary compatibility edge`, `Bounded slice rule` |",
		"| SPIRE JWT-SVID issuance | `Current invariant`, `Security-sensitive secret-bearing surface` |",
		"| Vault token, secret, and lease issuance | `Current invariant`, `Security-sensitive secret-bearing surface` |",
		"| `authority_handoff` and `authority_handoff.runtime_config_refs` | `Non-authority evidence/projection` |",
	)

	dExclusions := compactDocSection(t, decisionRaw, "## 6. Required D exclusions", "## 7. Required E exclusions")
	assertContainsAll(t, "runtime-identity D exclusions", dExclusions,
		"CGS authorize output",
		"`id.conf`",
		"`policy.id_conf_path`",
		"`audit.policy_version`",
		"CGS v1/v2 design docs",
		"EGS `publication.version`",
		"EGS unsigned publication metadata",
		"AGS `policy_decisions`",
		"These exclusions preserve the accepted D0-D1d guardrails.",
	)

	eExclusions := compactDocSection(t, decisionRaw, "## 7. Required E exclusions", "## 8. Required evidence exclusions")
	assertContainsAll(t, "runtime-identity E exclusions", eExclusions,
		"runtime-config refs",
		"`authority_handoff.runtime_config_refs`",
		"ARS blob storage/read mechanics",
		"digest-only runtime-config refs",
		"`workload_vault_auth.default_mode`",
		"runtime-config ownership docs/tests",
		"E0/E1 startup-guarantee tests",
		"These exclusions preserve the accepted E0/E1 guardrails.",
	)

	evidenceExclusions := compactDocSection(t, decisionRaw, "## 8. Required evidence exclusions", "## 9. Workstream F stop lines")
	assertContainsAll(t, "runtime-identity evidence exclusions", evidenceExclusions,
		"ES retained bundles",
		"`outcome_evidence`",
		"`authority_handoff`",
		"IM profiles",
		"support bundles",
		"logs",
		"traces",
		"reports",
		"`.out` artifacts",
		"CP review/approval/checkpoint/finalization state",
		"They must remain non-authoritative and non-secret.",
	)

	fStopLines := compactDocSection(t, decisionRaw, "## 9. Workstream F stop lines", "## 10. Remaining Workstream F seams")
	assertContainsAll(t, "runtime-identity F0 stop lines", fStopLines,
		"public DTOs, route handlers, or wire shapes",
		"`GET /v1/executions:contract`",
		"`POST /v1/executions:prepare`",
		"runtime-config schema/source files or ownership",
		"ES-to-CGS dependency",
		"`EXEC_WORKLOAD_IDENTITY_ENDPOINT` behavior",
		"SPIRE/Vault handoff implementation",
		"reserved runtime paths",
		"runtime helper behavior",
		"Nomad task user, workload UID/GID, Vault JWT login, token, secret, or lease semantics",
		"M6 support-bundle inputs or IM-facing evidence shapes",
		"Control Plane or Infrastructure Manager repositories",
		"F0 does not decide whether the current runtime-identity delivery model is final.",
	)

	assertContainsAll(t, "system contracts runtime-identity F0 alignment", runtimeIdentityContract,
		"`runtime_identity_handoff.md`",
		"`ES` selects the handoff and provisions the backing runtime-identity workspace, environment marker, reserved path layout, mounts, and Nomad job construction",
		"The platform-owned runtime supervisor/helper implements the endpoint inside the task.",
		"SPIRE owns JWT-SVID issuance.",
		"Vault owns token, secret, and lease issuance after workload-side login.",
		"F0 classifies `EXEC_WORKLOAD_IDENTITY_ENDPOINT` as the bounded workload-visible discovery contract only.",
		"It is not raw SPIRE socket exposure, Vault token brokerage, runtime-config authority, or a secret payload.",
		"Runtime identity handoff is currently ES-selected and platform-delivered.",
		"ES does not broker Vault tokens, Vault secrets, JWT-SVID payloads, leases, Codex credential material, or credential payloads.",
		"Runtime-config refs, `authority_handoff.runtime_config_refs`, ARS blob storage/read mechanics, digest-only runtime-config refs, and `workload_vault_auth.default_mode` are not runtime-identity or credential authority.",
		"CGS authorize output, `id.conf`, `policy.id_conf_path`, `audit.policy_version`, CGS v1/v2 design docs, EGS `publication.version`, EGS unsigned publication metadata, and AGS `policy_decisions` are not runtime-identity or credential authority.",
		"Retained bundles, `outcome_evidence`, `authority_handoff`, IM profiles, support bundles, logs, traces, reports, `.out` artifacts, and CP review/approval/checkpoint/finalization state remain evidence/projection",
		"Helper start as `0:0`, Nomad task `User: \"0:0\"`, fixed workload `10000:10000`, helper-private SPIRE traversal, and current reserved runtime paths are bounded or compatibility-heavy first-slice surfaces.",
	)

	assertContainsAll(t, "system boundaries runtime-identity F0 alignment", esBoundary,
		"Current runtime-identity handoff selection, environment injection, reserved path layout, mount assembly, and Nomad job construction for the bounded slice",
		"Runtime identity endpoint implementation inside the task; the current supervisor/helper owns endpoint serving, helper-private SPIRE traversal, readiness-before-workload, and root-to-workload privilege boundary",
		"Raw SPIRE socket exposure to workloads",
		"JWT-SVID issuance or payload brokerage",
		"Vault token, secret, or lease issuance after workload-side login",
		"Runtime identity or credential authority from CGS authorize output",
		"`EXEC_WORKLOAD_IDENTITY_ENDPOINT` is the bounded workload-visible discovery contract only.",
		"Helper start as `0:0`, Nomad task `User: \"0:0\"`, fixed workload `10000:10000`, helper-private SPIRE traversal, and current reserved runtime paths are bounded or compatibility-heavy first-slice surfaces.",
		"The long-term runtime-identity owner, helper/root/task-user model, SPIRE selector posture, Vault posture, and reserved-path architecture",
	)

	assertContainsAll(t, "architecture runtime-identity F0 alignment", architecture,
		"`.docs/system_overview/runtime_identity_handoff.md`: runtime identity handoff is currently ES-selected and platform-delivered",
		"`EXEC_WORKLOAD_IDENTITY_ENDPOINT` is the bounded workload-visible discovery contract",
		"the runtime supervisor/helper owns the in-task endpoint implementation and helper-private SPIRE traversal",
		"SPIRE owns JWT-SVID issuance",
		"Vault owns token/secret/lease issuance after workload-side login",
		"F0 records this current ownership split without making helper/root/Nomad task user/SPIRE traversal/reserved-path surfaces final generalized architecture.",
		"`EXEC_WORKLOAD_IDENTITY_ENDPOINT` is not raw SPIRE socket exposure, Vault token brokerage, runtime-config authority, or a secret payload.",
		"ES does not broker Vault tokens, Vault secrets, JWT-SVID payloads, leases, Codex credential material, or credential payloads.",
	)

	assertContainsAll(t, "configuration runtime-identity F0 alignment", configuration,
		"`.docs/system_overview/runtime_identity_handoff.md`",
		"Runtime identity handoff is currently ES-selected and platform-delivered.",
		"`EXEC_WORKLOAD_IDENTITY_ENDPOINT` is the bounded workload-visible discovery contract; it is not raw SPIRE socket exposure, Vault token brokerage, runtime-config authority, or a secret payload.",
		"The runtime supervisor/helper owns the in-task endpoint implementation, helper-private SPIRE traversal, readiness-before-workload, and the root-to-workload privilege boundary",
		"SPIRE owns JWT-SVID issuance.",
		"Vault owns token, secret, and lease issuance after workload-side login.",
		"Current helper/root/Nomad task user/SPIRE traversal/reserved-path surfaces are bounded or compatibility-heavy, not final generalized architecture.",
		"F0 does not claim full ES/runtime de-root, rootless Nomad client, production readiness, production Vault readiness, or generalized remote deployment architecture.",
	)

	assertContainsAll(t, "admission model runtime-identity F0 alignment", admissionModel,
		"`.docs/system_overview/runtime_identity_handoff.md`",
		"F0 records that runtime identity handoff is currently ES-selected and platform-delivered.",
		"the runtime supervisor/helper owns in-task endpoint implementation, helper-private SPIRE traversal, readiness-before-workload, and root-to-workload privilege boundary",
		"SPIRE owns JWT-SVID issuance; Vault owns token, secret, and lease issuance after workload-side login.",
		"F0 classifies `EXEC_WORKLOAD_IDENTITY_ENDPOINT` as the bounded workload-visible discovery contract only.",
		"F0 does not change runtime-config ownership from E0/E1",
		"Runtime identity handoff ownership | `bounded slice rule`",
		"Do not reinterpret `EXEC_WORKLOAD_IDENTITY_ENDPOINT` as raw SPIRE socket exposure, Vault token brokerage, runtime-config authority, or a secret payload.",
	)

	assertContainsAll(t, "execution lifecycle runtime-identity F0 alignment", lifecycleRuntimeIdentity,
		"`.docs/system_overview/runtime_identity_handoff.md`",
		"Runtime identity handoff is currently ES-selected and platform-delivered.",
		"ES owns handoff selection, env injection, reserved path layout, mounts, and Nomad job construction for the current slice.",
		"The runtime supervisor/helper owns the in-task endpoint implementation, helper-private SPIRE traversal, readiness-before-workload, and root-to-workload privilege boundary",
		"SPIRE owns JWT-SVID issuance.",
		"Vault owns token, secret, and lease issuance after workload-side login.",
		"`EXEC_WORKLOAD_IDENTITY_ENDPOINT` is the bounded workload-visible discovery contract only.",
		"ES does not broker Vault tokens, Vault secrets, JWT-SVID payloads, leases, Codex credential material, or credential payloads.",
		"Current helper/root/Nomad task user/SPIRE traversal/reserved-path surfaces are bounded or compatibility-heavy, not final generalized architecture.",
		"Runtime-config refs, `authority_handoff.runtime_config_refs`, ARS blob storage/read mechanics, digest-only runtime-config refs, and `workload_vault_auth.default_mode` are not runtime-identity or credential authority.",
	)
	assertContainsAll(t, "execution lifecycle authority handoff F0 alignment", authorityHandoffContract,
		"F0 classifies `authority_handoff` as non-secret runtime-handoff evidence only.",
		"It is not runtime-identity authority, credential authority, proof of live JWT-SVID/Vault token/secret/lease possession, or Control Plane review/approval/checkpoint/finalization state.",
	)

	assertContainsAll(t, "execution implementation runtime-identity F0 alignment", implementationRuntimeIdentity,
		"The current supervisor/helper implementation owns endpoint serving, helper-private SPIRE traversal, readiness-before-workload, helper death handling, and fixed root-to-workload privilege boundary enforcement.",
		"SPIRE owns JWT-SVID issuance behind the helper. Vault owns token, secret, and lease issuance after workload-side login.",
		"`EXEC_WORKLOAD_IDENTITY_ENDPOINT` is bounded workload-visible discovery only.",
		"It is not raw SPIRE socket exposure, Vault token brokerage, runtime-config authority, or a secret payload.",
		"Current helper start as `0:0`, Nomad task `User: \"0:0\"`, fixed workload `10000:10000`, helper-private SPIRE traversal, and reserved-path surfaces are bounded or compatibility-heavy implementation surfaces",
		"`authority_handoff`, `outcome_evidence`, retained bundles, support bundles, logs, traces, reports, profiles, and `.out` artifacts remain non-authority evidence/projection",
		"ES does not broker Vault tokens, Vault secrets, JWT-SVID payloads, leases, Codex credential material, or credential payloads.",
	)
}

func TestWorkstreamFRuntimeIdentityKeepsESCGSOutOfESInternal(t *testing.T) {
	forbidden := []string{
		"execution-substrate/cgs",
		"credential-governance",
		"/v1/credential/authorize",
		"id.conf",
		"id_conf_path",
	}

	for _, root := range []string{"es", "internal"} {
		if err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if info.IsDir() {
				return nil
			}
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			text := string(data)
			for _, phrase := range forbidden {
				if strings.Contains(text, phrase) {
					t.Fatalf("%s must not contain ES/internal CGS or id.conf dependency phrase %q", path, phrase)
				}
			}
			return nil
		}); err != nil {
			t.Fatalf("walk %s: %v", root, err)
		}
	}
}

func TestWorkstreamCResultSurfaceClassificationStaysConsistent(t *testing.T) {
	mvpRaw := mustRead(t, ".docs/mvp.md")
	decisionRaw := mustRead(t, ".docs/execution_lifecycle/es_execution_admission_model.md")
	contractsRaw := mustRead(t, ".docs/system_overview/contracts.md")
	boundariesRaw := mustRead(t, ".docs/system_overview/boundaries.md")
	lifecycleRaw := mustRead(t, ".docs/execution_lifecycle/contracts.md")
	lifecycleDesignRaw := mustRead(t, ".docs/execution_lifecycle/design.md")

	mvpExecutionSubstrate := compactDocSection(t, mvpRaw, "### Execution Substrate", "### Control Plane")
	decisionPublic := compactDocSection(t, decisionRaw, "### 4A. Public execution surfaces", "### 4B. Admission, handoff, and projection ownership surfaces")
	decisionOwnership := compactDocSection(t, decisionRaw, "### 4B. Admission, handoff, and projection ownership surfaces", "### 4C. Temporary compatibility edge metadata")
	decisionCompatibility := compactDocSection(t, decisionRaw, "### 4C. Temporary compatibility edge metadata", "### 4D. Current relationship map")
	esContracts := compactDocSection(t, contractsRaw, "## 7. ES Admission And Execution Contract", "## 8. EGS Policy Contract")
	esStableContracts := compactDocSection(t, esContracts, "Stable semantic contracts for the ES Admission And Runtime Boundary Realignment package:", "`Temporary compatibility edge`")
	esCompatibilityContracts := compactDocSection(t, esContracts, "Compatibility edges to preserve during the next package unless a coordinated migration/versioning note says otherwise:", "`Observed current contract`")
	esTemporaryCompatibilityEdges := compactDocSection(t, esContracts, "### Temporary compatibility edges", "### Reopened seams")
	esBoundary := compactDocSection(t, boundariesRaw, "## 8. ES boundary", "## 9. EGS boundary")
	esBoundaryCompatibility := compactDocSection(t, esBoundary, "**Temporary compatibility edges**", "**Reopened seams**")
	resultContract := compactDocSection(t, lifecycleRaw, "## 9. Result contract", "## 10. Cancel contract")
	resultRuntimeOutput := compactDocSection(t, resultContract, "### Runtime output convention", "### Lookup and retention contract")
	resultLookup := compactDocSection(t, resultContract, "### Lookup and retention contract", "### Response contract")
	designTerminalResult := compactDocSection(t, lifecycleDesignRaw, "### 5.4 Terminal result materialization phase", "## 6. Current lifecycle invariants")
	designBoundedSliceRules := compactDocSection(t, lifecycleDesignRaw, "## 7. Bounded slice rules", "## 8. Deliberate absences")

	assertContainsAll(t, "mvp retained-result compatibility row", mvpExecutionSubstrate,
		"`GET /v1/executions/{run_id}/logs`, `GET /v1/executions/{run_id}/result`, and `POST /v1/executions/{run_id}:cancel` current consumer path | `compatibility edge`",
		"Preserve the current CP-consumed lifecycle, logs, result, and cancel path for MVP continuity without promoting it into a broader orchestration or scheduler contract.",
	)
	assertContainsNone(t, "mvp retained-result compatibility row", mvpExecutionSubstrate,
		"`GET /v1/executions/{run_id}/logs`, `GET /v1/executions/{run_id}/result`, and `POST /v1/executions/{run_id}:cancel` current consumer path | `stable contract`",
	)
	assertContainsAll(t, "mvp retained-result ownership row", mvpExecutionSubstrate,
		"ES-retained opaque result bundles | `stable contract` | Freeze the ownership rule that ES retains opaque output bundles and CP interprets them semantically.",
	)
	assertContainsNone(t, "mvp retained-result ownership row", mvpExecutionSubstrate,
		"ES-retained opaque result bundles | `compatibility edge`",
	)

	assertContainsAll(t, "workstream C decision public result surface", decisionPublic,
		"`GET /v1/executions/{run_id}/result` | `temporary compatibility edge`",
		"Current retained-result retrieval route for ES-owned opaque bundles keyed by public `run_id`.",
	)
	assertContainsNone(t, "workstream C decision public result surface", decisionPublic,
		"`GET /v1/executions/{run_id}/result` | `stable contract`",
	)

	assertContainsAll(t, "workstream C decision retained-result ownership surface", decisionOwnership,
		"Retained opaque result bundles | `stable contract` | ES retains opaque output bundles outside staging and serves them through the current bounded result surface without interpreting their contents as CP state.",
	)
	assertContainsAll(t, "workstream C decision retained-result compatibility edge", decisionCompatibility,
		"Current `GET /v1/executions/{run_id}/result` route plus retained `application/gzip` bundles keyed by public `run_id`",
		"Public result-route path, `run_id`-keyed lookup, `application/gzip` media type, opaque tar.gz result-bundle behavior, and the current CP-consumed result retrieval path only.",
	)

	assertContainsAll(t, "system contracts retained-result ownership section", esStableContracts,
		"retained opaque result-bundle ownership",
		"ES-retained result bundles are opaque output material.",
	)
	assertContainsNone(t, "system contracts retained-result ownership section", esStableContracts,
		"retained opaque result-bundle retrieval",
	)
	assertContainsAll(t, "system contracts retained-result compatibility section", esCompatibilityContracts,
		"retained `application/gzip` result bundles keyed by public `run_id`",
	)
	assertContainsAll(t, "system contracts retained-result temporary-compatibility edges", esTemporaryCompatibilityEdges,
		"The current `GET /v1/executions/{run_id}/result` route, public `run_id` lookup, and retained `application/gzip` bundle retrieval shape are the active CP-consumed compatibility path for the bounded terminal-result slice.",
	)

	assertContainsAll(t, "system boundaries retained-result compatibility section", esBoundaryCompatibility,
		"The current `GET /v1/executions/{run_id}/result` route, public `run_id` lookup, and retained `application/gzip` bundle retrieval shape are active compatibility edges for the bounded retained-result slice, not a broad output platform, raw path reference model, artifact-serving authority, or CP materialization authority.",
	)

	assertContainsAll(t, "execution lifecycle retained-result ownership section", resultRuntimeOutput,
		"ES packages retained result content opaquely and does not parse Control Plane semantics, checkpoint decisions, review outcomes, or finalization metadata from those files.",
	)
	assertContainsAll(t, "execution lifecycle retained-result lookup section", resultLookup,
		"The only public retained-result lookup reference documented today is the `run_id` in `GET /v1/executions/{run_id}/result`.",
		"Any later retained-result reference vocabulary must be documented as a safe handle scoped to a `run_id` or another explicitly documented result reference.",
		"The current route shape, public `run_id` lookup, `application/gzip` encoding, and successful outcome-evidence headers are the active bounded compatibility retrieval path for those ES-owned bundles.",
		"Result availability is evidence/projection for the ES-retained output surface.",
		"`result_not_found` means ES has no retained bundle for that `run_id`; it is not, by itself, Control Plane workflow failure, review failure, checkpoint failure, finalization failure, or Temporal run-control truth.",
	)
	assertContainsAll(t, "execution lifecycle design retained-result materialization", designTerminalResult,
		"ES treats the directory contents as opaque output material",
	)
	assertContainsAll(t, "execution lifecycle design retained-result bounded-slice rule", designBoundedSliceRules,
		"The current `GET /v1/executions/{run_id}/result` route, public `run_id` lookup, and opaque tar.gz bundle encoding remain the bounded compatibility retrieval path for that retained bundle surface.",
	)
}

func TestWorkstreamCRetainedResultBundleClarificationIsDocumented(t *testing.T) {
	decisionRaw := mustRead(t, ".docs/execution_lifecycle/es_execution_admission_model.md")
	lifecycleRaw := mustRead(t, ".docs/execution_lifecycle/contracts.md")
	boundariesRaw := mustRead(t, ".docs/system_overview/boundaries.md")
	runbook := compactText(mustRead(t, ".docs/supported_local_cp_consumer_runbook.md"))

	decisionPublic := compactDocSection(t, decisionRaw, "### 4A. Public execution surfaces", "### 4B. Admission, handoff, and projection ownership surfaces")
	decisionReopened := compactDocSection(t, decisionRaw, "### 4E. Reopened seams", "## 5. Guardrails for future edits")
	resultContract := compactDocSection(t, lifecycleRaw, "## 9. Result contract", "## 10. Cancel contract")
	resultResponse := compactDocSection(t, resultContract, "### Response contract", "### Error contract")
	resultBoundedSlice := compactDocSection(t, resultContract, "### Bounded slice notes", "")
	boundaryReopened := compactDocSection(t, boundariesRaw, "**Reopened seams**", "## 9. EGS boundary")

	assertContainsAll(t, "workstream C retained result public non-claims", decisionPublic,
		"`GET /v1/executions/{run_id}/result` | `temporary compatibility edge`",
		"Current retained-result retrieval route for ES-owned opaque bundles keyed by public `run_id`.",
		"Not a logs wrapper, checkpoint API, finalization record, semantic result interpretation surface, artifact-serving authority, or CP materialization authority.",
	)
	assertContainsAll(t, "workstream C retained result reopened seams", decisionReopened,
		"Retained-result route evolution and result-reference vocabulary",
		"documented safe handle scoped to `run_id` or another explicit result reference",
		"not a raw path, scheduler ID, support/proof path, or artifact-discovery/index leak",
		"Result payload identity, artifact identity, and CP materialization semantics",
		"This decision does not settle whether future result payload identity differs from artifact identity",
		"how artifact discovery/index should expose result material",
		"how CP materializes retrieved content beyond CP-owned review/checkpoint/finalization semantics",
	)
	assertContainsAll(t, "execution lifecycle result envelope redaction", resultResponse,
		"ES does not add raw logs, proof payloads, support bundle payloads",
		"retained-internal metadata",
		"credentials, environment values, TLS/SPIFFE/Vault material, PEM/cert/key bodies, endpoint secrets, unsafe paths, scheduler IDs",
		"CP workflow fields, review fields, checkpoint fields, or finalization fields",
		"this is not a sanitization guarantee over those workload-authored bytes",
		"The result route is not a CP artifact-serving authority.",
	)
	assertContainsAll(t, "execution lifecycle result reopened seams", resultBoundedSlice,
		"Retained-result route evolution, result-reference vocabulary, result payload identity versus artifact identity, CP materialization semantics, and artifact discovery/index long-term shape remain reopened seams",
	)
	assertContainsAll(t, "system boundaries retained result reopened seams", boundaryReopened,
		"The current execution-package layout, retained-result behavior, result-reference vocabulary, and reserved path conventions",
		"Retained-result route evolution, result payload identity versus artifact identity, CP materialization semantics, and artifact discovery/index long-term shape",
	)
	assertContainsAll(t, "CP consumer retained result contract clarification", runbook,
		"The public result reference documented today is the `run_id` in `GET /v1/executions/{run_id}/result`.",
		"CP must not derive or pass retention filesystem paths, host paths, scheduler IDs, Nomad allocation IDs, support bundle paths, proof paths, artifact-discovery/index internals, or guessed bundle names as result references.",
		"Result availability is evidence/projection for ES-retained output.",
		"A missing retained bundle is not, by itself, CP workflow failure, review failure, checkpoint failure, finalization failure, or Temporal run-control truth.",
		"Retained-result route evolution, result-reference vocabulary, result payload identity versus artifact identity, CP materialization semantics, and artifact discovery/index long-term shape remain reopened seams",
	)
}

func TestWorkstreamCRuntimeProfileBoundaryStaysNarrow(t *testing.T) {
	mvpRaw := mustRead(t, ".docs/mvp.md")
	decisionRaw := mustRead(t, ".docs/execution_lifecycle/es_execution_admission_model.md")
	contractsRaw := mustRead(t, ".docs/system_overview/contracts.md")
	boundariesRaw := mustRead(t, ".docs/system_overview/boundaries.md")
	lifecycleContractsRaw := mustRead(t, ".docs/execution_lifecycle/contracts.md")
	lifecycleDesignRaw := mustRead(t, ".docs/execution_lifecycle/design.md")

	mvpExecutionSubstrate := compactDocSection(t, mvpRaw, "### Execution Substrate", "### Control Plane")
	decisionRuntimeProfile := compactDocSection(t, decisionRaw, "| Runtime-profile selection |", "| `authority_handoff` read surface |")
	decisionRuntimeProfileCompatibility := compactDocSection(t, decisionRaw, "| `invocation.annotations[\"execution_substrate.runtime_profile\"]` plus `control-plane-normal-shell/v1` and the current `static-script` overlay |", "| Current `/execution/staged`, `/execution/run`, `/execution/run/result`, and run-scoped runtime-identity path conventions |")
	esContracts := compactDocSection(t, contractsRaw, "## 7. ES Admission And Execution Contract", "## 8. EGS Policy Contract")
	esBoundary := compactDocSection(t, boundariesRaw, "## 8. ES boundary", "## 9. EGS boundary")
	submitContract := compactDocSection(t, lifecycleContractsRaw, "## 6. Submit contract", "## 7. Status contract")
	runtimeIdentityContract := compactDocSection(t, lifecycleContractsRaw, "## 14. Runtime identity and lifecycle edge", "## 15. Bounded slice rules")
	boundedSliceRules := compactDocSection(t, lifecycleContractsRaw, "## 15. Bounded slice rules", "## 16. Deliberate absences")
	designBoundedSliceRules := compactDocSection(t, lifecycleDesignRaw, "## 7. Bounded slice rules", "## 8. Deliberate absences")
	runtimeIdentityDesign := compactDocSection(t, lifecycleDesignRaw, "## 10. Runtime identity and lifecycle interaction", "## 11. Relationship to other docs")

	assertContainsAll(t, "mvp runtime-profile compatibility row", mvpExecutionSubstrate,
		"`control-plane-normal-shell/v1` plus `execution_substrate.runtime_profile` compatibility | `compatibility edge` | Keep this as the accepted opt-in CP normal-shell runtime edge for the MVP. It is not a general package-kind redesign or a transfer of CP control semantics into ES.",
	)
	assertContainsNone(t, "mvp runtime-profile compatibility row", mvpExecutionSubstrate,
		"`control-plane-normal-shell/v1` plus `execution_substrate.runtime_profile` compatibility | `stable contract`",
	)
	assertContainsAll(t, "workstream C decision runtime-profile row", decisionRuntimeProfile,
		"| Runtime-profile selection | `temporary compatibility edge` | `invocation.annotations[\"execution_substrate.runtime_profile\"]` plus `control-plane-normal-shell/v1` remains the current opt-in `static-script` runtime overlay. Omitted or empty annotation resolves to the current default `static-script/default` runtime name; unsupported or disabled non-empty selection fails `:prepare`/`:submit`. |",
	)
	assertContainsNone(t, "workstream C decision runtime-profile row", decisionRuntimeProfile,
		"| Runtime-profile selection | `stable contract` |",
	)
	assertContainsAll(t, "workstream C decision runtime-profile compatibility row", decisionRuntimeProfileCompatibility,
		"Preserve the accepted CP normal-shell runtime selection path without widening it into a package-kind redesign or CP control-plane transfer.",
	)

	assertContainsAll(t, "system contracts runtime-profile boundary", esContracts,
		"The bounded `control-plane-normal-shell/v1` runtime profile is an explicit prepare/submit-time opt-in using `invocation.annotations[\"execution_substrate.runtime_profile\"]`.",
		"keeps any profile-image tool contents, supported-local image checks, and proof-only shims outside the ES public execution contract; those remain current-slice runtime support and proof scaffolding only",
		"`control-plane-normal-shell/v1` is a bounded compatibility-heavy runtime contract for one CP-owned normal-shell attempt path. It should not be generalized into an arbitrary image/toolchain marketplace or used to absorb CP orchestration semantics into ES.",
	)
	assertContainsAll(t, "system boundaries runtime-profile boundary", esBoundary,
		"`control-plane-normal-shell/v1` is a bounded `static-script` runtime-profile overlay for the CP normal-shell attempt slice. It is not a broad package-kind redesign, a general developer image contract, or a transfer of CP control semantics into ES.",
	)
	assertContainsAll(t, "execution lifecycle submit runtime-profile boundary", submitContract,
		"`invocation.annotations[\"execution_substrate.runtime_profile\"]=\"control-plane-normal-shell/v1\"` selects the bounded Control Plane normal-shell runtime profile.",
		"an absolute configured Codex CLI path metadata value",
	)
	assertContainsAll(t, "execution lifecycle runtime-profile failure boundary", lifecycleContractsRaw,
		"Unsupported or disabled profile selections fail during `:prepare` before any run ID exists.",
		"`control-plane-normal-shell/v1` is a bounded runtime contract for the CP-owned normal-shell attempt path, not an ES-owned orchestration, review, checkpoint, or finalization contract.",
	)
	assertContainsAll(t, "execution lifecycle bounded-slice runtime-profile boundary", boundedSliceRules,
		"`control-plane-normal-shell/v1` is a bounded runtime-profile slice rule layered on the current `static-script` package/runtime path.",
	)
	assertContainsAll(t, "execution lifecycle design runtime-profile boundary", designBoundedSliceRules,
		"`control-plane-normal-shell/v1` is one explicit opt-in runtime-profile overlay on the current `static-script` package/runtime path. It exists to give the CP-owned remote normal-shell attempt path a governed ES-owned runtime-profile-selection and runtime-identity-delivery contract without moving CP orchestration or review semantics into ES.",
	)
	assertContainsAll(t, "execution lifecycle runtime-identity design boundary", runtimeIdentityDesign,
		"For `control-plane-normal-shell/v1`, ES also injects non-secret Codex CLI location metadata, workload-vault credential-location metadata, and any configured workload-zone Vault CA trust material.",
	)

	for _, section := range []struct {
		label string
		text  string
	}{
		{label: "mvp runtime-profile compatibility row", text: mvpExecutionSubstrate},
		{label: "workstream C decision runtime-profile row", text: decisionRuntimeProfile},
		{label: "workstream C decision runtime-profile compatibility row", text: decisionRuntimeProfileCompatibility},
		{label: "system contracts runtime-profile boundary", text: esContracts},
		{label: "execution lifecycle submit runtime-profile boundary", text: submitContract},
		{label: "execution lifecycle design runtime-profile boundary", text: designBoundedSliceRules},
		{label: "execution lifecycle runtime-identity design boundary", text: runtimeIdentityDesign},
	} {
		assertContainsNone(t, section.label, section.text,
			"general developer image contract",
			"developer image contract",
			"general tooling guarantee",
		)
	}

	for _, section := range []struct {
		label string
		text  string
	}{
		{label: "mvp runtime-profile compatibility row", text: mvpExecutionSubstrate},
		{label: "workstream C decision runtime-profile row", text: decisionRuntimeProfile},
		{label: "workstream C decision runtime-profile compatibility row", text: decisionRuntimeProfileCompatibility},
		{label: "system contracts runtime-profile boundary", text: esContracts},
		{label: "system boundaries runtime-profile boundary", text: esBoundary},
		{label: "execution lifecycle submit runtime-profile boundary", text: submitContract},
		{label: "execution lifecycle runtime-identity boundary", text: runtimeIdentityContract},
		{label: "execution lifecycle design runtime-profile boundary", text: designBoundedSliceRules},
		{label: "execution lifecycle runtime-identity design boundary", text: runtimeIdentityDesign},
	} {
		assertContainsNone(t, section.label, section.text,
			"guarantees the profile image contract",
			"Python, git, narrow shell utilities",
			"configured Codex CLI availability",
			"tooling guarantee",
		)
	}
}

func TestWorkstreamCRuntimeProfileCompatibilityMatrixIsDocumented(t *testing.T) {
	lifecycleContractsRaw := mustRead(t, ".docs/execution_lifecycle/contracts.md")
	lifecycleContracts := compactText(lifecycleContractsRaw)
	matrix := compactDocSection(t, lifecycleContractsRaw, "## 4B. Runtime profile compatibility matrix", "## 5. Prepare contract")
	decision := compactText(mustRead(t, ".docs/execution_lifecycle/es_execution_admission_model.md"))
	runbookRaw := mustRead(t, ".docs/supported_local_cp_consumer_runbook.md")
	runbookRuntimeProfile := compactDocSection(t, runbookRaw, "## 6. Runtime profile selection", "## 7. Workload runtime contract")

	assertContainsAll(t, "runtime profile compatibility matrix scope", matrix,
		"This matrix records the current runtime-profile vocabulary and adjacent runtime-profile-looking values.",
		"It is a compatibility cleanup, not a final runtime-selection design.",
	)
	assertContainsAll(t, "runtime profile compatibility matrix values", matrix,
		"| `execution_substrate.runtime_profile` | `Temporary compatibility edge` | The only current request annotation key for opt-in runtime-profile selection. Omitted or empty keeps the default current `static-script` runtime behavior.",
		"| omitted or empty `execution_substrate.runtime_profile` | `Bounded slice rule` | Accepted. Resolves to the current default runtime name `static-script/default`, uses `execution.base_image`, and injects no profile-specific Codex credential-location metadata.",
		"| `static-script/default` | `Bounded slice rule` | The current default runtime name used in producer declarations, submit metadata, and `authority_handoff`. It is selected by omitting the annotation or leaving it empty; current source does not treat a non-empty annotation value of `static-script/default` as a separate opt-in selector.",
		"| `control-plane-normal-shell/v1` | `Temporary compatibility edge` | Accepted only as an explicit opt-in annotation when submit is configured, `execution.runtime_profiles.control_plane_normal_shell.enabled=true`, the artifact is `static-script`, and signed evidence has `network_access=true`.",
		"| `execution.runtime_profiles.control_plane_normal_shell.*` | `Bounded slice rule` | ES deployment/admin config for enabling and parameterizing the bounded Control Plane normal-shell profile image, Codex CLI path metadata, and workload-Vault credential-location metadata.",
		"| `execution-substrate/control-plane-normal-shell:supported-local`, `execution-substrate/control-plane-normal-shell:local`, and the supported-local proof Codex shim | `Proof-only or bounded local proof` | Runtime support image/shim values that can realize the configured Control Plane normal-shell profile in local proof paths. They are not accepted runtime-profile annotation values.",
		"| unsupported or unknown non-empty profile values | `Rejected/unsupported` | Rejected by `:prepare` and by the configured `:submit` path as `unsupported_runtime_profile` before run ID creation, staging, scheduler handoff, or CP run failure.",
		"| long-term runtime-profile vocabulary, runtime identity handoff owner, and workload-zone runtime-config owner | `Reopened redesign seam` | Remain open beyond the bounded CP normal-shell compatibility edge and the current default runtime behavior.",
	)
	assertContainsAll(t, "runtime profile matrix non-claims", matrix,
		"Not the default runtime model, not a package-kind redesign, not a general image/tool marketplace, and not a transfer of CP orchestration, review, checkpoint, or finalization semantics into ES.",
		"Not a public runtime-profile name, not credential material, not credential brokerage, and not runtime identity ownership.",
		"No fallback profile is selected and no CP review/checkpoint/finalization state is created.",
		"This cleanup does not settle final package layout, DTOs, runtime identity, workload-zone config, credential acquisition, or final runtime vocabulary.",
	)
	assertContainsAll(t, "runtime profile matrix redaction", matrix,
		"Runtime-profile public surfaces remain non-secret.",
		"Producer declarations expose only profile names, status, disabled reasons, and outcome-evidence declarations.",
		"`authority_handoff` may expose only the documented non-secret runtime profile, workload identity endpoint, workload-Vault metadata, runtime-config digest, and Codex credential-location labels.",
		"Runtime-profile fields must not expose private keys, PEM bodies, raw cert bodies, env values, endpoint secrets, TLS/SPIFFE/Vault material beyond documented safe labels, raw logs, support/retained/proof payloads, unsafe paths, or CP workflow, review, checkpoint, and finalization fields.",
	)
	assertContainsAll(t, "runtime profile decision row names default and unsupported behavior", decision,
		"Omitted or empty annotation resolves to the current default `static-script/default` runtime name; unsupported or disabled non-empty selection fails `:prepare`/`:submit`.",
	)
	assertContainsAll(t, "CP runbook runtime profile matrix reference", runbookRuntimeProfile,
		"The authoritative current matrix is in `.docs/execution_lifecycle/contracts.md`.",
		"the runtime-profile vocabulary remains a reopened seam beyond the bounded CP normal-shell compatibility edge.",
		"Omitting `execution_substrate.runtime_profile` or setting it to an empty value keeps the current default `static-script/default` runtime behavior.",
		"`static-script/default` may appear in producer declarations and `authority_handoff`, but current source does not treat a non-empty annotation value of `static-script/default` as a separate opt-in selector.",
		"Supported-local image tags and proof shims are runtime support/proof assets, not additional runtime-profile annotation values.",
	)
	assertContainsNone(t, "runtime profile matrix avoids finalized vocabulary", lifecycleContracts,
		"runtime profile vocabulary is final",
		"final runtime-profile vocabulary",
		"all runtime profiles are supported",
		"enables package-kind redesign",
		"enables credential brokerage",
	)
}

func TestGoldenProducerProofPathIsDocumented(t *testing.T) {
	runbook := compactText(mustRead(t, ".docs/supported_local_cp_consumer_runbook.md"))
	lifecycleContracts := compactText(mustRead(t, ".docs/execution_lifecycle/contracts.md"))
	capabilityProbing := compactText(mustRead(t, ".docs/system_overview/capability_probing.md"))

	for _, required := range []string{
		"Golden producer proof path",
		"`GET /v1/executions:contract`",
		"`schema_version = \"execution-substrate.producer-contract/v1\"`",
		"`service = \"execution\"`",
		"`governed_execution.contract = \"governed-execution-producer/v1\"`",
		"`governed_execution.enabled = true`",
		"`control-plane-normal-shell/v1`",
		"`invocation.annotations[\"execution_substrate.runtime_profile\"] = \"control-plane-normal-shell/v1\"`",
		"`authority_handoff`",
		"`status.lifecycle_projection.revision`",
		"`outcome_evidence`",
		"`Content-Type: text/plain; charset=utf-8`",
		"`Content-Type: application/gzip`",
		"`Execution-Substrate-Outcome-*` headers",
		"A passing static contract check without supported-local readiness is not a live runtime proof.",
		"A passing Docker/Nomad-backed proof without the producer declaration above is not current governed-execution producer compatibility.",
	} {
		if !strings.Contains(runbook, required) {
			t.Fatalf("supported-local CP consumer runbook missing golden producer proof phrase %q", required)
		}
	}

	for _, required := range []string{
		"status JSON to include `outcome_evidence`",
		"cancel JSON to include `outcome_evidence`",
		"successful logs responses to preserve `text/plain; charset=utf-8`",
		"successful result responses to preserve `application/gzip`",
		"`authority_handoff` is additive and read-only.",
		"No claim that a JWT-SVID, Vault token, Codex token, or lease exists or is still valid.",
	} {
		if !strings.Contains(lifecycleContracts, required) {
			t.Fatalf("execution lifecycle contract missing producer proof phrase %q", required)
		}
	}

	if !strings.Contains(capabilityProbing, "Read-only producer contract declarations, such as ES `GET /v1/executions:contract`, are not runtime capability probes.") {
		t.Fatalf("capability probing doc missing static producer declaration boundary")
	}
}

func TestProducerFailurePathDistinctionsAreDocumented(t *testing.T) {
	contracts := compactText(mustRead(t, ".docs/system_overview/contracts.md"))
	lifecycleContracts := compactText(mustRead(t, ".docs/execution_lifecycle/contracts.md"))
	runbook := compactText(mustRead(t, ".docs/supported_local_cp_consumer_runbook.md"))

	for _, required := range []string{
		"`disabled_reason = \"submit_not_configured\"`",
		"`disabled_reason = \"profile_not_enabled\"`",
		"`not_run_existence_proof`",
		"`execution_not_found` is a lifecycle observation absence",
		"not a producer declaration incompatibility",
		"not, by itself, a submit-readiness or substrate-health result",
	} {
		if !strings.Contains(lifecycleContracts, required) {
			t.Fatalf("execution lifecycle contract missing failure-path distinction %q", required)
		}
	}

	for _, required := range []string{
		"`submit_not_configured`",
		"`profile_not_enabled`",
		"`not_run_existence_proof`",
		"static compatibility metadata for live lifecycle observation",
	} {
		if !strings.Contains(contracts, required) {
			t.Fatalf("system contracts doc missing producer failure-path distinction %q", required)
		}
	}

	for _, required := range []string{
		"producer declaration incompatibility",
		"runtime/live substrate readiness failure",
		"missing mandatory outcome-evidence support",
		"required runtime profile is unavailable",
		"run lifecycle observation absence",
		"not producer declaration incompatibility or submit readiness",
	} {
		if !strings.Contains(runbook, required) {
			t.Fatalf("CP consumer runbook missing producer failure-path distinction %q", required)
		}
	}
}

func TestMilestone1LeastPrivilegeBoundaryCloseoutIsDocumented(t *testing.T) {
	milestone1 := hostRuntimeSection(t, milestone1Heading)
	remote := compactText(mustRead(t, ".docs/system_overview/remote_supported_host_alpha.md"))

	for _, required := range []string{
		"Milestone 1: Least-Privilege Runtime/Security Boundary Closeout",
		"Do not call this milestone `rootless everything` or full ES/runtime de-root.",
		"Nomad remains lifecycle authority after ES submission.",
		"ES remains a lifecycle projector, not a parallel scheduler.",
		"The raw SPIRE Workload API socket remains helper-private.",
		"Workloads see `EXEC_WORKLOAD_IDENTITY_ENDPOINT`, not the raw SPIRE Workload API socket.",
		"Workload-side Vault credential acquisition remains preserved.",
		"ES does not fetch, mint, broker, store, rotate, parse, or validate Vault tokens.",
		"Infrastructure Manager support bundles and readiness/support artifacts remain evidence/projection/diagnostics only. They are not authority and are not governed execution proof by themselves.",
	} {
		if !strings.Contains(milestone1, required) || !strings.Contains(remote, required) {
			t.Fatalf("Milestone 1 least-privilege boundary docs missing %q", required)
		}
	}
}

func TestMilestone1BoundaryPostureMatrixIsDocumented(t *testing.T) {
	milestone1 := hostRuntimeSection(t, milestone1Heading)
	remote := compactText(mustRead(t, ".docs/system_overview/remote_supported_host_alpha.md"))

	for _, required := range []string{
		"Milestone 1 boundary posture matrix:",
		"Nomad host client/server substrate",
		"`blocker`",
		"Milestone 1 does not claim a rootless Nomad client or full Nomad least-privilege closeout.",
		"SPIRE raw-socket traversal and selector posture",
		"`accepted MVP compatibility edge`",
		"Workloads do not receive the raw SPIRE Workload API socket, and this milestone does not claim final SPIRE selector least privilege.",
		"Vault workload-side auth / workload-zone handoff",
		"the intended direction is a dedicated unprivileged Vault service account rather than root",
		"ES runtime helper",
		"Nomad task user",
		"Evidence/support artifacts",
		"Support bundles, readiness reports, and apply summaries are not ES/CP/IM authority and are not governed execution proof by themselves.",
	} {
		if !strings.Contains(milestone1, required) || !strings.Contains(remote, required) {
			t.Fatalf("Milestone 1 posture matrix docs missing %q", required)
		}
	}
}

func TestRemoteSupportedHostAlphaRuntimeSecurityBoundaryCheckerIsDocumented(t *testing.T) {
	plans := compactText(mustRead(t, "PLANS.md"))
	milestone1 := hostRuntimeSection(t, milestone1Heading)
	remote := compactText(mustRead(t, ".docs/system_overview/remote_supported_host_alpha.md"))
	configuration := compactText(mustRead(t, ".docs/system_overview/configuration.md"))

	for _, required := range []string{
		"`scripts/remote_alpha_runtime_security_boundary_check.sh`",
		"`scripts/internal/remote_alpha_runtime_security_boundary_check.sh`",
		"`execution-substrate.remote-alpha.runtime-security-boundary-check.v1`",
		"`runtime-security-boundary-check.json`",
		"default to `check_only`",
		"non-mutating",
		"must not SSH by default",
		"mutate services",
		"change ownership",
		"restart services",
		"archive files",
		"delete anything",
		"`mode`",
		"`non_mutating`",
		"`schema`",
		"`generated_at`",
		"`host`",
		"`runtime_inventory`",
		"`cve_readiness`",
		"`runtime_chain`",
		"`surfaces`",
		"`accepted_compatibility_edges`",
		"`least_privilege_findings`",
		"`blockers`",
		"`not_evaluated`",
		"`redaction`",
		"`non_authority_labels`",
		"`explicit_non_claims`",
		"`nomad_roles_detected`",
		"`evaluation_source`",
		"`independently_evaluated`",
		"`combined_single_node_service`",
		"`role_evidence`",
		"Nomad server privilege posture",
		"Nomad client privilege posture",
		"independently evaluated or are only one combined-service reading",
		"host/runtime inventory",
		"package versions",
		"Docker/Nomad runtime chain observations",
		"CVE-2026-31431",
		"CVE-2026-31465",
		"`fixed`",
		"`vulnerable`",
		"`not_affected`",
		"`mitigated_not_fixed`",
		"`unknown`",
		"`algif_aead`",
		"modprobe policy blocks autoload",
		"not a kernel patch",
		"`--accept-cve-31431-mitigation-risk-for-internal-alpha`",
		"`not_cve_patch_authority`",
		"accepted MVP substrate dependency",
		"combined_nomad_systemd_unit",
		"one combined service unit does not prove separate server/client posture",
		"Nomad task `User: \"0:0\"` remains an accepted MVP compatibility edge",
		"root-start ES runtime helper/supervisor remains an accepted MVP compatibility edge",
		"the raw SPIRE Workload API socket remains helper-private",
		"`EXEC_WORKLOAD_IDENTITY_ENDPOINT`",
		"ES Vault token brokerage must remain false",
		"support bundles and related evidence artifacts remain non-authoritative",
		"JWT-SVID material",
		"Vault tokens",
		"root tokens",
		"unseal keys",
		"PEM private keys",
		"API keys",
		"Codex credentials",
		"raw secret payloads",
		"`full ES/runtime de-root`",
		"`rootless Nomad client`",
		"`governed execution proof`",
		"`Vault production readiness`",
		"`workload credential success`",
		"`support-bundle authority`",
		"honest `blockers` or `not_evaluated` entries",
	} {
		if !strings.Contains(plans, required) && !strings.Contains(milestone1, required) && !strings.Contains(remote, required) && !strings.Contains(configuration, required) {
			t.Fatalf("remote runtime/security boundary checker docs missing %q", required)
		}
	}
}

func TestRemoteSupportedHostAlphaDirectBoundaryIsDocumented(t *testing.T) {
	remote := compactText(mustRead(t, ".docs/system_overview/remote_supported_host_alpha.md"))
	runbook := compactText(mustRead(t, ".docs/supported_local_cp_consumer_runbook.md"))

	for _, required := range []string{
		"Remote Supported-Host Alpha 0.3 is an intermediate alpha",
		"Control Plane profile diagnostics and Infrastructure Manager remote-doctor output",
		"not the final commercial deployment target",
		"Control Plane API, UI, worker, and Temporal remain on the Mac",
		"ES, AGS, ARS, EGS, Docker, Nomad, SPIRE, Vault, and runtime support run on one remote Linux host.",
		"CP connects to AGS and ES over direct routable HTTPS with mTLS.",
		"No shared filesystem is assumed between Mac and remote host.",
		"Bridge or tunnel mode is a temporary compatibility edge",
		"AGS and ES listeners can bind routable interfaces",
		"server certificates include DNS or IP SANs matching the Control Plane profile endpoint hosts",
		"mTLS accepts the Control Plane service identity",
		"ES `/health`",
		"ES `GET /v1/executions:contract`",
		"AGS `POST /v1/artifacts:publish`",
		"ES `POST /v1/executions:prepare`",
		"ES `POST /v1/executions:submit`",
		"ES `GET /v1/executions/{run_id}/status`",
		"ES `GET /v1/executions/{run_id}/logs`",
		"ES `GET /v1/executions/{run_id}/result`",
		"ES `POST /v1/executions/{run_id}:cancel`",
		"`execution-substrate.producer-contract/v1`",
		"`governed-execution-producer/v1`",
		"`control-plane-normal-shell/v1`",
		"Nomad APIs",
		"Vault APIs",
		"SPIRE sockets",
		"ES staging root paths",
		"ES results root paths",
		"remote filesystem paths",
		"Infrastructure Manager may emit profile, doctor, support-bundle, and combined readiness-report outputs",
		"Direct HTTPS/mTLS with matching DNS/IP SANs is the acceptance posture",
	} {
		if !strings.Contains(remote, required) {
			t.Fatalf("remote supported-host alpha doc missing %q", required)
		}
	}

	if !strings.Contains(runbook, "Remote Supported-Host Alpha 0.3") {
		t.Fatalf("supported-local CP consumer runbook missing remote alpha link")
	}
}

func TestDocsRemoteAlphaOperatorFacadeBoundaries(t *testing.T) {
	plansRaw := mustRead(t, "PLANS.md")
	plans := compactText(plansRaw)
	planCutoffSection := docSection(t, plansRaw,
		"### Current Remote Alpha operator evidence-compatibility cutoff",
		"### Historical P0g evidence ingestion — superseded and non-authoritative",
	)
	remoteRaw := mustRead(t, ".docs/system_overview/remote_supported_host_alpha.md")
	statusSection := compactDocSection(t, remoteRaw, "## Future ES-Owned Remote Alpha Operator Facade", "### Operator Involvement Model")
	configuration := compactText(mustRead(t, ".docs/system_overview/configuration.md"))

	assertContainsAll(t, "Remote Alpha operator cutoff plan", plans,
		"ES product architecture leads",
		"an implemented Remote Alpha operator compatibility surface is not thereby an ES product invariant",
		"The former P0g evidence-ingestion surface and the P0n/P0r facade staging and aggregation routes are superseded compatibility history",
		"optional owner-local proof emitters under their separately documented contracts",
		"Their facade compatibility is not a Tranche B prerequisite",
		"introduces no replacement schema, adapter, projection, registry, v2 protocol, or Infrastructure Manager reader",
	)
	assertExpectedTreeInventoryClause(t, planCutoffSection)
	assertContainsAll(t, "Remote Alpha operator cutoff current status", statusSection,
		"ES product architecture leads this boundary",
		"Operator-facade compatibility is not a product invariant merely because it was implemented",
		"compatibility for the retired runtime-identity, Vault workload-auth, and Vault service-user artifact families is not a Tranche B prerequisite",
		"optional owner-local proof emitters for this tranche",
		"does not retire or change the underlying ES runtime-identity, SPIRE, admission-handoff, or workload-side Vault product boundaries",
		"P0g's former local evidence-ingestion mode is retired",
		"provides no generic evidence parser, schema interpretation, automatic discovery, aggregation, or projection adapter",
		"P0n's former Mac-side workload-auth checker staging route is retired",
		"P0r's former Mac-side runtime-identity summary staging route is retired",
		"operator-compatibility surface has exactly four refusal classes",
		"These classes do not promise identical stderr",
		"global privacy prefilter",
		"adds no replacement schema, parser, adapter, registry, v2 protocol, or Infrastructure Manager dependency",
		"P0i adds exactly one secret-sensitive recovery-session route",
		"P0q implements exactly that secret-sensitive workload-auth bootstrap helper",
		"P0s/P0t retain only the bounded interactive `es-service-tls-status` and",
		"Both renewal names refuse before host contact",
		"P0u adds exactly one bounded Remote Alpha host-local operator healthcheck client TLS status/renew helper pair",
		"P0v implements the ES-owned noninteractive read-only operator-healthcheck TLS status route",
	)
	assertContainsNone(t, "Remote Alpha current status excludes retired compatibility", statusSection,
		"P0g implements one safe/local recovery workflow skeleton",
		"P0n adds one separate Mac-side post-reset workload-auth evidence route",
		"P0r implements exactly one Mac-side runtime identity evidence route",
		"`recovery-session --evidence-check` is current-only",
		"current-only local evidence-check mode",
		"automatic filename discovery is current",
		"The readiness session remains available for current follow-up use.",
	)

	for _, heading := range []string{
		"### Historical P0g Evidence Ingestion — Superseded and Non-Authoritative",
		"### Historical P0n Mac-Side Vault Workload-Auth Check — Superseded and Non-Authoritative",
		"### Historical P0r Mac-Side Runtime Identity Summary — Superseded and Non-Authoritative",
	} {
		if !strings.Contains(remoteRaw, heading) {
			t.Fatalf("Remote Alpha doc lacks explicit historical heading %q", heading)
		}
	}
	assertContainsAll(t, "standalone producer contracts remain documented", remoteRaw+"\n"+configuration,
		"## Runtime Identity Helper Proof Slice",
		"scripts/remote_alpha_runtime_identity_helper_summary.sh",
		"sudo scripts/remote_alpha_vault_workload_auth_check.sh",
		"execution-substrate.remote-alpha.vault-workload-auth-summary.v1",
		"scripts/remote_alpha_migrate_vault_service_user.sh",
		"execution-substrate.remote-alpha.vault-service-user-migration-summary.v1",
	)
	assertContainsAll(t, "operator compatibility is not a Tranche B gate", compactText(planCutoffSection)+"\n"+statusSection,
		"Their facade compatibility is not a Tranche B prerequisite and must not block core ES work.",
		"compatibility for the retired runtime-identity, Vault workload-auth, and Vault service-user artifact families is not a Tranche B prerequisite.",
	)
	assertContainsNone(t, "operator compatibility is not a Tranche B gate", compactText(planCutoffSection)+"\n"+statusSection,
		"operator compatibility is a Tranche B prerequisite",
		"operator compatibility must be preserved before Tranche B",
		"Tranche B requires operator evidence ingestion",
		"Preserving operator compatibility is mandatory before the second tranche can begin.",
	)
}

func TestRemoteAlphaOperatorRefusalTaxonomyDocsContract(t *testing.T) {
	remoteRaw := mustRead(t, ".docs/system_overview/remote_supported_host_alpha.md")
	statusSection := compactDocSection(t, remoteRaw, "## Future ES-Owned Remote Alpha Operator Facade", "### Operator Involvement Model")

	assertContainsAll(t, "Remote Alpha current refusal taxonomy", statusSection,
		"Current effect-free evidence-refusal taxonomy",
		"operator-compatibility surface has exactly four refusal classes",
		"These classes do not promise identical stderr",
		"Canonically recognized retired routes, aliases, and evidence flags receive the exact two-line operator-compatibility retirement refusal",
		"remote alpha operator evidence ingestion, staging, aggregation, and projection compatibility is retired; no artifact inspection, helper execution, staging, or evidence projection occurred",
		"use the owning producer directly only under its separately documented contract; this operator facade provides no compatibility adapter",
		"The historical P0h options `--readiness-summary` and `--staging-record` receive the fixed one-line historical-option refusal",
		"error: retired historical ES evidence options are unavailable",
		"Prefixed, malformed, or otherwise unrecognized stale forms receive the fixed generic refusal",
		"error: unknown operator subcommand",
		"No helper execution routing occurred.",
		"no raw argument, option, path, or value is echoed",
		"Secret-like forms receive the fixed privacy refusal",
		"error: secret material must never be passed by CLI args/env/logs/reports/artifacts",
		"The common safety invariant across all four classes is",
		"exit `2`",
		"zero stdout",
		"no supplied-value echo",
		"no file access",
		"no helper or subprocess",
		"no host inspection",
		"no staging, discovery, mutation, or projection",
		"Every class completes before script-directory canonicalization or helper-path initialization",
		"The retired grammar is not widened merely to make prefixed or malformed stale forms enter the exact two-line retirement handler",
		"P0f's former `readiness-session` workflow is retired",
		"produces no current readiness projection or artifact refresh",
		"the retired readiness session now prints no follow-up commands",
		"the retired readiness session is not available for follow-up use and currently stages, creates, refreshes, and owns no artifact",
	)
	assertContainsNone(t, "Remote Alpha current refusal taxonomy rejects broad or current-use contradictions", statusSection,
		"For every retired operator evidence route, alias, and flag, every non-secret argument shape produces the exact two-line retirement tombstone",
		"Every stale invocation receives the same tombstone.",
		"Every stale invocation receives the exact two-line retirement tombstone.",
		"The readiness session remains available for current follow-up use.",
	)
}

func TestRemoteAlphaOperatorByteStablePrivacyScannerDocsContract(t *testing.T) {
	remoteRaw := mustRead(t, ".docs/system_overview/remote_supported_host_alpha.md")
	statusSection := compactDocSection(t, remoteRaw, "## Future ES-Owned Remote Alpha Operator Facade", "### Operator Involvement Model")
	assertContainsAll(t, "Remote Alpha byte-stable global privacy scanner", statusSection,
		"`Current invariant` — secret-like option recognition is byte-deterministic",
		"independent of the caller's locale",
		"ASCII uppercase letters",
		"ASCII underscore to hyphen",
		"`root-token`, `unseal-key`, `client-token`, `vault-token`, `api-key`, `jwt-svid`",
		"`private-key`, `password`, `secret`, `token-file`, and `secret-value`",
		"any raw token occurrence of `--<secret-family>`",
		"end-of-token or outside ASCII `[A-Za-z0-9_-]`",
		"non-ASCII following byte is",
		"fail-closed delimiter",
		"ASCII alphanumeric, underscore, or hyphen",
		"`--api-keyboard`, `--token-filed`",
		"`--passwordless`, `--secretary`, and `--private-keyboard`",
		"`--<prefix>-<secret-family>` option",
		"`Temporary compatibility edge`",
		"work bounded linearly by token length",
		"Repeated shrinking-token copies",
		"locale-sensitive",
		"The global privacy prefilter remains the first argument-sensitive operation.",
	)
}

func TestRemoteAlphaOperatorDocsInvolvementAndP0dEvidenceBoundaries(t *testing.T) {
	plans := compactText(mustRead(t, "PLANS.md"))
	remoteRaw := mustRead(t, ".docs/system_overview/remote_supported_host_alpha.md")
	operatorSection := compactDocSection(t, remoteRaw, "## Future ES-Owned Remote Alpha Operator Facade", "## Direct Remote Requirements")
	involvementSection := compactDocSection(t, remoteRaw, "### Operator Involvement Model", "Purpose:")
	evidenceSection := compactDocSection(t, remoteRaw, "### Historical P0d interactive validation evidence — superseded and non-authoritative", "## Direct Remote Requirements")

	assertContainsAll(t, "Remote Alpha operator objective", plans,
		"one repo-supported ES operator facade/workflow/script",
		"minimizes manual stitching, copying, and recovery sequencing",
		"Operator involvement is expected and allowed",
		"success does not mean eliminating every prompt",
		"Explicit interactive modes are valid when they are named, bounded to a mode or subcommand, visible to the operator, and secret-safe.",
		"Default noninteractive sudo remains an ergonomic optimization for helpers that support it, not a universal success criterion for the operator facade.",
	)

	assertContainsAll(t, "Remote Alpha operator involvement model", involvementSection,
		"Human operator involvement is expected and allowed",
		"The goal is to minimize manual stitching, copying, and recovery sequencing, not to eliminate all prompts.",
		"The human operator remains the authority for interactive prompts.",
		"The script is a bounded operator facade/workflow, not the operator and not an authority source.",
		"Interactive sudo is allowed only under the explicit `--interactive-sudo` route flag",
		"Future Vault, reset, unseal, or workload-auth prompts may be allowed only in explicit secret-sensitive modes",
		"silent where appropriate",
		"never through CLI arguments, environment variables, environment files, local or remote files, logs, reports, `.out`, support bundles, retained bundles, CP artifacts, helper summaries, readiness outputs, printed commands, or Codex output.",
		"The P0m execute-reset phrase `RESET DISPOSABLE REMOTE ALPHA VAULT` must be typed by the operator directly in the visible remote helper/Vault terminal",
		"must not be accepted via CLI args, environment values, environment files, files, logs, artifacts, or Codex output.",
		"Root tokens, unseal keys, client tokens, JWT-SVID payloads, API keys, TLS private keys, SPIFFE material, passwords, raw prompts, and secret payloads must not be recorded",
		"Helper outputs remain evidence/projection only.",
		"Infrastructure Manager live refresh and support-bundle collection remain separate IM evidence/provenance/diagnostics actions",
		"Remote Alpha remains bounded proof/support posture only",
		"not production, HA, multi-tenant, general deployment architecture, remote provisioning, or reconciliation",
	)

	assertContainsAll(t, "Remote Alpha P0d interactive evidence", evidenceSection,
		"Historical P0d interactive validation evidence — superseded and non-authoritative",
		"This is a superseded historical record, not a current-status section or an invocable helper contract.",
		"It grants no current readiness, migration, apply, cleanup, or reclamation authority.",
		"operator-workstation-to-remote interactive-sudo validation evidence only",
		"generated output, not tracked source, not design authority",
		"validated the P0d operator route handoff to the staged writable-state readiness helper",
		"remote temporary staging",
		"checker execution",
		"readiness and staging-record artifact schemas",
		"transient-staging cleanup evidence",
		"secret-like redaction scan",
		"`execution-substrate.remote-alpha.es-writable-state-readiness.v1`",
		"`operation_mode=check_only`",
		"`non_mutating=true`",
		"`checker_mode=alpha-compat`",
		"`overall_classification=warning`",
		"`blockers_count=0`",
		"`warnings_count=2`",
		"`execution-substrate.remote-alpha.es-writable-state-readiness-stage-provenance.v1`",
		"`sudo_mode=interactive`",
		"`staging_occurred=true`",
		"`checker_ran=true`",
		"`sudo_unavailable=false`",
		"`wrapper_exit_code=0`",
		"`checker_exit_code=0`",
		"`transient_staging_removed=true`",
		"`staging_retained_for_diagnostics=false`",
		"did not validate the default noninteractive `sudo -n` path",
		"did not prove governed execution, CP orchestration, production readiness, Vault workload authentication, IM authority",
		"Remote Alpha deployment architecture",
		"Digest summary for the untracked evidence files",
	)

	assertContainsAll(t, "Remote Alpha operator boundary non-claims", operatorSection,
		"not IM automation or reconciliation",
		"not CP authority",
		"not Vault production lifecycle",
		"not ES token brokerage",
		"not deployment architecture",
		"The facade must not make IM a remote reconciler, CP a Vault/runtime recovery authority, ES a Vault token broker, or Remote Alpha a production/general deployment architecture.",
	)
	assertContainsNone(t, "Remote Alpha operator objective overclaim", operatorSection,
		"zero operator involvement",
		"must eliminate operator prompts",
		"must eliminate every prompt",
	)
}

func TestRemoteAlphaOperatorDocsRetireExistingHostESRoutes(t *testing.T) {
	plans := compactText(mustRead(t, "PLANS.md"))
	routeRules := compactText(mustRead(t, standingRouteRulesPath))
	remoteRaw := mustRead(t, ".docs/system_overview/remote_supported_host_alpha.md")
	implementation := mustRead(t, ".docs/execution_lifecycle/implementation.md")
	writableState := compactText(mustRead(t, ".docs/system_overview/remote_alpha_beta_es_writable_state_ownership.md"))
	implementationFacts := compactMarkedDocSection(t, "test-backed implementation facts", implementation, "## 13. Test-backed implementation facts", "## 14. Current simplifications")
	statusSection := compactDocSection(t, remoteRaw, "## Future ES-Owned Remote Alpha Operator Facade", "### Operator Involvement Model")
	p0dSection := compactDocSection(t, remoteRaw, "### Historical P0d Staged-Helper Delegation Implementation — Retired", "### Historical P0f Readiness Session Workflow — Retired")
	p0fSection := compactDocSection(t, remoteRaw, "### Historical P0f Readiness Session Workflow — Retired", "### Historical P0g Evidence Ingestion — Superseded and Non-Authoritative")

	assertContainsAll(t, "Remote Alpha retirement PLANS boundary", plans,
		"P0c, P0d, and P0f are now retired compatibility history.",
		"no longer inspect or contact a host and no longer produce or refresh evidence",
		"underlying six public wrappers remain only as compatibility delegators to fixed exit-2 tombstones",
		"Selecting a future diagnostic or existing-host migration contract is a separately governed decision",
		"privacy prefilter is the first argument-sensitive operation",
		"before script-directory canonicalization or helper-path initialization",
	)
	assertContainsAll(t, "Remote Alpha retirement standing route rules boundary", routeRules,
		"public names are preserved only as fixed effect-free compatibility tombstones, not as helper or readiness workflows",
	)
	assertContainsAll(t, "Remote Alpha retirement current status", statusSection,
		"P0d's former staged-helper delegation route",
		"Every non-secret argument shape now reaches a fixed two-line exit-2 refusal with no host inspection, staging, mutation, or evidence production.",
		"secret-like argument shapes receive its fixed one-line privacy refusal instead",
		"P0f's former `readiness-session` workflow is retired under the same fixed precedence",
		"produces no current readiness projection or artifact refresh",
		"privacy prefilter is the first argument-sensitive operation",
		"before script-directory canonicalization or helper-path initialization",
	)
	assertContainsAll(t, "Remote Alpha P0d historical boundary", p0dSection,
		"historical v1 implementation context only",
		"Non-secret operator-facade argument shapes reach the fixed two-line tombstone",
		"secret-like shapes are rejected first by the fixed one-line privacy prefilter",
	)
	assertContainsAll(t, "Remote Alpha P0f historical boundary", p0fSection,
		"historical v1 context only",
		"readiness session no longer stages, invokes, discovers, refreshes, or projects current readiness evidence",
	)
	assertContainsNone(t, "Remote Alpha current retired-route status", statusSection,
		"P0d implements exactly one staged-helper delegation route",
		"P0f implements exactly one bounded readiness workflow command",
	)
	assertContainsAll(t, "retired existing-host ownership route in implementation facts", implementationFacts,
		"`scripts/internal/remote_alpha_prepare_es_writable_state_ownership.sh` is a fixed, effect-free exit-2 tombstone",
		"no current host or artifact inspection, mutation, repair, quarantine, or evidence production",
		"six retired internal routes and their unchanged public-wrapper delegators",
		"no v2 replacement or current existing-host migration authority",
		"Historical ownership-normalization artifacts and old helper tests grant no current operational permission",
		"ES still validates existing result objects and normalization evidence without in-place metadata repair",
		"may initialize owner and mode on newly created unpublished result temporaries, records, and normalization evidence",
		"Existing-object repair and deletion based on an uncertain pathname are unsupported",
	)
	assertContainsNone(t, "superseded ownership helper repair claim", implementationFacts,
		"The bounded writable-state ownership helper may now repair only direct retained-result artifacts",
		"may quarantine incompatible legacy retained run directories",
	)
	assertContainsAll(t, "owning existing-host retirement decision", writableState,
		"six internal implementations are fixed exit-2 tombstones",
		"six public wrappers remain unchanged delegators",
		"inspect no host or artifact, contact no service, create no temporary or evidence file, and perform no mutation",
		"No read-only current-readiness mode, apply simulation, structured unsupported artifact, or v2 replacement exists",
		"ES still qualifies configured staging and result roots",
		"No v2 replacement exists for this retired family",
	)
}

func TestBoundedRepairRemoteAlphaCurrentAndHistoricalDocBoundaries(t *testing.T) {
	remoteRaw := mustRead(t, ".docs/system_overview/remote_supported_host_alpha.md")
	statusSection := compactDocSection(t, remoteRaw, "## Future ES-Owned Remote Alpha Operator Facade", "### Operator Involvement Model")
	assertContainsAll(t, "Remote Alpha repaired current status", statusSection,
		"operator-compatibility surface has exactly four refusal classes",
		"Canonically recognized retired routes, aliases, and evidence flags receive the exact two-line operator-compatibility retirement refusal",
		"The historical P0h options `--readiness-summary` and `--staging-record` receive the fixed one-line historical-option refusal",
		"Prefixed, malformed, or otherwise unrecognized stale forms receive the fixed generic refusal",
		"Secret-like forms receive the fixed privacy refusal",
		"The common safety invariant across all four classes is",
		"former current-schema evidence checker, automatic filename discovery, schema maps, and safe-field projections are absent from the live facade",
		"No schema, validator, fixture, producer, artifact, or protocol v2 replacement exists for the retired ES writable-state/service-user migration family",
		"unrelated current EGS hardening v2 schema remains current",
	)
	assertContainsNone(t, "Remote Alpha repaired current status excludes retired behavior", statusSection,
		"P0d implements exactly one staged-helper delegation route",
		"P0f implements exactly one bounded readiness workflow command",
		"delegates writable-state readiness to `scripts/remote_alpha_stage_es_writable_state_readiness_check.sh`",
		"preserves the exact existing Infrastructure Manager-consumed local artifact filenames",
		"For every retired operator evidence route, alias, and flag, every non-secret argument shape produces the exact two-line retirement tombstone",
	)

	historicalParser := compactDocSection(t, remoteRaw, "### Historical P0g Evidence Ingestion — Superseded and Non-Authoritative", "### P0i Host-Local Vault Unseal Existing Recovery Session")
	assertContainsAll(t, "Remote Alpha parser rationale is historical only", historicalParser,
		"This entire subsection is design history only",
		"grants no current evidence-check flag, parser, schema interpretation, discovery, aggregation, or projection behavior",
		"The local Python runtime must expose `O_NOFOLLOW`; capability absence fails closed rather than substituting zero",
		"performs `lstat` before open",
		"opens no-follow",
		"revalidates the descriptor",
		"`lstat`s the visible path again",
		"same regular object with the same size",
		"strict duplicate-aware decoder",
		"explicit bounded stack rather than recursive calls",
		"before the complete output is published",
	)

	for _, path := range []string{
		".docs/system_overview/remote_alpha_beta_es_privilege_boundary_assessment.md",
		".docs/system_overview/remote_alpha_beta_es_privileged_operation_matrix.md",
		".docs/system_overview/remote_alpha_beta_es_runtime_ownership_normalization.md",
	} {
		doc := compactText(mustRead(t, path))
		assertContainsAll(t, "preserved superseded historical design "+path, doc,
			"## Historical design record — superseded and non-authoritative",
			"**superseded** and **non-authoritative**",
			"**not an available operator route**",
			"**not migration, cleanup, or reclamation authority**",
		)
	}
}

func TestCurrentLifecycleAndRemoteDocsRejectBoundedContradictionClasses(t *testing.T) {
	contractsRaw := mustRead(t, ".docs/execution_lifecycle/contracts.md")
	resultSection := strings.ToLower(compactDocSection(t, contractsRaw, "## 9. Result contract", "## 10. Cancel contract"))
	cancelSection := strings.ToLower(compactDocSection(t, contractsRaw, "## 10. Cancel contract", "## 11. Run-ID and scheduler lookup contract"))
	submitSection := strings.ToLower(compactDocSection(t, contractsRaw, "## 6. Submit contract", "## 7. Status contract"))
	remoteRaw := mustRead(t, ".docs/system_overview/remote_supported_host_alpha.md")
	remoteCurrent := strings.ToLower(compactDocSection(t, remoteRaw, "## Future ES-Owned Remote Alpha Operator Facade", "### Operator Involvement Model"))

	checks := []struct {
		label    string
		text     string
		patterns []string
	}{
		{
			label: "terminal or result-triggered staging deletion",
			text:  resultSection,
			patterns: []string{
				`(?:terminal (?:success|failure|loss|cancellation|state)|result(?: publication| packaging| success| availability)).{0,120}\b(?:may|must|will|can|triggers?|authorizes?|permits?)\b.{0,60}\b(?:delete|remove|clean up|cleanup|reclaim|quarantine)\b.{0,80}\b(?:staging|run root|run-root)\b`,
				`(?:terminal (?:success|failure|loss|cancellation|state)|result(?: publication| packaging| success| availability)).{0,120}\b(?:may|must|will|can|triggers?|authorizes?|permits?)\b.{0,60}\b(?:staging|run root|run-root)\b.{0,30}\b(?:deletion|removal|cleanup|reclamation|quarantine)\b`,
				`\b(?:staging|run root|run-root)\b.{0,80}\b(?:may|must|will|can|is)\b.{0,30}\b(?:deleted|removed|cleaned up|reclaimed|quarantined)\b.{0,100}(?:terminal|result)`,
			},
		},
		{
			label: "cancellation-authorized quarantine or reclamation",
			text:  cancelSection,
			patterns: []string{
				`cancel(?:lation|led|ed)?.{0,100}\b(?:authorizes?|permits?|triggers?|may|must|will|can)\b.{0,60}\b(?:quarantine|reclamation|reclaim|delete|remove)\b`,
				`\b(?:quarantine|reclamation|reclaim)\b.{0,80}\b(?:is|becomes?)\b.{0,30}\b(?:authorized|permitted)\b.{0,60}cancel`,
			},
		},
		{
			label: "no-receipt-implies-no-claim wording",
			text:  submitSection,
			patterns: []string{
				`(?:no|absent|missing) (?:submit )?receipt.{0,50}(?:means|proves|implies|establishes).{0,40}(?:no|absent|missing).{0,30}(?:claim|staging)`,
				`without (?:a )?receipt.{0,60}(?:no|never).{0,30}(?:claim|staging)`,
			},
		},
		{
			label: "current readiness-session or helper inspection",
			text:  remoteCurrent,
			patterns: []string{
				`readiness-session.{0,40}(?:is|remains) (?:active|available|current|implemented)`,
				`(?:readiness-session|writable-state readiness route).{0,60}\b(?:inspects the|contacts the|stages the|invokes the|refreshes current|produces current)\b`,
				`(?:readiness helper|writable-state helper).{0,40}(?:is|remains) (?:active|available|current)`,
			},
		},
		{
			label: "archived readiness becoming current authority",
			text:  remoteCurrent,
			patterns: []string{
				`(?:archived|historical).{0,100}(?:apply_ready|readiness).{0,100}(?:is|becomes?|remains?|provides?) (?:current )?(?:authority|authoritative)`,
				`(?:apply_ready|readiness).{0,100}(?:from )?(?:archived|historical).{0,80}(?:authorizes?|permits?)`,
			},
		},
		{
			label: "retired route described as active",
			text:  remoteCurrent,
			patterns: []string{
				`retired route.{0,60}(?:is active|remains available|delegates to|invokes)`,
				`(?:es-writable-state-readiness-check|readiness-session).{0,80}(?:remains available|delegates to|invokes the readiness)`,
			},
		},
	}

	for _, check := range checks {
		for _, expression := range check.patterns {
			if match := regexp.MustCompile(expression).FindString(check.text); match != "" {
				t.Fatalf("%s contradiction matched %q", check.label, match)
			}
		}
	}

	headingPattern := regexp.MustCompile(`(?im)^#{2,4}\s+[^\n]*p0d[^\n]*validation evidence[^\n]*$`)
	headings := headingPattern.FindAllString(remoteRaw, -1)
	if len(headings) != 1 {
		t.Fatalf("P0d validation-evidence heading count = %d, want 1", len(headings))
	}
	heading := strings.ToLower(headings[0])
	for _, required := range []string{"historical", "superseded", "non-authoritative"} {
		if !strings.Contains(heading, required) {
			t.Fatalf("historical P0d evidence heading lacks %q: %q", required, headings[0])
		}
	}
}

func TestRemoteAlphaOperatorDocsRetireAllSelectedEvidenceCompatibility(t *testing.T) {
	plans := compactText(mustRead(t, "PLANS.md"))
	remoteRaw := mustRead(t, ".docs/system_overview/remote_supported_host_alpha.md")
	statusSection := compactDocSection(t, remoteRaw, "## Future ES-Owned Remote Alpha Operator Facade", "### Operator Involvement Model")
	operatorModel := compactDocSection(t, remoteRaw, "### Operator Involvement Model", "### Historical P0c Staged-Helper Delegation Plan — Retired")
	recoverySection := compactDocSection(t, remoteRaw, "### Historical P0g Evidence Ingestion — Superseded and Non-Authoritative", "### P0h Historical-v1 Evidence Interpretation")
	historicalSection := compactDocSection(t, remoteRaw, "### P0h Historical-v1 Evidence Interpretation", "### P0i Host-Local Vault Unseal Existing Recovery Session")

	assertContainsAll(t, "Remote Alpha evidence compatibility cutoff PLANS boundary", plans,
		"The former P0g evidence-ingestion surface and the P0n/P0r facade staging and aggregation routes are superseded compatibility history",
		"no longer parses, validates, interprets, aggregates, discovers, stages, or projects",
		"P0h's historical-v1 display is retired",
		"no longer accepts `--readiness-summary` or `--staging-record`",
		"Archived v1 fixture and artifact bytes remain evidence only outside live operator behavior",
		"The former current-schema checker, its automatic evidence-directory discovery, and its safe-field projections are retired with P0g",
	)
	assertContainsNone(t, "Remote Alpha facade compatibility is not a Tranche B gate", plansAndStandingRules(t)+" "+compactText(remoteRaw),
		"operator compatibility is a Tranche B prerequisite",
		"facade compatibility is required before Tranche B",
		"Tranche B requires preservation of operator compatibility",
	)
	assertContainsAll(t, "Remote Alpha recovery parser is explicit history", recoverySection,
		"This entire subsection is design history only",
		"grants no current evidence-check flag, parser, schema interpretation, discovery, aggregation, or projection behavior",
		"strict duplicate-aware decoder",
	)
	assertContainsAll(t, "Remote Alpha historical-v1 docs boundary", historicalSection,
		"P0h's former local historical-v1 display is retired",
		"no live operator route parses, validates, or projects those schemas",
		"fixed non-echoing stale-input refusal before file access",
		"former local-only evidence-directory mode discovered four direct filenames",
		"current facade does not accept that control and performs no artifact discovery",
		"execution-substrate.remote-alpha.vault-workload-auth-summary.v1",
		"execution-substrate.remote-runtime-identity-helper-summary.v1alpha1",
		"execution-substrate.remote-alpha.vault-service-user-migration-summary.v1",
	)
	assertContainsNone(t, "Remote Alpha current status has no live evidence compatibility", statusSection,
		"`recovery-session --evidence-check` is current-only",
		"Known current schemas are interpreted through explicit safe-field allowlists",
		"P0n adds one separate Mac-side post-reset workload-auth evidence route",
		"P0r implements exactly one Mac-side runtime identity evidence route",
		"stages only `scripts/remote_alpha_runtime_identity_helper_summary.sh`",
		"stages exactly the public workload-auth helper and its internal implementation helper",
	)
	assertContainsAll(t, "Remote Alpha current operator model records the cutoff", operatorModel,
		"The former P0n workload-auth evidence facade is retired",
		"The former P0r runtime-identity summary facade is retired",
		"The former P0n and P0r evidence compatibility routes are retired and are not Mac-side execution contexts",
		"The operator facade provides no route or compatibility adapter for those three evidence families",
	)
	assertContainsNone(t, "Remote Alpha current operator model has no live retired route", operatorModel,
		"P0n adds the Mac-side",
		"P0r adds the Mac-side",
		"P0n workload-auth evidence route",
		"P0r runtime identity summary evidence route",
	)
}
func TestRemoteAlphaOperatorP0iDocsHostLocalUnsealBoundary(t *testing.T) {
	routeRules := compactText(mustRead(t, standingRouteRulesPath))
	remoteRaw := mustRead(t, ".docs/system_overview/remote_supported_host_alpha.md")
	operatorSection := compactDocSection(t, remoteRaw, "### P0i Host-Local Vault Unseal Existing Recovery Session", "### P0j Mac-Side Vault Unseal Existing Recovery Session")

	assertContainsAll(t, "Remote Alpha operator P0i standing route rules boundary", routeRules,
		"The P0i implementation/self-audit slice may add exactly one secret-sensitive",
		"`scripts/remote_alpha_operator.sh recovery-session vault-unseal-existing --host-local`",
		"host-local only",
		"must require explicit `--host-local`",
		"may delegate only to the public helper",
		"`scripts/remote_alpha_reset_disposable_vault.sh --unseal-only`",
		"fixed path resolved from the operator script",
		"must not use SSH, remote staging, host detection, helper path overrides, generic helper dispatch, `scripts/internal` paths",
		"must not run or add destructive reset",
		"post-unseal workload-auth checks",
		"runtime identity generation",
		"Vault service-user execution",
		"Infrastructure Manager execution",
		"support-bundle collection",
		"CP proof",
		"default noninteractive readiness validation",
		"the human remains the operator",
		"unseal key entry happens directly in the visible terminal owned by the delegated helper and Vault CLI",
		"Codex and the operator facade must not receive, type, read, log, relay, persist, summarize, or accept unseal keys",
		"CLI arguments, environment files, logs, `.out`, reports, support bundles, retained bundles, helper summaries, readiness outputs, printed commands, or Codex output",
		"secret-sensitive but non-destructive evidence/support workflow glue only",
		"must not make ES a Vault token broker, IM a reconciler, CP a recovery authority, or Remote Alpha deployment/provisioning/reconciliation architecture",
	)

	assertContainsAll(t, "Remote Alpha operator P0i docs boundary", operatorSection,
		"`Bounded slice rule`: P0i adds exactly one secret-sensitive",
		"`scripts/remote_alpha_operator.sh recovery-session vault-unseal-existing --host-local`",
		"explicit host-local operator mode",
		"must be run on the Remote Alpha host where Vault is installed and reachable",
		"must require `--host-local` before delegation",
		"does not detect the host",
		"does not use SSH or remote staging",
		"does not provide a Mac-side path for unseal",
		"`scripts/remote_alpha_reset_disposable_vault.sh --unseal-only`",
		"The helper path is fixed relative to the operator script",
		"must not source helper scripts",
		"call `scripts/internal/*`",
		"helper path overrides",
		"generic helper dispatch",
		"the human remains the operator",
		"visible delegated helper/Vault CLI terminal prompt",
		"Codex and the facade must not receive, type, read, log, relay, persist, summarize, or accept unseal keys",
		"secret material must never be passed through CLI arguments, environment files, logs, `.out`, reports, support bundles, retained bundles, helper summaries, readiness outputs, printed commands, or Codex output",
		"Allowed flags for this route are:",
		"`--host-local`",
		"The route must reject:",
		"`--ssh-target`",
		"`--execute-reset`",
		"`--post-unseal-check`",
		"`--interactive-sudo`",
		"equals-form options",
		"secret-like arguments",
		"secret-sensitive but non-destructive",
		"not destructive reset",
		"not workload-auth bootstrap or check",
		"not Infrastructure Manager refresh or support-bundle collection",
		"not CP proof",
		"not default noninteractive readiness validation",
		"must not write logs, `.out`, transcripts, reports, operator summaries, support bundles, or retained bundles",
		"must not wrap the delegated helper in transcript capture",
		"not ES Vault token brokerage, IM authority or reconciliation, CP recovery authority",
		"not Remote Alpha deployment/provisioning/reconciliation architecture",
	)
}

func TestRemoteAlphaOperatorP0jDocsMacSideUnsealBoundary(t *testing.T) {
	routeRules := compactText(mustRead(t, standingRouteRulesPath))
	remoteRaw := mustRead(t, ".docs/system_overview/remote_supported_host_alpha.md")
	operatorSection := compactDocSection(t, remoteRaw, "### P0j Mac-Side Vault Unseal Existing Recovery Session", "### P0k Mac-Side Disposable Vault Reset Dry-Run Recovery Session")

	assertContainsAll(t, "Remote Alpha operator P0j standing route rules boundary", routeRules,
		"The P0j implementation/self-audit slice may extend exactly that",
		"`recovery-session vault-unseal-existing`",
		"`scripts/remote_alpha_operator.sh recovery-session vault-unseal-existing --ssh-target <target> --interactive-tty`",
		"The P0i `--host-local` route remains available only for an operator already on the Linux Remote Alpha host.",
		"must require explicit `--ssh-target` plus `--interactive-tty`",
		"must fail before staging when local stdin or stdout is not a visible terminal",
		"must reject bare execution",
		"`--host-local` combined with `--ssh-target`",
		"`--ssh-target` without `--interactive-tty`",
		"`--interactive-tty` without `--ssh-target`",
		"The `--ssh-target` value must be a single SSH target, not an SSH option or shell command.",
		"stage only the public helper",
		"`scripts/remote_alpha_reset_disposable_vault.sh`",
		"`remote_alpha_reset_disposable_vault.sh --unseal-only`",
		"interactive SSH TTY such as `ssh -tt`",
		"must not stage `scripts/remote_alpha_operator.sh`",
		"stage a helper bundle",
		"source helpers",
		"call `scripts/internal/*`",
		"introduce generic helper dispatch",
		"offer `--keep-staging-on-failure`",
		"capture transcripts",
		"use `tee`",
		"run `script`",
		"write `.out`, logs, reports, summaries, support bundles, retained bundles, or generated JSON",
		"must attempt remote staged-helper cleanup by default",
		"must not run or add destructive reset",
		"post-unseal workload-auth checks",
		"Infrastructure Manager execution",
		"support-bundle collection",
		"CP proof",
		"unseal key entry happens only inside the visible SSH/helper/Vault terminal prompt",
		"must not receive, type, read, parse, log, relay, persist, summarize, or accept unseal keys",
		"must not make ES a Vault token broker, IM a reconciler, CP a recovery authority, or Remote Alpha deployment/provisioning/reconciliation architecture",
	)

	assertContainsAll(t, "Remote Alpha operator P0j docs boundary", operatorSection,
		"`Bounded slice rule`: P0j extends only the existing",
		"`scripts/remote_alpha_operator.sh recovery-session vault-unseal-existing --ssh-target <target> --interactive-tty`",
		"The P0i host-local route remains available",
		"operator normally works from the Mac/operator workstation",
		"Linux Remote Alpha host does not necessarily have `scripts/remote_alpha_operator.sh`",
		"Topology rules:",
		"exactly one topology is required",
		"`--host-local` and `--ssh-target` together must fail",
		"`--interactive-tty` without `--ssh-target` must fail",
		"`--ssh-target` without `--interactive-tty` must fail",
		"bare `vault-unseal-existing` execution must fail",
		"`--ssh-target` value must be a single SSH target",
		"local stdin and stdout must both be visible terminals",
		"Allowed flags for `vault-unseal-existing` are:",
		"`--ssh-target <target>`",
		"`--interactive-tty`",
		"The route must reject:",
		"`--execute-reset`",
		"`--post-unseal-check`",
		"`--unseal-only`",
		"`--keep-staging-on-failure`",
		"secret-like arguments",
		"stage only `scripts/remote_alpha_reset_disposable_vault.sh`",
		"do not stage `scripts/remote_alpha_operator.sh`",
		"do not stage a bundle",
		"do not source helper scripts",
		"do not call `scripts/internal/*`",
		"do not construct helper paths from user input",
		"do not introduce generic helper dispatch",
		"route-specific remote scratch path",
		"allocate an interactive SSH TTY",
		"`remote_alpha_reset_disposable_vault.sh --unseal-only`",
		"never pass `--execute-reset`, `--post-unseal-check`, workload-auth flags",
		"do not capture stdout or stderr to files",
		"do not use `tee`",
		"do not run `script`",
		"cleanup of the staged helper/root must be attempted by default",
		"writes no `.out`",
		"writes no operator summary",
		"writes no support bundle",
		"writes no report",
		"writes no generated JSON",
		"process exit plus operator-visible terminal output",
		"post-unseal evidence checks, Infrastructure Manager refresh, support-bundle collection, and workload-auth checks remain separate follow-up actions and are not executed here",
		"the human remains the operator",
		"visible SSH/helper/Vault CLI terminal prompt",
		"must not receive, type, read, parse, log, relay, persist, summarize, or accept unseal keys",
		"not ES Vault token brokerage, IM authority or reconciliation, CP recovery authority",
		"not Remote Alpha deployment/provisioning/reconciliation architecture",
	)
}

func TestRemoteAlphaOperatorP0kDocsMacSideResetDryRunBoundary(t *testing.T) {
	routeRules := compactText(mustRead(t, standingRouteRulesPath))
	remoteRaw := mustRead(t, ".docs/system_overview/remote_supported_host_alpha.md")
	operatorSection := compactDocSection(t, remoteRaw, "### P0k Mac-Side Disposable Vault Reset Dry-Run Recovery Session", "### P0l Mac-Side Disposable Vault Reset Execute-Reset Contract Prep")

	assertContainsAll(t, "Remote Alpha operator P0k standing route rules boundary", routeRules,
		"The P0k implementation/self-audit slice may add exactly one Mac-side disposable",
		"`scripts/remote_alpha_operator.sh recovery-session vault-reset-disposable --ssh-target <target> --dry-run`",
		"dry-run-only and non-destructive",
		"stage only the public helper",
		"`scripts/remote_alpha_reset_disposable_vault.sh`",
		"fixed path resolved from `BASH_SOURCE[0]`",
		"invoke the staged helper only in the helper's documented `--dry-run` mode",
		"must pass `--dry-run` explicitly",
		"must require explicit `--ssh-target` plus `--dry-run`",
		"must not require `--interactive-tty`",
		"must reject `--host-local`, `--interactive-tty`, `--execute-reset`, `--unseal-only`, `--post-unseal-check`",
		"`--keep-staging-on-failure`",
		"helper path overrides",
		"workload-auth flags",
		"Infrastructure Manager commands",
		"all secret-like arguments",
		"must not stage `scripts/remote_alpha_operator.sh`",
		"stage a bundle",
		"source helper scripts",
		"call `scripts/internal/*`",
		"introduce generic helper dispatch",
		"capture transcripts",
		"use `tee`",
		"run `script`",
		"write `.out`, logs, reports, summaries, support bundles, retained bundles, generated JSON, or any operator-owned artifact",
		"attempt cleanup of the staged reset-capable helper by default",
		"must not offer `--keep-staging-on-failure`",
		"planning/inspection only",
		"must not stop Vault, move raft storage, run `vault operator init`, unseal Vault",
		"run post-unseal checks",
		"run workload-auth checks",
		"refresh Infrastructure Manager evidence",
		"collect support bundles",
		"run CP proof",
		"Destructive `--execute-reset` remains a future explicit destructive mode with the exact confirmation phrase `RESET DISPOSABLE REMOTE ALPHA VAULT`",
		"outputs remain operator-visible evidence/projection/diagnostics only, never authority",
		"must not make ES a Vault token broker, IM a reconciler, CP a recovery authority, or Remote Alpha deployment/provisioning/reconciliation architecture",
	)

	assertContainsAll(t, "Remote Alpha operator P0k docs boundary", operatorSection,
		"`Bounded slice rule`: P0k adds exactly one Mac-side dry-run planning route",
		"`scripts/remote_alpha_operator.sh recovery-session vault-reset-disposable --ssh-target <target> --dry-run`",
		"inspect the disposable reset plan",
		"without performing the reset",
		"not Vault lifecycle automation and not a new authority source",
		"Topology rules:",
		"Mac-side only for this slice",
		"`--ssh-target <target>` is required",
		"`--dry-run` is required",
		"`--interactive-tty` is not required for dry-run and is rejected",
		"`--host-local` is not accepted for this route",
		"bare `vault-reset-disposable` execution must fail",
		"Allowed flags for `vault-reset-disposable` are:",
		"`--ssh-target <target>`",
		"`--dry-run`",
		"The route must reject:",
		"`--execute-reset`",
		"`--unseal-only`",
		"`--post-unseal-check`",
		"`--host-local`",
		"`--interactive-tty`",
		"`--keep-staging-on-failure`",
		"workload-auth flags",
		"Infrastructure Manager commands",
		"helper path overrides",
		"secret-like arguments",
		"stage only `scripts/remote_alpha_reset_disposable_vault.sh`",
		"do not stage `scripts/remote_alpha_operator.sh`",
		"do not stage a bundle",
		"do not source helper scripts",
		"do not call `scripts/internal/*`",
		"do not construct helper paths from user input",
		"do not introduce generic helper dispatch",
		"route-specific remote scratch path",
		"`remote_alpha_reset_disposable_vault.sh --dry-run`",
		"the helper supports `--dry-run`, so the operator facade passes it explicitly",
		"never pass `--execute-reset`, `--unseal-only`, `--post-unseal-check`",
		"do not allocate an interactive SSH TTY for dry-run",
		"do not capture stdout or stderr to files",
		"do not use `tee`",
		"do not run `script`",
		"cleanup of the staged helper/root must be attempted by default",
		"writes no `.out`",
		"writes no operator summary",
		"writes no support bundle",
		"writes no report",
		"writes no generated JSON",
		"artifacts and outputs remain evidence/projection/diagnostics only, never authority",
		"the route does not stop Vault",
		"the route does not move raft storage",
		"the route does not run `vault operator init`",
		"the route does not unseal Vault",
		"the route does not run post-unseal checks",
		"the route does not run workload-auth checks",
		"the route does not run Infrastructure Manager refresh",
		"the route does not collect support bundles",
		"Destructive `--execute-reset` remains a future explicit destructive mode",
		"`RESET DISPOSABLE REMOTE ALPHA VAULT`",
		"not ES Vault token brokerage, IM authority or reconciliation, CP recovery authority",
		"not Remote Alpha deployment/provisioning/reconciliation architecture",
	)
}

func TestRemoteAlphaOperatorP0lDocsMacSideResetExecuteContractPrep(t *testing.T) {
	routeRules := compactText(mustRead(t, standingRouteRulesPath))
	remoteRaw := mustRead(t, ".docs/system_overview/remote_supported_host_alpha.md")
	operatorSection := compactDocSection(t, remoteRaw, "### P0l Mac-Side Disposable Vault Reset Execute-Reset Contract Prep", "### P0m Mac-Side Disposable Vault Reset Execute-Reset Recovery Session")
	allowedFlags := compactDocSection(t, remoteRaw, "Allowed flags for the P0l `vault-reset-disposable --execute-reset` contract are:", "The P0l contract route must reject:")

	assertContainsAll(t, "Remote Alpha operator P0l standing route rules boundary", routeRules,
		"The P0l design/static-test prep slice may define, but must not implement, the future Mac-side destructive disposable Vault reset route",
		"`scripts/remote_alpha_operator.sh recovery-session vault-reset-disposable --ssh-target <target> --execute-reset --interactive-tty`",
		"The already validated P0k dry-run route is the prerequisite for this design",
		"commit `b1a561a` passed live validation",
		"`scripts/remote_alpha_operator.sh recovery-session vault-reset-disposable --ssh-target host_to_remote_linux_m75q --dry-run`",
		"proving the non-destructive staging, invocation, and cleanup-attempt behavior for reset planning",
		"P0l stayed docs/static-test only",
		"at P0l, `--execute-reset` remained future until later separate implementation, audit, and live-validation slices",
		"must require `--ssh-target` plus `--interactive-tty`",
		"`--execute-reset` must require `--interactive-tty`",
		"`--dry-run` and `--execute-reset` are mutually exclusive",
		"must not add a host-local execute-reset path through the operator facade in this slice",
		"stage only `scripts/remote_alpha_reset_disposable_vault.sh`",
		"invoke only the staged helper with `--execute-reset`",
		"must never include `--post-unseal-check` in the first destructive slice",
		"must never combine reset with workload-auth checks, runtime identity summaries, Infrastructure Manager refresh, support-bundle collection, CP proof",
		"preinstalled remote bundles",
		"generic helper dispatch",
		"must attempt cleanup of the staged reset-capable helper by default",
		"must not offer `--keep-staging-on-failure`",
		"The exact confirmation phrase remains `RESET DISPOSABLE REMOTE ALPHA VAULT`",
		"must not be accepted through CLI arguments, environment variables, environment files, local or remote files",
		"must not be logged, summarized, captured, parsed, or relayed by the operator facade",
		"Root tokens, unseal keys, client tokens, Vault tokens, API keys, private keys, passwords, JWT-SVID payloads, and secret payloads must never be accepted",
		"Any Vault init/unseal material is handled only by the human operator in the visible remote helper/Vault terminal",
		"process exit plus operator-visible helper output only",
		"must not tee, run `script`, record, capture, parse, or summarize terminal transcripts",
		"write no `.out` summary, operator summary file, support bundle, report, generated JSON, retained bundle, or CP artifact",
		"Post-reset evidence checks are separate later steps",
		"Stop conditions for the future route include no visible TTY, SSH host-auth prompts",
		"reset-helper broad raft path guard failures",
		"exact phrase mismatch",
		"failure to clean up the staged reset-capable helper",
		"bounded Remote Alpha proof/support workflow glue only",
		"must not make ES a Vault token broker, IM a reconciler, CP a recovery authority, or Remote Alpha production/deployment/reconciliation architecture",
	)

	assertContainsAll(t, "Remote Alpha operator P0l docs boundary", operatorSection,
		"`Bounded slice rule`: P0l was design/static-test prep only.",
		"did not implement `--execute-reset`",
		"did not add a behavior route",
		"did not run live SSH, sudo, Vault, reset, unseal, Infrastructure Manager refresh, support-bundle collection, CP proof, workload-auth checks, or runtime identity generation",
		"At P0l, execute-reset remained future until later separate implementation, audit, and live-validation slices.",
		"The already validated P0k dry-run route was the prerequisite for this contract",
		"`scripts/remote_alpha_operator.sh recovery-session vault-reset-disposable --ssh-target host_to_remote_linux_m75q --dry-run`",
		"proved non-destructive staging, helper invocation, and cleanup-attempt behavior for the reset planning path only",
		"It did not prove or enable destructive reset execution.",
		"Contract command shape:",
		"`scripts/remote_alpha_operator.sh recovery-session vault-reset-disposable --ssh-target <target> --execute-reset --interactive-tty`",
		"Mac-side only for this operator-facade route",
		"`--ssh-target <target>` is required",
		"`--execute-reset` is required for the destructive route",
		"`--interactive-tty` is required for `--execute-reset`",
		"`--dry-run` and `--execute-reset` are mutually exclusive",
		"`--host-local` is not accepted for this operator-facade route in P0l",
		"local stdin and stdout must both be visible terminals",
		"Allowed flags for the P0l `vault-reset-disposable --execute-reset` contract are:",
		"`--execute-reset`",
		"`--interactive-tty`",
		"The P0l contract route must reject:",
		"`--dry-run`",
		"`--post-unseal-check`",
		"`--keep-staging-on-failure`",
		"workload-auth flags",
		"Infrastructure Manager commands",
		"support-bundle commands",
		"CP proof or governed-smoke commands",
		"runtime identity summary flags",
		"helper path overrides",
		"preinstalled remote bundle assumptions",
		"secret-like arguments",
		"Confirmation behavior:",
		"the exact confirmation phrase remains `RESET DISPOSABLE REMOTE ALPHA VAULT`",
		"typed by the human operator in the visible remote helper/Vault terminal",
		"must not be accepted via CLI arguments, environment variables, environment files, local files, remote files",
		"must not be logged, summarized, captured, parsed, replayed, or relayed by the operator facade",
		"exact phrase mismatch is a stop condition",
		"Secret handling:",
		"root tokens, unseal keys, client tokens, Vault tokens, API keys, private keys, passwords, JWT-SVID payloads, and secret payloads must not be accepted",
		"any Vault init output, root token, unseal key, or Vault unseal material is handled only by the human operator in the visible remote helper/Vault terminal",
		"must not tee, run `script`, record, capture, parse, or summarize terminal transcripts",
		"stage only `scripts/remote_alpha_reset_disposable_vault.sh`",
		"do not stage `scripts/remote_alpha_operator.sh`",
		"do not stage a bundle",
		"do not call `scripts/internal/*`",
		"do not introduce generic helper dispatch",
		"do not require a preinstalled remote bundle",
		"invoke the staged helper only as `remote_alpha_reset_disposable_vault.sh --execute-reset`",
		"never include `--post-unseal-check` in the first destructive slice",
		"never combine reset with workload-auth check, runtime identity summary, Infrastructure Manager refresh, support-bundle collection, CP proof",
		"do not capture stdout or stderr to files",
		"do not use `tee`",
		"do not run `script`",
		"cleanup of the staged reset-capable helper/root must be attempted by default",
		"failure to clean up the staged reset-capable helper is a route failure",
		"no `.out` summary from the ES operator route",
		"no operator summary file",
		"no support bundle",
		"no Infrastructure Manager execution",
		"process exit and operator-visible helper output are the only route result surfaces for this destructive route",
		"post-reset evidence checks are separate later steps",
		"evidence/projection output is non-authoritative",
		"Stop conditions for the contract route:",
		"SSH host-auth prompt or unknown-host authenticity prompt",
		"reset helper broad raft path guard triggers",
		"failure to clean up the staged reset-capable helper",
		"The contract remains bounded ES Remote Alpha proof/support workflow glue only.",
		"The human remains the operator.",
		"does not eliminate explicit operator prompts",
		"not Vault production lifecycle automation",
		"not ES Vault token brokerage",
		"not IM authority or reconciliation",
		"not CP recovery authority",
		"not governed execution proof",
		"not Remote Alpha production, deployment, provisioning, or reconciliation architecture",
	)

	assertContainsAll(t, "Remote Alpha operator P0l allowed flags", allowedFlags,
		"`--help`",
		"`--ssh-target <target>`",
		"`--execute-reset`",
		"`--interactive-tty`",
	)
	assertContainsNone(t, "Remote Alpha operator P0l allowed flags", allowedFlags,
		"`--dry-run`",
		"`--post-unseal-check`",
		"`--host-local`",
		"`--keep-staging-on-failure`",
		"workload-auth",
		"support-bundle",
	)
}

func TestRemoteAlphaOperatorP0mDocsMacSideResetExecuteImplementationBoundary(t *testing.T) {
	routeRules := compactText(mustRead(t, standingRouteRulesPath))
	remoteRaw := mustRead(t, ".docs/system_overview/remote_supported_host_alpha.md")
	operatorSection := compactDocSection(t, remoteRaw, "### P0m Mac-Side Disposable Vault Reset Execute-Reset Recovery Session", "### Historical P0d interactive validation evidence — superseded and non-authoritative")
	allowedFlags := compactDocSection(t, remoteRaw, "Allowed flags for `vault-reset-disposable` in P0m are:", "P0m must reject:")

	assertContainsAll(t, "Remote Alpha operator P0m standing route rules boundary", routeRules,
		"The P0m implementation/self-audit slice may implement exactly the Mac-side destructive disposable Vault reset route defined by P0l",
		"`scripts/remote_alpha_operator.sh recovery-session vault-reset-disposable --ssh-target <target> --execute-reset --interactive-tty`",
		"P0m may validate only with static and fake SSH/SCP tests",
		"must not run live SSH, sudo, Vault, reset, unseal, execute-reset, Infrastructure Manager refresh, support-bundle collection, CP proof, workload-auth live checks, runtime identity generation, or network-dependent integration tests",
		"The P0k dry-run route remains the prerequisite/planning route",
		"P0m must preserve the existing P0k dry-run, P0i/P0j unseal-existing, and recovery-session evidence/plan/inventory behavior.",
		"The `readiness-session` and `es-writable-state-readiness-check` public names are preserved only as fixed effect-free compatibility tombstones",
		"P0m's execute-reset route must require `--ssh-target` and `--interactive-tty`",
		"`--execute-reset` without either must fail before staging",
		"`--dry-run` and `--execute-reset` are mutually exclusive",
		"There is no host-local execute-reset route through the operator facade in this slice",
		"stage only `scripts/remote_alpha_reset_disposable_vault.sh`",
		"invoke only `remote_alpha_reset_disposable_vault.sh --execute-reset` over an interactive SSH TTY",
		"It must never pass `--dry-run`, `--unseal-only`, `--post-unseal-check`",
		"must not offer `--keep-staging-on-failure`",
		"cleanup of the staged reset-capable helper must be attempted by default",
		"The exact confirmation phrase remains `RESET DISPOSABLE REMOTE ALPHA VAULT`",
		"typed only by the operator in the visible remote helper/Vault terminal",
		"The route must not accept the phrase, root token, unseal key, client token, Vault token, API key, private key, password, JWT-SVID payload, Vault init output, or secret payload",
		"The operator facade must not receive, parse, log, store, echo, summarize, persist, tee, run `script`, capture, or transcript terminal content",
		"P0m writes no `.out` summary, operator summary, report, support bundle, generated JSON, retained bundle, or CP artifact",
		"Process exit and operator-visible helper output are the only route result surfaces",
		"Post-reset evidence checks remain separate later steps",
		"must not make ES a Vault token broker, IM a reconciler, CP a recovery authority, or Remote Alpha production/deployment/reconciliation architecture",
	)

	assertContainsAll(t, "Remote Alpha operator P0m docs boundary", operatorSection,
		"`Bounded slice rule`: P0m implements exactly the P0l Mac-side destructive disposable Vault reset contract as an explicit operator route",
		"`scripts/remote_alpha_operator.sh recovery-session vault-reset-disposable --ssh-target <target> --execute-reset --interactive-tty`",
		"P0m is implementation/self-audit with static and fake SSH/SCP validation only.",
		"It does not run live SSH, sudo, Vault, reset, unseal, execute-reset, Infrastructure Manager refresh, support-bundle collection, CP proof, workload-auth live checks, runtime identity generation, or network-dependent integration tests.",
		"The already validated P0k dry-run route remains the prerequisite/planning route.",
		"Live execute-reset must be run only when the human operator intentionally wants to reset disposable Remote Alpha Vault state.",
		"Topology and mode rules:",
		"`--ssh-target <target>` is required",
		"`--execute-reset` requires `--interactive-tty`",
		"local stdin and stdout must both be visible terminals before staging or SSH",
		"`--dry-run` and `--execute-reset` are mutually exclusive",
		"`--dry-run` remains the non-destructive prerequisite/planning route",
		"`--host-local` is not accepted for execute-reset through the operator facade",
		"Allowed flags for `vault-reset-disposable` in P0m are:",
		"`--dry-run`",
		"`--execute-reset`",
		"`--interactive-tty`",
		"P0m must reject:",
		"`--execute-reset` without `--ssh-target`",
		"`--execute-reset` without `--interactive-tty`",
		"`--execute-reset` combined with `--dry-run`",
		"`--execute-reset` combined with `--post-unseal-check`",
		"`--execute-reset` combined with `--unseal-only`",
		"`--execute-reset` combined with `--host-local`",
		"`--keep-staging-on-failure`",
		"helper path overrides",
		"unknown flags",
		"duplicate flags",
		"secret-like arguments",
		"Prompt and secret model:",
		"the exact confirmation phrase remains `RESET DISPOSABLE REMOTE ALPHA VAULT`",
		"typed only by the human operator in the visible remote helper/Vault terminal",
		"must not be accepted through CLI arguments, environment variables, environment files, local files, remote files",
		"must not be logged, summarized, captured, parsed, replayed, relayed, printed, or persisted by the operator facade",
		"root tokens, unseal keys, client tokens, Vault tokens, API keys, private keys, passwords, JWT-SVID payloads, Vault init output, and secret payloads",
		"handled only by the human operator in the visible remote helper/Vault terminal",
		"must not tee, run `script`, record, capture, parse, or summarize terminal transcripts",
		"stage only `scripts/remote_alpha_reset_disposable_vault.sh`",
		"do not stage `scripts/remote_alpha_operator.sh`",
		"do not stage a bundle",
		"do not source helper scripts",
		"do not call `scripts/internal/*`",
		"do not construct helper paths from user input",
		"do not introduce generic helper dispatch",
		"use a fixed helper path resolved from `BASH_SOURCE[0]`",
		"allocate an interactive SSH TTY with `ssh -tt`",
		"invoke the staged helper only as `remote_alpha_reset_disposable_vault.sh --execute-reset`",
		"never pass `--dry-run`, `--unseal-only`, `--post-unseal-check`",
		"never include `--post-unseal-check` in this destructive slice",
		"never combine reset with workload-auth check, runtime identity summary, Infrastructure Manager refresh, support-bundle collection, CP proof",
		"do not capture stdout or stderr to files",
		"do not use `tee`",
		"do not run `script`",
		"do not create transcripts or logs",
		"cleanup of the staged reset-capable helper/root must be attempted by default",
		"failure to clean up the staged reset-capable helper is a route failure",
		"no `.out` summary from the ES operator route",
		"no operator summary file",
		"no support bundle",
		"no Infrastructure Manager execution",
		"process exit and operator-visible helper output are the only route result surfaces",
		"post-reset evidence checks are separate later steps",
		"evidence/projection output is non-authoritative",
		"Stop conditions for P0m:",
		"no visible local TTY",
		"SSH host-auth prompt or unknown-host authenticity prompt",
		"reset helper broad raft path guard triggers",
		"exact phrase mismatch",
		"failure to clean up the staged reset-capable helper",
		"P0m remains bounded ES Remote Alpha proof/support workflow glue only.",
		"The human remains the operator.",
		"does not eliminate explicit operator prompts",
		"not Vault production lifecycle automation",
		"not ES Vault token brokerage",
		"not IM authority or reconciliation",
		"not CP recovery authority",
		"not governed execution proof",
		"not Remote Alpha production, deployment, provisioning, or reconciliation architecture",
	)

	assertContainsAll(t, "Remote Alpha operator P0m allowed flags", allowedFlags,
		"`--help`",
		"`--ssh-target <target>`",
		"`--dry-run`",
		"`--execute-reset`",
		"`--interactive-tty`",
	)
	assertContainsNone(t, "Remote Alpha operator P0m allowed flags", allowedFlags,
		"`--post-unseal-check`",
		"`--host-local`",
		"`--keep-staging-on-failure`",
		"workload-auth",
		"support-bundle",
		"root tokens",
		"unseal keys",
	)
}

func TestRemoteAlphaOperatorP0nDocsAreSupersededHistory(t *testing.T) {
	plans := compactText(mustRead(t, plansRecordPath))
	remoteRaw := mustRead(t, ".docs/system_overview/remote_supported_host_alpha.md")
	history := compactDocSection(t, remoteRaw,
		"### Historical P0n Mac-Side Vault Workload-Auth Check — Superseded and Non-Authoritative",
		"### P0o Vault Workload-Auth Bootstrap Planning Surface",
	)
	status := compactDocSection(t, remoteRaw, "## Future ES-Owned Remote Alpha Operator Facade", "### Operator Involvement Model")

	assertContainsAll(t, "P0n superseded plan history", plans,
		"### Historical P0n workload-auth facade route — superseded and non-authoritative",
		"grants no current operator route, staging authority, evidence compatibility, or Tranche B prerequisite",
		"P0n formerly added one Mac-side post-reset evidence route",
	)
	assertContainsAll(t, "P0n superseded design history", history,
		"This entire subsection records superseded compatibility design",
		"grants no current operator route, alias, helper staging, artifact ingestion, discovery, aggregation, projection, or Tranche B prerequisite",
		"direct producer contract described later remains independent of this history",
		"Historical bounded-slice record: P0n implemented one Mac-side post-reset workload-auth evidence route",
	)
	assertContainsAll(t, "P0n direct producer remains documented", remoteRaw,
		"`sudo scripts/remote_alpha_vault_workload_auth_check.sh`",
		"`execution-substrate.remote-alpha.vault-workload-auth-summary.v1`",
		"bounded host-local audit record, not an ES lifecycle or readiness surface",
	)
	assertContainsNone(t, "P0n route is absent from current status", status,
		"P0n adds one separate Mac-side post-reset workload-auth evidence route",
		"stages only `scripts/remote_alpha_vault_workload_auth_check.sh`",
	)
}

func TestRemoteAlphaOperatorP0oDocsVaultWorkloadAuthBootstrapPlanningBoundary(t *testing.T) {
	routeRules := compactText(mustRead(t, standingRouteRulesPath))
	remoteRaw := mustRead(t, ".docs/system_overview/remote_supported_host_alpha.md")
	operatorSection := compactDocSection(t, remoteRaw, "### P0o Vault Workload-Auth Bootstrap Planning Surface", "### Historical P0d interactive validation evidence — superseded and non-authoritative")
	allowedFlags := compactDocSection(t, remoteRaw, "Allowed flags for `vault-workload-auth-bootstrap` in P0o are:", "With no mode")

	assertContainsAll(t, "Remote Alpha operator P0o standing route rules boundary", routeRules,
		"The P0o combined implementation/self-audit/merge-readiness slice may add exactly one safe local/print-only planning surface",
		"`scripts/remote_alpha_operator.sh recovery-session vault-workload-auth-bootstrap [--help|--plan|--inventory]`",
		"must not implement live bootstrap execution",
		"`--execute-bootstrap`",
		"`--ssh-target` execution",
		"`--interactive-tty` execution",
		"Vault writes",
		"root-token prompts",
		"proof secret creation",
		"workload-auth check execution",
		"Infrastructure Manager execution",
		"support-bundle collection",
		"CP proof",
		"reset/unseal behavior",
		"runtime identity generation",
		"`.out` writes",
		"JSON/report/summary creation",
		"generic helper dispatch",
		"Vault reported `initialized=true` and `sealed=false`",
		"`auth_mount=jwt`",
		"`role=service_execution`",
		"`audience=vault`",
		"`auth_smoke.vault_login=fail`",
		"`Vault JWT login rejected or not configured`",
		"must not claim that any individual Vault object is missing",
		"auth mount `jwt`",
		"JWT auth config with SPIRE JWT validation material selected for the workload trust domain and bound issuer",
		"`bound_audiences=vault`",
		"`bound_subject=spiffe://execution.internal/workload`",
		"`runtime-identity-proof`",
		"`proof-secrets/data/runtime-identity-vault-login`",
		"`proof-secrets/data/codex-runtime-profile`",
		"`api_key` present and non-empty",
		"`/etc/execution-substrate/vault/workload-zone-vault-config.json`",
		"Allowed P0o bootstrap flags are only `--help`, `--plan`, and `--inventory`",
		"with no mode, the submode defaults to printing the plan/help and exiting zero.",
		"must reject `--execute-bootstrap`, `--ssh-target`, `--interactive-tty`, `--host-local`",
		"workload-auth helper override flags",
		"proof secret value flags",
		"Any future bootstrap execution must be a separate audited secret-sensitive route.",
		"Root tokens must never be accepted as CLI arguments, environment variables, files, `.out`, reports, support bundles, retained bundles, or Codex output.",
		"explicit visible or silent prompt",
		"no transcript capture, no `tee`, and no `script`",
		"Proof secret values must never be printed, copied, summarized, logged, or persisted by the operator facade.",
		"Bootstrap must only configure expected Vault objects; it must not claim workload-auth success",
		"Workload-auth check remains a separate post-bootstrap command.",
	)
	// This phrase stood in the superseded P0n route's record, which moved to
	// PLANS.md's closed record on 2026-11-24.
	assertContainsAll(t, "Remote Alpha operator P0o PLANS record boundary", compactText(mustRead(t, plansRecordPath)),
		"not ES Vault token brokerage",
	)

	assertContainsAll(t, "Remote Alpha operator P0o docs boundary", operatorSection,
		"`Bounded slice rule`: P0o implements exactly one safe local/print-only post-reset bootstrap planning surface",
		"`scripts/remote_alpha_operator.sh recovery-session vault-workload-auth-bootstrap [--help|--plan|--inventory]`",
		"proved route mechanics far enough to write the canonical summary",
		"functional smoke failed at Vault JWT login",
		"schema matched",
		"summary was fresh",
		"redaction scan passed",
		"`vault.initialized=true`",
		"`vault.sealed=false`",
		"`vault.auth_mount=jwt`",
		"`vault.role=service_execution`",
		"`vault.audience=vault`",
		"`vault_workload_auth_smoke=fail`",
		"`auth_smoke.vault_login=fail`",
		"`Vault JWT login rejected or not configured`",
		"does not prove which Vault object is missing or mismatched",
		"P0o is plan/inventory only.",
		"It does not run live SSH, sudo, Vault, workload-auth checks, reset/unseal, Infrastructure Manager refresh, support-bundle collection, CP proof, runtime identity generation",
		"It does not write `.out`, JSON, reports, support bundles, operator summaries, generated artifacts, retained bundles, or CP artifacts.",
		"does not stage helpers and does not introduce generic helper dispatch",
		"auth mount: `jwt`",
		"JWT auth config with SPIRE JWT validation material selected for the workload trust domain and bound issuer",
		"role: `service_execution`",
		"`role_type=jwt`",
		"`user_claim=sub`",
		"`bound_audiences=vault`",
		"`bound_subject=spiffe://execution.internal/workload`",
		"policy such as `runtime-identity-proof`",
		"`proof-secrets/data/runtime-identity-vault-login`",
		"`proof-secrets/data/codex-runtime-profile`",
		"field `api_key` present and non-empty",
		"`/etc/execution-substrate/vault/workload-zone-vault-config.json`",
		"P0o must reject:",
		"`--execute-bootstrap`",
		"`--ssh-target`",
		"`--interactive-tty`",
		"`--root-token`",
		"`--vault-token`",
		"`--api-key`",
		"`--secret`",
		"workload-auth helper override flags",
		"proof secret value flags",
		"Future bootstrap execution, if implemented, must be a separately audited secret-sensitive route.",
		"Root tokens must never be accepted as CLI arguments, environment variables, files, `.out`, reports, support bundles, retained bundles, or Codex output.",
		"explicit visible or silent operator prompt",
		"no transcript capture, no `tee`, and no `script`",
		"Proof secret values must never be printed, copied, summarized, or logged.",
		"Bootstrap must not claim workload-auth success",
		"The workload-auth check remains a separate command after bootstrap.",
		"non-secret evidence/projection only",
		"not become readiness authority",
		"ES Vault token brokerage",
		"Remote Alpha deployment/provisioning/reconciliation architecture",
	)

	assertContainsAll(t, "Remote Alpha operator P0o allowed flags", allowedFlags,
		"`--help`",
		"`--plan`",
		"`--inventory`",
	)
	assertContainsNone(t, "Remote Alpha operator P0o allowed flags", allowedFlags,
		"`--execute-bootstrap`",
		"`--ssh-target`",
		"`--interactive-tty`",
		"`--root-token`",
		"`--vault-token`",
		"`--secret`",
	)
}

func TestRemoteAlphaOperatorP0pDocsVaultWorkloadAuthBootstrapExecutionContractPrep(t *testing.T) {
	routeRules := compactText(mustRead(t, standingRouteRulesPath))
	remoteRaw := mustRead(t, ".docs/system_overview/remote_supported_host_alpha.md")
	operatorSection := compactDocSection(t, remoteRaw, "### P0p Vault Workload-Auth Bootstrap Execution Contract Prep", "### Historical P0d interactive validation evidence — superseded and non-authoritative")

	assertContainsAll(t, "Remote Alpha operator P0p standing route rules boundary", routeRules,
		"The P0p design/static-test prep slice may define, but must not implement, the future secret-sensitive workload-auth bootstrap execution route",
		"`scripts/remote_alpha_operator.sh recovery-session vault-workload-auth-bootstrap --ssh-target <target> --execute-bootstrap --interactive-tty`",
		"P0p stays docs/static-test only.",
		"must not add live bootstrap execution, Vault writes, helper files, helper staging, root-token prompts, proof-secret prompts, workload-auth checks, reset/unseal behavior, Infrastructure Manager execution, support-bundle collection, CP proof, runtime identity generation",
		"P0p fixes the preferred helper strategy",
		"`scripts/remote_alpha_vault_workload_auth_bootstrap.sh`",
		"`scripts/internal/remote_alpha_vault_workload_auth_bootstrap.sh`",
		"must not print ad hoc manual Vault write commands as the primary execution mechanism",
		"`--ssh-target <target> --execute-bootstrap --interactive-tty`",
		"`--execute-bootstrap` requires both",
		"Duplicate route flags, equals-form options, unknown flags, extra positionals, and secret-like arguments must fail before staging or live action.",
		"auth mount `jwt`",
		"JWT auth config with SPIRE validation material selected for the workload trust domain and bound issuer",
		"role `service_execution`",
		"`role_type=jwt`",
		"`user_claim=sub`",
		"`bound_audiences=vault`",
		"`bound_subject=spiffe://execution.internal/workload`",
		"`runtime-identity-proof`",
		"`proof-secrets/data/runtime-identity-vault-login`",
		"`proof-secrets/data/codex-runtime-profile`",
		"`api_key` present and non-empty with the value never printed",
		"`/etc/execution-substrate/vault/workload-zone-vault-config.json`",
		"prompt-only and operator-owned",
		"Root tokens must never be accepted as CLI arguments, environment variables",
		"If a proof secret value is required, it must use the same TTY-only prompt posture.",
		"must not rely on token-bearing `VAULT_TOKEN` environment variables",
		"token files such as `.vault-token`",
		"configure only the intended Vault objects",
		"must not run a workload-auth check, reset, unseal, Infrastructure Manager refresh, support-bundle collection, CP proof, runtime identity summary, runtime identity generation",
		"must not claim workload-auth success",
		"`/var/tmp/execution-substrate-remote-alpha/vault-workload-auth-bootstrap-summary.json`",
		"`execution-substrate.remote-alpha.vault-workload-auth-bootstrap-summary.v1`",
		"evidence/projection only, never authority",
		"must not be copied back to Mac `.out`",
		"must not contain a root token, unseal key, client token, Vault token, JWT-SVID payload, API key value, private key, password, proof secret value, secret payload, raw Vault output, or terminal transcript",
		"Future implementation tests for P0p's contract must remain fake/static",
		"fake SSH/SCP",
		"fake Vault/API command capture",
		"assert only the dedicated bootstrap helper pair is staged",
		"assert the route cannot bundle workload-auth checks, reset/unseal, IM, support bundles, CP proof, or runtime identity work",
	)

	assertContainsAll(t, "Remote Alpha operator P0p docs boundary", operatorSection,
		"`Bounded slice rule`: P0p defines the future secret-sensitive workload-auth bootstrap execution route before implementation.",
		"docs/static-test prep only",
		"`scripts/remote_alpha_operator.sh recovery-session vault-workload-auth-bootstrap --ssh-target <target> --execute-bootstrap --interactive-tty`",
		"Current safe modes remain:",
		"`--execute-bootstrap`, `--ssh-target` execution, helper staging, root-token prompts, proof-secret prompts, Vault writes, remote summary creation, or live validation",
		"Helper strategy:",
		"`scripts/remote_alpha_vault_workload_auth_bootstrap.sh`",
		"`scripts/internal/remote_alpha_vault_workload_auth_bootstrap.sh`",
		"Ad hoc manual Vault write commands are not the preferred execution path",
		"must not stage `scripts/remote_alpha_operator.sh`",
		"Intended Vault objects/config:",
		"auth mount `jwt`",
		"JWT auth config with SPIRE validation material selected for the workload trust domain and bound issuer",
		"role `service_execution`",
		"`role_type=jwt`",
		"`user_claim=sub`",
		"`bound_audiences=vault`",
		"`bound_subject=spiffe://execution.internal/workload`",
		"policy `runtime-identity-proof`",
		"`proof-secrets/data/runtime-identity-vault-login`",
		"`proof-secrets/data/codex-runtime-profile`",
		"proof runtime field `api_key` present and non-empty, with the value never printed",
		"`/etc/execution-substrate/vault/workload-zone-vault-config.json`",
		"The human remains the operator.",
		"ES remains a bounded Remote Alpha operator facade/workflow, not a Vault token broker.",
		"Vault owns token, secret, and lease authority.",
		"SPIRE owns JWT-SVID issuance.",
		"If the future route needs a Vault root token or equivalent bootstrap authority",
		"reading from the interactive TTY only",
		"If the future route needs a proof secret value",
		"Root tokens, unseal keys, client tokens, Vault tokens, JWT-SVID payloads, API keys, private keys, passwords, proof secret values, and secret payloads must never enter CLI arguments, environment variables, environment files, local or remote files, shell history, logs, `.out`, reports, support bundles, retained bundles, CP artifacts, helper summaries, printed commands, terminal transcripts, or Codex output.",
		"must not rely on token-bearing `VAULT_TOKEN` environment variables",
		"token files such as `.vault-token`, `tee`, or `script`",
		"may configure only the intended Vault objects/config",
		"must not run a workload-auth check",
		"must not run Infrastructure Manager refresh",
		"must not collect support bundles",
		"must not run CP proof",
		"must not run runtime identity summary or runtime identity generation",
		"must not claim workload-auth success",
		"The workload-auth check remains a separate post-bootstrap command.",
		"`/var/tmp/execution-substrate-remote-alpha/vault-workload-auth-bootstrap-summary.json`",
		"`execution-substrate.remote-alpha.vault-workload-auth-bootstrap-summary.v1`",
		"must not copy that summary back to Mac `.out`",
		"evidence/projection only, not authority and not an IM input",
		"The summary must not contain a root token, unseal key, client token, Vault token, JWT-SVID payload, API key value, private key, password, proof secret value, secret payload, raw Vault output, or terminal transcript.",
		"Allowed future execution flags:",
		"`--ssh-target <target>`",
		"`--execute-bootstrap`",
		"`--interactive-tty`",
		"Duplicate route flags, equals-form options, unknown flags, extra positionals, and secret-like arguments must fail before staging or live action.",
		"Forbidden future execution flags and inputs include:",
		"`--host-local`",
		"`--interactive-sudo`",
		"`--keep-staging-on-failure`",
		"proof secret value flags",
		"Future implementation tests:",
		"fake/static before any live-validation slice",
		"must not run live Vault, live SSH, sudo, workload-auth checks, reset/unseal",
		"fake SSH/SCP",
		"fake Vault/API command capture",
		"should assert no secret is passed by argv, env, file, printed command, transcript, `.out`, report, support bundle, retained bundle, CP artifact, helper summary, or Codex-facing output",
		"should assert only the dedicated public/internal bootstrap helper pair is staged",
		"should assert the future route cannot bundle workload-auth checks, reset/unseal, IM refresh, support-bundle collection, CP proof, runtime identity summary, runtime identity generation",
	)

	assertContainsNone(t, "Remote Alpha operator P0p docs overclaims", operatorSection,
		"workload-auth success is proved",
		"ES brokers Vault tokens",
	)
}

func TestRemoteAlphaOperatorP0qDocsVaultWorkloadAuthBootstrapExecutionRoute(t *testing.T) {
	routeRules := compactText(mustRead(t, standingRouteRulesPath))
	remoteRaw := mustRead(t, ".docs/system_overview/remote_supported_host_alpha.md")
	operatorSection := compactDocSection(t, remoteRaw, "### P0q Vault Workload-Auth Bootstrap Execution Route", "### Historical P0r Mac-Side Runtime Identity Summary — Superseded and Non-Authoritative")

	assertContainsAll(t, "Remote Alpha operator P0q standing route rules boundary", routeRules,
		"The P0q implementation/self-audit/merge-readiness slice may implement exactly one dedicated secret-sensitive workload-auth bootstrap helper, exactly one Mac-side recovery-session execution route, one bounded preparation form for the bootstrap summary path, and one bounded preparation form for fixed workload-zone config readability, and one bounded preparation form for fixed SPIRE server bundle-read access",
		"`scripts/remote_alpha_operator.sh recovery-session vault-workload-auth-bootstrap --ssh-target <target> --execute-bootstrap --interactive-tty`",
		"`scripts/remote_alpha_operator.sh recovery-session vault-workload-auth-bootstrap --ssh-target <target> --prepare-summary-path --interactive-tty`",
		"`scripts/remote_alpha_operator.sh recovery-session vault-workload-auth-bootstrap --ssh-target <target> --prepare-config-readability --interactive-tty`",
		"`scripts/remote_alpha_operator.sh recovery-session vault-workload-auth-bootstrap --ssh-target <target> --prepare-spire-bundle-read --interactive-tty`",
		"`scripts/remote_alpha_vault_workload_auth_bootstrap.sh`",
		"`scripts/internal/remote_alpha_vault_workload_auth_bootstrap.sh`",
		"must not run live bootstrap, live SSH, sudo, Vault, workload-auth checks, reset/unseal, Infrastructure Manager refresh, support-bundle collection, CP proof, runtime identity generation",
		"`--ssh-target <target> --execute-bootstrap --prepare-summary-path --prepare-config-readability --prepare-spire-bundle-read --interactive-tty`",
		"summary preparation runs first, config-readability preparation runs second, SPIRE bundle-read preparation runs third",
		"visible/silent remote helper TTY prompt only",
		"must not use `VAULT_TOKEN`",
		"`vault login`",
		"The first real bootstrap attempt failed after the Vault operation flow because `/var/tmp/execution-substrate-remote-alpha` existed as `root:root` mode `0755`",
		"Commit `e4d7016` added the helper-side secret-free writability preflight before secrets",
		"`--prepare-summary-path` follow-up is OS/filesystem preparation only",
		"`--prepare-config-readability` follow-up is OS/filesystem preparation only",
		"`--prepare-spire-bundle-read` follow-up is OS/filesystem/capability preparation only",
		"fixed-path user ACL",
		"`spire_socket_present_accessible`",
		"`spire_socket_present_needs_acl`",
		"`spire_socket_parent_missing`",
		"`spire_socket_missing`",
		"`spire_socket_not_socket`",
		"`spire_server_inactive_or_unknown`",
		"`spire_server_command_missing`",
		"`spire_bundle_show_failed`",
		"sudo-visible inspection shows",
		"do not create SPIRE parents or sockets",
		"helper user/group with mode `0750`",
		"SSH stdin attached to that terminal rather than feeding the remote script over SSH stdin",
		"helper-owned mode `0600`",
		"create no final bootstrap summary in standalone preparation",
		"secret-free writability preflight for the canonical remote bootstrap summary path before any Vault bootstrap authority prompt, proof secret prompt, config load, SPIRE/Vault operation, or Vault write",
		"config readability preflight before prompts and Vault writes",
		"If the parent exists but is not writable by the helper user, or the summary path cannot be written safely, the helper must fail before prompting",
		"write through a temp file in the summary directory and atomically rename it only after redaction checks pass",
		"summary writability preflight before prompts and Vault writes",
		"config readability preflight before prompts and Vault writes",
		"SPIRE bundle-read preflight before prompts and Vault writes",
		"public JWT validation material for the workload SPIFFE ID trust domain",
		"selects all active JWT-SVID RSA validation public keys for that trust domain",
		"validation pubkey count, and a digest set or aggregate digest",
		"redaction checks before final summary rename",
		"fake summary-path preparation over only the bounded remote filesystem command",
		"fake config-readability preparation over only the bounded fixed-path ACL command",
		"fake SPIRE bundle-read preparation over only the bounded fixed-path ACL command",
		"combined preparation ordering before helper staging/execution",
		"in-process Vault API client",
		"auth mount `jwt`",
		"JWT auth config with SPIRE validation material selected for the workload trust domain and bound issuer",
		"all active SPIRE JWT-SVID RSA validation public keys selected for the workload trust domain",
		"role `service_execution`",
		"`role_type=jwt`",
		"`user_claim=sub`",
		"`bound_audiences=vault`",
		"`bound_subject=spiffe://execution.internal/workload`",
		"`runtime-identity-proof`",
		"`proof-secrets/data/runtime-identity-vault-login`",
		"`proof-secrets/data/codex-runtime-profile`",
		"field `api_key` present and non-empty with the value never printed",
		"`/etc/execution-substrate/vault/workload-zone-vault-config.json`",
		"`/var/tmp/execution-substrate-remote-alpha/vault-workload-auth-bootstrap-summary.json`",
		"`execution-substrate.remote-alpha.vault-workload-auth-bootstrap-summary.v1`",
		"safe failure phase/class labels",
		"source labels, shape labels, counts, digests",
		"`failure_phase`",
		"`failure_class`",
		"`secret_prompts_started`",
		"`vault_operations_started`",
		"raw exception string",
		"must not copy that summary back to Mac `.out`",
		"must not claim workload-auth success",
		"The workload-auth check remains a separate post-bootstrap command.",
		"P0q validation remains fake/static only",
		"exact Vault JWT auth config validation-key/issuer shape",
		"workload-auth check JWT claim alignment with the bootstrap config labels",
		"fake SSH/SCP staging of exactly the bootstrap public/internal helper pair",
		"no transcript/`tee`/`script`",
		"no copy-back to Mac `.out`",
	)

	assertContainsAll(t, "Remote Alpha operator P0q docs boundary", operatorSection,
		"`Bounded slice rule`: P0q implements the dedicated secret-sensitive workload-auth bootstrap execution route and bounded summary-path preparation route plus bounded config-readability and SPIRE bundle-read preparation routes",
		"fake/static validation only",
		"Public helper:",
		"`scripts/remote_alpha_vault_workload_auth_bootstrap.sh`",
		"Internal helper:",
		"`scripts/internal/remote_alpha_vault_workload_auth_bootstrap.sh`",
		"Mac-side operator route:",
		"`scripts/remote_alpha_operator.sh recovery-session vault-workload-auth-bootstrap --ssh-target <target> --execute-bootstrap --interactive-tty`",
		"`scripts/remote_alpha_operator.sh recovery-session vault-workload-auth-bootstrap --ssh-target <target> --prepare-summary-path --interactive-tty`",
		"`scripts/remote_alpha_operator.sh recovery-session vault-workload-auth-bootstrap --ssh-target <target> --prepare-config-readability --interactive-tty`",
		"`scripts/remote_alpha_operator.sh recovery-session vault-workload-auth-bootstrap --ssh-target <target> --prepare-spire-bundle-read --interactive-tty`",
		"Combined form:",
		"Safe modes remain:",
		"`scripts/remote_alpha_operator.sh recovery-session vault-workload-auth-bootstrap --help`",
		"Secret prompt model:",
		"The human remains the operator.",
		"ES remains a bounded Remote Alpha operator facade/workflow, not a Vault token broker.",
		"Vault owns token, secret, and lease authority.",
		"SPIRE owns JWT-SVID issuance.",
		"The helper prompts for Vault bootstrap authority and proof secret values only on the visible/silent remote TTY",
		"Summary-path preparation:",
		"first real bootstrap attempt failed because the remote summary parent",
		"Commit `e4d7016` added helper-side summary writability preflight before any Vault/root/proof prompt",
		"Preparation is OS/filesystem setup only",
		"helper-user/group owned with mode `0750`",
		"SSH stdin attached to the visible terminal instead of feeding the remote script over SSH stdin",
		"helper-owned with mode `0600`",
		"creates no final bootstrap summary in standalone mode",
		"In the combined form, preparation must complete before helper staging",
		"Config-readability preparation:",
		"fixed-path user ACLs",
		"does not print config contents",
		"SPIRE bundle-read preparation:",
		"fixed SPIRE server socket path",
		"`spire_socket_present_accessible`",
		"`spire_socket_present_needs_acl`",
		"`spire_socket_parent_missing`",
		"`spire_socket_missing`",
		"`spire_socket_not_socket`",
		"`spire_server_inactive_or_unknown`",
		"`spire_bundle_show_failed`",
		"sudo-visible inspection shows",
		"do not create SPIRE parents or sockets",
		"bundle output is discarded",
		"summary-path preparation, then config-readability preparation, then SPIRE bundle-read preparation, then helper staging/execution",
		"Vault API strategy:",
		"in-process HTTPS client",
		"must not use `VAULT_TOKEN`",
		"`vault login`",
		"Before either prompt, and before any SPIRE/Vault operation or Vault write, the helper must run a secret-free writability preflight",
		"`summary_preflight_failed`",
		"Configured Vault objects/config:",
		"auth mount `jwt`",
		"JWT auth config with SPIRE validation material selected for the workload trust domain and bound issuer",
		"all active JWT-SVID RSA validation public keys for the selected workload trust domain",
		"role `service_execution`",
		"policy `runtime-identity-proof`",
		"`proof-secrets/data/runtime-identity-vault-login`",
		"`proof-secrets/data/codex-runtime-profile`",
		"proof runtime field `api_key` present and non-empty, with the value never printed",
		"Execution boundaries:",
		"must not run a workload-auth check",
		"must not run Infrastructure Manager refresh",
		"must not collect support bundles",
		"must not run CP proof",
		"must not run runtime identity summary or runtime identity generation",
		"must not claim workload-auth success",
		"The workload-auth check remains a separate post-bootstrap command.",
		"Summary/evidence behavior:",
		"`/var/tmp/execution-substrate-remote-alpha/vault-workload-auth-bootstrap-summary.json`",
		"`execution-substrate.remote-alpha.vault-workload-auth-bootstrap-summary.v1`",
		"safe failure phase/class labels",
		"source labels, shape labels, counts, digests",
		"`failure_phase`",
		"`failure_class`",
		"`secret_prompts_started`",
		"`vault_operations_started`",
		"raw exception string",
		"must not copy that summary back to Mac `.out`",
		"must not create an operator summary",
		"atomically rename it only after redaction checks pass",
		"Allowed execution flags:",
		"`--execute-bootstrap`",
		"`--prepare-summary-path`",
		"`--prepare-config-readability`",
		"`--prepare-spire-bundle-read`",
		"Standalone `--prepare-summary-path` runs only the fixed bounded remote preparation command",
		"Standalone `--prepare-config-readability` runs only the fixed bounded remote preparation command",
		"Standalone `--prepare-spire-bundle-read` runs only the fixed bounded remote preparation command",
		"Combined `--execute-bootstrap --prepare-summary-path",
		"Forbidden execution flags and inputs include:",
		"`--root-token`",
		"`--vault-token`",
		"`--api-key`",
		"proof secret value flags",
		"P0q tests:",
		"fake bootstrap writes the Vault JWT auth config with the expected validation material and bound issuer shape",
		"fake bootstrap writes all selected workload-trust-domain JWT-SVID RSA validation public keys and ignores non-JWT-SVID RSA keys",
		"fake workload-auth check JWT claims align with the bootstrap config labels",
		"preflight failure before secret prompts proves no root-token prompt, no proof secret prompt, no fake Vault API call, and no summary or temp summary",
		"config readability preflight failure before secret prompts proves no root-token prompt",
		"SPIRE bundle-read preflight failure before secret prompts proves no root-token prompt",
		"fake SSH tests prove `--prepare-summary-path` uses only the bounded remote preparation command",
		"fake SSH tests prove `--prepare-config-readability` uses only the bounded fixed-path ACL preparation command",
		"fake SSH tests prove `--prepare-spire-bundle-read` uses only the bounded fixed-path ACL preparation command",
		"fake SSH tests prove combined `--execute-bootstrap --prepare-summary-path",
		"static source tests prove redaction checks run before final summary rename",
		"fake SSH/SCP tests prove exactly the two bootstrap helper files are staged",
		"no transcript/`tee`/`script` is used",
		"no Mac `.out` copy-back occurs",
	)
	assertContainsNone(t, "Remote Alpha operator P0q docs overclaims", operatorSection,
		"workload-auth success is proved",
		"ES brokers Vault tokens",
		"production readiness is proved",
	)
}

func TestRemoteAlphaOperatorP0rDocsAreSupersededHistory(t *testing.T) {
	plans := compactText(mustRead(t, plansRecordPath))
	remoteRaw := mustRead(t, ".docs/system_overview/remote_supported_host_alpha.md")
	history := compactDocSection(t, remoteRaw,
		"### Historical P0r Mac-Side Runtime Identity Summary — Superseded and Non-Authoritative",
		"### P0s/P0t Dedicated ES TLS Status-Only Collector",
	)
	status := compactDocSection(t, remoteRaw, "## Future ES-Owned Remote Alpha Operator Facade", "### Operator Involvement Model")
	directProducer := compactDocSection(t, remoteRaw, "## Runtime Identity Helper Proof Slice", "## Remote Normal-Shell Runtime Image Slice")

	assertContainsAll(t, "P0r superseded plan history", plans,
		"### Historical P0r runtime-identity facade route — superseded and non-authoritative",
		"grants no current operator route, staging authority, evidence compatibility, or Tranche B prerequisite",
		"P0r formerly added one Mac-side recovery-session runtime identity evidence route",
	)
	assertContainsAll(t, "P0r superseded design history", history,
		"This entire subsection records superseded compatibility design",
		"grants no current operator route, alias, helper staging, artifact ingestion, discovery, aggregation, projection, or Tranche B prerequisite",
		"direct producer proof section remains independent of this history",
		"Historical bounded-slice record: P0r implemented one Mac-side runtime identity evidence route",
	)
	assertContainsAll(t, "P0r direct producer remains documented", directProducer,
		"scripts/remote_alpha_runtime_identity_helper_summary.sh",
		"runtime identity helper proof slice",
		"narrower than a live remote governed-execution proof",
	)
	assertContainsNone(t, "P0r route is absent from current status", status,
		"P0r implements exactly one Mac-side runtime identity evidence route",
		"stages only `scripts/remote_alpha_runtime_identity_helper_summary.sh`",
	)
}

func TestRemoteAlphaP0tGrammarDiagnosticDocsContract(t *testing.T) {
	routeRules := compactText(mustRead(t, standingRouteRulesPath))
	remote := compactText(mustRead(t, ".docs/system_overview/remote_supported_host_alpha.md"))
	access := compactText(mustRead(t, ".docs/system_overview/remote_alpha_access_contract.md"))
	artifact := compactText(mustRead(t, ".docs/system_overview/artifact_hygiene.md"))

	for label, doc := range map[string]string{"route rules": routeRules, "host": remote, "access": access, "artifact": artifact} {
		assertContainsAll(t, label+" P0t diagnostic boundary", doc,
			"es-governance-tls-grammar-diagnostic", "execution-governance",
			"Bounded slice rule", "Temporary compatibility edge",
			"first", "nonpublishing", "status")
		assertContainsAll(t, label+" P0t diagnostic nonauthority", doc,
			"no", "retry", "restoration", "source", "lock")
	}
	assertContainsAll(t, "plan diagnostic effect boundary", routeRules,
		"--verify-only", "zero", "at most eighteen", "first_grammar_rejection",
		"no_grammar_rejection_reached", "incomplete_other",
		"ES_TLS_GRAMMAR_DIAGNOSTIC_V2", "2048", "no status generation",
		"recognized_literal_count", "cap_reached=true", "sequence_complete=false")
	assertContainsAll(t, "host diagnostic custody and ownership", remote,
		"O_RDWR|O_NOFOLLOW|O_CLOEXEC|O_NONBLOCK", "size-zero", "flock(LOCK_EX|LOCK_NB)",
		"one explicit", "status descriptor", "child", "no canonical", "os._exit(child_code)")
	assertContainsAll(t, "access diagnostic privilege boundary", access,
		"visible", "sudo", "SUDO", "zero remote", "no new account-wide sudo grant",
		"remote phase is unproved", "no helper ran")
	assertContainsAll(t, "artifact private schema boundary", artifact,
		"grammar_diagnostic_v2_schema.json", "reference/test data", "not a protected P0t status schema",
		"No raw stdout/stderr", "2048", "other", "material-derived hashes")
	assertContainsAll(t, "plan diagnostic projection precision", routeRules,
		"exactly one complete supported LF-terminated", "original stdout or stderr stream",
		"split fragments", "repeated lines", "LF/non-LF capacity", "counts authenticate native contents")
	assertContainsAll(t, "host diagnostic projection precision", remote,
		"original native stream", "repeated identical lines", "multiple recognized",
		"distinct CR, NUL and invalid UTF-8", "minimum", "do not reconstruct")
	assertContainsAll(t, "access diagnostic projection nonauthority", access,
		"one complete supported line", "original native stream", "not whole-response status acceptance")
	assertContainsAll(t, "artifact diagnostic projection privacy", artifact,
		"original stdout and stderr streams", "zero, split, repeated or multiple",
		"byte/line/CR/NUL/UTF-8 capacity", "do not export or authenticate native content")
	assertContainsAll(t, "plan diagnostic literal capacity", routeRules,
		"two admitted ASCII literal lengths", "every other LF consumes a byte",
		"distinct", "outside the literal", "no nonliteral flag or residual byte")
	assertContainsAll(t, "host diagnostic literal capacity", remote,
		"two admitted ASCII literal", "after all other LF bytes", "unterminated tail",
		"outside that literal", "no nonliteral")
	assertContainsAll(t, "access and artifact capacity boundary", access+artifact,
		"structural capacity is not access proof", "two admitted ASCII literal lengths",
		"charging other LF bytes", "sole line has no nonliteral residual capacity")
	assertContainsAll(t, "plan prior reader close precision", routeRules,
		"shared protected-summary reader", "disposition-unproved marker",
		"same exception", "53-function freeze", "other 52 original functions",
		"Settled read/metadata failure with successful close")
	assertContainsAll(t, "host prior reader close precision", remote,
		"canonical-leaf close attempt", "disposition unproved", "FileNotFoundError",
		"other 52 original functions", "does not blanket-suppress")
	assertContainsAll(t, "access prior reader close precision", access,
		"failed canonical-leaf close", "disposition unproved", "FileNotFoundError",
		"independent lock and status close attempts")
	for label, value := range map[string]string{"route rules": routeRules, "host": remote, "access": access} {
		assertContainsAll(t, label+" fixed verify-success predicate", value,
			"verify_success_stderr_nonempty", "verify_success_stdout_not_exact",
			"15 bytes", "one line", "UTF-8", "final LF", "no CR", "no NUL")
		assertContainsAll(t, label+" exact scalar types", value,
			"schema", "scope", "exact string types")
	}
	schema := mustRead(t, "testdata/remote_alpha_es_tls_status/grammar_diagnostic_schema.json")
	assertContainsAll(t, "private diagnostic schema precision", schema,
		"schema_version and scope must be built-in strings", "verify_success_stderr_nonempty implies",
		"bytes=15", "lines=1", "empty=false", "utf8=true", "final_lf=true",
		"has_cr=false", "has_nul=false", "shape does not authenticate native text")
	v2 := mustRead(t, "testdata/remote_alpha_es_tls_status/grammar_diagnostic_v2_schema.json")
	assertContainsAll(t, "current private diagnostic schema", v2,
		"es-p0t-openssl-grammar-diagnostic/v2", "verify_projection",
		"context_invalid_unclassified", "recognized_literal_count", "cap_reached",
		"sequence_complete", "unknown_numeric", "terminal", "opaque")
	assertContainsAll(t, "plan context-placement refusal", routeRules,
		"both original streams nonempty", "single context-invalid literal",
		"Replacing that token with `other` is also refused", "global sequence cap")
	assertContainsAll(t, "host context-placement refusal", remote,
		"one context-invalid literal", "placement retains priority",
		"substituted `other` token also fails", "ordered sequences are absent")
	assertContainsAll(t, "private schema context-placement refusal", v2,
		"exactly one recognized context-invalid literal", "zero known literals",
		"replacing it with other is also refused", "full or capped sequences")
	assertContainsAll(t, "v2 diagnostic ownership", artifact+remote+access,
		"historical v1", "2048", "both sequences", "native text")
}

func TestRemoteAlphaESServiceTLSStatusOnlyContract(t *testing.T) {
	routeRules := compactText(mustRead(t, standingRouteRulesPath))
	remote := compactText(mustRead(t, ".docs/system_overview/remote_supported_host_alpha.md"))
	artifact := compactText(mustRead(t, ".docs/system_overview/artifact_hygiene.md"))
	facade := mustRead(t, remoteAlphaOperatorScriptPath())
	collector := mustRead(t, "scripts/internal/remote_alpha_es_tls_status.py")
	wrapper := mustRead(t, "scripts/remote_alpha_es_service_tls_renew.sh")

	for label, value := range map[string]string{"route rules": routeRules, "Remote Alpha": remote} {
		assertContainsAll(t, label+" status-only boundary", value,
			"`Reopened redesign seam`", "dedicated", "status-only", "renewal", "held",
			"es-service-tls-status", "es-governance-tls-status",
			"artifact-registry", "execution-governance",
			"execution-substrate.remote-alpha.es-tls-status-collector/v1",
			"execution-substrate.remote-alpha.es-service-tls-status-summary.v1",
			"execution-substrate.remote-alpha.es-governance-tls-status-summary.v1",
			"finalized=true", "generation", "five minutes", "thirty seconds",
			"os.replace", "os._exit(0)", "visible", "crash",
			"P0q", "P0u", "P0v",
		)
	}
	assertContainsAll(t, "artifact custody", artifact,
		"execution-substrate.remote-alpha.es-tls-status-evidence/v1",
		"es-service-tls-status-summary.json", "es-governance-tls-status-summary.json",
		"Incomplete attempts",
	)
	assertContainsAll(t, "status facade", facade,
		"REMOTE_ALPHA_ES_TLS_STATUS_COLLECTOR",
		"es-service-tls-status", "es-governance-tls-status",
		"es-service-tls-renew", "es-governance-tls-renew",
		"--execute-renew", "--interactive-tty",
	)
	assertContainsNone(t, "status collector renewal authority", collector,
		"remote_alpha_es_service_tls_renew", "--execute-renew", "private-backups",
		"systemctl", "curl", "install ", "backup_created = True",
	)
	assertContainsAll(t, "public renewal wrapper hold", wrapper,
		"renewal is held", "exit 2")
	assertContainsNone(t, "public renewal wrapper dispatch", wrapper,
		"source ", "remote_alpha_es_service_tls_renew_main")
}

func TestRemoteAlphaESServiceTLSStatusOnlyRepairContract(t *testing.T) {
	routeRules := compactDocSection(t, mustRead(t, standingRouteRulesPath),
		"`Reopened redesign seam`: the P0s/P0t shared status-and-renewal helper",
		"The P0u implementation/self-audit/merge-readiness slice")
	remoteRaw := mustRead(t, ".docs/system_overview/remote_supported_host_alpha.md")
	status := compactDocSection(t, remoteRaw,
		"### P0s/P0t Dedicated ES TLS Status-Only Collector",
		"### P0u Mac-Side Operator Healthcheck TLS Status/Renew Recovery Session")
	accessRaw := mustRead(t, ".docs/system_overview/remote_alpha_access_contract.md")
	accessScope := compactDocSection(t, accessRaw,
		"## 1. Authority, scope, and status", "## 2. Versioned profile and ownership")
	accessPrivilege := compactDocSection(t, accessRaw,
		"## 6. Service and privilege boundaries", "## 7. Future work and restoration boundary")
	fixtureHygiene := compactDocSection(t, mustRead(t, ".docs/system_overview/artifact_hygiene.md"),
		"`Bounded slice rule`: the tracked synthetic public fixtures",
		"The P0u operator healthcheck TLS status/renew summary")

	assertContainsAll(t, "P0s/P0t x509 text plan refinement", routeRules,
		"`Bounded slice rule refinement`", "exactly", "two complete terminal signature tails",
		"nine-space-indented lowercase hexadecimal", "Signature Value:",
		"eight-space-indented lowercase hexadecimal", "heading-plus-nine",
		"no-heading-plus-eight", "mixed-indentation", "unknown-heading",
		"target host's OpenSSL 3.0.13")
	assertContainsAll(t, "P0s/P0t x509 text whole-response contract", status,
		"exactly one of two complete signature-tail alternatives",
		"nine-space-indented lowercase hexadecimal", "Signature Value:",
		"eight-space-indented lowercase hexadecimal", "consistent indentation",
		"anchored at end of output", "mixed indentation", "repeated or unknown headings",
		"by itself it did not qualify")
	for label, section := range map[string]string{"route rules": routeRules, "status": status} {
		assertContainsAll(t, "P0s/P0t target 3.0.13 finite response grammar "+label, section,
			"39", "13", "three", "nonroot", "certificate_malformed", "key_malformed",
			"Could not read certificate from /dev/stdin\\nUnable to load certificate\\n",
			"Could not read key from /dev/stdin\\n",
			"CN = <subject>\\nerror <code> at <depth> depth lookup: <reason>\\nerror /dev/stdin: verification failed\\n",
			"unable to get local issuer certificate", "certificate has expired",
			"certificate is not yet valid", "Remote Alpha Internal Runtime Root CA",
			"unsuitable certificate purpose", "hostname mismatch", "sslclient", "sslserver",
			"chain_failed", "incomplete", "generation")
	}
	assertContainsAll(t, "P0s/P0t synthetic fixture hygiene", fixtureHygiene,
		"openssl3_x509_text.stdout", "openssl3_public_cert.pem",
		"non-authoritative test inputs", "not Remote Alpha host",
		"No synthetic private key", "other whole-response acceptance sets",
		"openssl3013_negative_responses.json", "retained malformed literals",
		"no private key", "incomplete grammar preserves prior bytes")

	for label, section := range map[string]string{"route rules status slice": routeRules, "Remote Alpha status slice": status} {
		assertContainsAll(t, label+" interactive stdin contract", section,
			"source-controlled bytes", "independent", "SSH stdin", "real local",
			"remote TTY", "password-required sudo", "cached sudo", "NOPASSWD",
			"captured", "relayed outside", "retained", "before", "contact")
		assertContainsAll(t, label+" stage identity and cleanup exception contract", section,
			"strict unsigned decimal", "custody-acquisition identity", "device", "inode",
			"O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC", "UID/GID",
			"same-path replacement", "digest", "sudo launch",
			"no destructive stage cleanup", "diagnostic residue",
			"status lock", "bounded backoff", "ordinary `Exception`",
			"exactly one direct-child reap", "identity-based",
			"waitid(P_PID, WEXITED|WNOHANG|WNOWAIT)",
			"before any OpenSSL spawn", "probe child")
		assertContainsAll(t, label+" audit repair", section,
			"related_config_malformed", "absent", "incomplete",
			"checked_at > not_after", "checked_at < not_before",
			"no `exists` field", "same", "semantic",
			"first `fstat`", "OpenSSL", "grammar drift",
			"cleanup", "os.replace", "os._exit(0)")
		assertContainsNone(t, label+" completed status vocabulary", section,
			"config_unreadable", "certificate_unreadable", "key_unreadable")
		assertContainsAll(t, label+" fixture-proven verify failures", section,
			"four P0s", "three repetitions",
			"CN = Remote Alpha Internal Runtime Root CA\\nerror 10 at 1 depth lookup:certificate has expired\\n",
			"error 10 at 0 depth lookup:certificate has expired\\n",
			"error 9 at 0 depth lookup:certificate is not yet valid\\n",
			"[A-Za-z0-9.-]+", "incomplete")
		assertContainsAll(t, label+" input and lifecycle repair", section,
			"strict JSON", "NaN", "Infinity", "-Infinity", "1e10000", "-1e10000", "duplicate keys",
			"absolute lexical canonical POSIX material path", "repeated separators",
			"no-follow", "absent final leaf", "unsafe", "incomplete",
			"immutable", "/dev/stdin", "/dev/fd/<n>", "-trusted",
			"-verify_hostname", "selected anchor", "LC_ALL=C",
			"hostname mismatch", "whole tuple", "host-preflight",
			"identity-safe same-group member", "wait/poll", "custody-acquisition",
			"never signals a process group after reaping",
			"diagnostic residue", "generation")
		assertContainsAll(t, label+" bounded strict JSON depth", section,
			"MAX_JSON_CONTAINER_DEPTH = 64", "depth 1", "Depth 64", "depth 65",
			"config_malformed", "related_config_malformed", "invalid/unaccepted",
			"incomplete", "no new generation", "unaccepted evidence",
			"controlled", "schema", "byte-size")
		assertContainsAll(t, label+" stage, summary, and group repair", section,
			"bootstrap", "-I -B -c", "SHA-256", "bytes in memory",
			"bootstrap marker", "direct pathname invocation",
			"O_RDONLY|O_NOFOLLOW|O_CLOEXEC|O_NONBLOCK",
			"regular-to-FIFO", "pidfd", "unresolved-cleanup hold")
	}
	assertContainsAll(t, "Remote Alpha status semantic contract", status,
		"all five 64-character SHA-256 fields", "not_before <= not_after",
		"equality at either boundary is valid", "nested record", "blockers",
		"collector uses this same validator before publication",
		"P0s related EGS", "P0t related ARS",
		"status=pass, code=absent", "config_missing", "related_config_malformed",
		"None may infer a pass from an empty-object fallback",
		"unsafe", "no new generation")
	assertContainsNone(t, "Remote Alpha completed status vocabulary excludes unsafe reads", status,
		"config_unreadable", "certificate_unreadable", "key_unreadable")
	assertContainsAll(t, "Remote Alpha status whole-response grammar", status,
		"whole-response", "unable to load certificate", "unable to load key",
		"TRUSTED CERTIFICATE", "ANY PRIVATE KEY",
		"error 20 at 0 depth lookup:unable to get local issuer certificate",
		"[A-Za-z0-9.-]+", "/dev/stdin", "Raw child output never enters evidence",
		"Certificate:\\n Data:\\n", "Signature Algorithm: <token>",
		"nine-space-indented lowercase hexadecimal", "intervening certificate text is not independently validated")
	assertContainsAll(t, "Remote Alpha status cleanup ownership", status,
		"immediately after a successful `Popen`", "selector construction and registration",
		"terminates and reaps", "Once exclusive temporary creation succeeds",
		"unlinks only after revalidating", "prior canonical generation is unchanged")
	assertContainsAll(t, "Remote Alpha strict reader JSON", status,
		"strict JSON decoding", "duplicate keys", "non-finite", "stable descriptor metadata")

	assertContainsAll(t, "access contract current P0s/P0t status relationship", accessScope,
		"`Temporary compatibility edge`", "es-service-tls-status",
		"es-governance-tls-status", "scripts/internal/remote_alpha_es_tls_status.py",
		"artifact-registry", "execution-governance", "ssh -tt",
		"visible remote sudo", "self-cleans", "protected status summary",
		"`Bounded slice rule`", "es-service-tls-renew", "es-governance-tls-renew",
		"refuse before stage, SSH, SCP, sudo, or host contact",
		"old shared status/renewal helper is historical and undispatched",
		"Tranche A contract", "P0v", "custody-acquisition identity",
		"device/inode", "upload", "diagnostic residue",
		"no fresh generation", "post-publication stage cleanup")
	assertContainsAll(t, "access contract interactive stdin contract", accessScope,
		"source-controlled wrapper", "independently of SSH stdin", "real local",
		"remote TTY", "password-required sudo", "cached credentials", "NOPASSWD",
		"captured", "relayed outside", "retained", "before contact")
	assertContainsAll(t, "access contract bounded strict JSON depth", accessScope,
		"MAX_JSON_CONTAINER_DEPTH = 64", "depth 1", "Depth 64", "depth 65",
		"config_malformed", "related_config_malformed", "invalid/unaccepted",
		"incomplete", "no new generation", "unaccepted evidence",
		"controlled", "schema", "byte-size")
	assertContainsAll(t, "access contract stage and cleanup exception repair", accessScope,
		"strict unsigned decimal", "custody-acquisition", "caller UID/GID",
		"O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC", "same-path replacement",
		"digest", "sudo launch", "no destructive stage", "diagnostic",
		"ordinary `Exception`", "bounded backoff", "status lock",
		"exactly one direct-child reap", "identity-based proc absence scan",
		"waitid(P_PID, WEXITED|WNOHANG|WNOWAIT)", "probe child")
	for label, section := range map[string]string{"route rules": routeRules, "Remote Alpha": status, "access": accessScope} {
		assertContainsAll(t, label+" invocation custody and preflight", section,
			"same-UID", "one fixed", "empty entry set", "measured identity",
			"automatic", "one", "capability", "before", "OpenSSL",
			"no generation", "no", "probe")
		assertContainsAll(t, label+" prior canonical snapshot states", section,
			"ABSENT", "VALID(generation)", "INVALID_OR_UNACCEPTED",
			"schema_version", "collector_contract", "finalized=true",
			"scope", "route", "32 lowercase hexadecimal characters",
			"strict-JSON", "mixed", "stale", "completed-fail",
			"OpenSSL spawn", "publication setup", "metadata identity")
		assertContainsNone(t, label+" obsolete exact creation and caller deletion", section,
			"exact creation identity", "creation device/inode",
			"fixed nonroot path", "cleanup armed")
	}
	collector := mustRead(t, "scripts/internal/remote_alpha_es_tls_status.py")
	assertContainsAll(t, "collector prior snapshot private-state gate", collector,
		"_PriorSummaryState", "ABSENT", "VALID", "INVALID_OR_UNACCEPTED",
		"prior_summary_unaccepted")
	assertContainsNone(t, "access contract stale P0t helper relationship", accessScope,
		"use the fixed ES service TLS helper pair", "stage the pair",
		"Committed P0t", "P0t status/renew routes retain")
	assertContainsAll(t, "access contract current sudo and renewal boundary", accessPrivilege,
		"P0s/P0t status", "visible operator-interactive sudo",
		"both renewal routes are held before contact",
		"Neither is authorized by access-status v1")
	assertContainsNone(t, "access contract stale sudo boundary", accessPrivilege,
		"Current P0t status/renew routes")
}

func TestRemoteAlphaESServiceTLSStatusFIFOProcessAndAnchorRepairContract(t *testing.T) {
	routeRules := compactDocSection(t, mustRead(t, standingRouteRulesPath),
		"`Reopened redesign seam`: the P0s/P0t shared status-and-renewal helper",
		"The P0u implementation/self-audit/merge-readiness slice")
	remote := compactDocSection(t, mustRead(t, ".docs/system_overview/remote_supported_host_alpha.md"),
		"### P0s/P0t Dedicated ES TLS Status-Only Collector",
		"### P0u Mac-Side Operator Healthcheck TLS Status/Renew Recovery Session")
	access := compactDocSection(t, mustRead(t, ".docs/system_overview/remote_alpha_access_contract.md"),
		"## 1. Authority, scope, and status", "## 2. Versioned profile and ownership")
	for label, section := range map[string]string{"route rules": routeRules, "Remote Alpha": remote} {
		assertContainsAll(t, label+" nonblocking leaf and group contract", section,
			"FIFO", "before any blocking", "O_NOFOLLOW|O_CLOEXEC|O_NONBLOCK",
			"device", "inode", "type", "owner", "mode", "link count",
			"previous", "generation", "waitid", "WNOWAIT",
			"TERM", "KILL", "descendant", "reserved", "incomplete")
		assertContainsAll(t, label+" single selected trust anchor", section,
			"one selected", "PEM `CERTIFICATE`", "ASCII whitespace",
			"trust_anchor_count_mismatch", "certificate_unavailable",
			"-trusted", "bundle", "reader")
	}
	assertContainsAll(t, "access contract stage refusal", access,
		"FIFO", "nonregular", "before any blocking", "O_NONBLOCK",
		"fstat", "diagnostic residue", "generation", "Tranche A",
		"no renewal, restoration, access-profile, IM, CP, monitor, or scheduler",
		"trust_anchor_count_mismatch", "certificate_unavailable", "-trusted",
		"waitid", "WNOWAIT", "reserved", "TERM/KILL", "non-signaling")
	assertContainsAll(t, "access contract in-memory and reader repair", access,
		"root bootstrap", "exact bytes", "bootstrap marker", "direct pathname invocation",
		"O_RDONLY|O_NOFOLLOW|O_CLOEXEC|O_NONBLOCK", "pidfd/proc",
		"unresolved-cleanup hold")
}

func TestRemoteAlphaProtectedEvidencePathsV1Contract(t *testing.T) {
	routeRules := compactText(mustRead(t, standingRouteRulesPath))
	remote := compactText(mustRead(t, ".docs/system_overview/remote_supported_host_alpha.md"))
	artifact := compactText(mustRead(t, ".docs/system_overview/artifact_hygiene.md"))
	for label, value := range map[string]string{"route rules": routeRules, "Remote Alpha": remote, "artifact hygiene": artifact} {
		assertContainsAll(t, label+" protected status acceptance", value,
			"/var/lib/execution-substrate-remote-alpha/v1/status",
			"es-service-tls-status-summary.json", "es-governance-tls-status-summary.json",
			".es-service-tls-status.lock", ".es-governance-tls-status.lock",
			"root:root", "0755", "0644", "0600", "single-link",
			"finalized", "generation", "legacy", "no", "private-backups")
	}
	assertContainsAll(t, "remote final publication", remote,
		"stage cleanup", "child", "before", "replacement",
		"without required", "reader", "scope", "route",
		"result", "non-effect", "different", "five")
}

func TestRemoteAlphaOperatorP0uDocsOperatorHealthcheckTLSRenewRoute(t *testing.T) {
	routeRules := compactText(mustRead(t, standingRouteRulesPath))
	remoteRaw := mustRead(t, ".docs/system_overview/remote_supported_host_alpha.md")
	operatorSection := compactDocSection(t, remoteRaw, "### P0u Mac-Side Operator Healthcheck TLS Status/Renew Recovery Session", "### Historical P0d interactive validation evidence — superseded and non-authoritative")
	allowedFlags := compactDocSection(t, remoteRaw, "Allowed flags for P0u are:", "P0u must reject:")
	artifact := compactText(mustRead(t, ".docs/system_overview/artifact_hygiene.md"))
	source := mustRead(t, remoteAlphaOperatorScriptPath())
	sourceSection := docSection(t, source, "recovery_session_operator_healthcheck_tls_usage() {", "\nrecovery_session() {")

	assertContainsAll(t, "Remote Alpha operator P0u standing route rules boundary", routeRules,
		"The P0u implementation/self-audit/merge-readiness slice may add exactly one bounded Remote Alpha host-local operator healthcheck client TLS helper pair and exactly two Mac-side recovery-session routes",
		"`scripts/remote_alpha_operator.sh recovery-session operator-healthcheck-tls-status --ssh-target <target> --interactive-tty`",
		"`scripts/remote_alpha_operator.sh recovery-session operator-healthcheck-tls-renew --ssh-target <target> --interactive-tty --execute-renew`",
		"`scripts/remote_alpha_operator_healthcheck_tls_renew.sh`",
		"`scripts/internal/remote_alpha_operator_healthcheck_tls_renew.sh`",
		"`/etc/execution-substrate/tls/operator-client-cert.pem`",
		"`/etc/execution-substrate/tls/operator-client-key.pem`",
		"`/etc/execution-substrate/tls/combined-service-ca-bundle.pem` only as the healthcheck server trust bundle",
		"`spiffe://execution.internal/operator` as a legacy mismatch",
		"`spiffe://execution.internal/operator/local`",
		"status mode is non-mutating",
		"`/var/tmp/execution-substrate-remote-alpha/operator-healthcheck-tls-renew-summary.json`",
		"Client certificate renewal must not restart ES",
		"Allowed P0u route flags are only `--help`, `--ssh-target <target>`, `--interactive-tty`, and `--execute-renew` for the renew route only",
		"P0u validation remains fake/static only",
	)

	assertContainsAll(t, "Remote Alpha operator P0u docs boundary", operatorSection,
		"`Bounded slice rule`: P0u implements exactly one bounded Remote Alpha host-local operator healthcheck client TLS helper pair",
		"`scripts/remote_alpha_operator.sh recovery-session operator-healthcheck-tls-status --ssh-target <target> --interactive-tty`",
		"`scripts/remote_alpha_operator.sh recovery-session operator-healthcheck-tls-renew --ssh-target <target> --interactive-tty --execute-renew`",
		"static and fake SSH/SCP only",
		"The route is separate from IM, CP, Vault, SPIRE, Nomad, workload-auth, reset, unseal, runtime identity, ES service TLS renewal, ES governance TLS renewal, and general deployment.",
		"Covered topology and fixed paths:",
		"`/etc/execution-substrate/tls/operator-client-cert.pem`",
		"`/etc/execution-substrate/tls/operator-client-key.pem`",
		"Identity rule:",
		"`spiffe://execution.internal/operator/local`",
		"The previously observed `spiffe://execution.internal/operator` SAN is a legacy mismatch",
		"`operator-healthcheck-tls-status` is non-mutating.",
		"public certificate fields only: subject, issuer, SAN, EKU, notBefore, notAfter",
		"confirms operator cert/key public-key match without printing private keys",
		"`operator-healthcheck-tls-renew` requires explicit `--execute-renew`.",
		"The Mac-side facade stages only `scripts/remote_alpha_operator_healthcheck_tls_renew.sh` and `scripts/internal/remote_alpha_operator_healthcheck_tls_renew.sh`.",
		"The remote command invokes only `--status` or `--execute-renew` through `ssh -tt`; it passes no helper override flags.",
		"Current renewal is design-blocked because no authoritative Remote Alpha CA custody/signing topology exists for this host-local operator client identity.",
		"The helper must not assume a retained remote CA private key such as `/etc/execution-substrate/tls/runtime-ca-key.pem` and must not accept ad hoc signing material.",
		"It fails closed with `unsupported_signing_topology` before backup, install, service restart, or post-renew probes.",
		"It records explicit next-step text requiring a future documented CA custody/signing design.",
		"It does not restart ES",
		"`/var/tmp/execution-substrate-remote-alpha/operator-healthcheck-tls-renew-summary.json`",
		"`execution-substrate.remote-alpha.operator-healthcheck-tls-renew-summary.v1`",
		"evidence/projection only, never authority and not an IM input",
		"unsupported-signing-topology failure classification",
		"not-run backup/install/probe metadata",
		"Allowed flags for P0u are:",
		"P0u must reject:",
		"TLS/config/path overrides",
		"fake SSH/SCP tests prove exactly the fixed public/internal operator healthcheck TLS helper pair is staged",
		"fake renew tests prove `unsupported_signing_topology` before backup, install, service restart, or post-renew probes",
		"fake/static renew tests prove no retained remote CA private key is required",
		"Stop conditions for P0u:",
		"not generic TLS deployment, not Infrastructure Manager reconciliation, not Control Plane authority, not Vault/SPIRE/Nomad authority, not workload-auth or runtime identity authority, not production readiness",
	)
	assertContainsNone(t, "Remote Alpha operator P0u docs overclaims", operatorSection,
		"production readiness is proved",
		"IM reconciliation succeeds",
		"CP proof is run",
		"Vault tokens are brokered",
	)

	assertContainsAll(t, "Remote Alpha operator P0u allowed flags", allowedFlags,
		"`--help`",
		"`--ssh-target <target>`",
		"`--interactive-tty`",
		"`--execute-renew` only for `operator-healthcheck-tls-renew`",
	)
	assertContainsNone(t, "Remote Alpha operator P0u allowed flags", allowedFlags,
		"`--host-local`",
		"`--dry-run`",
		"`--status`",
		"`--scope`",
		"`--apply`",
		"private keys",
		"Vault tokens",
	)

	assertContainsAll(t, "Remote Alpha operator P0u artifact hygiene", artifact,
		"`/var/tmp/execution-substrate-remote-alpha/operator-healthcheck-tls-renew-summary.json`",
		"`execution-substrate.remote-alpha.operator-healthcheck-tls-renew-summary.v1`",
		"non-secret helper summary only",
		"configured SPIFFE URI/SAN classification",
		"current file policy metadata",
		"unsupported-signing-topology failure classification",
		"future CA custody/signing next-step text",
		"not-run backup/install/probe metadata",
		"must not be copied back to Mac `.out` by the operator facade",
		"must not become an IM input or CP proof artifact",
		"must not contain private key PEM bodies, full certificate PEM bodies, private-key backup digests, Vault tokens, root tokens, unseal keys, client tokens, JWT-SVID payloads, API keys, passwords, proof secrets, terminal transcripts, support-bundle content, raw retained bundles, raw workspace contents, or raw secret-bearing command output",
	)

	assertContainsAll(t, "Remote Alpha operator P0u source", sourceSection,
		"REMOTE_ALPHA_OPERATOR_HEALTHCHECK_TLS_RENEW_PUBLIC_HELPER",
		"REMOTE_ALPHA_OPERATOR_HEALTHCHECK_TLS_RENEW_INTERNAL_HELPER",
		"REMOTE_ALPHA_OPERATOR_HEALTHCHECK_TLS_RENEW_REMOTE_SUMMARY",
		`scp "${REMOTE_ALPHA_OPERATOR_HEALTHCHECK_TLS_RENEW_PUBLIC_HELPER}" "${ssh_target}:${remote_public_helper_path}"`,
		`scp "${REMOTE_ALPHA_OPERATOR_HEALTHCHECK_TLS_RENEW_INTERNAL_HELPER}" "${ssh_target}:${remote_internal_helper_path}"`,
		`ssh -tt "${ssh_target}" "${remote_shell_command}"`,
		`"${helper_path}" %q`,
		`sudo "${helper_path}" %q`,
		"--status|--execute-renew",
		"recovery-session operator-healthcheck-tls-renew requires --execute-renew",
		"recovery-session operator-healthcheck-tls-status forbids --execute-renew",
	)
	assertContainsNone(t, "Remote Alpha operator P0u source forbidden helper bundle", sourceSection,
		"remote_alpha_reset_disposable_vault.sh",
		"remote_alpha_vault_workload_auth_check.sh",
		"remote_alpha_vault_workload_auth_bootstrap.sh",
		"remote_alpha_runtime_identity_helper_summary.sh",
		"remote_alpha_es_service_tls_renew.sh",
		"remote-alpha-live-refresh",
		"remote-alpha-live-support-bundle",
		`"${helper_path}" --dry-run`,
		`"${helper_path}" --check-only`,
		"tee ",
	)
}

func TestRemoteAlphaOperatorP0vDocsOperatorHealthcheckTLSNoninteractiveStatusDesign(t *testing.T) {
	routeRules := compactText(mustRead(t, standingRouteRulesPath))
	designRaw := mustRead(t, ".docs/remote_alpha_operator_healthcheck_noninteractive_status.md")
	design := compactText(designRaw)
	runtimeContract := compactDocSection(t, designRaw, "## 4. Local Runtime Contract", "## 5. SSH And Remote Command")
	subprocessBounds := compactDocSection(t, designRaw, "## 6. Subprocess Bounds", "## 7. Internal Remote Protocol")
	internalProtocol := compactDocSection(t, designRaw, "## 7. Internal Remote Protocol", "## 8. Remote Collector Behavior")
	remoteCollector := compactDocSection(t, designRaw, "## 8. Remote Collector Behavior", "## 9. Remote Privilege Posture")
	privilege := compactDocSection(t, designRaw, "## 9. Remote Privilege Posture", "## 10. Final Route Schema")
	finalSchema := compactDocSection(t, designRaw, "## 10. Final Route Schema", "## 11. Failure Mapping")
	failures := compactDocSection(t, designRaw, "## 11. Failure Mapping", "## 12. Exit Semantics")
	boundaries := compactDocSection(t, designRaw, "## 13. Consumer And Authority Boundaries", "## 14. Validation And Later Gates")
	remoteRaw := mustRead(t, ".docs/system_overview/remote_supported_host_alpha.md")
	p0vSection := compactDocSection(t, remoteRaw, "### P0v Operator Healthcheck TLS Noninteractive Status Implementation", "### Remote Alpha Maintenance Monitor Boundary")
	source := mustRead(t, remoteAlphaOperatorScriptPath())
	dispatchSections := docSection(t, source, "recovery_session() {", "\nprint_refresh_command() {") +
		"\n" + docSection(t, source, "main() {", "\nmain \"$@\"")
	p0vSource := docSection(t, source, "recovery_session_operator_healthcheck_tls_status_noninteractive_usage() {", "\nrecovery_session_operator_healthcheck_tls_usage() {")
	runtimeSource := mustRead(t, "scripts/remote_alpha_operator_healthcheck_tls_status_noninteractive.py")
	collectorSource := mustRead(t, "scripts/internal/remote_alpha_operator_healthcheck_tls_status_noninteractive_remote.py")

	assertContainsAll(t, "Remote Alpha operator P0v standing route rules boundary", routeRules,
		"The P0v noninteractive TLS status implementation slice implements",
		"operator-healthcheck-tls-status-noninteractive --ssh-target <target> --format json",
		"`.docs/remote_alpha_operator_healthcheck_noninteractive_status.md`",
		"dedicated checked-in local Python runtime",
		"fixed checked-in remote Python collector is streamed over SSH stdin",
		"There is no shell fallback JSON assembly.",
		"not renewal",
		"not a signing-topology decision",
		"not a profile mutation path",
		"not a Maintenance Agent scheduling change",
		"implementation is validated only through local/static/fake tests",
		"requires no local stdin/stdout TTY",
		"allocates no pseudo-TTY",
		"uses no-prompt SSH semantics",
		"avoids remote helper staging",
		"avoids remote summary mutation",
		"implemented status schema is `execution-substrate.remote-alpha.operator-healthcheck-tls-status-noninteractive.v1`",
		"supports_noninteractive=true",
		"requires_interactive_tty=false",
		"current_status=implemented",
		"`scheduled_execution_allowed=false` remains the current ES status",
		"`operator-healthcheck-tls-renew` remains blocked/status-only with `unsupported_signing_topology`",
		"CP consumes nothing in this tranche",
		"IM consumes nothing in this tranche",
		"MA consumes, invokes, and schedules nothing in this tranche",
	)

	assertContainsAll(t, "Remote Alpha operator P0v design", design,
		"Remote Alpha Operator Healthcheck TLS Noninteractive Status Contract",
		"`Bounded slice rule`: P0v implements one read-only ES observation route",
		"`Current invariant`: the existing P0u interactive",
		"`Current invariant`: no fallback emitter is allowed.",
		"`Current invariant`: `scheduled_execution_allowed=false`.",
		"scripts/remote_alpha_operator.sh recovery-session operator-healthcheck-tls-status --ssh-target <target> --interactive-tty",
		"`operator-healthcheck-tls-status-noninteractive`",
		"scripts/remote_alpha_operator.sh recovery-session operator-healthcheck-tls-status-noninteractive --ssh-target <target> --format json",
		"current status: `implemented`",
		"requires interactive TTY: `false`",
		"supports noninteractive: `true`",
		"scheduled execution allowed: `false`",
		"Bash facade",
		"Local Python runtime",
		"Remote Python collector",
		"There is no shell fallback JSON path.",
	)
	assertContainsAll(t, "Remote Alpha operator P0v local runtime contract", runtimeContract,
		"scripts/remote_alpha_operator_healthcheck_tls_status_noninteractive.py",
		"Python standard library only",
		"`-I -S -B`",
		"`--ssh-target <target>`",
		"`--format json`",
		"Parser and validation failures emit only fixed safe diagnostics.",
		"no collector-path argument",
		"no environment override",
		"computes SHA-256 digests",
		"`provenance.source_revision` is always `null`",
		"does not spawn a Git subprocess",
		"not remote attestation",
		"SHA-256 label for the validated SSH target",
	)
	assertContainsAll(t, "Remote Alpha operator P0v subprocess bounds", subprocessBounds,
		"maximum checked-in collector source: `131072` bytes",
		"maximum SSH stdout: `65536` bytes",
		"maximum SSH stderr: `8192` bytes",
		"maximum final route JSON: `65536` bytes",
		"SSH wall-clock timeout: `20` seconds",
		"graceful termination interval: `2` seconds",
		"terminates the SSH process group",
		"does not retry",
	)
	assertContainsAll(t, "Remote Alpha operator P0v internal protocol", internalProtocol,
		"execution-substrate.remote-alpha.operator-healthcheck-tls-status-noninteractive.remote.v1",
		"not the final route schema",
		"exact field allowlist",
		"duplicate-key rejection",
		"unknown-field rejection",
		"JSON constants such as NaN and Infinity rejection",
		"fixed failure-class vocabulary",
		"closed enum vocabularies",
		"The runtime distinguishes a valid remote protocol document from a transport failure by the protocol marker and collector digest",
		"SSH process exit code must agree with `helper_exit_code`",
	)
	assertContainsAll(t, "Remote Alpha operator P0v remote collector", remoteCollector,
		"scripts/internal/remote_alpha_operator_healthcheck_tls_status_noninteractive_remote.py",
		"fixed current Remote Alpha paths",
		"never emitted",
		"certificate file SHA-256",
		"public certificate fingerprint",
		"public key fingerprint",
		"legacy operator URI presence",
		"certificate/key public-key match",
		"trust verification classification",
		"exact parsed `CN=client.operator`",
		"extracts exact URI SAN entries",
		"explicit minimal environment",
		"performs no network operation",
		"performs no service operation",
		"performs no certificate mutation",
		"`/health` probe",
		"`/v1/executions:contract` probe",
	)
	assertContainsAll(t, "Remote Alpha operator P0v privilege", privilege,
		"must never run through:",
		"`sudo -n python3 -`",
		"`sudo python3`",
		"`sudo -n bash`",
		"closed in-source set of immutable, non-mutating argv tuples",
		"absolute executables",
		"no shell",
		"no write operation",
		"`failure_class=noninteractive_auth_required`",
	)
	assertContainsAll(t, "Remote Alpha operator P0v final schema", finalSchema,
		"execution-substrate.remote-alpha.operator-healthcheck-tls-status-noninteractive.v1",
		"`target` contains only a fixed target kind label and the SHA-256",
		"`provenance` contains only:",
		"local route runtime SHA-256",
		"remote collector SHA-256",
		"internal protocol version",
		"`null` source revision in P0v v1",
		"`key_pair` contains bounded public-key-match evidence only",
		"No remote-provided arbitrary string may become a final summary or failure message.",
		"one typed local outcome",
		"one canonical builder",
		"validates the complete final object with an explicit schema validator",
		"performs a complete forbidden-material scan",
		"Target privacy is structural",
		"does not reject a document merely because a valid target alias is a substring of fixed route vocabulary",
	)
	assertContainsAll(t, "Remote Alpha operator P0v failure mapping", failures,
		"`ssh_batch_mode_failed`",
		"`remote_status_unavailable`",
		"`unexpected_output_shape`",
		"`forbidden_output_material`",
		"`noninteractive_auth_required`",
		"`cert_metadata_expired`",
		"`cert_metadata_not_yet_valid`",
		"`trust_chain_unavailable`",
		"`trust_chain_failed`",
		"`identity_mismatch`",
		"`key_pair_mismatch`",
		"`local_runtime_failed`",
		"Unexpected local selector, pipe, spawn, or process-management failure",
		"Failure classes do not authorize retries, mutation, renewal, profile acceptance, scheduling, or run-control.",
	)
	assertContainsAll(t, "Remote Alpha operator P0v boundaries", boundaries,
		"CP consumes nothing in this tranche.",
		"IM consumes nothing in this tranche.",
		"MA consumes, invokes, and schedules nothing in this tranche.",
		"Bridge invokes and synthesizes nothing in this tranche.",
		"Coordinator consumes nothing in this tranche.",
		"not CP run-control truth",
		"not ES runtime truth",
		"not IM readiness authority",
		"not MA authority",
		"not Bridge authority",
		"not renewal authorization",
		"Renewal remains blocked with `unsupported_signing_topology`.",
	)
	assertContainsNone(t, "Remote Alpha operator P0v design overclaims", design,
		"production readiness is proved",
		"CP proof is run",
		"IM reconciliation succeeds",
		"scheduled execution allowed: `true`",
		"renewal is now enabled",
	)

	assertContainsAll(t, "Remote Alpha operator P0v remote docs", p0vSection,
		"`Bounded slice rule`: P0v implements the ES-owned read-only operator",
		"operator-healthcheck-tls-status-noninteractive --ssh-target <target> --format json",
		"`.docs/remote_alpha_operator_healthcheck_noninteractive_status.md`",
		"chooses a new route id",
		"does not change P0u behavior or MA route metadata",
		"no local stdin/stdout TTY requirement",
		"no pseudo-TTY creation",
		"no prompt-capable SSH or sudo path",
		"fixed Bash facade argument parsing",
		"dedicated checked-in local Python runtime as the sole final JSON emitter",
		"fixed checked-in remote Python collector streamed over SSH stdin",
		"no Bash JSON assembly and no fallback emitter",
		"no password storage or replay",
		"no remote helper staging and no remote summary mutation",
		"`execution-substrate.remote-alpha.operator-healthcheck-tls-status-noninteractive.v1`",
		"`execution-substrate.remote-alpha.operator-healthcheck-tls-status-noninteractive.remote.v1`",
		"no raw stdout/stderr transcripts, helper transcripts, SSH transcripts, PEM bodies",
		"`noninteractive_auth_required`",
		"`ssh_batch_mode_failed`",
		"`remote_status_unavailable`",
		"`cert_metadata_expired`",
		"`cert_metadata_not_yet_valid`",
		"`trust_chain_unavailable`",
		"`trust_chain_failed`",
		"`identity_mismatch`",
		"`key_pair_mismatch`",
		"CP consumes nothing in this tranche",
		"IM consumes nothing in this tranche",
		"MA consumes, invokes, and schedules nothing in this tranche",
		"Bridge invokes and synthesizes nothing in this tranche",
		"Coordinator consumes nothing in this tranche",
		"`requires_interactive_tty=false`",
		"`supports_noninteractive=true`",
		"`current_status=implemented`",
		"`scheduled_execution_allowed=false`",
		"CP diagnose rerun and IM profile-lineage refresh remain future owning-repo tranches.",
		"Stop conditions for P0v:",
		"the route would require a local TTY, pseudo-TTY, SSH prompt, sudo prompt, or password storage/replay",
		"the route would need fallback JSON assembly because local runtime, schema, or redaction prerequisites are unavailable",
		"bounded JSON redaction cannot be guaranteed",
		"the route would be treated as renewal, CP run-control truth, ES runtime truth, IM authority, MA authority, Bridge authority, production readiness, live proof, operational acceptance, or infrastructure reconciliation truth",
	)
	assertContainsNone(t, "Remote Alpha operator P0v remote docs overclaims", p0vSection,
		"production readiness is proved",
		"CP proof is run",
		"IM reconciliation succeeds",
		"`scheduled_execution_allowed=true`",
		"renewal is now enabled",
	)
	assertContainsAll(t, "Remote Alpha operator P0v source dispatch", dispatchSections,
		`"$1" == "operator-healthcheck-tls-status-noninteractive"`,
		"recovery_session_operator_healthcheck_tls_status_noninteractive",
	)
	assertContainsAll(t, "Remote Alpha operator P0v Bash source", p0vSource,
		"exec \"${recovery_session_p0v_python3_path}\" -I -S -B",
		"REMOTE_ALPHA_OPERATOR_HEALTHCHECK_TLS_STATUS_NONINTERACTIVE_RUNTIME",
		"REMOTE_ALPHA_OPERATOR_HEALTHCHECK_TLS_STATUS_NONINTERACTIVE_REMOTE_COLLECTOR",
		"command -v python3",
		"recovery_session_p0v_require_fixed_ssh",
		"operator-healthcheck-tls-status-noninteractive requires --format json",
		"forbids helper, path, command, SSH, privilege, runtime, collector, schema, timeout, and limit overrides",
	)
	assertContainsNone(t, "Remote Alpha operator P0v Bash source forbidden behavior", p0vSource,
		"scp ",
		"ssh -tt",
		"ssh \"${ssh_target}\"",
		"sudo ",
		"schema_version",
		"fallback",
		"remote_stage_dir",
	)
	assertContainsAll(t, "Remote Alpha operator P0v runtime source", runtimeSource,
		"FINAL_SCHEMA_VERSION",
		"REMOTE_PROTOCOL_VERSION",
		"SAFE_STARTUP_ERROR = \"p0v_isolated_runtime_required\"",
		"SAFE_FINAL_EMISSION_ERROR = \"p0v_final_emission_failed\"",
		"SAFE_RUNTIME_ERROR = \"p0v_runtime_failed\"",
		"RouteOutcome",
		"local_runtime_failed",
		"build_ssh_argv",
		"BatchMode=yes",
		"SUPPORTED_SSH = \"/usr/bin/ssh\"",
		"NULL_SSH_CONFIG = \"/dev/null\"",
		"ProxyCommand=none",
		"ProxyJump=none",
		"PermitLocalCommand=no",
		"ClearAllForwardings=yes",
		"ForwardAgent=no",
		"RequestTTY=no",
		"ControlMaster=no",
		"ControlPath=none",
		"ControlPersist=no",
		"CanonicalizeHostname=no",
		"NumberOfPasswordPrompts=0",
		"KbdInteractiveAuthentication=no",
		"PasswordAuthentication=no",
		"StrictHostKeyChecking=yes",
		"ConnectTimeout=10",
		"ConnectionAttempts=1",
		"bounded_subprocess_run",
		"start_new_session=True",
		"terminate_process_group",
		"validate_remote_protocol_bytes",
		"validate_final_document",
		"scan_forbidden_material",
	)
	assertContainsNone(t, "Remote Alpha operator P0v runtime source forbidden behavior", runtimeSource,
		"shell=True",
		"scp",
		"fallback",
		"subprocess.run(",
		"git",
		"raw_target",
		"sudo python3",
		"sudo bash",
		"sudo sh",
		"--collector-path",
		"--ssh-option",
	)
	assertContainsAll(t, "Remote Alpha operator P0v collector source", collectorSource,
		"PROTOCOL_VERSION",
		"OPERATOR_CERT_PATH",
		"OPERATOR_KEY_PATH",
		"SERVER_CLIENT_CA_PATH",
		"MAX_FIXED_TLS_FILE_BYTES = 1048576",
		"MAX_COMMAND_STDOUT_BYTES = 65536",
		"MAX_COMMAND_STDERR_BYTES = 8192",
		"MAX_COMMAND_STDIN_BYTES = 65536",
		"COMMAND_TIMEOUT_SECONDS = 10.0",
		"COMMAND_TERMINATION_GRACE_SECONDS = 1.0",
		"READ_CHUNK_SIZE = 16384",
		"sudo_allowlist",
		"CHILD_ENV",
		"OPENSSL_CONF",
		"direct_file_sha256",
		"selectors.DefaultSelector",
		"decode_client_certificate",
		"rfc2253_component_values",
		"collect_status",
		"public_key_digest_from_cert",
		"public_key_digest_from_key",
		"classify_identity",
		"classify_trust",
		"safe_failure_payload",
	)
	assertContainsNone(t, "Remote Alpha operator P0v collector source forbidden behavior", collectorSource,
		"sudo python3",
		"sudo bash",
		"sudo sh",
		"/health",
		"/v1/executions:contract",
		"mktemp",
		"communicate(",
		"read_bytes(",
		"socket",
		"curl",
		"chmod",
		"chown",
		" tee ",
	)
}

func TestRemoteAlphaOperatorP0vCompanionDocsCurrentStatusAlignment(t *testing.T) {
	companionPaths := []string{
		".docs/remote_alpha_operator_healthcheck_tls_operator_authorized_replacement.md",
		".docs/remote_alpha_operator_healthcheck_tls_signing_custody.md",
		".docs/remote_alpha_operator_healthcheck_tls_signing_custody_decision.md",
		".docs/remote_alpha_operator_healthcheck_tls_signing_custody_resolution.md",
	}
	for _, path := range companionPaths {
		t.Run(path, func(t *testing.T) {
			raw := mustRead(t, path)
			compact := compactText(raw)
			assertContainsAll(t, "P0v companion status alignment "+path, compact,
				"at the time",
				"was the only implemented operator-healthcheck TLS status route",
				"A later P0v tranche now implements only read-only noninteractive status evidence",
				"`operator-healthcheck-tls-renew` remains blocked with `unsupported_signing_topology`",
				"signing",
				"custody",
			)
			assertContainsNone(t, "P0v companion stale current only-route claim "+path, compact,
				"route is the only implemented operator-healthcheck TLS status route",
				"route remains the only implemented operator-healthcheck TLS status route",
				"route not implemented",
				"scheduled execution is allowed",
				"renewal is now enabled",
			)
		})
	}

	replacement := compactText(mustRead(t, ".docs/remote_alpha_operator_healthcheck_tls_operator_authorized_replacement.md"))
	assertContainsAll(t, "P0v replacement optional evidence alignment", replacement,
		"including the later implemented P0v read-only status route where available",
		"Treat P0v as replacement authorization",
		"P0v missing/failed/blocked",
		"P0v evidence may be used only as optional read-only evidence",
		"P0v is not replacement authorization",
		"is not post-replacement acceptance by itself",
		"never resolves signing or custody",
		"`scheduled_execution_allowed=false`",
		"Missing, failed, or blocked P0v evidence remains a blocker or unknown",
	)
}

func TestRemoteAlphaOperatorHealthcheckTLSDocsOperatorAuthorizedReplacementDesign(t *testing.T) {
	access := standingRuleSection(t, standingRouteRulesPath, remoteAlphaAccessHeading)
	remoteRaw := mustRead(t, ".docs/system_overview/remote_supported_host_alpha.md")
	replacementRaw := mustRead(t, ".docs/remote_alpha_operator_healthcheck_tls_operator_authorized_replacement.md")
	replacement := compactText(replacementRaw)
	phases := compactDocSection(t, replacementRaw, "## 7. Operator-Authorized Replacement Phases", "## 8. Post-Checks")
	stopConditions := compactDocSection(t, replacementRaw, "## 14. Stop Conditions", "## 15. Validation Plan")

	assertContainsAll(t, "operator healthcheck replacement access contract standing rules boundary", access,
		"operator-authorized operator-healthcheck TLS replacement design tranche is also docs/static-test only",
		"`.docs/remote_alpha_operator_healthcheck_tls_operator_authorized_replacement.md`",
		"`.docs/remote_alpha_operator_healthcheck_tls_signing_custody.md`",
		"not a P0v route implementation",
		"not renewal execution",
		"not Bridge or Maintenance Agent authority",
		"not CP diagnose execution",
		"not profile mutation",
		"`operator-healthcheck-tls-renew` as blocked/status-only with `unsupported_signing_topology`",
		"`spiffe://execution.internal/operator/local`",
	)

	assertContainsAll(t, "operator healthcheck replacement remote overview", compactText(remoteRaw),
		"operator-authorized operator-healthcheck TLS replacement design",
		"`.docs/remote_alpha_operator_healthcheck_tls_operator_authorized_replacement.md`",
		"`.docs/remote_alpha_operator_healthcheck_tls_signing_custody.md`",
		"does not implement renewal, replacement, CP diagnose, IM profile-lineage refresh",
		"route eligibility widening",
		"preserves `operator-healthcheck-tls-renew` as blocked with `unsupported_signing_topology`",
	)

	assertContainsAll(t, "operator healthcheck replacement design", replacement,
		"Remote Alpha Operator-Authorized Operator-Healthcheck TLS Replacement Design",
		"`Design/static-test prep only`",
		"`operator-healthcheck-tls-renew` remains blocked with `unsupported_signing_topology`",
		"later P0v tranche now implements only the read-only",
		"That later status route does not implement renewal or replacement",
		"`.docs/remote_alpha_operator_healthcheck_tls_signing_custody.md`",
		"`Reopened redesign seam`: signing authority and private-key custody",
		"operator-authorized replacement design",
		"CP `diagnose-remote-profile` command consumes `control-plane.remote-supported-host-profile.v1` profile metadata",
		"not a live remote TLS handshake, ES route execution, CP proof, Temporal proof, ES submit, or Remote Alpha live proof",
		"`spiffe://execution.internal/operator/local`",
		"`spiffe://execution.internal/operator`",
		"`client.operator`",
		"Current signing topology is undocumented for this scope.",
		"That is why `operator-healthcheck-tls-renew` still fails closed with `unsupported_signing_topology`",
		"currently records no allowed signer for this scope",
		"CP, IM, Maintenance Agent, and Bridge are explicitly not signing authorities.",
		"A future Maintenance Agent biometric lease may approve only an exact canonical plan digest.",
		"Private keys remain inside ES-owned or host-local custody",
		"Bridge, Maintenance Agent, Control Plane, Infrastructure Manager reports, support bundles, readiness reports, and profile lineage artifacts must never retain, print, copy, expose, parse, or summarize private keys.",
		"Key reuse, key replacement, and key rotation are not enabled by this design.",
		"ES owns TLS route/material semantics",
		"IM owns Remote Alpha profile, provenance, readiness, support-bundle, and profile-lineage refresh emission.",
		"CP owns remote-supported-host profile parsing, profile diagnostics, profile acceptance",
		"Backup And Rollback Evidence Requirements",
		"Renewing service or governance TLS does not refresh the operator-healthcheck client certificate",
		"This replacement design is separate from P0v.",
		"Bridge preflight evidence is local-only and non-authoritative.",
		"Neither CP nor IM becomes ES signing authority",
	)

	assertContainsAll(t, "operator healthcheck replacement phases", phases,
		"Source-of-truth confirmation",
		"Backup and safe inventory",
		"Signing and custody confirmation",
		"Plan digest generation",
		"Operator authorization lease approval",
		"Public cert/profile replacement by owning path",
		"IM profile/provenance refresh",
		"CP diagnose rerun",
		"Optional ES/IM read-only status evidence",
		"Remote Alpha proof resumption gate",
		"No live proof claim until the proof path runs.",
	)

	assertContainsAll(t, "operator healthcheck replacement stop conditions", stopConditions,
		"signing topology is unclear",
		"signing authority is unclear",
		"signer custody is unclear",
		"key custody is unclear",
		"CSR flow is unclear",
		"key-pair match cannot be proven without exposing private key material",
		"backup evidence is unavailable",
		"profile lineage owner is unclear",
		"CP diagnose expected input is unclear",
		"rollback evidence is unavailable",
		"redaction cannot be guaranteed",
		"the exact plan digest does not match",
		"a future biometric lease is invalid, expired, consumed, or mismatched",
		"service/governance TLS renewal is being used as a substitute for operator-healthcheck TLS",
	)

	assertContainsNone(t, "operator healthcheck replacement design forbidden overclaims", replacement,
		"renewal is now supported",
		"Remote Alpha proof is complete",
		"Bridge may approve replacement",
		"Maintenance Agent may define signing topology",
		"CP owns TLS signing",
		"IM owns TLS signing",
		"fallback emitter is allowed",
		"scheduled execution is allowed",
	)
}

func TestRemoteAlphaOperatorHealthcheckTLSDocsSigningCustodyDesign(t *testing.T) {
	access := standingRuleSection(t, standingRouteRulesPath, remoteAlphaAccessHeading)
	remoteRaw := mustRead(t, ".docs/system_overview/remote_supported_host_alpha.md")
	replacement := compactText(mustRead(t, ".docs/remote_alpha_operator_healthcheck_tls_operator_authorized_replacement.md"))
	signingRaw := mustRead(t, ".docs/remote_alpha_operator_healthcheck_tls_signing_custody.md")
	signing := compactText(signingRaw)
	stopConditions := compactDocSection(t, signingRaw, "## 10. Stop Conditions", "## 11. Static-Test Expectations")
	staticExpectations := compactDocSection(t, signingRaw, "## 11. Static-Test Expectations", "")
	source := mustRead(t, remoteAlphaOperatorScriptPath())
	dispatchSections := docSection(t, source, "recovery_session() {", "\nprint_refresh_command() {") +
		"\n" + docSection(t, source, "main() {", "\nmain \"$@\"")
	assertContainsAll(t, "Remote Alpha operator P0v source dispatch", dispatchSections,
		`"$1" == "operator-healthcheck-tls-status-noninteractive"`,
		"recovery_session_operator_healthcheck_tls_status_noninteractive",
	)

	assertContainsAll(t, "operator healthcheck signing custody access contract standing rules boundary", access,
		"`.docs/remote_alpha_operator_healthcheck_tls_signing_custody.md`",
		"blocked/status-only with `unsupported_signing_topology`",
		"signing authority, signer custody, key custody, CSR/cert flow, backup/rollback evidence, redaction, and post-check semantics remain ES unresolved stop conditions",
	)

	assertContainsAll(t, "operator healthcheck signing custody remote overview", compactText(remoteRaw),
		"with signing/custody hardening in `.docs/remote_alpha_operator_healthcheck_tls_signing_custody.md`",
		"does not implement renewal, replacement, CP diagnose, IM profile-lineage refresh",
		"route eligibility widening",
		"signing authority, signer custody, key custody, CSR/cert flow, backup/rollback evidence, redaction, and post-check semantics remain explicit ES unresolved stop conditions",
	)

	assertContainsAll(t, "operator healthcheck signing custody replacement linkage", replacement,
		"`.docs/remote_alpha_operator_healthcheck_tls_signing_custody.md`",
		"companion records the stricter material-custody stop conditions",
		"currently records no allowed signer for this scope",
		"CP, IM, Maintenance Agent, and Bridge are explicitly not signing authorities.",
		"Key reuse, key replacement, and key rotation are not enabled by this design.",
	)

	assertContainsAll(t, "operator healthcheck signing custody design", signing,
		"Remote Alpha Operator-Healthcheck TLS Signing And Custody Design",
		"`Design/static-test prep only`: this document does not execute replacement",
		"`operator-healthcheck-tls-renew` remains blocked with `unsupported_signing_topology`",
		"`Reopened redesign seam`: signing authority and private-key custody",
		"Current answer: unresolved. No ES-owned or host-local authority is currently documented as allowed to sign replacement operator-healthcheck client certificates for this scope.",
		"Therefore no reusable P0u replacement may proceed today.",
		"continue to fail closed with `unsupported_signing_topology`",
		"explicit statement that CP, IM, Maintenance Agent, and Bridge are not signing authorities",
		"The future design must not assume a retained runtime CA private-key topology",
		"must not accept ad hoc signing material",
		"must not infer authority from service or governance TLS routes",
		"Only an ES-owned host-local process running under the documented operator healthcheck TLS route/custody model may read or use the key.",
		"Reuse existing host-local key for cert-only replacement",
		"`unresolved stop condition`",
		"Replace or rotate the key through host-local generation",
		"Import, export, copy, escrow, print, hash for evidence, or pass private key material outside host-local ES custody",
		"`prohibited`",
		"Any key reuse, replacement, rotation, or generation in this tranche",
		"CSR flow, if selected later:",
		"Cert-only replacement, if selected later:",
		"checks that the replacement certificate public key matches the host-local private key by comparing public-key fingerprints derived locally",
		"Before any future replacement, the owning ES path must record safe backup evidence",
		"Rollback after a failed replacement remains an owner-path action, not authority widening.",
		"Allowed safe fields",
		"Cert metadata freshness",
		"Safe identity/SAN/SPIFFE match",
		"Trust-chain match",
		"Key-pair match without exposing key",
		"CP `diagnose-remote-profile` pass",
		"IM profile lineage refresh",
		"No live proof claim is allowed until the later Milestone 3 path actually runs.",
		"`operator-healthcheck-tls-renew` still blocks because ES has not documented an allowed signer",
		"Before the renew route could move from blocked to operator-approved renewal",
		"Before auto-renew eligibility could even be discussed",
		"None of those are enabled here.",
		"`es-service-tls-renew` and `es-governance-tls-renew` are separate scopes.",
		"Service or governance TLS renewal cannot repair operator-healthcheck TLS by inference",
		"A future biometric lease may approve only the exact canonical plan digest",
		"It cannot create signing authority, signer custody, key custody, CSR flow, profile lineage, CP diagnose ownership, renewal eligibility",
	)

	assertContainsAll(t, "operator healthcheck signing custody stop conditions", stopConditions,
		"signing authority is unclear",
		"signer custody is unclear",
		"key custody is unclear",
		"CSR flow is unclear",
		"key-pair match cannot be proven without private-key exposure",
		"backup evidence is unavailable",
		"rollback evidence is unavailable",
		"redaction cannot be guaranteed",
		"CP diagnose expected input is unclear",
		"IM profile lineage owner is unclear",
		"hidden SSH, hidden provisioning, hidden helper staging, or hidden reconciler behavior would be required",
		"fallback emitter behavior would be required",
		"route eligibility would be widened by implication",
		"plan digest mismatches",
		"future biometric lease gating is invalid, expired, consumed, mismatched, or outside route eligibility",
	)

	assertContainsAll(t, "operator healthcheck signing custody static tests", staticExpectations,
		"signing authority and key custody are explicit unresolved stop conditions",
		"no renewal is enabled by this design",
		"`unsupported_signing_topology` remains the current renewal blocker",
		"service and governance TLS scopes remain separate",
		"raw PEM, private-key, and raw certificate bodies are absent from the design docs",
		"route eligibility is not widened",
		"At the time of this signing/custody design, P0v noninteractive status was unimplemented.",
		"later P0v tranche implements read-only status only",
		"no route from status to renewal permission",
		"CP, IM, Maintenance Agent, and Bridge authority boundaries remain preserved",
		"biometric leases remain exact-plan-digest approval only and not authority",
	)

	assertContainsNone(t, "operator healthcheck signing custody forbidden raw material", signingRaw,
		"-----BEGIN",
		"BEGIN PRIVATE KEY",
		"BEGIN RSA PRIVATE KEY",
		"BEGIN CERTIFICATE",
		"PRIVATE KEY-----",
		"CERTIFICATE-----",
		"renewal is now supported",
		"scheduled execution is allowed",
		"fallback emitter is allowed",
		"CP owns TLS signing",
		"IM owns TLS signing",
		"Maintenance Agent may define signing topology",
		"Bridge may approve replacement",
	)
}

func TestRemoteAlphaOperatorHealthcheckTLSSigningCustodyResolutionCriteria(t *testing.T) {
	access := standingRuleSection(t, standingRouteRulesPath, remoteAlphaAccessHeading)
	routeRules := compactText(mustRead(t, standingRouteRulesPath))
	remoteOverview := compactText(mustRead(t, ".docs/system_overview/remote_supported_host_alpha.md"))
	replacementRaw := mustRead(t, ".docs/remote_alpha_operator_healthcheck_tls_operator_authorized_replacement.md")
	signingRaw := mustRead(t, ".docs/remote_alpha_operator_healthcheck_tls_signing_custody.md")
	resolutionRaw := mustRead(t, ".docs/remote_alpha_operator_healthcheck_tls_signing_custody_resolution.md")
	resolution := compactText(resolutionRaw)
	signerEvidence := compactDocSection(t, resolutionRaw, "## 2. Acceptable Signer Evidence", "## 3. Key Custody Evidence")
	keyCustody := compactDocSection(t, resolutionRaw, "## 3. Key Custody Evidence", "## 4. CSR, Cert-Only, Key-Reuse, And Key-Rotation Criteria")
	flowCriteria := compactDocSection(t, resolutionRaw, "## 4. CSR, Cert-Only, Key-Reuse, And Key-Rotation Criteria", "## 5. Backup And Rollback Proof Model")
	backupRollback := compactDocSection(t, resolutionRaw, "## 5. Backup And Rollback Proof Model", "## 6. Redaction Gate")
	redactionGate := compactDocSection(t, resolutionRaw, "## 6. Redaction Gate", "## 7. Post-Check Evidence Gates")
	postChecks := compactDocSection(t, resolutionRaw, "## 7. Post-Check Evidence Gates", "## 8. Route Metadata Transition Criteria")
	routeTransitions := compactDocSection(t, resolutionRaw, "## 8. Route Metadata Transition Criteria", "## 9. Relationship To Biometric Leases")
	biometric := compactDocSection(t, resolutionRaw, "## 9. Relationship To Biometric Leases", "## 10. Owner Boundaries")
	boundaries := compactDocSection(t, resolutionRaw, "## 10. Owner Boundaries", "## 11. Static-Test Expectations")
	staticExpectations := compactDocSection(t, resolutionRaw, "## 11. Static-Test Expectations", "")
	source := mustRead(t, remoteAlphaOperatorScriptPath())
	dispatchSections := docSection(t, source, "recovery_session() {", "\nprint_refresh_command() {") +
		"\n" + docSection(t, source, "main() {", "\nmain \"$@\"")

	assertContainsAll(t, "Remote Alpha operator noninteractive status implemented dispatch", dispatchSections,
		`"$1" == "operator-healthcheck-tls-status-noninteractive"`,
		"recovery_session_operator_healthcheck_tls_status_noninteractive",
	)
	assertNoActiveShellDispatchArm(t, "Remote Alpha operator replacement route remains unimplemented", dispatchSections, "operator-healthcheck-tls-replace")
	assertNoActiveShellDispatchArm(t, "Remote Alpha operator replacement route remains unimplemented", dispatchSections, "operator-healthcheck-tls-replacement")

	assertContainsAll(t, "operator healthcheck resolution access contract standing rules boundary", access,
		"operator-authorized operator-healthcheck TLS replacement design tranche is also docs/static-test only",
		"signing authority, signer custody, key custody, CSR/cert flow, backup/rollback evidence, redaction, and post-check semantics remain ES unresolved stop conditions",
	)
	assertContainsAll(t, "operator healthcheck resolution standing route rules boundary", routeRules,
		"`operator-healthcheck-tls-renew` remains blocked/status-only with `unsupported_signing_topology`",
	)

	assertContainsAll(t, "operator healthcheck resolution overview link", remoteOverview,
		"resolution criteria in `.docs/remote_alpha_operator_healthcheck_tls_signing_custody_resolution.md`",
		"It is docs/static-test only and does not implement renewal, replacement, CP diagnose, IM profile-lineage refresh",
		"preserves `operator-healthcheck-tls-renew` as blocked with `unsupported_signing_topology`",
	)

	assertContainsAll(t, "operator healthcheck resolution replacement link", compactText(replacementRaw),
		"`.docs/remote_alpha_operator_healthcheck_tls_signing_custody_resolution.md`",
		"replacement sequence",
		"resolution criteria remain explicit non-execution gates",
	)
	assertContainsAll(t, "operator healthcheck resolution signing link", compactText(signingRaw),
		"`.docs/remote_alpha_operator_healthcheck_tls_signing_custody_resolution.md`",
		"checklist completion cannot be confused with replacement execution or renewal authorization",
	)

	assertContainsAll(t, "operator healthcheck resolution criteria", resolution,
		"Remote Alpha Operator-Healthcheck TLS Signing/Custody Resolution Criteria",
		"evidence gate for moving Remote Alpha operator-healthcheck TLS signing/custody from unresolved/fail-closed to operator-authorized replacement design-ready",
		"`Design/static-test prep only`: this document does not execute replacement",
		"`operator-healthcheck-tls-renew` remains blocked with `unsupported_signing_topology`",
		"authorize or consume the later read-only noninteractive status route",
		"`Reopened redesign seam`: signer authority, signer custody, key custody, key reuse, key rotation, and CSR/cert material flow remain unresolved",
		"Current reusable P0u resolution verdict: blocked.",
		"No current ES source satisfies the signer authority and custody evidence gate below",
		"No current ES source satisfies this list.",
		"resolution remains blocked and the renewal failure class remains `unsupported_signing_topology`",
	)

	assertContainsAll(t, "operator healthcheck resolution signer evidence", signerEvidence,
		"documented ES-owned signing authority",
		"documented host-local signer custody",
		"documented CA/trust ownership",
		"documented issuer/trust-chain metadata expected by CP profile diagnostics",
		"documented separation from `es-service-tls-renew` and `es-governance-tls-renew` signers unless an ES contract explicitly proves a shared signing authority",
		"`client.operator`",
		"`spiffe://execution.internal/operator/local`",
		"explicit non-authority labels for CP, IM, Maintenance Agent, and Bridge",
		"assumption that a retained runtime CA private key exists",
		"ad hoc signing material supplied through CLI args, env files, reports, support bundles, retained bundles, proof artifacts, Bridge evidence, MA plans, CP diagnostics, or IM profile lineage",
		"authority inferred from service TLS, governance TLS, profile refresh, CP diagnostics, Bridge preflight, or a biometric lease",
	)

	assertContainsAll(t, "operator healthcheck resolution key custody", keyCustody,
		"Current key custody owner",
		"Key reuse policy",
		"Key rotation policy",
		"CSR author",
		"Key-pair match owner",
		"Public metadata artifacts",
		"Never-private artifacts",
		"Unresolved stop condition.",
		"Current invariant.",
		"reusable P0u replacement remains blocked",
	)

	assertContainsAll(t, "operator healthcheck resolution flow criteria", flowCriteria,
		"CSR flow",
		"Cert-only replacement",
		"Key reuse",
		"Key rotation",
		"Required evidence",
		"Prohibited actions",
		"Redaction requirements",
		"Stop conditions",
		"ES host-local custody",
		"Service TLS and governance TLS renewal criteria do not substitute",
	)

	assertContainsAll(t, "operator healthcheck resolution backup rollback", backupRollback,
		"pre-replacement public operator client certificate metadata",
		"trust-bundle metadata",
		"profile material metadata received from or destined for IM-owned profile contracts",
		"safe public-material digests or fingerprints only where the owner contract allows them",
		"rollback labels and rollback target labels",
		"owner confirmation labels for ES TLS material and IM profile/provenance material",
		"redaction status and final deny-scan status",
		"post-rollback check labels",
		"Rollback evidence is not authority until the owning path confirms it",
		"CP owner diagnostics are required before profile acceptance can be claimed",
	)

	assertContainsAll(t, "operator healthcheck resolution redaction gate", redactionGate,
		"private keys",
		"PEM bodies",
		"raw certificate bodies",
		"env values",
		"endpoint secrets",
		"TLS/SPIFFE/SPIRE/Vault material beyond safe labels and owner-allowed digests",
		"raw helper, SSH, shell, CP, IM, MA, or Bridge transcripts",
		"unsafe local paths",
		"unsafe remote paths",
		"support-bundle payloads",
		"retained-bundle payloads",
		"proof payloads",
		"redaction policy label",
		"deny-scan status",
	)

	assertContainsAll(t, "operator healthcheck resolution post checks", postChecks,
		"cert metadata freshness",
		"identity/SAN/SPIFFE match",
		"trust-chain match",
		"key-pair match without key exposure",
		"CP diagnose-remote-profile pass",
		"IM profile lineage refreshed",
		"redaction pass",
		"no authority widening",
		"no live proof claim",
	)

	assertContainsAll(t, "operator healthcheck resolution route transitions", routeTransitions,
		"All route metadata transitions are blocked today.",
		"Before `operator-healthcheck-tls-renew` can move from blocked to operator-approved renewal",
		"source-grounded signing authority",
		"signer custody",
		"key custody and selected key action",
		"CSR or cert-only material flow",
		"backup-before-replace and rollback model",
		"`unsupported_signing_topology` is no longer active for the selected path",
		"Before the implemented read-only noninteractive status route can be consumed by MA",
		"ES must complete independent audit of the route in a later tranche",
		"`scheduled_execution_allowed=false`",
		"MA must update its own route metadata/docs/tests before consumption",
		"Before auto-renew eligibility can be discussed",
		"a noninteractive renewal route must be separately documented, implemented, audited, and tested",
		"`operator-healthcheck-tls-renew`: blocked/status-only with `unsupported_signing_topology`",
		"`operator-healthcheck-tls-status-noninteractive`: implemented read-only status only",
		"not MA-consumable until later MA-owned metadata/docs/tests and audit",
		"auto-renew: not eligible and not discussable as executable design",
	)

	assertContainsAll(t, "operator healthcheck resolution biometric lease", biometric,
		"A future biometric lease may approve only the exact canonical plan digest",
		"after signer/custody evidence is resolved",
		"create signer authority",
		"create signer custody",
		"create key custody",
		"override route eligibility",
		"bypass CP profile diagnostics ownership",
		"bypass IM profile lineage ownership",
		"make `unsupported_signing_topology` safe",
	)

	assertContainsAll(t, "operator healthcheck resolution owner boundaries", boundaries,
		"ES owns:",
		"operator-healthcheck TLS route/material semantics",
		"signing topology resolution",
		"key custody and key action classification",
		"IM owns:",
		"Remote Alpha profile/provenance/readiness emission",
		"CP owns:",
		"`diagnose-remote-profile`",
		"Maintenance Agent owns:",
		"its own route metadata",
		"Bridge owns:",
		"local coordination/preflight evidence only",
		"must not act as ES signing authorities",
		"must not wrap missing ES prerequisites into ES status truth",
	)

	assertContainsAll(t, "operator healthcheck resolution static tests", staticExpectations,
		"this resolution criteria doc exists",
		"the gate is docs/static only",
		"no replacement execution is enabled",
		"no renewal is enabled",
		"`unsupported_signing_topology` remains blocked today",
		"signer evidence remains unresolved unless explicitly documented by ES",
		"key custody evidence is required",
		"CSR/cert-only, key reuse, and key rotation criteria are present",
		"backup/rollback proof model is present",
		"redaction gates are present",
		"post-check evidence gates are present",
		"route metadata transition criteria are present and keep renewal, noninteractive MA consumption, and auto-renew blocked today",
		"biometric leases approve only exact plan digests after owner evidence exists and cannot create signer authority or key custody",
		"raw PEM/key/cert material is absent from docs",
		"CP, IM, Maintenance Agent, and Bridge boundaries remain preserved",
	)

	combinedDocs := replacementRaw + "\n" + signingRaw + "\n" + resolutionRaw
	assertContainsNone(t, "operator healthcheck resolution forbidden raw material and overclaims", combinedDocs,
		"-----BEGIN",
		"BEGIN PRIVATE KEY",
		"BEGIN RSA PRIVATE KEY",
		"BEGIN CERTIFICATE",
		"PRIVATE KEY-----",
		"CERTIFICATE-----",
		"renewal is now enabled",
		"replacement execution is now enabled",
		"replacement is authorized",
		"auto-renew is eligible",
		"CP owns TLS signing",
		"IM owns TLS signing",
		"Maintenance Agent may define signing topology",
		"Bridge may approve replacement",
	)
}

func TestRemoteAlphaOperatorHealthcheckTLSDocsSigningCustodyDecisionRecord(t *testing.T) {
	access := standingRuleSection(t, standingRouteRulesPath, remoteAlphaAccessHeading)
	routeRules := compactText(mustRead(t, standingRouteRulesPath))
	remoteOverview := compactText(mustRead(t, ".docs/system_overview/remote_supported_host_alpha.md"))
	replacementRaw := mustRead(t, ".docs/remote_alpha_operator_healthcheck_tls_operator_authorized_replacement.md")
	signingRaw := mustRead(t, ".docs/remote_alpha_operator_healthcheck_tls_signing_custody.md")
	resolutionRaw := mustRead(t, ".docs/remote_alpha_operator_healthcheck_tls_signing_custody_resolution.md")
	decisionRaw := mustRead(t, ".docs/remote_alpha_operator_healthcheck_tls_signing_custody_decision.md")
	decision := compactText(decisionRaw)
	options := compactDocSection(t, decisionRaw, "## 2. Options Compared", "## 3. External Evidence Requirements")
	externalEvidence := compactDocSection(t, decisionRaw, "## 3. External Evidence Requirements", "## 4. Decision Consequences")
	consequences := compactDocSection(t, decisionRaw, "## 4. Decision Consequences", "## 5. Relationship To Existing Docs")
	relationships := compactDocSection(t, decisionRaw, "## 5. Relationship To Existing Docs", "## 6. Static-Test Expectations")
	staticExpectations := compactDocSection(t, decisionRaw, "## 6. Static-Test Expectations", "")
	source := mustRead(t, remoteAlphaOperatorScriptPath())
	dispatchSections := docSection(t, source, "recovery_session() {", "\nprint_refresh_command() {") +
		"\n" + docSection(t, source, "main() {", "\nmain \"$@\"")

	assertContainsAll(t, "Remote Alpha operator decision sees implemented noninteractive status", dispatchSections,
		`"$1" == "operator-healthcheck-tls-status-noninteractive"`,
	)
	assertNoActiveShellDispatchArm(t, "Remote Alpha operator decision keeps replacement unimplemented", dispatchSections, "operator-healthcheck-tls-replace")
	assertNoActiveShellDispatchArm(t, "Remote Alpha operator decision keeps replacement unimplemented", dispatchSections, "operator-healthcheck-tls-replacement")

	assertContainsAll(t, "operator healthcheck signing custody decision access contract standing rules boundary", access,
		"operator-authorized operator-healthcheck TLS replacement design tranche is also docs/static-test only",
		"signing authority, signer custody, key custody, CSR/cert flow, backup/rollback evidence, redaction, and post-check semantics remain ES unresolved stop conditions",
	)
	assertContainsAll(t, "operator healthcheck signing custody decision standing route rules boundary", routeRules,
		"`operator-healthcheck-tls-renew` remains blocked/status-only with `unsupported_signing_topology`",
	)

	assertContainsAll(t, "operator healthcheck signing custody decision overview link", remoteOverview,
		"blocked signer/custody decision record in `.docs/remote_alpha_operator_healthcheck_tls_signing_custody_decision.md`",
		"preserves `operator-healthcheck-tls-renew` as blocked with `unsupported_signing_topology`",
	)

	assertContainsAll(t, "operator healthcheck signing custody decision cross links",
		compactText(replacementRaw+"\n"+signingRaw+"\n"+resolutionRaw),
		"`.docs/remote_alpha_operator_healthcheck_tls_signing_custody_decision.md`",
		"records that no signer/custody option is selected today",
		"compares candidate signer/custody options and records that no option is selected today",
		"options comparison and selection status must not be confused with resolution criteria",
	)

	assertContainsAll(t, "operator healthcheck signing custody decision record", decision,
		"Remote Alpha Operator-Healthcheck TLS Signer/Custody Decision Record",
		"Decision status for reusable P0u: blocked.",
		"What signer authority and private-key custody model may be used for operator-healthcheck client TLS replacement?",
		"`Design/static-test prep only`: this record does not execute replacement",
		"`operator-healthcheck-tls-renew` remains blocked with `unsupported_signing_topology`",
		"P0v was design/static-only at the time of this decision record.",
		"A later P0v tranche now implements read-only status only",
		"no route from status to renewal permission",
		"`Reopened redesign seam`: signer authority, signer custody, key custody, key reuse, key rotation, and CSR/cert material flow remain unresolved",
		"No option is selected for reusable P0u.",
		"Reusable P0u replacement remains blocked.",
		"Service and governance TLS signers cannot be reused by inference.",
		"CP, IM, Maintenance Agent, Bridge, biometric leases, profile diagnostics, profile lineage, preflight evidence, support bundles, retained bundles, proof artifacts, and reports cannot create ES signer authority or key custody.",
		"Future work must source-ground signer authority, signer custody, CA/trust ownership, key custody, key action classification, CSR/cert flow, backup/rollback, redaction, and post-check ownership",
	)

	assertContainsAll(t, "operator healthcheck signing custody decision options", options,
		"Option A: Reuse Service TLS Signer/CA",
		"Current source evidence: ES documents service TLS renewal as a separate ARS/AGS/ES artifact-registry mTLS scope.",
		"Disposition: rejected by inference; blocked and not selected.",
		"Option B: Reuse Governance TLS Signer/CA",
		"Current source evidence: ES documents governance TLS renewal as a separate ES to EGS execution-governance trust-model mTLS scope.",
		"Option C: Define A Dedicated ES-Owned Operator-Healthcheck Signer/CA",
		"Disposition: deferred candidate; blocked and not selected.",
		"Option D: Define A Host-Local Operator-Healthcheck Signer",
		"Option E: External/Manual Operator-Provided Public Cert Only",
		"Manual public cert input cannot be accepted as ad hoc signer authority.",
		"Option F: CSR Flow From Host-Local Key To Future ES-Approved Signer",
		"Option G: Cert-Only Replacement Against Existing Host-Local Key",
		"no current source selects it, approves key reuse, or identifies an approved signer",
		"Stop conditions:",
	)

	assertContainsAll(t, "operator healthcheck signing custody decision external evidence", externalEvidence,
		"signer owner",
		"signer custody",
		"CA/trust ownership",
		"issuer/trust metadata expected by CP",
		"key custody owner",
		"reuse vs rotation decision",
		"CSR vs cert-only decision",
		"key-pair match method that does not expose private-key material",
		"backup/rollback owner and evidence labels",
		"redaction proof",
		"CP diagnose input contract",
		"IM lineage refresh input contract",
		"source-grounded in ES-owned docs/tests or in an owning-repo contract that ES explicitly adopts",
	)

	assertContainsAll(t, "operator healthcheck signing custody decision consequences", consequences,
		"no replacement execution",
		"no renewal",
		"no route eligibility widening",
		"no noninteractive renewal route",
		"no MA scheduled execution",
		"no biometric lease approval path for renewal",
		"no CP diagnose rerun",
		"no IM refresh execution",
		"no Remote Alpha proof resumption",
		"no Bridge projection or preflight may become ES status truth",
		"no service/governance TLS signer may be reused by inference",
		"The current helper and route behavior remains fail-closed.",
	)

	assertContainsAll(t, "operator healthcheck signing custody decision relationships", relationships,
		"`.docs/remote_alpha_operator_healthcheck_tls_signing_custody.md` records custody boundaries and stop conditions.",
		"`.docs/remote_alpha_operator_healthcheck_tls_signing_custody_resolution.md` records the evidence gate and exact criteria",
		"`.docs/remote_alpha_operator_healthcheck_tls_operator_authorized_replacement.md` records the future replacement sequence",
		"`.docs/remote_alpha_operator_healthcheck_noninteractive_status.md` now records P0v as an implemented no-fallback read-only status route",
		"IM `remote-alpha-operator-healthcheck-profile-lineage-refresh.md`",
		"CP `diagnose-remote-profile` owns contact-free profile diagnostics",
		"MA `macos-biometric-maintenance-authorization.md`",
		"Bridge `es-operator-healthcheck-preflight-design.md` records local-only, non-authoritative preflight evidence",
	)

	assertContainsAll(t, "operator healthcheck signing custody decision static tests", staticExpectations,
		"this decision record exists",
		"decision status is blocked, not selected",
		"options A through G are enumerated",
		"no option is selected today",
		"service/governance TLS reuse is not selected by inference",
		"replacement remains blocked",
		"`operator-healthcheck-tls-renew` remains blocked by `unsupported_signing_topology`",
		"route eligibility is not widened",
		"P0v was design/static-only at the time of this record, and the later implementation remains read-only with no fallback emitter",
		"external evidence requirements are documented",
		"no raw PEM/key/cert material is present",
		"CP, IM, Maintenance Agent, Bridge, and biometric leases cannot provide ES signer authority",
		"no route execution, renewal, CP diagnose, IM refresh, MA scheduled execution, Bridge control, or live proof is enabled",
	)

	assertContainsNone(t, "operator healthcheck signing custody decision forbidden raw material and overclaims", decisionRaw,
		"-----BEGIN",
		"BEGIN PRIVATE KEY",
		"BEGIN RSA PRIVATE KEY",
		"BEGIN CERTIFICATE",
		"PRIVATE KEY-----",
		"CERTIFICATE-----",
		"Decision status: selected",
		"renewal is now enabled",
		"replacement execution is now enabled",
		"replacement is authorized",
		"auto-renew is eligible",
		"CP owns TLS signing",
		"IM owns TLS signing",
		"Maintenance Agent may define signing topology",
		"Bridge may approve replacement",
	)
}

const remoteAlphaTLSIncidentContractPath = ".docs/system_overview/remote_alpha_external_tls_one_time_incident_contract.md"
const remoteAlphaTLSIncidentRecordKind = "execution-substrate.remote-alpha.external-tls-single-use-incident-contract.v1"
const remoteAlphaTLSMaxRecordBytes, remoteAlphaTLSMaxDepth = 64 << 10, 8
const remoteAlphaTLSMaxObjectMembers, remoteAlphaTLSMaxArrayItems = 64, 64
const remoteAlphaTLSMaxMemberBytes, remoteAlphaTLSMaxStringBytes = 256, 4096

// This sorted vocabulary is fixed by the incident contract, not by candidate JSON or struct-field matching.
var remoteAlphaTLSCanonicalMemberNames = strings.Fields(`
acceptance active_authorization_docs_and_tests_removed_or_converted_on_terminal_closure ags_application_authorization_claim_requires_source_defined_check
ags_es_allowlists_must_already_accept_required_identities ags_es_share_server_leaf ags_nonmutating_application_authorization_operation_available authorization
authorization_configuration_mutation_allowed authorization_from_common_name_allowed automatic_renewal bootstrap_issuer_comparison_values_must_be_inventoried
ca_basic_constraints_critical ca_key_end_condition_required ca_key_usage ca_keys_encrypted_at_rest ca_keys_human_custodied_on_mac ca_path_length ca_roles
ca_validity_is_leaf_coverage_plus_bounded_grace certificate_signature changed_candidate_requires_new_es_decision
changed_candidate_requires_new_independent_audit classification client_leaf_eku client_uri_count_per_leaf closure_states complete_candidate_validation_required
complete_host_disk_set_before_restart complete_private_backup_required consume_on_first_effect control_plane_uri cross_role_key_reuse_allowed
cross_role_trust_allowed cryptography custody cutover default_disposition digital_signature_required es_authorizes_profile_mutation exact_san_required
exact_sunset_required_before_first_effect executions first_effect_irreversibly_consumes_authority fresh_keypairs hosts identities
im_contract_commit_and_tree_bound_before_first_es_effect_when_handoff_required im_projection_is_acceptance im_recovery_authority implementation_status incidents
initial_state installation_may_use_only_second_gate_manifest key_algorithm key_reuse_allowed leaf_basic_constraints_critical leaf_keys_generated_at_point_of_use
leaf_maximum_days leaf_must_not_exceed_sunset leaf_roles legacy_operator_uri_allowed live_inventory_required ma_execution_authority minimum_tls non_goals
nonterminal_closure_state ongoing_remote_alpha_support only_csr_and_public_material_cross_machine operator_compatibility_cn operator_compatibility_dns
operator_uri os_update_or_reboot owner post_generation_candidate_manifest_required pre_effect_binding pre_effect_candidate_manifest_allowed preflight
private_key_cross_machine production_pki profile_handoff profile_handoff_failure_revokes_es_acceptance profile_handoff_failure_state
profile_handoff_failure_triggers_automatic_host_tls_rollback profile_replacement_is_es_consuming_effect profile_replacement_occurs_only_after_es_acceptance
public_protocol record_kind reported_expiry_is_not_repository_truth required_checks restart_order retirement_action_minimum_scope retirement_action_required
retirement_evidence_required retirement_owner_required return_to_authorized_not_consumed_allowed reusable_recovery_route rollback_outcome
rollback_outcome_claims_health scheduler scope second_human_gate_required_before_installation second_packet_allowed separate_committed_im_contract_required
server_leaf_eku sunset terminal_closeout_requires_handoff_or_explicit_retirement terminal_closure_states terminal_state_authorizes_another_packet
tls_binding_mutation_before_inventory_allowed topology unchanged_rollback_packet_allowed_within_consumed_incident unchanged_rollback_packet_is_new_authority
`)

func remoteAlphaTLSScanJSON(decoder *json.Decoder, opening json.Delim, depth int) error {
	if depth > remoteAlphaTLSMaxDepth {
		return fmt.Errorf("json_limit_exceeded path=$")
	}
	object, limit := opening == '{', remoteAlphaTLSMaxArrayItems
	var seen map[string]struct{}
	if object {
		limit, seen = remoteAlphaTLSMaxObjectMembers, make(map[string]struct{})
	}
	count := 0
	for decoder.More() {
		count++
		if count > limit {
			return fmt.Errorf("json_limit_exceeded path=$")
		}
		if object {
			token, _ := decoder.Token()
			key, ok := token.(string)
			if !ok {
				return fmt.Errorf("malformed_json path=$")
			}
			if len(key) > remoteAlphaTLSMaxMemberBytes {
				return fmt.Errorf("json_limit_exceeded path=$")
			}
			if !slices.Contains(remoteAlphaTLSCanonicalMemberNames, key) {
				return fmt.Errorf("unknown_json_key path=$")
			}
			if _, exists := seen[key]; exists {
				return fmt.Errorf("duplicate_json_key path=$")
			}
			seen[key] = struct{}{}
		}
		token, _ := decoder.Token()
		switch value := token.(type) {
		case string:
			if len(value) > remoteAlphaTLSMaxStringBytes {
				return fmt.Errorf("json_limit_exceeded path=$")
			}
		case nil, bool, json.Number:
		case json.Delim:
			if err := remoteAlphaTLSScanJSON(decoder, value, depth+1); err != nil {
				return err
			}
		default:
			return fmt.Errorf("malformed_json path=$")
		}
	}
	decoder.Token() // Consume the matching delimiter from the already-valid RawMessage.
	return nil
}

func remoteAlphaTLSJSONPreflight(raw []byte) error {
	if len(raw) > remoteAlphaTLSMaxRecordBytes {
		return fmt.Errorf("json_limit_exceeded path=$")
	}
	source := json.NewDecoder(bytes.NewReader(raw))
	var rootJSON json.RawMessage
	if err := source.Decode(&rootJSON); err != nil {
		return fmt.Errorf("malformed_json path=$")
	}
	if len(bytes.TrimSpace(raw[source.InputOffset():])) != 0 {
		return fmt.Errorf("trailing_json_content path=$")
	}
	decoder := json.NewDecoder(bytes.NewReader(rootJSON))
	decoder.UseNumber()
	// rootJSON was decoded successfully, so token reads cannot fail.
	token, _ := decoder.Token()
	root, ok := token.(json.Delim)
	if !ok || root != '{' {
		return fmt.Errorf("json_type_mismatch path=$")
	}
	return remoteAlphaTLSScanJSON(decoder, root, 1)
}

type remoteAlphaTLSBool bool

func (v *remoteAlphaTLSBool) is(want bool) bool { return v != nil && bool(*v) == want }

// Preserve the source token kind for the seven numeric documentation members.
// A null remains an absent value so the existing field-specific diagnostic wins.
type remoteAlphaTLSNumber string

func (v *remoteAlphaTLSNumber) UnmarshalJSON(raw []byte) error {
	if bytes.Equal(raw, []byte("null")) {
		*v = ""
		return nil
	}
	if len(raw) == 0 || (raw[0] != '-' && (raw[0] < '0' || raw[0] > '9')) || !json.Valid(raw) {
		return fmt.Errorf("expected JSON number token")
	}
	*v = remoteAlphaTLSNumber(raw)
	return nil
}

func (v remoteAlphaTLSNumber) String() string { return string(v) }

type remoteAlphaTLSIncident struct {
	Record_kind, Classification, Implementation_status string
	Public_protocol                                    *remoteAlphaTLSBool
	Scope                                              remoteAlphaTLSScope
	Authorization                                      remoteAlphaTLSAuthorization
	Topology                                           remoteAlphaTLSTopology
	Identities                                         remoteAlphaTLSIdentities
	Cryptography                                       remoteAlphaTLSCryptography
	Custody                                            remoteAlphaTLSCustody
	Preflight                                          remoteAlphaTLSPreflight
	Cutover                                            remoteAlphaTLSCutover
	Acceptance                                         remoteAlphaTLSAcceptance
	Profile_handoff                                    remoteAlphaTLSProfileHandoff
	Sunset                                             remoteAlphaTLSSunset
	Non_goals                                          remoteAlphaTLSNonGoals
}
type remoteAlphaTLSScope struct{ Hosts, Incidents, Executions remoteAlphaTLSNumber }
type remoteAlphaTLSAuthorization struct {
	Initial_state, Nonterminal_closure_state                                                                                                                                                    string
	Pre_effect_binding, Consume_on_first_effect, Closure_states, Terminal_closure_states                                                                                                        []string
	Pre_effect_candidate_manifest_allowed, First_effect_irreversibly_consumes_authority, Post_generation_candidate_manifest_required, Second_human_gate_required_before_installation            *remoteAlphaTLSBool
	Installation_may_use_only_second_gate_manifest, Changed_candidate_requires_new_es_decision, Changed_candidate_requires_new_independent_audit, Second_packet_allowed                         *remoteAlphaTLSBool
	Return_to_authorized_not_consumed_allowed, Unchanged_rollback_packet_allowed_within_consumed_incident, Unchanged_rollback_packet_is_new_authority, Terminal_state_authorizes_another_packet *remoteAlphaTLSBool
}
type remoteAlphaTLSTopology struct {
	Ca_roles, Leaf_roles                                                       []string
	Fresh_keypairs                                                             remoteAlphaTLSNumber
	Key_reuse_allowed, Cross_role_key_reuse_allowed, Private_key_cross_machine *remoteAlphaTLSBool
}
type remoteAlphaTLSIdentities struct {
	Control_plane_uri, Operator_uri, Operator_compatibility_cn, Operator_compatibility_dns        string
	Client_uri_count_per_leaf                                                                     remoteAlphaTLSNumber
	Authorization_from_common_name_allowed, Legacy_operator_uri_allowed, Ags_es_share_server_leaf *remoteAlphaTLSBool
}
type remoteAlphaTLSCryptography struct {
	Key_algorithm, Certificate_signature, Minimum_tls                                                                                                                                                                      string
	Leaf_maximum_days, Ca_path_length                                                                                                                                                                                      remoteAlphaTLSNumber
	Ca_key_usage, Server_leaf_eku, Client_leaf_eku                                                                                                                                                                         []string
	Leaf_must_not_exceed_sunset, Ca_validity_is_leaf_coverage_plus_bounded_grace, Ca_basic_constraints_critical, Leaf_basic_constraints_critical, Digital_signature_required, Exact_san_required, Cross_role_trust_allowed *remoteAlphaTLSBool
}
type remoteAlphaTLSCustody struct {
	Ca_keys_human_custodied_on_mac, Ca_keys_encrypted_at_rest, Leaf_keys_generated_at_point_of_use, Only_csr_and_public_material_cross_machine, Ca_key_end_condition_required *remoteAlphaTLSBool
}
type remoteAlphaTLSPreflight struct {
	Live_inventory_required, Reported_expiry_is_not_repository_truth, Ags_es_allowlists_must_already_accept_required_identities, Bootstrap_issuer_comparison_values_must_be_inventoried, Authorization_configuration_mutation_allowed, Tls_binding_mutation_before_inventory_allowed *remoteAlphaTLSBool
}
type remoteAlphaTLSCutover struct {
	Complete_candidate_validation_required, Complete_private_backup_required, Complete_host_disk_set_before_restart, Rollback_outcome_claims_health *remoteAlphaTLSBool
	Restart_order                                                                                                                                   []string
	Rollback_outcome                                                                                                                                string
}
type remoteAlphaTLSAcceptance struct {
	Owner                                                                                                                                                         string
	Required_checks                                                                                                                                               []string
	Im_projection_is_acceptance, Ags_nonmutating_application_authorization_operation_available, Ags_application_authorization_claim_requires_source_defined_check *remoteAlphaTLSBool
}
type remoteAlphaTLSProfileHandoff struct {
	Owner, Profile_handoff_failure_state                                                                                                                                                                         string
	Es_authorizes_profile_mutation, Separate_committed_im_contract_required, Im_contract_commit_and_tree_bound_before_first_es_effect_when_handoff_required                                                      *remoteAlphaTLSBool
	Profile_replacement_is_es_consuming_effect, Profile_replacement_occurs_only_after_es_acceptance, Profile_handoff_failure_revokes_es_acceptance, Profile_handoff_failure_triggers_automatic_host_tls_rollback *remoteAlphaTLSBool
	Terminal_closeout_requires_handoff_or_explicit_retirement                                                                                                                                                    *remoteAlphaTLSBool
}
type remoteAlphaTLSSunset struct {
	Default_disposition                                                                                                                                                                                          string
	Retirement_action_minimum_scope                                                                                                                                                                              []string
	Exact_sunset_required_before_first_effect, Retirement_owner_required, Retirement_action_required, Retirement_evidence_required, Active_authorization_docs_and_tests_removed_or_converted_on_terminal_closure *remoteAlphaTLSBool
}
type remoteAlphaTLSNonGoals struct {
	Reusable_recovery_route, Automatic_renewal, Scheduler, Production_pki, Ongoing_remote_alpha_support, Im_recovery_authority, Ma_execution_authority, Os_update_or_reboot *remoteAlphaTLSBool
}

func (v remoteAlphaTLSAuthorization) valid() bool {
	return v.Initial_state == "AUTHORIZED_NOT_CONSUMED" && v.Nonterminal_closure_state == "CONSUMED_OPEN_INCIDENT" &&
		remoteAlphaTLSSet(v.Pre_effect_binding, "incident_id", "physical_host", "es_contract_commit", "es_contract_tree", "private_plan_sha256", "incident_packet_sha256", "rollback_packet_sha256") &&
		remoteAlphaTLSSet(v.Consume_on_first_effect, "key_generation", "csr_generation", "certificate_signing", "private_backup_creation", "active_tls_installation", "service_restart") &&
		remoteAlphaTLSSet(v.Closure_states, "ABANDONED_UNUSED", "CONSUMED_OPEN_INCIDENT", "CONSUMED_AND_CLOSED") &&
		remoteAlphaTLSSet(v.Terminal_closure_states, "ABANDONED_UNUSED", "CONSUMED_AND_CLOSED") &&
		v.Pre_effect_candidate_manifest_allowed.is(false) && v.First_effect_irreversibly_consumes_authority.is(true) &&
		v.Post_generation_candidate_manifest_required.is(true) && v.Second_human_gate_required_before_installation.is(true) &&
		v.Installation_may_use_only_second_gate_manifest.is(true) && v.Changed_candidate_requires_new_es_decision.is(true) &&
		v.Changed_candidate_requires_new_independent_audit.is(true) && v.Second_packet_allowed.is(false) &&
		v.Return_to_authorized_not_consumed_allowed.is(false) && v.Unchanged_rollback_packet_allowed_within_consumed_incident.is(true) &&
		v.Unchanged_rollback_packet_is_new_authority.is(false) && v.Terminal_state_authorizes_another_packet.is(false)
}
func remoteAlphaTLSSet(got []string, want ...string) bool {
	got = slices.Clone(got)
	slices.Sort(got)
	slices.Sort(want)
	return slices.Equal(got, want)
}
func decodeRemoteAlphaTLSIncidentJSON(raw []byte) (*remoteAlphaTLSIncident, error) {
	if err := remoteAlphaTLSJSONPreflight(raw); err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	decoder.DisallowUnknownFields()
	var record remoteAlphaTLSIncident
	if err := decoder.Decode(&record); err != nil {
		if strings.HasPrefix(err.Error(), "json: unknown field ") {
			return nil, fmt.Errorf("unknown_json_key path=$")
		}
		return nil, fmt.Errorf("json_type_mismatch path=$")
	}
	if err := validateRemoteAlphaTLSIncidentRecord(&record); err != nil {
		return nil, err
	}
	return &record, nil
}
func validateRemoteAlphaTLSIncidentRecord(r *remoteAlphaTLSIncident) error {
	if r.Record_kind != remoteAlphaTLSIncidentRecordKind || r.Classification != "bounded_proof_support_incident" || r.Implementation_status != "documentation_only" || !r.Public_protocol.is(false) {
		return fmt.Errorf("unexpected_json_value path=$")
	}
	for _, number := range []struct {
		ok   bool
		path string
	}{
		{r.Scope.Hosts.String() == "1", "$.scope.hosts"},
		{r.Scope.Incidents.String() == "1", "$.scope.incidents"},
		{r.Scope.Executions.String() == "1", "$.scope.executions"},
		{r.Topology.Fresh_keypairs.String() == "6", "$.topology.fresh_keypairs"},
		{r.Identities.Client_uri_count_per_leaf.String() == "1", "$.identities.client_uri_count_per_leaf"},
		{r.Cryptography.Leaf_maximum_days.String() == "365", "$.cryptography.leaf_maximum_days"},
		{r.Cryptography.Ca_path_length.String() == "0", "$.cryptography.ca_path_length"},
	} {
		if !number.ok {
			return fmt.Errorf("unexpected_json_value path=%s", number.path)
		}
	}
	c := r.Cryptography
	p := r.Profile_handoff
	s := r.Sunset
	n := r.Non_goals
	fixed := []struct {
		path  string
		valid bool
	}{
		{"$.authorization", r.Authorization.valid()},
		{"$.topology", remoteAlphaTLSSet(r.Topology.Ca_roles, "external_server_auth", "external_client_auth") && remoteAlphaTLSSet(r.Topology.Leaf_roles, "ags_server", "es_server", "control_plane_client", "operator_client") && r.Topology.Key_reuse_allowed.is(false) && r.Topology.Cross_role_key_reuse_allowed.is(false) && r.Topology.Private_key_cross_machine.is(false)},
		{"$.identities", r.Identities.Control_plane_uri == "spiffe://execution.internal/service/control-plane" && r.Identities.Operator_uri == "spiffe://execution.internal/operator/local" && r.Identities.Operator_compatibility_cn == "client.operator" && r.Identities.Operator_compatibility_dns == "client.operator" && r.Identities.Authorization_from_common_name_allowed.is(false) && r.Identities.Legacy_operator_uri_allowed.is(false) && r.Identities.Ags_es_share_server_leaf.is(false)},
		{"$.cryptography", c.Key_algorithm == "RSA-3072" && c.Certificate_signature == "SHA-256" && c.Minimum_tls == "1.2" && remoteAlphaTLSSet(c.Ca_key_usage, "keyCertSign", "cRLSign") && remoteAlphaTLSSet(c.Server_leaf_eku, "serverAuth") && remoteAlphaTLSSet(c.Client_leaf_eku, "clientAuth") && c.Leaf_must_not_exceed_sunset.is(true) && c.Ca_validity_is_leaf_coverage_plus_bounded_grace.is(true) && c.Ca_basic_constraints_critical.is(true) && c.Leaf_basic_constraints_critical.is(true) && c.Digital_signature_required.is(true) && c.Exact_san_required.is(true) && c.Cross_role_trust_allowed.is(false)},
		{"$.custody", r.Custody.Ca_keys_human_custodied_on_mac.is(true) && r.Custody.Ca_keys_encrypted_at_rest.is(true) && r.Custody.Leaf_keys_generated_at_point_of_use.is(true) && r.Custody.Only_csr_and_public_material_cross_machine.is(true) && r.Custody.Ca_key_end_condition_required.is(true)},
		{"$.preflight", r.Preflight.Live_inventory_required.is(true) && r.Preflight.Reported_expiry_is_not_repository_truth.is(true) && r.Preflight.Ags_es_allowlists_must_already_accept_required_identities.is(true) && r.Preflight.Bootstrap_issuer_comparison_values_must_be_inventoried.is(true) && r.Preflight.Authorization_configuration_mutation_allowed.is(false) && r.Preflight.Tls_binding_mutation_before_inventory_allowed.is(false)},
		{"$.cutover", r.Cutover.Complete_candidate_validation_required.is(true) && r.Cutover.Complete_private_backup_required.is(true) && r.Cutover.Complete_host_disk_set_before_restart.is(true) && slices.Equal(r.Cutover.Restart_order, []string{"ags.service", "es.service"}) && r.Cutover.Rollback_outcome == "restored_prior_incident_state" && r.Cutover.Rollback_outcome_claims_health.is(false)},
		{"$.acceptance", r.Acceptance.Owner == "execution_substrate" && r.Acceptance.Im_projection_is_acceptance.is(false) && remoteAlphaTLSSet(r.Acceptance.Required_checks, "installed_set_integrity", "configured_allowlist_match", "direct_operator_mtls", "direct_control_plane_ags_mtls", "direct_control_plane_es_mtls", "es_contract_endpoint", "fresh_substrate_observations") && r.Acceptance.Ags_nonmutating_application_authorization_operation_available.is(false) && r.Acceptance.Ags_application_authorization_claim_requires_source_defined_check.is(true)},
		{"$.profile_handoff", p.Owner == "infrastructure_manager" && p.Es_authorizes_profile_mutation.is(false) && p.Separate_committed_im_contract_required.is(true) && p.Im_contract_commit_and_tree_bound_before_first_es_effect_when_handoff_required.is(true) && p.Profile_replacement_is_es_consuming_effect.is(false) && p.Profile_replacement_occurs_only_after_es_acceptance.is(true) && p.Profile_handoff_failure_state == "CONSUMED_OPEN_INCIDENT" && p.Profile_handoff_failure_revokes_es_acceptance.is(false) && p.Profile_handoff_failure_triggers_automatic_host_tls_rollback.is(false) && p.Terminal_closeout_requires_handoff_or_explicit_retirement.is(true)},
		{"$.sunset", s.Default_disposition == "RETIRE_BEFORE_LEAF_EXPIRY" && s.Exact_sunset_required_before_first_effect.is(true) && s.Retirement_owner_required.is(true) && s.Retirement_action_required.is(true) && s.Retirement_evidence_required.is(true) && remoteAlphaTLSSet(s.Retirement_action_minimum_scope, "disable_or_retire_external_access_path", "deactivate_runnable_mac_profile", "complete_ca_key_disposition", "record_host_topology_disposition") && s.Active_authorization_docs_and_tests_removed_or_converted_on_terminal_closure.is(true)},
		{"$.non_goals", n.Reusable_recovery_route.is(true) && n.Automatic_renewal.is(true) && n.Scheduler.is(true) && n.Production_pki.is(true) && n.Ongoing_remote_alpha_support.is(true) && n.Im_recovery_authority.is(true) && n.Ma_execution_authority.is(true) && n.Os_update_or_reboot.is(true)},
	}
	for _, check := range fixed {
		if !check.valid {
			return fmt.Errorf("unexpected_json_value path=%s", check.path)
		}
	}
	return nil
}
func validateRemoteAlphaTLSIncidentJSON(raw []byte) error {
	_, err := decodeRemoteAlphaTLSIncidentJSON(raw)
	return err
}

func requireRemoteAlphaTLS(t *testing.T, ok bool, format string, args ...any) {
	t.Helper()
	if !ok {
		t.Fatalf(format, args...)
	}
}

func remoteAlphaTLSIncidentJSON(t *testing.T) ([]byte, string) {
	t.Helper()
	raw := mustRead(t, remoteAlphaTLSIncidentContractPath)
	const heading, fence = "## Normative incident record", "\x60\x60\x60"
	requireRemoteAlphaTLS(t, strings.Count(raw, heading) == 1, "expected exactly one normative incident record heading")
	section := markedDocSection(t, "normative incident record", raw, heading, "## One-Time State Transitions")
	requireRemoteAlphaTLS(t, strings.Count(section, fence+"json\n") == 1 && strings.Count(section, fence) == 2, "normative incident record must contain exactly one fenced JSON object")
	jsonTail := section[strings.Index(section, fence+"json\n")+len(fence+"json\n"):]
	jsonEnd := strings.Index(jsonTail, "\n"+fence)
	requireRemoteAlphaTLS(t, jsonEnd >= 0, "normative incident record closing fence not found")
	return []byte(jsonTail[:jsonEnd]), raw
}
func remoteAlphaTLSIncidentRecord(t *testing.T) (*remoteAlphaTLSIncident, string) {
	t.Helper()
	jsonRecord, raw := remoteAlphaTLSIncidentJSON(t)
	record, err := decodeRemoteAlphaTLSIncidentJSON(jsonRecord)
	requireRemoteAlphaTLS(t, err == nil, "validate normative incident record: %v", err)
	return record, raw
}
func remoteAlphaTLSIncidentReplaceOnce(t *testing.T, raw []byte, old, replacement string) []byte {
	t.Helper()
	count := bytes.Count(raw, []byte(old))
	requireRemoteAlphaTLS(t, count == 1, "mutation anchor count = %d, want 1", count)
	return bytes.Replace(raw, []byte(old), []byte(replacement), 1)
}
func remoteAlphaTLSIncidentDiagnostic(t *testing.T, raw []byte, classification, path string) string {
	t.Helper()
	err := validateRemoteAlphaTLSIncidentJSON(raw)
	requireRemoteAlphaTLS(t, err != nil, "expected %s at %s", classification, path)
	diagnostic := err.Error()
	requireRemoteAlphaTLS(t, len(diagnostic) <= 160 && !strings.ContainsAny(diagnostic, "\r\n"), "validation diagnostic is not bounded to one line")
	requireRemoteAlphaTLS(t, diagnostic == classification+" path="+path, "validation diagnostic classification or path mismatch")
	return diagnostic
}

type remoteAlphaTLSMutation struct{ name, old, replacement, classification, path string }

func remoteAlphaTLSRunMutations(t *testing.T, raw []byte, cases []remoteAlphaTLSMutation) {
	t.Helper()
	err := validateRemoteAlphaTLSIncidentJSON(raw)
	requireRemoteAlphaTLS(t, err == nil, "canonical incident record: %v", err)
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			mutated := remoteAlphaTLSIncidentReplaceOnce(t, raw, c.old, c.replacement)
			diagnostic := remoteAlphaTLSIncidentDiagnostic(t, mutated, c.classification, c.path)
			requireRemoteAlphaTLS(t, remoteAlphaTLSIncidentDiagnostic(t, mutated, c.classification, c.path) == diagnostic, "validation diagnostic is nondeterministic")
		})
	}
}

func remoteAlphaTLSCaseAlias(name string) string {
	alias := []byte(name)
	for index, value := range alias {
		if value >= 'a' && value <= 'z' {
			alias[index] = value - ('a' - 'A')
			return string(alias)
		}
	}
	return ""
}

func TestRemoteAlphaExternalTLSIncidentCanonicalMemberNamesAreExact(t *testing.T) {
	raw, _ := remoteAlphaTLSIncidentJSON(t)
	requireRemoteAlphaTLS(t, len(remoteAlphaTLSCanonicalMemberNames) == 112, "canonical member vocabulary size changed")
	requireRemoteAlphaTLS(t, remoteAlphaTLSJSONPreflight(raw) == nil, "canonical record contains a decoded member outside the vocabulary")
	for index, name := range remoteAlphaTLSCanonicalMemberNames {
		requireRemoteAlphaTLS(t, bytes.Contains(raw, []byte(`"`+name+`":`)), "canonical vocabulary member %q is absent from the record", name)
		for _, other := range remoteAlphaTLSCanonicalMemberNames[index+1:] {
			requireRemoteAlphaTLS(t, !strings.EqualFold(name, other), "canonical member names %q and %q have a case-fold collision", name, other)
		}
		alias := remoteAlphaTLSCaseAlias(name)
		requireRemoteAlphaTLS(t, alias != "" && alias != name && strings.EqualFold(alias, name), "canonical member %q has no deterministic case alias", name)
		mutated := bytes.Replace(raw, []byte(`"`+name+`":`), []byte(`"`+alias+`":`), 1)
		diagnostic := remoteAlphaTLSIncidentDiagnostic(t, mutated, "unknown_json_key", "$")
		requireRemoteAlphaTLS(t, remoteAlphaTLSIncidentDiagnostic(t, mutated, "unknown_json_key", "$") == diagnostic, "case-alias diagnostic is nondeterministic")
	}
}

func TestRemoteAlphaExternalTLSIncidentStrictJSONRejectsDuplicateMembers(t *testing.T) {
	raw, _ := remoteAlphaTLSIncidentJSON(t)
	top, auth, profile := "  \"record_kind\": \""+remoteAlphaTLSIncidentRecordKind+"\",", "    \"initial_state\": \"AUTHORIZED_NOT_CONSUMED\",", "    \"owner\": \"infrastructure_manager\","
	remoteAlphaTLSRunMutations(t, raw, []remoteAlphaTLSMutation{
		{"top same", top, top + "\n" + top, "duplicate_json_key", "$"}, {"top conflict", top, top + "\n  \"record_kind\": \"conflict\",", "duplicate_json_key", "$"},
		{"nested same", auth, auth + "\n" + auth, "duplicate_json_key", "$"}, {"nested conflict", auth, auth + "\n    \"initial_state\": \"conflict\",", "duplicate_json_key", "$"},
		{"handoff same", profile, profile + "\n" + profile, "duplicate_json_key", "$"}, {"handoff conflict", profile, profile + "\n    \"owner\": \"conflict\",", "duplicate_json_key", "$"},
		{"Unicode-equivalent", profile, profile + "\n    \"\\u006fwner\": \"execution_substrate\",", "duplicate_json_key", "$"},
	})
}

func TestRemoteAlphaExternalTLSIncidentStrictJSONRejectsCaseFoldAliases(t *testing.T) {
	raw, _ := remoteAlphaTLSIncidentJSON(t)
	top, hosts := "  \"record_kind\": \""+remoteAlphaTLSIncidentRecordKind+"\",", "    \"hosts\": 1,"
	remoteAlphaTLSRunMutations(t, raw, []remoteAlphaTLSMutation{
		{"top alias only", top, "  \"RECORD_KIND\": \"" + remoteAlphaTLSIncidentRecordKind + "\",", "unknown_json_key", "$"},
		{"top same alias", top, top + "\n  \"RECORD_KIND\": \"" + remoteAlphaTLSIncidentRecordKind + "\",", "unknown_json_key", "$"},
		{"top conflicting alias", top, top + "\n  \"RECORD_KIND\": \"conflict\",", "unknown_json_key", "$"},
		{"nested alias only", hosts, "    \"HOSTS\": 1,", "unknown_json_key", "$"},
		{"nested same alias", hosts, hosts + "\n    \"HOSTS\": 1,", "unknown_json_key", "$"},
		{"invalid canonical then alias", hosts, "    \"hosts\": 999,\n    \"HOSTS\": 1,", "unknown_json_key", "$"},
		{"alias then invalid canonical", hosts, "    \"HOSTS\": 1,\n    \"hosts\": 999,", "unknown_json_key", "$"},
		{"Unicode case alias", hosts, "    \"\\u0048OSTS\": 1,", "unknown_json_key", "$"},
	})
}

func TestRemoteAlphaExternalTLSIncidentStrictJSONRejectsUnknownNestedMembers(t *testing.T) {
	raw, _ := remoteAlphaTLSIncidentJSON(t)
	for _, object := range []string{"scope", "authorization", "topology", "identities", "cryptography", "custody", "preflight", "cutover", "acceptance", "profile_handoff", "sunset", "non_goals"} {
		mutated := remoteAlphaTLSIncidentReplaceOnce(t, raw, "  \""+object+"\": {\n", "  \""+object+"\": {\n    \"unexpected_member\": false,\n")
		remoteAlphaTLSIncidentDiagnostic(t, mutated, "unknown_json_key", "$")
	}
}

func TestRemoteAlphaExternalTLSIncidentStrictJSONRejectsMissingNestedMembers(t *testing.T) {
	raw, _ := remoteAlphaTLSIncidentJSON(t)
	remoteAlphaTLSRunMutations(t, raw, []remoteAlphaTLSMutation{
		{"scope", "    \"hosts\": 1,\n", "", "unexpected_json_value", "$.scope.hosts"}, {"authorization", "    \"initial_state\": \"AUTHORIZED_NOT_CONSUMED\",\n", "", "unexpected_json_value", "$.authorization"},
		{"topology", "    \"fresh_keypairs\": 6,\n", "", "unexpected_json_value", "$.topology.fresh_keypairs"}, {"identities", "    \"control_plane_uri\": \"spiffe://execution.internal/service/control-plane\",\n", "", "unexpected_json_value", "$.identities"},
		{"cryptography", "    \"key_algorithm\": \"RSA-3072\",\n", "", "unexpected_json_value", "$.cryptography"}, {"custody", "    \"ca_keys_human_custodied_on_mac\": true,\n", "", "unexpected_json_value", "$.custody"},
		{"preflight", "    \"live_inventory_required\": true,\n", "", "unexpected_json_value", "$.preflight"}, {"cutover", "    \"complete_candidate_validation_required\": true,\n", "", "unexpected_json_value", "$.cutover"},
		{"acceptance", "    \"owner\": \"execution_substrate\",\n", "", "unexpected_json_value", "$.acceptance"}, {"handoff", "    \"owner\": \"infrastructure_manager\",\n", "", "unexpected_json_value", "$.profile_handoff"},
		{"sunset", "    \"default_disposition\": \"RETIRE_BEFORE_LEAF_EXPIRY\",\n", "", "unexpected_json_value", "$.sunset"}, {"non-goals", "    \"reusable_recovery_route\": true,\n", "", "unexpected_json_value", "$.non_goals"},
	})
}

func TestRemoteAlphaExternalTLSIncidentStrictJSONRejectsTypeMalformedAndTrailingDefects(t *testing.T) {
	raw, _ := remoteAlphaTLSIncidentJSON(t)
	scope := "  \"scope\": {\n    \"hosts\": 1,\n    \"incidents\": 1,\n    \"executions\": 1\n  }"
	binding := "    \"pre_effect_binding\": [\n      \"incident_id\",\n      \"physical_host\",\n      \"es_contract_commit\",\n      \"es_contract_tree\",\n      \"private_plan_sha256\",\n      \"incident_packet_sha256\",\n      \"rollback_packet_sha256\"\n    ]"
	remoteAlphaTLSRunMutations(t, raw, []remoteAlphaTLSMutation{
		{"object/list", scope, "  \"scope\": []", "json_type_mismatch", "$"}, {"list/object", binding, "    \"pre_effect_binding\": {}", "json_type_mismatch", "$"},
		{"scalar/list", "    \"hosts\": 1,", "    \"hosts\": [],", "json_type_mismatch", "$"}, {"list element", "      \"incident_id\",", "      false,", "json_type_mismatch", "$"},
		{"boolean/string", "    \"es_authorizes_profile_mutation\": false,", "    \"es_authorizes_profile_mutation\": \"false\",", "json_type_mismatch", "$"},
		{"null", "    \"hosts\": 1,", "    \"hosts\": null,", "unexpected_json_value", "$.scope.hosts"},
		{"bad escape", "  \"record_kind\": \"" + remoteAlphaTLSIncidentRecordKind + "\",", "  \"record_kind\": \"bad\\q\",", "malformed_json", "$"},
		{"bad number", "    \"hosts\": 1,", "    \"hosts\": 01,", "malformed_json", "$"},
	})
	remoteAlphaTLSIncidentDiagnostic(t, raw[:len(raw)-1], "malformed_json", "$")
	remoteAlphaTLSIncidentDiagnostic(t, append(slices.Clone(raw), []byte("\n{}")...), "trailing_json_content", "$")
	remoteAlphaTLSIncidentDiagnostic(t, []byte("[]"), "json_type_mismatch", "$")
}

func TestRemoteAlphaExternalTLSIncidentExactNumericAndDiagnosticBounds(t *testing.T) {
	raw, _ := remoteAlphaTLSIncidentJSON(t)
	remoteAlphaTLSRunMutations(t, raw, []remoteAlphaTLSMutation{
		{"near hosts", "\"hosts\": 1", "\"hosts\": 1.0000000000000000000000000000000001", "unexpected_json_value", "$.scope.hosts"},
		{"near incidents", "\"incidents\": 1", "\"incidents\": 1.0000000000000000000000000000000001", "unexpected_json_value", "$.scope.incidents"},
		{"near executions", "\"executions\": 1", "\"executions\": 1.0000000000000000000000000000000001", "unexpected_json_value", "$.scope.executions"},
		{"near keypairs", "\"fresh_keypairs\": 6", "\"fresh_keypairs\": 6.0000000000000000000000000000000001", "unexpected_json_value", "$.topology.fresh_keypairs"},
		{"near URI count", "\"client_uri_count_per_leaf\": 1", "\"client_uri_count_per_leaf\": 1.0000000000000000000000000000000001", "unexpected_json_value", "$.identities.client_uri_count_per_leaf"},
		{"near leaf days", "\"leaf_maximum_days\": 365", "\"leaf_maximum_days\": 365.0000000000000000000000000000000001", "unexpected_json_value", "$.cryptography.leaf_maximum_days"},
		{"near path length", "\"ca_path_length\": 0", "\"ca_path_length\": 0.0000000000000000000000000000000001", "unexpected_json_value", "$.cryptography.ca_path_length"},
		{"decimal", "\"hosts\": 1", "\"hosts\": 1.0", "unexpected_json_value", "$.scope.hosts"}, {"exponent", "\"hosts\": 1", "\"hosts\": 1e0", "unexpected_json_value", "$.scope.hosts"},
		{"negative", "\"hosts\": 1", "\"hosts\": -1", "unexpected_json_value", "$.scope.hosts"}, {"oversized", "\"hosts\": 1", "\"hosts\": 999999999999999999999999999999999999", "unexpected_json_value", "$.scope.hosts"},
	})
	sentinel := "SYNTHETIC_REJECTED_VALUE_SENTINEL_4D761B6C"
	sentinelRaw := remoteAlphaTLSIncidentReplaceOnce(t, raw, remoteAlphaTLSIncidentRecordKind, sentinel)
	diagnostic := remoteAlphaTLSIncidentDiagnostic(t, sentinelRaw, "unexpected_json_value", "$")
	requireRemoteAlphaTLS(t, !strings.Contains(diagnostic, sentinel), "diagnostic exposed candidate sentinel")
	for range 20 {
		requireRemoteAlphaTLS(t, remoteAlphaTLSIncidentDiagnostic(t, sentinelRaw, "unexpected_json_value", "$") == diagnostic, "diagnostic is nondeterministic")
	}
	arrayRaw := remoteAlphaTLSIncidentReplaceOnce(t, raw, "    \"pre_effect_binding\": [\n", "    \"pre_effect_binding\": [\n"+strings.Repeat("      \"LIST_SENTINEL\",\n", 200))
	diagnostic = remoteAlphaTLSIncidentDiagnostic(t, arrayRaw, "json_limit_exceeded", "$")
	requireRemoteAlphaTLS(t, !strings.Contains(diagnostic, "LIST_SENTINEL"), "diagnostic exposed candidate list")
	oversized := append(slices.Clone(raw), bytes.Repeat([]byte(" "), remoteAlphaTLSMaxRecordBytes-len(raw)+1)...)
	remoteAlphaTLSIncidentDiagnostic(t, oversized, "json_limit_exceeded", "$")
	nested := remoteAlphaTLSIncidentReplaceOnce(t, raw, "\"record_kind\": \""+remoteAlphaTLSIncidentRecordKind+"\"", "\"record_kind\": [[[[[[[[[\"x\"]]]]]]]]]")
	remoteAlphaTLSIncidentDiagnostic(t, nested, "json_limit_exceeded", "$")
	var members strings.Builder
	memberCount := 0
	for _, name := range remoteAlphaTLSCanonicalMemberNames {
		if name == "hosts" || name == "incidents" || name == "executions" {
			continue
		}
		fmt.Fprintf(&members, "    %q: false,\n", name)
		memberCount++
		if memberCount > remoteAlphaTLSMaxObjectMembers {
			break
		}
	}
	remoteAlphaTLSIncidentDiagnostic(t, remoteAlphaTLSIncidentReplaceOnce(t, raw, "  \"scope\": {\n", "  \"scope\": {\n"+members.String()), "json_limit_exceeded", "$")
	longName := strings.Repeat("n", remoteAlphaTLSMaxMemberBytes+1)
	remoteAlphaTLSIncidentDiagnostic(t, remoteAlphaTLSIncidentReplaceOnce(t, raw, "  \"scope\": {\n", "  \"scope\": {\n    \""+longName+"\": false,\n"), "json_limit_exceeded", "$")
	longString := strings.Repeat("s", remoteAlphaTLSMaxStringBytes+1)
	remoteAlphaTLSIncidentDiagnostic(t, remoteAlphaTLSIncidentReplaceOnce(t, raw, remoteAlphaTLSIncidentRecordKind, longString), "json_limit_exceeded", "$")
}

func TestRemoteAlphaExternalTLSIncidentNumericTokenKinds(t *testing.T) {
	raw, _ := remoteAlphaTLSIncidentJSON(t)
	requireRemoteAlphaTLS(t, validateRemoteAlphaTLSIncidentJSON(raw) == nil, "canonical numeric record must be accepted")
	requireRemoteAlphaTLS(t, fmt.Sprintf("%x", sha256.Sum256(raw)) == "0ca3c1d42d0886b93f9e3740f59723738a1f80c1cec704c0e9dc16c11260dcdd", "canonical fixture identity changed")
	requireRemoteAlphaTLS(t, bytes.Contains(raw, []byte(`"minimum_tls": "1.2"`)), "legitimate string-valued minimum_tls changed")

	fields := []struct {
		path, key, number, quotedSHA256 string
		last                            bool
	}{
		{"$.scope.hosts", "hosts", "1", "1fdb0c57ceb8571b53052c9f95d65ee12200213c8a42361541eb0e2547c11d55", false},
		{"$.scope.incidents", "incidents", "1", "6d83205c6c7c261a67745f9562cdf2eaa381ca66688dc326e9d610beaca71a55", false},
		{"$.scope.executions", "executions", "1", "981bacd7480c23a3a162136f35a3bac7366a6803b29f8be88fb5c0f404ace013", true},
		{"$.topology.fresh_keypairs", "fresh_keypairs", "6", "87af5f83ac0354021efead68c1cf5cc73d7c6792e0cfe93254b8ac4a65be9253", false},
		{"$.identities.client_uri_count_per_leaf", "client_uri_count_per_leaf", "1", "5c961209ea078b3b557befdab12fd0eb129ce18341087fed6c8176ed73efc55d", false},
		{"$.cryptography.leaf_maximum_days", "leaf_maximum_days", "365", "a8b8220d24031cef96513c0a2349e89b79f0b73af712def0abe28c7749b98934", false},
		{"$.cryptography.ca_path_length", "ca_path_length", "0", "0f02062cb166007aeac3907bd9cb91591447f606a0bc13bdbc17d393f90f09f5", false},
	}
	mutate := func(t *testing.T, old, replacement string) []byte {
		t.Helper()
		oldBytes, newBytes := []byte(old), []byte(replacement)
		requireRemoteAlphaTLS(t, bytes.Count(raw, oldBytes) == 1, "numeric mutation anchor %q must occur once", old)
		index := bytes.Index(raw, oldBytes)
		candidate := remoteAlphaTLSIncidentReplaceOnce(t, raw, old, replacement)
		requireRemoteAlphaTLS(t, bytes.Equal(candidate[:index], raw[:index]) && bytes.Equal(candidate[index+len(newBytes):], raw[index+len(oldBytes):]), "numeric mutation changed unrelated bytes")
		requireRemoteAlphaTLS(t, json.Valid(candidate), "numeric-kind specimen is malformed JSON")
		return candidate
	}
	for _, field := range fields {
		t.Run(field.key, func(t *testing.T) {
			old := fmt.Sprintf("%q: %s", field.key, field.number)
			quoted := fmt.Sprintf("%q: %q", field.key, field.number)
			t.Run("quoted", func(t *testing.T) {
				candidate := mutate(t, old, quoted)
				requireRemoteAlphaTLS(t, fmt.Sprintf("%x", sha256.Sum256(candidate)) == field.quotedSHA256, "supplied quoted specimen identity mismatch")
				first := remoteAlphaTLSIncidentDiagnostic(t, candidate, "json_type_mismatch", "$")
				requireRemoteAlphaTLS(t, remoteAlphaTLSIncidentDiagnostic(t, candidate, "json_type_mismatch", "$") == first, "quoted diagnostic changed")
			})
			t.Run("restored_matching_number", func(t *testing.T) {
				quotedCandidate := mutate(t, old, quoted)
				restored := bytes.Replace(quotedCandidate, []byte(quoted), []byte(old), 1)
				requireRemoteAlphaTLS(t, bytes.Equal(restored, raw), "matching numeric token did not restore canonical bytes")
				requireRemoteAlphaTLS(t, validateRemoteAlphaTLSIncidentJSON(restored) == nil, "matching numeric token must be accepted")
			})
			for _, variant := range []struct {
				name, value, class, path string
			}{
				{"boolean", "true", "json_type_mismatch", "$"},
				{"null", "null", "unexpected_json_value", field.path},
				{"object", "{}", "json_type_mismatch", "$"},
				{"array", "[]", "json_type_mismatch", "$"},
			} {
				t.Run(variant.name, func(t *testing.T) {
					candidate := mutate(t, old, fmt.Sprintf("%q: %s", field.key, variant.value))
					first := remoteAlphaTLSIncidentDiagnostic(t, candidate, variant.class, variant.path)
					requireRemoteAlphaTLS(t, remoteAlphaTLSIncidentDiagnostic(t, candidate, variant.class, variant.path) == first, "numeric-kind diagnostic changed")
				})
			}
			t.Run("omitted", func(t *testing.T) {
				member := fmt.Sprintf("    %q: %s,\n", field.key, field.number)
				if field.last {
					member = fmt.Sprintf(",\n    %q: %s", field.key, field.number)
				}
				candidate := mutate(t, member, "")
				first := remoteAlphaTLSIncidentDiagnostic(t, candidate, "unexpected_json_value", field.path)
				requireRemoteAlphaTLS(t, remoteAlphaTLSIncidentDiagnostic(t, candidate, "unexpected_json_value", field.path) == first, "omission diagnostic changed")
			})
		})
	}
	t.Run("escaped_digit_string", func(t *testing.T) {
		candidate := mutate(t, `"hosts": 1`, `"hosts": "\u0031"`)
		requireRemoteAlphaTLS(t, fmt.Sprintf("%x", sha256.Sum256(candidate)) == "f1c1f361a7221b26576f97be70a9bd703085f05bf9446490749ea03deff1b750", "supplied escaped-digit specimen identity mismatch")
		first := remoteAlphaTLSIncidentDiagnostic(t, candidate, "json_type_mismatch", "$")
		requireRemoteAlphaTLS(t, remoteAlphaTLSIncidentDiagnostic(t, candidate, "json_type_mismatch", "$") == first, "escaped-digit diagnostic changed")
	})
}

func TestRemoteAlphaExternalTLSIncidentNumericTokenKindContract(t *testing.T) {
	jsonRecord, doc := remoteAlphaTLSIncidentJSON(t)
	requireRemoteAlphaTLS(t, fmt.Sprintf("%x", sha256.Sum256(jsonRecord)) == "0ca3c1d42d0886b93f9e3740f59723738a1f80c1cec704c0e9dc16c11260dcdd", "normative JSON changed")
	section := markedDocSection(t, "numeric token-kind rule", doc, "## Normative incident record", "## One-Time State Transitions")
	assertContainsAll(t, "numeric token-kind contract", compactText(section),
		"The seven numeric members require JSON number tokens with exactly these integer spellings:",
		"`$.scope.hosts=1`", "`$.scope.incidents=1`", "`$.scope.executions=1`",
		"`$.topology.fresh_keypairs=6`", "`$.identities.client_uri_count_per_leaf=1`",
		"`$.cryptography.leaf_maximum_days=365`", "`$.cryptography.ca_path_length=0`",
		"Quoted equivalents, escape-encoded digit strings, booleans, nulls, objects, arrays, absent members, and decimal or exponent alternatives are invalid at those positions.",
		"This rule does not change string-valued fields such as `minimum_tls`.",
	)
}

func TestRemoteAlphaExternalTLSIncidentProfileHandoffAuthority(t *testing.T) {
	raw, _ := remoteAlphaTLSIncidentJSON(t)
	remoteAlphaTLSRunMutations(t, raw, []remoteAlphaTLSMutation{
		{"replacement consuming", "      \"active_tls_installation\",\n      \"service_restart\"", "      \"active_tls_installation\",\n      \"service_restart\",\n      \"mac_profile_replacement\"", "unexpected_json_value", "$.authorization"},
		{"owner", "    \"owner\": \"infrastructure_manager\",", "    \"owner\": \"execution_substrate\",", "unexpected_json_value", "$.profile_handoff"},
		{"ES mutation", "    \"es_authorizes_profile_mutation\": false,", "    \"es_authorizes_profile_mutation\": true,", "unexpected_json_value", "$.profile_handoff"},
		{"separate contract", "    \"separate_committed_im_contract_required\": true,", "    \"separate_committed_im_contract_required\": false,", "unexpected_json_value", "$.profile_handoff"},
		{"IM binding", "    \"im_contract_commit_and_tree_bound_before_first_es_effect_when_handoff_required\": true,", "    \"im_contract_commit_and_tree_bound_before_first_es_effect_when_handoff_required\": false,", "unexpected_json_value", "$.profile_handoff"},
		{"post-acceptance", "    \"profile_replacement_occurs_only_after_es_acceptance\": true,", "    \"profile_replacement_occurs_only_after_es_acceptance\": false,", "unexpected_json_value", "$.profile_handoff"},
		{"ES consumption", "    \"profile_replacement_is_es_consuming_effect\": false,", "    \"profile_replacement_is_es_consuming_effect\": true,", "unexpected_json_value", "$.profile_handoff"},
		{"failure state", "    \"profile_handoff_failure_state\": \"CONSUMED_OPEN_INCIDENT\",", "    \"profile_handoff_failure_state\": \"CONSUMED_AND_CLOSED\",", "unexpected_json_value", "$.profile_handoff"},
		{"revokes acceptance", "    \"profile_handoff_failure_revokes_es_acceptance\": false,", "    \"profile_handoff_failure_revokes_es_acceptance\": true,", "unexpected_json_value", "$.profile_handoff"},
		{"automatic rollback", "    \"profile_handoff_failure_triggers_automatic_host_tls_rollback\": false,", "    \"profile_handoff_failure_triggers_automatic_host_tls_rollback\": true,", "unexpected_json_value", "$.profile_handoff"},
		{"terminal closure", "    \"terminal_closeout_requires_handoff_or_explicit_retirement\": true", "    \"terminal_closeout_requires_handoff_or_explicit_retirement\": false", "unexpected_json_value", "$.profile_handoff"},
	})
}

func TestRemoteAlphaExternalTLSOneTimeIncidentContract(t *testing.T) {
	_, raw := remoteAlphaTLSIncidentRecord(t)
	assertContainsAll(t, "incident authority", compactText(raw), "If explanatory prose is ambiguous, this record governs.", "Unknown or duplicated normative members are invalid.", "Report-derived operational evidence", "no non-mutating application operation", "does not claim the prior state is healthy, current, expired, or usable", "ES does not authorize IM profile mutation", "exact committed and independently audited IM contract commit and tree before any ES effect", "Only after ES acceptance may IM replace or emit the runnable profile", "does not revoke ES acceptance or automatically roll back the accepted host TLS set", "successful separately authorized IM handoff or explicit retirement and closure without a runnable CP profile")
	assertContainsNone(t, "incident overlay independence", raw, "operator-facade cutoff", "retired evidence-adapter", "retired writable-state", "retired service-user", "reliable-submit tranche", "Because the prior certificates are expired")
}

func TestRemoteAlphaExternalTLSOneTimeIncidentClosureAndSunset(t *testing.T) {
	const canonical = ".docs/system_overview/remote_alpha_external_tls_one_time_incident_contract.md"
	for _, path := range []string{".docs/remote_alpha_operator_healthcheck_tls_operator_authorized_replacement.md", ".docs/remote_alpha_operator_healthcheck_tls_signing_custody.md", ".docs/remote_alpha_operator_healthcheck_tls_signing_custody_resolution.md", ".docs/remote_alpha_operator_healthcheck_tls_signing_custody_decision.md"} {
		doc := mustRead(t, path)
		requireRemoteAlphaTLS(t, strings.Count(doc, canonical) == 1, "%s must reference the canonical incident contract exactly once", path)
		assertContainsAll(t, "P0u alignment "+path, compactText(doc), "no-signer/no-replacement conclusion here continues to govern reusable P0u", "does not unblock or widen P0u", "provides no reusable signer or route", "unsupported_signing_topology")
		assertContainsNone(t, "P0u removed alignment "+path, doc, "Single-use scope clarification:", "ES has separately authorized one single-use complete external-family incident", "incident unblocks P0u", "provides a reusable signer or route")
	}
	replacement := compactText(mustRead(t, ".docs/remote_alpha_operator_healthcheck_tls_operator_authorized_replacement.md"))
	assertContainsAll(t, "IM handoff ownership", replacement, "does not authorize IM profile mutation", "exact committed and independently audited IM contract commit and tree before the first ES incident effect", "Profile replacement follows ES acceptance", "runs only under that separate IM contract", "Handoff failure leaves the ES incident \x60CONSUMED_OPEN_INCIDENT\x60", "neither revokes ES acceptance nor automatically rolls back the accepted host TLS set")
	rules := markedDocSection(t, "route rules incident", mustRead(t, standingRouteRulesPath), "The Remote Alpha external TLS single-use incident is a \x60Bounded slice rule\x60", "The Remote Alpha maintenance-monitor contract alignment slice")
	overview := markedDocSection(t, "overview incident", mustRead(t, ".docs/system_overview/remote_supported_host_alpha.md"), "### External TLS Single-Use Incident Authorization", "### P0v Operator Healthcheck TLS Noninteractive Status Implementation")
	assertContainsAll(t, "compact incident cross-references", compactText(rules+"\n"+overview), "Report-derived", "read-only inventory", "adds no executable route", "P0u renewal remains blocked", "remove or convert")
	assertContainsNone(t, "cross-reference overlay independence", rules+overview, "operator-facade cutoff", "retired evidence-adapter", "retired writable-state", "retired service-user", "blocked by expired material")
	operatorSource := mustRead(t, remoteAlphaOperatorScriptPath())
	renewUsage := docSection(t, operatorSource, "recovery_session_operator_healthcheck_tls_usage() {", "\nrecovery_session() {")
	assertContainsAll(t, "existing P0u source boundary", renewUsage, "operator-healthcheck-tls-renew", "unsupported_signing_topology")
	for lineNumber, line := range strings.Split(operatorSource, "\n") {
		lower := strings.ToLower(line)
		namesRoute := strings.Contains(lower, "external") && strings.Contains(lower, "tls") && (strings.Contains(lower, "incident") || strings.Contains(lower, "single-use"))
		requireRemoteAlphaTLS(t, !namesRoute, "operator source names a single-use external TLS route at line %d", lineNumber+1)
	}
	for _, root := range []string{"ags", "ars", "cgs", "cmd", "egs", "es", "internal", "scripts"} {
		err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
			if walkErr != nil || entry.IsDir() || strings.HasSuffix(path, "_test.go") || (!strings.HasSuffix(path, ".go") && !strings.HasSuffix(path, ".sh")) {
				return walkErr
			}
			source := mustRead(t, path)
			requireRemoteAlphaTLS(t, !strings.Contains(source, remoteAlphaTLSIncidentRecordKind) && !strings.Contains(source, canonical), "production source %s must not consume the documentation-only incident contract", path)
			return nil
		})
		requireRemoteAlphaTLS(t, err == nil, "walk production source %s: %v", root, err)
	}
	record, _ := remoteAlphaTLSIncidentRecord(t)
	requireRemoteAlphaTLS(t, record.Sunset.Active_authorization_docs_and_tests_removed_or_converted_on_terminal_closure.is(true), "terminal closure must remove or convert active incident docs and tests")
}
func TestRemoteAlphaMaintenanceMonitorBoundaryAndRouteMatrix(t *testing.T) {
	access := standingRuleSection(t, standingRouteRulesPath, remoteAlphaAccessHeading)
	remoteRaw := mustRead(t, ".docs/system_overview/remote_supported_host_alpha.md")
	monitorSection := compactDocSection(t, remoteRaw, "### Remote Alpha Maintenance Monitor Boundary", "### Historical P0d interactive validation evidence — superseded and non-authoritative")
	monitor := compactText(monitorSection)
	artifact := compactText(mustRead(t, ".docs/system_overview/artifact_hygiene.md"))

	assertContainsAll(t, "Remote Alpha maintenance monitor access contract standing rules boundary", access,
		"maintenance-monitor contract alignment slice is docs/static contract work only",
		"ES keeps ownership of every Remote Alpha status, renewal, repair, and route-contract semantic",
		"External schedulers may invoke only documented allowlisted ES commands",
		"Remote Alpha remains bounded proof/support posture only",
		"`operator-healthcheck-tls-renew` remains blocked/status-only until a signing topology and operator/local identity renewal authority are documented",
	)

	assertContainsAll(t, "Remote Alpha maintenance monitor docs boundary", monitor,
		"documentation/contract alignment only",
		"future Mac-side Remote Alpha maintenance project may exist only as scheduler, notifier, local-evidence summarizer, and allowlisted invoker of ES-owned commands",
		"ES remains the owner of all Remote Alpha status, renewal, repair, helper routing, topology validation, mutation semantics, and route contracts",
		"External schedulers may invoke documented allowlisted ES commands, but they may not define command semantics",
		"hidden remote reconciler",
		"broad provisioning automation",
		"Remote Alpha remains bounded proof/support posture only",
		"`es-service-tls-status` | future candidate; no current monitor",
		"`es-service-tls-renew` | held",
		"`es-governance-tls-status` | future candidate; no current monitor",
		"`es-governance-tls-renew` | held",
		"`operator-healthcheck-tls-status` | eligible",
		"`operator-healthcheck-tls-renew` | blocked/status-only | not eligible | blocked",
		"`spiffe://execution.internal/operator/local`",
		"binary deployment check | eligible",
		"binary deployment apply | evidence may be summarized after an operator-run helper | not eligible through a monitor | not eligible",
		"workload-auth check | eligible",
		"workload-auth bootstrap | evidence may be summarized after an operator-run helper | not eligible through a monitor | not eligible",
		"runtime identity summary | eligible",
		"Automatic renewal eligibility requires all of the following before a route can be marked eligible: route-specific docs, route-specific tests, audit evidence, idempotence, backup-before-replace, post-renew verification, fail-closed topology and capability behavior, explicit no-secret monitor-controlled surfaces",
	)

	assertContainsAll(t, "Remote Alpha maintenance monitor artifact hygiene", artifact,
		"Future Mac-side Remote Alpha maintenance-monitor summaries, if introduced by a separate project later, are local evidence/projection only.",
		"They must not become ES renewal semantics, IM readiness authority, CP run-control authority, production readiness, or deployment/reconciliation truth.",
		"They must never record private keys, token values, secret environment values, raw PEM bodies",
	)
}

func TestDocsRemoteAlphaOperatorP0cIsHistoricalRetiredContext(t *testing.T) {
	plans := compactText(mustRead(t, "PLANS.md"))
	remoteRaw := mustRead(t, ".docs/system_overview/remote_supported_host_alpha.md")
	operatorSection := compactDocSection(t, remoteRaw, "### Historical P0c Staged-Helper Delegation Plan — Retired", "### Historical P0d Staged-Helper Delegation Implementation — Retired")

	assertContainsAll(t, "Remote Alpha P0c retirement plan", plans,
		"P0c, P0d, and P0f are now retired compatibility history",
		"no longer inspect or contact a host and no longer produce or refresh evidence",
		"fixed exit-2 tombstones",
	)
	assertContainsAll(t, "Remote Alpha P0c historical docs boundary", operatorSection,
		"historical design context only",
		"does not authorize a current route, helper execution, readiness claim, staging action, or evidence refresh",
		"selected in that historical plan",
	)
}
func TestRemoteSupportedHostAlphaDoctorVocabularyIsDocumented(t *testing.T) {
	remote := compactText(mustRead(t, ".docs/system_overview/remote_supported_host_alpha.md"))

	for _, required := range []string{
		"Doctor And Support-Bundle Vocabulary",
		"`remote_host_reachable`",
		"`docker_ready`",
		"`nomad_ready`",
		"`runtime_profile_ready`",
		"`es_services_healthy`",
		"`cert_trust_ok`",
		"`producer_contract_compatible`",
		"`ags_publish_probe`",
		"`es_prepare_probe`",
		"`submit_ready`",
		"`retained_result_fetch`",
		"`cp_profile_usable`",
		"operator diagnostics, readiness-report inputs, and support-bundle provenance",
		"not ES core lifecycle contracts",
		"not Control Plane run-control authority",
		"product blocker codes",
		"not surface script numbers, Lima implementation details, bridge ports, proof-harness names, or remote filesystem paths",
	} {
		if !strings.Contains(remote, required) {
			t.Fatalf("remote supported-host alpha doc missing doctor vocabulary phrase %q", required)
		}
	}
}

func TestRemoteSupportedHostAlphaSupportBundleSummarySectionsAreDocumented(t *testing.T) {
	remote := compactText(mustRead(t, ".docs/system_overview/remote_supported_host_alpha.md"))

	for _, required := range []string{
		"Support-Bundle Summary Sections",
		"`evidence/execution-substrate/producer-contract-summary.json`",
		"`evidence/execution-substrate/health-readiness-summary.json`",
		"`evidence/execution-substrate/probe-summaries.json`",
		"`execution-substrate.producer-contract-summary.v1`",
		"`execution-substrate.health-readiness-summary.v1`",
		"`execution-substrate.probe-summaries.v1`",
		"bounded summary evidence",
		"AGS publish probe summary",
		"ES prepare, submit, status, and result summaries",
		"Nomad, Docker, Vault, and SPIRE structured status summaries",
		"must not contribute: - raw logs",
		"raw retained-result bundles",
		"do not change ES lifecycle semantics",
		"or the producer declaration boundary",
	} {
		if !strings.Contains(remote, required) {
			t.Fatalf("remote supported-host alpha doc missing support-bundle phrase %q", required)
		}
	}
}

func TestRemoteSupportedHostAlphaVaultWorkloadAuthSummarySchemaIsDocumented(t *testing.T) {
	remote := compactText(mustRead(t, ".docs/system_overview/remote_supported_host_alpha.md"))
	configuration := compactText(mustRead(t, ".docs/system_overview/configuration.md"))

	for _, required := range []string{
		"`execution-substrate.remote-alpha.vault-workload-auth-summary.v1`",
		"`sudo scripts/remote_alpha_vault_workload_auth_check.sh`",
		"optional owner-local host check under its own contract",
		"operator facade does not stage or invoke it and does not ingest, discover, aggregate, or project its summary",
		"bounded host-local audit record",
		"not an ES lifecycle or readiness surface",
		"`vault_workload_auth_smoke`",
		"`host_identity`",
		"`vault.address`",
		"`vault.auth_mount`",
		"`vault.role`",
		"`vault.audience`",
		"`vault.policy_names`",
		"`vault.initialized`",
		"`vault.sealed`",
		"`vault.storage`",
		"`spire.trust_domain`",
		"`spire.socket_path`",
		"`workload.spiffe_id`",
		"`workload.registration_selector_scope`",
		"`workload.registration_alpha_only`",
		"`auth_smoke.jwt_fetch`",
		"`auth_smoke.jwt_issuer_verified`",
		"`auth_smoke.jwt_issuer_expected_source`",
		"`auth_smoke.jwt_issuer_expected_class`",
		"`auth_smoke.jwt_issuer_actual_class`",
		"`auth_smoke.vault_login_failure_alignment_hint`",
		"`auth_smoke.vault_login`",
		"`auth_smoke.vault_login_failure_phase`",
		"`auth_smoke.vault_login_failure_class`",
		"`auth_smoke.vault_login_http_status`",
		"`auth_smoke.vault_login_error_count`",
		"`auth_smoke.vault_login_error_class`",
		"`auth_smoke.vault_login_raw_error_recorded`",
		"`auth_smoke.token_lookup`",
		"`auth_smoke.proof_read`",
		"`auth_smoke.proof_runtime_secret`",
		"`auth_smoke.token_revoked`",
		"`auth_smoke_requirements.token_lookup_required`",
		"`auth_smoke_requirements.proof_read_required`",
		"`auth_smoke_requirements.proof_runtime_secret_required`",
		"`auth_smoke_requirements.token_revoked_required`",
		"`auth_smoke_requirements.proof_read_path`",
		"`auth_smoke_requirements.proof_runtime_secret_path`",
		"`auth_smoke_requirements.proof_runtime_secret_field`",
		"`proof_runtime_secret.status`",
		"`proof_runtime_secret.path`",
		"`proof_runtime_secret.field`",
		"`proof_runtime_secret.field_present`",
		"`proof_runtime_secret.field_nonempty`",
		"`proof_runtime_secret.field_shape`",
		"`proof-secrets/data/runtime-identity-vault-login`",
		"`proof-secrets/data/codex-runtime-profile`",
		"`api_key`",
		"`GET /auth/token/lookup-self`",
		"`security.ds_not_in_docker_group`",
		"`security.passwordless_sudo_for_ds`",
		"`security.raw_spire_socket_access_ds`",
		"`security.raw_spire_socket_access_uid_10000`",
		"`redaction.jwt_persisted`",
		"`redaction.vault_client_token_persisted`",
		"`redaction.root_token_persisted`",
		"`redaction.secret_payload_persisted`",
		"`readiness_not_claimed.runtime_profile_ready`",
		"`readiness_not_claimed.submit_ready`",
		"`readiness_not_claimed.es_services_healthy`",
		"`readiness_not_claimed.producer_contract_compatible`",
		"`readiness_not_claimed.retained_result_fetch`",
		"`https://172.17.0.1:8200/v1/sys/health`",
		"`/etc/execution-substrate/vault/workload-zone-vault-config.json`",
		"`invalid_issuer_or_validation_key`",
		"`issuer_mismatch`",
		"`validation_key_mismatch_or_rotation`",
		"`trust_domains` maps keyed by bare trust-domain labels",
		"`vault_login_raw_error_recorded=false`",
		"do not persist raw Vault error strings, raw Vault response bodies, raw HTTP headers, Authorization headers, stack traces, JWT-SVIDs, Vault tokens, root tokens, unseal keys, proof secret values, API keys, or private keys",
		"must not print or persist JWT-SVIDs, Vault client tokens, root tokens, unseal keys, private keys, or secret payloads",
	} {
		if !strings.Contains(remote, required) && !strings.Contains(configuration, required) {
			t.Fatalf("remote Vault/workload-auth schema docs missing %q", required)
		}
	}
}

func TestRemoteSupportedHostAlphaVaultServiceUserMigrationSurfaceIsDocumented(t *testing.T) {
	plans := compactText(mustRead(t, "PLANS.md"))
	remote := compactText(mustRead(t, ".docs/system_overview/remote_supported_host_alpha.md"))
	configuration := compactText(mustRead(t, ".docs/system_overview/configuration.md"))

	for _, required := range []string{
		"`scripts/remote_alpha_migrate_vault_service_user.sh`",
		"`scripts/internal/remote_alpha_migrate_vault_service_user.sh`",
		"`execution-substrate.remote-alpha.vault-service-user-migration-summary.v1`",
		"`/var/tmp/execution-substrate-remote-alpha/vault-service-user-migration-check-only.json`",
		"`/var/tmp/execution-substrate-remote-alpha/vault-service-user-migration-apply-summary.json`",
		"`check_only`",
		"non-mutating",
		"explicit `--apply`",
		"dedicated Vault service account",
		"current Vault service identity",
		"planned Vault systemd drop-in",
		"local storage path",
		"log path",
		"audit-device path",
		"TLS read paths",
		"backup evidence",
		"rollback notes",
		"Vault `/v1/sys/health`",
		"ES `/health`",
		"ES `GET /v1/executions:contract`",
		"`skipped`, not passed",
		"`EXEC_WORKLOAD_IDENTITY_ENDPOINT`",
		"`es_vault_token_brokerage=false`",
		"`not_vault_production_ready`",
		"`not_governed_execution_proof`",
		"`not_full_es_runtime_deroot`",
		"`not_full_nomad_client_deroot`",
		"`not_spire_redesign`",
		"`sudo -n true`",
		"`collection_status = \"preflight_blocked\"`",
		"`apply_performed = false`",
		"`governed_smoke_performed = false`",
		"`skipped_checks`",
		"`non_authority_labels`",
	} {
		if !strings.Contains(plans, required) && !strings.Contains(remote, required) && !strings.Contains(configuration, required) {
			t.Fatalf("remote Vault service-user migration docs missing %q", required)
		}
	}
}

func TestRemoteSupportedHostAlphaNormalShellRuntimeImageSummarySchemaIsDocumented(t *testing.T) {
	remote := compactText(mustRead(t, ".docs/system_overview/remote_supported_host_alpha.md"))
	configuration := compactText(mustRead(t, ".docs/system_overview/configuration.md"))

	for _, required := range []string{
		"Remote Normal-Shell Runtime Image Slice",
		"`execution-substrate.remote-alpha.normal-shell-runtime-image-summary.v1`",
		"`sudo scripts/remote_alpha_normal_shell_runtime_image_check.sh`",
		"`/var/tmp/execution-substrate-remote-alpha/normal-shell-runtime-image-summary.json`",
		"`execution-substrate/control-plane-normal-shell:supported-local`",
		"`sudo scripts/remote_alpha_build_normal_shell_runtime_image.sh`",
		"`scripts/remote_alpha_build_normal_shell_runtime_image.sh`",
		"`scripts/build_control_plane_normal_shell_image.sh`",
		"`/usr/local/bin/codex`",
		"`CONTROL_PLANE_NORMAL_SHELL_IMAGE=execution-substrate/control-plane-normal-shell:supported-local`",
		"`es/runtimeprofiles/control_plane_normal_shell/Dockerfile`",
		"`CONTROL_PLANE_NORMAL_SHELL_CODEX_CLI_PATH=/usr/local/bin/codex`",
		"`CONTROL_PLANE_NORMAL_SHELL_CODEX_REALIZATION=proof`",
		"`image.ref`",
		"`image.present`",
		"`image.image_id`",
		"`build.expected_recipe_script`",
		"`build.expected_recipe_script_present`",
		"`build.expected_recipe_script_sha256`",
		"`build.build_context_files`",
		"`build.recipe_matches_slice`",
		"`build.codex_realization`",
		"`build.codex_credential_posture`",
		"`build.real_codex_credentials_required_for_build`",
		"`host.docker_service_active`",
		"`host.nomad_ready`",
		"`validation.image_present`",
		"`validation.docker_info_ok`",
		"`validation.minimal_container_run.status`",
		"`validation.codex_realization_expected`",
		"`security.ds_not_in_docker_group`",
		"`security.passwordless_sudo_for_ds`",
		"`security.no_real_codex_credentials_in_build_context`",
		"`security.no_api_keys_or_tokens_printed`",
		"`readiness_not_claimed.runtime_profile_ready`",
		"`readiness_not_claimed.submit_ready`",
		"`readiness_not_claimed.es_services_healthy`",
		"`readiness_not_claimed.producer_contract_compatible`",
		"`readiness_not_claimed.retained_result_fetch`",
		"does not build or rebuild the image by default",
		"does not install or start ES, AGS, ARS, or EGS",
		"not an ES lifecycle or readiness surface",
		"not yet: - an Infrastructure Manager doctor stage payload",
		"fail fast instead of silently honoring a different image ref, Dockerfile, Codex CLI path, or Codex realization",
		"must not accept `REMOTE_ALPHA_RUNTIME_IMAGE_REF`, `REMOTE_ALPHA_CODEX_CLI_PATH`, `REMOTE_ALPHA_BUILD_SCRIPT`, `--image-ref`, or `--codex-cli-path` as mutable inputs",
		"not runtime-profile readiness",
		"not submit readiness",
		"not producer-contract compatibility",
		"not retained-result proof",
		"`build.recipe_matches_slice`: `true` only when the current repo snapshot still carries the expected repo-owned wrapper for this slice",
		"`build.codex_realization`: literal `proof` for the current repo-owned slice",
		"`placeholder` is not the current repo-owned slice posture",
		"does not, by itself, prove that the current image was historically built through that wrapper",
		"must not persist: - OpenAI or Codex credentials",
		"raw build logs",
		"raw retained-result bundles",
	} {
		if !strings.Contains(remote, required) && !strings.Contains(configuration, required) {
			t.Fatalf("remote normal-shell runtime image schema docs missing %q", required)
		}
	}
}

func TestRemoteSupportedHostAlphaAGSServiceHardeningSliceIsDocumented(t *testing.T) {
	plans := compactText(mustRead(t, "PLANS.md"))
	hardening := hostRuntimeSection(t, raHardeningHeading)
	remote := compactText(mustRead(t, ".docs/system_overview/remote_supported_host_alpha.md"))
	configuration := compactText(mustRead(t, ".docs/system_overview/configuration.md"))

	for _, required := range []string{
		"`AGS sealed + ARS de-root + EGS de-root`",
		"AGS is already de-rooted and sealed",
		"ARS is already de-rooted",
		"EGS is already de-rooted",
		"Archived v1 evidence recorded this earlier bounded ES state",
		"the observed long-lived `es.service` ran as `User=es`, `Group=es`, `UMask=0027`",
		"does not claim full ES/runtime de-root",
		"must not change ES public contracts",
		"Old root-era staging/results roots remain preserved as rollback/debug/evidence state",
	} {
		if !strings.Contains(plans, required) && !strings.Contains(hardening, required) && !strings.Contains(remote, required) && !strings.Contains(configuration, required) {
			t.Fatalf("remote alpha tranche docs missing %q", required)
		}
	}

	for _, required := range []string{
		"Remote AGS Sealed + ARS De-root + EGS De-root Hardening Tranche",
		"Landed AGS Seal Step",
		"The AGS step in this tranche is already landed.",
		"preserving direct HTTPS/mTLS from the Mac to AGS `/health` and `POST /v1/artifacts:publish`",
		"preserving AGS publication to ARS over the current loopback/internal HTTPS dependency path",
		"must preserve the current ARS `ars:ars`, EGS `egs:egs`, and ES `User=es`, `Group=es`, `UMask=0027` service postures",
		"leaving the current SPIRE selector model unchanged",
		"`sudo scripts/remote_alpha_harden_ags_service.sh`",
		"`execution-substrate.remote-alpha.ags-service-hardening-summary.v1`",
		"`/var/tmp/execution-substrate-remote-alpha/ags-service-hardening-summary.json`",
		"`slice.classification`",
		"`slice.not_a_new_happy_path_proof`",
		"`service.user`",
		"`service.group`",
		"`service.binary_path`",
		"`service.config_path`",
		"`/etc/execution-substrate/healthcheck.env`",
		"`dependencies.artifact_registry.base_url`",
		"`dependencies.server_tls.cert_file`",
		"`dependencies.server_tls.key_file`",
		"`dependencies.server_tls.client_ca_file`",
		"`dependencies.artifact_registry.client_cert_file`",
		"`dependencies.artifact_registry.client_key_file`",
		"`dependencies.artifact_registry.root_ca_file`",
		"`dependencies.signer.material_location`",
		"`dependencies.local_state_paths`",
		"`dependencies.log_sink`",
		"`ownership_model.config_file`",
		"`ownership_model.tls_directory`",
		"`ownership_model.tls_files`",
		"`ownership_model.systemd_dropin`",
		"`validation.local_health`",
		"`validation.local_publish_probe`",
		"`validation.ars_service_posture`",
		"`validation.egs_service_posture`",
		"`validation.es_service_posture`",
		"`validation.mac_health_probe`",
		"`validation.mac_publish_probe`",
		"`preserved_remote_path.direct_https_mtls`",
		"`preserved_remote_path.no_bridge`",
		"`preserved_remote_path.no_shared_filesystem`",
		"`security.ds_not_in_docker_group`",
		"`security.passwordless_sudo_for_ds`",
		"`not_claimed.es_runtime_hardening`",
		"`not_claimed.submit_runtime_profile_changes`",
		"`not_claimed.spire_selector_model_changes`",
		"`not_claimed.new_remote_happy_path_proof`",
		"`/usr/local/lib/execution-substrate/bin/ags`",
		"`/etc/execution-substrate/ags.json`",
		"`/etc/execution-substrate/tls/ags-server-cert.pem`",
		"`/etc/execution-substrate/tls/ags-server-key.pem`",
		"`/etc/execution-substrate/tls/combined-service-ca-bundle.pem`",
		"`/etc/execution-substrate/tls/ags-client-cert.pem`",
		"`/etc/execution-substrate/tls/ags-client-key.pem`",
		"`/etc/execution-substrate/tls/runtime-ca.pem`",
		"`/etc/systemd/system/ags.service`",
		"`/etc/systemd/system/ags.service.d`",
		"`/etc/systemd/system/ags.service.d/10-account.conf`",
		"`root:ags` mode `0640`",
		"`root:ags` mode `0710`",
		"must not accept `REMOTE_ALPHA_SERVICE_NAME`, `REMOTE_ALPHA_SERVICE_USER`, `REMOTE_ALPHA_SERVICE_GROUP`, `REMOTE_ALPHA_BINARY_PATH`, `REMOTE_ALPHA_CONFIG_PATH`, `REMOTE_ALPHA_HEALTHCHECK_ENV_PATH`, `REMOTE_ALPHA_SERVICE_UNIT_PATH`, `REMOTE_ALPHA_SERVICE_DROPIN_DIR`, `REMOTE_ALPHA_SERVICE_DROPIN_PATH`, `--service-name`, `--service-user`, `--service-group`, `--binary-path`, `--config-path`, `--healthcheck-env-path`, `--service-unit-path`, `--service-dropin-dir`, or `--service-dropin-path` as mutable inputs",
		"Only `--summary-path` and `REMOTE_ALPHA_SUMMARY_PATH` may vary for output placement",
		"must not introduce a shared `execution-substrate` account model",
		"must not change ES public contracts",
		"must not change the SPIRE selector model",
		"must not persist: - signer private-key bytes",
		"raw retained-result bundles",
	} {
		if !strings.Contains(remote, required) && !strings.Contains(configuration, required) {
			t.Fatalf("remote AGS hardening docs missing %q", required)
		}
	}
}

func TestRemoteSupportedHostAlphaARSServiceHardeningSliceIsDocumented(t *testing.T) {
	remote := compactText(mustRead(t, ".docs/system_overview/remote_supported_host_alpha.md"))
	configuration := compactText(mustRead(t, ".docs/system_overview/configuration.md"))

	for _, required := range []string{
		"Remote AGS Sealed + ARS De-root + EGS De-root Hardening Tranche",
		"Landed ARS De-root Step",
		"The ARS step in this tranche is already landed.",
		"preserving the landed `ars.service` non-root `ars:ars` account",
		"preserving the current ARS internal-only loopback listener at `https://127.0.0.1:8442`",
		"preserving AGS local `/health` plus a focused `POST /v1/artifacts:publish` probe through the existing AGS -> ARS loopback dependency path",
		"preserving the current AGS `ags:ags` posture",
		"preserving the current EGS `egs:egs` posture and the current ES `User=es`, `Group=es`, `UMask=0027` posture on any current rerun of this landed step",
		"leaving the current SPIRE selector model unchanged",
		"`sudo scripts/remote_alpha_harden_ars_service.sh`",
		"`execution-substrate.remote-alpha.ars-service-hardening-summary.v1`",
		"`/var/tmp/execution-substrate-remote-alpha/ars-service-hardening-summary.json`",
		"`slice.classification`",
		"`slice.not_a_new_happy_path_proof`",
		"`service.user`",
		"`service.group`",
		"`service.binary_path`",
		"`service.config_path`",
		"`/etc/execution-substrate/healthcheck.env`",
		"`dependencies.server_tls.cert_file`",
		"`dependencies.server_tls.key_file`",
		"`dependencies.server_tls.client_ca_file`",
		"`dependencies.blob_root`",
		"`dependencies.index_file`",
		"`dependencies.local_state_paths`",
		"`dependencies.log_sink`",
		"`ownership_model.config_file`",
		"`ownership_model.tls_directory`",
		"`ownership_model.tls_files`",
		"`ownership_model.state_root`",
		"`ownership_model.blob_root`",
		"`ownership_model.index_file`",
		"`ownership_model.systemd_dropin`",
		"`validation.local_ars_health`",
		"`validation.local_ags_health`",
		"`validation.local_ags_publish_probe`",
		"`validation.state_ownership`",
		"`validation.ags_service_posture`",
		"`validation.egs_service_posture`",
		"`validation.es_service_posture`",
		"`preserved_remote_path.ars_loopback_only`",
		"`preserved_remote_path.direct_https_mtls`",
		"`preserved_remote_path.no_bridge`",
		"`preserved_remote_path.no_shared_filesystem`",
		"`security.ds_not_in_docker_group`",
		"`security.passwordless_sudo_for_ds`",
		"`not_claimed.es_or_egs_hardening`",
		"`not_claimed.es_public_contract_changes`",
		"`not_claimed.spire_selector_model_changes`",
		"`not_claimed.new_remote_happy_path_proof`",
		"`/usr/local/lib/execution-substrate/bin/ars`",
		"`/etc/execution-substrate/ars.json`",
		"`/etc/execution-substrate/tls/ars-server-cert.pem`",
		"`/etc/execution-substrate/tls/ars-server-key.pem`",
		"`/etc/execution-substrate/tls/runtime-ca.pem`",
		"`/etc/execution-substrate/ars-tls`",
		"`/etc/execution-substrate/ars-tls/ars-server-cert.pem`",
		"`/etc/execution-substrate/ars-tls/ars-server-key.pem`",
		"`/etc/execution-substrate/ars-tls/runtime-ca.pem`",
		"`/var/lib/execution-substrate/ars/blobs`",
		"`/var/lib/execution-substrate/ars/index.json`",
		"`/etc/systemd/system/ars.service`",
		"`/etc/systemd/system/ars.service.d`",
		"`/etc/systemd/system/ars.service.d/10-account.conf`",
		"`root:ars` mode `0640`",
		"`root:ars` mode `0710`",
		"`ars:ars` mode `0750`",
		"`ars:ars` mode `0600`",
		"`UMask=0027`",
		"must not widen `/etc/execution-substrate/tls`",
		"must not accept `REMOTE_ALPHA_SERVICE_NAME`, `REMOTE_ALPHA_SERVICE_USER`, `REMOTE_ALPHA_SERVICE_GROUP`, `REMOTE_ALPHA_BINARY_PATH`, `REMOTE_ALPHA_CONFIG_PATH`, `REMOTE_ALPHA_HEALTHCHECK_ENV_PATH`, `REMOTE_ALPHA_SERVICE_UNIT_PATH`, `REMOTE_ALPHA_SERVICE_DROPIN_DIR`, `REMOTE_ALPHA_SERVICE_DROPIN_PATH`, `--service-name`, `--service-user`, `--service-group`, `--binary-path`, `--config-path`, `--healthcheck-env-path`, `--service-unit-path`, `--service-dropin-dir`, or `--service-dropin-path` as mutable inputs",
		"Only `--summary-path` and `REMOTE_ALPHA_SUMMARY_PATH` may vary for output placement",
		"must not introduce a shared `execution-substrate` account model",
		"must not change ES public contracts",
		"must not change the SPIRE selector model",
		"must not persist JWT-SVIDs, Vault tokens, TLS private-key PEM bodies, API keys, private keys, or secret payloads",
	} {
		if !strings.Contains(remote, required) && !strings.Contains(configuration, required) {
			t.Fatalf("remote ARS hardening docs missing %q", required)
		}
	}
}

func TestRemoteSupportedHostAlphaEGSServiceHardeningSliceIsDocumented(t *testing.T) {
	remote := compactText(mustRead(t, ".docs/system_overview/remote_supported_host_alpha.md"))
	configuration := compactText(mustRead(t, ".docs/system_overview/configuration.md"))

	for _, required := range []string{
		"Remote AGS Sealed + ARS De-root + EGS De-root Hardening Tranche",
		"EGS De-root Step",
		"The EGS step in this tranche is already landed.",
		"moving only `egs.service` from the default root service context to a dedicated non-root `egs:egs` account",
		"preserving the current EGS internal-only loopback listener at `https://127.0.0.1:8443`",
		"preserving AGS local `/health` plus a focused `POST /v1/artifacts:publish` probe through the existing AGS -> ARS loopback dependency path",
		"preserving local ES `/health` plus `GET /v1/executions:contract` through the current direct HTTPS/mTLS path",
		"preserving the current AGS `ags:ags` posture",
		"preserving the current ARS `ars:ars` posture",
		"preserving the current ES `User=es`, `Group=es`, `UMask=0027` posture",
		"leaving the current SPIRE selector model unchanged",
		"If the target host already has an `egs` user/group",
		"At minimum, that check must confirm primary group `egs`, no supplementary groups, and no unexpected extra members in the `egs` group itself",
		"`sudo scripts/remote_alpha_harden_egs_service.sh`",
		"`execution-substrate.remote-alpha.egs-service-hardening-summary.v2`",
		"`/var/tmp/execution-substrate-remote-alpha/egs-service-hardening-summary.json`",
		"`slice.classification`",
		"`slice.not_a_new_happy_path_proof`",
		"`service.user`",
		"`service.group`",
		"`service.binary_path`",
		"`service.config_path`",
		"`/etc/execution-substrate/healthcheck.env`",
		"`dependencies.server_tls.cert_file`",
		"`dependencies.server_tls.key_file`",
		"`dependencies.server_tls.client_ca_file`",
		"`dependencies.signer.material_location`",
		"`dependencies.runtime_trust.material_location`",
		"`dependencies.publication.material_location`",
		"`dependencies.local_state_paths`",
		"`dependencies.log_sink`",
		"`ownership_model.config_file`",
		"`ownership_model.tls_directory`",
		"`ownership_model.tls_files`",
		"`ownership_model.runtime_state`",
		"`ownership_model.systemd_dropin`",
		"`validation.local_egs_health`",
		"`validation.local_ags_health`",
		"`validation.local_ags_publish_probe`",
		"`validation.local_es_health`",
		"`validation.local_es_contract_probe`",
		"`validation.service_account_narrowness`",
		"`ownership_model.account.group_members`",
		"`validation.service_account_narrowness.group_members`",
		"`validation.service_account_narrowness.unexpected_group_members`",
		"`validation.ownership`",
		"`validation.ags_service_posture`",
		"`validation.ars_service_posture`",
		"`validation.es_service_posture`",
		"`preserved_remote_path.egs_loopback_only`",
		"`preserved_remote_path.direct_https_mtls`",
		"`preserved_remote_path.no_bridge`",
		"`preserved_remote_path.no_shared_filesystem`",
		"`security.ds_not_in_docker_group`",
		"`security.passwordless_sudo_for_ds`",
		"`security.shared_unix_account_model_introduced`",
		"`not_claimed.es_de_root`",
		"`not_claimed.es_public_contract_changes`",
		"`not_claimed.spire_selector_model_changes`",
		"`not_claimed.new_remote_happy_path_proof`",
		"`/usr/local/lib/execution-substrate/bin/egs`",
		"`/etc/execution-substrate/egs.json`",
		"`/etc/execution-substrate/tls/egs-server-cert.pem`",
		"`/etc/execution-substrate/tls/egs-server-key.pem`",
		"`/etc/execution-substrate/tls/runtime-ca.pem`",
		"`/etc/execution-substrate/egs-tls`",
		"`/etc/execution-substrate/egs-tls/egs-server-cert.pem`",
		"`/etc/execution-substrate/egs-tls/egs-server-key.pem`",
		"`/etc/execution-substrate/egs-tls/runtime-ca.pem`",
		"`/etc/systemd/system/egs.service`",
		"`/etc/systemd/system/egs.service.d`",
		"`/etc/systemd/system/egs.service.d/10-account.conf`",
		"`root:egs` mode `0640`",
		"`root:egs` mode `0710`",
		"`UMask=0027`",
		"must not widen `/etc/execution-substrate/tls`",
		"must not accept `REMOTE_ALPHA_SERVICE_NAME`, `REMOTE_ALPHA_SERVICE_USER`, `REMOTE_ALPHA_SERVICE_GROUP`, `REMOTE_ALPHA_BINARY_PATH`, `REMOTE_ALPHA_CONFIG_PATH`, `REMOTE_ALPHA_HEALTHCHECK_ENV_PATH`, `REMOTE_ALPHA_SERVICE_UNIT_PATH`, `REMOTE_ALPHA_SERVICE_DROPIN_DIR`, `REMOTE_ALPHA_SERVICE_DROPIN_PATH`, `--service-name`, `--service-user`, `--service-group`, `--binary-path`, `--config-path`, `--healthcheck-env-path`, `--service-unit-path`, `--service-dropin-dir`, or `--service-dropin-path` as mutable inputs",
		"Only `--summary-path` and `REMOTE_ALPHA_SUMMARY_PATH` may vary for output placement",
		"must not introduce a shared Unix-account model",
		"`preserved_remote_path.direct_https_mtls` must be an inference record",
		"not a Mac-side reachability proof",
		"`preserved_remote_path.no_bridge` and `preserved_remote_path.no_shared_filesystem` must be explicit operator assertion records",
		"`security.shared_unix_account_model_introduced` must be derived from `validation.service_account_narrowness`",
		"`validation.service_account_narrowness` must record the actual primary group, supplementary groups, and effective `egs` group members",
		"It must not report `false` unless the helper has proved the EGS account remained narrow for this slice.",
		"must not change ES public contracts",
		"must not change the SPIRE selector model",
		"must not persist: - signer private-key bytes",
		"raw retained-result bundles",
	} {
		if !strings.Contains(remote, required) && !strings.Contains(configuration, required) {
			t.Fatalf("remote EGS hardening docs missing %q", required)
		}
	}
}

func TestRemoteSupportedHostAlphaESConfigTLSPrepSliceIsDocumented(t *testing.T) {
	remote := compactText(mustRead(t, ".docs/system_overview/remote_supported_host_alpha.md"))
	configuration := compactText(mustRead(t, ".docs/system_overview/configuration.md"))
	plans := compactText(mustRead(t, "PLANS.md"))
	prep := hostRuntimeSection(t, raESConfigTLSPrepHeading)

	for _, required := range []string{
		"Current Remote Alpha ES Config/TLS Ownership Prep Slice",
		"Remote Supported-Host Alpha may now extend the current host-local hardening work with one separate ES config/TLS ownership prep slice",
		"introduces a dedicated ES-readable config ownership model and a dedicated ES-readable TLS directory",
		"may create a narrow dedicated `es:es` prep account",
		"At apply time, this slice kept the live `es.service` user/group posture unchanged",
		"must not change ES public contracts, the current SPIRE selector posture, current SPIRE socket traversal, Vault/runtime-helper semantics, or Nomad task user model",
		"must not move ES writable state, including staging and retained results ownership",
		"preserves the current AGS, ARS, and EGS service postures plus the direct Mac -> ES HTTPS+mTLS posture",
		"bounded host-local config/TLS ownership preparation only",
		"the ES config/TLS ownership prep bridge where live `es.service` stays `root(default)` while dedicated `root:es` readable config/TLS material is staged for a later ES de-root slice",
	} {
		if !strings.Contains(plans, required) && !strings.Contains(prep, required) && !strings.Contains(remote, required) && !strings.Contains(configuration, required) {
			t.Fatalf("remote ES prep docs missing %q", required)
		}
	}

	for _, required := range []string{
		"Remote ES Config/TLS Ownership Prep Slice",
		"`Bounded slice rule`: this slice prepares only ES-readable config/TLS ownership for a later non-root ES step.",
		"`Temporary compatibility edge`: at that earlier step, the live `es.service` user/group remained `root(default)` while the ES config file and dedicated ES TLS directory were prepared under `root:es` readability for a later de-root slice.",
		"The config/TLS, binary-deployment, and writable-state subsections below still describe earlier bounded slices whose own apply summaries intentionally record `root(default)` at those earlier steps.",
		"preserving the current direct HTTPS/mTLS ES `/health` and `GET /v1/executions:contract` path",
		"preserving the current SPIRE selector posture, SPIRE socket traversal, and Vault/runtime-helper semantics",
		"preserving the current Nomad task user model",
		"leaving ES staging and retained-results ownership untouched",
		"`scripts/remote_alpha_prepare_es_config_tls.sh`",
		"`execution-substrate.remote-alpha.es-config-tls-prep-summary.v1`",
		"`/var/tmp/execution-substrate-remote-alpha/es-config-tls-prep-summary.json`",
		"`slice.classification`",
		"`slice.not_a_new_happy_path_proof`",
		"`slice.temporary_compatibility_edge`",
		"`mode.name`",
		"`mode.non_mutating`",
		"`mode.output`",
		"`service.live_user`",
		"`service.live_group`",
		"`service.binary_path`",
		"`service.config_path`",
		"`service.health_url`",
		"`service.contract_url`",
		"`dependencies.server_tls.cert_file`",
		"`dependencies.server_tls.key_file`",
		"`dependencies.server_tls.client_ca_file`",
		"`dependencies.artifact_registry.base_url`",
		"`dependencies.artifact_registry.client_cert_file`",
		"`dependencies.artifact_registry.client_key_file`",
		"`dependencies.artifact_registry.root_ca_file`",
		"`dependencies.execution_governance.base_url`",
		"`dependencies.execution_governance.client_cert_file`",
		"`dependencies.execution_governance.client_key_file`",
		"`dependencies.execution_governance.root_ca_file`",
		"`dependencies.local_state_paths`",
		"`dependencies.log_sink`",
		"`plan.paths_read`",
		"`plan.paths_written`",
		"`plan.ownership_changes`",
		"`plan.prep_account`",
		"`plan.service_identity_would_remain_root_default`",
		"`plan.restart_required_in_apply_mode`",
		"`plan.warnings`",
		"`plan.blockers`",
		"`backup.status`",
		"`backup.parent_dir`",
		"`backup.path`",
		"`backup.pre_apply_config_copy`",
		"`backup.snapshot_manifest_path`",
		"`backup.pre_apply_source_tls`",
		"`backup.pre_apply_prep_account`",
		"`backup.pre_apply_service`",
		"`backup.rollback_notes`",
		"`ownership_model.prep_account`",
		"`ownership_model.config_file`",
		"`ownership_model.tls_directory`",
		"`ownership_model.tls_files`",
		"`ownership_model.live_service_posture`",
		"`ownership_model.writable_state`",
		"`validation.local_es_health`",
		"`validation.local_es_contract_probe`",
		"`validation.prep_account_narrowness`",
		"`validation.ownership`",
		"`validation.config_rewrite_scope`",
		"`validation.ags_service_posture`",
		"`validation.ars_service_posture`",
		"`validation.egs_service_posture`",
		"`validation.es_service_posture`",
		"`preserved_remote_path.direct_https_mtls`",
		"`preserved_remote_path.no_bridge`",
		"`preserved_remote_path.no_shared_filesystem`",
		"`security.ds_not_in_docker_group`",
		"`security.passwordless_sudo_for_ds`",
		"`security.shared_unix_account_model_introduced`",
		"`not_claimed.es_de_root`",
		"`not_claimed.es_public_contract_changes`",
		"`not_claimed.spire_selector_model_changes`",
		"`not_claimed.spire_socket_traversal_changes`",
		"`not_claimed.nomad_task_user_model_changes`",
		"`not_claimed.vault_runtime_helper_changes`",
		"`not_claimed.staging_or_results_ownership_changes`",
		"`not_claimed.new_remote_happy_path_proof`",
		"`result.status`",
		"`result.ok`",
		"`result.non_mutating`",
		"`sudo /var/tmp/execution-substrate-remote-alpha/helper-staging/scripts/remote_alpha_prepare_es_config_tls.sh --check-only`",
		"`--dry-run` is an accepted alias",
		"required first step before any live apply",
		"machine-readable JSON plan/report to stdout",
		"must not create users or",
		"groups, call `chown` or `chmod`",
		"rewrite `/etc/execution-substrate/es.json`",
		"create or replace `/etc/execution-substrate/es-tls`",
		"create a backup directory under `/var/tmp/execution-substrate-remote-alpha/`",
		"restart `es.service`",
		"Before any apply-mode mutation primitive runs, the helper must create a timestamped backup directory under",
		"`/var/tmp/execution-substrate-remote-alpha/`",
		"`pre-apply-snapshot.json`",
		"record the pre-apply source TLS path, size, owner, group, mode, and sha256",
		"record whether the `es` prep user and group existed before apply",
		"record the current `es.service` `User`, `Group`, `ActiveState`, and `SubState` before apply",
		"record rollback notes for restoring the pre-apply ES config/TLS posture",
		"If the target host already has an `es` user/group",
		"At minimum, that check must confirm primary group `es` and no supplementary groups",
		"must not accept `REMOTE_ALPHA_SERVICE_NAME`, `REMOTE_ALPHA_PREP_USER`, `REMOTE_ALPHA_PREP_GROUP`, `REMOTE_ALPHA_BINARY_PATH`, `REMOTE_ALPHA_CONFIG_PATH`, `REMOTE_ALPHA_HEALTHCHECK_ENV_PATH`, `REMOTE_ALPHA_SERVICE_UNIT_PATH`, `--service-name`, `--prep-user`, `--prep-group`, `--binary-path`, `--config-path`, `--healthcheck-env-path`, or `--service-unit-path` as mutable inputs",
		"Only `--summary-path` and `REMOTE_ALPHA_SUMMARY_PATH` may vary for output placement",
		"`/usr/local/lib/execution-substrate/bin/es`",
		"`/etc/execution-substrate/es.json`",
		"`/etc/execution-substrate/healthcheck.env`",
		"`/etc/systemd/system/es.service`",
		"`/etc/execution-substrate/tls/es-server-cert.pem`",
		"`/etc/execution-substrate/tls/es-server-key.pem`",
		"`/etc/execution-substrate/tls/runtime-ca.pem`",
		"`/etc/execution-substrate/tls/es-client-cert.pem`",
		"`/etc/execution-substrate/tls/es-client-key.pem`",
		"`/etc/execution-substrate/es-tls`",
		"`/etc/execution-substrate/es-tls/es-server-cert.pem`",
		"`/etc/execution-substrate/es-tls/es-server-key.pem`",
		"`/etc/execution-substrate/es-tls/server-client-ca.pem`",
		"`/etc/execution-substrate/es-tls/artifact-registry-client-cert.pem`",
		"`/etc/execution-substrate/es-tls/artifact-registry-client-key.pem`",
		"`/etc/execution-substrate/es-tls/artifact-registry-root-ca.pem`",
		"`/etc/execution-substrate/es-tls/execution-governance-client-cert.pem`",
		"`/etc/execution-substrate/es-tls/execution-governance-client-key.pem`",
		"`/etc/execution-substrate/es-tls/execution-governance-root-ca.pem`",
		"`root:es` mode `0640`",
		"`root:es` mode `0710`",
		"current staging and retained-results ownership remain unchanged in this slice",
		"`validation.config_rewrite_scope` must prove that only ES config/TLS path fields changed",
		"`validation.es_service_posture` must show the live service still runs as `root(default)` after the prep apply",
		"`preserved_remote_path.direct_https_mtls` must be an inference record",
		"not a Mac-side reachability proof",
		"`preserved_remote_path.no_bridge` and `preserved_remote_path.no_shared_filesystem` must be explicit operator assertion records",
		"`security.ds_not_in_docker_group` and `security.passwordless_sudo_for_ds` are host-posture observations recorded in the summary",
		"must not, by themselves, turn an otherwise-valid ES config/TLS ownership prep apply into a failed slice result",
		"`security.shared_unix_account_model_introduced` must be derived from `validation.prep_account_narrowness`",
		"must not persist TLS private-key PEM bodies, client-cert private keys, JWT-SVIDs, Vault tokens, API keys, private keys, secret payloads, or raw retained-result bundles",
	} {
		if !strings.Contains(remote, required) && !strings.Contains(configuration, required) && !strings.Contains(plans, required) {
			t.Fatalf("remote ES prep docs missing %q", required)
		}
	}
}

func TestRemoteSupportedHostAlphaESConfigTLSPrepOperatorStagingFlowIsDocumented(t *testing.T) {
	remote := compactText(mustRead(t, ".docs/system_overview/remote_supported_host_alpha.md"))
	configuration := compactText(mustRead(t, ".docs/system_overview/configuration.md"))

	for _, required := range []string{
		"The remote host does not need a full Execution Substrate repo checkout for this slice.",
		"transient helper staging from the operator repo into a root-owned staging tree under `/var/tmp/execution-substrate-remote-alpha/helper-staging/`",
		"the operator must stage the repo-owned wrapper `scripts/remote_alpha_prepare_es_config_tls.sh` and its sourced helper `scripts/internal/remote_alpha_prepare_es_config_tls.sh`",
		"`/var/tmp/execution-substrate-remote-alpha/helper-staging/scripts/remote_alpha_prepare_es_config_tls.sh`",
		"Execution must run from that root-owned staged tree, not from a user-writable upload path.",
		"Any user-scoped upload directory is transport only and must not be used as the execution path for the live helper invocation.",
		"The required operator-staged provenance record for that transient helper tree must include:",
		"the local git commit when available",
		"the sha256 of each staged helper file",
		"the remote staged path",
		"the remote owner/mode proving the staged tree is root-owned rather than a user-writable upload path",
		"The required operator-staged flow for this slice is:",
		"Copy only the minimal helper tree from the local operator repo snapshot; a full remote repo checkout is not required.",
		"Run the staged wrapper with `--check-only` before any live apply.",
		"Apply may proceed only when `result.ok=true`, `plan.blockers` is empty, `plan.service_identity_would_remain_root_default=true`, and `validation.config_rewrite_scope.status=pass`",
		"the planned writes must stay limited to `/etc/execution-substrate/es.json`, `/etc/execution-substrate/es-tls`, the files beneath that dedicated TLS directory, and the configured summary path.",
		"Preserve the apply summary, backup path, rollback notes, live `es.service` identity, and post-apply `/health` plus `GET /v1/executions:contract` status as the bounded post-apply evidence set.",
		"Remove the transient helper staging tree after that bounded evidence is collected, while preserving the apply backup and summaries under `/var/tmp/execution-substrate-remote-alpha/`.",
		"Do not run governed proof as part of this staged operator flow.",
		"This operator-staged flow is ownership prep only. It is not ES de-rooting.",
		"`sudo /var/tmp/execution-substrate-remote-alpha/helper-staging/scripts/remote_alpha_prepare_es_config_tls.sh --check-only`",
		"`sudo /var/tmp/execution-substrate-remote-alpha/helper-staging/scripts/remote_alpha_prepare_es_config_tls.sh`",
	} {
		if !strings.Contains(remote, required) && !strings.Contains(configuration, required) {
			t.Fatalf("remote ES prep operator-staging docs missing %q", required)
		}
	}
}

func TestRemoteSupportedHostAlphaExistingHostESRoutesAreDocumentedAsRetired(t *testing.T) {
	plans := compactText(mustRead(t, "PLANS.md"))
	remote := compactText(mustRead(t, ".docs/system_overview/remote_supported_host_alpha.md"))
	configuration := compactText(mustRead(t, ".docs/system_overview/configuration.md"))
	ownership := compactText(mustRead(t, ".docs/system_overview/remote_alpha_beta_es_writable_state_ownership.md"))
	normalization := compactText(mustRead(t, ".docs/system_overview/remote_alpha_beta_es_runtime_ownership_normalization.md"))

	assertContainsAll(t, "Remote Alpha retirement plan", plans,
		"retires the six existing-host ES writable-state, ES service-user, ownership, staging, rollback-generation, and old-root-planning helper implementations",
		"fixed fail-closed tombstones produce no evidence",
		"no live operator route parses or projects them",
		"no v2 replacement exists for that retired family",
		"unrelated current EGS hardening v2 schema also remains current",
	)
	assertContainsAll(t, "Remote Alpha retired helper configuration", configuration,
		"### Retired Remote Alpha existing-host ES helpers",
		"public wrappers remain compatibility delegators to fixed exit-2 tombstones",
		"No check-only, apply, discovery, inspection, staging, backup, JSON, Markdown, or migration simulation remains",
		"a complete supported fresh-host ES provisioner is not currently implemented",
	)
	assertContainsAll(t, "Remote Alpha retired historical sections", remote,
		"## Historical Remote ES Writable-State Readiness Evidence Flow — Retired",
		"wrapper now reaches a fixed tombstone for every argument",
		"## Historical Remote ES Writable-State Ownership Surface — Retired",
		"current wrapper delegates to a fixed tombstone",
		"## Historical Remote ES Service-User Migration Surface — Retired",
		"service-user, readiness, rollback-generation, and old-root-planning wrappers now delegate to fixed tombstones",
		"Archived v1 files have no readiness, migration, drain, reclamation, or mutation authority",
	)
	assertContainsAll(t, "Remote Alpha current writable-state contract", ownership,
		"fixed exit-2 tombstones",
		"routes inspect no host or artifact, contact no service, create no temporary or evidence file, and perform no mutation",
		"No read-only current-readiness mode, apply simulation, structured unsupported artifact, or v2 replacement exists",
		"Once run-root creation succeeds, the visible root is retained on every return",
	)
	assertContainsAll(t, "Remote Alpha historical normalization contract", normalization,
		"historical evidence only",
		"public wrappers now delegate to fixed fail-closed tombstones",
		"No v2 schema, validator, fixture, or artifact exists for that retired ES writable-state/service-user migration family",
	)
}
func TestRemoteSupportedHostAlphaESBinaryDeploymentOperatorFlowIsDocumented(t *testing.T) {
	remote := compactText(mustRead(t, ".docs/system_overview/remote_supported_host_alpha.md"))
	configuration := compactText(mustRead(t, ".docs/system_overview/configuration.md"))

	for _, required := range []string{
		"Remote ES Binary Deployment Surface",
		"`scripts/remote_alpha_deploy_es_binaries.sh`",
		"`scripts/internal/remote_alpha_deploy_es_binaries.sh`",
		"`/usr/local/lib/execution-substrate/bin/es`",
		"`/usr/local/bin/es-runtime-support`",
		"`<upload-root>/scripts/remote_alpha_deploy_es_binaries.sh`",
		"`<upload-root>/scripts/internal/remote_alpha_deploy_es_binaries.sh`",
		"`es-binary-deployment-check-only.json`",
		"`es-binary-deployment-helper-staging-record.json`",
		"`es-binary-deployment-apply-summary.json`",
		"dirty-worktree",
		"`deployment_needed`",
		"The default staged-wrapper path must perform a noninteractive `sudo -n` preflight and fail cleanly with structured `sudo_unavailable` evidence",
		"An explicit `--interactive-sudo` mode may be used only from a visible terminal when a bounded password handoff is authorized.",
		"`install: cannot stat`",
		"preserving the accepted live `es.service` identity for the current host slice",
		"current post-migration binary refreshes must instead preserve the accepted long-lived `User=es`, `Group=es`, `UMask=0027` posture",
		"current post-migration binary refreshes must block any root-like service identity",
		"`plan.service_identity_matches_current_supported_posture=true`",
		"Historical earlier-slice artifacts may preserve the then live `root(default)` service identity",
		"restart `es.service` at most once",
		"validate `/health` plus `GET /v1/executions:contract` afterward",
	} {
		if !strings.Contains(remote, required) && !strings.Contains(configuration, required) {
			t.Fatalf("remote ES binary deployment docs missing %q", required)
		}
	}
}

func TestIntegratedResultCustodyDocumentationMatchesSelectedEffects(t *testing.T) {
	admissionRules := mustRead(t, standingAdmissionRulesPath)
	design := mustRead(t, ".docs/execution_lifecycle/design.md")
	implementation := mustRead(t, ".docs/execution_lifecycle/implementation.md")
	contracts := mustRead(t, ".docs/execution_lifecycle/contracts.md")
	systemContracts := mustRead(t, ".docs/system_overview/contracts.md")
	boundaries := mustRead(t, ".docs/system_overview/boundaries.md")

	planCustody := compactDocSection(t, admissionRules, "**Current invariant — staging non-mutation and retained-output independence.**", "The mount-archive namespace validator")
	assertContainsAll(t, "current plan result custody", planCustody,
		"**Bounded slice rule pending integrated review — paired-root qualification.**",
		"Pair proof is a prerequisite, not deletion or repair authority.",
		"Existing result directories, finals, and normalization evidence are validated without metadata repair or adoption.",
		"New unpublished result temporaries/records and newly created normalization evidence may receive their selected owner and mode through `Fchown`/`Fchmod`.",
		"No result pathname cleanup or whole-root reclamation is selected.",
	)
	assertContainsNone(t, "obsolete current plan effect claims", planCustody,
		"retained-result directory reconciliation, creation, cleanup",
		"Result mutations reobserve at each named directory, metadata, temporary, publication, sidecar, and cleanup boundary",
		"Failed cleanup revalidation retains the exact temporary",
	)

	designCustody := compactDocSection(t, design, "## 14. Current root-custody refinement", "")
	assertContainsAll(t, "current lifecycle design custody", designCustody,
		"An existing bundle becomes eligible only after authenticated final/record checks",
		"an unmarked or invalid pair is refused, not adopted",
		"initialization of newly created unpublished records and normalization evidence",
		"Existing directories, finals, and normalization evidence are validated without metadata repair or adoption",
		"Pair proof does not grant deletion or repair authority",
		"incomplete leaves, uncertain temporaries, and startup probe fixtures remain retained",
		"The owning eligibility and retention contract is `.docs/execution_lifecycle/contracts.md`",
	)
	assertContainsNone(t, "obsolete current lifecycle design effects", designCustody,
		"Every result-side create, metadata reconciliation, temporary, publication, sidecar, and cleanup effect",
		"Loss of custody before cleanup retains the exact temporary object",
	)

	currentImplementation := compactDocSection(t, implementation, "Result paths open one pair", "The current stable-service-namespace/trusted-operator assumption")
	assertContainsAll(t, "current result implementation effects", currentImplementation,
		"new-object initialization, no-replace final/record publication, and authenticated read/check",
		"`Fchown` and `Fchmod` initialize newly created unpublished result temporaries/records",
		"they do not repair existing directories, finals, or evidence",
		"No result pathname cleanup or existing-object reconciliation is selected",
		"incomplete leaves and uncertain temporaries remain",
		"An existing final is publicly eligible only with its authenticated completion record",
	)
	assertContainsNone(t, "obsolete current implementation effects", currentImplementation,
		"metadata reconciliation, temporary creation, no-replace final or sidecar publication, and exact cleanup",
		"A cleanup whose pair proof fails retains its exact temporary",
	)

	currentContract := compactDocSection(t, contracts, "Exclusive descriptor-held claim refuses every pre-existing run-root object.", "The following Review-20/21/22 source-stage fixture requirements")
	assertContainsAll(t, "owning lifecycle result contract", currentContract,
		"Every successfully claimed root is retained",
		"Current capability-probe fixtures also remain",
		"Existing result directories and normalization evidence are validated without chown, chmod or adoption",
		"Fresh pair/topology qualification is a prerequisite for named result operations",
		"New unpublished result temporaries/records and newly created normalization evidence receive their selected owner/mode on creation",
		"private authenticated completion record before public result bytes are eligible",
		"A pre-existing unmarked final is never signed or adopted on retry",
	)
	systemResult := compactDocSection(t, systemContracts, "- ES result retention is independent of staging retention.", "- B2 preserves every public route")
	assertContainsAll(t, "system result ownership", systemResult,
		"Publication success, absence, conflict, or failure never authorizes staging mutation",
		"`.docs/execution_lifecycle/contracts.md`",
		"Pair proof is a prerequisite for permitted result operations, not existing-object repair or deletion authority",
		"New unpublished result objects may receive initial owner/mode",
		"existing directories, finals, and normalization evidence are checked without repair or adoption",
		"no whole-root reclamation authority is selected",
	)
	boundary := compactDocSection(t, boundaries, "The authoritative Workstream C classification of ES public execution surfaces", "**Current ownership**")
	assertContainsAll(t, "ES ownership boundary", boundary,
		"paired-root custody and authenticated final/record eligibility contract",
		"`.docs/execution_lifecycle/contracts.md`",
		"pair proof gates permitted ES result operations but grants no existing-object repair, pathname deletion, or cross-service reclamation authority",
	)
}

func TestPrivateReplayProgressSynchronizationInventoryDocsContract(t *testing.T) {
	t.Parallel()
	const guardPath = "es/admission/workstream_c_guardrails_test.go"
	const guardName = "TestExecutionSubstrateProductionHasNoA3LeaseRegistryOrPoisonDesign"
	file, err := parser.ParseFile(token.NewFileSet(), guardPath, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	want := make(map[string]string)
	for _, declaration := range file.Decls {
		fn, ok := declaration.(*ast.FuncDecl)
		if !ok || fn.Name.Name != guardName {
			continue
		}
		for _, statement := range fn.Body.List {
			assign, ok := statement.(*ast.AssignStmt)
			if !ok || len(assign.Lhs) != 1 || len(assign.Rhs) != 1 {
				continue
			}
			name, ok := assign.Lhs[0].(*ast.Ident)
			if !ok || name.Name != "wantSynchronizationFields" {
				continue
			}
			list, ok := assign.Rhs[0].(*ast.CompositeLit)
			if !ok {
				t.Fatal("expected the frozen synchronization inventory literal")
			}
			for _, item := range list.Elts {
				literal, ok := item.(*ast.BasicLit)
				if !ok || literal.Kind != token.STRING {
					t.Fatal("expected an exact typed field string")
				}
				field, err := strconv.Unquote(literal.Value)
				if err != nil || !strings.HasPrefix(field, "execution-substrate/es/") {
					t.Fatalf("invalid frozen typed field %q: %v", field, err)
				}
				field = strings.TrimPrefix(field, "execution-substrate/")
				category := "Reference"
				switch field[strings.LastIndexByte(field, ':')+1:] {
				case "sync.RWMutex", "sync.Mutex":
					category = "Lock"
				case "atomic.Bool":
					category = "Atomic"
				}
				if _, exists := want[field]; exists {
					t.Fatalf("duplicate frozen typed field %s", field)
				}
				want[field] = category
			}
		}
	}
	if len(want) != 55 {
		t.Fatalf("expected 55 exact structural fields, got %d", len(want))
	}
	admission := mustRead(t, ".docs/execution_lifecycle/es_execution_admission_model.md")
	section := docSection(t, admission, "### 7.4 Exact synchronized mutable-state inventory", "### 7.5 Rejected A3 topology inventory")
	if err := checkPrivateReplayProgressSynchronizationInventory(section, want); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, before, after, reason string
	}{
		{"MissingAtomic", "| Atomic | `es/admission/internal/reliablesubmit:progressAccessState.used:atomic.Bool` |", "", "missing exact field"},
		{"OmittedScope2Wrapper", "| Reference | `es/admission/internal/reliablesubmit:ProgressSealPermit.permit:reliablesubmit.PrivateReplaySealPermit` |", "", "missing exact field"},
		{"OmittedSharedPermitReader", "`PrivateReplayCustody.publishReplayOriginal`, `PrivateReplayProgressCustody.PublishProgressOriginal`", "`PrivateReplayProgressCustody.PublishProgressOriginal`", "permit roles"},
		{"ReferenceClaimedAsPrimitive", "| Reference | `es/admission/internal/reliablesubmit:ProgressAccess.state:*reliablesubmit.progressAccessState` |", "| Lock | `es/admission/internal/reliablesubmit:ProgressAccess.state:*reliablesubmit.progressAccessState` |", "wrong category"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if strings.Count(section, tc.before) != 1 {
				t.Fatalf("expected one document mutation target %q", tc.before)
			}
			target := tc.before
			if tc.after == "" {
				row := section[strings.Index(section, target):]
				target = row[:strings.IndexByte(row, '\n')+1]
			}
			err := checkPrivateReplayProgressSynchronizationInventory(strings.Replace(section, target, tc.after, 1), want)
			if err == nil || !strings.Contains(err.Error(), tc.reason) {
				t.Fatalf("expected %q rejection, got %v", tc.reason, err)
			}
		})
	}
}

func checkPrivateReplayProgressSynchronizationInventory(section string, want map[string]string) error {
	fields := make(map[string]string)
	counts := make(map[string]int)
	permits := make(map[string][2]string)
	permitRoles := map[string][2]string{
		"`PrivateReplaySealPermit.permit`": {
			"`PrivateReplayCustody.ReserveSealUse`, `PrivateReplayProgressCustody.ReserveProgressSealUse`, `OperationalCustody.EstablishOperational`",
			"`PrivateReplayCustody.publishReplayOriginal`, `PrivateReplayProgressCustody.PublishProgressOriginal`",
		},
		"`ProgressSealPermit.permit`": {
			"`PrivateReplayProgressCustody.ReserveProgressSealUse`",
			"`PrivateReplayProgressCustody.PublishProgressOriginal`",
		},
		"`privateSealPermit.used`": {
			"`privateSealPermit.consume`, `privateSealPermit.burn`",
			"`privateSealPermit.consume`, `privateSealPermit.matchesAllocation`",
		},
	}
	for _, line := range strings.Split(section, "\n") {
		if !strings.HasPrefix(line, "| ") {
			continue
		}
		cells := strings.Split(line, "|")
		category := strings.TrimSpace(cells[1])
		switch category {
		case "Lock", "Atomic", "Reference":
			if len(cells) < 3 {
				return fmt.Errorf("malformed synchronization row %q", line)
			}
			field := strings.Trim(strings.TrimSpace(cells[2]), "`")
			if want[field] != category {
				return fmt.Errorf("unexpected exact field or wrong category for %q: %s", field, category)
			}
			if (category == "Reference" && len(cells) != 5) || (category != "Reference" && len(cells) != 8) {
				return fmt.Errorf("malformed synchronization row %q", line)
			}
			if _, exists := fields[field]; exists {
				return fmt.Errorf("duplicate exact field %q", field)
			}
			fields[field] = category
			counts[category]++
		default:
			if _, expected := permitRoles[category]; !expected {
				continue
			}
			if _, exists := permits[category]; exists || len(cells) != 5 {
				return fmt.Errorf("duplicate or malformed permit roles for %q", category)
			}
			permits[category] = [2]string{strings.TrimSpace(cells[2]), strings.TrimSpace(cells[3])}
		}
	}
	for field := range want {
		if _, exists := fields[field]; !exists {
			return fmt.Errorf("missing exact field %q", field)
		}
	}
	if counts["Lock"] != 8 || counts["Atomic"] != 4 || counts["Reference"] != 43 {
		return fmt.Errorf("synchronization category counts differ: %v", counts)
	}
	for field, roles := range permitRoles {
		if permits[field] != roles {
			return fmt.Errorf("permit roles differ for %s", field)
		}
	}
	text := compactText(section)
	for _, rule := range []string{
		"non-test production source under `./es/...` and `./cmd/es/...`",
		"55 structurally synchronization-bearing fields: eight direct lock fields, four `atomic.Bool` fields, and 43 transitive reference, request or wrapper fields",
		"private replay path remains runtime-unwired",
		"SQLite owns committed claim, progress, key and grant/use state",
		"no package-level synchronization authority",
		"Reference carriers convey those same protections without independent authority",
		"confer no durable run truth, process-global state, lease, registry, poison subsystem, worker, or staging/results-root authority",
		"rejected A3 topology in §7.5 remains excluded",
	} {
		if !strings.Contains(text, rule) {
			return fmt.Errorf("missing synchronization boundary %q", rule)
		}
	}
	return nil
}

func TestPrivateOriginalReplayProgressContractSelection(t *testing.T) {
	plans := mustRead(t, plansRecordPath)
	adr := mustRead(t, ".docs/execution_lifecycle/reliable_submit_persistence_and_concurrency.md")
	submit := mustRead(t, ".docs/execution_lifecycle/submit_idempotency_correlation_and_recovery.md")
	admission := mustRead(t, ".docs/execution_lifecycle/es_execution_admission_model.md")

	selection := compactDocSection(t, plans,
		"## Post-PR #10 source publication and private replay progress contract candidate (2026-11-18)",
		"## Post-PR #9 source publication and A1 read cleanup selection (2026-11-18)")
	assertContainsAll(t, "proposed integrated selection", selection,
		"advances the SQLite head to schema 4", "immutable private codec 3",
		"independently versioned migration 4", "same ES SQLite authority",
		"Phase 1 is the local pooled `loadClaim` cleanup repair",
		"one fresh independent audit", "contains the pooled repair, schema 4, codec 4", "reader-only PR",
		"historical evidence", "allocator serves both fixture publishers",
		"K1 limits fixture proof to the current row and each invocation's own write disposition",
		"The full operational Validated No-Dispatch Evidence requirement remains unchanged",
	)

	prerequisite := compactDocSection(t, adr, "### 15B.1 Pooled loadClaim prerequisite and exit precedence",
		"### 15B.2 Complete logical row and original fields")
	assertContainsAll(t, "read prerequisite", prerequisite,
		"five-second deadline", "before self-cancel",
		"observed expiry even with nil response", "one bounded A1-equivalent rescue",
		"withhold the wrapper", "No post-attempt rollback or semantic read retry",
		"`loadClaimFresh`, its callers/lifetime", "Scope2 has no fresh-reader consumer",
	)
	row := compactDocSection(t, adr, "### 15B.2 Complete logical row and original fields",
		"### 15B.3 Existing transition model and exact operation identity")
	assertContainsAll(t, "immutable original and evolving row", row,
		"all 47 physical fields", "`claim_rowid`", "`plan_binding`",
		"`witness_resolved_mask`, `witness_inapplicable_mask`", "`replay_scope`",
		"`intent_commitment`, `context_commitment`", "`envelope_sha256`",
		"`run_ref` and assignment time", "`receipt_ref`", "`revision`",
		"`effect_intent_ref`", "`staging_ref`", "`dispatch_ref`",
		"`provider_observation_kind`", "`reconciliation_kind`",
		"Every sealed field is fixed at establishment", "current mutable facts never enter the sealed original",
	)
	decisions := compactDocSection(t, adr, "### 15B.3 Existing transition model and exact operation identity",
		"### 15B.5 Migration 4, physical constraints and compatibility")
	assertContainsAll(t, "authenticated progress and write uncertainty", decisions,
		"preserves codec 4 and scope 2", "dedicated mutable-only SQL",
		"before stale-revision", "Only exact full expected record confirms own commit",
		"The earlier write remains unknown", "Exact latest-operation replay is a separate query",
		"Evidenced not-applied or refused", "retain known commit and withhold projection",
	)
	reconciliation := compactDocSection(t, adr, "#### Codec-4 reconciliation records an observation of this attempt",
		"### 15B.4 Replay, contention and uncertainty decisions")
	assertContainsAll(t, "codec-specific reconciliation and first marker", reconciliation,
		"static owner/source mismatch", "Codec-1/2 checks and transitions",
		"preserve every byte of the prior reconciliation tuple", "phase 3 or 4–7",
		"NoDispatch (fixture no-marker observation)", "A new explicit op 5 is a storage-model transition",
		"Recheck this predicate against the current row in the CAS writer transaction",
		"`FixtureTerminalEvidence` is redacted and has private claim, run, marker, fact, outcome and receipt fields",
		"`NewFixtureAcceptedEvidence", "`NewFixtureNotAcceptedEvidence",
		"the separately constructed evidence receipt", "Candidate phase checks still follow latest replay classification",
		"The same complete predecessor as A", "A/B after later explicit first marker", "C accepted on one branch",
		"Old reconciliation mutation replayed", "Keep write unknown and withhold projection in that invocation",
	)
	k1 := docSection(t, adr, "#### K1 invocation scopes and operational gate", "### 15B.5 Migration 4, physical constraints and compatibility")
	scopeRules := []struct {
		name string
		rule string
	}{
		{
			"One write invocation and its recovery",
			"Preserve known commit, evidenced not-applied/refused, or unknown. Only an authenticated full expected record can confirm its own COMMIT during recovery. Unknown recovery performs no second semantic write, automatic fresh mutation, rebase or retry loop. A failed recovery withholds projection. Failed post-commit authentication withholds projection and preserves known commit.",
		},
		{
			"Later explicit fixture command",
			"A separately supplied command requires fresh original authentication, a new live one-use borrow and the caller's exact current expected revision and mutation input. Evaluate a new marker against the current persisted row. An absent marker does not resolve a prior unknown write. The fixture predicate does not establish the complete operational no-dispatch predicate.",
		},
		{
			"Later authenticated fixture read",
			"Current replay may project authenticated current fixture state. It does not resolve a prior unknown write or rewrite a known disposition. Exact latest replay describes the current descriptor, without confirming ownership of an earlier uncertain transaction.",
		},
		{
			"Operational dispatch or restart recovery",
			"A later explicit fixture command grants no operational permission. The selected codec-5 interpretation of §8 delegates present-state eligibility and sender proof to Operational Handoff. Fixture eligibility and write-disposition guarantees above remain unchanged.",
		},
	}
	checkScopeRules := func(section string) string {
		rows := make(map[string]string, len(scopeRules))
		for _, line := range strings.Split(section, "\n") {
			line = strings.TrimSpace(line)
			if !strings.HasPrefix(line, "|") || line == "| Scope | Guarantee |" || line == "| --- | --- |" {
				continue
			}
			cells := strings.Split(line, "|")
			if len(cells) != 4 || cells[3] != "" {
				return "malformed scope row"
			}
			name := strings.TrimSpace(cells[1])
			if _, exists := rows[name]; exists {
				return name
			}
			rows[name] = compactText(cells[2])
		}
		for _, expected := range scopeRules {
			if rows[expected.name] != expected.rule {
				return expected.name
			}
		}
		if len(rows) != len(scopeRules) {
			return "unexpected scope row"
		}
		return ""
	}
	if issue := checkScopeRules(k1); issue != "" {
		t.Fatalf("K1 invocation boundary differs at %q", issue)
	}
	for _, tc := range []struct {
		name        string
		before      string
		replacement string
		wantIssue   string
	}{
		{
			"K1FixtureClaimsOperationalPredicate",
			"The fixture predicate does not establish the complete operational no-dispatch predicate.",
			"The fixture predicate establishes the complete operational no-dispatch predicate.",
			"Later explicit fixture command",
		},
		{
			"K1CurrentReplayResolvesPriorUnknown",
			"It does not resolve a prior unknown write or rewrite a known disposition.",
			"It resolves a prior unknown write.",
			"Later authenticated fixture read",
		},
		{
			"K1AbsentMarkerResolvesPriorUnknown",
			"An absent marker does not resolve a prior unknown write.",
			"An absent marker resolves a prior unknown write.",
			"Later explicit fixture command",
		},
		{
			"K1AllowsAutomaticFreshMutationOrRebase",
			"Unknown recovery performs no second semantic write, automatic fresh mutation, rebase or retry loop.",
			"Unknown recovery may rebase and issue an automatic fresh mutation.",
			"One write invocation and its recovery",
		},
		{
			"K1OmitsFixtureAndOperationalDistinction",
			"A later explicit fixture command grants no operational permission. ",
			"",
			"Operational dispatch or restart recovery",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if strings.Count(k1, tc.before) != 1 {
				t.Fatalf("expected one K1 mutation target %q", tc.before)
			}
			mutant := strings.Replace(k1, tc.before, tc.replacement, 1)
			if got := checkScopeRules(mutant); got != tc.wantIssue {
				t.Fatalf("K1 mutant issue = %q, want %q", got, tc.wantIssue)
			}
		})
	}

	migration := compactDocSection(t, adr, "### 15B.5 Migration 4, physical constraints and compatibility",
		"### 15B.5A Shared fixture object allocator and budget boundaries")
	assertContainsAll(t, "append-only migration and compatibility", migration,
		"Preserve literal bytes and ledger hashes 1–3", "both full-row EXCEPT directions",
		"seven-character `sqlite_` prefix", "The validated lock-held version supplies the recovery baseline",
		"exact initial shape", "always reject codec3", "Exact authenticated recorded old shape",
		"TestSQLiteV3OldBinaryRefusesWithoutMutation", "A schema-2 binary result cannot qualify this schema-3 binary",
		"separate codec-4 historical tuple compatibility rule", "Sole semantic transition writer",
		"Classifies only the invocation and its own recovery",
		"No SQL digest validation, evidence authentication, prior-response history",
	)
	assertContainsAll(t, "migration pre-COMMIT recovery", migration,
		"against an authenticated lock-held baseline", "before self-cancel",
		"ROLLBACK reports that its wrapper is already closed",
		"checks the close result of the original unpublished pool before one fresh checked nonmigrating observation on the caller context",
		"That observation alone classifies the old or current state",
		"This pre-COMMIT route records zero COMMIT attempts",
		"returns recovered-old refusal and closes the observation pool", "Recovery issues no migration retry",
	)

	allocator := compactDocSection(t, adr, "### 15B.5A Shared fixture object allocator and budget boundaries",
		"### 15B.6 Prospective source and test map")
	assertContainsAll(t, "count/create ownership and cleanup", allocator,
		"`PublishSealedSynthetic` (scope 1)", "`PublishProgressOriginal` (scope 2)", "`allocateReplayObject`",
		"before BEGIN dispatch", "request-independent private five-second", "immediately before self-cancel",
		"withhold ordinary `Conn.Close`", "inert counted orphan", "Then run the existing permit consumption",
		"Four custody-bearing claim slots", "32 object names", "32 aggregate durable reservations",
		"2^32 reservations per envelope key", "16 MiB database/sidecar budget",
	)
	format := compactDocSection(t, submit, "### 6B. Proposed private original replay and durable claim progress",
		"## 7. Narrow Durable Correlation Semantics")
	assertContainsAll(t, "format, private interface and nonclaims", format,
		"SQL schema and per-row codec are separate version axes",
		"`synthetic_nonoperational_v1` / 1", "`synthetic_progress_nonoperational_v1` / 2",
		"`ESRSPAY2`", "`ESRSENV2`", "`ESRSAAD2`", "`ESRSINT2`", "`ESRSCTX2`", "`ESRSFRZ2`",
		"AEAD authenticates only the immutable original", "`ProgressOriginalView`",
		"`WithAuthenticatedProgressOriginal", "`ApplyFixtureProgress", "full-record getter or verified boolean",
		"Scope 1 participates in serialized", "bounded fixture no-marker observation and supplies no operational permission",
		"The attempt expires when that invocation returns", "It cannot change the earlier disposition",
		"Public structural reliable-request refusal and unkeyed Submit stay in force",
	)
	authority := compactDocSection(t, admission, "### Private replay progress candidate classification", "### 4E. Reopened seams")
	assertContainsAll(t, "admission ownership and effect ceiling", authority,
		"fixture-only and effect-ineligible at every phase", "Admission owns typed original",
		"Custody owns sealed bytes", "existing durable service owns semantic transition checks",
		"SQLite enforces persisted shape, CAS and storage deltas",
		"earlier invocation's write disposition unchanged", "cross-restart authority lies outside this fixture slice",
		"authentication-before-existence-disclosure", "Nomad owns the current accepted-execution lifecycle",
	)
	acceptance := compactDocSection(t, adr, "### 15B.6 Prospective source and test map", "## 16. Explicit Non-Claims And Open Decisions")
	assertContainsAll(t, "prospective acceptance map", acceptance,
		"TestSQLitePooledClaimReadCleanup", "TestSQLiteV4PreviousSchema3BinaryRefusesWithoutMutation",
		"TestPrivateReplayProgressConcurrencyAndCommitOutcome", "TestPrivateReplayProgressHasNoEffectPaths",
		"FixtureNoMarkerThenFirstMarkerAfterRestart", "UnknownMarkerCommitDoesNotRetryWithinInvocation",
		"IndistinguishableRestartHistoriesHaveSameFixtureEligibility", "ExplicitLaterFixtureCommandDoesNotConfirmPriorUnknown",
		"CurrentReplayDoesNotConfirmPriorUnknown", "ExistingMarkerExactReplayOnly",
		"TestPrivateReplaySharedObjectAllocation", "CrossSelectorFinalSlotHelperProcess",
		"cd \"$SCHEMA3_SOURCE\" || exit", "workspace-off cached module graph",
		"Command results belong to a separately bound source generation and evidence record",
		"Consolidated repair path map", "TestPrivateReplayProgressAdmissionUnknownNoEffects",
		"executes real COMMIT, reports the modeled response failure",
	)
}

func TestIntegratedAcceptanceGateDocumentationIsConsistent(t *testing.T) {
	admissionRules := mustRead(t, standingAdmissionRulesPath)
	record := mustRead(t, plansRecordPath)
	contracts := mustRead(t, ".docs/execution_lifecycle/contracts.md")
	design := mustRead(t, ".docs/execution_lifecycle/design.md")
	implementation := mustRead(t, ".docs/execution_lifecycle/implementation.md")
	capabilities := mustRead(t, ".docs/system_overview/capability_probing.md")
	remoteAlpha := mustRead(t, ".docs/system_overview/remote_supported_host_alpha.md")
	linuxQualification := mustRead(t, ".docs/system_overview/supported_linux_host_qualification.md")

	currentStatus := compactDocSection(t, record, "## Post-PR #10 source publication and private replay progress contract candidate (2026-11-18)", "## Post-PR #9 source publication and A1 read cleanup selection (2026-11-18)")
	assertContainsAll(t, "integration status", currentStatus,
		"PR #10 completed A1 source publication",
		"f1aa8b934cc26c16a966a110c7b408abdaeadce7",
		"8dd27f9acba98ed70d93736bdef8300ef1aba53f",
		"public reliable-submit authority",
		"K1 owner contract was selected for bounded implementation",
	)
	priorStatus := compactDocSection(t, record, "## Post-PR #9 source publication and A1 read cleanup selection (2026-11-18)", "## Historical current-remote-base private synthetic replay custody selection (2026-11-17)")
	assertContainsAll(t, "prior integration status", priorStatus,
		"2478a24a18852f1abd7d474c0525c46bd2c05e5e",
		"e7defd3a0df278ad70762f17f0f2a5b1c14a795b",
		"fb9ae55797d9fcc02863c23fe8d3e43d16eac542",
		"be8437c8ce48cbcbed53f60a03810283abbd9235",
		"PR #9 completed source publication of O2",
		"A1 original-key read cleanup",
		"synthetic_nonoperational_v1", "runtime-unwired", "effect-ineligible",
		"unavailable as public reliable Submit", "official `trunk_dev`",
		"does not qualify operational behavior",
		"does not itself supply independent acceptance or runtime qualification",
	)
	historicalStatus := compactDocSection(t, record, "## Historical current-remote-base private synthetic replay custody selection (2026-11-17)", "## Superseded Remote Alpha Operator Facade Routes")
	assertContainsAll(t, "historical integration selection", historicalStatus,
		"effect-free existing-host route retirements",
		"At that point, development acceptance, a later commit, operational rollout, and publication were distinct decisions",
	)
	foundation := compactDocSection(t, mustRead(t, standingAdmissionRulesPath), "**Acceptance boundaries selected on 2026-11-13:**", "")
	assertContainsAll(t, "C foundation acceptance scope", foundation,
		"exact authenticated implementation and selected observations",
		"A local source-preservation commit is a separate, explicitly authorized effect",
		"Environment-bound operational/rollout acceptance remains open",
	)
	currentGate := compactDocSection(t, admissionRules, "### Current paired-root custody and acceptance scope", "**Current invariant — staging non-mutation and retained-output independence.**")
	assertContainsAll(t, "current integrated gate", currentGate,
		"**Superseded CUST-1/CUST-2 gate history.**",
		"That pre-integration linkage is not a current local commit rule",
		"then-current-base candidate, which at that gate remained uncommitted and",
		"Focused changed-interaction assessment, validation, and separately authorized commit were required there",
		"C's selected native observations remain historical evidence for exact C source and command identities, not executions of this tree",
		"Any new bounded witness must be selected for a concrete changed interaction rather than inferred from merge ancestry",
		"Operational topology, key exposure, capacity, residence, reclamation, and publication gates remain open for their operational scope",
		"one-time WIP checkpoint exception is consumed",
	)
	assertContainsNone(t, "old current blanket gate", currentGate,
		"The running-deployment observation and mounted fixtures remain pre-final-acceptance and pre-commit gates",
		"Until all of those gates are complete, these bytes are an implementation candidate",
	)
	classification := compactDocSection(t, admissionRules, "**Current invariant — staging non-mutation and retained-output independence.**", "Linux binds each held descriptor")
	assertContainsAll(t, "safety and bounded-rule classification", classification,
		"Result retention, publication, and read do not mutate a claimed staging root",
		"**Bounded slice rule pending integrated review — paired-root qualification.**",
	)
	fixtureGate := compactDocSection(t, admissionRules, "**App-fixture migration and local revalidation scope.**", "**CUST-2 nsfs assurance continuation.**")
	assertContainsAll(t, "fixture evidence scope", fixtureGate,
		"does not qualify an operational deployment",
		"do not collectively become a blanket local pre-commit requirement",
	)
	assertContainsNone(t, "obsolete fixture blanket gate", fixtureGate, "all remain pre-final-acceptance and pre-commit gates")

	lifecycleStatus := compactDocSection(t, contracts, "## H/C/T integration candidate status and exact boundary", "## 1. Purpose and status")
	assertContainsAll(t, "owning lifecycle status", lifecycleStatus,
		"This uncommitted source is unaccepted",
		"C's dated exact-source development acceptance",
		"T is a preservation-only WIP",
		"requires changed-interaction review",
		"paired-root topology contract is a **Bounded slice rule pending integrated review**",
		"operational key/topology/capacity/residence/reclamation gates",
	)
	designGate := compactDocSection(t, design, "Local implementation and modeled tests do not establish mounted or deployment", "")
	assertContainsAll(t, "design evidence scope", designGate,
		"C's selected native observations were historical exact-C evidence, not executions of the then-unaccepted integrated tree",
		"focused independent changed-interaction assessment may still select a new bounded witness for a concrete operating claim",
		"Running-deployment topology, key isolation, capacity, residence, reclamation, publication, and native qualification for claimed architectures remain gates for their operational scope",
		"not blanket local pre-commit conditions",
	)
	assertContainsNone(t, "obsolete design gate", designGate, "remain pre-final gates; their timing was deferred")
	implementationGate := compactDocSection(t, implementation, "The current stable-service-namespace/trusted-operator assumption is explicit:", "")
	assertContainsAll(t, "implementation evidence scope", implementationGate,
		"C's selected native observations remain historical exact-source evidence",
		"Focused changed-interaction review/validation and a separately authorized commit were pending at that gate",
		"remain operational gates for claimed environments",
		"not a blanket local source-preservation or integration commit gate",
	)
	assertContainsNone(t, "obsolete implementation gate", implementationGate, "remain pending acceptance gates")
	capabilityGate := compactDocSection(t, capabilities, "Local modeled records and ordinary filesystem tests do not prove mounted bind", "## Example: Execution-root custody")
	assertContainsAll(t, "capability evidence scope", capabilityGate,
		"C's selected native observations remain historical exact-source evidence, not integrated-source execution",
		"operational qualification gates for claimed environments",
		"A new integrated-source bounded witness requires a concrete changed-interaction selection",
	)
	capabilityCommit := compactDocSection(t, capabilities, "Darwin syscall tests are current local runtime evidence.", "## Test Harness Use")
	assertContainsAll(t, "capability commit scope", capabilityCommit,
		"not an automatic local source-preservation or integration pre-commit gate",
		"no integrated native qualification or narrower architecture claim is inferred",
	)
	assertContainsNone(t, "obsolete capability blanket gate", capabilityCommit, "before final combined audit and commit")

	remoteGate := compactDocSection(t, remoteAlpha, "### Current Remote Alpha root-custody observation gate", "It is not the final commercial deployment target.")
	assertContainsAll(t, "current Remote Alpha operating gate", remoteGate,
		"one concrete currently running in-scope ES process",
		"process/start identity, mount namespace, configured roots, held descriptor identities",
		"selected mount records, source coordinates, root-value classification, and descendant-mount result",
		"Historical `es.service` prose, launcher source, and modeled mountinfo are not observations",
		"retain unrelated valid opaque `nsfs` namespace-object records for complete analysis",
		"refusing an opaque selected root as a pathname-coordinate source",
		"must not filter away records or substitute mountpoint or configured spelling for source coordinates",
		"Real repaired-helper mounted-alias evidence remains required where the operational claim depends on it",
		"`.docs/standing_rules/execution_admission_and_custody.md` and `.docs/execution_lifecycle/contracts.md`",
		"not an independent blanket prerequisite to a separately authorized local",
		"the H/C/T integrated source was unaccepted",
		"focused changed-interaction assessment and explicit commit authority",
		"merge ancestry alone does not create a blanket native campaign",
		"No current deployment compatibility, supported-host claim, or rollout readiness is inferred here",
	)
	assertContainsNone(t, "superseded Remote Alpha blanket local gate", remoteGate,
		"The observation and real repaired-helper mounted alias fixtures remain pre-final-acceptance and pre-commit gates",
	)

	linuxGate := compactDocSection(t, linuxQualification, "### Tranche A filesystem-custody validation posture", "## 4. Explicit Disqualifiers")
	assertContainsAll(t, "current Linux operating gate", linuxGate,
		"Historical Tranche A sequencing allowed a fresh read-only audit",
		"does not impose a blanket native pre-commit gate on local source preservation or integration",
		"`.docs/standing_rules/execution_admission_and_custody.md` and `.docs/execution_lifecycle/contracts.md`",
		"governed Ubuntu 24.04 linux/amd64 for Remote Alpha and governed Ubuntu 24.04 linux/arm64 for supported-local",
		"`openat2` with beneath, no-magic-link, no-symlink, and no-cross-device resolution",
		"`renameat2(RENAME_NOREPLACE)` collision behavior",
		"exclusive run-root claim and descriptor-held identity custody",
		"an actual mount-crossing refusal",
		"Cross-compilation is compile evidence only and cannot replace those runtime observations",
		"Darwin behavior, a fake filesystem, containers running a different kernel or architecture, and an OS label cannot replace them either",
		"C's selected native programme remains historical evidence for its exact source and environments, not an execution of the then-unaccepted H/C/T integrated tree",
		"Evidence reuse or a new bounded witness depends on the concrete changed interaction and operating claim",
		"report that operating claim as pending rather than supported by inference",
		"Neither the Remote Alpha amd64 nor supported-local arm64 claim is narrowed",
		"not an automatic prerequisite to a separately authorized local source-preservation or integration commit",
	)
	assertContainsNone(t, "superseded Linux blanket local gate", linuxGate,
		"Before final combined ES audit and commit",
		"Until both claimed-architecture runtime executions pass",
	)

	archiveAndRoots := compactMarkedDocSection(t, "final-audit archive and execution-root contract", contracts, "## 19. Final-audit archive and execution-root contract refinements", "")
	assertContainsAll(t, "section 19 retained custody and archive requirements", archiveAndRoots,
		"one invocation-local iterative compressed byte-radix namespace ledger",
		"File ancestry is recognized only across a `/` boundary",
		"one operation-local qualified root set",
		"Canonical descriptor identity and platform topology must reject equality and either-direction ancestry",
		"Complete source-valid `nsfs` records with opaque namespace-object roots remain in snapshot integrity and descendant checks",
		"an opaque selected root refuses before coordinate arithmetic or effects",
		"Ambiguous dual-missing roots fail closed",
		"topology failure does not fall through to Nomad",
	)
	assertContainsAll(t, "section 19 local and operational acceptance split", archiveAndRoots,
		"Modeled topology tests do not claim an actual bind or casefold mount",
		"historical evidence for exact C source and its environments, not executions of the then-unaccepted integrated tree",
		"T and that candidate did not inherit C's development acceptance",
		"At that gate, local source or integration acceptance required focused candidate-specific changed-interaction assessment and validation",
		"followed by separate explicit commit authority",
		"Running-deployment topology observation for a claimed Remote Alpha environment",
		"real repaired-helper mounted-alias fixtures where the operational claim depends on them",
		"native syscall and mount-crossing evidence for each claimed Linux operating architecture",
		"not an independent blanket prerequisite to a separately authorized local commit",
		"A concrete uncovered changed interaction or operating claim may require a separately selected bounded witness",
		"merge ancestry alone does not create a blanket native campaign",
		"No integrated native observation, supported-host qualification, or rollout readiness is inferred here",
		"Operational topology, key exposure, capacity, sensitive-material residence, reclamation, and publication gates remain open",
		"`.docs/standing_rules/execution_admission_and_custody.md` under \"Current paired-root custody and acceptance scope\"",
	)
	assertContainsNone(t, "superseded section 19 blanket commit linkage", archiveAndRoots,
		"and independent audit remain required before final acceptance or commit",
	)
}

func TestIntegratedCandidateStatusSeparatesCAndT(t *testing.T) {
	admissionRules := mustRead(t, standingAdmissionRulesPath)
	record := mustRead(t, plansRecordPath)
	contracts := mustRead(t, ".docs/execution_lifecycle/contracts.md")
	section := func(body, heading string) string {
		t.Helper()
		at := strings.Index(body, heading)
		if at < 0 {
			t.Fatalf("missing owning heading %q", heading)
		}
		body = body[at+len(heading):]
		if end := strings.Index(body, "\n## "); end >= 0 {
			body = body[:end]
		}
		return body
	}
	current := section(record, "## Historical current-remote-base H/C/T foundation selection (2026-11-17)")
	contract := section(contracts, "## H/C/T integration candidate status and exact boundary")
	for _, required := range []string{
		"reviewed H/C/T foundation tree", "preservation-only T commit",
		"effect-free existing-host route retirements", "one-time checkpoint exception is consumed",
		"At that point, development acceptance, a later commit, operational rollout, and publication were distinct decisions",
		"Reliable submit remains unavailable and runtime-unwired",
	} {
		if !strings.Contains(current, required) {
			t.Errorf("candidate plan status missing %q", required)
		}
	}
	if !strings.Contains(admissionRules, "**Acceptance boundaries selected on 2026-11-13:**") {
		t.Error("dated C acceptance boundary was lost")
	}
	for _, required := range []string{
		"This uncommitted source is unaccepted", "C's dated exact-source development acceptance",
		"T is a preservation-only WIP", "consumed one-time checkpoint exception",
		"requires changed-interaction review", "operational key/topology/capacity/residence/reclamation gates",
	} {
		if !strings.Contains(contract, required) {
			t.Errorf("lifecycle contract status missing %q", required)
		}
	}
}

func TestResolvedPlanCustodyCandidateDocumentation(t *testing.T) {
	admissionRules := compactText(mustRead(t, standingAdmissionRulesPath))
	contract := compactText(mustRead(t, ".docs/execution_lifecycle/contracts.md"))
	implementation := compactText(mustRead(t, ".docs/execution_lifecycle/implementation.md"))
	capabilities := compactText(mustRead(t, ".docs/system_overview/capability_probing.md"))
	configuration := compactText(mustRead(t, ".docs/system_overview/configuration.md"))
	model := compactText(mustRead(t, ".docs/execution_lifecycle/es_execution_admission_model.md"))
	for _, required := range []string{
		"resolved-execution-plan-extraction-foundation",
		"one owned execution/placement configuration snapshot",
		"not an atomic snapshot of earlier admission",
		"Duplicate regular destinations",
		"GNU sparse file representations are unsupported",
		"component whitespace exposed by cleaning is significant",
		"private custody-placement value",
		"results root is outside the semantic plan",
		"Review-19 A2/material-capture and focused composition source acceptance",
		"linux/amd64 and linux/arm64",
		"test-owned installed-mount witness",
		"Acceptance boundaries selected on 2026-11-13",
		"reclamation gap",
		"Two missing roots under the same deepest existing lookup context reject",
		"private authenticated completion record",
	} {
		if !strings.Contains(admissionRules, required) {
			t.Fatalf("admission standing rules missing candidate rule %q", required)
		}
	}
	if !strings.Contains(standingRuleSection(t, standingAdmissionRulesPath, pairedRootCustodyHeading), "No result pathname cleanup or whole-root reclamation is selected") {
		t.Fatal("paired-root custody standing rules missing candidate rule \"No result pathname cleanup or whole-root reclamation is selected\"")
	}
	for _, required := range []string{
		"32 MiB for primary Submit payload",
		"64 MiB aggregate",
		"524,289 bytes",
		"one Nomad registration",
		"no-replace publication",
		"fstat/statx mount ID",
		"Current capability-probe fixtures also remain",
		"Structural `reliable_submit` bodies remain strictly rejected",
		"one effective",
		"16 MiB",
		"additional compressed gzip member/bytes",
		"GNU sparse representations are outside the current static-script archive contract",
		"without re-trimming it",
		"execution-substrate.reliable-submit-request/v1",
		"execution-substrate.reliable-submit/v1",
	} {
		if !strings.Contains(contract, required) {
			t.Fatalf("Submit contract missing %q", required)
		}
	}
	if !strings.Contains(implementation, "After admission succeeds") ||
		!strings.Contains(implementation, "does not atomically capture earlier admission") ||
		!strings.Contains(model, "duplicate canonical regular destinations") {
		t.Fatal("admission interpretation or snapshot ordering documentation missing")
	}
	if !strings.Contains(model, "every returned header with a `GNU.sparse.*` PAX") ||
		!strings.Contains(model, "passed unchanged to the runtime path resolver") {
		t.Fatal("sparse or once-only destination contract missing")
	}
	if !strings.Contains(capabilities, "Configured Submit startup validates the staging/results root pair") ||
		!strings.Contains(configuration, "one normalized pair from one configuration snapshot") ||
		!strings.Contains(model, "temporary compatibility edge") {
		t.Fatal("capability, configuration, or admission-model candidate classification missing")
	}
}

func TestFoundationAcceptanceBoundaryDocumentation(t *testing.T) {
	section := func(path, start, end string) string {
		t.Helper()
		content := mustRead(t, path)
		begin := strings.Index(content, start)
		if begin < 0 {
			t.Fatalf("%s missing section start %q", path, start)
		}
		remaining := content[begin+len(start):]
		finish := strings.Index(remaining, end)
		if finish < 0 {
			t.Fatalf("%s missing section end %q", path, end)
		}
		return compactText(content[begin : begin+len(start)+finish])
	}
	require := func(label, content string, phrases ...string) {
		t.Helper()
		for _, phrase := range phrases {
			if !strings.Contains(content, phrase) {
				t.Fatalf("%s missing foundation boundary %q", label, phrase)
			}
		}
	}

	status := section(standingAdmissionRulesPath, "**2026-11-13 Review-22 development-source disposition:**", "**Bounded material and custody rules:**")
	require("dated development status", status,
		"DEVELOPMENT_SOURCE_FOUNDATION_ACCEPTED",
		"3e89fa9e0b7cc788e2b6c829ea25af00ea6a37b57f249e84d2b98c918511ad65",
		"d108e59ed5a9708bfd38c08f0d9202263fb5207e1d6522772181421ddd4b718d",
		"documentation-only successor retains those implementation bytes",
		"original source and command identities",
		"r22-20261113-arm64-n5-71ce04a8",
		"Review-17's accepted 23-phase supported-local compatibility proof applies only to its original source and inputs",
		"Process status remains PARTIAL",
		"post-N5 recursive allocation was intentionally unmeasured")
	boundaries := section(standingAdmissionRulesPath, "**Acceptance boundaries selected on 2026-11-13:**", "Tranche B1, `ES-B1-SEMANTIC-OWNERSHIP-COMMAND`")
	require("admission standing rules acceptance boundaries", boundaries,
		"not final product acceptance",
		"It grants no staging, cleanup, Git, integration, publication or deployment effect",
		"A local source-preservation commit is a separate, explicitly authorized effect",
		"exact candidate, index and intended commit contents are reauthenticated",
		"Integration into another checkout or branch, merge, remote publication and rollout require separate authority",
		"origin/trunk_dev` tracking ref is not current remote truth",
		"Environment-bound operational/rollout acceptance remains open",
		"named environment and architecture",
		"actual service/operator/workload trust and permission relationships",
		"running mount/source paths and backing-object observations",
		"actual key exposure and isolation",
		"selected and enforced accumulated-root/result/probe capacity",
		"explicit reclamation owner",
		"temporary qualification scratch limits are not an ES product retention policy",
		"Before expanded or unattended workload operation",
		"reliable-submit-unavailable guards remain in force")
	contract := section(".docs/execution_lifecycle/contracts.md", "### Development-source foundation and acceptance boundaries", "Selected Submit-path fixed operational messages")
	require("lifecycle acceptance contract", contract,
		"DEVELOPMENT_SOURCE_FOUNDATION_ACCEPTED",
		"not a historical native execution identity",
		"no standing workload or feature/producer enablement",
		"reliable-submit availability",
		"A local source-preservation commit is a separate, explicitly authorized effect",
		"Development evidence alone grants no Git effect",
		"Environment-bound operational/rollout acceptance remains open",
		"actual running mount/source paths and backing objects",
		"key exposure and isolation, including physical aliases and relevant same-UID contexts",
		"selected and enforced accumulated-root/result/probe capacity",
		"explicit reclamation owner",
		"4 GiB task cap and 8 GiB free-space gate, are not an ES product retention policy",
		"No target, trust model, TTL, numeric product cap, cleanup authority or successful deployment-key-isolation result is selected here")
	keyGate := section(".docs/execution_lifecycle/contracts.md", "Static file checks", "Key exclusion uses")
	require("environment-bound key gate", keyGate,
		"Actual key isolation and exposure remain environment-bound",
		"Development-source acceptance does not establish deployment isolation")
	history := section(".docs/execution_lifecycle/contracts.md", "The following Review-20/21/22 source-stage fixture requirements", "### Development-source foundation and acceptance boundaries")
	require("historical fixture status", history,
		"historical",
		"N5 and arm64 did not run",
		"no v2 identity record")
	capability := section(".docs/system_overview/capability_probing.md", "The 2026-11-13 current evidence overlay", "The selected R1 record protocol")
	require("capability evidence scope", capability,
		"selected linux/amd64 and linux/arm64 N1-N5 native programme",
		"historical Review-21 report",
		"test-owned witness does not observe the running deployment",
		"old resource refusal's first offending entry remains unknown")
	implementation := section(".docs/execution_lifecycle/implementation.md", "This candidate has no whole-root", "## 2. How to read this document")
	require("implementation evidence scope", implementation,
		"Selected native Linux and test-owned installed-source evidence is accepted",
		"actual running-deployment topology, key exposure and operating capacity/residence remain unqualified")
	model := section(".docs/execution_lifecycle/es_execution_admission_model.md", "### Isolated candidate classification", "### 4E. Reopened seams")
	require("admission model boundary", model,
		"All-claimed-root retention is a temporary compatibility edge",
		"Actual running-deployment topology, key exposure and capacity/residence enforcement remain environment-bound",
		"no admission or Submit authority changes here")
	configuration := section(".docs/system_overview/configuration.md", "- `execution.staging_root_dir`", "- the runtime identity contract no longer")
	require("configuration operating scope", configuration,
		"before environment-bound operational/rollout acceptance",
		"capacity and residence bounds must be selected and enforced",
		"actual deployment isolation/exposure, key loss and rotation remain environment-bound operational/rollout acceptance gates",
		"no recovery or rotation behavior is selected here")
	runbook := section(".docs/supported_local_cp_consumer_runbook.md", "The 2026-11-13 development-source evidence overlay", "## 3. Ownership boundaries")
	require("historical supported-local proof", runbook,
		"Review-17 23-phase canonical supported-local compatibility proof only for its original source and inputs",
		"Review-16 bundle limit above remains its historical source-stage statement",
		"not rewritten as a Review-22 canonical run",
		"there is no automatic proof inheritance or default repeat")
}

func TestRetainedResultAuthProtocolDocsContract(t *testing.T) {
	admissionRules := compactText(mustRead(t, standingAdmissionRulesPath))
	contract := compactText(mustRead(t, ".docs/execution_lifecycle/contracts.md"))
	implementation := compactText(mustRead(t, ".docs/execution_lifecycle/implementation.md"))
	configuration := compactText(mustRead(t, ".docs/system_overview/configuration.md"))
	capabilities := compactText(mustRead(t, ".docs/system_overview/capability_probing.md"))
	for _, required := range []string{
		"R1 is selected for a candidate-only refinement",
		"private authenticated completion record",
		"pre-existing unmarked final",
		"not a migration policy",
		"Reliable submit remains unavailable",
	} {
		if !strings.Contains(admissionRules, required) {
			t.Fatalf("admission standing rules missing retained result rule %q", required)
		}
	}
	for _, required := range []string{
		"execution.retained_result_auth.store_id",
		"exactly 32 raw bytes",
		"es-retained-result-commit-v1",
		"result.commit.v1",
		"at most 512 bytes",
		"crypto/hmac.Equal",
		"buffered response bytes",
		"never signed or adopted",
		"409 result_unavailable",
		"404 result_not_found",
		"not anti-rollback",
	} {
		if !strings.Contains(contract, required) {
			t.Fatalf("result contract missing %q", required)
		}
	}
	if !strings.Contains(implementation, "hashes the compressed writer output") ||
		!strings.Contains(configuration, "execution.retained_result_auth") ||
		!strings.Contains(capabilities, "behavior rather than OS label") {
		t.Fatal("implementation, configuration, or capability protocol rule missing")
	}
}

func TestRetainedResultAuditF2CurrentClaimedRootRetentionDocs(t *testing.T) {
	section := func(path, start, end string) string {
		t.Helper()
		content := mustRead(t, path)
		first := strings.Index(content, start)
		if first < 0 {
			t.Fatalf("%s missing section start", path)
		}
		last := strings.Index(content[first:], end)
		if last < 0 {
			t.Fatalf("%s missing section end", path)
		}
		return compactText(content[first : first+last])
	}
	contract := section(".docs/system_overview/contracts.md", "- ES result retention is independent of staging retention.", "- Lifecycle is Nomad-backed only:")
	for _, required := range []string{"every post-claim outcome retains that visible root", "materialization error", "registration failure or ambiguity", "terminal success/failure/cancel/loss", "result-publication failure", "Closing held descriptors does not delete it", "sensitive-material residence"} {
		if !strings.Contains(contract, required) {
			t.Fatalf("system contract missing retained-root rule %q", required)
		}
	}
	for _, forbidden := range []string{"Failed submit staging is cleaned immediately", "only while the workload may still depend"} {
		if strings.Contains(contract, forbidden) {
			t.Fatalf("system contract retains contradictory current rule %q", forbidden)
		}
	}
	recovery := section(".docs/execution_lifecycle/submit_idempotency_correlation_and_recovery.md", "### B. ES-To-Nomad Ambiguity", "## 4. Authority And Identity Ownership")
	if !strings.Contains(recovery, "retains the complete staging root") ||
		strings.Contains(recovery, "may clean staging because submitted was not confirmed") {
		t.Fatal("recovery contract misstates current unkeyed retention")
	}
	runbook := section(".runbooks/system/Governed Execution ES System Bring-Up.md", "| Failure class |", "The collector accepts")
	for _, required := range []string{"every successfully claimed", "terminal success", "descriptor close does not delete"} {
		if !strings.Contains(runbook, required) {
			t.Fatalf("bring-up runbook missing retention rule %q", required)
		}
	}
	for _, forbidden := range []string{"terminal success may remove", "only useful after a successful", "best-effort removes that staging root"} {
		if strings.Contains(runbook, forbidden) {
			t.Fatalf("bring-up runbook retains contradictory rule %q", forbidden)
		}
	}
	loop := section(".runbooks/system/Governed Execution ES System Bring-Up.md", "Because that helper waits for terminal status", "Keep host qualification and smoke proof distinct:")
	if !strings.Contains(loop, "retains every successfully claimed staging root") ||
		strings.Contains(loop, "best-effort removes that staging root") {
		t.Fatal("bring-up execution-loop passage misstates current retention")
	}
}

func TestRetainedResultAuditF1F3OperatorReferenceAndPlacementDocs(t *testing.T) {
	admissionRules := compactText(mustRead(t, standingAdmissionRulesPath))
	config := compactText(mustRead(t, ".docs/system_overview/configuration.md"))
	contract := compactText(mustRead(t, ".docs/execution_lifecycle/contracts.md"))
	runbook := compactText(mustRead(t, ".docs/supported_local_cp_consumer_runbook.md"))
	for _, phrase := range []string{"returned BLOCK", "configured-consumer compatibility", "key-placement validation", "requires new independent assessment"} {
		if !strings.Contains(admissionRules, phrase) {
			t.Fatalf("admission standing rules missing audit status %q", phrase)
		}
	}
	for _, content := range []string{config, contract, runbook} {
		for _, phrase := range []string{"non-root parent", "guest-local", "key-file reference"} {
			if !strings.Contains(content, phrase) {
				t.Fatalf("operator/key contract missing %q", phrase)
			}
		}
	}
}

func TestRetainedResultReview04ConsumerEntrypointAndOwnedScopeDocs(t *testing.T) {
	admissionRules := compactText(mustRead(t, standingAdmissionRulesPath))
	configuration := compactText(mustRead(t, ".docs/system_overview/configuration.md"))
	contract := compactText(mustRead(t, ".docs/execution_lifecycle/contracts.md"))
	implementation := compactText(mustRead(t, ".docs/execution_lifecycle/implementation.md"))
	runbook := compactText(mustRead(t, ".docs/supported_local_cp_consumer_runbook.md"))
	for _, phrase := range []string{"F1", "bash -s -- setup", "clean single-leading-slash", "F2 retention and F3 key-parent fixes remain in force", "independent assessment"} {
		if !strings.Contains(admissionRules, phrase) {
			t.Fatalf("Review-04 follow-up plan missing %q", phrase)
		}
	}
	for _, document := range []string{configuration, contract, implementation, runbook} {
		for _, phrase := range []string{"single-leading-slash", "non-root", "sourcing"} {
			if !strings.Contains(strings.ToLower(document), phrase) {
				t.Fatalf("supported-local boundary document missing %q", phrase)
			}
		}
	}
}

func TestStartupProbeUseAgreementDocsContract(t *testing.T) {
	checks := []struct {
		path    string
		phrases []string
	}{
		{standingAdmissionRulesPath, []string{"`STARTUP-PROBE-USE-AGREEMENT-01` (bounded slice rule)", "staging refuses any mode outside it, so a new staging mode cannot skip the probe", "only the second rename proves the primitive", "ES also never changes the owning user of a directory it opened by name", "`staging probe directory does not belong to the execution roots' owning user`", "The probe retains 13 entries per start", "ES also refuses to start on a staging file system that cannot keep those modes although submissions without governed mounts would work there", "ES starts only where every submission it accepts can be staged", "a bindfs mount with `--create-for-user`, is refused although it started before this rule"}},
		{".docs/system_overview/capability_probing.md", []string{"Staging refuses any mode the probe does not stage.", "a results file system whose rename accepts no flags refuses startup instead of losing every result", "it never changes an owning user", "prove the results no-replace rename both ways", "a staging file system that cannot keep them refuses startup even though submissions without governed mounts would work there"}},
		{".docs/execution_lifecycle/implementation.md", []string{"(`probeStagedEntries`)", "(`probeRetainedResultFiles`)", "(`requireOpenedDirectoryOwnedByRootsUser`)", "onto an existing name, which must fail with `EEXIST`", "startup refuses a staging file system that cannot keep them even when no submission would use governed mounts"}},
		{".runbooks/system/Governed Execution ES System Bring-Up.md", []string{"the file system under the roots stores the modes ES gives files and directories, gives regular files the same device as directories, and supports the no-replace rename", "`no-replace rename to a free result name is unavailable`", "ES refuses such a file system even if your submissions never use governed mounts"}},
		{"es/admission/staging_custody.go", []string{"so a mode cannot reach staging without reaching the startup probe", "is not proved by the startup probe", "gives somebody else's directory to the roots' owner."}},
	}
	for _, check := range checks {
		content := compactText(mustRead(t, check.path))
		for _, phrase := range check.phrases {
			if !strings.Contains(content, phrase) {
				t.Fatalf("%s missing startup probe and use agreement contract %q", check.path, phrase)
			}
		}
	}
	// The probe description from before the free-name rename must not come back.
	assertContainsNone(t, "capability_probing.md one-sided no-replace probe", compactText(mustRead(t, ".docs/system_overview/capability_probing.md")),
		"refuse the results no-replace publication primitive when the destination already exists; and",
	)
	// The refused file systems do not all fail every submission: those that
	// cannot keep only the governed-mount modes stage the others (audit 16 of
	// pull request #20, finding A16-2).
	assertContainsNone(t, "capability_probing.md every-submission claim", compactText(mustRead(t, ".docs/system_overview/capability_probing.md")),
		"refuses startup instead of failing every submission",
	)
	assertContainsNone(t, "PLANS.md and standing rules every-submission claim", plansAndStandingRules(t),
		"instead of reporting ready while every submission, or every retention, fails",
	)
	// Nor may the comments of the admission code (audit 18 of pull request
	// #20, finding A18-1): the comment of probeStagedEntries states the chosen
	// rule. Comment markers are dropped so that a phrase may span lines.
	commentText := func(path string) string {
		lines := strings.Split(mustRead(t, path), "\n")
		for i, line := range lines {
			lines[i] = strings.TrimPrefix(strings.TrimSpace(line), "//")
		}
		return compactText(strings.Join(lines, "\n"))
	}
	if !strings.Contains(commentText("es/admission/execution_roots.go"), "so startup also refuses a staging file system that cannot keep them, although submissions without governed mounts would work there") {
		t.Fatal("es/admission/execution_roots.go missing the governed-mount mode rule in the comment of probeStagedEntries")
	}
	sources, err := filepath.Glob("es/admission/*.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range sources {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		assertContainsNone(t, path+" every-submission claim", commentText(path),
			"refuse every submission", "refuses every submission", "fail every submission", "fails every submission",
		)
	}
}

func TestNestedStagingOwnerProbeDocsContract(t *testing.T) {
	checks := []struct {
		path    string
		phrases []string
	}{
		{standingAdmissionRulesPath, []string{"`NESTED-STAGING-OWNER-PROBE-01` (bounded slice rule)", "as staging does inside each claimed run staging root", "inherited a group it is not a member of from a setgid parent directory", "`nested staging directory ownership is unavailable`"}},
		{".docs/system_overview/capability_probing.md", []string{"creates a `nested` directory inside its staging probe directory", "as staging does inside each claimed run staging root", "`nested staging directory ownership is unavailable`", "roots that inherit another group from a setgid parent directory refuse startup instead of failing at the first submission"}},
		{".docs/execution_lifecycle/implementation.md", []string{"(`probeNestedStagingDirectory`)", "`stagingCustody.ensureDirectory` does the same inside each claimed run staging root", "`nested staging directory ownership is unavailable`", "the nested staging probe above refuses them"}},
		{".runbooks/system/Governed Execution ES System Bring-Up.md", []string{"or inherited from a setgid parent directory; the inherited case is reported as `nested staging directory ownership is unavailable`"}},
		{"es/admission/execution_roots.go", []string{"roots.probeNestedStagingDirectory(stagingFD, owner)", `nestedStagingProbeName, stableStageDirMode, owner, "nested staging directory")`, `fmt.Errorf("%s ownership is unavailable: %w", label, err)`}},
	}
	for _, check := range checks {
		content := compactText(mustRead(t, check.path))
		for _, phrase := range check.phrases {
			if !strings.Contains(content, phrase) {
				t.Fatalf("%s missing nested staging owner probe contract %q", check.path, phrase)
			}
		}
	}
	// The known gap these documents described before the probe existed must
	// not come back.
	for _, path := range []string{".runbooks/system/Governed Execution ES System Bring-Up.md", ".docs/execution_lifecycle/implementation.md", ".docs/system_overview/capability_probing.md"} {
		assertContainsNone(t, path+" stale setgid-inherited group gap", compactText(mustRead(t, path)),
			"inherit another group from a setgid parent directory are not refused",
			"do not yet catch roots that inherit another group",
			"so ES reports ready but every submission fails to stage",
		)
	}
}

func TestRetainedResultReviewDocsContract(t *testing.T) {
	checks := []struct {
		path    string
		phrases []string
	}{
		{standingAdmissionRulesPath, []string{"before staging traversal or candidate creation", "natural `0750` result run-directory creation"}},
		{".docs/execution_lifecycle/contracts.md", []string{"even if retained staging later", "only an absent final and record", "derived parent are opened exactly", "held final descriptor must itself satisfy"}},
		{".docs/execution_lifecycle/implementation.md", []string{"before traversing staging", "full metadata policy before response buffering", "active process mask"}},
		{".docs/system_overview/configuration.md", []string{"effective `Clean(TrimSpace(root))`", "space in a parent component"}},
		{".docs/system_overview/capability_probing.md", []string{"natural owner and exact `0750` mode", "restrictive process mask or owner mismatch"}},
	}
	for _, check := range checks {
		content := compactText(mustRead(t, check.path))
		for _, phrase := range check.phrases {
			if !strings.Contains(content, phrase) {
				t.Fatalf("%s missing targeted result repair contract %q", check.path, phrase)
			}
		}
	}
}

func TestReview06GovernedRuntimeMountReadabilityContract(t *testing.T) {
	checks := []struct {
		path    string
		phrases []string
	}{
		{standingAdmissionRulesPath, []string{"Review-06 MOUNT-READ-01 bounded slice refinement", "normalized `0755` directories, `0644` non-executable regular files, and `0755` executable regular files", "The claimed run root remains `0750`", "The Nomad/Docker governed bind remains read-only", "does not qualify actual Docker/Nomad mount topology"}},
		{".docs/execution_lifecycle/contracts.md", []string{"distinct normalized workload-visibility rule", "`0755` directories, `0644` non-executable regular files, and `0755` executable regular files", "generic private payload, runtime-support, platform, trust, result-auth, and non-mount modes do not change", "complete-tree pre-dispatch validation", "mount stays read-only"}},
		{".docs/execution_lifecycle/implementation.md", []string{"mount-specific mode normalizer retains only executable intent", "mount directories are `0755`, ordinary files `0644`, and executable files `0755`", "narrow custody file writer uses mount-directory mode", "The claimed run root remains `0750`", "does not observe or qualify the later Docker/Nomad mount topology", "failed-allocation assertion includes bounded test-owned stdout and stderr when available"}},
	}
	for _, check := range checks {
		content := compactText(mustRead(t, check.path))
		for _, phrase := range check.phrases {
			if !strings.Contains(content, phrase) {
				t.Fatalf("%s missing governed mount readability contract %q", check.path, phrase)
			}
		}
	}
}

func TestReview20InstalledMountIdentityFixtureContract(t *testing.T) {
	checks := []struct {
		path    string
		phrases []string
	}{
		{standingAdmissionRulesPath, []string{"Review-19 A2/composition source disposition", "A2_AND_COMPOSITION_SOURCE_ACCEPTED_RUNTIME_GATES_OPEN", "Review-20 bounded qualification-fixture refinement", "Review-21 bounded qualification-fixture correction", "test-mounted-source-identity/v2", "common host/container backing-filesystem identity domain", "native fixture remains unexecuted", "running-deployment observation"}},
		{".docs/system_overview/capability_probing.md", []string{"bounded native single-host qualification witness", "offline modeled comparison tests", "held staged directory and file anchors before provider registration", "same Linux backing-filesystem domain", "missing observation, or skip leaves topology unqualified", "Review-21 bounded fixture correction", "Running allocation/container state alone does not prove readiness"}},
		{".docs/execution_lifecycle/contracts.md", []string{"test-owned governed-mount fixture", "held pre-registration source anchor", "Offline modeled comparisons", "running-deployment topology observation", "Review-21 test-only repair orders fixed workload readiness", "observer cannot release before readiness"}},
	}
	for _, check := range checks {
		content := compactText(mustRead(t, check.path))
		for _, phrase := range check.phrases {
			if !strings.Contains(content, phrase) {
				t.Fatalf("%s missing Review-20 qualification boundary %q", check.path, phrase)
			}
		}
	}
}

func TestReview22TaskLabelFixtureContract(t *testing.T) {
	checks := []struct {
		path    string
		phrases []string
	}{
		{standingAdmissionRulesPath, []string{"Review-22 test-owned task-label prerequisite correction", "extra_labels = [\"task_name\"]", "N4 refusal", "no native v2 installed-identity", "N5 and linux/arm64 did not run", "Default harness and capability-probe agents retain"}},
		{".docs/system_overview/capability_probing.md", []string{"Review-22 test-owned task-label prerequisite correction", "fresh Nomad Docker plugin profile", "Ordinary harness and capability-probe agents retain", "before readiness and installed-object observation", "N5 and arm64 not run", "future native witness"}},
		{".docs/execution_lifecycle/contracts.md", []string{"Review-22 test-owned task-label prerequisite correction", "exactly", "Bounded slice rule", "not an unconditional Nomad label guarantee", "before adoption or any Docker effect", "no v2 identity record", "fixture-agent configuration only"}},
	}
	for _, check := range checks {
		content := compactText(mustRead(t, check.path))
		for _, phrase := range check.phrases {
			if !strings.Contains(content, phrase) {
				t.Fatalf("%s missing Review-22 task-label contract %q", check.path, phrase)
			}
		}
	}
}

func TestReview07CustodyRecordedModeContract(t *testing.T) {
	checks := []struct {
		path    string
		phrases []string
	}{
		{standingAdmissionRulesPath, []string{"Review-07 CUSTODY-MODE-01 bounded custody refinement", "Review-06 source/evidence audit returned `BLOCK`", "Unix file type, ordinary permissions, and all three special mode bits exactly", "fresh independent Review-07 re-audit"}},
		{".docs/execution_lifecycle/contracts.md", []string{"Review-07 CUSTODY-MODE-01 repair", "Unix file type, ordinary `0777` permissions, setuid, setgid, and sticky bits exactly", "mismatch fails before provider submission"}},
		{".docs/execution_lifecycle/implementation.md", []string{"Review-07 repairs the independently found CUSTODY-MODE-01", "`S_IFMT | 07777`", "object-identity predicate remains separate", "does not repair or remove the retained object"}},
	}
	for _, check := range checks {
		content := compactText(mustRead(t, check.path))
		for _, phrase := range check.phrases {
			if !strings.Contains(content, phrase) {
				t.Fatalf("%s missing custody recorded-mode contract %q", check.path, phrase)
			}
		}
	}
}

func TestReview08RegistrationModeContract(t *testing.T) {
	checks := []struct {
		path    string
		phrases []string
	}{
		{standingAdmissionRulesPath, []string{"Review-08 REGISTRATION-MODE-01 bounded custody refinement", "post-creation descriptor stat must match the intended Unix file type", "all `07777` mode bits exactly", "fresh independent Review-08 audit"}},
		{".docs/execution_lifecycle/contracts.md", []string{"Review-08 REGISTRATION-MODE-01 repair", "before its identity enters the expected tree", "unregistered child and claimed root without metadata repair or deletion", "Later complete-tree handoff still validates the exact recorded state"}},
		{".docs/execution_lifecycle/implementation.md", []string{"Review-08 closes the registration-time REGISTRATION-MODE-01 gap", "content write and `Fsync`, before recording the descriptor stat", "A later handoff sees the retained child as unexpected"}},
	}
	for _, check := range checks {
		content := compactText(mustRead(t, check.path))
		for _, phrase := range check.phrases {
			if !strings.Contains(content, phrase) {
				t.Fatalf("%s missing registration-mode contract %q", check.path, phrase)
			}
		}
	}
}

func TestReview10ProofArtifactBoundaryContract(t *testing.T) {
	checks := []struct {
		path    string
		phrases []string
	}{
		{standingAdmissionRulesPath, []string{"Review-10 PROOF-RAW-OBS-01", "host proof directory is evidence-only", "tracked `.out/Dockerfile`", "independent Review-10 audit"}},
		{".docs/execution_lifecycle/contracts.md", []string{"host `.out` proof directory is evidence-only", "bootstrap/transport scratch is separate", "Raw", "opaque result bundles are not retained", "final host manifest is the root evidence record"}},
		{".docs/supported_local_cp_consumer_runbook.md", []string{"Review-10 proof artifact boundary", "guest-evidence/", "tracked `.out/Dockerfile`", "Raw Nomad/Docker/systemd output", "normal-shell result is", "fresh independent Review-10 audit"}},
		{"scripts/73_supported_local_proof.sh", []string{"create_private_host_proof_dir", "create_private_host_bootstrap_dir", "collect_guest_workspace()", "finalize_host_evidence_manifest", "cleanup_host_bootstrap_scratch"}},
		{"scripts/internal/supported_local_proof_evidence.sh", []string{"supported-local-proof-safe-evidence-v1", "MAX_FILE_BYTES", "MAX_TOTAL_BYTES", "O_NOFOLLOW", "safe-evidence-manifest.json", "collect-safe", "receive-safe"}},
		{"scripts/internal/supported_local_proof_source_snapshot.py", []string{"host-repo-snapshot.tar.gz", "source-manifest.json", "GIT_OPTIONAL_LOCKS", "Dockerfile"}},
		{"scripts/internal/supported_local_proof_projection.py", []string{"nomad-agent-safe.json", "control-plane-normal-shell-result-evidence.json", "docker-info-safe.json"}},
		{"scripts/internal/supported_local_proof_host_manifest.py", []string{"host-evidence-manifest.json", "guest-evidence", "classification"}},
	}
	for _, check := range checks {
		content := compactText(mustRead(t, check.path))
		for _, phrase := range check.phrases {
			if !strings.Contains(content, phrase) {
				t.Fatalf("%s missing proof evidence contract %q", check.path, phrase)
			}
		}
	}
}

func TestReview11ProofCaptureAndManifestContract(t *testing.T) {
	checks := []struct {
		path    string
		phrases []string
	}{
		{standingAdmissionRulesPath, []string{"Review-11 PROOF-EXEC-STATUS-01", "A labeled capture writes only its", "self-exclusion field", "independent Review-11 audit"}},
		{".docs/execution_lifecycle/contracts.md", []string{"A labeled capture writes only its own summary, status, and fixed", "Node-detail admission parses a loopback-only URL", "self_excluded", "every other retained"}},
		{".docs/supported_local_cp_consumer_runbook.md", []string{"Review-11 capture lineage and root manifest", "A labeled execution capture writes only labeled summary, status, and fixed", "127.0.0.1", "self_excluded: true", "fresh independent Review-11 audit"}},
		{"scripts/73_supported_local_proof.sh", []string{"capture_execution_evidence()", "validate_control_plane_normal_shell_result_bundle"}},
		{"scripts/internal/supported_local_proof_projection.py", []string{"fetch_node_details", "execution-status"}},
		{"scripts/internal/supported_local_proof_evidence.sh", []string{"supported-local-proof-summary-v1", "nomad-execution-safe.json"}},
		{"scripts/internal/supported_local_proof_host_manifest.py", []string{"self_excluded", "host-evidence-manifest.json"}},
	}
	for _, check := range checks {
		content := compactText(mustRead(t, check.path))
		for _, phrase := range check.phrases {
			if !strings.Contains(content, phrase) {
				t.Fatalf("%s missing Review-11 proof contract %q", check.path, phrase)
			}
		}
	}
}

func TestReview12ProofAllocationExactOneContract(t *testing.T) {
	checks := []struct {
		path    string
		phrases []string
	}{
		{standingAdmissionRulesPath, []string{"Review-12 PROOF-RUN-LINEAGE-01 exact-one allocation repair", "exactly one", "internal allocation-selection policy", "independent Review-12 audit"}},
		{".docs/execution_lifecycle/contracts.md", []string{"exactly one", "Zero or multiple allocations", "latest-`ModifyIndex`", "explicit redesign"}},
		{".docs/supported_local_cp_consumer_runbook.md", []string{"Review-12 exact-one proof allocation lineage", "Zero or multiple entries", "latest-`ModifyIndex`", "independent Review-12 audit"}},
		{"scripts/73_supported_local_proof.sh", []string{"proof allocation count must be exactly one", "proof allocation entry invalid", "proof allocation id invalid"}},
	}
	for _, check := range checks {
		content := compactText(mustRead(t, check.path))
		for _, phrase := range check.phrases {
			if !strings.Contains(content, phrase) {
				t.Fatalf("%s missing Review-12 allocation contract %q", check.path, phrase)
			}
		}
	}
}

func TestReview13ProofAllocationStrictJSONContract(t *testing.T) {
	checks := []struct {
		path    string
		phrases []string
	}{
		{standingAdmissionRulesPath, []string{"Review-13 PROOF-RUN-LINEAGE-01 strict-JSON allocation refinement", "complete allocation list", "fixed safe allocation-list error", "fresh independent Review-13 audit"}},
		{".docs/execution_lifecycle/contracts.md", []string{"complete allocation-list response must be strict JSON", "inside unknown or nested fields", "before allocation selection or observation"}},
		{".docs/supported_local_cp_consumer_runbook.md", []string{"Review-13 strict JSON allocation parsing", "including unknown and nested fields", "independent Review-13 audit"}},
		{"scripts/73_supported_local_proof.sh", []string{"parse_constant=reject_nonstandard_constant", "proof allocation list invalid"}},
	}
	for _, check := range checks {
		content := compactText(mustRead(t, check.path))
		for _, phrase := range check.phrases {
			if !strings.Contains(content, phrase) {
				t.Fatalf("%s missing Review-13 strict JSON proof contract %q", check.path, phrase)
			}
		}
	}
}

func TestReview14SupportedLocalRootOwnerIntegrationContract(t *testing.T) {
	checks := []struct {
		path    string
		phrases []string
	}{
		{standingHostRuntimePath, []string{"SUPPORTED-LOCAL-ROOT-OWNER-01", "fresh proof root", "0:0", "0755", "static owner/mode contract", "fixed safe setup projection", "key loading and root capability qualification before listening"}},
		{".docs/system_overview/configuration.md", []string{"service-root-v1", "exclusively provisions the two fresh configured roots", "0:0", "0755", "Config.SubmitConfigured()", "before ES listens"}},
		{".docs/system_overview/capability_probing.md", []string{"service-root-v1", "static preflight", "0:0", "0755", "behavioral capability", "before HTTP listening"}},
		{".docs/execution_lifecycle/contracts.md", []string{"service-root-v1", "sole creator", "0:0", "0755", "ordinary operator's own write access", "Generic callers without that profile"}},
		{".docs/execution_lifecycle/implementation.md", []string{"root-service profile", "two fresh configured roots", "0:0", "0755", "natural `0750`", "future container view"}},
		{".docs/supported_local_cp_consumer_runbook.md", []string{"service-root-v1", "noninteractive privilege", "refuses an existing proof root", "0:0", "0755", "shared static preflight", "execution-roots-setup-safe.json", "external key", "bootstrap scratch"}},
		{"scripts/72_supported_local_setup.sh", []string{"preflight_supported_local_setup_execution_roots", "provision_supported_local_execution_roots", "sudo -n python3", "SUPPORTED_LOCAL_ES_ROOTS_PROFILE", "write_supported_local_execution_root_evidence", "execution-roots-setup-safe.json", "supported-local execution roots invalid"}},
		{"scripts/internal/control_plane.sh", []string{"service-root-v1", "supported_local_execution_roots.py", "configured_root_mode", "operator_write_access_required", "container_identity_or_behavioral_capability_proved"}},
		{"scripts/internal/supported_local_proof_evidence.sh", []string{"execution-roots-setup-safe.json", "supported-local-execution-roots-setup-safe-v1", "container_identity_or_behavioral_capability_proved"}},
		{"scripts/internal/supported_local_proof_host_manifest.py", []string{"execution-roots-setup-safe.json", "proof_assertions"}},
	}
	for _, check := range checks {
		content := compactText(mustRead(t, check.path))
		for _, phrase := range check.phrases {
			if !strings.Contains(content, phrase) {
				t.Fatalf("%s missing Review-14 root-owner contract %q", check.path, phrase)
			}
		}
	}
}

func TestReview16SupportedLocalFullReadinessRootOwnerContract(t *testing.T) {
	checks := []struct {
		path    string
		phrases []string
	}{
		{standingHostRuntimePath, []string{"SUPPORTED-LOCAL-ROOT-OWNER-01", "full-profile submit-readiness", "ordinary operator needs static inspection access", "Generic callers without this explicit profile", "first failed subcheck"}},
		{".docs/system_overview/capability_probing.md", []string{"read-only validator", "full-profile submit-readiness", "operator's root-write", "Generic readiness"}},
		{".docs/system_overview/configuration.md", []string{"full-profile submit-readiness share a read-only", "caller writability", "does not create missing roots"}},
		{".docs/execution_lifecycle/contracts.md", []string{"one static, no-repair read-only validator", "direct health", "diagnostics consumer", "unknown profiles refuse", "Readiness does not create roots"}},
		{".docs/execution_lifecycle/implementation.md", []string{"Full-profile submit-readiness and diagnostics consume the same read-only", "generic", "creates none"}},
		{".docs/supported_local_cp_consumer_runbook.md", []string{"full-profile submit-readiness", "Direct `10_health_check.sh`", "diagnostics checker", "not write authority"}},
	}
	for _, check := range checks {
		content := compactText(mustRead(t, check.path))
		for _, phrase := range check.phrases {
			if !strings.Contains(content, phrase) {
				t.Fatalf("%s missing Review-16 full-readiness contract %q", check.path, phrase)
			}
		}
	}
}

func TestReview17ProofResultHandoffContract(t *testing.T) {
	checks := []struct {
		path    string
		phrases []string
	}{
		{standingAdmissionRulesPath, []string{"Review-17 PROOF-RESULT-HANDOFF-01", "already captured normal-shell", "no legacy alias", "historical live bundle was not inspected"}},
		{".docs/execution_lifecycle/contracts.md", []string{"selected private workdir", "Result-validation uses that captured summary", "rejecting duplicate object keys and nonstandard constants", "Held no-follow", "Raw bytes and workdir paths remain private"}},
		{".docs/supported_local_cp_consumer_runbook.md", []string{"Review-17 normal-shell result handoff", "<selected-workdir>/result.tar.gz", "no duplicate object keys or nonstandard constants", "newer workdir", "exact proof result validator"}},
		{"scripts/60_execute_loop.sh", []string{"RESULT_PATH=\"${WORKDIR}/result.tar.gz\"", "\"result_path\": sys.argv[21]", "\"result_available\": sys.argv[22]", "\"result_bytes\": int(sys.argv[23])"}},
		{"scripts/73_supported_local_proof.sh", []string{"summary.get(\"workdir\")", "summary.get(\"result_path\")", "captured-result", "run_phase result-validation"}},
		{"scripts/internal/supported_local_proof_projection.py", []string{"captured-result", "control-plane-normal-shell-summary.json", "control-plane-normal-shell-nomad-execution-safe.json", "result_projection"}},
		{"es/app/supported_local_proof_evidence_test.go", []string{"proofExecutionLoopSummary", "TestSupportedLocalProofCapturedResultBinding", "TestSupportedLocalProofResultValidationFinalizerContinuation"}},
	}
	for _, check := range checks {
		content := compactText(mustRead(t, check.path))
		for _, phrase := range check.phrases {
			if !strings.Contains(content, phrase) {
				t.Fatalf("%s missing Review-17 result handoff contract %q", check.path, phrase)
			}
		}
	}
}

const operationalHandoffOwnerDoc = ".docs/execution_lifecycle/reliable_submit_operational_handoff.md"

type handoffContractRow struct {
	key        string
	evidence   string
	senders    string
	permission string
	projection string
}

type handoffContractTable struct {
	name, start, end string
	headers          []string
	rows             []handoffContractRow
}

func operationalHandoffTables() []handoffContractTable {
	return []handoffContractTable{
		{
			name:    "write outcomes",
			start:   "| Decision | Evidence | Sender count | Permission | Projection |",
			end:     "An invocation reports the selected operation",
			headers: []string{"Decision", "Evidence", "Sender count", "Permission", "Projection"},
			rows: []handoffContractRow{
				{"AppliedFirstMarkerDirect", "Applied NULL-to-marker CAS and own direct COMMIT ACK", "1", "ConsumeOnce", "Known marker, same run, ambiguous until positive acceptance"},
				{"AppliedFirstMarkerReleaseFailed", "Applied and direct ACK, failed post-COMMIT qualification or disposal", "0", "Stop", "Known applied, withhold projection when release cannot authenticate"},
				{"AppliedOtherDirect", "Applied establish, assign, intent, stamp or accept and own direct COMMIT ACK", "0", "AdvanceOnlySelectedNextStep", "Committed phase with authorized projection"},
				{"DefinitelyNotApplied", "Proven rollback/refusal before successful COMMIT", "0", "Stop", "Preserve refusal and eligible current projection"},
				{"OwnCommitConfirmed", "Full authenticated own-commit readback after indeterminate command", "0", "Stop", "Own applied confirmed, eligible read-only projection"},
				{"UnknownCommit", "Indeterminate and own readback unavailable or fails full equality", "0", "Stop", "Unknown, withhold projection in this invocation"},
				{"ExactLatestReplay", "Exact mutation, operation, predecessor and input match latest", "0", "ReadOnly", "Authenticated current projection"},
				{"NoChange", "Successful current read or read-only/no-change transaction", "0", "ReadOnly", "Authenticated current projection"},
				{"StaleCAS", "Stale revision, failed CAS or advanced record", "0", "Stop", "Stale, eligible authenticated winner or withhold"},
				{"ConflictOrOccupied", "Different intent, foreign scope or unique-key loser", "0", "Stop", "Conflict or eligible authenticated same-scope winner"},
				{"Refused", "Validation, permission, capacity, context or integrity refusal", "0", "Stop", "Fixed refusal class, withhold unqualified facts"},
			},
		},
		{
			name:    "crash histories and disclosure",
			start:   "| Scenario | Evidence | Sender count | Permission | Projection |",
			end:     "K1 indistinguishable histories:",
			headers: []string{"Scenario", "Evidence", "Sender count", "Permission", "Projection"},
			rows: []handoffContractRow{
				{"FreshPrestage", "Fresh qualified writer turn, absent stamp and physical stage, exclusive-create only", "0", "CreateOneStage", "Same run, pending until first marker"},
				{"UnlockedAbsence", "Snapshot, cache, preflight or unlocked marker absence", "0", "Stop", "No effect eligibility"},
				{"StageOwnerLost", "Stage residue or retained stamp without original live owner", "0", "Stop", "Same run pending or ambiguous, residue charged"},
				{"PrestageUnknownSettled", "Prior invocation stopped, fresh checked turn and no stamp or physical stage", "0", "CreateOneStage", "Earlier response preserved, independent same-run eligibility"},
				{"MarkerRollbackAfterStage", "Real marker rollback or failed marker with completed stage residue", "0", "StopBothInvocations", "Fresh absent marker cannot confer stage ownership"},
				{"MarkerCommitReplyLost", "Real marker COMMIT, response lost, even with exact readback", "0", "NeverPost", "Same-run ambiguity until positive proof"},
				{"MarkerDirectOwnerConsumed", "Directly acknowledged first marker and one valid consumed live owner", "1", "AtMostOneReceiverDelivery", "Receiver-count positive witness has exactly one ingress total"},
				{"MarkerDirectOwnerLost", "Known marker with canceled, failed or crashed owner before entry", "0", "NeverPost", "Possibly indefinite ambiguity"},
				{"MarkerCASLoser", "Two marker commands, only the applied and directly acknowledged command eligible", "0", "NeverPost", "Current projection only"},
				{"Provider404", "Qualified GET absence or any inconclusive evidence", "0", "PositiveObservationOnly", "Ambiguous, no negative terminal"},
				{"AcceptedReplay", "Current caller and qualified equivalent retained original with an eligible ACTIVE or RETIRED key pair", "0", "ReceiptOnly", "Same immutable run and receipt without mutable admission, resolution, staging or provider"},
				{"SyntheticAuthority", "Synthetic row, object, permit, borrow, marker or receipt", "0", "OccupancyOnly", "Unavailable across scope"},
				{"PublicOrRouteOnly", "Public route/startup or route-level permission alone", "0", "Refuse", "Public keyed refusal and claim-scoped later gate"},
			},
		},
		{
			name:    "provider exchanges",
			start:   "| Exchange condition | Selected behavior | Extra POST deliveries |",
			end:     "Direct `POST /v1/jobs?",
			headers: []string{"Exchange condition", "Selected behavior", "Extra POST deliveries"},
			rows: []handoffContractRow{
				{key: "FirstMarkerSender", evidence: "One synchronous direct bounded POST, consumed before entry", senders: "0"},
				{key: "RedirectOrReplay", evidence: "Refuse redirect, retry and transport replay, including fallback", senders: "0"},
				{key: "MissingOrRejected", evidence: "Preserve ambiguity on 404, collision, timeout or other inconclusive response", senders: "0"},
				{key: "PositiveAcceptance", evidence: "Require qualified Job plus unique matching initial registration evaluation before receipt CAS", senders: "0"},
			},
		},
	}
}

func checkOperationalHandoffTable(section string, table handoffContractTable) string {
	lines := strings.Split(strings.TrimSpace(section), "\n")
	width := len(table.headers)
	if len(lines) < 2 || lines[0] != table.start {
		return "header"
	}
	separator := "| " + strings.TrimSuffix(strings.Repeat("--- | ", width), " ")
	if strings.TrimSpace(lines[1]) != separator {
		return "separator"
	}

	expected := make(map[string]handoffContractRow, len(table.rows))
	for _, row := range table.rows {
		expected[row.key] = row
	}
	seen := make(map[string]bool, len(table.rows))
	for _, raw := range lines[2:] {
		line := strings.TrimSpace(raw)
		cells := strings.Split(line, "|")
		if len(cells) != width+2 || cells[0] != "" || cells[width+1] != "" {
			return "malformed row"
		}
		key := strings.TrimSpace(cells[1])
		want, ok := expected[key]
		if !ok || seen[key] {
			return key
		}
		if strings.TrimSpace(cells[2]) != want.evidence || strings.TrimSpace(cells[3]) != want.senders {
			return key
		}
		if width == 5 && (strings.TrimSpace(cells[4]) != want.permission || strings.TrimSpace(cells[5]) != want.projection) {
			return key
		}
		seen[key] = true
	}
	for _, row := range table.rows {
		if !seen[row.key] {
			return row.key
		}
	}
	return ""
}

func operationalPrestageOwnerRule(owner string) bool {
	return strings.Contains(owner, "| Pre-stage turn | Only a complete NoChange plus ReasonNone result allows one following exclusive attempt.")
}

func TestOperationalSubmitHandoffContractSelection(t *testing.T) {
	owner := mustRead(t, operationalHandoffOwnerDoc)
	if !operationalPrestageOwnerRule(owner) {
		t.Fatal("owner lacks the complete positive pre-stage prerequisite")
	}
	assertContainsAll(t, "complete pre-stage prerequisite", owner,
		"Only a complete NoChange plus ReasonNone result allows one following exclusive attempt",
		"Failed cleanup, release, observed cancellation, denied or stale cuts stop effects",
		"direct exchange-method entry", "standard HTTP GetConn callbacks", "receiver ingress")
	prestageSource := mustRead(t, "es/admission/reliable_submit_operational_handoff.go")
	if !strings.Contains(prestageSource, "prestage.Disposition() != reliablesubmit.OperationalNoChange ||\n\t\tprestage.Reason() != reliablesubmit.OperationalReasonNone") {
		t.Fatal("admission lacks the complete positive pre-stage result gate")
	}
	for _, table := range operationalHandoffTables() {
		if issue := checkOperationalHandoffTable(docSection(t, owner, table.start, table.end), table); issue != "" {
			t.Errorf("%s contract differs at %q", table.name, issue)
		}
	}

	record := mustRead(t, plansRecordPath)
	selection := compactDocSection(t, record, "### Post-PR #11 operational handoff owner-contract candidate", "### Private replay-progress pre-COMMIT")
	assertContainsAll(t, "published base and selected status", selection,
		"ae326b0ddc30ec6b35883ee32945c622405b68b6", "e066cd4afa77fcb665f31b69bf00465989f9744e",
		"Current production source is schema 4", "the private progress path is fixture-only",
		"schema 5, codec 5 and encoded scope 3", "source acceptance remain separate gates")
	adr := mustRead(t, ".docs/execution_lifecycle/reliable_submit_persistence_and_concurrency.md")
	cut := compactDocSection(t, adr, "### Selected codec-5 interpretation of §8", "Ordering implications:")
	assertContainsAll(t, "scoped §8 exception", cut, "scoped to codec 5", "retains conditions 1–8 and 11",
		"expected-revision CAS for 12", "after `BEGIN IMMEDIATE` on the same unchanged authority domain for conditions 9–10",
		"supersedes the repair/reuse permission", "§15B continues to govern the fixture scope")
	submit := mustRead(t, ".docs/execution_lifecycle/submit_idempotency_correlation_and_recovery.md")
	receipt := compactDocSection(t, submit, "### 6C. Selected operational handoff and receipt-only recovery", "## 7. Narrow Durable Correlation Semantics")
	assertContainsAll(t, "receipt access", receipt, "Current exact caller authorization precedes lookup",
		"exact ACTIVE key pair", "qualified retained original and immutable receipt with the exact ACTIVE or RETIRED pair",
		"Mutable execution admission, current resolution, staging and provider access are excluded",
		"§6B continues to govern the completed private fixture")
	admission := mustRead(t, ".docs/execution_lifecycle/es_execution_admission_model.md")
	composition := compactDocSection(t, admission, "### Selected operational composition and ownership", "### 7.5 Rejected A3 topology inventory")
	assertContainsAll(t, "composition scope", composition, "bounded private composition",
		"invocation-local lifetime", "Current §7.4 describes current source",
		"Public routing, startup and the rejected A3 topology remain outside the selection")
	for _, doc := range []string{adr, submit, admission} {
		assertContainsAll(t, "owner delegation", doc, "(reliable_submit_operational_handoff.md)")
	}

	state := compactDocSection(t, owner, "## 2. Installation, scope and physical state", "## 3. Original, key cuts and encodings")
	assertContainsAll(t, "retained state", state, "`operational_local_v2` / 3",
		"including the removed `operational_local_v1` literal",
		"Global caller/key occupation spans the table", "cannot be promoted, relabeled or republished as operational originals",
		"Copy every field including physical rowid", "Marker is permanent", "No operations 6, 7, 9 or 10 on codec 5",
		"`reliable_submit_operational_admission`, a STRICT table", "that can hold exactly one row",
		"A codec-5 insert aborts unless an enabled admission row exists",
		"operation kind is not 8 aborts unless an enabled admission row exists",
		"Migration 5 copies the earlier rows before it creates any trigger",
		"schema-5 shape published at `8058561` is refused on open")
	if strings.Contains(state, "| 5 | 5 | `operational_local_v1` / 3 |") {
		t.Fatal("the removed v1 scope row is still selected")
	}
	custody := compactDocSection(t, owner, "## 5. Exclusive staging and exact bindings", "## 6. Provider exchange and receipt")
	assertContainsAll(t, "staging qualification", custody, "one exclusive descriptor-relative mkdir", "stamp without its live owner",
		"No cross-invocation stamp authority", "Preserve every residue and capacity charge",
		"Job0 has no carrier, stage digest or filesystem inode")
	transport := compactDocSection(t, owner, "### Exchange limits and positive witness", "## 7. Authority and history matrix")
	assertContainsAll(t, "pinned provider observation", transport, "EnforceIndex=true and JobModifyIndex=0",
		"JobModifyIndex=CreateIndex=Job.CreateIndex=Job.JobModifyIndex>0",
		"No requirement that both reads be one atomic Job+Eval snapshot", "A 404 carries no negative terminal inference",
		"Require LastContact integer 0, KnownLeader false, NextToken empty string",
		"Job index header equals Job.ModifyIndex",
		"a2a5fee9c42d6481adcb9be865bcbccf8fd4d725")
}

func TestOperationalSubmitHandoffContractRejectsUnsafeMutants(t *testing.T) {
	owner := mustRead(t, operationalHandoffOwnerDoc)
	t.Run("PrestageReasonOmitted", func(t *testing.T) {
		row := "Only a complete NoChange plus ReasonNone result allows one following exclusive attempt"
		if !strings.Contains(owner, row) {
			t.Fatal("real pre-stage owner rule missing")
		}
		mutant := strings.Replace(owner, row, "NoChange allows one following exclusive attempt", 1)
		if mutant == owner || operationalPrestageOwnerRule(mutant) {
			t.Fatal("unsafe disposition-only owner rule survived")
		}
	})
	tables := operationalHandoffTables()
	for _, mutant := range []struct {
		name, row, from, to string
		table               int
	}{
		{"RecoveredCommitMints", "OwnCommitConfirmed", "| 0 | Stop |", "| 1 | ConsumeOnce |", 0},
		{"LatestReplayMints", "ExactLatestReplay", "| 0 | ReadOnly |", "| 1 | ConsumeOnce |", 0},
		{"NoOpMints", "NoChange", "| 0 | ReadOnly |", "| 1 | ConsumeOnce |", 0},
		{"ReadMints", "NoChange", "Successful current read", "Authenticated current read mints a sender", 0},
		{"MarkerUnknownPosts", "UnknownCommit", "| 0 | Stop |", "| 1 | ConsumeOnce |", 0},
		{"MarkerUnknownRetries", "UnknownCommit", "| 0 | Stop |", "| 0 | RetryMarker |", 0},
		{"UnlockedAbsenceAuthorizes", "UnlockedAbsence", "| 0 | Stop |", "| 0 | CreateOneStage |", 1},
		{"OmittedPhysicalPrerequisite", "PrestageUnknownSettled", "no stamp or physical stage", "no stamp", 1},
		{"AdoptAbandonedStage", "StageOwnerLost", "| 0 | Stop |", "| 0 | AdoptStage |", 1},
		{"RolledBackMarkerAllowsDistinctOwner", "MarkerRollbackAfterStage", "| 0 | StopBothInvocations |", "| 0 | CreateOneStage |", 1},
		{"LostMarkerReplyPermitsPost", "MarkerCommitReplyLost", "| 0 | NeverPost |", "| 1 | ConsumeOnce |", 1},
		{"KnownMarkerGuaranteesSend", "MarkerDirectOwnerLost", "Possibly indefinite ambiguity", "Guaranteed send, acceptance and execution", 1},
		{"FixtureConvertsToOperational", "SyntheticAuthority", "| 0 | OccupancyOnly |", "| 1 | ConsumeOnce |", 1},
		{"ReceiptRerunsMutableResolution", "AcceptedReplay", "without mutable admission, resolution, staging or provider", "after mutable admission, resolution, staging and provider", 1},
		{"RouteOrPublicWiring", "PublicOrRouteOnly", "Public keyed refusal and claim-scoped later gate", "Current public wiring and route ACL establish claim ownership", 1},
		{"RedirectOrAutomaticRetry", "RedirectOrReplay", "Refuse redirect, retry and transport replay", "Permit redirect, retry and transport replay", 2},
		{"Provider404IsNegativeTerminal", "MissingOrRejected", "Preserve ambiguity on 404", "Record provably not accepted on 404", 2},
	} {
		t.Run(mutant.name, func(t *testing.T) {
			table := tables[mutant.table]
			section := docSection(t, owner, table.start, table.end)
			if issue := checkOperationalHandoffTable(section, table); issue != "" {
				t.Fatalf("real table differs at %q", issue)
			}
			prefix := "| " + mutant.row + " |"
			lines := strings.Split(section, "\n")
			mutated := 0
			for idx, line := range lines {
				if strings.HasPrefix(line, prefix) {
					if strings.Count(line, mutant.from) != 1 {
						t.Fatalf("row %q lacks a unique mutation target %q", mutant.row, mutant.from)
					}
					lines[idx] = strings.Replace(line, mutant.from, mutant.to, 1)
					mutated++
				}
			}
			if mutated != 1 {
				t.Fatalf("mutated %d rows, want one", mutated)
			}
			if issue := checkOperationalHandoffTable(strings.Join(lines, "\n"), table); issue != mutant.row {
				t.Fatalf("mutant rejected at %q, want %q", issue, mutant.row)
			}
		})
	}
}

func operationalCurrentAdmissionV2OwnerRule(owner string) bool {
	return strings.Contains(owner, "a first-effect cut proceeds only if the presented token equals") &&
		strings.Contains(owner, "the enabled admission row read under the SQLite writer lock") &&
		strings.Contains(owner, "The presented token equals the enabled row read through the turn's connection.") &&
		strings.Contains(owner, "the returned match must carry a token equal to that row") &&
		strings.Contains(owner, "only bounded local Service admission") &&
		strings.Contains(owner, "less than 30 seconds elapsed since it on both the monotonic and") &&
		strings.Contains(owner, "a permanent local superseded latch is set") &&
		strings.Contains(owner, "A fetch or verification failure changes nothing.") &&
		strings.Contains(owner, "Receipt-only") && strings.Contains(owner, "but no view, token, confirmation,")
}

func operationalV1RemovalRule(owner string) bool {
	return strings.Contains(owner, "`operational_local_v1` is removed and is not a compatibility edge.") &&
		strings.Contains(owner, "Scope-3 custody refuses the") &&
		strings.Contains(owner, "the reader refuses it in its fail-closed default") &&
		strings.Contains(owner, "refuses an empty evidence record instead of choosing a literal") &&
		strings.Contains(owner, "no\nproduction source contains the v1 literal") &&
		!strings.Contains(owner, "Temporary compatibility edge")
}

func operationalAdmissionOutcomeRule(owner string) bool {
	return strings.Contains(owner, "| Retained original: signer not allowed or revoked, artifact revoked, built-in policy denies | `OperationalDenied` | No |") &&
		strings.Contains(owner, "| Retained evidence does not verify under the current verifier | `OperationalDenied`.") &&
		strings.Contains(owner, "| First delivery that ordinary resolution refuses, whatever the cause: the rules, an unsupported request or an unavailable dependency | `OperationalUnavailable`. Nothing is stored. | No |") &&
		strings.Contains(owner, "| The context of the call has ended and the admission returned no refusal of its own in this call | `OperationalCanceled`. `OperationalTimeout` where the deadline of the call passes while the provider is asked about the job (below) | No, except while a durable marker is reconciled, where the stored run is returned (below) |") &&
		strings.Contains(owner, "When the deadline of the call passes while the provider\nis asked about the job, the exchange reports `OperationalTimeout`") &&
		strings.Contains(owner, "the result is the same\nambiguous one with the run") &&
		strings.Contains(owner, "At the other three points, and before the marker,\na passed deadline answers `OperationalCanceled` like a cancellation.") &&
		strings.Contains(owner, "The first five rows are value-free and withhold run and receipt at the\nrefused cut.") &&
		strings.Contains(owner, "A cancelled call returns the stored run only while it reconciles a durable\nmarker: at the reconciliation entry, at the final sender entry, whose answer\narrives at that entry, during the observation of the job and at the binding\nof a completed observation.") &&
		strings.Contains(owner, "a binding before the marker is value-free. So is the one from the\nverification of an accepted receipt, although run and receipt are durable") &&
		strings.Contains(owner, "names it as the prerequisite `CP-PUBLIC-MAPPING`") &&
		!strings.Contains(owner, "Every row is value-free") &&
		!strings.Contains(owner, "a later gate, and the handoff has no production caller") &&
		strings.Contains(owner, "`OperationalDenied` is the answer of the re-judgment only.") &&
		strings.Contains(owner, "an ended context reports the cancellation and not `OperationalUnavailable` or") &&
		strings.Contains(owner, "also when the\ncontext has ended meanwhile") &&
		strings.Contains(owner, "That holds whatever stopped the call between staging and the stamp") &&
		strings.Contains(owner, "| No view, token not equal to the row, withdrawn, superseded, deadline passed, unsupported required input or missing bounded payload | `OperationalUnavailable` | No |") &&
		strings.Contains(owner, "an existing original whose realm is not the domain's | `OperationalIntegrity` | No |") &&
		strings.Contains(owner, "the authority\nrefusal is reported, at reconciliation and at the final sender entry alike") &&
		strings.Contains(owner, "reports the last writer\nattempted in that call") &&
		strings.Contains(owner, "returns the stored run to the\nauthenticated original caller under any authority and sends no trust request") &&
		strings.Contains(owner, "so before staging a denial does not poison the claim") &&
		strings.Contains(owner, "it needs a new submit key") &&
		strings.Contains(owner, "one\nsender already past its release re-read may still POST")
}

// operationalAdmissionLockRule holds the statements about which locks the
// admission operations and the confirmation hold, and refuses the three
// sentences the code never matched.
func operationalAdmissionLockRule(owner string) bool {
	return strings.Contains(owner, "handle's lock in read mode (`OperationalCustody.mu`), so `Close` waits for it.") &&
		strings.Contains(owner, "must therefore be called outside every borrow of the same handle") &&
		strings.Contains(owner, "Confirmation runs outside every writer turn and every transaction, and holds\nneither `Service.mu` nor the owner mutex while it fetches.") &&
		strings.Contains(owner, "pre-checks it runs inside the borrow of the original, so the custody handle's\nread lock is held across the request") &&
		strings.Contains(owner, "The confirmation of a\nfresh delivery holds no lock.") &&
		!strings.Contains(owner, "outside every lock") &&
		!strings.Contains(owner, "takes no lock") &&
		!strings.Contains(owner, "never custody")
}

// operationalCustodyLockHolders lists the methods of OperationalCustody in
// the store package's non-test sources that lock or read-lock its mutex.
func operationalCustodyLockHolders(t *testing.T) []string {
	t.Helper()
	const directory = "es/admission/internal/reliablesubmit"
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	var holders []string
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(token.NewFileSet(), filepath.Join(directory, name), nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, declaration := range file.Decls {
			function, ok := declaration.(*ast.FuncDecl)
			if !ok || function.Recv == nil || len(function.Recv.List) != 1 || function.Body == nil {
				continue
			}
			pointer, ok := function.Recv.List[0].Type.(*ast.StarExpr)
			if !ok || len(function.Recv.List[0].Names) != 1 {
				continue
			}
			if owner, ok := pointer.X.(*ast.Ident); !ok || owner.Name != "OperationalCustody" {
				continue
			}
			receiver := function.Recv.List[0].Names[0].Name
			locks := false
			ast.Inspect(function.Body, func(node ast.Node) bool {
				call, ok := node.(*ast.CallExpr)
				if !ok {
					return true
				}
				method, ok := call.Fun.(*ast.SelectorExpr)
				if !ok || (method.Sel.Name != "Lock" && method.Sel.Name != "RLock") {
					return true
				}
				field, ok := method.X.(*ast.SelectorExpr)
				if !ok || field.Sel.Name != "mu" {
					return true
				}
				if base, ok := field.X.(*ast.Ident); ok && base.Name == receiver {
					locks = true
				}
				return true
			})
			if locks {
				holders = append(holders, function.Name.Name)
			}
		}
	}
	slices.Sort(holders)
	return holders
}

// operationalCustodyLockRowHolders reads the methods the admission model's
// lock inventory row names for OperationalCustody.mu.
func operationalCustodyLockRowHolders(admission string) []string {
	const prefix = "| Lock | `es/admission/internal/reliablesubmit:OperationalCustody.mu:sync.RWMutex` |"
	var holders []string
	for _, line := range strings.Split(admission, "\n") {
		if !strings.HasPrefix(line, prefix) {
			continue
		}
		cells := strings.Split(line, "|")
		if len(cells) < 7 {
			return nil
		}
		for _, cell := range cells[4:6] {
			for _, match := range regexp.MustCompile("`OperationalCustody\\.([A-Za-z0-9_]+)`").FindAllStringSubmatch(cell, -1) {
				if !slices.Contains(holders, match[1]) {
					holders = append(holders, match[1])
				}
			}
		}
	}
	slices.Sort(holders)
	return holders
}

func operationalV2AssuranceOwnerRule(owner string) bool {
	return strings.Contains(owner, "zero non-test references") &&
		strings.Contains(owner, "exactly one view construction, in the install method of the state") &&
		strings.Contains(owner, "exactly one construction of the\nadmission state, in its constructor, which `NewService` alone calls") &&
		strings.Contains(owner, "`es/admission/internal/admissionstate`, under that package's own read-write\nlock. `Service.mu` does not cover them.") &&
		strings.Contains(owner, "It imports neither `reflect`, `unsafe` nor `C` and performs no I/O") &&
		strings.Contains(owner, "Each is a struct whose only field is an unexported pointer\nto an unexported struct") &&
		strings.Contains(owner, "A Service built any other way holds the zero handle, which is closed") &&
		strings.Contains(owner, "It is copied on the way in and on every way out") &&
		strings.Contains(owner, "Outside the package the following do not compile") &&
		strings.Contains(owner, "type-checking each form against the real packages for all three build\ntargets") &&
		strings.Contains(owner, "it does not run the compiler itself") &&
		strings.Contains(owner, "Two things remain possible outside the package, and the guard below holds\nboth by exact inventories") &&
		strings.Contains(owner, "A call cannot clear a latch, move the\nconfirmation time back or install a second view") &&
		strings.Contains(owner, "A\nhandle saved earlier names the same state and restores nothing") &&
		strings.Contains(owner, "The package boundary does not hold against reflection or `unsafe`") &&
		strings.Contains(owner, "Neither the package boundary nor any inventory below holds against code that\nwrites the memory of its own process without going through the language") &&
		strings.Contains(owner, "The function imports neither\n`reflect`, `unsafe` nor `C`, names no protected field") &&
		strings.Contains(owner, "No source inventory can hold that\nroad in general") &&
		strings.Contains(owner, "dependency is therefore inside the trust boundary of the admission\nstate") &&
		strings.Contains(owner, "The boundary is one of the language, not of the process") &&
		strings.Contains(owner, "nothing may\nrely on it against code of lower trust in the same process") &&
		strings.Contains(owner, "One limit has no inventory at all") &&
		strings.Contains(owner, "The other ways to that memory are system calls") &&
		strings.Contains(owner, "The import inventory below does not list the files that import\n`syscall` or `golang.org/x/sys/unix`") &&
		strings.Contains(owner, "Two kinds of road do go through the language without a `reflect`, `unsafe`\nor `C` import, and the guard holds both") &&
		strings.Contains(owner, "converts to a pointer of any type in every\nfile; the import of `unsafe` is needed only to spell the type") &&
		strings.Contains(owner, "So a raw pointer value may appear only in a file that imports\n`unsafe`") &&
		strings.Contains(owner, "So an import of a dependency package outside a\nreviewed list puts its file into the import inventory as well") &&
		strings.Contains(owner, "`unsafe`, `C` or `plugin` import in any production package fails a test") &&
		strings.Contains(owner, "and so does an import of a dependency package outside the reviewed list") &&
		strings.Contains(owner, "a new dependency import, a further package of a\nlisted module, a new version and a replacement each fail until the list is\nupdated") &&
		strings.Contains(owner, "value whose type has the underlying type `unsafe.Pointer` in a file that\ndoes not import `unsafe` fails it") &&
		strings.Contains(owner, "It judges the file that holds each such\nvalue by the value's real position, not by the file and line that a\n`//line` or `/*line` directive names") &&
		strings.Contains(owner, "a test refuses the calls that read an adjusted position in the\ntest files of the module") &&
		strings.Contains(owner, "another test refuses such a directive in every\nnon-test Go file of the repository") &&
		strings.Contains(owner, "The rule reads the static types of the source") &&
		strings.Contains(owner, "it cannot become a typed pointer there\nwithout a constraint that spells the type") &&
		strings.Contains(owner, "Raw system calls through `syscall` and `golang.org/x/sys/unix` are part of\nthat limit") &&
		strings.Contains(owner, "a source inventory\ncannot show that no other road exists") &&
		strings.Contains(owner, "aggregate HEAD ceiling for PR #12 plus its repairs was 52 files") &&
		strings.Contains(owner, "It adds exactly one more path, a test file:\nA/workstream_a_guardrails_test.go") &&
		strings.Contains(owner, "HEAD ceiling for PR #12 plus its repairs was 53 files") &&
		strings.Contains(owner, "HEAD ceiling for PR #12 plus its repairs was 56 files") &&
		strings.Contains(owner, "HEAD ceiling for PR #12 plus its repairs was 66 files") &&
		strings.Contains(owner, "HEAD ceiling for PR #12 plus its repairs was 69 files") &&
		strings.Contains(owner, "HEAD ceiling for PR #12 plus its repairs is 70 files") &&
		strings.Contains(owner, "`trunk_dev` after its\nPRs #43, #42, #34, #31, #38, #44 and #46, are a further owner reconciliation\nat this gate.") &&
		strings.Contains(owner, "It adds exactly one more path, a test file:\nA/nomad_request_guard_test.go, PR #31's token guard, which now covers the\nprovider and reads unadjusted positions.") &&
		strings.Contains(owner, "A/reliable_submit_operational_handoff.go, A/service.go and their tests,\nwhich are already counted.") &&
		strings.Contains(owner, "gains the prerequisite `CP-NOMAD-ACL`.") &&
		strings.Contains(owner, "the provider's token is the one ES loads from `nomad.token_file` at startup for the current submit client;") &&
		strings.Contains(owner, "carries ES's Nomad\nACL client token in one `X-Nomad-Token` header and never in the URL.") &&
		strings.Contains(owner, "the provider cannot be built without a token in\nNomad's canonical SecretID form.") &&
		strings.Contains(owner, "`trunk_dev` after its PRs #33, #41, #37 and #39, are a further owner\nreconciliation at this gate.") &&
		strings.Contains(owner, "remote_alpha_es_service_tls_status_local_boundary_test.go, which keeps its\ncount there.") &&
		strings.Contains(owner, "It adds exactly three more paths, the module file and two test files:\ngo.mod, which makes `golang.org/x/text` a direct requirement at the version\nalready selected, A/nomad_request_strings_redteam31_finding_test.go\n(new), the re-check's tests, and internal/testutil/testutil_test.go, whose\nthree position reads now ignore line directives.") &&
		strings.Contains(owner, "packages of `golang.org/x/text` that the rule imports, in\nA/workstream_c_guardrails_test.go, which is already counted.") &&
		strings.Contains(owner, "test of those lengths are in A/workstream_c_guardrails_test.go and\nI/operational_handoff_test.go, which are already counted.") &&
		strings.Contains(owner, "owner reconciliation at this gate. Taking up `trunk_dev` adds no path.") &&
		strings.Contains(owner, "It adds exactly ten more paths, one production file, two\ndocuments and seven test files:\nA/mounts.go, whose mount target rule refuses those strings") &&
		strings.Contains(owner, ".docs/execution_lifecycle/contracts.md and\n.docs/system_overview/contracts.md, which state the refusal") &&
		strings.Contains(owner, "A/nomad_request_strings_test.go (new),\nA/reliable_submit_operational_job_bound_test.go (new) and the red-team's\nfive test files") &&
		strings.Contains(owner, "A/reliable_submit_operational_admission_redteam3_test.go (new),\nA/reliable_submit_operational_admission_redteam3_codec_test.go (new),\nA/reliable_submit_operational_admission_redteam3_finding_test.go (new),\nA/reliable_submit_operational_admission_redteam3_fuzz_test.go (new) and\nA/reliable_submit_operational_admission_redteam3_process_test.go (new)") &&
		strings.Contains(owner, "Job0 ≤65536\nbytes as Go's `encoding/json` writes it") &&
		strings.Contains(owner, "That form is at least as long as the one Nomad's\nAPI writes when GET Job returns the job") &&
		strings.Contains(owner, "Before the claim is stored, ES\nprojects Job0 and the POST body") &&
		strings.Contains(owner, "either bound as `OperationalMalformed`, with no claim, no reservation and no\npublication") &&
		strings.Contains(owner, "`//go:cgo_import_dynamic _ _\n\"name\"` makes a `CGO_ENABLED=0` build a dynamic executable") &&
		strings.Contains(owner, "may hold only\nthe `//go:` directives of an exact reviewed list, today `//go:build`\nalone") &&
		strings.Contains(owner, "and a test fails on any other verb and on a listed verb that no\nfile holds") &&
		!strings.Contains(owner, "Canonical Job0") &&
		strings.Contains(owner, "It adds exactly three more paths, two test files and the CI's list:\nA/internal/admissionstate/testtmpdir_main_test.go (new)") &&
		strings.Contains(owner, "remote_alpha_es_service_tls_status_local_boundary_test.go, whose two\nposition reads now ignore line directives") &&
		strings.Contains(owner, ".github/ci/environment-only-tests.txt, which gains two lines") &&
		strings.Contains(owner, "Every exported\nfunction and method of the package has an exact list of the functions that\nreference it") &&
		strings.Contains(owner, "and the inspection method and the question whether a handle names a view,\nwhich exist for tests, nowhere") &&
		strings.Contains(owner, "The exported\nsurface of the package is a closed list") &&
		strings.Contains(owner, "package is pinned by the SHA-256 hash of its bytes") &&
		strings.Contains(owner, "Installing a view takes\n`Service.mu` and then the lock of the admission state") &&
		strings.Contains(owner, "field of a production struct whose type holds one of its two handle types,\nfails the guard until it has an inventory, and a package variable that holds\na handle is refused") &&
		!strings.Contains(owner, "operationalAdmissionSnapshot") &&
		!strings.Contains(owner, "the latches and the\nconfirmation included") &&
		strings.Contains(owner, "independently build the full scope-3 TLV and PB1") &&
		strings.Contains(owner, "Transparent parentheses enclosing a resolved field") &&
		strings.Contains(owner, "parenthesized reads") &&
		strings.Contains(owner, "targets remain assignments") &&
		strings.Contains(owner, "targets remain read-writes") &&
		strings.Contains(owner, "Range-clause `=` key and value whole-field targets") &&
		strings.Contains(owner, "Taking a field's address is an `address` access") &&
		strings.Contains(owner, "is a `write-through` access") &&
		strings.Contains(owner, "A conversion is a transparent step in that chain") &&
		strings.Contains(owner, "A protected field can also be written without being spelled") &&
		strings.Contains(owner, "occurrence of its owning struct type as its own access kind") &&
		strings.Contains(owner, "a zero-value declaration and a same-shape") &&
		strings.Contains(owner, "a conversion in either direction") &&
		strings.Contains(owner, "is listed as well (`whole-instantiate`)") &&
		strings.Contains(owner, "(`interface-selection`), are references to the method") &&
		strings.Contains(owner, "Every type argument is read.") &&
		strings.Contains(owner, "equal the owning type's\n(`whole-mirror`)") &&
		strings.Contains(owner, "whatever its field types and\ntags") &&
		strings.Contains(owner, "through a named or embedded constraint (`whole-constrain`)") &&
		strings.Contains(owner, "The inventory therefore lists, at its declaration, every type parameter") &&
		strings.Contains(owner, "an exact inventory holds\nevery type parameter declared in a package that declares an owning type") &&
		strings.Contains(owner, "Each owning type is read in every production package of the module") &&
		strings.Contains(owner, "Every protected field is unexported, which a test holds") &&
		strings.Contains(owner, "non-test Go file of the module is compiled for none of them") &&
		strings.Contains(owner, "a statement assembled at run time is not seen") &&
		strings.Contains(owner, "exact import inventory\ncovers every non-test source file of the module") &&
		strings.Contains(owner, "A production package is chosen by the\ndirectory the go command compiles it from, not by a pattern or by its import\npath") &&
		strings.Contains(owner, "compiles such a package when another one imports it, so it is read like every\nother") &&
		strings.Contains(owner, "in the Go root nor in the module cache fails the loader") &&
		strings.Contains(owner, "It reads every non-test Go file in every directory of the repository\nexcept `.git`, whatever the directory is called.") &&
		strings.Contains(owner, "holds each file that has such an import by the SHA-256 of its content") &&
		strings.Contains(owner, "The check lists every\ndirectory of the repository except `.git`") &&
		strings.Contains(owner, "a directive of\n`go.mod` outside the exact list `go`, `module` and `require`, which refuses a\n`replace` line") &&
		strings.Contains(owner, "a `go.work` file anywhere in the repository or above it") &&
		strings.Contains(owner, "a `go.mod` below the repository root") &&
		strings.Contains(owner, "the flags `-modfile` and `-overlay`") &&
		!strings.Contains(owner, "only at an instantiation that names an owning type") &&
		!strings.Contains(owner, "Their scope is these two") &&
		!strings.Contains(owner, "of the two packages is compiled") &&
		strings.Contains(owner, "exactly one reference to `Service.confirmOperationalAdmission`") &&
		strings.Contains(owner, "Exactly three store functions contain a statement that") &&
		strings.Contains(owner, "not a general proof of aliases or")
}

// operationalCommissioningPrerequisiteIDs reads the identifiers of the owner
// contract's §8 commissioning gate table in document order.
func operationalCommissioningPrerequisiteIDs(owner string) []string {
	var ids []string
	inTable := false
	for _, line := range strings.Split(owner, "\n") {
		if line == "| Identifier | Prerequisite |" {
			inTable = true
			continue
		}
		if !inTable {
			continue
		}
		if !strings.HasPrefix(line, "|") {
			break
		}
		cells := strings.Split(line, "|")
		if len(cells) < 3 {
			break
		}
		id := strings.TrimSpace(cells[1])
		if strings.HasPrefix(id, "`") && strings.HasSuffix(id, "`") && len(id) > 2 {
			ids = append(ids, strings.Trim(id, "`"))
		}
	}
	return ids
}

// operationalCommissioningGateIDs reads the same identifiers from the typed
// gate beside the zero-reference inventory in the admission package.
func operationalCommissioningGateIDs(source string) []string {
	const open = "var operationalCommissioningPrerequisites = []string{"
	start := strings.Index(source, open)
	if start < 0 || strings.Count(source, open) != 1 {
		return nil
	}
	body := source[start+len(open):]
	end := strings.Index(body, "}")
	if end < 0 {
		return nil
	}
	var ids []string
	for _, field := range strings.Split(body[:end], ",") {
		field = strings.TrimSpace(field)
		if field == "" {
			continue
		}
		if len(field) < 3 || field[0] != '"' || field[len(field)-1] != '"' {
			return nil
		}
		ids = append(ids, field[1:len(field)-1])
	}
	return ids
}

// Nomad's client evaluates "${...}" and "%{...}" in the strings of a task as
// a template, so the request contract refuses them, and NUL, in every string
// ES places in a job.
func TestNomadEvaluatedRequestStringsContract(t *testing.T) {
	lifecycle := compactText(mustRead(t, ".docs/execution_lifecycle/contracts.md"))
	overview := compactText(mustRead(t, ".docs/system_overview/contracts.md"))
	assertContainsAll(t, "execution lifecycle request contract", lifecycle,
		"`invocation.output_id`, every `argv` element, every environment key and value, and every mount target path must not contain `${`, `%{` or a NUL byte.",
		"rewrites the escapes `$${` and `%%{`, and replaces `${name}` in environment and meta values",
		"ES refuses such a request with `400 invalid_request` before anything is staged or sent",
		"Other control bytes are passed on as written.",
		"Every `argv` element and every mount target path must also be in Unicode Normalization Form C, must hold only code points that are assigned in the Unicode version of ES's normalization tables (today 15.0.0), and must not begin with a byte order mark (U+FEFF).",
		"which drops a byte order mark at the start of a string and holds every string in Normalization Form C",
		"two mount targets that differ only in normal form would be one path for the container",
		"A string that holds only assigned code points and is in Normalization Form C stays unchanged under every later version of the normalization tables.",
		"Environment keys and values and `invocation.output_id` are not parsed that way and are not held to this rule.",
		"CPU must be greater than zero and `memory_mb` must be at least 10, the least memory Nomad registers a task with.")
	assertContainsNone(t, "execution lifecycle request contract", lifecycle,
		"both CPU and memory must be greater than zero")
	assertContainsAll(t, "system overview invocation shape", overview,
		"(`output_id`, each `argv` element, each `env` key and value, and each mount `target_path`) must not contain `${`, `%{` or a NUL byte",
		"Each `argv` element and each mount `target_path` must also be in Unicode Normalization Form C, hold only code points assigned in the Unicode version of ES's normalization tables and not begin with a byte order mark")
}

func TestOperationalSubmitHandoffCurrentAdmissionV2Contract(t *testing.T) {
	owner := mustRead(t, operationalHandoffOwnerDoc)
	record := mustRead(t, plansRecordPath)
	admission := mustRead(t, ".docs/execution_lifecycle/es_execution_admission_model.md")
	persistence := mustRead(t, ".docs/execution_lifecycle/reliable_submit_persistence_and_concurrency.md")
	recovery := mustRead(t, ".docs/execution_lifecycle/submit_idempotency_correlation_and_recovery.md")
	boundary := mustRead(t, ".docs/system_overview/boundaries.md")
	implementation := mustRead(t, ".docs/execution_lifecycle/implementation.md")
	assertContainsAll(t, "selected v2 owner", owner,
		"operational_local_v2", "Claims **and** Seal", "256 KiB", "same admission before it can release a sender",
		"Commission, advance and withdrawal take the custody\nhandle's lock in read mode and then the SQLite writer, without `Service.mu`",
		"Unknown variants fail closed", "Re-derivation of the reliable-submit Reopened redesign seam",
		"schema 5 is unmerged, stays on the reopened seam and is not a Current invariant")
	assertContainsAll(t, "durable admission row and operations", owner,
		"SHA-256 over the label `ESOHADM1`", "Only the store mints a nonzero token",
		"| Commission | Empty table: insert generation 1 with this digest.",
		"| Advance (expected generation g) | Row at generation g with a different digest, enabled or withdrawn",
		"| Withdraw | Enabled row with the token's installation and epoch: write withdrawn.",
		"Withdrawal sets the local latch first and then writes the durable row",
		"advances the generation in the same epoch and does\nnot invalidate any original",
		"None of the three operations may run\ninside a writer turn",
		"The digest covers trust, verifier and policy configuration",
		"Confirmation is attempted at\nmost once per invocation and only at three points",
		"can only add a non-negative skew")
	assertContainsAll(t, "authority and independent evidence obligations", owner,
		"zero non-test references", "exactly one view construction, in the install method of the state", "Exact protected-field reads",
		"independently build the full scope-3 TLV and PB1", "valid signature but",
		"Transparent parentheses enclosing a resolved field", "parenthesized reads",
		"targets remain assignments", "targets remain read-writes", "not a general proof of aliases or",
		"Range-clause `=` key and value whole-field targets", "Taking a field's address is an `address` access",
		"is a `write-through` access", "ceiling for PR #12 plus its repairs was 48 files",
		"ceiling for PR #12 plus its repairs was 52 files",
		"HEAD ceiling for PR #12 plus its repairs was 53 files",
		"HEAD ceiling for PR #12 plus its repairs was 56 files",
		"HEAD ceiling for PR #12 plus its repairs was 66 files",
		"HEAD ceiling for PR #12 plus its repairs was 69 files",
		"HEAD ceiling for PR #12 plus its repairs is 70 files",
		"`trunk_dev` after its\nPRs #43, #42, #34, #31, #38, #44 and #46, are a further owner reconciliation\nat this gate.",
		"It adds exactly one more path, a test file:\nA/nomad_request_guard_test.go, PR #31's token guard, which now covers the\nprovider and reads unadjusted positions.",
		"A/reliable_submit_operational_handoff.go, A/service.go and their tests,\nwhich are already counted.",
		"gains the prerequisite `CP-NOMAD-ACL`.",
		"the provider's token is the one ES loads from `nomad.token_file` at startup for the current submit client;",
		"carries ES's Nomad\nACL client token in one `X-Nomad-Token` header and never in the URL.",
		"the provider cannot be built without a token in\nNomad's canonical SecretID form.",
		"`trunk_dev` after its PRs #33, #41, #37 and #39, are a further owner\nreconciliation at this gate.",
		"remote_alpha_es_service_tls_status_local_boundary_test.go, which keeps its\ncount there.",
		"It adds exactly three more paths, the module file and two test files:\ngo.mod, which makes `golang.org/x/text` a direct requirement at the version\nalready selected, A/nomad_request_strings_redteam31_finding_test.go\n(new), the re-check's tests, and internal/testutil/testutil_test.go, whose\nthree position reads now ignore line directives.",
		"packages of `golang.org/x/text` that the rule imports, in\nA/workstream_c_guardrails_test.go, which is already counted.",
		"owner reconciliation at this gate. Taking up `trunk_dev` adds no path.",
		"It adds exactly ten more paths, one production file, two\ndocuments and seven test files:\nA/mounts.go, whose mount target rule refuses those strings",
		".docs/execution_lifecycle/contracts.md and\n.docs/system_overview/contracts.md, which state the refusal",
		"A/nomad_request_strings_test.go (new),\nA/reliable_submit_operational_job_bound_test.go (new) and the red-team's\nfive test files",
		"A/reliable_submit_operational_admission_redteam3_test.go (new),\nA/reliable_submit_operational_admission_redteam3_codec_test.go (new),\nA/reliable_submit_operational_admission_redteam3_finding_test.go (new),\nA/reliable_submit_operational_admission_redteam3_fuzz_test.go (new) and\nA/reliable_submit_operational_admission_redteam3_process_test.go (new)",
		"It adds exactly one more path, a test file:\nA/workstream_a_guardrails_test.go",
		"It adds exactly three more paths, two test files and the CI's list:\nA/internal/admissionstate/testtmpdir_main_test.go (new)",
		"remote_alpha_es_service_tls_status_local_boundary_test.go, whose two\nposition reads now ignore line directives",
		".github/ci/environment-only-tests.txt, which gains two lines",
		"A/reliable_submit_operational_admission_redteam2_test.go (new),\nA/reliable_submit_operational_admission_redteam2_crash_test.go (new),\nA/reliable_submit_operational_admission_redteam2_guard_test.go (new) and\nA/reliable_submit_operational_admission_limits_test.go (new)",
		"A/internal/admissionstate/state.go (new) and\nA/internal/admissionstate/state_test.go (new)",
		"A retry after a changed configured literal policy, artifact revocation or", "a denial does not")
	assertContainsAll(t, "selected plan", record,
		"PR #12 retained-current-admission v2 repair", "fresh independent audit",
		"PR #12 v2 field-access guard completion", "red-team review of its",
		"PR #12 durable admission generation, freshness and v1 removal",
		"PR #12 durable admission: corrections after the second audit",
		"PR #12 durable admission: corrections after the third audit",
		"PR #12 durable admission: corrections after the fourth audit",
		"PR #12 durable admission: the admission state package",
		"PR #12 durable admission: a limit named after the fifth audit",
		"PR #12 durable admission: repairs after the red-team",
		"PR #12 durable admission: line directives after the sixth audit",
		"PR #12 durable admission: taking up trunk_dev after its PRs #23 and #22",
		"The admission state package of PR #12 is a new test package, so it\ngets that file",
		"CI's list, so the path ceiling of PR #12 plus its repairs became 56 files",
		"PR #12 durable admission: repairs after the third red-team and the guard coverage review",
		"the refusal, and seven test files are new, so the path ceiling of PR #12\nplus its repairs became 66 files",
		"PR #12 durable admission: repairs after the red-team re-check",
		"more paths, so the path ceiling of PR #12 plus its repairs became 69 files.",
		"PR #12 durable admission: Nomad's token on the private path, after PR #31",
		"sets it in the `X-Nomad-Token` header of every request,\nnever in the URL.",
		"The gate gains a seventh prerequisite,\n`CP-NOMAD-ACL`",
		"That test file is one more path, so the path ceiling of PR #12\nplus its repairs is 70 files.",
		"This entry changes no public behaviour, request contract or stored format.",
		"Taking up `trunk_dev` after its PRs #33, #41,\n#37 and #39 moves one counted test file to `scripts/`",
		"which PR #12's position-read test refuses; they now read the real\nposition.",
		"The re-check's\ntests are adopted unchanged",
		"This entry changes behaviour: a request with such an argument or mount\ntarget, or with less than 10 MB of memory, which ES accepted before, is now\nrefused",
		"Taking up `trunk_dev` after its PRs #27 and #29 adds no path.",
		"no claim, no reservation and no POST on the private path, which shares the\nvalidation",
		"This entry changes behaviour: a request that holds one of those strings,\nwhich ES accepted before, is now refused.",
		"of a reviewed list, today `//go:build` alone",
		"This entry adds one test file, changes another, changes the CI's list of\nenvironment-only tests and changes documents.",
		"The CI's list of environment-only tests gains two lines for tests\nof the handoff",
		"The list's check refuses both lines on `trunk_dev`\nalone, so they come with PR #12.",
		"PR #22 added a root test file with two reads of an adjusted\nposition",
		"The rule\nand every other guard now read the real position of the code",
		"Every non-test Go file of the repository is refused such a\ndirective as well",
		"so the path ceiling of PR #12 plus its repairs became 53 files",
		"This entry changes guard tests and documents only.",
		"two more roads of the same class\nwere measured",
		"A new raw pointer rule refuses\nsuch a value in a file that does not import `unsafe`",
		"Raw system calls stay\noutside every inventory",
		"The red-team's tests are adopted as permanent tests",
		"It changes no behaviour, no stored format and no public\ncontract. The precise wording is owned by",
		"code that writes the memory of\nits own process through the operating system",
		"so this entry adds no guard rule",
		"is inside the trust boundary of the admission state, and nothing may rely on\nthe package boundary against code of lower trust",
		"This entry changes documents and the docs contract test only",
		"It is not added to\nthe commissioning gate as a seventh prerequisite",
		"It changes no behaviour, no stored format and no public\ncontract",
		"a\nnew package, `es/admission/internal/admissionstate`, under that package's\nown lock",
		"Outside the package the compiler now refuses what the guard searched for",
		"so the module-wide\n`reflect`, `unsafe` and cgo import inventory stays as it is",
		"which can refuse a claim or\nrequire an input and cannot allow one",
		"The guard now chooses what it reads by the directory a package is compiled\nfrom",
		"Its file-set check and its import inventory read every directory of the\nrepository except `.git`",
		"is held in\nthe import inventory by the SHA-256 of its content",
		"the answer is\n`OperationalTimeout` with the stored run",
		"It lists every struct type written in the module whose field names,\norder and embedding equal an owning type's (`whole-mirror`)",
		"at its declaration\n(`whole-constrain`)",
		"which the\ncommissioning gate names as the prerequisite `CP-PUBLIC-MAPPING`",
		"The commissioning gate gains a sixth\nprerequisite, `CP-PUBLIC-MAPPING`",
		"refusal of a retained original by the current rules reports the value-free",
		"ordinary resolution refuses, which stores nothing",
		"so those two have no re-read",
		"amend the\nunmerged migration 5 (decision D-1)", "with a 30 second limit (D-2)",
		"delete `operational_local_v1` (D-3)", "no **Temporary compatibility\nedge** remains on this path",
		"`CP-ROLLBACK`, `CP-EPOCH`, `CP-POLICY-CUSTODY`, `CP-NATIVE`, `CP-RELEASE`,\n`CP-NOMAD-ACL`, `CP-PUBLIC-MAPPING`")
	assertContainsAll(t, "separate evidence and policy ownership", admission,
		"separately on `resolvedExecution`", "private SQLite writer accepts only an exact inspected",
		"one durable admission row", "does not change the epoch", "no compatibility edge is retained on this",
		"The view is held by the admission\nstate package behind its own lock",
		"naming, copying or restoring that state does not compile\noutside the package",
		"the lock of the admission\nstate protects the latches and the confirmation time",
		"Before the claim, `operationalProvider.fits` directly projects the run once\nmore",
		"only to measure Job0 and the POST body; it sends nothing")
	assertContainsAll(t, "durable admission scope", persistence,
		"historical migrations 1–4 with their literal hashes", "bounded opaque full signed",
		"`reliable_submit_operational_admission`", "It is not a durable policy decision about",
		"`operational_local_v1` is removed at both layers", "codecs 1–4 are unaffected",
		"never\ncalled inside a writer turn", "must be called outside every borrow of the\nsame custody handle",
		"at the two\npre-checks it runs under the custody read lock of the borrow",
		"brief read of the\nadmission state under its own lock")
	assertContainsAll(t, "receipt exception", recovery,
		"a committed accepted receipt is verified", "positive registration",
		"`operational_local_v1` is removed and refused", "reports denied or unavailable",
		"sends no\ntrust request")
	assertContainsAll(t, "service boundary", boundary,
		"ES alone owns current admission", "It does not move admission authority",
		"Temporary compatibility edge: none. `operational_local_v1` is removed.",
		"stores no per-claim decision")
	assertContainsAll(t, "private confirmation note", implementation,
		"confirms its commissioned trust with EGS before a retained first effect",
		"refuses unless the last confirmation is less than 30 seconds old",
		"ordinary Submit does not confirm")
	if !operationalCurrentAdmissionV2OwnerRule(owner) {
		t.Fatal("current-admission owner rule incomplete")
	}
	if !operationalV1RemovalRule(owner) {
		t.Fatal("v1 removal owner rule is incomplete")
	}
	if !operationalAdmissionOutcomeRule(owner) {
		t.Fatal("outcome mapping owner rule is incomplete")
	}
	if !operationalAdmissionLockRule(owner) {
		t.Fatal("lock statements of the admission operations and the confirmation are incomplete")
	}
	// The lock inventory row names exactly the methods that take the lock.
	if code, row := operationalCustodyLockHolders(t), operationalCustodyLockRowHolders(admission); len(code) == 0 || !slices.Equal(code, row) {
		t.Fatalf("OperationalCustody.mu holders differ: code %q, admission model row %q", code, row)
	}
	if !operationalV2AssuranceOwnerRule(owner) {
		t.Fatal("v2 authority and independent vector obligations are incomplete")
	}
	for _, production := range []string{
		"es/admission/reliable_submit_operational_admission.go", "es/admission/reliable_submit_operational_handoff.go",
		"es/admission/reliable_submit_operational_format.go", "es/admission/service.go",
		"es/admission/internal/reliablesubmit/operational_handoff.go",
		"es/admission/internal/reliablesubmit/operational_admission.go",
		"es/admission/internal/reliablesubmit/replay_custody_structure.go",
	} {
		if strings.Contains(mustRead(t, production), "operational_local_v1") {
			t.Fatalf("%s still contains the removed v1 literal", production)
		}
	}

	wantIDs := []string{"CP-ROLLBACK", "CP-EPOCH", "CP-POLICY-CUSTODY", "CP-NATIVE", "CP-RELEASE", "CP-NOMAD-ACL", "CP-PUBLIC-MAPPING"}
	docIDs := operationalCommissioningPrerequisiteIDs(owner)
	gateIDs := operationalCommissioningGateIDs(mustRead(t, "es/admission/reliable_submit_guardrails_test.go"))
	if !slices.Equal(docIDs, wantIDs) || !slices.Equal(gateIDs, wantIDs) {
		t.Fatalf("commissioning prerequisites differ: owner %q, gate %q, want %q", docIDs, gateIDs, wantIDs)
	}
}

func TestOperationalSubmitHandoffCurrentAdmissionV2RejectsUnsafeMutants(t *testing.T) {
	owner := mustRead(t, operationalHandoffOwnerDoc)
	if !operationalCurrentAdmissionV2OwnerRule(owner) {
		t.Fatal("real owner rule incomplete")
	}
	for _, tc := range []struct{ name, from, to string }{
		{"TokenComparedOutsideWriter", "the enabled admission row read under the SQLite writer lock", "a cached copy of the admission row"},
		{"EstablishUnfenced", "The presented token equals the enabled row read through the turn's connection.", "The local view is sampled."},
		{"MatchWithoutToken", "the returned match must carry a token equal to that row", "the returned match is accepted"},
		{"WriterRemoteResolver", "only bounded local Service admission", "a current remote resolver"},
		{"DeadlineLengthened", "less than 30 seconds elapsed since it on both the monotonic and", "less than 30 minutes elapsed since it on either the monotonic or"},
		{"SupersessionForgiven", "a permanent local superseded latch is set", "the view adopts the fetched trust"},
		{"FailedConfirmationExtends", "A fetch or verification failure changes nothing.", "A fetch or verification failure keeps the last confirmation current."},
		{"ReceiptPolicyGate", "but no view, token, confirmation,", "and a current view, token and confirmation, but no"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if strings.Count(owner, tc.from) != 1 {
				t.Fatalf("owner mutation anchor count %d", strings.Count(owner, tc.from))
			}
			mutated := strings.Replace(owner, tc.from, tc.to, 1)
			if operationalCurrentAdmissionV2OwnerRule(mutated) {
				t.Fatal("unsafe owner mutation survived")
			}
		})
	}
	if !operationalV1RemovalRule(owner) {
		t.Fatal("real v1 removal rule incomplete")
	}
	for _, tc := range []struct{ name, from, to string }{
		{"V1Retained", "`operational_local_v1` is removed and is not a compatibility edge.", "An `operational_local_v1` original remains a **Temporary compatibility edge**."},
		{"CustodyAcceptsV1", "Scope-3 custody refuses the", "Scope-3 custody accepts the"},
		{"ReaderAcceptsV1", "the reader refuses it in its fail-closed default", "the reader accepts it as a historical variant"},
		{"EncoderFallsBack", "refuses an empty evidence record instead of choosing a literal", "falls back to the v1 literal for an empty evidence record"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if strings.Count(owner, tc.from) != 1 {
				t.Fatalf("owner mutation anchor count %d", strings.Count(owner, tc.from))
			}
			if operationalV1RemovalRule(strings.Replace(owner, tc.from, tc.to, 1)) {
				t.Fatal("unsafe v1 mutation survived")
			}
		})
	}
	if !operationalAdmissionOutcomeRule(owner) {
		t.Fatal("real outcome rule incomplete")
	}
	for _, tc := range []struct{ name, from, to string }{
		{"DenialReportedUnavailable", "built-in policy denies | `OperationalDenied` | No |", "built-in policy denies | `OperationalUnavailable` | No |"},
		{"DenialNotLimitedToRetainedOriginals", "| Retained original: signer not allowed or revoked", "| Signer not allowed or revoked"},
		{"FirstDeliveryReportedDenied", "an unavailable dependency | `OperationalUnavailable`. Nothing is stored. | No |", "an unavailable dependency | `OperationalDenied`. Nothing is stored. | No |"},
		{"CancellationRowDropped", "returned no refusal of its own in this call | `OperationalCanceled`. `OperationalTimeout` where", "returned no refusal of its own in this call | `OperationalUnavailable`. `OperationalTimeout` where"},
		{"CancelledAnswerNeverReturnsTheRun", "is asked about the job (below) | No, except while a durable marker is reconciled, where the stored run is returned (below) |", "is asked about the job (below) | No |"},
		{"DeadlineAtTheObservationReportedCanceled", "`OperationalCanceled`. `OperationalTimeout` where the deadline of the call passes while the provider is asked about the job (below) |", "`OperationalCanceled` |"},
		{"DeadlineAtTheObservationNotStated", "is asked about the job, the exchange reports `OperationalTimeout`", "is asked about the job, the exchange reports `OperationalCanceled`"},
		{"DeadlineAtTheObservationWithholdsTheRun", "the result is the same\nambiguous one with the run", "the result is\nvalue-free"},
		{"DeadlineReportedAsTimeoutEverywhere", "a passed deadline answers `OperationalCanceled` like a cancellation.", "a passed deadline answers `OperationalTimeout`."},
		{"EveryRowValueFree", "The first five rows are value-free and withhold run and receipt at the\nrefused cut.", "Every row is value-free and withholds run and receipt at the refused cut."},
		{"CancelledAnswerAlwaysReturnsTheRun", "returns the stored run only while it reconciles a durable\nmarker", "returns the stored run wherever a\nmarker"},
		{"CancelledObservationBindingWithholdsTheRun", "during the observation of the job and at the binding\nof a completed observation.", "and during the observation of the job."},
		{"CancelledReceiptReplayReturnsTheRun", "So is the one from the\nverification of an accepted receipt, although", "Not so the one from the\nverification of an accepted receipt, because"},
		{"PublicMappingLeftToALaterGate", "names it as the prerequisite `CP-PUBLIC-MAPPING`", "leaves it to a later gate"},
		{"CancelledStepReportsItsOwnReason", "an ended context reports the cancellation and not `OperationalUnavailable` or", "an ended context reports its own reason, `OperationalUnavailable` or"},
		{"CancellationBeatsDenial", "also when the\ncontext has ended meanwhile", "unless the\ncontext has ended meanwhile"},
		{"ResidueOnlyAfterDenial", "That holds whatever stopped the call between staging and the stamp", "That holds only for a denial between staging and the stamp"},
		{"DenialDisclosesRun", "built-in policy denies | `OperationalDenied` | No |", "built-in policy denies | `OperationalDenied` | Yes |"},
		{"FenceReportedDenied", "missing bounded payload | `OperationalUnavailable` | No |", "missing bounded payload | `OperationalDenied` | No |"},
		{"CancellationWins", "at reconciliation and at the final sender entry alike", "except at reconciliation and at the final sender entry"},
		{"DenialPoisonsEverywhere", "so before staging a denial does not poison the claim", "so a denial never poisons the claim"},
		{"WithdrawalRetractsSender", "one\nsender already past its release re-read may still POST", "no sender can POST afterwards"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if strings.Count(owner, tc.from) != 1 {
				t.Fatalf("owner mutation anchor count %d", strings.Count(owner, tc.from))
			}
			if operationalAdmissionOutcomeRule(strings.Replace(owner, tc.from, tc.to, 1)) {
				t.Fatal("unsafe outcome mutation survived")
			}
		})
	}
	if !operationalAdmissionLockRule(owner) {
		t.Fatal("real lock rule incomplete")
	}
	for _, tc := range []struct{ name, from, to string }{
		{"ConfirmationOutsideEveryLock", "Confirmation runs outside every writer turn and every transaction, and holds\nneither `Service.mu` nor the owner mutex while it fetches.", "Confirmation runs outside every lock and every transaction."},
		{"ConfirmationTakesNoLock", "pre-checks it runs inside the borrow of the original, so the custody handle's\nread lock is held across the request", "pre-checks it takes no lock while it fetches"},
		{"OperationsNeverTakeCustodyLock", "handle's lock in read mode (`OperationalCustody.mu`), so `Close` waits for it.", "handle's SQLite writer and never custody locks."},
		{"OperationsAllowedInsideBorrow", "must therefore be called outside every borrow of the same handle", "may be called inside a borrow of the same handle"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if strings.Count(owner, tc.from) != 1 {
				t.Fatalf("owner mutation anchor count %d", strings.Count(owner, tc.from))
			}
			if operationalAdmissionLockRule(strings.Replace(owner, tc.from, tc.to, 1)) {
				t.Fatal("unsafe lock statement survived")
			}
		})
	}
	t.Run("LockInventoryRowOmitsAHolder", func(t *testing.T) {
		admission := mustRead(t, ".docs/execution_lifecycle/es_execution_admission_model.md")
		const entry = "`OperationalCustody.operationalAdmissionWrite`, "
		if strings.Count(admission, entry) != 1 {
			t.Fatalf("lock row anchor count %d", strings.Count(admission, entry))
		}
		code := operationalCustodyLockHolders(t)
		if row := operationalCustodyLockRowHolders(strings.Replace(admission, entry, "", 1)); slices.Equal(code, row) {
			t.Fatalf("a row without operationalAdmissionWrite still equals the code: %q", row)
		}
		if row := operationalCustodyLockRowHolders(admission); !slices.Contains(code, "operationalAdmissionWrite") || !slices.Equal(code, row) {
			t.Fatalf("real lock row differs from the code: code %q row %q", code, row)
		}
	})
	for _, tc := range []struct{ name, phrase string }{
		{"MissingZeroCommissionInventory", "zero non-test references"},
		{"MissingViewConstructionOwner", "exactly one view construction, in the install method of the state"},
		{"MissingStateConstructionOwner", "admission state, in its constructor, which `NewService` alone calls"},
		{"MissingStatePackageOwnsItsLock", "under that package's own read-write\nlock"},
		{"MissingStatePackageImportRule", "It imports neither `reflect`, `unsafe` nor `C` and performs no I/O"},
		{"MissingOpaqueHandleRule", "Each is a struct whose only field is an unexported pointer\nto an unexported struct"},
		{"MissingClosedZeroHandle", "holds the zero handle, which is closed"},
		{"MissingContentCopyRule", "It is copied on the way in and on every way out"},
		{"MissingCompileRefusalList", "Outside the package the following do not compile"},
		{"MissingCompileRefusalTest", "type-checking each form against the real packages for all three build\ntargets"},
		{"MissingTypeCheckerNotCompiler", "it does not run the compiler itself"},
		{"MissingRemainingRoads", "Two things remain possible outside the package"},
		{"MissingCallLimits", "A call cannot clear a latch, move the\nconfirmation time back or install a second view"},
		{"MissingSavedHandleRule", "names the same state and restores nothing"},
		{"MissingReflectionLimitOfThePackage", "The package boundary does not hold against reflection or `unsafe`"},
		{"MissingOwnMemoryLimitOfThePackage", "holds against code that\nwrites the memory of its own process without going through the language"},
		{"MissingOwnMemoryNeedsNoPinnedImport", "The function imports neither\n`reflect`, `unsafe` nor `C`, names no protected field"},
		{"MissingOwnMemoryHasNoGeneralGuard", "No source inventory can hold that\nroad in general"},
		{"MissingTrustBoundaryOfTheState", "dependency is therefore inside the trust boundary of the admission\nstate"},
		{"MissingBoundaryOfTheLanguage", "The boundary is one of the language, not of the process"},
		{"MissingLowerTrustRule", "nothing may\nrely on it against code of lower trust in the same process"},
		{"MissingOwnMemoryInTheLimits", "One limit has no inventory at all"},
		{"MissingOSRoadNamed", "The other ways to that memory are system calls"},
		{"MissingSyscallImportersNotListed", "The import inventory below does not list the files that import\n`syscall` or `golang.org/x/sys/unix`"},
		{"MissingLanguageRoadsHeld", "Two kinds of road do go through the language without a `reflect`, `unsafe`\nor `C` import, and the guard holds both"},
		{"MissingRawPointerConverts", "converts to a pointer of any type in every\nfile; the import of `unsafe` is needed only to spell the type"},
		{"MissingRawPointerNeedsUnsafe", "So a raw pointer value may appear only in a file that imports\n`unsafe`"},
		{"MissingUnreviewedDependencyInventoried", "So an import of a dependency package outside a\nreviewed list puts its file into the import inventory as well"},
		{"MissingPluginInventoried", "`unsafe`, `C` or `plugin` import in any production package fails a test"},
		{"MissingUnreviewedDependencyFails", "and so does an import of a dependency package outside the reviewed list"},
		{"MissingReviewedVersionPin", "a new dependency import, a further package of a\nlisted module, a new version and a replacement each fail until the list is\nupdated"},
		{"MissingRawPointerRule", "value whose type has the underlying type `unsafe.Pointer` in a file that\ndoes not import `unsafe` fails it"},
		{"MissingRawPointerRealPosition", "It judges the file that holds each such\nvalue by the value's real position, not by the file and line that a\n`//line` or `/*line` directive names"},
		{"MissingAdjustedPositionReadsRefused", "a test refuses the calls that read an adjusted position in the\ntest files of the module"},
		{"MissingLineDirectivesRefused", "another test refuses such a directive in every\nnon-test Go file of the repository"},
		{"MissingStaticTypesOfTheSource", "The rule reads the static types of the source"},
		{"MissingTypeParameterCannotConvert", "it cannot become a typed pointer there\nwithout a constraint that spells the type"},
		{"MissingUnknownRoadsNotExcluded", "a source inventory\ncannot show that no other road exists"},
		{"MissingAdoptedTestsCeiling", "aggregate HEAD ceiling for PR #12 plus its repairs was 52 files"},
		{"MissingSixthAuditCeiling", "HEAD ceiling for PR #12 plus its repairs was 53 files"},
		{"MissingTrunkDevCeiling", "HEAD ceiling for PR #12 plus its repairs was 56 files"},
		{"MissingThirdRedTeamCeiling", "HEAD ceiling for PR #12 plus its repairs was 66 files"},
		{"MissingRedTeamRecheckCeiling", "HEAD ceiling for PR #12 plus its repairs was 69 files"},
		{"MissingNomadTokenCeiling", "HEAD ceiling for PR #12 plus its repairs is 70 files"},
		{"MissingNomadTokenTrunkDevPRs", "`trunk_dev` after its\nPRs #43, #42, #34, #31, #38, #44 and #46, are a further owner reconciliation\nat this gate."},
		{"MissingNomadTokenGuardPath", "It adds exactly one more path, a test file:\nA/nomad_request_guard_test.go, PR #31's token guard, which now covers the\nprovider and reads unadjusted positions."},
		{"MissingNomadTokenCountedPaths", "A/reliable_submit_operational_handoff.go, A/service.go and their tests,\nwhich are already counted."},
		{"MissingNomadTokenHeader", "carries ES's Nomad\nACL client token in one `X-Nomad-Token` header and never in the URL."},
		{"MissingNomadTokenRequired", "the provider cannot be built without a token in\nNomad's canonical SecretID form."},
		{"MissingNomadACLTokenCustody", "the provider's token is the one ES loads from `nomad.token_file` at startup for the current submit client;"},
		{"MissingRedTeamRecheckTrunkDevPRs", "`trunk_dev` after its PRs #33, #41, #37 and #39, are a further owner\nreconciliation at this gate."},
		{"MissingRedTeamRecheckMovedPath", "remote_alpha_es_service_tls_status_local_boundary_test.go, which keeps its\ncount there."},
		{"MissingRedTeamRecheckPaths", "It adds exactly three more paths, the module file and two test files:\ngo.mod, which makes `golang.org/x/text` a direct requirement at the version\nalready selected, A/nomad_request_strings_redteam31_finding_test.go\n(new), the re-check's tests, and internal/testutil/testutil_test.go, whose\nthree position reads now ignore line directives."},
		{"MissingRedTeamRecheckReviewedList", "packages of `golang.org/x/text` that the rule imports, in\nA/workstream_c_guardrails_test.go, which is already counted."},
		{"MissingThirdRedTeamCountedTests", "test of those lengths are in A/workstream_c_guardrails_test.go and\nI/operational_handoff_test.go, which are already counted."},
		{"MissingThirdRedTeamNoTrunkDevPath", "owner reconciliation at this gate. Taking up `trunk_dev` adds no path."},
		{"MissingThirdRedTeamMountsPath", "It adds exactly ten more paths, one production file, two\ndocuments and seven test files:\nA/mounts.go, whose mount target rule refuses those strings"},
		{"MissingThirdRedTeamContractsPaths", ".docs/execution_lifecycle/contracts.md and\n.docs/system_overview/contracts.md, which state the refusal"},
		{"MissingThirdRedTeamTestPaths", "A/nomad_request_strings_test.go (new),\nA/reliable_submit_operational_job_bound_test.go (new) and the red-team's\nfive test files"},
		{"MissingThirdRedTeamAdoptedTestPaths", "A/reliable_submit_operational_admission_redteam3_test.go (new),\nA/reliable_submit_operational_admission_redteam3_codec_test.go (new),\nA/reliable_submit_operational_admission_redteam3_finding_test.go (new),\nA/reliable_submit_operational_admission_redteam3_fuzz_test.go (new) and\nA/reliable_submit_operational_admission_redteam3_process_test.go (new)"},
		{"MissingJobBoundForm", "Job0 ≤65536\nbytes as Go's `encoding/json` writes it"},
		{"MissingJobBoundEchoReason", "That form is at least as long as the one Nomad's\nAPI writes when GET Job returns the job"},
		{"MissingJobFitBeforeClaim", "Before the claim is stored, ES\nprojects Job0 and the POST body"},
		{"MissingJobFitTakesNoClaim", "either bound as `OperationalMalformed`, with no claim, no reservation and no\npublication"},
		{"MissingDynamicImportDirective", "`//go:cgo_import_dynamic _ _\n\"name\"` makes a `CGO_ENABLED=0` build a dynamic executable"},
		{"MissingDirectiveAllowlist", "may hold only\nthe `//go:` directives of an exact reviewed list, today `//go:build`\nalone"},
		{"MissingDirectiveAllowlistExact", "and a test fails on any other verb and on a listed verb that no\nfile holds"},
		{"MissingTrunkDevStartupPath", "It adds exactly three more paths, two test files and the CI's list:\nA/internal/admissionstate/testtmpdir_main_test.go (new)"},
		{"MissingTrunkDevPositionReadsPath", "remote_alpha_es_service_tls_status_local_boundary_test.go, whose two\nposition reads now ignore line directives"},
		{"MissingTrunkDevCIListPath", ".github/ci/environment-only-tests.txt, which gains two lines"},
		{"MissingSixthAuditPath", "It adds exactly one more path, a test file:\nA/workstream_a_guardrails_test.go"},
		{"MissingSyscallsInTheLimit", "Raw system calls through `syscall` and `golang.org/x/sys/unix` are part of\nthat limit"},
		{"MissingCallSiteInventory", "has an exact list of the functions that\nreference it"},
		{"MissingInspectionInventory", "which exist for tests, nowhere"},
		{"MissingClosedSurface", "surface of the package is a closed list"},
		{"MissingStateFilePin", "package is pinned by the SHA-256 hash of its bytes"},
		{"MissingInstallLockOrder", "`Service.mu` and then the lock of the admission state"},
		{"MissingHolderInventoryRule", "fails the guard until it has an inventory"},
		{"MissingHandleVariableRule", "a package variable that holds\na handle is refused"},
		{"MissingIndependentBindingOracle", "independently build the full scope-3 TLV and PB1"},
		{"MissingParenthesizedAssignmentRule", "targets remain assignments"},
		{"MissingParenthesizedReadWriteRule", "targets remain read-writes"},
		{"MissingRangeAssignmentRule", "Range-clause `=` key and value whole-field targets"},
		{"MissingAddressAccessRule", "Taking a field's address is an `address` access"},
		{"MissingWriteThroughRule", "is a `write-through` access"},
		{"MissingConversionStepRule", "A conversion is a transparent step in that chain"},
		{"MissingWholeValueRule", "occurrence of its owning struct type as its own access kind"},
		{"MissingConstructionEscapeRule", "a zero-value declaration and a same-shape"},
		{"MissingConversionAwayRule", "a conversion in either direction"},
		{"MissingInstantiationRule", "is listed as well (`whole-instantiate`)"},
		{"MissingDynamicDispatchRule", "(`interface-selection`), are references to the method"},
		{"MissingEveryTypeArgumentRule", "Every type argument is read."},
		{"MissingMirrorRule", "equal the owning type's\n(`whole-mirror`)"},
		{"MissingMirrorFieldTypeRule", "whatever its field types and\ntags"},
		{"MissingConstrainRule", "through a named or embedded constraint (`whole-constrain`)"},
		{"MissingConstrainAtDeclarationRule", "The inventory therefore lists, at its declaration, every type parameter"},
		{"MissingTypeParameterInventory", "an exact inventory holds\nevery type parameter declared in a package that declares an owning type"},
		{"MissingModuleWideReading", "Each owning type is read in every production package of the module"},
		{"MissingUnexportedFieldRule", "Every protected field is unexported, which a test holds"},
		{"MissingFileSetRule", "non-test Go file of the module is compiled for none of them"},
		{"MissingRunTimeStatementLimit", "a statement assembled at run time is not seen"},
		{"MissingImportInventory", "exact import inventory\ncovers every non-test source file of the module"},
		{"MissingSelectionByDirectory", "A production package is chosen by the\ndirectory the go command compiles it from"},
		{"MissingUnmatchedDirectoryRule", "so it is read like every\nother"},
		{"MissingOutsideDirectoryRefusal", "in the Go root nor in the module cache fails the loader"},
		{"MissingEveryDirectoryImportReading", "It reads every non-test Go file in every directory of the repository\nexcept `.git`"},
		{"MissingContentPin", "holds each file that has such an import by the SHA-256 of its content"},
		{"MissingEveryDirectoryFileSet", "The check lists every\ndirectory of the repository except `.git`"},
		{"MissingDirectiveKindList", "outside the exact list `go`, `module` and `require`"},
		{"MissingWorkspaceRefusal", "a `go.work` file anywhere in the repository or above it"},
		{"MissingNestedModuleRefusal", "a `go.mod` below the repository root"},
		{"MissingBuildInputLimit", "the flags `-modfile` and `-overlay`"},
		{"MissingConfirmationInventory", "exactly one reference to `Service.confirmOperationalAdmission`"},
		{"MissingAdmissionTableWriterInventory", "Exactly three store functions contain a statement that"},
		{"MissingFiniteGuardLimit", "not a general proof of aliases or"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if !strings.Contains(owner, tc.phrase) {
				t.Fatal("owner contract anchor missing")
			}
			mutant := strings.Replace(owner, tc.phrase, "unmaintained", 1)
			if operationalV2AssuranceOwnerRule(mutant) {
				t.Fatal("unsafe owner deletion survived")
			}
		})
	}
	for _, tc := range []struct{ name, from, to string }{
		{"GenericListedOnlyAtInstantiation", "which is a limit of dataflow\nand no longer one of generics", "where a generic one is listed\nonly at an instantiation that names an owning type"},
		{"InventoriesScopedToTwoPackages", "Each owning type is read in every production package of the module", "Their scope is these two packages"},
		{"FileSetScopedToTwoPackages", "non-test Go file of the module is compiled for none of them", "non-test Go file of the two packages is compiled for none of them"},
		{"ImportInventoryScopedToTwoPackages", "covers every non-test source file of the module", "covers every non-test source file of `es/admission` and the store package"},
		{"MirrorRuleLimitedToFieldTypes", "whatever its field types and\ntags", "where its field types and\ntags are the owner's"},
		{"PackagesChosenByPattern", "directory the go command compiles it from, not by a pattern or by its import\npath", "pattern `./...`, not by the directory the go command compiles it from"},
		{"UnmatchedDirectoriesNotRead", "so it is read like every\nother", "and it is not\nread"},
		{"ImportInventorySkipsDirectories", "in every directory of the repository\nexcept `.git`, whatever the directory is called", "in every directory that `./...` matches"},
		{"ImportedFilesHeldByNameOnly", "by the SHA-256 of its content", "by its name"},
		{"FileSetSkipsDirectories", "The check lists every\ndirectory of the repository except `.git`", "The check lists every\ndirectory that `./...` matches"},
		{"ReplaceLineAllowed", "which refuses a\n`replace` line", "which allows a\n`replace` line"},
		{"WorkspaceOnlyInsideTheRepository", "anywhere in the repository or above it", "at the repository root"},
		{"StateBackUnderTheServiceLock", "lock. `Service.mu` does not cover them.", "lock. `Service.mu` covers them as well."},
		{"StatePackageMayReflect", "It imports neither `reflect`, `unsafe` nor `C` and performs no I/O", "It may import `reflect` and performs no I/O"},
		{"HandleFieldExported", "whose only field is an unexported pointer\nto an unexported struct", "whose only field is an exported pointer\nto an unexported struct"},
		{"ZeroHandleOpen", "holds the zero handle, which is closed", "holds the zero handle, which is commissioned on first use"},
		{"ContentSharedWithTheCaller", "It is copied on the way in and on every way out", "It is shared with the caller on the way in"},
		{"CompileRefusalsUntested", "type-checking each form against the real packages for all three build\ntargets", "reading the Go specification"},
		{"FormsSaidToRunTheCompiler", "it does not run the compiler itself", "it runs the compiler itself"},
		{"CallsNotInventoried", "the guard below holds\nboth by exact inventories", "review holds\nboth"},
		{"CallClearsALatch", "A call cannot clear a latch, move the\nconfirmation time back or install a second view", "A call can clear a latch"},
		{"SavedHandleRestores", "names the same state and restores nothing", "restores the latches it held"},
		{"PackageBoundaryHoldsReflection", "The package boundary does not hold against reflection or `unsafe`", "The package boundary holds against reflection and `unsafe`"},
		{"PackageBoundaryHoldsOwnMemoryWrites", "Neither the package boundary nor any inventory below holds against code that\nwrites the memory of its own process", "The package boundary and the inventories below hold against code that\nwrites the memory of its own process"},
		{"OwnMemoryWriteNeedsAPinnedImport", "The function imports neither\n`reflect`, `unsafe` nor `C`, names no protected field", "The function imports\n`unsafe` and names a protected field"},
		{"OwnMemoryHeldByAnInventory", "No source inventory can hold that\nroad in general", "The import inventory holds that\nroad"},
		{"DependenciesOutsideTheTrustBoundary", "dependency is therefore inside the trust boundary of the admission\nstate", "dependency is nevertheless outside the trust boundary of the admission\nstate"},
		{"BoundaryOfTheProcess", "The boundary is one of the language, not of the process", "The boundary is one of the process"},
		{"LowerTrustCodeMayRelyOnIt", "nothing may\nrely on it against code of lower trust in the same process", "code of lower trust in the same process may\nbe held by it"},
		{"EveryLimitInventoried", "One limit has no inventory at all", "Every limit has an inventory"},
		{"OSRoadInventoried", "The other ways to that memory are system calls", "The other ways to that memory are held by the import inventory"},
		{"SyscallImportersListed", "The import inventory below does not list the files that import\n`syscall` or `golang.org/x/sys/unix`", "The import inventory below lists every file that imports\n`syscall` or `golang.org/x/sys/unix`"},
		{"LanguageRoadsUnheld", "or `C` import, and the guard holds both", "or `C` import, and no guard holds them"},
		{"RawPointerNeedsTheImportToConvert", "converts to a pointer of any type in every\nfile; the import of `unsafe` is needed only to spell the type", "converts to a pointer only in a file that imports `unsafe`"},
		{"RawPointerAnywhere", "So a raw pointer value may appear only in a file that imports\n`unsafe`", "So a raw pointer value may appear in any file"},
		{"UnreviewedDependencyFree", "reviewed list puts its file into the import inventory as well", "reviewed list needs no inventory"},
		{"PluginNotInventoried", "`unsafe`, `C` or `plugin` import in any production package fails a test", "`unsafe` or `C` import in any production package fails a test"},
		{"NewVersionPasses", "a new version and a replacement each fail until the list is\nupdated", "a new version and a replacement pass without a change of the\nlist"},
		{"RawPointerWithoutUnsafePasses", "does not import `unsafe` fails it", "does not import `unsafe` passes it"},
		{"RawPointerPlacedByDirective", "by the value's real position, not by the file and line that a\n`//line` or `/*line` directive names", "by the file and line that a\n`//line` or `/*line` directive names"},
		{"AdjustedPositionReadsAllowed", "a test refuses the calls that read an adjusted position", "a test allows the calls that read an adjusted position"},
		{"LineDirectivesAllowed", "another test refuses such a directive in every\nnon-test Go file", "such a directive is allowed in every\nnon-test Go file"},
		{"InstancesClaimedRead", "The rule reads the static types of the source", "The rule reads every instance of a type parameter"},
		{"TypeParameterConverts", "it cannot become a typed pointer there\nwithout a constraint that spells the type", "it can become a typed pointer there\nwithout a constraint that spells the type"},
		{"NoOtherRoadClaimed", "a source inventory\ncannot show that no other road exists", "no other road\nexists"},
		{"CeilingNotRaisedForAdoptedTests", "aggregate HEAD ceiling for PR #12 plus its repairs was 52 files", "aggregate HEAD ceiling for PR #12 plus its repairs was 48 files"},
		{"CeilingNotRaisedForSixthAudit", "HEAD ceiling for PR #12 plus its repairs was 53 files", "HEAD ceiling for PR #12 plus its repairs was 52 files"},
		{"CeilingNotRaisedForTrunkDev", "HEAD ceiling for PR #12 plus its repairs was 56 files", "HEAD ceiling for PR #12 plus its repairs was 55 files"},
		{"CeilingNotRaisedForThirdRedTeam", "HEAD ceiling for PR #12 plus its repairs was 66 files", "HEAD ceiling for PR #12 plus its repairs was 56 files"},
		{"CeilingNotRaisedForRedTeamRecheck", "HEAD ceiling for PR #12 plus its repairs was 69 files", "HEAD ceiling for PR #12 plus its repairs was 66 files"},
		{"CeilingNotRaisedForNomadToken", "HEAD ceiling for PR #12 plus its repairs is 70 files", "HEAD ceiling for PR #12 plus its repairs is 69 files"},
		{"NomadTokenGuardPathUnnamed", "It adds exactly one more path, a test file:\nA/nomad_request_guard_test.go,", "It adds no path:\nnone,"},
		{"NomadTokenInURL", "in one `X-Nomad-Token` header and never in the URL.", "in the URL query."},
		{"NomadTokenOptional", "the provider cannot be built without a token in\nNomad's canonical SecretID form.", "the provider may be built without a token."},
		{"RedTeamRecheckModulePathUnnamed", "It adds exactly three more paths, the module file and two test files:\ngo.mod, which makes `golang.org/x/text` a direct requirement at the version\nalready selected", "It adds exactly one more path, a test file:\nnone"},
		{"RedTeamRecheckTestPathUnnamed", "A/nomad_request_strings_redteam31_finding_test.go\n(new), the re-check's tests,", "and the re-check's tests,"},
		{"RedTeamRecheckTestutilPathUnnamed", "and internal/testutil/testutil_test.go, whose\nthree position reads now ignore line directives.", "and no other file."},
		{"RedTeamRecheckMovedPathUncounted", "which keeps its\ncount there.", "which no longer\ncounts."},
		{"ThirdRedTeamMountsPathUnnamed", "It adds exactly ten more paths, one production file, two\ndocuments and seven test files:\nA/mounts.go, whose mount target rule refuses those strings", "It adds no path"},
		{"ThirdRedTeamAdoptedTestsUnnamed", "A/reliable_submit_operational_admission_redteam3_test.go (new),\nA/reliable_submit_operational_admission_redteam3_codec_test.go (new),\nA/reliable_submit_operational_admission_redteam3_finding_test.go (new),\nA/reliable_submit_operational_admission_redteam3_fuzz_test.go (new) and\nA/reliable_submit_operational_admission_redteam3_process_test.go (new)", "and the red-team's tests"},
		{"JobBoundCanonicalAgain", "Job0 ≤65536\nbytes as Go's `encoding/json` writes it", "Canonical Job0 ≤65536\nbytes"},
		{"JobFitAfterClaim", "Before the claim is stored, ES\nprojects Job0 and the POST body", "After the claim is stored, ES\nprojects Job0 and the POST body"},
		{"JobFitTakesAClaim", "either bound as `OperationalMalformed`, with no claim, no reservation and no\npublication", "either bound as `OperationalMalformed` after its claim"},
		{"DirectivesUnlisted", "may hold only\nthe `//go:` directives of an exact reviewed list, today `//go:build`\nalone", "may hold any\n`//go:` directive"},
		{"TrunkDevStartupPathUnnamed", "It adds exactly three more paths, two test files and the CI's list:\nA/internal/admissionstate/testtmpdir_main_test.go (new)", "It adds no path"},
		{"TrunkDevPositionReadsPathUnnamed", "remote_alpha_es_service_tls_status_local_boundary_test.go, whose two\nposition reads now ignore line directives", "and no other file"},
		{"TrunkDevCIListPathUnnamed", ".github/ci/environment-only-tests.txt, which gains two lines", "the CI's list is unchanged"},
		{"SixthAuditPathUnnamed", "It adds exactly one more path, a test file:\nA/workstream_a_guardrails_test.go", "It adds no path"},
		{"SyscallsHeldByTheInventory", "Raw system calls through `syscall` and `golang.org/x/sys/unix` are part of\nthat limit", "Raw system calls through `syscall` and `golang.org/x/sys/unix` are held by\nthe import inventory"},
		{"InspectionUsedInProduction", "which exist for tests, nowhere", "in production diagnostics"},
		{"SurfaceOpen", "surface of the package is a closed list", "surface of the package is open"},
		{"StateFileHeldByNameOnly", "package is pinned by the SHA-256 hash of its bytes", "package is held by its name"},
		{"InstallLockOrderReversed", "Installing a view takes\n`Service.mu` and then the lock of the admission state", "Installing a view takes\nthe lock of the admission state and then `Service.mu`"},
		{"HoldersNeedNoInventory", "fails the guard until it has an inventory", "needs no inventory"},
		{"HandleVariableAllowed", "a package variable that holds\na handle is refused", "a package variable may hold\na handle"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if strings.Count(owner, tc.from) != 1 {
				t.Fatalf("owner mutation anchor count %d", strings.Count(owner, tc.from))
			}
			if operationalV2AssuranceOwnerRule(strings.Replace(owner, tc.from, tc.to, 1)) {
				t.Fatal("a corrected guard limit stated again survived")
			}
		})
	}
	t.Run("ParenthesizedWriteDowngrade", func(t *testing.T) {
		const accurate = "targets remain assignments"
		if strings.Count(owner, accurate) != 1 {
			t.Fatalf("parenthesized assignment owner anchor count %d", strings.Count(owner, accurate))
		}
		mutant := strings.Replace(owner, accurate, "targets become reads", 1)
		if operationalV2AssuranceOwnerRule(mutant) {
			t.Fatal("parenthesized write downgrade survived owner wording guard")
		}
	})
	t.Run("WriteThroughDowngrade", func(t *testing.T) {
		const accurate = "is a `write-through` access"
		if strings.Count(owner, accurate) != 1 {
			t.Fatalf("write-through owner anchor count %d", strings.Count(owner, accurate))
		}
		mutant := strings.Replace(owner, accurate, "remains a read", 1)
		if operationalV2AssuranceOwnerRule(mutant) {
			t.Fatal("write-through downgrade survived owner wording guard")
		}
	})
	t.Run("PrerequisiteRemovedFromOwner", func(t *testing.T) {
		const row = "| `CP-EPOCH` |"
		if strings.Count(owner, row) != 1 {
			t.Fatalf("prerequisite row anchor count %d", strings.Count(owner, row))
		}
		ids := operationalCommissioningPrerequisiteIDs(strings.Replace(owner, row, "| CP-EPOCH (answered) |", 1))
		if slices.Contains(ids, "CP-EPOCH") || len(ids) != 6 {
			t.Fatalf("a removed prerequisite was still read: %q", ids)
		}
	})
	t.Run("PublicMappingRemovedFromOwner", func(t *testing.T) {
		const row = "| `CP-PUBLIC-MAPPING` |"
		if strings.Count(owner, row) != 1 {
			t.Fatalf("prerequisite row anchor count %d", strings.Count(owner, row))
		}
		ids := operationalCommissioningPrerequisiteIDs(strings.Replace(owner, row, "| CP-PUBLIC-MAPPING (later) |", 1))
		if slices.Contains(ids, "CP-PUBLIC-MAPPING") || len(ids) != 6 {
			t.Fatalf("a removed prerequisite was still read: %q", ids)
		}
	})
	t.Run("PublicMappingRemovedFromGate", func(t *testing.T) {
		gate := mustRead(t, "es/admission/reliable_submit_guardrails_test.go")
		const entry = ", \"CP-PUBLIC-MAPPING\""
		if strings.Count(gate, entry) != 1 {
			t.Fatalf("gate anchor count %d", strings.Count(gate, entry))
		}
		ids := operationalCommissioningGateIDs(strings.Replace(gate, entry, "", 1))
		if slices.Contains(ids, "CP-PUBLIC-MAPPING") || len(ids) != 6 {
			t.Fatalf("a removed gate prerequisite was still read: %q", ids)
		}
	})
	t.Run("NomadACLRemovedFromOwner", func(t *testing.T) {
		const row = "| `CP-NOMAD-ACL` |"
		if strings.Count(owner, row) != 1 {
			t.Fatalf("prerequisite row anchor count %d", strings.Count(owner, row))
		}
		ids := operationalCommissioningPrerequisiteIDs(strings.Replace(owner, row, "| CP-NOMAD-ACL (done by PR #31) |", 1))
		if slices.Contains(ids, "CP-NOMAD-ACL") || len(ids) != 6 {
			t.Fatalf("a removed prerequisite was still read: %q", ids)
		}
	})
	t.Run("NomadACLRemovedFromGate", func(t *testing.T) {
		gate := mustRead(t, "es/admission/reliable_submit_guardrails_test.go")
		const entry = " \"CP-NOMAD-ACL\","
		if strings.Count(gate, entry) != 1 {
			t.Fatalf("gate anchor count %d", strings.Count(gate, entry))
		}
		ids := operationalCommissioningGateIDs(strings.Replace(gate, entry, "", 1))
		if slices.Contains(ids, "CP-NOMAD-ACL") || len(ids) != 6 {
			t.Fatalf("a removed gate prerequisite was still read: %q", ids)
		}
	})
	t.Run("PrerequisiteRemovedFromGate", func(t *testing.T) {
		gate := mustRead(t, "es/admission/reliable_submit_guardrails_test.go")
		const entry = "\"CP-ROLLBACK\", "
		if strings.Count(gate, entry) != 1 {
			t.Fatalf("gate anchor count %d", strings.Count(gate, entry))
		}
		ids := operationalCommissioningGateIDs(strings.Replace(gate, entry, "", 1))
		if slices.Contains(ids, "CP-ROLLBACK") || len(ids) != 6 {
			t.Fatalf("a removed gate prerequisite was still read: %q", ids)
		}
	})
}

// TestARSStorageCheckDocsContract pins what the plan, the bring-up runbook and
// the configuration page say about bring-up's ARS storage check after audit
// 20 of pull request #19: storage paths must be in normal form (A20-1), the
// check scales to ARS's full sha256/xx/yy fan-out and ARS's readiness wait
// starts only after its launcher's check (A20-2), the check no longer lists
// directories with ls, and the full fan-out test pins the check's cost by the
// processes it starts, not by a time limit (audit 24, O24-1).
func TestARSStorageCheckDocsContract(t *testing.T) {
	stale := []string{
		"few hundred",
		"lists every storage directory",
		"lists every such directory",
		"`mktemp`, `ls`, `cat`",
		"requires under 30 s",
	}
	checks := []struct {
		path     string
		required []string
	}{
		// PLANS.md and the other three standing rule files get only the
		// stale-wording check: the rule itself is in the host and runtime
		// boundary standing rules.
		{"PLANS.md", nil},
		{standingAdmissionRulesPath, nil},
		{standingRouteRulesPath, nil},
		{standingWorkstreamsPath, nil},
		{standingHostRuntimePath, []string{
			"`storage.root_dir` and `storage.index_file` must be absolute and written in normal form, as Python's `os.path.normpath` writes it",
			"because ARS opens both exactly as written while the mounts it gets use the normal form",
			"creates a file in every directory under the storage root and finds it again by listing that directory",
			"The check needs `/bin/sh` with `mktemp`, `xargs`, `rm`, `cat`, `chmod` and `mv` in the image",
			"starts no process per directory, because ARS's blob layout `sha256/xx/yy/<digest>` grows to 65,794 directories with the root",
			"`TestARSStorageCheckScalesToARSFullFanOut` pins that cost by structure, not by time: it counts the processes the check starts at that size",
			"and requires fewer than one per 32 directories",
			"ARS's readiness wait (`READY_TIMEOUT_SECONDS`) starts only once the launcher reports that its check passed",
			"the report cannot skip the check",
			"the check passes the first such signal on to its probe and waits until the probe has removed its files and ended, however often it is signalled again",
			"can leave at most one batch of its empty `.ars-storage-check.*` files, those of 256 directories",
		}},
		{".runbooks/system/Governed Execution ES System Bring-Up.md", []string{
			"`storage.root_dir` and `storage.index_file` are absolute paths written in normal form",
			"so the refusal prints the form to write instead",
			"finds its file again by listing each storage directory",
			"The check takes seconds even when ARS's storage holds all 65,794 directories its `sha256/xx/yy` layout can create",
			"ARS's readiness wait (`READY_TIMEOUT_SECONDS`, 30 s by default) starts only once ARS's launcher has passed its own run of the check",
			"Ctrl-C during the check, or during `up` while ARS's launcher runs it, leaves the storage as it was",
		}},
		{".docs/system_overview/configuration.md", []string{
			"refuses unless `storage.root_dir` and `storage.index_file` are absolute and in normal form (ARS opens them exactly as written, while its mounts use the normal form)",
			"finds its file again by listing each storage directory",
			"The check starts no process per directory and takes seconds even at ARS's full `sha256/xx/yy` fan-out of 65,794 directories",
			"`scripts/01_bringup.sh up` starts ARS's readiness wait only once ARS's launcher has passed its own run of the check",
		}},
	}
	for _, check := range checks {
		text := compactText(mustRead(t, check.path))
		assertContainsAll(t, check.path+" ARS storage check", text, check.required...)
		assertContainsNone(t, check.path+" stale ARS storage check", text, stale...)
	}
}
