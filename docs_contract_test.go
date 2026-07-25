package executionsubstrate_test

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func mustRead(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(data)
}

func compactText(text string) string {
	return strings.Join(strings.Fields(text), " ")
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

func assertDocIncludesAuthorityHierarchy(t *testing.T, doc string, label string) {
	t.Helper()

	lastIndex := -1
	for _, required := range authorityHierarchyLines(t) {
		idx := strings.Index(doc, required)
		if idx == -1 {
			t.Fatalf("%s missing authority phrase %q", label, required)
		}
		if idx <= lastIndex {
			t.Fatalf("%s authority phrase %q is out of order", label, required)
		}
		lastIndex = idx
	}
}

func docSection(t *testing.T, doc string, start string, end string) string {
	t.Helper()

	startIndex := strings.Index(doc, start)
	if startIndex == -1 {
		t.Fatalf("document section start %q not found", start)
	}
	section := doc[startIndex:]
	if end == "" {
		return section
	}
	endIndex := strings.Index(section, end)
	if endIndex == -1 {
		t.Fatalf("document section end %q not found after %q", end, start)
	}
	return section[:endIndex]
}

func compactDocSection(t *testing.T, doc string, start string, end string) string {
	t.Helper()
	return compactText(docSection(t, doc, start, end))
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

	for _, phrase := range required {
		if !strings.Contains(text, phrase) {
			t.Fatalf("%s missing %q", label, phrase)
		}
	}
}

func assertContainsNone(t *testing.T, label string, text string, forbidden ...string) {
	t.Helper()

	for _, phrase := range forbidden {
		if strings.Contains(text, phrase) {
			t.Fatalf("%s must not contain %q", label, phrase)
		}
	}
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
		"TARGET-ONLY: submit idempotency, correlation, and recovery in this document are target contract direction only.",
		"CURRENT-UNCHANGED: current unkeyed submit remains the implemented behavior.",
		"does not implement runtime behavior",
		"does not select final request fields",
		"does not select a response shape",
		"does not select a persistence implementation",
		"selects only the public opt-in and versioning posture",
		"the existing submit route is retained",
		"the future reliable request is a submit-specific request family distinct from `PrepareRequest`",
		"producer-declaration preflight and an in-band structural request discriminator are both required",
		"header-only opt-in is rejected",
		"silent downgrade to current unkeyed submit is forbidden",
		"No current request field, response DTO field, producer field, handler behavior, query route, durable store, migration, Nomad behavior, or runtime behavior is implemented",
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
		"On an in-process non-submitted return after staging, current submit removes the staged root",
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
		"may return `submission_failed` and may clean staging because submitted was not confirmed",
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
		"does not select database, table, file, lock, migration, transaction API, or storage implementation shape",
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
		"without selecting exact JSON names, HTTP status codes, route shapes, or error strings",
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
		"Exact public vocabulary remains open",
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
		"The reliable variant uses a future submit-specific request family or envelope",
		"must not remain merely an optional semantic interpretation of `PrepareRequest`",
		"required in-band structural reliable-submit discriminator",
		"unknown to the current `PrepareRequest` decoder",
		"current server rejects the future reliable body before calling current `Submit` behavior",
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
		"no runtime behavior implemented",
		"no producer declaration field implemented",
		"no request DTO implemented",
		"no handler or decoder implemented",
		"no route implementation",
		"no persistence",
		"no schema or migration",
		"no exact HTTP code selected",
		"no error string selected",
		"no persistent receipt-store implementation",
		"no final reliable request field names",
		"no final reliable schema/version strings",
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
	assertContainsAll(t, "submit recovery gates", gates,
		"preserved public opt-in and versioning docs-contract coverage",
		"reliable request and producer sub-contract model tests",
		"private request-equivalence and plan-binding decision",
		"narrow persistence and concurrency decision",
		"ES-to-Nomad uncertain-outcome reconciliation decision",
		"retention and expiry decision",
		"security and privacy review",
		"request, receipt, and error model tests",
		"compatibility tests",
		"implementation provenance and independent audit",
	)
	assertContainsAll(t, "submit recovery open seams", openSeams,
		"exact reliable producer sub-contract JSON field names",
		"exact reliable producer sub-contract family/version strings",
		"exact reliable request envelope field names",
		"exact reliable request schema/version strings",
		"submit key field name",
		"recovery field names",
		"replay-only versus query route",
		"exact outcome and error vocabulary",
		"storage implementation",
		"lock and concurrency implementation",
		"TTL, tombstone, and garbage collection",
		"canonicalization",
		"private binding mechanism",
		"plan snapshot versus immutable references",
		"Nomad reconciliation mechanism",
		"deterministic versus random assigned `run_id`",
		"bootstrap exception",
		"caller namespace refinement beyond authenticated identity",
		"later Coordinator consumer mapping",
	)
	plansPointer := compactDocSection(t, mustRead(t, "PLANS.md"), "## Cross-Repo Hybrid Integration ADR Pointer", "## Highest-Priority Backlog Entry")
	contractsSubmitTarget := compactDocSection(t, mustRead(t, ".docs/execution_lifecycle/contracts.md"), "### Target reliable keyed-submit contract", "## 7. Status contract")
	designPressure := compactDocSection(t, mustRead(t, ".docs/execution_lifecycle/design.md"), "## 9A. Submit Idempotency And Recovery Pressure", "## 10. Runtime identity and lifecycle interaction")
	implementationAbsence := compactDocSection(t, mustRead(t, ".docs/execution_lifecycle/implementation.md"), "**Current keyed-recovery absence**", "## 8. Lifecycle projection implementation")
	admissionDecision := compactText(mustRead(t, ".docs/execution_lifecycle/es_execution_admission_model.md"))
	boundaries := compactText(mustRead(t, ".docs/system_overview/boundaries.md"))
	adrRecovery := compactDocSection(t, mustRead(t, ".docs/system_overview/hybrid_integration_architecture_adr.md"), "### Correlation And Recovery", "## Bridge <-> Codex Evidence Boundary")

	for _, doc := range []struct {
		label string
		text  string
	}{
		{label: "PLANS submit recovery tranche", text: plansPointer},
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
	assertContainsAll(t, "PLANS submit recovery tranche", plansPointer,
		"ES-owned documentation seam",
		"documentation and docs-contract coverage only",
		"does not implement runtime behavior",
		"public opt-in/versioning posture",
		"current outer producer-contract v1 identity",
		"one narrow versioned reliable-submit producer sub-contract",
		"keep `POST /v1/executions:submit` as the route",
		"submit-specific reliable request family distinct from `PrepareRequest`",
		"in-band structural reliable-submit discriminator",
		"producer-declaration preflight plus in-band request discrimination",
		"reject header-only opt-in",
		"forbid silent downgrade",
		"caller-to-ES response loss",
		"ES-to-Nomad registration-response uncertainty",
		"prevent duplicate semantic execution from transport redelivery",
		"current no-key submit compatibility path",
		"`control-plane-normal-shell/v1`",
		"prohibition on a broad ES lifecycle store",
	)
	assertContainsAll(t, "implementation keyed recovery absence", implementationAbsence,
		"Current `Submit` has no submit idempotency key input",
		"no durable submit-correlation record",
		"Current `SubmitResult` has no replay or submit-correlation vocabulary",
		"Current code can be ambiguous at the caller-to-ES boundary",
		"Current code can also be ambiguous at the ES-to-Nomad boundary",
		"not a reliable proof that no provider effect was accepted",
		"not implemented here",
	)
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
	plansPointer := compactDocSection(t, mustRead(t, "PLANS.md"), "## Cross-Repo Hybrid Integration ADR Pointer", "## Highest-Priority Backlog Entry")

	assertContainsAll(t, "reliable submit current outer producer contract preserved", producerTarget,
		"`execution-substrate.producer-contract/v1`",
		"`governed-execution-producer/v1`",
		"The current producer declaration has no implemented reliable-submit sub-contract",
	)
	assertContainsAll(t, "reliable submit producer declaration remains narrow", producerTarget,
		"one explicitly named and versioned reliable-submit producer sub-contract",
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
		"selects only the public opt-in and versioning posture",
		"No current request field, response DTO field, producer field, handler behavior, query route, durable store, migration, Nomad behavior, or runtime behavior is implemented",
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
	)
	assertContainsAll(t, "reliable submit route and request-family selection", compatibility,
		"Current submit without the new key remains valid current behavior",
		"The target reliable request uses the existing `POST /v1/executions:submit` route",
		"does not select a new route",
		"The reliable variant uses a future submit-specific request family or envelope",
		"must not remain merely an optional semantic interpretation of `PrepareRequest`",
		"required in-band structural reliable-submit discriminator",
		"unknown to the current `PrepareRequest` decoder",
		"current server rejects the future reliable body before calling current `Submit` behavior",
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
		"submit-specific request family or envelope distinct from `PrepareRequest`",
		"required in-band structural reliable-submit discriminator",
		"current strict `PrepareRequest` decoding rejects",
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
		"Exact DTO field names",
		"exact reliable schema/version strings",
		"receipt vocabulary",
		"error vocabulary",
		"recovery route remain open",
	)
	assertContainsAll(t, "reliable submit implementation absence", implementationAbsence,
		"Current `Submit` has no submit idempotency key input",
		"Current `SubmitResult` has no replay or submit-correlation vocabulary",
		"Current `handleSubmit` still decodes the current `PrepareRequest` body",
		"no submit-specific reliable request envelope",
		"reliable discriminator",
		"reliable request DTO is implemented",
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
	assertContainsAll(t, "reliable submit plans tranche", plansPointer,
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
		"exact reliable producer sub-contract JSON field names",
		"exact reliable producer sub-contract family/version strings",
		"exact reliable request envelope field names",
		"exact reliable request schema/version strings",
		"submit key field name",
		"recovery field names",
		"replay-only versus query route",
		"exact outcome and error vocabulary",
		"storage implementation",
		"TTL, tombstone, and garbage collection",
		"Nomad reconciliation mechanism",
		"deterministic versus random assigned `run_id`",
	)
	assertContainsAll(t, "reliable submit non-claims", nonClaims,
		"no runtime behavior implemented",
		"no producer declaration field implemented",
		"no request DTO implemented",
		"no handler or decoder implemented",
		"no route implementation",
		"no persistence",
		"no schema or migration",
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
	assertContainsAll(t, "reliable submit required next gates", gates,
		"preserved public opt-in and versioning docs-contract coverage",
		"reliable request and producer sub-contract model tests",
		"private request-equivalence and plan-binding decision",
		"narrow persistence and concurrency decision",
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

func TestSystemOverviewAuthorityHeadersFollowRepoHierarchy(t *testing.T) {
	for _, doc := range []struct {
		label string
		path  string
	}{
		{label: "system contracts doc", path: ".docs/system_overview/contracts.md"},
		{label: "system boundaries doc", path: ".docs/system_overview/boundaries.md"},
		{label: "hybrid integration architecture ADR", path: ".docs/system_overview/hybrid_integration_architecture_adr.md"},
	} {
		text := mustRead(t, doc.path)
		assertDocIncludesAuthorityHierarchy(t, text, doc.label)
		if !strings.Contains(text, "Authority for this document follows the repo-wide authority hierarchy:") {
			t.Fatalf("%s missing repo-wide authority preface", doc.label)
		}
	}
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
	assertContainsNone(t, "PLANS stale target relationships", plansPointer,
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
	assertNoStaleTargetRelationship(t, "PLANS stale target relationships", plansPointer)
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
	assertContainsNone(t, "PLANS and ADR Bridge evidence agreement", plans,
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
	assertOmitsLifecycleProjectionSchedulerDerivation(t, "PLANS lifecycle projection authority", plans)

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
	plans := compactText(mustRead(t, "PLANS.md"))
	sharedKernel := compactText(mustRead(t, ".docs/system_overview/shared_kernel.md"))
	contracts := compactText(mustRead(t, ".docs/system_overview/contracts.md"))
	boundaries := compactText(mustRead(t, ".docs/system_overview/boundaries.md"))
	lifecycle := compactText(mustRead(t, ".docs/execution_lifecycle/contracts.md"))
	artifactPublication := compactText(mustRead(t, ".docs/system_overview/artifact_publication_storage.md"))
	artifactHygiene := compactText(mustRead(t, ".docs/system_overview/artifact_hygiene.md"))

	assertDocIncludesAuthorityHierarchy(t, sharedKernel, "shared-kernel decision doc")
	if !strings.Contains(sharedKernel, "Authority for this document follows the repo-wide authority hierarchy:") {
		t.Fatalf("shared-kernel decision doc missing authority preface")
	}
	if strings.Contains(sharedKernel, "Authority for this document is, in order: 1. `PLANS.md`") {
		t.Fatalf("shared-kernel decision doc must not define a conflicting authority order that omits AGENTS.md")
	}

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
		if !strings.Contains(plans, required) {
			t.Fatalf("PLANS missing Workstream A shared-kernel decision phrase %q", required)
		}
	}

	for _, required := range []string{
		"`shared_kernel.md`",
		"`claims.package.publication` remains AGS-owned publish-time meaning carried inside the signed record",
		"`claims.admission.authorization` is intentionally limited to `derivation_spec_digest` and `output_id`",
		"`claims.admission.execution` is intentionally limited to runtime env allowlist, required capabilities, `target_platform`, and `network_access`",
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
		"`:prepare` uses only the narrow shared execution/runtime claims ES currently enforces from aggregate artifact evidence: runtime env allowlist, required capabilities, `target_platform`, and `network_access`.",
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
	plans := compactText(mustRead(t, "PLANS.md"))
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

	assertDocIncludesAuthorityHierarchy(t, decisionRaw, "artifact publication/storage decision doc")
	if !strings.Contains(decision, "Authority for this document follows the repo-wide authority hierarchy:") {
		t.Fatalf("artifact publication/storage decision doc missing authority preface")
	}

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
		if !strings.Contains(plans, required) {
			t.Fatalf("PLANS missing Workstream B decision phrase %q", required)
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
	plans := compactText(mustRead(t, "PLANS.md"))
	decision := compactText(mustRead(t, ".docs/system_overview/artifact_publication_storage.md"))

	assertContainsAll(t, "PLANS Workstream B1 guardrail posture", plans,
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
	plans := compactText(mustRead(t, "PLANS.md"))
	decision := compactText(mustRead(t, ".docs/system_overview/artifact_publication_storage.md"))
	sharedKernel := compactText(mustRead(t, ".docs/system_overview/shared_kernel.md"))
	contracts := compactText(mustRead(t, ".docs/system_overview/contracts.md"))
	boundaries := compactText(mustRead(t, ".docs/system_overview/boundaries.md"))
	artifactHygiene := compactText(mustRead(t, ".docs/system_overview/artifact_hygiene.md"))

	for _, doc := range []struct {
		label string
		text  string
	}{
		{label: "PLANS Workstream B0 gate", text: plans},
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
	plans := compactText(mustRead(t, "PLANS.md"))
	decisionRaw := mustRead(t, ".docs/execution_lifecycle/es_execution_admission_model.md")
	decision := compactText(decisionRaw)
	contracts := compactText(mustRead(t, ".docs/system_overview/contracts.md"))
	boundaries := compactText(mustRead(t, ".docs/system_overview/boundaries.md"))
	lifecycleContracts := compactText(mustRead(t, ".docs/execution_lifecycle/contracts.md"))
	lifecycleDesign := compactText(mustRead(t, ".docs/execution_lifecycle/design.md"))
	publicSurfaceSection := compactDocSection(t, decisionRaw, "### 4A. Public execution surfaces", "### 4B. Admission, handoff, and projection ownership surfaces")
	compatibilitySection := compactDocSection(t, decisionRaw, "### 4C. Temporary compatibility edge metadata", "### 4D. Current relationship map")

	assertDocIncludesAuthorityHierarchy(t, decisionRaw, "workstream C execution-admission decision doc")
	if !strings.Contains(decision, "Authority for this document follows the repo-wide authority hierarchy:") {
		t.Fatalf("workstream C execution-admission decision doc missing authority preface")
	}

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
		if !strings.Contains(plans, required) {
			t.Fatalf("PLANS missing Workstream C decision phrase %q", required)
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
	plans := compactText(mustRead(t, "PLANS.md"))
	checkpointRaw := mustRead(t, ".docs/execution_lifecycle/workstream_c7_checkpoint.md")
	checkpoint := compactText(checkpointRaw)
	decision := compactText(mustRead(t, ".docs/execution_lifecycle/es_execution_admission_model.md"))
	tlsDecision := compactText(mustRead(t, ".docs/remote_alpha_operator_healthcheck_tls_signing_custody_decision.md"))
	tlsResolution := compactText(mustRead(t, ".docs/remote_alpha_operator_healthcheck_tls_signing_custody_resolution.md"))
	remoteAlpha := compactText(mustRead(t, ".docs/system_overview/remote_supported_host_alpha.md"))
	runbook := compactText(mustRead(t, ".docs/supported_local_cp_consumer_runbook.md"))

	assertDocIncludesAuthorityHierarchy(t, checkpointRaw, "workstream C7 checkpoint doc")
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
		"P0v noninteractive status remains design/static only.",
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
	assertContainsAll(t, "PLANS Workstream C7 pointer", plans,
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
		"Decision status: blocked.",
		"No option is selected.",
		"`operator-healthcheck-tls-renew` remains blocked by `unsupported_signing_topology`.",
		"P0v remains design/static only and no fallback emitter is introduced",
	)
	assertContainsAll(t, "Remote Alpha TLS resolution remains blocked", tlsResolution,
		"Current resolution verdict: blocked.",
		"No current ES source satisfies the signer authority and custody evidence gate",
		"no replacement, renewal, profile-lineage refresh, CP diagnose rerun, MA execution, Bridge projection, or live proof may proceed by inference",
	)
	assertContainsAll(t, "Remote Alpha TLS route matrix still blocked", remoteAlpha,
		"P0v is design/static-test prep only",
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
		{label: "PLANS C0 gate", text: plans},
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

	assertContainsAll(t, "PLANS C0 no implementation", plans,
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
	plans := compactText(mustRead(t, "PLANS.md"))
	decision := compactText(mustRead(t, ".docs/execution_lifecycle/es_execution_admission_model.md"))
	postureSection := compactDocSection(t, mustRead(t, ".docs/execution_lifecycle/es_execution_admission_model.md"), "## 6. Code-facing guardrail posture", "")

	for _, doc := range []struct {
		label string
		text  string
	}{
		{label: "PLANS C1 guardrail posture", text: plans},
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
	plans := compactText(mustRead(t, "PLANS.md"))
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
		{label: "PLANS C2 posture", text: plans},
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

	assertContainsAll(t, "PLANS C2 CP grammar exclusions", plans,
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
	plans := compactText(mustRead(t, "PLANS.md"))
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
		{label: "PLANS C3 posture", text: plans},
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
	plans := compactText(mustRead(t, "PLANS.md"))
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
		{label: "PLANS C4 posture", text: plans},
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
	plans := compactText(mustRead(t, "PLANS.md"))
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
		{label: "PLANS C5 posture", text: plans},
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
	plans := compactText(mustRead(t, "PLANS.md"))
	decisionRaw := mustRead(t, ".docs/execution_lifecycle/es_execution_admission_model.md")
	decision := compactText(decisionRaw)
	lifecycleContracts := compactText(mustRead(t, ".docs/execution_lifecycle/contracts.md"))
	systemBoundaries := compactText(mustRead(t, ".docs/system_overview/boundaries.md"))
	artifactStorage := compactText(mustRead(t, ".docs/system_overview/artifact_publication_storage.md"))
	mvp := compactText(mustRead(t, ".docs/mvp.md"))

	assertContainsAll(t, "PLANS C6 admission policy posture", plans,
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
		"policy denial occurs before payload staging or Nomad submission.",
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
	plans := compactText(mustRead(t, "PLANS.md"))
	decision := compactText(mustRead(t, ".docs/execution_lifecycle/es_execution_admission_model.md"))
	lifecycleContracts := compactText(mustRead(t, ".docs/execution_lifecycle/contracts.md"))
	configuration := compactText(mustRead(t, ".docs/system_overview/configuration.md"))
	mvp := compactText(mustRead(t, ".docs/mvp.md"))

	for _, doc := range []struct {
		label string
		text  string
	}{
		{label: "PLANS C6 configurable inputs", text: plans},
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
	workstreamF := compactDocSection(t, plansRaw, "### Workstream F - Runtime Identity Handoff Reset", "## Ordered Execution Plan")

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
	plansRaw := mustRead(t, "PLANS.md")
	contractsRaw := mustRead(t, ".docs/system_overview/contracts.md")
	boundariesRaw := mustRead(t, ".docs/system_overview/boundaries.md")
	architectureRaw := mustRead(t, ".docs/system_overview/architecture.md")
	configurationRaw := mustRead(t, ".docs/system_overview/configuration.md")
	admissionModelRaw := mustRead(t, ".docs/execution_lifecycle/es_execution_admission_model.md")

	workstreamD := compactDocSection(t, plansRaw, "### Workstream D - Policy And Authorization Reset", "### Workstream E - Lookup And Config Indirection Reset")
	egsContractSection := compactDocSection(t, contractsRaw, "## 8. EGS Policy Contract", "## 9. CGS Authorization Contract")
	cgsContractSection := compactDocSection(t, contractsRaw, "## 9. CGS Authorization Contract", "## 10. Runtime Identity Handoff Contract")
	esBoundarySection := compactDocSection(t, boundariesRaw, "## 8. ES boundary", "## 9. EGS boundary")
	egsBoundarySection := compactDocSection(t, boundariesRaw, "## 9. EGS boundary", "## 10. CGS boundary")
	cgsBoundarySection := compactDocSection(t, boundariesRaw, "## 10. CGS boundary", "## 11. Cross-cutting packages that are not service boundaries")
	architecture := compactText(architectureRaw)
	configuration := compactText(configurationRaw)
	admissionModel := compactText(admissionModelRaw)

	assertContainsAll(t, "Workstream D versioning direction", workstreamD,
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
	plansRaw := mustRead(t, "PLANS.md")
	contractsRaw := mustRead(t, ".docs/system_overview/contracts.md")
	boundariesRaw := mustRead(t, ".docs/system_overview/boundaries.md")
	architectureRaw := mustRead(t, ".docs/system_overview/architecture.md")
	configurationRaw := mustRead(t, ".docs/system_overview/configuration.md")
	admissionModelRaw := mustRead(t, ".docs/execution_lifecycle/es_execution_admission_model.md")

	workstreamD := compactDocSection(t, plansRaw, "### Workstream D - Policy And Authorization Reset", "### Workstream E - Lookup And Config Indirection Reset")
	egsContractSection := compactDocSection(t, contractsRaw, "## 8. EGS Policy Contract", "## 9. CGS Authorization Contract")
	cgsContractSection := compactDocSection(t, contractsRaw, "## 9. CGS Authorization Contract", "## 10. Runtime Identity Handoff Contract")
	esBoundarySection := compactDocSection(t, boundariesRaw, "## 8. ES boundary", "## 9. EGS boundary")
	egsBoundarySection := compactDocSection(t, boundariesRaw, "## 9. EGS boundary", "## 10. CGS boundary")
	cgsBoundarySection := compactDocSection(t, boundariesRaw, "## 10. CGS boundary", "## 11. Cross-cutting packages that are not service boundaries")
	architecture := compactText(architectureRaw)
	configuration := compactText(configurationRaw)
	admissionModel := compactText(admissionModelRaw)

	assertContainsAll(t, "Workstream D1b design-only plan", workstreamD,
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
	plansRaw := mustRead(t, "PLANS.md")
	contractsRaw := mustRead(t, ".docs/system_overview/contracts.md")
	boundariesRaw := mustRead(t, ".docs/system_overview/boundaries.md")
	architectureRaw := mustRead(t, ".docs/system_overview/architecture.md")
	configurationRaw := mustRead(t, ".docs/system_overview/configuration.md")
	admissionModelRaw := mustRead(t, ".docs/execution_lifecycle/es_execution_admission_model.md")

	workstreamD := compactDocSection(t, plansRaw, "### Workstream D - Policy And Authorization Reset", "### Workstream E - Lookup And Config Indirection Reset")
	egsContractSection := compactDocSection(t, contractsRaw, "## 8. EGS Policy Contract", "## 9. CGS Authorization Contract")
	esBoundarySection := compactDocSection(t, boundariesRaw, "## 8. ES boundary", "## 9. EGS boundary")
	egsBoundarySection := compactDocSection(t, boundariesRaw, "## 9. EGS boundary", "## 10. CGS boundary")
	architecture := compactText(architectureRaw)
	configuration := compactText(configurationRaw)
	admissionModel := compactText(admissionModelRaw)

	assertContainsAll(t, "Workstream D1c design-only plan", workstreamD,
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
	plansRaw := mustRead(t, "PLANS.md")
	contractsRaw := mustRead(t, ".docs/system_overview/contracts.md")
	boundariesRaw := mustRead(t, ".docs/system_overview/boundaries.md")
	architectureRaw := mustRead(t, ".docs/system_overview/architecture.md")
	configurationRaw := mustRead(t, ".docs/system_overview/configuration.md")
	admissionModelRaw := mustRead(t, ".docs/execution_lifecycle/es_execution_admission_model.md")

	workstreamD := compactDocSection(t, plansRaw, "### Workstream D - Policy And Authorization Reset", "### Workstream E - Lookup And Config Indirection Reset")
	cgsContractSection := compactDocSection(t, contractsRaw, "## 9. CGS Authorization Contract", "## 10. Runtime Identity Handoff Contract")
	esBoundarySection := compactDocSection(t, boundariesRaw, "## 8. ES boundary", "## 9. EGS boundary")
	cgsBoundarySection := compactDocSection(t, boundariesRaw, "## 10. CGS boundary", "## 11. Cross-cutting packages that are not service boundaries")
	architecture := compactText(architectureRaw)
	configuration := compactText(configurationRaw)
	admissionModel := compactText(admissionModelRaw)

	assertContainsAll(t, "Workstream D1d design-only plan", workstreamD,
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

	assertContainsAll(t, "Workstream D checkpoint status", workstreamD,
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

	plans := compactText(plansRaw)
	decision := compactText(decisionRaw)
	architecture := compactText(architectureRaw)
	configuration := compactText(configurationRaw)
	admissionModel := compactText(admissionModelRaw)

	workstreamD := compactDocSection(t, plansRaw, "### Workstream D - Policy And Authorization Reset", "### Workstream E - Lookup And Config Indirection Reset")
	workstreamE := compactDocSection(t, plansRaw, "### Workstream E - Lookup And Config Indirection Reset", "### Workstream F - Runtime Identity Handoff Reset")
	workstreamF := compactDocSection(t, plansRaw, "### Workstream F - Runtime Identity Handoff Reset", "## Ordered Execution Plan")
	runtimeConfigContract := compactDocSection(t, contractsRaw, "## 4. Workload-Zone Vault Runtime-Config Contract", "## 5. AGS Publication Contract")
	runtimeConfigBoundary := compactDocSection(t, boundariesRaw, "## 5. Workload-zone Vault runtime-config surface", "## 6. ARS boundary")
	esBoundary := compactDocSection(t, boundariesRaw, "## 8. ES boundary", "## 9. EGS boundary")
	prepareContract := compactDocSection(t, lifecycleContractsRaw, "## 5. Prepare contract", "## 6. Submit contract")
	authorityHandoffContract := compactDocSection(t, lifecycleContractsRaw, "### Authority handoff read surface", "### Error contract")
	implementationApp := compactDocSection(t, implementationRaw, "## 5. Application wiring", "## 6. Prepare path implementation")
	implementationPrepare := compactDocSection(t, implementationRaw, "## 6. Prepare path implementation", "## 7. Submit path implementation")

	assertDocIncludesAuthorityHierarchy(t, decisionRaw, "runtime-config ownership decision doc")
	if !strings.Contains(decision, "Authority for this document follows the repo-wide authority hierarchy:") {
		t.Fatalf("runtime-config ownership decision doc missing authority preface")
	}

	assertContainsAll(t, "PLANS Workstream D checkpoint remains open", workstreamD,
		"D0-D1d completed the guardrail/design phase.",
		"Workstream D remains open;",
		"No D2 behavior-changing slice is required before Workstream E planning.",
		"D1 does not settle Workstream E runtime-config ownership or Workstream F runtime-identity handoff.",
	)
	assertContainsAll(t, "PLANS Workstream E E0 status", workstreamE,
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

	assertContainsAll(t, "PLANS E0 global docs", plans,
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
	plansRaw := mustRead(t, "PLANS.md")
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
	workstreamF := compactDocSection(t, plansRaw, "### Workstream F - Runtime Identity Handoff Reset", "## Ordered Execution Plan")
	runtimeIdentityContract := compactDocSection(t, contractsRaw, "## 10. Runtime Identity Handoff Contract", "## 11. Temporary Compatibility Edges")
	esBoundary := compactDocSection(t, boundariesRaw, "## 8. ES boundary", "## 9. EGS boundary")
	lifecycleRuntimeIdentity := compactDocSection(t, lifecycleContractsRaw, "## 14. Runtime identity and lifecycle edge", "## 15. Bounded slice rules")
	authorityHandoffContract := compactDocSection(t, lifecycleContractsRaw, "### Authority handoff read surface", "### Error contract")
	implementationRuntimeIdentity := compactDocSection(t, implementationRaw, "## 9. Runtime identity and mount implementation", "## 10. Filesystem and local side effects")

	assertDocIncludesAuthorityHierarchy(t, decisionRaw, "runtime-identity handoff ownership decision doc")
	if !strings.Contains(decision, "Authority for this document follows the repo-wide authority hierarchy:") {
		t.Fatalf("runtime-identity handoff ownership decision doc missing authority preface")
	}

	assertContainsAll(t, "PLANS Workstream F F0 status", workstreamF,
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
	plans := compactText(mustRead(t, "PLANS.md"))
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
		if !strings.Contains(plans, required) || !strings.Contains(remote, required) {
			t.Fatalf("Milestone 1 least-privilege boundary docs missing %q", required)
		}
	}
}

func TestMilestone1BoundaryPostureMatrixIsDocumented(t *testing.T) {
	plans := compactText(mustRead(t, "PLANS.md"))
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
		if !strings.Contains(plans, required) || !strings.Contains(remote, required) {
			t.Fatalf("Milestone 1 posture matrix docs missing %q", required)
		}
	}
}

func TestRemoteSupportedHostAlphaRuntimeSecurityBoundaryCheckerIsDocumented(t *testing.T) {
	plans := compactText(mustRead(t, "PLANS.md"))
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
		if !strings.Contains(plans, required) && !strings.Contains(remote, required) && !strings.Contains(configuration, required) {
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
	plans := compactText(mustRead(t, "PLANS.md"))
	remoteRaw := mustRead(t, ".docs/system_overview/remote_supported_host_alpha.md")
	operatorSection := compactDocSection(t, remoteRaw, "## Future ES-Owned Remote Alpha Operator Facade", "## Direct Remote Requirements")

	assertContainsAll(t, "Remote Alpha operator facade PLANS backlog", plans,
		"P0: ES Remote Alpha operator-helper consolidation and manual recovery minimization.",
		"Implementation must be split into small audited slices",
		"docs/static-test prep",
		"help/inventory/print-command ergonomics",
		"staged helpers",
		"secret-sensitive reset/unseal routing",
		"must not widen ES public contracts, CP orchestration semantics, IM authority, Nomad task-user semantics, SPIRE exposure boundaries, or Vault token brokerage",
		"preserve existing IM-consumed artifact filenames",
		"The objective is one repo-supported ES operator facade/workflow/script",
		"minimizes manual stitching, copying, and recovery sequencing",
		"Operator involvement is expected and allowed",
		"success does not mean eliminating every prompt",
		"Explicit interactive modes are valid when they are named, bounded to a mode or subcommand, visible to the operator, and secret-safe.",
		"Default noninteractive sudo remains an ergonomic optimization",
		"not a universal success criterion",
	)

	assertContainsAll(t, "Remote Alpha operator facade docs", operatorSection,
		"`Bounded slice rule`",
		"bounded MVP proof/support helper plus evidence/projection outputs only",
		"`scripts/remote_alpha_operator.sh`",
		"Current implementation/design status through P0u:",
		"P0e aligned help, inventory, and route wording with the operator involvement model",
		"P0d implements exactly one staged-helper delegation route",
		"`es-writable-state-readiness-check`",
		"P0f implements exactly one bounded readiness workflow command",
		"`readiness-session`",
		"P0g implements one safe/local recovery workflow skeleton",
		"`recovery-session`",
		"P0h extends only `recovery-session --evidence-check` with known-schema interpretation",
		"`--strict-known-schema`",
		"non-recursive `--evidence-dir` discovery",
		"P0i adds exactly one secret-sensitive recovery-session route",
		"`recovery-session vault-unseal-existing --host-local`",
		"P0j preserves that host-local fallback and adds one Mac-side secret-sensitive",
		"`recovery-session vault-unseal-existing --ssh-target <target> --interactive-tty`",
		"P0k adds one Mac-side dry-run-only disposable reset planning route",
		"`recovery-session vault-reset-disposable --ssh-target <target> --dry-run`",
		"P0l is design/static-test prep only",
		"`recovery-session vault-reset-disposable --ssh-target <target> --execute-reset --interactive-tty`",
		"at P0l it did not implement `--execute-reset`",
		"that route remained future until later implementation, audit, and live-validation slices",
		"P0m implements exactly that Mac-side destructive disposable reset operator route",
		"static and fake SSH/SCP validation only",
		"does not run live SSH, sudo, Vault, reset, unseal, execute-reset",
		"P0n adds one separate Mac-side post-reset workload-auth evidence route",
		"`recovery-session vault-workload-auth-check --ssh-target <target> --interactive-tty`",
		"stages only `scripts/remote_alpha_vault_workload_auth_check.sh` and `scripts/internal/remote_alpha_vault_workload_auth_check.sh`",
		"keeps the canonical summary on the remote host at `/var/tmp/execution-substrate-remote-alpha/vault-workload-auth-summary.json`",
		"does not copy the summary back to Mac `.out`",
		"keeps IM refresh, support-bundle collection, CP proof, runtime identity generation, and reset/unseal separate",
		"P0o adds one safe local/print-only post-reset Vault workload-auth bootstrap planning surface",
		"`recovery-session vault-workload-auth-bootstrap [--help|--plan|--inventory]`",
		"performs no live bootstrap, no SSH, no sudo, no Vault command, no root-token prompt, no proof secret creation, no workload-auth check, no reset/unseal, no IM execution, no support-bundle collection, no CP proof, and no runtime identity generation",
		"P0p is design/static-test prep only for the future secret-sensitive execution route",
		"`recovery-session vault-workload-auth-bootstrap --ssh-target <target> --execute-bootstrap --interactive-tty`",
		"defines the helper, prompt, summary, flag, boundary, and fake/static-test contract",
		"implements no helper, no staging, no Vault writes, no root-token or proof-secret prompt",
		"P0q implements exactly that secret-sensitive workload-auth bootstrap helper",
		"`recovery-session vault-workload-auth-bootstrap --ssh-target <target> --prepare-summary-path --interactive-tty`",
		"bounded remote filesystem preparation",
		"stages only `scripts/remote_alpha_vault_workload_auth_bootstrap.sh` and `scripts/internal/remote_alpha_vault_workload_auth_bootstrap.sh`",
		"uses an in-process Vault API client rather than `VAULT_TOKEN` or `vault login`",
		"writes only the remote non-secret summary at `/var/tmp/execution-substrate-remote-alpha/vault-workload-auth-bootstrap-summary.json`",
		"copies no summary back to Mac `.out`",
		"keeps workload-auth checks, reset/unseal, IM refresh, support bundles, CP proof, and runtime identity work separate",
		"P0r implements exactly one Mac-side runtime identity evidence route",
		"`recovery-session runtime-identity-summary --ssh-target <target> --interactive-tty`",
		"stages only `scripts/remote_alpha_runtime_identity_helper_summary.sh`",
		"keeps the canonical summary on the remote host at `/var/tmp/execution-substrate-remote-alpha/runtime-identity-helper-summary.json`",
		"keeps workload-auth bootstrap/check, reset/unseal, IM refresh, support bundles, CP proof, runtime identity generation, runtime-profile readiness, submit readiness, and retained-result readiness separate",
		"P0s implements exactly one bounded Remote Alpha internal ES service TLS status/renew helper pair and two Mac-side recovery-session routes",
		"`recovery-session es-service-tls-status --ssh-target <target> --interactive-tty`",
		"`recovery-session es-service-tls-renew --ssh-target <target> --interactive-tty --execute-renew`",
		"P0s stages only `scripts/remote_alpha_es_service_tls_renew.sh` and `scripts/internal/remote_alpha_es_service_tls_renew.sh`",
		"keeps the canonical summary on the remote host at `/var/tmp/execution-substrate-remote-alpha/es-service-tls-renew-summary.json`",
		"keeps IM refresh, support-bundle collection, CP proof, Vault/SPIRE/Nomad changes, workload-auth, reset/unseal, and runtime identity work separate",
		"P0t extends that same fixed ES service TLS helper pair with exactly one additional bounded scope",
		"`recovery-session es-governance-tls-status --ssh-target <target> --interactive-tty`",
		"`recovery-session es-governance-tls-renew --ssh-target <target> --interactive-tty --execute-renew`",
		"fixed helper scope `--scope execution-governance`",
		"keeps the canonical summary on the remote host at `/var/tmp/execution-substrate-remote-alpha/es-governance-tls-renew-summary.json`",
		"P0u adds exactly one bounded Remote Alpha host-local operator healthcheck client TLS status/renew helper pair",
		"`recovery-session operator-healthcheck-tls-status --ssh-target <target> --interactive-tty`",
		"`recovery-session operator-healthcheck-tls-renew --ssh-target <target> --interactive-tty --execute-renew`",
		"stages only `scripts/remote_alpha_operator_healthcheck_tls_renew.sh` and `scripts/internal/remote_alpha_operator_healthcheck_tls_renew.sh`",
		"`spiffe://execution.internal/operator/local`",
		"`/var/tmp/execution-substrate-remote-alpha/operator-healthcheck-tls-renew-summary.json`",
		"does not restart ES",
		"stages only",
		"`scripts/remote_alpha_reset_disposable_vault.sh`",
		"invokes only the staged helper's `--unseal-only` mode over an interactive SSH TTY",
		"invokes only the staged helper's `--dry-run` mode",
		"delegates only to the public reset helper's `--unseal-only` mode",
		"delegates only to the public staged wrapper",
		"`scripts/remote_alpha_stage_es_writable_state_readiness_check.sh`",
		"delegates only through the existing readiness route/helper path",
		"prints only non-secret local metadata after scanning the artifacts for secret-like content",
		"local evidence-check mode over operator-supplied existing JSON evidence files",
		"accepts only its own allowlisted safe/local flags plus the explicit host-local and Mac-side interactive TTY `vault-unseal-existing`",
		"P0n Mac-side interactive TTY `vault-workload-auth-check` submode",
		"P0r Mac-side interactive TTY `runtime-identity-summary` evidence submode",
		"P0s Mac-side interactive TTY `es-service-tls-status` and `es-service-tls-renew` submodes",
		"P0t Mac-side interactive TTY `es-governance-tls-status` and `es-governance-tls-renew` submodes",
		"P0u Mac-side interactive TTY `operator-healthcheck-tls-status` and `operator-healthcheck-tls-renew` submodes",
		"safe modes do not use SSH or remote staging",
		"dispatch generic helpers",
		"destructive or authority-bearing work",
		"`vault-unseal-existing --ssh-target <target> --interactive-tty` route",
		"requires a visible local terminal before staging",
		"attempts staged-helper cleanup by default",
		"writes no `.out`, transcript, log, support bundle, report, generated JSON, or operator summary",
		"`vault-reset-disposable --ssh-target <target> --dry-run` route",
		"Mac-side topology for disposable Vault reset planning only",
		"does not require an interactive TTY",
		"invokes only `--dry-run`",
		"non-destructive: it does not stop Vault, move raft storage, init or unseal Vault, run post-unseal checks, run workload-auth checks, run Infrastructure Manager, or collect support bundles",
		"The `vault-reset-disposable --ssh-target <target> --execute-reset --interactive-tty` route is the P0m Mac-side destructive disposable reset operator route",
		"requires a visible local terminal before staging",
		"allocates an interactive SSH TTY",
		"requires the existing exact confirmation phrase",
		"`RESET DISPOSABLE REMOTE ALPHA VAULT`",
		"invokes only `--execute-reset`",
		"writes no `.out` summary or operator summary",
		"captures no transcript",
		"handles no secrets",
		"post-reset evidence checks as separate later steps",
		"P0m validation is static and fake SSH/SCP only; it is not live execute-reset validation.",
		"The `vault-workload-auth-check --ssh-target <target> --interactive-tty` route is the P0n Mac-side post-reset workload-auth evidence route.",
		"stages exactly the public workload-auth helper and its internal implementation helper",
		"invokes only the staged public helper with no helper override flags",
		"does not print full summary JSON",
		"The route is evidence/projection only: it is not workload-auth bootstrap, not ES token brokerage",
		"The `vault-workload-auth-bootstrap [--help|--plan|--inventory]` submode is the P0o safe local/print-only planning surface",
		"The `vault-workload-auth-bootstrap --ssh-target <target> --execute-bootstrap --interactive-tty` route is the P0q Mac-side secret-sensitive bootstrap route",
		"The `runtime-identity-summary --ssh-target <target> --interactive-tty` route is the P0r Mac-side runtime identity evidence route.",
		"The `es-service-tls-status --ssh-target <target> --interactive-tty` route is the P0s Mac-side internal TLS evidence route.",
		"The `es-service-tls-renew --ssh-target <target> --interactive-tty --execute-renew` route is the P0s Mac-side internal TLS recovery route.",
		"The `es-governance-tls-status --ssh-target <target> --interactive-tty` route is the P0t Mac-side ES -> EGS execution-governance TLS evidence route.",
		"The `es-governance-tls-renew --ssh-target <target> --interactive-tty --execute-renew` route is the P0t Mac-side ES -> EGS execution-governance TLS recovery route.",
		"The `operator-healthcheck-tls-status --ssh-target <target> --interactive-tty` route is the P0u Mac-side host-local operator healthcheck client TLS evidence route.",
		"The `operator-healthcheck-tls-renew --ssh-target <target> --interactive-tty --execute-renew` route is the P0u Mac-side host-local operator healthcheck client TLS recovery route.",
		"stages exactly the ES service TLS public/internal helper pair",
		"It may renew the bounded internal CA/certs, back up current material first, restart only `ars.service`, `ags.service`, and `es.service`, and run post-renew ARS mTLS probes using the AGS and ES artifact-registry client identities.",
		"not generic TLS deployment",
		"`--prepare-summary-path`",
		"OS/filesystem",
		"stages exactly the dedicated workload-auth bootstrap public/internal helper pair",
		"writes only a remote non-secret summary",
		"With no mode, the submode defaults to printing the plan/help and exiting zero.",
		"accepts only `--help`, `--plan`, and `--inventory`",
		"writes no `.out`, JSON, support bundle, report, generated artifact, operator summary, retained bundle, or CP artifact",
		"secret-sensitive but non-destructive",
		"visible delegated helper/Vault CLI prompt",
		"The facade does not prompt for, read, type, log, relay, persist, summarize, or accept secret material",
		"creates no summary file, writes no `.out`",
		"does not wrap the P0i/P0j unseal delegation, the P0k reset dry-run delegation, or the P0m execute-reset delegation in transcript capture",
		"follow-up evidence/provenance actions only",
		"operator ergonomics over existing bounded helpers",
		"Mac-side only: inventory, print IM commands, staged-wrapper delegation for existing repo-side staged helpers, P0j",
		"`recovery-session vault-reset-disposable --ssh-target <target> --dry-run`",
		"`recovery-session vault-reset-disposable --ssh-target <target> --execute-reset --interactive-tty`",
		"`recovery-session vault-workload-auth-check --ssh-target <target> --interactive-tty`",
		"`recovery-session runtime-identity-summary --ssh-target <target> --interactive-tty`",
		"`recovery-session es-service-tls-status --ssh-target <target> --interactive-tty`",
		"`recovery-session es-service-tls-renew --ssh-target <target> --interactive-tty --execute-renew`",
		"`recovery-session es-governance-tls-status --ssh-target <target> --interactive-tty`",
		"`recovery-session es-governance-tls-renew --ssh-target <target> --interactive-tty --execute-renew`",
		"`recovery-session operator-healthcheck-tls-status --ssh-target <target> --interactive-tty`",
		"`recovery-session operator-healthcheck-tls-renew --ssh-target <target> --interactive-tty --execute-renew`",
		"Remote-host only: P0i `recovery-session vault-unseal-existing --host-local`, and Vault service-user check.",
		"The host-local runtime identity helper remains available as a direct helper, but P0r adds the Mac-side operator topology for that evidence route.",
		"The host-local ES service TLS helper remains available as a direct helper, but P0s adds the Mac-side operator topology for the bounded ARS/AGS/ES artifact-registry status/renew route and P0t adds the Mac-side operator topology for the bounded ES -> EGS execution-governance status/renew route.",
		"The host-local operator healthcheck TLS helper remains available as a direct helper, but P0u adds the Mac-side operator topology for that bounded host-local client identity status/renew route.",
		"P0m does not add a host-local execute-reset route through the operator facade",
		"Not v1 except the P0j unseal-existing route, the P0k reset dry-run planning route, the P0m explicit execute-reset operator route, the P0n workload-auth evidence route, the P0o safe bootstrap planning surface, and the P0q workload-auth bootstrap execution route, the P0r runtime identity summary evidence route, the P0s ES service TLS status/renew route, and the P0t ES governance TLS status/renew route, and the P0u operator healthcheck TLS status/renew route",
		"post-unseal/service-user/IM/support-bundle/CP-proof bundling",
		"docs/static-test prep",
		"help/inventory/print-command skeleton",
		"staged-helper delegation after sudo-model review",
		"host-local Vault unseal-existing after reset-helper tests and audit",
		"destructive reset kept for a later exact-phrase slice",
		"Mac-side disposable Vault reset dry-run planning over the existing reset helper",
		"without destructive reset, init, unseal, post-unseal checks, IM, support-bundle collection, generic helper dispatch, transcripts, or generated evidence",
		"Mac-side disposable Vault reset execute-reset contract prep as docs/static-test only",
		"with the P0k dry-run route as prerequisite",
		"no post-unseal/workload-auth/IM/support-bundle/CP-proof bundling",
		"Mac-side disposable Vault reset execute-reset implementation with static and fake SSH/SCP validation only",
		"Mac-side post-reset Vault workload-auth evidence route over the fixed public/internal workload-auth helper pair",
		"no summary copy-back, no bootstrap, no token brokerage",
		"later separate audit/live-validation and post-reset evidence slices before any live destructive execute-reset validation or post-reset authority claim",
		"safe local/print-only workload-auth bootstrap planning surface after the post-reset evidence route reported a conservative Vault JWT login failure",
		"secret-sensitive workload-auth bootstrap execution contract prep as docs/static-test only",
		"secret-sensitive workload-auth bootstrap implementation with static and fake validation only",
		"Mac-side runtime identity summary evidence route over only the fixed public runtime identity helper summary script",
		"Mac-side ES service TLS status/renew route over only the fixed public/internal TLS renewal helper pair",
		"prefer one explicit interactive sudo validation followed by `sudo -n` where supported",
		"noninteractive default for staged wrappers that support it",
		"config/TLS staged wrapper is currently a sudo-model gap unless fixed",
		"not IM automation or reconciliation",
		"not CP authority",
		"not Vault production lifecycle",
		"not ES token brokerage",
		"not deployment architecture",
		"The facade must not make IM a remote reconciler, CP a Vault/runtime recovery authority, ES a Vault token broker, or Remote Alpha a production/general deployment architecture.",
		"The facade must not rename, replace, aggregate, or obscure existing IM-consumed artifact filenames.",
		"Any optional operator summary is non-secret evidence/projection only, not an IM input in v1.",
		"Live validation remains blocked/reopened for a later audited slice.",
		"Root tokens must never be accepted as CLI arguments, environment variables, files, `.out`, reports, support bundles, retained bundles, or Codex output.",
		"Bootstrap must not claim workload-auth success",
	)
}

func TestRemoteAlphaOperatorDocsInvolvementAndP0dEvidenceBoundaries(t *testing.T) {
	plans := compactText(mustRead(t, "PLANS.md"))
	remoteRaw := mustRead(t, ".docs/system_overview/remote_supported_host_alpha.md")
	operatorSection := compactDocSection(t, remoteRaw, "## Future ES-Owned Remote Alpha Operator Facade", "## Direct Remote Requirements")
	involvementSection := compactDocSection(t, remoteRaw, "### Operator Involvement Model", "Purpose:")
	evidenceSection := compactDocSection(t, remoteRaw, "### P0d Interactive Validation Evidence", "## Direct Remote Requirements")

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

func TestRemoteAlphaOperatorP0dDocsFirstDelegationBoundary(t *testing.T) {
	plans := compactText(mustRead(t, "PLANS.md"))
	remoteRaw := mustRead(t, ".docs/system_overview/remote_supported_host_alpha.md")
	operatorSection := compactDocSection(t, remoteRaw, "### P0d First Staged-Helper Delegation Implementation", "### P0f Readiness Session Workflow")

	assertContainsAll(t, "Remote Alpha operator P0d PLANS boundary", plans,
		"The P0d implementation slice is limited to exactly that one check-only route",
		"`scripts/remote_alpha_operator.sh es-writable-state-readiness-check`",
		"require an explicit `--ssh-target`",
		"accept only the P0c allowlisted helper flags",
		"reject `--apply`, `--dry-run`, unknown flags, unknown positional arguments, duplicate route flags, and secret-like arguments before helper execution",
		"delegate only to the public staged wrapper",
		"`scripts/remote_alpha_stage_es_writable_state_readiness_check.sh`",
		"must not source helpers",
		"invoke `scripts/internal/*`",
		"add generic staging or helper routing",
		"call Infrastructure Manager",
		"create an operator-owned summary",
		"rename helper artifacts",
	)

	assertContainsAll(t, "Remote Alpha operator P0d docs boundary", operatorSection,
		"`Bounded slice rule`: P0d implements exactly one Remote Alpha operator route",
		"`scripts/remote_alpha_operator.sh es-writable-state-readiness-check`",
		"The implemented route delegates only to:",
		"`scripts/remote_alpha_stage_es_writable_state_readiness_check.sh`",
		"does not source helper scripts",
		"does not invoke `scripts/internal/*`",
		"does not construct helper paths from user input",
		"does not introduce generic staging or generic helper routing",
		"Host-local execution is intentionally not enabled through the operator facade in P0d.",
		"The route may pass only these helper flags:",
		"`--ssh-target <user@host>`",
		"`--mode <alpha-compat|future-non-root-required>`",
		"`--run-id <timestamp-or-id>`",
		"`--output-dir </path/to/output-dir>`",
		"`--readiness-output </path/to/es-writable-state-readiness.json>`",
		"`--helper-staging-record-output </path/to/es-writable-state-readiness-helper-staging-record.json>`",
		"`--provenance-output </path/to/es-writable-state-readiness-helper-staging-record.json>`",
		"`--interactive-sudo`",
		"`--keep-staging-on-failure`",
		"`--help`",
		"The route rejects before helper execution:",
		"`--apply`",
		"`--dry-run`",
		"unknown positional arguments",
		"duplicate route flags",
		"does not rely on helper last-one-wins parsing",
		"secret-like arguments",
		"The operator facade itself does not call `sudo`, `ssh`, `scp`, Vault, Nomad, Docker, SPIRE, `systemctl`, Infrastructure Manager refresh, support-bundle collection, reset/unseal flows, workload-auth bootstrap or checks, runtime-identity summaries, service-user migration helpers, config/TLS helpers, binary deployment helpers, or writable-state ownership helpers.",
		"only run when an operator intentionally invokes this route with an explicit `--ssh-target`",
		"preserves the exact existing Infrastructure Manager-consumed local artifact filenames",
		"`es-writable-state-readiness.json`",
		"`es-writable-state-readiness-helper-staging-record.json`",
		"writes no aggregate operator summary and does not call Infrastructure Manager",
		"the facade may continue to print the Mac-side IM refresh and support-bundle commands only",
	)
}

func TestRemoteAlphaOperatorP0fDocsReadinessSessionBoundary(t *testing.T) {
	plans := compactText(mustRead(t, "PLANS.md"))
	remoteRaw := mustRead(t, ".docs/system_overview/remote_supported_host_alpha.md")
	operatorSection := compactDocSection(t, remoteRaw, "### P0f Readiness Session Workflow", "### P0g Recovery Session Safe Skeleton")

	assertContainsAll(t, "Remote Alpha operator P0f PLANS boundary", plans,
		"The P0f combined slice may fold in the P0e help/inventory wording alignment",
		"`scripts/remote_alpha_operator.sh readiness-session`",
		"operator-workflow consolidation over the already approved writable-state readiness route",
		"not a live validation slice and not a new authority source",
		"the human remains the operator",
		"noninteractive sudo remains an ergonomic optimization rather than a universal success criterion",
		"require an explicit `--ssh-target` for execution",
		"delegate only through the existing `es-writable-state-readiness-check` route/helper path",
		"use a fresh run-specific output directory by default unless `--output-dir` is supplied",
		"scan those artifacts for secret-like content before reading JSON fields",
		"print only non-secret metadata",
		"print IM refresh and support-bundle commands as follow-up evidence/provenance instructions only",
		"write no operator summary file",
		"add no generic helper dispatch",
	)

	assertContainsAll(t, "Remote Alpha operator P0f docs boundary", operatorSection,
		"`Bounded slice rule`: P0f implements exactly one Remote Alpha operator",
		"`scripts/remote_alpha_operator.sh readiness-session`",
		"bounded workflow consolidation over the already implemented",
		"`es-writable-state-readiness-check`",
		"not a live validation slice by itself",
		"not a new authority source",
		"not a new helper-dispatch framework",
		"not an Infrastructure Manager runner",
		"The session requires:",
		"`--ssh-target <user@host>`",
		"The session may accept only these flags:",
		"`--mode <alpha-compat|future-non-root-required>`",
		"`--output-dir </path/to/output-dir>`",
		"`--interactive-sudo`",
		"`--ssh-alias <alias>` for printed IM commands only",
		"`--im-profile-dir </path/to/profile-dir>` for printed IM commands only",
		"`--support-output-root </path/to/support-bundles>` for printed IM commands",
		"The session rejects before route execution:",
		"`--apply`",
		"`--dry-run`",
		"equals-form options",
		"positional arguments",
		"duplicate workflow flags",
		"secret-like arguments",
		"generate a fresh run-specific directory",
		"must refuse to proceed if the selected directory already contains either expected artifact",
		"`es-writable-state-readiness.json`",
		"`es-writable-state-readiness-helper-staging-record.json`",
		"both artifacts pass a secret-like content scan before any JSON fields are read",
		"`execution-substrate.remote-alpha.es-writable-state-readiness.v1`",
		"`execution-substrate.remote-alpha.es-writable-state-readiness-stage-provenance.v1`",
		"readiness `operation_mode` is `check_only`",
		"readiness `non_mutating` is `true`",
		"readiness `checker_mode` matches the requested mode",
		"`checker_ran=true`",
		"may print only non-secret metadata",
		"must not print full JSON contents",
		"must not write an operator summary file",
		"printed commands remain IM evidence/provenance/diagnostics actions only",
		"does not execute them",
		"not authority",
		"does not add Vault reset/unseal, Vault workload-auth, runtime identity, service-user migration, config/TLS, binary deployment, writable-state ownership, generic remote staging, arbitrary shell passthrough, live IM execution, CP proof, support-bundle collection, or Remote Alpha deployment architecture",
	)
}

func TestRemoteAlphaOperatorP0gDocsRecoverySessionBoundary(t *testing.T) {
	plans := compactText(mustRead(t, "PLANS.md"))
	remoteRaw := mustRead(t, ".docs/system_overview/remote_supported_host_alpha.md")
	operatorSection := compactDocSection(t, remoteRaw, "### P0g Recovery Session Safe Skeleton", "### P0h Schema-Aware Recovery Evidence Interpretation")

	assertContainsAll(t, "Remote Alpha operator P0g PLANS boundary", plans,
		"The P0g combined slice may add one bounded safe/local recovery workflow surface",
		"`scripts/remote_alpha_operator.sh recovery-session`",
		"recovery sequencing skeleton plus local evidence-check only",
		"`--help`, `--plan`, `--inventory`, `--next-steps`, and `--evidence-check`",
		"default no-mode behavior must print the plan/help and exit zero without running live tools",
		"`--plan`, `--inventory`, and `--next-steps` are print-only",
		"IM refresh and support-bundle commands may be printed as separate evidence/provenance instructions only",
		"never executed by ES and never described as authority",
		"`--evidence-check` may read only operator-supplied local JSON evidence paths",
		"scan for secret-like content before JSON parsing",
		"compute byte counts and SHA-256 digests",
		"print only non-secret metadata",
		"must not print full JSON, create a session summary, write `.out`, inspect live host state, dispatch helpers",
		"must reject `--ssh-target`, `--interactive-sudo`, `--apply`, `--dry-run`, `--execute-reset`, `--unseal-only`, `--post-unseal-check`, `--governed-smoke-command`",
		"Unseal-existing, disposable reset, workload-auth check execution, runtime identity summary generation, and Vault service-user check/apply remain separate audited future slices",
		"P0g must not add Vault token brokerage, IM authority, CP recovery authority, or Remote Alpha deployment/provisioning/reconciliation architecture",
	)

	assertContainsAll(t, "Remote Alpha operator P0g docs boundary", operatorSection,
		"`Bounded slice rule`: P0g implements one safe/local Remote Alpha operator workflow command",
		"`scripts/remote_alpha_operator.sh recovery-session`",
		"recovery sequencing skeleton and local evidence-check only",
		"not a live validation slice",
		"not a new authority source",
		"not a helper-dispatch framework",
		"not an Infrastructure Manager runner",
		"not Vault token brokerage",
		"not Remote Alpha deployment/provisioning/reconciliation architecture",
		"The supported modes are:",
		"`--plan`",
		"`--inventory`",
		"`--next-steps`",
		"`--evidence-check`",
		"Calling `recovery-session` with no mode prints the plan/help and exits zero",
		"must not run live tools",
		"`--ssh-alias <alias>` for printed IM commands only",
		"`--im-profile-dir </path/to/profile-dir>` for printed IM commands only",
		"`--support-output-root </path/to/support-bundles>` for printed IM commands",
		"`--vault-workload-auth-summary <path>`",
		"`--runtime-identity-summary <path>`",
		"`--vault-service-user-summary <path>`",
		"`--readiness-summary <path>`",
		"`--staging-record <path>`",
		"The session rejects:",
		"`--ssh-target`",
		"`--interactive-sudo`",
		"`--apply`",
		"`--dry-run`",
		"`--execute-reset`",
		"`--unseal-only`",
		"`--post-unseal-check`",
		"`--governed-smoke-command`",
		"helper path overrides",
		"duplicate operational flags",
		"equals-form options",
		"secret-like arguments",
		"`--plan` prints the bounded recovery sequence only",
		"unseal-existing is a future explicit secret-sensitive mode",
		"disposable reset dry-run planning is implemented later in P0k as an explicit Mac-side dry-run submode",
		"disposable reset execute-reset remains a future destructive exact-phrase mode",
		"workload-auth check execution is a future audited live check",
		"runtime identity summary generation is a future audited evidence route",
		"Vault service-user check/apply remains separate",
		"`--inventory` prints static helper inventory only",
		"must not inspect live host state and must not run any helper",
		"`--next-steps` prints command text only",
		"not ES execution and not authority",
		"`--evidence-check` is local-only",
		"require that the file exists",
		"compute byte count and SHA-256 digest",
		"scan for secret-like content before JSON parsing",
		"print only non-secret metadata",
		"must not print full JSON, create a session summary file, write `.out`, run helpers, run IM, or treat evidence as authority",
		"If secret-like content is detected or JSON is malformed, it must fail with the path classification only",
		"must not print file contents",
		"does not add Vault reset/unseal execution, Vault workload-auth check execution, runtime identity summary generation, Vault service-user check/apply execution",
	)
}

func TestRemoteAlphaOperatorP0hDocsSchemaAwareRecoveryEvidenceBoundary(t *testing.T) {
	plans := compactText(mustRead(t, "PLANS.md"))
	remoteRaw := mustRead(t, ".docs/system_overview/remote_supported_host_alpha.md")
	operatorSection := compactDocSection(t, remoteRaw, "### P0h Schema-Aware Recovery Evidence Interpretation", "### P0i Host-Local Vault Unseal Existing Recovery Session")

	assertContainsAll(t, "Remote Alpha operator P0h PLANS boundary", plans,
		"The P0h combined slice may extend only",
		"`scripts/remote_alpha_operator.sh recovery-session --evidence-check`",
		"schema-aware interpretation of known local evidence summaries",
		"remains local-only",
		"readiness summary, readiness staging record, Vault workload-auth summary, runtime identity helper summary, and Vault service-user migration summary schemas",
		"explicit safe-field allowlists",
		"print only non-secret status, classification, boolean, count, schema, byte-count, and SHA-256 metadata",
		"Unknown schemas are allowed by default with `schema_interpretation=unknown`",
		"`--strict-known-schema` may fail unknown schemas",
		"`--evidence-dir <path>` may inspect only direct expected filenames",
		"report missing expected filenames as `not_supplied`",
		"must not recurse or write into the directory",
		"must not print full JSON, create a session summary, write `.out`, run live tools, dispatch helpers",
		"Schema interpretation is evidence/projection only",
		"must not add IM authority, CP recovery authority, ES Vault token brokerage, or Remote Alpha deployment/provisioning/reconciliation architecture",
	)

	assertContainsAll(t, "Remote Alpha operator P0h docs boundary", operatorSection,
		"`Bounded slice rule`: P0h extends only the local",
		"`scripts/remote_alpha_operator.sh recovery-session --evidence-check`",
		"local-only evidence interpretation",
		"does not add live helper execution",
		"Infrastructure Manager execution",
		"support-bundle collection",
		"CP proof",
		"reset/unseal behavior",
		"workload-auth live checks",
		"runtime identity summary generation",
		"Vault service-user apply",
		"generic helper dispatch",
		"generated session summaries",
		"`.out` writes",
		"The known schemas are:",
		"`execution-substrate.remote-alpha.es-writable-state-readiness.v1`",
		"`execution-substrate.remote-alpha.es-writable-state-readiness-stage-provenance.v1`",
		"`execution-substrate.remote-alpha.vault-workload-auth-summary.v1`",
		"`execution-substrate.remote-runtime-identity-helper-summary.v1alpha1`",
		"`execution-substrate.remote-alpha.vault-service-user-migration-summary.v1`",
		"explicit safe-field allowlists",
		"selected status/classification fields",
		"booleans, and counts",
		"must not print full JSON, JWT-SVIDs, Vault tokens, root tokens, unseal keys, API keys, private keys, passwords, proof secret values",
		"raw identity payloads, arbitrary smoke-command output, or secret-bearing paths",
		"Unknown schemas are allowed by default",
		"`schema_interpretation=unknown`",
		"With `--strict-known-schema`, unknown schemas must fail without printing file contents",
		"`--evidence-dir <path>` is local-only",
		"`es-writable-state-readiness.json`",
		"`es-writable-state-readiness-helper-staging-record.json`",
		"`vault-workload-auth-summary.json`",
		"`runtime-identity-helper-summary.json`",
		"`vault-service-user-migration-check-only.json`",
		"`vault-service-user-migration-apply-summary.json`",
		"must not recurse",
		"must inspect only files that exist",
		"must report missing expected filenames as `not_supplied`",
		"must never write into the directory",
		"Schema-aware interpretation remains evidence/projection/diagnostics only",
		"not IM authority, CP recovery authority, ES Vault token brokerage",
	)
}

func TestRemoteAlphaOperatorP0iDocsHostLocalUnsealBoundary(t *testing.T) {
	plans := compactText(mustRead(t, "PLANS.md"))
	remoteRaw := mustRead(t, ".docs/system_overview/remote_supported_host_alpha.md")
	operatorSection := compactDocSection(t, remoteRaw, "### P0i Host-Local Vault Unseal Existing Recovery Session", "### P0j Mac-Side Vault Unseal Existing Recovery Session")

	assertContainsAll(t, "Remote Alpha operator P0i PLANS boundary", plans,
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
	plans := compactText(mustRead(t, "PLANS.md"))
	remoteRaw := mustRead(t, ".docs/system_overview/remote_supported_host_alpha.md")
	operatorSection := compactDocSection(t, remoteRaw, "### P0j Mac-Side Vault Unseal Existing Recovery Session", "### P0k Mac-Side Disposable Vault Reset Dry-Run Recovery Session")

	assertContainsAll(t, "Remote Alpha operator P0j PLANS boundary", plans,
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
	plans := compactText(mustRead(t, "PLANS.md"))
	remoteRaw := mustRead(t, ".docs/system_overview/remote_supported_host_alpha.md")
	operatorSection := compactDocSection(t, remoteRaw, "### P0k Mac-Side Disposable Vault Reset Dry-Run Recovery Session", "### P0l Mac-Side Disposable Vault Reset Execute-Reset Contract Prep")

	assertContainsAll(t, "Remote Alpha operator P0k PLANS boundary", plans,
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
	plans := compactText(mustRead(t, "PLANS.md"))
	remoteRaw := mustRead(t, ".docs/system_overview/remote_supported_host_alpha.md")
	operatorSection := compactDocSection(t, remoteRaw, "### P0l Mac-Side Disposable Vault Reset Execute-Reset Contract Prep", "### P0m Mac-Side Disposable Vault Reset Execute-Reset Recovery Session")
	allowedFlags := compactDocSection(t, remoteRaw, "Allowed flags for the P0l `vault-reset-disposable --execute-reset` contract are:", "The P0l contract route must reject:")

	assertContainsAll(t, "Remote Alpha operator P0l PLANS boundary", plans,
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
	plans := compactText(mustRead(t, "PLANS.md"))
	remoteRaw := mustRead(t, ".docs/system_overview/remote_supported_host_alpha.md")
	operatorSection := compactDocSection(t, remoteRaw, "### P0m Mac-Side Disposable Vault Reset Execute-Reset Recovery Session", "### P0d Interactive Validation Evidence")
	allowedFlags := compactDocSection(t, remoteRaw, "Allowed flags for `vault-reset-disposable` in P0m are:", "P0m must reject:")

	assertContainsAll(t, "Remote Alpha operator P0m PLANS boundary", plans,
		"The P0m implementation/self-audit slice may implement exactly the Mac-side destructive disposable Vault reset route defined by P0l",
		"`scripts/remote_alpha_operator.sh recovery-session vault-reset-disposable --ssh-target <target> --execute-reset --interactive-tty`",
		"P0m may validate only with static and fake SSH/SCP tests",
		"must not run live SSH, sudo, Vault, reset, unseal, execute-reset, Infrastructure Manager refresh, support-bundle collection, CP proof, workload-auth live checks, runtime identity generation, or network-dependent integration tests",
		"The P0k dry-run route remains the prerequisite/planning route",
		"P0m must preserve the existing P0k dry-run, P0i/P0j unseal-existing, recovery-session evidence/plan/inventory, readiness session, and writable-state readiness routes",
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

func TestRemoteAlphaOperatorP0nDocsMacSideWorkloadAuthCheckBoundary(t *testing.T) {
	plans := compactText(mustRead(t, "PLANS.md"))
	remoteRaw := mustRead(t, ".docs/system_overview/remote_supported_host_alpha.md")
	operatorSection := compactDocSection(t, remoteRaw, "### P0n Mac-Side Vault Workload-Auth Check Recovery Session", "### P0d Interactive Validation Evidence")
	allowedFlags := compactDocSection(t, remoteRaw, "Allowed flags for `vault-workload-auth-check` in P0n are:", "P0n must reject:")

	assertContainsAll(t, "Remote Alpha operator P0n PLANS boundary", plans,
		"The P0n implementation/self-audit slice may add exactly one Mac-side post-reset evidence route",
		"`scripts/remote_alpha_operator.sh recovery-session vault-workload-auth-check --ssh-target <target> --interactive-tty`",
		"operator runs the ES operator facade from the Mac",
		"stages bounded helper files to the Remote Alpha host",
		"secrets never pass through args, env, logs, artifacts, or Codex",
		"P0n may validate only with static and fake SSH/SCP tests",
		"must not run live SSH, sudo, Vault, workload-auth checks, reset/unseal, Infrastructure Manager refresh, support-bundle collection, CP proof, runtime identity generation, or network-dependent integration tests",
		"stage only:",
		"`scripts/remote_alpha_vault_workload_auth_check.sh`",
		"`scripts/internal/remote_alpha_vault_workload_auth_check.sh`",
		"preserve that public/internal relative layout",
		"invoke only the staged public workload-auth helper",
		"using `ssh -tt` only because `--interactive-tty` is mandatory",
		"must not stage `scripts/remote_alpha_operator.sh`, reset/unseal helpers, runtime identity helpers, service-user helpers, config/TLS helpers, binary deployment helpers, bundles, unrelated helpers, or a generic helper dispatcher",
		"Allowed flags for P0n are only `--help`, `--ssh-target <target>`, and `--interactive-tty`",
		"must reject `--host-local`, `--dry-run`, `--execute-reset`, `--unseal-only`, `--post-unseal-check`, `--apply`, `--interactive-sudo`, `--governed-smoke-command`",
		"workload-auth helper override flags",
		"summary path overrides",
		"all secret-like arguments",
		"`/var/tmp/execution-substrate-remote-alpha/vault-workload-auth-summary.json`",
		"must not copy that summary back to Mac `.out`",
		"print full summary JSON",
		"create an operator summary",
		"create generated artifacts",
		"tee, run `script`, capture transcripts",
		"After remote success it may print only non-secret next steps",
		"recommendation to use `recovery-session --evidence-check` after separately collecting IM/local evidence",
		"The workload-auth summary remains evidence/projection only, not readiness authority",
		"not ES Vault token brokerage",
		"not CP recovery authority",
		"safe Vault JWT login failure classification",
		"`auth_smoke.vault_login_raw_error_recorded=false`",
		"raw Vault login response body, raw HTTP headers, Authorization header",
	)

	assertContainsAll(t, "Remote Alpha operator P0n docs boundary", operatorSection,
		"`Bounded slice rule`: P0n implements exactly one Mac-side post-reset workload-auth evidence route",
		"`scripts/remote_alpha_operator.sh recovery-session vault-workload-auth-check --ssh-target <target> --interactive-tty`",
		"P0n is implementation/self-audit with static and fake SSH/SCP validation only.",
		"It does not run live SSH, sudo, Vault, workload-auth checks, reset, unseal, Infrastructure Manager refresh, support-bundle collection, CP proof, runtime identity generation, or network-dependent integration tests during validation.",
		"The route is separate from reset/unseal.",
		"not workload-auth bootstrap",
		"not ES token brokerage",
		"Topology rules:",
		"`--ssh-target <target>` is required",
		"`--interactive-tty` is required",
		"local stdin and stdout must both be visible terminals before staging or SSH",
		"`--host-local` is not accepted for this Mac-side route",
		"bare `vault-workload-auth-check` execution must fail",
		"Allowed flags for `vault-workload-auth-check` in P0n are:",
		"P0n must reject:",
		"workload-auth helper override flags",
		"Vault address, role, audience, path, or proof-path overrides",
		"SPIFFE ID overrides",
		"config path overrides",
		"summary path overrides",
		"container probe image overrides",
		"SPIRE socket overrides",
		"Secret model:",
		"must not accept, parse, print, log, relay, persist, summarize, or copy JWT-SVIDs, Vault client tokens, proof secret payloads, root tokens, unseal keys, API keys, private keys, passwords, or secret payloads",
		"when the helper reaches Vault JWT login and `auth_smoke.vault_login=fail`",
		"`auth_smoke.vault_login_failure_class`",
		"`auth_smoke.vault_login_raw_error_recorded=false`",
		"`invalid_issuer_or_validation_key`",
		"the raw Vault login response body, raw HTTP headers, Authorization header, full Vault login JSON",
		"must not print full summary JSON",
		"stage only `scripts/remote_alpha_vault_workload_auth_check.sh`",
		"`scripts/internal/remote_alpha_vault_workload_auth_check.sh`",
		"preserve the remote `scripts/` and `scripts/internal/` relative layout",
		"do not stage `scripts/remote_alpha_operator.sh`",
		"do not stage reset/unseal helpers",
		"do not stage runtime identity helpers",
		"do not stage service-user helpers",
		"do not stage config/TLS helpers",
		"do not stage binary deployment helpers",
		"do not stage bundles or unrelated helpers",
		"do not introduce generic helper dispatch",
		"allocate an interactive SSH TTY with `ssh -tt`",
		"invoke only the staged public helper as `remote_alpha_vault_workload_auth_check.sh`",
		"pass no workload-auth helper override flags",
		"never combine workload-auth evidence with reset, unseal, post-unseal checks, runtime identity summary, Infrastructure Manager refresh, support-bundle collection, CP proof",
		"do not capture stdout or stderr to files",
		"do not use `tee`",
		"do not run `script`",
		"cleanup of the staged workload-auth helper files/root must be attempted by default",
		"the canonical summary remains remote at `/var/tmp/execution-substrate-remote-alpha/vault-workload-auth-summary.json`",
		"no summary is copied back to Mac `.out` in this route",
		"no operator summary file",
		"after remote success, the operator facade may print only non-secret next steps",
		"Stop conditions for P0n:",
		"staging the workload-auth route requires more files than the public wrapper and internal helper",
		"helper override flags are accepted",
		"copies the summary back to Mac `.out`",
		"prints full summary JSON",
		"creates operator summaries or generated artifacts",
		"runs Infrastructure Manager refresh, support-bundle collection, CP proof, reset/unseal, runtime identity generation, or workload-auth bootstrap",
		"combines workload-auth evidence with reset/unseal",
		"a generic helper dispatcher is introduced",
		"P0n remains bounded ES Remote Alpha proof/support workflow glue only.",
		"not workload-auth bootstrap",
		"not ES Vault token brokerage",
		"not governed execution proof",
		"not Remote Alpha production, deployment, provisioning, or reconciliation architecture",
	)

	assertContainsAll(t, "Remote Alpha operator P0n allowed flags", allowedFlags,
		"`--help`",
		"`--ssh-target <target>`",
		"`--interactive-tty`",
	)
	assertContainsNone(t, "Remote Alpha operator P0n allowed flags", allowedFlags,
		"`--host-local`",
		"`--dry-run`",
		"`--execute-reset`",
		"`--post-unseal-check`",
		"`--summary-path`",
		"`--vault-role`",
		"root tokens",
		"unseal keys",
		"JWT-SVID",
	)
}

func TestRemoteAlphaOperatorP0oDocsVaultWorkloadAuthBootstrapPlanningBoundary(t *testing.T) {
	plans := compactText(mustRead(t, "PLANS.md"))
	remoteRaw := mustRead(t, ".docs/system_overview/remote_supported_host_alpha.md")
	operatorSection := compactDocSection(t, remoteRaw, "### P0o Vault Workload-Auth Bootstrap Planning Surface", "### P0d Interactive Validation Evidence")
	allowedFlags := compactDocSection(t, remoteRaw, "Allowed flags for `vault-workload-auth-bootstrap` in P0o are:", "With no mode")

	assertContainsAll(t, "Remote Alpha operator P0o PLANS boundary", plans,
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
	plans := compactText(mustRead(t, "PLANS.md"))
	remoteRaw := mustRead(t, ".docs/system_overview/remote_supported_host_alpha.md")
	operatorSection := compactDocSection(t, remoteRaw, "### P0p Vault Workload-Auth Bootstrap Execution Contract Prep", "### P0d Interactive Validation Evidence")

	assertContainsAll(t, "Remote Alpha operator P0p PLANS boundary", plans,
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
	plans := compactText(mustRead(t, "PLANS.md"))
	remoteRaw := mustRead(t, ".docs/system_overview/remote_supported_host_alpha.md")
	operatorSection := compactDocSection(t, remoteRaw, "### P0q Vault Workload-Auth Bootstrap Execution Route", "### P0r Mac-Side Runtime Identity Summary Recovery Session")

	assertContainsAll(t, "Remote Alpha operator P0q PLANS boundary", plans,
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

func TestRemoteAlphaOperatorP0rDocsRuntimeIdentitySummaryRoute(t *testing.T) {
	plans := compactText(mustRead(t, "PLANS.md"))
	remoteRaw := mustRead(t, ".docs/system_overview/remote_supported_host_alpha.md")
	operatorSection := compactDocSection(t, remoteRaw, "### P0r Mac-Side Runtime Identity Summary Recovery Session", "### P0s Mac-Side ES Service TLS Status/Renew Recovery Session")
	allowedFlags := compactDocSection(t, remoteRaw, "Allowed flags for `runtime-identity-summary` in P0r are:", "P0r must reject:")
	source := mustRead(t, remoteAlphaOperatorScriptPath())
	sourceSection := docSection(t, source, "recovery_session_runtime_identity_summary_require_command() {", "\nrecovery_session_evidence_check() {")

	assertContainsAll(t, "Remote Alpha operator P0r PLANS boundary", plans,
		"The P0r implementation/self-audit/merge-readiness slice may add exactly one Mac-side recovery-session runtime identity evidence route",
		"`scripts/remote_alpha_operator.sh recovery-session runtime-identity-summary --ssh-target <target> --interactive-tty`",
		"evidence/projection only over the existing host-local runtime identity helper summary script",
		"does not settle the reopened runtime-identity handoff seam",
		"does not claim runtime-profile readiness, submit readiness, retained-result readiness, governed execution proof, CP proof, or production readiness",
		"stage only:",
		"`scripts/remote_alpha_runtime_identity_helper_summary.sh`",
		"resolve that helper from `BASH_SOURCE[0]`",
		"invoke only the staged helper over `ssh -tt`",
		"must not stage `scripts/remote_alpha_operator.sh`, `scripts/internal/*`, reset/unseal helpers, workload-auth helpers, workload-auth bootstrap helpers, service-user helpers",
		"must not source helper scripts",
		"must not print full summary JSON",
		"`/var/tmp/execution-substrate-remote-alpha/runtime-identity-helper-summary.json`",
		"`--help`, `--ssh-target <target>`, and `--interactive-tty`",
		"`--host-local`, `--dry-run`, `--check-only`, `--apply`, `--execute-reset`, `--unseal-only`, `--post-unseal-check`, `--execute-bootstrap`, `--prepare-summary-path`",
		"`--output`, `--runtime-support-path`, `--spire-agent-socket-path`, `--spire-server-socket-path`, `--workload-spiffe-id`, and `--audience`",
		"all secret-like arguments including root tokens, unseal keys, client tokens, Vault tokens, JWT-SVID payloads, API keys, private keys, passwords, proof secrets, raw identity payloads, and secret payloads",
		"P0r validation remains fake/static only",
		"fake SSH/SCP staging of exactly the one public runtime identity helper",
		"no transcript/`tee`/`script`",
		"no `.out`, operator summary, support bundle, IM, CP proof, reset/unseal, workload-auth bootstrap/check, runtime identity generation, generic helper dispatch, or `scripts/internal/*`",
	)

	assertContainsAll(t, "Remote Alpha operator P0r docs boundary", operatorSection,
		"`Bounded slice rule`: P0r implements exactly one Mac-side runtime identity evidence route",
		"`scripts/remote_alpha_operator.sh recovery-session runtime-identity-summary --ssh-target <target> --interactive-tty`",
		"static and fake SSH/SCP validation only",
		"It does not run live SSH, sudo, SPIRE commands, Vault, workload-auth bootstrap/check, reset, unseal, Infrastructure Manager refresh, support-bundle collection, CP proof, runtime identity summary live, runtime identity generation, or network-dependent integration tests during validation.",
		"The route is separate from workload-auth bootstrap/check and reset/unseal.",
		"evidence/projection only over the existing host-local runtime identity helper summary script",
		"does not settle the reopened runtime-identity handoff seam",
		"Topology rules:",
		"`--ssh-target <target>` is required",
		"`--interactive-tty` is required",
		"local stdin and stdout must both be visible terminals before staging or SSH",
		"`--host-local` is not accepted for this Mac-side route",
		"bare `runtime-identity-summary` execution must fail",
		"Allowed flags for `runtime-identity-summary` in P0r are:",
		"P0r must reject:",
		"runtime identity helper override flags",
		"output or summary path overrides",
		"runtime-support path overrides",
		"SPIRE socket overrides",
		"workload SPIFFE ID overrides",
		"audience overrides",
		"Secret model:",
		"must not accept, parse, print, log, relay, persist, summarize, or copy JWT-SVIDs, Vault tokens, root tokens, unseal keys, API keys, private keys, passwords, proof secrets, raw identity payloads, or secret material",
		"must not print full summary JSON",
		"stage only `scripts/remote_alpha_runtime_identity_helper_summary.sh`",
		"do not stage `scripts/remote_alpha_operator.sh`",
		"do not stage `scripts/internal/*`",
		"do not stage reset/unseal helpers",
		"do not stage workload-auth helpers",
		"do not stage workload-auth bootstrap helpers",
		"do not stage service-user helpers",
		"do not stage config/TLS helpers",
		"do not stage binary deployment helpers",
		"do not stage bundles or unrelated helpers",
		"do not introduce generic helper dispatch",
		"allocate an interactive SSH TTY with `ssh -tt`",
		"invoke only the staged runtime identity helper summary script",
		"pass no runtime identity helper override flags",
		"never combine runtime identity evidence with workload-auth bootstrap/check, reset, unseal, post-unseal checks, Infrastructure Manager refresh, support-bundle collection, CP proof, runtime identity generation, runtime profile readiness, submit readiness, or retained-result readiness",
		"do not capture stdout or stderr to files",
		"do not use `tee`",
		"do not run `script`",
		"cleanup of the staged helper file/root must be attempted by default",
		"`/var/tmp/execution-substrate-remote-alpha/runtime-identity-helper-summary.json`",
		"no summary is copied back to Mac `.out` in this route",
		"no operator summary file is created",
		"after remote success, the operator facade may print only the canonical remote summary path",
		"`recovery-session --evidence-check --runtime-identity-summary <local-path>`",
		"Stop conditions for P0r:",
		"staging the route requires more files than the public runtime identity helper summary script",
		"helper override flags are accepted",
		"copies the summary back to Mac `.out`",
		"prints full summary JSON",
		"creates operator summaries or generated artifacts",
		"runs Infrastructure Manager refresh, support-bundle collection, CP proof, reset/unseal, workload-auth bootstrap/check, runtime identity generation, or readiness proof",
		"a generic helper dispatcher is introduced",
		"not runtime-profile readiness",
		"not submit readiness",
		"not retained-result readiness",
		"not governed execution proof",
		"not CP proof",
		"not production readiness",
	)

	assertContainsAll(t, "Remote Alpha operator P0r allowed flags", allowedFlags,
		"`--help`",
		"`--ssh-target <target>`",
		"`--interactive-tty`",
	)
	assertContainsNone(t, "Remote Alpha operator P0r allowed flags", allowedFlags,
		"`--host-local`",
		"`--dry-run`",
		"`--check-only`",
		"`--output`",
		"`--audience`",
		"root tokens",
		"JWT-SVID",
	)
	assertContainsAll(t, "Remote Alpha operator P0r source", sourceSection,
		"REMOTE_ALPHA_RUNTIME_IDENTITY_SUMMARY_HELPER",
		"REMOTE_ALPHA_RUNTIME_IDENTITY_SUMMARY_STAGE_ROOT",
		"REMOTE_ALPHA_RUNTIME_IDENTITY_SUMMARY_REMOTE_SUMMARY",
		`scp "${REMOTE_ALPHA_RUNTIME_IDENTITY_SUMMARY_HELPER}" "${ssh_target}:${remote_helper_path}"`,
		`ssh -tt "${ssh_target}"`,
		`"${helper_path}"`,
	)
	assertContainsNone(t, "Remote Alpha operator P0r source forbidden bundle", sourceSection,
		"scripts/internal/",
		"remote_alpha_vault_workload_auth_check.sh",
		"remote_alpha_vault_workload_auth_bootstrap.sh",
		"remote_alpha_reset_disposable_vault.sh",
		"remote-alpha-live-refresh",
		"remote-alpha-live-support-bundle",
		`"${helper_path}" --dry-run`,
		`"${helper_path}" --check-only`,
		"tee ",
	)
}

func TestRemoteAlphaOperatorP0sDocsESServiceTLSRenewRoute(t *testing.T) {
	plans := compactText(mustRead(t, "PLANS.md"))
	remoteRaw := mustRead(t, ".docs/system_overview/remote_supported_host_alpha.md")
	operatorSection := compactDocSection(t, remoteRaw, "### P0s Mac-Side ES Service TLS Status/Renew Recovery Session", "### P0d Interactive Validation Evidence")
	allowedFlags := compactDocSection(t, remoteRaw, "Allowed flags for P0s are:", "P0s must reject:")
	artifact := compactText(mustRead(t, ".docs/system_overview/artifact_hygiene.md"))
	source := mustRead(t, remoteAlphaOperatorScriptPath())
	sourceSection := docSection(t, source, "recovery_session_es_service_tls_usage() {", "\nrecovery_session() {")

	assertContainsAll(t, "Remote Alpha operator P0s PLANS boundary", plans,
		"The P0s implementation/self-audit/merge-readiness slice may add exactly one bounded Remote Alpha internal ES service TLS helper pair and exactly two Mac-side recovery-session routes for ARS/AGS/ES artifact-registry mTLS status and renewal",
		"`scripts/remote_alpha_operator.sh recovery-session es-service-tls-status --ssh-target <target> --interactive-tty`",
		"`scripts/remote_alpha_operator.sh recovery-session es-service-tls-renew --ssh-target <target> --interactive-tty --execute-renew`",
		"`scripts/remote_alpha_es_service_tls_renew.sh`",
		"`scripts/internal/remote_alpha_es_service_tls_renew.sh`",
		"must not run live SSH, sudo, live remote OpenSSL, Vault, reset/unseal, workload-auth bootstrap/check, runtime identity summary, Infrastructure Manager refresh, support-bundle collection, CP proof, SPIRE/Nomad mutation",
		"not generic TLS deployment, provisioning, reconciliation, production readiness, IM authority, CP authority, Vault lifecycle, SPIRE lifecycle, Nomad lifecycle, workload-auth bootstrap/check, or runtime identity evidence",
		"`/etc/execution-substrate/ars-tls/runtime-ca.pem`",
		"`/etc/execution-substrate/ars-tls/ars-server-cert.pem`",
		"`/etc/execution-substrate/ars-tls/ars-server-key.pem`",
		"`/etc/execution-substrate/tls/ags-client-cert.pem`",
		"`/etc/execution-substrate/tls/ags-client-key.pem`",
		"`/etc/execution-substrate/tls/runtime-ca.pem`",
		"`/etc/execution-substrate/es-tls/artifact-registry-client-cert.pem`",
		"`/etc/execution-substrate/es-tls/artifact-registry-client-key.pem`",
		"`/etc/execution-substrate/es-tls/artifact-registry-root-ca.pem`",
		"must inspect the current config topology before status or renewal",
		"covered renewal path, the helper must stop with a non-secret topology blocker",
		"status mode is non-mutating",
		"verify AGS and ES client certificates against the ARS trusted runtime/client CA",
		"verify the ARS server certificate against the AGS and ES root CAs",
		"`/var/tmp/execution-substrate-remote-alpha/es-service-tls-renew-summary.json`",
		"restart only the bounded affected service set `ars.service`, `ags.service`, and `es.service`",
		"Mac-side IM health refresh remains a separate later action",
		"private key PEM bodies, full certificate PEM bodies",
		"Allowed P0s route flags are only `--help`, `--ssh-target <target>`, `--interactive-tty`, and `--execute-renew` for the renew route only",
		"P0s validation remains fake/static only",
	)

	assertContainsAll(t, "Remote Alpha operator P0s docs boundary", operatorSection,
		"`Bounded slice rule`: P0s implements exactly one bounded Remote Alpha internal ES service TLS helper pair and exactly two Mac-side recovery-session routes",
		"`scripts/remote_alpha_operator.sh recovery-session es-service-tls-status --ssh-target <target> --interactive-tty`",
		"`scripts/remote_alpha_operator.sh recovery-session es-service-tls-renew --ssh-target <target> --interactive-tty --execute-renew`",
		"static and fake SSH/SCP validation only",
		"It does not run live SSH, sudo, live OpenSSL against the remote host, Vault, reset, unseal, workload-auth bootstrap/check, runtime identity summary, Infrastructure Manager refresh, support-bundle collection, CP proof, SPIRE or Nomad mutation",
		"The route is separate from IM, CP, Vault, SPIRE, Nomad, workload-auth, reset, unseal, runtime identity, and general deployment.",
		"Covered topology and fixed paths:",
		"`/etc/execution-substrate/ars-tls/runtime-ca.pem`",
		"`/etc/execution-substrate/ars-tls/ars-server-cert.pem`",
		"`/etc/execution-substrate/ars-tls/ars-server-key.pem`",
		"`/etc/execution-substrate/tls/ags-client-cert.pem`",
		"`/etc/execution-substrate/tls/ags-client-key.pem`",
		"`/etc/execution-substrate/tls/runtime-ca.pem`",
		"`/etc/execution-substrate/es-tls/artifact-registry-client-cert.pem`",
		"`/etc/execution-substrate/es-tls/artifact-registry-client-key.pem`",
		"`/etc/execution-substrate/es-tls/artifact-registry-root-ca.pem`",
		"Topology stop line:",
		"the helper must stop with a non-secret topology blocker",
		"P0s intentionally does not cover AGS external server certs, ES external server certs, EGS TLS/CAs, Vault, SPIRE, Nomad",
		"Status behavior:",
		"`es-service-tls-status` is non-mutating.",
		"public certificate fields only: subject, issuer, SAN, EKU, notBefore, notAfter",
		"confirms ARS/AGS/ES cert/key public-key matches without printing private keys",
		"verifies AGS and ES client certificates against the ARS trusted runtime/client CA",
		"verifies the ARS server certificate against the AGS and ES root CAs",
		"Renew behavior:",
		"`es-service-tls-renew` requires explicit `--execute-renew`.",
		"Both status and renew require visible `--interactive-tty` and `--ssh-target <target>`.",
		"The Mac-side facade stages only `scripts/remote_alpha_es_service_tls_renew.sh` and `scripts/internal/remote_alpha_es_service_tls_renew.sh`.",
		"The remote command invokes only `--status` or `--execute-renew` through `ssh -tt`; it passes no helper override flags.",
		"Renewal creates a backup directory with non-secret metadata before replacing files.",
		"Ownership/mode policy is fixed: ARS material `root:ars 0640`, AGS material `root:ags 0640`, and ES material `root:es 0640`.",
		"It restarts only `ars.service`, `ags.service`, and `es.service`.",
		"Post-renew verification re-runs the certificate verification checks and probes ARS `/health` over mTLS using the configured AGS and ES artifact-registry client identities.",
		"Summary/evidence behavior:",
		"`/var/tmp/execution-substrate-remote-alpha/es-service-tls-renew-summary.json`",
		"`execution-substrate.remote-alpha.es-service-tls-renew-summary.v1`",
		"evidence/projection only, never authority and not an IM input",
		"must not print full summary JSON and must not copy the summary back to Mac `.out`",
		"Allowed flags for P0s are:",
		"P0s must reject:",
		"TLS/config path overrides",
		"secret-like arguments, including private keys, root tokens, unseal keys, client tokens, Vault tokens, JWT-SVID payloads, API keys, passwords, proof secrets, and secret payloads",
		"P0s tests:",
		"fake SSH/SCP tests prove exactly the fixed public/internal TLS renewal helper pair is staged",
		"fake renew tests prove private key PEM bodies are not printed or persisted to summaries",
		"Stop conditions for P0s:",
		"not generic TLS deployment, not Infrastructure Manager reconciliation, not Control Plane authority, not Vault/SPIRE/Nomad authority, not production readiness",
	)
	assertContainsNone(t, "Remote Alpha operator P0s docs overclaims", operatorSection,
		"production readiness is proved",
		"IM reconciliation succeeds",
		"CP proof is run",
		"Vault tokens are brokered",
	)

	assertContainsAll(t, "Remote Alpha operator P0s allowed flags", allowedFlags,
		"`--help`",
		"`--ssh-target <target>`",
		"`--interactive-tty`",
		"`--execute-renew` only for `es-service-tls-renew`",
	)
	assertContainsNone(t, "Remote Alpha operator P0s allowed flags", allowedFlags,
		"`--host-local`",
		"`--dry-run`",
		"`--status`",
		"`--apply`",
		"private keys",
		"Vault tokens",
	)

	assertContainsAll(t, "Remote Alpha operator P0s artifact hygiene", artifact,
		"`/var/tmp/execution-substrate-remote-alpha/es-service-tls-renew-summary.json`",
		"`execution-substrate.remote-alpha.es-service-tls-renew-summary.v1`",
		"non-secret helper summary only",
		"public fingerprints",
		"cert/key public-key match status",
		"must not be copied back to Mac `.out` by the operator facade",
		"must not become an IM input or CP proof artifact",
		"must not contain private key PEM bodies, full certificate PEM bodies, private-key backup digests, Vault tokens, root tokens, unseal keys, client tokens, JWT-SVID payloads, API keys, passwords, proof secrets, terminal transcripts, support-bundle content, or raw secret-bearing command output",
	)

	assertContainsAll(t, "Remote Alpha operator P0s source", sourceSection,
		"REMOTE_ALPHA_ES_SERVICE_TLS_RENEW_PUBLIC_HELPER",
		"REMOTE_ALPHA_ES_SERVICE_TLS_RENEW_INTERNAL_HELPER",
		"REMOTE_ALPHA_ES_SERVICE_TLS_RENEW_REMOTE_SUMMARY",
		`scp "${REMOTE_ALPHA_ES_SERVICE_TLS_RENEW_PUBLIC_HELPER}" "${ssh_target}:${remote_public_helper_path}"`,
		`scp "${REMOTE_ALPHA_ES_SERVICE_TLS_RENEW_INTERNAL_HELPER}" "${ssh_target}:${remote_internal_helper_path}"`,
		`ssh -tt "${ssh_target}" "${remote_shell_command}"`,
		`"${helper_path}" %q`,
		`sudo "${helper_path}" %q`,
		"--status|--execute-renew",
		"recovery-session es-service-tls-renew requires --execute-renew",
		"recovery-session es-service-tls-status forbids --execute-renew",
	)
	assertContainsNone(t, "Remote Alpha operator P0s source forbidden helper bundle", sourceSection,
		"remote_alpha_reset_disposable_vault.sh",
		"remote_alpha_vault_workload_auth_check.sh",
		"remote_alpha_vault_workload_auth_bootstrap.sh",
		"remote_alpha_runtime_identity_helper_summary.sh",
		"remote-alpha-live-refresh",
		"remote-alpha-live-support-bundle",
		`"${helper_path}" --dry-run`,
		`"${helper_path}" --check-only`,
		"tee ",
	)
}

func TestRemoteAlphaOperatorP0tDocsESGovernanceTLSRenewRoute(t *testing.T) {
	plans := compactText(mustRead(t, "PLANS.md"))
	remoteRaw := mustRead(t, ".docs/system_overview/remote_supported_host_alpha.md")
	operatorSection := compactDocSection(t, remoteRaw, "### P0t Mac-Side ES Governance TLS Status/Renew Recovery Session", "### P0d Interactive Validation Evidence")
	allowedFlags := compactDocSection(t, remoteRaw, "Allowed flags for P0t are:", "P0t must reject:")
	artifact := compactText(mustRead(t, ".docs/system_overview/artifact_hygiene.md"))
	source := mustRead(t, remoteAlphaOperatorScriptPath())
	sourceSection := docSection(t, source, "recovery_session_es_governance_tls_usage() {", "\nrecovery_session() {")

	assertContainsAll(t, "Remote Alpha operator P0t PLANS boundary", plans,
		"The P0t implementation/self-audit/merge-readiness slice may extend the existing bounded Remote Alpha internal ES service TLS helper pair with exactly one additional fixed scope and exactly two Mac-side recovery-session routes for the ES -> EGS execution-governance trust-model mTLS path",
		"`scripts/remote_alpha_operator.sh recovery-session es-governance-tls-status --ssh-target <target> --interactive-tty`",
		"`scripts/remote_alpha_operator.sh recovery-session es-governance-tls-renew --ssh-target <target> --interactive-tty --execute-renew`",
		"`scripts/remote_alpha_es_service_tls_renew.sh`",
		"`scripts/internal/remote_alpha_es_service_tls_renew.sh`",
		"fixed `--scope execution-governance` helper invocation",
		"must not run live SSH, sudo, live remote OpenSSL, Vault, reset/unseal, workload-auth bootstrap/check, runtime identity summary, Infrastructure Manager refresh, support-bundle collection, CP proof, SPIRE/Nomad mutation",
		"not generic TLS deployment, provisioning, reconciliation, production readiness, IM authority, CP authority, Vault lifecycle, SPIRE lifecycle, Nomad lifecycle, workload-auth bootstrap/check, runtime identity evidence, or a redesign of EGS trust-model semantics",
		"`/etc/execution-substrate/egs-tls/egs-server-cert.pem`",
		"`/etc/execution-substrate/egs-tls/egs-server-key.pem`",
		"`/etc/execution-substrate/egs-tls/runtime-ca.pem`",
		"`/etc/execution-substrate/es-tls/execution-governance-client-cert.pem`",
		"`/etc/execution-substrate/es-tls/execution-governance-client-key.pem`",
		"`/etc/execution-substrate/es-tls/execution-governance-root-ca.pem`",
		"AGS config has no execution-governance dependency",
		"The current EGS trusted client CA is the same runtime CA file",
		"Any AGS client-to-EGS material is out of scope for P0t",
		"status mode is non-mutating",
		"verify the ES client certificate against the EGS trusted runtime/client CA",
		"verify the EGS server certificate against the ES execution-governance root CA",
		"`/var/tmp/execution-substrate-remote-alpha/es-governance-tls-renew-summary.json`",
		"restart only the bounded affected service set `egs.service` and `es.service`",
		"probe EGS `/v1/trust-model` over mTLS",
		"private key PEM bodies, full certificate PEM bodies",
		"Allowed P0t route flags are only `--help`, `--ssh-target <target>`, `--interactive-tty`, and `--execute-renew` for the renew route only",
		"P0t validation remains fake/static only",
	)

	assertContainsAll(t, "Remote Alpha operator P0t docs boundary", operatorSection,
		"`Bounded slice rule`: P0t extends the existing bounded Remote Alpha internal ES service TLS helper pair with exactly one additional fixed scope",
		"`scripts/remote_alpha_operator.sh recovery-session es-governance-tls-status --ssh-target <target> --interactive-tty`",
		"`scripts/remote_alpha_operator.sh recovery-session es-governance-tls-renew --ssh-target <target> --interactive-tty --execute-renew`",
		"static and fake SSH/SCP validation only",
		"It does not run live SSH, sudo, live OpenSSL against the remote host, Vault, reset, unseal, workload-auth bootstrap/check, runtime identity summary, Infrastructure Manager refresh, support-bundle collection, CP proof, SPIRE or Nomad mutation",
		"The route is separate from IM, CP, Vault, SPIRE, Nomad, workload-auth, reset, unseal, runtime identity, EGS trust-model redesign, and general deployment.",
		"Covered topology and fixed paths:",
		"`/etc/execution-substrate/egs-tls/egs-server-cert.pem`",
		"`/etc/execution-substrate/egs-tls/egs-server-key.pem`",
		"`/etc/execution-substrate/egs-tls/runtime-ca.pem`",
		"`/etc/execution-substrate/es-tls/execution-governance-client-cert.pem`",
		"`/etc/execution-substrate/es-tls/execution-governance-client-key.pem`",
		"`/etc/execution-substrate/es-tls/execution-governance-root-ca.pem`",
		"Topology stop line:",
		"AGS has no current client-to-EGS dependency in the repo config model",
		"Any AGS client-to-EGS material observed in config is out of scope for P0t",
		"the helper must stop with a non-secret topology blocker",
		"Status behavior:",
		"`es-governance-tls-status` is non-mutating.",
		"public certificate fields only: subject, issuer, SAN, EKU, notBefore, notAfter",
		"confirms EGS server cert/key and ES execution-governance client cert/key public-key matches without printing private keys",
		"verifies the ES execution-governance client certificate against the EGS trusted runtime/client CA",
		"verifies the EGS server certificate against the ES execution-governance root CA",
		"Renew behavior:",
		"`es-governance-tls-renew` requires explicit `--execute-renew`.",
		"Both status and renew require visible `--interactive-tty` and `--ssh-target <target>`.",
		"The Mac-side facade stages only `scripts/remote_alpha_es_service_tls_renew.sh` and `scripts/internal/remote_alpha_es_service_tls_renew.sh`.",
		"The remote command invokes only `--scope execution-governance --status` or `--scope execution-governance --execute-renew` through `ssh -tt`; it passes no helper override flags.",
		"Renewal creates a backup directory with non-secret metadata before replacing files.",
		"Ownership/mode policy is fixed: EGS material `root:egs 0640` and ES execution-governance material `root:es 0640`.",
		"It restarts only `egs.service` and `es.service`.",
		"Post-renew verification re-runs the certificate verification checks and probes EGS `/v1/trust-model` over mTLS using the configured ES execution-governance client identity.",
		"Summary/evidence behavior:",
		"`/var/tmp/execution-substrate-remote-alpha/es-governance-tls-renew-summary.json`",
		"`execution-substrate.remote-alpha.es-governance-tls-renew-summary.v1`",
		"evidence/projection only, never authority and not an IM input",
		"must not print full summary JSON and must not copy the summary back to Mac `.out`",
		"Allowed flags for P0t are:",
		"P0t must reject:",
		"TLS/config path overrides",
		"secret-like arguments, including private keys, root tokens, unseal keys, client tokens, Vault tokens, JWT-SVID payloads, API keys, passwords, proof secrets, and secret payloads",
		"P0t tests:",
		"fake SSH/SCP tests prove exactly the fixed public/internal TLS renewal helper pair is staged",
		"fake post-renew verification exercises the ES -> EGS trust-model TLS path",
		"Stop conditions for P0t:",
		"not generic TLS deployment, not Infrastructure Manager reconciliation, not Control Plane authority, not Vault/SPIRE/Nomad authority, not EGS trust-model redesign, not production readiness",
	)
	assertContainsNone(t, "Remote Alpha operator P0t docs overclaims", operatorSection,
		"production readiness is proved",
		"IM reconciliation succeeds",
		"CP proof is run",
		"Vault tokens are brokered",
	)

	assertContainsAll(t, "Remote Alpha operator P0t allowed flags", allowedFlags,
		"`--help`",
		"`--ssh-target <target>`",
		"`--interactive-tty`",
		"`--execute-renew` only for `es-governance-tls-renew`",
	)
	assertContainsNone(t, "Remote Alpha operator P0t allowed flags", allowedFlags,
		"`--host-local`",
		"`--dry-run`",
		"`--status`",
		"`--scope`",
		"`--apply`",
		"private keys",
		"Vault tokens",
	)

	assertContainsAll(t, "Remote Alpha operator P0t artifact hygiene", artifact,
		"`/var/tmp/execution-substrate-remote-alpha/es-governance-tls-renew-summary.json`",
		"`execution-substrate.remote-alpha.es-governance-tls-renew-summary.v1`",
		"non-secret helper summary only",
		"public fingerprints",
		"cert/key public-key match status",
		"must not be copied back to Mac `.out` by the operator facade",
		"must not become an IM input or CP proof artifact",
		"must not contain private key PEM bodies, full certificate PEM bodies, private-key backup digests, Vault tokens, root tokens, unseal keys, client tokens, JWT-SVID payloads, API keys, passwords, proof secrets, terminal transcripts, support-bundle content, or raw secret-bearing command output",
	)

	assertContainsAll(t, "Remote Alpha operator P0t source", sourceSection,
		"REMOTE_ALPHA_ES_SERVICE_TLS_RENEW_PUBLIC_HELPER",
		"REMOTE_ALPHA_ES_SERVICE_TLS_RENEW_INTERNAL_HELPER",
		"REMOTE_ALPHA_ES_GOVERNANCE_TLS_RENEW_REMOTE_SUMMARY",
		"REMOTE_ALPHA_ES_GOVERNANCE_TLS_RENEW_STAGE_ROOT",
		`recovery_session_es_service_tls_stage_remote`,
		`ssh -tt "${ssh_target}" "${remote_shell_command}"`,
		`"${helper_path}" --scope execution-governance %q`,
		`sudo "${helper_path}" --scope execution-governance %q`,
		"--status|--execute-renew",
		"recovery-session es-governance-tls-renew requires --execute-renew",
		"recovery-session es-governance-tls-status forbids --execute-renew",
	)
	assertContainsNone(t, "Remote Alpha operator P0t source forbidden helper bundle", sourceSection,
		"remote_alpha_reset_disposable_vault.sh",
		"remote_alpha_vault_workload_auth_check.sh",
		"remote_alpha_vault_workload_auth_bootstrap.sh",
		"remote_alpha_runtime_identity_helper_summary.sh",
		"remote-alpha-live-refresh",
		"remote-alpha-live-support-bundle",
		`"${helper_path}" --dry-run`,
		`"${helper_path}" --check-only`,
		"tee ",
	)
}

func TestRemoteAlphaOperatorP0uDocsOperatorHealthcheckTLSRenewRoute(t *testing.T) {
	plans := compactText(mustRead(t, "PLANS.md"))
	remoteRaw := mustRead(t, ".docs/system_overview/remote_supported_host_alpha.md")
	operatorSection := compactDocSection(t, remoteRaw, "### P0u Mac-Side Operator Healthcheck TLS Status/Renew Recovery Session", "### P0d Interactive Validation Evidence")
	allowedFlags := compactDocSection(t, remoteRaw, "Allowed flags for P0u are:", "P0u must reject:")
	artifact := compactText(mustRead(t, ".docs/system_overview/artifact_hygiene.md"))
	source := mustRead(t, remoteAlphaOperatorScriptPath())
	sourceSection := docSection(t, source, "recovery_session_operator_healthcheck_tls_usage() {", "\nrecovery_session() {")

	assertContainsAll(t, "Remote Alpha operator P0u PLANS boundary", plans,
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
	plans := compactText(mustRead(t, "PLANS.md"))
	designRaw := mustRead(t, ".docs/remote_alpha_operator_healthcheck_noninteractive_status.md")
	design := compactText(designRaw)
	authPosture := compactDocSection(t, designRaw, "## 6. Auth Posture Classification", "## 7. Status Evidence Schema")
	remoteRaw := mustRead(t, ".docs/system_overview/remote_supported_host_alpha.md")
	p0vSection := compactDocSection(t, remoteRaw, "### P0v Operator Healthcheck TLS Noninteractive Status Design", "### Remote Alpha Maintenance Monitor Boundary")
	source := mustRead(t, remoteAlphaOperatorScriptPath())
	dispatchSections := docSection(t, source, "recovery_session() {", "\nprint_refresh_command() {") +
		"\n" + docSection(t, source, "main() {", "\nmain \"$@\"")
	assertNoActiveShellDispatchArm(t, "Remote Alpha operator P0v source dispatch", dispatchSections, "operator-healthcheck-tls-status-noninteractive")

	assertContainsAll(t, "Remote Alpha operator P0v PLANS boundary", plans,
		"The P0v design/static-test prep slice may define, but must not implement",
		"operator-healthcheck-tls-status-noninteractive --ssh-target <target> --format json",
		"`.docs/remote_alpha_operator_healthcheck_noninteractive_status.md`",
		"not renewal",
		"not a signing-topology decision",
		"not a profile mutation path",
		"not a Maintenance Agent scheduling change",
		"must not run live SSH, scp, BatchMode probes",
		"no-prompt SSH semantics",
		"avoid remote helper staging",
		"avoid remote summary mutation",
		"No fallback emitters are allowed for P0v.",
		"ES machine-readable route JSON is promised only after declared route prerequisites pass.",
		"Missing local runtime/validator dependencies are caller/integration preflight failures, not ES route-output obligations.",
		"must not split one schema contract across a primary runtime plus shell fallback JSON assembly",
		"the script still has no active dispatch arm for `operator-healthcheck-tls-status-noninteractive`",
		"execution-substrate.remote-alpha.operator-healthcheck-tls-status-noninteractive.v1",
		"must not carry raw stdout, raw stderr, helper or SSH transcripts",
		"supports_noninteractive=true",
		"scheduled_execution_allowed=true",
		"current MA scheduled/background execution remains disallowed",
		"`operator-healthcheck-tls-renew` remains blocked/status-only with `unsupported_signing_topology`",
		"Bridge/MA/CP/IM consumers must not wrap missing ES prerequisites into ES status truth.",
	)

	assertContainsAll(t, "Remote Alpha operator P0v design", design,
		"Remote Alpha Operator Healthcheck TLS Noninteractive Status Design",
		"`Design/static-test prep only`: this document proposes a future noninteractive route contract.",
		"scripts/remote_alpha_operator.sh recovery-session operator-healthcheck-tls-status --ssh-target <target> --interactive-tty",
		"`operator-healthcheck-tls-status-noninteractive`",
		"scripts/remote_alpha_operator.sh recovery-session operator-healthcheck-tls-status-noninteractive --ssh-target <target> --format json",
		"`--format json`",
		"`No fallback emitters`: ES machine-readable route JSON is promised only after declared route prerequisites pass.",
		"Missing local runtime/validator dependencies are caller/integration preflight failures, not ES route-output obligations.",
		"Local runtime/validator availability, or a dedicated checked-in runtime/validator available to the route implementation.",
		"Schema and redaction checks available before the route promises ES-owned machine-readable output.",
		"Caller/integration preflight may record separately owned local evidence and stop before invoking the ES route.",
		"must not split one schema contract across a primary runtime plus shell fallback JSON assembly",
		"Not require local stdin or stdout to be a TTY.",
		"Not allocate a pseudo-TTY.",
		"Not invoke SSH in a mode that prompts for passwords.",
		"Use no-prompt SSH semantics",
		"Not call sudo in a way that prompts interactively.",
		"Fail closed if required auth material is not already noninteractive-ready.",
		"Not stage helper files to a remote scratch directory.",
		"Not write the current remote summary file as the only evidence channel.",
		"Not mutate remote files, services, certs, keys, profiles, trust bundles, env files, state stores, support bundles, retained bundles, or proof artifacts.",
		"JSON only for the route contract after prerequisites pass.",
		"Missing local runtime/validator prerequisites remain caller/integration preflight blockers outside this ES schema.",
		"`0`: bounded JSON emitted, `status_available=true`, and no status blocker.",
		"`1`: bounded JSON emitted after route prerequisites passed, but status is blocked, unavailable, redaction failed, remote contact failed, helper failed, or a fail-closed condition was reached.",
		"`2`: usage, local preflight, policy/refusal, forbidden argument, or invalid route metadata.",
		"`facade_usage_failed`",
		"`remote_auth_not_ready`",
		"`noninteractive_auth_required`",
		"`ssh_batch_mode_failed`",
		"`remote_status_unavailable`",
		"`cert_metadata_expired`",
		"`trust_chain_unavailable`",
		"`identity_mismatch`",
		"`helper_usage_failed`",
		"`unsupported_signing_topology`",
		"`unknown_helper_failure`",
		"execution-substrate.remote-alpha.operator-healthcheck-tls-status-noninteractive.v1",
		"`live_contact_attempted`",
		"`status_available`",
		"`failure_class`",
		"`helper_exit_code`",
		"`not_before`",
		"`not_after`",
		`"expired": null`,
		`"safe_identity_label": null`,
		"`trust_chain`",
		"`redaction`",
		"`non_authority_labels`",
		"`owning_repo_contract_labels`",
		"`profile_lineage_hints`",
		"`scheduled_execution_allowed=true` is part of the proposed target contract, not current executable metadata.",
		"raw stdout/stderr, helper transcript, SSH transcript, PEM body, raw cert body, env value, raw log, or unsafe path",
		"endpoint secrets, cert bodies, PEM, env values, SPIFFE/Vault material, raw logs, raw helper transcripts, raw SSH transcripts, raw payloads, connector IDs, workspace IDs, org IDs, or unsafe local paths",
		"`diagnose-remote-profile` may consume this route output only as diagnostic evidence",
		"IM may consume this route output for readiness/profile/provenance reporting only after IM documents that consumption.",
		"MA may schedule or run this route only after ES implements and audits it",
		"Bridge may record ChatGPT/Codex coordination evidence or project already-safe evidence only.",
		"Bridge-owned preflight evidence for missing ES prerequisites must use a Bridge-owned schema, not this ES route schema.",
		"Preserve the existing interactive `operator-healthcheck-tls-status` route for foreground operator use.",
		"Preserve the existing blocked `operator-healthcheck-tls-renew` route and `unsupported_signing_topology` classification.",
		"Tests proving no fallback JSON emitter exists",
		"A fallback JSON emitter would be needed to preserve schema-shaped output.",
	)
	assertContainsAll(t, "Remote Alpha operator P0v redaction/output failure classes", authPosture,
		"Failure classes are stable strings in bounded JSON evidence only after route prerequisites pass.",
		"Missing local runtime/validator prerequisites are caller/integration preflight blockers and are not represented by ES fallback JSON.",
		"Failure classes do not authorize retries, mutation, renewal, profile acceptance, or run-control.",
		"Missing redaction/runtime dependencies before route execution are preflight blockers, not fallback JSON.",
		"`redaction_unavailable`: after the route runtime is available, the route cannot prove bounded output/redaction for collected status evidence.",
		"`unexpected_output_shape`: helper output is not valid bounded JSON or does not match the schema.",
		"`forbidden_output_material`: output contains or may contain forbidden secret/raw material.",
	)
	assertContainsNone(t, "Remote Alpha operator P0v redaction/output failure class overclaims", authPosture,
		"renewal success",
		"renewal succeeded",
		"runtime authority",
		"proof authority",
	)
	assertContainsNone(t, "Remote Alpha operator P0v design overclaims", design,
		"implement the route now",
		"production readiness is proved",
		"CP proof is run",
		"IM reconciliation succeeds",
		"local safe failure JSON emitted",
	)

	assertContainsAll(t, "Remote Alpha operator P0v remote docs", p0vSection,
		"`Bounded slice rule`: P0v is design/static-test prep only",
		"operator-healthcheck-tls-status-noninteractive --ssh-target <target> --format json",
		"`.docs/remote_alpha_operator_healthcheck_noninteractive_status.md`",
		"chooses a new route id",
		"does not implement the new route and does not change MA route metadata",
		"no local stdin/stdout TTY requirement",
		"no pseudo-TTY creation",
		"no prompt-capable SSH or sudo path",
		"fail-closed behavior when noninteractive auth is not already ready",
		"declared local runtime/validator availability or a dedicated checked-in runtime/validator before ES-owned JSON is promised",
		"schema and redaction checks available before ES-owned JSON is promised",
		"no password storage or replay",
		"no remote helper staging and no remote summary mutation",
		"No fallback emitters are allowed.",
		"ES machine-readable route JSON is promised only after declared route prerequisites pass.",
		"Missing local runtime/validator dependencies are caller/integration preflight failures, not ES route-output obligations.",
		"must not split one schema contract across a primary runtime plus shell fallback JSON assembly",
		"The script still has no active dispatch arm for `operator-healthcheck-tls-status-noninteractive`",
		"`execution-substrate.remote-alpha.operator-healthcheck-tls-status-noninteractive.v1`",
		"no raw stdout/stderr transcripts, helper transcripts, SSH transcripts, PEM bodies",
		"`facade_usage_failed`",
		"`remote_auth_not_ready`",
		"`noninteractive_auth_required`",
		"`ssh_batch_mode_failed`",
		"`remote_status_unavailable`",
		"`cert_metadata_expired`",
		"`trust_chain_unavailable`",
		"`identity_mismatch`",
		"`helper_usage_failed`",
		"`unsupported_signing_topology`",
		"`unknown_helper_failure`",
		"CP may later consume it only as remote-profile diagnostic evidence",
		"IM may later consume it only for readiness/profile/provenance evidence",
		"MA may run it only after ES implements and audits the route",
		"`supports_noninteractive=true`",
		"`scheduled_execution_allowed=true`",
		"Bridge remains an evidence/projection adapter only.",
		"Bridge/MA/CP/IM must not wrap missing ES prerequisites into ES status truth.",
		"MA scheduled eligibility remains false until the later ES and MA tranches land.",
		"CP diagnose rerun and IM profile-lineage refresh remain future owning-repo tranches.",
		"Stop conditions for P0v:",
		"the route would require a local TTY, pseudo-TTY, SSH prompt, sudo prompt, or password storage/replay",
		"the route would need fallback JSON assembly because local runtime/validator, schema, or redaction prerequisites are unavailable",
		"bounded JSON redaction cannot be guaranteed",
		"the route would be treated as renewal, CP run-control truth, ES runtime truth, IM authority, MA authority, Bridge authority, production readiness, live proof, or infrastructure reconciliation truth",
	)
	assertContainsNone(t, "Remote Alpha operator P0v remote docs overclaims", p0vSection,
		"implementation complete",
		"production readiness is proved",
		"CP proof is run",
		"IM reconciliation succeeds",
		"local safe failure JSON emitted",
	)
}

func TestRemoteAlphaOperatorHealthcheckTLSDocsOperatorAuthorizedReplacementDesign(t *testing.T) {
	plans := compactText(mustRead(t, "PLANS.md"))
	remoteRaw := mustRead(t, ".docs/system_overview/remote_supported_host_alpha.md")
	replacementRaw := mustRead(t, ".docs/remote_alpha_operator_healthcheck_tls_operator_authorized_replacement.md")
	replacement := compactText(replacementRaw)
	phases := compactDocSection(t, replacementRaw, "## 7. Operator-Authorized Replacement Phases", "## 8. Post-Checks")
	stopConditions := compactDocSection(t, replacementRaw, "## 14. Stop Conditions", "## 15. Validation Plan")

	assertContainsAll(t, "operator healthcheck replacement PLANS boundary", plans,
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
		"does not implement renewal, replacement, noninteractive status, CP diagnose, IM profile-lineage refresh",
		"route eligibility widening",
		"preserves `operator-healthcheck-tls-renew` as blocked with `unsupported_signing_topology`",
	)

	assertContainsAll(t, "operator healthcheck replacement design", replacement,
		"Remote Alpha Operator-Authorized Operator-Healthcheck TLS Replacement Design",
		"`Design/static-test prep only`",
		"`operator-healthcheck-tls-renew` remains blocked with `unsupported_signing_topology`",
		"`operator-healthcheck-tls-status` route is the only implemented operator-healthcheck TLS status route",
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
	plans := compactText(mustRead(t, "PLANS.md"))
	remoteRaw := mustRead(t, ".docs/system_overview/remote_supported_host_alpha.md")
	replacement := compactText(mustRead(t, ".docs/remote_alpha_operator_healthcheck_tls_operator_authorized_replacement.md"))
	signingRaw := mustRead(t, ".docs/remote_alpha_operator_healthcheck_tls_signing_custody.md")
	signing := compactText(signingRaw)
	stopConditions := compactDocSection(t, signingRaw, "## 10. Stop Conditions", "## 11. Static-Test Expectations")
	staticExpectations := compactDocSection(t, signingRaw, "## 11. Static-Test Expectations", "")
	source := mustRead(t, remoteAlphaOperatorScriptPath())
	dispatchSections := docSection(t, source, "recovery_session() {", "\nprint_refresh_command() {") +
		"\n" + docSection(t, source, "main() {", "\nmain \"$@\"")
	assertNoActiveShellDispatchArm(t, "Remote Alpha operator P0v source dispatch", dispatchSections, "operator-healthcheck-tls-status-noninteractive")

	assertContainsAll(t, "operator healthcheck signing custody PLANS boundary", plans,
		"`.docs/remote_alpha_operator_healthcheck_tls_signing_custody.md`",
		"blocked/status-only with `unsupported_signing_topology`",
		"signing authority, signer custody, key custody, CSR/cert flow, backup/rollback evidence, redaction, and post-check semantics remain ES unresolved stop conditions",
	)

	assertContainsAll(t, "operator healthcheck signing custody remote overview", compactText(remoteRaw),
		"with signing/custody hardening in `.docs/remote_alpha_operator_healthcheck_tls_signing_custody.md`",
		"does not implement renewal, replacement, noninteractive status, CP diagnose, IM profile-lineage refresh",
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
		"Therefore no replacement may proceed today.",
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
		"P0v noninteractive status remains unimplemented and no fallback emitter is introduced",
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
	plans := compactText(mustRead(t, "PLANS.md"))
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

	assertNoActiveShellDispatchArm(t, "Remote Alpha operator noninteractive status remains unimplemented", dispatchSections, "operator-healthcheck-tls-status-noninteractive")
	assertNoActiveShellDispatchArm(t, "Remote Alpha operator replacement route remains unimplemented", dispatchSections, "operator-healthcheck-tls-replace")
	assertNoActiveShellDispatchArm(t, "Remote Alpha operator replacement route remains unimplemented", dispatchSections, "operator-healthcheck-tls-replacement")

	assertContainsAll(t, "operator healthcheck resolution PLANS boundary", plans,
		"operator-authorized operator-healthcheck TLS replacement design tranche is also docs/static-test only",
		"signing authority, signer custody, key custody, CSR/cert flow, backup/rollback evidence, redaction, and post-check semantics remain ES unresolved stop conditions",
		"`operator-healthcheck-tls-renew` remains blocked/status-only with `unsupported_signing_topology`",
	)

	assertContainsAll(t, "operator healthcheck resolution overview link", remoteOverview,
		"resolution criteria in `.docs/remote_alpha_operator_healthcheck_tls_signing_custody_resolution.md`",
		"It is docs/static-test only and does not implement renewal, replacement, noninteractive status, CP diagnose, IM profile-lineage refresh",
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
		"`operator-healthcheck-tls-status` route remains the only implemented operator-healthcheck TLS status route",
		"`Reopened redesign seam`: signer authority, signer custody, key custody, key reuse, key rotation, and CSR/cert material flow remain unresolved",
		"Current resolution verdict: blocked.",
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
		"replacement remains blocked",
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
		"Before any noninteractive status route can be consumed by MA",
		"ES must implement and audit the route in a later tranche",
		"MA must update its own route metadata/docs/tests before consumption",
		"Before auto-renew eligibility can be discussed",
		"a noninteractive renewal route must be separately documented, implemented, audited, and tested",
		"`operator-healthcheck-tls-renew`: blocked/status-only with `unsupported_signing_topology`",
		"`operator-healthcheck-tls-status-noninteractive`: proposed only, not implemented, not MA-consumable",
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
	plans := compactText(mustRead(t, "PLANS.md"))
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

	assertNoActiveShellDispatchArm(t, "Remote Alpha operator decision keeps noninteractive status unimplemented", dispatchSections, "operator-healthcheck-tls-status-noninteractive")
	assertNoActiveShellDispatchArm(t, "Remote Alpha operator decision keeps replacement unimplemented", dispatchSections, "operator-healthcheck-tls-replace")
	assertNoActiveShellDispatchArm(t, "Remote Alpha operator decision keeps replacement unimplemented", dispatchSections, "operator-healthcheck-tls-replacement")

	assertContainsAll(t, "operator healthcheck signing custody decision PLANS boundary", plans,
		"operator-authorized operator-healthcheck TLS replacement design tranche is also docs/static-test only",
		"`operator-healthcheck-tls-renew` remains blocked/status-only with `unsupported_signing_topology`",
		"signing authority, signer custody, key custody, CSR/cert flow, backup/rollback evidence, redaction, and post-check semantics remain ES unresolved stop conditions",
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
		"Decision status: blocked.",
		"What signer authority and private-key custody model may be used for operator-healthcheck client TLS replacement?",
		"`Design/static-test prep only`: this record does not execute replacement",
		"`operator-healthcheck-tls-renew` remains blocked with `unsupported_signing_topology`",
		"`operator-healthcheck-tls-status` route remains the only implemented operator-healthcheck TLS status route",
		"`Reopened redesign seam`: signer authority, signer custody, key custody, key reuse, key rotation, and CSR/cert material flow remain unresolved",
		"No option is selected.",
		"Replacement remains blocked.",
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
		"`.docs/remote_alpha_operator_healthcheck_noninteractive_status.md` records P0v as a no-fallback, design/static-only status-route proposal",
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
		"P0v remains design/static only and no fallback emitter is introduced",
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

func TestRemoteAlphaMaintenanceMonitorBoundaryAndRouteMatrix(t *testing.T) {
	plans := compactText(mustRead(t, "PLANS.md"))
	remoteRaw := mustRead(t, ".docs/system_overview/remote_supported_host_alpha.md")
	monitorSection := compactDocSection(t, remoteRaw, "### Remote Alpha Maintenance Monitor Boundary", "### P0d Interactive Validation Evidence")
	monitor := compactText(monitorSection)
	artifact := compactText(mustRead(t, ".docs/system_overview/artifact_hygiene.md"))

	assertContainsAll(t, "Remote Alpha maintenance monitor PLANS boundary", plans,
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
		"`es-service-tls-status` | eligible",
		"`es-service-tls-renew` | status summary may be monitored | eligible through the documented ES helper only | candidate after audit gates",
		"`es-governance-tls-status` | eligible",
		"`es-governance-tls-renew` | status summary may be monitored | eligible through the documented ES helper only | candidate after audit gates",
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

func TestDocsRemoteAlphaOperatorP0cFirstDelegationBoundary(t *testing.T) {
	plans := compactText(mustRead(t, "PLANS.md"))
	remoteRaw := mustRead(t, ".docs/system_overview/remote_supported_host_alpha.md")
	operatorSection := compactDocSection(t, remoteRaw, "### P0c First Staged-Helper Delegation Plan", "## Direct Remote Requirements")

	assertContainsAll(t, "Remote Alpha operator P0c PLANS boundary", plans,
		"The P0c design/static-test prep slice is also docs/static-test only.",
		"The selected first future delegation target is the existing ES writable-state readiness staged wrapper",
		"`scripts/remote_alpha_stage_es_writable_state_readiness_check.sh`",
		"proposed operator subcommand `es-writable-state-readiness-check`",
		"`--apply` is forbidden in the first delegation slice",
		"no reset/unseal, Vault workload-auth, runtime-identity, service-user migration, config/TLS apply, binary deployment apply, generic remote staging, arbitrary shell passthrough, or new aggregate operator summary is allowed",
		"`es-writable-state-readiness.json`",
		"`es-writable-state-readiness-helper-staging-record.json`",
		"noninteractive `sudo -n` preflight by default",
		"it must not call IM",
	)

	assertContainsAll(t, "Remote Alpha operator P0c docs boundary", operatorSection,
		"`Bounded slice rule`: P0c is design/static-test prep only.",
		"does not implement helper delegation",
		"proposed operator subcommand: `es-writable-state-readiness-check`",
		"exact helper to delegate later:",
		"`scripts/remote_alpha_stage_es_writable_state_readiness_check.sh`",
		"`scripts/internal/remote_alpha_stage_es_writable_state_readiness_check.sh`",
		"The later route may pass only these helper flags:",
		"`--ssh-target <user@host>`",
		"`--mode <alpha-compat|future-non-root-required>`",
		"`--run-id <timestamp-or-id>`",
		"`--output-dir </path/to/output-dir>`",
		"`--readiness-output </path/to/es-writable-state-readiness.json>`",
		"`--helper-staging-record-output </path/to/es-writable-state-readiness-helper-staging-record.json>`",
		"`--provenance-output </path/to/es-writable-state-readiness-helper-staging-record.json>`",
		"`--interactive-sudo`",
		"`--keep-staging-on-failure`",
		"The later route must forbid:",
		"`--apply`",
		"arbitrary shell or command strings",
		"secret-like CLI arguments, environment values, logs, reports, summaries, or artifacts",
		"any new aggregate operator summary in the first delegation slice",
		"The first delegation slice must stay check-only/non-mutating.",
		"the operator facade itself must not introduce a generic remote staging framework",
		"Default sudo behavior must remain the helper's noninteractive `sudo -n` preflight",
		"must preserve the exact existing Infrastructure Manager-consumed local artifact filenames",
		"must not call Infrastructure Manager",
		"the facade may continue to print the Mac-side IM refresh and support-bundle commands only",
		"the route allows only the flags listed above and rejects `--apply`, unknown flags, arbitrary command strings, and secret-like arguments before routing",
		"writes no aggregate operator summary and does not call Infrastructure Manager",
		"This target is safer than the other staged candidates because it has no `--apply` mode",
		"The config/TLS staged wrapper is already called out above as a sudo-model gap unless fixed",
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
	remote := compactText(mustRead(t, ".docs/system_overview/remote_supported_host_alpha.md"))
	configuration := compactText(mustRead(t, ".docs/system_overview/configuration.md"))

	for _, required := range []string{
		"`AGS sealed + ARS de-root + EGS de-root + ES config/TLS prep applied + ES stable writable-state prep applied + long-lived es.service de-root applied`",
		"AGS is already de-rooted and sealed",
		"ARS is already de-rooted",
		"EGS is already de-rooted",
		"The current live long-lived `es.service` now runs as `User=es`, `Group=es`, `UMask=0027`",
		"does not claim full ES/runtime de-root",
		"must not change ES public contracts",
		"Old root-era staging/results roots remain preserved as rollback/debug/evidence state",
	} {
		if !strings.Contains(plans, required) && !strings.Contains(remote, required) && !strings.Contains(configuration, required) {
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
		if !strings.Contains(plans, required) && !strings.Contains(remote, required) && !strings.Contains(configuration, required) {
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

func TestRemoteSupportedHostAlphaESWritableStateReadinessOperatorFlowIsDocumented(t *testing.T) {
	remote := compactText(mustRead(t, ".docs/system_overview/remote_supported_host_alpha.md"))
	ownership := compactText(mustRead(t, ".docs/system_overview/remote_alpha_beta_es_writable_state_ownership.md"))
	normalization := compactText(mustRead(t, ".docs/system_overview/remote_alpha_beta_es_runtime_ownership_normalization.md"))

	for _, required := range []string{
		"Remote ES Writable-State Readiness Evidence Flow",
		"`scripts/remote_alpha_stage_es_writable_state_readiness_check.sh`",
		"`scripts/remote_alpha_check_es_writable_state_readiness.sh`",
		"`scripts/internal/remote_alpha_check_es_writable_state_readiness.sh`",
		"`/var/tmp/execution-substrate-remote-alpha/helper-staging/<run-id>/scripts/remote_alpha_check_es_writable_state_readiness.sh`",
		"The remote host does not need a full Execution Substrate repo checkout for this evidence flow.",
		"At minimum, the operator must stage only:",
		"Execution must run from that root-owned staged tree, not from a user-writable upload path.",
		"transient helper staging from the operator repo into a root-owned staging tree under `/var/tmp/execution-substrate-remote-alpha/helper-staging/`",
		"The wrapper must default to `--mode alpha-compat`.",
		"Operators must request explicit `--mode future-non-root-required` when they want a non-mutating future-readiness gate.",
		"Those blocker findings were expected before the now-applied long-lived service-user migration",
		"`es-writable-state-readiness.json`",
		"`es-writable-state-readiness-helper-staging-record.json`",
		"the requested checker mode",
		"the sudo mode used for staged execution",
		"whether staging occurred",
		"whether the checker ran",
		"whether transient staging was removed",
		"whether `sudo_unavailable` blocked noninteractive root-owned staging",
		"whether `wrapper_tooling_error` blocked execution before checker evidence was accepted",
		"any sudo or preflight blocker if staging could not proceed",
		"The default wrapper path must perform a noninteractive `sudo -n` preflight and fail cleanly with structured `sudo_unavailable` evidence",
		"An explicit `--interactive-sudo` mode may be used only from a visible terminal when a bounded password handoff is authorized.",
		"must not rely on a forced-PTY heredoc path",
		"`overall_classification=blocker` is still valid measurement evidence",
		"Collection must fail closed only when the staged helper tree is not root-owned, staged files are group-writable or world-writable, checker output is malformed, checker output claims mutation, or checker output does not match the requested mode.",
		"`--keep-staging-on-failure` may retain it for diagnostics.",
		"Do not run governed proof as part of this staged operator flow.",
		"This operator-staged flow is readiness evidence only. It is not proof. It is not approval to de-root ES.",
		"That wrapper is non-mutating except for temporary checker staging.",
		"Valid `overall_classification=blocker` output from `--mode future-non-root-required` must still be preserved as honest measurement evidence",
	} {
		if !strings.Contains(remote, required) && !strings.Contains(ownership, required) && !strings.Contains(normalization, required) {
			t.Fatalf("remote ES writable-state readiness operator docs missing %q", required)
		}
	}
}

func TestRemoteSupportedHostAlphaESServiceUserMigrationOperatorFlowIsDocumented(t *testing.T) {
	remote := compactText(mustRead(t, ".docs/system_overview/remote_supported_host_alpha.md"))
	configuration := compactText(mustRead(t, ".docs/system_overview/configuration.md"))

	for _, required := range []string{
		"Remote ES Service-User Migration Surface",
		"`scripts/remote_alpha_migrate_es_service_user.sh`",
		"`scripts/internal/remote_alpha_migrate_es_service_user.sh`",
		"`<upload-root>/scripts/remote_alpha_migrate_es_service_user.sh`",
		"`<upload-root>/scripts/internal/remote_alpha_migrate_es_service_user.sh`",
		"`<upload-root>/scripts/remote_alpha_check_es_writable_state_readiness.sh`",
		"`<upload-root>/scripts/internal/remote_alpha_check_es_writable_state_readiness.sh`",
		"`es-service-user-migration-check-only.json`",
		"`es-service-user-migration-helper-staging-record.json`",
		"`es-service-user-migration-apply-summary.json`",
		"`es-service-user-migration-apply-stdout.txt`",
		"The current live bounded state after that later helper apply is now:",
		"the long-lived `es.service` runs as `User=es`, `Group=es`, `UMask=0027`",
		"future writable-state readiness passed",
		"old root-era staging/results roots remain preserved as rollback/debug/evidence state",
		"The default staged-wrapper path must perform a noninteractive `sudo -n` preflight and fail cleanly with structured `sudo_unavailable` evidence",
		"`--interactive-sudo` may be used only from a visible terminal when a bounded password handoff is explicitly authorized",
		"must still use bounded remote commands rather than a forced-PTY heredoc path",
		"The helper staging record must distinguish `sudo_unavailable` from `wrapper_tooling_error`",
		"record whether staging occurred, whether the check-only helper ran, and whether transient staging was removed",
	} {
		if !strings.Contains(remote, required) && !strings.Contains(configuration, required) {
			t.Fatalf("remote ES service-user migration docs missing %q", required)
		}
	}
}

func TestRemoteSupportedHostAlphaESServiceUserRollbackRehearsalIsDocumented(t *testing.T) {
	remote := compactText(mustRead(t, ".docs/system_overview/remote_supported_host_alpha.md"))
	configuration := compactText(mustRead(t, ".docs/system_overview/configuration.md"))

	for _, required := range []string{
		"`scripts/remote_alpha_es_service_user_rollback_rehearsal.sh`",
		"`.out/remote-alpha-m75q`",
		"`es-service-user-rollback-rehearsal.json`",
		"`es-service-user-rollback-rehearsal.md`",
		"It must not SSH, use `sudo`, mutate the live host, execute rollback, run ES apply, run governed proof, or do PR/merge prep.",
		"classify findings as `pass`, `warning`, or `blocker`",
		"the bounded drop-in remains limited to `User=es`, `Group=es`, and `UMask=0027`",
		"no recorded rollback instruction requires recursive chown or broad deletion",
	} {
		if !strings.Contains(remote, required) && !strings.Contains(configuration, required) {
			t.Fatalf("remote ES service-user rollback rehearsal docs missing %q", required)
		}
	}
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

func TestRemoteSupportedHostAlphaESWritableStateOwnershipOperatorFlowIsDocumented(t *testing.T) {
	remote := compactText(mustRead(t, ".docs/system_overview/remote_supported_host_alpha.md"))
	configuration := compactText(mustRead(t, ".docs/system_overview/configuration.md"))

	for _, required := range []string{
		"Remote ES Writable-State Ownership Surface",
		"`scripts/remote_alpha_prepare_es_writable_state_ownership.sh`",
		"`scripts/internal/remote_alpha_prepare_es_writable_state_ownership.sh`",
		"`<upload-root>/scripts/remote_alpha_prepare_es_writable_state_ownership.sh`",
		"`<upload-root>/scripts/internal/remote_alpha_prepare_es_writable_state_ownership.sh`",
		"`es-writable-state-ownership-check-only.json`",
		"`es-writable-state-ownership-helper-staging-record.json`",
		"`es-writable-state-ownership-apply-summary.json`",
		"target owner `es:es` mode `0750` for both stable roots",
		"block by default when either stable root is non-empty",
		"must not recursively re-owner retained run/debug trees",
		"must not restart `es.service`",
		"The default staged-wrapper path must perform a noninteractive `sudo -n` preflight and fail cleanly with structured `sudo_unavailable` evidence",
		"An explicit `--interactive-sudo` mode may be used only from a visible terminal when a bounded password handoff is authorized.",
	} {
		if !strings.Contains(remote, required) && !strings.Contains(configuration, required) {
			t.Fatalf("remote ES writable-state ownership docs missing %q", required)
		}
	}
}
