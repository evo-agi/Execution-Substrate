package executionsubstrate_test

import (
	"os"
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

func TestSystemOverviewAuthorityHeadersFollowRepoHierarchy(t *testing.T) {
	for _, doc := range []struct {
		label string
		path  string
	}{
		{label: "system contracts doc", path: ".docs/system_overview/contracts.md"},
		{label: "system boundaries doc", path: ".docs/system_overview/boundaries.md"},
	} {
		text := mustRead(t, doc.path)
		assertDocIncludesAuthorityHierarchy(t, text, doc.label)
		if !strings.Contains(text, "Authority for this document follows the repo-wide authority hierarchy:") {
			t.Fatalf("%s missing repo-wide authority preface", doc.label)
		}
	}
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
	} {
		if !strings.Contains(sharedKernel, required) {
			t.Fatalf("shared-kernel decision doc missing %q", required)
		}
	}

	for _, required := range []string{
		"The Workstream A shared-kernel decision is recorded in `.docs/system_overview/shared_kernel.md`.",
		"`internal/contracts/evidence/v1` remains the only active shared artifact evidence kernel for the current `AGS -> ARS -> ES` path, but it is not a standalone service boundary.",
		"Kernel-level shared meaning stays limited to package identity, narrow derivation request-binding authorization, narrow execution/runtime claims ES actually enforces, and evidence canonicalization plus `seal` verification.",
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
		"Runtime auth-plan shaping",
		"Credential material, Vault token material, or JWT-SVID material",
		"declared complete production policy grammar or final policy architecture",
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
		"this decision does not settle Workstream E runtime-config ownership or Workstream F runtime-identity handoff ownership.",
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
		"The current `GET /v1/executions/{run_id}/result` route, public `run_id` lookup, and retained `application/gzip` bundle retrieval shape are active compatibility edges for the bounded retained-result slice, not a broad output platform.",
	)

	assertContainsAll(t, "execution lifecycle retained-result ownership section", resultRuntimeOutput,
		"ES packages retained result content opaquely and does not parse Control Plane semantics, checkpoint decisions, review outcomes, or finalization metadata from those files.",
	)
	assertContainsAll(t, "execution lifecycle retained-result lookup section", resultLookup,
		"The current route shape, public `run_id` lookup, `application/gzip` encoding, and successful outcome-evidence headers are the active bounded compatibility retrieval path for those ES-owned bundles.",
	)
	assertContainsAll(t, "execution lifecycle design retained-result materialization", designTerminalResult,
		"ES treats the directory contents as opaque output material",
	)
	assertContainsAll(t, "execution lifecycle design retained-result bounded-slice rule", designBoundedSliceRules,
		"The current `GET /v1/executions/{run_id}/result` route, public `run_id` lookup, and opaque tar.gz bundle encoding remain the bounded compatibility retrieval path for that retained bundle surface.",
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
		"| Runtime-profile selection | `temporary compatibility edge` | `invocation.annotations[\"execution_substrate.runtime_profile\"]` plus `control-plane-normal-shell/v1` remains the current opt-in `static-script` runtime overlay. Unsupported or disabled selection fails `:prepare`/`:submit`. |",
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
		"`auth_smoke.vault_login`",
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
