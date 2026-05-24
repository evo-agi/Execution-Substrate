package executionsubstrate_test

import (
	"os"
	"path/filepath"
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
		"Current implementation/design status through P0q:",
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
		"stages only `scripts/remote_alpha_vault_workload_auth_bootstrap.sh` and `scripts/internal/remote_alpha_vault_workload_auth_bootstrap.sh`",
		"uses an in-process Vault API client rather than `VAULT_TOKEN` or `vault login`",
		"writes only the remote non-secret summary at `/var/tmp/execution-substrate-remote-alpha/vault-workload-auth-bootstrap-summary.json`",
		"copies no summary back to Mac `.out`",
		"keeps workload-auth checks, reset/unseal, IM refresh, support bundles, CP proof, and runtime identity work separate",
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
		"Remote-host only: P0i `recovery-session vault-unseal-existing --host-local`, runtime identity summary and Vault service-user check.",
		"P0m does not add a host-local execute-reset route through the operator facade",
		"Not v1 except the P0j unseal-existing route, the P0k reset dry-run planning route, the P0m explicit execute-reset operator route, the P0n workload-auth evidence route, the P0o safe bootstrap planning surface, and the P0q workload-auth bootstrap execution route",
		"post-unseal/runtime identity/service-user/IM/support-bundle/CP-proof bundling",
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
		"JWT auth config with SPIRE JWT validation material and bound issuer",
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
		"JWT auth config with SPIRE JWT validation material and bound issuer",
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
		"JWT auth config with SPIRE validation material and bound issuer",
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
		"JWT auth config with SPIRE validation material and bound issuer",
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
	operatorSection := compactDocSection(t, remoteRaw, "### P0q Vault Workload-Auth Bootstrap Execution Route", "### P0d Interactive Validation Evidence")

	assertContainsAll(t, "Remote Alpha operator P0q PLANS boundary", plans,
		"The P0q implementation/self-audit/merge-readiness slice may implement exactly one dedicated secret-sensitive workload-auth bootstrap helper and exactly one Mac-side recovery-session route",
		"`scripts/remote_alpha_operator.sh recovery-session vault-workload-auth-bootstrap --ssh-target <target> --execute-bootstrap --interactive-tty`",
		"`scripts/remote_alpha_vault_workload_auth_bootstrap.sh`",
		"`scripts/internal/remote_alpha_vault_workload_auth_bootstrap.sh`",
		"must not run live bootstrap, live SSH, sudo, Vault, workload-auth checks, reset/unseal, Infrastructure Manager refresh, support-bundle collection, CP proof, runtime identity generation",
		"visible/silent remote helper TTY prompt only",
		"must not use `VAULT_TOKEN`",
		"`vault login`",
		"in-process Vault API client",
		"auth mount `jwt`",
		"JWT auth config with SPIRE validation material and bound issuer",
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
		"must not copy that summary back to Mac `.out`",
		"must not claim workload-auth success",
		"The workload-auth check remains a separate post-bootstrap command.",
		"P0q validation remains fake/static only",
		"fake SSH/SCP staging of exactly the bootstrap public/internal helper pair",
		"no transcript/`tee`/`script`",
		"no copy-back to Mac `.out`",
	)

	assertContainsAll(t, "Remote Alpha operator P0q docs boundary", operatorSection,
		"`Bounded slice rule`: P0q implements the dedicated secret-sensitive workload-auth bootstrap execution route",
		"fake/static validation only",
		"Public helper:",
		"`scripts/remote_alpha_vault_workload_auth_bootstrap.sh`",
		"Internal helper:",
		"`scripts/internal/remote_alpha_vault_workload_auth_bootstrap.sh`",
		"Mac-side operator route:",
		"`scripts/remote_alpha_operator.sh recovery-session vault-workload-auth-bootstrap --ssh-target <target> --execute-bootstrap --interactive-tty`",
		"Safe modes remain:",
		"`scripts/remote_alpha_operator.sh recovery-session vault-workload-auth-bootstrap --help`",
		"Secret prompt model:",
		"The human remains the operator.",
		"ES remains a bounded Remote Alpha operator facade/workflow, not a Vault token broker.",
		"Vault owns token, secret, and lease authority.",
		"SPIRE owns JWT-SVID issuance.",
		"The helper prompts for Vault bootstrap authority and proof secret values only on the visible/silent remote TTY",
		"Vault API strategy:",
		"in-process HTTPS client",
		"must not use `VAULT_TOKEN`",
		"`vault login`",
		"Configured Vault objects/config:",
		"auth mount `jwt`",
		"JWT auth config with SPIRE validation material and bound issuer",
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
		"must not copy that summary back to Mac `.out`",
		"must not create an operator summary",
		"Allowed execution flags:",
		"`--execute-bootstrap`",
		"Forbidden execution flags and inputs include:",
		"`--root-token`",
		"`--vault-token`",
		"`--api-key`",
		"proof secret value flags",
		"P0q tests:",
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
