package admission

import (
	"bytes"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

func TestResolvedPlanSourceBoundaryIsPrivateAndPure(t *testing.T) {
	file := mustParseResolvedPlanSource(t)
	source := mustReadResolvedPlanSource(t)

	assertResolvedPlanTypesArePrivate(t, file)
	assertResolvedPlanHasNoProjectionMethods(t, file)
	assertResolvedPlanOmitsAll(t, "resolvedplan.go", source,
		"MarshalJSON",
		"MarshalText",
		"String()",
		"GoString",
		"Format(",
		"database/sql",
		"modernc.org/sqlite",
		"internal/reliablesubmit",
		"net/http",
		"http.",
		"os.",
		"ioutil",
		"ReadFile",
		"WriteFile",
		"Mkdir",
		"OpenFile",
		"nomadClient",
		"submitJob",
		"buildNomadJobSpec",
		"newExecutionLocator",
		"stageExecutionInputs",
		"stageRuntimeMounts",
		"fetchPayloadBytes",
		"fetchAdmissionPolicyPayloadBytes",
		"prepareAdmission(",
		"validatePrepareRequest(",
		"validateInvocationAgainstManifest(",
		"PlanBinding",
		"EffectivePlanWitness",
		"SHA256",
		"sha256.Sum",
		"canonical",
		"commitment",
		"job-spec digest",
	)
}

func TestResolvedPlanConstructorConsumesPreparedNormalizedFacts(t *testing.T) {
	source := mustReadResolvedPlanSource(t)
	assertResolvedPlanContainsAll(t, "resolvedplan.go", source,
		"func (s *Service) resolveCurrentSubmitExecutionPlan(prepared preparedAdmission) (resolvedExecutionPlan, *Error)",
		"req := prepared.normalizedRequest",
		"resolveExecutionRuntimeProfile(s.cfg.Execution, req, prepared.artifact)",
		"resolveTaskResources(req.Resources)",
		"resolveSubmitMountPlan(req.Invocation.Mounts)",
	)
	serviceSource := mustReadAdmissionSource(t, "service.go")
	assertResolvedPlanContainsAll(t, "service.go", serviceSource,
		"if err := validatePrepareRequest(&req); err != nil",
		"normalizedRequest:           clonePrepareRequest(req)",
	)
	assertResolvedPlanOmitsAll(t, "resolvedplan.go", source,
		"req.SchemaVersion = \"v1\"",
		"req.Invocation.SchemaVersion = \"v1\"",
	)
}

func TestSubmitConsumesResolvedPlanAfterFreeze(t *testing.T) {
	source := mustReadAdmissionSource(t, "submit.go")
	assertResolvedPlanContainsAll(t, "submit.go", source,
		"plan, planErr := s.resolveCurrentSubmitExecutionPlan(prepared)",
		"s.fetchPayloadBytes(ctx, plan.artifact.payloadDigest)",
		"s.stageRuntimeMounts(ctx, prepared.trustModel, stage.layout, plan.runtimeMounts(), platformStateOwner)",
		"stage.layout.stageWorkloadVaultTrustMaterial(plan.authority.workloadVaultPlan, platformStateOwner)",
		"buildRuntimeEnvironment(stage.layout, plan.artifact.artifactDigest, plan.authority.workloadVaultPlan, runtimeProfile, stage.trustMaterial, plan.environment.callerEnv, &platformStateOwner)",
		"plan.authority.workloadZoneVaultConfigDigest",
		"layout.runtimeSupervisorArgs(plan.command.workloadArgv, plan.command.timeoutSeconds, plan.command.supervisorOperationIdentity)",
		"\"command\":      plan.command.runtimeSupportCommandIdentity,",
		"buildNomadJobSpec(",
	)

	afterFreeze := source[strings.Index(source, "plan, planErr := s.resolveCurrentSubmitExecutionPlan(prepared)"):]
	assertResolvedPlanOmitsAll(t, "submit.go after plan freeze", afterFreeze,
		"req.Invocation.Argv",
		"req.Invocation.Env",
		"req.Invocation.Mounts",
		"req.Invocation.ArtifactDigest",
		"req.Invocation.DerivationSpecDigest",
		"req.Invocation.OutputID",
		"req.Invocation.Annotations",
		"req.Resources",
		"req.TimeoutSeconds",
		"prepared.artifact.networkAccess",
		"prepared.artifact.payloadDigest",
		"prepared.workloadVaultPlan",
		"resolveTaskResources(req.Resources)",
		"resolveExecutionRuntimeProfile(",
		"\"command\":      executionRuntimeSupportPath",
	)
}

func TestExecutionPackageConsumesPrivateSupervisorOperationInput(t *testing.T) {
	fileSet := token.NewFileSet()
	file, err := parser.ParseFile(fileSet, filepath.Join(admissionRepoRoot(t), "es/admission/executionpackage.go"), nil, parser.ParseComments)
	if err != nil {
		t.Fatalf("parse executionpackage.go: %v", err)
	}
	source := mustReadAdmissionSource(t, "executionpackage.go")
	assertResolvedPlanContainsAll(t, "executionpackage.go", source,
		"executionRuntimeSupervisorOperation = \"supervisor\"",
	)

	fn := mustFindFuncDecl(t, file, "runtimeSupervisorArgs")
	if fn.Type.Params == nil || len(fn.Type.Params.List) != 3 {
		t.Fatalf("runtimeSupervisorArgs parameter count mismatch")
	}
	supervisorParam := fn.Type.Params.List[2]
	if len(supervisorParam.Names) != 1 || supervisorParam.Names[0].Name != "supervisorOperation" {
		t.Fatalf("runtimeSupervisorArgs supervisor operation parameter mismatch")
	}
	if _, ok := supervisorParam.Type.(*ast.Ellipsis); ok {
		t.Fatalf("runtimeSupervisorArgs must not use a variadic supervisor operation")
	}
	supervisorType, ok := supervisorParam.Type.(*ast.Ident)
	if !ok || supervisorType.Name != "string" {
		t.Fatalf("runtimeSupervisorArgs supervisor operation must be a required string parameter")
	}
	body := sourceForNode(t, fileSet, fn.Body)
	assertResolvedPlanContainsAll(t, "executionpackage.go supervisor args body", body,
		"supervisorOperation,",
	)
	assertResolvedPlanOmitsAll(t, "executionpackage.go supervisor args body", body,
		"executionRuntimeSupervisorOperation",
		"len(supervisorOperation",
		"operation :=",
		"operation =",
		"\"supervisor\",",
	)
	ast.Inspect(fn.Body, func(node ast.Node) bool {
		if _, ok := node.(*ast.IfStmt); ok {
			t.Fatalf("runtimeSupervisorArgs must not contain a fallback branch")
		}
		return true
	})

	submitSource := mustReadAdmissionSource(t, "submit.go")
	if strings.Count(submitSource, "runtimeSupervisorArgs(") != 1 {
		t.Fatalf("production runtimeSupervisorArgs call count mismatch")
	}
	assertResolvedPlanContainsAll(t, "submit.go", submitSource,
		"layout.runtimeSupervisorArgs(plan.command.workloadArgv, plan.command.timeoutSeconds, plan.command.supervisorOperationIdentity)",
	)
	assertResolvedPlanOmitsAll(t, "submit.go", submitSource,
		"runtimeSupervisorArgs(plan.command.workloadArgv, plan.command.timeoutSeconds, executionRuntimeSupervisorOperation)",
	)

	for _, rel := range []string{
		"es/admission/types.go",
		"es/config/config.go",
		"es/api/server.go",
		"es/app/app.go",
	} {
		assertResolvedPlanOmitsAll(t, rel, mustReadAdmissionRepoSource(t, admissionRepoRoot(t), rel),
			"supervisor_operation",
			"SupervisorOperation",
			"RuntimeSupervisorOperation",
			"executionRuntimeSupervisorOperation",
		)
	}
}

func TestResolvedPlanStructsExcludeRunMaterializationAndRuntimeState(t *testing.T) {
	fileSet := token.NewFileSet()
	file, err := parser.ParseFile(fileSet, filepath.Join(admissionRepoRoot(t), "es/admission/resolvedplan.go"), nil, parser.ParseComments)
	if err != nil {
		t.Fatalf("parse resolvedplan.go: %v", err)
	}
	protectedTypes := resolvedPlanPrivateTypeNames()
	forbiddenFieldFragments := []string{
		"runID",
		"nomadJobID",
		"jobID",
		"evalID",
		"allocationID",
		"allocID",
		"hostPath",
		"stagePath",
		"stagingPath",
		"resultPath",
		"resultsPath",
		"runtimeIdentityEndpointURI",
		"endpointURI",
		"stagedCAPath",
		"stagedTLSPath",
		"mountExtractionPath",
		"platformUID",
		"platformGID",
		"payloadBytes",
		"policyBytes",
		"policyPayloadBytes",
		"trustModel",
		"nomadJob",
		"jobSpec",
		"timestamp",
		"createdAt",
		"updatedAt",
		"submittedAt",
	}
	for _, decl := range file.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok {
			continue
		}
		for _, spec := range gen.Specs {
			typeSpec, ok := spec.(*ast.TypeSpec)
			if !ok || !protectedTypes[typeSpec.Name.Name] {
				continue
			}
			structType, ok := typeSpec.Type.(*ast.StructType)
			if !ok {
				continue
			}
			for _, field := range structType.Fields.List {
				fieldType := sourceForNode(t, fileSet, field.Type)
				lowerFieldType := strings.ToLower(fieldType)
				if strings.Contains(lowerFieldType, "nomad") || strings.Contains(lowerFieldType, "api.job") {
					t.Fatalf("resolved plan private type %s defines a concrete scheduler field", typeSpec.Name.Name)
				}
				for _, name := range field.Names {
					lowerName := strings.ToLower(name.Name)
					for _, fragment := range forbiddenFieldFragments {
						if strings.Contains(lowerName, strings.ToLower(fragment)) {
							t.Fatalf("resolved plan private type %s defines materialization field %s", typeSpec.Name.Name, name.Name)
						}
					}
				}
			}
		}
	}
}

func TestResolvedPlanTestsDoNotProjectPrivatePlanValues(t *testing.T) {
	fileSet := token.NewFileSet()
	rel := "es/admission/resolvedplan_test.go"
	file, err := parser.ParseFile(fileSet, filepath.Join(admissionRepoRoot(t), rel), nil, parser.ParseComments)
	if err != nil {
		t.Fatalf("parse resolved plan tests: %v", err)
	}
	source := mustReadAdmissionRepoSource(t, admissionRepoRoot(t), rel)
	assertResolvedPlanOmitsAll(t, rel, source,
		"\"reflect\"",
		"reflect.",
		"allResolvedPlanStrings",
		"fmt.Sprintf",
		"fmt.Sprint",
		"json.Marshal(plan",
		"json.MarshalIndent(plan",
		"json.NewEncoder",
	)

	protectedTypes := resolvedPlanPrivateTypeNames()
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok {
			continue
		}
		if functionAcceptsAnyType(fn, protectedTypes) && functionReturnsGenericProjection(fn) {
			t.Fatalf("resolved plan tests define helper-mediated private plan projection %s", fn.Name.Name)
		}
		ast.Inspect(fn.Body, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok || !isWholePlanProjectionCall(call) {
				return true
			}
			for _, arg := range call.Args {
				expr := sourceForExpr(t, fileSet, arg)
				if strings.Contains(expr, "plan") || strings.Contains(expr, "Plan") {
					t.Fatalf("resolved plan tests project a complete plan expression in %s", fn.Name.Name)
				}
			}
			return true
		})
	}
}

func TestResolvedPlanPrivacyGuardedFilesStayBounded(t *testing.T) {
	findings := resolvedPlanPrivacyFindingsInPackage(t)
	if len(findings) > 0 {
		t.Fatalf("admission package has bounded privacy guard finding (%s)", strings.Join(findings, ", "))
	}
}

func TestResolvedPlanPrivacyGuardCoversArbitraryNewTestFunctions(t *testing.T) {
	source := `
package admission

import (
	"fmt"
	"testing"
)

type resolvedExecutionPlan struct{}

func TestPreviouslyKnownShape(t *testing.T) {
	t.Fatal("static classification")
}

func TestArbitraryNewShape(t *testing.T) {
	var plan resolvedExecutionPlan
	_ = fmt.Sprint(plan)
}
`
	if findings := resolvedPlanPrivacyFindingsInSource(t, "arbitrary-new-test", source); len(findings) == 0 {
		t.Fatalf("arbitrary Test function was not automatically guarded")
	}
}

func TestResolvedPlanProtectedHelperBoundaryRejectsSyntheticCrossings(t *testing.T) {
	for _, tc := range []struct {
		name   string
		source string
	}{
		{
			name: "direct alias",
			source: `
package admission

import (
	"fmt"
	"testing"
)

type resolvedExecutionPlan struct{}

func helper(subject resolvedExecutionPlan) { fmt.Print(subject) }

func TestSynthetic(t *testing.T) {
	var plan resolvedExecutionPlan
	p := plan
	helper(p)
}
`,
		},
		{
			name: "alias chain",
			source: `
package admission

import (
	"fmt"
	"testing"
)

type resolvedExecutionPlan struct{}

func helper(subject resolvedExecutionPlan) { fmt.Print(subject) }

func TestSynthetic(t *testing.T) {
	var plan resolvedExecutionPlan
	q := plan
	r := q
	helper(r)
}
`,
		},
		{
			name: "selector aggregate",
			source: `
package admission

import (
	"fmt"
	"testing"
)

type resolvedExecutionPlan struct {
	environment struct {
		caller map[string]string
	}
}

func helper(env map[string]string) { fmt.Print(env) }

func TestSynthetic(t *testing.T) {
	var plan resolvedExecutionPlan
	env := plan.environment.caller
	helper(env)
}
`,
		},
		{
			name: "handoff evidence",
			source: `
package admission

import (
	"fmt"
	"testing"
)

type authorityHandoff struct {
	Evidence map[string]string
}

type resolvedExecutionPlan struct {
	authority authorityHandoff
}

func helper(evidence map[string]string) { fmt.Print(evidence) }

func TestSynthetic(t *testing.T) {
	var handoff authorityHandoff
	e := handoff.Evidence
	helper(e)
}
`,
		},
		{
			name: "helper returns protected argument",
			source: `
package admission

import (
	"fmt"
	"testing"
)

type resolvedExecutionPlan struct{}

func identity(subject resolvedExecutionPlan) resolvedExecutionPlan {
	return subject
}

func TestSynthetic(t *testing.T) {
	var plan resolvedExecutionPlan
	fmt.Print(identity(plan))
}
`,
		},
	} {
		if findings := resolvedPlanPrivacyFindingsInSource(t, tc.name, tc.source); len(findings) == 0 {
			t.Fatalf("%s protected helper boundary was not rejected", tc.name)
		}
	}
}

func TestResolvedPlanProtectedHelperBoundaryPermitsSafeScalars(t *testing.T) {
	source := `
package admission

import "testing"

type resolvedExecutionPlan struct {
	mounts    []string
	authority struct {
		applicable bool
	}
}

func helperCount(count int) {}
func helperBool(ok bool) {}
func helperLabel(label string) {}
func helperIndex(index int) {}

func TestSynthetic(t *testing.T) {
	var plan resolvedExecutionPlan
	helperCount(len(plan.mounts))
	helperBool(plan.authority.applicable == true)
	helperLabel("mounts")
	helperIndex(1)
}
`
	if findings := resolvedPlanPrivacyFindingsInSource(t, "safe-scalar-helper-crossing", source); len(findings) != 0 {
		t.Fatalf("safe scalar helper crossing was rejected")
	}
}

func TestResolvedPlanDiagnosticHelpersStayFixedAndBounded(t *testing.T) {
	for _, tc := range []struct {
		name   string
		source string
	}{
		{
			name: "variadic helper",
			source: `
package admission

import "testing"

type resolvedExecutionPlan struct {
	labels []string
}

func helper(t *testing.T, values ...string) { t.Fatal(values) }

func TestSynthetic(t *testing.T) {
	var plan resolvedExecutionPlan
	helper(t, plan.labels...)
}
`,
		},
		{
			name: "helper prints dynamic string parameter",
			source: `
package admission

import "testing"

type resolvedExecutionPlan struct {
	label string
}

func helper(t *testing.T, value string) {
	t.Fatalf("value %s", value)
}

func TestSynthetic(t *testing.T) {
	var plan resolvedExecutionPlan
	helper(t, plan.label)
}
`,
		},
		{
			name: "protected diagnostic string argument",
			source: `
package admission

import "testing"

type resolvedExecutionPlan struct {
	environment struct {
		caller map[string]string
	}
}

func helper(t *testing.T, label string) {
	t.Fatalf("diagnostic %s", label)
}

func TestSynthetic(t *testing.T) {
	var plan resolvedExecutionPlan
	label := plan.environment.caller["SECRET"]
	helper(t, label)
}
`,
		},
	} {
		if findings := resolvedPlanPrivacyFindingsInSource(t, tc.name, tc.source); len(findings) == 0 {
			t.Fatalf("%s diagnostic helper shape was not rejected", tc.name)
		}
	}

	allowed := `
package admission

import "testing"

type resolvedExecutionPlan struct{}

func helper(t *testing.T, label string, index int) {
	t.Helper()
	if label == "" {
		t.Fatalf("bounded helper label mismatch at index %d", index)
	}
}

func TestSynthetic(t *testing.T) {
	helper(t, "static classification", 1)
}
`
	if findings := resolvedPlanPrivacyFindingsInSource(t, "bounded-diagnostic-helper", allowed); len(findings) != 0 {
		t.Fatalf("bounded fixed diagnostic helper was rejected")
	}
}

func TestResolvedPlanPrivacyProjectionGuardRejectsProjectionPackageImportAliases(t *testing.T) {
	for _, tc := range []struct {
		name   string
		source string
	}{
		{name: "alias fmt", source: `package admission
import f "fmt"
type resolvedExecutionPlan struct{}
func project(plan resolvedExecutionPlan) { f.Print(plan) }
`},
		{name: "alias json", source: `package admission
import j "encoding/json"
type resolvedExecutionPlan struct{}
func project(plan resolvedExecutionPlan) { _, _ = j.Marshal(plan) }
`},
		{name: "alias reflect", source: `package admission
import r "reflect"
type resolvedExecutionPlan struct{}
func project(plan resolvedExecutionPlan) { _ = r.ValueOf(plan) }
`},
		{name: "alias strings", source: `package admission
import (
	"fmt"
	s "strings"
)
type resolvedExecutionPlan struct { argv []string }
func project(plan resolvedExecutionPlan) { fmt.Print(s.Join(plan.argv, ",")) }
`},
		{name: "dot fmt", source: `package admission
import . "fmt"
type resolvedExecutionPlan struct{}
func project(plan resolvedExecutionPlan) { Print(plan) }
`},
		{name: "dot json", source: `package admission
import . "encoding/json"
type resolvedExecutionPlan struct{}
func project(plan resolvedExecutionPlan) { _, _ = Marshal(plan) }
`},
		{name: "dot reflect", source: `package admission
import . "reflect"
type resolvedExecutionPlan struct{}
func project(plan resolvedExecutionPlan) { _ = ValueOf(plan) }
`},
		{name: "dot strings", source: `package admission
import (
	"fmt"
	. "strings"
)
type resolvedExecutionPlan struct { argv []string }
func project(plan resolvedExecutionPlan) { fmt.Print(Join(plan.argv, ",")) }
`},
	} {
		findings := resolvedPlanPrivacyFindingsInSource(t, tc.name, tc.source)
		if len(findings) == 0 {
			t.Fatalf("%s projection package alias bypass was not rejected", tc.name)
		}
	}

	allowed := `package admission
import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
)
type resolvedExecutionPlan struct{}
`
	if findings := resolvedPlanPrivacyFindingsInSource(t, "ordinary imports", allowed); len(findings) != 0 {
		t.Fatalf("ordinary unaliased projection package imports were rejected")
	}
}

func TestResolvedPlanPrivacyProjectionGuardRejectsSyntheticBypasses(t *testing.T) {
	for _, tc := range []struct {
		name   string
		source string
	}{
		{
			name: "direct fmt",
			source: `
package admission

import (
	"fmt"
	"testing"
)

type resolvedExecutionPlan struct{}

func TestSynthetic(t *testing.T) {
	var plan resolvedExecutionPlan
	_ = fmt.Sprintf("%v", plan)
}
`,
		},
		{
			name: "json marshal",
			source: `
package admission

import (
	"encoding/json"
	"testing"
)

type resolvedExecutionPlan struct{}

func TestSynthetic(t *testing.T) {
	var plan resolvedExecutionPlan
	_, _ = json.Marshal(plan)
}
`,
		},
		{
			name: "reflection traversal",
			source: `
package admission

import (
	"reflect"
	"testing"
)

type resolvedExecutionPlan struct{}

func TestSynthetic(t *testing.T) {
	var plan resolvedExecutionPlan
	_ = reflect.ValueOf(plan)
}
`,
		},
		{
			name: "local alias projection",
			source: `
package admission

import (
	"fmt"
	"testing"
)

type resolvedExecutionPlan struct{}

func TestSynthetic(t *testing.T) {
	var plan resolvedExecutionPlan
	p := plan
	_ = fmt.Sprint(p)
}
`,
		},
		{
			name: "helper projection",
			source: `
package admission

import (
	"fmt"
	"testing"
)

type resolvedExecutionPlan struct{}

func projectPlan(plan resolvedExecutionPlan) string {
	return fmt.Sprint(plan)
}

func TestSynthetic(t *testing.T) {
	var plan resolvedExecutionPlan
	rendered := projectPlan(plan)
	if rendered != "" {
		t.Fatal("static failure label")
	}
}
`,
		},
		{
			name: "helper renamed parameter projection",
			source: `
package admission

import (
	"fmt"
	"testing"
)

type resolvedExecutionPlan struct{}

func projectPlan(subject resolvedExecutionPlan) {
	_ = fmt.Sprint(subject)
}

func TestSynthetic(t *testing.T) {
	var plan resolvedExecutionPlan
	projectPlan(plan)
}
`,
		},
		{
			name: "helper alias parameter projection",
			source: `
package admission

import (
	"fmt"
	"testing"
)

type resolvedExecutionPlan struct{}

func projectPlan(subject resolvedExecutionPlan) {
	alias := subject
	_ = fmt.Sprint(alias)
}

func TestSynthetic(t *testing.T) {
	var plan resolvedExecutionPlan
	projectPlan(plan)
}
`,
		},
		{
			name: "helper chain projection",
			source: `
package admission

import (
	"fmt"
	"testing"
)

type resolvedExecutionPlan struct{}

func first(subject resolvedExecutionPlan) {
	second(subject)
}

func second(renamed resolvedExecutionPlan) {
	_ = fmt.Sprint(renamed)
}

func TestSynthetic(t *testing.T) {
	var plan resolvedExecutionPlan
	first(plan)
}
`,
		},
		{
			name: "join protected collection",
			source: `
	package admission

import (
	"strings"
	"testing"
)

func TestSynthetic(t *testing.T) {
		var argv []string
		_ = strings.Join(argv, ",")
	}
	`,
		},
		{
			name: "testing fatalf whole plan",
			source: `
	package admission

	import "testing"

	type resolvedExecutionPlan struct{}

	func TestSynthetic(t *testing.T) {
		var plan resolvedExecutionPlan
		t.Fatalf("%+v", plan)
	}
	`,
		},
		{
			name: "testing errorf plan field",
			source: `
	package admission

	import "testing"

	type resolvedExecutionPlan struct {
		environment map[string]string
	}

	func TestSynthetic(t *testing.T) {
		var plan resolvedExecutionPlan
		t.Errorf("%v", plan.environment)
	}
	`,
		},
		{
			name: "testing logf handoff",
			source: `
	package admission

	import "testing"

type authorityHandoff struct {
	Evidence map[string]string
}

type resolvedExecutionPlan struct {
	authority authorityHandoff
}

	func TestSynthetic(t *testing.T) {
		var handoff authorityHandoff
		t.Logf("%#v", handoff)
	}
	`,
		},
		{
			name: "testing fatal whole plan",
			source: `
	package admission

	import "testing"

	type resolvedExecutionPlan struct{}

	func TestSynthetic(t *testing.T) {
		var plan resolvedExecutionPlan
		t.Fatal(plan)
	}
	`,
		},
		{
			name: "testing error handoff evidence",
			source: `
	package admission

	import "testing"

	type authorityHandoff struct {
		Evidence map[string]string
	}

	type resolvedExecutionPlan struct {
		authority authorityHandoff
	}

	func TestSynthetic(t *testing.T) {
		var handoff authorityHandoff
		t.Error(handoff.Evidence)
	}
	`,
		},
		{
			name: "testing handle alias",
			source: `
	package admission

	import "testing"

	type resolvedExecutionPlan struct{}

	func TestSynthetic(t *testing.T) {
		var plan resolvedExecutionPlan
		tt := t
		tt.Fatalf("%v", plan)
	}
	`,
		},
	} {
		findings := resolvedPlanPrivacyFindingsInSource(t, tc.name, tc.source)
		if len(findings) == 0 {
			t.Fatalf("%s synthetic projection was not rejected", tc.name)
		}
	}
}

func TestResolvedPlanPrivacyProjectionGuardPermitsBoundedDiagnostics(t *testing.T) {
	source := `
	package admission

	import "testing"

type resolvedExecutionPlan struct {
	mounts []string
	ok     bool
}

func assertFieldName(t *testing.T, name string) {
	t.Helper()
	if name == "" {
		t.Fatal("field-name assertion mismatch")
	}
}

	func TestSynthetic(t *testing.T) {
		var plan resolvedExecutionPlan
		gotCount := len(plan.mounts)
		wantCount := 2
		index := 1
		safeClassification := true
		if len(plan.mounts) != 2 {
			t.Fatalf("mount category count mismatch: got %d want %d", gotCount, wantCount)
		}
		if gotCount != wantCount {
			t.Errorf("mismatch at index %d", index)
		}
		if !plan.ok {
			t.Fatal("static classification mismatch")
		}
		if !safeClassification {
			t.Fatalf("safe boolean classification: %t", safeClassification)
		}
		assertFieldName(t, "resolvedExecutionPlan.mounts")
	}
	`
	findings := resolvedPlanPrivacyFindingsInSource(t, "safe bounded diagnostics", source)
	if len(findings) != 0 {
		t.Fatalf("safe bounded diagnostics were rejected")
	}
}

func TestResolvedPlanPrivacyProjectionGuardRecognizesTestingTBHandles(t *testing.T) {
	source := `
	package admission

	import "testing"

	type resolvedExecutionPlan struct{}

	func assertWithTB(t testing.TB, subject resolvedExecutionPlan) {
		t.Fatalf("%v", subject)
	}

	func TestSynthetic(t *testing.T) {
		var plan resolvedExecutionPlan
		assertWithTB(t, plan)
	}
	`
	findings := resolvedPlanPrivacyFindingsInSource(t, "testing-tb-handle", source)
	for _, finding := range findings {
		if strings.Contains(finding, "assertWithTB:testing-output:Fatalf") {
			return
		}
	}
	t.Fatalf("testing.TB handle projection was not rejected (%s)", strings.Join(findings, ", "))
}

func TestBuildNomadJobSpecNoLongerAcceptsPrepareRequest(t *testing.T) {
	file := mustParseAdmissionSource(t, "submit.go")
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "buildNomadJobSpec" {
			continue
		}
		for _, param := range fn.Type.Params.List {
			switch typed := param.Type.(type) {
			case *ast.Ident:
				if typed.Name == "PrepareRequest" {
					t.Fatalf("buildNomadJobSpec must not accept PrepareRequest after resolved-plan extraction")
				}
			}
		}
		return
	}
	t.Fatal("buildNomadJobSpec not found")
}

func TestResolvedPlanTrancheDoesNotWireReliableSubmitRuntime(t *testing.T) {
	repoRoot := admissionRepoRoot(t)
	for _, rel := range []string{
		"es/admission/types.go",
		"es/admission/service.go",
		"es/admission/submit.go",
		"es/admission/producercontract.go",
		"es/admission/executionlocator.go",
		"es/admission/executionpackage.go",
		"es/admission/lifecycle.go",
		"es/admission/results.go",
		"es/api/server.go",
		"es/config/config.go",
		"es/app/app.go",
	} {
		source := mustReadAdmissionRepoSource(t, repoRoot, rel)
		assertResolvedPlanOmitsAll(t, rel, source,
			"ReliableSubmitHandler",
			"HandleReliableSubmit",
			"reliable_submit_handler",
			"reliable submit handler",
			"PlanBinding",
			"EffectivePlanWitness",
			"internal/reliablesubmit",
			"modernc.org/sqlite",
			"replay envelope",
		)
	}
}

func assertResolvedPlanTypesArePrivate(t *testing.T, file *ast.File) {
	t.Helper()
	for _, decl := range file.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok {
			continue
		}
		for _, spec := range gen.Specs {
			typeSpec, ok := spec.(*ast.TypeSpec)
			if ok && typeSpec.Name.IsExported() {
				t.Fatalf("resolvedplan.go must not export type %s", typeSpec.Name.Name)
			}
			if ok {
				structType, ok := typeSpec.Type.(*ast.StructType)
				if !ok {
					continue
				}
				for _, field := range structType.Fields.List {
					for _, name := range field.Names {
						if name.IsExported() {
							t.Fatalf("resolvedplan.go type %s exports field %s", typeSpec.Name.Name, name.Name)
						}
					}
				}
			}
		}
	}
}

func assertResolvedPlanHasNoProjectionMethods(t *testing.T, file *ast.File) {
	t.Helper()
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Recv == nil {
			continue
		}
		switch fn.Name.Name {
		case "MarshalJSON", "MarshalText", "String", "GoString", "Format", "Error":
			t.Fatalf("resolvedplan.go must not define projection method %s", fn.Name.Name)
		}
	}
}

func mustFindFuncDecl(t *testing.T, file *ast.File, name string) *ast.FuncDecl {
	t.Helper()
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if ok && fn.Name.Name == name {
			return fn
		}
	}
	t.Fatalf("function %s not found", name)
	return nil
}

func resolvedPlanPrivateTypeNames() map[string]bool {
	return map[string]bool{
		"resolvedExecutionPlan":               true,
		"resolvedRequestPlan":                 true,
		"resolvedTimeoutPlan":                 true,
		"resolvedResourcePlan":                true,
		"resolvedRuntimeProfilePlan":          true,
		"resolvedArtifactIdentityPlan":        true,
		"resolvedDerivationIdentityPlan":      true,
		"resolvedOutputIdentityPlan":          true,
		"resolvedCommandPlan":                 true,
		"resolvedEnvironmentPlan":             true,
		"resolvedMountPlan":                   true,
		"resolvedNetworkPosture":              true,
		"resolvedAuthorityHandoffPlan":        true,
		"resolvedCodexCredentialLocationPlan": true,
	}
}

func functionAcceptsAnyType(fn *ast.FuncDecl, names map[string]bool) bool {
	if fn.Type.Params == nil {
		return false
	}
	for _, param := range fn.Type.Params.List {
		if typeExprMentionsAny(param.Type, names) {
			return true
		}
	}
	return false
}

func typeExprMentionsAny(expr ast.Expr, names map[string]bool) bool {
	switch typed := expr.(type) {
	case *ast.Ident:
		return names[typed.Name]
	case *ast.StarExpr:
		return typeExprMentionsAny(typed.X, names)
	case *ast.ArrayType:
		return typeExprMentionsAny(typed.Elt, names)
	case *ast.MapType:
		return typeExprMentionsAny(typed.Key, names) || typeExprMentionsAny(typed.Value, names)
	case *ast.SelectorExpr:
		return names[typed.Sel.Name]
	default:
		return false
	}
}

func functionReturnsGenericProjection(fn *ast.FuncDecl) bool {
	if fn.Type.Results == nil {
		return false
	}
	for _, result := range fn.Type.Results.List {
		if isGenericProjectionType(result.Type) {
			return true
		}
	}
	return false
}

func isGenericProjectionType(expr ast.Expr) bool {
	switch typed := expr.(type) {
	case *ast.Ident:
		return typed.Name == "string" || typed.Name == "any"
	case *ast.InterfaceType:
		return true
	case *ast.ArrayType:
		return true
	case *ast.MapType:
		return true
	case *ast.StarExpr:
		return isGenericProjectionType(typed.X)
	default:
		return false
	}
}

func isWholePlanProjectionCall(call *ast.CallExpr) bool {
	selector, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	switch selectedPackageName(selector.X) {
	case "json":
		return selector.Sel.Name == "Marshal" || selector.Sel.Name == "MarshalIndent" || selector.Sel.Name == "NewEncoder"
	case "fmt":
		return strings.HasPrefix(selector.Sel.Name, "Sprint")
	case "reflect":
		return true
	default:
		return selector.Sel.Name == "Encode"
	}
}

func assignedIdentifierName(expr ast.Expr) (string, bool) {
	ident, ok := expr.(*ast.Ident)
	if !ok || ident.Name == "_" {
		return "", false
	}
	return ident.Name, true
}

func stringLiteralValue(expr ast.Expr) (string, bool) {
	literal, ok := expr.(*ast.BasicLit)
	if !ok || literal.Kind != token.STRING {
		return "", false
	}
	value, err := strconv.Unquote(literal.Value)
	if err != nil {
		return "", false
	}
	return value, true
}

func sourceForExpr(t *testing.T, fileSet *token.FileSet, expr ast.Expr) string {
	t.Helper()
	var buf bytes.Buffer
	if err := printer.Fprint(&buf, fileSet, expr); err != nil {
		t.Fatalf("print diagnostic expression: %v", err)
	}
	return buf.String()
}

func sourceForNode(t *testing.T, fileSet *token.FileSet, node ast.Node) string {
	t.Helper()
	var buf bytes.Buffer
	if err := printer.Fprint(&buf, fileSet, node); err != nil {
		t.Fatalf("print source node: %v", err)
	}
	return buf.String()
}

func selectedPackageName(expr ast.Expr) string {
	ident, ok := expr.(*ast.Ident)
	if !ok {
		return ""
	}
	return ident.Name
}

func compactSourceAfter(t *testing.T, source string, marker string) string {
	t.Helper()
	index := strings.Index(source, marker)
	if index < 0 {
		t.Fatalf("source missing marker %q", marker)
	}
	return source[index:]
}

func mustParseResolvedPlanSource(t *testing.T) *ast.File {
	t.Helper()
	file, err := parser.ParseFile(token.NewFileSet(), filepath.Join(admissionRepoRoot(t), "es/admission/resolvedplan.go"), nil, parser.ParseComments)
	if err != nil {
		t.Fatalf("parse resolvedplan.go: %v", err)
	}
	return file
}

func mustReadResolvedPlanSource(t *testing.T) string {
	t.Helper()
	payload, err := os.ReadFile(filepath.Join(admissionRepoRoot(t), "es/admission/resolvedplan.go"))
	if err != nil {
		t.Fatalf("read resolvedplan.go: %v", err)
	}
	return string(payload)
}

func assertTextOmitsAll(t *testing.T, text string, fragments ...string) {
	t.Helper()
	for index, fragment := range fragments {
		if strings.Contains(text, fragment) {
			t.Fatalf("forbidden text fragment present at index %d", index)
		}
	}
}

func assertExactCallCount(t *testing.T, counts map[string]int, path string, want int) {
	t.Helper()
	if got := counts[path]; got != want {
		t.Fatalf("ARS request count mismatch: got %d want %d", got, want)
	}
}

func assertResolvedPlanContainsAll(t *testing.T, label string, source string, fragments ...string) {
	t.Helper()
	for _, fragment := range fragments {
		if !strings.Contains(source, fragment) {
			t.Fatalf("%s missing required source fragment %q", label, fragment)
		}
	}
}

func assertResolvedPlanOmitsAll(t *testing.T, label string, source string, fragments ...string) {
	t.Helper()
	for _, fragment := range fragments {
		if strings.Contains(source, fragment) {
			t.Fatalf("%s must not contain forbidden source fragment %q", label, fragment)
		}
	}
}

func TestResolvedPlanPrivacyAnalyzerDiscoversFuturePackageFiles(t *testing.T) {
	directory := t.TempDir()
	files := map[string]string{
		"resolvedplan.go": `package admission
type resolvedExecutionPlan struct { command struct { argv []string } }
`,
		"existing_test.go": `package admission
import "testing"
func TestExisting(t *testing.T) { t.Fatal("static class") }
`,
		"production.go": `package admission
func safeProductionCount(plan resolvedExecutionPlan) int { return len(plan.command.argv) }
`,
		"future_resolvedplan_output_test.go": `package admission
import (
	"fmt"
	"testing"
)
func TestFutureProjection(t *testing.T) {
	var plan resolvedExecutionPlan
	fmt.Printf("%v", plan)
}
`,
	}
	for name, source := range files {
		if err := os.WriteFile(filepath.Join(directory, name), []byte(source), 0o600); err != nil {
			t.Fatalf("write package discovery fixture: %v", err)
		}
	}
	discovered, discoveryFindings := discoverResolvedPlanPrivacySources(directory)
	if len(discoveryFindings) != 0 {
		t.Fatalf("package discovery rejected regular fixture files")
	}
	if len(discovered) != len(files) {
		t.Fatalf("package discovery count mismatch: got %d want %d", len(discovered), len(files))
	}
	for index := 1; index < len(discovered); index++ {
		if discovered[index-1].name >= discovered[index].name {
			t.Fatal("package discovery order is not lexical")
		}
	}
	findings := analyzeResolvedPlanPrivacySources(discovered)
	if !resolvedPlanPrivacyFindingContains(findings, "future_resolvedplan_output_test.go") {
		t.Fatal("future same-package Go file escaped privacy analysis")
	}
	if err := os.Symlink(filepath.Join(directory, "resolvedplan.go"), filepath.Join(directory, "symlinked.go")); err != nil {
		t.Fatalf("create package discovery symlink fixture: %v", err)
	}
	if err := os.Mkdir(filepath.Join(directory, "directory.go"), 0o700); err != nil {
		t.Fatalf("create non-regular Go entry fixture: %v", err)
	}
	_, rejectedEntries := discoverResolvedPlanPrivacySources(directory)
	if !resolvedPlanPrivacyFindingContains(rejectedEntries, "symlinked.go:go-source-symlink") {
		t.Fatal("Go source symlink was followed instead of rejected")
	}
	if !resolvedPlanPrivacyFindingContains(rejectedEntries, "directory.go:go-source-not-regular") {
		t.Fatal("non-regular Go entry was not rejected")
	}
}

func TestResolvedPlanPrivacyAnalyzerRejectsRequiredBypassMatrix(t *testing.T) {
	for _, tc := range []struct {
		name         string
		imports      string
		declarations string
		body         string
	}{
		{name: "any conversion", body: `_ = any(plan)`},
		{name: "empty interface conversion", body: `_ = interface{}(plan)`},
		{name: "named interface conversion", declarations: `type planEnvelope interface{}`, body: `_ = planEnvelope(plan)`},
		{name: "interface variable wrapping", body: `var wrapped any = plan; _ = wrapped`},
		{name: "interface container wrapping", body: `_ = []any{plan}`},
		{name: "fmt percent x", imports: `"fmt"`, body: `fmt.Printf("%x", plan)`},
		{name: "fmt percent upper x", imports: `"fmt"`, body: `fmt.Printf("%X", plan)`},
		{name: "fmt percent v", imports: `"fmt"`, body: `fmt.Printf("%v", plan)`},
		{name: "fmt percent plus v", imports: `"fmt"`, body: `fmt.Printf("%+v", plan)`},
		{name: "fmt percent sharp v", imports: `"fmt"`, body: `fmt.Printf("%#v", plan)`},
		{name: "fmt percent q", imports: `"fmt"`, body: `fmt.Printf("%q", plan)`},
		{name: "fmt raw field", imports: `"fmt"`, body: `fmt.Sprintf("%s", plan.command.argv)`},
		{name: "fmt import alias", imports: `format "fmt"`, body: `format.Printf("%x", plan)`},
		{name: "fmt function value", imports: `"fmt"`, body: `printer := fmt.Printf; printer("%v", plan)`},
		{
			name:    "local function alias",
			imports: `"fmt"`,
			declarations: `func projectPlan(subject resolvedExecutionPlan) {
	fmt.Print(subject)
}`,
			body: `helper := projectPlan; helper(plan)`,
		},
		{
			name:    "closure capture",
			imports: `"fmt"`,
			body: `f := func() { fmt.Printf("%v", plan) }
	f()`,
		},
		{
			name: "returned closure capture",
			declarations: `func capturePlan(subject resolvedExecutionPlan) func() []string {
	values := subject.command.argv
	return func() []string { return values }
}`,
			body: `f := capturePlan(plan); _ = f`,
		},
		{
			name:    "direct method",
			imports: `"fmt"`,
			declarations: `type planSink struct{}
func (planSink) write(subject resolvedExecutionPlan) { fmt.Print(subject) }`,
			body: `var sink planSink; sink.write(plan)`,
		},
		{
			name:         "private receiver method",
			imports:      `"fmt"`,
			declarations: `func (subject resolvedExecutionPlan) project() { fmt.Print(subject) }`,
			body:         `plan.project()`,
		},
		{
			name:    "method value",
			imports: `"fmt"`,
			declarations: `type planSink struct{}
func (planSink) write(subject resolvedExecutionPlan) { fmt.Print(subject) }`,
			body: `var sink planSink; writer := sink.write; writer(plan)`,
		},
		{
			name:    "method expression",
			imports: `"fmt"`,
			declarations: `type planSink struct{}
func (planSink) write(subject resolvedExecutionPlan) { fmt.Print(subject) }`,
			body: `writer := planSink.write; writer(planSink{}, plan)`,
		},
		{
			name:    "method result",
			imports: `"fmt"`,
			declarations: `type planSink struct{}
func (planSink) value(subject resolvedExecutionPlan) []string { return subject.command.argv }`,
			body: `var sink planSink; fmt.Print(sink.value(plan))`,
		},
		{name: "standard log print", imports: `"log"`, body: `log.Print(plan)`},
		{name: "standard log alias printf", imports: `loggerpkg "log"`, body: `loggerpkg.Printf("%x", plan)`},
		{name: "standard logger method", imports: `"log"`, body: `logger := log.New(nil, "", 0); logger.Print(plan)`},
		{name: "slog info", imports: `"log/slog"`, body: `slog.Info("plan", "value", plan)`},
		{name: "slog Any", imports: `"log/slog"`, body: `slog.Error("plan", slog.Any("value", plan))`},
		{name: "slog alias logger", imports: `structured "log/slog"`, body: `logger := structured.New(nil); logger.Info("plan", "value", plan)`},
		{name: "json marshal", imports: `"encoding/json"`, body: `_, _ = json.Marshal(plan)`},
		{name: "json marshal indent", imports: `"encoding/json"`, body: `_, _ = json.MarshalIndent(plan, "", "  ")`},
		{name: "json encoder", imports: `"bytes"
	"encoding/json"`, body: `var writer bytes.Buffer; _ = json.NewEncoder(&writer).Encode(plan)`},
		{name: "json function alias", imports: `"encoding/json"`, body: `marshal := json.Marshal; _, _ = marshal(plan)`},
		{name: "xml marshal", imports: `"encoding/xml"`, body: `_, _ = xml.Marshal(plan)`},
		{name: "xml encoder", imports: `"bytes"
	"encoding/xml"`, body: `var writer bytes.Buffer; _ = xml.NewEncoder(&writer).Encode(plan)`},
		{name: "reflect value", imports: `"reflect"`, body: `_ = reflect.ValueOf(plan)`},
		{name: "reflect type", imports: `"reflect"`, body: `_ = reflect.TypeOf(plan)`},
		{name: "testing Log", body: `t.Log(plan)`},
		{name: "testing Logf", body: `t.Logf("%x", plan)`},
		{name: "testing Errorf", body: `t.Errorf("%v", plan)`},
		{name: "testing Fatalf", body: `t.Fatalf("%+v", plan)`},
		{name: "testing method value", body: `fail := t.Fatalf; fail("%v", plan)`},
		{name: "assert Equal", imports: `assert "example/assert"`, body: `assert.Equal(t, resolvedExecutionPlan{}, plan)`},
		{name: "require Equal", imports: `require "example/require"`, body: `require.Equal(t, resolvedExecutionPlan{}, plan)`},
		{name: "cmp Diff", imports: `cmp "example/cmp"`, body: `_ = cmp.Diff(resolvedExecutionPlan{}, plan)`},
		{name: "external generic package helper", imports: `check "example/check"`, body: `check.That(t, plan)`},
		{name: "unresolved generic helper", body: `externalCheck(plan)`},
		{name: "package variable flow", imports: `"fmt"`, declarations: `var packagePlan resolvedExecutionPlan`, body: `fmt.Print(packagePlan)`},
		{
			name:    "package variable assignment flow",
			imports: `"fmt"`,
			declarations: `var packageValues []string
func savePackageValues(values []string) { packageValues = values }
func printPackageValues() { fmt.Print(packageValues) }`,
			body: `savePackageValues(plan.command.argv); printPackageValues()`,
		},
		{name: "local variable flow", imports: `"fmt"`, body: `copyOfPlan := plan; fmt.Print(copyOfPlan)`},
		{name: "pointer flow", imports: `"fmt"`, body: `pointer := &plan; fmt.Print(*pointer)`},
		{name: "index flow", imports: `"fmt"`, body: `fmt.Print(plan.command.argv[0])`},
		{name: "field variable flow", imports: `"fmt"`, body: `argv := plan.command.argv; fmt.Print(argv)`},
		{
			name:         "helper parameter flow",
			imports:      `"fmt"`,
			declarations: `func projectArgv(values []string) { fmt.Print(values) }`,
			body:         `projectArgv(plan.command.argv)`,
		},
		{
			name:         "helper return flow",
			imports:      `"fmt"`,
			declarations: `func returnArgv(subject resolvedExecutionPlan) []string { return subject.command.argv }`,
			body:         `fmt.Print(returnArgv(plan))`,
		},
		{name: "container flow", imports: `"fmt"`, body: `wrapped := []any{plan.command.argv}; fmt.Print(wrapped)`},
		{name: "field closure flow", imports: `"fmt"`, body: `argv := plan.command.argv; f := func() { fmt.Print(argv) }; f()`},
		{name: "multiple assignment flow", imports: `"fmt"`, body: `copyOfPlan, ok := plan, true; _ = ok; fmt.Print(copyOfPlan)`},
		{
			name:         "multiple result flow",
			imports:      `"fmt"`,
			declarations: `func splitPlan(subject resolvedExecutionPlan) ([]string, bool) { return subject.command.argv, true }`,
			body:         `argv, ok := splitPlan(plan); _ = ok; fmt.Print(argv)`,
		},
		{name: "safe count wrong verb", body: `count := len(plan.mounts); t.Fatalf("count %s", count)`},
		{name: "safe count dynamic format", body: `count := len(plan.mounts); format := "count %d"; t.Fatalf(format, count)`},
		{name: "safe count unformatted interface", body: `t.Log(any(len(plan.mounts)))`},
		{name: "safe count converted then unformatted", body: `t.Log(int(len(plan.mounts)))`},
		{name: "safe count formatted outside testing", imports: `"fmt"`, body: `_ = fmt.Sprintf("%d", len(plan.mounts))`},
		{name: "safe count container wrapping", body: `t.Log([]int{len(plan.mounts)})`},
		{name: "unresolved function variable", declarations: `func consume(project func(resolvedExecutionPlan), subject resolvedExecutionPlan) { project(subject) }`, body: `var project func(resolvedExecutionPlan); consume(project, plan)`},
		{name: "interface method", declarations: `type projector interface { Project(any) }`, body: `var project projector; project.Project(plan)`},
		{name: "unresolved receiver method", body: `_ = plan.String()`},
		{name: "builtin print", body: `print(plan)`},
		{name: "builtin println", body: `println(plan)`},
		{name: "builtin panic", body: `panic(plan)`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			source := resolvedPlanPrivacyFixture(tc.imports, tc.declarations, tc.body)
			if findings := resolvedPlanPrivacyFindingsInSource(t, tc.name, source); len(findings) == 0 {
				t.Fatalf("required privacy bypass was accepted")
			}
		})
	}
}

func TestResolvedPlanPrivacyAnalyzerRejectsMultiFileTransitiveFlow(t *testing.T) {
	findings := resolvedPlanPrivacyFindingsInSources(t, map[string]string{
		"resolvedplan.go": `package admission
type resolvedExecutionPlan struct { command struct { argv []string } }
`,
		"helper.go": `package admission
func returnArgv(subject resolvedExecutionPlan) []string { return subject.command.argv }
`,
		"future_resolvedplan_output.go": `package admission
import (
	"fmt"
)
func projectFuturePlan() {
	var plan resolvedExecutionPlan
	fmt.Print(returnArgv(plan))
}
`,
	})
	if len(findings) == 0 {
		t.Fatal("multi-file helper return escaped package analyzer")
	}
}

func TestResolvedPlanPrivacyAnalyzerGuardsMaterializationBoundaryBody(t *testing.T) {
	findings := resolvedPlanPrivacyFindingsInSources(t, map[string]string{
		"resolvedplan.go": `package admission
type resolvedExecutionPlan struct { command struct { argv []string } }
`,
		"submit.go": `package admission
import "fmt"
func buildRuntimeEnvironment(values []string) []string {
	fmt.Print(values)
	return values
}
func projectMaterializationBoundary(plan resolvedExecutionPlan) {
	_ = buildRuntimeEnvironment(plan.command.argv)
}
`,
	})
	if !resolvedPlanPrivacyFindingContains(findings, "submit.go:buildRuntimeEnvironment:formatting:Print") {
		t.Fatalf("direct materialization-boundary sink escaped privacy analysis (%s)", strings.Join(findings, ", "))
	}
}

func TestResolvedPlanPrivacyAnalyzerPermitsSafeDeclassificationMatrix(t *testing.T) {
	source := resolvedPlanPrivacyFixture("", `
func reportCount(t *testing.T, count int) {
	t.Helper()
	t.Fatalf("bounded category count %d", count)
}

func countMounts(subject resolvedExecutionPlan) int {
	return len(subject.mounts)
}
`, `
	argvCount := len(plan.command.argv)
	environmentCount := len(plan.environment.additions)
	capacity := cap(plan.command.argv)
	equal := plan.ok == true
	notEqual := plan.ok != false
	mismatchIndex := 1
	if argvCount != 2 {
		t.Fatalf("argv count %d", argvCount)
	}
	if environmentCount != 0 {
		t.Errorf("environment count %d", environmentCount)
	}
	if capacity != 4 {
		t.Logf("capacity %d", capacity)
	}
	if !equal || !notEqual {
		t.Fatalf("boolean classes %t %t", equal, notEqual)
	}
	if mismatchIndex != 0 {
		t.Fatalf("mismatch index %d", mismatchIndex)
	}
	for index := range plan.mounts {
		t.Fatalf("bounded range index %d", index)
	}
	reportCount(t, len(plan.mounts))
	t.Logf("helper-derived mount count %d", countMounts(plan))
	t.Logf("padded mount count %03d", len(plan.mounts))
	t.Log("static failure class")
`)
	if findings := resolvedPlanPrivacyFindingsInSource(t, "safe-declassification-matrix", source); len(findings) != 0 {
		t.Fatalf("safe declassification controls were rejected (%s)", strings.Join(findings, ", "))
	}
}

func resolvedPlanPrivacyFixture(extraImports string, declarations string, body string) string {
	imports := "\t\"testing\"\n"
	if strings.TrimSpace(extraImports) != "" {
		imports += "\t" + strings.ReplaceAll(strings.TrimSpace(extraImports), "\n", "\n\t") + "\n"
	}
	return `package admission
import (
` + imports + `)
type resolvedExecutionPlan struct {
	command struct { argv []string }
	environment struct { additions map[string]string }
	mounts []string
	ok bool
}
` + declarations + `
func TestSynthetic(t *testing.T) {
	var plan resolvedExecutionPlan
` + body + `
}
`
}

func resolvedPlanPrivacyFindingContains(findings []string, fragment string) bool {
	for _, finding := range findings {
		if strings.Contains(finding, fragment) {
			return true
		}
	}
	return false
}

type resolvedPlanPrivacySource struct {
	name   string
	source []byte
}

type resolvedPlanPrivacyFile struct {
	name       string
	file       *ast.File
	imports    map[string]string
	dotImports map[string]bool
}

type resolvedPlanPrivacyValue struct {
	tainted  bool
	safe     string
	typeName string
	callable *resolvedPlanPrivacyCallable
}

type resolvedPlanPrivacyCallable struct {
	kind                    string
	localKey                string
	packagePath             string
	name                    string
	boundReceiver           bool
	boundReceiverTainted    bool
	boundReceiverSafe       string
	boundReceiverType       string
	methodExpression        bool
	capturesPrivateMaterial bool
}

type resolvedPlanPrivacyFunction struct {
	key            string
	name           string
	file           *resolvedPlanPrivacyFile
	body           *ast.BlockStmt
	functionType   *ast.FuncType
	receiverName   string
	receiverType   string
	parameterNames []string
	parameterTypes []ast.Expr
	resultTypes    []ast.Expr
	parent         *resolvedPlanPrivacyFunction
	literal        *ast.FuncLit
	tainted        map[string]bool
	safe           map[string]string
	variableTypes  map[string]string
	callables      map[string]*resolvedPlanPrivacyCallable
	returnTainted  []bool
	returnSafe     []string
}

type resolvedPlanPrivacyAnalyzer struct {
	fileSet       *token.FileSet
	files         []*resolvedPlanPrivacyFile
	typeSpecs     map[string]ast.Expr
	structFields  map[string]map[string]string
	privateTypes  map[string]bool
	functions     map[string]*resolvedPlanPrivacyFunction
	functionNames map[string]string
	methods       map[string]string
	closures      map[*ast.FuncLit]string
	globalTainted map[string]bool
	globalTypes   map[string]string
	findings      map[string]bool
	flowChanged   bool
}

func resolvedPlanPrivacyFindingsInPackage(t *testing.T) []string {
	t.Helper()
	return resolvedPlanPrivacyFindingsInDirectory(t, filepath.Join(admissionRepoRoot(t), "es/admission"))
}

func resolvedPlanPrivacyFindingsInDirectory(t *testing.T, directory string) []string {
	t.Helper()
	sources, discoveryFindings := discoverResolvedPlanPrivacySources(directory)
	findings := append([]string{}, discoveryFindings...)
	findings = append(findings, analyzeResolvedPlanPrivacySources(sources)...)
	sort.Strings(findings)
	return findings
}

func discoverResolvedPlanPrivacySources(directory string) ([]resolvedPlanPrivacySource, []string) {
	entries, err := os.ReadDir(directory)
	if err != nil {
		return nil, []string{"source-discovery:" + err.Error()}
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	var sources []resolvedPlanPrivacySource
	var findings []string
	for _, entry := range entries {
		name := entry.Name()
		if filepath.Ext(name) != ".go" {
			continue
		}
		if entry.Type()&os.ModeSymlink != 0 {
			findings = append(findings, name+":go-source-symlink")
			continue
		}
		info, infoErr := entry.Info()
		if infoErr != nil {
			findings = append(findings, name+":go-source-stat")
			continue
		}
		if !info.Mode().IsRegular() {
			findings = append(findings, name+":go-source-not-regular")
			continue
		}
		payload, readErr := os.ReadFile(filepath.Join(directory, name))
		if readErr != nil {
			findings = append(findings, name+":go-source-read")
			continue
		}
		sources = append(sources, resolvedPlanPrivacySource{name: name, source: payload})
	}
	return sources, findings
}

func resolvedPlanPrivacyFindingsInSources(t *testing.T, sources map[string]string) []string {
	t.Helper()
	files := make([]resolvedPlanPrivacySource, 0, len(sources))
	for name, source := range sources {
		files = append(files, resolvedPlanPrivacySource{name: name, source: []byte(source)})
	}
	sort.Slice(files, func(i, j int) bool { return files[i].name < files[j].name })
	return analyzeResolvedPlanPrivacySources(files)
}

func resolvedPlanPrivacyFindingsInSource(t *testing.T, label string, source string) []string {
	t.Helper()
	return resolvedPlanPrivacyFindingsInSources(t, map[string]string{label + "_test.go": source})
}

func analyzeResolvedPlanPrivacySources(sources []resolvedPlanPrivacySource) []string {
	analyzer := &resolvedPlanPrivacyAnalyzer{
		fileSet:       token.NewFileSet(),
		typeSpecs:     map[string]ast.Expr{},
		structFields:  map[string]map[string]string{},
		privateTypes:  map[string]bool{},
		functions:     map[string]*resolvedPlanPrivacyFunction{},
		functionNames: map[string]string{},
		methods:       map[string]string{},
		closures:      map[*ast.FuncLit]string{},
		globalTainted: map[string]bool{},
		globalTypes:   map[string]string{},
		findings:      map[string]bool{},
	}
	for _, item := range sources {
		file, err := parser.ParseFile(analyzer.fileSet, item.name, item.source, parser.AllErrors|parser.ParseComments)
		if err != nil {
			analyzer.addFinding(item.name, "", "parse-failed")
			continue
		}
		parsed := &resolvedPlanPrivacyFile{
			name:       item.name,
			file:       file,
			imports:    map[string]string{},
			dotImports: map[string]bool{},
		}
		for _, imported := range file.Imports {
			importPath, unquoteErr := strconv.Unquote(imported.Path.Value)
			if unquoteErr != nil {
				analyzer.addFinding(item.name, "", "invalid-import-path")
				continue
			}
			alias := path.Base(importPath)
			if imported.Name != nil {
				alias = imported.Name.Name
			}
			if alias == "." {
				parsed.dotImports[importPath] = true
				continue
			}
			if alias != "_" {
				parsed.imports[alias] = importPath
			}
		}
		analyzer.files = append(analyzer.files, parsed)
	}
	if len(analyzer.files) == 0 {
		analyzer.addFinding("package", "", "no-parseable-go-source")
		return analyzer.sortedFindings()
	}
	analyzer.collectTypeSpecs()
	analyzer.derivePrivateTypeFamily()
	analyzer.collectFunctions()
	analyzer.collectGlobals()
	analyzer.seedPrivateFlow()
	analyzer.runFixedPoint()
	return analyzer.sortedFindings()
}

func (analyzer *resolvedPlanPrivacyAnalyzer) collectGlobals() {
	for _, file := range analyzer.files {
		for _, declaration := range file.file.Decls {
			general, ok := declaration.(*ast.GenDecl)
			if !ok || general.Tok != token.VAR {
				continue
			}
			for _, rawSpec := range general.Specs {
				spec, ok := rawSpec.(*ast.ValueSpec)
				if !ok {
					continue
				}
				for index, name := range spec.Names {
					typeName := resolvedPlanPrivacyTypeName(file, spec.Type)
					analyzer.globalTypes[name.Name] = typeName
					tainted := spec.Type != nil && analyzer.typeContainsPrivate(spec.Type)
					if len(spec.Values) > 0 {
						valueIndex := index
						if len(spec.Values) == 1 {
							valueIndex = 0
						}
						if valueIndex < len(spec.Values) {
							tainted = tainted || analyzer.topLevelExpressionContainsPrivate(spec.Values[valueIndex])
						}
					}
					if tainted {
						analyzer.globalTainted[name.Name] = true
					}
				}
			}
		}
	}
}

func (analyzer *resolvedPlanPrivacyAnalyzer) topLevelExpressionContainsPrivate(expression ast.Expr) bool {
	containsPrivate := false
	ast.Inspect(expression, func(node ast.Node) bool {
		identifier, ok := node.(*ast.Ident)
		if ok && analyzer.privateTypes[identifier.Name] {
			containsPrivate = true
			return false
		}
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return !containsPrivate
		}
		name, ok := call.Fun.(*ast.Ident)
		if !ok {
			return !containsPrivate
		}
		target := analyzer.functions[analyzer.functionNames[name.Name]]
		if target == nil {
			return !containsPrivate
		}
		for _, resultType := range target.resultTypes {
			if analyzer.typeContainsPrivate(resultType) {
				containsPrivate = true
				return false
			}
		}
		return !containsPrivate
	})
	return containsPrivate
}

func (analyzer *resolvedPlanPrivacyAnalyzer) collectTypeSpecs() {
	for _, file := range analyzer.files {
		for _, declaration := range file.file.Decls {
			general, ok := declaration.(*ast.GenDecl)
			if !ok || general.Tok != token.TYPE {
				continue
			}
			for _, rawSpec := range general.Specs {
				spec, ok := rawSpec.(*ast.TypeSpec)
				if !ok {
					continue
				}
				if _, exists := analyzer.typeSpecs[spec.Name.Name]; exists {
					analyzer.addFinding(file.name, "", "duplicate-local-type:"+spec.Name.Name)
					continue
				}
				analyzer.typeSpecs[spec.Name.Name] = spec.Type
				if structure, ok := spec.Type.(*ast.StructType); ok {
					fields := map[string]string{}
					for _, field := range structure.Fields.List {
						fieldType := resolvedPlanPrivacyTypeName(file, field.Type)
						for _, name := range field.Names {
							fields[name.Name] = fieldType
						}
					}
					analyzer.structFields[spec.Name.Name] = fields
				}
			}
		}
	}
}

func (analyzer *resolvedPlanPrivacyAnalyzer) derivePrivateTypeFamily() {
	if analyzer.typeSpecs["resolvedExecutionPlan"] != nil {
		analyzer.privateTypes["resolvedExecutionPlan"] = true
	}
	if !analyzer.privateTypes["resolvedExecutionPlan"] {
		analyzer.addFinding("package", "", "resolved-plan-root-type-missing")
	}
	changed := true
	for changed {
		changed = false
		for name := range analyzer.privateTypes {
			expression := analyzer.typeSpecs[name]
			if expression == nil {
				continue
			}
			ast.Inspect(expression, func(node ast.Node) bool {
				identifier, ok := node.(*ast.Ident)
				if !ok {
					return true
				}
				if ast.IsExported(identifier.Name) || analyzer.typeSpecs[identifier.Name] == nil || analyzer.privateTypes[identifier.Name] {
					return true
				}
				analyzer.privateTypes[identifier.Name] = true
				changed = true
				return true
			})
		}
	}
}

func (analyzer *resolvedPlanPrivacyAnalyzer) collectFunctions() {
	for _, file := range analyzer.files {
		for _, declaration := range file.file.Decls {
			function, ok := declaration.(*ast.FuncDecl)
			if !ok || function.Body == nil {
				continue
			}
			receiverName := ""
			receiverType := ""
			key := "func:" + function.Name.Name
			if function.Recv != nil && len(function.Recv.List) > 0 {
				receiverType = resolvedPlanPrivacyTypeName(file, function.Recv.List[0].Type)
				if len(function.Recv.List[0].Names) > 0 {
					receiverName = function.Recv.List[0].Names[0].Name
				}
				key = "method:" + receiverType + "." + function.Name.Name
			}
			unit := newResolvedPlanPrivacyFunction(key, function.Name.Name, file, function.Type, function.Body)
			unit.receiverName = receiverName
			unit.receiverType = receiverType
			if analyzer.functions[key] != nil {
				analyzer.addFinding(file.name, function.Name.Name, "duplicate-local-function")
				continue
			}
			analyzer.functions[key] = unit
			if receiverType == "" {
				analyzer.functionNames[function.Name.Name] = key
			} else {
				analyzer.methods[receiverType+"."+function.Name.Name] = key
			}
			analyzer.collectClosures(unit, function.Body)
		}
	}
}

func newResolvedPlanPrivacyFunction(key string, name string, file *resolvedPlanPrivacyFile, functionType *ast.FuncType, body *ast.BlockStmt) *resolvedPlanPrivacyFunction {
	unit := &resolvedPlanPrivacyFunction{
		key:           key,
		name:          name,
		file:          file,
		body:          body,
		functionType:  functionType,
		tainted:       map[string]bool{},
		safe:          map[string]string{},
		variableTypes: map[string]string{},
		callables:     map[string]*resolvedPlanPrivacyCallable{},
	}
	if functionType.Params != nil {
		for _, field := range functionType.Params.List {
			for _, name := range field.Names {
				unit.parameterNames = append(unit.parameterNames, name.Name)
				unit.parameterTypes = append(unit.parameterTypes, field.Type)
				unit.variableTypes[name.Name] = resolvedPlanPrivacyTypeName(file, field.Type)
			}
		}
	}
	if functionType.Results != nil {
		for _, field := range functionType.Results.List {
			count := len(field.Names)
			if count == 0 {
				count = 1
			}
			for index := 0; index < count; index++ {
				unit.resultTypes = append(unit.resultTypes, field.Type)
			}
		}
	}
	unit.returnTainted = make([]bool, len(unit.resultTypes))
	unit.returnSafe = make([]string, len(unit.resultTypes))
	return unit
}

func (analyzer *resolvedPlanPrivacyAnalyzer) collectClosures(parent *resolvedPlanPrivacyFunction, node ast.Node) {
	ast.Inspect(node, func(candidate ast.Node) bool {
		literal, ok := candidate.(*ast.FuncLit)
		if !ok {
			return true
		}
		position := analyzer.fileSet.Position(literal.Pos())
		key := "closure:" + parent.file.name + ":" + strconv.Itoa(position.Line) + ":" + strconv.Itoa(position.Column)
		unit := newResolvedPlanPrivacyFunction(key, "closure", parent.file, literal.Type, literal.Body)
		unit.parent = parent
		unit.literal = literal
		analyzer.functions[key] = unit
		analyzer.closures[literal] = key
		analyzer.collectClosures(unit, literal.Body)
		return false
	})
}

func (analyzer *resolvedPlanPrivacyAnalyzer) seedPrivateFlow() {
	for _, unit := range analyzer.functions {
		if unit.receiverName != "" {
			unit.variableTypes[unit.receiverName] = unit.receiverType
			if analyzer.privateTypes[unit.receiverType] {
				unit.tainted[unit.receiverName] = true
			}
		}
		for index, name := range unit.parameterNames {
			if analyzer.typeContainsPrivate(unit.parameterTypes[index]) {
				unit.tainted[name] = true
			}
		}
		for index, resultType := range unit.resultTypes {
			if analyzer.typeContainsPrivate(resultType) {
				unit.returnTainted[index] = true
			}
		}
	}
}

func (analyzer *resolvedPlanPrivacyAnalyzer) typeContainsPrivate(expression ast.Expr) bool {
	found := false
	ast.Inspect(expression, func(node ast.Node) bool {
		identifier, ok := node.(*ast.Ident)
		if ok && analyzer.privateTypes[identifier.Name] {
			found = true
			return false
		}
		return !found
	})
	return found
}

func resolvedPlanPrivacyTypeName(file *resolvedPlanPrivacyFile, expression ast.Expr) string {
	switch typed := expression.(type) {
	case *ast.Ident:
		return typed.Name
	case *ast.StarExpr:
		return resolvedPlanPrivacyTypeName(file, typed.X)
	case *ast.SelectorExpr:
		if identifier, ok := typed.X.(*ast.Ident); ok {
			prefix := identifier.Name
			if importPath := file.imports[prefix]; importPath != "" {
				prefix = importPath
			}
			return prefix + "." + typed.Sel.Name
		}
		return typed.Sel.Name
	case *ast.ArrayType:
		return "[]" + resolvedPlanPrivacyTypeName(file, typed.Elt)
	case *ast.MapType:
		return "map"
	case *ast.InterfaceType:
		return "interface"
	case *ast.FuncType:
		return "func"
	default:
		return ""
	}
}

func (analyzer *resolvedPlanPrivacyAnalyzer) addFinding(file string, function string, kind string) {
	prefix := file
	if function != "" {
		prefix += ":" + function
	}
	analyzer.findings[prefix+":"+kind] = true
}

func (analyzer *resolvedPlanPrivacyAnalyzer) sortedFindings() []string {
	findings := make([]string, 0, len(analyzer.findings))
	for finding := range analyzer.findings {
		findings = append(findings, finding)
	}
	sort.Strings(findings)
	return findings
}

func (analyzer *resolvedPlanPrivacyAnalyzer) runFixedPoint() {
	keys := make([]string, 0, len(analyzer.functions))
	for key := range analyzer.functions {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for iteration := 0; iteration < 256; iteration++ {
		changed := false
		analyzer.flowChanged = false
		for _, key := range keys {
			if analyzer.analyzeFunction(analyzer.functions[key]) {
				changed = true
			}
		}
		changed = changed || analyzer.flowChanged
		if !changed {
			return
		}
	}
	analyzer.addFinding("package", "", "privacy-flow-fixed-point-not-reached")
}

func (analyzer *resolvedPlanPrivacyAnalyzer) analyzeFunction(unit *resolvedPlanPrivacyFunction) bool {
	changed := false
	ast.Inspect(unit.body, func(node ast.Node) bool {
		if literal, ok := node.(*ast.FuncLit); ok {
			changed = analyzer.propagateClosureCaptures(unit, literal) || changed
			return false
		}
		switch typed := node.(type) {
		case *ast.ValueSpec:
			var values []resolvedPlanPrivacyValue
			if len(typed.Values) == 1 {
				values = analyzer.evaluateExpressionValues(unit, typed.Values[0])
			} else {
				for _, expression := range typed.Values {
					values = append(values, analyzer.evaluateExpression(unit, expression))
				}
			}
			for index, name := range typed.Names {
				if name.Name == "_" {
					continue
				}
				if typed.Type != nil {
					changed = analyzer.setVariableType(unit, name.Name, resolvedPlanPrivacyTypeName(unit.file, typed.Type)) || changed
					if analyzer.typeContainsPrivate(typed.Type) {
						changed = analyzer.setTainted(unit, name.Name) || changed
					}
				}
				if len(values) == 0 {
					continue
				}
				valueIndex := index
				if len(values) == 1 {
					valueIndex = 0
				}
				if valueIndex < len(values) {
					if values[valueIndex].tainted && typed.Type != nil && analyzer.typeContainsInterface(typed.Type) {
						analyzer.addFinding(unit.file.name, unit.name, "interface-variable-boundary")
					}
					changed = analyzer.assignIdentifier(unit, name.Name, values[valueIndex]) || changed
				}
			}
		case *ast.AssignStmt:
			var values []resolvedPlanPrivacyValue
			if len(typed.Rhs) == 1 {
				values = analyzer.evaluateExpressionValues(unit, typed.Rhs[0])
			} else {
				for _, expression := range typed.Rhs {
					values = append(values, analyzer.evaluateExpression(unit, expression))
				}
			}
			for index, left := range typed.Lhs {
				if len(values) == 0 {
					continue
				}
				valueIndex := index
				if len(values) == 1 {
					valueIndex = 0
				}
				if valueIndex >= len(values) {
					valueIndex = len(values) - 1
				}
				changed = analyzer.assignExpression(unit, left, values[valueIndex]) || changed
			}
		case *ast.RangeStmt:
			collection := analyzer.evaluateExpression(unit, typed.X)
			if name, ok := assignedIdentifierName(typed.Key); ok && collection.tainted {
				changed = analyzer.setSafe(unit, name, "index") || changed
			}
			if name, ok := assignedIdentifierName(typed.Value); ok {
				if collection.tainted {
					changed = analyzer.setTainted(unit, name) || changed
				}
			}
		case *ast.ReturnStmt:
			for index, expression := range typed.Results {
				value := analyzer.evaluateExpression(unit, expression)
				if value.callable != nil && value.callable.capturesPrivateMaterial {
					analyzer.addFinding(unit.file.name, unit.name, "private-closure-return")
				}
				if value.tainted {
					changed = analyzer.setReturnTainted(unit, index) || changed
				} else if value.safe != "" {
					changed = analyzer.setReturnSafe(unit, index, value.safe) || changed
				}
			}
		case *ast.CallExpr:
			analyzer.evaluateExpression(unit, typed)
		}
		return true
	})
	return changed
}

func (analyzer *resolvedPlanPrivacyAnalyzer) evaluateExpressionValues(unit *resolvedPlanPrivacyFunction, expression ast.Expr) []resolvedPlanPrivacyValue {
	value := analyzer.evaluateExpression(unit, expression)
	call, ok := expression.(*ast.CallExpr)
	if !ok {
		return []resolvedPlanPrivacyValue{value}
	}
	callable := analyzer.evaluateExpression(unit, call.Fun).callable
	if callable == nil || callable.kind != "local" {
		return []resolvedPlanPrivacyValue{value}
	}
	target := analyzer.functions[callable.localKey]
	if target == nil || len(target.returnTainted) <= 1 {
		return []resolvedPlanPrivacyValue{value}
	}
	arguments := analyzer.evaluateArguments(unit, call.Args)
	callCarriesPrivate := callable.boundReceiverTainted || callable.capturesPrivateMaterial || resolvedPlanPrivacyAnyTainted(arguments)
	callCarriesSafe := callable.boundReceiverSafe != "" || resolvedPlanPrivacyAnyDerivedSafe(arguments)
	values := make([]resolvedPlanPrivacyValue, len(target.returnTainted))
	for index := range values {
		intrinsicallyPrivate := index < len(target.resultTypes) && analyzer.typeContainsPrivate(target.resultTypes[index])
		values[index].tainted = target.returnTainted[index] && (intrinsicallyPrivate || callCarriesPrivate)
		if (callCarriesPrivate || callCarriesSafe) && target.returnSafe[index] != "conflict" {
			values[index].safe = target.returnSafe[index]
		}
		if index < len(target.resultTypes) {
			values[index].typeName = resolvedPlanPrivacyTypeName(target.file, target.resultTypes[index])
		}
	}
	return values
}

func (analyzer *resolvedPlanPrivacyAnalyzer) propagateClosureCaptures(parent *resolvedPlanPrivacyFunction, literal *ast.FuncLit) bool {
	key := analyzer.closures[literal]
	closure := analyzer.functions[key]
	if closure == nil {
		return false
	}
	changed := false
	for name := range parent.tainted {
		if resolvedPlanPrivacyNodeMentionsIdentifier(literal.Body, name) {
			changed = analyzer.setTainted(closure, name) || changed
		}
	}
	for name, safe := range parent.safe {
		if resolvedPlanPrivacyNodeMentionsIdentifier(literal.Body, name) {
			changed = analyzer.setSafe(closure, name, safe) || changed
		}
	}
	for name, typeName := range parent.variableTypes {
		if resolvedPlanPrivacyNodeMentionsIdentifier(literal.Body, name) {
			changed = analyzer.setVariableType(closure, name, typeName) || changed
		}
	}
	for name, callable := range parent.callables {
		if resolvedPlanPrivacyNodeMentionsIdentifier(literal.Body, name) {
			changed = analyzer.setCallable(closure, name, callable) || changed
		}
	}
	return changed
}

func resolvedPlanPrivacyNodeMentionsIdentifier(node ast.Node, name string) bool {
	found := false
	ast.Inspect(node, func(candidate ast.Node) bool {
		identifier, ok := candidate.(*ast.Ident)
		if ok && identifier.Name == name {
			found = true
			return false
		}
		return !found
	})
	return found
}

func (analyzer *resolvedPlanPrivacyAnalyzer) assignExpression(unit *resolvedPlanPrivacyFunction, expression ast.Expr, value resolvedPlanPrivacyValue) bool {
	if name, ok := assignedIdentifierName(expression); ok {
		return analyzer.assignIdentifier(unit, name, value)
	}
	if !value.tainted {
		return false
	}
	root := resolvedPlanPrivacyRootIdentifier(expression)
	if root == "" {
		return false
	}
	return analyzer.setTainted(unit, root)
}

func resolvedPlanPrivacyRootIdentifier(expression ast.Expr) string {
	switch typed := expression.(type) {
	case *ast.Ident:
		return typed.Name
	case *ast.SelectorExpr:
		return resolvedPlanPrivacyRootIdentifier(typed.X)
	case *ast.IndexExpr:
		return resolvedPlanPrivacyRootIdentifier(typed.X)
	case *ast.StarExpr:
		return resolvedPlanPrivacyRootIdentifier(typed.X)
	case *ast.ParenExpr:
		return resolvedPlanPrivacyRootIdentifier(typed.X)
	default:
		return ""
	}
}

func (analyzer *resolvedPlanPrivacyAnalyzer) assignIdentifier(unit *resolvedPlanPrivacyFunction, name string, value resolvedPlanPrivacyValue) bool {
	if name == "_" {
		return false
	}
	changed := false
	declaredType := unit.variableTypes[name]
	if declaredType == "" {
		declaredType = analyzer.globalTypes[name]
	}
	if value.tainted {
		if analyzer.typeNameIsInterface(declaredType) {
			analyzer.addFinding(unit.file.name, unit.name, "interface-variable-boundary")
		}
		if _, global := analyzer.globalTypes[name]; global && unit.variableTypes[name] == "" && !analyzer.globalTainted[name] {
			analyzer.globalTainted[name] = true
			changed = true
		}
		changed = analyzer.setTainted(unit, name) || changed
	} else if value.safe != "" {
		changed = analyzer.setSafe(unit, name, value.safe) || changed
	}
	if value.typeName != "" {
		changed = analyzer.setVariableType(unit, name, value.typeName) || changed
	}
	if value.callable != nil {
		changed = analyzer.setCallable(unit, name, value.callable) || changed
	}
	return changed
}

func (analyzer *resolvedPlanPrivacyAnalyzer) typeNameIsInterface(typeName string) bool {
	if typeName == "any" || typeName == "interface" {
		return true
	}
	underlying := analyzer.typeSpecs[typeName]
	return underlying != nil && analyzer.typeContainsInterface(underlying)
}

func (analyzer *resolvedPlanPrivacyAnalyzer) setTainted(unit *resolvedPlanPrivacyFunction, name string) bool {
	if name == "" || name == "_" || unit.tainted[name] {
		return false
	}
	unit.tainted[name] = true
	delete(unit.safe, name)
	return true
}

func (analyzer *resolvedPlanPrivacyAnalyzer) setSafe(unit *resolvedPlanPrivacyFunction, name string, safe string) bool {
	if name == "" || name == "_" || safe == "" || unit.tainted[name] {
		return false
	}
	if existing := unit.safe[name]; existing == safe || existing == "conflict" {
		return false
	} else if existing != "" && existing != safe {
		unit.safe[name] = "conflict"
		return true
	}
	unit.safe[name] = safe
	return true
}

func (analyzer *resolvedPlanPrivacyAnalyzer) setVariableType(unit *resolvedPlanPrivacyFunction, name string, typeName string) bool {
	if name == "" || name == "_" || typeName == "" || unit.variableTypes[name] == typeName {
		return false
	}
	if existing := unit.variableTypes[name]; existing == "interface" {
		return false
	} else if existing != "" && existing != typeName {
		unit.variableTypes[name] = "interface"
		return true
	}
	unit.variableTypes[name] = typeName
	return true
}

func (analyzer *resolvedPlanPrivacyAnalyzer) setCallable(unit *resolvedPlanPrivacyFunction, name string, callable *resolvedPlanPrivacyCallable) bool {
	if name == "" || name == "_" || callable == nil {
		return false
	}
	existing := unit.callables[name]
	if resolvedPlanPrivacyCallablesEqual(existing, callable) {
		return false
	}
	if existing != nil {
		if existing.kind == "unresolved" {
			if callable.capturesPrivateMaterial && !existing.capturesPrivateMaterial {
				existing.capturesPrivateMaterial = true
				return true
			}
			return false
		}
		unit.callables[name] = &resolvedPlanPrivacyCallable{kind: "unresolved", name: name, capturesPrivateMaterial: existing.capturesPrivateMaterial || callable.capturesPrivateMaterial}
		return true
	}
	copyValue := *callable
	unit.callables[name] = &copyValue
	return true
}

func resolvedPlanPrivacyCallablesEqual(left *resolvedPlanPrivacyCallable, right *resolvedPlanPrivacyCallable) bool {
	if left == nil || right == nil {
		return left == right
	}
	return *left == *right
}

func (analyzer *resolvedPlanPrivacyAnalyzer) setReturnTainted(unit *resolvedPlanPrivacyFunction, index int) bool {
	if len(unit.returnTainted) == 0 {
		return false
	}
	if index >= len(unit.returnTainted) {
		index = len(unit.returnTainted) - 1
	}
	if unit.returnTainted[index] {
		return false
	}
	unit.returnTainted[index] = true
	unit.returnSafe[index] = ""
	return true
}

func (analyzer *resolvedPlanPrivacyAnalyzer) setReturnSafe(unit *resolvedPlanPrivacyFunction, index int, safe string) bool {
	if len(unit.returnSafe) == 0 || safe == "" {
		return false
	}
	if index >= len(unit.returnSafe) {
		index = len(unit.returnSafe) - 1
	}
	if unit.returnTainted[index] || unit.returnSafe[index] == safe {
		return false
	}
	if unit.returnSafe[index] == "conflict" {
		return false
	}
	if unit.returnSafe[index] != "" && unit.returnSafe[index] != safe {
		unit.returnSafe[index] = "conflict"
		return true
	}
	unit.returnSafe[index] = safe
	return true
}

func (analyzer *resolvedPlanPrivacyAnalyzer) evaluateExpression(unit *resolvedPlanPrivacyFunction, expression ast.Expr) resolvedPlanPrivacyValue {
	if expression == nil {
		return resolvedPlanPrivacyValue{}
	}
	switch typed := expression.(type) {
	case *ast.Ident:
		if unit.tainted[typed.Name] {
			return resolvedPlanPrivacyValue{tainted: true, typeName: unit.variableTypes[typed.Name]}
		}
		if safe := unit.safe[typed.Name]; safe != "" && safe != "conflict" {
			return resolvedPlanPrivacyValue{safe: safe, typeName: unit.variableTypes[typed.Name]}
		}
		if callable := unit.callables[typed.Name]; callable != nil {
			return resolvedPlanPrivacyValue{callable: callable, typeName: "func"}
		}
		if key := analyzer.functionNames[typed.Name]; key != "" {
			return resolvedPlanPrivacyValue{callable: &resolvedPlanPrivacyCallable{kind: "local", localKey: key, name: typed.Name}, typeName: "func"}
		}
		if analyzer.globalTainted[typed.Name] {
			return resolvedPlanPrivacyValue{tainted: true, typeName: analyzer.globalTypes[typed.Name]}
		}
		for importPath := range unit.file.dotImports {
			if resolvedPlanPrivacyExternalFunctionKnown(importPath, typed.Name) {
				return resolvedPlanPrivacyValue{callable: &resolvedPlanPrivacyCallable{kind: "external", packagePath: importPath, name: typed.Name}, typeName: "func"}
			}
		}
		switch typed.Name {
		case "true", "false":
			return resolvedPlanPrivacyValue{typeName: "bool"}
		}
		return resolvedPlanPrivacyValue{typeName: unit.variableTypes[typed.Name]}
	case *ast.BasicLit:
		switch typed.Kind {
		case token.STRING:
			return resolvedPlanPrivacyValue{safe: "static", typeName: "string"}
		case token.INT:
			return resolvedPlanPrivacyValue{typeName: "int"}
		default:
			return resolvedPlanPrivacyValue{}
		}
	case *ast.ParenExpr:
		return analyzer.evaluateExpression(unit, typed.X)
	case *ast.SelectorExpr:
		if identifier, ok := typed.X.(*ast.Ident); ok {
			if importPath := unit.file.imports[identifier.Name]; importPath != "" {
				return resolvedPlanPrivacyValue{callable: &resolvedPlanPrivacyCallable{kind: "external", packagePath: importPath, name: typed.Sel.Name}, typeName: "func"}
			}
			if analyzer.typeSpecs[identifier.Name] != nil {
				if key := analyzer.methods[identifier.Name+"."+typed.Sel.Name]; key != "" {
					return resolvedPlanPrivacyValue{callable: &resolvedPlanPrivacyCallable{kind: "local", localKey: key, name: typed.Sel.Name, methodExpression: true}, typeName: "func"}
				}
			}
		}
		receiver := analyzer.evaluateExpression(unit, typed.X)
		receiverType := receiver.typeName
		fieldType := analyzer.resolvedPlanPrivacyFieldType(receiverType, typed.Sel.Name)
		if key := analyzer.methods[resolvedPlanPrivacyTrimType(receiverType)+"."+typed.Sel.Name]; key != "" {
			return resolvedPlanPrivacyValue{callable: &resolvedPlanPrivacyCallable{
				kind:                    "local",
				localKey:                key,
				name:                    typed.Sel.Name,
				boundReceiver:           true,
				boundReceiverTainted:    receiver.tainted,
				boundReceiverSafe:       receiver.safe,
				boundReceiverType:       receiverType,
				capturesPrivateMaterial: receiver.tainted,
			}, typeName: "func"}
		}
		if resolvedPlanPrivacyIsTestingType(receiverType) && resolvedPlanPrivacyTestingMethod(typed.Sel.Name) {
			return resolvedPlanPrivacyValue{callable: &resolvedPlanPrivacyCallable{kind: "testing", packagePath: "testing", name: typed.Sel.Name, boundReceiver: true}, typeName: "func"}
		}
		if resolvedPlanPrivacyReceiverMethodIsKnownSink(receiverType, typed.Sel.Name) {
			return resolvedPlanPrivacyValue{callable: &resolvedPlanPrivacyCallable{kind: "external", packagePath: resolvedPlanPrivacyReceiverPackage(receiverType), name: typed.Sel.Name, boundReceiver: true}, typeName: "func"}
		}
		if receiver.tainted {
			return resolvedPlanPrivacyValue{tainted: true, typeName: fieldType}
		}
		return resolvedPlanPrivacyValue{typeName: fieldType}
	case *ast.IndexExpr:
		collection := analyzer.evaluateExpression(unit, typed.X)
		analyzer.evaluateExpression(unit, typed.Index)
		return resolvedPlanPrivacyValue{tainted: collection.tainted}
	case *ast.IndexListExpr:
		value := analyzer.evaluateExpression(unit, typed.X)
		for _, index := range typed.Indices {
			analyzer.evaluateExpression(unit, index)
		}
		return value
	case *ast.SliceExpr:
		collection := analyzer.evaluateExpression(unit, typed.X)
		analyzer.evaluateExpression(unit, typed.Low)
		analyzer.evaluateExpression(unit, typed.High)
		analyzer.evaluateExpression(unit, typed.Max)
		return resolvedPlanPrivacyValue{tainted: collection.tainted}
	case *ast.StarExpr:
		return analyzer.evaluateExpression(unit, typed.X)
	case *ast.UnaryExpr:
		value := analyzer.evaluateExpression(unit, typed.X)
		if typed.Op == token.NOT && value.safe == "bool" {
			return resolvedPlanPrivacyValue{safe: "bool", typeName: "bool"}
		}
		return value
	case *ast.BinaryExpr:
		left := analyzer.evaluateExpression(unit, typed.X)
		right := analyzer.evaluateExpression(unit, typed.Y)
		if resolvedPlanPrivacyComparisonOperator(typed.Op) {
			if left.tainted || right.tainted || resolvedPlanPrivacyValueIsDerivedSafe(left) || resolvedPlanPrivacyValueIsDerivedSafe(right) {
				return resolvedPlanPrivacyValue{safe: "bool", typeName: "bool"}
			}
			return resolvedPlanPrivacyValue{typeName: "bool"}
		}
		if left.tainted || right.tainted {
			return resolvedPlanPrivacyValue{tainted: true}
		}
		if left.safe == right.safe {
			return resolvedPlanPrivacyValue{safe: left.safe}
		}
		return resolvedPlanPrivacyValue{}
	case *ast.TypeAssertExpr:
		return analyzer.evaluateExpression(unit, typed.X)
	case *ast.CompositeLit:
		value := resolvedPlanPrivacyValue{typeName: resolvedPlanPrivacyTypeName(unit.file, typed.Type)}
		for _, rawElement := range typed.Elts {
			var elementValue resolvedPlanPrivacyValue
			switch element := rawElement.(type) {
			case *ast.KeyValueExpr:
				elementValue = analyzer.evaluateExpression(unit, element.Value)
			case ast.Expr:
				elementValue = analyzer.evaluateExpression(unit, element)
			}
			value.tainted = value.tainted || elementValue.tainted || resolvedPlanPrivacyValueIsDerivedSafe(elementValue)
		}
		if value.tainted && analyzer.typeContainsInterface(typed.Type) && !resolvedPlanPrivacyAuthorizedMaterializationBoundary(unit) {
			analyzer.addFinding(unit.file.name, unit.name, "interface-container-boundary")
		}
		return value
	case *ast.FuncLit:
		key := analyzer.closures[typed]
		closure := analyzer.functions[key]
		captures := false
		if closure != nil {
			for name := range closure.tainted {
				if resolvedPlanPrivacyNodeMentionsIdentifier(typed.Body, name) {
					captures = true
					break
				}
			}
		}
		return resolvedPlanPrivacyValue{callable: &resolvedPlanPrivacyCallable{kind: "local", localKey: key, name: "closure", capturesPrivateMaterial: captures}, typeName: "func"}
	case *ast.CallExpr:
		return analyzer.evaluateCall(unit, typed)
	default:
		return resolvedPlanPrivacyValue{}
	}
}

func resolvedPlanPrivacyComparisonOperator(operator token.Token) bool {
	switch operator {
	case token.EQL, token.NEQ, token.LSS, token.LEQ, token.GTR, token.GEQ:
		return true
	default:
		return false
	}
}

func resolvedPlanPrivacyTrimType(typeName string) string {
	return strings.TrimPrefix(strings.TrimPrefix(typeName, "*"), "[]")
}

func resolvedPlanPrivacyIsTestingType(typeName string) bool {
	typeName = resolvedPlanPrivacyTrimType(typeName)
	switch typeName {
	case "testing.T", "testing.B", "testing.F", "testing.TB":
		return true
	default:
		return false
	}
}

func resolvedPlanPrivacyTestingMethod(name string) bool {
	switch name {
	case "Log", "Logf", "Error", "Errorf", "Fatal", "Fatalf", "Skip", "Skipf":
		return true
	default:
		return false
	}
}

func resolvedPlanPrivacyReceiverPackage(typeName string) string {
	typeName = resolvedPlanPrivacyTrimType(typeName)
	if index := strings.LastIndex(typeName, "."); index >= 0 {
		return typeName[:index]
	}
	return ""
}

func resolvedPlanPrivacyReceiverMethodIsKnownSink(typeName string, method string) bool {
	packageName := resolvedPlanPrivacyReceiverPackage(typeName)
	switch packageName {
	case "log":
		return resolvedPlanPrivacyLogMethod(method)
	case "log/slog", "slog":
		return resolvedPlanPrivacySlogMethod(method)
	case "encoding/json", "json", "encoding/xml", "xml":
		return method == "Encode"
	}
	return false
}

func (analyzer *resolvedPlanPrivacyAnalyzer) resolvedPlanPrivacyFieldType(receiverType string, selector string) string {
	base := resolvedPlanPrivacyTrimType(receiverType)
	return analyzer.structFields[base][selector]
}

func resolvedPlanPrivacyExternalFunctionKnown(importPath string, name string) bool {
	switch importPath {
	case "fmt":
		return resolvedPlanPrivacyFmtFunction(name)
	case "log":
		return resolvedPlanPrivacyLogMethod(name) || name == "New"
	case "log/slog":
		return resolvedPlanPrivacySlogFunction(name) || name == "New"
	case "encoding/json":
		return name == "Marshal" || name == "MarshalIndent" || name == "NewEncoder"
	case "encoding/xml":
		return name == "Marshal" || name == "NewEncoder"
	case "reflect":
		return name == "ValueOf" || name == "TypeOf" || name == "Indirect" || name == "VisibleFields"
	default:
		return false
	}
}

func (analyzer *resolvedPlanPrivacyAnalyzer) evaluateCall(unit *resolvedPlanPrivacyFunction, call *ast.CallExpr) resolvedPlanPrivacyValue {
	if analyzer.isInterfaceConversion(call.Fun) {
		value := resolvedPlanPrivacyValue{}
		for _, argument := range call.Args {
			argumentValue := analyzer.evaluateExpression(unit, argument)
			if argumentValue.tainted {
				analyzer.addFinding(unit.file.name, unit.name, "interface-conversion")
				value.tainted = true
			} else if value.safe == "" && argumentValue.safe != "" {
				value.safe = argumentValue.safe
			}
		}
		return value
	}
	if analyzer.isTypeConversion(call.Fun) {
		value := resolvedPlanPrivacyValue{typeName: resolvedPlanPrivacyTypeName(unit.file, call.Fun)}
		for _, argument := range call.Args {
			argumentValue := analyzer.evaluateExpression(unit, argument)
			value.tainted = value.tainted || argumentValue.tainted
			if value.safe == "" && argumentValue.safe != "" {
				value.safe = argumentValue.safe
			}
		}
		return value
	}
	if identifier, ok := call.Fun.(*ast.Ident); ok {
		switch identifier.Name {
		case "len", "cap":
			derived := false
			for _, argument := range call.Args {
				value := analyzer.evaluateExpression(unit, argument)
				derived = derived || value.tainted || value.safe != ""
			}
			if derived {
				return resolvedPlanPrivacyValue{safe: "count", typeName: "int"}
			}
			return resolvedPlanPrivacyValue{typeName: "int"}
		case "append":
			result := resolvedPlanPrivacyValue{}
			for _, argument := range call.Args {
				value := analyzer.evaluateExpression(unit, argument)
				result.tainted = result.tainted || value.tainted || resolvedPlanPrivacyValueIsDerivedSafe(value)
			}
			return result
		case "copy":
			derived := false
			for _, argument := range call.Args {
				value := analyzer.evaluateExpression(unit, argument)
				derived = derived || value.tainted || value.safe != ""
			}
			if derived {
				return resolvedPlanPrivacyValue{safe: "count", typeName: "int"}
			}
			return resolvedPlanPrivacyValue{typeName: "int"}
		case "print", "println", "panic":
			arguments := analyzer.evaluateArguments(unit, call.Args)
			if resolvedPlanPrivacyAnyTainted(arguments) {
				analyzer.addFinding(unit.file.name, unit.name, "builtin-output:"+identifier.Name)
			}
			return resolvedPlanPrivacyValue{tainted: resolvedPlanPrivacyAnyTainted(arguments)}
		case "new":
			if len(call.Args) == 1 {
				return resolvedPlanPrivacyValue{typeName: resolvedPlanPrivacyTypeName(unit.file, call.Args[0])}
			}
		case "make":
			return resolvedPlanPrivacyValue{}
		}
	}
	callableValue := analyzer.evaluateExpression(unit, call.Fun)
	arguments := analyzer.evaluateArguments(unit, call.Args)
	callable := callableValue.callable
	if callable == nil {
		callable = &resolvedPlanPrivacyCallable{
			kind:                 "unresolved",
			name:                 sourceForNodeText(analyzer.fileSet, call.Fun),
			boundReceiverTainted: callableValue.tainted,
			boundReceiverSafe:    callableValue.safe,
			boundReceiverType:    callableValue.typeName,
			methodExpression:     false,
			boundReceiver:        callableValue.tainted || callableValue.safe != "",
		}
	}
	return analyzer.invokeCallable(unit, callable, call, arguments)
}

func (analyzer *resolvedPlanPrivacyAnalyzer) evaluateArguments(unit *resolvedPlanPrivacyFunction, arguments []ast.Expr) []resolvedPlanPrivacyValue {
	values := make([]resolvedPlanPrivacyValue, len(arguments))
	for index, argument := range arguments {
		values[index] = analyzer.evaluateExpression(unit, argument)
	}
	return values
}

func (analyzer *resolvedPlanPrivacyAnalyzer) isInterfaceConversion(expression ast.Expr) bool {
	switch typed := expression.(type) {
	case *ast.InterfaceType:
		return true
	case *ast.Ident:
		if typed.Name == "any" || typed.Name == "interface{}" {
			return true
		}
		underlying := analyzer.typeSpecs[typed.Name]
		return underlying != nil && analyzer.typeContainsInterface(underlying)
	default:
		return false
	}
}

func (analyzer *resolvedPlanPrivacyAnalyzer) isTypeConversion(expression ast.Expr) bool {
	switch typed := expression.(type) {
	case *ast.Ident:
		if analyzer.typeSpecs[typed.Name] != nil {
			return true
		}
		switch typed.Name {
		case "string", "[]byte", "int", "int64", "uint", "uint64", "bool", "error":
			return true
		}
	case *ast.ArrayType, *ast.MapType, *ast.ChanType, *ast.FuncType, *ast.StarExpr:
		return true
	}
	return false
}

func sourceForNodeText(fileSet *token.FileSet, node ast.Node) string {
	var buffer bytes.Buffer
	if err := printer.Fprint(&buffer, fileSet, node); err != nil {
		return "unprintable"
	}
	return buffer.String()
}

func resolvedPlanPrivacyAnyTainted(values []resolvedPlanPrivacyValue) bool {
	for _, value := range values {
		if value.tainted {
			return true
		}
	}
	return false
}

func (analyzer *resolvedPlanPrivacyAnalyzer) invokeCallable(unit *resolvedPlanPrivacyFunction, callable *resolvedPlanPrivacyCallable, call *ast.CallExpr, arguments []resolvedPlanPrivacyValue) resolvedPlanPrivacyValue {
	switch callable.kind {
	case "local":
		return analyzer.invokeLocalFunction(unit, callable, arguments)
	case "testing":
		analyzer.inspectTestingSink(unit, callable.name, call, arguments)
		return resolvedPlanPrivacyValue{}
	case "external":
		return analyzer.invokeExternalFunction(unit, callable, call, arguments)
	default:
		if callable.boundReceiverTainted || callable.capturesPrivateMaterial || resolvedPlanPrivacyAnyTainted(arguments) {
			analyzer.addFinding(unit.file.name, unit.name, "unresolved-private-call")
			return resolvedPlanPrivacyValue{tainted: true}
		}
		return resolvedPlanPrivacyValue{}
	}
}

func (analyzer *resolvedPlanPrivacyAnalyzer) invokeLocalFunction(caller *resolvedPlanPrivacyFunction, callable *resolvedPlanPrivacyCallable, arguments []resolvedPlanPrivacyValue) resolvedPlanPrivacyValue {
	target := analyzer.functions[callable.localKey]
	if target == nil {
		if callable.boundReceiverTainted || callable.capturesPrivateMaterial || resolvedPlanPrivacyAnyTainted(arguments) {
			analyzer.addFinding(caller.file.name, caller.name, "unresolved-private-call")
			return resolvedPlanPrivacyValue{tainted: true}
		}
		return resolvedPlanPrivacyValue{}
	}
	materializationBoundary := resolvedPlanPrivacyAuthorizedMaterializationBoundary(target)
	callerMaterializationBoundary := resolvedPlanPrivacyAuthorizedMaterializationBoundary(caller)
	values := append([]resolvedPlanPrivacyValue{}, arguments...)
	if target.receiverName != "" {
		receiver := resolvedPlanPrivacyValue{}
		if callable.boundReceiver {
			receiver = resolvedPlanPrivacyValue{tainted: callable.boundReceiverTainted, safe: callable.boundReceiverSafe, typeName: callable.boundReceiverType}
		} else if callable.methodExpression && len(values) > 0 {
			receiver = values[0]
			values = values[1:]
		}
		if !callerMaterializationBoundary {
			analyzer.propagateArgument(caller, target, target.receiverName, nil, receiver)
		}
	}
	for index, value := range values {
		if len(target.parameterNames) == 0 {
			if value.tainted {
				analyzer.addFinding(caller.file.name, caller.name, "unresolved-private-call")
			}
			continue
		}
		parameterIndex := index
		if parameterIndex >= len(target.parameterNames) {
			parameterIndex = len(target.parameterNames) - 1
		}
		parameterName := target.parameterNames[parameterIndex]
		var parameterType ast.Expr
		if parameterIndex < len(target.parameterTypes) {
			parameterType = target.parameterTypes[parameterIndex]
		}
		if !callerMaterializationBoundary {
			analyzer.propagateArgument(caller, target, parameterName, parameterType, value)
		}
	}
	result := resolvedPlanPrivacyValue{}
	if materializationBoundary || callerMaterializationBoundary {
		if len(target.resultTypes) > 0 {
			result.typeName = resolvedPlanPrivacyTypeName(target.file, target.resultTypes[0])
		}
		return result
	}
	callCarriesPrivate := callable.boundReceiverTainted || callable.capturesPrivateMaterial || resolvedPlanPrivacyAnyTainted(arguments)
	callCarriesSafe := callable.boundReceiverSafe != "" || resolvedPlanPrivacyAnyDerivedSafe(arguments)
	for index := range target.returnTainted {
		intrinsicallyPrivate := index < len(target.resultTypes) && analyzer.typeContainsPrivate(target.resultTypes[index])
		if target.returnTainted[index] && (intrinsicallyPrivate || callCarriesPrivate) {
			result.tainted = true
		}
		if (callCarriesPrivate || callCarriesSafe) && result.safe == "" && target.returnSafe[index] != "" && target.returnSafe[index] != "conflict" {
			result.safe = target.returnSafe[index]
		}
		if result.typeName == "" && index < len(target.resultTypes) {
			result.typeName = resolvedPlanPrivacyTypeName(target.file, target.resultTypes[index])
		}
	}
	return result
}

// These exact existing functions are the resolved plan's governed runtime
// materialization consumers. They may consume private fields, but their outputs
// are not diagnostic declassifications and must not make every downstream
// runtime value appear printable. Flow is propagated into each boundary so its
// direct sinks and closures remain guarded, then stops at its downstream runtime
// materialization calls. Private-typed parameters are also seeded independently.
func resolvedPlanPrivacyAuthorizedMaterializationBoundary(target *resolvedPlanPrivacyFunction) bool {
	if target == nil {
		return false
	}
	key := target.file.name + ":" + target.name
	switch key {
	case "authorityhandoff.go:buildExecutionAuthorityHandoff",
		"authorityhandoff.go:executionAuthorityMetadata",
		"mounts.go:stageRuntimeMounts",
		"submit.go:buildNomadJobSpec",
		"submit.go:buildRuntimeEnvironment",
		"submit.go:fetchPayloadBytes",
		"executionpackage.go:stageWorkloadVaultTrustMaterial":
		return true
	default:
		return false
	}
}

func (analyzer *resolvedPlanPrivacyAnalyzer) propagateArgument(caller *resolvedPlanPrivacyFunction, target *resolvedPlanPrivacyFunction, parameterName string, parameterType ast.Expr, value resolvedPlanPrivacyValue) {
	if value.tainted {
		analyzer.flowChanged = analyzer.setTainted(target, parameterName) || analyzer.flowChanged
		if parameterType != nil && analyzer.isInterfaceType(parameterType) {
			analyzer.addFinding(caller.file.name, caller.name, "interface-parameter-boundary")
		}
	} else if value.safe != "" {
		analyzer.flowChanged = analyzer.setSafe(target, parameterName, value.safe) || analyzer.flowChanged
	}
	if value.typeName != "" && target.variableTypes[parameterName] == "" {
		analyzer.flowChanged = analyzer.setVariableType(target, parameterName, value.typeName) || analyzer.flowChanged
	}
	if value.callable != nil {
		analyzer.flowChanged = analyzer.setCallable(target, parameterName, value.callable) || analyzer.flowChanged
	}
}

func (analyzer *resolvedPlanPrivacyAnalyzer) isInterfaceType(expression ast.Expr) bool {
	switch typed := expression.(type) {
	case *ast.InterfaceType:
		return true
	case *ast.Ident:
		if typed.Name == "any" {
			return true
		}
		underlying := analyzer.typeSpecs[typed.Name]
		return underlying != nil && analyzer.typeContainsInterface(underlying)
	default:
		return false
	}
}

func (analyzer *resolvedPlanPrivacyAnalyzer) typeContainsInterface(expression ast.Expr) bool {
	return analyzer.typeContainsInterfaceWithVisited(expression, map[string]bool{})
}

func (analyzer *resolvedPlanPrivacyAnalyzer) typeContainsInterfaceWithVisited(expression ast.Expr, visited map[string]bool) bool {
	switch typed := expression.(type) {
	case *ast.InterfaceType:
		return true
	case *ast.Ident:
		if typed.Name == "any" {
			return true
		}
		if visited[typed.Name] {
			return false
		}
		visited[typed.Name] = true
		underlying := analyzer.typeSpecs[typed.Name]
		return underlying != nil && analyzer.typeContainsInterfaceWithVisited(underlying, visited)
	case *ast.ArrayType:
		return analyzer.typeContainsInterfaceWithVisited(typed.Elt, visited)
	case *ast.MapType:
		return analyzer.typeContainsInterfaceWithVisited(typed.Key, visited) || analyzer.typeContainsInterfaceWithVisited(typed.Value, visited)
	case *ast.StructType:
		for _, field := range typed.Fields.List {
			if analyzer.typeContainsInterfaceWithVisited(field.Type, visited) {
				return true
			}
		}
	}
	return false
}

func (analyzer *resolvedPlanPrivacyAnalyzer) inspectTestingSink(unit *resolvedPlanPrivacyFunction, name string, call *ast.CallExpr, arguments []resolvedPlanPrivacyValue) {
	if resolvedPlanPrivacyAnyTainted(arguments) {
		analyzer.addFinding(unit.file.name, unit.name, "testing-output:"+name)
		return
	}
	if !resolvedPlanPrivacyAnyDerivedSafe(arguments) {
		return
	}
	if strings.HasSuffix(name, "f") {
		if !resolvedPlanPrivacyStaticFormatAccepts(call.Args, arguments, 0) {
			analyzer.addFinding(unit.file.name, unit.name, "unsafe-safe-scalar-format:"+name)
		}
		return
	}
	analyzer.addFinding(unit.file.name, unit.name, "safe-scalar-without-static-format:"+name)
}

func resolvedPlanPrivacyAnyDerivedSafe(values []resolvedPlanPrivacyValue) bool {
	for _, value := range values {
		if resolvedPlanPrivacyValueIsDerivedSafe(value) {
			return true
		}
	}
	return false
}

func resolvedPlanPrivacyValueIsDerivedSafe(value resolvedPlanPrivacyValue) bool {
	switch value.safe {
	case "count", "index", "bool":
		return true
	default:
		return false
	}
}

func resolvedPlanPrivacyStaticFormatAccepts(expressions []ast.Expr, values []resolvedPlanPrivacyValue, formatIndex int) bool {
	if formatIndex < 0 || formatIndex >= len(expressions) || formatIndex >= len(values) {
		return false
	}
	format, ok := stringLiteralValue(expressions[formatIndex])
	if !ok {
		return false
	}
	verbs := resolvedPlanPrivacyFormatVerbs(format)
	for index, value := range values[formatIndex+1:] {
		if index >= len(verbs) {
			if value.safe != "" {
				return false
			}
			continue
		}
		switch value.safe {
		case "count", "index":
			if verbs[index] != 'd' {
				return false
			}
		case "bool":
			if verbs[index] != 't' {
				return false
			}
		}
	}
	return true
}

func resolvedPlanPrivacyFormatVerbs(format string) []rune {
	var verbs []rune
	for index := 0; index < len(format); index++ {
		if format[index] != '%' {
			continue
		}
		index++
		if index >= len(format) {
			break
		}
		if format[index] == '%' {
			continue
		}
		for index < len(format) {
			character := format[index]
			if character == '[' || character == ']' || character == '#' || character == '0' || character == '+' || character == '-' || character == ' ' || character == '.' || character == '*' || (character >= '1' && character <= '9') {
				index++
				continue
			}
			verbs = append(verbs, rune(character))
			break
		}
	}
	return verbs
}

func (analyzer *resolvedPlanPrivacyAnalyzer) invokeExternalFunction(unit *resolvedPlanPrivacyFunction, callable *resolvedPlanPrivacyCallable, call *ast.CallExpr, arguments []resolvedPlanPrivacyValue) resolvedPlanPrivacyValue {
	packagePath := callable.packagePath
	name := callable.name
	if resolvedPlanPrivacyAnyTainted(arguments) || callable.boundReceiverTainted {
		kind := resolvedPlanPrivacyExternalSinkKind(packagePath, name)
		if kind != "" {
			analyzer.addFinding(unit.file.name, unit.name, kind+":"+name)
		} else if resolvedPlanPrivacyExternalAssertionCall(packagePath, name) {
			analyzer.addFinding(unit.file.name, unit.name, "external-generic-assertion:"+name)
		}
		return resolvedPlanPrivacyExternalReturnValue(packagePath, name, arguments)
	}
	if resolvedPlanPrivacyAnyDerivedSafe(arguments) {
		if packagePath == "testing" {
			analyzer.inspectTestingSink(unit, name, call, arguments)
		} else {
			analyzer.addFinding(unit.file.name, unit.name, "safe-scalar-non-test-output:"+name)
		}
	}
	result := resolvedPlanPrivacyValue{}
	switch packagePath {
	case "encoding/json":
		if name == "NewEncoder" {
			result.typeName = "encoding/json.Encoder"
		}
	case "encoding/xml":
		if name == "NewEncoder" {
			result.typeName = "encoding/xml.Encoder"
		}
	case "log":
		if name == "New" {
			result.typeName = "log.Logger"
		}
	case "log/slog":
		if name == "New" {
			result.typeName = "log/slog.Logger"
		}
	}
	return result
}

func resolvedPlanPrivacyExternalAssertionCall(packagePath string, name string) bool {
	base := path.Base(packagePath)
	switch base {
	case "assert", "require", "cmp":
		return true
	}
	switch name {
	case "Equal", "EqualValues", "Exactly", "ElementsMatch", "Diff", "Compare":
		return strings.Contains(packagePath, "assert") || strings.Contains(packagePath, "require") || strings.Contains(packagePath, "cmp")
	default:
		firstSegment := strings.Split(packagePath, "/")[0]
		return firstSegment == "example" || strings.Contains(firstSegment, ".")
	}
}

func resolvedPlanPrivacyExternalReturnValue(packagePath string, name string, arguments []resolvedPlanPrivacyValue) resolvedPlanPrivacyValue {
	tainted := resolvedPlanPrivacyAnyTainted(arguments)
	switch packagePath {
	case "strings", "bytes":
		switch name {
		case "Contains", "ContainsAny", "ContainsRune", "EqualFold", "HasPrefix", "HasSuffix":
			if tainted {
				return resolvedPlanPrivacyValue{safe: "bool", typeName: "bool"}
			}
			return resolvedPlanPrivacyValue{typeName: "bool"}
		default:
			return resolvedPlanPrivacyValue{tainted: tainted}
		}
	case "path", "path/filepath", "strconv":
		return resolvedPlanPrivacyValue{tainted: tainted}
	case "fmt", "log", "log/slog", "encoding/json", "encoding/xml", "reflect":
		return resolvedPlanPrivacyValue{tainted: tainted}
	default:
		return resolvedPlanPrivacyValue{tainted: tainted}
	}
}

func resolvedPlanPrivacyExternalSinkKind(packagePath string, name string) string {
	switch packagePath {
	case "fmt":
		if resolvedPlanPrivacyFmtFunction(name) {
			return "formatting"
		}
	case "log":
		if resolvedPlanPrivacyLogMethod(name) {
			return "standard-log"
		}
	case "log/slog":
		if resolvedPlanPrivacySlogFunction(name) || resolvedPlanPrivacySlogMethod(name) {
			return "structured-log"
		}
	case "encoding/json", "encoding/xml":
		return "serialization"
	case "reflect":
		return "reflection"
	case "testing":
		if resolvedPlanPrivacyTestingMethod(name) {
			return "testing-output"
		}
	}
	return ""
}

func resolvedPlanPrivacyFmtFunction(name string) bool {
	switch name {
	case "Print", "Println", "Printf", "Sprint", "Sprintln", "Sprintf", "Append", "Appendf", "Appendln", "Fprint", "Fprintln", "Fprintf", "Errorf":
		return true
	default:
		return false
	}
}

func resolvedPlanPrivacyLogMethod(name string) bool {
	switch name {
	case "Print", "Println", "Printf", "Fatal", "Fatalf", "Fatalln", "Panic", "Panicf", "Panicln":
		return true
	default:
		return false
	}
}

func resolvedPlanPrivacySlogFunction(name string) bool {
	switch name {
	case "Debug", "Info", "Warn", "Error", "Log", "LogAttrs", "Any", "Group":
		return true
	default:
		return false
	}
}

func resolvedPlanPrivacySlogMethod(name string) bool {
	switch name {
	case "Debug", "Info", "Warn", "Error", "Log", "LogAttrs":
		return true
	default:
		return false
	}
}
