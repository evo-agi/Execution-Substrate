package admission

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"testing"

	esconfig "execution-substrate/es/config"
	evidencev1 "execution-substrate/internal/contracts/evidence/v1"
	runtimeconfigv1 "execution-substrate/internal/contracts/runtimeconfig/v1"
)

const validWorkloadZoneVaultConfigBlob = `{"vault_config":{"address":"https://vault.internal:8200","auth_mount":"jwt","auth_role":"execution","jwt_audience":"vault"}}`

func TestResolvedExecutionPlanSourcePrivacyGuardrails(t *testing.T) {
	file := mustParseAdmissionSource(t, "resolved_execution_plan.go")
	source := mustReadAdmissionSource(t, "resolved_execution_plan.go")
	privateTypes := map[string]bool{
		"submitConfigSnapshot":            false,
		"resolvedTaskResources":           false,
		"resolvedRuntimeProfile":          false,
		"resolvedWorkloadVaultPlan":       false,
		"resolvedMountPlan":               false,
		"resolvedRuntimeMountInputs":      false,
		"resolvedRestartPolicy":           false,
		"resolvedReschedulePolicy":        false,
		"resolvedJobEnvelope":             false,
		"resolvedCodexCredentialLocation": false,
		"resolvedAuthorityPlan":           false,
		"resolvedPlanFacts":               false,
		"resolvedExecutionPlan":           false,
		"resolvedTrustMaterial":           false,
		"validatedMountArchive":           false,
		"validatedMountEntry":             false,
		"resolvedMaterialFacts":           false,
		"resolvedExecutionMaterial":       false,
		"hostMaterializationContext":      false,
		"normalizedSubmitPlacementFacts":  false,
		"resolvedRunProjection":           false,
		"resolvedNomadJobProjection":      false,
		"resolvedExecution":               false,
	}
	formatMethods := 0

	for _, decl := range file.Decls {
		switch typed := decl.(type) {
		case *ast.GenDecl:
			for _, spec := range typed.Specs {
				typeSpec, ok := spec.(*ast.TypeSpec)
				if !ok {
					continue
				}
				if typeSpec.Name.IsExported() {
					t.Fatalf("resolved-plan source exports type %s", typeSpec.Name.Name)
				}
				structType, guarded := typeSpec.Type.(*ast.StructType)
				if !guarded {
					continue
				}
				_, required := privateTypes[typeSpec.Name.Name]
				embedsMarker := false
				for _, field := range structType.Fields.List {
					if field.Tag != nil {
						t.Fatalf("private type %s must not have serialization tags", typeSpec.Name.Name)
					}
					if len(field.Names) == 0 && exprSourceName(field.Type) == "privateExecutionValue" {
						embedsMarker = true
					}
					for _, name := range field.Names {
						if name.IsExported() {
							t.Fatalf("private type %s exports field %s", typeSpec.Name.Name, name.Name)
						}
						fieldType := exprSourceName(field.Type)
						if fieldType == "PrepareRequest" || fieldType == "esconfig.Config" || fieldType == "executionRuntimeProfile" || fieldType == "esconfig.ResolvedWorkloadVaultAuthPlan" {
							t.Fatalf("private type %s retains unresolved source type %s", typeSpec.Name.Name, fieldType)
						}
					}
				}
				if required {
					privateTypes[typeSpec.Name.Name] = true
					if !embedsMarker {
						t.Fatalf("private type %s must embed privateExecutionValue", typeSpec.Name.Name)
					}
				}
			}
		case *ast.FuncDecl:
			if typed.Recv == nil {
				if typed.Name.IsExported() {
					t.Fatalf("resolved-plan source exports function %s", typed.Name.Name)
				}
				continue
			}
			receiver := receiverTypeName(typed.Recv.List[0].Type)
			switch typed.Name.Name {
			case "String", "GoString", "Error", "MarshalJSON", "MarshalText":
				t.Fatalf("private execution type %s must not implement %s", receiver, typed.Name.Name)
			case "Format":
				if receiver != "privateExecutionValue" {
					t.Fatalf("only privateExecutionValue may implement Format, got %s", receiver)
				}
				formatMethods++
			}
		}
	}
	for typeName, found := range privateTypes {
		if !found {
			t.Fatalf("resolved-plan privacy guard did not find %s", typeName)
		}
	}
	if formatMethods != 1 {
		t.Fatalf("expected exactly one private formatter method, got %d", formatMethods)
	}
	assertAdmissionFoundationOmitsAll(t, "resolved-plan privacy source", source,
		"encoding/json", "reflect", "unsafe", "json:\"", "MarshalJSON", "MarshalText", "GoString", "runtimeProfileEnvironment",
	)
}

func TestResolvedExecutionPlanPostFreezeConsumerGuardrails(t *testing.T) {
	assertSingleTypedParameter(t, "submit.go", "buildNomadJobSpec", "resolvedNomadJobProjection")
	assertSingleTypedParameter(t, "authorityhandoff.go", "buildResolvedExecutionAuthorityHandoff", "executionAuthorityHandoffProjection")
	authoritySource := mustReadAdmissionSource(t, "authorityhandoff.go")
	authorityProjection := admissionSourceSection(t, authoritySource, "type executionAuthorityHandoffProjection struct", "func newExecutionAuthorityHandoffProjection")
	assertAdmissionFoundationOmitsAll(t, "post-freeze authority projections", authorityProjection,
		"map[string]string", "executionRuntimeProfile", "esconfig.ResolvedWorkloadVaultAuthPlan",
	)
	authorityBuilder := admissionSourceSection(t, authoritySource, "func buildResolvedExecutionAuthorityHandoff", "func buildExecutionAuthorityHandoff")
	assertAdmissionFoundationOmitsAll(t, "typed authority builder defaults", authorityBuilder,
		"strings.TrimSpace", "map[string]string", "executionRuntimeProfile", "esconfig.ResolvedWorkloadVaultAuthPlan",
	)
	metadataBuilder := admissionSourceSection(t, authoritySource, "func executionAuthorityMetadata", "func executionAuthorityHandoffFromSubmittedRuntimeSpec")
	assertAdmissionFoundationOmitsAll(t, "typed authority metadata defaults", metadataBuilder,
		"strings.TrimSpace", "map[string]string", "executionRuntimeProfile", "esconfig.ResolvedWorkloadVaultAuthPlan",
	)

	submitSource := mustReadAdmissionSource(t, "submit.go")
	jobBuilder := admissionSourceSection(t, submitSource, "func buildNomadJobSpec", "func newNomadClient")
	assertAdmissionFoundationOmitsAll(t, "typed Nomad builder defaults", jobBuilder,
		"defaultSubmit", "runtimeSupervisorArgs", "resolveTaskResources", "selectedRuntimeImage", "s.cfg", "strings.TrimSpace",
	)
	views := loadTypedProductionPackages(t, "./es/admission", "./es/internal/staticarchive", "./es/runtimehelper")
	for _, view := range views {
		pkg := requireTypedProductionPackage(t, view.packages, "execution-substrate/es/admission")
		if err := validateResolvedPlanSemanticCallFlow(pkg); err != nil {
			t.Fatalf("%s: %v", view.target, err)
		}
		archivePkg := requireTypedProductionPackage(t, view.packages, "execution-substrate/es/internal/staticarchive")
		runtimePkg := requireTypedProductionPackage(t, view.packages, "execution-substrate/es/runtimehelper")
		if err := validateReviewedStaticArchiveBoundary(pkg, archivePkg, runtimePkg); err != nil {
			t.Fatalf("%s: %v", view.target, err)
		}
	}
	mountSource := mustReadAdmissionSource(t, "mounts.go")
	mountParserSource := admissionSourceSection(t, mountSource, "func validateRuntimeMountArchive", "func materializeValidatedMountEntries")
	assertAdmissionFoundationOmitsAll(t, "governed mount parser candidate-only limits", mountParserSource,
		"maxRuntimeMountEntries", "maxRuntimeMountEntryName", "make([]byte, int(header.Size))",
	)

	mountFile := mustParseAdmissionSource(t, "mounts.go")
	assertMountEntryAllocationStructure(t, mountFile)
	for _, mutation := range []struct {
		name   string
		source string
	}{
		{
			name: "direct header allocation",
			source: `package admission
func validateRuntimeMountArchiveWithinBudgets() {
	contents := make([]byte, int(header.Size))
	_ = contents
}`,
		},
		{
			name: "aliased header allocation",
			source: `package admission
func validateRuntimeMountArchiveWithinBudgets() {
	size := header.Size
	contents := make([]byte, int(size))
	_ = contents
}`,
		},
	} {
		t.Run(mutation.name, func(t *testing.T) {
			mutant, err := parser.ParseFile(token.NewFileSet(), mutation.name+".go", mutation.source, 0)
			if err != nil {
				t.Fatalf("parse guard mutant: %v", err)
			}
			if !functionAllocatesByteSlice(mutant, "validateRuntimeMountArchiveWithinBudgets") {
				t.Fatal("mount parser allocation guard did not reject the mutation")
			}
		})
	}
	const archiveFlowBase = `package admission
type Reader struct{}
func Open() *Reader { return &Reader{} }
func (reader *Reader) Next() int { return 1 }
func (reader *Reader) Finish() {}
type Namespace struct{}
func (namespace *Namespace) Add(int) {}
func inspect() {
	archive := Open()
	header := archive.Next()
	var namespace Namespace
	namespace.Add(header)
	archive.Finish()
}
`
	archiveFlowBaseline := typeCheckSyntheticProductionPackage(t, "mutant.go", archiveFlowBase)
	if err := validateSyntheticArchiveBoundary(archiveFlowBaseline); err != nil {
		t.Fatalf("reviewed archive flow baseline failed: %v", err)
	}
	for _, mutation := range []struct {
		name string
		from string
		to   string
	}{
		{"policy completion bypass", "\tarchive.Finish()", "\t_ = archive"},
		{"new unreviewed archive caller", "func inspect() {", "func unreviewed() { _ = Open() }\nfunc inspect() {"},
		{"archive opener function-value escape", "\tarchive := Open()", "\topener := Open\n\tarchive := opener()"},
	} {
		t.Run(mutation.name, func(t *testing.T) {
			mutant := strings.Replace(archiveFlowBase, mutation.from, mutation.to, 1)
			if mutant == archiveFlowBase {
				t.Fatal("archive flow mutation anchor absent")
			}
			pkg := typeCheckSyntheticProductionPackage(t, "mutant.go", mutant)
			if err := validateSyntheticArchiveBoundary(pkg); err == nil {
				t.Fatal("archive flow bypass/caller/escape mutation was accepted")
			}
		})
	}
	const parserBase = `package admission
import (
	"archive/tar"
	"bytes"
	"compress/gzip"
)
func governedParser() {
	reader, _ := gzip.NewReader(bytes.NewReader(nil))
	_ = tar.NewReader(reader)
}
`
	validateParser := func(pkg *typedProductionPackage) error {
		if err := validateTypedReferenceInventory("governed gzip constructor", pkg.referencesToPackageFunction("compress/gzip", "NewReader"), map[string]int{"mutant.go:governedParser": 1}, true); err != nil {
			return err
		}
		return validateTypedReferenceInventory("governed tar constructor", pkg.referencesToPackageFunction("archive/tar", "NewReader"), map[string]int{"mutant.go:governedParser": 1}, true)
	}
	parserBaseline := typeCheckSyntheticProductionPackage(t, "mutant.go", parserBase)
	if err := validateParser(parserBaseline); err != nil {
		t.Fatalf("governed parser baseline failed: %v", err)
	}
	for _, mutation := range []struct {
		name string
		from string
		to   string
	}{
		{"unreviewed parser", "func governedParser() {", "func unreviewedParser() { _, _ = gzip.NewReader(bytes.NewReader(nil)) }\nfunc governedParser() {"},
		{"gzip constructor escape", "\treader, _ := gzip.NewReader(bytes.NewReader(nil))", "\topener := gzip.NewReader\n\treader, _ := opener(bytes.NewReader(nil))"},
	} {
		t.Run(mutation.name, func(t *testing.T) {
			mutant := strings.Replace(parserBase, mutation.from, mutation.to, 1)
			if mutant == parserBase {
				t.Fatal("parser mutation anchor absent")
			}
			pkg := typeCheckSyntheticProductionPackage(t, "mutant.go", mutant)
			if err := validateParser(pkg); err == nil {
				t.Fatal("unreviewed parser or constructor escape was accepted")
			}
		})
	}
	for _, decl := range mountFile.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "materializeValidatedRuntimeMounts" {
			continue
		}
		ast.Inspect(fn.Body, func(node ast.Node) bool {
			selector, ok := node.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if (exprSourceName(selector.X) == "gzip" || exprSourceName(selector.X) == "tar") && selector.Sel.Name != "" {
				t.Fatalf("post-freeze mount materializer must not parse gzip/tar through %s.%s", exprSourceName(selector.X), selector.Sel.Name)
			}
			return true
		})
		return
	}
	t.Fatal("materializeValidatedRuntimeMounts not found")
}

func validateSyntheticArchiveBoundary(pkg *typedProductionPackage) error {
	if err := validateTypedReferenceInventory("reviewed archive opener", pkg.referencesTo(requireSyntheticArchiveFunction(pkg, "Open")), map[string]int{"mutant.go:inspect": 1}, true); err != nil {
		return err
	}
	return validateSemanticCallSequence(pkg, "", "inspect", []semanticCallDefinition{
		{label: "open", name: "Open"},
		{label: "next", receiver: "Reader", name: "Next"},
		{label: "namespace", receiver: "Namespace", name: "Add"},
		{label: "finish", receiver: "Reader", name: "Finish"},
	})
}

func requireSyntheticArchiveFunction(pkg *typedProductionPackage, name string) types.Object {
	return pkg.pkg.Scope().Lookup(name)
}

func TestTrancheB1FiniteSemanticShapeGuardrails(t *testing.T) {
	sources := map[string]string{
		"authorityhandoff.go":             mustReadAdmissionSource(t, "authorityhandoff.go"),
		"executionpackage.go":             mustReadAdmissionSource(t, "executionpackage.go"),
		"resolved_execution_plan.go":      mustReadAdmissionSource(t, "resolved_execution_plan.go"),
		"service.go":                      mustReadAdmissionSource(t, "service.go"),
		"submit.go":                       mustReadAdmissionSource(t, "submit.go"),
		"types.go":                        mustReadAdmissionSource(t, "types.go"),
		"resolved_execution_plan_test.go": mustReadAdmissionSource(t, "resolved_execution_plan_test.go"),
		"submit_test.go":                  mustReadAdmissionSource(t, "submit_test.go"),
	}
	if err := validateTrancheB1StructInventories(sources); err != nil {
		t.Fatal(err)
	}
	if err := validateTrancheB1BoundedSourceInventories(sources); err != nil {
		t.Fatal(err)
	}
	if err := validateTrancheB1LiteralGoldenSource(sources["resolved_execution_plan_test.go"], sources["submit_test.go"]); err != nil {
		t.Fatal(err)
	}
	if err := validateTrancheB1PayloadProjectionSources(sources); err != nil {
		t.Fatal(err)
	}

	views := loadTypedProductionPackages(t, "./es/admission")
	type referenceInventory struct {
		label    string
		method   bool
		receiver string
		name     string
		want     map[string]int
	}
	inventories := []referenceInventory{
		{label: "submit resolver", method: true, receiver: "Service", name: "resolveExecutionForSubmit", want: map[string]int{"es/admission/submit.go:Service.Submit": 1, "es/admission/reliable_submit_replay_private.go:Service.composePrivateSyntheticReplay": 1}},
		{label: "private admission intent", method: true, receiver: "Service", name: "prepareAdmission", want: map[string]int{"es/admission/resolved_execution_plan.go:Service.resolveExecutionForSubmit": 1, "es/admission/service.go:Service.Prepare": 1}},
		{label: "admission request snapshot", name: "snapshotAdmissionRequest", want: map[string]int{"es/admission/service.go:Service.prepareAdmission": 2}},
		{label: "admission validation/defaulting", name: "validatePrepareRequest", want: map[string]int{"es/admission/service.go:Service.prepareAdmission": 1}},
		{label: "normalized submit placement", name: "normalizeSubmitPlacementFacts", want: map[string]int{"es/admission/resolved_execution_plan.go:Service.resolveExecutionForSubmit": 1}},
		{label: "host context constructor", name: "newHostMaterializationContext", want: map[string]int{"es/admission/resolved_execution_plan.go:Service.resolveExecutionForSubmit": 1, "es/admission/reliable_submit_replay_hydration.go:privateReplayReader.placement": 1}},
		{label: "semantic plan constructor", name: "newResolvedExecutionPlan", want: map[string]int{"es/admission/resolved_execution_plan.go:Service.resolveExecutionForSubmit": 1, "es/admission/reliable_submit_replay_hydration.go:decodePrivateReplayOriginal": 1}},
		{label: "typed command constructor", name: "newResolvedRuntimeCommand", want: map[string]int{"es/admission/resolved_execution_plan.go:Service.resolveExecutionForSubmit": 1}},
		{label: "run projection constructor", name: "newResolvedRunProjection", want: map[string]int{"es/admission/submit.go:Service.Submit": 1}},
		{label: "provider projection constructor", method: true, receiver: "resolvedRunProjection", name: "nomadJobProjection", want: map[string]int{"es/admission/submit.go:Service.Submit": 1}},
		{label: "Nomad job builder", name: "buildNomadJobSpec", want: map[string]int{"es/admission/submit.go:Service.Submit": 1}},
		{label: "Nomad registration", method: true, receiver: "nomadClient", name: "submitJob", want: map[string]int{"es/admission/submit.go:Service.Submit": 1}},
	}
	for _, inventory := range inventories {
		references := mergedProductionReferences(t, views, "execution-substrate/es/admission", func(pkg *typedProductionPackage) types.Object {
			if inventory.method {
				return requirePackageMethod(t, pkg, inventory.receiver, inventory.name)
			}
			return requirePackageFunction(t, pkg, inventory.name)
		})
		if err := validateTypedReferenceInventory(inventory.label, references, inventory.want, true); err != nil {
			t.Fatal(err)
		}
	}
	for _, view := range views {
		pkg := requireTypedProductionPackage(t, view.packages, "execution-substrate/es/admission")
		if err := validateTrancheB1SemanticProducerFreeze(pkg); err != nil {
			t.Fatalf("%s: %v", view.target, err)
		}
		if err := validateTrancheB1PostFreezeClosure(pkg, trancheB1ExpectedPostFreezeInventory(view.target)); err != nil {
			t.Fatalf("%s: %v", view.target, err)
		}
	}
}

func TestTrancheB1FiniteSemanticShapeGuardrailsRejectMutants(t *testing.T) {
	baseSources := map[string]string{
		"authorityhandoff.go":             mustReadAdmissionSource(t, "authorityhandoff.go"),
		"executionpackage.go":             mustReadAdmissionSource(t, "executionpackage.go"),
		"resolved_execution_plan.go":      mustReadAdmissionSource(t, "resolved_execution_plan.go"),
		"service.go":                      mustReadAdmissionSource(t, "service.go"),
		"submit.go":                       mustReadAdmissionSource(t, "submit.go"),
		"types.go":                        mustReadAdmissionSource(t, "types.go"),
		"resolved_execution_plan_test.go": mustReadAdmissionSource(t, "resolved_execution_plan_test.go"),
		"submit_test.go":                  mustReadAdmissionSource(t, "submit_test.go"),
	}
	cloneSources := func() map[string]string {
		cloned := make(map[string]string, len(baseSources))
		for name, source := range baseSources {
			cloned[name] = source
		}
		return cloned
	}
	mutations := []struct {
		name     string
		validate func(map[string]string) error
		mutate   func(map[string]string)
	}{
		{
			name:     "verified mount artifact provenance removed",
			validate: validateTrancheB1StructInventories,
			mutate: func(sources map[string]string) {
				sources["resolved_execution_plan.go"] = strings.Replace(sources["resolved_execution_plan.go"], "verifiedArtifactDigest", "lostVerifiedArtifactDigest", 1)
			},
		},
		{
			name:     "host owner in semantic plan",
			validate: validateTrancheB1StructInventories,
			mutate: func(sources map[string]string) {
				sources["resolved_execution_plan.go"] = strings.Replace(sources["resolved_execution_plan.go"], "type resolvedExecutionPlan struct {\n\tprivateExecutionValue", "type resolvedExecutionPlan struct {\n\tprivateExecutionValue\n\towner executionPlatformStateOwner", 1)
			},
		},
		{
			name:     "duplicate supervisor grammar",
			validate: validateTrancheB1BoundedSourceInventories,
			mutate: func(sources map[string]string) {
				sources["executionpackage.go"] += "\nfunc duplicateCommandGrammar() []string { return []string{\"supervisor\", \"--payload-archive\", \"--work-dir\", \"--result-dir\", \"--entrypoint\", \"--timeout-seconds\", \"--\"} }\n"
			},
		},
		{
			name:     "payload sourced from artifact identity",
			validate: validateTrancheB1BoundedSourceInventories,
			mutate: func(sources map[string]string) {
				sources["resolved_execution_plan.go"] = strings.Replace(sources["resolved_execution_plan.go"], "payloadDigest:           prepared.artifact.payloadDigest", "payloadDigest:           prepared.admittedRequest.Invocation.ArtifactDigest", 1)
			},
		},
		{
			name:     "caller mode mutation before owned snapshot",
			validate: validateTrancheB1BoundedSourceInventories,
			mutate: func(sources map[string]string) {
				sources["service.go"] = strings.Replace(sources["service.go"], "func (s *Service) prepareAdmission(ctx context.Context, req PrepareRequest, intent admissionIntent) (preparedAdmission, *Error) {\n\treq = snapshotAdmissionRequest(req)", "func (s *Service) prepareAdmission(ctx context.Context, req PrepareRequest, intent admissionIntent) (preparedAdmission, *Error) {\n\treq.Mode = ExecutionModeAsync\n\treq = snapshotAdmissionRequest(req)", 1)
			},
		},
		{
			name: "production-derived golden expected value",
			validate: func(sources map[string]string) error {
				return validateTrancheB1LiteralGoldenSource(sources["resolved_execution_plan_test.go"], sources["submit_test.go"])
			},
			mutate: func(sources map[string]string) {
				sources["resolved_execution_plan_test.go"] = strings.Replace(sources["resolved_execution_plan_test.go"], "json.Unmarshal([]byte(trancheB1DefaultNomadJobGolden), &expectedJob)", "json.Unmarshal(submittedBody, &expectedJob)", 1)
			},
		},
		{
			name: "direct payload metadata",
			validate: func(sources map[string]string) error {
				return validateTrancheB1PayloadProjectionSources(sources)
			},
			mutate: func(sources map[string]string) {
				sources["authorityhandoff.go"] = strings.Replace(sources["authorityhandoff.go"], "\t\texecutionAuthorityMetadataSchemaKey:                  executionAuthorityMetadataSchemaVersion,", "\t\t\"payload_digest\": \"private\",\n\t\texecutionAuthorityMetadataSchemaKey:                  executionAuthorityMetadataSchemaVersion,", 1)
			},
		},
		{
			name:     "payload digest in environment",
			validate: validateTrancheB1BoundedSourceInventories,
			mutate: func(sources map[string]string) {
				sources["resolved_execution_plan.go"] = strings.Replace(sources["resolved_execution_plan.go"], "\tenvironment[\"EXEC_RUN_ID\"] = locator.RunID", "\tenvironment[\"EXEC_RUN_ID\"] = locator.RunID\n\tenvironment[\"PRIVATE\"] = plan.payloadDigest", 1)
			},
		},
		{
			name: "payload digest in authority handoff",
			validate: func(sources map[string]string) error {
				return validateTrancheB1PayloadProjectionSources(sources)
			},
			mutate: func(sources map[string]string) {
				sources["authorityhandoff.go"] = strings.Replace(sources["authorityhandoff.go"], "\treturn result\n}\n\nfunc buildExecutionAuthorityHandoff", "\tresult.Evidence.Source = \"payload_digest:\" + projection.runtimeProfileName\n\treturn result\n}\n\nfunc buildExecutionAuthorityHandoff", 1)
			},
		},
		{
			name: "payload digest in public receipt",
			validate: func(sources map[string]string) error {
				return validateTrancheB1PayloadProjectionSources(sources)
			},
			mutate: func(sources map[string]string) {
				sources["types.go"] = strings.Replace(sources["types.go"], "type SubmitResult struct {", "type SubmitResult struct {\n\tPayloadDigest string `json:\"payload_digest\"`", 1)
			},
		},
		{
			name: "golden expected value returned by helper",
			validate: func(sources map[string]string) error {
				return validateTrancheB1LiteralGoldenSource(sources["resolved_execution_plan_test.go"], sources["submit_test.go"])
			},
			mutate: func(sources map[string]string) {
				sources["resolved_execution_plan_test.go"] = strings.Replace(sources["resolved_execution_plan_test.go"], "\tstagingInfo, statErr := os.Stat(stagingRoot)", "\texpectedJob = mutationExpectedTree(actualJob)\n\tstagingInfo, statErr := os.Stat(stagingRoot)", 1)
			},
		},
		{
			name: "golden expected subtree imported by helper",
			validate: func(sources map[string]string) error {
				return validateTrancheB1LiteralGoldenSource(sources["resolved_execution_plan_test.go"], sources["submit_test.go"])
			},
			mutate: func(sources map[string]string) {
				sources["resolved_execution_plan_test.go"] = strings.Replace(sources["resolved_execution_plan_test.go"], "\tstagingInfo, statErr := os.Stat(stagingRoot)", "\texpectedJob.(map[string]any)[\"Job\"] = mutationExpectedSubtree()\n\tstagingInfo, statErr := os.Stat(stagingRoot)", 1)
			},
		},
		{
			name: "golden expected literal composed from production constant",
			validate: func(sources map[string]string) error {
				return validateTrancheB1LiteralGoldenSource(sources["resolved_execution_plan_test.go"], sources["submit_test.go"])
			},
			mutate: func(sources map[string]string) {
				sources["resolved_execution_plan_test.go"] = strings.Replace(sources["resolved_execution_plan_test.go"], "const trancheB1DefaultNomadJobGolden = `", "const trancheB1DefaultNomadJobGolden = executionRuntimeSupportPath + `", 1)
			},
		},
	}
	for _, mutation := range mutations {
		t.Run(mutation.name, func(t *testing.T) {
			sources := cloneSources()
			mutation.mutate(sources)
			if err := mutation.validate(sources); err == nil {
				t.Fatal("bounded B1 source mutation escaped its guard")
			}
		})
	}

	for _, mutation := range []struct {
		name   string
		source string
	}{
		{
			name: "method value",
			source: `package admission
func newResolvedRuntimeCommand() {}
func use() { constructor := newResolvedRuntimeCommand; constructor() }
`,
		},
		{
			name: "closure",
			source: `package admission
func newResolvedRuntimeCommand() {}
func use() { func() { newResolvedRuntimeCommand() }() }
`,
		},
		{
			name: "extra producer",
			source: `package admission
func newResolvedRuntimeCommand() {}
func use() { newResolvedRuntimeCommand() }
func hidden() { newResolvedRuntimeCommand() }
`,
		},
	} {
		t.Run("typed command "+mutation.name, func(t *testing.T) {
			pkg := typeCheckSyntheticProductionPackage(t, "mutant.go", mutation.source)
			references := pkg.referencesTo(requirePackageFunction(t, pkg, "newResolvedRuntimeCommand"))
			if err := validateTypedReferenceInventory("typed command constructor", references, map[string]int{"mutant.go:use": 1}, true); err == nil {
				t.Fatal("typed command reference mutation escaped")
			}
		})
	}

	const hookFile = "es/admission/staging_custody.go"
	const hookBaseline = `package admission
type stagingCustody struct{}
var beforeStagingChildRegistrationStatForTest func(relativePath string, fd int, directory bool)
func (custody *stagingCustody) ensureDirectory() {
	if beforeStagingChildRegistrationStatForTest != nil {
		beforeStagingChildRegistrationStatForTest("child", 1, true)
	}
}
func (custody *stagingCustody) writeFileWithHookAndParentMode() {
	if beforeStagingChildRegistrationStatForTest != nil {
		beforeStagingChildRegistrationStatForTest("child", 1, false)
	}
}
`
	baselineHookPackage := typeCheckSyntheticProductionPackage(t, hookFile, hookBaseline)
	if _, err := validateTrancheB1ReviewedChildRegistrationHook(baselineHookPackage); err != nil {
		t.Fatalf("reviewed nil-hook baseline failed: %v", err)
	}
	for _, mutation := range []struct {
		name string
		from string
		to   string
	}{
		{"nonnil production hook initializer", "var beforeStagingChildRegistrationStatForTest func(relativePath string, fd int, directory bool)", "var beforeStagingChildRegistrationStatForTest func(relativePath string, fd int, directory bool) = func(string, int, bool) {}"},
		{"production hook assignment", "func (custody *stagingCustody) ensureDirectory() {", "func assignHook() { beforeStagingChildRegistrationStatForTest = func(string, int, bool) {} }\nfunc (custody *stagingCustody) ensureDirectory() {"},
		{"unreviewed hook use", "func (custody *stagingCustody) ensureDirectory() {", "func unreviewedHookUse() { _ = beforeStagingChildRegistrationStatForTest }\nfunc (custody *stagingCustody) ensureDirectory() {"},
	} {
		t.Run(mutation.name, func(t *testing.T) {
			mutant := strings.Replace(hookBaseline, mutation.from, mutation.to, 1)
			if mutant == hookBaseline {
				t.Fatal("hook mutation anchor absent")
			}
			pkg := typeCheckSyntheticProductionPackage(t, hookFile, mutant)
			if _, err := validateTrancheB1ReviewedChildRegistrationHook(pkg); err == nil {
				t.Fatal("child-registration hook mutation escaped exact object/site guard")
			}
		})
	}

	const globalClosureBaseline = `package admission
type Service struct{}
type nomadClient struct{}
type resolvedRunProjection struct{}
type executionPackageLayout struct{}
func (s *Service) resolveExecutionForSubmit() {}
func (s *Service) Submit() { s.resolveExecutionForSubmit(); cleanHelper() }
func newResolvedRunProjection() {}
func (resolvedRunProjection) nomadJobProjection() {}
func buildNomadJobSpec() {}
func buildResolvedExecutionAuthorityHandoff() {}
func executionAuthorityMetadata() {}
func (executionPackageLayout) runtimeMountSpecs() {}
func cleanHelper() {}
`
	globalBaseline := typeCheckSyntheticProductionPackage(t, "submit.go", globalClosureBaseline)
	if _, err := trancheB1BuildPostFreezeClosure(globalBaseline); err != nil {
		t.Fatalf("package-global closure baseline failed: %v", err)
	}
	t.Run("another mutable package-global even with ForTest suffix", func(t *testing.T) {
		mutant := strings.Replace(globalClosureBaseline, "func cleanHelper() {}", "var otherMutableForTest func()\nfunc cleanHelper() { if otherMutableForTest != nil { otherMutableForTest() } }", 1)
		pkg := typeCheckSyntheticProductionPackage(t, "submit.go", mutant)
		_, err := trancheB1BuildPostFreezeClosure(pkg)
		if err == nil || !strings.Contains(err.Error(), "mutable package-global otherMutableForTest") {
			t.Fatalf("unreviewed mutable global escaped exact closure guard: %v", err)
		}
	})
}

func TestTrancheB1FiniteAssuranceRepairCriticalReferenceMultiplicity(t *testing.T) {
	const source = `package admission
func criticalConstructor() {}
func use() {
	criticalConstructor()
	criticalConstructor()
}
`
	pkg := typeCheckSyntheticProductionPackage(t, "mutant.go", source)
	target := requirePackageFunction(t, pkg, "criticalConstructor")
	references := pkg.referencesTo(target)
	if len(references) != 2 {
		t.Fatalf("critical reference occurrences were collapsed: %v", references)
	}
	for _, reference := range references {
		if reference.packagePath != "synthetic/admission" || reference.site != "mutant.go:use" || reference.position.Line == 0 || reference.position.Column == 0 || reference.objectIdentity == "" || reference.referenceKind != "direct-call" {
			t.Fatalf("critical occurrence identity is incomplete: %+v", reference)
		}
	}
	if references[0].position == references[1].position {
		t.Fatalf("same-function critical occurrences lost source-position identity: %v", references)
	}
	if err := validateTypedReferenceInventory("critical constructor", references, map[string]int{"mutant.go:use": 1}, true); err == nil {
		t.Fatal("second same-function critical occurrence escaped the frozen inventory")
	}
}

func TestTrancheB1SemanticProducerFreezeRejectsMutants(t *testing.T) {
	const base = `package admission
type ExecutionMode string
type Service struct{}
type resolvedPlanFacts struct {
	mode ExecutionMode
	payloadDigest string
}
type resolvedExecutionPlan struct {
	mode ExecutionMode
	payloadDigest string
}
func newResolvedExecutionPlan(facts resolvedPlanFacts) resolvedExecutionPlan {
	return resolvedExecutionPlan{mode: facts.mode, payloadDigest: facts.payloadDigest}
}
func (s *Service) resolveExecutionForSubmit() {
	plan := newResolvedExecutionPlan(resolvedPlanFacts{mode: "async", payloadDigest: "private"})
	_ = plan
}
`
	const fileName = "es/admission/resolved_execution_plan.go"
	want := trancheB1SemanticFreezeExpectation{
		want: trancheB1SemanticFreezeInventory{
			factsComposite: []string{fileName + ":Service.resolveExecutionForSubmit"},
			planComposite:  []string{fileName + ":newResolvedExecutionPlan"},
			planCalls:      []string{fileName + ":Service.resolveExecutionForSubmit"},
			planFunctions:  []string{fileName + ":newResolvedExecutionPlan"},
			planReturns:    []string{fileName + ":newResolvedExecutionPlan"},
			planBindings:   []string{fileName + ":Service.resolveExecutionForSubmit"},
			factsPayload:   []string{fileName + ":Service.resolveExecutionForSubmit", fileName + ":newResolvedExecutionPlan"},
			planPayload:    []string{fileName + ":newResolvedExecutionPlan"},
		},
		hydrationWrites: 0,
	}
	baseline := typeCheckSyntheticProductionPackage(t, fileName, base)
	if err := validateTrancheB1SemanticProducerFreeze(baseline, want); err != nil {
		t.Fatalf("synthetic semantic-producer baseline failed: %v", err)
	}
	for _, test := range []struct {
		name    string
		mutant  string
		wantErr string
	}{
		{"direct post-freeze field write", strings.Replace(base, "\t_ = plan", "\tplan.mode = \"sync\"", 1), "semantic field writes"},
		{"frozen-plan alias write", strings.Replace(base, "\t_ = plan", "\talias := &plan\n\talias.mode = \"sync\"", 1), "semantic field writes"},
		{"alias type", base + "type mutationAlias = resolvedExecutionPlan\n", "semantic aliases"},
		{"type conversion producer", base + "type mutationPlan resolvedExecutionPlan\nfunc mutationConversion() resolvedExecutionPlan { return resolvedExecutionPlan(mutationPlan{}) }\n", "semantic type conversions"},
		{"composite helper producer", base + "func mutationComposite() resolvedExecutionPlan { return resolvedExecutionPlan{} }\n", "resolved-plan composite producers"},
		{"closure producer", base + "func mutationClosure() { producer := func() resolvedExecutionPlan { return resolvedExecutionPlan{} }; _ = producer }\n", "semantic producer closures"},
	} {
		t.Run(test.name, func(t *testing.T) {
			pkg := typeCheckSyntheticProductionPackage(t, fileName, test.mutant)
			if err := validateTrancheB1SemanticProducerFreeze(pkg, want); err == nil || !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("semantic producer/freeze mutant did not fail for %s: %v", test.wantErr, err)
			}
		})
	}
	t.Run("constructor function value", func(t *testing.T) {
		pkg := typeCheckSyntheticProductionPackage(t, fileName, base+"func mutationFunctionValue() { producer := newResolvedExecutionPlan; _ = producer }\n")
		references := pkg.referencesTo(requirePackageFunction(t, pkg, "newResolvedExecutionPlan"))
		if err := validateTypedReferenceInventory("semantic plan constructor", references, map[string]int{fileName + ":Service.resolveExecutionForSubmit": 1}, true); err == nil {
			t.Fatal("semantic constructor function-value mutation escaped")
		}
	})
}

func TestTrancheB1FiniteAssuranceRepairSemanticAggregateMutations(t *testing.T) {
	const fileName = "es/admission/resolved_execution_plan.go"
	const base = `package admission
type resolvedMountPlan struct { readOnly bool }
type resolvedPlanFacts struct {
	payloadDigest string
	semanticEnvironment map[string]string
	mounts []resolvedMountPlan
	counters []int
}
type resolvedExecutionPlan struct {
	payloadDigest string
	semanticEnvironment map[string]string
	mounts []resolvedMountPlan
	counters []int
}
type Service struct{}
func copyStringMap(source map[string]string) map[string]string {
	result := make(map[string]string, len(source))
	for key, value := range source { result[key] = value }
	return result
}
func newResolvedExecutionPlan(facts resolvedPlanFacts) resolvedExecutionPlan {
	return resolvedExecutionPlan{
		payloadDigest: facts.payloadDigest,
		semanticEnvironment: copyStringMap(facts.semanticEnvironment),
		mounts: append([]resolvedMountPlan(nil), facts.mounts...),
		counters: append([]int(nil), facts.counters...),
	}
}
func (s *Service) resolveExecutionForSubmit() {
	plan := newResolvedExecutionPlan(resolvedPlanFacts{
		payloadDigest: "private",
		semanticEnvironment: map[string]string{"KEY": "VALUE"},
		mounts: []resolvedMountPlan{{readOnly: true}},
		counters: []int{1},
	})
	_ = plan
}
`
	want := trancheB1SemanticFreezeExpectation{
		want: trancheB1SemanticFreezeInventory{
			factsComposite: []string{fileName + ":Service.resolveExecutionForSubmit"},
			planComposite:  []string{fileName + ":newResolvedExecutionPlan"},
			planCalls:      []string{fileName + ":Service.resolveExecutionForSubmit"},
			planFunctions:  []string{fileName + ":newResolvedExecutionPlan"},
			planReturns:    []string{fileName + ":newResolvedExecutionPlan"},
			planBindings:   []string{fileName + ":Service.resolveExecutionForSubmit"},
			factsPayload:   []string{fileName + ":Service.resolveExecutionForSubmit", fileName + ":newResolvedExecutionPlan"},
			planPayload:    []string{fileName + ":newResolvedExecutionPlan"},
		},
		hydrationWrites: 0,
	}
	baseline := typeCheckSyntheticProductionPackage(t, fileName, base)
	if err := validateTrancheB1SemanticProducerFreeze(baseline, want); err != nil {
		t.Fatalf("defensive-copy semantic constructor baseline failed: %v", err)
	}
	mutateAtFreeze := func(fragment string) string {
		return strings.Replace(base, "\t_ = plan", fragment+"\n\t_ = plan", 1)
	}
	for _, test := range []struct {
		name    string
		mutant  string
		wantErr string
	}{
		{name: "map element assignment", mutant: mutateAtFreeze(`	plan.semanticEnvironment["MUTATION"] = "changed"`), wantErr: "semantic field writes"},
		{name: "nested slice element field", mutant: mutateAtFreeze(`	plan.mounts[0].readOnly = !plan.mounts[0].readOnly`), wantErr: "semantic field writes"},
		{name: "compound indexed numeric member", mutant: mutateAtFreeze(`	plan.counters[0] += 1`), wantErr: "semantic field writes"},
		{name: "multi-value indexed assignment", mutant: mutateAtFreeze("	local := false\n\tplan.mounts[0].readOnly, local = false, true\n\t_ = local"), wantErr: "semantic field writes"},
		{name: "indexed increment", mutant: mutateAtFreeze(`	plan.counters[0]++`), wantErr: "semantic field writes"},
		{name: "map delete", mutant: mutateAtFreeze(`	delete(plan.semanticEnvironment, "KEY")`), wantErr: "semantic field writes"},
		{name: "map clear", mutant: mutateAtFreeze(`	clear(plan.semanticEnvironment)`), wantErr: "semantic field writes"},
		{name: "slice copy", mutant: mutateAtFreeze(`	copy(plan.mounts, []resolvedMountPlan{{readOnly: false}})`), wantErr: "semantic field writes"},
		{name: "direct mutable-member alias", mutant: mutateAtFreeze("	alias := plan.mounts\n\talias[0].readOnly = false"), wantErr: "semantic field writes"},
		{name: "direct plan pointer alias", mutant: mutateAtFreeze("	alias := &plan\n\talias.mounts[0].readOnly = false"), wantErr: "semantic field writes"},
		{name: "nested indexed selector", mutant: mutateAtFreeze(`	plan.mounts[0].readOnly = false`), wantErr: "semantic field writes"},
		{name: "nested closure mutation", mutant: mutateAtFreeze(`	func() { plan.semanticEnvironment["MUTATION"] = "changed" }()`), wantErr: "semantic field writes"},
		{name: "append assigned back", mutant: mutateAtFreeze(`	plan.mounts = append(plan.mounts, resolvedMountPlan{})`), wantErr: "semantic field writes"},
		{name: "new resolved plan", mutant: base + "func extraPlanAllocation() { _ = new(resolvedExecutionPlan) }\n", wantErr: "semantic new allocations"},
		{name: "new resolved facts", mutant: base + "func extraFactsAllocation() { _ = new(resolvedPlanFacts) }\n", wantErr: "semantic new allocations"},
		{name: "new exact plan alias", mutant: base + "type exactPlanAlias = resolvedExecutionPlan\nfunc extraAliasAllocation() { _ = new(exactPlanAlias) }\n", wantErr: "semantic aliases"},
		{name: "second same-function plan producer", mutant: mutateAtFreeze(`	_ = newResolvedExecutionPlan(resolvedPlanFacts{})`), wantErr: "resolved-plan producing calls"},
	} {
		t.Run(test.name, func(t *testing.T) {
			pkg := typeCheckSyntheticProductionPackage(t, fileName, test.mutant)
			if err := validateTrancheB1SemanticProducerFreeze(pkg, want); err == nil || !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("semantic mutant did not fail for %s: %v", test.wantErr, err)
			}
		})
	}

	t.Run("unrelated local aggregates remain outside", func(t *testing.T) {
		positive := base + `
func localAggregateWrites() {
	values := map[string]string{"KEY": "VALUE"}
	values["KEY"] = "changed"
	delete(values, "KEY")
	clear(values)
	numbers := []int{1}
	numbers[0]++
	copy(numbers, []int{2})
}
`
		pkg := typeCheckSyntheticProductionPackage(t, fileName, positive)
		if err := validateTrancheB1SemanticProducerFreeze(pkg, want); err != nil {
			t.Fatalf("unrelated local aggregate write rejected: %v", err)
		}
	})
}

func TestTrancheB1ValidationOwnershipRejectsSecondCallers(t *testing.T) {
	const fileName = "es/admission/service.go"
	const base = `package admission
type PrepareRequest struct{}
type Service struct{}
func validatePrepareRequest(*PrepareRequest) {}
func (s *Service) prepareAdmission() {
	request := PrepareRequest{}
	validatePrepareRequest(&request)
}
func (s *Service) Submit() {}
`
	for _, test := range []struct {
		name   string
		mutant string
	}{
		{"caller request after freeze", strings.Replace(base, "func (s *Service) Submit() {}", "func (s *Service) Submit() { request := PrepareRequest{}; validatePrepareRequest(&request) }", 1)},
		{"helper after freeze", strings.Replace(base, "func (s *Service) Submit() {}", "func (s *Service) Submit() { request := PrepareRequest{}; mutationValidate(&request) }\nfunc mutationValidate(request *PrepareRequest) { validatePrepareRequest(request) }", 1)},
	} {
		t.Run(test.name, func(t *testing.T) {
			pkg := typeCheckSyntheticProductionPackage(t, fileName, test.mutant)
			references := pkg.referencesTo(requirePackageFunction(t, pkg, "validatePrepareRequest"))
			if err := validateTypedReferenceInventory("admission validation/defaulting", references, map[string]int{fileName + ":Service.prepareAdmission": 1}, true); err == nil {
				t.Fatal("second validation/defaulting owner escaped")
			}
		})
	}
}

func TestTrancheB1PostFreezeClosureRejectsHelperIndirectionMutants(t *testing.T) {
	base := `package admission
type Config struct { Datacenter string; StagingRoot string }
type PrepareRequest struct { Root string }
type preparedAdmission struct { Value string }
type nomadClient struct{}
type Service struct { cfg Config; nomadClient *nomadClient }
type resolvedRunProjection struct{}
type executionPackageLayout struct{}
func (s *Service) resolveExecutionForSubmit() {}
func (s *Service) Submit() { s.resolveExecutionForSubmit(); newResolvedRunProjection() }
func newResolvedRunProjection() { cleanHelper() }
func (resolvedRunProjection) nomadJobProjection() {}
func buildNomadJobSpec() {}
func buildResolvedExecutionAuthorityHandoff() {}
func executionAuthorityMetadata() {}
func (executionPackageLayout) runtimeMountSpecs() {}
func cleanHelper() {}
`
	baselinePackage := typeCheckSyntheticProductionPackage(t, "submit.go", base)
	baseline, err := trancheB1BuildPostFreezeClosure(baselinePackage)
	if err != nil {
		t.Fatalf("synthetic post-freeze baseline failed: %v", err)
	}
	for _, test := range []struct {
		name        string
		replacement string
		want        string
		dynamic     bool
	}{
		{"Service.cfg datacenter helper", `func cleanHelper() { _ = liveDatacenter(&Service{}) }
func liveDatacenter(service *Service) string { return service.cfg.Datacenter }`, "forbidden Service field cfg", false},
		{"Service.cfg staging helper", `func cleanHelper() { _ = liveStagingRoot(&Service{}) }
func liveStagingRoot(service *Service) string { return service.cfg.StagingRoot }`, "forbidden Service field cfg", false},
		{"runtime-profile lookup helper", `func cleanHelper() { resolveExecutionRuntimeProfile() }
func resolveExecutionRuntimeProfile() {}`, "forbidden post-freeze source function resolveExecutionRuntimeProfile", false},
		{"prepared-admission helper", `func cleanHelper() { _ = preparedValue(preparedAdmission{}) }
func preparedValue(prepared preparedAdmission) string { return prepared.Value }`, "preparedAdmission", false},
		{"profile-conditional private metadata helper", `func cleanHelper() { appendPrivateMetadata("control-plane", map[string]string{}) }
var privateIdentity string
func appendPrivateMetadata(profile string, metadata map[string]string) {
	if profile == "control-plane" { metadata["payload_digest"] = privateIdentity }
}`, "mutable package-global privateIdentity", false},
		{"package function value", `func cleanHelper() { helper := directHelper; helper() }
func directHelper() {}`, "directHelper", true},
	} {
		t.Run(test.name, func(t *testing.T) {
			mutant := strings.Replace(base, "func cleanHelper() {}", test.replacement, 1)
			pkg := typeCheckSyntheticProductionPackage(t, "submit.go", mutant)
			got, buildErr := trancheB1BuildPostFreezeClosure(pkg)
			if test.dynamic {
				if buildErr != nil {
					t.Fatalf("function-value mutant returned unrelated error: %v", buildErr)
				}
				if reflect.DeepEqual(got.dynamic, baseline.dynamic) || !strings.Contains(strings.Join(got.dynamic, " "), test.want) {
					t.Fatalf("function-valued package helper did not change the exact dynamic-call inventory: %v", got.dynamic)
				}
				return
			}
			if buildErr == nil || !strings.Contains(buildErr.Error(), test.want) {
				t.Fatalf("helper-indirection mutant error = %v, want specific %q failure", buildErr, test.want)
			}
		})
	}
}

func TestTrancheB1PostFreezeStructuredResponseInventoryReconciliation(t *testing.T) {
	const base = `package admission
import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
)
type Config struct{}
type PrepareRequest struct{}
type preparedAdmission struct{}
type nomadClient struct{}
type Service struct { nomadClient *nomadClient }
type resolvedRunProjection struct{}
type executionPackageLayout struct{}
func (s *Service) resolveExecutionForSubmit() {}
func (s *Service) Submit(response *http.Response) {
	s.resolveExecutionForSubmit()
	_ = s.nomadClient.submitJob(response)
}
func newResolvedRunProjection() {}
func (resolvedRunProjection) nomadJobProjection() {}
func buildNomadJobSpec() {}
func buildResolvedExecutionAuthorityHandoff() {}
func executionAuthorityMetadata() {}
func (executionPackageLayout) runtimeMountSpecs() {}
func (c *nomadClient) submitJob(response *http.Response) error {
	return decodeBoundedCompatibleJSONDocumentResponse(response, new(any))
}
func readBoundedResponseBody(response *http.Response) ([]byte, error) {
	return io.ReadAll(response.Body)
}
func decodeBoundedCompatibleJSONDocumentResponse(response *http.Response, target any) error {
	payload, err := readBoundedResponseBody(response)
	if err != nil { return err }
	return decodeCompatibleJSONDocument(bytes.NewReader(payload), target)
}
func decodeCompatibleJSONDocument(reader io.Reader, target any) error {
	decoder := json.NewDecoder(reader)
	if err := decoder.Decode(target); err != nil { return err }
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); err != io.EOF { return err }
	return nil
}
`
	baselinePackage := typeCheckSyntheticProductionPackage(t, "submit.go", base)
	baseline, err := trancheB1BuildPostFreezeClosure(baselinePackage)
	if err != nil {
		t.Fatalf("synthetic B2 response topology baseline failed: %v", err)
	}
	wantStructured := trancheB1InventoryOccurrences(`
submit.go:decodeBoundedCompatibleJSONDocumentResponse->bytes:bytes.NewReader 1
submit.go:decodeBoundedCompatibleJSONDocumentResponse->synthetic/admission.decodeCompatibleJSONDocument 1
submit.go:decodeBoundedCompatibleJSONDocumentResponse->synthetic/admission.readBoundedResponseBody 1
submit.go:decodeCompatibleJSONDocument->encoding/json:(*encoding/json.Decoder).Decode 2
submit.go:decodeCompatibleJSONDocument->encoding/json:encoding/json.NewDecoder 1
submit.go:nomadClient.submitJob->synthetic/admission.decodeBoundedCompatibleJSONDocumentResponse 1
submit.go:readBoundedResponseBody->io:io.ReadAll 1
`)
	if !reflect.DeepEqual(baseline.structured, wantStructured) {
		t.Fatalf("selected B2 structured-reader object/call-site inventory = %v, want %v", baseline.structured, wantStructured)
	}
	if strings.Contains(strings.Join(baseline.dynamic, "\n"), "(error).Error") {
		t.Fatalf("fixed Submit public error unexpectedly retains a cause Error call: %v", baseline.dynamic)
	}

	for _, mutation := range []struct {
		name string
		from string
		to   string
	}{
		{
			name: "second unreviewed decoder",
			from: "decoder := json.NewDecoder(reader)",
			to:   "decoder := json.NewDecoder(reader)\n\t_ = json.NewDecoder(reader)",
		},
		{
			name: "second unreviewed body reader",
			from: "return io.ReadAll(response.Body)",
			to:   "_, _ = io.ReadAll(response.Body)\n\treturn io.ReadAll(response.Body)",
		},
		{
			name: "selected one-document decoder removed",
			from: "return decodeCompatibleJSONDocument(bytes.NewReader(payload), target)",
			to:   "return json.NewDecoder(bytes.NewReader(payload)).Decode(target)",
		},
	} {
		t.Run(mutation.name, func(t *testing.T) {
			mutantSource := strings.Replace(base, mutation.from, mutation.to, 1)
			if mutantSource == base {
				t.Fatal("structured-response mutation anchor was absent")
			}
			mutantPackage := typeCheckSyntheticProductionPackage(t, "submit.go", mutantSource)
			if err := validateTrancheB1PostFreezeClosure(mutantPackage, baseline); err == nil {
				t.Fatal("unreviewed structured-response topology change escaped exact B1 accounting")
			}
		})
	}
}

func TestTrancheB1FiniteAssuranceRepairRetainedNomadDatacenter(t *testing.T) {
	const base = `package admission
import "net/http"
type nomadClient struct { datacenter string; client *http.Client }
type Service struct { nomadClient *nomadClient }
type resolvedRunProjection struct { datacenters []string }
type resolvedNomadJobProjection struct { datacenters []string }
type nomadJob struct { Datacenters []string; Meta map[string]string }
type executionPackageLayout struct{}
func (s *Service) resolveExecutionForSubmit() {}
func (s *Service) Submit() {
	s.resolveExecutionForSubmit()
	run := newResolvedRunProjection()
	job := buildNomadJobSpec(run.nomadJobProjection())
	s.nomadClient.submitJob(job)
}
func newResolvedRunProjection() resolvedRunProjection { return resolvedRunProjection{datacenters: []string{"captured"}} }
func (run resolvedRunProjection) nomadJobProjection() resolvedNomadJobProjection {
	return resolvedNomadJobProjection{datacenters: append([]string(nil), run.datacenters...)}
}
func buildNomadJobSpec(provider resolvedNomadJobProjection) *nomadJob {
	return &nomadJob{Datacenters: append([]string(nil), provider.datacenters...), Meta: map[string]string{}}
}
func buildResolvedExecutionAuthorityHandoff() {}
func executionAuthorityMetadata() {}
func (executionPackageLayout) runtimeMountSpecs() {}
func (c *nomadClient) submitJob(job *nomadJob) { c.client.CloseIdleConnections(); _ = job }
`
	baselinePackage := typeCheckSyntheticProductionPackage(t, "submit.go", base)
	baseline, err := trancheB1BuildPostFreezeClosure(baselinePackage)
	if err != nil {
		t.Fatalf("typed provider/Nomad transport baseline failed: %v", err)
	}
	if err := validateTrancheB1PostFreezeClosure(baselinePackage, baseline); err != nil {
		t.Fatalf("typed provider/Nomad transport inventory was not stable: %v", err)
	}

	for _, test := range []struct {
		name             string
		mutant           string
		inventoryFailure bool
	}{
		{
			name:   "direct provider override",
			mutant: strings.Replace(base, `func (c *nomadClient) submitJob(job *nomadJob) { c.client.CloseIdleConnections(); _ = job }`, `func (c *nomadClient) submitJob(job *nomadJob) { job.Datacenters = []string{c.datacenter}; c.client.CloseIdleConnections() }`, 1),
		},
		{
			name:   "helper-indirected read",
			mutant: strings.Replace(base, `func (c *nomadClient) submitJob(job *nomadJob) { c.client.CloseIdleConnections(); _ = job }`, "func (c *nomadClient) submitJob(job *nomadJob) { job.Datacenters = []string{retainedDatacenter(c)}; c.client.CloseIdleConnections() }\nfunc retainedDatacenter(c *nomadClient) string { return c.datacenter }", 1),
		},
		{
			name:   "closure-captured read",
			mutant: strings.Replace(base, `func (c *nomadClient) submitJob(job *nomadJob) { c.client.CloseIdleConnections(); _ = job }`, `func (c *nomadClient) submitJob(job *nomadJob) { read := func() string { return c.datacenter }; job.Datacenters = []string{read()}; c.client.CloseIdleConnections() }`, 1),
		},
		{
			name:   "metadata helper read",
			mutant: strings.Replace(base, `func (c *nomadClient) submitJob(job *nomadJob) { c.client.CloseIdleConnections(); _ = job }`, "func (c *nomadClient) submitJob(job *nomadJob) { copyRetainedDatacenter(c, job.Meta); c.client.CloseIdleConnections() }\nfunc copyRetainedDatacenter(c *nomadClient, metadata map[string]string) { metadata[\"datacenter\"] = c.datacenter }", 1),
		},
		{
			name:   "second same-function field reference",
			mutant: strings.Replace(base, `func (c *nomadClient) submitJob(job *nomadJob) { c.client.CloseIdleConnections(); _ = job }`, `func (c *nomadClient) submitJob(job *nomadJob) { job.Datacenters = []string{c.datacenter, c.datacenter}; c.client.CloseIdleConnections() }`, 1),
		},
		{
			name:             "reviewed function-valued site",
			mutant:           strings.Replace(base, `func (c *nomadClient) submitJob(job *nomadJob) { c.client.CloseIdleConnections(); _ = job }`, "func (c *nomadClient) submitJob(job *nomadJob) { read := retainedDatacenter; job.Datacenters = []string{read(c)}; c.client.CloseIdleConnections() }\nfunc retainedDatacenter(c *nomadClient) string { return c.datacenter }", 1),
			inventoryFailure: true,
		},
		{
			name:             "second same-function call occurrence",
			mutant:           strings.Replace(base, `func (c *nomadClient) submitJob(job *nomadJob) { c.client.CloseIdleConnections(); _ = job }`, `func (c *nomadClient) submitJob(job *nomadJob) { c.client.CloseIdleConnections(); c.client.CloseIdleConnections(); _ = job }`, 1),
			inventoryFailure: true,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			pkg := typeCheckSyntheticProductionPackage(t, "submit.go", test.mutant)
			if test.inventoryFailure {
				if err := validateTrancheB1PostFreezeClosure(pkg, baseline); err == nil {
					t.Fatal("function-valued retained datacenter mutation escaped the exact dynamic inventory")
				}
				return
			}
			_, buildErr := trancheB1BuildPostFreezeClosure(pkg)
			if buildErr == nil || !strings.Contains(buildErr.Error(), "reads forbidden retained nomadClient.datacenter") {
				t.Fatalf("retained datacenter mutation error = %v, want exact object-identity read failure", buildErr)
			}
		})
	}

	t.Run("unreachable lifecycle use remains outside B1 closure", func(t *testing.T) {
		positive := base + `
func (c *nomadClient) lifecycleDatacenterOutsideSubmitProjection() string { return c.datacenter }
`
		pkg := typeCheckSyntheticProductionPackage(t, "submit.go", positive)
		if _, err := trancheB1BuildPostFreezeClosure(pkg); err != nil {
			t.Fatalf("unreachable lifecycle use was accidentally frozen: %v", err)
		}
	})
}

func validateTrancheB1StructInventories(sources map[string]string) error {
	want := map[string][]string{
		"resolvedRuntimeCommand": {
			"privateExecutionValue", "executable:string", "arguments:[]string",
		},
		"resolvedMountPlan": {
			"privateExecutionValue", "artifactDigest:string", "verifiedArtifactDigest:string", "payloadDigest:string", "targetPath:string", "readOnly:bool",
		},
		"resolvedPlanFacts": {
			"privateExecutionValue", "requestSchemaVersion:string", "invocationSchemaVersion:string", "mode:ExecutionMode", "timeoutSeconds:int", "resources:resolvedTaskResources", "runtimeProfile:resolvedRuntimeProfile", "artifactDigest:string", "payloadDigest:string", "derivationSpecDigest:string", "outputID:string", "runtimeCommand:resolvedRuntimeCommand", "semanticEnvironment:map[string]string", "mounts:[]resolvedMountPlan", "networkAccess:bool", "authority:resolvedAuthorityPlan", "runtimeSupportDigest:string", "runtimeIdentityTmpfsSize:int64", "jobEnvelope:resolvedJobEnvelope",
		},
		"resolvedExecutionPlan": {
			"privateExecutionValue", "requestSchemaVersion:string", "invocationSchemaVersion:string", "mode:ExecutionMode", "timeoutSeconds:int", "resources:resolvedTaskResources", "runtimeProfile:resolvedRuntimeProfile", "artifactDigest:string", "payloadDigest:string", "derivationSpecDigest:string", "outputID:string", "runtimeCommand:resolvedRuntimeCommand", "semanticEnvironment:map[string]string", "mounts:[]resolvedMountPlan", "networkAccess:bool", "authority:resolvedAuthorityPlan", "runtimeSupportDigest:string", "runtimeIdentityTmpfsSize:int64", "jobEnvelope:resolvedJobEnvelope",
		},
		"resolvedMaterialFacts": {
			"privateExecutionValue", "payloadBytes:[]byte", "runtimeSupportBytes:[]byte", "mounts:[]validatedMountArchive", "trust:resolvedTrustMaterial",
		},
		"resolvedExecutionMaterial": {
			"privateExecutionValue", "payloadBytes:[]byte", "runtimeSupportBytes:[]byte", "mounts:[]validatedMountArchive", "trust:resolvedTrustMaterial",
		},
		"hostMaterializationContext": {
			"privateExecutionValue", "stagingRootDir:string", "owner:executionPlatformStateOwner", "spireSourceDir:string", "datacenter:string",
		},
		"normalizedSubmitPlacementFacts": {
			"privateExecutionValue", "stagingRootDir:string", "resultsRootDir:string", "spireSourceDir:string", "datacenter:string",
		},
		"resolvedRunProjection": {
			"privateExecutionValue", "runID:string", "jobID:string", "layout:executionPackageLayout", "runtimeCommand:resolvedRuntimeCommand", "runtimeImage:string", "environment:map[string]string", "mounts:[]resolvedMountPlan", "networkMode:string", "resources:resolvedTaskResources", "runtimeMountInputs:resolvedRuntimeMountInputs", "jobEnvelope:resolvedJobEnvelope", "datacenters:[]string", "artifactDigest:string", "derivationDigest:string", "outputID:string", "authorityHandoff:executionAuthorityHandoffProjection",
		},
		"resolvedNomadJobProjection": {
			"privateExecutionValue", "runID:string", "jobID:string", "layout:executionPackageLayout", "runtimeCommand:resolvedRuntimeCommand", "runtimeImage:string", "environment:map[string]string", "stagedMounts:[]stagedRuntimeMount", "networkMode:string", "resources:resolvedTaskResources", "runtimeMountInputs:resolvedRuntimeMountInputs", "jobEnvelope:resolvedJobEnvelope", "datacenters:[]string", "artifactDigest:string", "derivationDigest:string", "outputID:string", "authorityMetadata:executionAuthorityMetadataProjection",
		},
	}
	got := make(map[string][]string, len(want))
	for fileName, source := range sources {
		if fileName != "executionpackage.go" && fileName != "resolved_execution_plan.go" {
			continue
		}
		file, err := parser.ParseFile(token.NewFileSet(), fileName, source, parser.AllErrors)
		if err != nil {
			return err
		}
		for _, declaration := range file.Decls {
			general, ok := declaration.(*ast.GenDecl)
			if !ok || general.Tok != token.TYPE {
				continue
			}
			for _, specification := range general.Specs {
				typeSpec := specification.(*ast.TypeSpec)
				expected, governed := want[typeSpec.Name.Name]
				if !governed {
					continue
				}
				structure, ok := typeSpec.Type.(*ast.StructType)
				if !ok {
					return fmt.Errorf("B1 governed type %s is no longer a struct", typeSpec.Name.Name)
				}
				fields := make([]string, 0, len(structure.Fields.List))
				for _, field := range structure.Fields.List {
					fieldType := trancheB1ASTTypeName(field.Type)
					if len(field.Names) == 0 {
						fields = append(fields, fieldType)
						continue
					}
					for _, name := range field.Names {
						fields = append(fields, name.Name+":"+fieldType)
					}
				}
				if !reflect.DeepEqual(fields, expected) {
					return fmt.Errorf("B1 field inventory changed for %s: got %v want %v", typeSpec.Name.Name, fields, expected)
				}
				got[typeSpec.Name.Name] = fields
			}
		}
	}
	if len(got) != len(want) {
		return fmt.Errorf("B1 field inventory is incomplete: found %d of %d types", len(got), len(want))
	}
	return nil
}

func trancheB1ASTTypeName(expression ast.Expr) string {
	switch typed := expression.(type) {
	case *ast.Ident:
		return typed.Name
	case *ast.StarExpr:
		return "*" + trancheB1ASTTypeName(typed.X)
	case *ast.ArrayType:
		return "[]" + trancheB1ASTTypeName(typed.Elt)
	case *ast.MapType:
		return "map[" + trancheB1ASTTypeName(typed.Key) + "]" + trancheB1ASTTypeName(typed.Value)
	case *ast.SelectorExpr:
		return trancheB1ASTTypeName(typed.X) + "." + typed.Sel.Name
	default:
		return "<unsupported>"
	}
}

func validateTrancheB1BoundedSourceInventories(sources map[string]string) error {
	resolved := sources["resolved_execution_plan.go"]
	executionPackage := sources["executionpackage.go"]
	service := sources["service.go"]
	submit := sources["submit.go"]
	if resolved == "" || executionPackage == "" || service == "" || submit == "" {
		return fmt.Errorf("B1 source inventory is incomplete")
	}
	planSection, err := trancheB1SourceSection(resolved, "type resolvedPlanFacts struct", "type resolvedTrustMaterial struct")
	if err != nil {
		return err
	}
	for _, forbidden := range []string{"stagingRootDir", "resultsRootDir", "owner", "spireSourceDir", "datacenter", "runID", "jobID", "networkMode", "runtimeArguments", "[]byte", "PrepareRequest", "esconfig.Config"} {
		if strings.Contains(planSection, forbidden) {
			return fmt.Errorf("semantic plan retains forbidden host/run/raw fact %q", forbidden)
		}
	}
	authoritySection, err := trancheB1SourceSection(resolved, "type resolvedAuthorityPlan struct", "type resolvedPlanFacts struct")
	if err != nil {
		return err
	}
	if strings.Contains(authoritySection, "applicable") {
		return fmt.Errorf("current authority plan regained an inapplicable state")
	}
	runSection, err := trancheB1SourceSection(resolved, "func newResolvedRunProjection", "func (run resolvedRunProjection) nomadJobProjection")
	if err != nil {
		return err
	}
	for _, forbidden := range []string{"PrepareRequest", "preparedAdmission", "esconfig.", "s.cfg", "runtimeProfile.env", "runtimeProfile.environment", "payloadDigest", "resolveExecutionRuntimeProfile", "resolveExecutionPlatformStateOwnerModel"} {
		if strings.Contains(runSection, forbidden) {
			return fmt.Errorf("run projection rereads forbidden post-freeze source %q", forbidden)
		}
	}
	for value, count := range map[string]int{
		"host.spireSourceDir":                         1,
		"host.datacenter":                             1,
		"environment[platformStateOwnerUIDEnvKey]":    1,
		"environment[platformStateOwnerGIDEnvKey]":    1,
		"environment[platformStateOwnerSchemaEnvKey]": 1,
	} {
		if strings.Count(runSection, value) != count {
			return fmt.Errorf("host-only injection inventory changed for %q", value)
		}
	}
	providerSection, err := trancheB1SourceSection(resolved, "func (run resolvedRunProjection) nomadJobProjection", "func copyResolvedRuntimeProfile")
	if err != nil {
		return err
	}
	for _, forbidden := range []string{"PrepareRequest", "preparedAdmission", "esconfig.", "*Service", "s.cfg", "runtimeProfile.environment", "runtimeProfile.env", "payloadDigest", "host."} {
		if strings.Contains(providerSection, forbidden) {
			return fmt.Errorf("provider projection rereads forbidden post-freeze source %q", forbidden)
		}
	}
	if strings.Count(resolved, "payloadDigest:           prepared.artifact.payloadDigest") != 1 {
		return fmt.Errorf("payload digest must have one cross-checked plan producer")
	}
	jobBuilderSection, err := trancheB1SourceSection(submit, "func buildNomadJobSpec", "func newNomadClient")
	if err != nil {
		return err
	}
	if strings.Contains(providerSection, "payloadDigest") || strings.Contains(jobBuilderSection, "payloadDigest") {
		return fmt.Errorf("payload digest widened beyond the private semantic plan")
	}
	if strings.Contains(resolved, "resolvedRuntimeSupervisorArgs") || strings.Contains(executionPackage, "runtimeSupervisorArgs") {
		return fmt.Errorf("duplicate runtime command grammar returned")
	}
	normalizePathSection, err := trancheB1SourceSection(resolved, "func normalizeAbsoluteSubmitPath", "func normalizeSubmitPlacementFacts")
	if err != nil {
		return err
	}
	for _, required := range []string{"strings.TrimSpace(raw)", "filepath.Clean(trimmed)", "filepath.IsAbs(cleaned)"} {
		if strings.Count(normalizePathSection, required) != 1 {
			return fmt.Errorf("absolute host-path normalization inventory changed for %q", required)
		}
	}
	placementSection, err := trancheB1SourceSection(resolved, "func normalizeSubmitPlacementFacts", "func newHostMaterializationContext")
	if err != nil {
		return err
	}
	for _, required := range []string{
		`normalizeAbsoluteSubmitPath("execution staging root", config.stagingRootDir)`,
		`normalizeAbsoluteSubmitPath("execution results root", config.resultsRootDir)`,
		`normalizeAbsoluteSubmitPath("SPIRE workload API socket", config.spireWorkloadAPISocketPath)`,
		"spireSourceDir := filepath.Dir(spireSocketPath)",
		"filepath.IsAbs(spireSourceDir)",
		"datacenter := strings.TrimSpace(config.datacenter)",
	} {
		if strings.Count(placementSection, required) != 1 {
			return fmt.Errorf("normalized submit-placement inventory changed for %q", required)
		}
	}
	literalSites, err := trancheB1GrammarLiteralSites("executionpackage.go", executionPackage)
	if err != nil {
		return err
	}
	wantLiterals := []string{"--", "--entrypoint", "--payload-archive", "--result-dir", "--timeout-seconds", "--work-dir", "supervisor"}
	for _, literal := range wantLiterals {
		if !reflect.DeepEqual(literalSites[literal], []string{"executionpackage.go:newResolvedRuntimeCommand"}) {
			return fmt.Errorf("runtime command grammar inventory changed for %q: %v", literal, literalSites[literal])
		}
	}
	producerSites, err := trancheB1CompositeLiteralSites(map[string]string{"executionpackage.go": executionPackage, "resolved_execution_plan.go": resolved}, "resolvedRuntimeCommand")
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(producerSites, []string{"executionpackage.go:newResolvedRuntimeCommand"}) {
		return fmt.Errorf("typed runtime command producer inventory changed: %v", producerSites)
	}
	prepareSection, err := trancheB1SourceSection(service, "func (s *Service) prepareAdmission", "func (s *Service) prepareArtifact")
	if err != nil {
		return err
	}
	firstStatement := strings.Index(prepareSection, "req = snapshotAdmissionRequest(req)")
	modeMutation := strings.Index(prepareSection, "req.Mode = ExecutionModeAsync")
	validation := strings.Index(prepareSection, "validatePrepareRequest(&req)")
	if firstStatement < 0 || modeMutation < firstStatement || validation < modeMutation || strings.Count(prepareSection, "snapshotAdmissionRequest(req)") != 2 {
		return fmt.Errorf("one admission-owned mutable snapshot order changed")
	}
	prefix := prepareSection[:firstStatement]
	if strings.Contains(prefix, "req.") {
		return fmt.Errorf("caller-owned request is used or mutated before deep copy")
	}
	if strings.Count(service, "validatePrepareRequest(&req)") != 1 {
		return fmt.Errorf("admission request validation/defaulting gained a second mutable owner")
	}
	resolverSection, err := trancheB1SourceSection(resolved, "func (s *Service) resolveExecutionForSubmit", "func captureRuntimeSupport")
	if err != nil {
		return err
	}
	if strings.Contains(resolverSection, "request.Mode") || strings.Count(resolverSection, "admissionIntentSubmit") != 1 {
		return fmt.Errorf("Submit mode has a second owner outside admission")
	}
	for _, required := range []string{
		"placement, placementErr := normalizeSubmitPlacementFacts(config)",
		"resolveExecutionPlatformStateOwnerModel(placement.stagingRootDir, placement.resultsRootDir, nil)",
		"placement.stagingRootDir",
		"placement.spireSourceDir",
		"placement.datacenter",
	} {
		if !strings.Contains(resolverSection, required) {
			return fmt.Errorf("normalized host-context capture lost %q", required)
		}
	}
	for _, raw := range []string{"filepath.Dir(config.spireWorkloadAPISocketPath)", "newHostMaterializationContext(\n\t\tconfig.stagingRootDir", "\n\t\tconfig.datacenter"} {
		if strings.Contains(resolverSection, raw) {
			return fmt.Errorf("host-context capture rereads raw configured fact %q", raw)
		}
	}
	jobSites, err := trancheB1NomadJobLiteralSites("submit.go", submit)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(jobSites, []string{"submit.go:buildNomadJobSpec"}) {
		return fmt.Errorf("Nomad Job literal producer inventory changed: %v", jobSites)
	}
	return nil
}

func validateTrancheB1PayloadProjectionSources(sources map[string]string) error {
	resolved := sources["resolved_execution_plan.go"]
	submit := sources["submit.go"]
	authority := sources["authorityhandoff.go"]
	publicTypes := sources["types.go"]
	if resolved == "" || submit == "" || authority == "" || publicTypes == "" {
		return fmt.Errorf("payload projection source inventory is incomplete")
	}
	provider, err := trancheB1SourceSection(resolved, "func (run resolvedRunProjection) nomadJobProjection", "func copyResolvedRuntimeProfile")
	if err != nil {
		return err
	}
	jobBuilder, err := trancheB1SourceSection(submit, "func buildNomadJobSpec", "func newNomadClient")
	if err != nil {
		return err
	}
	authorityBuilder, err := trancheB1SourceSection(authority, "func buildResolvedExecutionAuthorityHandoff", "func buildExecutionAuthorityHandoff")
	if err != nil {
		return err
	}
	metadata, err := trancheB1SourceSection(authority, "func executionAuthorityMetadata", "func executionAuthorityHandoffFromSubmittedRuntimeSpec")
	if err != nil {
		return err
	}
	for label, source := range map[string]string{
		"provider projection": provider,
		"Nomad job":           jobBuilder,
		"authority handoff":   authorityBuilder,
		"provider metadata":   metadata,
		"public DTOs":         publicTypes,
	} {
		lower := strings.ToLower(source)
		if strings.Contains(source, "payloadDigest") || strings.Contains(lower, "payload_digest") {
			return fmt.Errorf("private payload digest widened into %s", label)
		}
	}
	for value, count := range map[string]int{
		"executionAuthorityMetadataSchemaKey:                  executionAuthorityMetadataSchemaVersion":  1,
		"executionAuthorityMetadataRuntimeProfileKey:          projection.runtimeProfileName":            1,
		"executionAuthorityMetadataWorkloadZoneVaultConfigKey: projection.workloadZoneVaultConfigDigest": 1,
	} {
		if strings.Count(metadata, value) != count {
			return fmt.Errorf("provider authority metadata key/source inventory changed for %q", value)
		}
	}
	if strings.Count(jobBuilder, `jobMeta["run_id"] = projection.runID`) != 1 {
		return fmt.Errorf("provider run metadata key/source inventory changed")
	}
	file, err := parser.ParseFile(token.NewFileSet(), "types.go", publicTypes, parser.AllErrors)
	if err != nil {
		return err
	}
	for _, declaration := range file.Decls {
		general, ok := declaration.(*ast.GenDecl)
		if !ok || general.Tok != token.TYPE {
			continue
		}
		for _, specification := range general.Specs {
			typeSpec, ok := specification.(*ast.TypeSpec)
			if !ok || !typeSpec.Name.IsExported() {
				continue
			}
			structure, ok := typeSpec.Type.(*ast.StructType)
			if !ok {
				continue
			}
			for _, field := range structure.Fields.List {
				for _, name := range field.Names {
					if strings.Contains(strings.ToLower(name.Name), "payloaddigest") {
						return fmt.Errorf("public DTO %s exposes payload digest field %s", typeSpec.Name.Name, name.Name)
					}
				}
				if field.Tag != nil && strings.Contains(strings.ToLower(field.Tag.Value), "payload_digest") {
					return fmt.Errorf("public DTO %s exposes payload_digest JSON field", typeSpec.Name.Name)
				}
			}
		}
	}
	return nil
}

func validateTrancheB1LiteralGoldenSource(resolvedTestSource string, submitTestSource string) error {
	if strings.Contains(resolvedTestSource, "newNomadJobTestProjection") || strings.Contains(submitTestSource, "newNomadJobTestProjection") {
		return fmt.Errorf("self-confirming Nomad projection helper returned")
	}
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "resolved_execution_plan_test.go", resolvedTestSource, parser.AllErrors)
	if err != nil {
		return err
	}
	directStringConstants := map[string]bool{
		"trancheB1DefaultNomadJobGolden":         false,
		"trancheB1DefaultAuthorityHandoffGolden": false,
	}
	directLedgers := map[string]bool{
		"trancheB1DefaultNomadJobTokenLedger":         false,
		"trancheB1DefaultAuthorityHandoffTokenLedger": false,
	}
	var goldenTest *ast.FuncDecl
	for _, declaration := range file.Decls {
		switch typed := declaration.(type) {
		case *ast.GenDecl:
			for _, specification := range typed.Specs {
				valueSpec, ok := specification.(*ast.ValueSpec)
				if !ok {
					continue
				}
				for index, name := range valueSpec.Names {
					if _, governed := directStringConstants[name.Name]; governed {
						if typed.Tok != token.CONST || len(valueSpec.Values) != len(valueSpec.Names) {
							return fmt.Errorf("golden expected truth %s must be one direct constant string literal", name.Name)
						}
						literal, ok := valueSpec.Values[index].(*ast.BasicLit)
						if !ok || literal.Kind != token.STRING {
							return fmt.Errorf("golden expected truth %s is composed or helper-derived", name.Name)
						}
						directStringConstants[name.Name] = true
					}
					if _, governed := directLedgers[name.Name]; governed {
						if typed.Tok != token.VAR || len(valueSpec.Values) != len(valueSpec.Names) {
							return fmt.Errorf("golden ledger %s must be one direct variable literal", name.Name)
						}
						ledger, ok := valueSpec.Values[index].(*ast.CompositeLit)
						if !ok || trancheB1ASTTypeName(ledger.Type) != "[]trancheB1GoldenTokenOccurrence" || len(ledger.Elts) == 0 {
							return fmt.Errorf("golden ledger %s is not a direct non-empty token-pointer literal", name.Name)
						}
						for _, element := range ledger.Elts {
							entry, ok := element.(*ast.CompositeLit)
							if !ok || len(entry.Elts) != 3 {
								return fmt.Errorf("golden ledger %s contains a helper-derived entry", name.Name)
							}
							for _, field := range entry.Elts {
								keyValue, ok := field.(*ast.KeyValueExpr)
								if !ok {
									return fmt.Errorf("golden ledger %s entry is not keyed direct literal", name.Name)
								}
								literal, literalOK := keyValue.Value.(*ast.BasicLit)
								if !literalOK || literal.Kind != token.STRING {
									return fmt.Errorf("golden ledger %s entry is not entirely direct literal", name.Name)
								}
							}
						}
						directLedgers[name.Name] = true
					}
				}
			}
		case *ast.FuncDecl:
			if typed.Name.Name == "TestTrancheB1DefaultProfileLiteralNomadJobAndAuthorityHandoff" {
				goldenTest = typed
			}
		}
	}
	for name, found := range directStringConstants {
		if !found {
			return fmt.Errorf("direct literal golden declaration %s is absent", name)
		}
	}
	for name, found := range directLedgers {
		if !found {
			return fmt.Errorf("direct literal golden ledger %s is absent", name)
		}
	}
	if goldenTest == nil || goldenTest.Body == nil {
		return fmt.Errorf("complete literal golden owning test is absent")
	}
	section := resolvedTestSource[fset.Position(goldenTest.Pos()).Offset:fset.Position(goldenTest.End()).Offset]
	for _, required := range []string{
		"service.Submit(context.Background(), request)",
		"json.Unmarshal(submittedBody, &actualJob)",
		"json.Unmarshal([]byte(trancheB1DefaultNomadJobGolden), &expectedJob)",
		"json.Unmarshal([]byte(trancheB1DefaultAuthorityHandoffGolden), &expectedHandoff)",
		"rejectTrancheB1ActualGoldenTokens(actualJob)",
		"rejectTrancheB1ActualGoldenTokens(actualHandoff)",
		"expandTrancheB1ExpectedGolden(expectedJob, trancheB1DefaultNomadJobTokenLedger, values)",
		"expandTrancheB1ExpectedGolden(expectedHandoff, trancheB1DefaultAuthorityHandoffTokenLedger, values)",
		"registrationCalls != 1",
	} {
		if strings.Count(section, required) != 1 {
			return fmt.Errorf("literal golden source lost required independent step %q", required)
		}
	}
	for _, forbidden := range []string{"newResolvedExecutionPlan", "newResolvedRunProjection", ".nomadJobProjection", "buildNomadJobSpec", "resolvedSemanticRuntimeEnvironment", "newResolvedRuntimeCommand", "json.Unmarshal(submittedBody, &expectedJob)", "normalizeTrancheB1GoldenTree", "os.ReadFile", "golden generator"} {
		if strings.Contains(section, forbidden) {
			return fmt.Errorf("literal golden expected value became production-derived through %q", forbidden)
		}
	}
	ast.Inspect(goldenTest.Body, func(node ast.Node) bool {
		switch typed := node.(type) {
		case *ast.AssignStmt:
			for _, lhs := range typed.Lhs {
				if trancheB1ExpressionContainsIdentifier(lhs, "expectedJob") || trancheB1ExpressionContainsIdentifier(lhs, "expectedHandoff") {
					err = fmt.Errorf("literal golden expected tree is assigned from an external value at %s", fset.Position(lhs.Pos()))
					return false
				}
			}
		case *ast.CallExpr:
			usesExpected := false
			for _, argument := range typed.Args {
				if trancheB1ExpressionContainsIdentifier(argument, "expectedJob") || trancheB1ExpressionContainsIdentifier(argument, "expectedHandoff") {
					usesExpected = true
				}
			}
			if usesExpected {
				callee := exprSourceName(typed.Fun)
				if callee != "json.Unmarshal" && callee != "expandTrancheB1ExpectedGolden" {
					err = fmt.Errorf("literal golden expected tree flows through unreviewed helper %s", callee)
					return false
				}
			}
		}
		return true
	})
	if err != nil {
		return err
	}
	expansionSection, expansionErr := trancheB1SourceSection(resolvedTestSource, "func expandTrancheB1ExpectedGolden", "func trancheB1ExpandExpectedValue")
	if expansionErr != nil {
		return expansionErr
	}
	if strings.Contains(expansionSection, "actual") {
		return fmt.Errorf("expected-only golden expansion regained access to actual JSON")
	}
	return nil
}

func trancheB1ExpressionContainsIdentifier(expression ast.Expr, name string) bool {
	found := false
	ast.Inspect(expression, func(node ast.Node) bool {
		identifier, ok := node.(*ast.Ident)
		if ok && identifier.Name == name {
			found = true
			return false
		}
		return !found
	})
	return found
}

func trancheB1SourceSection(source string, start string, end string) (string, error) {
	startIndex := strings.Index(source, start)
	if startIndex < 0 {
		return "", fmt.Errorf("B1 source section start %q not found", start)
	}
	endIndex := strings.Index(source[startIndex+len(start):], end)
	if endIndex < 0 {
		return "", fmt.Errorf("B1 source section end %q not found after %q", end, start)
	}
	return source[startIndex : startIndex+len(start)+endIndex], nil
}

func trancheB1GrammarLiteralSites(fileName string, source string) (map[string][]string, error) {
	file, err := parser.ParseFile(token.NewFileSet(), fileName, source, parser.AllErrors)
	if err != nil {
		return nil, err
	}
	parents := astParentMap(file)
	wanted := map[string]bool{"supervisor": true, "--payload-archive": true, "--work-dir": true, "--result-dir": true, "--entrypoint": true, "--timeout-seconds": true, "--": true}
	sites := make(map[string][]string, len(wanted))
	ast.Inspect(file, func(node ast.Node) bool {
		literal, ok := node.(*ast.BasicLit)
		if !ok || literal.Kind != token.STRING {
			return true
		}
		value, unquoteErr := strconv.Unquote(literal.Value)
		if unquoteErr != nil || !wanted[value] {
			return true
		}
		site := typedFunctionSite(fileName, enclosingFunction(parents, literal))
		sites[value] = append(sites[value], site)
		return true
	})
	for literal := range sites {
		sort.Strings(sites[literal])
	}
	return sites, nil
}

func trancheB1CompositeLiteralSites(sources map[string]string, typeName string) ([]string, error) {
	var sites []string
	for fileName, source := range sources {
		file, err := parser.ParseFile(token.NewFileSet(), fileName, source, parser.AllErrors)
		if err != nil {
			return nil, err
		}
		parents := astParentMap(file)
		ast.Inspect(file, func(node ast.Node) bool {
			literal, ok := node.(*ast.CompositeLit)
			if !ok || trancheB1ASTTypeName(literal.Type) != typeName {
				return true
			}
			sites = append(sites, typedFunctionSite(fileName, enclosingFunction(parents, literal)))
			return true
		})
	}
	sort.Strings(sites)
	return sites, nil
}

func trancheB1NomadJobLiteralSites(fileName string, source string) ([]string, error) {
	file, err := parser.ParseFile(token.NewFileSet(), fileName, source, parser.AllErrors)
	if err != nil {
		return nil, err
	}
	parents := astParentMap(file)
	var sites []string
	ast.Inspect(file, func(node ast.Node) bool {
		literal, ok := node.(*ast.CompositeLit)
		if !ok {
			return true
		}
		for _, element := range literal.Elts {
			keyValue, ok := element.(*ast.KeyValueExpr)
			if !ok {
				continue
			}
			key, ok := keyValue.Key.(*ast.BasicLit)
			if !ok || key.Kind != token.STRING {
				continue
			}
			value, unquoteErr := strconv.Unquote(key.Value)
			if unquoteErr == nil && value == "Job" {
				sites = append(sites, typedFunctionSite(fileName, enclosingFunction(parents, literal)))
			}
		}
		return true
	})
	sort.Strings(sites)
	return sites, nil
}

func TestAdmissionProductionHasOneResolverAndOneMaterializationPath(t *testing.T) {
	views := loadTypedProductionPackages(t, "./es/admission")
	resolverReferences := mergedProductionReferences(t, views, "execution-substrate/es/admission", func(pkg *typedProductionPackage) types.Object {
		return requirePackageMethod(t, pkg, "Service", "resolveExecutionForSubmit")
	})
	if err := validateTypedReferenceInventory("legacy and selected private resolver callers", resolverReferences, map[string]int{"es/admission/submit.go:Service.Submit": 1, "es/admission/reliable_submit_replay_private.go:Service.composePrivateSyntheticReplay": 1}, true); err != nil {
		t.Fatal(err)
	}

	type productionInventory struct {
		label        string
		receiverName string
		functionName string
		want         map[string]int
	}
	inventories := []productionInventory{
		{
			label:        "operation-local execution-root qualification",
			functionName: "qualifyExecutionRoots",
			want: map[string]int{
				"es/admission/execution_roots.go:provisionExecutionRoots":          3,
				"es/admission/results.go:Service.readRetainedResultBundle":         1,
				"es/admission/results.go:Service.reconcileRetainedResultArtifacts": 1,
				"es/admission/results.go:Service.retainTerminalResultWithHooks":    1,
				"es/admission/submit.go:Service.Submit":                            1,
			},
		},
		{
			label:        "startup execution-root provisioner",
			functionName: "provisionExecutionRoots",
			want:         map[string]int{"es/admission/service.go:NewService": 1},
		},
		{
			label:        "test-facing path-taking staging-tree opener",
			functionName: "openStagingTree",
			want:         map[string]int{},
		},
		{
			label:        "descriptor-taking staging-tree opener",
			functionName: "openStagingTreeFromQualifiedRoot",
			want: map[string]int{
				"es/admission/results.go:Service.retainTerminalResultWithHooks": 1,
				"es/admission/staging_custody.go:openStagingTree":               1,
			},
		},
		{
			label:        "test-facing path-taking run-root claim",
			functionName: "claimStagingCustody",
			want:         map[string]int{},
		},
		{
			label:        "descriptor-taking run-root claim",
			functionName: "claimStagingCustodyFromQualifiedRoot",
			want: map[string]int{
				"es/admission/staging_custody.go:claimStagingCustody":             1,
				"es/admission/staging_custody.go:probeStagingCustodyCapabilities": 1,
				"es/admission/submit.go:Service.Submit":                           1,
			},
		},
		{
			label:        "test-facing path-taking retained-result opener",
			functionName: "openRetainedResultDirectory",
			want:         map[string]int{},
		},
		{
			label:        "existing retained-result opener",
			functionName: "openExistingRetainedResultDirectory",
			want:         map[string]int{"es/admission/results.go:Service.readRetainedResultBundle": 1},
		},
		{
			label:        "create-capable retained-result opener",
			functionName: "openOrCreateRetainedResultDirectory",
			want: map[string]int{
				"es/admission/results.go:Service.reconcileRetainedResultArtifacts": 1,
				"es/admission/results.go:Service.retainTerminalResultWithHooks":    1,
			},
		},
		{
			label:        "descriptor-taking retained-result opener",
			functionName: "openRetainedResultDirectoryFromQualifiedRoot",
			want: map[string]int{
				"es/admission/results.go:openExistingRetainedResultDirectory": 1,
				"es/admission/results.go:openOrCreateRetainedResultDirectory": 1,
				"es/admission/results.go:openRetainedResultDirectory":         1,
			},
		},
		{
			label:        "typed execution materializer",
			functionName: "materializeExecutionInputs",
			want:         map[string]int{"es/admission/submit.go:Service.Submit": 1},
		},
		{
			label:        "qualified staging descriptor transfer",
			receiverName: "qualifiedExecutionRoots",
			functionName: "takeStagingQualifiedDirectory",
			want:         map[string]int{"es/admission/submit.go:Service.Submit": 1},
		},
		{
			label:        "qualified staging descriptor duplication",
			receiverName: "qualifiedExecutionRoots",
			functionName: "duplicateStagingQualifiedDirectory",
			want:         map[string]int{"es/admission/results.go:Service.retainTerminalResultWithHooks": 1},
		},
		{
			label:        "qualified results descriptor duplication",
			receiverName: "qualifiedExecutionRoots",
			functionName: "duplicateResultsQualifiedDirectory",
			want: map[string]int{
				"es/admission/results.go:openExistingRetainedResultDirectory": 1,
				"es/admission/results.go:openOrCreateRetainedResultDirectory": 1,
			},
		},
		{
			label:        "startup root capability probe",
			receiverName: "qualifiedExecutionRoots",
			functionName: "probeCapabilities",
			want:         map[string]int{"es/admission/service.go:NewService": 1},
		},
		{
			label:        "configured-root component creator",
			receiverName: "qualifiedExecutionRoots",
			functionName: "createNextConfiguredRootComponent",
			want:         map[string]int{"es/admission/execution_roots.go:provisionExecutionRoots": 2},
		},
		{
			label:        "retained-result effect authorization",
			receiverName: "retainedResultDirectory",
			functionName: "verifyBeforeEffect",
			want: map[string]int{
				"es/admission/results.go:retainedResultDirectory.createTempFile":                      3,
				"es/admission/results.go:retainedResultDirectory.ensureNormalizationEvidenceWithHook": 3,
				"es/admission/results.go:retainedResultDirectory.publishTemporaryBundle":              1,
				"es/admission/result_auth.go:retainedResultDirectory.publishRetainedResultRecord":     4,
			},
		},
		{
			label:        "platform no-replace publication primitive",
			functionName: "platformRenameNoReplace",
			want: map[string]int{
				"es/admission/execution_roots.go:qualifiedExecutionRoots.probeCapabilities":       1,
				"es/admission/results.go:retainedResultDirectory.publishTemporaryBundle":          1,
				"es/admission/result_auth.go:retainedResultDirectory.publishRetainedResultRecord": 1,
				"es/admission/staging_custody.go:probeStagingCustodyCapabilities":                 1,
			},
		},
		{
			label:        "payload stage",
			receiverName: "executionPackageLayout",
			functionName: "stagePayload",
			want:         map[string]int{"es/admission/executionpackage.go:materializeExecutionInputs": 1},
		},
		{
			label:        "workload trust stage",
			receiverName: "executionPackageLayout",
			functionName: "stageWorkloadVaultTrustMaterial",
			want:         map[string]int{"es/admission/executionpackage.go:materializeExecutionInputs": 1},
		},
		{
			label:        "runtime support stage",
			receiverName: "executionPackageLayout",
			functionName: "stageCapturedRuntimeSupportBinary",
			want:         map[string]int{"es/admission/executionpackage.go:materializeExecutionInputs": 1},
		},
		{
			label:        "runtime mount materializer",
			functionName: "materializeValidatedRuntimeMounts",
			want:         map[string]int{"es/admission/executionpackage.go:materializeExecutionInputs": 1},
		},
		{
			label:        "mount entry materializer",
			functionName: "materializeValidatedMountEntries",
			want:         map[string]int{"es/admission/mounts.go:materializeValidatedRuntimeMounts": 1},
		},
		{
			label:        "custody directory mutation",
			receiverName: "stagingCustody",
			functionName: "ensureDirectory",
			want: map[string]int{
				"es/admission/executionpackage.go:executionPackageLayout.stagePayload":                    1,
				"es/admission/executionpackage.go:executionPackageLayout.stageWorkloadVaultTrustMaterial": 1,
				"es/admission/mounts.go:materializeValidatedRuntimeMounts":                                2,
				"es/admission/mounts.go:materializeValidatedMountEntries":                                 2,
				"es/admission/staging_custody.go:stagingCustody.writeFileWithHookAndParentMode":           1,
			},
		},
		{
			label:        "custody file mutation",
			receiverName: "stagingCustody",
			functionName: "writeFile",
			want: map[string]int{
				"es/admission/executionpackage.go:executionPackageLayout.stagePayload":                      1,
				"es/admission/executionpackage.go:executionPackageLayout.stageWorkloadVaultTrustMaterial":   2,
				"es/admission/executionpackage.go:executionPackageLayout.stageCapturedRuntimeSupportBinary": 1,
			},
		},
		{
			label:        "governed mount file mutation uses explicit workload-readable parent mode",
			receiverName: "stagingCustody",
			functionName: "writeFileWithParentMode",
			want:         map[string]int{"es/admission/mounts.go:materializeValidatedMountEntries": 1},
		},
	}
	for _, inventory := range inventories {
		references := mergedProductionReferences(t, views, "execution-substrate/es/admission", func(pkg *typedProductionPackage) types.Object {
			if inventory.receiverName != "" {
				return requirePackageMethod(t, pkg, inventory.receiverName, inventory.functionName)
			}
			return requirePackageFunction(t, pkg, inventory.functionName)
		})
		if err := validateTypedReferenceInventory(inventory.label, references, inventory.want, true); err != nil {
			t.Fatal(err)
		}
	}
	resultsSource := mustReadAdmissionSource(t, "results.go")
	assertAdmissionFoundationOmitsAll(t, "retained result effects have no pathname temporary removal or existing-metadata repair", resultsSource,
		"func (directory *retainedResultDirectory) removeTemporary", "unix.Unlinkat", "reconcileRetainedResultRunMetadata", "reconcileRegularFile",
	)
	reobservations := mergedProductionReferences(t, views, "execution-substrate/es/admission", func(pkg *typedProductionPackage) types.Object {
		return requirePackageMethod(t, pkg, "qualifiedExecutionRoots", "reobserve")
	})
	wantReobservations := map[string]int{
		"es/admission/execution_roots.go:qualifyExecutionRoots":                               1,
		"es/admission/execution_roots.go:qualifiedExecutionRoots.probeCapabilities":           10,
		"es/admission/execution_roots.go:qualifiedExecutionRoots.probeNaturalResultDirectory": 2,
		"es/admission/results.go:openExistingRetainedResultDirectory":                         1,
		"es/admission/results.go:openOrCreateRetainedResultDirectory":                         1,
		"es/admission/service.go:NewService":                                                  1,
		"es/admission/submit.go:Service.Submit":                                               1,
	}
	if err := validateTypedObjectReferenceInventory("root-set topology reobservation", reobservations, wantReobservations, false); err != nil {
		t.Fatal(err)
	}
	for _, reference := range reobservations {
		wantMethodValue := reference.site == "es/admission/results.go:openExistingRetainedResultDirectory" ||
			reference.site == "es/admission/results.go:openOrCreateRetainedResultDirectory"
		if reference.directCall == wantMethodValue || reference.insideFuncLiteral {
			t.Fatalf("root-set reobservation changed direct-call/method-value role or entered an unexpected closure: %s", reference)
		}
	}

	creationVocabulary := map[string]map[string]int{
		"golang.org/x/sys/unix.Mkdirat": {
			"es/admission/execution_roots.go:qualifiedExecutionRoots.createNextConfiguredRootComponent": 1,
			"es/admission/execution_roots.go:qualifiedExecutionRoots.probeCapabilities":                 1,
			"es/admission/execution_roots.go:qualifiedExecutionRoots.probeNaturalResultDirectory":       1,
			"es/admission/results.go:openRetainedResultDirectoryFromQualifiedRoot":                      1,
			"es/admission/staging_custody.go:claimStagingCustodyFromQualifiedRoot":                      1,
			"es/admission/staging_custody.go:openQualifiedDirectoryClean":                               1,
			"es/admission/staging_custody.go:probeStagingCustodyCapabilities":                           1,
			"es/admission/staging_custody.go:stagingCustody.ensureDirectory":                            1,
		},
		"golang.org/x/sys/unix.Openat": {
			"es/admission/staging_custody_darwin.go:platformOpenAtNoFollow": 1,
		},
		"golang.org/x/sys/unix.Openat2": {
			"es/admission/staging_custody_linux.go:platformOpenAtNoFollow": 1,
		},
		"golang.org/x/sys/unix.Fchown": {
			"es/admission/execution_roots.go:qualifiedExecutionRoots.probeCapabilities":           2,
			"es/admission/result_auth.go:retainedResultDirectory.publishRetainedResultRecord":     1,
			"es/admission/results.go:retainedResultDirectory.createTempFile":                      1,
			"es/admission/results.go:retainedResultDirectory.ensureNormalizationEvidenceWithHook": 1,
			"es/admission/staging_custody.go:claimStagingCustodyFromQualifiedRoot":                1,
			"es/admission/staging_custody.go:stagingCustody.ensureDirectory":                      1,
			"es/admission/staging_custody.go:stagingCustody.writeFileWithHookAndParentMode":       1,
		},
		"golang.org/x/sys/unix.Fchmod": {
			"es/admission/execution_roots.go:qualifiedExecutionRoots.probeCapabilities":           2,
			"es/admission/result_auth.go:retainedResultDirectory.publishRetainedResultRecord":     1,
			"es/admission/results.go:retainedResultDirectory.createTempFile":                      1,
			"es/admission/results.go:retainedResultDirectory.ensureNormalizationEvidenceWithHook": 1,
			"es/admission/staging_custody.go:claimStagingCustodyFromQualifiedRoot":                1,
			"es/admission/staging_custody.go:stagingCustody.ensureDirectory":                      1,
			"es/admission/staging_custody.go:stagingCustody.writeFileWithHookAndParentMode":       1,
		},
		"golang.org/x/sys/unix.Symlinkat": {
			"es/admission/execution_roots.go:qualifiedExecutionRoots.probeCapabilities": 1,
			"es/admission/staging_custody.go:probeStagingCustodyCapabilities":           1,
		},
		"golang.org/x/sys/unix.Write": {
			"es/admission/staging_custody.go:writeAllDescriptor": 1,
		},
		"os.Create":     {},
		"os.CreateTemp": {},
		"os.Mkdir":      {},
		"os.MkdirAll":   {},
		"os.OpenFile":   {},
		"os.WriteFile":  {},
	}
	if err := validateDestructiveReferenceInventory(t, views, "execution-substrate/es/admission", creationVocabulary); err != nil {
		t.Fatal(err)
	}

	wantCustodyReturns := []string{
		"es/admission/staging_custody.go:claimStagingCustody",
		"es/admission/staging_custody.go:claimStagingCustodyFromQualifiedRoot",
	}
	wantCustodyConstructors := []string{"es/admission/staging_custody.go:claimStagingCustodyFromQualifiedRoot"}
	wantStagedProducers := []string{"es/admission/executionpackage.go:materializeExecutionInputs"}
	wantStagedConstructors := []string{"es/admission/executionpackage.go:materializeExecutionInputs"}
	wantCustodyAcceptors := []string{
		"es/admission/executionpackage.go:executionPackageLayout.stageCapturedRuntimeSupportBinary",
		"es/admission/executionpackage.go:executionPackageLayout.stagePayload",
		"es/admission/executionpackage.go:executionPackageLayout.stageWorkloadVaultTrustMaterial",
		"es/admission/executionpackage.go:materializeExecutionInputs",
		"es/admission/mounts.go:materializeValidatedMountEntries",
		"es/admission/mounts.go:materializeValidatedRuntimeMounts",
	}
	for _, view := range views {
		pkg := requireTypedProductionPackage(t, view.packages, "execution-substrate/es/admission")
		custodyReturns, custodyConstructors, stagedProducers, stagedConstructors, custodyAcceptors := stagingOwnershipDeclarationInventory(pkg)
		for label, pair := range map[string]struct{ got, want []string }{
			"custody-returning declarations": {custodyReturns, wantCustodyReturns},
			"custody constructors":           {custodyConstructors, wantCustodyConstructors},
			"staged-input producers":         {stagedProducers, wantStagedProducers},
			"staged-input constructors":      {stagedConstructors, wantStagedConstructors},
			"custody mutation acceptors":     {custodyAcceptors, wantCustodyAcceptors},
		} {
			if !reflect.DeepEqual(pair.got, pair.want) {
				t.Fatalf("%s changed for %s: got %v want %v", label, view.target, pair.got, pair.want)
			}
		}
	}
}

func TestAdmissionTestOnlyStagingCustodyClaimInventoryIsExact(t *testing.T) {
	views := loadTypedAdmissionTestPackages(t)
	references := mergedProductionReferences(t, views, "execution-substrate/es/admission", func(pkg *typedProductionPackage) types.Object {
		return requirePackageFunction(t, pkg, "claimStagingCustody")
	})
	want := map[string]int{
		"es/admission/executionpackage_test.go:Service.stageExecutionInputs":                                           1,
		"es/admission/lifecycle_test.go:TestDescriptorCloseRetainsSuccessfulRunRoot":                                   1,
		"es/admission/resolved_execution_plan_test.go:TestResolvedExecutionMaterialOwnsBytesBeforeHostMaterialization": 1,
		"es/admission/resolved_execution_plan_test.go:TestRuntimeSupportMaterialIdentityMatchesCapturedBytes":          1,
		"es/admission/staging_custody_test.go:TestPhysicalTestTempDirPreservesIntentionalSymlinkRefusal":               1,
		"es/admission/staging_custody_test.go:TestStagingCustodyRefusesEveryPreExistingObjectWithoutChangingIt":        1,
		"es/admission/staging_custody_test.go:claimTestStagingCustody":                                                 1,
		"es/admission/writablestate_readiness_test.go:newSyntheticNormalizedRunFixture":                                1,
	}
	if err := validateTypedReferenceInventory("test-only path-taking staging-custody claims", references, want, false); err != nil {
		t.Fatal(err)
	}
	for _, reference := range references {
		wantSubtestClosure := reference.site == "es/admission/staging_custody_test.go:TestStagingCustodyRefusesEveryPreExistingObjectWithoutChangingIt"
		if reference.insideFuncLiteral != wantSubtestClosure {
			t.Fatalf("test-only path-taking staging-custody claim moved across a closure boundary: %s", reference)
		}
	}
}

func TestStagingCustodyReadDirInventoryIsFinite(t *testing.T) {
	want := map[string]string{
		"es/admission/staging_custody.go:readDirectoryEntries":             "64",
		"es/admission/staging_custody.go:validateExpectedDirectoryEntries": "1",
	}
	for _, view := range loadTypedProductionPackages(t, "./es/admission") {
		pkg := requireTypedProductionPackage(t, view.packages, "execution-substrate/es/admission")
		if err := validateReadDirInventory(pkg.files, want); err != nil {
			t.Fatalf("%s: %v", view.target, err)
		}
	}
}

func TestStagingCustodyReadDirInventoryRejectsFiniteEscapes(t *testing.T) {
	base := `package admission
type reader interface { ReadDir(int) ([]int, error) }
func validateExpectedDirectoryEntries(r reader) { _, _ = r.ReadDir(1) }
func readDirectoryEntries(r reader) { _, _ = r.ReadDir(64) }
`
	mutations := map[string]string{
		"zero":            `func escape(r reader) { _, _ = r.ReadDir(0) }`,
		"negative":        `func escape(r reader) { _, _ = r.ReadDir(-1) }`,
		"hidden helper":   `func hidden(r reader) { _, _ = r.ReadDir(1) }`,
		"method value":    `func escape(r reader) { read := r.ReadDir; _, _ = read(1) }`,
		"nonliteral zero": `const all = 0; func escape(r reader) { _, _ = r.ReadDir(all) }`,
		"aliased count":   `const bounded = 1; func escape(r reader) { _, _ = r.ReadDir(bounded) }`,
		"extra call site": `func escape(r reader) { _, _ = r.ReadDir(64) }`,
	}
	want := map[string]string{
		"staging_custody.go:readDirectoryEntries":             "64",
		"staging_custody.go:validateExpectedDirectoryEntries": "1",
	}
	for name, mutation := range mutations {
		t.Run(name, func(t *testing.T) {
			file, err := parser.ParseFile(token.NewFileSet(), "staging_custody.go", base+mutation, parser.AllErrors)
			if err != nil {
				t.Fatal(err)
			}
			if err := validateReadDirInventory(map[string]*ast.File{"staging_custody.go": file}, want); err == nil {
				t.Fatal("ReadDir inventory mutation escaped")
			}
		})
	}
}

func TestTypedResolverAndMaterializerInventoryRejectsReferenceEscapes(t *testing.T) {
	tests := []struct {
		name       string
		source     string
		resolver   bool
		wantDirect map[string]int
	}{
		{
			name:     "resolver direct call",
			resolver: true,
			source:   `package admission; type Service struct{}; func (s *Service) resolveExecutionForSubmit() {}; func (s *Service) Submit() { s.resolveExecutionForSubmit() }`,
		},
		{
			name:     "resolver method value",
			resolver: true,
			source:   `package admission; type Service struct{}; func (s *Service) resolveExecutionForSubmit() {}; func (s *Service) Submit() { call := s.resolveExecutionForSubmit; call() }`,
		},
		{
			name:     "resolver method expression",
			resolver: true,
			source:   `package admission; type Service struct{}; func (s *Service) resolveExecutionForSubmit() {}; func (s *Service) Submit() { call := (*Service).resolveExecutionForSubmit; call(s) }`,
		},
		{
			name:     "resolver hidden helper",
			resolver: true,
			source:   `package admission; type Service struct{}; func (s *Service) resolveExecutionForSubmit() {}; func helper(s *Service) { s.resolveExecutionForSubmit() }; func (s *Service) Submit() { helper(s) }`,
		},
		{
			name:     "resolver nested closure",
			resolver: true,
			source:   `package admission; type Service struct{}; func (s *Service) resolveExecutionForSubmit() {}; func (s *Service) Submit() { deferred := func() { s.resolveExecutionForSubmit() }; _ = deferred }`,
		},
		{
			name:       "materializer direct call",
			source:     `package admission; func materializeExecutionInputs() {}; func Submit() { materializeExecutionInputs() }`,
			wantDirect: map[string]int{"submit.go:Submit": 1},
		},
		{
			name:       "materializer function value",
			source:     `package admission; func materializeExecutionInputs() {}; func Submit() { call := materializeExecutionInputs; call() }`,
			wantDirect: map[string]int{"submit.go:Submit": 1},
		},
		{
			name:       "materializer nested closure",
			source:     `package admission; func materializeExecutionInputs() {}; func Submit() { deferred := func() { materializeExecutionInputs() }; _ = deferred }`,
			wantDirect: map[string]int{"submit.go:Submit": 1},
		},
		{
			name:       "differently named materializer helper",
			source:     `package admission; func materializeExecutionInputs() {}; func alternateStage() { materializeExecutionInputs() }; func Submit() { alternateStage() }`,
			wantDirect: map[string]int{"submit.go:Submit": 1},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			pkg := typeCheckSyntheticProductionPackage(t, "submit.go", test.source)
			var err error
			if test.resolver {
				target := requirePackageMethod(t, pkg, "Service", "resolveExecutionForSubmit")
				err = validateSingleResolverReference(pkg.referencesTo(target), "submit.go:Service.Submit")
			} else {
				target := requirePackageFunction(t, pkg, "materializeExecutionInputs")
				err = validateTypedReferenceInventory("synthetic materializer", pkg.referencesTo(target), test.wantDirect, true)
			}
			wantError := strings.Contains(test.name, "value") || strings.Contains(test.name, "expression") || strings.Contains(test.name, "helper") || strings.Contains(test.name, "closure")
			if (err != nil) != wantError {
				t.Fatalf("error = %v, wantError = %v", err, wantError)
			}
		})
	}
}

func TestStagingOwnershipDeclarationInventoryRejectsAlternateEntryPoints(t *testing.T) {
	base := `package admission
type stagingCustody struct{}
type stagedExecutionInputs struct{}
func claimStagingCustody() *stagingCustody { return &stagingCustody{} }
func materializeExecutionInputs(*stagingCustody) stagedExecutionInputs { return stagedExecutionInputs{} }
`
	mutations := map[string]string{
		"independent custody constructor": `func alternateClaim() *stagingCustody { return &stagingCustody{} }`,
		"renamed materializer":            `func alternateMaterialize(*stagingCustody) stagedExecutionInputs { return stagedExecutionInputs{} }`,
		"function-valued materializer":    `var alternateMaterializer = func(*stagingCustody) stagedExecutionInputs { return stagedExecutionInputs{} }`,
	}
	want := [][]string{
		{"staging_custody.go:claimStagingCustody"},
		{"staging_custody.go:claimStagingCustody"},
		{"staging_custody.go:materializeExecutionInputs"},
		{"staging_custody.go:materializeExecutionInputs"},
		{"staging_custody.go:materializeExecutionInputs"},
	}
	for name, mutation := range mutations {
		t.Run(name, func(t *testing.T) {
			pkg := typeCheckSyntheticProductionPackage(t, "staging_custody.go", base+mutation)
			custodyReturns, custodyConstructors, stagedProducers, stagedConstructors, custodyAcceptors := stagingOwnershipDeclarationInventory(pkg)
			inventories := [][]string{custodyReturns, custodyConstructors, stagedProducers, stagedConstructors, custodyAcceptors}
			for index := range inventories {
				if !reflect.DeepEqual(inventories[index], want[index]) {
					return
				}
			}
			t.Fatal("alternate staging ownership entry point escaped")
		})
	}
}

func TestAdmissionRetentionAndReadOnlyStagingTreeGuardrails(t *testing.T) {
	production := productionAdmissionSource(t)
	assertAdmissionFoundationOmitsAll(t, "production admission staging reclamation", production,
		"os.RemoveAll", ".execution-substrate-stage-claim-v1", ".execution-substrate-quarantine-",
		"maybeCleanupSuccessfulStageRoot", "cleanupSuccessfulStageRoot", "reclaimStagingRoot",
	)

	resultsSource := mustReadAdmissionSource(t, "results.go")
	assertAdmissionFoundationOmitsAll(t, "result capture cannot delete staging", resultsSource,
		"os.Remove(", "os.RemoveAll", "unix.AT_REMOVEDIR", "cleanupStaging", "deleteStaging", "reclaimStaging",
	)

	custodyFile := mustParseAdmissionSource(t, "staging_custody.go")
	allowedMethods := map[string]bool{"verifyVisible": true, "openDirectory": true, "close": true}
	foundMethods := make(map[string]bool)
	for _, decl := range custodyFile.Decls {
		function, ok := decl.(*ast.FuncDecl)
		if !ok || function.Recv == nil || len(function.Recv.List) != 1 || receiverTypeName(function.Recv.List[0].Type) != "stagingTree" {
			continue
		}
		if !allowedMethods[function.Name.Name] {
			t.Fatalf("read-only stagingTree gained production method %s", function.Name.Name)
		}
		foundMethods[function.Name.Name] = true
		ast.Inspect(function.Body, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			switch calledFunctionName(call.Fun) {
			case "Unlinkat", "Renameat", "Renameat2", "RenameatxNp", "Remove", "RemoveAll", "Mkdirat", "Fchown", "Fchmod":
				t.Fatalf("read-only stagingTree.%s gained a mutating call %s", function.Name.Name, calledFunctionName(call.Fun))
			}
			return true
		})
	}
	if !reflect.DeepEqual(foundMethods, allowedMethods) {
		t.Fatalf("read-only stagingTree method set changed: got %v want %v", foundMethods, allowedMethods)
	}

	wantUnlinkSites := map[string]int{}
	views := loadTypedProductionPackages(t, "./es/admission")
	destructiveVocabulary := map[string]map[string]int{
		"golang.org/x/sys/unix.Unlinkat": wantUnlinkSites,
		"golang.org/x/sys/unix.Unlink":   {},
		"golang.org/x/sys/unix.Rmdir":    {},
		"golang.org/x/sys/unix.Remove":   {},
		"os.Remove":                      {},
		"os.RemoveAll":                   {},
		"syscall.Unlink":                 {},
		"syscall.Rmdir":                  {},
	}
	if err := validateDestructiveReferenceInventory(t, views, "execution-substrate/es/admission", destructiveVocabulary); err != nil {
		t.Fatal(err)
	}
}

func TestExecutionSubstrateProductionHasNoA3LeaseRegistryOrPoisonDesign(t *testing.T) {
	views := loadTypedProductionPackages(t, "./es/...", "./cmd/es/...")
	wantPackageState := []string{
		"execution-substrate/es/admission:reservedRuntimeEnvKeys:map[string]struct{}",
	}
	wantSynchronizationFields := []string{
		"execution-substrate/es/admission/internal/reliablesubmit:PrivateReplayProgressCustody.mu:sync.RWMutex",
		"execution-substrate/es/admission/internal/reliablesubmit:PrivateReplayProgressCustody.self:*reliablesubmit.PrivateReplayProgressCustody",
		"execution-substrate/es/admission/internal/reliablesubmit:PrivateReplaySealPermit.permit:*reliablesubmit.privateSealPermit",
		"execution-substrate/es/admission/internal/reliablesubmit:ProgressAccess.state:*reliablesubmit.progressAccessState",
		"execution-substrate/es/admission/internal/reliablesubmit:ProgressAttempt.token:*reliablesubmit.progressAttemptState",
		"execution-substrate/es/admission/internal/reliablesubmit:ProgressFrozen.issuer:*reliablesubmit.PrivateReplayProgressCustody",
		"execution-substrate/es/admission/internal/reliablesubmit:ProgressLookup.issuer:*reliablesubmit.PrivateReplayProgressCustody",
		"execution-substrate/es/admission/internal/reliablesubmit:ProgressOriginalField.life:*reliablesubmit.progressOriginalLifetime",
		"execution-substrate/es/admission/internal/reliablesubmit:ProgressOriginalView.life:*reliablesubmit.progressOriginalLifetime",
		"execution-substrate/es/admission/internal/reliablesubmit:ProgressPublication.issuer:*reliablesubmit.PrivateReplayProgressCustody",
		"execution-substrate/es/admission/internal/reliablesubmit:ProgressSealPermit.issuer:*reliablesubmit.PrivateReplayProgressCustody",
		"execution-substrate/es/admission/internal/reliablesubmit:ProgressSealPermit.permit:reliablesubmit.PrivateReplaySealPermit",
		"execution-substrate/es/admission/internal/reliablesubmit:acceptWithReceiptRequest.progress:*reliablesubmit.progressAccessState",
		"execution-substrate/es/admission/internal/reliablesubmit:assignRunRequest.progress:*reliablesubmit.progressAccessState",
		"execution-substrate/es/admission/internal/reliablesubmit:mutationRequest.progress:*reliablesubmit.progressAccessState",
		"execution-substrate/es/admission/internal/reliablesubmit:privateSealPermit.mu:sync.Mutex",
		"execution-substrate/es/admission/internal/reliablesubmit:progressAccessState.issuer:*reliablesubmit.PrivateReplayProgressCustody",
		"execution-substrate/es/admission/internal/reliablesubmit:progressAccessState.life:*reliablesubmit.progressOriginalLifetime",
		"execution-substrate/es/admission/internal/reliablesubmit:progressAccessState.self:*reliablesubmit.ProgressAccess",
		"execution-substrate/es/admission/internal/reliablesubmit:progressAccessState.used:atomic.Bool",
		"execution-substrate/es/admission/internal/reliablesubmit:progressAttemptState.issuer:*reliablesubmit.PrivateReplayProgressCustody",
		"execution-substrate/es/admission/internal/reliablesubmit:progressAttemptState.used:atomic.Bool",
		"execution-substrate/es/admission/internal/reliablesubmit:progressOriginalLifetime.closed:atomic.Bool",
		"execution-substrate/es/admission/internal/reliablesubmit:recordProvablyNotAcceptedRequest.progress:*reliablesubmit.progressAccessState",
		"execution-substrate/es/admission/internal/reliablesubmit:recordProviderCallObservationRequest.progress:*reliablesubmit.progressAccessState",
		"execution-substrate/es/admission/internal/reliablesubmit:recordProviderDispatchAttemptRequest.progress:*reliablesubmit.progressAccessState",
		"execution-substrate/es/admission/internal/reliablesubmit:recordProviderEffectIntentRequest.progress:*reliablesubmit.progressAccessState",
		"execution-substrate/es/admission/internal/reliablesubmit:recordReconciliationEvidenceRequest.progress:*reliablesubmit.progressAccessState",
		"execution-substrate/es/admission/internal/reliablesubmit:recordStagingEvidenceRequest.progress:*reliablesubmit.progressAccessState",
		"execution-substrate/es/admission:Service.mu:sync.RWMutex",
		"execution-substrate/es/app:App.mu:sync.RWMutex",
		"execution-substrate/es/runtimehelper:helperServer.mu:sync.RWMutex",
	}
	packageStateSet := make(map[string]bool)
	synchronizationFieldSet := make(map[string]bool)
	mapBesideSynchronizationSet := make(map[string]bool)
	seenSources := make(map[string]bool)
	for _, view := range views {
		packageState, synchronizationFields, mapsBesideSynchronization := structuralProductionStateInventory(view.packages)
		for _, item := range packageState {
			packageStateSet[item] = true
		}
		for _, item := range synchronizationFields {
			synchronizationFieldSet[item] = true
		}
		for _, item := range mapsBesideSynchronization {
			mapBesideSynchronizationSet[item] = true
		}
		for _, pkg := range view.packages {
			if refs := pkg.referencesToPackageFunction("golang.org/x/sys/unix", "Flock"); len(refs) != 0 {
				t.Fatalf("unix.Flock entered production namespace authority in %s: %v", view.target, refs)
			}
			for fileName, source := range pkg.sources {
				sourceKey := pkg.importPath + ":" + fileName
				if seenSources[sourceKey] {
					continue
				}
				seenSources[sourceKey] = true
				lowerSource := strings.ToLower(source)
				for _, rejectedToken := range []string{
					".execution-substrate-namespace-lease-v1",
					"namespacelease",
					"namespaceregistry",
					"stagingregistry",
					"resultsregistry",
					"processlifetimelease",
					"rootpair",
					"mutationpoison",
					"poisonstate",
				} {
					if strings.Contains(lowerSource, rejectedToken) {
						t.Fatalf("rejected A3 topology token %q entered %s:%s", rejectedToken, pkg.importPath, fileName)
					}
				}
			}
		}
	}
	packageState := sortedStringSet(packageStateSet)
	synchronizationFields := sortedStringSet(synchronizationFieldSet)
	mapsBesideSynchronization := sortedStringSet(mapBesideSynchronizationSet)
	if !reflect.DeepEqual(packageState, wantPackageState) {
		t.Fatalf("package-level mutable map/synchronization inventory changed: got %v want %v", packageState, wantPackageState)
	}
	if !reflect.DeepEqual(synchronizationFields, wantSynchronizationFields) {
		t.Fatalf("production synchronization-field inventory changed: got %v want %v", synchronizationFields, wantSynchronizationFields)
	}
	if len(mapsBesideSynchronization) != 0 {
		t.Fatalf("map fields beside synchronization primitives entered production: %v", mapsBesideSynchronization)
	}
}

func TestExecutionSubstrateSynchronizedMutableStateReferenceInventoryIsExact(t *testing.T) {
	views := loadTypedProductionPackages(t, "./es/...", "./cmd/es/...")
	type fieldInventory struct {
		label      string
		importPath string
		typeName   string
		fieldName  string
		want       map[string]int
	}
	inventories := []fieldInventory{
		{
			label:      "admission trust-model lock",
			importPath: "execution-substrate/es/admission",
			typeName:   "Service",
			fieldName:  "mu",
			want: map[string]int{
				"es/admission/service.go:Service.Health":            2,
				"es/admission/service.go:Service.Initialize":        2,
				"es/admission/service.go:Service.currentTrustModel": 2,
			},
		},
		{
			label:      "admission protected trust model",
			importPath: "execution-substrate/es/admission",
			typeName:   "Service",
			fieldName:  "trustModel",
			want: map[string]int{
				"es/admission/service.go:Service.Health":            1,
				"es/admission/service.go:Service.Initialize":        1,
				"es/admission/service.go:Service.currentTrustModel": 2,
			},
		},
		{
			label:      "app state lock",
			importPath: "execution-substrate/es/app",
			typeName:   "App",
			fieldName:  "mu",
			want: map[string]int{
				"es/app/app.go:App.Addr":     2,
				"es/app/app.go:App.Shutdown": 2,
				"es/app/app.go:App.Start":    2,
				"es/app/app.go:App.Started":  2,
			},
		},
		{
			label:      "app protected started state",
			importPath: "execution-substrate/es/app",
			typeName:   "App",
			fieldName:  "started",
			want: map[string]int{
				"es/app/app.go:App.Shutdown": 1,
				"es/app/app.go:App.Start":    1,
				"es/app/app.go:App.Started":  1,
			},
		},
		{
			label:      "app protected listener state",
			importPath: "execution-substrate/es/app",
			typeName:   "App",
			fieldName:  "listener",
			want: map[string]int{
				"es/app/app.go:App.Addr":  2,
				"es/app/app.go:App.Start": 1,
			},
		},
		{
			label:      "runtime-helper token lock",
			importPath: "execution-substrate/es/runtimehelper",
			typeName:   "helperServer",
			fieldName:  "mu",
			want: map[string]int{
				"es/runtimehelper/helper.go:helperServer.currentToken":       2,
				"es/runtimehelper/helper.go:helperServer.fetchAndStoreToken": 2,
			},
		},
		{
			label:      "runtime-helper protected token",
			importPath: "execution-substrate/es/runtimehelper",
			typeName:   "helperServer",
			fieldName:  "token",
			want: map[string]int{
				"es/runtimehelper/helper.go:helperServer.currentToken":       1,
				"es/runtimehelper/helper.go:helperServer.fetchAndStoreToken": 1,
			},
		},
		{
			label:      "operation-local seal permit wrapper",
			importPath: "execution-substrate/es/admission/internal/reliablesubmit",
			typeName:   "PrivateReplaySealPermit",
			fieldName:  "permit",
			want: map[string]int{
				"es/admission/internal/reliablesubmit/replay_custody_file.go:PrivateReplayCustody.ReserveSealUse":                  1,
				"es/admission/internal/reliablesubmit/replay_custody_file.go:PrivateReplayCustody.publishReplayOriginal":           4,
				"es/admission/internal/reliablesubmit/replay_custody_file.go:PrivateReplayProgressCustody.PublishProgressOriginal": 2,
				"es/admission/internal/reliablesubmit/replay_custody_file.go:PrivateReplayProgressCustody.ReserveProgressSealUse":  1,
			},
		},
		{
			label:      "scope-2 operation-local permit wrapper",
			importPath: "execution-substrate/es/admission/internal/reliablesubmit",
			typeName:   "ProgressSealPermit",
			fieldName:  "permit",
			want: map[string]int{
				"es/admission/internal/reliablesubmit/replay_custody_file.go:PrivateReplayProgressCustody.PublishProgressOriginal": 3,
				"es/admission/internal/reliablesubmit/replay_custody_file.go:PrivateReplayProgressCustody.ReserveProgressSealUse":  1,
			},
		},
		{
			label:      "operation-local seal permit lock",
			importPath: "execution-substrate/es/admission/internal/reliablesubmit",
			typeName:   "privateSealPermit",
			fieldName:  "mu",
			want: map[string]int{
				"es/admission/internal/reliablesubmit/replay_key_use_sqlite.go:privateSealPermit.consume":         2,
				"es/admission/internal/reliablesubmit/replay_key_use_sqlite.go:privateSealPermit.burn":            2,
				"es/admission/internal/reliablesubmit/replay_custody_file.go:privateSealPermit.matchesAllocation": 2,
			},
		},
		{
			label:      "operation-local seal permit burn state",
			importPath: "execution-substrate/es/admission/internal/reliablesubmit",
			typeName:   "privateSealPermit",
			fieldName:  "used",
			want: map[string]int{
				"es/admission/internal/reliablesubmit/replay_key_use_sqlite.go:privateSealPermit.consume":         2,
				"es/admission/internal/reliablesubmit/replay_key_use_sqlite.go:privateSealPermit.burn":            1,
				"es/admission/internal/reliablesubmit/replay_custody_file.go:privateSealPermit.matchesAllocation": 1,
			},
		},
	}
	for _, inventory := range inventories {
		references := mergedProductionReferences(t, views, inventory.importPath, func(pkg *typedProductionPackage) types.Object {
			return requirePackageStructField(t, pkg, inventory.typeName, inventory.fieldName)
		})
		if err := validateTypedObjectReferenceInventory(inventory.label, references, inventory.want, true); err != nil {
			t.Fatal(err)
		}
	}
}

func TestTypedObjectReferenceInventoryRejectsEscapes(t *testing.T) {
	const base = `package admission
import "sync"
type Service struct { mu sync.RWMutex; value int }
func (s *Service) Read() int { s.mu.RLock(); defer s.mu.RUnlock(); return s.value }
func (s *Service) Write() { s.mu.Lock(); s.value = 1; s.mu.Unlock() }
`
	want := map[string]int{
		"service.go:Service.Read":  1,
		"service.go:Service.Write": 1,
	}
	for name, mutation := range map[string]string{
		"hidden helper":  `func hidden(s *Service) int { return s.value }`,
		"nested closure": `func (s *Service) Escape() func() int { return func() int { return s.value } }`,
		"second writer":  `func (s *Service) AlternateWrite() { s.value = 2 }`,
	} {
		t.Run(name, func(t *testing.T) {
			pkg := typeCheckSyntheticProductionPackage(t, "service.go", base+mutation)
			target := requirePackageStructField(t, pkg, "Service", "value")
			if err := validateTypedObjectReferenceInventory("synthetic protected fact", pkg.referencesTo(target), want, true); err == nil {
				t.Fatal("protected-fact reference escape was not rejected")
			}
		})
	}
}

func TestStructuralProductionStateInventoryRejectsNeutralMapBesideLock(t *testing.T) {
	pkg := typeCheckSyntheticProductionPackage(t, "service.go", `package admission; import "sync"; type Service struct { mu sync.RWMutex; cache map[string]int }`)
	_, _, mapsBesideSynchronization := structuralProductionStateInventory([]*typedProductionPackage{pkg})
	if !reflect.DeepEqual(mapsBesideSynchronization, []string{"synthetic/admission:Service.cache:map[string]int"}) {
		t.Fatalf("neutral map beside lock inventory = %v", mapsBesideSynchronization)
	}
}

func TestStructuralProductionStateInventoryRejectsTransitiveSynchronizationAndMaps(t *testing.T) {
	tests := []struct {
		name           string
		source         string
		wantSyncSuffix string
		wantMapSuffix  string
	}{
		{
			name:           "pointer lock",
			source:         `package admission; import "sync"; type Service struct { guard *sync.Mutex }`,
			wantSyncSuffix: "Service.guard:*sync.Mutex",
		},
		{
			name:           "embedded lock",
			source:         `package admission; import "sync"; type Service struct { sync.Mutex }`,
			wantSyncSuffix: "Service.Mutex:sync.Mutex",
		},
		{
			name:           "owner wrapper lock",
			source:         `package admission; import "sync"; type guard struct { lock sync.Mutex }; type Service struct { guard guard }`,
			wantSyncSuffix: "Service.guard:admission.guard",
		},
		{
			name:          "named map alias beside lock",
			source:        `package admission; import "sync"; type cacheMap map[string]int; type Service struct { mu sync.Mutex; cache cacheMap }`,
			wantMapSuffix: "Service.cache:admission.cacheMap",
		},
		{
			name:           "atomic coordination",
			source:         `package admission; import "sync/atomic"; type Service struct { ready atomic.Bool }`,
			wantSyncSuffix: "Service.ready:atomic.Bool",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			pkg := typeCheckSyntheticProductionPackage(t, "service.go", test.source)
			_, synchronizationFields, mapsBesideSynchronization := structuralProductionStateInventory([]*typedProductionPackage{pkg})
			if test.wantSyncSuffix != "" && !inventoryContainsSuffix(synchronizationFields, test.wantSyncSuffix) {
				t.Fatalf("synchronization inventory %v lacks %q", synchronizationFields, test.wantSyncSuffix)
			}
			if test.wantMapSuffix != "" && !inventoryContainsSuffix(mapsBesideSynchronization, test.wantMapSuffix) {
				t.Fatalf("map-beside-lock inventory %v lacks %q", mapsBesideSynchronization, test.wantMapSuffix)
			}
		})
	}
}

func inventoryContainsSuffix(inventory []string, suffix string) bool {
	for _, item := range inventory {
		if strings.HasSuffix(item, suffix) {
			return true
		}
	}
	return false
}

func sortedStringSet(values map[string]bool) []string {
	result := make([]string, 0, len(values))
	for value := range values {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

type goListProductionPackage struct {
	Dir         string
	ImportPath  string
	ForTest     string
	Export      string
	GoFiles     []string
	TestGoFiles []string
	DepOnly     bool
	Error       *struct {
		Err string
	}
}

type productionBuildTarget struct {
	goos   string
	goarch string
}

func (target productionBuildTarget) String() string {
	return target.goos + "/" + target.goarch
}

type typedProductionView struct {
	target   productionBuildTarget
	packages []*typedProductionPackage
}

type typedProductionPackage struct {
	dir        string
	importPath string
	fset       *token.FileSet
	files      map[string]*ast.File
	sources    map[string]string
	info       *types.Info
	pkg        *types.Package
}

type typedReference struct {
	packagePath       string
	site              string
	objectIdentity    string
	referenceKind     string
	directCall        bool
	methodExpression  bool
	insideFuncLiteral bool
	position          token.Position
}

func (reference typedReference) String() string {
	return fmt.Sprintf("%s|%s@%s:%d:%d[%s->%s]", reference.packagePath, reference.site, filepath.Base(reference.position.Filename), reference.position.Line, reference.position.Column, reference.referenceKind, reference.objectIdentity)
}

type typedReferenceInventory struct {
	label  string
	target *types.Func
	want   map[string]int
}

func repositoryRootForAdmissionGuard(t *testing.T) string {
	t.Helper()
	current, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(current, "go.mod")); err == nil {
			return current
		} else if !os.IsNotExist(err) {
			t.Fatal(err)
		}
		parent := filepath.Dir(current)
		if parent == current {
			t.Fatal("repository root containing go.mod was not found")
		}
		current = parent
	}
}

func loadTypedProductionPackages(t *testing.T, patterns ...string) []typedProductionView {
	t.Helper()
	targets := []productionBuildTarget{
		{goos: "darwin", goarch: "arm64"},
		{goos: "linux", goarch: "amd64"},
		{goos: "linux", goarch: "arm64"},
	}
	views := make([]typedProductionView, 0, len(targets))
	for _, target := range targets {
		views = append(views, typedProductionView{
			target:   target,
			packages: loadTypedProductionPackageView(t, target, patterns...),
		})
	}
	return views
}

func loadTypedAdmissionTestPackages(t *testing.T) []typedProductionView {
	t.Helper()
	targets := []productionBuildTarget{
		{goos: "darwin", goarch: "arm64"},
		{goos: "linux", goarch: "amd64"},
		{goos: "linux", goarch: "arm64"},
	}
	views := make([]typedProductionView, 0, len(targets))
	for _, target := range targets {
		views = append(views, typedProductionView{
			target:   target,
			packages: []*typedProductionPackage{loadTypedAdmissionTestPackageView(t, target)},
		})
	}
	return views
}

func loadTypedAdmissionTestPackageView(t *testing.T, target productionBuildTarget) *typedProductionPackage {
	t.Helper()
	const admissionImportPath = "execution-substrate/es/admission"
	repositoryRoot := repositoryRootForAdmissionGuard(t)
	goBinary := filepath.Join(runtime.GOROOT(), "bin", "go")
	command := exec.Command(goBinary, "list", "-deps", "-test", "-export", "-json", "./es/admission")
	command.Dir = repositoryRoot
	command.Env = productionGoListEnvironment(target)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		t.Fatalf("load typed admission test metadata for %s: %v: %s", target, err, stderr.String())
	}

	metadata := make(map[string]goListProductionPackage)
	var selected *goListProductionPackage
	decoder := json.NewDecoder(bytes.NewReader(stdout.Bytes()))
	for {
		var item goListProductionPackage
		err := decoder.Decode(&item)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("decode admission test go list metadata: %v", err)
		}
		if item.Error != nil {
			t.Fatalf("go list package %s: %s", item.ImportPath, item.Error.Err)
		}
		metadata[item.ImportPath] = item
		if item.ForTest == admissionImportPath && len(item.TestGoFiles) != 0 {
			copy := item
			selected = &copy
		}
	}
	if selected == nil {
		t.Fatalf("admission internal-test package was not selected for %s", target)
	}

	fset := token.NewFileSet()
	parsed := make(map[string]*ast.File, len(selected.GoFiles))
	sources := make(map[string]string, len(selected.GoFiles))
	files := make([]*ast.File, 0, len(selected.GoFiles))
	for _, fileName := range selected.GoFiles {
		absolutePath := filepath.Join(selected.Dir, fileName)
		repositoryRelativePath, err := filepath.Rel(repositoryRoot, absolutePath)
		if err != nil || repositoryRelativePath == ".." || strings.HasPrefix(repositoryRelativePath, ".."+string(filepath.Separator)) {
			t.Fatalf("normalize admission test source path %s: %v", absolutePath, err)
		}
		repositoryRelativePath = filepath.ToSlash(repositoryRelativePath)
		raw, err := os.ReadFile(absolutePath)
		if err != nil {
			t.Fatalf("read admission test source %s: %v", absolutePath, err)
		}
		file, err := parser.ParseFile(fset, absolutePath, raw, parser.AllErrors)
		if err != nil {
			t.Fatalf("parse admission test source %s: %v", absolutePath, err)
		}
		parsed[repositoryRelativePath] = file
		sources[repositoryRelativePath] = string(raw)
		files = append(files, file)
	}
	info := &types.Info{
		Defs:       make(map[*ast.Ident]types.Object),
		Uses:       make(map[*ast.Ident]types.Object),
		Types:      make(map[ast.Expr]types.TypeAndValue),
		Selections: make(map[*ast.SelectorExpr]*types.Selection),
	}
	lookup := func(importPath string) (io.ReadCloser, error) {
		dependency, ok := metadata[importPath]
		if !ok || dependency.Export == "" {
			return nil, fmt.Errorf("export data is unavailable for %s", importPath)
		}
		return os.Open(dependency.Export)
	}
	config := types.Config{
		Importer: importer.ForCompiler(fset, "gc", lookup),
		Sizes:    types.SizesFor("gc", target.goarch),
	}
	typedPackage, err := config.Check(admissionImportPath, fset, files, info)
	if err != nil {
		t.Fatalf("type-check admission test package for %s: %v", target, err)
	}
	return &typedProductionPackage{
		dir:        selected.Dir,
		importPath: admissionImportPath,
		fset:       fset,
		files:      parsed,
		sources:    sources,
		info:       info,
		pkg:        typedPackage,
	}
}

func loadTypedProductionPackageView(t *testing.T, target productionBuildTarget, patterns ...string) []*typedProductionPackage {
	t.Helper()
	repositoryRoot := repositoryRootForAdmissionGuard(t)
	args := append([]string{"list", "-deps", "-export", "-json"}, patterns...)
	goBinary := filepath.Join(runtime.GOROOT(), "bin", "go")
	command := exec.Command(goBinary, args...)
	command.Dir = repositoryRoot
	command.Env = productionGoListEnvironment(target)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		t.Fatalf("load typed production package metadata for %s: %v: %s", target, err, stderr.String())
	}

	metadata := make(map[string]goListProductionPackage)
	decoder := json.NewDecoder(bytes.NewReader(stdout.Bytes()))
	for {
		var item goListProductionPackage
		err := decoder.Decode(&item)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("decode go list metadata: %v", err)
		}
		if item.Error != nil {
			t.Fatalf("go list package %s: %s", item.ImportPath, item.Error.Err)
		}
		metadata[item.ImportPath] = item
	}

	selected := make([]goListProductionPackage, 0)
	for _, item := range metadata {
		if !item.DepOnly && strings.HasPrefix(item.ImportPath, "execution-substrate/") {
			selected = append(selected, item)
		}
	}
	sort.Slice(selected, func(left int, right int) bool { return selected[left].ImportPath < selected[right].ImportPath })
	if len(selected) == 0 {
		t.Fatalf("no production packages selected for %v", patterns)
	}

	packages := make([]*typedProductionPackage, 0, len(selected))
	for _, item := range selected {
		fset := token.NewFileSet()
		parsed := make(map[string]*ast.File, len(item.GoFiles))
		sources := make(map[string]string, len(item.GoFiles))
		files := make([]*ast.File, 0, len(item.GoFiles))
		for _, fileName := range item.GoFiles {
			absolutePath := filepath.Join(item.Dir, fileName)
			repositoryRelativePath, err := filepath.Rel(repositoryRoot, absolutePath)
			if err != nil || repositoryRelativePath == ".." || strings.HasPrefix(repositoryRelativePath, ".."+string(filepath.Separator)) {
				t.Fatalf("normalize production source path %s: %v", absolutePath, err)
			}
			repositoryRelativePath = filepath.ToSlash(repositoryRelativePath)
			raw, err := os.ReadFile(absolutePath)
			if err != nil {
				t.Fatalf("read production source %s: %v", absolutePath, err)
			}
			file, err := parser.ParseFile(fset, absolutePath, raw, parser.AllErrors)
			if err != nil {
				t.Fatalf("parse production source %s: %v", absolutePath, err)
			}
			parsed[repositoryRelativePath] = file
			sources[repositoryRelativePath] = string(raw)
			files = append(files, file)
		}
		info := &types.Info{
			Defs:       make(map[*ast.Ident]types.Object),
			Uses:       make(map[*ast.Ident]types.Object),
			Types:      make(map[ast.Expr]types.TypeAndValue),
			Selections: make(map[*ast.SelectorExpr]*types.Selection),
		}
		lookup := func(importPath string) (io.ReadCloser, error) {
			dependency, ok := metadata[importPath]
			if !ok || dependency.Export == "" {
				return nil, fmt.Errorf("export data is unavailable for %s", importPath)
			}
			return os.Open(dependency.Export)
		}
		config := types.Config{
			Importer: importer.ForCompiler(fset, "gc", lookup),
			Sizes:    types.SizesFor("gc", target.goarch),
		}
		typedPackage, err := config.Check(item.ImportPath, fset, files, info)
		if err != nil {
			t.Fatalf("type-check production package %s: %v", item.ImportPath, err)
		}
		packages = append(packages, &typedProductionPackage{
			dir:        item.Dir,
			importPath: item.ImportPath,
			fset:       fset,
			files:      parsed,
			sources:    sources,
			info:       info,
			pkg:        typedPackage,
		})
	}
	return packages
}

func productionGoListEnvironment(target productionBuildTarget) []string {
	replaced := map[string]bool{
		"GIT_DIR": true, "GIT_WORK_TREE": true, "GIT_INDEX_FILE": true,
		"GIT_OBJECT_DIRECTORY": true, "GIT_ALTERNATE_OBJECT_DIRECTORIES": true, "GIT_COMMON_DIR": true,
		"GOOS": true, "GOARCH": true, "GOTOOLCHAIN": true, "GOENV": true, "CGO_ENABLED": true,
		"GOPROXY": true, "GOSUMDB": true, "GOFLAGS": true,
	}
	environment := make([]string, 0, len(os.Environ())+9)
	for _, entry := range os.Environ() {
		key, _, found := strings.Cut(entry, "=")
		if found && replaced[key] {
			continue
		}
		environment = append(environment, entry)
	}
	return append(environment,
		"GOOS="+target.goos,
		"GOARCH="+target.goarch,
		"GOTOOLCHAIN=local",
		"GOENV=off",
		"CGO_ENABLED=0",
		"GOPROXY=off",
		"GOSUMDB=off",
		"GOFLAGS=-mod=readonly",
	)
}

func requireTypedProductionPackage(t *testing.T, packages []*typedProductionPackage, importPath string) *typedProductionPackage {
	t.Helper()
	for _, pkg := range packages {
		if pkg.importPath == importPath {
			return pkg
		}
	}
	t.Fatalf("typed production package %s was not loaded", importPath)
	return nil
}

func mergedProductionReferences(t *testing.T, views []typedProductionView, importPath string, target func(*typedProductionPackage) types.Object) []typedReference {
	t.Helper()
	seen := make(map[string]typedReference)
	for _, view := range views {
		pkg := requireTypedProductionPackage(t, view.packages, importPath)
		for _, reference := range pkg.referencesTo(target(pkg)) {
			key := strings.Join([]string{
				reference.packagePath,
				reference.site,
				reference.objectIdentity,
				reference.referenceKind,
				filepath.Clean(reference.position.Filename),
				fmt.Sprintf("%d:%d:%t:%t:%t", reference.position.Line, reference.position.Column, reference.directCall, reference.methodExpression, reference.insideFuncLiteral),
			}, "|")
			seen[key] = reference
		}
	}
	references := make([]typedReference, 0, len(seen))
	for _, reference := range seen {
		references = append(references, reference)
	}
	sort.Slice(references, func(left int, right int) bool {
		if references[left].site != references[right].site {
			return references[left].site < references[right].site
		}
		return references[left].position.Offset < references[right].position.Offset
	})
	return references
}

func mergedPackageFunctionReferences(t *testing.T, views []typedProductionView, importPath string, functionImportPath string, functionName string) []typedReference {
	t.Helper()
	seen := make(map[string]typedReference)
	for _, view := range views {
		pkg := requireTypedProductionPackage(t, view.packages, importPath)
		for _, reference := range pkg.referencesToPackageFunction(functionImportPath, functionName) {
			key := strings.Join([]string{
				reference.packagePath,
				reference.site,
				reference.objectIdentity,
				reference.referenceKind,
				filepath.Clean(reference.position.Filename),
				fmt.Sprintf("%d:%d:%t:%t:%t", reference.position.Line, reference.position.Column, reference.directCall, reference.methodExpression, reference.insideFuncLiteral),
			}, "|")
			seen[key] = reference
		}
	}
	references := make([]typedReference, 0, len(seen))
	for _, reference := range seen {
		references = append(references, reference)
	}
	sort.Slice(references, func(left int, right int) bool {
		if references[left].site != references[right].site {
			return references[left].site < references[right].site
		}
		return references[left].position.Offset < references[right].position.Offset
	})
	return references
}

func requirePackageFunction(t *testing.T, pkg *typedProductionPackage, name string) *types.Func {
	t.Helper()
	function, ok := pkg.pkg.Scope().Lookup(name).(*types.Func)
	if !ok {
		t.Fatalf("package function %s.%s was not found", pkg.importPath, name)
	}
	return function
}

func requirePackageMethod(t *testing.T, pkg *typedProductionPackage, receiverName string, methodName string) *types.Func {
	t.Helper()
	typeName, ok := pkg.pkg.Scope().Lookup(receiverName).(*types.TypeName)
	if !ok {
		t.Fatalf("receiver type %s.%s was not found", pkg.importPath, receiverName)
	}
	named, ok := typeName.Type().(*types.Named)
	if !ok {
		t.Fatalf("receiver %s.%s is not named", pkg.importPath, receiverName)
	}
	selection := types.NewMethodSet(types.NewPointer(named)).Lookup(pkg.pkg, methodName)
	if selection == nil {
		selection = types.NewMethodSet(named).Lookup(pkg.pkg, methodName)
	}
	if selection == nil {
		t.Fatalf("method %s.%s.%s was not found", pkg.importPath, receiverName, methodName)
	}
	function, ok := selection.Obj().(*types.Func)
	if !ok {
		t.Fatalf("method %s.%s.%s is not a function", pkg.importPath, receiverName, methodName)
	}
	return function
}

func requirePackageStructField(t *testing.T, pkg *typedProductionPackage, typeName string, fieldName string) *types.Var {
	t.Helper()
	object, ok := pkg.pkg.Scope().Lookup(typeName).(*types.TypeName)
	if !ok {
		t.Fatalf("struct type %s.%s was not found", pkg.importPath, typeName)
	}
	named, ok := object.Type().(*types.Named)
	if !ok {
		t.Fatalf("type %s.%s is not named", pkg.importPath, typeName)
	}
	structure, ok := named.Underlying().(*types.Struct)
	if !ok {
		t.Fatalf("type %s.%s is not a struct", pkg.importPath, typeName)
	}
	for index := 0; index < structure.NumFields(); index++ {
		field := structure.Field(index)
		if field.Name() == fieldName {
			return field
		}
	}
	t.Fatalf("field %s.%s.%s was not found", pkg.importPath, typeName, fieldName)
	return nil
}

func (pkg *typedProductionPackage) referencesTo(target types.Object) []typedReference {
	return pkg.referencesMatching(func(object types.Object) bool { return object == target })
}

func (pkg *typedProductionPackage) referencesToPackageFunction(importPath string, name string) []typedReference {
	return pkg.referencesMatching(func(object types.Object) bool {
		function, ok := object.(*types.Func)
		return ok && function.Pkg() != nil && function.Pkg().Path() == importPath && function.Name() == name
	})
}

func (pkg *typedProductionPackage) referencesMatching(matches func(types.Object) bool) []typedReference {
	var references []typedReference
	for fileName, file := range pkg.files {
		parents := astParentMap(file)
		ast.Inspect(file, func(node ast.Node) bool {
			identifier, ok := node.(*ast.Ident)
			if !ok {
				return true
			}
			object := pkg.info.Uses[identifier]
			if object == nil || !matches(object) {
				return true
			}
			parent := parents[identifier]
			expression := ast.Expr(identifier)
			methodExpression := false
			if selector, ok := parent.(*ast.SelectorExpr); ok && selector.Sel == identifier {
				expression = selector
				if selection := pkg.info.Selections[selector]; selection != nil && selection.Kind() == types.MethodExpr {
					methodExpression = true
				}
			}
			call, directCall := parents[expression].(*ast.CallExpr)
			directCall = directCall && call.Fun == expression
			referenceKind := "reference"
			if directCall {
				referenceKind = "direct-call"
			}
			if methodExpression {
				referenceKind = "method-expression"
			}
			insideLiteral := insideFunctionLiteral(parents, identifier)
			if insideLiteral {
				referenceKind += "+closure"
			}
			references = append(references, typedReference{
				packagePath:       pkg.importPath,
				site:              typedFunctionSite(fileName, enclosingFunction(parents, identifier)),
				objectIdentity:    trancheB1ObjectIdentity(object),
				referenceKind:     referenceKind,
				directCall:        directCall,
				methodExpression:  methodExpression,
				insideFuncLiteral: insideLiteral,
				position:          pkg.fset.Position(identifier.Pos()),
			})
			return true
		})
	}
	sort.Slice(references, func(left int, right int) bool {
		if references[left].site != references[right].site {
			return references[left].site < references[right].site
		}
		return references[left].position.Offset < references[right].position.Offset
	})
	return references
}

func astParentMap(root ast.Node) map[ast.Node]ast.Node {
	parents := make(map[ast.Node]ast.Node)
	stack := make([]ast.Node, 0, 16)
	ast.Inspect(root, func(node ast.Node) bool {
		if node == nil {
			stack = stack[:len(stack)-1]
			return false
		}
		if len(stack) != 0 {
			parents[node] = stack[len(stack)-1]
		}
		stack = append(stack, node)
		return true
	})
	return parents
}

func enclosingFunction(parents map[ast.Node]ast.Node, node ast.Node) *ast.FuncDecl {
	for current := node; current != nil; current = parents[current] {
		if function, ok := current.(*ast.FuncDecl); ok {
			return function
		}
	}
	return nil
}

func insideFunctionLiteral(parents map[ast.Node]ast.Node, node ast.Node) bool {
	for current := node; current != nil; current = parents[current] {
		switch current.(type) {
		case *ast.FuncLit:
			return true
		case *ast.FuncDecl:
			return false
		}
	}
	return false
}

func typedFunctionSite(fileName string, function *ast.FuncDecl) string {
	if function == nil {
		return fileName + ":<package>"
	}
	if function.Recv == nil || len(function.Recv.List) != 1 {
		return fileName + ":" + function.Name.Name
	}
	return fileName + ":" + receiverTypeName(function.Recv.List[0].Type) + "." + function.Name.Name
}

func validateSingleResolverReference(references []typedReference, expectedSite string) error {
	if len(references) != 1 {
		return fmt.Errorf("resolveExecutionForSubmit reference inventory must contain exactly one entry: %v", references)
	}
	reference := references[0]
	if reference.site != expectedSite || !reference.directCall || reference.methodExpression || reference.insideFuncLiteral {
		return fmt.Errorf("resolveExecutionForSubmit must be one direct method call in Service.Submit: %v", references)
	}
	return nil
}

func validateTypedReferenceInventory(label string, references []typedReference, want map[string]int, rejectClosures bool) error {
	got := make(map[string]int)
	for _, reference := range references {
		if reference.packagePath == "" || reference.site == "" || reference.position.Filename == "" || reference.position.Line <= 0 || reference.position.Column <= 0 || reference.objectIdentity == "" || reference.referenceKind == "" {
			return fmt.Errorf("%s contains an incomplete critical occurrence identity: %v", label, reference)
		}
		if !reference.directCall || reference.methodExpression || (rejectClosures && reference.insideFuncLiteral) {
			return fmt.Errorf("%s contains an indirect reference escape: %s", label, reference)
		}
		got[reference.site]++
	}
	if !reflect.DeepEqual(got, want) {
		return fmt.Errorf("%s reference inventory changed: got %v want %v (references %v)", label, got, want, references)
	}
	return nil
}

func validateTypedObjectReferenceInventory(label string, references []typedReference, want map[string]int, rejectClosures bool) error {
	got := make(map[string]int)
	for _, reference := range references {
		if reference.packagePath == "" || reference.site == "" || reference.position.Filename == "" || reference.position.Line <= 0 || reference.position.Column <= 0 || reference.objectIdentity == "" || reference.referenceKind == "" {
			return fmt.Errorf("%s contains an incomplete critical occurrence identity: %v", label, reference)
		}
		if reference.methodExpression || (rejectClosures && reference.insideFuncLiteral) {
			return fmt.Errorf("%s contains an indirect reference escape: %s", label, reference)
		}
		got[reference.site]++
	}
	if !reflect.DeepEqual(got, want) {
		return fmt.Errorf("%s reference inventory changed: got %v want %v (references %v)", label, got, want, references)
	}
	return nil
}

func typeCheckSyntheticProductionPackage(t *testing.T, fileName string, source string) *typedProductionPackage {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, fileName, source, parser.AllErrors)
	if err != nil {
		t.Fatal(err)
	}
	info := &types.Info{
		Defs:       make(map[*ast.Ident]types.Object),
		Uses:       make(map[*ast.Ident]types.Object),
		Types:      make(map[ast.Expr]types.TypeAndValue),
		Selections: make(map[*ast.SelectorExpr]*types.Selection),
	}
	typedPackage, err := (&types.Config{Importer: importer.Default()}).Check("synthetic/admission", fset, []*ast.File{file}, info)
	if err != nil {
		t.Fatal(err)
	}
	return &typedProductionPackage{
		importPath: "synthetic/admission",
		fset:       fset,
		files:      map[string]*ast.File{fileName: file},
		sources:    map[string]string{fileName: source},
		info:       info,
		pkg:        typedPackage,
	}
}

type trancheB1PostFreezeInventory struct {
	reachable  []string
	external   []string
	dynamic    []string
	closures   []string
	structured []string
}

func trancheB1ExpectedPostFreezeInventory(target productionBuildTarget) trancheB1PostFreezeInventory {
	if target.goos != "darwin" && target.goos != "linux" {
		return trancheB1PostFreezeInventory{}
	}
	inventory := trancheB1PostFreezeInventory{
		reachable: trancheB1InventoryWords(`
es/admission/authorityhandoff.go:buildResolvedExecutionAuthorityHandoff
es/admission/authorityhandoff.go:executionAuthorityCodexCredential
es/admission/authorityhandoff.go:executionAuthorityMetadata
es/admission/authorityhandoff.go:newExecutionAuthorityHandoffProjectionFromResolvedPlan
es/admission/execution_roots.go:classifyExecutionRootCoordinateRelation
es/admission/execution_roots.go:classifyExecutionRootPlatformObservations
es/admission/execution_roots.go:classifyVisibleExecutionRootAncestry
es/admission/execution_roots.go:executionRootComponentRelation
es/admission/execution_roots.go:executionRootPlan.close
es/admission/execution_roots.go:executionRootPlan.observed
es/admission/execution_roots.go:identityAppearsInChain
es/admission/execution_roots.go:planExecutionRoot
es/admission/execution_roots.go:qualifiedExecutionRoots.close
es/admission/execution_roots.go:qualifiedExecutionRoots.owner
es/admission/execution_roots.go:qualifiedExecutionRoots.reobserve
es/admission/execution_roots.go:qualifiedExecutionRoots.takeStagingQualifiedDirectory
es/admission/execution_roots.go:qualifyExecutionRoots
es/admission/execution_roots.go:takeExecutionRootQualifiedDirectory
es/admission/execution_roots.go:verifyExecutionRootPlan
es/admission/execution_roots_darwin.go:darwinCString
es/admission/execution_roots_darwin.go:darwinDescriptorPath
es/admission/execution_roots_darwin.go:darwinFilesystemID
es/admission/execution_roots_darwin.go:darwinHasDescendantMount
es/admission/execution_roots_darwin.go:observeDarwinExecutionRoot
es/admission/execution_roots_darwin.go:platformObserveExecutionRoots
es/admission/execution_roots_darwin.go:readBoundedDarwinMounts
es/admission/execution_roots_darwin.go:readStableDarwinMounts
es/admission/executionlocator.go:executionLocator.JobID
es/admission/executionlocator.go:newExecutionLocator
es/admission/executionlocator.go:newExecutionLocatorFromRunID
es/admission/executionpackage.go:copyResolvedRuntimeCommand
es/admission/executionpackage.go:executionPackageLayout.mountContentsDir
es/admission/executionpackage.go:executionPackageLayout.mountStageDir
es/admission/executionpackage.go:executionPackageLayout.runtimeMountSpecs
es/admission/executionpackage.go:executionPackageLayout.stageCapturedRuntimeSupportBinary
es/admission/executionpackage.go:executionPackageLayout.stagePayload
es/admission/executionpackage.go:executionPackageLayout.stageWorkloadVaultTrustMaterial
es/admission/executionpackage.go:materializeExecutionInputs
es/admission/executionpackage.go:newExecutionPackageLayoutFromHost
es/admission/mounts.go:materializeValidatedMountEntries
es/admission/mounts.go:materializeValidatedRuntimeMounts
es/admission/mounts.go:mountArtifactError
es/admission/resolved_execution_plan.go:copyResolvedJobEnvelope
es/admission/resolved_execution_plan.go:copyResolvedMountPlans
es/admission/resolved_execution_plan.go:copyStagedRuntimeMounts
es/admission/resolved_execution_plan.go:copyStringMap
es/admission/resolved_execution_plan.go:copyStringSlice
es/admission/resolved_execution_plan.go:newResolvedRunProjection
es/admission/resolved_execution_plan.go:resolvedRunProjection.nomadJobProjection
es/admission/resource_limits.go:readBoundedResponseBody
es/admission/runtimeidentity.go:runtimeIdentityHandoff.endpointPath
es/admission/runtimeidentity.go:runtimeIdentityHandoff.internalDir
es/admission/runtimeidentity.go:runtimeIdentityHandoff.spireSourceDirPath
es/admission/runtimeidentity.go:runtimeIdentityHandoff.workspaceDir
es/admission/runtimeidentity.go:runtimeIdentityHandoffForRun
es/admission/service.go:decodeBoundedCompatibleJSONDocumentResponse
es/admission/service.go:decodeCompatibleJSONDocument
es/admission/staging_custody.go:claimStagingCustodyFromQualifiedRoot
es/admission/staging_custody.go:cleanCustodyRelative
es/admission/staging_custody.go:custodyExpectedNode.isDirectory
es/admission/staging_custody.go:custodyIdentityFromStat
es/admission/staging_custody.go:custodyIdentityIsDirectory
es/admission/staging_custody.go:custodyIdentityIsRegular
es/admission/staging_custody.go:newCustodyExpectedDirectory
es/admission/staging_custody.go:newCustodyExpectedFile
es/admission/staging_custody.go:openAbsoluteDirectoryNoFollow
es/admission/staging_custody.go:openQualifiedDirectoryClean
es/admission/staging_custody.go:openQualifiedDirectoryExact
es/admission/staging_custody.go:pathBase
es/admission/staging_custody.go:pathDir
es/admission/staging_custody.go:qualifiedDirectory.close
es/admission/staging_custody.go:qualifiedDirectory.verifyVisible
es/admission/staging_custody.go:sameCustodyObject
es/admission/staging_custody.go:sameCustodyRecordedMode
es/admission/staging_custody.go:stagingCustody.close
es/admission/staging_custody.go:stagingCustody.ensureDirectory
es/admission/staging_custody.go:stagingCustody.openRegisteredDirectoryNode
es/admission/staging_custody.go:stagingCustody.revalidateBeforeHandoff
es/admission/staging_custody.go:stagingCustody.revalidateDirectoryChildren
es/admission/staging_custody.go:stagingCustody.revalidateExpectedChildAt
es/admission/staging_custody.go:stagingCustody.validExpectedIdentity
es/admission/staging_custody.go:stagingCustody.verifyRootIdentity
es/admission/staging_custody.go:stagingCustody.verifyVisibleRootIdentity
es/admission/staging_custody.go:stagingCustody.writeFile
es/admission/staging_custody.go:stagingCustody.writeFileWithHook
es/admission/staging_custody.go:stagingCustody.writeFileWithHookAndParentMode
es/admission/staging_custody.go:stagingCustody.writeFileWithParentMode
es/admission/staging_custody.go:validCustodyComponent
es/admission/staging_custody.go:validateExpectedDirectoryEntries
es/admission/staging_custody.go:writeAllDescriptor
es/admission/staging_custody_darwin.go:platformOpenAtNoFollow
es/admission/staging_custody_darwin.go:platformStatSnapshotStable
es/admission/submit.go:Service.Submit#post-freeze
es/admission/submit.go:buildNomadJobSpec
es/admission/submit.go:nomadClient.submitJob
es/admission/submit.go:stagingClaimSubmissionError
`),
		external: trancheB1InventoryOccurrences(`
builtin.append 15
builtin.copy 3
builtin.delete 1
builtin.len 31
builtin.make 11
bytes:bytes.NewReader 1
crypto/rand:crypto/rand.Read 1
encoding/hex:encoding/hex.EncodeToString 1
encoding/json:(*encoding/json.Decoder).Decode 2
encoding/json:encoding/json.Marshal 1
encoding/json:encoding/json.NewDecoder 1
errors:errors.Is 8
errors:errors.Join 4
fmt:fmt.Errorf 112
fmt:fmt.Sprintf 3
golang.org/x/sys/unix:golang.org/x/sys/unix.Close 55
golang.org/x/sys/unix:golang.org/x/sys/unix.Fchmod 3
golang.org/x/sys/unix:golang.org/x/sys/unix.Fchown 3
golang.org/x/sys/unix:golang.org/x/sys/unix.Fstat 24
golang.org/x/sys/unix:golang.org/x/sys/unix.Fstatat 8
golang.org/x/sys/unix:golang.org/x/sys/unix.Fstatfs 1
golang.org/x/sys/unix:golang.org/x/sys/unix.Fsync 1
golang.org/x/sys/unix:golang.org/x/sys/unix.Getfsstat 2
golang.org/x/sys/unix:golang.org/x/sys/unix.Mkdirat 3
golang.org/x/sys/unix:golang.org/x/sys/unix.Open 3
golang.org/x/sys/unix:golang.org/x/sys/unix.Openat 1
golang.org/x/sys/unix:golang.org/x/sys/unix.Syscall 1
golang.org/x/sys/unix:golang.org/x/sys/unix.Write 1
io/fs:(io/fs.FileMode).Perm 8
io:io.ReadAll 1
net/http:(*net/http.Client).Do 1
net/http:(net/http.Header).Set 1
net/http:net/http.NewRequestWithContext 1
net/url:(*net/url.URL).ResolveReference 1
net/url:(*net/url.URL).String 1
os:(*os.File).Close 1
os:os.NewFile 1
path/filepath:path/filepath.Base 1
path/filepath:path/filepath.Clean 8
path/filepath:path/filepath.Dir 1
path/filepath:path/filepath.IsAbs 5
path/filepath:path/filepath.Join 11
path/filepath:path/filepath.ToSlash 1
path:path.Clean 1
path:path.Dir 1
path:path.Join 3
strconv:strconv.Itoa 2
strings:strings.Clone 2
strings:strings.ContainsRune 1
strings:strings.HasPrefix 4
strings:strings.IndexByte 1
strings:strings.LastIndexByte 2
strings:strings.NewReader 1
strings:strings.Split 5
strings:strings.TrimPrefix 3
strings:strings.TrimSpace 8
`),
		dynamic: trancheB1InventoryOccurrences(`
es/admission/mounts.go:materializeValidatedRuntimeMounts-><builtin>:(error).Error 1
es/admission/staging_custody.go:claimStagingCustodyFromQualifiedRoot->call-through-failAfterCreation 9
es/admission/staging_custody.go:stagingCustody.ensureDirectory->call-through-beforeStagingChildRegistrationStatForTest 1
es/admission/staging_custody.go:stagingCustody.ensureDirectory->reviewed-package-global.beforeStagingChildRegistrationStatForTest 2
es/admission/staging_custody.go:stagingCustody.revalidateBeforeHandoff->call-through-beforeStagingHandoffValidationForTest 1
es/admission/staging_custody.go:stagingCustody.revalidateBeforeHandoff->reviewed-package-global.beforeStagingHandoffValidationForTest 2
es/admission/staging_custody.go:stagingCustody.writeFileWithHookAndParentMode->call-through-afterCreate 1
es/admission/staging_custody.go:stagingCustody.writeFileWithHookAndParentMode->call-through-beforeStagingChildRegistrationStatForTest 1
es/admission/staging_custody.go:stagingCustody.writeFileWithHookAndParentMode->reviewed-package-global.beforeStagingChildRegistrationStatForTest 2
es/admission/staging_custody.go:validateExpectedDirectoryEntries->call-through-validateExpected 1
es/admission/staging_custody.go:validateExpectedDirectoryEntries->execution-substrate/es/admission:(execution-substrate/es/admission.directoryEntryReader).ReadDir 1
es/admission/staging_custody.go:validateExpectedDirectoryEntries->io/fs:(io/fs.DirEntry).Name 1
es/admission/submit.go:nomadClient.submitJob->io:(io.Closer).Close 1
`),
		closures: trancheB1InventoryWords(`
es/admission/staging_custody.go:claimStagingCustodyFromQualifiedRoot:func-literal
es/admission/staging_custody.go:openQualifiedDirectoryClean:func-literal
es/admission/staging_custody.go:stagingCustody.revalidateDirectoryChildren:func-literal
es/admission/staging_custody.go:stagingCustody.revalidateExpectedChildAt:func-literal
es/admission/submit.go:Service.Submit#post-freeze:func-literal
es/admission/submit.go:Service.Submit#post-freeze:func-literal
`),
		structured: trancheB1InventoryOccurrences(`
es/admission/resource_limits.go:readBoundedResponseBody->io:io.ReadAll 1
es/admission/service.go:decodeBoundedCompatibleJSONDocumentResponse->bytes:bytes.NewReader 1
es/admission/service.go:decodeBoundedCompatibleJSONDocumentResponse->execution-substrate/es/admission.decodeCompatibleJSONDocument 1
es/admission/service.go:decodeBoundedCompatibleJSONDocumentResponse->execution-substrate/es/admission.readBoundedResponseBody 1
es/admission/service.go:decodeCompatibleJSONDocument->encoding/json:(*encoding/json.Decoder).Decode 2
es/admission/service.go:decodeCompatibleJSONDocument->encoding/json:encoding/json.NewDecoder 1
es/admission/submit.go:nomadClient.submitJob->execution-substrate/es/admission.decodeBoundedCompatibleJSONDocumentResponse 1
`),
	}
	if target.goos == "linux" {
		linuxReachable := make([]string, 0, len(inventory.reachable)+2)
		for _, value := range inventory.reachable {
			if strings.HasPrefix(value, "es/admission/execution_roots_darwin.go:") {
				continue
			}
			linuxReachable = append(linuxReachable, strings.Replace(value, "staging_custody_darwin.go", "staging_custody_linux.go", 1))
		}
		linuxReachable = append(linuxReachable, trancheB1InventoryWords(`
es/admission/execution_roots_linux.go:decodeLinuxMountInfoPath
es/admission/execution_roots_linux.go:linuxHasDescendantMount
es/admission/execution_roots_linux.go:observeLinuxExecutionRoot
es/admission/execution_roots_linux.go:parseLinuxMountInfo
es/admission/execution_roots_linux.go:parseLinuxMountInfoDevice
es/admission/execution_roots_linux.go:platformObserveExecutionRoots
es/admission/execution_roots_linux.go:readBoundedLinuxMountInfo
es/admission/execution_roots_linux.go:readStableLinuxMountInfo
es/admission/execution_roots_linux.go:validLinuxMountInfoToken
es/admission/execution_roots_linux.go:validateLinuxStatxIdentity
`)...)
		inventory.reachable = linuxReachable
		inventory.external = trancheB1InventoryOccurrences(`
builtin.append 18
builtin.copy 3
builtin.delete 1
builtin.len 54
builtin.make 13
bytes:bytes.Equal 1
bytes:bytes.NewReader 1
bytes:bytes.Split 1
crypto/rand:crypto/rand.Read 1
encoding/hex:encoding/hex.EncodeToString 1
encoding/json:(*encoding/json.Decoder).Decode 2
encoding/json:encoding/json.Marshal 1
encoding/json:encoding/json.NewDecoder 1
errors:errors.Is 8
errors:errors.Join 4
fmt:fmt.Errorf 136
fmt:fmt.Sprintf 4
golang.org/x/sys/unix:golang.org/x/sys/unix.Close 55
golang.org/x/sys/unix:golang.org/x/sys/unix.Fchmod 3
golang.org/x/sys/unix:golang.org/x/sys/unix.Fchown 3
golang.org/x/sys/unix:golang.org/x/sys/unix.Fstat 24
golang.org/x/sys/unix:golang.org/x/sys/unix.Fstatat 8
golang.org/x/sys/unix:golang.org/x/sys/unix.Fsync 1
golang.org/x/sys/unix:golang.org/x/sys/unix.Major 1
golang.org/x/sys/unix:golang.org/x/sys/unix.Minor 1
golang.org/x/sys/unix:golang.org/x/sys/unix.Mkdirat 3
golang.org/x/sys/unix:golang.org/x/sys/unix.Open 3
golang.org/x/sys/unix:golang.org/x/sys/unix.Openat2 1
golang.org/x/sys/unix:golang.org/x/sys/unix.Statx 2
golang.org/x/sys/unix:golang.org/x/sys/unix.Write 1
io/fs:(io/fs.FileMode).Perm 8
io:io.LimitReader 1
io:io.ReadAll 2
net/http:(*net/http.Client).Do 1
net/http:(net/http.Header).Set 1
net/http:net/http.NewRequestWithContext 1
net/url:(*net/url.URL).ResolveReference 1
net/url:(*net/url.URL).String 1
os:(*os.File).Close 2
os:os.NewFile 1
os:os.Open 1
os:os.Readlink 1
path/filepath:path/filepath.Base 1
path/filepath:path/filepath.Clean 5
path/filepath:path/filepath.Dir 1
path/filepath:path/filepath.IsAbs 2
path/filepath:path/filepath.Join 11
path/filepath:path/filepath.ToSlash 1
path:path.Clean 4
path:path.Dir 1
path:path.IsAbs 2
path:path.Join 4
strconv:strconv.Itoa 2
strconv:strconv.ParseUint 4
strings:(*strings.Builder).Grow 1
strings:(*strings.Builder).String 1
strings:(*strings.Builder).WriteByte 5
strings:strings.Clone 2
strings:strings.ContainsRune 1
strings:strings.Fields 1
strings:strings.HasPrefix 6
strings:strings.IndexByte 1
strings:strings.LastIndexByte 2
strings:strings.NewReader 1
strings:strings.Split 6
strings:strings.TrimPrefix 5
strings:strings.TrimSpace 8
`)
		inventory.structured = append(inventory.structured, "es/admission/execution_roots_linux.go:readBoundedLinuxMountInfo->io:io.ReadAll")
		sort.Strings(inventory.reachable)
		sort.Strings(inventory.external)
		sort.Strings(inventory.structured)
	}
	return inventory
}

func trancheB1InventoryWords(value string) []string {
	result := strings.Fields(value)
	sort.Strings(result)
	return result
}

func trancheB1InventoryOccurrences(value string) []string {
	fields := strings.Fields(value)
	if len(fields)%2 != 0 {
		panic("B1 occurrence inventory must contain label/count pairs")
	}
	result := make([]string, 0)
	for index := 0; index < len(fields); index += 2 {
		count, err := strconv.Atoi(fields[index+1])
		if err != nil || count < 0 {
			panic("B1 occurrence inventory has an invalid count for " + fields[index])
		}
		for occurrence := 0; occurrence < count; occurrence++ {
			result = append(result, fields[index])
		}
	}
	sort.Strings(result)
	return result
}

type trancheB1SemanticFreezeInventory struct {
	factsComposite []string
	planComposite  []string
	allocations    []string
	planCalls      []string
	planFunctions  []string
	planReturns    []string
	planBindings   []string
	factsBindings  []string
	conversions    []string
	addresses      []string
	fieldWrites    []string
	aliases        []string
	closures       []string
	factsPayload   []string
	planPayload    []string
}

type trancheB1SemanticFreezeExpectation struct {
	want            trancheB1SemanticFreezeInventory
	hydrationWrites int
}

func validateTrancheB1SemanticProducerFreeze(pkg *typedProductionPackage, fixture ...trancheB1SemanticFreezeExpectation) error {
	if len(fixture) > 1 {
		return fmt.Errorf("semantic freeze accepts at most one fixture expectation")
	}
	facts := trancheB1RequireNamedType(pkg, "resolvedPlanFacts")
	plan := trancheB1RequireNamedType(pkg, "resolvedExecutionPlan")
	if facts == nil || plan == nil {
		return fmt.Errorf("semantic plan/facts type inventory is incomplete")
	}
	factsPayload := trancheB1StructFieldByName(facts, "payloadDigest")
	planPayload := trancheB1StructFieldByName(plan, "payloadDigest")
	if factsPayload == nil || planPayload == nil {
		return fmt.Errorf("semantic payload field inventory is incomplete")
	}
	directMembers := trancheB1DirectSemanticMemberBindings(pkg, facts, plan)
	inventory := trancheB1SemanticFreezeInventory{}
	for fileName, file := range pkg.files {
		parents := astParentMap(file)
		ast.Inspect(file, func(node ast.Node) bool {
			site := func(node ast.Node) string {
				return typedFunctionSite(fileName, enclosingFunction(parents, node))
			}
			switch typed := node.(type) {
			case *ast.TypeSpec:
				if typed.Name.Name == "resolvedPlanFacts" || typed.Name.Name == "resolvedExecutionPlan" {
					return true
				}
				object, ok := pkg.info.Defs[typed.Name].(*types.TypeName)
				if !ok {
					return true
				}
				candidate := object.Type()
				if types.Identical(candidate, facts) || types.Identical(candidate, plan) || types.Identical(candidate.Underlying(), facts.Underlying()) || types.Identical(candidate.Underlying(), plan.Underlying()) {
					inventory.aliases = append(inventory.aliases, fileName+":"+typed.Name.Name)
				}
			case *ast.CompositeLit:
				typeValue := pkg.info.TypeOf(typed)
				switch {
				case types.Identical(typeValue, facts):
					inventory.factsComposite = append(inventory.factsComposite, site(typed))
				case types.Identical(typeValue, plan):
					inventory.planComposite = append(inventory.planComposite, site(typed))
				}
			case *ast.CallExpr:
				callObject := trancheB1CallObject(pkg, typed)
				if builtin, ok := callObject.(*types.Builtin); ok {
					if builtin.Name() == "new" && len(typed.Args) == 1 {
						allocatedType := pkg.info.TypeOf(typed.Args[0])
						if types.Identical(allocatedType, facts) || types.Identical(allocatedType, plan) {
							inventory.allocations = append(inventory.allocations, trancheB1SemanticOccurrence(pkg, fileName, parents, typed, "new", trancheB1TypeIdentity(allocatedType)))
						}
					}
					if destination := trancheB1BuiltinMutationDestination(builtin.Name(), typed.Args); destination != nil {
						if root, rooted := trancheB1SemanticExpressionRoot(destination, pkg, facts, plan, directMembers); rooted {
							inventory.fieldWrites = append(inventory.fieldWrites, trancheB1SemanticOccurrence(pkg, fileName, parents, destination, "builtin-"+builtin.Name(), root))
						}
					}
				}
				resultType := pkg.info.TypeOf(typed)
				if !types.Identical(resultType, facts) && !types.Identical(resultType, plan) {
					return true
				}
				if pkg.info.Types[typed.Fun].IsType() {
					inventory.conversions = append(inventory.conversions, site(typed))
				} else if types.Identical(resultType, plan) {
					inventory.planCalls = append(inventory.planCalls, site(typed))
				}
			case *ast.UnaryExpr:
				if typed.Op == token.AND && (types.Identical(pkg.info.TypeOf(typed.X), facts) || types.Identical(pkg.info.TypeOf(typed.X), plan)) {
					inventory.addresses = append(inventory.addresses, site(typed))
				}
			case *ast.FuncDecl:
				object, ok := pkg.info.Defs[typed.Name].(*types.Func)
				if !ok {
					return true
				}
				signature, _ := object.Type().(*types.Signature)
				if signature != nil && trancheB1TupleContainsExactType(signature.Results(), plan) {
					inventory.planFunctions = append(inventory.planFunctions, typedFunctionSite(fileName, typed))
				}
			case *ast.FuncLit:
				signature, _ := pkg.info.TypeOf(typed).(*types.Signature)
				if signature != nil && (trancheB1TupleContainsExactType(signature.Results(), plan) || trancheB1TupleContainsExactType(signature.Results(), facts)) {
					inventory.closures = append(inventory.closures, site(typed))
				}
			case *ast.ReturnStmt:
				for _, result := range typed.Results {
					if types.Identical(pkg.info.TypeOf(result), plan) {
						inventory.planReturns = append(inventory.planReturns, site(typed))
					}
				}
			case *ast.AssignStmt:
				for _, lhs := range typed.Lhs {
					if left, ok := lhs.(*ast.Ident); ok {
						leftType := pkg.info.TypeOf(left)
						if types.Identical(leftType, plan) {
							inventory.planBindings = append(inventory.planBindings, site(left))
						} else if types.Identical(leftType, facts) {
							inventory.factsBindings = append(inventory.factsBindings, site(left))
						}
						continue
					}
					if root, rooted := trancheB1SemanticExpressionRoot(lhs, pkg, facts, plan, directMembers); rooted {
						inventory.fieldWrites = append(inventory.fieldWrites, trancheB1SemanticOccurrence(pkg, fileName, parents, lhs, "assignment", root))
					}
				}
			case *ast.IncDecStmt:
				if root, rooted := trancheB1SemanticExpressionRoot(typed.X, pkg, facts, plan, directMembers); rooted {
					inventory.fieldWrites = append(inventory.fieldWrites, trancheB1SemanticOccurrence(pkg, fileName, parents, typed.X, "inc-dec", root))
				}
			case *ast.Ident:
				object := pkg.info.Uses[typed]
				if object == factsPayload {
					inventory.factsPayload = append(inventory.factsPayload, site(typed))
				} else if object == planPayload {
					inventory.planPayload = append(inventory.planPayload, site(typed))
				}
			}
			return true
		})
	}
	for _, values := range [][]string{
		inventory.factsComposite, inventory.planComposite, inventory.allocations, inventory.planCalls, inventory.planFunctions,
		inventory.planReturns, inventory.planBindings, inventory.factsBindings, inventory.conversions,
		inventory.addresses, inventory.fieldWrites, inventory.aliases, inventory.closures,
		inventory.factsPayload, inventory.planPayload,
	} {
		sort.Strings(values)
	}
	var retainedFieldWrites []string
	var hydrationWrites int
	for _, occurrence := range inventory.fieldWrites {
		if strings.HasPrefix(occurrence, "es/admission/reliable_submit_replay_hydration.go:privateReplayReader.plan@") &&
			strings.HasSuffix(occurrence, "[assignment:resolvedPlanFacts]") {
			hydrationWrites++
			continue
		}
		retainedFieldWrites = append(retainedFieldWrites, occurrence)
	}
	wantHydrationWrites := 34 // Exact reviewed assignments in privateReplayReader.plan.
	if len(fixture) == 1 {
		wantHydrationWrites = fixture[0].hydrationWrites
	}
	if hydrationWrites != wantHydrationWrites {
		return fmt.Errorf("private verified-original hydration write inventory changed: got %d want %d", hydrationWrites, wantHydrationWrites)
	}
	inventory.fieldWrites = retainedFieldWrites
	want := trancheB1SemanticFreezeInventory{
		factsComposite: []string{"es/admission/reliable_submit_replay_hydration.go:privateReplayReader.plan", "es/admission/reliable_submit_replay_hydration.go:privateReplayReader.plan", "es/admission/resolved_execution_plan.go:Service.resolveExecutionForSubmit"},
		planComposite:  []string{"es/admission/resolved_execution_plan.go:newResolvedExecutionPlan"},
		planCalls:      []string{"es/admission/reliable_submit_replay_hydration.go:decodePrivateReplayOriginal", "es/admission/resolved_execution_plan.go:Service.resolveExecutionForSubmit"},
		planFunctions:  []string{"es/admission/resolved_execution_plan.go:newResolvedExecutionPlan"},
		planReturns:    []string{"es/admission/resolved_execution_plan.go:newResolvedExecutionPlan"},
		planBindings: []string{
			"es/admission/reliable_submit_binding_encoding.go:bindingEncodeCanonical",
			"es/admission/reliable_submit_binding_encoding.go:bindingRecordFields",
			"es/admission/reliable_submit_replay_format.go:privateReplayEncoder.provenance",
			"es/admission/reliable_submit_replay_hydration.go:decodePrivateReplayOriginal",
			"es/admission/resolved_execution_plan.go:Service.resolveExecutionForSubmit",
		},
		factsBindings: []string{"es/admission/reliable_submit_replay_hydration.go:decodePrivateReplayOriginal"},
		factsPayload: []string{
			"es/admission/reliable_submit_replay_hydration.go:privateReplayReader.plan",
			"es/admission/resolved_execution_plan.go:Service.resolveExecutionForSubmit",
			"es/admission/resolved_execution_plan.go:newResolvedExecutionPlan",
		},
		planPayload: []string{
			"es/admission/reliable_submit_binding.go:bindingPrimaryValid",
			"es/admission/reliable_submit_binding.go:bindingPrimaryValid",
			"es/admission/reliable_submit_binding_encoding.go:bindingRecordFields",
			"es/admission/reliable_submit_replay_format.go:privateReplayEncoder.plan",
			"es/admission/reliable_submit_replay_format.go:privateReplayEncoder.provenance",
			"es/admission/resolved_execution_plan.go:newResolvedExecutionPlan",
		},
	}
	if len(fixture) == 1 {
		want = fixture[0].want
	}
	var mismatches []string
	for label, pair := range map[string]struct {
		got  []string
		want []string
	}{
		"resolved-plan-facts composite producers": {inventory.factsComposite, want.factsComposite},
		"resolved-plan composite producers":       {inventory.planComposite, want.planComposite},
		"semantic new allocations":                {inventory.allocations, nil},
		"resolved-plan producing calls":           {inventory.planCalls, want.planCalls},
		"resolved-plan returning functions":       {inventory.planFunctions, want.planFunctions},
		"resolved-plan returned values":           {inventory.planReturns, want.planReturns},
		"resolved-plan value bindings":            {inventory.planBindings, want.planBindings},
		"resolved-plan-facts value bindings":      {inventory.factsBindings, want.factsBindings},
		"semantic type conversions":               {inventory.conversions, nil},
		"semantic address-taking":                 {inventory.addresses, nil},
		"semantic field writes":                   {inventory.fieldWrites, nil},
		"semantic aliases":                        {inventory.aliases, nil},
		"semantic producer closures":              {inventory.closures, nil},
		"facts payload field references":          {inventory.factsPayload, want.factsPayload},
		"plan payload field references":           {inventory.planPayload, want.planPayload},
	} {
		if !reflect.DeepEqual(pair.got, pair.want) {
			mismatches = append(mismatches, fmt.Sprintf("%s inventory changed: got %v want %v", label, pair.got, pair.want))
		}
	}
	if len(mismatches) != 0 {
		sort.Strings(mismatches)
		return fmt.Errorf("%s", strings.Join(mismatches, "; "))
	}
	return nil
}

func trancheB1DirectSemanticMemberBindings(pkg *typedProductionPackage, facts *types.Named, plan *types.Named) map[types.Object]string {
	bindings := make(map[types.Object]string)
	changed := true
	for changed {
		changed = false
		for _, file := range pkg.files {
			ast.Inspect(file, func(node ast.Node) bool {
				switch typed := node.(type) {
				case *ast.AssignStmt:
					if len(typed.Lhs) != len(typed.Rhs) {
						return true
					}
					for index, lhs := range typed.Lhs {
						identifier, ok := lhs.(*ast.Ident)
						if !ok || !trancheB1MutableAggregateType(pkg.info.TypeOf(identifier)) {
							continue
						}
						root, rooted := trancheB1SemanticExpressionRoot(typed.Rhs[index], pkg, facts, plan, bindings)
						if !rooted {
							continue
						}
						object := trancheB1IdentifierObject(pkg, identifier)
						if object != nil {
							existing := bindings[object]
							if existing == "" {
								bindings[object] = root
								changed = true
							} else if existing != root && existing != "resolvedSemanticAggregate" {
								bindings[object] = "resolvedSemanticAggregate"
								changed = true
							}
						}
					}
				case *ast.ValueSpec:
					if len(typed.Names) != len(typed.Values) {
						return true
					}
					for index, name := range typed.Names {
						if !trancheB1MutableAggregateType(pkg.info.TypeOf(name)) {
							continue
						}
						root, rooted := trancheB1SemanticExpressionRoot(typed.Values[index], pkg, facts, plan, bindings)
						if !rooted {
							continue
						}
						object := trancheB1IdentifierObject(pkg, name)
						if object != nil {
							existing := bindings[object]
							if existing == "" {
								bindings[object] = root
								changed = true
							} else if existing != root && existing != "resolvedSemanticAggregate" {
								bindings[object] = "resolvedSemanticAggregate"
								changed = true
							}
						}
					}
				}
				return true
			})
		}
	}
	return bindings
}

func trancheB1SemanticExpressionRoot(expression ast.Expr, pkg *typedProductionPackage, facts *types.Named, plan *types.Named, directMembers map[types.Object]string) (string, bool) {
	switch typed := expression.(type) {
	case *ast.Ident:
		if root, ok := directMembers[trancheB1IdentifierObject(pkg, typed)]; ok {
			return root, true
		}
		return trancheB1SemanticRootType(pkg.info.TypeOf(typed), facts, plan)
	case *ast.SelectorExpr:
		return trancheB1SemanticExpressionRoot(typed.X, pkg, facts, plan, directMembers)
	case *ast.IndexExpr:
		return trancheB1SemanticExpressionRoot(typed.X, pkg, facts, plan, directMembers)
	case *ast.IndexListExpr:
		return trancheB1SemanticExpressionRoot(typed.X, pkg, facts, plan, directMembers)
	case *ast.ParenExpr:
		return trancheB1SemanticExpressionRoot(typed.X, pkg, facts, plan, directMembers)
	case *ast.StarExpr:
		return trancheB1SemanticExpressionRoot(typed.X, pkg, facts, plan, directMembers)
	default:
		return "", false
	}
}

func trancheB1SemanticRootType(candidate types.Type, facts *types.Named, plan *types.Named) (string, bool) {
	for {
		pointer, ok := candidate.(*types.Pointer)
		if !ok {
			break
		}
		candidate = pointer.Elem()
	}
	if types.Identical(candidate, plan) {
		return "resolvedExecutionPlan", true
	}
	if types.Identical(candidate, facts) {
		return "resolvedPlanFacts", true
	}
	return "", false
}

func trancheB1MutableAggregateType(candidate types.Type) bool {
	if candidate == nil {
		return false
	}
	switch candidate.Underlying().(type) {
	case *types.Map, *types.Slice, *types.Pointer:
		return true
	default:
		return false
	}
}

func trancheB1IdentifierObject(pkg *typedProductionPackage, identifier *ast.Ident) types.Object {
	if object := pkg.info.Uses[identifier]; object != nil {
		return object
	}
	return pkg.info.Defs[identifier]
}

func trancheB1BuiltinMutationDestination(name string, arguments []ast.Expr) ast.Expr {
	if len(arguments) == 0 {
		return nil
	}
	switch name {
	case "delete", "clear", "copy":
		return arguments[0]
	default:
		return nil
	}
}

func trancheB1SemanticOccurrence(pkg *typedProductionPackage, fileName string, parents map[ast.Node]ast.Node, node ast.Node, kind string, objectIdentity string) string {
	position := pkg.fset.Position(node.Pos())
	return fmt.Sprintf("%s@%d:%d[%s:%s]", typedFunctionSite(fileName, enclosingFunction(parents, node)), position.Line, position.Column, kind, objectIdentity)
}

func trancheB1TypeIdentity(candidate types.Type) string {
	if candidate == nil {
		return "<nil>"
	}
	return types.TypeString(candidate, func(pkg *types.Package) string {
		if pkg == nil {
			return ""
		}
		return pkg.Path()
	})
}

func trancheB1RequireNamedType(pkg *typedProductionPackage, name string) *types.Named {
	typeName, _ := pkg.pkg.Scope().Lookup(name).(*types.TypeName)
	if typeName == nil {
		return nil
	}
	named, _ := typeName.Type().(*types.Named)
	return named
}

func trancheB1StructFieldSet(named *types.Named) map[*types.Var]bool {
	result := make(map[*types.Var]bool)
	if named == nil {
		return result
	}
	structure, _ := named.Underlying().(*types.Struct)
	if structure == nil {
		return result
	}
	for index := 0; index < structure.NumFields(); index++ {
		result[structure.Field(index)] = true
	}
	return result
}

func trancheB1StructFieldByName(named *types.Named, name string) *types.Var {
	if named == nil {
		return nil
	}
	structure, _ := named.Underlying().(*types.Struct)
	if structure == nil {
		return nil
	}
	for index := 0; index < structure.NumFields(); index++ {
		if structure.Field(index).Name() == name {
			return structure.Field(index)
		}
	}
	return nil
}

func trancheB1TupleContainsExactType(tuple *types.Tuple, target types.Type) bool {
	if tuple == nil || target == nil {
		return false
	}
	for index := 0; index < tuple.Len(); index++ {
		if types.Identical(tuple.At(index).Type(), target) {
			return true
		}
	}
	return false
}

func validateTrancheB1PostFreezeClosure(pkg *typedProductionPackage, want trancheB1PostFreezeInventory) error {
	got, err := trancheB1BuildPostFreezeClosure(pkg)
	if err != nil {
		return err
	}
	var mismatches []string
	for label, inventory := range map[string]struct {
		got  []string
		want []string
	}{
		"reachable package-local functions":  {got.reachable, want.reachable},
		"external/library calls":             {got.external, want.external},
		"reviewed dynamic calls":             {got.dynamic, want.dynamic},
		"reviewed closures":                  {got.closures, want.closures},
		"selected structured response calls": {got.structured, want.structured},
	} {
		if !reflect.DeepEqual(inventory.got, inventory.want) {
			mismatches = append(mismatches, fmt.Sprintf(
				"%s:\n got\n%s\nwant\n%s",
				label,
				trancheB1InventoryCountText(inventory.got),
				trancheB1InventoryCountText(inventory.want),
			))
		}
	}
	if len(mismatches) != 0 {
		sort.Strings(mismatches)
		return fmt.Errorf("post-freeze inventory changed:\n%s", strings.Join(mismatches, "\n"))
	}
	return nil
}

func trancheB1InventoryCountText(values []string) string {
	counts := make(map[string]int, len(values))
	for _, value := range values {
		counts[value]++
	}
	keys := make([]string, 0, len(counts))
	for value := range counts {
		keys = append(keys, value)
	}
	sort.Strings(keys)
	var result strings.Builder
	for index, value := range keys {
		if index != 0 {
			result.WriteByte('\n')
		}
		fmt.Fprintf(&result, "%s %d", value, counts[value])
	}
	return result.String()
}

// This exception is for one nil production hook at two owned-child registration
// sites. It is deliberately checked independently of the closure walker so an
// extra reference cannot become an implied exception merely by being reachable.
func validateTrancheB1ReviewedChildRegistrationHook(pkg *typedProductionPackage) (*types.Var, error) {
	const fileName = "es/admission/staging_custody.go"
	const hookName = "beforeStagingChildRegistrationStatForTest"
	hook, ok := pkg.pkg.Scope().Lookup(hookName).(*types.Var)
	if !ok || hook.Pkg() != pkg.pkg {
		return nil, fmt.Errorf("reviewed child registration hook is not an admission package variable")
	}
	wantType := types.NewSignatureType(nil, nil, nil, types.NewTuple(
		types.NewVar(token.NoPos, nil, "relativePath", types.Typ[types.String]),
		types.NewVar(token.NoPos, nil, "fd", types.Typ[types.Int]),
		types.NewVar(token.NoPos, nil, "directory", types.Typ[types.Bool]),
	), types.NewTuple(), false)
	if !types.Identical(hook.Type(), wantType) {
		return nil, fmt.Errorf("reviewed child registration hook has changed function type: %s", hook.Type())
	}
	file := pkg.files[fileName]
	if file == nil {
		return nil, fmt.Errorf("reviewed child registration hook source is absent")
	}
	declarations := 0
	for _, declaration := range file.Decls {
		group, ok := declaration.(*ast.GenDecl)
		if !ok || group.Tok != token.VAR {
			continue
		}
		for _, spec := range group.Specs {
			value, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for _, name := range value.Names {
				if pkg.info.Defs[name] != hook {
					continue
				}
				declarations++
				if len(value.Values) != 0 || len(value.Names) != 1 {
					return nil, fmt.Errorf("reviewed child registration hook must have a nil production initializer")
				}
			}
		}
	}
	if declarations != 1 {
		return nil, fmt.Errorf("reviewed child registration hook declaration moved or multiplied: %d", declarations)
	}
	want := map[string]int{
		fileName + ":stagingCustody.ensureDirectory|reference":                  1,
		fileName + ":stagingCustody.ensureDirectory|direct-call":                1,
		fileName + ":stagingCustody.writeFileWithHookAndParentMode|reference":   1,
		fileName + ":stagingCustody.writeFileWithHookAndParentMode|direct-call": 1,
	}
	got := make(map[string]int)
	for _, reference := range pkg.referencesTo(hook) {
		if reference.packagePath != pkg.importPath || reference.position.Filename == "" || reference.position.Line <= 0 || reference.position.Column <= 0 || reference.objectIdentity == "" || reference.insideFuncLiteral || reference.methodExpression {
			return nil, fmt.Errorf("reviewed child registration hook has an unbound occurrence: %v", reference)
		}
		got[reference.site+"|"+reference.referenceKind]++
	}
	if !reflect.DeepEqual(got, want) {
		return nil, fmt.Errorf("reviewed child registration hook read/call sites changed: got %v want %v", got, want)
	}
	parents := astParentMap(file)
	for identifier, object := range pkg.info.Uses {
		if object != hook {
			continue
		}
		if identifier.Pos() < file.Pos() || identifier.Pos() >= file.End() {
			continue
		}
		if call, ok := parents[identifier].(*ast.CallExpr); ok && call.Fun == identifier {
			continue
		}
		comparison, ok := parents[identifier].(*ast.BinaryExpr)
		if !ok || comparison.Op != token.NEQ || comparison.X != identifier || exprSourceName(comparison.Y) != "nil" {
			return nil, fmt.Errorf("reviewed child registration hook has a non-guarded read or assignment")
		}
	}
	return hook, nil
}

func trancheB1BuildPostFreezeClosure(pkg *typedProductionPackage) (trancheB1PostFreezeInventory, error) {
	if pkg.importPath != "execution-substrate/es/admission" && pkg.importPath != "synthetic/admission" {
		return trancheB1PostFreezeInventory{}, fmt.Errorf("post-freeze closure requires the admission package, got %s", pkg.importPath)
	}
	var reviewedChildHook *types.Var
	if pkg.importPath == "execution-substrate/es/admission" {
		var err error
		reviewedChildHook, err = validateTrancheB1ReviewedChildRegistrationHook(pkg)
		if err != nil {
			return trancheB1PostFreezeInventory{}, err
		}
	}
	functionDecls := make(map[*types.Func]*ast.FuncDecl)
	functionSites := make(map[*types.Func]string)
	parentsByFile := make(map[string]map[ast.Node]ast.Node, len(pkg.files))
	for fileName, file := range pkg.files {
		parentsByFile[fileName] = astParentMap(file)
		for _, declaration := range file.Decls {
			function, ok := declaration.(*ast.FuncDecl)
			if !ok {
				continue
			}
			object, ok := pkg.info.Defs[function.Name].(*types.Func)
			if !ok {
				continue
			}
			functionDecls[object] = function
			functionSites[object] = typedFunctionSite(fileName, function)
		}
	}
	serviceFields := trancheB1NamedStructFields(pkg, "Service")
	prepareRequestFields := trancheB1NamedStructFields(pkg, "PrepareRequest")
	preparedAdmissionFields := trancheB1NamedStructFields(pkg, "preparedAdmission")
	retainedNomadDatacenter := trancheB1NamedStructField(pkg, "nomadClient", "datacenter")
	forbiddenFunctions := map[string]bool{
		"prepareAdmission":                        true,
		"snapshotAdmissionRequest":                true,
		"validatePrepareRequest":                  true,
		"resolveExecutionForSubmit":               true,
		"resolveExecutionRuntimeProfile":          true,
		"resolveExecutionPlatformStateOwnerModel": true,
		"newSubmitConfigSnapshot":                 true,
		"normalizeSubmitPlacementFacts":           true,
		"fetchPayloadBytes":                       true,
		"fetchPayloadBytesWithin":                 true,
		"captureRuntimeSupport":                   true,
		"captureWorkloadTrustMaterial":            true,
	}

	resolver, resolverOK := trancheB1LookupMethod(pkg, "Service", "resolveExecutionForSubmit")
	submit, submitOK := trancheB1LookupMethod(pkg, "Service", "Submit")
	if !resolverOK || !submitOK {
		return trancheB1PostFreezeInventory{}, fmt.Errorf("post-freeze Submit/resolver roots are absent")
	}
	explicitRoots := []struct {
		receiver string
		name     string
	}{
		{"", "newResolvedRunProjection"},
		{"resolvedRunProjection", "nomadJobProjection"},
		{"", "buildNomadJobSpec"},
		{"", "buildResolvedExecutionAuthorityHandoff"},
		{"", "executionAuthorityMetadata"},
		{"executionPackageLayout", "runtimeMountSpecs"},
	}
	queue := make([]*types.Func, 0, 32)
	queued := make(map[*types.Func]bool)
	for _, root := range explicitRoots {
		var function *types.Func
		var ok bool
		if root.receiver == "" {
			function, ok = trancheB1LookupFunction(pkg, root.name)
		} else {
			function, ok = trancheB1LookupMethod(pkg, root.receiver, root.name)
		}
		if !ok {
			return trancheB1PostFreezeInventory{}, fmt.Errorf("post-freeze root %s.%s is absent", root.receiver, root.name)
		}
		if !queued[function] {
			queued[function] = true
			queue = append(queue, function)
		}
	}

	inventory := trancheB1PostFreezeInventory{reachable: []string{"es/admission/submit.go:Service.Submit#post-freeze"}}
	var violations []string
	processNode := func(root ast.Node, site string, parents map[ast.Node]ast.Node, allowSubmitClosure bool) {
		ast.Inspect(root, func(node ast.Node) bool {
			switch typed := node.(type) {
			case *ast.FuncLit:
				closure := site + ":func-literal"
				inventory.closures = append(inventory.closures, closure)
				_ = allowSubmitClosure
			case *ast.CallExpr:
				if literal, ok := typed.Fun.(*ast.FuncLit); ok {
					_ = literal
					return true
				}
				if pkg.info.Types[typed.Fun].IsType() {
					return true
				}
				object := trancheB1CallObject(pkg, typed)
				if object == nil {
					inventory.dynamic = append(inventory.dynamic, site+"->"+trancheB1ASTTypeName(typed.Fun))
					return true
				}
				if identity, selected := trancheB1SelectedStructuredCallIdentity(pkg, object); selected {
					inventory.structured = append(inventory.structured, site+"->"+identity)
				}
				switch callable := object.(type) {
				case *types.Builtin:
					inventory.external = append(inventory.external, "builtin."+callable.Name())
				case *types.Func:
					if selection, ok := typed.Fun.(*ast.SelectorExpr); ok {
						if selected := pkg.info.Selections[selection]; selected != nil {
							if selected.Kind() != types.MethodVal || trancheB1UnderlyingInterface(selected.Recv()) {
								inventory.dynamic = append(inventory.dynamic, site+"->"+trancheB1QualifiedFunction(callable))
								return true
							}
						}
					}
					if callable.Pkg() != nil && callable.Pkg().Path() == pkg.importPath {
						if forbiddenFunctions[callable.Name()] {
							violations = append(violations, site+" reaches forbidden post-freeze source function "+callable.Name())
						}
						if _, exists := functionDecls[callable]; !exists {
							inventory.dynamic = append(inventory.dynamic, site+"->"+trancheB1QualifiedFunction(callable))
						} else if !queued[callable] {
							queued[callable] = true
							queue = append(queue, callable)
						}
					} else {
						inventory.external = append(inventory.external, trancheB1QualifiedFunction(callable))
					}
				default:
					inventory.dynamic = append(inventory.dynamic, site+"->call-through-"+object.Name())
				}
			case *ast.Ident:
				object := pkg.info.Uses[typed]
				if object == nil {
					return true
				}
				if named, ok := object.(*types.TypeName); ok {
					if named.Name() == "PrepareRequest" || named.Name() == "preparedAdmission" || named.Pkg() != nil && named.Pkg().Path() == "execution-substrate/es/config" {
						violations = append(violations, site+" references forbidden post-freeze source type "+named.Name())
					}
				}
				if variable, ok := object.(*types.Var); ok {
					switch {
					case variable == retainedNomadDatacenter && trancheB1IdentifierIsRead(typed, parents):
						position := pkg.fset.Position(typed.Pos())
						violations = append(violations, fmt.Sprintf("%s reads forbidden retained nomadClient.datacenter at %s:%d:%d", site, filepath.Base(position.Filename), position.Line, position.Column))
					case serviceFields[variable] && variable.Name() != "nomadClient":
						violations = append(violations, site+" references forbidden Service field "+variable.Name())
					case prepareRequestFields[variable]:
						violations = append(violations, site+" references raw PrepareRequest field "+variable.Name())
					case preparedAdmissionFields[variable]:
						violations = append(violations, site+" references preparedAdmission field "+variable.Name())
					case variable.Pkg() != nil && variable.Pkg().Path() == pkg.importPath && variable.Parent() == pkg.pkg.Scope():
						if variable.Name() == "beforeStagingHandoffValidationForTest" || variable == reviewedChildHook {
							inventory.dynamic = append(inventory.dynamic, site+"->reviewed-package-global."+variable.Name())
						} else {
							violations = append(violations, site+" references mutable package-global "+variable.Name())
						}
					}
				}
				function, ok := object.(*types.Func)
				if !ok || function.Pkg() == nil || function.Pkg().Path() != pkg.importPath {
					return true
				}
				expression := ast.Expr(typed)
				if selector, ok := parents[typed].(*ast.SelectorExpr); ok && selector.Sel == typed {
					expression = selector
				}
				call, direct := parents[expression].(*ast.CallExpr)
				if !direct || call.Fun != expression {
					inventory.dynamic = append(inventory.dynamic, site+"->"+trancheB1QualifiedFunction(function))
				}
			}
			return true
		})
	}

	submitDecl := functionDecls[submit]
	if submitDecl == nil || submitDecl.Body == nil {
		return trancheB1PostFreezeInventory{}, fmt.Errorf("Service.Submit declaration is absent")
	}
	submitFile, submitParents := trancheB1FileAndParentsForNode(pkg, parentsByFile, submitDecl)
	_ = submitFile
	resolverStatement := -1
	for index, statement := range submitDecl.Body.List {
		found := false
		ast.Inspect(statement, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if ok && trancheB1CallObject(pkg, call) == resolver {
				found = true
				return false
			}
			return !found
		})
		if found {
			resolverStatement = index
			break
		}
	}
	if resolverStatement < 0 {
		return trancheB1PostFreezeInventory{}, fmt.Errorf("Service.Submit resolver return continuation was not found")
	}
	for _, statement := range submitDecl.Body.List[resolverStatement+1:] {
		processNode(statement, "es/admission/submit.go:Service.Submit#post-freeze", submitParents, true)
	}

	processed := make(map[*types.Func]bool)
	for len(queue) > 0 {
		function := queue[0]
		queue = queue[1:]
		if processed[function] {
			continue
		}
		processed[function] = true
		declaration := functionDecls[function]
		if declaration == nil || declaration.Body == nil {
			violations = append(violations, "reachable package-local function has no direct declaration: "+trancheB1QualifiedFunction(function))
			continue
		}
		site := functionSites[function]
		inventory.reachable = append(inventory.reachable, site)
		_, parents := trancheB1FileAndParentsForNode(pkg, parentsByFile, declaration)
		processNode(declaration.Body, site, parents, false)
	}
	sort.Strings(inventory.reachable)
	sort.Strings(inventory.external)
	sort.Strings(inventory.dynamic)
	sort.Strings(inventory.closures)
	sort.Strings(inventory.structured)
	sort.Strings(violations)
	if len(violations) != 0 {
		return inventory, fmt.Errorf("post-freeze forbidden-source closure violations: %s", strings.Join(violations, "; "))
	}
	return inventory, nil
}

func trancheB1SelectedStructuredCallIdentity(pkg *typedProductionPackage, object types.Object) (string, bool) {
	function, ok := object.(*types.Func)
	if !ok || function.Pkg() == nil {
		return "", false
	}
	if function.Pkg().Path() == pkg.importPath {
		switch function.Name() {
		case "decodeBoundedCompatibleJSONDocumentResponse", "decodeCompatibleJSONDocument", "readBoundedResponseBody":
			return pkg.importPath + "." + function.Name(), true
		default:
			return "", false
		}
	}
	identity := trancheB1QualifiedFunction(function)
	switch identity {
	case "bytes:bytes.NewReader", "encoding/json:(*encoding/json.Decoder).Decode", "encoding/json:encoding/json.NewDecoder", "io:io.ReadAll":
		return identity, true
	default:
		return "", false
	}
}
func trancheB1LookupFunction(pkg *typedProductionPackage, name string) (*types.Func, bool) {
	function, ok := pkg.pkg.Scope().Lookup(name).(*types.Func)
	return function, ok
}

func trancheB1LookupMethod(pkg *typedProductionPackage, receiverName string, methodName string) (*types.Func, bool) {
	typeName, ok := pkg.pkg.Scope().Lookup(receiverName).(*types.TypeName)
	if !ok {
		return nil, false
	}
	named, ok := typeName.Type().(*types.Named)
	if !ok {
		return nil, false
	}
	selection := types.NewMethodSet(types.NewPointer(named)).Lookup(pkg.pkg, methodName)
	if selection == nil {
		selection = types.NewMethodSet(named).Lookup(pkg.pkg, methodName)
	}
	if selection == nil {
		return nil, false
	}
	function, ok := selection.Obj().(*types.Func)
	return function, ok
}

func trancheB1NamedStructFields(pkg *typedProductionPackage, name string) map[*types.Var]bool {
	result := make(map[*types.Var]bool)
	typeName, ok := pkg.pkg.Scope().Lookup(name).(*types.TypeName)
	if !ok {
		return result
	}
	typeValue := typeName.Type()
	if pointer, ok := typeValue.(*types.Pointer); ok {
		typeValue = pointer.Elem()
	}
	named, ok := typeValue.(*types.Named)
	if !ok {
		return result
	}
	structure, ok := named.Underlying().(*types.Struct)
	if !ok {
		return result
	}
	for index := 0; index < structure.NumFields(); index++ {
		result[structure.Field(index)] = true
	}
	return result
}

func trancheB1NamedStructField(pkg *typedProductionPackage, typeName string, fieldName string) *types.Var {
	for field := range trancheB1NamedStructFields(pkg, typeName) {
		if field.Name() == fieldName {
			return field
		}
	}
	return nil
}

func trancheB1IdentifierIsRead(identifier *ast.Ident, parents map[ast.Node]ast.Node) bool {
	expression := ast.Expr(identifier)
	if selector, ok := parents[identifier].(*ast.SelectorExpr); ok && selector.Sel == identifier {
		expression = selector
	}
	switch parent := parents[expression].(type) {
	case *ast.AssignStmt:
		for _, lhs := range parent.Lhs {
			if lhs == expression {
				return parent.Tok != token.ASSIGN && parent.Tok != token.DEFINE
			}
		}
	case *ast.IncDecStmt:
		if parent.X == expression {
			return true
		}
	}
	return true
}

func trancheB1CallObject(pkg *typedProductionPackage, call *ast.CallExpr) types.Object {
	switch function := call.Fun.(type) {
	case *ast.Ident:
		return pkg.info.Uses[function]
	case *ast.SelectorExpr:
		if selection := pkg.info.Selections[function]; selection != nil {
			return selection.Obj()
		}
		return pkg.info.Uses[function.Sel]
	default:
		return nil
	}
}

func trancheB1UnderlyingInterface(value types.Type) bool {
	if pointer, ok := value.(*types.Pointer); ok {
		value = pointer.Elem()
	}
	_, ok := value.Underlying().(*types.Interface)
	return ok
}

func trancheB1QualifiedFunction(function *types.Func) string {
	path := "<builtin>"
	if function.Pkg() != nil {
		path = function.Pkg().Path()
	}
	return path + ":" + function.FullName()
}

func trancheB1ObjectIdentity(object types.Object) string {
	if object == nil {
		return "<nil>"
	}
	if function, ok := object.(*types.Func); ok {
		return trancheB1QualifiedFunction(function)
	}
	return types.ObjectString(object, func(pkg *types.Package) string {
		if pkg == nil {
			return ""
		}
		return pkg.Path()
	})
}

func trancheB1FileAndParentsForNode(pkg *typedProductionPackage, parentsByFile map[string]map[ast.Node]ast.Node, wanted ast.Node) (string, map[ast.Node]ast.Node) {
	for fileName, file := range pkg.files {
		if file.Pos() <= wanted.Pos() && wanted.End() <= file.End() {
			return fileName, parentsByFile[fileName]
		}
	}
	return "", nil
}

func validateDestructiveReferenceInventory(t *testing.T, views []typedProductionView, packageImportPath string, vocabulary map[string]map[string]int) error {
	t.Helper()
	for qualifiedName, want := range vocabulary {
		separator := strings.LastIndex(qualifiedName, ".")
		if separator < 1 || separator == len(qualifiedName)-1 {
			return fmt.Errorf("invalid destructive vocabulary entry %q", qualifiedName)
		}
		importPath, name := qualifiedName[:separator], qualifiedName[separator+1:]
		references := mergedPackageFunctionReferences(t, views, packageImportPath, importPath, name)
		if err := validateTypedReferenceInventory(qualifiedName, references, want, false); err != nil {
			return err
		}
	}
	return nil
}

func validateReadDirInventory(files map[string]*ast.File, want map[string]string) error {
	got := make(map[string]string)
	var inventoryErr error
	for fileName, file := range files {
		parents := astParentMap(file)
		ast.Inspect(file, func(node ast.Node) bool {
			if inventoryErr != nil {
				return false
			}
			selector, ok := node.(*ast.SelectorExpr)
			if !ok || selector.Sel.Name != "ReadDir" {
				return true
			}
			call, ok := parents[selector].(*ast.CallExpr)
			if !ok || call.Fun != selector {
				inventoryErr = fmt.Errorf("ReadDir method value or indirect dispatch is forbidden")
				return false
			}
			if len(call.Args) != 1 {
				inventoryErr = fmt.Errorf("ReadDir must have one literal count")
				return false
			}
			literal, ok := call.Args[0].(*ast.BasicLit)
			if !ok || literal.Kind != token.INT || (literal.Value != "1" && literal.Value != "64") {
				inventoryErr = fmt.Errorf("ReadDir count must be the selected positive literal")
				return false
			}
			site := typedFunctionSite(fileName, enclosingFunction(parents, selector))
			if _, duplicate := got[site]; duplicate {
				inventoryErr = fmt.Errorf("additional ReadDir call in %s", site)
				return false
			}
			got[site] = literal.Value
			return true
		})
		if inventoryErr != nil {
			break
		}
	}
	if inventoryErr != nil {
		return inventoryErr
	}
	if !reflect.DeepEqual(got, want) {
		return fmt.Errorf("ReadDir inventory changed: got %v want %v", got, want)
	}
	return nil
}

func stagingOwnershipDeclarationInventory(pkg *typedProductionPackage) ([]string, []string, []string, []string, []string) {
	custodyReturns := make(map[string]bool)
	custodyConstructors := make(map[string]bool)
	stagedProducers := make(map[string]bool)
	stagedConstructors := make(map[string]bool)
	custodyAcceptors := make(map[string]bool)
	for fileName, file := range pkg.files {
		parents := astParentMap(file)
		for _, declaration := range file.Decls {
			function, ok := declaration.(*ast.FuncDecl)
			if !ok {
				continue
			}
			site := typedFunctionSite(fileName, function)
			typedFunction, ok := pkg.info.Defs[function.Name].(*types.Func)
			if !ok {
				continue
			}
			signature := typedFunction.Type().(*types.Signature)
			if tupleContainsNamedType(signature.Results(), "stagingCustody") {
				custodyReturns[site] = true
			}
			if tupleContainsNamedType(signature.Results(), "stagedExecutionInputs") {
				stagedProducers[site] = true
			}
			if tupleContainsNamedType(signature.Params(), "stagingCustody") {
				custodyAcceptors[site] = true
			}
		}
		ast.Inspect(file, func(node ast.Node) bool {
			literal, ok := node.(*ast.CompositeLit)
			if !ok {
				return true
			}
			site := typedFunctionSite(fileName, enclosingFunction(parents, literal))
			switch localNamedTypeName(pkg.info.TypeOf(literal)) {
			case "stagingCustody":
				custodyConstructors[site] = true
			case "stagedExecutionInputs":
				stagedConstructors[site] = true
			}
			return true
		})
	}
	return sortedStringSet(custodyReturns), sortedStringSet(custodyConstructors), sortedStringSet(stagedProducers), sortedStringSet(stagedConstructors), sortedStringSet(custodyAcceptors)
}

func tupleContainsNamedType(tuple *types.Tuple, name string) bool {
	if tuple == nil {
		return false
	}
	for index := 0; index < tuple.Len(); index++ {
		if localNamedTypeName(tuple.At(index).Type()) == name {
			return true
		}
	}
	return false
}

func localNamedTypeName(value types.Type) string {
	for {
		value = types.Unalias(value)
		pointer, ok := value.(*types.Pointer)
		if !ok {
			break
		}
		value = pointer.Elem()
	}
	named, ok := value.(*types.Named)
	if !ok {
		return ""
	}
	return named.Obj().Name()
}

func structuralProductionStateInventory(packages []*typedProductionPackage) ([]string, []string, []string) {
	var packageState []string
	var synchronizationFields []string
	var mapsBesideSynchronization []string
	for _, pkg := range packages {
		for _, file := range pkg.files {
			for _, declaration := range file.Decls {
				general, ok := declaration.(*ast.GenDecl)
				if !ok || general.Tok != token.VAR {
					continue
				}
				for _, spec := range general.Specs {
					valueSpec := spec.(*ast.ValueSpec)
					for _, name := range valueSpec.Names {
						object := pkg.info.Defs[name]
						if object != nil && containsRegistryStateType(object.Type(), pkg.pkg, make(map[types.Type]bool)) {
							packageState = append(packageState, pkg.importPath+":"+name.Name+":"+shortTypeString(object.Type()))
						}
					}
				}
			}
		}
		for _, name := range pkg.pkg.Scope().Names() {
			typeName, ok := pkg.pkg.Scope().Lookup(name).(*types.TypeName)
			if !ok {
				continue
			}
			structure, ok := types.Unalias(typeName.Type()).Underlying().(*types.Struct)
			if !ok {
				continue
			}
			hasSynchronization := false
			var structureMapFields []string
			for index := 0; index < structure.NumFields(); index++ {
				field := structure.Field(index)
				fieldType := field.Type()
				fieldLabel := pkg.importPath + ":" + typeName.Name() + "." + field.Name() + ":" + shortTypeString(fieldType)
				if containsSynchronizationType(fieldType, pkg.pkg, make(map[types.Type]bool)) {
					hasSynchronization = true
					synchronizationFields = append(synchronizationFields, fieldLabel)
				}
				if containsMutableMapType(fieldType, pkg.pkg, make(map[types.Type]bool)) {
					structureMapFields = append(structureMapFields, fieldLabel)
				}
			}
			if hasSynchronization {
				mapsBesideSynchronization = append(mapsBesideSynchronization, structureMapFields...)
			}
		}
	}
	sort.Strings(packageState)
	sort.Strings(synchronizationFields)
	sort.Strings(mapsBesideSynchronization)
	return packageState, synchronizationFields, mapsBesideSynchronization
}

func containsMutableMapType(value types.Type, owner *types.Package, visited map[types.Type]bool) bool {
	if value == nil || visited[value] {
		return false
	}
	visited[value] = true
	value = types.Unalias(value)
	switch typed := value.(type) {
	case *types.Map:
		return true
	case *types.Pointer:
		return containsMutableMapType(typed.Elem(), owner, visited)
	case *types.Array:
		return containsMutableMapType(typed.Elem(), owner, visited)
	case *types.Slice:
		return containsMutableMapType(typed.Elem(), owner, visited)
	case *types.Named:
		if typed.Obj().Pkg() != owner {
			return false
		}
		return containsMutableMapType(typed.Underlying(), owner, visited)
	case *types.Struct:
		for index := 0; index < typed.NumFields(); index++ {
			if containsMutableMapType(typed.Field(index).Type(), owner, visited) {
				return true
			}
		}
	}
	return false
}

func containsRegistryStateType(value types.Type, owner *types.Package, visited map[types.Type]bool) bool {
	if containsSynchronizationType(value, owner, make(map[types.Type]bool)) {
		return true
	}
	return containsMutableMapType(value, owner, visited)
}

func containsSynchronizationType(value types.Type, owner *types.Package, visited map[types.Type]bool) bool {
	if value == nil || visited[value] {
		return false
	}
	visited[value] = true
	value = types.Unalias(value)
	switch typed := value.(type) {
	case *types.Pointer:
		return containsSynchronizationType(typed.Elem(), owner, visited)
	case *types.Array:
		return containsSynchronizationType(typed.Elem(), owner, visited)
	case *types.Slice:
		return containsSynchronizationType(typed.Elem(), owner, visited)
	case *types.Map:
		return containsSynchronizationType(typed.Key(), owner, visited) || containsSynchronizationType(typed.Elem(), owner, visited)
	case *types.Named:
		if typed.Obj().Pkg() != nil {
			switch typed.Obj().Pkg().Path() {
			case "sync", "sync/atomic":
				return true
			}
		}
		if typed.Obj().Pkg() != owner {
			return false
		}
		return containsSynchronizationType(typed.Underlying(), owner, visited)
	case *types.Struct:
		for index := 0; index < typed.NumFields(); index++ {
			if containsSynchronizationType(typed.Field(index).Type(), owner, visited) {
				return true
			}
		}
	}
	return false
}

func shortTypeString(value types.Type) string {
	return types.TypeString(value, func(pkg *types.Package) string { return pkg.Name() })
}

func productionAdmissionGoFiles(t *testing.T) []string {
	t.Helper()
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	production := files[:0]
	for _, file := range files {
		if !strings.HasSuffix(file, "_test.go") {
			production = append(production, file)
		}
	}
	sort.Strings(production)
	return production
}

func productionAdmissionSource(t *testing.T) string {
	t.Helper()
	var source strings.Builder
	for _, file := range productionAdmissionGoFiles(t) {
		source.WriteString(mustReadAdmissionSource(t, file))
		source.WriteByte('\n')
	}
	return source.String()
}

func calledFunctionName(expression ast.Expr) string {
	switch typed := expression.(type) {
	case *ast.Ident:
		return typed.Name
	case *ast.SelectorExpr:
		return typed.Sel.Name
	default:
		return ""
	}
}

type semanticCallDefinition struct {
	label             string
	importPath        string
	receiver          string
	name              string
	insideFuncLiteral bool
	deferred          bool
}

type semanticCallStep struct {
	semanticCallDefinition
	target types.Object
}

type semanticCallSite struct {
	statementIndex    int
	position          token.Pos
	insideFuncLiteral bool
	deferred          bool
}

func validateResolvedPlanSemanticCallFlow(pkg *typedProductionPackage) error {
	if err := validateSemanticCallSequence(pkg, "Service", "Submit", []semanticCallDefinition{
		{label: "resolve and freeze execution", receiver: "Service", name: "resolveExecutionForSubmit"},
		{label: "assign execution locator", name: "newExecutionLocator"},
		{label: "construct one run projection", name: "newResolvedRunProjection"},
		{label: "qualify the operation-local root set", name: "qualifyExecutionRoots"},
		{label: "compare the qualified root owner", receiver: "qualifiedExecutionRoots", name: "owner"},
		{label: "reobserve topology immediately before claim", receiver: "qualifiedExecutionRoots", name: "reobserve"},
		{label: "transfer the qualified staging descriptor", receiver: "qualifiedExecutionRoots", name: "takeStagingQualifiedDirectory"},
		{label: "claim staging custody through the qualified descriptor", name: "claimStagingCustodyFromQualifiedRoot"},
		{label: "materialize captured inputs", name: "materializeExecutionInputs"},
		{label: "construct authority handoff", name: "buildResolvedExecutionAuthorityHandoff"},
		{label: "construct Nomad job", name: "buildNomadJobSpec"},
		{label: "revalidate custody before handoff", receiver: "stagingCustody", name: "revalidateBeforeHandoff"},
		{label: "register one Nomad job", receiver: "nomadClient", name: "submitJob"},
	}); err != nil {
		return fmt.Errorf("Submit semantic flow: %w", err)
	}
	if err := validateSemanticCallSequence(pkg, "Service", "resolveExecutionForSubmit", []semanticCallDefinition{
		{label: "admit request", receiver: "Service", name: "prepareAdmission"},
		{label: "snapshot configuration", name: "newSubmitConfigSnapshot"},
		{label: "resolve runtime profile", name: "resolveExecutionRuntimeProfile"},
		{label: "normalize placement", name: "normalizeSubmitPlacementFacts"},
		{label: "resolve resources", name: "resolveTaskResources"},
		{label: "acquire payload", receiver: "Service", name: "fetchPayloadBytes"},
		{label: "capture runtime support", name: "captureRuntimeSupport"},
		{label: "resolve mounts", receiver: "Service", name: "resolveRuntimeMounts"},
		{label: "capture workload trust", name: "captureWorkloadTrustMaterial"},
		{label: "observe platform-state owner", name: "resolveExecutionPlatformStateOwnerModel"},
		{label: "freeze semantic plan", name: "newResolvedExecutionPlan"},
		{label: "freeze byte material", name: "newResolvedExecutionMaterial"},
		{label: "freeze host materialization context", name: "newHostMaterializationContext"},
	}); err != nil {
		return fmt.Errorf("submit resolver semantic flow: %w", err)
	}
	if err := validateSemanticCallSequence(pkg, "", "validateRuntimeMountArchiveWithinBudgets", []semanticCallDefinition{
		{label: "open bounded gzip stream", importPath: "compress/gzip", name: "NewReader"},
		{label: "construct tar reader", importPath: "archive/tar", name: "NewReader"},
		{label: "validate entry size", name: "checkMountEntrySize"},
		{label: "allocate checked entry", name: "readCheckedMountEntry"},
		{label: "drain bounded stream", importPath: "io", name: "Copy"},
	}); err != nil {
		return fmt.Errorf("mount parser semantic flow: %w", err)
	}

	for _, inventory := range []struct {
		label      string
		definition semanticCallDefinition
		want       map[string]int
	}{
		{label: "submit resolver", definition: semanticCallDefinition{receiver: "Service", name: "resolveExecutionForSubmit"}, want: map[string]int{"es/admission/submit.go:Service.Submit": 1, "es/admission/reliable_submit_replay_private.go:Service.composePrivateSyntheticReplay": 1}},
		{label: "execution locator", definition: semanticCallDefinition{name: "newExecutionLocator"}, want: map[string]int{"es/admission/submit.go:Service.Submit": 1}},
		{label: "run projection", definition: semanticCallDefinition{name: "newResolvedRunProjection"}, want: map[string]int{"es/admission/submit.go:Service.Submit": 1}},
		{label: "Nomad registration", definition: semanticCallDefinition{receiver: "nomadClient", name: "submitJob"}, want: map[string]int{"es/admission/submit.go:Service.Submit": 1}},
		{label: "semantic plan freeze", definition: semanticCallDefinition{name: "newResolvedExecutionPlan"}, want: map[string]int{"es/admission/resolved_execution_plan.go:Service.resolveExecutionForSubmit": 1, "es/admission/reliable_submit_replay_hydration.go:decodePrivateReplayOriginal": 1}},
		{label: "material freeze", definition: semanticCallDefinition{name: "newResolvedExecutionMaterial"}, want: map[string]int{"es/admission/resolved_execution_plan.go:Service.resolveExecutionForSubmit": 1, "es/admission/reliable_submit_replay_hydration.go:decodePrivateReplayOriginal": 1}},
		{label: "host context freeze", definition: semanticCallDefinition{name: "newHostMaterializationContext"}, want: map[string]int{"es/admission/resolved_execution_plan.go:Service.resolveExecutionForSubmit": 1, "es/admission/reliable_submit_replay_hydration.go:privateReplayReader.placement": 1}},
		{label: "mount target normalization", definition: semanticCallDefinition{name: "normalizeRuntimeMountTargetPath"}, want: map[string]int{
			"es/admission/mounts.go:validateRuntimeMounts":                                  1,
			"es/admission/reliable_submit_binding.go:bindingMountsValid":                    1,
			"es/admission/reliable_submit_replay_hydration.go:privateReplayReader.original": 1,
			"es/admission/reliable_submit_replay_intent.go:parsePrivateReplayDelivery":      1,
		}},
		{label: "gzip traversal", definition: semanticCallDefinition{importPath: "compress/gzip", name: "NewReader"}, want: map[string]int{
			"es/admission/mounts.go:validateRuntimeMountArchiveWithinBudgets": 1,
		}},
		{label: "tar traversal", definition: semanticCallDefinition{importPath: "archive/tar", name: "NewReader"}, want: map[string]int{
			"es/admission/mounts.go:validateRuntimeMountArchiveWithinBudgets": 1,
		}},
	} {
		target, err := resolveSemanticCallTarget(pkg, inventory.definition)
		if err != nil {
			return fmt.Errorf("%s: %w", inventory.label, err)
		}
		if err := validateTypedReferenceInventory(inventory.label, pkg.referencesTo(target), inventory.want, true); err != nil {
			return err
		}
	}
	return nil
}

func validateReviewedStaticArchiveBoundary(admissionPkg, archivePkg, runtimePkg *typedProductionPackage) error {
	const staticArchive = "execution-substrate/es/internal/staticarchive"
	for _, inventory := range []struct {
		label string
		pkg   *typedProductionPackage
		path  string
		name  string
		want  map[string]int
	}{
		{"shared gzip traversal", archivePkg, "compress/gzip", "NewReader", map[string]int{"es/internal/staticarchive/archive.go:Open": 1}},
		{"shared tar traversal", archivePkg, "archive/tar", "NewReader", map[string]int{"es/internal/staticarchive/archive.go:Open": 1}},
		{"policy shared archive open", admissionPkg, staticArchive, "Open", map[string]int{"es/admission/policy_payload.go:extractStaticScriptEntrypointText": 1}},
		{"policy shared archive traversal", admissionPkg, staticArchive, "Next", map[string]int{"es/admission/policy_payload.go:extractStaticScriptEntrypointText": 1}},
		{"policy shared namespace", admissionPkg, staticArchive, "Add", map[string]int{"es/admission/policy_payload.go:extractStaticScriptEntrypointText": 1}},
		{"policy shared completion", admissionPkg, staticArchive, "Finish", map[string]int{"es/admission/policy_payload.go:extractStaticScriptEntrypointText": 1}},
		{"runtime shared archive open", runtimePkg, staticArchive, "Open", map[string]int{"es/runtimehelper/supervisor.go:extractWorkloadArchive": 1}},
		{"runtime shared archive traversal", runtimePkg, staticArchive, "Next", map[string]int{"es/runtimehelper/supervisor.go:extractWorkloadArchive": 1}},
		{"runtime shared namespace", runtimePkg, staticArchive, "Add", map[string]int{"es/runtimehelper/supervisor.go:extractWorkloadArchive": 1}},
		{"runtime shared completion", runtimePkg, staticArchive, "Finish", map[string]int{"es/runtimehelper/supervisor.go:extractWorkloadArchive": 1}},
		{"runtime shared destination normalization", runtimePkg, staticArchive, "CleanName", map[string]int{"es/runtimehelper/supervisor.go:archiveDestinationPath": 1}},
		{"shared namespace normalization", archivePkg, staticArchive, "CleanName", map[string]int{"es/internal/staticarchive/archive.go:Namespace.Add": 1}},
	} {
		if err := validateTypedReferenceInventory(inventory.label, inventory.pkg.referencesToPackageFunction(inventory.path, inventory.name), inventory.want, true); err != nil {
			return err
		}
	}
	for _, flow := range []struct {
		label    string
		pkg      *typedProductionPackage
		receiver string
		caller   string
		steps    []semanticCallDefinition
	}{
		{"shared reader construction", archivePkg, "", "Open", []semanticCallDefinition{{label: "gzip reader", importPath: "compress/gzip", name: "NewReader"}, {label: "tar reader", importPath: "archive/tar", name: "NewReader"}}},
		{"policy traversal and completion", admissionPkg, "", "extractStaticScriptEntrypointText", []semanticCallDefinition{{label: "shared open", importPath: staticArchive, name: "Open"}, {label: "next entry", importPath: staticArchive, name: "Next"}, {label: "record namespace", importPath: staticArchive, name: "Add"}, {label: "verify tails", importPath: staticArchive, name: "Finish"}}},
		{"runtime traversal and completion", runtimePkg, "", "extractWorkloadArchive", []semanticCallDefinition{{label: "shared open", importPath: staticArchive, name: "Open"}, {label: "next entry", importPath: staticArchive, name: "Next"}, {label: "record namespace", importPath: staticArchive, name: "Add"}, {label: "verify tails", importPath: staticArchive, name: "Finish"}}},
		{"shared namespace validation", archivePkg, "Namespace", "Add", []semanticCallDefinition{{label: "clean effective path", name: "CleanName"}}},
	} {
		if err := validateSemanticCallSequence(flow.pkg, flow.receiver, flow.caller, flow.steps); err != nil {
			return fmt.Errorf("%s: %w", flow.label, err)
		}
	}
	return validateStaticArchiveCompletionBody(archivePkg)
}

func validateStaticArchiveCompletionBody(pkg *typedProductionPackage) error {
	const fileName = "es/internal/staticarchive/archive.go"
	file := pkg.files[fileName]
	if file == nil {
		return fmt.Errorf("shared archive implementation source is absent")
	}
	var finish, open *ast.FuncDecl
	for _, declaration := range file.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok {
			continue
		}
		if function.Recv == nil && function.Name.Name == "Open" {
			open = function
		}
		if function.Recv != nil && receiverTypeName(function.Recv.List[0].Type) == "Reader" && function.Name.Name == "Finish" {
			finish = function
		}
	}
	if finish == nil || open == nil {
		return fmt.Errorf("shared archive opening/completion method is absent")
	}
	var decodedRead, compressedPeek, decodedLimit int
	ast.Inspect(finish.Body, func(node ast.Node) bool {
		if comparison, ok := node.(*ast.BinaryExpr); ok && comparison.Op == token.EQL && exprSourceName(comparison.X) == "r.limit.N" {
			if value, ok := comparison.Y.(*ast.BasicLit); ok && value.Value == "0" {
				decodedLimit++
			}
		}
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		selector, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if selector.Sel.Name == "Read" && exprSourceName(selector.X) == "r.decoded" && len(call.Args) == 1 {
			if slice, ok := call.Args[0].(*ast.SliceExpr); ok && exprSourceName(slice.X) == "buf" && slice.Low == nil && slice.High == nil && slice.Max == nil {
				decodedRead++
			}
		}
		if selector.Sel.Name == "Peek" && exprSourceName(selector.X) == "r.source" && len(call.Args) == 1 {
			if value, ok := call.Args[0].(*ast.BasicLit); ok && value.Value == "1" {
				compressedPeek++
			}
		}
		return true
	})
	var singleMember int
	ast.Inspect(open.Body, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok || len(call.Args) != 1 || exprSourceName(call.Args[0]) != "false" {
			return true
		}
		selector, ok := call.Fun.(*ast.SelectorExpr)
		if ok && exprSourceName(selector.X) == "gzipReader" && selector.Sel.Name == "Multistream" {
			singleMember++
		}
		return true
	})
	if decodedRead != 1 || compressedPeek != 1 || decodedLimit != 1 || singleMember != 1 {
		return fmt.Errorf("shared archive completion no longer verifies decoded and compressed tails")
	}
	return nil
}

func validateTrancheASemanticCallFlow(pkg *typedProductionPackage) error {
	if err := validateSemanticCallSequence(pkg, "", "claimStagingCustodyFromQualifiedRoot", []semanticCallDefinition{
		{label: "revalidate configured root", receiver: "qualifiedDirectory", name: "verifyVisible"},
		{label: "exclusively create run root", importPath: "golang.org/x/sys/unix", name: "Mkdirat"},
		{label: "capture claimed identity", importPath: "golang.org/x/sys/unix", name: "Fstatat"},
		{label: "open claimed root without following", name: "platformOpenAtNoFollow"},
		{label: "set claimed owner", importPath: "golang.org/x/sys/unix", name: "Fchown"},
		{label: "set claimed mode", importPath: "golang.org/x/sys/unix", name: "Fchmod"},
		{label: "initialize expected tree", name: "newCustodyExpectedDirectory"},
	}); err != nil {
		return fmt.Errorf("exclusive custody semantic flow: %w", err)
	}
	for _, inventory := range []struct {
		label      string
		definition semanticCallDefinition
		want       map[string]int
	}{
		{
			label:      "test-facing path-taking run-root claim",
			definition: semanticCallDefinition{name: "claimStagingCustody"},
			want:       map[string]int{},
		},
		{
			label:      "descriptor-taking run-root claim",
			definition: semanticCallDefinition{name: "claimStagingCustodyFromQualifiedRoot"},
			want: map[string]int{
				"es/admission/staging_custody.go:claimStagingCustody":             1,
				"es/admission/staging_custody.go:probeStagingCustodyCapabilities": 1,
				"es/admission/submit.go:Service.Submit":                           1,
			},
		},
		{label: "materialization entry point", definition: semanticCallDefinition{name: "materializeExecutionInputs"}, want: map[string]int{"es/admission/submit.go:Service.Submit": 1}},
		{label: "pre-handoff revalidation", definition: semanticCallDefinition{receiver: "stagingCustody", name: "revalidateBeforeHandoff"}, want: map[string]int{"es/admission/submit.go:Service.Submit": 1}},
	} {
		target, err := resolveSemanticCallTarget(pkg, inventory.definition)
		if err != nil {
			return fmt.Errorf("%s: %w", inventory.label, err)
		}
		if err := validateTypedReferenceInventory(inventory.label, pkg.referencesTo(target), inventory.want, true); err != nil {
			return err
		}
	}
	return nil
}

func validateSemanticCallSequence(pkg *typedProductionPackage, callerReceiver string, callerName string, definitions []semanticCallDefinition) error {
	callerObject, err := resolveSemanticCallTarget(pkg, semanticCallDefinition{receiver: callerReceiver, name: callerName})
	if err != nil {
		return fmt.Errorf("caller: %w", err)
	}
	caller, ok := callerObject.(*types.Func)
	if !ok {
		return fmt.Errorf("caller %s is not a function", callerName)
	}
	declaration, parents, err := semanticFunctionDeclaration(pkg, caller)
	if err != nil {
		return err
	}
	steps := make([]semanticCallStep, 0, len(definitions))
	for _, definition := range definitions {
		target, err := resolveSemanticCallTarget(pkg, definition)
		if err != nil {
			return fmt.Errorf("%s: %w", definition.label, err)
		}
		steps = append(steps, semanticCallStep{semanticCallDefinition: definition, target: target})
	}

	sites := make(map[types.Object][]semanticCallSite, len(steps))
	for statementIndex, statement := range declaration.Body.List {
		ast.Inspect(statement, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			object := trancheB1CallObject(pkg, call)
			for _, step := range steps {
				if object != step.target {
					continue
				}
				_, deferred := statement.(*ast.DeferStmt)
				sites[step.target] = append(sites[step.target], semanticCallSite{
					statementIndex:    statementIndex,
					position:          call.Pos(),
					insideFuncLiteral: insideFunctionLiteral(parents, call),
					deferred:          deferred,
				})
			}
			return true
		})
	}

	previousStatement := -1
	var previousPosition token.Pos
	for _, step := range steps {
		found := sites[step.target]
		if len(found) == 0 {
			return fmt.Errorf("missing semantic object %q in %s", step.label, caller.FullName())
		}
		if len(found) != 1 {
			return fmt.Errorf("unexpected semantic object count for %q in %s: got %d want 1", step.label, caller.FullName(), len(found))
		}
		site := found[0]
		if site.insideFuncLiteral != step.insideFuncLiteral {
			return fmt.Errorf("wrong caller classification for %q in %s: closure=%t want %t", step.label, caller.FullName(), site.insideFuncLiteral, step.insideFuncLiteral)
		}
		if site.deferred != step.deferred {
			return fmt.Errorf("wrong governed order for %q in %s: deferred=%t want %t", step.label, caller.FullName(), site.deferred, step.deferred)
		}
		if site.statementIndex < previousStatement || site.statementIndex == previousStatement && site.position <= previousPosition {
			return fmt.Errorf("wrong governed order at %q in %s", step.label, caller.FullName())
		}
		previousStatement = site.statementIndex
		previousPosition = site.position
	}
	return nil
}

func resolveSemanticCallTarget(pkg *typedProductionPackage, definition semanticCallDefinition) (types.Object, error) {
	if definition.importPath != "" {
		var found *types.Func
		for _, object := range pkg.info.Uses {
			function, ok := object.(*types.Func)
			if !ok || function.Pkg() == nil || function.Pkg().Path() != definition.importPath || function.Name() != definition.name {
				continue
			}
			if found != nil && found != function {
				return nil, fmt.Errorf("package function %s.%s resolved to multiple objects", definition.importPath, definition.name)
			}
			found = function
		}
		if found == nil {
			return nil, fmt.Errorf("package function %s.%s is missing", definition.importPath, definition.name)
		}
		return found, nil
	}
	if definition.receiver != "" {
		function, ok := trancheB1LookupMethod(pkg, definition.receiver, definition.name)
		if !ok {
			return nil, fmt.Errorf("method %s.%s is missing", definition.receiver, definition.name)
		}
		return function, nil
	}
	function, ok := trancheB1LookupFunction(pkg, definition.name)
	if !ok {
		return nil, fmt.Errorf("function %s is missing", definition.name)
	}
	return function, nil
}

func semanticFunctionDeclaration(pkg *typedProductionPackage, target *types.Func) (*ast.FuncDecl, map[ast.Node]ast.Node, error) {
	for _, file := range pkg.files {
		for _, declaration := range file.Decls {
			function, ok := declaration.(*ast.FuncDecl)
			if !ok || pkg.info.Defs[function.Name] != target {
				continue
			}
			if function.Body == nil {
				return nil, nil, fmt.Errorf("function %s has no body", target.FullName())
			}
			return function, astParentMap(file), nil
		}
	}
	return nil, nil, fmt.Errorf("function declaration for %s is missing", target.FullName())
}

func TestSemanticCallSequenceRejectsLexicalAndControlFlowMutants(t *testing.T) {
	const base = `package admission
type Service struct{}
func resolve() int { return 1 }
func locate() int { return 2 }
func project(plan int, locator int) {}
func (s *Service) Submit() {
	resolved := resolve()
	locator := locate()
	project(resolved, locator)
}
`
	validate := func(source string) error {
		pkg := typeCheckSyntheticProductionPackage(t, "semantic.go", source)
		definitions := []semanticCallDefinition{
			{label: "resolve", name: "resolve"},
			{label: "locate", name: "locate"},
			{label: "project", name: "project"},
		}
		if err := validateSemanticCallSequence(pkg, "Service", "Submit", definitions); err != nil {
			return err
		}
		for _, definition := range definitions {
			target, err := resolveSemanticCallTarget(pkg, definition)
			if err != nil {
				return err
			}
			if err := validateTypedReferenceInventory(definition.label, pkg.referencesTo(target), map[string]int{"semantic.go:Service.Submit": 1}, true); err != nil {
				return err
			}
		}
		return nil
	}

	positive := map[string]string{
		"comments and strings are inert": strings.Replace(base, "\tresolved := resolve()", "\t// project(resolve(), locate())\n\t_ = \"project(resolve(), locate())\"\n\tresolved := resolve()", 1),
		"formatting and local rename": `package admission
type Service struct { }
func resolve ( ) int { return 1 }
func locate( ) int { return 2 }
func project(plan int, locator int) { }
func (s *Service) Submit( ) {
	planCopy:=resolve( )
	locationCopy := locate ( )
	project( planCopy , locationCopy )
}
`,
	}
	for name, source := range positive {
		t.Run(name, func(t *testing.T) {
			if err := validate(source); err != nil {
				t.Fatalf("semantically equivalent source failed: %v", err)
			}
		})
	}

	negative := map[string]string{
		"dead helper cannot satisfy live flow": strings.Replace(base, "\tproject(resolved, locator)", "\t_ = resolved\n\t_ = locator", 1) + "func deadHelper() { project(1, 2) }\n",
		"hidden helper call":                   strings.Replace(base, "\tproject(resolved, locator)", "\thidden(resolved, locator)", 1) + "func hidden(plan int, locator int) { project(plan, locator) }\n",
		"closure call":                         strings.Replace(base, "\tproject(resolved, locator)", "\tdeferred := func() { project(resolved, locator) }\n\t_ = deferred", 1),
		"wrong order": `package admission
type Service struct{}
func resolve() int { return 1 }
func locate() int { return 2 }
func project(plan int, locator int) {}
func (s *Service) Submit() {
	locator := locate()
	resolved := resolve()
	project(resolved, locator)
}
`,
		"alternate consumer":      base + "func alternateConsumer() { project(1, 2) }\n",
		"required object removed": strings.Replace(base, "\tlocator := locate()", "\tlocator := 2", 1),
		"unexpected object added": strings.Replace(base, "\tproject(resolved, locator)", "\tproject(resolved, locator)\n\tproject(resolved, locator)", 1),
	}
	for name, source := range negative {
		t.Run(name, func(t *testing.T) {
			if err := validate(source); err == nil {
				t.Fatal("semantic mutation escaped object/call-flow inventory")
			}
		})
	}
}

func TestTrancheAResourceAndFilesystemCustodySourceGuardrails(t *testing.T) {
	views := loadTypedProductionPackages(t, "./es/admission")
	for _, view := range views {
		pkg := requireTypedProductionPackage(t, view.packages, "execution-substrate/es/admission")
		if err := validateTrancheASemanticCallFlow(pkg); err != nil {
			t.Fatalf("%s: %v", view.target, err)
		}
		platformObserver := requirePackageFunction(t, pkg, "platformObserveExecutionRoots")
		if err := validateTypedReferenceInventory("platform execution-root observer", pkg.referencesTo(platformObserver), map[string]int{
			"es/admission/execution_roots.go:qualifiedExecutionRoots.reobserve": 1,
		}, true); err != nil {
			t.Fatalf("%s: %v", view.target, err)
		}
		switch view.target.goos {
		case "linux":
			if err := validateTypedReferenceInventory("Linux statx identity binding", pkg.referencesToPackageFunction("golang.org/x/sys/unix", "Statx"), map[string]int{
				"es/admission/execution_roots_linux.go:observeLinuxExecutionRoot": 2,
			}, true); err != nil {
				t.Fatalf("%s: %v", view.target, err)
			}
		case "darwin":
			if err := validateTypedReferenceInventory("Darwin bounded mount acquisition", pkg.referencesToPackageFunction("golang.org/x/sys/unix", "Getfsstat"), map[string]int{
				"es/admission/execution_roots_darwin.go:readBoundedDarwinMounts": 2,
			}, true); err != nil {
				t.Fatalf("%s: %v", view.target, err)
			}
			if err := validateTypedReferenceInventory("Darwin descriptor filesystem binding", pkg.referencesToPackageFunction("golang.org/x/sys/unix", "Fstatfs"), map[string]int{
				"es/admission/execution_roots_darwin.go:observeDarwinExecutionRoot": 1,
			}, true); err != nil {
				t.Fatalf("%s: %v", view.target, err)
			}
		}
	}

	custodySource := mustReadAdmissionSource(t, "staging_custody.go")
	assertAdmissionFoundationContainsAll(t, "retained custody and no pathname cleanup", custodySource,
		"type custodyExpectedNode struct", "children map[string]*custodyExpectedNode", "expectedRoot", "*custodyExpectedNode", "strings.Clone(component)", "strings.Clone(name)",
		"func (custody *stagingCustody) revalidateBeforeHandoff", "stack := []custodyDirectoryValidation", "func validateExpectedDirectoryEntries", "reader.ReadDir(1)", "maximumObserved := len(expectedChildren) + 1",
	)
	assertAdmissionFoundationOmitsAll(t, "hierarchical expected tree has no cumulative-path index", custodySource,
		"nodes map[string]custodyIdentity", "map[string]custodyIdentity", "custody.nodes", "expectedPaths", "expectedByPath",
	)
	assertAdmissionFoundationOmitsAll(t, "C custody retains leaves and has no pathname unlink", custodySource,
		"unix.Unlinkat", "cleanupUninitializedClaim", "removeDirectoryContentsDescriptorRelative",
	)
	assertAdmissionFoundationOmitsAll(t, "descriptor custody path fallbacks", custodySource,
		"os.RemoveAll", "filepath.Walk", "filepath.WalkDir", "os.Lstat", "os.Rename(", "os.MkdirAll", "os.WriteFile",
		"ReadDir(-1)", ".execution-substrate-stage-claim-v1", ".execution-substrate-quarantine-", "openClaimedStagingCustody", "cleanupUninitializedClaim", "removeDirectoryContentsDescriptorRelative", "stagingClaimPhase",
	)
	expectedEnumerationSource := admissionSourceSection(t, custodySource, "func validateExpectedDirectoryEntries", "func (custody *stagingCustody) revalidateExpectedChildAt")
	assertAdmissionFoundationOmitsAll(t, "expected-tree enumeration remains ledger bounded", expectedEnumerationSource,
		"append(", "sort.", "ReadDir(-1)",
	)
	directoryValidationSource := admissionSourceSection(t, custodySource, "func (custody *stagingCustody) revalidateDirectoryChildren", "type directoryEntryReader interface")
	assertAdmissionFoundationContainsAll(t, "fresh independent directory enumeration", directoryValidationSource,
		"unix.Fstat(directoryFD, &directoryBefore)",
		"enumerationFD, err := platformOpenAtNoFollow(directoryFD, \".\", unix.O_RDONLY|unix.O_DIRECTORY, 0, true)",
		"stream := os.NewFile(uintptr(enumerationFD), \"custody-directory\")",
		"unix.Fstat(directoryFD, &directoryAfter)",
	)
	assertAdmissionFoundationOmitsAll(t, "enumeration cannot share the identity descriptor cursor", directoryValidationSource,
		"unix.Dup(directoryFD)", "unix.Dup(enumerationFD)", "ReadDir(-1)",
	)
	revalidationSource := admissionSourceSection(t, custodySource, "func (custody *stagingCustody) revalidateBeforeHandoff", "func (custody *stagingCustody) revalidateDirectoryChildren")
	assertAdmissionFoundationContainsAll(t, "iterative expected-tree validation", revalidationSource,
		"stack := []custodyDirectoryValidation", "for len(stack) != 0", "stack = append(stack, children...)",
	)
	resultsSource := mustReadAdmissionSource(t, "results.go")
	assertAdmissionFoundationOmitsAll(t, "retained result path fallbacks", resultsSource,
		"filepath.Walk", "filepath.WalkDir", "os.Lstat", "os.Rename(", "os.CreateTemp", "unix.Linkat",
	)
	assertAdmissionFoundationOmitsAll(t, "C result custody has no existing metadata repair or pathname temporary removal", resultsSource,
		"unix.Unlinkat", "reconcileRetainedResultRunMetadata", "reconcileRegularFile", "removeTemporary",
	)
	assertAdmissionFoundationContainsAll(t, "retained result no-replace publication", resultsSource,
		"platformRenameNoReplace", "validateExistingRetainedResultBundle", "fingerprintOpenRegularFile",
	)
	assertAdmissionFoundationContainsAll(t, "result effects remain pair-bound and named by effect", resultsSource,
		"func openExistingRetainedResultDirectory", "func openOrCreateRetainedResultDirectory",
		"func (directory *retainedResultDirectory) verifyBeforeEffect", "func (directory *retainedResultDirectory) validateExistingRetainedResultBundle",
	)
	executionRootsSource := mustReadAdmissionSource(t, "execution_roots.go")
	assertAdmissionFoundationContainsAll(t, "operation-local execution-root custody", executionRootsSource,
		"type qualifiedExecutionRoots struct", "closed       bool", "func qualifyExecutionRoots",
		"func (roots *qualifiedExecutionRoots) reobserve", "func provisionExecutionRoots",
		"func (roots *qualifiedExecutionRoots) takeStagingQualifiedDirectory",
		"func (roots *qualifiedExecutionRoots) duplicateResultsQualifiedDirectory",
		"func (roots *qualifiedExecutionRoots) probeCapabilities",
	)
	assertAdmissionFoundationOmitsAll(t, "execution-root custody has no process-global coordination", executionRootsSource,
		"sync.Mutex", "sync.RWMutex", "go func", "time.NewTicker", "namespaceLease", "rootRegistry",
	)
	linuxRootSource := mustReadAdmissionSource(t, "execution_roots_linux.go")
	assertAdmissionFoundationContainsAll(t, "bounded Linux canonical descriptor topology proof", linuxRootSource,
		"linuxMountInfoByteLimit   = 8 << 20", "linuxMountInfoRecordLimit = 65536",
		"os.Open(\"/proc/self/mountinfo\")", "unix.STATX_BASIC_STATS | unix.STATX_MNT_ID",
		"/proc/self/fd/%d", "parseLinuxMountInfo", "linuxHasDescendantMount",
	)
	if strings.Count(linuxRootSource, "os.Open(\"/proc/self/mountinfo\")") != 1 {
		t.Fatal("Linux mountinfo acquisition must have exactly one source read site")
	}
	darwinRootSource := mustReadAdmissionSource(t, "execution_roots_darwin.go")
	assertAdmissionFoundationContainsAll(t, "bounded Darwin canonical descriptor topology proof", darwinRootSource,
		"darwinMountRecordLimit = 65536", "unix.Getfsstat", "unix.Fstatfs", "unix.F_GETPATH",
		"darwinHasDescendantMount", "descriptor filesystem does not select exactly one getfsstat record",
	)
	trustSource := admissionSourceSection(t, mustReadAdmissionSource(t, "executionpackage.go"), "func appendNormalizedPEMBundle", "func readSystemCABundle")
	assertAdmissionFoundationOmitsAll(t, "normalized trust bundle assembly", trustSource,
		"normalizePEMBytesForRuntimeFile",
	)
	vaultNormalizeSource := admissionSourceSection(t, mustReadAdmissionSource(t, "executionpackage.go"), "func normalizePEMForRuntimeFile", "func normalizePEMBytesForRuntimeFile")
	assertAdmissionFoundationOmitsAll(t, "normalized Vault CA capture", vaultNormalizeSource,
		"[]byte(value)", "normalizePEMBytesForRuntimeFile",
	)
	lifecycleSource := mustReadAdmissionSource(t, "lifecycle.go")
	assertAdmissionFoundationContainsAll(t, "terminal result attempt remains independent", lifecycleSource,
		"s.maybeRetainTerminalResult(locator, allocation)",
	)
	assertAdmissionFoundationOmitsAll(t, "lifecycle cannot mutate staging", lifecycleSource,
		"maybeCleanupSuccessfulStageRoot", "representsUnambiguousSuccessfulCompletion", "openClaimedStagingCustody", "custody.cleanup()", "StagingRootDir",
	)
	submitSource := mustReadAdmissionSource(t, "submit.go")
	assertAdmissionFoundationContainsAll(t, "submit closes and retains custody", submitSource, "_ = custody.close()", "custody.revalidateBeforeHandoff()")
	assertAdmissionFoundationOmitsAll(t, "submit has no whole-root cleanup", submitSource, "custody.cleanup()", "custody.retain()", "submission failed and staged execution cleanup failed")

	darwinSource := mustReadAdmissionSource(t, "staging_custody_darwin.go")
	assertAdmissionFoundationContainsAll(t, "Darwin custody primitives", darwinSource,
		"unix.O_NOFOLLOW_ANY", "unix.RENAME_EXCL", "unix.RENAME_NOFOLLOW_ANY",
	)
	linuxSource := mustReadAdmissionSource(t, "staging_custody_linux.go")
	assertAdmissionFoundationContainsAll(t, "Linux custody primitives", linuxSource,
		"unix.RESOLVE_BENEATH", "unix.RESOLVE_NO_MAGICLINKS", "unix.RESOLVE_NO_SYMLINKS", "unix.RESOLVE_NO_XDEV", "unix.RENAME_NOREPLACE",
	)
}

func assertMountEntryAllocationStructure(t *testing.T, file *ast.File) {
	t.Helper()
	if functionAllocatesByteSlice(file, "validateRuntimeMountArchiveWithinBudgets") {
		t.Fatal("runtime mount archive parser must not allocate a byte slice")
	}
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "readCheckedMountEntry" {
			continue
		}
		if fn.Type.Params == nil || len(fn.Type.Params.List) != 2 ||
			exprSourceName(fn.Type.Params.List[0].Type) != "io.Reader" ||
			exprSourceName(fn.Type.Params.List[1].Type) != "checkedMountEntrySize" {
			t.Fatal("readCheckedMountEntry must accept only io.Reader and checkedMountEntrySize")
		}
		if !functionAllocatesByteSlice(file, "readCheckedMountEntry") {
			t.Fatal("readCheckedMountEntry must own the checked byte-slice allocation")
		}
		return
	}
	t.Fatal("readCheckedMountEntry not found")
}

func functionAllocatesByteSlice(file *ast.File, functionName string) bool {
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name.Name != functionName {
			continue
		}
		found := false
		ast.Inspect(fn.Body, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok || exprSourceName(call.Fun) != "make" || len(call.Args) == 0 {
				return true
			}
			array, ok := call.Args[0].(*ast.ArrayType)
			if ok && array.Len == nil && exprSourceName(array.Elt) == "byte" {
				found = true
				return false
			}
			return true
		})
		return found
	}
	return false
}

func assertSingleTypedParameter(t *testing.T, rel string, name string, want string) {
	t.Helper()
	file := mustParseAdmissionSource(t, rel)
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name.Name != name {
			continue
		}
		if fn.Type.Params == nil || len(fn.Type.Params.List) != 1 || exprSourceName(fn.Type.Params.List[0].Type) != want {
			t.Fatalf("%s must accept only %s", name, want)
		}
		return
	}
	t.Fatalf("%s not found in %s", name, rel)
}

func TestWorkstreamCPrepareStaysBoundedAndAvoidsDescriptorGrammar(t *testing.T) {
	fixture := newPreparedArtifactFixture(t)
	service, stagingRoot, resultsRoot := newWorkstreamCTestService(t, fixture)
	request := fixture.prepareRequest()
	policyPayload := buildAdmissionPolicyStaticScriptArchive(t, map[string][]byte{
		staticScriptEntrypointName: []byte(benignPolicyFixtureText()),
	})

	arsCalls := map[string]int{}
	service.arsClient = newArtifactRegistryTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		arsCalls[r.URL.Path]++
		switch r.URL.Path {
		case "/v1/artifacts/" + fixture.discovery.Artifact.ArtifactDigest + "/discovery":
			writeJSONResponse(t, w, http.StatusOK, fixture.discovery)
		case "/v1/blobs/" + fixture.discovery.Evidence.Digest + ":json":
			writeJSONResponse(t, w, http.StatusOK, fixture.evidence)
		case "/v1/blobs/" + testWorkloadZoneVaultConfigDigest + ":json":
			_, _ = w.Write([]byte(validWorkloadZoneVaultConfigBlob))
		case "/v1/blobs/" + fixture.discovery.Payload.Digest + ":bytes":
			_, _ = w.Write(policyPayload)
		default:
			t.Fatalf("prepare reached unexpected ARS path %q", r.URL.Path)
		}
	}))
	service.nomadClient = newTestNomadClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("prepare must not call nomad, got %s %q", r.Method, r.URL.Path)
	}))

	result, err := service.Prepare(context.Background(), request)
	if err != nil {
		t.Fatalf("prepare: %+v", err)
	}
	if !result.Success {
		t.Fatalf("expected successful bounded prepare result, got %+v", result)
	}
	assertJSONFieldsExact(t, result, "success")

	assertDirectoryEmpty(t, stagingRoot)
	assertDirectoryEmpty(t, resultsRoot)
	assertExactCallCount(t, arsCalls, "/v1/artifacts/"+fixture.discovery.Artifact.ArtifactDigest+"/discovery", 1)
	assertExactCallCount(t, arsCalls, "/v1/blobs/"+fixture.discovery.Evidence.Digest+":json", 1)
	assertExactCallCount(t, arsCalls, "/v1/blobs/"+testWorkloadZoneVaultConfigDigest+":json", 1)
	assertExactCallCount(t, arsCalls, "/v1/blobs/"+fixture.discovery.Payload.Digest+":bytes", 1)
	if len(arsCalls) != 4 {
		t.Fatalf("expected prepare to use discovery, evidence, runtime-config, and bounded policy payload reads, got %v", arsCalls)
	}

	payload := mustMarshalWorkstreamCTestJSON(t, result)
	assertTextOmitsAll(t, payload,
		`"run_id"`,
		`"status"`,
		`"lifecycle_projection"`,
		`"authority_handoff"`,
		`"request_id"`,
		`"decision_id"`,
		`"audit"`,
		`"allowed"`,
		`"policy_approval"`,
		`"provider_run_id"`,
		`"cp_workflow_id"`,
		`"scheduler_handoff"`,
		`"retained_result_bundle"`,
		`"lifecycle_store"`,
		`"runtime_auth_plan"`,
		`"artifact_digest"`,
		`"descriptor"`,
		`"manifest"`,
	)
}

func TestWorkstreamCAdmissionConsumesDiscoveryEvidencePackageIdentityAndRuntimeClaims(t *testing.T) {
	fixture := newPreparedArtifactFixture(t)
	service := fixture.service()
	request := fixture.prepareRequest()
	request.Invocation.Env = map[string]string{
		"C1_ALLOWED_ENV": "true",
	}

	evidence := signedWorkstreamAEvidence(t, fixture, func(record *evidencev1.ArtifactEvidence) {
		record.Claims.Admission.Execution.Runtime.EnvironmentVariables = []string{"C1_ALLOWED_ENV"}
		record.Claims.Admission.Execution.Runtime.RequiredCapabilities = []string{"c1-special-runtime"}
		record.Claims.Admission.Execution.Workload.TargetPlatform = "docker"
		record.Claims.Admission.Execution.Access.NetworkAccess = false
	})

	artifact, err := service.prepareArtifactFromDiscovery(request, fixture.trustModel, discoveredArtifactWithEvidence(t, fixture.discovery, evidence))
	if err != nil {
		t.Fatalf("expected discovery, signed evidence, package identity, and runtime claims to prepare, got %+v", err)
	}
	if artifact.payloadDigest != evidence.Claims.Package.Identity.PayloadDigest {
		t.Fatalf("expected payload digest from claims.package.identity, got %q", artifact.payloadDigest)
	}
	if artifact.manifest.ArtifactDigest != evidence.Claims.Package.Identity.ArtifactDigest ||
		artifact.manifest.ArtifactType != evidence.Claims.Package.Identity.ArtifactType ||
		artifact.manifest.IntentDigest != evidence.Claims.Package.Identity.IntentDigest {
		t.Fatal("expected manifest projection from claims.package.identity")
	}
	if !reflect.DeepEqual(artifact.manifest.RuntimeInterface.EnvironmentVariables, []string{"C1_ALLOWED_ENV"}) {
		t.Fatal("expected runtime env allowlist from signed execution claims")
	}
	if !reflect.DeepEqual(artifact.manifest.RuntimeInterface.RequiredCapabilities, []string{"c1-special-runtime"}) {
		t.Fatal("expected required capabilities from signed execution claims")
	}
	if artifact.targetPlatform != "docker" || artifact.networkAccess {
		t.Fatalf("expected narrow workload/access claims from signed evidence, got target_platform=%q network_access=%t", artifact.targetPlatform, artifact.networkAccess)
	}

	tampered := evidence
	tampered.Claims.Admission.Execution.Runtime.EnvironmentVariables = append(tampered.Claims.Admission.Execution.Runtime.EnvironmentVariables, "UNSIGNED_AFTER_SEAL")
	_, err = service.prepareArtifactFromDiscovery(request, fixture.trustModel, discoveredArtifactWithEvidence(t, fixture.discovery, tampered))
	if err == nil || err.Code != codeArtifactEvidenceInvalid || !strings.Contains(err.Message, "signature verification failed") {
		t.Fatalf("expected signed evidence envelope/seal verification to reject tampered runtime claims, got %+v", err)
	}
}

func TestWorkstreamCAdmissionKeepsPayloadDigestAndPackageIdentityMismatchDistinct(t *testing.T) {
	fixture := newPreparedArtifactFixture(t)
	service := fixture.service()
	request := fixture.prepareRequest()

	payloadDigestUsedAsArtifactID := request
	payloadDigestUsedAsArtifactID.Invocation.ArtifactDigest = fixture.evidence.Claims.Package.Identity.PayloadDigest
	_, err := service.prepareArtifactFromDiscovery(payloadDigestUsedAsArtifactID, fixture.trustModel, discoveredArtifact{
		discovery: fixture.discovery,
		evidence:  fixture.evidence,
	})
	if err == nil || err.Code != codeInvalidRequest || !strings.Contains(err.Message, "artifact digest mismatch between request and artifact discovery") {
		t.Fatalf("expected artifact/package identity request mismatch to remain invalid_request, got %+v", err)
	}

	evidencePackageIdentityMismatch := fixture.evidence
	evidencePackageIdentityMismatch.Claims.Package.Identity.ArtifactDigest = labeledDigest("ee")
	_, err = service.prepareArtifactFromDiscovery(request, fixture.trustModel, discoveredArtifact{
		discovery: fixture.discovery,
		evidence:  evidencePackageIdentityMismatch,
	})
	if err == nil || err.Code != codeInvalidRequest || !strings.Contains(err.Message, "artifact digest mismatch between request and artifact evidence") {
		t.Fatalf("expected artifact/package identity evidence mismatch to remain invalid_request, got %+v", err)
	}

	payloadReferenceMismatch := fixture.discovery
	payloadReferenceMismatch.Payload.Digest = fixture.evidence.Claims.Package.Identity.ArtifactDigest
	_, err = service.prepareArtifactFromDiscovery(request, fixture.trustModel, discoveredArtifact{
		discovery: payloadReferenceMismatch,
		evidence:  fixture.evidence,
	})
	if err == nil || err.Code != codeArtifactEvidenceInvalid || !strings.Contains(err.Message, "payload reference does not match artifact evidence") {
		t.Fatalf("expected payload digest reference mismatch to remain artifact_evidence_invalid, got %+v", err)
	}
}

func TestWorkstreamCPrepareRejectsUnsupportedRuntimeProfileWithoutRunState(t *testing.T) {
	fixture := newPreparedArtifactFixture(t)
	service, stagingRoot, resultsRoot := newWorkstreamCTestService(t, fixture)
	request := fixture.prepareRequest()
	request.Invocation.Annotations = map[string]string{
		runtimeProfileAnnotationKey: runtimeProfileControlPlaneNormalShell,
	}
	policyPayload := buildAdmissionPolicyStaticScriptArchive(t, map[string][]byte{
		staticScriptEntrypointName: []byte(benignPolicyFixtureText()),
	})

	arsCalls := map[string]int{}
	service.arsClient = newArtifactRegistryTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		arsCalls[r.URL.Path]++
		switch r.URL.Path {
		case "/v1/artifacts/" + fixture.discovery.Artifact.ArtifactDigest + "/discovery":
			writeJSONResponse(t, w, http.StatusOK, fixture.discovery)
		case "/v1/blobs/" + fixture.discovery.Evidence.Digest + ":json":
			writeJSONResponse(t, w, http.StatusOK, fixture.evidence)
		case "/v1/blobs/" + testWorkloadZoneVaultConfigDigest + ":json":
			_, _ = w.Write([]byte(validWorkloadZoneVaultConfigBlob))
		case "/v1/blobs/" + fixture.discovery.Payload.Digest + ":bytes":
			_, _ = w.Write(policyPayload)
		default:
			t.Fatalf("prepare reached unexpected ARS path %q", r.URL.Path)
		}
	}))
	service.nomadClient = newTestNomadClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("prepare must not call nomad, got %s %q", r.Method, r.URL.Path)
	}))

	_, err := service.Prepare(context.Background(), request)
	assertAdmissionError(t, err, http.StatusBadRequest, codeUnsupportedRuntimeProfile)
	assertDirectoryEmpty(t, stagingRoot)
	assertDirectoryEmpty(t, resultsRoot)
	if len(arsCalls) != 4 {
		t.Fatalf("expected runtime-profile failure to remain admission-bounded, got ARS calls %v", arsCalls)
	}
}

func TestWorkstreamCSubmitRejectsSyncModeBeforeAdmission(t *testing.T) {
	fixture := newPreparedArtifactFixture(t)
	service, stagingRoot, resultsRoot := newWorkstreamCTestService(t, fixture)
	request := fixture.prepareRequest()
	request.Mode = ExecutionModeSync

	arsCalled := false
	service.arsClient = newArtifactRegistryTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		arsCalled = true
		t.Fatalf("sync submit must not read ARS before rejection, got %s %q", r.Method, r.URL.Path)
	}))
	service.nomadClient = newTestNomadClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("sync submit must not call nomad, got %s %q", r.Method, r.URL.Path)
	}))

	_, err := service.Submit(context.Background(), request)
	assertAdmissionError(t, err, http.StatusBadRequest, codeUnsupportedExecutionMode)
	if arsCalled {
		t.Fatal("expected sync submit to reject before admission reads")
	}
	assertDirectoryEmpty(t, stagingRoot)
	assertDirectoryEmpty(t, resultsRoot)
}

func TestWorkstreamCSubmitDoesNotBypassAdmissionBeforePayloadOrNomad(t *testing.T) {
	fixture := newPreparedArtifactFixture(t)
	service, stagingRoot, resultsRoot := newWorkstreamCTestService(t, fixture)
	request := fixture.prepareRequest()
	request.Mode = ExecutionModeAsync
	request.Invocation.DerivationSpecDigest = labeledDigest("ff")

	arsCalls := map[string]int{}
	service.arsClient = newArtifactRegistryTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		arsCalls[r.URL.Path]++
		switch r.URL.Path {
		case "/v1/artifacts/" + fixture.discovery.Artifact.ArtifactDigest + "/discovery":
			writeJSONResponse(t, w, http.StatusOK, fixture.discovery)
		case "/v1/blobs/" + fixture.discovery.Evidence.Digest + ":json":
			writeJSONResponse(t, w, http.StatusOK, fixture.evidence)
		default:
			t.Fatalf("submit reached unexpected ARS path before admission failed: %q", r.URL.Path)
		}
	}))
	service.nomadClient = newTestNomadClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("submit must not call nomad when admission fails, got %s %q", r.Method, r.URL.Path)
	}))

	_, err := service.Submit(context.Background(), request)
	assertAdmissionError(t, err, http.StatusBadRequest, codeInvalidRequest)
	assertDirectoryEmpty(t, stagingRoot)
	assertDirectoryEmpty(t, resultsRoot)
	assertExactCallCount(t, arsCalls, "/v1/artifacts/"+fixture.discovery.Artifact.ArtifactDigest+"/discovery", 1)
	assertExactCallCount(t, arsCalls, "/v1/blobs/"+fixture.discovery.Evidence.Digest+":json", 1)
	if len(arsCalls) != 2 {
		t.Fatalf("expected submit admission failure to stop before runtime-config or payload reads, got %v", arsCalls)
	}
}

func TestWorkstreamCSubmitReceiptRemainsBoundedAndHidesSchedulerIdentifiers(t *testing.T) {
	fixture := newPreparedArtifactFixture(t)
	service, _, _ := newWorkstreamCTestService(t, fixture)
	request := fixture.prepareRequest()
	request.Mode = ExecutionModeAsync
	policyPayload := buildAdmissionPolicyStaticScriptArchive(t, map[string][]byte{
		staticScriptEntrypointName: []byte(benignPolicyFixtureText()),
	})

	arsCalls := map[string]int{}
	service.arsClient = newArtifactRegistryTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		arsCalls[r.URL.Path]++
		switch r.URL.Path {
		case "/v1/artifacts/" + fixture.discovery.Artifact.ArtifactDigest + "/discovery":
			writeJSONResponse(t, w, http.StatusOK, fixture.discovery)
		case "/v1/blobs/" + fixture.discovery.Evidence.Digest + ":json":
			writeJSONResponse(t, w, http.StatusOK, fixture.evidence)
		case "/v1/blobs/" + testWorkloadZoneVaultConfigDigest + ":json":
			_, _ = w.Write([]byte(validWorkloadZoneVaultConfigBlob))
		case "/v1/blobs/" + fixture.discovery.Payload.Digest + ":bytes":
			_, _ = w.Write(policyPayload)
		default:
			t.Fatalf("submit reached unexpected ARS path %q", r.URL.Path)
		}
	}))

	nomadCalls := 0
	var submittedNomadJob string
	service.nomadClient = newTestNomadClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nomadCalls++
		if r.Method != http.MethodPost || r.URL.Path != "/v1/jobs" {
			t.Fatalf("unexpected nomad request %s %q", r.Method, r.URL.Path)
		}
		body, readErr := io.ReadAll(r.Body)
		if readErr == nil {
			submittedNomadJob = string(body)
		}
		_, _ = w.Write([]byte(`{"EvalID":"eval-123"}`))
	}))

	result, err := service.Submit(context.Background(), request)
	if err != nil {
		t.Fatalf("submit: %+v", err)
	}
	if !result.Success || !result.Submitted || strings.TrimSpace(result.RunID) == "" {
		t.Fatalf("expected bounded submit receipt, got %+v", result)
	}
	if result.Status != executionLifecycleStatusSubmitted {
		t.Fatalf("expected submitted receipt status, got %+v", result)
	}
	if result.AuthorityHandoff == nil {
		t.Fatalf("expected authority_handoff in submit receipt")
	}
	if nomadCalls != 1 {
		t.Fatalf("expected exactly one nomad submission call, got %d", nomadCalls)
	}
	if !strings.Contains(submittedNomadJob, `"ID":"exec-`) || !strings.Contains(submittedNomadJob, `"Driver":"docker"`) {
		t.Fatal("expected submit to hand one Docker job through ES/Nomad")
	}
	assertTextOmitsAll(t, submittedNomadJob,
		`"review"`,
		`"checkpoint"`,
		`"finalization"`,
		`"intervention"`,
		`"approval"`,
		`"hold"`,
		`"resume"`,
		`"reject"`,
		`"temporal"`,
		`"Temporal"`,
		`"workflow"`,
		`"workflow_id"`,
		`"cp_workflow_id"`,
	)
	if len(arsCalls) != 4 {
		t.Fatalf("expected submit to use discovery, evidence, runtime-config, and payload reads only, got %v", arsCalls)
	}

	payload := mustMarshalWorkstreamCTestJSON(t, result)
	assertJSONFieldsExact(t, result, "success", "submitted", "run_id", "status", "authority_handoff")
	assertTextOmitsAll(t, payload,
		`"attempt"`,
		`"task_attempt"`,
		`"review"`,
		`"checkpoint"`,
		`"finalization"`,
		`"intervention"`,
		`"approval"`,
		`"hold"`,
		`"resume"`,
		`"reject"`,
		`"temporal"`,
		`"Temporal"`,
		`"workflow"`,
		`"workflow_id"`,
		`"cp_workflow_id"`,
		`"run_control"`,
		`"job_id"`,
		`"allocation_id"`,
		`"task_id"`,
		`"eval_id"`,
		`"nomad_job_id"`,
		`"nomad_allocation_id"`,
		`"scheduler_id"`,
		`"provider_run_id"`,
		`"lifecycle_store"`,
		`"lifecycle_store_key"`,
		`"write_guard"`,
		`"write_precondition"`,
		`"lifecycle_projection"`,
		`"request_id"`,
		`"decision_id"`,
		`"audit"`,
		`"allowed"`,
		`"policy_approval"`,
		`"runtime_auth_plan"`,
		"exec-"+result.RunID,
	)
}

func TestWorkstreamC2PublicSubmitAndLifecycleDTOsExcludeCPRunControlGrammar(t *testing.T) {
	fieldNames := collectJSONFieldNames(t,
		SubmitResult{},
		ExecutionStatusResult{},
		ExecutionCancelResult{},
		LifecycleProjection{},
		ExecutionOutcomeEvidence{},
		ExecutionAuthorityHandoff{},
		ExecutionAuthorityRuntimeProfile{},
		ExecutionAuthorityIdentityHandoff{},
		ExecutionAuthorityWorkloadVault{},
		ExecutionAuthorityRuntimeConfigRefs{},
		ExecutionAuthorityCodexCredential{},
		ExecutionAuthorityEvidence{},
	)

	for _, forbidden := range []string{
		"attempt",
		"task_attempt",
		"review",
		"checkpoint",
		"finalization",
		"intervention",
		"approval",
		"hold",
		"resume",
		"reject",
		"temporal",
		"workflow",
		"workflow_id",
		"cp_workflow_id",
		"run_control",
		"review_state",
		"checkpoint_state",
		"finalization_state",
		"intervention_state",
		"provider_run_id",
		"nomad_job_id",
		"job_id",
		"allocation_id",
		"scheduler_id",
		"lifecycle_store",
		"lifecycle_store_key",
		"write_guard",
		"write_precondition",
		"retained_result_id",
	} {
		if _, ok := fieldNames[forbidden]; ok {
			t.Fatalf("C2 submit/lifecycle public DTOs must not expose CP run-control or scheduler-authority field %q", forbidden)
		}
	}
}

func TestWorkstreamC3PublicResultAuthorityAndOutcomeDTOsExcludeRunControlAndLiveAuthorityFields(t *testing.T) {
	fieldNames := collectJSONFieldNames(t,
		SubmitResult{},
		ExecutionStatusResult{},
		ExecutionCancelResult{},
		LifecycleProjection{},
		ExecutionOutcomeEvidence{},
		ExecutionAuthorityHandoff{},
		ExecutionAuthorityRuntimeProfile{},
		ExecutionAuthorityIdentityHandoff{},
		ExecutionAuthorityWorkloadVault{},
		ExecutionAuthorityRuntimeConfigRefs{},
		ExecutionAuthorityRuntimeConfigRef{},
		ExecutionAuthorityCodexCredential{},
		ExecutionAuthorityEvidence{},
	)

	for _, forbidden := range []string{
		"attempt",
		"task_attempt",
		"review",
		"checkpoint",
		"finalization",
		"intervention",
		"approval",
		"hold",
		"resume",
		"reject",
		"temporal",
		"workflow",
		"workflow_id",
		"cp_workflow_id",
		"run_control",
		"review_state",
		"checkpoint_state",
		"finalization_state",
		"intervention_state",
		"retained_result_ref",
		"retained_result_reference",
		"retained_result_id",
		"retained_result_manifest",
		"retained_result_archive",
		"retained_result_path",
		"materialized_workspace",
		"workspace_archive",
		"operator_authorization",
		"scheduler_truth",
		"scheduler_id",
		"nomad_job_id",
		"job_id",
		"allocation_id",
		"task_id",
		"token",
		"lease",
		"credential",
		"secret",
		"api_key",
		"vault_token",
		"codex_credential",
		"credential_material",
		"credential_value",
		"secret_material",
		"secret_value",
	} {
		if _, ok := fieldNames[forbidden]; ok {
			t.Fatalf("C3 public result/authority/outcome DTOs must not expose run-control or live-authority field %q", forbidden)
		}
	}

	for _, compatibilityField := range []string{
		"codex_credential_location",
		"credential_source",
		"vault_secret_path",
		"vault_secret_field",
	} {
		if _, ok := fieldNames[compatibilityField]; !ok {
			t.Fatalf("expected current control-plane normal-shell credential-location compatibility field %q to remain present", compatibilityField)
		}
	}
}

func TestWorkstreamC4RuntimeIdentityVaultPublicDTOsExcludeCredentialLeaseAndRawSPIREFields(t *testing.T) {
	fieldNames := collectJSONFieldNames(t,
		SubmitResult{},
		ExecutionStatusResult{},
		ExecutionCancelResult{},
		LifecycleProjection{},
		ExecutionOutcomeEvidence{},
		ExecutionAuthorityHandoff{},
		ExecutionAuthorityRuntimeProfile{},
		ExecutionAuthorityIdentityHandoff{},
		ExecutionAuthorityWorkloadVault{},
		ExecutionAuthorityRuntimeConfigRefs{},
		ExecutionAuthorityRuntimeConfigRef{},
		ExecutionAuthorityCodexCredential{},
		ExecutionAuthorityEvidence{},
		ProducerContractDeclaration{},
		GovernedExecutionProducerContractDeclaration{},
		ProducerRuntimeProfileDeclaration{},
		ProducerOutcomeEvidenceDeclaration{},
		ProducerOutcomeEvidenceSurfaceDeclaration{},
	)

	for _, forbidden := range workstreamC4ForbiddenCredentialFieldNames() {
		if _, ok := fieldNames[forbidden]; ok {
			t.Fatalf("C4 public DTOs must not expose runtime credential, Vault lease, or raw SPIRE field %q", forbidden)
		}
	}

	for _, compatibilityField := range []string{
		"endpoint_env",
		"endpoint_uri",
		"jwt_svid_target",
		"workload_vault",
		"runtime_config_refs",
		"codex_credential_location",
		"vault_secret_path",
		"vault_secret_field",
	} {
		if _, ok := fieldNames[compatibilityField]; !ok {
			t.Fatalf("expected non-secret C4 compatibility metadata field %q to remain present", compatibilityField)
		}
	}
}

func TestWorkstreamC4AuthorityHandoffCarriesOnlyNonSecretRuntimeIdentityVaultMetadata(t *testing.T) {
	handoff := buildResolvedExecutionAuthorityHandoff(newExecutionAuthorityHandoffProjection(
		executionRuntimeProfile{
			name: runtimeProfileControlPlaneNormalShell,
			env: map[string]string{
				codexCLIPathEnvKey:                    "/usr/local/bin/codex",
				codexCredentialSourceEnvKey:           codexCredentialSourceWorkloadVault,
				codexCredentialVaultSecretPathEnvKey:  "proof-secrets/data/codex-runtime-profile",
				codexCredentialVaultSecretFieldEnvKey: "runtime_profile_key_label",
			},
		},
		runtimeIdentityHandoff{
			endpointEnvKey: runtimeIdentityEndpointEnvKey,
			endpointURI:    "unix:///run/es-runtime-identity/run-0123456789abcdef/endpoint",
		},
		esconfig.ResolvedWorkloadVaultAuthPlan{
			Mode:        esconfig.WorkloadVaultAuthModeVaultIdentityJWT,
			Address:     "https://vault.internal:8200",
			AuthMount:   "jwt",
			AuthRole:    "service_execution",
			JWTAudience: "vault",
		},
		testWorkloadZoneVaultConfigDigest,
		stagedWorkloadTrustMaterial{
			vaultCACert:       true,
			workloadTLSBundle: true,
		},
	))

	if handoff.IdentityHandoff.EndpointEnv != runtimeIdentityEndpointEnvKey {
		t.Fatalf("expected workload-visible identity endpoint env, got %+v", handoff.IdentityHandoff)
	}
	if strings.Contains(handoff.IdentityHandoff.EndpointURI, "spire") || strings.Contains(handoff.IdentityHandoff.EndpointURI, "/internal/") {
		t.Fatalf("authority_handoff endpoint URI must not expose raw SPIRE internals, got %q", handoff.IdentityHandoff.EndpointURI)
	}
	if handoff.WorkloadVault.AuthMode != string(esconfig.WorkloadVaultAuthModeVaultIdentityJWT) ||
		handoff.WorkloadVault.Address != "https://vault.internal:8200" ||
		handoff.WorkloadVault.AuthMount != "jwt" ||
		handoff.WorkloadVault.AuthRole != "service_execution" ||
		handoff.WorkloadVault.JWTAudience != "vault" ||
		handoff.RuntimeConfigRefs.WorkloadZoneVaultConfig.Digest != testWorkloadZoneVaultConfigDigest {
		t.Fatalf("expected workload-zone Vault handoff metadata only, got %+v", handoff)
	}

	payload := mustMarshalWorkstreamCTestJSON(t, handoff)
	assertTextOmitsAll(t, payload, workstreamC4ForbiddenCredentialJSONKeys()...)
	assertTextOmitsAll(t, payload,
		"/run/spire/sockets/agent.sock",
		"/run/spire/server/private/api.sock",
		"/run/es-runtime-identity/run-0123456789abcdef/internal/spire-agent.sock",
		`"raw_spire_socket_path":`,
	)
}

func TestWorkstreamC4AuthorityHandoffRecoveryIgnoresCredentialLikeSubmittedEnv(t *testing.T) {
	env := map[string]string{
		runtimeIdentityEndpointEnvKey:      "unix:///run/es-runtime-identity/run-0123456789abcdef/endpoint",
		"VAULT_ADDR":                       "https://vault.internal:8200",
		"EXEC_WORKLOAD_VAULT_AUTH_MODE":    string(esconfig.WorkloadVaultAuthModeVaultIdentityJWT),
		"EXEC_WORKLOAD_VAULT_AUTH_MOUNT":   "jwt",
		"EXEC_WORKLOAD_VAULT_AUTH_ROLE":    "service_execution",
		"EXEC_WORKLOAD_VAULT_JWT_AUDIENCE": "vault",
		"VAULT_TOKEN":                      "blocked-test-value",
		"CLIENT_TOKEN":                     "blocked-test-value",
		"ROOT_TOKEN":                       "blocked-test-value",
		"UNSEAL_KEY":                       "blocked-test-value",
		"JWT_SVID":                         "blocked-test-value",
		"X509_SVID":                        "blocked-test-value",
		"PRIVATE_KEY":                      "blocked-test-value",
		"API_KEY":                          "blocked-test-value",
		"PROOF_SECRET":                     "blocked-test-value",
		"SECRET_PAYLOAD":                   "blocked-test-value",
		"LEASE_ID":                         "blocked-test-value",
		"LEASE_DURATION":                   "blocked-test-value",
		"SPIRE_WORKLOAD_API_SOCKET":        "/run/spire/sockets/agent.sock",
	}

	handoff, ok := executionAuthorityHandoffFromSubmittedRuntimeSpec(
		runtimeProfileDefaultStaticScript,
		testWorkloadZoneVaultConfigDigest,
		env,
	)
	if !ok {
		t.Fatal("expected authority handoff recovery from submitted non-secret runtime metadata")
	}
	payload := mustMarshalWorkstreamCTestJSON(t, handoff)
	assertTextOmitsAll(t, payload, workstreamC4ForbiddenCredentialJSONKeys()...)
	assertTextOmitsAll(t, payload,
		"blocked-test-value",
		"/run/spire/sockets/agent.sock",
		`"spire_workload_api_socket":`,
	)
}

func TestWorkstreamCLifecycleProjectionAndCancelReceiptsHideNomadIdentifiers(t *testing.T) {
	service := Service{
		cfg: minimalLifecycleConfig(t),
		nomadClient: newTestNomadClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch {
			case r.Method == http.MethodGet && r.URL.Path == "/v1/job/exec-run-0123456789abcdef":
				_, _ = w.Write([]byte(`{"ID":"exec-run-0123456789abcdef","Status":"running","ModifyIndex":10,"Meta":{"execution_substrate.authority_handoff.schema":"v1","execution_substrate.authority_handoff.runtime_profile":"static-script/default","execution_substrate.authority_handoff.workload_zone_vault_config_digest":"` + testWorkloadZoneVaultConfigDigest + `"},"TaskGroups":[{"Tasks":[{"Name":"task","Env":{"EXEC_WORKLOAD_IDENTITY_ENDPOINT":"unix:///run/es-runtime-identity/run-0123456789abcdef/endpoint","VAULT_ADDR":"https://vault.internal:8200","EXEC_WORKLOAD_VAULT_AUTH_MODE":"vault_identity_jwt","EXEC_WORKLOAD_VAULT_AUTH_MOUNT":"jwt","EXEC_WORKLOAD_VAULT_AUTH_ROLE":"execution","EXEC_WORKLOAD_VAULT_JWT_AUDIENCE":"vault"}}]}]}`))
			case r.Method == http.MethodGet && r.URL.Path == "/v1/job/exec-run-0123456789abcdef/allocations":
				_, _ = w.Write([]byte(`[{"ID":"alloc-new","ModifyIndex":20}]`))
			case r.Method == http.MethodGet && r.URL.Path == "/v1/allocation/alloc-new":
				_, _ = w.Write([]byte(`{"ID":"alloc-new","ClientStatus":"complete","ModifyIndex":25,"TaskStates":{"task":{"State":"dead","Events":[{"Type":"Terminated","ExitCode":7}]}}}`))
			case r.Method == http.MethodDelete && r.URL.Path == "/v1/job/exec-run-0123456789abcdef":
				_, _ = w.Write([]byte(`{"EvalID":"eval-1"}`))
			default:
				t.Fatalf("unexpected nomad request %s %q", r.Method, r.URL.Path)
			}
		})),
	}

	statusResult, err := service.Status(context.Background(), "run-0123456789abcdef")
	if err != nil {
		t.Fatalf("status: %+v", err)
	}
	if statusResult.AuthorityHandoff == nil {
		t.Fatalf("expected bounded authority_handoff recovery on status")
	}
	assertOpaqueLifecycleProjectionRevision(t, statusResult.LifecycleProjection.Revision)
	if statusResult.OutcomeEvidence.LifecycleProjection == nil || statusResult.OutcomeEvidence.LifecycleProjection.Revision != statusResult.LifecycleProjection.Revision {
		t.Fatalf("expected status outcome evidence to repeat the opaque lifecycle projection, got %+v", statusResult.OutcomeEvidence)
	}
	statusPayload := mustMarshalWorkstreamCTestJSON(t, statusResult)
	assertTextOmitsAll(t, statusPayload,
		`"job_id"`,
		`"allocation_id"`,
		`"task_id"`,
		`"request_id"`,
		`"decision_id"`,
		`"audit"`,
		`"allowed"`,
		`"policy_approval"`,
		`"runtime_auth_plan"`,
		"exec-run-0123456789abcdef",
		"alloc-new",
	)

	cancelResult, err := service.Cancel(context.Background(), "run-0123456789abcdef")
	if err != nil {
		t.Fatalf("cancel: %+v", err)
	}
	if cancelResult.OutcomeEvidence.ProviderTerminalObserved == nil || *cancelResult.OutcomeEvidence.ProviderTerminalObserved {
		t.Fatalf("expected bounded cancel receipt without terminal truth claim, got %+v", cancelResult)
	}
	cancelPayload := mustMarshalWorkstreamCTestJSON(t, cancelResult)
	assertTextOmitsAll(t, cancelPayload,
		`"job_id"`,
		`"allocation_id"`,
		`"task_id"`,
		`"request_id"`,
		`"decision_id"`,
		`"audit"`,
		`"allowed"`,
		`"policy_approval"`,
		`"runtime_auth_plan"`,
		"exec-run-0123456789abcdef",
		"alloc-new",
	)
}

func TestWorkstreamC2LifecycleProjectionRevisionIsOpaqueNomadReadCoordinationOnly(t *testing.T) {
	service := Service{
		cfg: minimalLifecycleConfig(t),
		nomadClient: newTestNomadClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch {
			case r.Method == http.MethodGet && r.URL.Path == "/v1/job/exec-run-0123456789abcdef":
				_, _ = w.Write([]byte(`{"ID":"exec-run-0123456789abcdef","Status":"running","ModifyIndex":42}`))
			case r.Method == http.MethodGet && r.URL.Path == "/v1/job/exec-run-0123456789abcdef/allocations":
				_, _ = w.Write([]byte(`[{"ID":"alloc-c2-latest","ModifyIndex":314}]`))
			case r.Method == http.MethodGet && r.URL.Path == "/v1/allocation/alloc-c2-latest":
				_, _ = w.Write([]byte(`{"ID":"alloc-c2-latest","ClientStatus":"running","ModifyIndex":2718,"TaskStates":{"task":{"State":"running"}}}`))
			default:
				t.Fatalf("unexpected nomad request %s %q", r.Method, r.URL.Path)
			}
		})),
	}

	result, err := service.Status(context.Background(), "run-0123456789abcdef")
	if err != nil {
		t.Fatalf("status: %+v", err)
	}
	if result.LifecycleProjection.Source != lifecycleProjectionSourceNomad {
		t.Fatalf("expected lifecycle projection source=nomad, got %+v", result.LifecycleProjection)
	}
	assertOpaqueLifecycleProjectionRevision(t, result.LifecycleProjection.Revision)
	for _, forbiddenRevision := range []string{
		"42",
		"314",
		"2718",
	} {
		if result.LifecycleProjection.Revision == forbiddenRevision {
			t.Fatalf("lifecycle projection revision must not be raw Nomad observation value %q", forbiddenRevision)
		}
	}
	for _, forbiddenRevisionFragment := range []string{
		"exec-run-0123456789abcdef",
		"alloc-c2-latest",
		result.RunID,
		result.RunID + "/result.tar.gz",
	} {
		if result.LifecycleProjection.Revision == forbiddenRevisionFragment || strings.Contains(result.LifecycleProjection.Revision, forbiddenRevisionFragment) {
			t.Fatalf("lifecycle projection revision must not be scheduler, store, or retained-result identity %q; got %q", forbiddenRevisionFragment, result.LifecycleProjection.Revision)
		}
	}
	if result.OutcomeEvidence.LifecycleProjection == nil || *result.OutcomeEvidence.LifecycleProjection != result.LifecycleProjection {
		t.Fatalf("expected outcome evidence to repeat opaque projection token, got %+v", result.OutcomeEvidence)
	}

	payload := mustMarshalWorkstreamCTestJSON(t, result)
	assertTextOmitsAll(t, payload,
		`"nomad_job_id"`,
		`"job_id"`,
		`"allocation_id"`,
		`"task_id"`,
		`"scheduler_id"`,
		`"lifecycle_store"`,
		`"lifecycle_store_key"`,
		`"write_guard"`,
		`"write_precondition"`,
		`"workflow_revision"`,
		`"cp_workflow_revision"`,
		`"retained_result_id"`,
		`"retained_result_bundle"`,
		"exec-run-0123456789abcdef",
		"alloc-c2-latest",
	)
}

func TestWorkstreamCAuthorityHandoffAndOutcomeEvidenceRemainBoundedNonAuthority(t *testing.T) {
	handoff := buildResolvedExecutionAuthorityHandoff(newExecutionAuthorityHandoffProjection(
		executionRuntimeProfile{name: runtimeProfileDefaultStaticScript},
		runtimeIdentityHandoff{
			endpointEnvKey: runtimeIdentityEndpointEnvKey,
			endpointURI:    "unix:///run/es-runtime-identity/run-0123456789abcdef/endpoint",
		},
		esconfig.ResolvedWorkloadVaultAuthPlan{
			Mode:        esconfig.WorkloadVaultAuthModeVaultIdentityJWT,
			Address:     "https://vault.internal:8200",
			AuthMount:   "jwt",
			AuthRole:    "execution",
			JWTAudience: "vault",
		},
		testWorkloadZoneVaultConfigDigest,
		stagedWorkloadTrustMaterial{},
	))
	if handoff.Evidence.Source != executionAuthorityEvidenceSourceSubmittedRuntimeSpec ||
		handoff.Evidence.RuntimeProfile != executionAuthorityEvidenceRuntimeProfile ||
		handoff.Evidence.IdentityHandoff != executionAuthorityEvidenceIdentityHandoff ||
		handoff.Evidence.WorkloadVault != executionAuthorityEvidenceWorkloadVault {
		t.Fatalf("expected bounded handoff evidence labels, got %+v", handoff.Evidence)
	}

	projection := LifecycleProjection{Source: lifecycleProjectionSourceNomad, Revision: "opaque-c1-read-token"}
	payload := mustMarshalWorkstreamCTestJSON(t, struct {
		AuthorityHandoff ExecutionAuthorityHandoff  `json:"authority_handoff"`
		OutcomeEvidence  []ExecutionOutcomeEvidence `json:"outcome_evidence"`
	}{
		AuthorityHandoff: handoff,
		OutcomeEvidence: []ExecutionOutcomeEvidence{
			statusOutcomeEvidence(outcomeObservationNomadTaskStateProjection, projection, true),
			logsOutcomeEvidence(false),
			cancelOutcomeEvidence(),
			retainedResultOutcomeEvidence(),
		},
	})

	assertTextOmitsAll(t, payload,
		`"vault_token"`,
		`"codex_token"`,
		`"jwt_svid_token"`,
		`"lease"`,
		`"lease_id"`,
		`"lease_duration"`,
		`"token_expiry"`,
		`"credential_material"`,
		`"credential_value"`,
		`"approval"`,
		`"policy_approval"`,
		`"intervention"`,
		`"hold"`,
		`"resume"`,
		`"reject"`,
		`"temporal"`,
		`"Temporal"`,
		`"run_control"`,
		`"workflow"`,
		`"workflow_id"`,
		`"checkpoint"`,
		`"finalization"`,
		`"job_id"`,
		`"allocation_id"`,
		`"task_id"`,
		`"eval_id"`,
		`"provider_run_id"`,
		`"scheduler_id"`,
		`"private_key_pem"`,
		`"pem_body"`,
		`"raw_spire_socket"`,
	)
}

func TestWorkstreamC3DefaultAuthorityHandoffExcludesLiveCredentialAndRetainedResultAuthority(t *testing.T) {
	handoff := buildResolvedExecutionAuthorityHandoff(newExecutionAuthorityHandoffProjection(
		executionRuntimeProfile{name: runtimeProfileDefaultStaticScript},
		runtimeIdentityHandoff{
			endpointEnvKey: runtimeIdentityEndpointEnvKey,
			endpointURI:    "unix:///run/es-runtime-identity/run-0123456789abcdef/endpoint",
		},
		esconfig.ResolvedWorkloadVaultAuthPlan{
			Mode:        esconfig.WorkloadVaultAuthModeVaultIdentityJWT,
			Address:     "https://vault.internal:8200",
			AuthMount:   "jwt",
			AuthRole:    "execution",
			JWTAudience: "vault",
		},
		testWorkloadZoneVaultConfigDigest,
		stagedWorkloadTrustMaterial{},
	))

	payload := mustMarshalWorkstreamCTestJSON(t, handoff)
	assertTextOmitsAll(t, payload,
		`"token"`,
		`"lease"`,
		`"approval"`,
		`"credential"`,
		`"secret"`,
		`"api_key"`,
		`"vault_token"`,
		`"codex_credential"`,
		`"scheduler_id"`,
		`"operator_authorization"`,
		`"workflow"`,
		`"workflow_id"`,
		`"checkpoint"`,
		`"finalization"`,
		`"retained_result_authority"`,
		`"retained_result_id"`,
		`"retained_result_path"`,
	)
}

func TestWorkstreamC3ControlPlaneNormalShellAuthorityHandoffOnlyCarriesCredentialLocationCompatibility(t *testing.T) {
	handoff := buildResolvedExecutionAuthorityHandoff(newExecutionAuthorityHandoffProjection(
		executionRuntimeProfile{
			name: runtimeProfileControlPlaneNormalShell,
			env: map[string]string{
				codexCLIPathEnvKey:                    "/usr/local/bin/codex",
				codexCredentialSourceEnvKey:           codexCredentialSourceWorkloadVault,
				codexCredentialVaultSecretPathEnvKey:  "proof-secrets/data/codex-runtime-profile",
				codexCredentialVaultSecretFieldEnvKey: "api_key",
			},
		},
		runtimeIdentityHandoff{
			endpointEnvKey: runtimeIdentityEndpointEnvKey,
			endpointURI:    "unix:///run/es-runtime-identity/run-0123456789abcdef/endpoint",
		},
		esconfig.ResolvedWorkloadVaultAuthPlan{
			Mode:        esconfig.WorkloadVaultAuthModeVaultIdentityJWT,
			Address:     "https://vault.internal:8200",
			AuthMount:   "jwt",
			AuthRole:    "execution",
			JWTAudience: "vault",
		},
		testWorkloadZoneVaultConfigDigest,
		stagedWorkloadTrustMaterial{},
	))
	if handoff.CodexCredentialLocation == nil ||
		handoff.CodexCredentialLocation.CredentialSource != codexCredentialSourceWorkloadVault ||
		handoff.CodexCredentialLocation.VaultSecretPath != "proof-secrets/data/codex-runtime-profile" ||
		handoff.CodexCredentialLocation.VaultSecretField != "api_key" {
		t.Fatalf("expected current non-secret credential-location compatibility metadata, got %+v", handoff.CodexCredentialLocation)
	}

	payload := mustMarshalWorkstreamCTestJSON(t, handoff)
	assertTextOmitsAll(t, payload,
		`"token"`,
		`"lease"`,
		`"approval"`,
		`"vault_token"`,
		`"codex_token"`,
		`"credential_material"`,
		`"credential_value"`,
		`"secret_material"`,
		`"secret_value"`,
		`"scheduler_id"`,
		`"operator_authorization"`,
		`"workflow"`,
		`"workflow_id"`,
		`"checkpoint"`,
		`"finalization"`,
		`"retained_result_authority"`,
		`"retained_result_id"`,
	)
}

func TestWorkstreamC3OutcomeEvidenceLabelsRemainBoundedCompatibilityVocabulary(t *testing.T) {
	projection := LifecycleProjection{Source: lifecycleProjectionSourceNomad, Revision: "opaque-c3-read-token"}

	tests := []struct {
		name     string
		evidence ExecutionOutcomeEvidence
		want     ExecutionOutcomeEvidence
	}{
		{
			name:     "status",
			evidence: statusOutcomeEvidence(outcomeObservationNomadTaskStateProjection, projection, true),
			want: ExecutionOutcomeEvidence{
				Source:      outcomeEvidenceSourceNomad,
				Observation: outcomeObservationNomadTaskStateProjection,
				LifecycleProjection: &LifecycleProjection{
					Source:   lifecycleProjectionSourceNomad,
					Revision: "opaque-c3-read-token",
				},
				ProviderTerminalObserved: boolPointer(true),
			},
		},
		{
			name:     "logs",
			evidence: logsOutcomeEvidence(false),
			want: ExecutionOutcomeEvidence{
				Source:                   outcomeEvidenceSourceNomad,
				Observation:              outcomeObservationNomadTaskStdout,
				AccessClass:              outcomeAccessClassPlaintextStdout,
				ProviderTerminalObserved: boolPointer(false),
			},
		},
		{
			name:     "cancel",
			evidence: cancelOutcomeEvidence(),
			want: ExecutionOutcomeEvidence{
				Source:                   outcomeEvidenceSourceNomad,
				Observation:              outcomeObservationNomadStopAccepted,
				ProviderTerminalObserved: boolPointer(false),
			},
		},
		{
			name:     "retained result",
			evidence: retainedResultOutcomeEvidence(),
			want: ExecutionOutcomeEvidence{
				Source:      outcomeEvidenceSourceRetainedResultStore,
				Observation: outcomeObservationRetainedResultBundle,
				AccessClass: outcomeAccessClassOpaqueResultBundle,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !reflect.DeepEqual(tt.evidence, tt.want) {
				t.Fatalf("outcome evidence label compatibility changed: got %+v want %+v", tt.evidence, tt.want)
			}
			payload := mustMarshalWorkstreamCTestJSON(t, tt.evidence)
			assertTextOmitsAll(t, payload,
				`"scheduler_id"`,
				`"workflow"`,
				`"checkpoint"`,
				`"finalization"`,
				`"approval"`,
				`"credential"`,
				`"token"`,
				`"retained_result_authority"`,
			)
		})
	}
}

func TestWorkstreamC5LifecycleCompatibilityDTOsAndEvidenceStayNonAuthority(t *testing.T) {
	fieldNames := collectJSONFieldNames(t,
		ExecutionStatusResult{},
		ExecutionCancelResult{},
		LifecycleProjection{},
		ExecutionOutcomeEvidence{},
		ExecutionAuthorityHandoff{},
		ExecutionAuthorityRuntimeProfile{},
		ExecutionAuthorityIdentityHandoff{},
		ExecutionAuthorityWorkloadVault{},
		ExecutionAuthorityRuntimeConfigRefs{},
		ExecutionAuthorityRuntimeConfigRef{},
		ExecutionAuthorityCodexCredential{},
		ExecutionAuthorityEvidence{},
	)

	for _, forbidden := range []string{
		"review",
		"checkpoint",
		"finalization",
		"intervention",
		"approval",
		"hold",
		"resume",
		"reject",
		"temporal",
		"workflow",
		"workflow_id",
		"cp_workflow_id",
		"operator_approval",
		"operator_authorization",
		"cp_run_control",
		"nomad_job_id",
		"job_id",
		"allocation_id",
		"task_id",
		"scheduler_id",
		"scheduler_authority",
		"lifecycle_store",
		"write_guard",
		"write_precondition",
		"retained_result_id",
		"vault_token",
		"client_token",
		"root_token",
		"unseal_key",
		"jwt_svid",
		"x509_svid",
		"private_key",
		"api_key",
		"proof_secret",
		"secret_payload",
		"lease_id",
		"lease_duration",
	} {
		if _, ok := fieldNames[forbidden]; ok {
			t.Fatalf("C5 status/cancel envelopes and evidence DTOs must not expose authority field %q", forbidden)
		}
	}

	for _, compatibilityField := range []string{
		"success",
		"run_id",
		"status",
		"lifecycle_projection",
		"source",
		"revision",
		"outcome_evidence",
		"provider_terminal_observed",
		"access_class",
		"authority_handoff",
		"runtime_profile",
		"workload_vault",
		"runtime_config_refs",
		"codex_credential_location",
	} {
		if _, ok := fieldNames[compatibilityField]; !ok {
			t.Fatalf("expected C5 compatibility field %q to remain present", compatibilityField)
		}
	}

	if runtimeProfileAnnotationKey != "execution_substrate.runtime_profile" {
		t.Fatalf("runtime profile annotation compatibility key changed to %q", runtimeProfileAnnotationKey)
	}
	if runtimeProfileControlPlaneNormalShell != "control-plane-normal-shell/v1" {
		t.Fatalf("control-plane normal-shell profile compatibility name changed to %q", runtimeProfileControlPlaneNormalShell)
	}

	projection := lifecycleProjectionFromNomad(42, 314)
	assertOpaqueLifecycleProjectionRevision(t, projection.Revision)
	if strings.Contains(projection.Revision, "42") ||
		strings.Contains(projection.Revision, "314") ||
		strings.Contains(projection.Revision, "exec-run-") ||
		strings.Contains(projection.Revision, "alloc-") {
		t.Fatalf("C5 lifecycle projection revision must stay opaque, got %q", projection.Revision)
	}

	evidenceBySurface := map[string]ExecutionOutcomeEvidence{
		"status": statusOutcomeEvidence(outcomeObservationNomadTaskStateProjection, projection, true),
		"logs":   logsOutcomeEvidence(false),
		"result": retainedResultOutcomeEvidence(),
		"cancel": cancelOutcomeEvidence(),
	}
	if evidenceBySurface["status"].Source != outcomeEvidenceSourceNomad ||
		evidenceBySurface["status"].Observation != outcomeObservationNomadTaskStateProjection ||
		evidenceBySurface["status"].LifecycleProjection == nil ||
		*evidenceBySurface["status"].LifecycleProjection != projection {
		t.Fatalf("unexpected C5 status outcome evidence %+v", evidenceBySurface["status"])
	}
	if evidenceBySurface["logs"].Source != outcomeEvidenceSourceNomad ||
		evidenceBySurface["logs"].Observation != outcomeObservationNomadTaskStdout ||
		evidenceBySurface["logs"].AccessClass != outcomeAccessClassPlaintextStdout {
		t.Fatalf("unexpected C5 logs outcome evidence %+v", evidenceBySurface["logs"])
	}
	if evidenceBySurface["result"].Source != outcomeEvidenceSourceRetainedResultStore ||
		evidenceBySurface["result"].Observation != outcomeObservationRetainedResultBundle ||
		evidenceBySurface["result"].AccessClass != outcomeAccessClassOpaqueResultBundle {
		t.Fatalf("unexpected C5 retained result outcome evidence %+v", evidenceBySurface["result"])
	}
	if evidenceBySurface["cancel"].Source != outcomeEvidenceSourceNomad ||
		evidenceBySurface["cancel"].Observation != outcomeObservationNomadStopAccepted ||
		evidenceBySurface["cancel"].ProviderTerminalObserved == nil ||
		*evidenceBySurface["cancel"].ProviderTerminalObserved {
		t.Fatalf("unexpected C5 cancel outcome evidence %+v", evidenceBySurface["cancel"])
	}

	payload := mustMarshalWorkstreamCTestJSON(t, evidenceBySurface)
	assertTextOmitsAll(t, payload,
		`"review":`,
		`"checkpoint":`,
		`"finalization":`,
		`"intervention":`,
		`"approval":`,
		`"hold":`,
		`"resume":`,
		`"reject":`,
		`"temporal":`,
		`"workflow":`,
		`"nomad_job_id":`,
		`"job_id":`,
		`"allocation_id":`,
		`"task_id":`,
		`"scheduler_id":`,
		`"vault_token":`,
		`"client_token":`,
		`"root_token":`,
		`"unseal_key":`,
		`"jwt_svid":`,
		`"x509_svid":`,
		`"private_key":`,
		`"api_key":`,
		`"proof_secret":`,
		`"secret_payload":`,
		`"lease_id":`,
		`"lease_duration":`,
	)
}

func TestWorkstreamCLifecycleProjectionAuthorityLabelsStayNomadReadModelOnly(t *testing.T) {
	fieldNames := collectJSONFieldNames(t,
		ExecutionStatusResult{},
		ExecutionCancelResult{},
		LifecycleProjection{},
		ExecutionOutcomeEvidence{},
		ExecutionLogsResult{},
		ExecutionResultBundle{},
	)

	for _, forbidden := range workstreamCLifecycleProjectionAuthorityForbiddenFields() {
		if _, ok := fieldNames[forbidden]; ok {
			t.Fatalf("lifecycle/status projection DTOs must not expose authority field %q", forbidden)
		}
	}

	projection := lifecycleProjectionFromNomad(101, 202, 303)
	if projection.Source != lifecycleProjectionSourceNomad {
		t.Fatalf("expected current documented projection source nomad, got %+v", projection)
	}
	assertOpaqueLifecycleProjectionRevision(t, projection.Revision)
	for _, forbidden := range []string{
		"101",
		"202",
		"303",
		"exec-run-0123456789abcdef",
		"alloc-authority",
		"workflow",
		"cp-workflow",
		"fresh",
		"result.tar.gz",
	} {
		if strings.Contains(projection.Revision, forbidden) {
			t.Fatalf("lifecycle projection revision must stay opaque and non-authoritative; found %q in %q", forbidden, projection.Revision)
		}
	}

	statusEvidence := statusOutcomeEvidence(outcomeObservationNomadTaskStateProjection, projection, true)
	if statusEvidence.Source != outcomeEvidenceSourceNomad ||
		statusEvidence.LifecycleProjection == nil ||
		*statusEvidence.LifecycleProjection != projection {
		t.Fatalf("status outcome evidence must repeat the same opaque Nomad projection token, got %+v", statusEvidence)
	}
	if logsOutcomeEvidence(false).Source != outcomeEvidenceSourceNomad ||
		cancelOutcomeEvidence().Source != outcomeEvidenceSourceNomad ||
		retainedResultOutcomeEvidence().Source != outcomeEvidenceSourceRetainedResultStore {
		t.Fatal("expected status/logs/cancel labels to stay Nomad-backed and result labels to stay retained-result-store backed")
	}

	payload := mustMarshalWorkstreamCTestJSON(t, struct {
		Status ExecutionStatusResult          `json:"status"`
		Logs   ExecutionOutcomeEvidence       `json:"logs"`
		Result ExecutionOutcomeEvidence       `json:"result"`
		Cancel ExecutionCancelResult          `json:"cancel"`
		Meta   map[string]LifecycleProjection `json:"meta"`
	}{
		Status: ExecutionStatusResult{
			Success:             true,
			RunID:               "run-0123456789abcdef",
			Status:              "terminal",
			LifecycleProjection: projection,
			OutcomeEvidence:     statusEvidence,
			Terminal:            true,
		},
		Logs:   logsOutcomeEvidence(false),
		Result: retainedResultOutcomeEvidence(),
		Cancel: ExecutionCancelResult{
			Success:         true,
			RunID:           "run-0123456789abcdef",
			Status:          "cancel_requested",
			OutcomeEvidence: cancelOutcomeEvidence(),
		},
		Meta: map[string]LifecycleProjection{"same_run_read_model": projection},
	})
	assertTextOmitsAll(t, payload, workstreamCLifecycleProjectionAuthorityForbiddenJSONTerms()...)
	assertTextOmitsAll(t, payload,
		"exec-run-0123456789abcdef",
		"alloc-authority",
		"cp-workflow-version",
		"global_freshness",
		"support payload",
		"proof payload",
		"raw log payload",
	)
}

func TestWorkstreamC2ControlPlaneNormalShellCompatibilitySurfaceUnchanged(t *testing.T) {
	if runtimeProfileAnnotationKey != "execution_substrate.runtime_profile" {
		t.Fatalf("runtime profile annotation compatibility key changed to %q", runtimeProfileAnnotationKey)
	}
	if runtimeProfileControlPlaneNormalShell != "control-plane-normal-shell/v1" {
		t.Fatalf("control-plane normal-shell profile compatibility name changed to %q", runtimeProfileControlPlaneNormalShell)
	}

	profile, err := resolveExecutionRuntimeProfile(controlPlaneNormalShellProfileExecutionConfig(), PrepareRequest{
		Invocation: ArtifactInvocation{
			Annotations: map[string]string{
				runtimeProfileAnnotationKey: runtimeProfileControlPlaneNormalShell,
			},
		},
	}, preparedArtifact{
		manifest: Manifest{
			ArtifactType: "static-script",
		},
		networkAccess: true,
	})
	if err != nil {
		t.Fatal("expected existing control-plane normal-shell profile to resolve")
	}
	if profile.name != runtimeProfileControlPlaneNormalShell ||
		profile.image != "execution-substrate/control-plane-normal-shell:test" ||
		profile.env[codexCLIPathEnvKey] != "/usr/local/bin/codex" ||
		profile.env[codexCredentialSourceEnvKey] != codexCredentialSourceWorkloadVault {
		t.Fatal("expected existing profile image and non-secret metadata compatibility")
	}
}

func TestWorkstreamCRuntimeSupportFixtureIsHermetic(t *testing.T) {
	fixture := newPreparedArtifactFixture(t)
	service, stagingRoot, resultsRoot := newWorkstreamCTestService(t, fixture)
	runtimeSupportPath := service.cfg.Execution.RuntimeSupportBinary

	if !filepath.IsAbs(runtimeSupportPath) {
		t.Fatalf("runtime-support fixture path is not absolute: %q", runtimeSupportPath)
	}
	for _, root := range []string{stagingRoot, resultsRoot} {
		relative, err := filepath.Rel(root, runtimeSupportPath)
		if err != nil {
			t.Fatalf("compare runtime-support fixture %q with root %q: %v", runtimeSupportPath, root, err)
		}
		if relative == "." || (relative != ".." && !strings.HasPrefix(relative, ".."+string(os.PathSeparator))) {
			t.Fatalf("runtime-support fixture %q must be separate from staging/results root %q", runtimeSupportPath, root)
		}
	}

	info, err := os.Lstat(runtimeSupportPath)
	if err != nil {
		t.Fatalf("lstat runtime-support fixture: %v", err)
	}
	if !info.Mode().IsRegular() {
		t.Fatalf("runtime-support fixture must be regular, got mode %v", info.Mode())
	}
	if info.Mode().Perm() != 0o700 {
		t.Fatalf("runtime-support fixture mode = %04o, want 0700", info.Mode().Perm())
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatalf("runtime-support fixture has unexpected stat type %T", info.Sys())
	}
	if stat.Nlink != 1 {
		t.Fatalf("runtime-support fixture link count = %d, want 1", stat.Nlink)
	}

	wantContent := []byte("execution-substrate workstream-c runtime-support fixture\n")
	const wantDigest = "sha256:e74859310b3470b3f735541e5163e9f309bded4bc697244049650ef6d962349a"
	captured, digest, err := captureRuntimeSupport(runtimeSupportPath)
	if err != nil {
		t.Fatalf("capture runtime-support fixture: %v", err)
	}
	if !bytes.Equal(captured, wantContent) {
		t.Fatalf("captured runtime-support fixture bytes = %q, want %q", captured, wantContent)
	}
	if digest != wantDigest {
		t.Fatalf("captured runtime-support fixture digest = %q, want %q", digest, wantDigest)
	}

	assertDirectoryEmpty(t, stagingRoot)
	assertDirectoryEmpty(t, resultsRoot)
}

func newWorkstreamCTestService(t *testing.T, fixture preparedArtifactFixture) (*Service, string, string) {
	t.Helper()

	stagingRoot := physicalTestTempDir(t)
	resultsRoot := physicalTestTempDir(t)
	runtimeSupportRoot := physicalTestTempDir(t)
	runtimeSupportPath := filepath.Join(runtimeSupportRoot, "es-runtime-support")
	runtimeSupport, err := os.OpenFile(runtimeSupportPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o700)
	if err != nil {
		t.Fatalf("create runtime-support fixture: %v", err)
	}
	if _, err := runtimeSupport.Write([]byte("execution-substrate workstream-c runtime-support fixture\n")); err != nil {
		_ = runtimeSupport.Close()
		t.Fatalf("write runtime-support fixture: %v", err)
	}
	if err := runtimeSupport.Chmod(0o700); err != nil {
		_ = runtimeSupport.Close()
		t.Fatalf("set runtime-support fixture mode: %v", err)
	}
	if err := runtimeSupport.Close(); err != nil {
		t.Fatalf("close runtime-support fixture: %v", err)
	}

	service := fixture.service()
	service.cfg = esconfig.Config{
		RuntimeConfig: esconfig.RuntimeConfigConfig{
			WorkloadZoneVaultConfigRef: runtimeconfigv1.WorkloadZoneVaultConfigRef{
				Digest: testWorkloadZoneVaultConfigDigest,
			},
		},
		WorkloadVaultAuth: esconfig.WorkloadVaultAuthConfig{
			DefaultMode: esconfig.WorkloadVaultAuthModeVaultIdentityJWT,
		},
		Nomad: esconfig.NomadConfig{
			BaseURL:        "http://127.0.0.1:4646",
			Datacenter:     "dc1",
			TimeoutSeconds: 1,
		},
		Execution: esconfig.ExecutionConfig{
			StagingRootDir:             stagingRoot,
			ResultsRootDir:             resultsRoot,
			BaseImage:                  "alpine:3.20",
			RuntimeSupportBinary:       runtimeSupportPath,
			SPIREWorkloadAPISocketPath: "/run/spire/sockets/agent.sock",
		},
	}
	service.workloadZoneVaultConfigRef = service.cfg.RuntimeConfig.WorkloadZoneVaultConfigRef
	service.trustModel = &fixture.trustModel

	return &service, stagingRoot, resultsRoot
}

func assertAdmissionError(t *testing.T, err *Error, status int, code string) {
	t.Helper()

	if err == nil {
		t.Fatalf("expected error status=%d code=%s", status, code)
	}
	if err.Status != status || err.Code != code {
		t.Fatalf("expected error status=%d code=%s, got %+v", status, code, err)
	}
}

func assertExactCallCount(t *testing.T, counts map[string]int, path string, want int) {
	t.Helper()

	if got := counts[path]; got != want {
		t.Fatalf("expected %s to be called %d time(s), got %d in %v", path, want, got, counts)
	}
}

func assertDirectoryEmpty(t *testing.T, dir string) {
	t.Helper()

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read directory %s: %v", dir, err)
	}
	if len(entries) != 0 {
		names := make([]string, 0, len(entries))
		for _, entry := range entries {
			names = append(names, entry.Name())
		}
		t.Fatalf("expected %s to remain empty, found %v", dir, names)
	}
}

func mustMarshalWorkstreamCTestJSON(t *testing.T, payload any) string {
	t.Helper()

	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	return string(data)
}

func assertJSONFieldsExact(t *testing.T, payload any, want ...string) {
	t.Helper()

	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		t.Fatalf("decode marshaled payload: %v", err)
	}
	if len(fields) != len(want) {
		t.Fatalf("expected JSON fields %v, got %s", want, string(data))
	}
	for _, field := range want {
		if _, ok := fields[field]; !ok {
			t.Fatalf("expected JSON field %q in %s", field, string(data))
		}
	}
}

func assertTextOmitsAll(t *testing.T, text string, forbidden ...string) {
	t.Helper()

	for _, item := range forbidden {
		if strings.Contains(text, item) {
			t.Fatalf("expected text to omit %q, got %s", item, text)
		}
	}
}

func workstreamC4ForbiddenCredentialFieldNames() []string {
	return []string{
		"vault_token",
		"client_token",
		"root_token",
		"unseal_key",
		"jwt_svid",
		"x509_svid",
		"private_key",
		"api_key",
		"proof_secret",
		"secret_payload",
		"lease_id",
		"lease_duration",
		"raw_spire_socket",
	}
}

func workstreamC4ForbiddenCredentialJSONKeys() []string {
	fields := workstreamC4ForbiddenCredentialFieldNames()
	keys := make([]string, 0, len(fields))
	for _, field := range fields {
		keys = append(keys, `"`+field+`":`)
	}
	return keys
}

func workstreamCLifecycleProjectionAuthorityForbiddenFields() []string {
	return []string{
		"nomad_job_id",
		"job_id",
		"allocation_id",
		"nomad_allocation_id",
		"task_id",
		"scheduler_id",
		"scheduler_revision",
		"scheduler_authority",
		"lifecycle_store",
		"lifecycle_store_key",
		"write_guard",
		"write_precondition",
		"cp_workflow_id",
		"cp_workflow_version",
		"workflow_version",
		"workflow_revision",
		"cp_workflow_revision",
		"global_freshness",
		"freshness_proof",
		"retained_result_id",
		"retained_result_path",
		"retained_bundle_internals",
		"raw_logs",
		"support_payload",
		"proof_payload",
		"env_values",
		"endpoint_secret",
		"pem_body",
		"raw_cert_body",
		"private_key",
		"vault_token",
		"jwt_svid",
		"x509_svid",
	}
}

func workstreamCLifecycleProjectionAuthorityForbiddenJSONTerms() []string {
	fields := workstreamCLifecycleProjectionAuthorityForbiddenFields()
	terms := make([]string, 0, len(fields))
	for _, field := range fields {
		terms = append(terms, `"`+field+`":`)
	}
	return terms
}
