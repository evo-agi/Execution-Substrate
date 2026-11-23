package admission

import (
	"bytes"
	"context"
	"crypto/sha256"
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
		{label: "submit resolver", method: true, receiver: "Service", name: "resolveExecutionForSubmit", want: map[string]int{"es/admission/submit.go:Service.Submit": 1, "es/admission/reliable_submit_replay_private.go:Service.composePrivateSyntheticReplay": 1, "es/admission/reliable_submit_operational_handoff.go:Service.composeOperationalOriginal": 1}},
		{label: "private admission intent", method: true, receiver: "Service", name: "prepareAdmission", want: map[string]int{"es/admission/resolved_execution_plan.go:Service.resolveExecutionForSubmit": 1, "es/admission/service.go:Service.Prepare": 1}},
		{label: "admission request snapshot", name: "snapshotAdmissionRequest", want: map[string]int{"es/admission/service.go:Service.prepareAdmission": 2}},
		{label: "admission validation/defaulting", name: "validatePrepareRequest", want: map[string]int{"es/admission/service.go:Service.prepareAdmission": 1}},
		{label: "normalized submit placement", name: "normalizeSubmitPlacementFacts", want: map[string]int{"es/admission/resolved_execution_plan.go:Service.resolveExecutionForSubmit": 1}},
		{label: "host context constructor", name: "newHostMaterializationContext", want: map[string]int{"es/admission/resolved_execution_plan.go:Service.resolveExecutionForSubmit": 1, "es/admission/reliable_submit_replay_hydration.go:privateReplayReader.placement": 1, "es/admission/reliable_submit_operational_format.go:verifyOperationalOriginal": 1}},
		{label: "semantic plan constructor", name: "newResolvedExecutionPlan", want: map[string]int{"es/admission/resolved_execution_plan.go:Service.resolveExecutionForSubmit": 1, "es/admission/reliable_submit_replay_hydration.go:decodePrivateReplayOriginal": 1, "es/admission/reliable_submit_operational_format.go:verifyOperationalOriginal": 1}},
		{label: "typed command constructor", name: "newResolvedRuntimeCommand", want: map[string]int{"es/admission/resolved_execution_plan.go:Service.resolveExecutionForSubmit": 1}},
		{label: "run projection constructor", name: "newResolvedRunProjection", want: map[string]int{"es/admission/submit.go:Service.Submit": 1, "es/admission/reliable_submit_operational_handoff.go:Service.advanceOperational": 1}},
		{label: "provider projection constructor", method: true, receiver: "resolvedRunProjection", name: "nomadJobProjection", want: map[string]int{"es/admission/submit.go:Service.Submit": 1, "es/admission/reliable_submit_operational_provider.go:operationalProvider.project": 1}},
		{label: "Nomad job builder", name: "buildNomadJobSpec", want: map[string]int{"es/admission/submit.go:Service.Submit": 1, "es/admission/reliable_submit_operational_provider.go:operationalProvider.project": 1}},
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
	if err := validateTypedReferenceInventory("legacy and selected private resolver callers", resolverReferences, map[string]int{"es/admission/submit.go:Service.Submit": 1, "es/admission/reliable_submit_replay_private.go:Service.composePrivateSyntheticReplay": 1, "es/admission/reliable_submit_operational_handoff.go:Service.composeOperationalOriginal": 1}, true); err != nil {
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
				"es/admission/reliable_submit_operational_handoff.go:operationalDomain.createOperationalStage": 1,
				"es/admission/staging_custody.go:claimStagingCustody":                                          1,
				"es/admission/staging_custody.go:probeStagingCustodyCapabilities":                              1,
				"es/admission/submit.go:Service.Submit":                                                        1,
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
			want:         map[string]int{"es/admission/submit.go:Service.Submit": 1, "es/admission/reliable_submit_operational_handoff.go:Service.advanceOperational": 1},
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
		"es/admission/reliable_submit_operational_handoff.go:operationalDomain.createOperationalStage",
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
		"es/admission/staging_custody.go:measureOperationalStage",
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
		"execution-substrate/es/admission/internal/admissionstate:State.s:*admissionstate.state",
		"execution-substrate/es/admission/internal/admissionstate:state.mu:sync.RWMutex",
		"execution-substrate/es/admission/internal/reliablesubmit:OperationalAccess.busy:atomic.Bool",
		"execution-substrate/es/admission/internal/reliablesubmit:OperationalAccess.issuer:*reliablesubmit.OperationalCustody",
		"execution-substrate/es/admission/internal/reliablesubmit:OperationalAccess.life:*reliablesubmit.progressOriginalLifetime",
		"execution-substrate/es/admission/internal/reliablesubmit:OperationalAccess.self:*reliablesubmit.OperationalAccess",
		"execution-substrate/es/admission/internal/reliablesubmit:OperationalCustody.mu:sync.RWMutex",
		"execution-substrate/es/admission/internal/reliablesubmit:OperationalCustody.self:*reliablesubmit.OperationalCustody",
		"execution-substrate/es/admission/internal/reliablesubmit:OperationalIntentInput.access:*reliablesubmit.OperationalAccess",
		"execution-substrate/es/admission/internal/reliablesubmit:OperationalIntentInput.self:*reliablesubmit.OperationalIntentInput",
		"execution-substrate/es/admission/internal/reliablesubmit:OperationalMarkerCandidate.self:*reliablesubmit.OperationalMarkerCandidate",
		"execution-substrate/es/admission/internal/reliablesubmit:OperationalMarkerCandidate.stage:*reliablesubmit.OperationalStageProof",
		"execution-substrate/es/admission/internal/reliablesubmit:OperationalOriginalView.life:*reliablesubmit.progressOriginalLifetime",
		"execution-substrate/es/admission/internal/reliablesubmit:OperationalPositiveProof.access:*reliablesubmit.OperationalAccess",
		"execution-substrate/es/admission/internal/reliablesubmit:OperationalPositiveProof.self:*reliablesubmit.OperationalPositiveProof",
		"execution-substrate/es/admission/internal/reliablesubmit:OperationalStageProof.access:*reliablesubmit.OperationalAccess",
		"execution-substrate/es/admission/internal/reliablesubmit:OperationalStageProof.self:*reliablesubmit.OperationalStageProof",
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
		"execution-substrate/es/admission/internal/reliablesubmit:operationalStepShape.stage:*reliablesubmit.OperationalStageProof",
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
		"execution-substrate/es/admission:Service.trustModelOwner:*admission.Service",
		"execution-substrate/es/admission:handoffOwner.mu:sync.Mutex",
		"execution-substrate/es/admission:handoffOwner.service:*admission.Service",
		"execution-substrate/es/admission:liveSender.owner:*admission.handoffOwner",
		"execution-substrate/es/admission:liveSender.self:*admission.liveSender",
		"execution-substrate/es/app:App.mu:sync.RWMutex",
		"execution-substrate/es/runtimehelper:helperServer.mu:sync.RWMutex",
	}
	packageStateSet := make(map[string]bool)
	synchronizationFieldSet := make(map[string]bool)
	mapBesideSynchronizationSet := make(map[string]bool)
	seenSources := make(map[string]bool)
	for _, view := range views {
		// The loader returns every package the patterns compile from the
		// repository, their dependencies included. This inventory is the one
		// of the ES source, so it reads the packages compiled from the two ES
		// directories, whatever a directory below them is called.
		scoped := packagesCompiledBelow(t, view.packages, "es", "cmd/es")
		// The scope is held by what it read. cmd/es declares no state of the
		// kinds listed here, so a scope that lost that directory would
		// otherwise pass until it does. The main package of the ES binary
		// stands for cmd/es and the admission package for es.
		if err := requirePackagesRead(scoped, "execution-substrate/cmd/es", "execution-substrate/es/admission"); err != nil {
			t.Fatalf("the ES source inventory of %s: %v", view.target, err)
		}
		packageState, synchronizationFields, mapsBesideSynchronization := structuralProductionStateInventory(scoped)
		for _, item := range packageState {
			packageStateSet[item] = true
		}
		for _, item := range synchronizationFields {
			synchronizationFieldSet[item] = true
		}
		for _, item := range mapsBesideSynchronization {
			mapBesideSynchronizationSet[item] = true
		}
		for _, pkg := range scoped {
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
	wantHeldStageReferences := []string{
		"execution-substrate/es/admission:handoffOwner.stage:*admission.stagingCustody",
		"execution-substrate/es/admission:liveSender.owner:*admission.handoffOwner",
		"execution-substrate/es/admission:liveSender.self:*admission.liveSender",
	}
	if !reflect.DeepEqual(mapsBesideSynchronization, wantHeldStageReferences) {
		t.Fatalf("structural map references beside synchronization changed: got %v want %v", mapsBesideSynchronization, wantHeldStageReferences)
	}
}

func TestExecutionSubstrateSynchronizedMutableStateReferenceInventoryIsExact(t *testing.T) {
	// Every production package of the module is loaded: the field inventories
	// read the package that declares each owning type, and the whole-value
	// inventory of each owning type is read in all the others as well.
	views := loadTypedProductionPackages(t, "./...")
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
				"es/admission/service.go:NewService|zero-initializer":                                       1,
				"es/admission/service.go:Service.Health":                                                    2,
				"es/admission/service.go:Service.Initialize":                                                3,
				"es/admission/service.go:Service.currentTrustModel":                                         2,
				"es/admission/reliable_submit_operational_admission.go:Service.installOperationalAdmission": 4,
			},
		},
		// The admission state lives in a package of its own behind its own
		// lock. Every method of the handle takes it; nothing else can.
		{
			label:      "admission state lock",
			importPath: "execution-substrate/es/admission/internal/admissionstate",
			typeName:   "state",
			fieldName:  "mu",
			want: map[string]int{
				"es/admission/internal/admissionstate/state.go:New|zero-initializer": 1,
				"es/admission/internal/admissionstate/state.go:State.Commissioned":   2,
				"es/admission/internal/admissionstate/state.go:State.Installable":    2,
				"es/admission/internal/admissionstate/state.go:State.Install":        2,
				"es/admission/internal/admissionstate/state.go:State.Withdraw":       2,
				"es/admission/internal/admissionstate/state.go:State.Confirmable":    2,
				"es/admission/internal/admissionstate/state.go:State.Confirm":        2,
				"es/admission/internal/admissionstate/state.go:State.Current":        2,
				"es/admission/internal/admissionstate/state.go:State.Inspect":        2,
			},
		},
		{
			label:      "admission protected trust model",
			importPath: "execution-substrate/es/admission",
			typeName:   "Service",
			fieldName:  "trustModel",
			want: map[string]int{
				"es/admission/service.go:NewService|zero-initializer":                                       1,
				"es/admission/service.go:Service.Health":                                                    1,
				"es/admission/service.go:Service.Initialize":                                                1,
				"es/admission/service.go:Service.currentTrustModel":                                         2,
				"es/admission/reliable_submit_operational_admission.go:Service.installOperationalAdmission": 2,
				"es/admission/reliable_submit_operational_admission.go:Service.operationalAdmissionContent": 4,
			},
		},
		{
			label:      "app state lock",
			importPath: "execution-substrate/es/app",
			typeName:   "App",
			fieldName:  "mu",
			want: map[string]int{
				"es/app/app.go:New|zero-initializer": 1,
				"es/app/app.go:App.Addr":             2,
				"es/app/app.go:App.Shutdown":         2,
				"es/app/app.go:App.Start":            2,
				"es/app/app.go:App.Started":          2,
			},
		},
		{
			label:      "app protected started state",
			importPath: "execution-substrate/es/app",
			typeName:   "App",
			fieldName:  "started",
			want: map[string]int{
				"es/app/app.go:New|zero-initializer": 1,
				"es/app/app.go:App.Shutdown":         1,
				"es/app/app.go:App.Start":            1,
				"es/app/app.go:App.Started":          1,
			},
		},
		{
			label:      "app protected listener state",
			importPath: "execution-substrate/es/app",
			typeName:   "App",
			fieldName:  "listener",
			want: map[string]int{
				"es/app/app.go:New|zero-initializer": 1,
				"es/app/app.go:App.Addr":             2,
				"es/app/app.go:App.Start":            1,
			},
		},
		{
			label:      "runtime-helper token lock",
			importPath: "execution-substrate/es/runtimehelper",
			typeName:   "helperServer",
			fieldName:  "mu",
			want: map[string]int{
				"es/runtimehelper/helper.go:runHelper|zero-initializer":      1,
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
				"es/runtimehelper/helper.go:runHelper|zero-initializer":      1,
				"es/runtimehelper/helper.go:helperServer.currentToken":       1,
				"es/runtimehelper/helper.go:helperServer.fetchAndStoreToken": 1,
			},
		},
		{
			label:      "operational custody lifetime lock",
			importPath: "execution-substrate/es/admission/internal/reliablesubmit",
			typeName:   "OperationalCustody",
			fieldName:  "mu",
			want: map[string]int{
				"es/admission/internal/reliablesubmit/operational_handoff.go:OpenProvisionedOperationalCustody|zero-initializer":            1,
				"es/admission/internal/reliablesubmit/operational_handoff.go:OperationalCustody.Close":                                      2,
				"es/admission/internal/reliablesubmit/operational_handoff.go:OperationalCustody.WithOperationalOriginal":                    2,
				"es/admission/internal/reliablesubmit/operational_handoff.go:OperationalCustody.EstablishOperational":                       2,
				"es/admission/internal/reliablesubmit/operational_handoff.go:OperationalCustody.ConfigureOperationalCommitFaultForProof":    2,
				"es/admission/internal/reliablesubmit/operational_handoff.go:OperationalCustody.ConfigureOperationalPrestageProofForProof":  2,
				"es/admission/internal/reliablesubmit/operational_admission.go:OperationalCustody.operationalAdmissionWrite":                2,
				"es/admission/internal/reliablesubmit/operational_admission.go:OperationalCustody.ConfigureOperationalReleaseProofForProof": 2,
			},
		},
		{
			label:      "operational access command latch",
			importPath: "execution-substrate/es/admission/internal/reliablesubmit",
			typeName:   "OperationalAccess",
			fieldName:  "busy",
			want: map[string]int{
				"es/admission/internal/reliablesubmit/operational_handoff.go:OperationalCustody.WithOperationalOriginal|zero-initializer": 1,
				"es/admission/internal/reliablesubmit/operational_handoff.go:OperationalAccess.Prestage":                                  2,
				"es/admission/internal/reliablesubmit/operational_handoff.go:OperationalAccess.applyOperational":                          2,
				"es/admission/internal/reliablesubmit/operational_handoff.go:OperationalAccess.BindVerifiedOperationalObservation":        2,
				"es/admission/internal/reliablesubmit/operational_handoff.go:OperationalAccess.VerifyOperationalReceipt":                  2,
				"es/admission/internal/reliablesubmit/operational_handoff.go:OperationalAccess.canBind":                                   2,
			},
		},
		{
			label:      "operational handoff owner lock",
			importPath: "execution-substrate/es/admission",
			typeName:   "handoffOwner",
			fieldName:  "mu",
			want: map[string]int{
				"es/admission/reliable_submit_operational_handoff.go:Service.advanceOperational|zero-initializer": 1,
				"es/admission/reliable_submit_operational_handoff.go:handoffOwner.close":                          2,
				"es/admission/reliable_submit_operational_handoff.go:liveSender.consume":                          2,
			},
		},

		{
			label:      "operation-local seal permit wrapper",
			importPath: "execution-substrate/es/admission/internal/reliablesubmit",
			typeName:   "PrivateReplaySealPermit",
			fieldName:  "permit",
			// The wrapper is returned, passed and embedded by value, so each such
			// place is a whole-value occurrence listed with its kind.
			want: map[string]int{
				"es/admission/internal/reliablesubmit/replay_custody_file.go:PrivateReplayCustody.ReserveSealUse":                                  1,
				"es/admission/internal/reliablesubmit/replay_custody_file.go:PrivateReplayCustody.ReserveSealUse|whole-declare":                    1,
				"es/admission/internal/reliablesubmit/replay_custody_file.go:PrivateReplayCustody.ReserveSealUse|zero-initializer":                 3,
				"es/admission/internal/reliablesubmit/replay_custody_file.go:PrivateReplayCustody.PublishSealedSynthetic|whole-declare":            1,
				"es/admission/internal/reliablesubmit/replay_custody_file.go:PrivateReplayCustody.PublishSealedSynthetic|whole-read":               1,
				"es/admission/internal/reliablesubmit/operational_handoff.go:OperationalCustody.EstablishOperational":                              1,
				"es/admission/internal/reliablesubmit/replay_custody_file.go:PrivateReplayCustody.publishReplayOriginal":                           4,
				"es/admission/internal/reliablesubmit/replay_custody_file.go:PrivateReplayCustody.publishReplayOriginal|whole-declare":             1,
				"es/admission/internal/reliablesubmit/replay_custody_file.go:<package>|whole-declare":                                              1,
				"es/admission/internal/reliablesubmit/replay_custody_file.go:PrivateReplayProgressCustody.PublishProgressOriginal":                 2,
				"es/admission/internal/reliablesubmit/replay_custody_file.go:PrivateReplayProgressCustody.PublishProgressOriginal|whole-declare":   1,
				"es/admission/internal/reliablesubmit/replay_custody_file.go:PrivateReplayProgressCustody.PublishProgressOriginal|whole-read":      1,
				"es/admission/internal/reliablesubmit/replay_custody_file.go:PrivateReplayProgressCustody.ReserveProgressSealUse":                  1,
				"es/admission/internal/reliablesubmit/replay_custody_file.go:PrivateReplayProgressCustody.ReserveProgressSealUse|whole-declare":    1,
				"es/admission/internal/reliablesubmit/replay_custody_file.go:PrivateReplayProgressCustody.ReserveProgressSealUse|zero-initializer": 4,
			},
		},
		{
			label:      "scope-2 operation-local permit wrapper",
			importPath: "execution-substrate/es/admission/internal/reliablesubmit",
			typeName:   "ProgressSealPermit",
			fieldName:  "permit",
			want: map[string]int{
				"es/admission/internal/reliablesubmit/replay_custody_file.go:PrivateReplayProgressCustody.PublishProgressOriginal":                 3,
				"es/admission/internal/reliablesubmit/replay_custody_file.go:PrivateReplayProgressCustody.PublishProgressOriginal|whole-declare":   1,
				"es/admission/internal/reliablesubmit/replay_custody_file.go:PrivateReplayProgressCustody.ReserveProgressSealUse":                  1,
				"es/admission/internal/reliablesubmit/replay_custody_file.go:PrivateReplayProgressCustody.ReserveProgressSealUse|whole-declare":    1,
				"es/admission/internal/reliablesubmit/replay_custody_file.go:PrivateReplayProgressCustody.ReserveProgressSealUse|zero-initializer": 4,
			},
		},
		{
			label:      "operation-local seal permit lock",
			importPath: "execution-substrate/es/admission/internal/reliablesubmit",
			typeName:   "privateSealPermit",
			fieldName:  "mu",
			want: map[string]int{
				"es/admission/internal/reliablesubmit/replay_key_use_sqlite.go:sqliteClaimStore.reserveReplaySealUseWithScope|zero-initializer": 1,
				"es/admission/internal/reliablesubmit/replay_key_use_sqlite.go:privateSealPermit.consume":                                       2,
				"es/admission/internal/reliablesubmit/replay_key_use_sqlite.go:privateSealPermit.burn":                                          2,
				"es/admission/internal/reliablesubmit/replay_custody_file.go:privateSealPermit.matchesAllocation":                               2,
			},
		},
		{
			label:      "operation-local seal permit burn state",
			importPath: "execution-substrate/es/admission/internal/reliablesubmit",
			typeName:   "privateSealPermit",
			fieldName:  "used",
			want: map[string]int{
				"es/admission/internal/reliablesubmit/replay_key_use_sqlite.go:sqliteClaimStore.reserveReplaySealUseWithScope|zero-initializer": 1,
				"es/admission/internal/reliablesubmit/replay_key_use_sqlite.go:privateSealPermit.consume":                                       2,
				"es/admission/internal/reliablesubmit/replay_key_use_sqlite.go:privateSealPermit.burn":                                          1,
				"es/admission/internal/reliablesubmit/replay_custody_file.go:privateSealPermit.matchesAllocation":                               1,
			},
		},
	}
	const admissionPath = "execution-substrate/es/admission"
	const admission = "es/admission/reliable_submit_operational_admission.go:"
	const service = "es/admission/service.go:"
	const handoff = "es/admission/reliable_submit_operational_handoff.go:"
	type accessInventory struct {
		owner, name string
		want        map[string]int
	}
	accessInventories := []accessInventory{
		// The Service is created once, by the literal in NewService, which leaves
		// every protected field at its zero value.
		{"Service", "trustModelVerified", map[string]int{
			service + "NewService|zero-initializer": 1, service + "Service.Initialize|assignment": 1,
			admission + "Service.operationalAdmissionContent|read": 1, admission + "Service.installOperationalAdmission|read": 1,
		}},
		{"Service", "trustModelOwner", map[string]int{
			service + "NewService|zero-initializer": 1, service + "Service.Initialize|assignment": 1,
			admission + "Service.operationalAdmissionContent|read": 1, admission + "Service.installOperationalAdmission|read": 1,
		}},
		// The handle of the admission state. NewService sets it once, after the
		// literal, with the address of the Service it has just made. Every
		// other occurrence is a method call on it: the handle is never copied,
		// compared or handed on.
		{"Service", "operational", map[string]int{
			service + "NewService|zero-initializer": 1, service + "NewService|assignment": 1, service + "Service.Initialize|read": 2,
			admission + "Service.installOperationalAdmission|read": 2, admission + "Service.withdrawOperationalEffects|read": 1,
			admission + "Service.confirmOperationalAdmission|read": 2, admission + "Service.currentOperationalAdmission|read": 1,
		}},
		{"Service", "operationalProof", map[string]int{service + "NewService|zero-initializer": 1, admission + "Service.installOperationalAdmission|read": 1}},
		// What a confirmation asks, and with which key it verifies the answer,
		// and what commissioning reads its content from. Each is set once, by
		// the literal in NewService.
		{"Service", "egsClient", map[string]int{
			service + "NewService|initializer": 1, service + "Service.fetchVerifiedTrustModel|read": 2,
			admission + "Service.confirmOperationalAdmission|read": 2,
		}},
		{"Service", "trustModelVerifier", map[string]int{
			service + "NewService|initializer": 1, service + "Service.verifyTrustModelEnvelope|read": 3,
			admission + "Service.confirmOperationalAdmission|read": 1,
		}},
		{"Service", "provenanceVerifier", map[string]int{
			service + "NewService|initializer": 1, service + "Service.prepareArtifactFromEvidenceRecord|read": 3,
			admission + "Service.operationalAdmissionContent|read": 2,
		}},
		{"Service", "admissionPolicyEvaluator", map[string]int{
			service + "NewService|initializer": 1, "es/admission/policy_payload.go:Service.enforceAdmissionPolicy|read": 1,
			admission + "Service.operationalAdmissionContent|read": 2,
		}},
		{"handoffOwner", "service", map[string]int{handoff + "Service.advanceOperational|initializer": 1, handoff + "liveSender.consume|read": 1}},
		{"handoffOwner", "admission", map[string]int{handoff + "Service.advanceOperational|initializer": 1, handoff + "liveSender.consume|read": 1}},
		{"operationalAdmissionProofHooks", "required", map[string]int{admission + "Service.qualifyOperationalRetained|read": 2}},
		{"operationalAdmissionProofHooks", "evaluated", map[string]int{admission + "Service.qualifyOperationalRetained|read": 2}},
		{"operationalAdmissionProofHooks", "contextObserved", map[string]int{admission + "Service.qualifyOperationalRetained|read": 2}},
		// The skew hook is read inside the function the install hands to the
		// state, which asks it at every sample. The stricter evaluator is
		// appended behind the built-in set of the view.
		{"operationalAdmissionProofHooks", "skew", map[string]int{admission + "Service.installOperationalAdmission|read+closure": 2}},
		{"operationalAdmissionProofHooks", "stricter", map[string]int{admission + "Service.qualifyOperationalRetained|read": 2}},
	}
	// The package that owns the admission state. No other package can name
	// one of these fields, so this inventory is the whole of what is done to
	// them. The file is also held by the hash of its content
	// (TestOperationalAdmissionStatePackageIsOneReviewedFile), which implies
	// this list; the list says what the reviewed content does.
	const statePath = "execution-substrate/es/admission/internal/admissionstate"
	const state = "es/admission/internal/admissionstate/state.go:"
	stateAccessInventories := []accessInventory{
		// The owner is set by the one literal and read by the one function
		// every method but Commissioned goes through.
		{"state", "owner", map[string]int{state + "New|initializer": 1, state + "State.held|read": 1}},
		// The view is assigned once, by Install, which reads it first.
		{"state", "view", map[string]int{
			state + "New|zero-initializer": 1, state + "State.Install|read": 1, state + "State.Install|assignment": 1,
			state + "State.Commissioned|read": 1, state + "State.Installable|read": 1, state + "State.Withdraw|read": 1,
			state + "State.Confirmable|read": 2, state + "State.Confirm|read": 1, state + "State.Current|read": 1,
			state + "State.Inspect|read": 1,
		}},
		// Each latch has one assignment, and it sets the latch. The
		// confirmation time has one, behind a comparison that only lets it
		// move forward.
		{"state", "withdrawn", map[string]int{
			state + "New|zero-initializer": 1, state + "State.Withdraw|assignment": 1, state + "State.Commissioned|read": 1,
			state + "State.Installable|read": 1, state + "State.Install|read": 1, state + "State.Confirmable|read": 1,
			state + "State.Current|read": 1, state + "State.Inspect|read": 1,
		}},
		{"state", "superseded", map[string]int{
			state + "New|zero-initializer": 1, state + "State.Confirm|assignment": 1, state + "State.Installable|read": 1,
			state + "State.Install|read": 1, state + "State.Confirmable|read": 1, state + "State.Current|read": 1,
			state + "State.Inspect|read": 1,
		}},
		{"state", "confirmed", map[string]int{
			state + "New|zero-initializer": 1, state + "State.Confirm|read": 1, state + "State.Confirm|assignment": 1,
			state + "State.Current|read": 1, state + "State.Inspect|read": 1,
		}},
		// Every field of a view is set by the literal in Install and only read
		// afterwards.
		{"view", "installation", map[string]int{
			state + "State.Install|initializer": 1, state + "State.Withdraw|read": 1, state + "State.Confirm|read": 1, state + "State.Current|read": 1,
		}},
		{"view", "epoch", map[string]int{
			state + "State.Install|initializer": 1, state + "State.Withdraw|read": 1, state + "State.Confirm|read": 1, state + "State.Current|read": 1,
		}},
		{"view", "token", map[string]int{
			state + "State.Install|initializer": 1, state + "State.Withdraw|read": 1, state + "State.Confirm|read": 1, state + "View.Token|read": 1,
		}},
		{"view", "content", map[string]int{
			state + "State.Install|initializer": 1, state + "State.Confirm|read": 2, state + "View.Trust|read": 1,
			state + "View.Verifier|read": 1, state + "View.Policies|read": 1,
		}},
		{"view", "proof", map[string]int{state + "State.Install|initializer": 1, state + "View.Proof|read": 1}},
		{"view", "skew", map[string]int{state + "State.Install|initializer": 1, state + "State.Current|read": 1}},
	}
	const storePath = "execution-substrate/es/admission/internal/reliablesubmit"
	const storeAdmission = "es/admission/internal/reliablesubmit/operational_admission.go:"
	const storeHandoff = "es/admission/internal/reliablesubmit/operational_handoff.go:"
	storeAccessInventories := []accessInventory{
		// The seam that replaces the COMMIT of an admission write in the store's
		// own tests. No production code sets it: the one place that makes a
		// custody leaves it nil, and the admission write reads it twice.
		{"OperationalCustody", "admissionCommit", map[string]int{
			storeHandoff + "OpenProvisionedOperationalCustody|zero-initializer":  1,
			storeAdmission + "OperationalCustody.operationalAdmissionWrite|read": 2,
		}},
	}
	validateObject := func(views []typedProductionView, inventory fieldInventory) error {
		references := mergedProductionReferences(t, views, inventory.importPath, func(pkg *typedProductionPackage) types.Object {
			return requirePackageStructField(t, pkg, inventory.typeName, inventory.fieldName)
		})
		return validateTypedObjectReferenceInventory(inventory.label, references, inventory.want, true)
	}
	validateAccess := func(views []typedProductionView, importPath string, field accessInventory) error {
		references := mergedProductionReferences(t, views, importPath, func(pkg *typedProductionPackage) types.Object {
			return requirePackageStructField(t, pkg, field.owner, field.name)
		})
		return validateTypedFieldAccessInventory(field.owner+"."+field.name, references, field.want)
	}
	// An owning type is a struct with an inventoried field. The same rules
	// hold for each of them.
	type owner struct{ importPath, typeName string }
	type accessOwner struct {
		importPath string
		field      accessInventory
	}
	var owners []owner
	var accessFields []accessOwner
	listed := make(map[owner]bool)
	addOwner := func(key owner, fieldName string) {
		if err := validateProtectedFieldName(key.importPath, key.typeName, fieldName); err != nil {
			t.Fatal(err)
		}
		if !listed[key] {
			listed[key] = true
			owners = append(owners, key)
		}
	}
	for _, inventory := range inventories {
		addOwner(owner{inventory.importPath, inventory.typeName}, inventory.fieldName)
	}
	for _, field := range accessInventories {
		addOwner(owner{admissionPath, field.owner}, field.name)
		accessFields = append(accessFields, accessOwner{admissionPath, field})
	}
	for _, field := range storeAccessInventories {
		addOwner(owner{storePath, field.owner}, field.name)
		accessFields = append(accessFields, accessOwner{storePath, field})
	}
	for _, field := range stateAccessInventories {
		addOwner(owner{statePath, field.owner}, field.name)
		accessFields = append(accessFields, accessOwner{statePath, field})
	}
	// What the other packages of the module do with a whole value of an owning
	// type. A type that is not named here has no such occurrence anywhere.
	const replayPrivate = "es/admission/reliable_submit_replay_private.go:"
	foreignInventories := map[owner]map[string]int{
		// The admission package receives a seal permit from the store by value
		// and hands it back to the store's publication call.
		{storePath, "PrivateReplaySealPermit"}: {
			replayPrivate + "Service.admitPrivateSyntheticReplay|whole-declare": 1, replayPrivate + "Service.admitPrivateSyntheticReplay|whole-read": 1,
			replayPrivate + "Service.admitPrivateProgressReplay|whole-declare": 1, replayPrivate + "Service.admitPrivateProgressReplay|whole-read": 1,
		},
		// The progress permit holds a seal permit by value, so its one
		// occurrence is listed for both.
		{storePath, "ProgressSealPermit"}: {
			replayPrivate + "Service.admitPrivateProgressReplay|whole-declare": 1, replayPrivate + "Service.admitPrivateProgressReplay|whole-read": 1,
		},
	}
	validateForeign := func(views []typedProductionView, key owner) error {
		want := foreignInventories[key]
		if want == nil {
			want = map[string]int{}
		}
		references := mergedForeignOwningStructReferences(t, views, key.importPath, key.typeName)
		return validateTypedFieldAccessInventory(key.typeName+" outside "+key.importPath, references, want)
	}
	// The type parameters declared in the packages that declare an owning
	// type. A generic body is the one place where code handles a value without
	// naming its type, so each is a listed, reviewed declaration.
	genericInventories := map[string][]string{
		admissionPath: {"es/admission/reliable_submit_replay_intent.go:<package> type replayPresence[T any]"},
	}
	validateGenerics := func(views []typedProductionView, importPath string) error {
		want := genericInventories[importPath]
		if got := mergedTypeParameterDeclarations(t, views, importPath); !reflect.DeepEqual(got, append([]string{}, want...)) {
			return fmt.Errorf("type parameter declarations of %s changed: got %q want %q", importPath, got, want)
		}
		return nil
	}
	for _, inventory := range inventories {
		if err := validateObject(views, inventory); err != nil {
			t.Fatal(err)
		}
	}
	for _, field := range accessFields {
		if err := validateAccess(views, field.importPath, field.field); err != nil {
			t.Fatal(err)
		}
	}
	for key := range foreignInventories {
		if !listed[key] {
			t.Fatalf("%s.%s has an inventory for other packages but no protected field", key.importPath, key.typeName)
		}
	}
	declaringPackages := make(map[string]bool)
	for _, key := range owners {
		declaringPackages[key.importPath] = true
		if err := validateForeign(views, key); err != nil {
			t.Fatal(err)
		}
	}
	for importPath := range genericInventories {
		if !declaringPackages[importPath] {
			t.Fatalf("%s has a type parameter inventory but declares no owning type", importPath)
		}
	}
	for _, importPath := range sortedStringSet(declaringPackages) {
		if err := validateGenerics(views, importPath); err != nil {
			t.Fatal(err)
		}
	}
	// Which fields must have an inventory because of the admission state is
	// read from the types, not from the lists above: every field of the two
	// structs of the state package, and every field of a struct of any package
	// whose type holds one of the two handle types. A list that loses such an
	// entry fails here, and so does a new field of either kind.
	inventoried := make(map[string]bool)
	for _, inventory := range inventories {
		inventoried[inventory.importPath+"."+inventory.typeName+"."+inventory.fieldName] = true
	}
	for _, field := range accessFields {
		inventoried[field.importPath+"."+field.field.owner+"."+field.field.name] = true
	}
	validateHolders := func(packages []*typedProductionPackage) error {
		fields, variables := admissionStateHolders(t, packages, statePath)
		return validateAdmissionStateHolders(fields, variables, inventoried)
	}
	for _, view := range views {
		if err := validateHolders(view.packages); err != nil {
			t.Fatalf("%s: %v", view.target, err)
		}
	}
	// The inventories above are run again over the real packages with probe
	// functions added in memory to the file that declares each protected
	// struct. Each probe takes a pointer to the struct and reaches its storage
	// without spelling a field or a value of it. The anonymous mirror is the
	// text of the struct's own declaration, so it follows every change of it.
	t.Run("storage aliases added to the real packages", func(t *testing.T) {
		view := views[len(views)-1]
		control := make(map[string]map[string]string)
		probes := make(map[string]map[string]string)
		declaredIn := make(map[owner]string)
		appendTo := func(overlays map[string]map[string]string, pkg *typedProductionPackage, fileName string, text string) {
			if overlays[pkg.importPath] == nil {
				overlays[pkg.importPath] = make(map[string]string)
			}
			if _, started := overlays[pkg.importPath][fileName]; !started {
				overlays[pkg.importPath][fileName] = pkg.sources[fileName] + "\n"
			}
			overlays[pkg.importPath][fileName] += text
		}
		for _, key := range owners {
			pkg := requireTypedProductionPackage(t, view.packages, key.importPath)
			fileName, mirror := productionStructDeclarationText(t, pkg, key.typeName)
			declaredIn[key] = fileName
			name := strings.ToUpper(key.typeName[:1]) + key.typeName[1:]
			appendTo(control, pkg, fileName, fmt.Sprintf("func zzGuardProbeKeep%s(target *%s) *%s { return target }\n", name, key.typeName, key.typeName))
			// Constrained names the owner only in a constraint, and Shape only
			// writes a type of its shape: each is one rule on its own. Reach is
			// the form of the third audit: a generic function that converts its
			// type parameter, with no instantiation in the package.
			appendTo(probes, pkg, fileName, fmt.Sprintf(
				"func zzGuardProbeMirror%[1]s(target *%[2]s) { mirror := (*%[3]s)(target); _ = mirror }\n"+
					"func zzGuardProbeOverwrite%[1]s(target *%[2]s) { *(*%[3]s)(target) = %[3]s{} }\n"+
					"func zzGuardProbeZero%[1]s[T any](v *T) { var z T; *v = z }\n"+
					"func zzGuardProbeGeneric%[1]s(target *%[2]s) { zzGuardProbeZero%[1]s(target) }\n"+
					"func zzGuardProbeConstrained%[1]s[S interface{ *%[2]s }](target S) S { return target }\n"+
					"func zzGuardProbeShape%[1]s() { type shaped %[3]s; var _ *shaped }\n"+
					"func zzGuardProbeReach%[1]s[S interface{ *%[2]s }](target S) { mirror := (*%[3]s)(target); _ = mirror }\n",
				name, key.typeName, mirror))
			// The forms the second audit ran end to end against b6d2f77 (Write),
			// and the generic forms the third audit ran against c41e177: one
			// that clears the latches of the Service, one that reaches its view
			// and one that rewrites the view, and one that clears the command
			// latch of a store access. None is instantiated in its package.
			// Since the admission state has a package of its own, the latches
			// and the view are fields of its two structs there, and the Service
			// holds a handle. The same forms are added where the fields now are,
			// and to the Service for what it still holds.
			switch key {
			case owner{statePath, "view"}:
				appendTo(probes, pkg, fileName, fmt.Sprintf("func zzGuardProbeWrite%[1]s(target *%[2]s) { mirror := (*%[3]s)(target); "+
					"mirror.content.Trust.SignerPolicy.RevokedSigners = nil; mirror.content.Trust.ArtifactPolicy.RevokedArtifacts = nil }\n"+
					"func zzGuardProbeClear%[1]s[V interface{ *%[2]s }](target V) { mirror := (*%[3]s)(target); "+
					"mirror.content.Trust.SignerPolicy.RevokedSigners = nil; mirror.content.Trust.ArtifactPolicy.RevokedArtifacts = nil }\n", name, key.typeName, mirror))
			case owner{statePath, "state"}:
				appendTo(probes, pkg, fileName, fmt.Sprintf("func zzGuardProbeWrite%[1]s(target *%[2]s) { mirror := (*%[3]s)(target); "+
					"mirror.withdrawn = false; mirror.superseded = false; mirror.confirmed = time.Now() }\n"+
					"func zzGuardProbeReopen%[1]s[S interface{ *%[2]s }](target S) { mirror := (*%[3]s)(target); "+
					"mirror.withdrawn = false; mirror.superseded = false; mirror.confirmed = time.Now() }\n"+
					"func zzGuardProbeView%[1]s[S interface{ *%[2]s }](target S) *view { return (*%[3]s)(target).view }\n",
					name, key.typeName, mirror))
			case owner{admissionPath, "Service"}:
				appendTo(probes, pkg, fileName, fmt.Sprintf("func zzGuardProbeWrite%[1]s(target *%[2]s) { mirror := (*%[3]s)(target); "+
					"mirror.trustModelVerified = true; mirror.trustModelOwner = target; mirror.operational = admissionstate.State{} }\n"+
					"func zzGuardProbeReopen%[1]s[S interface{ *%[2]s }](target S) { mirror := (*%[3]s)(target); "+
					"mirror.trustModelVerified = true; mirror.operational = admissionstate.State{} }\n"+
					"func zzGuardProbeView%[1]s[S interface{ *%[2]s }](target S) admissionstate.State { return (*%[3]s)(target).operational }\n",
					name, key.typeName, mirror))
			case owner{storePath, "OperationalAccess"}:
				appendTo(probes, pkg, fileName, fmt.Sprintf("func zzGuardProbeIdle%[1]s[A interface{ *%[2]s }](target A) { (*%[3]s)(target).busy.Store(false) }\n",
					name, key.typeName, mirror))
			}
		}
		overlaid := func(overlays map[string]map[string]string) []typedProductionView {
			packages := make([]*typedProductionPackage, 0, len(overlays))
			for importPath, overlay := range overlays {
				packages = append(packages, view.metadata.typeCheckWithOverlay(t, importPath, overlay))
			}
			return []typedProductionView{{target: view.target, packages: packages}}
		}
		// Control: a function that only keeps the pointer changes no inventory.
		kept := overlaid(control)
		for _, inventory := range inventories {
			if err := validateObject(kept, inventory); err != nil {
				t.Fatalf("control probe changed an inventory: %v", err)
			}
		}
		for _, field := range accessFields {
			if err := validateAccess(kept, field.importPath, field.field); err != nil {
				t.Fatalf("control probe changed an inventory: %v", err)
			}
		}
		aliased := overlaid(probes)
		requireRefused := func(label string, key owner, fieldName string, err error) {
			t.Helper()
			if err == nil {
				t.Fatalf("%s passed with storage aliases of %s in the package", label, key.typeName)
			}
			name := strings.ToUpper(key.typeName[:1]) + key.typeName[1:]
			pkg := requireTypedProductionPackage(t, aliased[0].packages, key.importPath)
			got := make(map[string]int)
			for _, reference := range pkg.referencesTo(requirePackageStructField(t, pkg, key.typeName, fieldName)) {
				if strings.HasSuffix(reference.site, name) && strings.Contains(reference.site, ":zzGuardProbe") {
					got[strings.TrimPrefix(reference.site, declaredIn[key]+":")+"|"+reference.accessKind]++
				}
			}
			want := map[string]int{
				"zzGuardProbeMirror" + name + "|whole-convert":        1,
				"zzGuardProbeMirror" + name + "|whole-mirror":         1,
				"zzGuardProbeOverwrite" + name + "|whole-convert":     1,
				"zzGuardProbeOverwrite" + name + "|whole-mirror":      2,
				"zzGuardProbeGeneric" + name + "|whole-instantiate":   1,
				"zzGuardProbeConstrained" + name + "|whole-constrain": 1,
				"zzGuardProbeShape" + name + "|whole-mirror":          1,
				"zzGuardProbeReach" + name + "|whole-constrain":       1,
				"zzGuardProbeReach" + name + "|whole-mirror":          1,
			}
			var forms []string
			switch key {
			case owner{statePath, "view"}:
				want["zzGuardProbeWrite"+name+"|whole-convert"] = 1
				forms = []string{"Write", "Clear"}
			case owner{statePath, "state"}, owner{admissionPath, "Service"}:
				want["zzGuardProbeWrite"+name+"|whole-convert"] = 1
				forms = []string{"Write", "Reopen", "View"}
			case owner{storePath, "OperationalAccess"}:
				forms = []string{"Idle"}
			}
			for _, form := range forms {
				want["zzGuardProbe"+form+name+"|whole-mirror"] = 1
				if form != "Write" {
					want["zzGuardProbe"+form+name+"|whole-constrain"] = 1
				}
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("%s probe occurrences: got %v want %v", label, got, want)
			}
		}
		for _, inventory := range inventories {
			requireRefused(inventory.label, owner{inventory.importPath, inventory.typeName}, inventory.fieldName, validateObject(aliased, inventory))
		}
		for _, field := range accessFields {
			requireRefused(field.field.owner+"."+field.field.name, owner{field.importPath, field.field.owner}, field.field.name, validateAccess(aliased, field.importPath, field.field))
		}
		// The probes declare type parameters, so the type parameter inventory
		// of each package refuses them as well; the control declares none.
		for _, importPath := range sortedStringSet(declaringPackages) {
			if err := validateGenerics(kept, importPath); err != nil {
				t.Fatalf("control probe changed the type parameter inventory: %v", err)
			}
			if err := validateGenerics(aliased, importPath); err == nil {
				t.Fatalf("type parameter inventory of %s passed with generic probes in the package", importPath)
			}
		}
	})
	// The rule that every holder of admission state has an inventory, over the
	// real packages with one declaration added in memory. A handle may sit
	// behind a pointer, in a container, in a function type, in a struct without
	// a name, behind a named type or an alias, or in a type argument.
	t.Run("what holds admission state has an inventory", func(t *testing.T) {
		view := views[len(views)-1]
		const hostName = "es/admission/reliable_submit_operational_handoff.go"
		const stateName = "es/admission/internal/admissionstate/state.go"
		hostSource, hosted := requireTypedProductionPackage(t, view.packages, admissionPath).sources[hostName]
		stateSource, stated := requireTypedProductionPackage(t, view.packages, statePath).sources[stateName]
		if !hosted || !stated || !strings.Contains(hostSource, "\"execution-substrate/es/admission/internal/admissionstate\"") {
			t.Fatalf("%s must be a file of %s that imports the admission state package, and %s a file of that package", hostName, admissionPath, stateName)
		}
		with := func(importPath string, fileName string, source string) []*typedProductionPackage {
			packages := []*typedProductionPackage{view.metadata.typeCheckWithOverlay(t, importPath, map[string]string{fileName: source})}
			for _, pkg := range view.packages {
				if pkg.importPath != importPath {
					packages = append(packages, pkg)
				}
			}
			return packages
		}
		// What the real packages hold: the fields of the two structs, the
		// handle of the Service and the view of a handoff owner, and no
		// package variable.
		fields, variables := admissionStateHolders(t, view.packages, statePath)
		for _, name := range []string{statePath + ".state.withdrawn", statePath + ".view.content", admissionPath + ".Service.operational", admissionPath + ".handoffOwner.admission"} {
			if index := sort.SearchStrings(fields, name); index == len(fields) || fields[index] != name {
				t.Fatalf("%s is not among the holders of admission state: %q", name, fields)
			}
		}
		if len(variables) != 0 {
			t.Fatalf("package variables hold a handle: %q", variables)
		}
		for name, text := range map[string]string{
			"plain data of the state package": "type zzGuardProbeHolder struct {\n\tcontent admissionstate.Content\n\towner *Service\n\tnext *zzGuardProbeHolder\n}",
			"a variable with plain data":      "var zzGuardProbeKept []admissionstate.Policy",
			"a named type that names itself":  "type zzGuardProbeList []zzGuardProbeList\ntype zzGuardProbeHolder struct{ kept zzGuardProbeList }",
			"a named type of handles alone":   "type zzGuardProbeViews []admissionstate.View",
		} {
			if err := validateHolders(with(admissionPath, hostName, hostSource+"\n"+text+"\n")); err != nil {
				t.Fatalf("control %q: %v", name, err)
			}
		}
		for name, text := range map[string]string{
			"a view":                         "type zzGuardProbeHolder struct{ kept admissionstate.View }",
			"a state":                        "type zzGuardProbeHolder struct{ kept admissionstate.State }",
			"an embedded state":              "type zzGuardProbeHolder struct{ admissionstate.State }",
			"a pointer to a view":            "type zzGuardProbeHolder struct{ kept *admissionstate.View }",
			"a slice of views":               "type zzGuardProbeHolder struct{ kept []admissionstate.View }",
			"an array of states":             "type zzGuardProbeHolder struct{ kept [2]admissionstate.State }",
			"a map to views":                 "type zzGuardProbeHolder struct{ kept map[string]admissionstate.View }",
			"a map keyed by views":           "type zzGuardProbeHolder struct{ kept map[admissionstate.View]bool }",
			"a channel of views":             "type zzGuardProbeHolder struct{ kept chan admissionstate.View }",
			"a function that returns a view": "type zzGuardProbeHolder struct{ kept func() admissionstate.View }",
			"a function that takes a state":  "type zzGuardProbeHolder struct{ kept func(admissionstate.State) }",
			"a struct without a name":        "type zzGuardProbeHolder struct{ kept struct{ inner admissionstate.View } }",
			"a named slice of views":         "type zzGuardProbeViews []admissionstate.View\ntype zzGuardProbeHolder struct{ kept zzGuardProbeViews }",
			"an alias of the view":           "type zzGuardProbeAlias = admissionstate.View\ntype zzGuardProbeHolder struct{ kept zzGuardProbeAlias }",
			"a type argument":                "type zzGuardProbeBox[T any] struct{ value T }\ntype zzGuardProbeHolder struct{ kept zzGuardProbeBox[admissionstate.View] }",
			"the result of an inspection":    "type zzGuardProbeHolder struct{ kept admissionstate.Status }",
		} {
			err := validateHolders(with(admissionPath, hostName, hostSource+"\n"+text+"\n"))
			if err == nil || !strings.Contains(err.Error(), admissionPath+".zzGuardProbeHolder.") || !strings.Contains(err.Error(), "has no inventory") {
				t.Fatalf("a field that holds %s: %v", name, err)
			}
		}
		for name, text := range map[string]string{
			"a view":         "var zzGuardProbeKept admissionstate.View",
			"a map of views": "var zzGuardProbeKept = map[string]admissionstate.View{}",
		} {
			err := validateHolders(with(admissionPath, hostName, hostSource+"\n"+text+"\n"))
			if err == nil || !strings.Contains(err.Error(), "package variable "+admissionPath+".zzGuardProbeKept holds a handle") {
				t.Fatalf("a package variable that holds %s: %v", name, err)
			}
		}
		// Inside the state package: a struct beside the two changes nothing,
		// and a new field of either of the two has no inventory.
		if err := validateHolders(with(statePath, stateName, stateSource+"\ntype zzGuardProbeOther struct{ plain int }\n")); err != nil {
			t.Fatalf("control: a third struct in the state package: %v", err)
		}
		for name, line := range map[string]string{
			"state": "\twithdrawn  bool\n",
			"view":  "\tproof        any\n",
		} {
			if strings.Count(stateSource, line) != 1 {
				t.Fatalf("%s has %d lines %q", stateName, strings.Count(stateSource, line), line)
			}
			err := validateHolders(with(statePath, stateName, strings.Replace(stateSource, line, line+"\tzzGuardProbeAdded bool\n", 1)))
			if err == nil || !strings.Contains(err.Error(), statePath+"."+name+".zzGuardProbeAdded has no inventory") {
				t.Fatalf("a new field of %s: %v", name, err)
			}
		}
	})
	// The third audit reached an owning type from another package: a generic
	// function declared beside the type and instantiated elsewhere, and a
	// whole value written elsewhere. Probes of the second kind are added in
	// memory to a package that imports the owner's.
	t.Run("whole values of owning types added to other packages", func(t *testing.T) {
		view := views[len(views)-1]
		for _, host := range []struct {
			owner                         owner
			importPath, fileName, spelled string
		}{
			{owner{admissionPath, "Service"}, "execution-substrate/es/app", "es/app/app.go", "admission.Service"},
			{owner{storePath, "OperationalCustody"}, admissionPath, "es/admission/reliable_submit_operational_handoff.go", "reliablesubmit.OperationalCustody"},
			{owner{storePath, "OperationalAccess"}, admissionPath, "es/admission/reliable_submit_operational_handoff.go", "reliablesubmit.OperationalAccess"},
			{owner{storePath, "PrivateReplaySealPermit"}, admissionPath, "es/admission/reliable_submit_operational_handoff.go", "reliablesubmit.PrivateReplaySealPermit"},
		} {
			t.Run(host.owner.typeName, func(t *testing.T) {
				hostPackage := requireTypedProductionPackage(t, view.packages, host.importPath)
				source, ok := hostPackage.sources[host.fileName]
				if !ok {
					t.Fatalf("%s is not a file of %s", host.fileName, host.importPath)
				}
				overlaid := func(text string) []typedProductionView {
					packages := []*typedProductionPackage{view.metadata.typeCheckWithOverlay(t, host.importPath, map[string]string{host.fileName: source + "\n" + text})}
					for _, pkg := range view.packages {
						if pkg.importPath != host.importPath {
							packages = append(packages, pkg)
						}
					}
					return []typedProductionView{{target: view.target, packages: packages}}
				}
				kept := overlaid(fmt.Sprintf("func zzGuardProbeForeignKeep(target *%[1]s) *%[1]s { return target }\n", host.spelled))
				if err := validateForeign(kept, host.owner); err != nil {
					t.Fatalf("control probe changed the inventory: %v", err)
				}
				probed := overlaid(fmt.Sprintf(
					"func zzGuardProbeForeignOverwrite(target *%[1]s) { *target = %[1]s{} }\n"+
						"func zzGuardProbeForeignRestore(target *%[1]s) { saved := *target; *target = saved }\n"+
						"func zzGuardProbeForeignZero[T any](v *T) { var z T; *v = z }\n"+
						"func zzGuardProbeForeignGeneric(target *%[1]s) { zzGuardProbeForeignZero(target) }\n"+
						"func zzGuardProbeForeignConstrained[S interface{ *%[1]s }](target S) S { return target }\n"+
						"func zzGuardProbeForeignDefined(target *%[1]s) { type defined %[1]s; _ = (*defined)(target) }\n"+
						"type zzGuardProbeForeignHolder struct{ inner %[1]s }\n",
					host.spelled))
				if err := validateForeign(probed, host.owner); err == nil {
					t.Fatalf("whole values of %s in %s passed", host.spelled, host.importPath)
				}
				got := make(map[string]int)
				for _, reference := range mergedForeignOwningStructReferences(t, probed, host.owner.importPath, host.owner.typeName) {
					if strings.Contains(reference.site, ":zzGuardProbeForeign") {
						got[strings.TrimPrefix(reference.site, host.fileName+":")+"|"+reference.accessKind]++
					} else if reference.accessKind == "whole-declare" && strings.HasSuffix(reference.site, ":<package>") && filepath.Base(reference.position.Filename) == filepath.Base(host.fileName) {
						got["<package>|"+reference.accessKind]++
					}
				}
				want := map[string]int{
					"zzGuardProbeForeignOverwrite|whole-assign":      1,
					"zzGuardProbeForeignOverwrite|initializer":       1,
					"zzGuardProbeForeignRestore|whole-declare":       1,
					"zzGuardProbeForeignRestore|whole-read":          2,
					"zzGuardProbeForeignRestore|whole-assign":        1,
					"zzGuardProbeForeignGeneric|whole-instantiate":   1,
					"zzGuardProbeForeignConstrained|whole-constrain": 1,
					"zzGuardProbeForeignDefined|whole-convert":       1,
					"<package>|whole-declare":                        1,
				}
				if !reflect.DeepEqual(got, want) {
					t.Fatalf("probe occurrences: got %v want %v", got, want)
				}
			})
		}
	})
	// The admission state has a package of its own so that the forms the
	// audits found do not compile anywhere else. Each form below is added in
	// memory to a file of es/admission, the one package that holds a handle,
	// and type-checked against the real packages. The type checker has to
	// refuse it, in the added line and nowhere else. This is the first line;
	// the inventories above are the second, for what does compile.
	t.Run("what does not compile outside the admission state package", func(t *testing.T) {
		const fileName = "es/admission/reliable_submit_operational_handoff.go"
		for _, view := range views {
			host := requireTypedProductionPackage(t, view.packages, admissionPath)
			source, ok := host.sources[fileName]
			if !ok || !strings.Contains(source, "\"execution-substrate/es/admission/internal/admissionstate\"") {
				t.Fatalf("%s is not a file of %s that imports the admission state package", fileName, admissionPath)
			}
			lines := strings.Count(source, "\n") + 1
			check := func(text string) []string {
				return view.metadata.typeErrorsWithOverlay(t, admissionPath, map[string]string{fileName: source + "\n" + text + "\n"})
			}
			// Controls: what another package may do compiles. It calls the
			// exported methods, and it holds, copies and compares handles.
			for name, text := range map[string]string{
				"nothing added":            "",
				"a method call":            "func zzCompiles(s *Service) bool { return s.operational.Commissioned() }",
				"a handle copied":          "func zzCompiles(s *Service) admissionstate.State { kept := s.operational; return kept }",
				"the zero handle":          "func zzCompiles() admissionstate.View { return admissionstate.View{} }",
				"handles compared":         "func zzCompiles(a, b admissionstate.View) bool { return a == b }",
				"a type with a handle":     "type zzCompiles struct{ held admissionstate.State }",
				"content made by a caller": "func zzCompiles() admissionstate.Content { return admissionstate.Content{Policies: []admissionstate.Policy{{ID: \"x\"}}} }",
			} {
				if got := check(text); len(got) != 0 {
					t.Fatalf("%s: control %q does not compile: %q", view.target, name, got)
				}
			}
			for _, probe := range []struct {
				name, text, message string
			}{
				// A field of the state or of a view, through either handle.
				{"the pointer of the state handle", "func zzRefused(s *Service) { _ = s.operational.s }", "unexported field s"},
				{"the pointer of the view handle", "func zzRefused(v admissionstate.View) { _ = v.v }", "unexported field v"},
				{"a latch through the handle", "func zzRefused(s *Service) { s.operational.s.withdrawn = false }", "unexported field s"},
				{"the confirmation time through the handle", "func zzRefused(s *Service) { s.operational.s.confirmed = s.operational.s.confirmed }", "unexported field s"},
				{"the content of a view", "func zzRefused(v admissionstate.View) { v.v.content.Trust.SignerPolicy.RevokedSigners = nil }", "unexported field v"},
				// The two types, by name: a variable, a conversion, a mirror
				// that needs the name for one of its fields, a type parameter
				// constraint.
				{"the state type", "func zzRefused() { var _ *admissionstate.state }", "not exported by package admissionstate"},
				{"the view type", "func zzRefused() { var _ admissionstate.view }", "not exported by package admissionstate"},
				{"a constraint that names the state", "func zzRefused[S interface{ *admissionstate.state }](target S) {}", "not exported by package admissionstate"},
				{"a new state by literal", "func zzRefused() { _ = &admissionstate.state{} }", "not exported by package admissionstate"},
				// A handle made by hand, to carry a pointer of the caller's choice.
				{"a state handle with a keyed field", "func zzRefused() { _ = admissionstate.State{s: nil} }", "unexported field s"},
				{"a state handle with a positional field", "func zzRefused() { _ = admissionstate.State{nil} }", "unexported field s"},
				{"a view handle with a keyed field", "func zzRefused() { _ = admissionstate.View{v: nil} }", "unexported field v"},
				{"a view handle with a positional field", "func zzRefused() { _ = admissionstate.View{nil} }", "unexported field v"},
				// A struct type of the handle's shape, written here. Its field s
				// is another package's s, so the two types never convert.
				{"a mirror of the state handle", "func zzRefused(s *Service) { type mirror struct{ s *struct{} }; _ = (*mirror)(&s.operational) }", "cannot convert"},
				{"a mirror of the view handle", "func zzRefused(v *admissionstate.View) { type mirror struct{ v *struct{} }; _ = (*mirror)(v) }", "cannot convert"},
				{"a mirror of the state handle with another pointer type", "func zzRefused(s *Service) { type mirror struct{ s *int }; _ = (*mirror)(&s.operational) }", "cannot convert"},
				{"a defined type of the handle, then its field", "func zzRefused(s *Service) { type defined admissionstate.State; _ = defined(s.operational).s }", "unexported field s"},
				{"an embedded handle, then its field", "func zzRefused(s *Service) { type holder struct{ admissionstate.State }; _ = holder{s.operational}.s }", "undefined"},
				// The whole value of the state: a copy, an overwrite, a restore.
				{"a copy of the state", "func zzRefused(s *Service) { saved := *s.operational.s; _ = saved }", "unexported field s"},
				{"an overwrite of the state through a generic function", "func zzZero[T any](v *T) { var z T; *v = z }\nfunc zzRefused(s *Service) { zzZero(s.operational.s) }", "unexported field s"},
				// What the package keeps to itself. The export data names an
				// unexported function only where an exported one inlines it, so
				// the type checker has two ways to say that it cannot be named.
				{"the function that reads the owner", "func zzRefused(s *Service) { _ = s.operational.held(s) }", "unexported method held"},
				{"the deadline arithmetic", "func zzRefused() { _ = admissionstate.fresh }", "fresh not exported by package admissionstate|undefined: admissionstate.fresh"},
				{"the copy of the trust lists", "func zzRefused(c admissionstate.Content) { _ = admissionstate.cloneTrust(c.Trust) }", "cloneTrust not exported by package admissionstate|undefined: admissionstate.cloneTrust"},
			} {
				if err := compileRefusal(check(probe.text), fileName, lines, probe.message); err != nil {
					t.Fatalf("%s: %q outside the admission state package: %v", view.target, probe.name, err)
				}
			}
		}
	})
	t.Run("how a form that must not compile is judged", func(t *testing.T) {
		const file = "es/admission/host.go"
		if err := compileRefusal([]string{file + ":11: s.operational.s undefined (cannot refer to unexported field s)"}, file, 10, "unexported field s"); err != nil {
			t.Fatalf("a refusal in the added text with the expected message was not accepted: %v", err)
		}
		if err := compileRefusal([]string{file + ":12: undefined: admissionstate.fresh"}, file, 10, "fresh not exported by package admissionstate|undefined: admissionstate.fresh"); err != nil {
			t.Fatalf("the second of two expected messages was not accepted: %v", err)
		}
		for name, found := range map[string][]string{
			"a form that compiles":                nil,
			"an error for another reason":         {file + ":11: missing return"},
			"an error in the last host line":      {file + ":10: unexported field s"},
			"an error in another file":            {"es/admission/other.go:11: unexported field s"},
			"an error without a line":             {file + ": unexported field s"},
			"an error without a file name":        {"11: unexported field s"},
			"a second error in the host text":     {file + ":11: unexported field s", file + ":3: unexported field s"},
			"an error of a file with this ending": {"x" + file + ":11: unexported field s"},
		} {
			if err := compileRefusal(found, file, 10, "unexported field s"); err == nil {
				t.Fatalf("%s was judged a refusal of the added text", name)
			}
		}
	})
	t.Run("a protected field is unexported", func(t *testing.T) {
		if err := validateProtectedFieldName("synthetic/admission", "Service", "trustModelVerified"); err != nil {
			t.Fatalf("an unexported protected field was refused: %v", err)
		}
		for _, name := range []string{"TrustModelVerified", "Äußeres"} {
			if err := validateProtectedFieldName("synthetic/admission", "Service", name); err == nil {
				t.Fatalf("the exported protected field %s passed", name)
			}
		}
	})
	t.Run("an owning type has a field", func(t *testing.T) {
		pkg := typeCheckSyntheticProductionPackage(t, "fixture.go", "package admission; type Service struct{ value int }; type Marker struct{}")
		if err := validateOwningStructShape(pkg.importPath, "Service", owningStructShapeOf(pkg.importPath, requirePackageStruct(t, pkg, "Service"))); err != nil {
			t.Fatalf("an owning type with a field was refused: %v", err)
		}
		if err := validateOwningStructShape(pkg.importPath, "Marker", owningStructShapeOf(pkg.importPath, requirePackageStruct(t, pkg, "Marker"))); err == nil {
			t.Fatal("an owning type without fields passed")
		}
	})
	t.Run("protected admission field access kinds", func(t *testing.T) {
		const declarations = "package admission; type Service struct{ trustModelVerified bool }; "
		const approved = "func (s *Service) Initialize(){s.trustModelVerified=true}; func (s *Service) commission(){_ = s.trustModelVerified}; "
		want := map[string]int{"fixture.go:Service.Initialize|assignment": 1, "fixture.go:Service.commission|read": 1}
		positive := typeCheckSyntheticProductionPackage(t, "fixture.go", declarations+approved)
		field := requirePackageStructField(t, positive, "Service", "trustModelVerified")
		if err := validateTypedFieldAccessInventory("synthetic trust verification", positive.referencesTo(field), want); err != nil {
			t.Fatal(err)
		}
		for name, mutation := range map[string]string{
			"extra same-site read": "func (s *Service) extra(){_ = s.trustModelVerified}",
			"alternate assignment": "func (s *Service) extra(){s.trustModelVerified=true}",
			"keyed initializer":    "func extra(){_ = Service{trustModelVerified:true}}",
		} {
			t.Run(name, func(t *testing.T) {
				mutant := typeCheckSyntheticProductionPackage(t, "fixture.go", declarations+approved+mutation)
				field := requirePackageStructField(t, mutant, "Service", "trustModelVerified")
				if err := validateTypedFieldAccessInventory("synthetic trust verification", mutant.referencesTo(field), want); err == nil {
					t.Fatal("extra protected field access passed exact access inventory")
				}
			})
		}
		wrongKind := strings.Replace(approved, "_ = s.trustModelVerified", "s.trustModelVerified=false", 1)
		mutant := typeCheckSyntheticProductionPackage(t, "fixture.go", declarations+wrongKind)
		field = requirePackageStructField(t, mutant, "Service", "trustModelVerified")
		if err := validateTypedFieldAccessInventory("synthetic trust verification", mutant.referencesTo(field), want); err == nil {
			t.Fatal("same-site protected write masqueraded as the allowed read")
		}
		t.Run("transparent parenthesized field access", func(t *testing.T) {
			for _, test := range []struct {
				name, declarations, fieldName, body, accessKind string
			}{
				{"read unwrapped", "type Service struct{ trustModelVerified bool }; ", "trustModelVerified", "_ = s.trustModelVerified", "read"},
				{"read parenthesized", "type Service struct{ trustModelVerified bool }; ", "trustModelVerified", "_ = (s.trustModelVerified)", "read"},
				{"read nested", "type Service struct{ trustModelVerified bool }; ", "trustModelVerified", "_ = (((s.trustModelVerified)))", "read"},
				{"read parenthesized RHS", "type Service struct{ trustModelVerified bool }; ", "trustModelVerified", "value := (s.trustModelVerified); _ = value", "read"},
				{"read parenthesized receiver", "type Service struct{ trustModelVerified bool }; ", "trustModelVerified", "_ = ((s)).trustModelVerified", "read"},
				{"assignment unwrapped", "type Service struct{ trustModelVerified bool }; ", "trustModelVerified", "s.trustModelVerified = false", "assignment"},
				{"assignment parenthesized", "type Service struct{ trustModelVerified bool }; ", "trustModelVerified", "(s.trustModelVerified) = false", "assignment"},
				{"assignment nested", "type Service struct{ trustModelVerified bool }; ", "trustModelVerified", "(((s.trustModelVerified))) = false", "assignment"},
				{"compound unwrapped", "type Service struct{ value int }; ", "value", "s.value += 1", "read-write"},
				{"compound nested", "type Service struct{ value int }; ", "value", "((s.value)) += 1", "read-write"},
				{"increment unwrapped", "type Service struct{ value int }; ", "value", "s.value++", "read-write"},
				{"increment nested", "type Service struct{ value int }; ", "value", "((s.value))++", "read-write"},
				{"decrement unwrapped", "type Service struct{ value int }; ", "value", "s.value--", "read-write"},
				{"decrement nested", "type Service struct{ value int }; ", "value", "((s.value))--", "read-write"},
				{"parallel LHS", "type Service struct{ value int }; ", "value", "other := 0; ((s.value)), other = 1, 2; _ = other", "assignment"},
				{"parallel RHS", "type Service struct{ value int }; ", "value", "other := 0; next := 0; other, next = ((s.value)), 2; _, _ = other, next", "read"},
			} {
				t.Run(test.name, func(t *testing.T) {
					pkg := typeCheckSyntheticProductionPackage(t, "fixture.go", "package admission; "+test.declarations+"func (s *Service) commission(){"+test.body+"}")
					field := requirePackageStructField(t, pkg, "Service", test.fieldName)
					references := pkg.referencesTo(field)
					if len(references) != 1 || references[0].site != "fixture.go:Service.commission" {
						t.Fatalf("same-site protected field occurrence changed: %v", references)
					}
					if references[0].accessKind != test.accessKind {
						t.Fatalf("protected field access kind: got %q want %q", references[0].accessKind, test.accessKind)
					}
					allowedRead := map[string]int{"fixture.go:Service.commission|read": 1}
					readErr := validateTypedFieldAccessInventory(test.name, references, allowedRead)
					if test.accessKind == "read" {
						if readErr != nil {
							t.Fatal(readErr)
						}
					} else if readErr == nil || !strings.Contains(readErr.Error(), "field access inventory changed") ||
						!strings.Contains(readErr.Error(), "|"+test.accessKind) {
						t.Fatalf("expected intended access-kind mismatch, got %v", readErr)
					}
					appropriate := map[string]int{"fixture.go:Service.commission|" + test.accessKind: 1}
					if err := validateTypedFieldAccessInventory(test.name, references, appropriate); err != nil {
						t.Fatalf("correctly classified access refused: %v", err)
					}
				})
			}
		})
		t.Run("write, address and write-through field access", func(t *testing.T) {
			const inner = "type inner struct{ n int }; func (i *inner) bump(){ i.n++ }; func (i inner) get() int { return i.n }; "
			for _, test := range []struct {
				name, declarations, fieldName, body, accessKind string
			}{
				{"range key assignment", "type Service struct{ trustModelVerified bool }; ", "trustModelVerified", "for s.trustModelVerified = range map[bool]int{false: 0} {}", "assignment"},
				{"range value assignment", "type Service struct{ value int }; ", "value", "for _, s.value = range []int{1} {}", "assignment"},
				{"range parenthesized key", "type Service struct{ value int }; ", "value", "for (s.value) = range 3 {}", "assignment"},
				{"address-of", "type Service struct{ trustModelVerified bool }; ", "trustModelVerified", "p := &s.trustModelVerified; *p = false", "address"},
				{"address-of dereferenced assignment", "type Service struct{ trustModelVerified bool }; ", "trustModelVerified", "*(&(s.trustModelVerified)) = false", "address"},
				{"pointer-receiver call on value", inner + "type Service struct{ value inner }; ", "value", "s.value.bump()", "address"},
				{"pointer-receiver method value", inner + "type Service struct{ value inner }; ", "value", "bump := (s.value).bump; bump()", "address"},
				{"array slice alias", "type Service struct{ value [2]int }; ", "value", "alias := s.value[:]; alias[0] = 1", "address"},
				{"subfield assignment", inner + "type Service struct{ value inner }; ", "value", "s.value.n = 1", "write-through"},
				{"parenthesized subfield assignment", inner + "type Service struct{ value inner }; ", "value", "((s.value).n) = 1", "write-through"},
				{"subfield increment", inner + "type Service struct{ value inner }; ", "value", "s.value.n++", "write-through"},
				{"subfield compound", inner + "type Service struct{ value inner }; ", "value", "s.value.n += 1", "write-through"},
				{"subfield range target", inner + "type Service struct{ value inner }; ", "value", "for s.value.n = range 2 {}", "write-through"},
				{"subfield address", inner + "type Service struct{ value inner }; ", "value", "p := &s.value.n; *p = 2", "write-through"},
				{"slice element assignment", "type Service struct{ value []int }; ", "value", "s.value[0] = 1", "write-through"},
				{"resliced element assignment", "type Service struct{ value []int }; ", "value", "s.value[1:][0] = 1", "write-through"},
				{"array element increment", "type Service struct{ value [2]int }; ", "value", "s.value[0]++", "write-through"},
				{"map element assignment", "type Service struct{ value map[string]int }; ", "value", "s.value[\"k\"] = 1", "write-through"},
				{"pointer dereference assignment", "type Service struct{ value *int }; ", "value", "*s.value = 1", "write-through"},
				{"pointer subfield assignment", inner + "type Service struct{ value *inner }; ", "value", "s.value.n = 1", "write-through"},
				{"builtin delete", "type Service struct{ value map[string]int }; ", "value", "delete(s.value, \"k\")", "write-through"},
				{"builtin clear", "type Service struct{ value []int }; ", "value", "clear(s.value)", "write-through"},
				{"builtin copy destination", "type Service struct{ value []int }; ", "value", "copy(s.value, []int{1})", "write-through"},
				{"builtin close", "type Service struct{ value chan int }; ", "value", "close(s.value)", "write-through"},
				{"builtin append first argument", "type Service struct{ value []int }; ", "value", "_ = append(s.value, 1)", "write-through"},
				{"builtin append through a reslice", "type Service struct{ value []int }; ", "value", "_ = append(s.value[:0], 1)", "write-through"},
				{"channel send", "type Service struct{ value chan int }; ", "value", "s.value <- 1", "write-through"},
				{"channel send through an element", "type Service struct{ value []chan int }; ", "value", "s.value[0] <- 1", "write-through"},
				{"conversion chain subfield assignment", inner + "type twin inner; type Service struct{ value *inner }; ", "value", "(*twin)(s.value).n = 1", "write-through"},
				{"anonymous conversion chain assignment", inner + "type Service struct{ value *inner }; ", "value", "(*struct{ n int })(s.value).n = 1", "write-through"},
				{"conversion chain element assignment", "type list []int; type Service struct{ value []int }; ", "value", "list(s.value)[0] = 1", "write-through"},
				{"conversion chain clear", "type list []int; type Service struct{ value []int }; ", "value", "clear(list(s.value))", "write-through"},
				{"type assertion chain assignment", inner + "type Service struct{ value any }; ", "value", "s.value.(*inner).n = 1", "write-through"},
				{"type assertion chain element increment", "type Service struct{ value any }; ", "value", "s.value.([]int)[0]++", "write-through"},
				{"builtin append later argument", "type Service struct{ value []int }; ", "value", "other := []int{}; _ = append(other, s.value...)", "read"},
				{"channel receive", "type Service struct{ value chan int }; ", "value", "_ = <-s.value", "read"},
				{"channel send value", "type Service struct{ value int }; ", "value", "other := make(chan int, 1); other <- s.value", "read"},
				{"conversion read", "type Service struct{ value int }; ", "value", "_ = int64(s.value)", "read"},
				{"type assertion read", inner + "type Service struct{ value any }; ", "value", "_ = s.value.(*inner).n", "read"},
				{"builtin copy source", "type Service struct{ value []int }; ", "value", "dst := make([]int, 1); copy(dst, s.value)", "read"},
				{"subfield read", inner + "type Service struct{ value inner }; ", "value", "_ = s.value.n", "read"},
				{"element read", "type Service struct{ value []int }; ", "value", "_ = s.value[0]", "read"},
				{"index operand read", "type Service struct{ value int }; ", "value", "other := []int{1}; _ = other[s.value]", "read"},
				{"value-receiver call", inner + "type Service struct{ value inner }; ", "value", "_ = s.value.get()", "read"},
				{"pointer field method call", inner + "type Service struct{ value *inner }; ", "value", "s.value.bump()", "read"},
				{"range over field", "type Service struct{ value []int }; ", "value", "for range s.value {}", "read"},
			} {
				t.Run(test.name, func(t *testing.T) {
					pkg := typeCheckSyntheticProductionPackage(t, "fixture.go", "package admission; "+test.declarations+"func (s *Service) commission(){"+test.body+"}")
					field := requirePackageStructField(t, pkg, "Service", test.fieldName)
					references := pkg.referencesTo(field)
					if len(references) != 1 || references[0].site != "fixture.go:Service.commission" {
						t.Fatalf("same-site protected field occurrence changed: %v", references)
					}
					if references[0].accessKind != test.accessKind {
						t.Fatalf("protected field access kind: got %q want %q", references[0].accessKind, test.accessKind)
					}
					allowedRead := map[string]int{"fixture.go:Service.commission|read": 1}
					readErr := validateTypedFieldAccessInventory(test.name, references, allowedRead)
					if test.accessKind == "read" {
						if readErr != nil {
							t.Fatal(readErr)
						}
					} else if readErr == nil || !strings.Contains(readErr.Error(), "field access inventory changed") ||
						!strings.Contains(readErr.Error(), "|"+test.accessKind) {
						t.Fatalf("expected intended access-kind mismatch, got %v", readErr)
					}
					appropriate := map[string]int{"fixture.go:Service.commission|" + test.accessKind: 1}
					if err := validateTypedFieldAccessInventory(test.name, references, appropriate); err != nil {
						t.Fatalf("correctly classified access refused: %v", err)
					}
				})
			}
		})
		t.Run("field access inside a function literal", func(t *testing.T) {
			const declarations = "package admission; type Service struct{ value int }; "
			for _, test := range []struct{ name, body, accessKind string }{
				{"read", "func(){ _ = s.value }()", "read"},
				{"assignment", "func(){ s.value = 1 }()", "assignment"},
				{"deferred assignment", "defer func(){ s.value = 1 }()", "assignment"},
				{"nested literal read", "func(){ func(){ _ = s.value }() }()", "read"},
			} {
				t.Run(test.name, func(t *testing.T) {
					pkg := typeCheckSyntheticProductionPackage(t, "fixture.go", declarations+"func (s *Service) commission(){"+test.body+"}")
					references := pkg.referencesTo(requirePackageStructField(t, pkg, "Service", "value"))
					if len(references) != 1 || !references[0].insideFuncLiteral || references[0].accessKind != test.accessKind {
						t.Fatalf("closure occurrence: %v", references)
					}
					plain := map[string]int{"fixture.go:Service.commission|" + test.accessKind: 1}
					if err := validateTypedFieldAccessInventory(test.name, references, plain); err == nil {
						t.Fatal("an occurrence inside a function literal passed as an occurrence of the function body")
					}
					listed := map[string]int{"fixture.go:Service.commission|" + test.accessKind + "+closure": 1}
					if err := validateTypedFieldAccessInventory(test.name, references, listed); err != nil {
						t.Fatalf("listed closure occurrence refused: %v", err)
					}
				})
			}
		})
		t.Run("unresolved selection is unclassified", func(t *testing.T) {
			const source = "package admission; type inner struct{ n int }; type Service struct{ value inner }; func (s *Service) commission(){ s.value.n = 1 }"
			pkg := typeCheckSyntheticProductionPackage(t, "fixture.go", source)
			field := requirePackageStructField(t, pkg, "Service", "value")
			if references := pkg.referencesTo(field); len(references) != 1 || references[0].accessKind != "write-through" {
				t.Fatalf("resolved control: %v", references)
			}
			// Forget what the outer selector resolved to, as an incomplete type
			// check would. The chain can then no longer be followed.
			removed := 0
			for selector := range pkg.info.Selections {
				if selector.Sel.Name == "n" {
					delete(pkg.info.Selections, selector)
					removed++
				}
			}
			if removed != 1 {
				t.Fatalf("removed %d selections", removed)
			}
			references := pkg.referencesTo(field)
			if len(references) != 1 || references[0].accessKind != "unclassified" {
				t.Fatalf("unresolved chain: %v", references)
			}
			for _, kind := range []string{"read", "write-through", "assignment"} {
				if err := validateTypedFieldAccessInventory("unresolved", references, map[string]int{"fixture.go:Service.commission|" + kind: 1}); err == nil {
					t.Fatalf("unresolved chain passed as %s", kind)
				}
			}
		})
		t.Run("whole-value occurrences of the owning struct", func(t *testing.T) {
			const owner = "type Service struct{ value int; other int }; "
			const twin = "type twin struct{ value int; other int }; "
			const holder = "type holder struct{ inner Service; n int }; "
			const held = "fixture.go:<package>|whole-declare"
			const zero = "func zero[T any](v *T){ var z T; *v = z }; "
			// A type of another shape: it has one field name the owner has not.
			const unrelated = "type unrelated struct{ value int; third int }; "
			const phantom = "type phantom[T any] struct{ n int }; "
			const mirrored = "fixture.go:<package>|whole-mirror"
			const mirror = "fixture.go:f|whole-mirror"
			const constrained = "fixture.go:f|whole-constrain"
			for _, test := range []struct {
				name, source string
				want         map[string]int
			}{
				{"positional literal", "func f(){ _ = Service{1, 2} }", map[string]int{"fixture.go:f|initializer": 1}},
				{"keyed literal naming the field", "func f(){ _ = Service{value: 1} }", map[string]int{"fixture.go:f|initializer": 1}},
				{"keyed literal omitting the field", "func f(){ _ = Service{other: 1} }", map[string]int{"fixture.go:f|zero-initializer": 1}},
				{"empty literal", "func f(){ _ = Service{} }", map[string]int{"fixture.go:f|zero-initializer": 1}},
				{"empty pointer literal", "func f(){ _ = &Service{} }", map[string]int{"fixture.go:f|zero-initializer": 1}},
				{"new", "func f(){ _ = new(Service) }", map[string]int{"fixture.go:f|whole-declare": 1}},
				{"zero-value declaration", "func f(){ var v Service; _ = &v }", map[string]int{"fixture.go:f|whole-declare": 1}},
				{"package variable", "var kept Service", map[string]int{"fixture.go:<package>|whole-declare": 1}},
				{"overwrite through a pointer", "func f(s *Service){ *s = Service{value: 1} }", map[string]int{"fixture.go:f|whole-assign": 1, "fixture.go:f|initializer": 1}},
				{"overwrite with zero", "func f(s *Service){ *s = Service{} }", map[string]int{"fixture.go:f|whole-assign": 1, "fixture.go:f|zero-initializer": 1}},
				{"parenthesized overwrite", "func f(s *Service){ (*s) = Service{} }", map[string]int{"fixture.go:f|whole-assign": 1, "fixture.go:f|zero-initializer": 1}},
				{"copy between pointers", "func f(a, b *Service){ *a = *b }", map[string]int{"fixture.go:f|whole-assign": 1, "fixture.go:f|whole-read": 1}},
				{"range assignment target", "func f(list []Service, s *Service){ for _, *s = range list {} }", map[string]int{"fixture.go:f|whole-assign": 1}},
				{"range definition", "func f(list []Service){ for _, v := range list { _ = &v } }", map[string]int{"fixture.go:f|whole-declare": 1}},
				{"conversion from a same-shape type", twin + "func f(t *twin){ _ = Service(*t) }", map[string]int{"fixture.go:f|whole-convert": 1, mirrored: 1}},
				{"conversion from an anonymous struct", "func f(t *struct{ value int; other int }){ _ = Service(*t) }", map[string]int{"fixture.go:f|whole-convert": 1, mirror: 1}},
				{"conversion to a pointer", twin + "func f(t *twin){ _ = (*Service)(t) }", map[string]int{"fixture.go:f|whole-convert": 1, mirrored: 1}},
				{"conversion to a slice", "type listed []Service; func f(t []Service){ _ = listed(t) }", map[string]int{"fixture.go:f|whole-convert": 1}},
				{"defined type over the owner", "type second Service; func f(a *second){ *a = second{} }", map[string]int{"fixture.go:f|whole-assign": 1, "fixture.go:f|zero-initializer": 1}},
				{"conversion to a defined type over the owner", "type second Service; func f(s *Service){ _ = second(*s) }", map[string]int{"fixture.go:f|whole-convert": 1, "fixture.go:f|whole-read": 1}},
				// A conversion away from the owner. From a pointer it gives the same
				// storage another type's field names; none of these spells a field
				// or a value of the owner. Each needs a type of the owner's shape,
				// which is listed where it is written, with or without the
				// conversion.
				{"pointer conversion to a same-shape type", twin + "func f(s *Service){ (*twin)(s).value = 1 }", map[string]int{"fixture.go:f|whole-convert": 1, mirrored: 1}},
				{"pointer conversion to an anonymous struct", "func f(s *Service){ (*struct{ value int; other int })(s).value = 1 }", map[string]int{"fixture.go:f|whole-convert": 1, mirror: 1}},
				{"pointer conversion to a tagged struct", "func f(s *Service){ (*struct{ value int `k:\"v\"`; other int })(s).value = 1 }", map[string]int{"fixture.go:f|whole-convert": 1, mirror: 1}},
				{"pointer conversion kept in a variable", "func f(s *Service){ p := (*struct{ value int; other int })(s); p.value = 1 }", map[string]int{"fixture.go:f|whole-convert": 1, mirror: 1}},
				{"whole overwrite through a converted pointer", twin + "func f(s *Service){ *(*twin)(s) = twin{} }", map[string]int{"fixture.go:f|whole-convert": 1, mirrored: 1}},
				{"pointer conversion to a named pointer type", twin + "type twinPointer *twin; func f(s *Service){ twinPointer((*twin)(s)).value = 1 }", map[string]int{"fixture.go:f|whole-convert": 1, mirrored: 1}},
				{"pointer conversion from a named pointer type", twin + "type servicePointer *Service; func f(s servicePointer){ (*twin)((*Service)(s)).value = 1 }", map[string]int{"fixture.go:f|whole-convert": 2, mirrored: 1}},
				{"pointer conversion of a defined type over the owner", "type second Service; " + twin + "func f(s *second){ (*twin)(s).value = 1 }", map[string]int{"fixture.go:f|whole-convert": 1, mirrored: 1}},
				{"pointer conversion of the owner inside a holder", holder + twin + "func f(h *holder){ (*twin)(&h.inner).value = 1 }", map[string]int{held: 1, "fixture.go:f|whole-convert": 1, mirrored: 1}},
				{"pointer conversion of a holder", holder + "func f(h *holder){ (*struct{ inner Service; n int })(h).inner.other = 1 }", map[string]int{held: 1, "fixture.go:f|whole-convert": 1, "fixture.go:f|whole-declare": 1}},
				{"pointer conversion at package level", twin + "var kept *Service; var alias = (*twin)(kept)", map[string]int{"fixture.go:<package>|whole-convert": 1, mirrored: 1}},
				{"pointer conversion to a type parameter", twin + "func f[T interface{ *twin }](s *Service) T { return T(s) }", map[string]int{"fixture.go:f|whole-convert": 1, mirrored: 1}},
				{"conversion away by value", twin + "func f(s *Service){ _ = twin(*s) }", map[string]int{"fixture.go:f|whole-convert": 1, "fixture.go:f|whole-read": 1, mirrored: 1}},
				{"conversion away by value to an anonymous struct", "func f(s *Service){ _ = struct{ value int; other int }(*s) }", map[string]int{"fixture.go:f|whole-convert": 1, "fixture.go:f|whole-read": 1, mirror: 1}},
				{"conversion of a value to an interface", "func f(s *Service) any { return any(*s) }", map[string]int{"fixture.go:f|whole-read": 1}},
				// A generic body writes a value of its type parameter without spelling
				// the owner. The instantiation is the place that names it.
				{"generic function instantiated by inference", zero + "func f(s *Service){ zero(s) }", map[string]int{"fixture.go:f|whole-instantiate": 1}},
				{"generic function instantiated explicitly", zero + "func f(s *Service){ zero[Service](s) }", map[string]int{"fixture.go:f|whole-instantiate": 1}},
				// An instantiation is listed where the generic is named, called or
				// not, and whether its type argument is written or inferred.
				{"generic function taken as a value with a written type argument", zero + "func f() func(*Service) { return zero[Service] }", map[string]int{"fixture.go:f|whole-instantiate": 1}},
				{"generic function taken as a value with an inferred type argument", zero + "func f() func(*Service) { var h func(*Service) = zero; return h }", map[string]int{"fixture.go:f|whole-instantiate": 1}},
				{"generic function value instantiated by assignment", zero + "func f(s *Service){ var g func(*Service) = zero; g(s) }", map[string]int{"fixture.go:f|whole-instantiate": 1}},
				{"generic function instantiated with a pointer to the owner", twin + "func away[S interface{ *Service }](s S) *twin { return (*twin)(s) }; func f(s *Service){ away(s).value = 1 }", map[string]int{"fixture.go:f|whole-instantiate": 1, "fixture.go:away|whole-constrain": 1, mirrored: 1}},
				{"generic function instantiated with a pointer to a pointer", zero + "func f(s **Service){ zero(s) }", map[string]int{"fixture.go:f|whole-instantiate": 1}},
				{"generic function instantiated with a container of the owner", "func first[L ~[]E, E any](l L) *E { return &l[0] }; func f(list []Service){ _ = first(list) }", map[string]int{"fixture.go:f|whole-instantiate": 1}},
				{"generic type instantiated with the owner", "type cell[T any] struct{ p *T }; func (c cell[T]) zero(){ var z T; *c.p = z }; func f(s *Service){ cell[Service]{p: s}.zero() }", map[string]int{"fixture.go:f|whole-instantiate": 1}},
				{"generic type instantiated with the owner at package level", "type cell[T any] struct{ p *T }; var kept cell[Service]", map[string]int{"fixture.go:<package>|whole-instantiate": 1}},
				// Every type argument is read, not only the first or the last.
				{"generic function with the owner as its first type argument only", "func pair[A, B any](a *A, b *B){}; func f(s *Service, n *int){ pair(s, n) }", map[string]int{"fixture.go:f|whole-instantiate": 1}},
				{"generic function with the owner as its second type argument only", "func pair[A, B any](a *A, b *B){}; func f(s *Service, n *int){ pair(n, s) }", map[string]int{"fixture.go:f|whole-instantiate": 1}},
				{"generic function with the owner as its middle type argument only", "func triple[A, B, C any](a *A, b *B, c *C){}; func f(s *Service, n *int){ triple(n, s, n) }", map[string]int{"fixture.go:f|whole-instantiate": 1}},
				// A type parameter whose constraint names the owner. Its body
				// handles the owner under the parameter's name, and the
				// instantiation that names the owner can be written in any other
				// package, so the parameter is listed where it is declared. None
				// of these is instantiated here.
				{"type parameter converted to a same-shape type", twin + "func f[S interface{ *Service }](s S) *twin { return (*twin)(s) }", map[string]int{constrained: 1, mirrored: 1}},
				{"type parameter converted to an anonymous struct", "func f[S interface{ *Service }](s S){ _ = (*struct{ value int; other int })(s) }", map[string]int{constrained: 1, mirror: 1}},
				{"type parameter converted with a write through it", "func f[S interface{ *Service }](s S){ (*struct{ value int; other int })(s).value = 1 }", map[string]int{constrained: 1, mirror: 1}},
				{"type parameter converted with a whole overwrite through it", twin + "func f[S interface{ *Service }](s S){ *(*twin)(s) = twin{} }", map[string]int{constrained: 1, mirrored: 1}},
				{"type parameter converted to a type parameter", twin + "func f[S interface{ *Service }, T interface{ *twin }](s S) T { return T(s) }", map[string]int{constrained: 1, mirrored: 1}},
				{"generic type with a converting method", twin + "type box[S interface{ *Service }] struct{ s S }; func (b box[S]) away() *twin { return (*twin)(b.s) }", map[string]int{"fixture.go:<package>|whole-constrain": 1, "fixture.go:box.away|whole-constrain": 1, mirrored: 1}},
				{"chain of two generic functions", twin + "func inner[S interface{ *Service }](s S) *twin { return (*twin)(s) }; func f[S interface{ *Service }](s S){ inner(s).value = 1 }", map[string]int{constrained: 1, "fixture.go:inner|whole-constrain": 1, mirrored: 1}},
				{"type parameter constrained to the owner by value", "func f[S interface{ Service }](s *S){ var z S; *s = z }", map[string]int{constrained: 1}},
				{"type parameter with an approximate pointer term", "func f[S interface{ ~*Service }](s S) S { return s }", map[string]int{constrained: 1}},
				{"type parameter with an implicit constraint", "func f[S *Service](s S) S { return s }", map[string]int{constrained: 1}},
				{"type parameter with the owner in a union", unrelated + "func f[S interface{ *unrelated | *Service }](s S) S { return s }", map[string]int{constrained: 1}},
				{"type parameter with a named constraint", "type pointing interface{ *Service }; func f[S pointing](s S) S { return s }", map[string]int{constrained: 1}},
				{"type parameter with an embedded constraint", "type pointing interface{ *Service }; func f[S interface{ comparable; pointing }](s S) S { return s }", map[string]int{constrained: 1}},
				{"type parameter with a generic constraint", "type pointing[T any] interface{ *T }; func f[S pointing[Service]](s S) S { return s }", map[string]int{constrained: 1, "fixture.go:f|whole-instantiate": 1}},
				{"second type parameter constrained to the owner", "func f[A any, S interface{ *Service }](a A, s S) S { return s }", map[string]int{constrained: 1}},
				{"type parameter constrained through another type parameter", "func f[T interface{ Service }, P interface{ *T }](p P){ var z T; *p = z }", map[string]int{constrained: 2}},
				{"type parameter constrained to a slice of the owner", "func f[L interface{ ~[]Service }](l L) L { return l }", map[string]int{constrained: 1}},
				{"type parameter constrained to a pointer to a pointer", "func f[S interface{ **Service }](s S) S { return s }", map[string]int{constrained: 1}},
				{"type parameter constrained to a map of pointers", "func f[M interface{ ~map[string]*Service }](m M) M { return m }", map[string]int{constrained: 1}},
				{"type parameter constrained to an array of pointers", "func f[A interface{ ~[2]*Service }](a A) A { return a }", map[string]int{constrained: 1}},
				{"type parameter constrained to a channel of pointers", "func f[C interface{ ~chan *Service }](c C) C { return c }", map[string]int{constrained: 1}},
				{"type parameter constrained to a map keyed by pointers", "func f[M interface{ ~map[*Service]bool }](m M) M { return m }", map[string]int{constrained: 1}},
				{"type parameter with the owner first in a union", unrelated + "func f[S interface{ *Service | *unrelated }](s S) S { return s }", map[string]int{constrained: 1}},
				{"type parameter with the owner in the middle of a union", unrelated + "func f[S interface{ *unrelated | *Service | *int }](s S) S { return s }", map[string]int{constrained: 1}},
				{"type parameter constrained to a struct that points to the owner", "func f[L interface{ struct{ inner *Service } }](l L) L { return l }", map[string]int{constrained: 1}},
				{"type parameter constrained to a holder", holder + "func f[H interface{ *holder }](h H) H { return h }", map[string]int{held: 1, constrained: 1}},
				{"type parameter of a generic type", "type box[S interface{ *Service }] struct{ s S }", map[string]int{"fixture.go:<package>|whole-constrain": 1}},
				// A type argument is followed although the generic type does not
				// use it: the instance still names the owner.
				{"type parameter constrained to an instance that only names the owner", phantom + "func f[P interface{ *phantom[*Service] }](p P) P { return p }", map[string]int{constrained: 1, "fixture.go:f|whole-instantiate": 1}},
				{"type parameter constrained to an alias of such an instance", phantom + "type aliased = phantom[*Service]; func f[P interface{ *aliased }](p P) P { return p }", map[string]int{constrained: 1, "fixture.go:<package>|whole-instantiate": 1}},
				// A type that refers to itself is followed once.
				{"type parameter constrained to a recursive type that points to the owner", "type node struct{ next *node; s *Service }; func f[N interface{ *node }](n N) N { return n }", map[string]int{constrained: 1}},
				{"type parameter of a local generic function type", "func f(){ type local[S interface{ *Service }] struct{ s S }; var _ *local[*Service] }", map[string]int{constrained: 1, "fixture.go:f|whole-instantiate": 1}},
				// A type of the owner's shape is listed where it is written,
				// whether anything converts to it or not.
				{"same-shape type on its own", twin + "func f(t *twin){ *t = twin{} }", map[string]int{mirrored: 1}},
				{"pointer conversion between two same-shape types", twin + "type third struct{ value int; other int }; func f(t *twin){ (*third)(t).value = 1 }", map[string]int{mirrored: 2}},
				{"same-shape type with other field types", "type near struct{ value string; other bool }", map[string]int{mirrored: 1}},
				{"same-shape type with tags", "type near struct{ value int `k:\"v\"`; other int `k:\"w\"` }", map[string]int{mirrored: 1}},
				{"generic same-shape type", "type near[T any] struct{ value T; other int }", map[string]int{mirrored: 1}},
				{"generic same-shape type reached from a type parameter", "type near[T any] struct{ value T; other int }; func f[S interface{ *Service }](s S){ (*near[int])(s).value = 1 }", map[string]int{mirrored: 1, constrained: 1}},
				{"same-shape type declared inside a function", "func f(){ type local struct{ value int; other int }; var _ *local }", map[string]int{mirror: 1}},
				{"same-shape type as a field type", "type wrap struct{ inner *struct{ value int; other int } }", map[string]int{mirrored: 1}},
				{"same-shape type as a parameter type", "func f(t *struct{ value int; other int }){}", map[string]int{mirror: 1}},
				{"same-shape type in a constraint", "func f[T interface{ *struct{ value int; other int } }](s *Service) T { return T(s) }", map[string]int{mirror: 1, "fixture.go:f|whole-convert": 1}},
				{"same-shape type in an alias declaration", "type near = struct{ value int; other int }", map[string]int{mirrored: 1}},
				{"by-value parameter", "func f(v Service){}", map[string]int{"fixture.go:f|whole-declare": 1}},
				{"unnamed by-value parameter", "func f(Service){}", map[string]int{"fixture.go:f|whole-declare": 1}},
				{"unnamed by-value result", "func f(s *Service) Service { return *s }", map[string]int{"fixture.go:f|whole-declare": 1, "fixture.go:f|whole-read": 1}},
				{"named by-value result", "func f() (v Service) { return }", map[string]int{"fixture.go:f|whole-declare": 1}},
				{"value receiver", "func (v Service) get() int { return v.other }", map[string]int{"fixture.go:Service.get|whole-declare": 1}},
				{"unnamed value receiver", "func (Service) get() {}", map[string]int{"fixture.go:Service.get|whole-declare": 1}},
				{"function type result", "func f(g func() Service){}", map[string]int{"fixture.go:f|whole-declare": 1}},
				{"type switch clause", "func f(x any){ switch v := x.(type) { case Service: _ = &v } }", map[string]int{"fixture.go:f|whole-declare": 1}},
				{"type assertion", "func f(x any){ _ = x.(Service) }", map[string]int{"fixture.go:f|whole-read": 1}},
				{"call result", "func g() *Service { return nil }; func f(){ _ = *g() }", map[string]int{"fixture.go:f|whole-read": 1}},
				{"array declaration", "func f(){ var list [2]Service; _ = &list }", map[string]int{"fixture.go:f|whole-declare": 1}},
				{"slice make", "func f(){ _ = make([]Service, 1) }", map[string]int{"fixture.go:f|whole-declare": 1}},
				{"map make", "func f(){ _ = make(map[string]Service) }", map[string]int{"fixture.go:f|whole-declare": 1}},
				{"channel make", "func f(){ _ = make(chan Service, 1) }", map[string]int{"fixture.go:f|whole-declare": 1}},
				{"slice literal of spelled elements", "func f(){ _ = []Service{{value: 1}} }", map[string]int{"fixture.go:f|initializer": 1}},
				{"slice literal of positional elements", "func f(){ _ = []Service{{1, 2}} }", map[string]int{"fixture.go:f|initializer": 1}},
				{"slice literal of pointers", "func f(){ _ = []*Service{{other: 1}} }", map[string]int{"fixture.go:f|zero-initializer": 1}},
				{"keyed slice literal", "func f(){ _ = []Service{3: {value: 1}} }", map[string]int{"fixture.go:f|zero-initializer": 1, "fixture.go:f|initializer": 1}},
				{"short array literal", "func f(){ _ = [2]Service{{value: 1}} }", map[string]int{"fixture.go:f|zero-initializer": 1, "fixture.go:f|initializer": 1}},
				{"full array literal", "func f(){ _ = [1]Service{{value: 1}} }", map[string]int{"fixture.go:f|initializer": 1}},
				{"map literal element", "func f(){ _ = map[string]Service{\"k\": {other: 1}} }", map[string]int{"fixture.go:f|zero-initializer": 1}},
				{"builtin copy", "func f(dst, src []Service){ copy(dst, src) }", map[string]int{"fixture.go:f|whole-copy": 1}},
				{"builtin clear", "func f(list []Service){ clear(list) }", map[string]int{"fixture.go:f|whole-copy": 1}},
				{"builtin append", "func f(list []Service, v *Service){ _ = append(list, *v) }", map[string]int{"fixture.go:f|whole-copy": 1, "fixture.go:f|whole-read": 1}},
				{"slice element overwrite", "func f(list []Service){ list[0] = Service{value: 1} }", map[string]int{"fixture.go:f|whole-assign": 1, "fixture.go:f|initializer": 1}},
				{"map element overwrite", "func f(m map[string]Service, v *Service){ m[\"k\"] = *v }", map[string]int{"fixture.go:f|whole-assign": 1, "fixture.go:f|whole-read": 1}},
				{"channel send of a value", "func f(c chan Service, v *Service){ c <- *v }", map[string]int{"fixture.go:f|whole-read": 1}},
				{"channel receive of a value", "func f(c chan Service, v *Service){ *v = <-c }", map[string]int{"fixture.go:f|whole-assign": 1, "fixture.go:f|whole-read": 1}},
				{"field holding the owner by value", holder, map[string]int{held: 1}},
				{"holder literal leaving the owner implicit", holder + "func f(){ _ = holder{n: 1} }", map[string]int{held: 1, "fixture.go:f|zero-initializer": 1}},
				{"empty holder literal", holder + "func f(){ _ = &holder{} }", map[string]int{held: 1, "fixture.go:f|zero-initializer": 1}},
				{"holder literal spelling the owner", holder + "func f(){ _ = holder{inner: Service{value: 1}} }", map[string]int{held: 1, "fixture.go:f|initializer": 1}},
				{"holder overwrite", holder + "func f(h *holder){ *h = holder{inner: Service{value: 1}} }", map[string]int{held: 1, "fixture.go:f|whole-assign": 1, "fixture.go:f|initializer": 1}},
				{"owner overwrite inside a holder", holder + "func f(h *holder){ h.inner = Service{} }", map[string]int{held: 1, "fixture.go:f|whole-assign": 1, "fixture.go:f|zero-initializer": 1}},
				{"holder copy", holder + "func f(a, b *holder){ *a = *b }", map[string]int{held: 1, "fixture.go:f|whole-assign": 1, "fixture.go:f|whole-read": 1}},
				{"pointer only", "func f(s *Service) *Service { return s }", map[string]int{}},
				{"other field through a pointer", "func f(s *Service) int { return (*s).other }", map[string]int{}},
				{"address of an element", "func f(list []Service) *Service { return &list[0] }", map[string]int{}},
				{"other field of an element", "func f(list *[2]Service) int { return list[1].other }", map[string]int{}},
				{"slice of pointers", "func f(){ var list []*Service; _ = list }", map[string]int{}},
				{"reslice", "func f(list []Service) []Service { return list[1:] }", map[string]int{}},
				{"holder through a pointer", "type link struct{ inner *Service }; func f(l *link){ *l = link{} }", map[string]int{}},
				{"type of another shape", unrelated + "func f(t *unrelated){ *t = unrelated{} }", map[string]int{}},
				{"pointer conversion between two types of another shape", unrelated + "type third struct{ value int; third int }; func f(t *unrelated){ (*third)(t).value = 1 }", map[string]int{}},
				{"struct with the fields in another order", "type near struct{ other int; value int }", map[string]int{}},
				{"struct with one field more", "type near struct{ value int; other int; more int }", map[string]int{}},
				{"struct with one field fewer", "type near struct{ value int }", map[string]int{}},
				{"struct with an embedded field of the same name", "type value int; type near struct{ value; other int }", map[string]int{}},
				{"struct without fields", "type near struct{}", map[string]int{}},
				{"alias of the owner", "type same = Service; func f(s *same) *Service { return s }", map[string]int{}},
				{"pointer conversion to an interface", "func f(s *Service) any { return any(s) }", map[string]int{}},
				{"generic function instantiated with another type", unrelated + zero + "func f(t *unrelated){ zero(t) }", map[string]int{}},
				{"type parameter without a type term", "func f[S any](s S) S { return s }", map[string]int{}},
				{"type parameter constrained to another type", unrelated + "func f[S interface{ *unrelated }](s S) S { return s }", map[string]int{}},
				{"type parameter constrained to a recursive type", "type ring struct{ next *ring }; func f[R interface{ *ring }](r R) R { return r }", map[string]int{}},
				{"type parameter constrained to an instance that names another type", unrelated + phantom + "func f[P interface{ *phantom[*unrelated] }](p P) P { return p }", map[string]int{}},
				{"type parameter constrained by a method that takes the owner", "func f[S interface{ take(*Service) }](s S) S { return s }", map[string]int{}},
				{"type parameter constrained to a function type", "func f[F interface{ ~func(*Service) }](g F) F { return g }", map[string]int{}},
			} {
				t.Run(test.name, func(t *testing.T) {
					pkg := typeCheckSyntheticProductionPackage(t, "fixture.go", "package admission; "+owner+test.source)
					field := requirePackageStructField(t, pkg, "Service", "value")
					references := pkg.referencesTo(field)
					if err := validateTypedFieldAccessInventory(test.name, references, test.want); err != nil {
						t.Fatal(err)
					}
					// The same occurrences are refused by an inventory that knows only
					// a read of the field, and by the object inventory of its sites.
					if len(test.want) != 0 {
						if err := validateTypedFieldAccessInventory(test.name, references, map[string]int{"fixture.go:f|read": 1}); err == nil {
							t.Fatal("whole-value occurrence passed as a read")
						}
						if err := validateTypedObjectReferenceInventory(test.name, references, map[string]int{}, false); err == nil {
							t.Fatal("whole-value occurrence passed an empty object inventory")
						}
					}
				})
			}
			t.Run("identifier occurrences stay beside whole-value ones", func(t *testing.T) {
				pkg := typeCheckSyntheticProductionPackage(t, "fixture.go", "package admission; "+owner+
					"func f(s *Service, v Service) int { s.value = v.value; *s = v; return s.value }")
				field := requirePackageStructField(t, pkg, "Service", "value")
				references := pkg.referencesTo(field)
				if err := validateTypedFieldAccessInventory("mixed", references, map[string]int{
					"fixture.go:f|assignment": 1, "fixture.go:f|read": 2, "fixture.go:f|whole-declare": 1, "fixture.go:f|whole-assign": 1, "fixture.go:f|whole-read": 1,
				}); err != nil {
					t.Fatal(err)
				}
				if err := validateTypedObjectReferenceInventory("mixed", references, map[string]int{
					"fixture.go:f": 3, "fixture.go:f|whole-declare": 1, "fixture.go:f|whole-assign": 1, "fixture.go:f|whole-read": 1,
				}, true); err != nil {
					t.Fatal(err)
				}
				if err := validateTypedObjectReferenceInventory("mixed", references, map[string]int{"fixture.go:f": 3}, true); err == nil {
					t.Fatal("object inventory ignored the whole-value occurrences")
				}
				if err := validateTypedObjectReferenceInventory("mixed", references, map[string]int{"fixture.go:f": 6}, true); err == nil {
					t.Fatal("object inventory merged whole-value occurrences into the site count")
				}
			})
			t.Run("whole-value occurrence inside a function literal", func(t *testing.T) {
				pkg := typeCheckSyntheticProductionPackage(t, "fixture.go", "package admission; "+owner+"func f(s *Service){ func(){ *s = Service{} }() }")
				field := requirePackageStructField(t, pkg, "Service", "value")
				references := pkg.referencesTo(field)
				if len(references) != 2 || !references[0].insideFuncLiteral || !references[1].insideFuncLiteral {
					t.Fatalf("closure occurrences: %v", references)
				}
				if err := validateTypedFieldAccessInventory("closure", references, map[string]int{"fixture.go:f|whole-assign": 1, "fixture.go:f|zero-initializer": 1}); err == nil {
					t.Fatal("whole-value occurrence inside a function literal passed the field inventory")
				}
				if err := validateTypedFieldAccessInventory("closure", references, map[string]int{"fixture.go:f|whole-assign+closure": 1, "fixture.go:f|zero-initializer+closure": 1}); err != nil {
					t.Fatalf("listed closure occurrences refused: %v", err)
				}
				if err := validateTypedObjectReferenceInventory("closure", references, map[string]int{"fixture.go:f|whole-assign": 1, "fixture.go:f|zero-initializer": 1}, true); err == nil {
					t.Fatal("whole-value occurrence inside a function literal passed the object inventory")
				}
			})
		})
		t.Run("whole-value occurrences of an owning struct in another package", func(t *testing.T) {
			// The declaring package: an owning type with unexported fields, as
			// every protected type has; one whose field names are all exported;
			// and a generic type of the first one's shape, which that package's
			// own inventory lists as a mirror.
			declaring := typeCheckSyntheticProductionPackage(t, "fixture.go", "package admission; "+
				"type Service struct{ value int; other int }; type Open struct{ Value int; Other int }; type Pair[T any] struct{ value T; other int }")
			const header = "package app; import admission \"synthetic/admission\"; var _ *admission.Service; "
			const zero = "func zero[T any](v *T){ var z T; *v = z }; "
			const holder = "type holder struct{ inner admission.Service; n int }; "
			const held = "app.go:<package>|whole-declare"
			const mirrored = "app.go:<package>|whole-mirror"
			for _, test := range []struct {
				name, owner, source string
				want                map[string]int
			}{
				{"overwrite through a pointer", "Service", "func f(s *admission.Service){ *s = admission.Service{} }", map[string]int{"app.go:f|whole-assign": 1, "app.go:f|initializer": 1}},
				{"saved and restored", "Service", "func f(s *admission.Service){ saved := *s; *s = saved }", map[string]int{"app.go:f|whole-declare": 1, "app.go:f|whole-read": 2, "app.go:f|whole-assign": 1}},
				{"copy between pointers", "Service", "func f(a, b *admission.Service){ *a = *b }", map[string]int{"app.go:f|whole-assign": 1, "app.go:f|whole-read": 1}},
				{"package variable", "Service", "var kept admission.Service", map[string]int{held: 1}},
				{"new", "Service", "func f() *admission.Service { return new(admission.Service) }", map[string]int{"app.go:f|whole-declare": 1}},
				{"pointer literal", "Service", "func f() *admission.Service { return &admission.Service{} }", map[string]int{"app.go:f|initializer": 1}},
				{"by-value parameter", "Service", "func f(v admission.Service){}", map[string]int{"app.go:f|whole-declare": 1}},
				{"field holding the owner by value", "Service", holder, map[string]int{held: 1}},
				{"holder overwrite", "Service", holder + "func f(h *holder){ *h = holder{} }", map[string]int{held: 1, "app.go:f|whole-assign": 1, "app.go:f|zero-initializer": 1}},
				{"embedded by value", "Service", "type outer struct{ admission.Service }", map[string]int{held: 1}},
				{"slice make", "Service", "func f() []admission.Service { return make([]admission.Service, 1) }", map[string]int{"app.go:f|whole-declare": 1}},
				{"builtin clear", "Service", "func f(list []admission.Service){ clear(list) }", map[string]int{"app.go:f|whole-copy": 1}},
				{"conversion of a value to an interface", "Service", "func f(s *admission.Service) any { return *s }", map[string]int{"app.go:f|whole-read": 1}},
				{"generic function instantiated with the owner", "Service", zero + "func f(s *admission.Service){ zero(s) }", map[string]int{"app.go:f|whole-instantiate": 1}},
				{"generic type of the declaring package instantiated with the owner", "Service", "var kept *admission.Pair[admission.Service]", map[string]int{"app.go:<package>|whole-instantiate": 1}},
				{"type parameter constrained to the owner", "Service", "func f[S interface{ *admission.Service }](s S) S { return s }", map[string]int{"app.go:f|whole-constrain": 1}},
				{"defined type over the owner", "Service", "type second admission.Service; func f(s *admission.Service) *second { return (*second)(s) }", map[string]int{"app.go:f|whole-convert": 1}},
				{"defined type over the owner by value", "Service", "type second admission.Service; var kept second", map[string]int{held: 1}},
				// The declaring package's generic type has the owner's shape, so a
				// pointer to the owner converts to a pointer to an instance of it.
				{"pointer conversion to an instance of a generic same-shape type", "Service", "func f(s *admission.Service) *admission.Pair[int] { return (*admission.Pair[int])(s) }", map[string]int{"app.go:f|whole-convert": 1}},
				// Another package can write a struct type of an owner's shape only
				// when every field name of the owner is exported.
				{"same-shape type of an owner with exported fields", "Open", "type twin struct{ Value int; Other int }", map[string]int{mirrored: 1}},
				{"pointer conversion to a same-shape type of an owner with exported fields", "Open", "type twin struct{ Value int; Other int }; func f(o *admission.Open){ (*twin)(o).Value = 1 }", map[string]int{mirrored: 1, "app.go:f|whole-convert": 1}},
				{"pointer conversion to an anonymous struct of an owner with exported fields", "Open", "func f(o *admission.Open){ (*struct{ Value int; Other int })(o).Value = 1 }", map[string]int{"app.go:f|whole-mirror": 1, "app.go:f|whole-convert": 1}},
				{"unexported field names of another package", "Service", "type twin struct{ value int; other int }", map[string]int{}},
				{"exported field names in another order", "Open", "type near struct{ Other int; Value int }", map[string]int{}},
				{"pointer only", "Service", "func f(s *admission.Service) *admission.Service { return s }", map[string]int{}},
				{"slice of pointers", "Service", "func f(list []*admission.Service) int { return len(list) }", map[string]int{}},
				{"holder through a pointer", "Service", "type link struct{ inner *admission.Service }; func f(l *link){ *l = link{} }", map[string]int{}},
				{"another type of the declaring package", "Service", "var kept admission.Open", map[string]int{}},
				{"another owner of the declaring package", "Open", "var kept admission.Service", map[string]int{}},
				{"generic function instantiated with another type", "Service", zero + "func f(o *admission.Open){ zero(o) }", map[string]int{}},
				{"type parameter constrained to another type", "Service", "func f[S interface{ *admission.Open }](s S) S { return s }", map[string]int{}},
			} {
				t.Run(test.name, func(t *testing.T) {
					foreign := typeCheckSyntheticImportingPackage(t, "synthetic/app", "app.go", header+test.source, declaring)
					target := owningStruct{shape: owningStructShapeOf(declaring.importPath, requirePackageStruct(t, declaring, test.owner))}
					references := foreign.wholeValueOccurrences(target, nil, "synthetic/admission."+test.owner)
					if err := validateTypedFieldAccessInventory(test.name, references, test.want); err != nil {
						t.Fatal(err)
					}
				})
			}
			// In the declaring package the shape alone does not make a value the
			// owner's: only the owner's own struct does.
			t.Run("the declaring package knows the owner by identity", func(t *testing.T) {
				references := declaring.referencesTo(requirePackageStructField(t, declaring, "Service", "value"))
				if err := validateTypedFieldAccessInventory("declaring", references, map[string]int{"fixture.go:<package>|whole-mirror": 1}); err != nil {
					t.Fatal(err)
				}
			})
			// An owning struct without fields has no storage to reach, so no
			// written struct type is its mirror, here or in another package.
			t.Run("an owning struct without fields", func(t *testing.T) {
				empty := typeCheckSyntheticProductionPackage(t, "fixture.go", "package admission; "+
					"type Marker struct{}; type other struct{}; var kept struct{}; func f(m *Marker) *other { return (*other)(m) }")
				marker := requirePackageStruct(t, empty, "Marker")
				if err := validateTypedFieldAccessInventory("declaring", empty.wholeValueReferences(marker, nil, "Marker"),
					map[string]int{"fixture.go:f|whole-convert": 1}); err != nil {
					t.Fatal(err)
				}
				foreign := typeCheckSyntheticImportingPackage(t, "synthetic/app", "app.go",
					"package app; import admission \"synthetic/admission\"; var _ *admission.Marker; type twin struct{}; var kept struct{}", empty)
				target := owningStruct{shape: owningStructShapeOf(empty.importPath, marker)}
				if references := foreign.wholeValueOccurrences(target, nil, "synthetic/admission.Marker"); len(references) != 0 {
					t.Fatalf("an owner without fields matched %v", references)
				}
			})
			// What cannot be compared is not known to differ: a written struct
			// type for which the type checker recorded no type is listed.
			t.Run("a struct type without a recorded type", func(t *testing.T) {
				const source = "package admission; type Service struct{ value int; other int }; type unrelated struct{ n int }"
				recorded := typeCheckSyntheticProductionPackage(t, "fixture.go", source)
				if err := validateTypedFieldAccessInventory("recorded", recorded.wholeValueReferences(requirePackageStruct(t, recorded, "Service"), nil, "Service"),
					map[string]int{}); err != nil {
					t.Fatal(err)
				}
				unrecorded := typeCheckSyntheticProductionPackage(t, "fixture.go", source)
				removed := 0
				for _, file := range unrecorded.files {
					ast.Inspect(file, func(node ast.Node) bool {
						if written, ok := node.(*ast.StructType); ok && len(written.Fields.List) == 1 {
							delete(unrecorded.info.Types, written)
							removed++
						}
						return true
					})
				}
				if removed != 1 {
					t.Fatalf("removed the recorded type of %d struct types, want 1", removed)
				}
				if err := validateTypedFieldAccessInventory("unrecorded", unrecorded.wholeValueReferences(requirePackageStruct(t, unrecorded, "Service"), nil, "Service"),
					map[string]int{"fixture.go:<package>|whole-mirror": 1}); err != nil {
					t.Fatal(err)
				}
			})
			// The inventory is the union over the build targets: an occurrence
			// that one target alone compiles is listed, and one that every
			// target compiles is listed once.
			t.Run("an occurrence under one build target only", func(t *testing.T) {
				clean := typeCheckSyntheticImportingPackage(t, "synthetic/app", "app.go", header, declaring)
				written := typeCheckSyntheticImportingPackage(t, "synthetic/app", "app.go", header+"var kept admission.Service", declaring)
				without := typedProductionView{packages: []*typedProductionPackage{declaring, clean}}
				with := typedProductionView{packages: []*typedProductionPackage{declaring, written}}
				for name, views := range map[string][]typedProductionView{
					"first target": {with, without, without}, "middle target": {without, with, without}, "last target": {without, without, with},
					"every target": {with, with, with},
				} {
					references := mergedForeignOwningStructReferences(t, views, "synthetic/admission", "Service")
					if err := validateTypedFieldAccessInventory(name, references, map[string]int{held: 1}); err != nil {
						t.Fatal(err)
					}
				}
				if references := mergedForeignOwningStructReferences(t, []typedProductionView{without, without}, "synthetic/admission", "Service"); len(references) != 0 {
					t.Fatalf("a package without an occurrence lists %v", references)
				}
			})
		})
		t.Run("type parameter declarations", func(t *testing.T) {
			pkg := typeCheckSyntheticProductionPackage(t, "fixture.go", "package admission; type Service struct{ value int }; "+
				"func plain(v int) int { return v }; func one[T any](v T) T { return v }; func two[K comparable, V interface{ *Service }](k K, v V){}; "+
				"type cell[T any] struct{ v T }; func (c cell[T]) get() T { return c.v }; func (c *cell[T]) set(v T){ c.v = v }; "+
				"func outer(){ type local[E any] []E; var _ local[int] }; type plainType struct{ v cell[int] }")
			want := []string{
				"fixture.go:<package> type cell[T any]",
				"fixture.go:cell.get[T any]",
				"fixture.go:cell.set[T any]",
				"fixture.go:one[T any]",
				"fixture.go:outer type local[E any]",
				"fixture.go:two[K comparable]",
				"fixture.go:two[V interface{*Service}]",
			}
			if got := pkg.typeParameterDeclarations(); !reflect.DeepEqual(got, want) {
				t.Fatalf("type parameter declarations: got %q want %q", got, want)
			}
			plain := typeCheckSyntheticProductionPackage(t, "fixture.go", "package admission; type Service struct{ value int }; func plain(){}")
			if got := plain.typeParameterDeclarations(); len(got) != 0 {
				t.Fatalf("a package without type parameters lists %q", got)
			}
			// The inventory is the union over the build targets.
			without := typedProductionView{packages: []*typedProductionPackage{plain}}
			with := typedProductionView{packages: []*typedProductionPackage{pkg}}
			for name, views := range map[string][]typedProductionView{
				"first target": {with, without, without}, "middle target": {without, with, without}, "last target": {without, without, with},
				"every target": {with, with, with},
			} {
				if got := mergedTypeParameterDeclarations(t, views, "synthetic/admission"); !reflect.DeepEqual(got, want) {
					t.Fatalf("%s: type parameter declarations: got %q want %q", name, got, want)
				}
			}
			if got := mergedTypeParameterDeclarations(t, []typedProductionView{without, without}, "synthetic/admission"); len(got) != 0 {
				t.Fatalf("targets without type parameters list %q", got)
			}
		})
	})
}

// productionStructDeclarationText returns the file that declares the named
// struct type and the text of its struct type, as written.
func productionStructDeclarationText(t *testing.T, pkg *typedProductionPackage, typeName string) (string, string) {
	t.Helper()
	for fileName, file := range pkg.files {
		for _, declaration := range file.Decls {
			general, ok := declaration.(*ast.GenDecl)
			if !ok {
				continue
			}
			for _, spec := range general.Specs {
				named, ok := spec.(*ast.TypeSpec)
				if !ok || named.Name.Name != typeName {
					continue
				}
				structure, ok := named.Type.(*ast.StructType)
				if !ok {
					t.Fatalf("%s.%s is not declared as a struct type", pkg.importPath, typeName)
				}
				source := pkg.sources[fileName]
				return fileName, source[pkg.fset.Position(structure.Pos()).Offset:pkg.fset.Position(structure.End()).Offset]
			}
		}
	}
	t.Fatalf("%s.%s declaration was not found", pkg.importPath, typeName)
	return "", ""
}

// repositoryProductionListings lists the files of every directory of the
// repository and reads the non-test Go sources among them, whatever their
// build constraints. No directory name is left out except .git, whose content
// no commit can carry. A wildcard pattern such as ./... does not match a
// directory named testdata or one whose name begins with a dot or an
// underscore, but the go command compiles a package from such a directory as
// soon as another package imports it, so those are read like every other. A
// vendor directory or a nested module is read as well and fails the tree
// check.
func repositoryProductionListings(t *testing.T, root string) (map[string][]string, map[string]string) {
	t.Helper()
	listings := make(map[string][]string)
	sources := make(map[string]string)
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		relative = filepath.ToSlash(relative)
		if entry.IsDir() {
			if path != root && entry.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		directory := filepath.ToSlash(filepath.Dir(relative))
		listings[directory] = append(listings[directory], entry.Name())
		if strings.HasSuffix(entry.Name(), ".go") && !strings.HasSuffix(entry.Name(), "_test.go") {
			contents, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			sources[relative] = string(contents)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return listings, sources
}

// operationalGuardImportInventory lists, for every production source file of
// the module, the imports through which storage can be written without any
// syntax the typed inventories classify.
func operationalGuardImportInventory(sources map[string]string) (map[string][]string, error) {
	inventory := make(map[string][]string)
	for name, source := range sources {
		file, err := parser.ParseFile(token.NewFileSet(), name, source, parser.ImportsOnly)
		if err != nil {
			return nil, err
		}
		for _, spec := range file.Imports {
			path, err := strconv.Unquote(spec.Path.Value)
			if err != nil {
				return nil, err
			}
			if path == "reflect" || path == "unsafe" || path == "C" {
				inventory[name] = append(inventory[name], path)
			}
		}
		sort.Strings(inventory[name])
	}
	return inventory, nil
}

// operationalGuardImportPins names, for every production source file that
// imports reflect, unsafe or C, those imports and the SHA-256 of the file. The
// imports alone say which files can write storage past the typed inventories,
// not what those files do with it. The hash makes every change to such a file
// a change of this inventory.
func operationalGuardImportPins(sources map[string]string) (map[string]string, error) {
	inventory, err := operationalGuardImportInventory(sources)
	if err != nil {
		return nil, err
	}
	pins := make(map[string]string, len(inventory))
	for name, imports := range inventory {
		pins[name] = fmt.Sprintf("%s sha256:%x", strings.Join(imports, ","), sha256.Sum256([]byte(sources[name])))
	}
	return pins, nil
}

// The typed inventories cannot follow reflection, unsafe or cgo. This exact
// inventory makes a new import of any of them a visible, reviewed change in
// every production package of the module: a package that holds a pointer to an
// owning type can write its storage through any of the three. It reads every
// non-test source file of every directory of the repository, whatever its
// build constraints, and holds each listed file by the hash of its content.
func TestOperationalGuardReflectUnsafeImportInventoryIsExact(t *testing.T) {
	_, sources := repositoryProductionListings(t, repositoryRootForAdmissionGuard(t))
	if len(sources) < 100 {
		t.Fatalf("read only %d production sources", len(sources))
	}
	for _, name := range []string{"es/admission/service.go", "es/admission/internal/reliablesubmit/operational_handoff.go", "es/app/app.go", "cmd/es/main.go"} {
		if _, ok := sources[name]; !ok {
			t.Fatalf("%s was not read", name)
		}
	}
	want := map[string]string{
		"es/admission/execution_roots_darwin.go": "unsafe sha256:ef4eb848684af759689740b9c7526dccff3a8c063fb3cf55485fa60ecd78531c",
		"es/runtimehelper/privilege_linux.go":    "unsafe sha256:e7c05914ec8734e71d23147c99ed7a3c330110130f470a252c3835806e9f8c60",
	}
	got, err := operationalGuardImportPins(sources)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("reflect, unsafe and cgo import inventory changed, or a listed file did: got %v want %v", got, want)
	}
	mutations := map[string]string{
		"reflect":         "package admission\nimport \"reflect\"\nvar _ = reflect.TypeOf\n",
		"unsafe":          "package admission\nimport \"unsafe\"\nvar _ unsafe.Pointer\n",
		"renamed unsafe":  "package admission\nimport hidden \"unsafe\"\nvar _ hidden.Pointer\n",
		"blank unsafe":    "package admission\nimport _ \"unsafe\"\n",
		"grouped reflect": "package admission\nimport (\n\t\"fmt\"\n\t\"reflect\"\n)\nvar _ = fmt.Sprint\nvar _ = reflect.TypeOf\n",
		"cgo":             "package admission\nimport \"C\"\n",
	}
	for name, mutation := range mutations {
		// In a guarded package, in two packages that hold a pointer to an
		// owning type without declaring one, and in the directories that no
		// wildcard pattern matches.
		for _, added := range []string{"es/admission/added.go", "es/app/added.go", "cmd/es/added.go",
			"es/app/testdata/added/added.go", "es/app/_added/added.go", "es/app/.added/added.go"} {
			t.Run(name+" in "+filepath.Dir(added), func(t *testing.T) {
				mutated := make(map[string]string, len(sources)+1)
				for file, source := range sources {
					mutated[file] = source
				}
				mutated[added] = mutation
				got, err := operationalGuardImportPins(mutated)
				if err != nil {
					t.Fatal(err)
				}
				if reflect.DeepEqual(got, want) {
					t.Fatal("a new reflect, unsafe or cgo import passed the inventory")
				}
			})
		}
	}
	for known := range want {
		t.Run("removed known import "+known, func(t *testing.T) {
			mutated := make(map[string]string, len(sources))
			for file, source := range sources {
				mutated[file] = source
			}
			delete(mutated, known)
			got, err := operationalGuardImportPins(mutated)
			if err != nil {
				t.Fatal(err)
			}
			if reflect.DeepEqual(got, want) {
				t.Fatal("the inventory did not depend on the known unsafe import")
			}
		})
		// The import list of the file is unchanged in both cases: only the hash
		// can tell.
		for name, change := range map[string]func(string) string{
			"a function added to": func(source string) string { return source + "\nfunc zzAdded() {}\n" },
			"one byte changed in": func(source string) string { return source + " " },
		} {
			t.Run(name+" "+known, func(t *testing.T) {
				mutated := make(map[string]string, len(sources))
				for file, source := range sources {
					mutated[file] = source
				}
				mutated[known] = change(sources[known])
				inventory, err := operationalGuardImportInventory(mutated)
				if err != nil {
					t.Fatal(err)
				}
				if !reflect.DeepEqual(inventory[known], []string{"unsafe"}) {
					t.Fatalf("the change altered the import list: %v", inventory[known])
				}
				got, err := operationalGuardImportPins(mutated)
				if err != nil {
					t.Fatal(err)
				}
				if reflect.DeepEqual(got, want) {
					t.Fatal("a changed file that imports unsafe passed the inventory")
				}
			})
		}
	}
	t.Run("a change to a file without such an import", func(t *testing.T) {
		mutated := make(map[string]string, len(sources))
		for file, source := range sources {
			mutated[file] = source
		}
		mutated["es/app/app.go"] += "\nfunc zzAdded() {}\n"
		got, err := operationalGuardImportPins(mutated)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("a file without such an import is held by a hash: %v", got)
		}
	})
}

// The admission state package is one production file, and the guard holds it
// by the hash of its content. Whatever the package does to the state it does
// in that file, so every change to it is a change of this constant in the
// same commit, and a second production file, or a file of another language,
// is refused. Test files are not held.
const operationalAdmissionStateDirectory = "es/admission/internal/admissionstate"
const operationalAdmissionStatePin = "sha256:e18a153eb0115085fec9a80b049ddbd44cd2aa59a8410792951c3c392368dc8f"

func validateOperationalAdmissionStatePackage(listings map[string][]string, sources map[string]string, pin string) error {
	entries, ok := listings[operationalAdmissionStateDirectory]
	if !ok {
		return fmt.Errorf("%s was not listed", operationalAdmissionStateDirectory)
	}
	for directory := range listings {
		if strings.HasPrefix(directory, operationalAdmissionStateDirectory+"/") {
			return fmt.Errorf("%s is a directory below the admission state package", directory)
		}
	}
	const file = "state.go"
	found := false
	for _, name := range entries {
		switch {
		case name == file:
			found = true
		case strings.HasSuffix(name, "_test.go"):
		default:
			return fmt.Errorf("%s/%s is a second file of the admission state package", operationalAdmissionStateDirectory, name)
		}
	}
	source, read := sources[operationalAdmissionStateDirectory+"/"+file]
	if !found || !read {
		return fmt.Errorf("%s/%s is missing", operationalAdmissionStateDirectory, file)
	}
	if got := fmt.Sprintf("sha256:%x", sha256.Sum256([]byte(source))); got != pin {
		return fmt.Errorf("%s/%s changed: its content is %s and the reviewed content is %s", operationalAdmissionStateDirectory, file, got, pin)
	}
	return nil
}

func TestOperationalAdmissionStatePackageIsOneReviewedFile(t *testing.T) {
	listings, sources := repositoryProductionListings(t, repositoryRootForAdmissionGuard(t))
	if err := validateOperationalAdmissionStatePackage(listings, sources, operationalAdmissionStatePin); err != nil {
		t.Fatal(err)
	}
	const file = operationalAdmissionStateDirectory + "/state.go"
	// The file is among those the import inventory reads, and it imports
	// none of reflect, unsafe and C.
	imports, err := operationalGuardImportInventory(map[string]string{file: sources[file]})
	if err != nil || len(imports) != 0 {
		t.Fatalf("the admission state file imports reflect, unsafe or C: %v %v", imports, err)
	}
	copied := func() (map[string][]string, map[string]string) {
		l := make(map[string][]string, len(listings))
		for directory, entries := range listings {
			l[directory] = append([]string(nil), entries...)
		}
		s := make(map[string]string, len(sources))
		for name, source := range sources {
			s[name] = source
		}
		return l, s
	}
	for name, change := range map[string]func(map[string][]string, map[string]string){
		"a function added to the file":   func(_ map[string][]string, s map[string]string) { s[file] += "\nfunc zzAdded() {}\n" },
		"one byte changed in the file":   func(_ map[string][]string, s map[string]string) { s[file] += " " },
		"one byte removed from the file": func(_ map[string][]string, s map[string]string) { s[file] = s[file][:len(s[file])-1] },
		"a second production file": func(l map[string][]string, s map[string]string) {
			l[operationalAdmissionStateDirectory] = append(l[operationalAdmissionStateDirectory], "added.go")
			s[operationalAdmissionStateDirectory+"/added.go"] = "package admissionstate\n"
		},
		"a second file that only one platform builds": func(l map[string][]string, s map[string]string) {
			l[operationalAdmissionStateDirectory] = append(l[operationalAdmissionStateDirectory], "added_windows.go")
			s[operationalAdmissionStateDirectory+"/added_windows.go"] = "package admissionstate\n"
		},
		"an assembly file": func(l map[string][]string, _ map[string]string) {
			l[operationalAdmissionStateDirectory] = append(l[operationalAdmissionStateDirectory], "state_amd64.s")
		},
		"a file without a name ending": func(l map[string][]string, _ map[string]string) {
			l[operationalAdmissionStateDirectory] = append(l[operationalAdmissionStateDirectory], "state")
		},
		"a file whose name only ends like a test": func(l map[string][]string, _ map[string]string) {
			l[operationalAdmissionStateDirectory] = append(l[operationalAdmissionStateDirectory], "state_test.go.s")
		},
		"a directory below the package": func(l map[string][]string, _ map[string]string) {
			l[operationalAdmissionStateDirectory+"/inner"] = []string{"inner.go"}
		},
		"the file renamed": func(l map[string][]string, s map[string]string) {
			l[operationalAdmissionStateDirectory] = []string{"moved.go", "state_test.go"}
			s[operationalAdmissionStateDirectory+"/moved.go"] = s[file]
			delete(s, file)
		},
		"the file gone, the tests left": func(l map[string][]string, s map[string]string) {
			l[operationalAdmissionStateDirectory] = []string{"state_test.go"}
			delete(s, file)
		},
		"the directory gone": func(l map[string][]string, s map[string]string) {
			delete(l, operationalAdmissionStateDirectory)
			delete(s, file)
		},
	} {
		t.Run(name, func(t *testing.T) {
			l, s := copied()
			change(l, s)
			if err := validateOperationalAdmissionStatePackage(l, s, operationalAdmissionStatePin); err == nil {
				t.Fatal("the change passed")
			}
		})
	}
	// Controls: test files come and go freely, and so does a file elsewhere.
	for name, change := range map[string]func(map[string][]string, map[string]string){
		"a second test file": func(l map[string][]string, _ map[string]string) {
			l[operationalAdmissionStateDirectory] = append(l[operationalAdmissionStateDirectory], "more_test.go")
		},
		"no test file": func(l map[string][]string, _ map[string]string) {
			l[operationalAdmissionStateDirectory] = []string{"state.go"}
		},
		"a file changed in another package": func(_ map[string][]string, s map[string]string) { s["es/app/app.go"] += "\nfunc zzAdded() {}\n" },
		"a directory beside the package": func(l map[string][]string, _ map[string]string) {
			l[operationalAdmissionStateDirectory+"x"] = []string{"x.go"}
		},
	} {
		t.Run("control: "+name, func(t *testing.T) {
			l, s := copied()
			change(l, s)
			if err := validateOperationalAdmissionStatePackage(l, s, operationalAdmissionStatePin); err != nil {
				t.Fatalf("refused: %v", err)
			}
		})
	}
	// A pin of another content refuses the file as it is.
	if err := validateOperationalAdmissionStatePackage(listings, sources, "sha256:"+strings.Repeat("0", 64)); err == nil {
		t.Fatal("the file passed under another pin")
	}
}

// validateGuardedProductionFileSet compares the entries of one directory with
// the files the typed loader read for it under its build targets. A Go file
// that no target includes stands behind a build constraint the guards do not
// evaluate, so nothing in it is inventoried while a build with that constraint
// compiles it. A source file of another language is compiled into the package
// without the type checker reading it.
func validateGuardedProductionFileSet(directory string, entries []string, loaded map[string]bool) error {
	present := make(map[string]bool, len(entries))
	for _, name := range entries {
		present[directory+"/"+name] = true
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		if strings.HasSuffix(name, ".go") {
			if !loaded[directory+"/"+name] {
				return fmt.Errorf("%s/%s is built for none of the guarded targets: the typed inventories do not read it", directory, name)
			}
			continue
		}
		switch strings.ToLower(filepath.Ext(name)) {
		case ".s", ".sx", ".c", ".cc", ".cpp", ".cxx", ".m", ".h", ".hh", ".hpp", ".hxx", ".f", ".for", ".f90", ".swig", ".swigcxx", ".syso":
			return fmt.Errorf("%s/%s is a source or object file the typed inventories cannot read", directory, name)
		}
	}
	for name := range loaded {
		if strings.HasPrefix(name, directory+"/") && !strings.Contains(strings.TrimPrefix(name, directory+"/"), "/") && !present[name] {
			return fmt.Errorf("%s was type-checked but is not in the directory listing", name)
		}
	}
	return nil
}

// validateGuardedProductionTree applies the file-set check to every listed
// directory of a repository, in both directions, and refuses the two files
// that make the go command compile a module from somewhere else: a workspace
// file, and a go.mod below the root, which a replace line or a workspace
// turns into part of the build.
func validateGuardedProductionTree(listings map[string][]string, loaded map[string]bool) error {
	for directory, entries := range listings {
		for _, name := range entries {
			if name == "go.work" || name == "go.work.sum" {
				return fmt.Errorf("%s/%s is a workspace file: it changes which modules the go command compiles", directory, name)
			}
			if name == "go.mod" && directory != "." {
				return fmt.Errorf("%s/go.mod declares a nested module, which no pattern of this module matches", directory)
			}
		}
		if directory == "." {
			// The repository root holds tests and documents only. Its paths
			// have no directory part.
			for _, name := range entries {
				if err := validateGuardedProductionFileSet(".", []string{name}, map[string]bool{}); err != nil {
					return err
				}
			}
			continue
		}
		if err := validateGuardedProductionFileSet(directory, entries, loaded); err != nil {
			return err
		}
	}
	for name := range loaded {
		if directory := filepath.ToSlash(filepath.Dir(name)); listings[directory] == nil {
			return fmt.Errorf("%s was type-checked but its directory was not listed", name)
		}
	}
	return nil
}

// goModDirectiveKinds returns the distinct keywords of the directives of a
// go.mod file, sorted. A replace, exclude, toolchain, godebug, tool or ignore
// directive changes what the go command compiles or how, so the kinds a
// go.mod uses are held as an exact list.
func goModDirectiveKinds(contents string) []string {
	kinds := make(map[string]bool)
	block := ""
	for _, line := range strings.Split(contents, "\n") {
		if comment := strings.Index(line, "//"); comment >= 0 {
			line = line[:comment]
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if block != "" {
			if strings.HasPrefix(line, ")") {
				block = ""
				continue
			}
			kinds[block] = true
			continue
		}
		keyword := line
		if end := strings.IndexAny(line, " \t("); end >= 0 {
			keyword = line[:end]
		}
		kinds[keyword] = true
		if rest := strings.TrimSpace(strings.TrimPrefix(line, keyword)); strings.HasPrefix(rest, "(") && !strings.Contains(rest, ")") {
			block = keyword
		}
	}
	sorted := make([]string, 0, len(kinds))
	for kind := range kinds {
		sorted = append(sorted, kind)
	}
	sort.Strings(sorted)
	return sorted
}

func typedProductionFileSet(views []typedProductionView) map[string]bool {
	loaded := make(map[string]bool)
	for _, view := range views {
		for _, pkg := range view.packages {
			for fileName := range pkg.files {
				loaded[fileName] = true
			}
		}
	}
	return loaded
}

// writeGuardProbeModule writes a small module to a new directory and returns
// its root with symbolic links resolved, as the go command reports it. The
// files are named by their slash-separated path. A go.mod is added unless one
// is given.
func writeGuardProbeModule(t *testing.T, files map[string]string) string {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	root = filepath.Join(root, "module")
	if _, ok := files["go.mod"]; !ok {
		files["go.mod"] = guardProbeGoMod(t, "")
	}
	for name, contents := range files {
		path := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

// guardProbeGoMod is the go.mod of a probe module, with the go line of the
// repository's own go.mod and the given further lines.
func guardProbeGoMod(t *testing.T, more string) string {
	t.Helper()
	contents, err := os.ReadFile(filepath.Join(repositoryRootForAdmissionGuard(t), "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(contents), "\n") {
		if strings.HasPrefix(line, "go ") {
			return "module guardprobe\n\n" + line + "\n" + more
		}
	}
	t.Fatal("the repository's go.mod has no go line")
	return ""
}

// The typed inventories read the packages the go command compiles from the
// repository for three build targets. This test makes sure that is every
// production file in it: a file behind any other build constraint, a Go file
// that no compiled package holds, whatever its directory is called, and an
// assembly, C or object file, fail it. So do the forms that make the go
// command compile from somewhere the inventories do not read: a directive of
// go.mod other than the listed kinds, a workspace file and a nested module.
func TestOperationalGuardLoadsEveryProductionFile(t *testing.T) {
	root := repositoryRootForAdmissionGuard(t)
	views := loadTypedProductionPackages(t, "./...")
	loaded := typedProductionFileSet(views)
	listings, sources := repositoryProductionListings(t, root)
	// The floor only shows that both sides were read at all. The comparison is
	// the file-set check below, in both directions.
	if len(loaded) < 100 || len(sources) < 100 {
		t.Fatalf("the typed loader read %d production sources, the listing holds %d", len(loaded), len(sources))
	}
	validate := func(listings map[string][]string) error {
		return validateGuardedProductionTree(listings, loaded)
	}
	if err := validate(listings); err != nil {
		t.Fatal(err)
	}
	// A replace line makes the go command compile a module from a local
	// directory or from another origin, an exclude line changes which version
	// of a dependency it selects, and the other kinds change the toolchain or
	// its settings. None exists today, so each is a reviewed change here.
	goMod, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	if got, want := goModDirectiveKinds(string(goMod)), []string{"go", "module", "require"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("directive kinds of go.mod: got %v want %v", got, want)
	}
	for _, directory := range []string{"es/admission", "es/admission/internal/reliablesubmit", "es/app", "cmd/es"} {
		if len(listings[directory]) == 0 {
			t.Fatalf("%s was not listed", directory)
		}
	}
	with := func(directory string, added string) map[string][]string {
		changed := make(map[string][]string, len(listings)+1)
		for name, entries := range listings {
			changed[name] = entries
		}
		changed[directory] = append(append([]string{}, listings[directory]...), added)
		return changed
	}
	// In a guarded package, in a package that holds a pointer to an owning
	// type, in the repository root, in a directory without any package, and in
	// the directories that no wildcard pattern matches.
	for _, directory := range []string{"es/admission", "es/app", ".", "es/admission/zzadded",
		"es/app/testdata/zzadded", "es/app/_zzadded", "es/app/.zzadded", "vendor/example.com/zzadded"} {
		for name, added := range map[string]string{
			"file behind a custom build tag": "zz_tagged.go",
			"file for another platform":      "zz_windows.go",
			"assembly file":                  "zz_amd64.s",
			"preprocessed assembly file":     "zz_amd64.S",
			"C file":                         "zz.c",
			"object file":                    "zz.syso",
		} {
			t.Run(name+" in "+directory, func(t *testing.T) {
				if err := validate(with(directory, added)); err == nil {
					t.Fatalf("%s passed the file-set check", added)
				}
			})
		}
		for name, added := range map[string]string{
			"test file behind a custom build tag": "zz_tagged_test.go",
			"document":                            "README.md",
		} {
			t.Run(name+" in "+directory, func(t *testing.T) {
				if err := validate(with(directory, added)); err != nil {
					t.Fatalf("%s was refused: %v", added, err)
				}
			})
		}
	}
	t.Run("type-checked file missing from the listing", func(t *testing.T) {
		const directory = "es/admission"
		var shortened []string
		removed := false
		for _, name := range listings[directory] {
			if !removed && loaded[directory+"/"+name] {
				removed = true
				continue
			}
			shortened = append(shortened, name)
		}
		if !removed {
			t.Fatal("no type-checked file in the listing")
		}
		changed := with(directory, "README.md")
		changed[directory] = shortened
		if err := validate(changed); err == nil {
			t.Fatal("a listing without a type-checked file passed")
		}
	})
	t.Run("type-checked directory missing from the listing", func(t *testing.T) {
		changed := with("es/app", "README.md")
		delete(changed, "es/app")
		if err := validate(changed); err == nil {
			t.Fatal("a listing without a type-checked directory passed")
		}
	})
	t.Run("every directory but .git is listed", func(t *testing.T) {
		// A checkout whose own directory has any of these names is read like
		// any other: only a .git below the root is left out.
		for _, rootName := range []string{"checkout", "_checkout", ".checkout", "testdata", ".git"} {
			scratch := filepath.Join(t.TempDir(), rootName)
			for _, name := range []string{"pkg/kept.go", "pkg/kept_test.go", "pkg/testdata/fixture.go", "pkg/.hidden/hidden.go", "pkg/_ignored/ignored.go",
				"pkg/vendor/dep/dep.go", "pkg/.git/planted.go", ".git/planted/planted.go", "top.go"} {
				if err := os.MkdirAll(filepath.Join(scratch, filepath.Dir(name)), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(scratch, name), []byte("package p\n"), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			listings, sources := repositoryProductionListings(t, scratch)
			if want := map[string][]string{".": {"top.go"}, "pkg": {"kept.go", "kept_test.go"}, "pkg/testdata": {"fixture.go"},
				"pkg/.hidden": {"hidden.go"}, "pkg/_ignored": {"ignored.go"}, "pkg/vendor/dep": {"dep.go"}}; !reflect.DeepEqual(listings, want) {
				t.Fatalf("root %s: listings: got %v want %v", rootName, listings, want)
			}
			if want := map[string]string{"top.go": "package p\n", "pkg/kept.go": "package p\n", "pkg/testdata/fixture.go": "package p\n",
				"pkg/.hidden/hidden.go": "package p\n", "pkg/_ignored/ignored.go": "package p\n", "pkg/vendor/dep/dep.go": "package p\n"}; !reflect.DeepEqual(sources, want) {
				t.Fatalf("root %s: sources: got %v want %v", rootName, sources, want)
			}
		}
	})
	t.Run("workspace files and nested modules", func(t *testing.T) {
		for name, test := range map[string]struct {
			directory, added string
			refused          bool
		}{
			"workspace file at the root":          {".", "go.work", true},
			"workspace sum at the root":           {".", "go.work.sum", true},
			"workspace file below the root":       {"es/app", "go.work", true},
			"nested module":                       {"es/app/testdata/zzmod", "go.mod", true},
			"nested module in a production place": {"es/app", "go.mod", true},
			"the module's own go.mod":             {".", "go.mod", false},
			"the module's own go.sum":             {".", "go.sum", false},
			"a go.sum below the root":             {"es/app", "go.sum", false},
		} {
			t.Run(name, func(t *testing.T) {
				err := validate(with(test.directory, test.added))
				if test.refused && err == nil {
					t.Fatalf("%s/%s passed the tree check", test.directory, test.added)
				}
				if !test.refused && err != nil {
					t.Fatalf("%s/%s was refused: %v", test.directory, test.added, err)
				}
			})
		}
	})
	t.Run("directive kinds of go.mod", func(t *testing.T) {
		const head = "module m\n\ngo 1.26\n\nrequire a v1.0.0\n"
		for name, test := range map[string]struct {
			contents string
			want     []string
		}{
			"today's kinds":                  {head, []string{"go", "module", "require"}},
			"require block":                  {head + "require (\n\tb v1.0.0\n\tc v1.0.0 // indirect\n)\n", []string{"go", "module", "require"}},
			"replace line":                   {head + "replace a => ./local\n", []string{"go", "module", "replace", "require"}},
			"replace line to another origin": {head + "replace a => example.com/fork v1.0.1\n", []string{"go", "module", "replace", "require"}},
			"replace block":                  {head + "replace (\n\ta => ./local\n)\n", []string{"go", "module", "replace", "require"}},
			"replace block without a space":  {head + "replace(\n\ta => ./local\n)\n", []string{"go", "module", "replace", "require"}},
			"indented replace line":          {head + "\treplace a => ./local\n", []string{"go", "module", "replace", "require"}},
			"replace line after a block":     {head + "require (\n\tb v1.0.0\n)\nreplace a => ./local\n", []string{"go", "module", "replace", "require"}},
			"exclude line":                   {head + "exclude a v1.0.0\n", []string{"exclude", "go", "module", "require"}},
			"toolchain line":                 {head + "toolchain go1.26.5\n", []string{"go", "module", "require", "toolchain"}},
			"godebug line":                   {head + "godebug default=go1.21\n", []string{"go", "godebug", "module", "require"}},
			"tool line":                      {head + "tool example.com/cmd\n", []string{"go", "module", "require", "tool"}},
			"ignore line":                    {head + "ignore ./es/app\n", []string{"go", "ignore", "module", "require"}},
			"retract line":                   {head + "retract v1.0.0\n", []string{"go", "module", "require", "retract"}},
			"replace in a comment only":      {head + "// replace a => ./local\nrequire b v1.0.0 // replace\n", []string{"go", "module", "require"}},
			// A comment ends at the line end, also behind the bracket that opens a
			// block and with a bracket of its own.
			"require block opened before a comment": {head + "require ( // direct (see the plan)\n\tb v1.0.0\n)\n", []string{"go", "module", "require"}},
			"replace block opened before a comment": {head + "replace ( // local (for now)\n\ta => ./local\n)\n", []string{"go", "module", "replace", "require"}},
			"windows line ends":                     {"module m\r\ngo 1.26\r\nreplace a => ./local\r\n", []string{"go", "module", "replace"}},
		} {
			t.Run(name, func(t *testing.T) {
				if got := goModDirectiveKinds(test.contents); !reflect.DeepEqual(got, test.want) {
					t.Fatalf("got %v want %v", got, test.want)
				}
			})
		}
	})
	t.Run("packages are selected by their directory", func(t *testing.T) {
		const repository, cache = "/work/repository", "/home/go/pkg/mod"
		closure := map[string]goListProductionPackage{
			"fmt":                             {ImportPath: "fmt", Dir: "/usr/local/go/src/fmt", Standard: true, DepOnly: true},
			"example.com/dep":                 {ImportPath: "example.com/dep", Dir: cache + "/example.com/dep@v1.0.0", DepOnly: true},
			"m/es/app":                        {ImportPath: "m/es/app", Dir: repository + "/es/app"},
			"m/es/app/testdata/hidden":        {ImportPath: "m/es/app/testdata/hidden", Dir: repository + "/es/app/testdata/hidden", DepOnly: true},
			"m/es/app/_hidden":                {ImportPath: "m/es/app/_hidden", Dir: repository + "/es/app/_hidden", DepOnly: true},
			"m/es/app/.hidden":                {ImportPath: "m/es/app/.hidden", Dir: repository + "/es/app/.hidden", DepOnly: true},
			"nested/other":                    {ImportPath: "nested/other", Dir: repository + "/es/app/testdata/nested/other", DepOnly: true},
			"m":                               {ImportPath: "m", Dir: repository},
			"m/matched/by/a/narrower/pattern": {ImportPath: "m/dep", Dir: repository + "/dep", DepOnly: true},
		}
		names := func(selected []goListProductionPackage) []string {
			var paths []string
			for _, item := range selected {
				paths = append(paths, item.ImportPath)
			}
			return paths
		}
		selected, err := selectCompiledRepositoryPackages(repository, cache, closure)
		if err != nil {
			t.Fatal(err)
		}
		if got, want := names(selected), []string{"m", "m/dep", "m/es/app", "m/es/app/.hidden", "m/es/app/_hidden", "m/es/app/testdata/hidden", "nested/other"}; !reflect.DeepEqual(got, want) {
			t.Fatalf("selected: got %v want %v", got, want)
		}
		for name, outside := range map[string]goListProductionPackage{
			"a directory beside the repository":       {ImportPath: "other/pkg", Dir: "/work/other/pkg", DepOnly: true},
			"a directory whose name extends the root": {ImportPath: "other/pkg", Dir: repository + "-copy/pkg", DepOnly: true},
			"a directory above the repository":        {ImportPath: "other/pkg", Dir: "/work", DepOnly: true},
			"no directory":                            {ImportPath: "other/pkg", DepOnly: true},
			"a matched package outside":               {ImportPath: "m/outside", Dir: "/elsewhere/outside"},
		} {
			t.Run(name, func(t *testing.T) {
				changed := map[string]goListProductionPackage{"other/pkg": outside}
				for path, item := range closure {
					changed[path] = item
				}
				if selected, err := selectCompiledRepositoryPackages(repository, cache, changed); err == nil {
					t.Fatalf("a package outside the repository and the module cache was accepted: %v", names(selected))
				}
			})
		}
		t.Run("a module cache inside the repository is not read", func(t *testing.T) {
			inside := repository + "/.cache/mod"
			changed := map[string]goListProductionPackage{"example.com/dep": {ImportPath: "example.com/dep", Dir: inside + "/example.com/dep@v1.0.0", DepOnly: true}}
			for path, item := range closure {
				if path != "example.com/dep" {
					changed[path] = item
				}
			}
			selected, err := selectCompiledRepositoryPackages(repository, inside, changed)
			if err != nil {
				t.Fatal(err)
			}
			if got := names(selected); len(got) != 7 {
				t.Fatalf("selected: %v", got)
			}
		})
	})
	// The rule on the real go command: a small module on disk whose ordinary
	// package imports packages from the directories that no wildcard pattern
	// matches. Each of them is compiled, so each has to be read by the loader,
	// by the whole-value inventory of the other packages, by the import
	// inventory and by the tree check.
	const probeOwner = "package owner\n\ntype Service struct {\n\tlatch bool\n\tview  *int\n}\n\nfunc New() *Service { return &Service{} }\n"
	const probeApp = "package app\n\nimport (\n\tdot \"guardprobe/app/.dot\"\n\tunder \"guardprobe/app/_under\"\n\t\"guardprobe/app/testdata/td\"\n\t\"guardprobe/owner\"\n)\n\nfunc Run(s *owner.Service) {\n\ttd.Reopen(s)\n\tunder.Keep(s)\n\tdot.Keep(s)\n}\n"
	probeFiles := func() map[string]string {
		return map[string]string{
			"owner/owner.go": probeOwner,
			"app/app.go":     probeApp,
			// With reflect and unsafe.
			"app/testdata/td/td.go": "package td\n\nimport (\n\t\"reflect\"\n\t\"unsafe\"\n\n\t\"guardprobe/owner\"\n)\n\nfunc Reopen(s *owner.Service) {\n\t_ = reflect.TypeOf(s)\n\t_ = unsafe.Pointer(s)\n\t*s = owner.Service{}\n}\n",
			// Without either: a saved and restored whole value.
			"app/_under/under.go": "package under\n\nimport \"guardprobe/owner\"\n\nfunc Keep(s *owner.Service) {\n\tsaved := *s\n\t*s = saved\n}\n",
			// Without either: a holder by value.
			"app/.dot/dot.go": "package dot\n\nimport \"guardprobe/owner\"\n\ntype holder struct{ value owner.Service }\n\nfunc Keep(s *owner.Service) { _ = holder{value: *s} }\n",
		}
	}
	importPaths := func(view typedProductionView) []string {
		var paths []string
		for _, pkg := range view.packages {
			paths = append(paths, pkg.importPath)
		}
		return paths
	}
	t.Run("packages compiled from directories that no pattern matches", func(t *testing.T) {
		probeRoot := writeGuardProbeModule(t, probeFiles())
		probeViews := loadTypedProductionPackagesAt(t, probeRoot, "./...")
		if len(probeViews) != 3 {
			t.Fatalf("loaded %d build targets", len(probeViews))
		}
		for _, view := range probeViews {
			if got, want := importPaths(view), []string{"guardprobe/app", "guardprobe/app/.dot", "guardprobe/app/_under", "guardprobe/app/testdata/td", "guardprobe/owner"}; !reflect.DeepEqual(got, want) {
				t.Fatalf("%s: selected %v want %v", view.target, got, want)
			}
		}
		references := mergedForeignOwningStructReferences(t, probeViews, "guardprobe/owner", "Service")
		if err := validateTypedFieldAccessInventory("probe Service outside its package", references, map[string]int{
			// The conversion is the one to unsafe.Pointer.
			"app/testdata/td/td.go:Reopen|whole-assign": 1, "app/testdata/td/td.go:Reopen|initializer": 1, "app/testdata/td/td.go:Reopen|whole-convert": 1,
			"app/_under/under.go:Keep|whole-declare": 1, "app/_under/under.go:Keep|whole-read": 2, "app/_under/under.go:Keep|whole-assign": 1,
			"app/.dot/dot.go:<package>|whole-declare": 1, "app/.dot/dot.go:Keep|whole-read": 1,
		}); err != nil {
			t.Fatal(err)
		}
		probeListings, probeSources := repositoryProductionListings(t, probeRoot)
		imports, err := operationalGuardImportInventory(probeSources)
		if err != nil {
			t.Fatal(err)
		}
		if want := map[string][]string{"app/testdata/td/td.go": {"reflect", "unsafe"}}; !reflect.DeepEqual(imports, want) {
			t.Fatalf("import inventory of the probe module: got %v want %v", imports, want)
		}
		if err := validateGuardedProductionTree(probeListings, typedProductionFileSet(probeViews)); err != nil {
			t.Fatalf("the probe module, whose every file is compiled, was refused: %v", err)
		}
	})
	t.Run("a Go file that no compiled package holds", func(t *testing.T) {
		for _, added := range []string{"app/testdata/fixture/fixture.go", "app/_fixture/fixture.go", "app/.fixture/fixture.go", "app/testdata/td/zz_tagged.go"} {
			files := probeFiles()
			files[added] = "//go:build zzcustom\n\npackage fixture\n"
			if strings.HasSuffix(added, "fixture.go") {
				files[added] = "package fixture\n"
			}
			probeRoot := writeGuardProbeModule(t, files)
			probeViews := loadTypedProductionPackagesAt(t, probeRoot, "./...")
			probeListings, _ := repositoryProductionListings(t, probeRoot)
			if err := validateGuardedProductionTree(probeListings, typedProductionFileSet(probeViews)); err == nil ||
				!strings.Contains(err.Error(), added+" is built for none of the guarded targets") {
				t.Fatalf("%s is read by no inventory and passed the tree check: %v", added, err)
			}
		}
	})
	t.Run("a nested module behind a replace line", func(t *testing.T) {
		files := probeFiles()
		files["go.mod"] = guardProbeGoMod(t, "\nrequire nested v0.0.0\n\nreplace nested => ./app/testdata/nested\n")
		files["app/testdata/nested/go.mod"] = strings.Replace(guardProbeGoMod(t, "\nrequire guardprobe v0.0.0\n\nreplace guardprobe => ../../..\n"), "module guardprobe", "module nested", 1)
		files["app/testdata/nested/nested.go"] = "package nested\n\nimport \"guardprobe/owner\"\n\nfunc Reopen(s *owner.Service) { *s = owner.Service{} }\n"
		files["app/app.go"] = strings.Replace(strings.Replace(probeApp, "\t\"guardprobe/owner\"\n", "\t\"guardprobe/owner\"\n\t\"nested\"\n", 1), "\tdot.Keep(s)\n", "\tdot.Keep(s)\n\tnested.Reopen(s)\n", 1)
		probeRoot := writeGuardProbeModule(t, files)
		probeViews := loadTypedProductionPackagesAt(t, probeRoot, "./...")
		for _, view := range probeViews {
			if got, want := importPaths(view), []string{"guardprobe/app", "guardprobe/app/.dot", "guardprobe/app/_under", "guardprobe/app/testdata/td", "guardprobe/owner", "nested"}; !reflect.DeepEqual(got, want) {
				t.Fatalf("%s: selected %v want %v", view.target, got, want)
			}
		}
		count := 0
		for _, reference := range mergedForeignOwningStructReferences(t, probeViews, "guardprobe/owner", "Service") {
			if strings.HasPrefix(reference.site, "app/testdata/nested/nested.go:") {
				count++
			}
		}
		if count != 2 {
			t.Fatalf("the nested module's overwrite of the owner is listed %d times, want 2", count)
		}
		probeListings, _ := repositoryProductionListings(t, probeRoot)
		if err := validateGuardedProductionTree(probeListings, typedProductionFileSet(probeViews)); err == nil || !strings.Contains(err.Error(), "nested module") {
			t.Fatalf("the nested module passed the tree check: %v", err)
		}
		if got, want := goModDirectiveKinds(files["go.mod"]), []string{"go", "module", "replace", "require"}; !reflect.DeepEqual(got, want) {
			t.Fatalf("directive kinds: got %v want %v", got, want)
		}
	})
	t.Run("a workspace file above the repository", func(t *testing.T) {
		probeRoot := writeGuardProbeModule(t, probeFiles())
		target := productionBuildTarget{goos: "linux", goarch: "amd64"}
		if moduleCache, err := guardModuleCache(probeRoot, target); err != nil || !filepath.IsAbs(moduleCache) {
			t.Fatalf("the probe module without a workspace: module cache %q: %v", moduleCache, err)
		}
		probeViews := loadTypedProductionPackagesAt(t, probeRoot, "./...")
		workFile := filepath.Join(filepath.Dir(probeRoot), "go.work")
		goLine := strings.SplitN(strings.SplitN(guardProbeGoMod(t, ""), "\n\n", 2)[1], "\n", 2)[0]
		if err := os.WriteFile(workFile, []byte(goLine+"\n\nuse ./module\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := guardModuleCache(probeRoot, target); err == nil || !strings.Contains(err.Error(), "workspace mode through "+workFile) {
			t.Fatalf("a workspace file above the repository was accepted: %v", err)
		}
		// The tree check cannot see it: it lists the repository only. That is
		// why the loader asks the go command.
		probeListings, _ := repositoryProductionListings(t, probeRoot)
		if err := validateGuardedProductionTree(probeListings, typedProductionFileSet(probeViews)); err != nil {
			t.Fatalf("the tree check saw a workspace file outside the repository: %v", err)
		}
		for name, test := range map[string]struct {
			workspace string
			refused   bool
		}{
			"none":           {"", false},
			"switched off":   {"off", false},
			"a file":         {"/work/go.work", true},
			"a relative one": {"go.work", true},
		} {
			if err := validateGuardWorkspace(test.workspace); (err != nil) != test.refused {
				t.Fatalf("%s: %v", name, err)
			}
		}
	})
	t.Run("a package directory that is a symbolic link", func(t *testing.T) {
		files := probeFiles()
		probeRoot := writeGuardProbeModule(t, files)
		target := filepath.Join(filepath.Dir(probeRoot), "elsewhere")
		if err := os.MkdirAll(target, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(target, "linked.go"), []byte("package linked\n\nimport \"guardprobe/owner\"\n\nfunc Reopen(s *owner.Service) { *s = owner.Service{} }\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, filepath.Join(probeRoot, "app", "linked")); err != nil {
			t.Skipf("no symbolic links here: %v", err)
		}
		app := strings.Replace(strings.Replace(probeApp, "\t\"guardprobe/owner\"\n", "\t\"guardprobe/app/linked\"\n\t\"guardprobe/owner\"\n", 1), "\tdot.Keep(s)\n", "\tdot.Keep(s)\n\tlinked.Reopen(s)\n", 1)
		if err := os.WriteFile(filepath.Join(probeRoot, "app", "app.go"), []byte(app), 0o644); err != nil {
			t.Fatal(err)
		}
		probeViews := loadTypedProductionPackagesAt(t, probeRoot, "./...")
		probeListings, _ := repositoryProductionListings(t, probeRoot)
		if !typedProductionFileSet(probeViews)["app/linked/linked.go"] {
			t.Fatal("the package behind the symbolic link was not read")
		}
		if err := validateGuardedProductionTree(probeListings, typedProductionFileSet(probeViews)); err == nil ||
			!strings.Contains(err.Error(), "app/linked/linked.go was type-checked but its directory was not listed") {
			t.Fatalf("a package compiled through a symbolic link passed the tree check: %v", err)
		}
	})
}

// A method inventory counts references to the method object. A call through
// an interface resolves to the interface's method instead, so the inventory
// also counts each interface that declares a method of the same identity and
// each selection of one.
func TestTypedMethodReferenceInventoryCountsDynamicDispatch(t *testing.T) {
	const declarations = "package admission; import \"io\"; type Service struct{}; func (*Service) Close() error { return nil }; func (*Service) hidden() {}; "
	for _, test := range []struct {
		name, method, source string
		want                 map[string]int
	}{
		{"direct call", "Close", "func owner(s *Service){ _ = s.Close(); var _ io.Reader }", map[string]int{"direct-call": 1}},
		{"interface of another package", "Close", "func owner(s *Service){ var c io.Closer = s; _ = c.Close() }", map[string]int{"interface-selection": 1}},
		{"embedded interface of another package", "Close", "func owner(s *Service){ var c io.ReadCloser; _ = c.Close() }", map[string]int{"interface-selection": 1}},
		{"local interface", "hidden", "func owner(s *Service){ var c interface{ hidden() } = s; c.hidden(); var _ io.Reader }", map[string]int{"interface-method": 1, "interface-selection": 1}},
		{"declaration only", "hidden", "type gate interface{ hidden() }; var _ io.Reader", map[string]int{"interface-method": 1}},
		{"method value through an interface", "hidden", "func owner(s *Service){ var c interface{ hidden() } = s; _ = c.hidden; var _ io.Reader }", map[string]int{"interface-method": 1, "interface-selection": 1}},
		{"type parameter", "hidden", "func call[T interface{ hidden() }](v T){ v.hidden() }; var _ io.Reader", map[string]int{"interface-method": 1, "interface-selection": 1}},
		{"same name on another type", "hidden", "type other struct{}; func (other) hidden(){}; func owner(){ other{}.hidden(); var _ io.Reader }", map[string]int{}},
		{"another method of an interface", "hidden", "func owner(s *Service){ var c io.Closer = s; _ = c.Close() }", map[string]int{}},
	} {
		t.Run(test.name, func(t *testing.T) {
			pkg := typeCheckSyntheticProductionPackage(t, "fixture.go", declarations+test.source)
			got := make(map[string]int)
			for _, reference := range pkg.referencesTo(requirePackageMethod(t, pkg, "Service", test.method)) {
				got[reference.referenceKind]++
				if reference.referenceKind != "direct-call" && reference.directCall {
					t.Fatalf("dynamic occurrence is marked as a direct call: %v", reference)
				}
			}
			if !reflect.DeepEqual(got, test.want) {
				t.Fatalf("occurrences: got %v want %v", got, test.want)
			}
		})
	}
	t.Run("function without a receiver", func(t *testing.T) {
		pkg := typeCheckSyntheticProductionPackage(t, "fixture.go", "package admission; func hidden(){}; type gate interface{ hidden() }; func owner(){ hidden() }")
		if dynamic := pkg.dynamicMethodReferences(requirePackageFunction(t, pkg, "hidden")); len(dynamic) != 0 {
			t.Fatalf("a plain function has dynamic occurrences: %v", dynamic)
		}
	})
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
		"hidden helper":       `func hidden(s *Service) int { return s.value }`,
		"nested closure":      `func (s *Service) Escape() func() int { return func() int { return s.value } }`,
		"second writer":       `func (s *Service) AlternateWrite() { s.value = 2 }`,
		"whole overwrite":     `func (s *Service) Reset() { *s = Service{} }`,
		"whole copy":          `func (s *Service) Copy() Service { return *s }`,
		"second construction": `func another() *Service { return &Service{} }`,
		"zero declaration":    `func another() *Service { var s Service; return &s }`,
		"same-shape convert":  `type twin struct { mu sync.RWMutex; value int }; func another(t *twin) *Service { return (*Service)(t) }`,
		"pointer convert away to a same-shape type":      `type twin struct { mu sync.RWMutex; value int }; func (s *Service) Alias() { (*twin)(s).value = 2 }`,
		"pointer convert away to an anonymous struct":    `func (s *Service) Alias() { (*struct { mu sync.RWMutex; value int })(s).value = 2 }`,
		"pointer convert away kept in a variable":        `func (s *Service) Alias() { mirror := (*struct { mu sync.RWMutex; value int })(s); mirror.value = 2 }`,
		"whole overwrite through a converted pointer":    `type twin struct { mu sync.RWMutex; value int }; func (s *Service) Reset() { *(*twin)(s) = twin{} }`,
		"generic helper instantiated with the owner":     `func zero[T any](v *T) { var z T; *v = z }; func (s *Service) Reset() { zero(s) }`,
		"generic conversion instantiated with a pointer": `type twin struct { mu sync.RWMutex; value int }; func away[S interface{ *Service }](s S) *twin { return (*twin)(s) }; func (s *Service) Alias() { away(s).value = 2 }`,
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
	Standard    bool
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
	metadata *typedProductionMetadata
}

// typedProductionMetadata is one go list run for one build target. A package
// is type-checked from it, from the files on disk or with the content of some
// of them replaced in memory.
type typedProductionMetadata struct {
	repositoryRoot string
	target         productionBuildTarget
	packages       map[string]goListProductionPackage
	selected       []goListProductionPackage
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
	accessKind        string
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
	return loadTypedProductionPackagesAt(t, repositoryRootForAdmissionGuard(t), patterns...)
}

// loadTypedProductionPackagesAt loads the module rooted at one directory. The
// guards read the repository; their self-tests read a small module on disk.
func loadTypedProductionPackagesAt(t *testing.T, repositoryRoot string, patterns ...string) []typedProductionView {
	t.Helper()
	targets := []productionBuildTarget{
		{goos: "darwin", goarch: "arm64"},
		{goos: "linux", goarch: "amd64"},
		{goos: "linux", goarch: "arm64"},
	}
	views := make([]typedProductionView, 0, len(targets))
	for _, target := range targets {
		metadata := loadTypedProductionMetadataAt(t, repositoryRoot, target, patterns...)
		views = append(views, typedProductionView{
			target:   target,
			packages: metadata.typeCheckSelected(t),
			metadata: metadata,
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
		Instances:  make(map[*ast.Ident]types.Instance),
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
	return loadTypedProductionMetadata(t, target, patterns...).typeCheckSelected(t)
}

func loadTypedProductionMetadata(t *testing.T, target productionBuildTarget, patterns ...string) *typedProductionMetadata {
	t.Helper()
	return loadTypedProductionMetadataAt(t, repositoryRootForAdmissionGuard(t), target, patterns...)
}

// pathIsWithin reports whether a path is the directory or lies below it.
func pathIsWithin(directory string, path string) bool {
	relative, err := filepath.Rel(directory, path)
	return err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}

// compileRefusal judges the type errors of one text added to a file. The text
// is refused as expected when there is at least one error, every error lies
// in the added lines of that file, and one of them carries one of the
// expected messages, which are separated by "|". An error anywhere else
// would say that the file did not compile for a reason of its own.
func compileRefusal(found []string, fileName string, hostLines int, messages string) error {
	if len(found) == 0 {
		return errors.New("it compiles")
	}
	matched := false
	for _, message := range found {
		var line int
		rest, inFile := strings.CutPrefix(message, fileName+":")
		if _, err := fmt.Sscanf(rest, "%d:", &line); !inFile || err != nil || line <= hostLines {
			return fmt.Errorf("it is refused by an error outside the added text: %q", found)
		}
		for _, expected := range strings.Split(messages, "|") {
			matched = matched || strings.Contains(message, expected)
		}
	}
	if !matched {
		return fmt.Errorf("it is refused for another reason than %q: %q", messages, found)
	}
	return nil
}

// packagesCompiledBelow returns the loaded packages that are compiled from one
// of the named repository directories or from a directory below one. An
// inventory whose scope is a part of the repository reads these. The scope is
// a directory and not a pattern or an import path, so a package in a testdata,
// dot or underscore directory below it is read, and a dependency compiled
// from another part of the repository is not.
func packagesCompiledBelow(t *testing.T, packages []*typedProductionPackage, directories ...string) []*typedProductionPackage {
	t.Helper()
	scoped := selectPackagesCompiledBelow(repositoryRootForAdmissionGuard(t), packages, directories...)
	if len(scoped) == 0 {
		t.Fatalf("no loaded package is compiled from %v", directories)
	}
	return scoped
}

func selectPackagesCompiledBelow(repositoryRoot string, packages []*typedProductionPackage, directories ...string) []*typedProductionPackage {
	var scoped []*typedProductionPackage
	for _, pkg := range packages {
		for _, directory := range directories {
			if pkg.dir != "" && pathIsWithin(filepath.Join(repositoryRoot, filepath.FromSlash(directory)), pkg.dir) {
				scoped = append(scoped, pkg)
				break
			}
		}
	}
	return scoped
}

// requirePackagesRead fails when one of the named packages is not among those
// an inventory read.
func requirePackagesRead(packages []*typedProductionPackage, importPaths ...string) error {
	read := make(map[string]bool, len(packages))
	for _, pkg := range packages {
		read[pkg.importPath] = true
	}
	for _, importPath := range importPaths {
		if !read[importPath] {
			return fmt.Errorf("%s was not read", importPath)
		}
	}
	return nil
}

func TestPackagesCompiledBelowReadsADirectoryScope(t *testing.T) {
	root := filepath.FromSlash("/repository")
	at := func(directory string) *typedProductionPackage {
		return &typedProductionPackage{dir: filepath.Join(root, filepath.FromSlash(directory)), importPath: directory}
	}
	packages := []*typedProductionPackage{
		at("es"), at("es/admission"), at("es/admission/testdata/hidden"), at("es/.dot/x"), at("es/_under"),
		at("cmd/es"), at("cmd/es/internal/x"),
		at("ars/index"), at("cmd/esx"), at("essential"), at("cmd"), at("internal/es"), {importPath: "no directory"},
	}
	var got []string
	for _, pkg := range selectPackagesCompiledBelow(root, packages, "es", "cmd/es") {
		got = append(got, pkg.importPath)
	}
	want := []string{"es", "es/admission", "es/admission/testdata/hidden", "es/.dot/x", "es/_under", "cmd/es", "cmd/es/internal/x"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("scope differs: got %v want %v", got, want)
	}
	if scoped := selectPackagesCompiledBelow(root, packages, "missing"); len(scoped) != 0 {
		t.Fatalf("a directory that holds no package selected %d", len(scoped))
	}
	// A scope is held by the packages it must have read.
	if err := requirePackagesRead(selectPackagesCompiledBelow(root, packages, "es", "cmd/es"), "cmd/es", "es/admission"); err != nil {
		t.Fatalf("the whole scope: %v", err)
	}
	for name, directories := range map[string][]string{
		"without cmd/es": {"es"},
		"without es":     {"cmd/es"},
		"another part":   {"ars"},
		"nothing":        nil,
	} {
		if err := requirePackagesRead(selectPackagesCompiledBelow(root, packages, directories...), "cmd/es", "es/admission"); err == nil {
			t.Fatalf("a scope %s passed", name)
		}
	}
	if err := requirePackagesRead(nil); err != nil {
		t.Fatalf("nothing required: %v", err)
	}
}

// selectCompiledRepositoryPackages names what the typed inventories read out
// of one go list -deps closure: every package the go command compiles from a
// directory of the repository. That is decided by the package's directory
// alone. Whether a pattern matched the package (DepOnly) and what its import
// path is do not count: a package in a testdata, dot or underscore directory
// is matched by no wildcard pattern and is compiled when it is imported, and a
// nested module behind a replace line has an import path of its own. A package
// of the standard library or of the module cache is a dependency and is not
// read. A package whose directory is anywhere else is refused, because
// nothing would read it.
func selectCompiledRepositoryPackages(repositoryRoot string, moduleCache string, closure map[string]goListProductionPackage) ([]goListProductionPackage, error) {
	selected := make([]goListProductionPackage, 0)
	for _, item := range closure {
		switch {
		case item.Standard:
		case item.Dir == "":
			return nil, fmt.Errorf("go list reports no directory for %s", item.ImportPath)
		case pathIsWithin(moduleCache, item.Dir):
		case pathIsWithin(repositoryRoot, item.Dir):
			selected = append(selected, item)
		default:
			return nil, fmt.Errorf("%s is compiled from %s, which is neither in the repository nor in the module cache: the typed inventories do not read it", item.ImportPath, item.Dir)
		}
	}
	sort.Slice(selected, func(left int, right int) bool { return selected[left].ImportPath < selected[right].ImportPath })
	return selected, nil
}

// guardModuleCache asks the go command, in the environment the typed loader
// uses, for the module cache directory it applies in a directory. It fails
// when the go command is in workspace mode there.
func guardModuleCache(directory string, target productionBuildTarget) (string, error) {
	command := exec.Command(filepath.Join(runtime.GOROOT(), "bin", "go"), "env", "-json", "GOMODCACHE", "GOWORK")
	command.Dir = directory
	command.Env = productionGoListEnvironment(target)
	output, err := command.Output()
	if err != nil {
		return "", err
	}
	var values struct {
		GOMODCACHE string
		GOWORK     string
	}
	if err := json.Unmarshal(output, &values); err != nil {
		return "", err
	}
	if err := validateGuardWorkspace(values.GOWORK); err != nil {
		return "", err
	}
	if values.GOMODCACHE == "" {
		return "", errors.New("the go command reports no module cache directory")
	}
	return values.GOMODCACHE, nil
}

// validateGuardWorkspace refuses a build in workspace mode. The go command
// applies a go.work file of the repository or of any directory above it, or
// the one the GOWORK variable names, and then compiles the modules that file
// lists. The tree check sees only a workspace file inside the repository.
func validateGuardWorkspace(workspace string) error {
	if workspace != "" && workspace != "off" {
		return fmt.Errorf("the go command is in workspace mode through %s: a workspace changes which modules it compiles", workspace)
	}
	return nil
}

func loadTypedProductionMetadataAt(t *testing.T, repositoryRoot string, target productionBuildTarget, patterns ...string) *typedProductionMetadata {
	t.Helper()
	moduleCache, err := guardModuleCache(repositoryRoot, target)
	if err != nil {
		t.Fatalf("read the go environment for %s: %v", target, err)
	}
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

	selected, err := selectCompiledRepositoryPackages(repositoryRoot, moduleCache, metadata)
	if err != nil {
		t.Fatalf("select production packages for %s: %v", target, err)
	}
	if len(selected) == 0 {
		t.Fatalf("no production packages selected for %v", patterns)
	}
	return &typedProductionMetadata{repositoryRoot: repositoryRoot, target: target, packages: metadata, selected: selected}
}

func (metadata *typedProductionMetadata) typeCheckSelected(t *testing.T) []*typedProductionPackage {
	t.Helper()
	packages := make([]*typedProductionPackage, 0, len(metadata.selected))
	for _, item := range metadata.selected {
		packages = append(packages, metadata.typeCheck(t, item, nil))
	}
	return packages
}

// typeCheckWithOverlay type-checks one selected package with the content of
// some of its files replaced in memory. The overlay is keyed by the
// repository-relative path, and every key has to name a file of the package.
// The packages it imports are read as they are on disk.
func (metadata *typedProductionMetadata) typeCheckWithOverlay(t *testing.T, importPath string, overlay map[string]string) *typedProductionPackage {
	t.Helper()
	for _, item := range metadata.selected {
		if item.ImportPath == importPath {
			return metadata.typeCheck(t, item, overlay)
		}
	}
	t.Fatalf("production package %s was not selected", importPath)
	return nil
}

// typeErrorsWithOverlay type-checks one selected package with the content of
// some of its files replaced in memory, like typeCheckWithOverlay, and returns
// the type errors instead of failing on them. Each is "file:line: message"
// with the repository-relative file. It is how a test shows that a form does
// not compile.
func (metadata *typedProductionMetadata) typeErrorsWithOverlay(t *testing.T, importPath string, overlay map[string]string) []string {
	t.Helper()
	for _, item := range metadata.selected {
		if item.ImportPath == importPath {
			var found []string
			metadata.typeCheckCollecting(t, item, overlay, &found)
			return found
		}
	}
	t.Fatalf("production package %s was not selected", importPath)
	return nil
}

func (metadata *typedProductionMetadata) typeCheck(t *testing.T, item goListProductionPackage, overlay map[string]string) *typedProductionPackage {
	t.Helper()
	return metadata.typeCheckCollecting(t, item, overlay, nil)
}

// typeCheckCollecting fails the test on a type error unless the caller asks
// for the errors, in which case it returns no package.
func (metadata *typedProductionMetadata) typeCheckCollecting(t *testing.T, item goListProductionPackage, overlay map[string]string, typeErrors *[]string) *typedProductionPackage {
	t.Helper()
	fset := token.NewFileSet()
	parsed := make(map[string]*ast.File, len(item.GoFiles))
	sources := make(map[string]string, len(item.GoFiles))
	files := make([]*ast.File, 0, len(item.GoFiles))
	replaced := 0
	for _, fileName := range item.GoFiles {
		absolutePath := filepath.Join(item.Dir, fileName)
		repositoryRelativePath, err := filepath.Rel(metadata.repositoryRoot, absolutePath)
		if err != nil || repositoryRelativePath == ".." || strings.HasPrefix(repositoryRelativePath, ".."+string(filepath.Separator)) {
			t.Fatalf("normalize production source path %s: %v", absolutePath, err)
		}
		repositoryRelativePath = filepath.ToSlash(repositoryRelativePath)
		raw, err := os.ReadFile(absolutePath)
		if err != nil {
			t.Fatalf("read production source %s: %v", absolutePath, err)
		}
		if replacement, ok := overlay[repositoryRelativePath]; ok {
			raw = []byte(replacement)
			replaced++
		}
		file, err := parser.ParseFile(fset, absolutePath, raw, parser.AllErrors)
		if err != nil {
			t.Fatalf("parse production source %s: %v", absolutePath, err)
		}
		parsed[repositoryRelativePath] = file
		sources[repositoryRelativePath] = string(raw)
		files = append(files, file)
	}
	if replaced != len(overlay) {
		t.Fatalf("overlay for %s names %d files, %d of them belong to the package", item.ImportPath, len(overlay), replaced)
	}
	info := &types.Info{
		Defs:       make(map[*ast.Ident]types.Object),
		Uses:       make(map[*ast.Ident]types.Object),
		Types:      make(map[ast.Expr]types.TypeAndValue),
		Selections: make(map[*ast.SelectorExpr]*types.Selection),
		Instances:  make(map[*ast.Ident]types.Instance),
	}
	lookup := func(importPath string) (io.ReadCloser, error) {
		dependency, ok := metadata.packages[importPath]
		if !ok || dependency.Export == "" {
			return nil, fmt.Errorf("export data is unavailable for %s", importPath)
		}
		return os.Open(dependency.Export)
	}
	config := types.Config{
		Importer: importer.ForCompiler(fset, "gc", lookup),
		Sizes:    types.SizesFor("gc", metadata.target.goarch),
	}
	if typeErrors != nil {
		config.Error = func(err error) {
			var typeError types.Error
			if !errors.As(err, &typeError) {
				*typeErrors = append(*typeErrors, err.Error())
				return
			}
			position := typeError.Fset.Position(typeError.Pos)
			name := position.Filename
			if relative, relErr := filepath.Rel(metadata.repositoryRoot, name); relErr == nil {
				name = filepath.ToSlash(relative)
			}
			*typeErrors = append(*typeErrors, fmt.Sprintf("%s:%d: %s", name, position.Line, typeError.Msg))
		}
		_, _ = config.Check(item.ImportPath, fset, files, info)
		return nil
	}
	typedPackage, err := config.Check(item.ImportPath, fset, files, info)
	if err != nil {
		t.Fatalf("type-check production package %s: %v", item.ImportPath, err)
	}
	return &typedProductionPackage{
		dir:        item.Dir,
		importPath: item.ImportPath,
		fset:       fset,
		files:      parsed,
		sources:    sources,
		info:       info,
		pkg:        typedPackage,
	}
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
				reference.accessKind,
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
		if references[left].position.Offset != references[right].position.Offset {
			return references[left].position.Offset < references[right].position.Offset
		}
		return references[left].accessKind < references[right].accessKind
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

// validateProtectedFieldName refuses an exported protected field. Another
// package cannot spell an unexported field, and reflection inside a called
// library function cannot set one, so what another package can do to an owning
// type is what the whole-value inventory of that package lists.
func validateProtectedFieldName(importPath string, typeName string, fieldName string) error {
	if token.IsExported(fieldName) {
		return fmt.Errorf("protected field %s.%s.%s is exported", importPath, typeName, fieldName)
	}
	return nil
}

// admissionStateHolders lists what holds admission state in the loaded
// packages: every field of the two structs of the state package and, in every
// other package, every field of a package-level struct whose type holds one of
// the two handle types and every package variable whose type does. A field is
// named "import path.type.field" and a variable "import path.name". The other
// declarations of the state package are not listed: the one file of that
// package is held by the hash of its content.
func admissionStateHolders(t *testing.T, packages []*typedProductionPackage, statePath string) (fields []string, variables []string) {
	t.Helper()
	held := make(map[string]bool)
	state := requireTypedProductionPackage(t, packages, statePath)
	for _, typeName := range []string{"state", "view"} {
		structure := requirePackageStruct(t, state, typeName)
		for index := 0; index < structure.NumFields(); index++ {
			held[statePath+"."+typeName+"."+structure.Field(index).Name()] = true
		}
	}
	for _, pkg := range packages {
		if pkg.importPath == statePath {
			continue
		}
		scope := pkg.pkg.Scope()
		for _, name := range scope.Names() {
			switch object := scope.Lookup(name).(type) {
			case *types.Var:
				if holdsAdmissionStateHandle(object.Type(), statePath, make(map[*types.Named]bool)) {
					variables = append(variables, pkg.importPath+"."+name)
				}
			case *types.TypeName:
				structure, ok := object.Type().Underlying().(*types.Struct)
				if !ok || object.IsAlias() {
					continue
				}
				for index := 0; index < structure.NumFields(); index++ {
					if field := structure.Field(index); holdsAdmissionStateHandle(field.Type(), statePath, make(map[*types.Named]bool)) {
						held[pkg.importPath+"."+name+"."+field.Name()] = true
					}
				}
			}
		}
	}
	sort.Strings(variables)
	return sortedStringSet(held), variables
}

// holdsAdmissionStateHandle reports whether a value of the type holds a handle
// of the admission state: the type is one of the two handle types, or is built
// from one by a pointer, a container, a function type, a struct without a
// name, a type argument, an alias or a named type that is not a struct. A
// named struct of the state package is looked into as well: the result of an
// inspection carries a view. A named struct of another package is not: its
// own fields are judged where it is declared. A value behind an interface type
// is not seen.
func holdsAdmissionStateHandle(typ types.Type, statePath string, seen map[*types.Named]bool) bool {
	switch typ := types.Unalias(typ).(type) {
	case *types.Named:
		object := typ.Obj()
		ofState := object.Pkg() != nil && object.Pkg().Path() == statePath
		if ofState && (object.Name() == "State" || object.Name() == "View") {
			return true
		}
		for index := 0; index < typ.TypeArgs().Len(); index++ {
			if holdsAdmissionStateHandle(typ.TypeArgs().At(index), statePath, seen) {
				return true
			}
		}
		if _, isStruct := typ.Underlying().(*types.Struct); (isStruct && !ofState) || seen[typ] {
			return false
		}
		seen[typ] = true
		return holdsAdmissionStateHandle(typ.Underlying(), statePath, seen)
	case *types.Pointer:
		return holdsAdmissionStateHandle(typ.Elem(), statePath, seen)
	case *types.Slice:
		return holdsAdmissionStateHandle(typ.Elem(), statePath, seen)
	case *types.Array:
		return holdsAdmissionStateHandle(typ.Elem(), statePath, seen)
	case *types.Chan:
		return holdsAdmissionStateHandle(typ.Elem(), statePath, seen)
	case *types.Map:
		return holdsAdmissionStateHandle(typ.Key(), statePath, seen) || holdsAdmissionStateHandle(typ.Elem(), statePath, seen)
	case *types.Struct:
		for index := 0; index < typ.NumFields(); index++ {
			if holdsAdmissionStateHandle(typ.Field(index).Type(), statePath, seen) {
				return true
			}
		}
	case *types.Signature:
		return holdsAdmissionStateHandle(typ.Params(), statePath, seen) || holdsAdmissionStateHandle(typ.Results(), statePath, seen)
	case *types.Tuple:
		for index := 0; index < typ.Len(); index++ {
			if holdsAdmissionStateHandle(typ.At(index).Type(), statePath, seen) {
				return true
			}
		}
	}
	return false
}

// validateAdmissionStateHolders requires an inventory for every field that
// holds admission state or a handle of it. A package variable that holds a
// handle is refused: it has no owning type whose accesses a list could name.
func validateAdmissionStateHolders(fields []string, variables []string, inventoried map[string]bool) error {
	if len(variables) != 0 {
		return fmt.Errorf("package variable %s holds a handle of the admission state", variables[0])
	}
	for _, field := range fields {
		if !inventoried[field] {
			return fmt.Errorf("%s has no inventory: it holds admission state or a handle of it", field)
		}
	}
	return nil
}

// validateOwningStructShape refuses an owning type without fields. No written
// struct type is the mirror of such a type, so the inventory of the other
// packages would say nothing about it.
func validateOwningStructShape(importPath string, typeName string, shape owningStructShape) error {
	if len(shape.fields) == 0 {
		return fmt.Errorf("owning type %s.%s has no field", importPath, typeName)
	}
	return nil
}

func requirePackageStruct(t *testing.T, pkg *typedProductionPackage, typeName string) *types.Struct {
	t.Helper()
	object, ok := pkg.pkg.Scope().Lookup(typeName).(*types.TypeName)
	if !ok {
		t.Fatalf("struct type %s.%s was not found", pkg.importPath, typeName)
	}
	structure, ok := object.Type().Underlying().(*types.Struct)
	if !ok {
		t.Fatalf("type %s.%s is not a struct", pkg.importPath, typeName)
	}
	return structure
}

// mergedForeignOwningStructReferences lists the whole-value occurrences of one
// owning type in every loaded package other than the one that declares it.
// Such a package cannot spell an unexported field, so all it can do to the
// type's storage is listed here: declare, copy, overwrite or convert a whole
// value, instantiate a generic with the type, constrain a type parameter to
// it, or write a struct type of its shape.
func mergedForeignOwningStructReferences(t *testing.T, views []typedProductionView, importPath string, typeName string) []typedReference {
	t.Helper()
	seen := make(map[string]typedReference)
	for _, view := range views {
		declaring := requireTypedProductionPackage(t, view.packages, importPath)
		target := owningStruct{shape: owningStructShapeOf(importPath, requirePackageStruct(t, declaring, typeName))}
		if err := validateOwningStructShape(importPath, typeName, target.shape); err != nil {
			t.Fatal(err)
		}
		for _, pkg := range view.packages {
			if pkg.importPath == importPath {
				continue
			}
			for _, reference := range pkg.wholeValueOccurrences(target, nil, importPath+"."+typeName) {
				key := strings.Join([]string{
					reference.packagePath,
					reference.site,
					filepath.Clean(reference.position.Filename),
					fmt.Sprintf("%d:%d:%t", reference.position.Line, reference.position.Column, reference.insideFuncLiteral),
					reference.accessKind,
				}, "|")
				seen[key] = reference
			}
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
		if references[left].position.Offset != references[right].position.Offset {
			return references[left].position.Offset < references[right].position.Offset
		}
		return references[left].accessKind < references[right].accessKind
	})
	return references
}

// typeParameterDeclarations lists every type parameter the package declares:
// those of a generic function, of a generic type, and of the receiver of a
// method of a generic type. Each entry names the file, the declaration and the
// parameter with its constraint.
func (pkg *typedProductionPackage) typeParameterDeclarations() []string {
	var declarations []string
	for fileName, file := range pkg.files {
		parents := astParentMap(file)
		ast.Inspect(file, func(node ast.Node) bool {
			identifier, ok := node.(*ast.Ident)
			if !ok {
				return true
			}
			declared, ok := pkg.info.Defs[identifier].(*types.TypeName)
			if !ok {
				return true
			}
			parameter, ok := declared.Type().(*types.TypeParam)
			if !ok {
				return true
			}
			declaration := typedFunctionSite(fileName, enclosingFunction(parents, identifier))
			for current := parents[identifier]; current != nil; current = parents[current] {
				if spec, ok := current.(*ast.TypeSpec); ok {
					declaration += " type " + spec.Name.Name
					break
				}
			}
			declarations = append(declarations, fmt.Sprintf("%s[%s %s]", declaration, identifier.Name,
				types.TypeString(parameter.Constraint(), types.RelativeTo(pkg.pkg))))
			return true
		})
	}
	sort.Strings(declarations)
	return declarations
}

// mergedTypeParameterDeclarations lists the type parameters one package
// declares under any of the build targets.
func mergedTypeParameterDeclarations(t *testing.T, views []typedProductionView, importPath string) []string {
	t.Helper()
	seen := make(map[string]bool)
	for _, view := range views {
		for _, declaration := range requireTypedProductionPackage(t, view.packages, importPath).typeParameterDeclarations() {
			seen[declaration] = true
		}
	}
	return sortedStringSet(seen)
}

// referencesTo lists the identifier occurrences that resolve to target. For a
// struct field it also lists every whole-value occurrence of the struct that
// declares the field, because such an occurrence writes, creates or copies
// the field without spelling it.
func (pkg *typedProductionPackage) referencesTo(target types.Object) []typedReference {
	references := pkg.referencesMatching(func(object types.Object) bool { return object == target })
	if method, ok := target.(*types.Func); ok {
		if dynamic := pkg.dynamicMethodReferences(method); len(dynamic) != 0 {
			references = append(references, dynamic...)
			sortTypedReferences(references)
		}
	}
	if field, ok := target.(*types.Var); ok && field.IsField() {
		if owner := pkg.structDeclaring(field); owner != nil {
			references = append(references, pkg.wholeValueReferences(owner, field, trancheB1ObjectIdentity(field))...)
			sortTypedReferences(references)
		}
	}
	return references
}

// dynamicMethodReferences lists the places in pkg from which the method target
// can be reached without a reference to it: an interface type or a constraint
// that declares a method of the same identity, and a selection of such a
// method from an interface or type-parameter value. A value of the method's
// receiver type can be stored in such an interface, and a call through it is
// resolved to the interface's method, not to target. A method of the same
// name on another concrete type is not such a place. An occurrence is never a
// direct call of target, so an exact reference inventory refuses it.
func (pkg *typedProductionPackage) dynamicMethodReferences(target *types.Func) []typedReference {
	if signature, ok := target.Type().(*types.Signature); !ok || signature.Recv() == nil {
		return nil
	}
	abstract := func(object types.Object) bool {
		function, ok := object.(*types.Func)
		if !ok || function == target || function.Id() != target.Id() {
			return false
		}
		signature, ok := function.Type().(*types.Signature)
		return ok && signature.Recv() != nil && types.IsInterface(signature.Recv().Type())
	}
	var references []typedReference
	for fileName, file := range pkg.files {
		parents := astParentMap(file)
		ast.Inspect(file, func(node ast.Node) bool {
			identifier, ok := node.(*ast.Ident)
			if !ok {
				return true
			}
			kind := ""
			switch {
			case abstract(pkg.info.Defs[identifier]):
				kind = "interface-method"
			case abstract(pkg.info.Uses[identifier]):
				kind = "interface-selection"
			default:
				return true
			}
			references = append(references, typedReference{
				packagePath:       pkg.importPath,
				site:              typedFunctionSite(fileName, enclosingFunction(parents, identifier)),
				objectIdentity:    trancheB1ObjectIdentity(target),
				referenceKind:     kind,
				accessKind:        kind,
				insideFuncLiteral: insideFunctionLiteral(parents, identifier),
				position:          pkg.fset.Position(identifier.Pos()),
			})
			return true
		})
	}
	sortTypedReferences(references)
	return references
}

func sortTypedReferences(references []typedReference) {
	sort.SliceStable(references, func(left int, right int) bool {
		if references[left].site != references[right].site {
			return references[left].site < references[right].site
		}
		return references[left].position.Offset < references[right].position.Offset
	})
}

// structDeclaring finds the struct type whose field list holds field. A
// defined type over another struct type shares that struct, so one result
// stands for all of them.
func (pkg *typedProductionPackage) structDeclaring(field *types.Var) *types.Struct {
	seen := make(map[types.Type]bool)
	var find func(types.Type) *types.Struct
	find = func(t types.Type) *types.Struct {
		if t == nil || seen[t] {
			return nil
		}
		seen[t] = true
		switch u := t.Underlying().(type) {
		case *types.Struct:
			for index := 0; index < u.NumFields(); index++ {
				if u.Field(index) == field {
					return u
				}
			}
			for index := 0; index < u.NumFields(); index++ {
				if found := find(u.Field(index).Type()); found != nil {
					return found
				}
			}
		case *types.Pointer:
			return find(u.Elem())
		case *types.Slice:
			return find(u.Elem())
		case *types.Array:
			return find(u.Elem())
		case *types.Chan:
			return find(u.Elem())
		case *types.Map:
			if found := find(u.Key()); found != nil {
				return found
			}
			return find(u.Elem())
		}
		return nil
	}
	identifiers := make([]*ast.Ident, 0)
	for identifier, object := range pkg.info.Defs {
		if _, ok := object.(*types.TypeName); ok {
			identifiers = append(identifiers, identifier)
		}
	}
	sort.Slice(identifiers, func(left int, right int) bool { return identifiers[left].Pos() < identifiers[right].Pos() })
	for _, identifier := range identifiers {
		if found := find(pkg.info.Defs[identifier].Type()); found != nil {
			return found
		}
	}
	return nil
}

// owningStructShape is what a struct type needs to be convertible to an owning
// struct: the same field names in the same order, embedded where the owner's
// are, and, for an unexported name, declared in the owner's package. Field
// types and tags are left out on purpose. Go converts between two struct types
// only when their fields agree in all of this and in their types, so every
// convertible type has this shape, and a generic struct has it whatever its
// type arguments are.
type owningStructShape struct {
	importPath string
	fields     []owningStructShapeField
}

type owningStructShapeField struct {
	name     string
	embedded bool
}

func owningStructShapeOf(importPath string, structure *types.Struct) owningStructShape {
	shape := owningStructShape{importPath: importPath}
	for index := 0; index < structure.NumFields(); index++ {
		field := structure.Field(index)
		shape.fields = append(shape.fields, owningStructShapeField{name: field.Name(), embedded: field.Embedded()})
	}
	return shape
}

// matches reports whether candidate has the shape. A struct without fields
// has no storage to reach and matches nothing.
func (shape owningStructShape) matches(candidate *types.Struct) bool {
	if candidate == nil || len(shape.fields) == 0 || candidate.NumFields() != len(shape.fields) {
		return false
	}
	for index, want := range shape.fields {
		field := candidate.Field(index)
		if field.Name() != want.name || field.Embedded() != want.embedded {
			return false
		}
		if !field.Exported() && (field.Pkg() == nil || field.Pkg().Path() != shape.importPath) {
			return false
		}
	}
	return true
}

// owningStruct names an owning struct type inside one type-checked package. In
// the package that declares the type, own is its struct and a value of it is
// known by that identity. Any other package reads the type from export data,
// as another object, so there own is nil and the struct is known by its shape.
type owningStruct struct {
	own   *types.Struct
	shape owningStructShape
}

func (target owningStruct) is(candidate *types.Struct) bool {
	if target.own != nil {
		return candidate == target.own
	}
	return target.shape.matches(candidate)
}

// mirrors reports whether a struct type written in a source file is another
// type of the owner's shape. Outside the declaring package every struct type
// written with that shape is one.
func (target owningStruct) mirrors(written *types.Struct) bool {
	return written != target.own && target.shape.matches(written)
}

// wholeValueReferences lists the whole-value occurrences of the owner struct
// in the package that declares it.
func (pkg *typedProductionPackage) wholeValueReferences(owner *types.Struct, field *types.Var, identity string) []typedReference {
	return pkg.wholeValueOccurrences(owningStruct{own: owner, shape: owningStructShapeOf(pkg.importPath, owner)}, field, identity)
}

// wholeValueOccurrences lists every place where a value of the owner struct, or
// of a type that holds one by value, is created, overwritten, converted or
// copied as a whole, and every place that makes such a value reachable under
// another type. No field is spelled at such a place, so identifier occurrences
// alone do not see it.
//
// The access kinds are: "initializer" for a positional literal, which sets
// every field (with a nil field, for any literal of the owner);
// "zero-initializer" for a literal that leaves the field implicit; a keyed
// literal that names the field is left to the identifier occurrence of its
// key. "whole-assign" is an assignment or range target that is or holds the
// owner by value. "whole-convert" is a conversion between the owner, or a
// pointer or container of it, and another type, in either direction: to the
// owner it makes a value of it from a same-shape type, and away from a pointer
// to the owner it makes a pointer through which the same storage is written
// under another type's field names. A conversion to an interface type is not
// one: it reinterprets nothing, and the copy it takes of a by-value operand is
// a "whole-read". "whole-instantiate" is a generic function or type
// instantiated, explicitly or by inference, with a type argument that is or
// holds the owner or is a pointer or container of it: the generic body can
// write such a value without spelling its type. "whole-declare" is a declared
// variable, parameter, result, receiver or struct field that is or holds the
// owner by value, a type-switch clause for it, and new or make of it.
// "whole-copy" is copy, clear or append over a container of it. "whole-read"
// is any other use of such a value: it copies the field.
//
// Two kinds do not wait for a use. "whole-mirror" is a struct type written
// with the owner's shape, named, anonymous or generic: a pointer to the owner
// converts only to a pointer to such a type, so where none is written no
// conversion can give the owner's storage other field names, in this package
// or in one that imports it. "whole-constrain" is a type parameter whose
// constraint has a type term that is the owner or reaches it through pointers,
// slices, arrays, channels, maps or struct fields: its body handles the owner
// under the parameter's name and is instantiated from any package.
func (pkg *typedProductionPackage) wholeValueOccurrences(target owningStruct, field *types.Var, identity string) []typedReference {
	if pkg.info.Instances == nil {
		panic("whole-value inventory needs the instance information of the typed package")
	}
	memo := make(map[types.Type]bool)
	var holds func(types.Type) bool
	holds = func(t types.Type) bool {
		if t == nil {
			return false
		}
		if known, ok := memo[t]; ok {
			return known
		}
		// A type can only hold itself through a pointer, slice, map or channel,
		// none of which holds by value.
		memo[t] = false
		result := false
		switch u := t.Underlying().(type) {
		case *types.Struct:
			result = target.is(u)
			for index := 0; !result && index < u.NumFields(); index++ {
				result = holds(u.Field(index).Type())
			}
		case *types.Array:
			result = holds(u.Elem())
		}
		memo[t] = result
		return result
	}
	contains := func(t types.Type) bool {
		if t == nil {
			return false
		}
		switch u := t.Underlying().(type) {
		case *types.Pointer:
			return holds(u.Elem())
		case *types.Slice:
			return holds(u.Elem())
		case *types.Chan:
			return holds(u.Elem())
		case *types.Map:
			return holds(u.Key()) || holds(u.Elem())
		}
		return false
	}
	// reinterprets reports whether a conversion from operand to result gives
	// the owner's storage, or a copy of it, another type on either side.
	reinterprets := func(result types.Type, operand types.Type) bool {
		if holds(result) || contains(result) {
			return true
		}
		if !holds(operand) && !contains(operand) {
			return false
		}
		if _, parameter := types.Unalias(result).(*types.TypeParam); parameter {
			return true
		}
		return !types.IsInterface(result)
	}
	// reaches reports whether t is the owner or leads to it by value, through
	// pointers and containers, or as a type term of a constraint, at any depth.
	var reaches func(types.Type, map[types.Type]bool) bool
	reaches = func(t types.Type, seen map[types.Type]bool) bool {
		if t == nil || seen[t] {
			return false
		}
		seen[t] = true
		if holds(t) {
			return true
		}
		if named, ok := types.Unalias(t).(*types.Named); ok {
			for index := 0; index < named.TypeArgs().Len(); index++ {
				if reaches(named.TypeArgs().At(index), seen) {
					return true
				}
			}
		}
		switch u := t.Underlying().(type) {
		case *types.Pointer:
			return reaches(u.Elem(), seen)
		case *types.Slice:
			return reaches(u.Elem(), seen)
		case *types.Array:
			return reaches(u.Elem(), seen)
		case *types.Chan:
			return reaches(u.Elem(), seen)
		case *types.Map:
			return reaches(u.Key(), seen) || reaches(u.Elem(), seen)
		case *types.Struct:
			for index := 0; index < u.NumFields(); index++ {
				if reaches(u.Field(index).Type(), seen) {
					return true
				}
			}
		case *types.Interface:
			// The type terms of a constraint. Its methods name no storage.
			for index := 0; index < u.NumEmbeddeds(); index++ {
				if reaches(u.EmbeddedType(index), seen) {
					return true
				}
			}
		case *types.Union:
			for index := 0; index < u.Len(); index++ {
				if reaches(u.Term(index).Type(), seen) {
					return true
				}
			}
		}
		return false
	}
	var references []typedReference
	for fileName, file := range pkg.files {
		parents := astParentMap(file)
		add := func(node ast.Node, accessKind string) {
			references = append(references, typedReference{
				packagePath:       pkg.importPath,
				site:              typedFunctionSite(fileName, enclosingFunction(parents, node)),
				objectIdentity:    identity,
				referenceKind:     "whole-value",
				accessKind:        accessKind,
				insideFuncLiteral: insideFunctionLiteral(parents, node),
				position:          pkg.fset.Position(node.Pos()),
			})
		}
		unnamed := func(list *ast.FieldList) {
			if list == nil {
				return
			}
			for _, entry := range list.List {
				if len(entry.Names) == 0 && holds(pkg.info.TypeOf(entry.Type)) {
					add(entry.Type, "whole-declare")
				}
			}
		}
		ast.Inspect(file, func(node ast.Node) bool {
			switch current := node.(type) {
			case *ast.Ident:
				if declared, ok := pkg.info.Defs[current].(*types.Var); ok && holds(declared.Type()) {
					add(current, "whole-declare")
				}
				if declared, ok := pkg.info.Defs[current].(*types.TypeName); ok {
					if parameter, ok := declared.Type().(*types.TypeParam); ok && reaches(parameter.Constraint(), make(map[types.Type]bool)) {
						add(current, "whole-constrain")
					}
				}
				if instance, ok := pkg.info.Instances[current]; ok {
					for index := 0; index < instance.TypeArgs.Len(); index++ {
						if argument := instance.TypeArgs.At(index); holds(argument) || contains(argument) {
							add(current, "whole-instantiate")
							break
						}
					}
				}
			case *ast.StructType:
				// A struct type the type checker gave no type is listed as well:
				// what cannot be compared is not known to differ.
				if written, known := pkg.info.TypeOf(current).(*types.Struct); !known || target.mirrors(written) {
					add(current, "whole-mirror")
				}
			case *ast.FuncDecl:
				unnamed(current.Recv)
			case *ast.FuncType:
				unnamed(current.Params)
				unnamed(current.Results)
			case *ast.TypeSwitchStmt:
				if _, bound := current.Assign.(*ast.AssignStmt); bound {
					for _, statement := range current.Body.List {
						clause := statement.(*ast.CaseClause)
						if len(clause.List) == 1 && holds(pkg.info.TypeOf(clause.List[0])) {
							add(clause, "whole-declare")
						}
					}
				}
			case *ast.CallExpr:
				if name, ok := ast.Unparen(current.Fun).(*ast.Ident); ok && len(current.Args) != 0 {
					if builtin, ok := pkg.info.Uses[name].(*types.Builtin); ok {
						first := pkg.info.TypeOf(current.Args[0])
						switch builtin.Name() {
						case "new":
							if holds(first) {
								add(current, "whole-declare")
							}
						case "make":
							if contains(first) {
								add(current, "whole-declare")
							}
						case "copy", "clear", "append":
							if contains(first) {
								add(current, "whole-copy")
							}
						}
					}
				}
			}
			expression, ok := node.(ast.Expr)
			if !ok {
				return true
			}
			if _, parenthesized := expression.(*ast.ParenExpr); parenthesized {
				return true
			}
			value, ok := pkg.info.Types[expression]
			if !ok || !value.IsValue() {
				return true
			}
			if literal, ok := expression.(*ast.CompositeLit); ok {
				if kind := wholeValueLiteralKind(pkg.info, literal, value.Type, target, field, holds); kind != "" {
					add(literal, kind)
				}
				return true
			}
			if call, ok := expression.(*ast.CallExpr); ok && len(call.Args) == 1 {
				if converted, ok := pkg.info.Types[call.Fun]; ok && converted.IsType() {
					if operand := pkg.info.TypeOf(call.Args[0]); reinterprets(value.Type, operand) && (operand == nil || !types.Identical(value.Type, operand)) {
						add(call, "whole-convert")
						return true
					}
				}
			}
			if !holds(value.Type) {
				return true
			}
			outer := expression
			for {
				parenthesis, ok := parents[outer].(*ast.ParenExpr)
				if !ok {
					break
				}
				outer = parenthesis
			}
			switch parent := parents[outer].(type) {
			case *ast.SelectorExpr:
				// The base of a selection is not copied, and a selected name is
				// described by its selector expression.
				return true
			case *ast.UnaryExpr:
				if parent.Op == token.AND {
					return true
				}
			case *ast.IndexExpr:
				if parent.X == outer {
					return true
				}
			case *ast.SliceExpr:
				if parent.X == outer {
					return true
				}
			case *ast.AssignStmt:
				for _, target := range parent.Lhs {
					if target == outer {
						add(expression, "whole-assign")
						return true
					}
				}
			case *ast.RangeStmt:
				if parent.Key == outer || parent.Value == outer {
					add(expression, "whole-assign")
					return true
				}
			}
			add(expression, "whole-read")
			return true
		})
	}
	sortTypedReferences(references)
	return references
}

// wholeValueLiteralKind classifies a composite literal. The empty string means
// the literal is not a whole-value occurrence of its own: either it has
// nothing to do with the owner, or every value of the owner inside it is
// spelled as an element, which is classified where it stands.
func wholeValueLiteralKind(info *types.Info, literal *ast.CompositeLit, literalType types.Type, target owningStruct, field *types.Var,
	holds func(types.Type) bool) string {
	if pointer, ok := literalType.Underlying().(*types.Pointer); ok && literal.Type == nil {
		// An elided &T{} element of a container of pointers.
		literalType = pointer.Elem()
	}
	keyed := len(literal.Elts) != 0
	for _, element := range literal.Elts {
		if _, ok := element.(*ast.KeyValueExpr); !ok {
			keyed = false
		}
	}
	switch structure := literalType.Underlying().(type) {
	case *types.Struct:
		if target.is(structure) {
			if field == nil {
				return "initializer"
			}
			if len(literal.Elts) == 0 {
				return "zero-initializer"
			}
			if !keyed {
				return "initializer"
			}
			for _, element := range literal.Elts {
				if key, ok := element.(*ast.KeyValueExpr).Key.(*ast.Ident); ok && info.Uses[key] == field {
					return ""
				}
			}
			return "zero-initializer"
		}
		if !holds(literalType) {
			return ""
		}
		if len(literal.Elts) != 0 && !keyed {
			return ""
		}
		named := make(map[types.Object]bool)
		for _, element := range literal.Elts {
			if key, ok := element.(*ast.KeyValueExpr).Key.(*ast.Ident); ok {
				named[info.Uses[key]] = true
			}
		}
		for index := 0; index < structure.NumFields(); index++ {
			if holds(structure.Field(index).Type()) && !named[structure.Field(index)] {
				return "zero-initializer"
			}
		}
	case *types.Array:
		if holds(structure.Elem()) && (keyed || int64(len(literal.Elts)) != structure.Len()) {
			return "zero-initializer"
		}
	case *types.Slice:
		if holds(structure.Elem()) && keyed {
			return "zero-initializer"
		}
	}
	return ""
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
			accessKind := typedReferenceAccessKind(pkg.info, parents, expression)
			if insideLiteral {
				referenceKind += "+closure"
			}
			references = append(references, typedReference{
				packagePath:       pkg.importPath,
				site:              typedFunctionSite(fileName, enclosingFunction(parents, identifier)),
				objectIdentity:    trancheB1ObjectIdentity(object),
				referenceKind:     referenceKind,
				accessKind:        accessKind,
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

// Field access is classified from the resolved identifier's syntax. This is
// deliberately separate from call classification, which other guards use.
//
// The kind describes what the expression itself does to storage rooted at the
// resolved field: "read", whole-field "assignment" or "read-write", a keyed
// "initializer", taking the field's "address" (explicitly with & or implicitly
// through slicing an addressable array or a pointer-receiver method on an
// addressable value), or "write-through" when an assignment,
// increment/decrement, range target, address-of, channel send or mutating
// builtin is applied through a selector, index, slice, type assertion,
// conversion or dereference chain rooted at the field. A conversion is a
// transparent step: the converted value still reaches the same storage.
// Called functions and methods are not analyzed beyond Go's implicit
// address-of. An unresolved selection in that chain is "unclassified".
func typedReferenceAccessKind(info *types.Info, parents map[ast.Node]ast.Node, expression ast.Expr) string {
	// Parentheses enclosing the whole resolved access are transparent to its
	// syntactic role.
	for {
		parent, ok := parents[expression].(*ast.ParenExpr)
		if !ok || parent.X != expression {
			break
		}
		expression = parent
	}
	if pair, ok := parents[expression].(*ast.KeyValueExpr); ok && pair.Key == expression {
		return "initializer"
	}
	switch typedStorageEffect(info, parents, expression) {
	case "assign":
		return "assignment"
	case "read-write":
		return "read-write"
	case "address":
		return "address"
	case "builtin-write":
		return "write-through"
	}
	location := expression
	for {
		next, implicitAddress, known, ok := typedLocationStep(info, parents, location)
		if !known {
			return "unclassified"
		}
		if implicitAddress {
			if location == expression {
				return "address"
			}
			return "write-through"
		}
		if !ok {
			return "read"
		}
		location = next
		if typedStorageEffect(info, parents, location) != "" {
			return "write-through"
		}
	}
}

// typedStorageEffect reports a syntactic storage effect applied directly to
// location by its parent node.
func typedStorageEffect(info *types.Info, parents map[ast.Node]ast.Node, location ast.Expr) string {
	switch parent := parents[location].(type) {
	case *ast.AssignStmt:
		for _, lhs := range parent.Lhs {
			if lhs == location {
				if parent.Tok == token.ASSIGN || parent.Tok == token.DEFINE {
					return "assign"
				}
				return "read-write"
			}
		}
	case *ast.IncDecStmt:
		if parent.X == location {
			return "read-write"
		}
	case *ast.RangeStmt:
		if parent.Tok == token.ASSIGN && (parent.Key == location || parent.Value == location) {
			return "assign"
		}
	case *ast.UnaryExpr:
		if parent.Op == token.AND && parent.X == location {
			return "address"
		}
	case *ast.CallExpr:
		if len(parent.Args) == 0 || parent.Args[0] != location {
			return ""
		}
		name, ok := ast.Unparen(parent.Fun).(*ast.Ident)
		if !ok {
			return ""
		}
		if builtin, ok := info.Uses[name].(*types.Builtin); ok {
			switch builtin.Name() {
			// append may write into the backing array its first argument shares.
			case "append", "clear", "close", "copy", "delete":
				return "builtin-write"
			}
		}
	case *ast.SendStmt:
		if parent.Chan == location {
			return "builtin-write"
		}
	}
	return ""
}

// typedLocationStep moves from location to the enclosing expression that
// still denotes storage reached from it. known is false when a selector in
// the chain has no recorded selection.
func typedLocationStep(info *types.Info, parents map[ast.Node]ast.Node, location ast.Expr) (next ast.Expr, implicitAddress, known, ok bool) {
	switch parent := parents[location].(type) {
	case *ast.ParenExpr:
		return parent, false, true, parent.X == location
	case *ast.StarExpr:
		return parent, false, true, parent.X == location
	case *ast.IndexExpr:
		return parent, false, true, parent.X == location
	case *ast.TypeAssertExpr:
		return parent, false, true, parent.X == location
	case *ast.CallExpr:
		// A conversion T(location) still denotes what location reaches.
		if converted, ok := info.Types[parent.Fun]; ok && converted.IsType() && len(parent.Args) == 1 && parent.Args[0] == location {
			return parent, false, true, true
		}
		return nil, false, true, false
	case *ast.SliceExpr:
		if parent.X != location {
			return nil, false, true, false
		}
		if _, array := typedUnderlying(info.TypeOf(location)).(*types.Array); array {
			return nil, true, true, false
		}
		return parent, false, true, true
	case *ast.SelectorExpr:
		if parent.X != location {
			return nil, false, true, false
		}
		selection := info.Selections[parent]
		if selection == nil {
			return nil, false, false, false
		}
		switch selection.Kind() {
		case types.FieldVal:
			return parent, false, true, true
		case types.MethodVal:
			signature, isSignature := selection.Obj().Type().(*types.Signature)
			if !isSignature || signature.Recv() == nil {
				return nil, false, false, false
			}
			_, pointerReceiver := typedUnderlying(signature.Recv().Type()).(*types.Pointer)
			_, pointerOperand := typedUnderlying(info.TypeOf(location)).(*types.Pointer)
			return nil, pointerReceiver && !pointerOperand, true, false
		}
		return nil, false, false, false
	}
	return nil, false, true, false
}

func typedUnderlying(t types.Type) types.Type {
	if t == nil {
		return nil
	}
	return t.Underlying()
}

// validateTypedFieldAccessInventory counts occurrences by function site and
// access kind. An occurrence inside a function literal runs when that literal
// is called, not where it is written, so it is a kind of its own
// ("site|kind+closure") and passes only where an inventory lists it.
func validateTypedFieldAccessInventory(label string, references []typedReference, want map[string]int) error {
	got := make(map[string]int)
	for _, reference := range references {
		if reference.packagePath == "" || reference.site == "" || reference.position.Filename == "" ||
			reference.position.Line <= 0 || reference.position.Column <= 0 || reference.objectIdentity == "" ||
			reference.accessKind == "" {
			return fmt.Errorf("%s contains an incomplete field reference: %v", label, reference)
		}
		key := reference.site + "|" + reference.accessKind
		if reference.insideFuncLiteral {
			key += "+closure"
		}
		got[key]++
	}
	if !reflect.DeepEqual(got, want) {
		return fmt.Errorf("%s field access inventory changed: got %v want %v (references %v)", label, got, want, references)
	}
	return nil
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

// validateTypedObjectReferenceInventory counts identifier occurrences by
// function site. A whole-value occurrence of the owning struct spells no
// field, so it is counted under its site and access kind ("site|kind"): an
// inventory names each place where the struct is created, copied or
// overwritten as a whole, apart from the places that name the field.
func validateTypedObjectReferenceInventory(label string, references []typedReference, want map[string]int, rejectClosures bool) error {
	got := make(map[string]int)
	for _, reference := range references {
		if reference.packagePath == "" || reference.site == "" || reference.position.Filename == "" || reference.position.Line <= 0 || reference.position.Column <= 0 || reference.objectIdentity == "" || reference.referenceKind == "" {
			return fmt.Errorf("%s contains an incomplete critical occurrence identity: %v", label, reference)
		}
		if reference.methodExpression || (rejectClosures && reference.insideFuncLiteral) {
			return fmt.Errorf("%s contains an indirect reference escape: %s", label, reference)
		}
		if reference.referenceKind == "whole-value" {
			if reference.accessKind == "" {
				return fmt.Errorf("%s contains an unclassified whole-value occurrence: %v", label, reference)
			}
			got[reference.site+"|"+reference.accessKind]++
			continue
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
	return typeCheckSyntheticImportingPackage(t, "synthetic/admission", fileName, source)
}

// syntheticImporter resolves the synthetic packages a synthetic package
// imports, and everything else as the default importer does.
type syntheticImporter struct {
	packages map[string]*types.Package
	fallback types.Importer
}

func (source syntheticImporter) Import(path string) (*types.Package, error) {
	if pkg, ok := source.packages[path]; ok {
		return pkg, nil
	}
	return source.fallback.Import(path)
}

// typeCheckSyntheticImportingPackage type-checks one synthetic package that can
// import the given synthetic packages by their paths.
func typeCheckSyntheticImportingPackage(t *testing.T, importPath string, fileName string, source string, imported ...*typedProductionPackage) *typedProductionPackage {
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
		Instances:  make(map[*ast.Ident]types.Instance),
	}
	resolver := syntheticImporter{packages: make(map[string]*types.Package), fallback: importer.Default()}
	for _, dependency := range imported {
		resolver.packages[dependency.importPath] = dependency.pkg
	}
	typedPackage, err := (&types.Config{Importer: resolver}).Check(importPath, fset, []*ast.File{file}, info)
	if err != nil {
		t.Fatal(err)
	}
	return &typedProductionPackage{
		importPath: importPath,
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
		planCalls:      []string{"es/admission/reliable_submit_operational_format.go:verifyOperationalOriginal", "es/admission/reliable_submit_replay_hydration.go:decodePrivateReplayOriginal", "es/admission/resolved_execution_plan.go:Service.resolveExecutionForSubmit"},
		planFunctions:  []string{"es/admission/resolved_execution_plan.go:newResolvedExecutionPlan"},
		planReturns:    []string{"es/admission/resolved_execution_plan.go:newResolvedExecutionPlan"},
		planBindings: []string{
			"es/admission/reliable_submit_binding_encoding.go:bindingEncodeCanonical",
			"es/admission/reliable_submit_binding_encoding.go:bindingRecordFields",
			"es/admission/reliable_submit_operational_admission.go:operationalEvidenceMatchesOriginal",
			"es/admission/reliable_submit_operational_format.go:encodeOperationalOriginal",
			"es/admission/reliable_submit_operational_format.go:validateOperationalPlan",
			"es/admission/reliable_submit_replay_format.go:privateReplayEncoder.provenance",
			"es/admission/reliable_submit_replay_hydration.go:decodePrivateReplayOriginal",
			"es/admission/resolved_execution_plan.go:Service.resolveExecutionForSubmit",
		},
		factsBindings: []string{"es/admission/reliable_submit_operational_format.go:verifyOperationalOriginal", "es/admission/reliable_submit_replay_hydration.go:decodePrivateReplayOriginal"},
		factsPayload: []string{
			"es/admission/reliable_submit_replay_hydration.go:privateReplayReader.plan",
			"es/admission/resolved_execution_plan.go:Service.resolveExecutionForSubmit",
			"es/admission/resolved_execution_plan.go:newResolvedExecutionPlan",
		},
		planPayload: []string{
			"es/admission/reliable_submit_binding.go:bindingPrimaryValid",
			"es/admission/reliable_submit_binding.go:bindingPrimaryValid",
			"es/admission/reliable_submit_binding_encoding.go:bindingRecordFields",
			"es/admission/reliable_submit_operational_admission.go:operationalEvidenceMatchesOriginal",
			"es/admission/reliable_submit_operational_format.go:encodeOperationalOriginal",
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
		{label: "submit resolver", definition: semanticCallDefinition{receiver: "Service", name: "resolveExecutionForSubmit"}, want: map[string]int{"es/admission/submit.go:Service.Submit": 1, "es/admission/reliable_submit_replay_private.go:Service.composePrivateSyntheticReplay": 1, "es/admission/reliable_submit_operational_handoff.go:Service.composeOperationalOriginal": 1}},
		{label: "execution locator", definition: semanticCallDefinition{name: "newExecutionLocator"}, want: map[string]int{"es/admission/submit.go:Service.Submit": 1}},
		{label: "run projection", definition: semanticCallDefinition{name: "newResolvedRunProjection"}, want: map[string]int{"es/admission/submit.go:Service.Submit": 1, "es/admission/reliable_submit_operational_handoff.go:Service.advanceOperational": 1}},
		{label: "Nomad registration", definition: semanticCallDefinition{receiver: "nomadClient", name: "submitJob"}, want: map[string]int{"es/admission/submit.go:Service.Submit": 1}},
		{label: "semantic plan freeze", definition: semanticCallDefinition{name: "newResolvedExecutionPlan"}, want: map[string]int{"es/admission/resolved_execution_plan.go:Service.resolveExecutionForSubmit": 1, "es/admission/reliable_submit_replay_hydration.go:decodePrivateReplayOriginal": 1, "es/admission/reliable_submit_operational_format.go:verifyOperationalOriginal": 1}},
		{label: "material freeze", definition: semanticCallDefinition{name: "newResolvedExecutionMaterial"}, want: map[string]int{"es/admission/resolved_execution_plan.go:Service.resolveExecutionForSubmit": 1, "es/admission/reliable_submit_replay_hydration.go:decodePrivateReplayOriginal": 1, "es/admission/reliable_submit_operational_format.go:verifyOperationalOriginal": 1}},
		{label: "host context freeze", definition: semanticCallDefinition{name: "newHostMaterializationContext"}, want: map[string]int{"es/admission/resolved_execution_plan.go:Service.resolveExecutionForSubmit": 1, "es/admission/reliable_submit_replay_hydration.go:privateReplayReader.placement": 1, "es/admission/reliable_submit_operational_format.go:verifyOperationalOriginal": 1}},
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
				"es/admission/reliable_submit_operational_handoff.go:operationalDomain.createOperationalStage": 1,
				"es/admission/staging_custody.go:claimStagingCustody":                                          1,
				"es/admission/staging_custody.go:probeStagingCustodyCapabilities":                              1,
				"es/admission/submit.go:Service.Submit":                                                        1,
			},
		},
		{label: "materialization entry point", definition: semanticCallDefinition{name: "materializeExecutionInputs"}, want: map[string]int{"es/admission/submit.go:Service.Submit": 1, "es/admission/reliable_submit_operational_handoff.go:Service.advanceOperational": 1}},
		{label: "pre-handoff revalidation", definition: semanticCallDefinition{receiver: "stagingCustody", name: "revalidateBeforeHandoff"}, want: map[string]int{"es/admission/submit.go:Service.Submit": 1, "es/admission/staging_custody.go:measureOperationalStage": 2}},
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
