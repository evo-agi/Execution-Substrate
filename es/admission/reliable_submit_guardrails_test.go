package admission

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"
)

func assertPrivateReplayProgressCallers(t *testing.T) {
	t.Helper()
	const internal = "execution-substrate/es/admission/internal/reliablesubmit"
	const admissionPackage = "execution-substrate/es/admission"
	const owner = "es/admission/reliable_submit_replay_private.go:"
	views := loadTypedProductionPackages(t, "./es/...", "./cmd/es/...")
	for _, view := range views {
		pkg := requireTypedProductionPackage(t, view.packages, admissionPackage)
		for _, name := range []string{"admitPrivateProgressReplay", "applyPrivateProgressReplay"} {
			method := requirePackageMethod(t, pkg, "Service", name)
			if err := validateTypedReferenceInventory(name, pkg.referencesTo(method), map[string]int{}, true); err != nil {
				t.Fatal(err)
			}
		}
		for _, inventory := range []struct {
			name string
			want map[string]int
		}{
			{"OpenPrivateReplayProgressCustody", map[string]int{}},
			{"NewFixtureAcceptedEvidence", map[string]int{}},
			{"NewFixtureNotAcceptedEvidence", map[string]int{}},
			{"NewProgressOriginalInput", map[string]int{owner + "Service.composePrivateSyntheticReplay": 1}},
			{"NewProgressOriginalMatch", map[string]int{owner + "verifyPrivateProgressOriginal": 1}},
			{"LookupProgressOriginal", map[string]int{owner + "Service.admitPrivateProgressReplay": 2, owner + "Service.applyPrivateProgressReplay": 1}},
			{"FreezeProgressOriginal", map[string]int{owner + "Service.admitPrivateProgressReplay": 1}},
			{"ReserveProgressSealUse", map[string]int{owner + "Service.admitPrivateProgressReplay": 1}},
			{"PublishProgressOriginal", map[string]int{owner + "Service.admitPrivateProgressReplay": 1}},
			{"EstablishProgress", map[string]int{owner + "Service.admitPrivateProgressReplay": 1}},
			{"WithAuthenticatedProgressOriginal", map[string]int{owner + "readPrivateProgressReplay": 1, owner + "Service.applyPrivateProgressReplay": 1}},
			{"ReadFixtureProgress", map[string]int{owner + "readPrivateProgressReplay": 1}},
			{"ApplyFixtureProgress", map[string]int{owner + "Service.applyPrivateProgressReplay": 1}},
		} {
			var refs []typedReference
			for _, consumer := range view.packages {
				if consumer.importPath != internal || inventory.name == "NewFixtureAcceptedEvidence" || inventory.name == "NewFixtureNotAcceptedEvidence" {
					refs = append(refs, consumer.referencesToPackageFunction(internal, inventory.name)...)
				}
			}
			if err := validateTypedReferenceInventory(inventory.name, refs, inventory.want, false); err != nil {
				t.Fatalf("%s: %v", view.target, err)
			}
		}
	}
	const rel = "reliable_submit_replay_private.go"
	source := mustReadAdmissionSource(t, rel)
	check := func(source string) error {
		file, err := parser.ParseFile(token.NewFileSet(), rel, source, 0)
		if err != nil {
			return err
		}
		return validatePrivateProgressEffects(file)
	}
	if err := check(source); err != nil {
		t.Fatal(err)
	}
	for _, mutant := range []struct {
		name string
		code string
	}{
		{"Provider", "s.nomadClient.submitJob(ctx)"},
		{"Staging", "s.stageRun(ctx)"},
		{"Runtime", "s.Submit(ctx)"},
		{"Startup", "s.Start(ctx)"},
		{"LiveCredential", "s.loadLiveCredentials(ctx)"},
		{"PublicProjection", "_ = reliablesubmit.NewReceiptRef"},
		{"TerminalAssertionConstructor", "_ = reliablesubmit.NewFixtureAcceptedEvidence"},
		{"TransitiveMethod", "s.unreviewedHelper(ctx)"},
		{"AsynchronousBorrow", "go use(nil)"},
	} {
		t.Run("Reject"+mutant.name, func(t *testing.T) {
			anchor := "ctx, cancel := context.WithCancel(ctx)"
			changed := strings.Replace(source, anchor, mutant.code+"\n\t"+anchor, 1)
			if changed == source || check(changed) == nil {
				t.Fatal("private progress effect guard accepted mutant")
			}
		})
	}
}

func validatePrivateProgressEffects(file *ast.File) error {
	allowedImports := map[string]bool{"context": true, "crypto/hmac": true, "crypto/sha256": true,
		"encoding/binary": true, "errors": true, "execution-substrate/es/admission/internal/reliablesubmit": true}
	for _, imported := range file.Imports {
		path, err := strconv.Unquote(imported.Path.Value)
		if err != nil || !allowedImports[path] || imported.Name != nil {
			return fmt.Errorf("unreviewed private replay import %s", imported.Path.Value)
		}
	}
	var violation error
	ast.Inspect(file, func(node ast.Node) bool {
		switch value := node.(type) {
		case *ast.GoStmt:
			violation = fmt.Errorf("asynchronous private replay authority")
		case *ast.SelectorExpr:
			receiver, ok := value.X.(*ast.Ident)
			if ok && receiver.Name == "s" && value.Sel.Name != "composePrivateSyntheticReplay" && value.Sel.Name != "resolveExecutionForSubmit" {
				violation = fmt.Errorf("unreviewed Service edge %s", value.Sel.Name)
			}
			if ok && receiver.Name == "reliablesubmit" && (value.Sel.Name == "NewReceiptRef" || value.Sel.Name == "ReceiptRef" || value.Sel.Name == "RunRef") {
				violation = fmt.Errorf("operational projection %s", value.Sel.Name)
			}
			if ok && receiver.Name == "reliablesubmit" && (value.Sel.Name == "NewFixtureAcceptedEvidence" || value.Sel.Name == "NewFixtureNotAcceptedEvidence") {
				violation = fmt.Errorf("fixture terminal constructor in production %s", value.Sel.Name)
			}
		}
		return violation == nil
	})
	return violation
}

func TestReliableSubmitFoundationHasNoRuntimeWiring(t *testing.T) {
	repoRoot := admissionRepoRoot(t)
	for _, rel := range []string{
		"es/admission/types.go",
		"es/admission/service.go",
		"es/admission/submit.go",
		"es/admission/resolved_execution_plan.go",
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
		assertAdmissionFoundationOmitsAll(t, rel, source,
			"reliableSubmit",
			"ReliableSubmit",
			"reliable_submit",
			"reliable-submit-request",
			"internal/reliablesubmit",
			"modernc.org/sqlite",
		)
	}
}

func TestReliableSubmitBindingProducerHasNoProductionCaller(t *testing.T) {
	producerFiles := []string{"reliable_submit_binding.go", "reliable_submit_binding_encoding.go"}
	allowed := map[string]bool{
		producerFiles[0]: true,
		producerFiles[1]: true,
	}
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		name := entry.Name()
		if strings.HasPrefix(name, "reliable_submit_binding") && strings.HasSuffix(name, ".go") &&
			!strings.HasSuffix(name, "_test.go") && !allowed[name] {
			t.Fatalf("unreviewed reliable binding production source %s", name)
		}
	}

	for _, rel := range producerFiles {
		if err := bindingValidateProducerSource(rel, mustReadAdmissionSource(t, rel)); err != nil {
			t.Fatal(err)
		}
	}

	views := loadTypedProductionPackages(t, "./es/admission")
	admissionPackagePath := "execution-substrate/es/admission"
	allowedExistingCalls := map[string]bool{
		"addWithinLimit":                           true,
		"defaultResolvedJobEnvelope":               true,
		"digestBytes":                              true,
		"hasOverlappingRuntimeMountTargets":        true,
		"isLabeledSHA256Digest":                    true,
		"normalizeAbsoluteSubmitPath":              true,
		"normalizeRuntimeMountTargetPath":          true,
		"ValidateReservedRuntimePaths":             true,
		"validateResolvedExecutionMaterialBudget":  true,
		"validateRuntimeMountArchiveWithinBudgets": true,
	}
	for _, view := range views {
		pkg := requireTypedProductionPackage(t, view.packages, admissionPackagePath)
		for rel, file := range pkg.files {
			if err := bindingValidateOtherProductionSource(rel, file); err != nil {
				t.Fatal(err)
			}
		}
		builder := requirePackageFunction(t, pkg, "buildReliableSubmitAdmissionBinding")
		if err := validateTypedReferenceInventory("selected private binding callers", pkg.referencesTo(builder), privateBindingCallerInventory(), true); err != nil {
			t.Fatalf("%s private binding caller closure: %v", view.target, err)
		}
		for _, rel := range producerFiles {
			file := pkg.files["es/admission/"+rel]
			if file == nil {
				t.Fatalf("%s typed production view omitted %s", view.target, rel)
			}
			parents := astParentMap(file)
			ast.Inspect(file, func(node ast.Node) bool {
				identifier, ok := node.(*ast.Ident)
				if !ok {
					return true
				}
				function, ok := pkg.info.Uses[identifier].(*types.Func)
				if !ok || function.Pkg() == nil || function.Pkg().Path() != admissionPackagePath {
					return true
				}
				definitionFile := filepath.Base(guardPosition(pkg.fset, function.Pos()).Filename)
				if allowed[definitionFile] {
					return true
				}
				if !allowedExistingCalls[function.Name()] {
					t.Fatalf("%s calls unreviewed admission helper %s from %s", rel, function.Name(), definitionFile)
				}
				var expression ast.Expr = identifier
				if selector, ok := parents[identifier].(*ast.SelectorExpr); ok && selector.Sel == identifier {
					expression = selector
				}
				call, ok := parents[expression].(*ast.CallExpr)
				if !ok || call.Fun != expression {
					t.Fatalf("%s escapes existing admission helper %s as a function value", rel, function.Name())
				}
				return true
			})
			for _, declaration := range file.Decls {
				function, ok := declaration.(*ast.FuncDecl)
				if !ok || function.Name.Name == "buildReliableSubmitAdmissionBinding" {
					continue
				}
				var references []typedReference
				if function.Recv == nil {
					references = pkg.referencesTo(requirePackageFunction(t, pkg, function.Name.Name))
				} else {
					receiver := receiverTypeName(function.Recv.List[0].Type)
					references = pkg.referencesTo(requirePackageMethod(t, pkg, receiver, function.Name.Name))
				}
				for _, reference := range references {
					privateHelperSites := map[string]map[string]bool{
						"newReliableBindingFamily": {
							"es/admission/reliable_submit_replay_intent.go:parsePrivateReplayDelivery":     true,
							"es/admission/reliable_submit_replay_hydration.go:decodePrivateReplayOriginal": true,
							"es/admission/reliable_submit_operational_format.go:verifyOperationalOriginal": true,
						},
						"newPrivateBindingKey": {
							"es/admission/reliable_submit_replay_private.go:newPrivateSyntheticKeyBundle":   true,
							"es/admission/reliable_submit_operational_format.go:newOperationalOriginalKeys": true,
						},
					}
					if privateHelperSites[function.Name.Name][reference.site] && reference.directCall && !reference.methodExpression && !reference.insideFuncLiteral {
						continue
					}
					if !reference.directCall || reference.methodExpression || reference.insideFuncLiteral ||
						!strings.HasPrefix(reference.site, "es/admission/reliable_submit_binding.go:") &&
							!strings.HasPrefix(reference.site, "es/admission/reliable_submit_binding_encoding.go:") {
						t.Fatalf("%s helper %s escaped private direct-call closure: %v", view.target, function.Name.Name, reference)
					}
				}
			}
		}
	}
	modelPath := "execution-substrate/es/admission/internal/reliablesubmit"
	for _, name := range []string{"ResolvedCategory", "NewEffectivePlanWitness", "NewPlanBinding", "NewBoundPlan"} {
		references := mergedPackageFunctionReferences(t, views, "execution-substrate/es/admission", modelPath, name)
		if len(references) == 0 {
			t.Fatalf("private binding producer never constructs model value through %s", name)
		}
		for _, reference := range references {
			if !reference.directCall || reference.methodExpression || reference.insideFuncLiteral ||
				!strings.HasPrefix(reference.site, "es/admission/reliable_submit_binding.go:") &&
					!strings.HasPrefix(reference.site, "es/admission/reliable_submit_binding_encoding.go:") {
				t.Fatalf("private model constructor %s escaped unwired binding source: %v", name, reference)
			}
		}
	}
	for _, name := range []string{"ExplicitlyInapplicableCategory", "OutputIdentityExplicitlyInapplicableForPermittedExecutionKind"} {
		if references := mergedPackageFunctionReferences(t, views, "execution-substrate/es/admission", modelPath, name); len(references) != 0 {
			t.Fatalf("current admission binding selected generic inapplicability through %s: %v", name, references)
		}
	}
}

// This is a closed check for the two current, unwired producer files. The
// source mutants below use the same checker as the real-source guard.
const bindingPrimaryFunctionNames = "newReliableBindingFamily newPrivateBindingKey bindingKeyIDValid buildReliableSubmitAdmissionBinding bindingHeader bindingMaterialBudgetValid bindingSchemaValid bindingModeValid bindingTimeoutValid bindingCPUValid bindingMemoryValid bindingProfileValid bindingExactDigest bindingPrimaryValid bindingDerivationValid bindingOutputValid bindingCommandValid bindingEnvironmentValid bindingMountsValid bindingNetworkValid bindingAuthorityValid bindingSupportValid bindingTmpfsValid bindingJobEnvelopeValid bindingTrustValid bindingPlacementValid bindingCaptureMaterialIdentities bindingPresentMaterial bindingOptionalTrustMaterial bindingInvalidFamily bindingInvalidKey bindingInvalidFacts bindingInputTooLarge"

const bindingEncodingFunctionNames = "bindingCheckedAdd fieldHeader writeBytes writeString writeUint64 bindingEmitString bindingEmitI64 bindingEmitBool bindingEmitState bindingEmitDigestOfBytes bindingEmitMaterialDescriptor bindingMeasureRecord bindingEmitRecord bindingRecordFields bindingEmitStringSequence bindingEmitMountSequence bindingEmitEntrySequence bindingEmitMap bindingEncodeCanonical bindingMeasureCanonical"

func bindingValidateProducerSource(rel, source string) error {
	file, err := parser.ParseFile(token.NewFileSet(), rel, source, parser.ParseComments)
	if err != nil {
		return fmt.Errorf("%s parse: %w", rel, err)
	}
	imports := map[string]string{}
	var expectedImports, expectedAPIs, expectedFunctions string
	switch rel {
	case "reliable_submit_binding.go":
		expectedImports = "bytes crypto/hmac crypto/sha256 errors slices strconv strings execution-substrate/es/admission/internal/reliablesubmit"
		expectedAPIs = "bytes.Equal crypto/hmac.New crypto/sha256.New crypto/sha256.Size crypto/sha256.Sum256 errors.New slices.Equal strconv.Itoa strings.TrimSpace reliablesubmit.BoundPlan reliablesubmit.EffectivePlanCategory reliablesubmit.EffectivePlanCategoryArtifactIdentity reliablesubmit.EffectivePlanCategoryAuthorityHandoffApplicability reliablesubmit.EffectivePlanCategoryCPU reliablesubmit.EffectivePlanCategoryCommandAndArgv reliablesubmit.EffectivePlanCategoryCompleteness reliablesubmit.EffectivePlanCategoryDerivationSpecIdentity reliablesubmit.EffectivePlanCategoryEnvironmentAdditions reliablesubmit.EffectivePlanCategoryExecutionMode reliablesubmit.EffectivePlanCategoryMemory reliablesubmit.EffectivePlanCategoryMounts reliablesubmit.EffectivePlanCategoryNetworkPosture reliablesubmit.EffectivePlanCategoryOutputIdentity reliablesubmit.EffectivePlanCategoryRequestSchemaOrVersion reliablesubmit.EffectivePlanCategoryRuntimeProfile reliablesubmit.EffectivePlanCategoryTimeoutSemantics reliablesubmit.NewBoundPlan reliablesubmit.NewEffectivePlanWitness reliablesubmit.NewPlanBinding reliablesubmit.ResolvedCategory"
		expectedFunctions = bindingPrimaryFunctionNames
	case "reliable_submit_binding_encoding.go":
		expectedImports = "crypto/sha256 encoding/binary io sort unicode/utf8"
		expectedAPIs = "crypto/sha256.Size crypto/sha256.Sum256 encoding/binary.BigEndian io.Writer sort.Strings unicode/utf8.ValidString"
		expectedFunctions = bindingEncodingFunctionNames
	default:
		return fmt.Errorf("unreviewed binding producer file %s", rel)
	}
	expectedImportSet := bindingWordSet(expectedImports)
	expectedAPISet := bindingWordSet(expectedAPIs)
	expectedFunctionSet := bindingWordSet(expectedFunctions)
	allProducerFunctions := bindingWordSet(bindingPrimaryFunctionNames + " " + bindingEncodingFunctionNames)
	if len(file.Imports) != len(expectedImportSet) {
		return fmt.Errorf("%s changed exact reviewed import count", rel)
	}
	for _, imported := range file.Imports {
		path, err := strconv.Unquote(imported.Path.Value)
		if err != nil || !expectedImportSet[path] || imported.Name != nil {
			return fmt.Errorf("%s has unreviewed import %s", rel, imported.Path.Value)
		}
		name := path[strings.LastIndex(path, "/")+1:]
		if path == "execution-substrate/es/admission/internal/reliablesubmit" {
			name = "reliablesubmit"
		}
		if imports[name] != "" {
			return fmt.Errorf("%s repeats import name %s", rel, name)
		}
		imports[name] = path
	}
	for _, declaration := range file.Decls {
		switch typed := declaration.(type) {
		case *ast.GenDecl:
			if typed.Tok == token.VAR {
				return fmt.Errorf("%s adds package-global mutable state", rel)
			}
			for _, specification := range typed.Specs {
				switch spec := specification.(type) {
				case *ast.TypeSpec:
					if spec.Name.IsExported() {
						return fmt.Errorf("%s exports type %s", rel, spec.Name.Name)
					}
					structure, ok := spec.Type.(*ast.StructType)
					if !ok {
						continue
					}
					redacted := false
					for _, field := range structure.Fields.List {
						if field.Tag != nil {
							return fmt.Errorf("%s type %s has serialization tag", rel, spec.Name.Name)
						}
						if len(field.Names) == 0 && exprSourceName(field.Type) == "privateExecutionValue" {
							redacted = true
						}
						for _, name := range field.Names {
							if name.IsExported() {
								return fmt.Errorf("%s type %s exports field %s", rel, spec.Name.Name, name.Name)
							}
						}
					}
					if !redacted {
						return fmt.Errorf("%s type %s lacks private redaction marker", rel, spec.Name.Name)
					}
				case *ast.ValueSpec:
					for _, name := range spec.Names {
						if name.IsExported() {
							return fmt.Errorf("%s exports value %s", rel, name.Name)
						}
					}
				}
			}
		case *ast.FuncDecl:
			if typed.Name.IsExported() || !expectedFunctionSet[typed.Name.Name] {
				return fmt.Errorf("%s has unreviewed function or method %s", rel, typed.Name.Name)
			}
			delete(expectedFunctionSet, typed.Name.Name)
			if err := bindingValidateInputOwnership(rel, typed); err != nil {
				return err
			}
		}
	}
	if len(expectedFunctionSet) != 0 {
		return fmt.Errorf("%s omits reviewed producer functions", rel)
	}
	forbidden := bindingWordSet("Service PrepareRequest esconfig snapshotAdmissionRequest validatePrepareRequest prepareAdmission resolveExecutionForSubmit resolveRuntimeMounts fetchArtifactDiscovery fetchPayloadBytesWithin captureRuntimeSupport captureWorkloadTrustMaterial newResolvedExecutionPlan materializeExecutionInputs newResolvedRunProjection buildNomadJobSpec claimStagingCustodyFromQualifiedRoot defaultSubmitCPU defaultSubmitMemoryMB")
	parents := astParentMap(file)
	var violation error
	ast.Inspect(file, func(node ast.Node) bool {
		if violation != nil {
			return false
		}
		switch typed := node.(type) {
		case *ast.Ident:
			if forbidden[typed.Name] {
				violation = fmt.Errorf("%s references admission/runtime source %s", rel, typed.Name)
			} else if allProducerFunctions[typed.Name] {
				if declaration, ok := parents[typed].(*ast.FuncDecl); ok && declaration.Name == typed {
					break
				}
				if typed.Name == "buildReliableSubmitAdmissionBinding" {
					violation = fmt.Errorf("%s references unwired binding builder", rel)
					break
				}
				var expression ast.Expr = typed
				if selector, ok := parents[typed].(*ast.SelectorExpr); ok && selector.Sel == typed {
					expression = selector
				}
				call, ok := parents[expression].(*ast.CallExpr)
				if !ok || call.Fun != expression {
					violation = fmt.Errorf("%s escapes producer helper %s as function value", rel, typed.Name)
				}
			}
		case *ast.SelectorExpr:
			if root, ok := typed.X.(*ast.Ident); ok && imports[root.Name] != "" {
				path := imports[root.Name]
				api := path + "." + typed.Sel.Name
				if path == "execution-substrate/es/admission/internal/reliablesubmit" {
					api = "reliablesubmit." + typed.Sel.Name
				}
				if !expectedAPISet[api] {
					violation = fmt.Errorf("%s references unreviewed imported API %s", rel, api)
				}
			}
		}
		return true
	})
	return violation
}

func bindingWordSet(words string) map[string]bool {
	set := make(map[string]bool)
	for _, word := range strings.Fields(words) {
		set[word] = true
	}
	return set
}

func bindingValidateInputOwnership(rel string, function *ast.FuncDecl) error {
	if function.Body == nil {
		return nil
	}
	roots := make(map[*ast.Object]bool)
	if function.Type.Params != nil {
		for _, field := range function.Type.Params.List {
			_, slice := field.Type.(*ast.ArrayType)
			_, mapping := field.Type.(*ast.MapType)
			resolved := exprSourceName(field.Type) == "resolvedExecution"
			if !slice && !mapping && !resolved {
				continue
			}
			for _, name := range field.Names {
				if name.Obj != nil {
					roots[name.Obj] = true
				}
			}
		}
	}
	var rooted func(ast.Expr) bool
	rooted = func(expr ast.Expr) bool {
		switch typed := expr.(type) {
		case *ast.Ident:
			return typed.Obj != nil && roots[typed.Obj]
		case *ast.SelectorExpr:
			return rooted(typed.X)
		case *ast.IndexExpr:
			return rooted(typed.X)
		case *ast.SliceExpr:
			return rooted(typed.X)
		case *ast.ParenExpr:
			return rooted(typed.X)
		case *ast.StarExpr:
			return rooted(typed.X)
		case *ast.UnaryExpr:
			return rooted(typed.X)
		case *ast.TypeAssertExpr:
			return rooted(typed.X)
		default:
			return false
		}
	}
	var violation error
	ast.Inspect(function.Body, func(node ast.Node) bool {
		if violation != nil {
			return false
		}
		switch typed := node.(type) {
		case *ast.AssignStmt:
			for _, lhs := range typed.Lhs {
				if rooted(lhs) {
					violation = fmt.Errorf("%s %s writes captured input or alias", rel, function.Name.Name)
					return false
				}
			}
			for index, lhs := range typed.Lhs {
				if typed.Tok != token.DEFINE && typed.Tok != token.ASSIGN || index >= len(typed.Rhs) || !rooted(typed.Rhs[index]) {
					continue
				}
				if name, ok := lhs.(*ast.Ident); ok {
					if name.Obj != nil {
						roots[name.Obj] = true
					}
				} else {
					violation = fmt.Errorf("%s %s escapes captured input through assignment", rel, function.Name.Name)
				}
			}
		case *ast.ValueSpec:
			for index, name := range typed.Names {
				if index < len(typed.Values) && rooted(typed.Values[index]) && name.Obj != nil {
					roots[name.Obj] = true
				}
			}
		case *ast.RangeStmt:
			if rooted(typed.X) && typed.Tok == token.DEFINE {
				if name, ok := typed.Value.(*ast.Ident); ok && name.Obj != nil {
					roots[name.Obj] = true
				}
			}
		case *ast.IncDecStmt:
			if rooted(typed.X) {
				violation = fmt.Errorf("%s %s increments captured input or alias", rel, function.Name.Name)
			}
		case *ast.UnaryExpr:
			if typed.Op == token.AND && rooted(typed.X) {
				violation = fmt.Errorf("%s %s takes mutable pointer to captured input or alias", rel, function.Name.Name)
			}
		case *ast.ReturnStmt:
			for _, result := range typed.Results {
				if rooted(result) {
					violation = fmt.Errorf("%s %s returns captured input or alias", rel, function.Name.Name)
				}
			}
		case *ast.CallExpr:
			rootedArg := false
			for _, arg := range typed.Args {
				rootedArg = rootedArg || rooted(arg)
			}
			if !rootedArg {
				break
			}
			if callee, ok := typed.Fun.(*ast.Ident); ok {
				if len(typed.Args) != 0 && rooted(typed.Args[0]) && bindingWordSet("append copy delete clear")[callee.Name] {
					violation = fmt.Errorf("%s %s mutates captured input or alias through %s", rel, function.Name.Name, callee.Name)
				} else if callee.Obj != nil && callee.Obj.Kind == ast.Var {
					violation = fmt.Errorf("%s %s escapes captured input to function variable %s", rel, function.Name.Name, callee.Name)
				} else if callee.Obj == nil && !strings.HasPrefix(callee.Name, "binding") &&
					!bindingPermittedEntryModeConversion(function.Name.Name, callee.Name, typed.Args) &&
					!bindingWordSet("addWithinLimit defaultResolvedJobEnvelope digestBytes hasOverlappingRuntimeMountTargets isLabeledSHA256Digest normalizeAbsoluteSubmitPath normalizeRuntimeMountTargetPath ValidateReservedRuntimePaths validateResolvedExecutionMaterialBudget validateRuntimeMountArchiveWithinBudgets append copy len int64 string")[callee.Name] {
					violation = fmt.Errorf("%s %s passes captured input to unreviewed function %s", rel, function.Name.Name, callee.Name)
				}
			} else if callee, ok := typed.Fun.(*ast.SelectorExpr); ok {
				if pkg, ok := callee.X.(*ast.Ident); ok && (pkg.Name == "sort" || pkg.Name == "slices") && callee.Sel.Name != "Equal" {
					violation = fmt.Errorf("%s %s passes captured input or alias to mutator %s.%s", rel, function.Name.Name, pkg.Name, callee.Sel.Name)
				}
			} else {
				violation = fmt.Errorf("%s %s escapes captured input through indirect call", rel, function.Name.Name)
			}
		}
		return true
	})
	return violation
}

// The sole input-rooted uint32 conversion detaches a parsed mode into an
// output descriptor. It neither calls an effect owner nor writes its input.
func bindingPermittedEntryModeConversion(functionName, calleeName string, args []ast.Expr) bool {
	if functionName != "bindingCaptureMaterialIdentities" || calleeName != "uint32" || len(args) != 1 {
		return false
	}
	selector, ok := args[0].(*ast.SelectorExpr)
	if !ok || selector.Sel.Name != "mode" {
		return false
	}
	entry, ok := selector.X.(*ast.Ident)
	return ok && entry.Name == "entry"
}

func bindingValidateOtherProductionSource(rel string, file *ast.File) error {
	name := filepath.Base(rel)
	if name == "reliable_submit_binding.go" || name == "reliable_submit_binding_encoding.go" {
		return nil
	}
	guarded := bindingWordSet(bindingPrimaryFunctionNames + " " + bindingEncodingFunctionNames)
	parents := astParentMap(file)
	var violation error
	ast.Inspect(file, func(node ast.Node) bool {
		identifier, ok := node.(*ast.Ident)
		if !ok || !guarded[identifier.Name] ||
			!strings.HasPrefix(identifier.Name, "binding") && identifier.Name != "buildReliableSubmitAdmissionBinding" &&
				identifier.Name != "newReliableBindingFamily" && identifier.Name != "newPrivateBindingKey" {
			return true
		}
		if declaration, ok := parents[identifier].(*ast.FuncDecl); ok && declaration.Name == identifier {
			return true
		}
		// Only the named runtime-unwired fixture and operational sites consume
		// PB1 and its selected family/key constructors.
		allowedPrivate := map[string]map[string]string{
			"es/admission/reliable_submit_replay_private.go": {
				"buildReliableSubmitAdmissionBinding": "composePrivateSyntheticReplay",
				"newPrivateBindingKey":                "newPrivateSyntheticKeyBundle",
			},
			"es/admission/reliable_submit_replay_hydration.go": {
				"buildReliableSubmitAdmissionBinding": "decodePrivateReplayOriginal",
				"newReliableBindingFamily":            "decodePrivateReplayOriginal",
			},
			"es/admission/reliable_submit_replay_intent.go": {
				"newReliableBindingFamily": "parsePrivateReplayDelivery",
			},
			"es/admission/reliable_submit_operational_handoff.go": {
				"buildReliableSubmitAdmissionBinding": "composeOperationalOriginal",
			},
			"es/admission/reliable_submit_operational_format.go": {
				"buildReliableSubmitAdmissionBinding": "verifyOperationalOriginal",
				"newReliableBindingFamily":            "verifyOperationalOriginal",
				"newPrivateBindingKey":                "newOperationalOriginalKeys",
			},
		}
		if byName := allowedPrivate[rel]; byName != nil {
			if owner := byName[identifier.Name]; owner != "" {
				function := enclosingFunction(parents, identifier)
				call, ok := parents[identifier].(*ast.CallExpr)
				if function != nil && function.Name.Name == owner && ok && call.Fun == identifier {
					return true
				}
			}
		}
		violation = fmt.Errorf("%s references private binding producer %s outside closed files", rel, identifier.Name)
		return false
	})
	return violation
}

func TestReliableSubmitBindingGuardrailsRejectMutants(t *testing.T) {
	const primary = "reliable_submit_binding.go"
	const encoding = "reliable_submit_binding_encoding.go"
	const builderOpening = "func buildReliableSubmitAdmissionBinding(resolved resolvedExecution, family reliableBindingFamily, key privateBindingKey) (admissionBindingAssessment, error) {\n"
	baseline := map[string]string{
		primary:  mustReadAdmissionSource(t, primary),
		encoding: mustReadAdmissionSource(t, encoding),
	}
	replaceOne := func(t *testing.T, source, old, replacement string) string {
		t.Helper()
		if count := strings.Count(source, old); count != 1 {
			t.Fatalf("source mutation anchor occurs %d times, want one", count)
		}
		return strings.Replace(source, old, replacement, 1)
	}
	mutants := []struct {
		name   string
		rel    string
		mutate func(*testing.T, string) string
	}{
		{"effect import and Open call", primary, func(t *testing.T, source string) string {
			source = replaceOne(t, source, "\t\"strings\"\n", "\t\"strings\"\n\t\"syscall\"\n")
			return replaceOne(t, source, builderOpening, builderOpening+"\t_, _ = syscall.Open(\"/not-executed\", 0, 0)\n")
		}},
		{"unreviewed imported API", encoding, func(t *testing.T, source string) string {
			return replaceOne(t, source, "sort.Strings(keys)", "sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })")
		}},
		{"direct input write", primary, func(t *testing.T, source string) string {
			return replaceOne(t, source, builderOpening, builderOpening+"\tresolved.plan.semanticEnvironment[\"sentinel\"] = \"changed\"\n")
		}},
		{"map alias write", primary, func(t *testing.T, source string) string {
			return replaceOne(t, source, builderOpening, builderOpening+"\talias := resolved.plan.semanticEnvironment\n\talias[\"sentinel\"] = \"changed\"\n")
		}},
		{"map alias reassignment", primary, func(t *testing.T, source string) string {
			return replaceOne(t, source, builderOpening, builderOpening+"\tvar alias map[string]string\n\talias = resolved.plan.semanticEnvironment\n\talias[\"sentinel\"] = \"changed\"\n")
		}},
		{"slice alias write", primary, func(t *testing.T, source string) string {
			return replaceOne(t, source, builderOpening, builderOpening+"\talias := resolved.material.mounts\n\talias[0].entries = nil\n")
		}},
		{"slice alias reassignment", primary, func(t *testing.T, source string) string {
			return replaceOne(t, source, builderOpening, builderOpening+"\tvar alias []validatedMountArchive\n\talias = resolved.material.mounts\n\talias[0].entries = nil\n")
		}},
		{"map alias delete", primary, func(t *testing.T, source string) string {
			return replaceOne(t, source, builderOpening, builderOpening+"\talias := resolved.plan.semanticEnvironment\n\tdelete(alias, \"sentinel\")\n")
		}},
		{"slice alias append", primary, func(t *testing.T, source string) string {
			return replaceOne(t, source, builderOpening, builderOpening+"\talias := resolved.material.mounts\n\t_ = append(alias, resolved.material.mounts[0])\n")
		}},
		{"input alias escape", primary, func(t *testing.T, source string) string {
			return replaceOne(t, source, builderOpening, builderOpening+"\talias := resolved.plan.semanticEnvironment\n\tsink := func(map[string]string) {}\n\tsink(alias)\n")
		}},
		{"builder function value", primary, func(t *testing.T, source string) string {
			return replaceOne(t, source, builderOpening, builderOpening+"\t_ = buildReliableSubmitAdmissionBinding\n")
		}},
		{"helper function value", primary, func(t *testing.T, source string) string {
			return replaceOne(t, source, builderOpening, builderOpening+"\t_ = bindingEmitMap\n")
		}},
		{"config reread", primary, func(t *testing.T, source string) string {
			return replaceOne(t, source, builderOpening, builderOpening+"\tvar _ *Service\n")
		}},
		{"public exposure", primary, func(t *testing.T, source string) string {
			return replaceOne(t, source, "func bindingHeader(id string) []byte {", "func BindingHeader(id string) []byte {")
		}},
	}
	for _, mutant := range mutants {
		t.Run(mutant.name, func(t *testing.T) {
			source := baseline[mutant.rel]
			if err := bindingValidateProducerSource(mutant.rel, source); err != nil {
				t.Fatalf("unmodified source fails its mutant checker: %v", err)
			}
			changed := mutant.mutate(t, source)
			if err := bindingValidateProducerSource(mutant.rel, changed); err == nil {
				t.Fatal("source mutant escaped the producer guard")
			}
		})
	}
	for _, rel := range []string{"service.go", "submit.go"} {
		source := mustReadAdmissionSource(t, rel)
		parse := func(t *testing.T, data string) *ast.File {
			t.Helper()
			file, err := parser.ParseFile(token.NewFileSet(), rel, data, 0)
			if err != nil {
				t.Fatalf("parse source fixture: %v", err)
			}
			return file
		}
		for _, mutant := range []struct {
			name string
			body string
		}{
			{"direct production caller", "func unreviewedBindingCaller(resolved resolvedExecution, family reliableBindingFamily, key privateBindingKey) { _, _ = buildReliableSubmitAdmissionBinding(resolved, family, key) }"},
			{"builder function value outside closure", "var escapedBuilder = buildReliableSubmitAdmissionBinding"},
			{"helper function value outside closure", "var escapedHelper = bindingEmitMap"},
		} {
			t.Run(rel+"/"+mutant.name, func(t *testing.T) {
				if err := bindingValidateOtherProductionSource(rel, parse(t, source)); err != nil {
					t.Fatalf("unmodified source fails its mutant checker: %v", err)
				}
				if err := bindingValidateOtherProductionSource(rel, parse(t, source+"\n"+mutant.body+"\n")); err == nil {
					t.Fatal("outside-closure source mutant escaped the producer guard")
				}
			})
		}
	}
}

func TestReliableSubmitFoundationSourceBoundary(t *testing.T) {
	for _, rel := range reliableSubmitFoundationFiles() {
		file := mustParseAdmissionSource(t, rel)
		assertReliableSubmitFoundationImports(t, rel, file)
		assertReliableSubmitFoundationHasNoExportedSurface(t, rel, file)
		source := mustReadAdmissionSource(t, rel)
		assertAdmissionFoundationOmitsAll(t, rel, source,
			"database/sql",
			"modernc.org/sqlite",
			"pgx",
			"postgres",
			"net/http",
			"StatusAccepted",
			"StatusOK",
			"HTTPStatus",
			"http.Status",
			"os.",
			"Mkdir",
			"OpenFile",
			"Coordinator",
			"ControlPlane",
			"Bridge",
			"work_item_id",
			"attempt_id",
			"trace_id",
			"request_id",
			"provider_id",
			"nomad_job_id",
			"allocation_id",
			"EvalID",
			"rawBytes",
			"func (k reliableSubmitKey) Bytes",
			"func (k reliableSubmitKey) Raw",
			"type reliableSubmitPhase",
			"ClaimPhase",
			"ProviderEffectPhase",
			"ProducerContract",
			"producer contract",
			"capability",
			"enabled",
		)
	}
}

func TestReliableSubmitRequestPrivacyGuardrails(t *testing.T) {
	file := mustParseAdmissionSource(t, "reliable_submit_contract.go")
	source := mustReadAdmissionSource(t, "reliable_submit_contract.go")
	identityFile := mustParseAdmissionSource(t, "reliable_submit_identity.go")
	outcomeFile := mustParseAdmissionSource(t, "reliable_submit_outcome.go")
	assertValidatedReliableSubmitRequestDoesNotRetainRawKey(t, file)
	assertReliableSubmitHasNoPackageRawKeyBearingTypes(t, file)
	assertReliableSubmitWireSurrogateIsFunctionLocal(t, file)
	assertReliableSubmitTypesHaveNoProjectionOrErrorMethods(t, file)
	assertReliableSubmitTypesHaveNoProjectionOrErrorMethods(t, identityFile)
	assertReliableSubmitTypesHaveNoProjectionOrErrorMethods(t, outcomeFile)
	assertReliableSubmitKeyMaterialHasNoRawAccessor(t, file)
	assertReliableSubmitProductionHasNoMalformedWrapping(t, file)
	assertReliableSubmitProductionHasNoMalformedWrapping(t, identityFile)
	assertReliableSubmitProductionHasNoMalformedWrapping(t, outcomeFile)
	assertReliableSubmitContractOmitsFormattingImportsAndCalls(t, file)
	assertAdmissionFoundationContainsAll(t, "reliable-submit request privacy source", source,
		"func parseValidatedReliableSubmitRequest",
		"func decodeStrictReliableSubmitJSON",
		"func decodeCanonicalReliableSubmitKey",
		"deriveReliableSubmitClaimRefs(canonicalSPIFFEURI, rawSubmitKey)",
		"type reliableSubmitWireMarker struct",
	)
	assertAdmissionFoundationOmitsAll(t, "reliable-submit request privacy source", source,
		"type reliableSubmitRequest struct",
		"type reliableSubmitRequestMarker struct",
		"type reliableSubmitKey struct",
		"type validatedReliableSubmitRequest struct {\n\trequest",
		"func (k reliableSubmitKey) Bytes",
		"func (k reliableSubmitKey) Raw",
		"func (k reliableSubmitKey) MarshalJSON",
		"func (k reliableSubmitKey) MarshalText",
		"func (r validatedReliableSubmitRequest) MarshalJSON",
		"func (r validatedReliableSubmitRequest) MarshalText",
		"func (r validatedReliableSubmitRequest) String",
		"func (r validatedReliableSubmitRequest) GoString",
		"func (r validatedReliableSubmitRequest) Format",
		"func (r validatedReliableSubmitRequest) Error",
	)
}

func TestReliableSubmitFoundationRejectedPlanSourceIsAbsent(t *testing.T) {
	for _, rel := range []string{
		"reliable_submit_plan.go",
		"reliable_submit_plan_test.go",
	} {
		if _, err := os.Stat(rel); !os.IsNotExist(err) {
			t.Fatalf("%s must be absent after reliable-submit scope reset, stat error: %v", rel, err)
		}
	}
}

func TestReliableSubmitFoundationDoesNotAlterCurrentPublicDeclarationOrConfig(t *testing.T) {
	repoRoot := admissionRepoRoot(t)
	typesSource := mustReadAdmissionRepoSource(t, repoRoot, "es/admission/types.go")
	producerSource := mustReadAdmissionRepoSource(t, repoRoot, "es/admission/producercontract.go")
	configSource := mustReadAdmissionRepoSource(t, repoRoot, "es/config/config.go")
	serverSource := mustReadAdmissionRepoSource(t, repoRoot, "es/api/server.go")
	httpxSource := mustReadAdmissionRepoSource(t, repoRoot, "internal/httpx/httpx.go")

	producerDeclaration := admissionSourceSection(t, typesSource, "type ProducerContractDeclaration struct {", "type RuntimeInterface struct {")
	assertAdmissionFoundationOmitsAll(t, "ProducerContractDeclaration", producerDeclaration,
		"Reliable",
		"reliable_submit",
		"Capability",
	)
	assertAdmissionFoundationOmitsAll(t, "producercontract.go", producerSource,
		"ReliableSubmit",
		"reliable_submit",
		reliableSubmitContractV1,
	)
	executionConfig := admissionSourceSection(t, configSource, "type ExecutionConfig struct {", "type VerificationConfig struct {")
	assertAdmissionFoundationOmitsAll(t, "ExecutionConfig", executionConfig,
		"ReliableSubmit",
		"reliable_submit",
		"SQLite",
		"Database",
		"StorePath",
	)
	assertAdmissionFoundationContainsAll(t, "server strict submit path", serverSource,
		"func (s *Server) handleSubmit",
		"request, ok := s.decodeAuthorizedExecutionRequest(w, r)",
		"result, err := s.service.Submit(r.Context(), request)",
	)
	assertAdmissionFoundationContainsAll(t, "strict decoder", httpxSource,
		"decoder.DisallowUnknownFields()",
		"trailing data after first JSON document",
	)
	assertAdmissionFoundationOmitsAll(t, "server.go reliable handling", serverSource,
		"reliable_submit",
		"ReliableSubmit",
		reliableSubmitRequestSchemaV1,
	)
}

func TestReliableSubmitFoundationDoesNotModifyPrivateModelOrStoreBoundary(t *testing.T) {
	repoRoot := admissionRepoRoot(t)
	for _, rel := range []string{
		"es/admission/internal/reliablesubmit/model.go",
		"es/admission/internal/reliablesubmit/durable_operation.go",
		"es/admission/internal/reliablesubmit/durable_record.go",
		"es/admission/internal/reliablesubmit/store.go",
		"es/admission/internal/reliablesubmit/durable_service.go",
		"es/admission/internal/reliablesubmit/sqlite_store.go",
		"es/admission/internal/reliablesubmit/sqlite_migrations.go",
	} {
		source := mustReadAdmissionRepoSource(t, repoRoot, rel)
		assertAdmissionFoundationOmitsAll(t, rel, source,
			"reliableSubmitRequest",
			"reliableSubmitEffectivePlan",
			"reliableSubmitOutcome",
			"execution-substrate.reliable-submit-request/v1",
			"es/reliable-submit/caller-ref/v1",
			"es/reliable-submit/effective-plan/v1",
		)
	}
}

func reliableSubmitFoundationFiles() []string {
	return []string{
		"reliable_submit_contract.go",
		"reliable_submit_identity.go",
		"reliable_submit_outcome.go",
	}
}

func assertReliableSubmitFoundationImports(t *testing.T, rel string, file *ast.File) {
	t.Helper()
	for _, imported := range file.Imports {
		importPath, err := strconv.Unquote(imported.Path.Value)
		if err != nil {
			t.Fatalf("%s unquote import path: %v", rel, err)
		}
		switch importPath {
		case "database/sql", "modernc.org/sqlite", "net", "net/http", "os", "io", "io/fs", "path", "path/filepath":
			t.Fatalf("%s imports forbidden runtime/storage/filesystem package %q", rel, importPath)
		}
		for _, fragment := range []string{"pgx", "postgres", "nomad", "coordinator", "bridge"} {
			if strings.Contains(strings.ToLower(importPath), fragment) {
				t.Fatalf("%s import %q violates foundation boundary %q", rel, importPath, fragment)
			}
		}
	}
}

func TestReliableSubmitSourceRepairPreservesRuntimeBoundary(t *testing.T) {
	repoRoot := admissionRepoRoot(t)
	durableService := mustReadAdmissionRepoSource(t, repoRoot, "es/admission/internal/reliablesubmit/durable_service.go")
	assertAdmissionFoundationContainsAll(t, "private durable replay service source", durableService,
		"deriveDurableOperationDescriptor",
		"compareDurableLatestOperation",
		"reloadAfterUnknown",
	)
	assertAdmissionFoundationOmitsAll(t, "private durable replay service source", durableService,
		"reliableSubmitRequest",
		"execution-substrate.reliable-submit-request/v1",
		"SubmitResult",
		"ProducerContractDeclaration",
		"Config",
	)
	TestReliableSubmitFoundationHasNoRuntimeWiring(t)
}

func assertReliableSubmitFoundationHasNoExportedSurface(t *testing.T, rel string, file *ast.File) {
	t.Helper()
	for _, decl := range file.Decls {
		switch typed := decl.(type) {
		case *ast.GenDecl:
			for _, spec := range typed.Specs {
				switch s := spec.(type) {
				case *ast.TypeSpec:
					if s.Name.IsExported() {
						t.Fatalf("%s exports type %s", rel, s.Name.Name)
					}
				case *ast.ValueSpec:
					for _, name := range s.Names {
						if name.IsExported() {
							t.Fatalf("%s exports value %s", rel, name.Name)
						}
					}
				}
			}
		case *ast.FuncDecl:
			if typed.Name.IsExported() {
				if typed.Recv != nil && isReliableSubmitOpaqueProjectionMethod(typed.Name.Name) {
					continue
				}
				t.Fatalf("%s exports function or method %s", rel, typed.Name.Name)
			}
		}
	}
}

func isReliableSubmitOpaqueProjectionMethod(name string) bool {
	switch name {
	case "Format", "String", "GoString", "MarshalJSON", "MarshalText":
		return true
	default:
		return false
	}
}

func assertValidatedReliableSubmitRequestDoesNotRetainRawKey(t *testing.T, file *ast.File) {
	t.Helper()
	structType := reliableSubmitStructType(t, file, "validatedReliableSubmitRequest")
	for _, field := range structType.Fields.List {
		fieldType := exprSourceName(field.Type)
		if fieldType == "reliableSubmitRequest" || fieldType == "reliableSubmitRequestMarker" {
			t.Fatalf("validatedReliableSubmitRequest must not retain raw-key-bearing request type")
		}
		if fieldType == "[32]byte" || fieldType == "[]byte" {
			t.Fatalf("validatedReliableSubmitRequest must not retain raw key bytes")
		}
		if fieldType == "interface{}" || fieldType == "any" || fieldType == "func" {
			t.Fatalf("validatedReliableSubmitRequest must not retain interface or closure-capable field")
		}
		for _, name := range field.Names {
			normalized := strings.ToLower(name.Name)
			if fieldType == "string" && strings.Contains(normalized, "key") {
				t.Fatalf("validatedReliableSubmitRequest must not retain raw submit-key string field")
			}
			if normalized == "request" || strings.Contains(normalized, "wire") || strings.Contains(normalized, "marker") {
				t.Fatalf("validatedReliableSubmitRequest must not retain original request object")
			}
		}
	}
}

func assertReliableSubmitHasNoPackageRawKeyBearingTypes(t *testing.T, file *ast.File) {
	t.Helper()
	for _, decl := range file.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok {
			continue
		}
		for _, spec := range gen.Specs {
			typed, ok := spec.(*ast.TypeSpec)
			if !ok {
				continue
			}
			switch typed.Name.Name {
			case "reliableSubmitRequest", "reliableSubmitRequestMarker", "reliableSubmitKey":
				t.Fatalf("raw-key-bearing package type %s must not exist", typed.Name.Name)
			}
			structType, ok := typed.Type.(*ast.StructType)
			if !ok {
				continue
			}
			for _, field := range structType.Fields.List {
				fieldType := exprSourceName(field.Type)
				for _, name := range field.Names {
					normalized := strings.ToLower(name.Name)
					if name.Name == "SubmitKey" && fieldType == "string" {
						t.Fatalf("package struct %s retains raw submit key field", typed.Name.Name)
					}
					if (fieldType == "[32]byte" || fieldType == "[]byte") &&
						(strings.Contains(normalized, "raw") || strings.Contains(normalized, "key")) {
						t.Fatalf("package struct %s retains raw key byte field %s", typed.Name.Name, name.Name)
					}
				}
			}
		}
	}
}

func assertReliableSubmitWireSurrogateIsFunctionLocal(t *testing.T, file *ast.File) {
	t.Helper()
	foundSubmitKeyField := 0
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "parseValidatedReliableSubmitRequest" {
			continue
		}
		ast.Inspect(fn.Body, func(node ast.Node) bool {
			typed, ok := node.(*ast.TypeSpec)
			if !ok {
				return true
			}
			structType, ok := typed.Type.(*ast.StructType)
			if !ok {
				return true
			}
			for _, field := range structType.Fields.List {
				for _, name := range field.Names {
					if name.Name == "SubmitKey" && exprSourceName(field.Type) == "string" {
						foundSubmitKeyField++
					}
				}
			}
			return true
		})
	}
	if foundSubmitKeyField != 1 {
		t.Fatalf("raw submit key must exist exactly once in the function-local wire surrogate, got %d", foundSubmitKeyField)
	}
}

func assertReliableSubmitTypesHaveNoProjectionOrErrorMethods(t *testing.T, file *ast.File) {
	t.Helper()
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Recv == nil || len(fn.Recv.List) != 1 {
			continue
		}
		receiver := receiverTypeName(fn.Recv.List[0].Type)
		if !strings.HasPrefix(receiver, "reliableSubmit") && receiver != "validatedReliableSubmitRequest" {
			continue
		}
		switch fn.Name.Name {
		case "Format", "String", "GoString", "MarshalJSON", "MarshalText", "Error":
			t.Fatalf("%s must not implement projection/error method %s", receiver, fn.Name.Name)
		}
	}
}

func assertReliableSubmitKeyMaterialHasNoRawAccessor(t *testing.T, file *ast.File) {
	t.Helper()
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Recv == nil || len(fn.Recv.List) != 1 {
			continue
		}
		receiver := receiverTypeName(fn.Recv.List[0].Type)
		if !strings.Contains(strings.ToLower(receiver), "key") {
			continue
		}
		name := strings.ToLower(fn.Name.Name)
		if strings.Contains(name, "raw") || strings.Contains(name, "bytes") || strings.Contains(name, "slice") || strings.Contains(name, "array") {
			t.Fatalf("%s exposes raw key accessor %s", receiver, fn.Name.Name)
		}
	}
}

func assertReliableSubmitProductionHasNoMalformedWrapping(t *testing.T, file *ast.File) {
	t.Helper()
	ast.Inspect(file, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok || len(call.Args) == 0 {
			return true
		}
		lit, ok := call.Args[0].(*ast.BasicLit)
		if !ok {
			return true
		}
		text, err := strconv.Unquote(lit.Value)
		if err != nil {
			return true
		}
		if strings.Contains(text, "%w") {
			t.Fatalf("reliable-submit foundation source must not format reliable values with %%w")
		}
		return true
	})
}

func assertReliableSubmitContractOmitsFormattingImportsAndCalls(t *testing.T, file *ast.File) {
	t.Helper()
	for _, imported := range file.Imports {
		importPath, err := strconv.Unquote(imported.Path.Value)
		if err != nil {
			t.Fatalf("unquote import path: %v", err)
		}
		switch importPath {
		case "fmt", "log", "log/slog":
			t.Fatalf("reliable-submit contract parser must not import formatting/logging package %q", importPath)
		}
	}
	ast.Inspect(file, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		selector, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		switch selector.Sel.Name {
		case "Printf", "Sprintf", "Errorf", "Print", "Println":
			t.Fatalf("reliable-submit contract parser must not call formatting/logging helper %s", selector.Sel.Name)
		}
		return true
	})
}

func reliableSubmitStructType(t *testing.T, file *ast.File, typeName string) *ast.StructType {
	t.Helper()
	for _, decl := range file.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok {
			continue
		}
		for _, spec := range gen.Specs {
			typed, ok := spec.(*ast.TypeSpec)
			if !ok || typed.Name.Name != typeName {
				continue
			}
			structType, ok := typed.Type.(*ast.StructType)
			if !ok {
				t.Fatalf("%s must remain a struct", typeName)
			}
			return structType
		}
	}
	t.Fatalf("type %s not found", typeName)
	return nil
}

func receiverTypeName(expr ast.Expr) string {
	switch typed := expr.(type) {
	case *ast.Ident:
		return typed.Name
	case *ast.StarExpr:
		return receiverTypeName(typed.X)
	case *ast.ParenExpr:
		return receiverTypeName(typed.X)
	case *ast.IndexExpr:
		// The receiver of a method of a generic type: its type parameters are
		// not part of the name.
		return receiverTypeName(typed.X)
	case *ast.IndexListExpr:
		return receiverTypeName(typed.X)
	default:
		return ""
	}
}

func exprSourceName(expr ast.Expr) string {
	switch typed := expr.(type) {
	case *ast.Ident:
		return typed.Name
	case *ast.StarExpr:
		return "*" + exprSourceName(typed.X)
	case *ast.ArrayType:
		return "[]" + exprSourceName(typed.Elt)
	case *ast.SelectorExpr:
		return exprSourceName(typed.X) + "." + typed.Sel.Name
	case *ast.InterfaceType:
		return "interface{}"
	case *ast.FuncType:
		return "func"
	default:
		return ""
	}
}

func mustParseAdmissionSource(t *testing.T, rel string) *ast.File {
	t.Helper()
	data, err := os.ReadFile(rel)
	if err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}
	file, err := parser.ParseFile(token.NewFileSet(), rel, data, parser.ParseComments)
	if err != nil {
		t.Fatalf("parse %s: %v", rel, err)
	}
	return file
}

func mustReadAdmissionSource(t *testing.T, rel string) string {
	t.Helper()
	data, err := os.ReadFile(rel)
	if err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}
	return string(data)
}

func mustReadAdmissionRepoSource(t *testing.T, repoRoot string, rel string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(repoRoot, rel))
	if err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}
	return string(data)
}

func admissionRepoRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatalf("resolve repo root: %v", err)
	}
	return root
}

func admissionSourceSection(t *testing.T, source string, start string, end string) string {
	t.Helper()
	startIndex := strings.Index(source, start)
	if startIndex == -1 {
		t.Fatalf("section start %q not found", start)
	}
	endIndex := strings.Index(source[startIndex:], end)
	if endIndex == -1 {
		t.Fatalf("section end %q not found after %q", end, start)
	}
	return source[startIndex : startIndex+endIndex]
}

func assertAdmissionFoundationContainsAll(t *testing.T, label string, source string, required ...string) {
	t.Helper()
	for _, phrase := range required {
		if !strings.Contains(source, phrase) {
			t.Fatalf("%s missing %q", label, phrase)
		}
	}
}

func assertAdmissionFoundationOmitsAll(t *testing.T, label string, source string, forbidden ...string) {
	t.Helper()
	for _, phrase := range forbidden {
		if strings.Contains(source, phrase) {
			t.Fatalf("%s must not contain %q", label, phrase)
		}
	}
}

// operationalCommissioningPrerequisites names what §8 of the owner contract
// requires before production code may commission, advance or withdraw private
// operational admission, or enter the private handoff. The documentation
// contract test requires the same identifiers, in this order, in that table.
// The list stays on one line.
var operationalCommissioningPrerequisites = []string{"CP-ROLLBACK", "CP-EPOCH", "CP-POLICY-CUSTODY", "CP-NATIVE", "CP-RELEASE", "CP-PUBLIC-MAPPING"}

// operationalCommissioningEntries are the Service methods that create, replace
// or stop the admission view. None has a production caller.
var operationalCommissioningEntries = []string{"commissionOperationalAdmission", "advanceOperationalAdmission", "withdrawOperationalEffects"}

// validateOperationalCommissioningGate is the zero-reference rule of the
// commissioning gate. A production reference fails it and prints the
// prerequisites, so an edit that opens the gate has to name each of them.
func validateOperationalCommissioningGate(entry string, references []typedReference) error {
	if err := validateTypedReferenceInventory(entry, references, map[string]int{}, true); err != nil {
		return fmt.Errorf("%w; a production reference to %s first requires the commissioning prerequisites of the owner contract §8: %s",
			err, entry, strings.Join(operationalCommissioningPrerequisites, ", "))
	}
	return nil
}

type operationalMemberInventory struct {
	typ, name string
	want      map[string]int
	closures  bool
}

// operationalAdmissionStoreMembers are the store operations that write the
// admission row and the store's release proof hook. Each writer has exactly
// one reference, from the Service method of the same purpose, which itself
// has no production caller. The hook has none.
func operationalAdmissionStoreMembers(admission string) []operationalMemberInventory {
	return []operationalMemberInventory{
		{"OperationalCustody", "CommissionOperationalAdmission", map[string]int{admission + "Service.commissionOperationalAdmission": 1}, false},
		{"OperationalCustody", "AdvanceOperationalAdmission", map[string]int{admission + "Service.advanceOperationalAdmission": 1}, false},
		{"OperationalCustody", "WithdrawOperationalAdmission", map[string]int{admission + "Service.withdrawOperationalEffects": 1}, true},
		{"OperationalCustody", "ConfigureOperationalReleaseProofForProof", map[string]int{}, true},
	}
}

// operationalAdmissionStateMembers lists every production reference to the
// exported functions and methods of the admission state package. No other
// package can name a field of the state or hold its value, so these calls are
// all that other packages can do to it. Inspect exists for tests and has no
// production reference; Installed has none either. Token is read where it is
// presented to the store: at establishment, and twice inside the qualifier
// that every first-effect cut calls, which is a function literal.
func operationalAdmissionStateMembers(admission string, handoff string, stateFile string) []operationalMemberInventory {
	return []operationalMemberInventory{
		{"", "New", map[string]int{"es/admission/service.go:NewService": 1}, true},
		{"", "Digest", map[string]int{admission + "Service.operationalAdmissionContent": 1, stateFile + "State.Install": 1, stateFile + "State.Confirm": 1}, true},
		{"State", "Commissioned", map[string]int{"es/admission/service.go:Service.Initialize": 2}, true},
		{"State", "Installable", map[string]int{admission + "Service.installOperationalAdmission": 1}, true},
		{"State", "Install", map[string]int{admission + "Service.installOperationalAdmission": 1}, true},
		{"State", "Withdraw", map[string]int{admission + "Service.withdrawOperationalEffects": 1}, true},
		{"State", "Confirmable", map[string]int{admission + "Service.confirmOperationalAdmission": 1}, true},
		{"State", "Confirm", map[string]int{admission + "Service.confirmOperationalAdmission": 1}, true},
		{"State", "Current", map[string]int{admission + "Service.currentOperationalAdmission": 1}, true},
		{"State", "Inspect", map[string]int{}, true},
		{"View", "Installed", map[string]int{}, true},
		{"View", "Token", map[string]int{handoff + "Service.operatePrivateHandoff": 1, handoff + "Service.advanceOperational": 2}, false},
		{"View", "Trust", map[string]int{admission + "Service.qualifyOperationalRetained": 1}, true},
		{"View", "Verifier", map[string]int{admission + "Service.qualifyOperationalRetained": 1}, true},
		{"View", "Policies", map[string]int{admission + "Service.qualifyOperationalRetained": 1}, true},
		{"View", "Proof", map[string]int{admission + "operationalProofOf": 1}, true},
	}
}

// operationalAdmissionStateSurface is everything the admission state package
// exports: what another package can name at all. A new exported name is a new
// way to reach the state, so it fails here until it is listed, and a listed
// function or method has a call-site inventory above.
var operationalAdmissionStateSurface = []string{
	"const ConfirmationLimit",
	"func Digest", "func New",
	"method State.Commissioned", "method State.Confirm", "method State.Confirmable", "method State.Current", "method State.Inspect",
	"method State.Install", "method State.Installable", "method State.Withdraw",
	"method View.Installed", "method View.Policies", "method View.Proof", "method View.Token", "method View.Trust", "method View.Verifier",
	"type Content{Policies,Trust,Verifier}", "type Policy{Entries,ID}", "type PolicyEntry{ID,Literal}",
	"type State{}", "type Status{Confirmed,Superseded,View,Withdrawn}", "type Verifier{Algorithm,KeyID,PublicKey}", "type View{}",
}

// exportedSurfaceOf lists what a package exports, sorted: every exported
// constant, variable, function and type of the package scope, every exported
// method of an exported type, also one it gains from an embedded field, and
// for an exported struct type its exported and its embedded fields. It is
// what another package can name.
func exportedSurfaceOf(pkg *types.Package) []string {
	var got []string
	scope := pkg.Scope()
	for _, name := range scope.Names() {
		object := scope.Lookup(name)
		if !object.Exported() {
			continue
		}
		switch declared := object.(type) {
		case *types.Const:
			got = append(got, "const "+name)
		case *types.Var:
			got = append(got, "var "+name)
		case *types.Func:
			got = append(got, "func "+name)
		case *types.TypeName:
			var fields []string
			if structure, ok := declared.Type().Underlying().(*types.Struct); ok {
				for index := 0; index < structure.NumFields(); index++ {
					if field := structure.Field(index); field.Exported() || field.Embedded() {
						fields = append(fields, field.Name())
					}
				}
			} else {
				fields = append(fields, "not a struct")
			}
			sort.Strings(fields)
			got = append(got, "type "+name+"{"+strings.Join(fields, ",")+"}")
			methods := types.NewMethodSet(types.NewPointer(declared.Type()))
			for index := 0; index < methods.Len(); index++ {
				if method := methods.At(index).Obj(); method.Exported() {
					got = append(got, "method "+name+"."+method.Name())
				}
			}
		default:
			got = append(got, fmt.Sprintf("%T %s", object, name))
		}
	}
	sort.Strings(got)
	return got
}

// validateOperationalAdmissionStateSurface compares what the package exports
// with the list, and the functions and methods among it with the call-site
// inventories: each has exactly one, and no inventory names anything else.
func validateOperationalAdmissionStateSurface(surface []string, listed []string, members []operationalMemberInventory) error {
	want := append([]string{}, listed...)
	sort.Strings(want)
	if !reflect.DeepEqual(surface, want) {
		return fmt.Errorf("the exported surface of the admission state package changed: got %q want %q", surface, want)
	}
	var callable, inventoried []string
	for _, entry := range surface {
		if strings.HasPrefix(entry, "func ") || strings.HasPrefix(entry, "method ") {
			callable = append(callable, entry)
		}
	}
	for _, member := range members {
		if member.typ == "" {
			inventoried = append(inventoried, "func "+member.name)
		} else {
			inventoried = append(inventoried, "method "+member.typ+"."+member.name)
		}
	}
	sort.Strings(inventoried)
	if !reflect.DeepEqual(callable, inventoried) {
		return fmt.Errorf("the call-site inventories of the admission state package do not cover its functions and methods once each: exported %q inventoried %q", callable, inventoried)
	}
	return nil
}

func TestOperationalAdmissionStateSurfaceIsAClosedList(t *testing.T) {
	const handle = "type State struct{ s *state }; "
	const rest = "package admissionstate; type state struct{ value int }; func New() State { return State{} }; func (h State) Current() bool { return true }; const Limit = 1; "
	surface := func(source string) []string {
		return exportedSurfaceOf(typeCheckSyntheticProductionPackage(t, "fixture.go", source).pkg)
	}
	base := []string{"const Limit", "func New", "method State.Current", "type State{}"}
	if got := surface(rest + handle); !reflect.DeepEqual(got, base) {
		t.Fatalf("the surface of the synthetic package differs: got %q want %q", got, base)
	}
	members := []operationalMemberInventory{{"", "New", nil, true}, {"State", "Current", nil, true}}
	if err := validateOperationalAdmissionStateSurface(surface(rest+handle), base, members); err != nil {
		t.Fatalf("the listed surface was refused: %v", err)
	}
	// Each addition is one new way to reach the state from another package.
	for name, addition := range map[string]struct{ handle, added, entry, replaces string }{
		"an exported function":                    {handle, "func Reopen(h State) {}", "func Reopen", ""},
		"an exported method":                      {handle, "func (h State) Reopen() {}", "method State.Reopen", ""},
		"an exported method on the pointer":       {handle, "func (h *State) Reopen() {}", "method State.Reopen", ""},
		"an exported variable":                    {handle, "var Hook func(State)", "var Hook", ""},
		"an exported constant":                    {handle, "const Other = 2", "const Other", ""},
		"an exported struct type":                 {handle, "type Raw struct{ Value *state }", "type Raw{Value}", ""},
		"an exported alias of the state":          {handle, "type Raw = state", "type Raw{}", ""},
		"an exported defined type over the state": {handle, "type Raw state", "type Raw{}", ""},
		"an exported type that is not a struct":   {handle, "type Raw func() *state", "type Raw{not a struct}", ""},
		"an exported field of the handle":         {"type State struct{ s *state; Raw *state }; ", "", "type State{Raw}", "type State{}"},
		"an embedded field of the handle":         {"type State struct{ *state }; ", "", "type State{state}", "type State{}"},
		"a method the handle gains by embedding":  {"type State struct{ *state }; ", "func (s *state) Reopen() {}", "method State.Reopen", "type State{}"},
	} {
		got := surface(rest + addition.handle + addition.added)
		if reflect.DeepEqual(got, base) || !slices.Contains(got, addition.entry) || (addition.replaces != "" && slices.Contains(got, addition.replaces)) {
			t.Fatalf("%s is not listed as %q: %q", name, addition.entry, got)
		}
		if err := validateOperationalAdmissionStateSurface(got, base, members); err == nil {
			t.Fatalf("%s passed the closed list", name)
		}
	}
	// What another package cannot name is not part of the surface.
	for name, added := range map[string]string{
		"an unexported function": "func reopen(h State) {}",
		"an unexported method":   "func (h State) reopen() {}",
		"an unexported variable": "var hook func(State)",
		"an unexported type":     "type raw struct{ Value int }",
	} {
		if got := surface(rest + handle + added); !reflect.DeepEqual(got, base) {
			t.Fatalf("%s changed the surface: %q", name, got)
		}
	}
	// A function or method without a call-site inventory, a second inventory
	// of one, and an inventory of a name the package does not export.
	for name, changed := range map[string][]operationalMemberInventory{
		"a function without an inventory":   {{"State", "Current", nil, true}},
		"a method without an inventory":     {{"", "New", nil, true}},
		"no inventory at all":               nil,
		"two inventories of one function":   {{"", "New", nil, true}, {"", "New", nil, true}, {"State", "Current", nil, true}},
		"an inventory of an unknown method": {{"", "New", nil, true}, {"State", "Current", nil, true}, {"State", "Reopen", nil, true}},
		"an inventory under the wrong type": {{"", "New", nil, true}, {"View", "Current", nil, true}},
	} {
		if err := validateOperationalAdmissionStateSurface(surface(rest+handle), base, changed); err == nil {
			t.Fatalf("%s passed", name)
		}
	}
	if err := validateOperationalAdmissionStateSurface(surface(rest+handle), append([]string{"func Reopen"}, base...), members); err == nil {
		t.Fatal("a listed name the package does not export passed")
	}
}

// localVariable finds the one variable or parameter called name that is
// declared inside the function at site.
func (pkg *typedProductionPackage) localVariable(site string, name string) (*types.Var, error) {
	var found []*types.Var
	for fileName, file := range pkg.files {
		parents := astParentMap(file)
		ast.Inspect(file, func(node ast.Node) bool {
			identifier, ok := node.(*ast.Ident)
			if !ok || identifier.Name != name {
				return true
			}
			variable, ok := pkg.info.Defs[identifier].(*types.Var)
			if !ok || variable.IsField() {
				return true
			}
			if function := enclosingFunction(parents, identifier); function != nil && typedFunctionSite(fileName, function) == site {
				found = append(found, variable)
			}
			return true
		})
	}
	if len(found) != 1 {
		return nil, fmt.Errorf("%s declares %d variables named %s, want one", site, len(found), name)
	}
	return found[0], nil
}

// validateSiteReferenceKinds requires every reference to stay inside the
// function at site, with exactly the listed kinds: "direct-call" or
// "reference", each with "+closure" inside a function literal.
func validateSiteReferenceKinds(label string, site string, references []typedReference, want map[string]int) error {
	got := make(map[string]int)
	for _, reference := range references {
		if reference.site != site || reference.methodExpression || reference.referenceKind == "" {
			return fmt.Errorf("%s left %s or is indirect: %v", label, site, reference)
		}
		got[reference.referenceKind]++
	}
	if !reflect.DeepEqual(got, want) {
		return fmt.Errorf("%s reference kinds changed: got %v want %v (references %v)", label, got, want, references)
	}
	return nil
}

// validateOperationalConfirmationInventory pins where the private path may
// ask EGS. The confirmation has one reference, inside the once-per-invocation
// closure of operatePrivateHandoff. That closure is invoked at exactly three
// sites: once directly, before the first authority sample of a fresh
// delivery, and through the pre-check of advanceOperational, which runs
// before the run assignment and before the intent and pre-stage group.
func validateOperationalConfirmationInventory(t *testing.T, pkg *typedProductionPackage, file string) error {
	t.Helper()
	operate, advance := file+"Service.operatePrivateHandoff", file+"Service.advanceOperational"
	confirmation := requirePackageMethod(t, pkg, "Service", "confirmOperationalAdmission")
	if err := validateSiteReferenceKinds("confirmation", operate, pkg.referencesTo(confirmation),
		map[string]int{"direct-call+closure": 1}); err != nil {
		return err
	}
	advanceMethod := requirePackageMethod(t, pkg, "Service", "advanceOperational")
	if err := validateSiteReferenceKinds("advanceOperational", operate, pkg.referencesTo(advanceMethod),
		map[string]int{"direct-call+closure": 1}); err != nil {
		return err
	}
	var closure *types.Var
	for _, local := range []struct {
		site, name string
		want       map[string]int
	}{
		// Called once directly and handed once to advanceOperational.
		{operate, "confirm", map[string]int{"direct-call": 1, "reference+closure": 1}},
		// The same closure as a parameter: called only by the pre-check.
		{advance, "confirm", map[string]int{"direct-call+closure": 1}},
		{advance, "precheck", map[string]int{"direct-call": 2}},
	} {
		variable, err := pkg.localVariable(local.site, local.name)
		if err != nil {
			return err
		}
		if closure == nil {
			closure = variable
		}
		references := pkg.referencesMatching(func(object types.Object) bool { return object == variable })
		if err := validateSiteReferenceKinds(local.site+" "+local.name, local.site, references, local.want); err != nil {
			return err
		}
	}
	// The parameter is that closure: the one call of advanceOperational passes
	// it as its last argument.
	calls, passed := 0, 0
	for _, source := range pkg.files {
		ast.Inspect(source, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok || len(call.Args) == 0 {
				return true
			}
			selector, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr)
			if !ok || pkg.info.Uses[selector.Sel] != advanceMethod {
				return true
			}
			calls++
			if argument, ok := ast.Unparen(call.Args[len(call.Args)-1]).(*ast.Ident); ok && pkg.info.Uses[argument] == closure {
				passed++
			}
			return true
		})
	}
	if calls != 1 || passed != 1 {
		return fmt.Errorf("advanceOperational must be called once with the confirmation closure: %d calls, %d with the closure", calls, passed)
	}
	return nil
}

func TestOperationalHandoffNoPublicStartupOrdinaryOrFixtureCaller(t *testing.T) {
	const admissionPath = "execution-substrate/es/admission"
	const storagePath = admissionPath + "/internal/reliablesubmit"
	const statePath = admissionPath + "/internal/admissionstate"
	const handoff = "es/admission/reliable_submit_operational_handoff.go:"
	const admission = "es/admission/reliable_submit_operational_admission.go:"
	const provider = "es/admission/reliable_submit_operational_provider.go:"
	const storage = "es/admission/internal/reliablesubmit/operational_handoff.go:"
	const stateFile = "es/admission/internal/admissionstate/state.go:"
	views := loadTypedProductionPackages(t, "./es/...", "./cmd/es/...")
	// validateState holds the inventories of the admission state package: the
	// call sites of every exported function and method, the exported surface,
	// and the one place that makes a state and the one that makes a view.
	validateState := func(packages []*typedProductionPackage) error {
		state := requireTypedProductionPackage(t, packages, statePath)
		members := operationalAdmissionStateMembers(admission, handoff, stateFile)
		for _, member := range members {
			var ref types.Object
			if member.typ == "" {
				ref = requirePackageFunction(t, state, member.name)
			} else {
				ref = requirePackageMethod(t, state, member.typ, member.name)
			}
			if err := validateTypedReferenceInventory("admissionstate "+member.typ+"."+member.name, operationalMemberReferences(packages, ref), member.want, member.closures); err != nil {
				return err
			}
		}
		if err := validateOperationalAdmissionStateSurface(exportedSurfaceOf(state.pkg), operationalAdmissionStateSurface, members); err != nil {
			return err
		}
		return validateOperationalAuthorityConstruction(state, map[string]string{
			"state": stateFile + "New",
			"view":  stateFile + "State.Install",
		})
	}
	validate := func(packages []*typedProductionPackage) error {
		pkg := requireTypedProductionPackage(t, packages, admissionPath)
		for _, entry := range operationalCommissioningEntries {
			method := requirePackageMethod(t, pkg, "Service", entry)
			if err := validateOperationalCommissioningGate(entry, pkg.referencesTo(method)); err != nil {
				return err
			}
		}
		for _, entry := range []string{"handoffOperational", "recoverOperational"} {
			m := requirePackageMethod(t, pkg, "Service", entry)
			if err := validateOperationalCommissioningGate(entry, pkg.referencesTo(m)); err != nil {
				return err
			}
		}
		for _, name := range []string{"newOperationalDomain", "newOperationalLoopbackProvider"} {
			fn := requirePackageFunction(t, pkg, name)
			if err := validateOperationalCommissioningGate(name, pkg.referencesTo(fn)); err != nil {
				return err
			}
		}
		if err := validateOperationalConfirmationInventory(t, pkg, handoff); err != nil {
			return err
		}
		for _, member := range []struct {
			name string
			want map[string]int
		}{
			{"installOperationalAdmission", map[string]int{
				admission + "Service.commissionOperationalAdmission": 1, admission + "Service.advanceOperationalAdmission": 1}},
			{"fetchVerifiedTrustModel", map[string]int{
				"es/admission/service.go:Service.Initialize": 1, admission + "Service.confirmOperationalAdmission": 1}},
			{"operatePrivateHandoff", map[string]int{
				handoff + "Service.handoffOperational": 1, handoff + "Service.recoverOperational": 1}},
		} {
			method := requirePackageMethod(t, pkg, "Service", member.name)
			if err := validateTypedReferenceInventory(member.name, pkg.referencesTo(method), member.want, true); err != nil {
				return err
			}
		}
		store := requireTypedProductionPackage(t, packages, storagePath)
		for _, member := range append(operationalAdmissionStoreMembers(admission), []operationalMemberInventory{
			{"", "OpenProvisionedOperationalCustody", map[string]int{}, true},
			{"OperationalCustody", "ConfigureOperationalCommitFaultForProof", map[string]int{}, true},
			{"OperationalCustody", "ConfigureOperationalPrestageProofForProof", map[string]int{}, true},
			{"OperationalCustody", "EstablishOperational", map[string]int{handoff + "Service.operatePrivateHandoff": 1}, true},
			{"OperationalAccess", "AdmissionHint", map[string]int{handoff + "Service.advanceOperational": 1}, false},
			{"", "MatchOperationalOriginal", map[string]int{handoff + "Service.operatePrivateHandoff": 1, storage + "MatchAdmittedOperationalOriginal": 1}, false},
			{"", "MatchAdmittedOperationalOriginal", map[string]int{handoff + "Service.advanceOperational": 1}, false},
			{"OperationalAccess", "ApplyFirstMarker", map[string]int{handoff + "Service.advanceOperational": 1}, true},
			{"OperationalAccess", "BindOperationalIntent", map[string]int{handoff + "Service.advanceOperational": 1}, true},
			{"OperationalAccess", "BindOperationalStage", map[string]int{handoff + "Service.advanceOperational": 1}, true},
			{"OperationalAccess", "BindOperationalMarker", map[string]int{handoff + "Service.advanceOperational": 1}, true},
			{"OperationalAccess", "BindVerifiedOperationalObservation", map[string]int{provider + "verifiedOperationalObservation.bindOperationalObservation": 1}, true},
			{"OperationalMarkerCandidate", "Ref", map[string]int{handoff + "Service.advanceOperational": 1}, true},
			{"OperationalStageProof", "Requalify", map[string]int{
				handoff + "liveSender.consume": 1, storage + "OperationalAccess.BindOperationalMarker": 1,
				storage + "OperationalAccess.applyOperational": 1, storage + "OperationalAccess.operationalReleaseQualified": 1,
			}, false},
		}...) {
			var ref types.Object
			if member.typ == "" {
				ref = requirePackageFunction(t, store, member.name)
			} else {
				ref = requirePackageMethod(t, store, member.typ, member.name)
			}
			if err := validateTypedReferenceInventory(member.name, operationalMemberReferences(packages, ref), member.want, member.closures); err != nil {
				return err
			}
		}
		if err := validateState(packages); err != nil {
			return err
		}
		for _, member := range []struct {
			typ, name string
			want      map[string]int
		}{
			{"operationalProvider", "observe", map[string]int{handoff + "operationalDomain.reconcileOperational": 1}},
			{"verifiedOperationalObservation", "bindOperationalObservation", map[string]int{handoff + "operationalDomain.reconcileOperational": 1}},
			{"operationalProvider", "register", map[string]int{handoff + "liveSender.consume": 1}},
			{"operationalProvider", "prepareExchange", map[string]int{handoff + "liveSender.consume": 1, provider + "operationalProvider.observe": 2}},
			{"operationalProvider", "exchange", map[string]int{provider + "operationalProvider.register": 1, provider + "operationalProvider.observe": 2}},
		} {
			method := requirePackageMethod(t, pkg, member.typ, member.name)
			if err := validateTypedReferenceInventory(member.name, pkg.referencesTo(method), member.want, true); err != nil {
				return err
			}
		}
		for _, inventory := range []struct {
			pkg  *typedProductionPackage
			want map[string]string
		}{
			{pkg, map[string]string{
				"verifiedOperationalObservation": provider + "operationalProvider.observe",
				"liveSender":                     handoff + "Service.advanceOperational",
				"handoffOwner":                   handoff + "Service.advanceOperational",
			}},
			{store, map[string]string{
				"OperationalIntentInput":     storage + "OperationalAccess.BindOperationalIntent",
				"OperationalStageProof":      storage + "OperationalAccess.BindOperationalStage",
				"OperationalMarkerCandidate": storage + "OperationalAccess.BindOperationalMarker",
				"OperationalPositiveProof":   storage + "OperationalAccess.BindVerifiedOperationalObservation",
			}},
		} {
			if err := validateOperationalAuthorityConstruction(inventory.pkg, inventory.want); err != nil {
				return err
			}
		}
		consume := requirePackageMethod(t, pkg, "liveSender", "consume")
		if err := validateTypedReferenceInventory("synchronous operational marker continuation", pkg.referencesTo(consume),
			map[string]int{handoff + "Service.advanceOperational": 1}, false); err != nil {
			return err
		}
		return nil
	}
	for _, view := range views {
		if err := validate(view.packages); err != nil {
			t.Fatal(err)
		}
	}
	// The same inventories over the real packages with probe functions added
	// in memory beside the gated methods. Each probe stores the receiver in an
	// interface that declares one of those methods, with the signature as
	// written, and selects the method from it. That reaches the method without
	// a reference to it.
	t.Run("gated entries reached through an interface in the real packages", func(t *testing.T) {
		view := views[len(views)-1]
		for _, probe := range []struct {
			importPath, receiver string
			methods              []string
		}{
			{admissionPath, "Service", append(append([]string{}, operationalCommissioningEntries...), "handoffOperational", "recoverOperational")},
			{storagePath, "OperationalCustody", []string{"CommissionOperationalAdmission", "AdvanceOperationalAdmission", "WithdrawOperationalAdmission",
				"ConfigureOperationalReleaseProofForProof", "EstablishOperational"}},
		} {
			pkg := requireTypedProductionPackage(t, view.packages, probe.importPath)
			control := make(map[string]string)
			dispatch := make(map[string]string)
			for _, method := range probe.methods {
				fileName, signature := productionMethodSignatureText(t, pkg, probe.receiver, method)
				if _, started := control[fileName]; !started {
					control[fileName], dispatch[fileName] = pkg.sources[fileName]+"\n", pkg.sources[fileName]+"\n"
				}
				control[fileName] += "func zzGuardProbeDispatch" + method + "(target *" + probe.receiver + ") { _ = target }\n"
				dispatch[fileName] += "func zzGuardProbeDispatch" + method + "(target *" + probe.receiver + ") { var gate interface { " +
					method + signature + " } = target; _ = gate." + method + " }\n"
			}
			overlaid := func(overlay map[string]string) []*typedProductionPackage {
				packages := []*typedProductionPackage{view.metadata.typeCheckWithOverlay(t, probe.importPath, overlay)}
				for _, other := range view.packages {
					if other.importPath != probe.importPath {
						packages = append(packages, other)
					}
				}
				return packages
			}
			// Control: functions that only keep the pointer change no inventory.
			if err := validate(overlaid(control)); err != nil {
				t.Fatalf("control probes beside %s changed an inventory: %v", probe.receiver, err)
			}
			packages := overlaid(dispatch)
			if err := validate(packages); err == nil || !strings.Contains(err.Error(), "zzGuardProbeDispatch") {
				t.Fatalf("interface probes beside %s: %v", probe.receiver, err)
			}
			for _, method := range probe.methods {
				target := requirePackageMethod(t, packages[0], probe.receiver, method)
				got := make(map[string]int)
				var probed []typedReference
				for _, reference := range operationalMemberReferences(packages, target) {
					if strings.HasSuffix(reference.site, ":zzGuardProbeDispatch"+method) {
						got[reference.referenceKind]++
						probed = append(probed, reference)
					}
				}
				if want := map[string]int{"interface-method": 1, "interface-selection": 1}; !reflect.DeepEqual(got, want) {
					t.Fatalf("%s.%s probe occurrences: got %v want %v", probe.receiver, method, got, want)
				}
				// No inventory can list such an occurrence: it is refused whatever
				// count the inventory expects at that site.
				for _, reference := range probed {
					err := validateTypedReferenceInventory(method, []typedReference{reference}, map[string]int{reference.site: 1}, false)
					if err == nil || !strings.Contains(err.Error(), "indirect reference escape") {
						t.Fatalf("%s.%s %s occurrence was accepted by an inventory that lists its site: %v", probe.receiver, method, reference.referenceKind, err)
					}
				}
			}
		}
	})
	// The inventories of the admission state package (validateState, which the
	// validation above runs as well; the subtest shows that too) over the real
	// packages with one function added in memory. A call is all another
	// package can do to the state, so each added call, of each exported
	// function and method, has to fail the inventory of exactly that member.
	t.Run("calls of the admission state package added in the real packages", func(t *testing.T) {
		const fileName = "es/admission/reliable_submit_operational_admission.go"
		// One build target is enough here: the file has no build constraint,
		// and a reference is the same on every target.
		for _, view := range views[len(views)-1:] {
			pkg := requireTypedProductionPackage(t, view.packages, admissionPath)
			source, ok := pkg.sources[fileName]
			if !ok || !strings.Contains(source, "\"execution-substrate/es/admission/internal/admissionstate\"") || !strings.Contains(source, "\n\t\"time\"\n") {
				t.Fatalf("%s is not a file of %s that imports the admission state package and time", fileName, admissionPath)
			}
			overlaid := func(text string) []*typedProductionPackage {
				packages := []*typedProductionPackage{view.metadata.typeCheckWithOverlay(t, admissionPath, map[string]string{fileName: source + "\n" + text + "\n"})}
				for _, other := range view.packages {
					if other.importPath != admissionPath {
						packages = append(packages, other)
					}
				}
				return packages
			}
			// Controls: a function that calls nothing of the package, and one
			// that only holds and compares handles.
			for name, text := range map[string]string{
				"a function that keeps the Service": "func zzGuardProbeState(s *Service) *Service { return s }",
				"handles held and compared":         "func zzGuardProbeState(a, b admissionstate.View) bool { kept := a; return kept == b }",
			} {
				if err := validateState(overlaid(text)); err != nil {
					t.Fatalf("%s: control %q changed an inventory: %v", view.target, name, err)
				}
			}
			probed := make(map[string]bool)
			for _, probe := range []struct{ member, text, reason string }{
				{".New", "func zzGuardProbeState(s *Service) admissionstate.State { return admissionstate.New(s) }", "reference inventory changed"},
				{".Digest", "func zzGuardProbeState(c admissionstate.Content) bool { _, ok := admissionstate.Digest(c); return ok }", "reference inventory changed"},
				{"State.Commissioned", "func zzGuardProbeState(s *Service) bool { return s.operational.Commissioned() }", "reference inventory changed"},
				{"State.Installable", "func zzGuardProbeState(s *Service) bool { return s.operational.Installable(s) }", "reference inventory changed"},
				{"State.Install", "func zzGuardProbeState(s *Service, token reliablesubmit.OperationalAdmissionToken) bool { return s.operational.Install(s, [32]byte{1}, 1, token, admissionstate.Content{}, nil, nil) }", "reference inventory changed"},
				{"State.Withdraw", "func zzGuardProbeState(s *Service) bool { _, ok := s.operational.Withdraw(s, [32]byte{1}, 1); return ok }", "reference inventory changed"},
				{"State.Confirmable", "func zzGuardProbeState(s *Service) bool { _, ok := s.operational.Confirmable(s); return ok }", "reference inventory changed"},
				{"State.Confirm", "func zzGuardProbeState(s *Service, v admissionstate.View) { s.operational.Confirm(s, v, admissionstate.Content{}.Trust, time.Time{}) }", "reference inventory changed"},
				{"State.Current", "func zzGuardProbeState(s *Service) bool { _, ok := s.operational.Current(s, [32]byte{1}, 1); return ok }", "reference inventory changed"},
				{"State.Inspect", "func zzGuardProbeState(s *Service) bool { return s.operational.Inspect(s).Withdrawn }", "reference inventory changed"},
				{"View.Installed", "func zzGuardProbeState(v admissionstate.View) bool { return v.Installed() }", "reference inventory changed"},
				{"View.Token", "func zzGuardProbeState(v admissionstate.View) reliablesubmit.OperationalAdmissionToken { return v.Token() }", "reference inventory changed"},
				{"View.Trust", "func zzGuardProbeState(v admissionstate.View) int { return len(v.Trust().SignerPolicy.AllowedSigners) }", "reference inventory changed"},
				{"View.Verifier", "func zzGuardProbeState(v admissionstate.View) string { return v.Verifier().KeyID }", "reference inventory changed"},
				{"View.Policies", "func zzGuardProbeState(v admissionstate.View) int { return len(v.Policies()) }", "reference inventory changed"},
				{"View.Proof", "func zzGuardProbeState(v admissionstate.View) bool { return v.Proof() != nil }", "reference inventory changed"},
				// A method reached without a call at the site, which an
				// inventory cannot list at any count.
				{"State.Inspect", "func zzGuardProbeState(s *Service) func(any) admissionstate.Status { return s.operational.Inspect }", "indirect reference escape"},
				{"State.Withdraw", "func zzGuardProbeState() any { return admissionstate.State.Withdraw }", "indirect reference escape"},
				{"State.Commissioned", "func zzGuardProbeState(s *Service) bool { var gate interface{ Commissioned() bool } = s.operational; return gate.Commissioned() }", "indirect reference escape"},
				{"State.Install", "func zzGuardProbeState(s *Service) bool { install := func() bool { return s.operational.Installable(s) }; return install() }", ""},
			} {
				err := validateState(overlaid(probe.text))
				label := "admissionstate " + probe.member + " "
				if probe.reason == "" {
					// A call inside a function literal is refused by the
					// inventory of the member it calls.
					label, probe.reason = "admissionstate State.Installable ", "indirect reference escape"
				}
				if err == nil || !strings.HasPrefix(err.Error(), label) || !strings.Contains(err.Error(), probe.reason) || !strings.Contains(err.Error(), "zzGuardProbeState") {
					t.Fatalf("%s: a call of %s added to the real package: %v", view.target, probe.member, err)
				}
				probed[probe.member] = true
			}
			// Every member with a call-site inventory was probed.
			for _, member := range operationalAdmissionStateMembers(admission, handoff, stateFile) {
				if !probed[member.typ+"."+member.name] {
					t.Fatalf("no added call of %s.%s was tried", member.typ, member.name)
				}
			}
			// The validation of the real packages above runs these inventories:
			// an added call fails it as well, and the first control does not.
			if err := validate(overlaid("func zzGuardProbeState(s *Service) *Service { return s }")); err != nil {
				t.Fatalf("%s: a control function changed an inventory of the whole validation: %v", view.target, err)
			}
			if err := validate(overlaid("func zzGuardProbeState(c admissionstate.Content) bool { _, ok := admissionstate.Digest(c); return ok }")); err == nil ||
				!strings.HasPrefix(err.Error(), "admissionstate .Digest ") || !strings.Contains(err.Error(), "zzGuardProbeState") {
				t.Fatalf("%s: a call of the admission state package was added and the whole validation answered: %v", view.target, err)
			}
			// Inside the package, a second place that makes a state or a view
			// fails the construction inventory.
			const stateName = "es/admission/internal/admissionstate/state.go"
			stateSource, ok := requireTypedProductionPackage(t, view.packages, statePath).sources[stateName]
			if !ok {
				t.Fatalf("%s is not a file of %s", stateName, statePath)
			}
			inState := func(text string) []*typedProductionPackage {
				packages := []*typedProductionPackage{view.metadata.typeCheckWithOverlay(t, statePath, map[string]string{stateName: stateSource + "\n" + text + "\n"})}
				for _, other := range view.packages {
					if other.importPath != statePath {
						packages = append(packages, other)
					}
				}
				return packages
			}
			if err := validateState(inState("func zzGuardProbeState(h State) bool { return h.s != nil }")); err != nil {
				t.Fatalf("%s: a control function in the state package changed an inventory: %v", view.target, err)
			}
			for name, text := range map[string]string{
				"a second state literal": "func zzGuardProbeState(owner any) State { return State{s: &state{owner: owner}} }",
				"a second view literal":  "func zzGuardProbeState(h State) { h.s.view = &view{} }",
				"a view made by new":     "func zzGuardProbeState() View { return View{v: new(view)} }",
				"a view declared":        "func zzGuardProbeState() View { var made view; return View{v: &made} }",
			} {
				if err := validateState(inState(text)); err == nil || !strings.Contains(err.Error(), "zzGuardProbeState") {
					t.Fatalf("%s: %s in the state package: %v", view.target, name, err)
				}
			}
		}
	})
}

// operationalMemberReferences lists the references to one store member from
// every loaded package, together with the places that reach a method without
// naming it.
func operationalMemberReferences(packages []*typedProductionPackage, member types.Object) []typedReference {
	var references []typedReference
	for _, pkg := range packages {
		references = append(references, pkg.referencesMatching(func(candidate types.Object) bool {
			return trancheB1ObjectIdentity(candidate) == trancheB1ObjectIdentity(member)
		})...)
		if method, ok := member.(*types.Func); ok {
			references = append(references, pkg.dynamicMethodReferences(method)...)
		}
	}
	return references
}

// productionMethodSignatureText returns the file that declares the method and
// its parameter and result lists, as written.
func productionMethodSignatureText(t *testing.T, pkg *typedProductionPackage, receiverName string, methodName string) (string, string) {
	t.Helper()
	for fileName, file := range pkg.files {
		for _, declaration := range file.Decls {
			function, ok := declaration.(*ast.FuncDecl)
			if !ok || function.Recv == nil || len(function.Recv.List) != 1 || function.Name.Name != methodName {
				continue
			}
			receiver := function.Recv.List[0].Type
			if star, ok := receiver.(*ast.StarExpr); ok {
				receiver = star.X
			}
			if named, ok := receiver.(*ast.Ident); !ok || named.Name != receiverName {
				continue
			}
			source := pkg.sources[fileName]
			return fileName, source[guardPosition(pkg.fset, function.Type.Params.Pos()).Offset:guardPosition(pkg.fset, function.Type.End()).Offset]
		}
	}
	t.Fatalf("%s.%s.%s declaration was not found", pkg.importPath, receiverName, methodName)
	return "", ""
}

func TestOperationalHandoffOpaqueAuthorityBoundaries(t *testing.T) {
	if !reflect.DeepEqual(operationalCommissioningEntries, []string{"commissionOperationalAdmission", "advanceOperationalAdmission", "withdrawOperationalEffects"}) {
		t.Fatalf("commissioning entries changed: %v", operationalCommissioningEntries)
	}
	for _, entry := range operationalCommissioningEntries {
		t.Run("zero-production-"+entry, func(t *testing.T) {
			declarations := "package admission; type Service struct{}; func (*Service) " + entry + "(){}; "
			baseline := typeCheckSyntheticProductionPackage(t, "fixture.go", declarations+"func owner(s *Service){}")
			if err := validateOperationalCommissioningGate(entry, baseline.referencesTo(requirePackageMethod(t, baseline, "Service", entry))); err != nil {
				t.Fatal(err)
			}
			for name, body := range map[string]string{
				"direct":            "s." + entry + "()",
				"method-value":      "indirect := s." + entry + "; indirect()",
				"method-expression": "(*Service)." + entry + "(s)",
				"closure":           "func(){s." + entry + "()}()",
			} {
				t.Run(name, func(t *testing.T) {
					mutant := typeCheckSyntheticProductionPackage(t, "fixture.go", declarations+"func owner(s *Service){"+body+"}")
					err := validateOperationalCommissioningGate(entry, mutant.referencesTo(requirePackageMethod(t, mutant, "Service", entry)))
					if err == nil {
						t.Fatal("non-test admission authority reference passed zero-reference rule")
					}
					if len(operationalCommissioningPrerequisites) != 6 {
						t.Fatalf("commissioning prerequisites: %v", operationalCommissioningPrerequisites)
					}
					for _, prerequisite := range operationalCommissioningPrerequisites {
						if !strings.Contains(err.Error(), prerequisite) {
							t.Fatalf("the opened gate did not print prerequisite %s: %v", prerequisite, err)
						}
					}
				})
			}
			// Dynamic dispatch: the entry is reached through an interface or a
			// constraint that declares a method of its name. No reference to the
			// entry is spelled, so the gate counts the declaration and the
			// selection themselves.
			through := "interface{ " + entry + "() }"
			for name, source := range map[string]string{
				"interface-dispatch":   "func owner(s *Service){ var gate " + through + " = s; gate." + entry + "() }",
				"interface-conversion": "func owner(s *Service){ _ = " + through + "(s) }",
				"interface-assertion":  "func owner(s *Service){ any(s).(" + through + ")." + entry + "() }",
				"named-interface":      "type gate " + through + "; func owner(s *Service){}",
				"embedded-interface":   "type inner " + through + "; type outer interface{ inner }; func owner(s *Service){ var gate outer = s; gate." + entry + "() }",
				"constraint":           "func call[T " + through + "](v T){ v." + entry + "() }; func owner(s *Service){ call(s) }",
				"interface-parameter":  "func call(gate " + through + "){ gate." + entry + "() }; func owner(s *Service){ call(s) }",
			} {
				t.Run(name, func(t *testing.T) {
					mutant := typeCheckSyntheticProductionPackage(t, "fixture.go", declarations+source)
					err := validateOperationalCommissioningGate(entry, mutant.referencesTo(requirePackageMethod(t, mutant, "Service", entry)))
					if err == nil {
						t.Fatal("dynamic dispatch of an admission authority entry passed the zero-reference rule")
					}
					for _, prerequisite := range operationalCommissioningPrerequisites {
						if !strings.Contains(err.Error(), prerequisite) {
							t.Fatalf("the opened gate did not print prerequisite %s: %v", prerequisite, err)
						}
					}
				})
			}
			for name, source := range map[string]string{
				"same name on another type":     "type other struct{}; func (other) " + entry + "(){}; func owner(s *Service){ other{}." + entry + "() }",
				"interface with another method": "func (*Service) unrelated(){}; func owner(s *Service){ var gate interface{ unrelated() } = s; gate.unrelated() }",
				"function of the same name":     "func owner(s *Service){ " + entry + " := func(){}; " + entry + "() }",
			} {
				t.Run(name, func(t *testing.T) {
					unrelated := typeCheckSyntheticProductionPackage(t, "fixture.go", declarations+source)
					if err := validateOperationalCommissioningGate(entry, unrelated.referencesTo(requirePackageMethod(t, unrelated, "Service", entry))); err != nil {
						t.Fatalf("an occurrence that cannot reach the entry was refused: %v", err)
					}
				})
			}
		})
	}
	t.Run("store admission writers and release hook", func(t *testing.T) {
		const declarations = "package admission; type OperationalCustody struct{}; " +
			"func (*OperationalCustody) CommissionOperationalAdmission(){}; func (*OperationalCustody) AdvanceOperationalAdmission(){}; " +
			"func (*OperationalCustody) WithdrawOperationalAdmission(){}; func (*OperationalCustody) ConfigureOperationalReleaseProofForProof(){}; " +
			"type Service struct{ custody *OperationalCustody }; func install(write func()){ write() }; "
		const commission = "func (s *Service) commissionOperationalAdmission(){ install(func(){ s.custody.CommissionOperationalAdmission() }) }; "
		const advance = "func (s *Service) advanceOperationalAdmission(){ install(func(){ s.custody.AdvanceOperationalAdmission() }) }; "
		const withdraw = "func (s *Service) withdrawOperationalEffects(){ s.custody.WithdrawOperationalAdmission() }; "
		validate := func(source string) error {
			pkg := typeCheckSyntheticProductionPackage(t, "fixture.go", source)
			members := operationalAdmissionStoreMembers("fixture.go:")
			if len(members) != 4 {
				t.Fatalf("store admission members: %d", len(members))
			}
			for _, member := range members {
				method := requirePackageMethod(t, pkg, member.typ, member.name)
				if err := validateTypedReferenceInventory(member.name, operationalMemberReferences([]*typedProductionPackage{pkg}, method), member.want, member.closures); err != nil {
					return err
				}
			}
			return nil
		}
		if err := validate(declarations + commission + advance + withdraw); err != nil {
			t.Fatal(err)
		}
		if err := validate(declarations + commission + advance + withdraw + "type other struct{}; func (other) CommissionOperationalAdmission(){}; " +
			"func unrelated(s *Service){ var gate interface{ Close() }; _ = gate; other{}.CommissionOperationalAdmission() }"); err != nil {
			t.Fatalf("an occurrence that cannot reach a store writer was refused: %v", err)
		}
		for name, source := range map[string]string{
			"second commission caller":   declarations + commission + advance + withdraw + "func other(s *Service){ s.custody.CommissionOperationalAdmission() }",
			"second advance caller":      declarations + commission + advance + withdraw + "func other(s *Service){ s.custody.AdvanceOperationalAdmission() }",
			"second withdrawal caller":   declarations + commission + advance + withdraw + "func other(s *Service){ s.custody.WithdrawOperationalAdmission() }",
			"commission from advance":    declarations + commission + strings.Replace(advance, "s.custody.AdvanceOperationalAdmission()", "s.custody.AdvanceOperationalAdmission(); s.custody.CommissionOperationalAdmission()", 1) + withdraw,
			"withdrawal method value":    declarations + commission + advance + strings.Replace(withdraw, "s.custody.WithdrawOperationalAdmission()", "write := s.custody.WithdrawOperationalAdmission; write()", 1),
			"withdrawal inside closure":  declarations + commission + advance + strings.Replace(withdraw, "s.custody.WithdrawOperationalAdmission()", "func(){ s.custody.WithdrawOperationalAdmission() }()", 1),
			"commission method value":    declarations + strings.Replace(commission, "s.custody.CommissionOperationalAdmission()", "write := s.custody.CommissionOperationalAdmission; write()", 1) + advance + withdraw,
			"commission never called":    declarations + strings.Replace(commission, "s.custody.CommissionOperationalAdmission()", "", 1) + advance + withdraw,
			"release hook configuration": declarations + commission + advance + withdraw + "func other(s *Service){ s.custody.ConfigureOperationalReleaseProofForProof() }",
			"commission through an interface": declarations + commission + advance + withdraw +
				"func other(s *Service){ var gate interface{ CommissionOperationalAdmission() } = s.custody; gate.CommissionOperationalAdmission() }",
			"advance through a named interface": declarations + commission + advance + withdraw +
				"type gate interface{ AdvanceOperationalAdmission() }; func other(s *Service){ gate(s.custody).AdvanceOperationalAdmission() }",
			"withdrawal through a constraint": declarations + commission + advance + withdraw +
				"func call[T interface{ WithdrawOperationalAdmission() }](v T){ v.WithdrawOperationalAdmission() }; func other(s *Service){ call(s.custody) }",
			"release hook stored in an interface": declarations + commission + advance + withdraw +
				"func other(s *Service){ _ = interface{ ConfigureOperationalReleaseProofForProof() }(s.custody) }",
		} {
			t.Run(name, func(t *testing.T) {
				if err := validate(source); err == nil {
					t.Fatal("changed store admission reference passed its inventory")
				}
			})
		}
	})
	t.Run("confirmation call sites", func(t *testing.T) {
		const declarations = "package admission; type Service struct{}; func (*Service) confirmOperationalAdmission(){}; "
		const advance = "func (s *Service) advanceOperational(confirm func()){ precheck := func() bool { confirm(); return true }; if !precheck() { return }; if !precheck() { return } }; "
		operate := func(body string) string {
			return "func (s *Service) operatePrivateHandoff(){ confirmed := false; confirm := func(){ if !confirmed { confirmed = true; s.confirmOperationalAdmission() } }; " +
				"with := func(){ s.advanceOperational(confirm) }; with(); " + body + " }; "
		}
		validate := func(source string) error {
			return validateOperationalConfirmationInventory(t, typeCheckSyntheticProductionPackage(t, "fixture.go", source), "fixture.go:")
		}
		baseline := declarations + advance + operate("confirm()")
		if err := validate(baseline); err != nil {
			t.Fatal(err)
		}
		for name, source := range map[string]string{
			"second direct confirmation":         declarations + advance + operate("confirm(); confirm()"),
			"no direct confirmation":             declarations + advance + operate(""),
			"confirmation outside the closure":   declarations + advance + operate("confirm(); s.confirmOperationalAdmission()"),
			"confirmation from another function": baseline + "func other(s *Service){ s.confirmOperationalAdmission() }",
			"confirmation as a method value":     strings.Replace(baseline, "s.confirmOperationalAdmission() }", "ask := s.confirmOperationalAdmission; ask() }", 1),
			"closure kept":                       declarations + advance + operate("confirm(); kept := confirm; _ = kept"),
			"another closure passed": declarations + advance + strings.Replace(operate("confirm()"),
				"s.advanceOperational(confirm)", "kept := confirm; _ = kept; s.advanceOperational(func(){})", 1),
			"third pre-check":                      strings.Replace(baseline, "if !precheck() { return } }; ", "if !precheck() { return }; if !precheck() { return } }; ", 1),
			"single pre-check":                     strings.Replace(baseline, "if !precheck() { return }; if !precheck() { return } }; ", "if !precheck() { return } }; ", 1),
			"confirmation beside the pre-check":    strings.Replace(baseline, "if !precheck() { return }; ", "confirm(); if !precheck() { return }; ", 1),
			"pre-check without confirmation":       strings.Replace(baseline, "precheck := func() bool { confirm(); return true }", "precheck := func() bool { return true }; _ = confirm", 1),
			"pre-check kept":                       strings.Replace(baseline, "if !precheck() { return }; ", "if !precheck() { return }; kept := precheck; _ = kept; ", 1),
			"second advance caller":                baseline + "func other(s *Service){ s.advanceOperational(func(){}) }",
			"advance outside the original turn":    declarations + advance + strings.Replace(operate("confirm()"), "with := func(){ s.advanceOperational(confirm) }; with(); ", "s.advanceOperational(confirm); ", 1),
			"second confirmation closure variable": declarations + advance + operate("confirm(); { confirm := func(){}; confirm() }"),
		} {
			t.Run(name, func(t *testing.T) {
				if source == baseline {
					t.Fatal("mutation anchor missing")
				}
				if err := validate(source); err == nil {
					t.Fatal("changed confirmation call sites passed the inventory")
				}
			})
		}
	})
	for _, expression := range []string{"&view{}", "new(view)"} {
		t.Run("snapshot-construction/"+expression, func(t *testing.T) {
			const declarations = "package admission; type view struct{ owner int }; "
			const approved = "func commission() *view{return &view{owner:1}}; "
			want := map[string]string{"view": "fixture.go:commission"}
			if err := validateOperationalAuthorityConstruction(typeCheckSyntheticProductionPackage(t, "fixture.go", declarations+approved), want); err != nil {
				t.Fatal(err)
			}
			mutant := typeCheckSyntheticProductionPackage(t, "fixture.go", declarations+approved+"func alternate() *view{return "+expression+"}")
			if err := validateOperationalAuthorityConstruction(mutant, want); err == nil {
				t.Fatal("alternate snapshot construction passed exact inventory")
			}
		})
	}
	for name, mutation := range map[string]string{
		"proof assignment":        "s.operationalProof = &hooks{}",
		"proof keyed initializer": "_ = Service{operationalProof: &hooks{}}",
		"extra protected read":    "_ = s.operationalProof",
	} {
		t.Run(name, func(t *testing.T) {
			const declarations = "package admission; type hooks struct{}; type Service struct{ operationalProof *hooks }; "
			const baseline = "func owner(s *Service){_ = s.operationalProof}"
			want := map[string]int{"fixture.go:owner|read": 1}
			positive := typeCheckSyntheticProductionPackage(t, "fixture.go", declarations+baseline)
			field := requirePackageStructField(t, positive, "Service", "operationalProof")
			if err := validateTypedFieldAccessInventory("proof", positive.referencesTo(field), want); err != nil {
				t.Fatal(err)
			}
			mutant := typeCheckSyntheticProductionPackage(t, "fixture.go", declarations+"func owner(s *Service){_ = s.operationalProof; "+mutation+"}")
			field = requirePackageStructField(t, mutant, "Service", "operationalProof")
			if err := validateTypedFieldAccessInventory("proof", mutant.referencesTo(field), want); err == nil {
				t.Fatal("non-test proof configuration or extra read passed exact access inventory")
			}
		})
	}
	for _, entry := range []string{"bindOperationalObservation", "register", "exchange"} {
		for _, changed := range []string{"method-value", "method-expression", "closure", "alternate-site", "duplicate"} {
			t.Run(entry+"/"+changed, func(t *testing.T) {
				direct := "p." + entry + "()"
				bodies := map[string]string{
					"method-value":      "indirect := p." + entry + "; indirect()",
					"method-expression": "(*operationalProvider)." + entry + "(p)",
					"closure":           "func(){" + direct + "}()",
					"alternate-site":    direct + " }; func other(p *operationalProvider){ " + direct,
					"duplicate":         direct + ";" + direct,
				}
				declarations := "package admission; type operationalProvider struct{}; func (*operationalProvider) " + entry + "(){}; "
				baseline := typeCheckSyntheticProductionPackage(t, "fixture.go", declarations+"func owner(p *operationalProvider){"+direct+"}")
				want := map[string]int{"fixture.go:owner": 1}
				if err := validateTypedReferenceInventory(entry, baseline.referencesTo(requirePackageMethod(t, baseline, "operationalProvider", entry)), want, true); err != nil {
					t.Fatal(err)
				}
				mutant := typeCheckSyntheticProductionPackage(t, "fixture.go", declarations+"func owner(p *operationalProvider){"+bodies[changed]+"}")
				if err := validateTypedReferenceInventory(entry, mutant.referencesTo(requirePackageMethod(t, mutant, "operationalProvider", entry)), want, true); err == nil {
					t.Fatal("mutated authority reference passed its inventory")
				}
			})
		}
	}
	for _, alternate := range []string{"&verifiedOperationalObservation{}", "new(verifiedOperationalObservation)"} {
		t.Run(alternate, func(t *testing.T) {
			const declarations = "package admission; type verifiedOperationalObservation struct{ index int };"
			const verifier = "func verify() *verifiedOperationalObservation { return &verifiedOperationalObservation{index:1} };"
			want := map[string]string{"verifiedOperationalObservation": "fixture.go:verify"}
			if err := validateOperationalAuthorityConstruction(typeCheckSyntheticProductionPackage(t, "fixture.go", declarations+verifier), want); err != nil {
				t.Fatal(err)
			}
			mutant := typeCheckSyntheticProductionPackage(t, "fixture.go", declarations+verifier+"func alternate() *verifiedOperationalObservation { return "+alternate+"}")
			if err := validateOperationalAuthorityConstruction(mutant, want); err == nil {
				t.Fatal("additional observation construction escaped its inventory")
			}
		})
	}
	t.Run("same-site proof access kinds", func(t *testing.T) {
		const declarations = "package admission; type hooks struct{}; type Service struct{ operationalProof *hooks }; "
		for _, test := range []struct {
			name, body, accessKind string
		}{
			{"read", "_ = s.operationalProof", "read"},
			{"parenthesized read", "_ = (s.operationalProof)", "read"},
			{"nested read", "_ = ((s.operationalProof))", "read"},
			{"assignment", "s.operationalProof = nil", "assignment"},
			{"parenthesized assignment", "(s.operationalProof) = nil", "assignment"},
			{"nested assignment", "((s.operationalProof)) = nil", "assignment"},
		} {
			t.Run(test.name, func(t *testing.T) {
				pkg := typeCheckSyntheticProductionPackage(t, "fixture.go", declarations+"func owner(s *Service){"+test.body+"}")
				field := requirePackageStructField(t, pkg, "Service", "operationalProof")
				references := pkg.referencesTo(field)
				if len(references) != 1 || references[0].site != "fixture.go:owner" {
					t.Fatalf("same-site proof occurrence changed: %v", references)
				}
				if references[0].accessKind != test.accessKind {
					t.Fatalf("proof access kind: got %q want %q", references[0].accessKind, test.accessKind)
				}
				allowedRead := map[string]int{"fixture.go:owner|read": 1}
				readErr := validateTypedFieldAccessInventory("proof", references, allowedRead)
				if test.accessKind == "read" {
					if readErr != nil {
						t.Fatal(readErr)
					}
				} else if readErr == nil || !strings.Contains(readErr.Error(), "field access inventory changed") ||
					!strings.Contains(readErr.Error(), "|assignment") {
					t.Fatalf("expected intended proof access-kind mismatch, got %v", readErr)
				}
				appropriate := map[string]int{"fixture.go:owner|" + test.accessKind: 1}
				if err := validateTypedFieldAccessInventory("proof", references, appropriate); err != nil {
					t.Fatalf("correctly classified proof access refused: %v", err)
				}
			})
		}
	})
}

// validateOperationalAuthorityConstruction requires that a value of each named
// authority type comes to exist in exactly one way: one composite literal at
// the expected site. Every other whole-value occurrence of the type (a second
// literal, new, a zero-value declaration, a conversion from a same-shape
// type, an overwrite or a copy) is refused.
func validateOperationalAuthorityConstruction(pkg *typedProductionPackage, want map[string]string) error {
	for name, expectedSite := range want {
		declared, ok := pkg.pkg.Scope().Lookup(name).(*types.TypeName)
		if !ok {
			return fmt.Errorf("%s authority type was not found", name)
		}
		structure, ok := declared.Type().Underlying().(*types.Struct)
		if !ok {
			return fmt.Errorf("%s authority type is not a struct", name)
		}
		got := make(map[string]int)
		for _, reference := range pkg.wholeValueReferences(structure, nil, name) {
			got[reference.site+"|"+reference.accessKind]++
		}
		if len(got) != 1 || got[expectedSite+"|initializer"] != 1 {
			return fmt.Errorf("%s authority construction changed: got %v, want one literal in %s", name, got, expectedSite)
		}
	}
	return nil
}
