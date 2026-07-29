package admission

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestReliableSubmitFoundationHasNoRuntimeWiring(t *testing.T) {
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
