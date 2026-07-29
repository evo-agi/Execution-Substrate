package reliablesubmit_test

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

func TestReliableSubmitPureModelStaticGuardrails(t *testing.T) {
	path := filepath.Join("model.go")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read model source: %v", err)
	}
	source := string(data)

	file, err := parser.ParseFile(token.NewFileSet(), path, data, parser.ParseComments)
	if err != nil {
		t.Fatalf("parse model source: %v", err)
	}

	assertPureModelImports(t, file)
	assertNoStructTags(t, file)
	assertDistinctPhaseStructs(t, file)
	assertNoProjectionHelpers(t, file)
	assertNoForbiddenSourceCoupling(t, source)
	assertPhaseInterfaceOperationsNormalize(t, file, source)
	assertExactReplayStoresSnapshot(t, file, source)
}

func TestReliableSubmitPrivatePersistenceStaticGuardrails(t *testing.T) {
	backendNeutral := []string{
		"clock.go",
		"durable_operation.go",
		"durable_record.go",
		"durable_service.go",
		"store.go",
	}
	sqliteSpecific := map[string]bool{
		"sqlite_migrations.go": true,
		"sqlite_store.go":      true,
	}

	for _, path := range backendNeutral {
		file, source := mustParseReliableSubmitSource(t, path)
		assertNoStructTags(t, file)
		assertBackendNeutralPersistenceImports(t, path, file)
		assertNoPublicStorageSurface(t, path, file)
		assertNoForbiddenPersistenceSource(t, path, source)
	}
	for path := range sqliteSpecific {
		file, source := mustParseReliableSubmitSource(t, path)
		assertNoStructTags(t, file)
		assertSQLiteSpecificImports(t, path, file)
		assertNoPublicStorageSurface(t, path, file)
		assertNoPostgreSQLSource(t, path, source)
	}

	storeSource := mustReadReliableSubmitSource(t, "store.go")
	assertContainsUnexportedPort(t, storeSource)
	assertContainsNoneInSource(t, "claimStore common port", storeSource,
		"Backup",
		"*sql.DB",
		"*sql.Tx",
		"pgx",
		"SQLSTATE",
		"DSN",
		"Save(",
		"Delete(",
		"List(",
	)

	recordSource := mustReadReliableSubmitSource(t, "durable_record.go")
	assertContainsNoneInSource(t, "durable record phase storage", recordSource,
		"interface{}",
		"any `",
		"MarshalJSON",
		"UnmarshalJSON",
		"Value()",
		"Scan(",
	)
	recordFile, _ := mustParseReliableSubmitSource(t, "durable_record.go")
	assertDurableRecordDoesNotStoreClaimPhase(t, recordFile)
	for _, required := range []string{
		"type durablePhaseTag uint8",
		"type durablePhaseSnapshot struct",
		"func durablePhaseSnapshotFromPhase(phase ClaimPhase) (ClaimID, BoundPlan, durablePhaseSnapshot, error)",
		"func (s durablePhaseSnapshot) hydrate(claim ClaimID, plan BoundPlan) (ClaimPhase, error)",
		"NewPendingBeforeAssignment",
		"AssignRun",
		"NewAccepted",
		"NewProvablyNotAcceptedAfterAssignment",
	} {
		if !strings.Contains(recordSource, required) {
			t.Fatalf("durable record codec missing %q", required)
		}
	}

	repoRoot := reliableSubmitRepoRoot()
	assertNoSQLiteOutsideReliableSubmitPackage(t, repoRoot)
	assertNoReliableSubmitRuntimeWiring(t, repoRoot)
	assertNoReliableSubmitConfigFields(t, repoRoot)
}

func assertPureModelImports(t *testing.T, file *ast.File) {
	t.Helper()

	for _, imported := range file.Imports {
		importPath, err := strconv.Unquote(imported.Path.Value)
		if err != nil {
			t.Fatalf("unquote import path: %v", err)
		}

		for _, forbidden := range []string{
			"net/http",
			"database/sql",
			"os",
			"io",
			"io/fs",
			"path",
			"path/filepath",
			"time",
			"reflect",
			"sync",
			"sync/atomic",
			"encoding/json",
			"encoding/xml",
		} {
			if importPath == forbidden {
				t.Fatalf("pure reliable-submit model must not import %q", importPath)
			}
		}
		for _, forbiddenFragment := range []string{
			"execution-substrate/",
			"nomad",
			"yaml",
			"gorm",
			"sqlite",
		} {
			if strings.Contains(strings.ToLower(importPath), forbiddenFragment) {
				t.Fatalf("pure reliable-submit model import %q violates %q", importPath, forbiddenFragment)
			}
		}
	}
}

func mustParseReliableSubmitSource(t *testing.T, path string) (*ast.File, string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	file, err := parser.ParseFile(token.NewFileSet(), path, data, parser.ParseComments)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	return file, string(data)
}

func mustReadReliableSubmitSource(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(data)
}

func assertBackendNeutralPersistenceImports(t *testing.T, path string, file *ast.File) {
	t.Helper()
	for _, imported := range file.Imports {
		importPath := unquoteImportPath(t, imported)
		for _, forbidden := range []string{
			"database/sql",
			"modernc.org/sqlite",
			"net/http",
			"os",
			"io",
			"io/fs",
			"path",
			"path/filepath",
			"sync",
			"encoding/json",
			"encoding/xml",
		} {
			if importPath == forbidden {
				t.Fatalf("%s must remain backend-neutral and must not import %q", path, importPath)
			}
		}
		for _, forbiddenFragment := range []string{
			"pgx",
			"postgres",
			"nomad",
			"coordinator",
			"bridge",
			"yaml",
			"gorm",
		} {
			if strings.Contains(strings.ToLower(importPath), forbiddenFragment) {
				t.Fatalf("%s import %q violates backend-neutral guardrail %q", path, importPath, forbiddenFragment)
			}
		}
	}
}

func assertSQLiteSpecificImports(t *testing.T, path string, file *ast.File) {
	t.Helper()
	for _, imported := range file.Imports {
		importPath := unquoteImportPath(t, imported)
		for _, forbiddenFragment := range []string{
			"pgx",
			"postgres",
			"nomad",
			"coordinator",
			"bridge",
			"yaml",
			"gorm",
		} {
			if strings.Contains(strings.ToLower(importPath), forbiddenFragment) {
				t.Fatalf("%s import %q violates SQLite implementation guardrail %q", path, importPath, forbiddenFragment)
			}
		}
	}
}

func assertNoPublicStorageSurface(t *testing.T, path string, file *ast.File) {
	t.Helper()
	for _, decl := range file.Decls {
		switch typed := decl.(type) {
		case *ast.GenDecl:
			for _, spec := range typed.Specs {
				typeSpec, ok := spec.(*ast.TypeSpec)
				if !ok || !typeSpec.Name.IsExported() {
					continue
				}
				name := typeSpec.Name.Name
				if strings.Contains(name, "Store") ||
					strings.Contains(name, "Repository") ||
					strings.Contains(name, "Persistence") ||
					strings.Contains(name, "Record") ||
					strings.Contains(name, "Codec") {
					t.Fatalf("%s exposes storage type %s", path, name)
				}
			}
		case *ast.FuncDecl:
			if typed.Name.IsExported() {
				name := typed.Name.Name
				if strings.Contains(name, "Store") ||
					strings.Contains(name, "Repository") ||
					strings.Contains(name, "Persistence") ||
					strings.Contains(name, "Record") ||
					strings.Contains(name, "Codec") {
					t.Fatalf("%s exposes storage function %s", path, name)
				}
			}
		}
	}
}

func assertDurableRecordDoesNotStoreClaimPhase(t *testing.T, file *ast.File) {
	t.Helper()
	found := false
	for _, decl := range file.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok || gen.Tok != token.TYPE {
			continue
		}
		for _, spec := range gen.Specs {
			typeSpec, ok := spec.(*ast.TypeSpec)
			if !ok || typeSpec.Name.Name != "durableClaimRecord" {
				continue
			}
			found = true
			structType, ok := typeSpec.Type.(*ast.StructType)
			if !ok {
				t.Fatalf("durableClaimRecord must remain a struct")
			}
			for _, field := range structType.Fields.List {
				ident, ok := field.Type.(*ast.Ident)
				if ok && ident.Name == "ClaimPhase" {
					t.Fatalf("durableClaimRecord must not store ClaimPhase interface fields")
				}
			}
		}
	}
	if !found {
		t.Fatalf("durableClaimRecord type not found")
	}
}

func assertNoForbiddenPersistenceSource(t *testing.T, path string, source string) {
	t.Helper()
	assertContainsNoneInSource(t, path, source,
		"net/http",
		"Nomad",
		"nomad",
		"Coordinator",
		"Bridge",
		"pgx",
		"postgres",
		"SQLSTATE",
		"dsn",
		"DTO",
		"json:",
		"yaml:",
		"gorm:",
	)
}

func assertNoPostgreSQLSource(t *testing.T, path string, source string) {
	t.Helper()
	assertContainsNoneInSource(t, path, strings.ToLower(source),
		"pgx",
		"postgres",
		"sqlstate",
	)
}

func assertContainsUnexportedPort(t *testing.T, source string) {
	t.Helper()
	for _, required := range []string{
		"type claimStore interface",
		"establishClaim(context.Context, establishClaimCommand) (establishClaimStoreResult, error)",
		"loadClaim(context.Context, loadClaimQuery) (durableClaimRecord, error)",
		"compareAndSwapClaim(context.Context, compareAndSwapClaimCommand) (compareAndSwapClaimStoreResult, error)",
	} {
		if !strings.Contains(source, required) {
			t.Fatalf("claimStore port missing %q", required)
		}
	}
}

func assertContainsNoneInSource(t *testing.T, label string, source string, forbidden ...string) {
	t.Helper()
	for _, phrase := range forbidden {
		if strings.Contains(source, phrase) {
			t.Fatalf("%s must not contain %q", label, phrase)
		}
	}
}

func assertNoSQLiteOutsideReliableSubmitPackage(t *testing.T, repoRoot string) {
	t.Helper()
	if err := filepath.WalkDir(repoRoot, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			t.Fatalf("walk %s: %v", path, err)
		}
		if entry.IsDir() {
			switch entry.Name() {
			case ".git", ".out":
				return filepath.SkipDir
			}
			return nil
		}
		if filepath.Ext(path) != ".go" {
			return nil
		}
		if filepath.Base(path) == "docs_contract_test.go" {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		source := string(data)
		if importsModernCSQLite(t, path, data) || strings.Contains(source, `sql.Open("sqlite"`) {
			rel, err := filepath.Rel(repoRoot, path)
			if err != nil {
				t.Fatalf("rel %s: %v", path, err)
			}
			if !strings.HasPrefix(filepath.ToSlash(rel), "es/admission/internal/reliablesubmit/") {
				t.Fatalf("SQLite source outside reliable-submit package: %s", rel)
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("walk reliable-submit guardrail scope: %v", err)
	}
}

func importsModernCSQLite(t *testing.T, path string, data []byte) bool {
	t.Helper()
	file, err := parser.ParseFile(token.NewFileSet(), path, data, parser.ImportsOnly)
	if err != nil {
		t.Fatalf("parse imports %s: %v", path, err)
	}
	for _, imported := range file.Imports {
		if unquoteImportPath(t, imported) == "modernc.org/sqlite" {
			return true
		}
	}
	return false
}

func assertNoReliableSubmitRuntimeWiring(t *testing.T, repoRoot string) {
	t.Helper()
	for _, rel := range []string{
		"es/admission/submit.go",
		"es/admission/service.go",
		"es/admission/types.go",
		"es/admission/producercontract.go",
		"es/admission/executionlocator.go",
		"es/admission/executionpackage.go",
		"es/admission/lifecycle.go",
		"es/admission/results.go",
		"es/api/server.go",
		"es/config/config.go",
		"es/app/app.go",
	} {
		data, err := os.ReadFile(filepath.Join(repoRoot, rel))
		if err != nil {
			t.Fatalf("read %s: %v", rel, err)
		}
		source := string(data)
		assertContainsNoneInSource(t, rel, source,
			"internal/reliablesubmit",
			"reliablesubmit",
			"ReliableSubmit",
			"reliable_submit",
			"modernc.org/sqlite",
		)
	}
}

func assertNoReliableSubmitConfigFields(t *testing.T, repoRoot string) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(repoRoot, "es/config/config.go"))
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	source := string(data)
	sectionStart := strings.Index(source, "type ExecutionConfig struct {")
	sectionEnd := strings.Index(source, "type VerificationConfig struct {")
	if sectionStart == -1 || sectionEnd <= sectionStart {
		t.Fatalf("ExecutionConfig section not found")
	}
	assertContainsNoneInSource(t, "ExecutionConfig", source[sectionStart:sectionEnd],
		"ReliableSubmit",
		"SQLite",
		"Database",
		"StorePath",
	)
}

func reliableSubmitRepoRoot() string {
	return filepath.Clean(filepath.Join("..", "..", "..", ".."))
}

func unquoteImportPath(t *testing.T, imported *ast.ImportSpec) string {
	t.Helper()
	importPath, err := strconv.Unquote(imported.Path.Value)
	if err != nil {
		t.Fatalf("unquote import path: %v", err)
	}
	return importPath
}

func assertNoStructTags(t *testing.T, file *ast.File) {
	t.Helper()

	ast.Inspect(file, func(node ast.Node) bool {
		field, ok := node.(*ast.Field)
		if !ok || field.Tag == nil {
			return true
		}
		t.Fatalf("pure reliable-submit model must not define transport, JSON, YAML, database, or ORM tags: %s", field.Tag.Value)
		return false
	})
}

func assertDistinctPhaseStructs(t *testing.T, file *ast.File) {
	t.Helper()

	required := map[string]bool{
		"PendingBeforeAssignment":            false,
		"AmbiguousBeforeAssignment":          false,
		"EffectCapableAssigned":              false,
		"PendingAfterAssignment":             false,
		"AmbiguousAfterAssignment":           false,
		"Accepted":                           false,
		"ProvablyNotAcceptedAfterAssignment": false,
		"RecoveredAccepted":                  false,
		"ExactReplay":                        false,
		"Conflict":                           false,
		"Unauthorized":                       false,
		"ExpiredUnavailable":                 false,
	}

	for _, decl := range file.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok || gen.Tok != token.TYPE {
			continue
		}
		for _, spec := range gen.Specs {
			typeSpec, ok := spec.(*ast.TypeSpec)
			if !ok {
				continue
			}
			structType, ok := typeSpec.Type.(*ast.StructType)
			if !ok {
				continue
			}
			if _, ok := required[typeSpec.Name.Name]; ok {
				required[typeSpec.Name.Name] = true
				for _, field := range structType.Fields.List {
					switch expr := field.Type.(type) {
					case *ast.StarExpr:
						t.Fatalf("%s must not use optional pointer fields: %T", typeSpec.Name.Name, expr.X)
					case *ast.ArrayType:
						t.Fatalf("%s must not be a slice/array-backed optional field bag", typeSpec.Name.Name)
					case *ast.MapType:
						t.Fatalf("%s must not retain mutable maps", typeSpec.Name.Name)
					}
				}
			}
		}
	}

	for name, found := range required {
		if !found {
			t.Fatalf("reliable-submit model missing distinct struct %s", name)
		}
	}
}

func assertNoProjectionHelpers(t *testing.T, file *ast.File) {
	t.Helper()

	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok {
			continue
		}
		switch fn.Name.Name {
		case "String", "GoString", "Bytes", "Raw", "MarshalJSON", "UnmarshalJSON", "MarshalYAML", "UnmarshalYAML", "Value", "Scan":
			t.Fatalf("pure reliable-submit model must not define projection/storage helper %s", fn.Name.Name)
		}
		if strings.Contains(fn.Name.Name, "DTO") ||
			strings.Contains(fn.Name.Name, "HTTP") ||
			strings.Contains(fn.Name.Name, "JSON") ||
			strings.Contains(fn.Name.Name, "Database") ||
			strings.Contains(fn.Name.Name, "Persist") ||
			strings.Contains(fn.Name.Name, "Store") ||
			strings.Contains(fn.Name.Name, "RequestID") ||
			strings.Contains(fn.Name.Name, "TraceID") {
			t.Fatalf("pure reliable-submit model helper %s selects a forbidden boundary", fn.Name.Name)
		}
	}
}

func assertNoForbiddenSourceCoupling(t *testing.T, source string) {
	t.Helper()

	for _, forbidden := range []string{
		"executionLocator",
		"runIDPattern",
		"exec-<run_id>",
		"JobID",
		"jobID",
		"allocation ID",
		"allocation_id",
		"AllocationID",
		"EvalID",
		"trace ID",
		"trace_id",
		"TraceID",
		"request ID",
		"request_id",
		"RequestID",
		"CoordinatorProgressionPermitted",
		"Coordinator",
		"work_item_id",
		"attempt_id",
		"repair_id",
		"dispatch_command_id",
		"DevelopmentProgram",
		"adapter session",
		"session identity",
		"nomad",
		"Nomad",
		"net/http",
		"database/sql",
		"reflect",
		"sync.",
		"Mutex",
		"RWMutex",
		"sync.Once",
		"registry",
		"schema migration",
		"migration",
		"staging",
		"schema_version",
		"json:",
		"yaml:",
		"db:",
		"gorm:",
	} {
		if strings.Contains(source, forbidden) {
			t.Fatalf("pure reliable-submit model contains forbidden coupling %q", forbidden)
		}
	}
}

func assertPhaseInterfaceOperationsNormalize(t *testing.T, file *ast.File, source string) {
	t.Helper()

	for _, required := range []string{
		"func normalizeClaimPhase(phase ClaimPhase, invalid error) (ClaimPhase, error)",
		"func normalizePreAssignmentPhase(phase PreAssignmentPhase) (claimCore, error)",
		"func normalizeAssignedRunPhase(phase AssignedRunPhase) (assignedCore, error)",
		"func normalizeProviderOutcomeCandidatePhase(phase ProviderOutcomeCandidatePhase, invalid error) (assignedCore, error)",
		"normalized, err := normalizeClaimPhase(phase, ErrInvalidPhase)",
		"normalized, err := normalizeClaimPhase(phase, invalid)",
		"normalized, err := normalizeClaimPhase(phase, ErrInvalidReplay)",
		"core, err := normalizePreAssignmentPhase(phase)",
		"assigned, err := normalizeAssignedRunPhase(phase)",
		"return normalizeProviderOutcomeCandidatePhase(phase, ErrInvalidProviderOutcomeCandidatePhase)",
		"snapshot, err := newExactReplayPhaseSnapshot(phase)",
	} {
		if !strings.Contains(source, required) {
			t.Fatalf("pure reliable-submit model missing normalization guardrail source %q", required)
		}
	}

	if strings.Contains(source, "phase == nil") {
		t.Fatalf("phase interface operations must use closed type switches instead of nil-interface checks")
	}

	checked := map[string]bool{
		"AssignRun":                             false,
		"ValidateRunAssignment":                 false,
		"ValidatePlanBinding":                   false,
		"NewAccepted":                           false,
		"providerOutcomeCandidateCore":          false,
		"NewProvablyNotAcceptedAfterAssignment": false,
		"NewExactReplay":                        false,
	}
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok {
			continue
		}
		if _, ok := checked[fn.Name.Name]; !ok {
			continue
		}
		checked[fn.Name.Name] = true
		ast.Inspect(fn.Body, func(node ast.Node) bool {
			selector, ok := node.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			ident, ok := selector.X.(*ast.Ident)
			if !ok || ident.Name != "phase" {
				return true
			}
			switch selector.Sel.Name {
			case "Valid", "Kind", "HasAssignedRunRef", "AssignedRunRef", "ReceiptRef", "SameCallerRunRefDisclosure", "AcceptedSubmissionReferenceAvailable":
				t.Fatalf("%s calls %s on unnormalized phase input", fn.Name.Name, selector.Sel.Name)
			}
			return true
		})
	}
	for name, found := range checked {
		if !found {
			t.Fatalf("normalization guardrail did not inspect %s", name)
		}
	}
}

func assertExactReplayStoresSnapshot(t *testing.T, file *ast.File, source string) {
	t.Helper()

	for _, required := range []string{
		"type exactReplayPhaseSnapshot struct",
		"underlying exactReplayPhaseSnapshot",
		"func newExactReplayPhaseSnapshot(phase ClaimPhase) (exactReplayPhaseSnapshot, error)",
		"func (s exactReplayPhaseSnapshot) validPhase() (ClaimPhase, bool)",
		"AcceptedSubmissionReferenceAvailable() bool",
	} {
		if !strings.Contains(source, required) {
			t.Fatalf("pure reliable-submit model missing replay snapshot guardrail source %q", required)
		}
	}
	for _, forbidden := range []string{
		"underlying ClaimPhase",
		"underlying *",
		"CoordinatorProgressionPermitted",
	} {
		if strings.Contains(source, forbidden) {
			t.Fatalf("pure reliable-submit model violates replay/neutral-grammar guardrail with %q", forbidden)
		}
	}

	foundReplay := false
	for _, decl := range file.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok || gen.Tok != token.TYPE {
			continue
		}
		for _, spec := range gen.Specs {
			typeSpec, ok := spec.(*ast.TypeSpec)
			if !ok || typeSpec.Name.Name != "ExactReplay" {
				continue
			}
			foundReplay = true
			structType, ok := typeSpec.Type.(*ast.StructType)
			if !ok {
				t.Fatalf("ExactReplay must remain a struct")
			}
			if len(structType.Fields.List) != 1 {
				t.Fatalf("ExactReplay must retain only the private snapshot field")
			}
			field := structType.Fields.List[0]
			ident, ok := field.Type.(*ast.Ident)
			if !ok || ident.Name != "exactReplayPhaseSnapshot" {
				t.Fatalf("ExactReplay must store exactReplayPhaseSnapshot, got %T", field.Type)
			}
		}
	}
	if !foundReplay {
		t.Fatalf("ExactReplay type not found")
	}
}
