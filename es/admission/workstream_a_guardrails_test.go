package admission

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"

	arsapi "execution-substrate/ars/api"
	evidencev1 "execution-substrate/internal/contracts/evidence/v1"
)

func TestWorkstreamAAdmissionVerifiesSignedEvidenceEnvelopeAndPackageIdentity(t *testing.T) {
	fixture := newPreparedArtifactFixture(t)
	service := fixture.service()
	request := fixture.prepareRequest()

	artifact, err := service.prepareArtifactFromDiscovery(request, fixture.trustModel, discoveredArtifact{
		discovery: fixture.discovery,
		evidence:  fixture.evidence,
	})
	if err != nil {
		t.Fatalf("expected signed evidence and package identity to prepare, got %+v", err)
	}
	if artifact.payloadDigest != fixture.evidence.Claims.Package.Identity.PayloadDigest {
		t.Fatalf("expected payload digest from package identity, got %q", artifact.payloadDigest)
	}
	if artifact.manifest.ArtifactDigest != fixture.evidence.Claims.Package.Identity.ArtifactDigest {
		t.Fatalf("expected manifest projection to use package identity, got %+v", artifact.manifest)
	}

	tamperedEvidence := fixture.evidence
	tamperedEvidence.Claims.Admission.Execution.Runtime.EnvironmentVariables = append(tamperedEvidence.Claims.Admission.Execution.Runtime.EnvironmentVariables, "TAMPERED_AFTER_SIGNING")
	_, err = service.prepareArtifactFromDiscovery(request, fixture.trustModel, discoveredArtifact{
		discovery: fixture.discovery,
		evidence:  tamperedEvidence,
	})
	if err == nil || err.Code != codeArtifactEvidenceInvalid || !strings.Contains(err.Message, "signature verification failed") {
		t.Fatalf("expected evidence seal verification to reject tampered claims, got %+v", err)
	}

	mismatchedDiscovery := fixture.discovery
	mismatchedDiscovery.Payload.Digest = labeledDigest("99")
	_, err = service.prepareArtifactFromDiscovery(request, fixture.trustModel, discoveredArtifact{
		discovery: mismatchedDiscovery,
		evidence:  fixture.evidence,
	})
	if err == nil || err.Code != codeArtifactEvidenceInvalid || !strings.Contains(err.Message, "payload reference does not match artifact evidence") {
		t.Fatalf("expected package identity payload cross-check to reject mismatched discovery, got %+v", err)
	}
}

func TestWorkstreamAAdmissionUsesOnlyNarrowExecutionClaimsFromEvidence(t *testing.T) {
	fixture := newPreparedArtifactFixture(t)
	service := fixture.service()
	request := fixture.prepareRequest()
	request.Invocation.Env = map[string]string{
		"ALLOWED_MODE": "test",
	}

	evidence := signedWorkstreamAEvidence(t, fixture, func(record *evidencev1.ArtifactEvidence) {
		record.Claims.Admission.Execution.Runtime.EnvironmentVariables = []string{"ALLOWED_MODE"}
		record.Claims.Admission.Execution.Runtime.RequiredCapabilities = []string{"needs-special-device"}
		record.Claims.Admission.Execution.Workload.TargetPlatform = "docker"
		record.Claims.Admission.Execution.Access.NetworkAccess = false
	})

	artifact, err := service.prepareArtifactFromDiscovery(request, fixture.trustModel, discoveredArtifactWithEvidence(t, fixture.discovery, evidence))
	if err != nil {
		t.Fatalf("expected narrow execution claims to prepare, got %+v", err)
	}
	if artifact.targetPlatform != "docker" {
		t.Fatalf("expected target_platform from evidence, got %q", artifact.targetPlatform)
	}
	if artifact.networkAccess {
		t.Fatalf("expected network_access=false from evidence")
	}
	if !reflect.DeepEqual(artifact.manifest.RuntimeInterface.EnvironmentVariables, []string{"ALLOWED_MODE"}) {
		t.Fatalf("expected env allowlist from evidence, got %+v", artifact.manifest.RuntimeInterface.EnvironmentVariables)
	}
	if !reflect.DeepEqual(artifact.manifest.RuntimeInterface.RequiredCapabilities, []string{"needs-special-device"}) {
		t.Fatalf("expected required capabilities from evidence, got %+v", artifact.manifest.RuntimeInterface.RequiredCapabilities)
	}

	request.Invocation.Env = map[string]string{
		"UNDECLARED_MODE": "test",
	}
	_, err = service.prepareArtifactFromDiscovery(request, fixture.trustModel, discoveredArtifactWithEvidence(t, fixture.discovery, evidence))
	if err == nil || err.Code != codeInvalidRequest || !strings.Contains(err.Message, "environment key is not allowed") {
		t.Fatalf("expected evidence runtime env allowlist to guard request env, got %+v", err)
	}
}

func TestWorkstreamAAdmissionTreatsPublicationAsSignedButNotESGrammar(t *testing.T) {
	fixture := newPreparedArtifactFixture(t)
	service := fixture.service()
	request := fixture.prepareRequest()

	baseline, err := service.prepareArtifactFromDiscovery(request, fixture.trustModel, discoveredArtifactWithEvidence(t, fixture.discovery, fixture.evidence))
	if err != nil {
		t.Fatalf("expected baseline evidence to prepare, got %+v", err)
	}

	variedPublication := signedWorkstreamAEvidence(t, fixture, func(record *evidencev1.ArtifactEvidence) {
		record.Claims.Package.Publication = evidencev1.Publication{
			BuilderService: "alternate-ags-builder",
			Invoker: evidencev1.Invoker{
				Service:   "service/other-publisher",
				Principal: "spiffe://execution.internal/service/other-publisher",
			},
			PolicyDecisions: []evidencev1.PolicyDecision{
				{Rule: "z-publication-owned", Result: "recorded"},
				{Rule: "a-publication-owned", Result: "recorded"},
			},
			BuildLogDigest: labeledDigest("55"),
		}
	})
	preparedWithVariedPublication, err := service.prepareArtifactFromDiscovery(request, fixture.trustModel, discoveredArtifactWithEvidence(t, fixture.discovery, variedPublication))
	if err != nil {
		t.Fatalf("expected validly signed publication variation to prepare, got %+v", err)
	}
	if !reflect.DeepEqual(preparedWithVariedPublication, baseline) {
		t.Fatalf("expected AGS-owned publication variation not to alter ES prepared artifact\nbaseline=%+v\nvaried=%+v", baseline, preparedWithVariedPublication)
	}

	tamperedPublication := variedPublication
	tamperedPublication.Claims.Package.Publication.BuilderService = "tampered-after-signing"
	_, err = service.prepareArtifactFromDiscovery(request, fixture.trustModel, discoveredArtifactWithEvidence(t, fixture.discovery, tamperedPublication))
	if err == nil || err.Code != codeArtifactEvidenceInvalid || !strings.Contains(err.Message, "signature verification failed") {
		t.Fatalf("expected tampered signed publication bytes to fail evidence integrity, got %+v", err)
	}
}

func TestWorkstreamAAdmissionDTOsExcludePublicationARSSupportAndCPGrammar(t *testing.T) {
	fieldNames := collectJSONFieldNames(t,
		PrepareRequest{},
		ArtifactInvocation{},
		ExecutionResources{},
		RuntimeMount{},
		MountSource{},
		PrepareResult{},
		SubmitResult{},
		ExecutionStatusResult{},
		ExecutionCancelResult{},
		ProducerContractDeclaration{},
	)

	for _, forbidden := range []string{
		"publication",
		"builder_service",
		"invoker",
		"policy_decisions",
		"build_log_digest",
		"descriptor",
		"descriptor_digest",
		"manifest",
		"manifest_digest",
		"index",
		"index_entry",
		"discovery_digest",
		"attempt",
		"task_attempt",
		"review",
		"checkpoint",
		"finalization",
		"approval",
		"hold",
		"resume",
		"reject",
	} {
		if _, ok := fieldNames[forbidden]; ok {
			t.Fatalf("ES admission public DTOs must not expose upstream or CP-owned grammar field %q", forbidden)
		}
	}
}

func TestWorkstreamAESImplementationDoesNotExposeAGSPublicationGrammar(t *testing.T) {
	assertNoForbiddenWorkstreamASourceTerms(t, workstreamAESBoundaryNonTestGoFiles(t), []workstreamASourceTerm{
		{
			name:        "AGS-owned publication Go identifier",
			identifiers: []string{"Publication", "publication", "Published", "published", "Publisher", "publisher", "BuilderService", "builderService", "BuildLogDigest", "PolicyDecision", "PolicyDecisions", "Invoker", "SourceURI", "SourceUri", "PublishedAt"},
		},
		{
			name:            "AGS-owned publication JSON/string spelling",
			stringSpellings: []string{"builder_service", "source_uri", "published_at", "publication", "build_log_digest", "policy_decisions", "invoker"},
		},
	}, allowedWorkstreamAPublicationOccurrence)
}

// The allow rule of the publication guard judges the identifier or literal
// that holds a forbidden spelling, never the text of its line: a comment
// that names an allowed identifier, or an allowed field written beside other
// code, allows nothing.
func TestWorkstreamAPublicationAllowRuleJudgesTheCodeNotTheLine(t *testing.T) {
	terms := []workstreamASourceTerm{
		{
			name:        "AGS-owned publication Go identifier",
			identifiers: []string{"Publication", "publication", "Published", "published", "Publisher", "publisher", "BuilderService", "builderService", "BuildLogDigest", "PolicyDecision", "PolicyDecisions", "Invoker", "SourceURI", "SourceUri", "PublishedAt"},
		},
		{
			name:            "AGS-owned publication JSON/string spelling",
			stringSpellings: []string{"builder_service", "source_uri", "published_at", "publication", "build_log_digest", "policy_decisions", "invoker"},
		},
	}
	refused := func(file, source string) []string {
		var names []string
		for _, occurrence := range workstreamASourceOccurrencesOf(t, file, []byte(source), terms) {
			if !allowedWorkstreamAPublicationOccurrence(occurrence) {
				names = append(names, fmt.Sprintf("%d:%s", occurrence.line, occurrence.spelling))
			}
		}
		return names
	}
	const policy = "package admission\n\n" +
		"type AdmissionPolicyDecision struct{ Allowed bool }\n\n" +
		"func AllowAdmissionPolicyDecision() AdmissionPolicyDecision { return AdmissionPolicyDecision{Allowed: true} }\n\n" +
		"func DenyAdmissionPolicyDecision() AdmissionPolicyDecision { return AdmissionPolicyDecision{} }\n"
	const service = "package admission\n\nimport \"encoding/json\"\n\n" +
		"type signedRuntimeTrustResponse struct {\n" +
		"\tSignature   string          `json:\"signature\"`\n" +
		"\tPublication json.RawMessage `json:\"publication,omitempty\"`\n" +
		"}\n"
	for name, test := range map[string]struct{ file, source string }{
		"the policy seam type and its constructors":   {"policy.go", policy},
		"the ignored runtime-trust publication field": {"service.go", service},
	} {
		t.Run("allowed: "+name, func(t *testing.T) {
			if got := refused(test.file, test.source); len(got) != 0 {
				t.Fatalf("an allowed occurrence was refused: %v", got)
			}
		})
	}
	for name, test := range map[string]struct{ file, source, want string }{
		"an identifier with a comment that names the seam type": {"policy.go", policy + "\nvar zzProbePolicyDecision = 1 // AdmissionPolicyDecision\n", "9:PolicyDecision"},
		"an identifier on a line that uses the seam type":       {"policy.go", policy + "\nvar zzPolicyDecision AdmissionPolicyDecision\n", "9:PolicyDecision"},
		"the seam type in another file":                         {"service.go", policy, "3:PolicyDecision"},
		"an identifier that contains the seam type's name":      {"policy.go", policy + "\nvar AdmissionPolicyDecisionOverride = 1\n", "9:PolicyDecision"},
		"the seam type in a policy.go of another package":       {"../app/policy.go", policy, "3:PolicyDecision"},
		"an identifier with a comment that spells the field": {"service.go", service +
			"\nvar zzPublication = 1 // Publication json.RawMessage `json:\"publication,omitempty\"`\n", "10:Publication"},
		"an identifier of type json.RawMessage with the tag in a comment": {"service.go", service +
			"\nvar zzPublication json.RawMessage // `json:\"publication,omitempty\"`\n", "10:Publication"},
		"a read of the field on a line that spells it": {"service.go", service +
			"\nfunc zz(r signedRuntimeTrustResponse) json.RawMessage { return r.Publication } // json.RawMessage `json:\"publication,omitempty\"`\n", "10:Publication"},
		"the same field in another struct": {"service.go", service +
			"\ntype PrepareRequest struct {\n\tPublication json.RawMessage `json:\"publication,omitempty\"`\n}\n", "11:Publication"},
		"the field in a service.go of another package": {"../app/service.go", service, "7:Publication"},
		"the field in another struct only":             {"service.go", strings.Replace(service, "signedRuntimeTrustResponse", "PrepareRequest", 1), "7:Publication"},
		"the field with another tag":                   {"service.go", strings.Replace(service, "json:\"publication,omitempty\"", "json:\"publication\"", 1), "7:Publication"},
		"the field with another type":                  {"service.go", strings.Replace(service, "json.RawMessage", "string         ", 1), "7:Publication"},
		"the tag in another field":                     {"service.go", strings.Replace(service, "Publication json.RawMessage", "Payload     json.RawMessage", 1), "7:publication"},
	} {
		t.Run("refused: "+name, func(t *testing.T) {
			if got := refused(test.file, test.source); !slices.Contains(got, test.want) {
				t.Fatalf("refused %v, want %s among them", got, test.want)
			}
		})
	}
}

func TestWorkstreamAESBoundaryImportsExcludeARSSupportAndAGSPublicationPackages(t *testing.T) {
	blocked := []workstreamABlockedImport{
		{path: "execution-substrate/ars/index", reason: "ARS index support remains ARS-owned and must not become ES grammar"},
		{path: "execution-substrate/ars/store", reason: "ARS storage support remains ARS-owned and must not become ES grammar"},
		{path: "execution-substrate/ars/descriptor", reason: "ARS descriptor support remains ARS-owned and must not become ES grammar"},
		{path: "execution-substrate/ars/manifest", reason: "ARS manifest support remains ARS-owned and must not become ES grammar"},
		{path: "execution-substrate/ars/support", reason: "ARS support packages remain ARS-owned and must not become ES grammar"},
		{path: "execution-substrate/ags/", reason: "AGS publication packages remain AGS-owned and must not become ES grammar"},
	}

	for _, file := range workstreamAESBoundaryNonTestGoFiles(t) {
		data, err := os.ReadFile(file)
		if err != nil {
			t.Fatalf("read %s: %v", file, err)
		}
		parsed, err := parser.ParseFile(token.NewFileSet(), file, data, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("parse imports in %s: %v", file, err)
		}
		for _, imported := range parsed.Imports {
			importPath, err := strconv.Unquote(imported.Path.Value)
			if err != nil {
				t.Fatalf("unquote import in %s: %v", file, err)
			}
			for _, forbidden := range blocked {
				if blockedWorkstreamAImportMatches(importPath, forbidden.path) {
					t.Fatalf("%s imports %q: %s", file, importPath, forbidden.reason)
				}
			}
		}
	}
}

func TestWorkstreamAESImplementationExcludesControlPlaneGrammar(t *testing.T) {
	assertNoForbiddenWorkstreamASourceTerms(t, workstreamAESBoundaryNonTestGoFiles(t), []workstreamASourceTerm{
		{name: "CP attempt manifest grammar", identifiers: []string{"AttemptManifest"}, stringSpellings: []string{"attempt_manifest", "attempt-manifest"}},
		{name: "CP review grammar", identifiers: []string{"Review"}, stringSpellings: []string{"review"}},
		{name: "CP checkpoint grammar", identifiers: []string{"Checkpoint"}, stringSpellings: []string{"checkpoint"}},
		{name: "CP finalization grammar", identifiers: []string{"Finalization"}, stringSpellings: []string{"finalization"}},
		{name: "CP approval grammar", identifiers: []string{"Approval"}, stringSpellings: []string{"approval"}},
		{name: "CP hold grammar", identifiers: []string{"Hold"}, stringSpellings: []string{"hold"}},
		{name: "CP resume grammar", identifiers: []string{"Resume"}, stringSpellings: []string{"resume"}},
		{name: "CP reject grammar", identifiers: []string{"Reject"}, stringSpellings: []string{"reject"}},
		{name: "CP Temporal grammar", identifiers: []string{"Temporal"}, stringSpellings: []string{"Temporal"}},
		{name: "CP workflow grammar", identifiers: []string{"Workflow"}, stringSpellings: []string{"workflow"}},
	}, nil)
}

func TestWorkstreamAControlPlaneNormalShellCompatibilitySurfaceUnchanged(t *testing.T) {
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
		t.Fatalf("expected existing control-plane normal-shell profile to resolve, got %+v", err)
	}
	if profile.name != runtimeProfileControlPlaneNormalShell {
		t.Fatalf("expected profile %q, got %+v", runtimeProfileControlPlaneNormalShell, profile)
	}
}

func signedWorkstreamAEvidence(t *testing.T, fixture preparedArtifactFixture, mutate func(*evidencev1.ArtifactEvidence)) evidencev1.ArtifactEvidence {
	t.Helper()

	record := fixture.evidence
	mutate(&record)
	record.Seal = evidencev1.Seal{}
	canonical, err := record.CanonicalBytes()
	if err != nil {
		t.Fatalf("canonicalize mutated evidence: %v", err)
	}
	record.Seal = evidencev1.NewSeal(canonical, fixture.keyID, "ed25519", base64.StdEncoding.EncodeToString(ed25519.Sign(fixture.privateKey, canonical)))
	return record
}

func discoveredArtifactWithEvidence(t *testing.T, discovery arsapi.ArtifactDiscovery, evidence evidencev1.ArtifactEvidence) discoveredArtifact {
	t.Helper()

	evidenceBytes, err := json.Marshal(evidence)
	if err != nil {
		t.Fatalf("marshal evidence: %v", err)
	}
	discovery.Evidence.Digest = digestBytes(evidenceBytes)
	return discoveredArtifact{
		discovery: discovery,
		evidence:  evidence,
	}
}

func collectJSONFieldNames(t *testing.T, values ...any) map[string]struct{} {
	t.Helper()

	names := map[string]struct{}{}
	seen := map[reflect.Type]bool{}
	for _, value := range values {
		collectJSONFieldNamesFromType(reflect.TypeOf(value), names, seen)
	}
	return names
}

func collectJSONFieldNamesFromType(typ reflect.Type, names map[string]struct{}, seen map[reflect.Type]bool) {
	for typ.Kind() == reflect.Pointer || typ.Kind() == reflect.Slice || typ.Kind() == reflect.Array {
		typ = typ.Elem()
	}
	if typ.Kind() != reflect.Struct || seen[typ] {
		return
	}
	seen[typ] = true

	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)
		if field.PkgPath != "" {
			continue
		}
		tagName := strings.Split(field.Tag.Get("json"), ",")[0]
		if tagName != "" && tagName != "-" {
			names[tagName] = struct{}{}
		}
		collectJSONFieldNamesFromType(field.Type, names, seen)
	}
}

func nonTestGoFiles(t *testing.T, root string) []string {
	t.Helper()

	matches, err := filepath.Glob(filepath.Join(root, "*.go"))
	if err != nil {
		t.Fatalf("glob go files: %v", err)
	}
	files := make([]string, 0, len(matches))
	for _, match := range matches {
		if strings.HasSuffix(match, "_test.go") {
			continue
		}
		files = append(files, match)
	}
	return files
}

func workstreamAESBoundaryNonTestGoFiles(t *testing.T) []string {
	t.Helper()

	files := []string{}
	for _, root := range []string{".", "../api", "../app"} {
		files = append(files, nonTestGoFiles(t, root)...)
	}
	sort.Strings(files)
	return files
}

type workstreamASourceTerm struct {
	name            string
	identifiers     []string
	stringSpellings []string
}

type workstreamASourceOccurrence struct {
	file     string
	line     int
	term     workstreamASourceTerm
	spelling string
	source   string
	// node is the identifier or string literal that holds the spelling, and
	// syntax the parsed file around it. An allow rule judges these, never
	// the text of the line, which a comment can fill with anything.
	node   ast.Node
	syntax *ast.File
}

type workstreamABlockedImport struct {
	path   string
	reason string
}

func assertNoForbiddenWorkstreamASourceTerms(t *testing.T, files []string, terms []workstreamASourceTerm, allow func(workstreamASourceOccurrence) bool) {
	t.Helper()

	for _, file := range files {
		for _, occurrence := range forbiddenWorkstreamASourceOccurrences(t, file, terms) {
			if allow != nil && allow(occurrence) {
				continue
			}
			t.Fatalf("%s:%d must not contain %q as %s: %s", occurrence.file, occurrence.line, occurrence.spelling, occurrence.term.name, occurrence.source)
		}
	}
}

func forbiddenWorkstreamASourceOccurrences(t *testing.T, file string, terms []workstreamASourceTerm) []workstreamASourceOccurrence {
	t.Helper()

	data, err := os.ReadFile(file)
	if err != nil {
		t.Fatalf("read %s: %v", file, err)
	}
	return workstreamASourceOccurrencesOf(t, file, data, terms)
}

// workstreamASourceOccurrencesOf lists the occurrences of the terms in the
// identifiers and string literals of one Go source, read as the file named
// file.
func workstreamASourceOccurrencesOf(t *testing.T, file string, data []byte, terms []workstreamASourceTerm) []workstreamASourceOccurrence {
	t.Helper()

	fileSet := token.NewFileSet()
	parsed, err := parser.ParseFile(fileSet, file, data, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", file, err)
	}
	lines := strings.Split(string(data), "\n")
	occurrences := []workstreamASourceOccurrence{}

	ast.Inspect(parsed, func(node ast.Node) bool {
		switch n := node.(type) {
		case *ast.Ident:
			for _, term := range terms {
				for _, spelling := range term.identifiers {
					if strings.Contains(n.Name, spelling) {
						occurrences = append(occurrences, workstreamASourceOccurrence{
							file:     file,
							line:     fileSet.Position(n.Pos()).Line,
							term:     term,
							spelling: spelling,
							source:   workstreamASourceLine(lines, fileSet.Position(n.Pos()).Line),
							node:     n,
							syntax:   parsed,
						})
					}
				}
			}
		case *ast.BasicLit:
			if n.Kind != token.STRING {
				return true
			}
			value, err := strconv.Unquote(n.Value)
			if err != nil {
				value = n.Value
			}
			for _, term := range terms {
				for _, spelling := range term.stringSpellings {
					if strings.Contains(value, spelling) {
						occurrences = append(occurrences, workstreamASourceOccurrence{
							file:     file,
							line:     fileSet.Position(n.Pos()).Line,
							term:     term,
							spelling: spelling,
							source:   workstreamASourceLine(lines, fileSet.Position(n.Pos()).Line),
							node:     n,
							syntax:   parsed,
						})
					}
				}
			}
		}
		return true
	})
	return occurrences
}

func workstreamASourceLine(lines []string, line int) string {
	if line <= 0 || line > len(lines) {
		return ""
	}
	return strings.TrimSpace(lines[line-1])
}

// workstreamAAdmissionPolicyDecisionNames are the identifiers of es/admission's
// policy.go that hold PolicyDecision: ES Admission Policy Layer v0 owns
// AdmissionPolicyDecision as a local policy seam type and its two
// constructors. This is not AGS claims.package.publication PolicyDecision
// grammar.
var workstreamAAdmissionPolicyDecisionNames = map[string]bool{
	"AdmissionPolicyDecision":      true,
	"AllowAdmissionPolicyDecision": true,
	"DenyAdmissionPolicyDecision":  true,
}

// allowedWorkstreamAPublicationOccurrence allows an occurrence by the code
// that holds it, never by the text of its line: a comment on the same line
// allows nothing.
func allowedWorkstreamAPublicationOccurrence(occurrence workstreamASourceOccurrence) bool {
	switch occurrence.spelling {
	case "PolicyDecision":
		identifier, ok := occurrence.node.(*ast.Ident)
		return ok && occurrence.file == "policy.go" && workstreamAAdmissionPolicyDecisionNames[identifier.Name]
	case "Publication", "publication":
		// EGS publishes unsigned runtime-trust publication metadata beside the
		// signed runtime-trust payload. ES ignores that dependency metadata;
		// this is not AGS claims.package.publication or an ES public
		// admission/API/app field. Only the name and the tag of that one field
		// are allowed.
		field := workstreamAIgnoredRuntimeTrustPublicationField(occurrence.syntax)
		return occurrence.file == "service.go" && field != nil &&
			(occurrence.node == field.Names[0] || occurrence.node == field.Tag)
	}
	return false
}

// workstreamAIgnoredRuntimeTrustPublicationField finds the field
// Publication json.RawMessage `json:"publication,omitempty"` of the struct
// type signedRuntimeTrustResponse, or returns nil.
func workstreamAIgnoredRuntimeTrustPublicationField(syntax *ast.File) *ast.Field {
	if syntax == nil {
		return nil
	}
	for _, declaration := range syntax.Decls {
		general, ok := declaration.(*ast.GenDecl)
		if !ok || general.Tok != token.TYPE {
			continue
		}
		for _, spec := range general.Specs {
			typeSpec, ok := spec.(*ast.TypeSpec)
			if !ok || typeSpec.Name.Name != "signedRuntimeTrustResponse" {
				continue
			}
			structType, ok := typeSpec.Type.(*ast.StructType)
			if !ok {
				return nil
			}
			for _, field := range structType.Fields.List {
				if len(field.Names) != 1 || field.Names[0].Name != "Publication" || field.Tag == nil || field.Tag.Value != "`json:\"publication,omitempty\"`" {
					continue
				}
				selector, ok := field.Type.(*ast.SelectorExpr)
				if !ok {
					continue
				}
				if pkg, ok := selector.X.(*ast.Ident); ok && pkg.Name == "json" && selector.Sel.Name == "RawMessage" {
					return field
				}
			}
		}
	}
	return nil
}

func blockedWorkstreamAImportMatches(importPath string, blockedPath string) bool {
	if strings.HasSuffix(blockedPath, "/") {
		return importPath == strings.TrimSuffix(blockedPath, "/") || strings.HasPrefix(importPath, blockedPath)
	}
	return importPath == blockedPath || strings.HasPrefix(importPath, blockedPath+"/")
}
