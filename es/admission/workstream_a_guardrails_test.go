package admission

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
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

func allowedWorkstreamAPublicationOccurrence(occurrence workstreamASourceOccurrence) bool {
	if occurrence.spelling != "Publication" && occurrence.spelling != "publication" {
		return false
	}
	// EGS publishes unsigned runtime-trust publication metadata beside the
	// signed runtime-trust payload. ES ignores that dependency metadata; this is
	// not AGS claims.package.publication or an ES public admission/API/app field.
	return filepath.Base(occurrence.file) == "service.go" &&
		strings.Contains(occurrence.source, "Publication") &&
		strings.Contains(occurrence.source, "json.RawMessage") &&
		strings.Contains(occurrence.source, `json:"publication,omitempty"`)
}

func blockedWorkstreamAImportMatches(importPath string, blockedPath string) bool {
	if strings.HasSuffix(blockedPath, "/") {
		return importPath == strings.TrimSuffix(blockedPath, "/") || strings.HasPrefix(importPath, blockedPath)
	}
	return importPath == blockedPath || strings.HasPrefix(importPath, blockedPath+"/")
}
