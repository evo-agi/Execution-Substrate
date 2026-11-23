package admission

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"
	"unicode"

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

type zzJSONTrust struct {
	Publication json.RawMessage `json:"publication,omitempty"`
	KeyID       string          `json:"key_id"`
}

type zzJSONCheckpoint struct {
	Checkpoint string `json:"checkpoint"`
}

type ZzJSONResume string

type zzJSONName string

// The DTO guards above judge the object keys that collectJSONFieldNames
// records. It must record every key encoding/json writes, and a key that
// decoding matches to a guarded name must be found by that name: an embedded
// unexported struct, an untagged field or a key in another case would
// otherwise put a guarded name into a public DTO with every guard passing.
func TestWorkstreamAJSONFieldNamesFollowEncodingJSON(t *testing.T) {
	trust := zzJSONTrust{Publication: json.RawMessage("true"), KeyID: "k"}
	for _, test := range []struct {
		name  string
		value any
		want  []string
	}{
		{"an embedded unexported struct promotes its fields", struct {
			ID string `json:"id"`
			zzJSONTrust
		}{"i", trust}, []string{"id", "key_id", "publication"}},
		{"an embedded pointer to an unexported struct promotes its fields", struct {
			*zzJSONTrust
		}{&trust}, []string{"key_id", "publication"}},
		{"an embedded struct with a tag name is nested under it", struct {
			zzJSONTrust `json:"trust"`
		}{trust}, []string{"key_id", "publication", "trust"}},
		{"an untagged field is keyed by its Go name", struct {
			Review bool
		}{true}, []string{"Review", "review"}},
		{"a key in another case", struct {
			Hold bool `json:"HOLD"`
		}{true}, []string{"HOLD", "hold"}},
		{"a key with a rune whose case folds to ASCII", struct {
			Decisions int `json:"policy_deciſions"`
		}{1}, []string{"policy_deciſions", "policy_decisions"}},
		{"an invalid tag name leaves the Go name", struct {
			Approval bool `json:"appro'val"`
		}{true}, []string{"Approval", "approval"}},
		{"an embedded exported non-struct is keyed by its type name", struct {
			ZzJSONResume
		}{"r"}, []string{"ZzJSONResume", "zzjsonresume"}},
		{"a map value's fields", struct {
			Extra map[string]zzJSONCheckpoint `json:"extra"`
		}{map[string]zzJSONCheckpoint{}}, []string{"checkpoint", "extra"}},
		{"a field tagged - has no key", struct {
			Reject bool `json:"-"`
		}{true}, nil},
		{"a field tagged -, is keyed -", struct {
			Dash int `json:"-,"`
		}{1}, []string{"-"}},
		{"an unexported field and an embedded unexported non-struct have no key", struct {
			review bool
			zzJSONName
		}{true, "n"}, nil},
	} {
		t.Run(test.name, func(t *testing.T) {
			names := collectJSONFieldNames(t, test.value)
			got := slices.Sorted(maps.Keys(names))
			want := slices.Sorted(slices.Values(test.want))
			if !slices.Equal(got, want) {
				t.Fatalf("recorded keys %q, want %q", got, want)
			}
			// encoding/json itself: every key it writes is recorded.
			encoded, err := json.Marshal(test.value)
			if err != nil {
				t.Fatal(err)
			}
			var object map[string]any
			if err := json.Unmarshal(encoded, &object); err != nil {
				t.Fatal(err)
			}
			for _, key := range zzJSONObjectKeys(object) {
				if _, ok := names[key]; !ok {
					t.Fatalf("encoding/json writes key %q in %s, which was not recorded", key, encoded)
				}
			}
		})
	}

	// encoding/json itself: decoding matches a guarded name to these keys.
	var untagged struct{ Review bool }
	var folded struct {
		Decisions int `json:"policy_deciſions"`
	}
	if err := json.Unmarshal([]byte(`{"review":true}`), &untagged); err != nil || !untagged.Review {
		t.Fatalf("decoding no longer matches \"review\" to the untagged field Review: %v", err)
	}
	if err := json.Unmarshal([]byte(`{"policy_decisions":1}`), &folded); err != nil || folded.Decisions != 1 {
		t.Fatalf("decoding no longer matches \"policy_decisions\" to the folded key: %v", err)
	}
}

// zzJSONObjectKeys lists the object keys of a decoded JSON value, nested
// objects included.
func zzJSONObjectKeys(value any) []string {
	var keys []string
	switch value := value.(type) {
	case map[string]any:
		for key, nested := range value {
			keys = append(keys, key)
			keys = append(keys, zzJSONObjectKeys(nested)...)
		}
	case []any:
		for _, nested := range value {
			keys = append(keys, zzJSONObjectKeys(nested)...)
		}
	}
	return keys
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
		"the seam type under a line directive that names policy.go": {"service.go",
			"package admission\n\n//line policy.go:4\ntype AdmissionPolicyDecision struct{ Allowed bool }\n", "4:PolicyDecision"},
		"a local that shadows the seam type": {"policy.go", policy +
			"\nfunc zz() int { AdmissionPolicyDecision := 1; return AdmissionPolicyDecision }\n", "9:PolicyDecision"},
		"a parameter named like a constructor": {"policy.go", policy +
			"\nfunc zz(AllowAdmissionPolicyDecision int) int { return AllowAdmissionPolicyDecision }\n", "9:PolicyDecision"},
		"a field named like the seam type": {"policy.go", policy +
			"\ntype ZzView struct{ AdmissionPolicyDecision string }\n", "9:PolicyDecision"},
		"a method named like a constructor": {"policy.go", policy +
			"\ntype zzOther struct{}\n\nfunc (zzOther) DenyAdmissionPolicyDecision() {}\n", "11:PolicyDecision"},
		"a label named like the seam type": {"policy.go", policy +
			"\nfunc zz() {\nAdmissionPolicyDecision:\n\tfor {\n\t\tbreak AdmissionPolicyDecision\n\t}\n}\n", "10:PolicyDecision"},
		"a package variable named like a constructor": {"policy.go",
			"package admission\n\nvar AllowAdmissionPolicyDecision = 1\n", "3:PolicyDecision"},
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
		"the field under a line directive that names service.go": {"zz.go",
			"//line service.go:2\n" + service, "8:Publication"},
		"another forbidden identifier in policy.go": {"policy.go", policy +
			"\nvar zzPublishedAt = 1\n", "9:Published"},
		"another forbidden string in service.go": {"service.go", service +
			"\nconst zzDecisions = \"policy_decisions\"\n", "10:policy_decisions"},
		"a second name on the field": {"service.go",
			strings.Replace(service, "Publication json.RawMessage", "Publication, Zz json.RawMessage", 1), "7:Publication"},
		"the field in a function-local struct of that name": {"service.go",
			"package admission\n\nimport \"encoding/json\"\n\nfunc zz() any {\n\ttype signedRuntimeTrustResponse struct {\n" +
				"\t\tPublication json.RawMessage `json:\"publication,omitempty\"`\n\t}\n\treturn signedRuntimeTrustResponse{}\n}\n", "7:Publication"},
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

// collectJSONFieldNamesFromType records every object key that encoding/json
// writes or reads for typ, and for the struct types its fields, elements and
// map values hold. Each key is recorded as written and in the folded form in
// which decoding matches it (workstreamAJSONKeyFold), so a guard's lower-case
// name finds a key that differs from it only in case.
func collectJSONFieldNamesFromType(typ reflect.Type, names map[string]struct{}, seen map[reflect.Type]bool) {
	for typ.Kind() == reflect.Pointer || typ.Kind() == reflect.Slice || typ.Kind() == reflect.Array || typ.Kind() == reflect.Map {
		typ = typ.Elem()
	}
	if typ.Kind() != reflect.Struct || seen[typ] {
		return
	}
	seen[typ] = true

	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)
		key, promoted, encoded := workstreamAJSONFieldKey(field)
		if !encoded {
			continue
		}
		if !promoted {
			names[key] = struct{}{}
			names[workstreamAJSONKeyFold(key)] = struct{}{}
		}
		collectJSONFieldNamesFromType(field.Type, names, seen)
	}
}

// workstreamAJSONFieldKey applies encoding/json's rules (typeFields) to one
// struct field. A field tagged "-" is not encoded, and neither is an
// unexported field, unless it embeds a struct. An embedded struct, or a
// pointer to one, without a valid tag name has no key of its own: its fields
// are promoted, even when its type is unexported. Any other field's key is
// its valid tag name, or else its Go name.
func workstreamAJSONFieldKey(field reflect.StructField) (key string, promoted bool, encoded bool) {
	embedded := field.Type
	if embedded.Kind() == reflect.Pointer {
		embedded = embedded.Elem()
	}
	if field.Anonymous {
		if !field.IsExported() && embedded.Kind() != reflect.Struct {
			return "", false, false
		}
	} else if !field.IsExported() {
		return "", false, false
	}
	tag := field.Tag.Get("json")
	if tag == "-" {
		return "", false, false
	}
	name, _, _ := strings.Cut(tag, ",")
	if !workstreamAValidJSONTagName(name) {
		name = ""
	}
	if name == "" && field.Anonymous && embedded.Kind() == reflect.Struct {
		return "", true, true
	}
	if name == "" {
		name = field.Name
	}
	return name, false, true
}

// workstreamAValidJSONTagName is encoding/json's isValidTag. A field whose tag
// name fails it keeps its Go name as its key.
func workstreamAValidJSONTagName(name string) bool {
	if name == "" {
		return false
	}
	for _, c := range name {
		switch {
		case strings.ContainsRune("!#$%&()*+-./:;<=>?@[]^_{|}~ ", c):
		case !unicode.IsLetter(c) && !unicode.IsDigit(c):
			return false
		}
	}
	return true
}

// workstreamAJSONKeyFold is the form in which decoding compares an object key
// with a field's key: encoding/json matches keys without regard to case, as
// bytes.EqualFold does, so each rune stands for its whole case-folding orbit.
// The orbit is written as the lower case of its smallest rune, so "Review",
// "REVIEW" and "review" all fold to "review", and "policy_decisions" spelled
// with the long s U+017F folds to "policy_decisions".
func workstreamAJSONKeyFold(key string) string {
	return strings.Map(func(r rune) rune {
		smallest := r
		for next := unicode.SimpleFold(r); next != r; next = unicode.SimpleFold(next) {
			smallest = min(smallest, next)
		}
		return unicode.ToLower(smallest)
	}, key)
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

// workstreamAAdmissionPolicyDecisionObjects are the objects of es/admission's
// policy.go that hold PolicyDecision, with their kinds: ES Admission Policy
// Layer v0 owns AdmissionPolicyDecision as a local policy seam type and its
// two constructors. This is not AGS claims.package.publication PolicyDecision
// grammar.
var workstreamAAdmissionPolicyDecisionObjects = map[string]ast.ObjKind{
	"AdmissionPolicyDecision":      ast.Typ,
	"AllowAdmissionPolicyDecision": ast.Fun,
	"DenyAdmissionPolicyDecision":  ast.Fun,
}

// allowedWorkstreamAPublicationOccurrence allows an occurrence by the code
// that holds it, never by the text of its line: a comment on the same line
// allows nothing.
func allowedWorkstreamAPublicationOccurrence(occurrence workstreamASourceOccurrence) bool {
	switch occurrence.spelling {
	case "PolicyDecision":
		// Only the top-level declarations of the seam type and its
		// constructors in policy.go, and the identifiers the parser resolves
		// to them. A local, a parameter, a field, a method or a label with the
		// same name is another object.
		identifier, ok := occurrence.node.(*ast.Ident)
		if !ok || occurrence.file != "policy.go" || occurrence.syntax == nil || occurrence.syntax.Scope == nil {
			return false
		}
		kind, named := workstreamAAdmissionPolicyDecisionObjects[identifier.Name]
		object := occurrence.syntax.Scope.Lookup(identifier.Name)
		return named && object != nil && object.Kind == kind && identifier.Obj == object
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
