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

	arscontract "execution-substrate/ars/contract"
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

	// Every publication claim but the publisher principal leaves the
	// prepared artifact as it was.
	variedPublication := signedWorkstreamAEvidence(t, fixture, func(record *evidencev1.ArtifactEvidence) {
		record.Claims.Package.Publication = evidencev1.Publication{
			BuilderService: "alternate-ags-builder",
			Invoker: evidencev1.Invoker{
				Service:   "service/other-publisher",
				Principal: record.Claims.Package.Publication.Invoker.Principal,
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

	// The publisher principal is the one publication claim ES reads, as a
	// workload grant match fact (.docs/execution_lifecycle/contracts.md,
	// section 5B). It reaches that grant fact and nothing else.
	const otherPublisher = "spiffe://execution.internal/service/other-publisher"
	variedPublisher := signedWorkstreamAEvidence(t, fixture, func(record *evidencev1.ArtifactEvidence) {
		record.Claims.Package.Publication.Invoker.Principal = otherPublisher
	})
	preparedWithVariedPublisher, err := service.prepareArtifactFromDiscovery(request, fixture.trustModel, discoveredArtifactWithEvidence(t, fixture.discovery, variedPublisher))
	if err != nil {
		t.Fatalf("expected a validly signed publisher variation to prepare, got %+v", err)
	}
	if preparedWithVariedPublisher.grantFacts.publisherPrincipal != otherPublisher ||
		baseline.grantFacts.publisherPrincipal != fixture.evidence.Claims.Package.Publication.Invoker.Principal {
		t.Fatalf("publisher principal grant facts = %q and %q, want the signed principals", preparedWithVariedPublisher.grantFacts.publisherPrincipal, baseline.grantFacts.publisherPrincipal)
	}
	preparedWithVariedPublisher.grantFacts.publisherPrincipal = baseline.grantFacts.publisherPrincipal
	if !reflect.DeepEqual(preparedWithVariedPublisher, baseline) {
		t.Fatalf("expected the publisher principal to alter only the grant fact\nbaseline=%+v\nvaried=%+v", baseline, preparedWithVariedPublisher)
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
		// Workload grants read the publisher principal only to match a
		// grant (.docs/execution_lifecycle/contracts.md, section 5B).
		"publisher",
		"publisher_principal",
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
		if fieldNames.accepts(forbidden) {
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
			recorded := collectJSONFieldNames(t, test.value)
			got := slices.Sorted(maps.Keys(recorded.keys))
			want := slices.Sorted(slices.Values(test.want))
			if !slices.Equal(got, want) {
				t.Fatalf("recorded keys %q, want %q", got, want)
			}
			// encoding/json itself: every key it writes is recorded, and
			// accepted in any case.
			encoded, err := json.Marshal(test.value)
			if err != nil {
				t.Fatal(err)
			}
			var object map[string]any
			if err := json.Unmarshal(encoded, &object); err != nil {
				t.Fatal(err)
			}
			for _, key := range zzJSONObjectKeys(object) {
				if _, ok := recorded.keys[key]; !ok {
					t.Fatalf("encoding/json writes key %q in %s, which was not recorded", key, encoded)
				}
				if !recorded.accepts(key) || !recorded.accepts(strings.ToUpper(key)) {
					t.Fatalf("encoding/json writes key %q in %s, which is not accepted in every case", key, encoded)
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

	// A key that decoding does not match is not accepted: the dotless ı does
	// not fold to i.
	var dotless struct {
		Publication int `json:"publıcation"`
	}
	if err := json.Unmarshal([]byte(`{"publication":1}`), &dotless); err != nil || dotless.Publication != 0 {
		t.Fatalf("decoding now matches \"publication\" to a key with the dotless ı: %v", err)
	}
	if collectJSONFieldNames(t, dotless).accepts("publication") {
		t.Fatal(`a key with the dotless ı is accepted as "publication"`)
	}
}

type zzJSONOwnWriter struct {
	Hidden string `json:"hidden"`
}

func (zzJSONOwnWriter) MarshalJSON() ([]byte, error) {
	return []byte(`{"written":{"by":"code"}}`), nil
}

type zzJSONOwnReader struct {
	Seen string `json:"seen"`
}

func (*zzJSONOwnReader) UnmarshalJSON([]byte) error {
	return nil
}

type zzJSONEmbedsOwnWriter struct {
	zzJSONOwnWriter
}

type zzJSONOwnText struct {
	Inner string `json:"inner"`
}

func (zzJSONOwnText) MarshalText() ([]byte, error) {
	return []byte("text"), nil
}

func (*zzJSONOwnText) UnmarshalText([]byte) error {
	return nil
}

type zzJSONOwnPointerText struct {
	Inner string `json:"inner"`
}

func (*zzJSONOwnPointerText) MarshalText() ([]byte, error) {
	return []byte("text"), nil
}

type zzJSONOwnPointerWriter struct {
	Hidden string `json:"hidden"`
}

func (*zzJSONOwnPointerWriter) MarshalJSON() ([]byte, error) {
	return []byte(`{"written":{"by":"code"}}`), nil
}

type zzJSONOwnMap map[string]string

func (zzJSONOwnMap) MarshalJSON() ([]byte, error) {
	return []byte(`{"written":{"by":"code"}}`), nil
}

type zzJSONOwnBytes []byte

func (zzJSONOwnBytes) MarshalJSON() ([]byte, error) {
	return []byte(`{"written":{"by":"code"}}`), nil
}

type zzJSONOwnString string

func (zzJSONOwnString) MarshalJSON() ([]byte, error) {
	return []byte(`{"written":{"by":"code"}}`), nil
}

// zzJSONGuardRecorder stands in for the testing.T of a guard helper, so that a
// test can see what the helper reports.
type zzJSONGuardRecorder struct {
	testing.TB
	errors []string
	fatal  string
}

func (recorder *zzJSONGuardRecorder) Helper() {}

func (recorder *zzJSONGuardRecorder) Errorf(format string, args ...any) {
	recorder.errors = append(recorder.errors, fmt.Sprintf(format, args...))
}

func (recorder *zzJSONGuardRecorder) Fatalf(format string, args ...any) {
	recorder.fatal = fmt.Sprintf(format, args...)
	panic(recorder)
}

// zzJSONGuardReports runs check with a recorder and returns what check
// reported. A Fatalf ends check, as it would end a test.
func zzJSONGuardReports(t *testing.T, check func(testing.TB)) *zzJSONGuardRecorder {
	recorder := &zzJSONGuardRecorder{TB: t}
	func() {
		defer func() {
			if recovered := recover(); recovered != nil && recovered != any(recorder) {
				panic(recovered)
			}
		}()
		check(recorder)
	}()
	return recorder
}

// A type with its own MarshalJSON or UnmarshalJSON writes and reads whatever
// keys its code chooses, so the DTO guards refuse it rather than read fields
// that encoding/json does not use for it.
func TestWorkstreamAJSONFieldNamesRefuseOwnCodecs(t *testing.T) {
	for _, test := range []struct {
		name  string
		value any
		want  []string
	}{
		{"a field with its own MarshalJSON", struct{ Own zzJSONOwnWriter }{}, []string{"admission.zzJSONOwnWriter"}},
		{"a field whose pointer has its own UnmarshalJSON", struct{ Own *zzJSONOwnReader }{}, []string{"*admission.zzJSONOwnReader"}},
		{"in a slice and in a map", struct {
			List []zzJSONOwnWriter
			Map  map[string]zzJSONOwnReader
		}{}, []string{"admission.zzJSONOwnReader", "admission.zzJSONOwnWriter"}},
		{"promoted from an embedded type", zzJSONEmbedsOwnWriter{}, []string{"admission.zzJSONEmbedsOwnWriter"}},
		{"a named map type with its own MarshalJSON", struct {
			Labels zzJSONOwnMap `json:"labels"`
		}{}, []string{"admission.zzJSONOwnMap"}},
		{"a named []byte type with its own MarshalJSON", struct {
			Blob zzJSONOwnBytes `json:"blob"`
		}{}, []string{"admission.zzJSONOwnBytes"}},
		{"a named string type with its own MarshalJSON", struct {
			Name zzJSONOwnString `json:"name"`
		}{}, []string{"admission.zzJSONOwnString"}},
		{"a json.RawMessage carries data and has no keys of its own", struct {
			Raw json.RawMessage `json:"raw"`
		}{}, nil},
		// encoding/json writes a string for a type with its own MarshalText,
		// and refuses to decode an object into one with its own
		// UnmarshalText, so text methods can only take keys away.
		{"text methods write and read a string, never keys", struct {
			Text zzJSONOwnText `json:"text"`
		}{}, nil},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, custom := workstreamAJSONDecodableKeysOf(test.value)
			if !slices.Equal(custom, test.want) {
				t.Fatalf("types with their own codec %q, want %q", custom, test.want)
			}
		})
	}

	// collectJSONFieldNames, which every DTO guard calls, fails on them, and
	// only on them.
	refused := zzJSONGuardReports(t, func(t testing.TB) {
		collectJSONFieldNames(t, PrepareRequest{}, struct{ Own zzJSONOwnWriter }{})
	})
	if !strings.Contains(refused.fatal, `["admission.zzJSONOwnWriter"]`) || len(refused.errors) > 0 {
		t.Fatalf("collectJSONFieldNames reported %q and %q for a DTO with its own MarshalJSON", refused.fatal, refused.errors)
	}
	accepted := zzJSONGuardReports(t, func(t testing.TB) {
		collectJSONFieldNames(t, PrepareRequest{}, struct {
			Text zzJSONOwnText `json:"text"`
		}{})
	})
	if accepted.fatal != "" || len(accepted.errors) > 0 {
		t.Fatalf("collectJSONFieldNames reported %q and %q for DTOs without their own JSON codec", accepted.fatal, accepted.errors)
	}
}

type ZzJSONClashA struct {
	Service string `json:"service"`
}

type ZzJSONClashB struct {
	Service string `json:"service"`
}

type ZzJSONTaggedService struct {
	Value zzJSONCheckpoint `json:"Service"`
}

type ZzJSONUntaggedService struct {
	Service string
}

// zzJSONStruct builds a struct at run time from fields. The name-clash cases
// use it because vet refuses a repeated json tag written in source, which is
// the very thing they test.
func zzJSONStruct(fields ...reflect.StructField) any {
	return reflect.New(reflect.StructOf(fields)).Elem().Interface()
}

func zzJSONEmbedded[T any]() reflect.StructField {
	typ := reflect.TypeFor[T]()
	return reflect.StructField{Name: typ.Name(), Type: typ, Anonymous: true}
}

type zzJSONOptional struct {
	Value string `json:"value,omitempty"`
}

type zzJSONMissing struct {
	Service string           `json:"SERVICE"`
	Outer   zzJSONCheckpoint `json:"outer"`
}

type zzJSONNode struct {
	Name     string
	Next     *zzJSONNode
	Children []zzJSONNode `json:"children,omitempty"`
}

// The presence guards require keys that ES writes, where it writes them. The
// paths they compare must be exactly what encoding/json writes for a value
// whose fields all hold something.
func TestWorkstreamAJSONKeyPathsAreWhatEncodingJSONWrites(t *testing.T) {
	for _, test := range []struct {
		name  string
		value any
		want  []string
	}{
		{"a tag name exactly as written", struct {
			Service string `json:"SERVICE"`
		}{}, []string{"SERVICE"}},
		{"an untagged field by its Go name", struct{ Review bool }{}, []string{"Review"}},
		{"empty fields are filled, so omitempty fields are written", struct {
			Name   string            `json:"name,omitempty"`
			Count  int               `json:"count,omitempty"`
			Flag   bool              `json:"flag,omitempty"`
			Ptr    *zzJSONCheckpoint `json:"ptr,omitempty"`
			Labels map[string]string `json:"labels,omitempty"`
		}{}, []string{"count", "flag", "labels", "labels.*", "name", "ptr", "ptr.checkpoint"}},
		{"nested objects, array elements and map entries", struct {
			Outer struct {
				Inner string `json:"inner"`
			} `json:"outer"`
			Items []zzJSONCheckpoint          `json:"items"`
			Extra map[string]zzJSONCheckpoint `json:"extra"`
		}{}, []string{"extra", "extra.*", "extra.*.checkpoint", "items", "items[].checkpoint", "outer", "outer.inner"}},
		{"a field tagged - is not written", struct {
			Kept   string `json:"kept"`
			Hidden string `json:"-"`
		}{}, []string{"kept"}},
		{"an embedded unexported struct's fields are promoted", struct{ zzJSONTrust }{}, []string{"key_id", "publication"}},
		{"two fields with one name at one depth are both dropped", zzJSONStruct(
			zzJSONEmbedded[ZzJSONClashA](),
			zzJSONEmbedded[ZzJSONClashB](),
			reflect.StructField{Name: "Kept", Type: reflect.TypeFor[string](), Tag: `json:"kept"`},
		), []string{"kept"}},
		{"a shallower field hides a deeper one", zzJSONStruct(
			zzJSONEmbedded[ZzJSONClashA](),
			reflect.StructField{Name: "Service", Type: reflect.TypeFor[zzJSONCheckpoint](), Tag: `json:"service"`},
		), []string{"service", "service.checkpoint"}},
		{"a tagged field wins over an untagged one of the same name", zzJSONStruct(
			zzJSONEmbedded[ZzJSONTaggedService](),
			zzJSONEmbedded[ZzJSONUntaggedService](),
		), []string{"Service", "Service.checkpoint"}},
		{"each of two fields of one type is filled", struct {
			First  zzJSONOptional  `json:"first"`
			Second *zzJSONOptional `json:"second,omitempty"`
		}{}, []string{"first", "first.value", "second", "second.value"}},
		{"a type that holds itself ends", zzJSONNode{}, []string{"Name", "Next", "children", "children[].Name", "children[].Next"}},
		{"a type's own MarshalJSON decides", struct {
			Own zzJSONOwnWriter `json:"own"`
		}{}, []string{"own", "own.written", "own.written.by"}},
		{"a json.RawMessage is written", struct {
			Raw json.RawMessage `json:"raw"`
		}{}, []string{"raw"}},
		{"a type's own MarshalText writes a string", struct {
			Text zzJSONOwnText `json:"text"`
		}{}, []string{"text"}},
		// A method with a pointer receiver is used only when the value is
		// written through a pointer, so only the keys written both ways count.
		{"a MarshalText with a pointer receiver", struct {
			Text zzJSONOwnPointerText `json:"text"`
		}{}, []string{"text"}},
		{"a MarshalJSON with a pointer receiver", struct {
			Own zzJSONOwnPointerWriter `json:"own"`
		}{}, []string{"own"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			got := slices.Sorted(maps.Keys(workstreamAJSONWrittenKeyPaths(t, test.value)))
			want := slices.Sorted(slices.Values(test.want))
			if !slices.Equal(got, want) {
				t.Fatalf("written key paths %q, want %q", got, want)
			}
		})
	}

	// A key that holds ".", "[", "]" or "*" would let one path name two
	// places: a top-level key "governed_execution.contract" would pass for the
	// key "contract" inside "governed_execution". The paths refuse it.
	for _, value := range []any{
		struct {
			Moved string `json:"governed_execution.contract"`
		}{},
		struct {
			Moved string `json:"runtime_profiles[].name"`
		}{},
		struct {
			Star string `json:"*"`
		}{},
	} {
		refused := zzJSONGuardReports(t, func(t testing.TB) { workstreamAJSONWrittenKeyPaths(t, value) })
		if !strings.Contains(refused.fatal, "cannot name unambiguously") {
			t.Fatalf("key paths were built from %T's keys: %q", value, refused.fatal)
		}
	}

	// Only the exact key at the exact place counts, and
	// assertJSONKeyPathsWritten, which the presence guards call, reports each
	// missing path and nothing else.
	missing := missingJSONKeyPaths(t, zzJSONMissing{}, "SERVICE", "service", "outer.checkpoint", "checkpoint", "outer")
	if want := []string{"service", "checkpoint"}; !slices.Equal(missing, want) {
		t.Fatalf("missing key paths %q, want %q", missing, want)
	}
	reported := zzJSONGuardReports(t, func(t testing.TB) {
		assertJSONKeyPathsWritten(t, zzJSONMissing{}, "field", "SERVICE", "service", "outer.checkpoint", "checkpoint", "outer")
	})
	want := []string{
		`expected field "service" to remain present in admission.zzJSONMissing's JSON`,
		`expected field "checkpoint" to remain present in admission.zzJSONMissing's JSON`,
	}
	if !slices.Equal(reported.errors, want) || reported.fatal != "" {
		t.Fatalf("assertJSONKeyPathsWritten reported %q and %q, want %q", reported.errors, reported.fatal, want)
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
	const grants = "package admission\n\nimport evidencev1 \"execution-substrate/internal/contracts/evidence/v1\"\n\n" +
		"type workloadGrantEvidenceFacts struct {\n\tpublisherPrincipal string\n\tsignerKeyID        string\n}\n\n" +
		"func workloadGrantEvidenceFactsFrom(evidence evidencev1.ArtifactEvidence) workloadGrantEvidenceFacts {\n" +
		"\treturn workloadGrantEvidenceFacts{\n\t\tpublisherPrincipal: evidence.Claims.Package.Publication.Invoker.Principal,\n" +
		"\t\tsignerKeyID:        evidence.Seal.KeyID,\n\t}\n}\n\n" +
		"func zzKey(f workloadGrantEvidenceFacts) string { return f.publisherPrincipal }\n"
	for name, test := range map[string]struct{ file, source string }{
		"the policy seam type and its constructors":   {"policy.go", policy},
		"the ignored runtime-trust publication field": {"service.go", service},
		"the workload grant publisher read":           {"workload_grants.go", grants},
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
		"the workload grant publisher read in another file":                            {"service.go", grants, "12:Publication"},
		"the workload grant publisher read in a workload_grants.go of another package": {"../app/workload_grants.go", grants, "12:Invoker"},
		"the workload grant publisher read in another function": {"workload_grants.go", strings.Replace(grants,
			"func workloadGrantEvidenceFactsFrom(", "func zzEvidenceFacts(", 1), "12:Publication"},
		"the workload grant publisher read as a method": {"workload_grants.go", strings.Replace(grants,
			"func workloadGrantEvidenceFactsFrom(", "func (workloadGrantEvidenceFacts) workloadGrantEvidenceFactsFrom(", 1), "12:Invoker"},
		"the workload grant read function with another parameter type": {"workload_grants.go", strings.Replace(grants,
			"(evidence evidencev1.ArtifactEvidence)", "(evidence evidencev1.Claims)", 1), "12:Publication"},
		"another publication claim in the read function": {"workload_grants.go", grants +
			"\nfunc zz(evidence evidencev1.ArtifactEvidence) string { return evidence.Claims.Package.Publication.Invoker.Service }\n", "19:Publication"},
		"the invoker service in the read function": {"workload_grants.go", strings.Replace(grants,
			"Publication.Invoker.Principal", "Publication.Invoker.Service", 1), "12:Invoker"},
		"the builder service in the read function": {"workload_grants.go", strings.Replace(grants,
			"evidence.Seal.KeyID", "evidence.Claims.Package.Publication.BuilderService", 1), "13:Publication"},
		"the read rooted at a value other than the parameter": {"workload_grants.go", strings.Replace(grants,
			"evidence.Claims.Package.Publication.Invoker.Principal", "zzOther.Claims.Package.Publication.Invoker.Principal", 1), "12:Publication"},
		"the read rooted at a closure local that shadows the parameter": {"workload_grants.go", strings.Replace(grants,
			"\treturn workloadGrantEvidenceFacts{\n",
			"\tfunc() { evidence := zzOther; _ = evidence.Claims.Package.Publication.Invoker.Principal }()\n\treturn workloadGrantEvidenceFacts{\n", 1), "11:Publication"},
		"the read rooted at a closure parameter of the same name and type": {"workload_grants.go", strings.Replace(grants,
			"\treturn workloadGrantEvidenceFacts{\n",
			"\t_ = func(evidence evidencev1.ArtifactEvidence) string { return evidence.Claims.Package.Publication.Invoker.Principal }(zzOther)\n\treturn workloadGrantEvidenceFacts{\n", 1), "11:Invoker"},
		"a publisher field in another struct": {"workload_grants.go", grants +
			"\ntype PrepareView struct {\n\tpublisherPrincipal string\n}\n", "20:publisher"},
		"a publisher field in a function-local struct of the facts type's name": {"workload_grants.go", grants +
			"\nfunc zz() any {\n\ttype workloadGrantEvidenceFacts struct{ publisherPrincipal string }\n\treturn nil\n}\n", "20:publisher"},
		"a local variable named like the publisher field": {"workload_grants.go", grants +
			"\nfunc zz() string { publisherPrincipal := \"\"; return publisherPrincipal }\n", "19:publisher"},
		"a key of that name in a literal of another type": {"workload_grants.go", grants +
			"\nvar zz = struct{ publisherPrincipal string }{publisherPrincipal: \"\"}\n", "19:publisher"},
		"another publisher identifier in workload_grants.go": {"workload_grants.go", grants +
			"\nvar zzPublisherName = 1\n", "19:Publisher"},
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

func discoveredArtifactWithEvidence(t *testing.T, discovery arscontract.ArtifactDiscovery, evidence evidencev1.ArtifactEvidence) discoveredArtifact {
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

// workstreamAJSONDecodableKeys holds the object keys that encoding/json writes
// or reads for the public DTOs a guard names, as collectJSONFieldNames records
// them. It answers one question, for the guards that keep a key out of the
// DTOs: may decoding take this key? A guard that requires a key to stay
// present asks assertJSONKeyPathsWritten instead, because decoding takes a key
// in any case and from any depth, while encoding/json writes it in one case at
// one place.
type workstreamAJSONDecodableKeys struct {
	keys map[string]struct{}
}

// accepts reports whether decoding into one of the DTOs may take key: some
// field's key is key, or differs from it only in case.
func (decodable workstreamAJSONDecodableKeys) accepts(key string) bool {
	_, ok := decodable.keys[workstreamAJSONKeyFold(key)]
	return ok
}

func collectJSONFieldNames(t testing.TB, values ...any) workstreamAJSONDecodableKeys {
	t.Helper()

	decodable, custom := workstreamAJSONDecodableKeysOf(values...)
	if len(custom) > 0 {
		t.Fatalf("public DTO types %q have their own MarshalJSON or UnmarshalJSON, so no guard can see which keys they write or read", custom)
	}
	return decodable
}

// workstreamAJSONDecodableKeysOf records the keys of values' types
// (collectJSONFieldNamesFromType), and names every type it reached that has
// its own MarshalJSON or UnmarshalJSON (workstreamAJSONCustomCodec).
func workstreamAJSONDecodableKeysOf(values ...any) (workstreamAJSONDecodableKeys, []string) {
	names := map[string]struct{}{}
	seen := map[reflect.Type]bool{}
	custom := map[reflect.Type]bool{}
	for _, value := range values {
		collectJSONFieldNamesFromType(reflect.TypeOf(value), names, seen, custom)
	}
	var customNames []string
	for typ := range custom {
		customNames = append(customNames, typ.String())
	}
	slices.Sort(customNames)
	return workstreamAJSONDecodableKeys{keys: names}, customNames
}

// collectJSONFieldNamesFromType records every object key that encoding/json
// writes or reads for typ, and for the struct types its fields, elements and
// map values hold. Each key is recorded as written and in the folded form in
// which decoding matches it (workstreamAJSONKeyFold), so a guard's lower-case
// name finds a key that differs from it only in case.
func collectJSONFieldNamesFromType(typ reflect.Type, names map[string]struct{}, seen, custom map[reflect.Type]bool) {
	for {
		if workstreamAJSONCustomCodec(typ) {
			custom[typ] = true
			return
		}
		if kind := typ.Kind(); kind != reflect.Pointer && kind != reflect.Slice && kind != reflect.Array && kind != reflect.Map {
			break
		}
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
		collectJSONFieldNamesFromType(field.Type, names, seen, custom)
	}
}

var (
	workstreamAJSONMarshaler   = reflect.TypeFor[json.Marshaler]()
	workstreamAJSONUnmarshaler = reflect.TypeFor[json.Unmarshaler]()
	workstreamAJSONRawMessage  = reflect.TypeFor[json.RawMessage]()
)

// workstreamAJSONCustomCodec reports whether typ, or a pointer to it, has its
// own MarshalJSON or UnmarshalJSON. encoding/json then writes and reads
// whatever keys that code chooses, which no reading of typ's fields can see.
// json.RawMessage is the one exception: it carries a JSON value through as
// data and has no keys of its own.
func workstreamAJSONCustomCodec(typ reflect.Type) bool {
	if typ == workstreamAJSONRawMessage {
		return false
	}
	pointer := reflect.PointerTo(typ)
	return typ.Implements(workstreamAJSONMarshaler) || pointer.Implements(workstreamAJSONMarshaler) ||
		typ.Implements(workstreamAJSONUnmarshaler) || pointer.Implements(workstreamAJSONUnmarshaler)
}

// assertJSONKeyPathsWritten fails, naming each missing path, unless
// encoding/json writes every one of paths for root's type
// (missingJSONKeyPaths).
func assertJSONKeyPathsWritten(t testing.TB, root any, what string, paths ...string) {
	t.Helper()

	for _, path := range missingJSONKeyPaths(t, root, paths...) {
		t.Errorf("expected %s %q to remain present in %T's JSON", what, path, root)
	}
}

// missingJSONKeyPaths returns the paths, of those given, that encoding/json
// does not write for root's type (workstreamAJSONWrittenKeyPaths). Only the
// exact key at the exact place counts: a key in another case, without its
// tag, moved into another object or dropped by a name clash is missing.
func missingJSONKeyPaths(t testing.TB, root any, paths ...string) []string {
	t.Helper()

	written := workstreamAJSONWrittenKeyPaths(t, root)
	var missing []string
	for _, path := range paths {
		if !written[path] {
			missing = append(missing, path)
		}
	}
	return missing
}

// workstreamAJSONWrittenKeyPaths returns every object-key path that
// encoding/json writes for a value of root's type whose fields all hold
// something (workstreamAFillJSONValue). json.Marshal itself decides the keys:
// tag names exactly as written, Go names for untagged fields, the fields of
// embedded structs promoted, a field tagged "-" left out, two fields that
// claim one name at one depth both dropped, a shallower or tagged field
// winning over the others, and a type's own MarshalJSON or MarshalText
// obeyed. A method with a pointer receiver is used only when the value is
// written through a pointer, so a path counts only if encoding/json writes it
// both through a pointer and from the value itself. A path joins the keys from
// the top with ".". "[]" after a key stands for the elements of the array it
// holds, and "*" for the one entry of a map. A key that holds ".", "[", "]"
// or "*" would let one path name two places, so it fails the test instead.
func workstreamAJSONWrittenKeyPaths(t testing.TB, root any) map[string]bool {
	t.Helper()

	value := reflect.New(reflect.TypeOf(root))
	workstreamAFillJSONValue(value.Elem(), map[reflect.Type]bool{})
	var both map[string]bool
	for _, written := range []any{value.Interface(), value.Elem().Interface()} {
		encoded, err := json.Marshal(written)
		if err != nil {
			t.Fatalf("encoding/json cannot write a filled %T: %v", written, err)
		}
		var decoded any
		if err := json.Unmarshal(encoded, &decoded); err != nil {
			t.Fatalf("encoding/json wrote %s for %T, which does not decode: %v", encoded, written, err)
		}
		paths, ambiguous := map[string]bool{}, map[string]bool{}
		workstreamAJSONObjectKeyPaths("", decoded, paths, ambiguous)
		if len(ambiguous) > 0 {
			t.Fatalf("encoding/json writes keys %q for %T, which a key path cannot name unambiguously", slices.Sorted(maps.Keys(ambiguous)), written)
		}
		if both == nil {
			both = paths
			continue
		}
		maps.DeleteFunc(both, func(path string, _ bool) bool { return !paths[path] })
	}
	return both
}

// workstreamAFillJSONValue puts something into value and into everything it
// holds, so that json.Marshal writes every key it would ever write for
// value's type: the string "x", the number 1, true, a pointer to a filled
// value, one filled element in a slice, filled elements in an array, one
// filled entry under the empty key in a map with string keys, null in a
// json.RawMessage, and every exported field of a struct and of the structs it
// embeds. A struct type that is already being filled is left empty where it
// recurs, and a pointer to it stays nil, so a type that holds itself ends. An
// interface value, a map with other keys and an embedded pointer to an
// unexported struct type (which reflection cannot set, and encoding/json
// cannot decode into) stay empty: no key beneath them is written, so none can
// be required.
func workstreamAFillJSONValue(value reflect.Value, filling map[reflect.Type]bool) {
	typ := value.Type()
	if typ == workstreamAJSONRawMessage {
		value.SetBytes([]byte("null"))
		return
	}
	switch typ.Kind() {
	case reflect.Pointer:
		if filling[typ.Elem()] {
			return
		}
		pointer := reflect.New(typ.Elem())
		workstreamAFillJSONValue(pointer.Elem(), filling)
		value.Set(pointer)
	case reflect.Struct:
		if filling[typ] {
			return
		}
		filling[typ] = true
		defer delete(filling, typ)
		for i := range typ.NumField() {
			field := value.Field(i)
			// An embedded struct of an unexported type cannot be set as a
			// whole, but its exported fields can, and encoding/json promotes
			// them.
			if field.CanSet() || (typ.Field(i).Anonymous && field.Kind() == reflect.Struct) {
				workstreamAFillJSONValue(field, filling)
			}
		}
	case reflect.Slice:
		slice := reflect.MakeSlice(typ, 1, 1)
		workstreamAFillJSONValue(slice.Index(0), filling)
		value.Set(slice)
	case reflect.Array:
		for i := range value.Len() {
			workstreamAFillJSONValue(value.Index(i), filling)
		}
	case reflect.Map:
		if typ.Key().Kind() != reflect.String {
			return
		}
		entry := reflect.New(typ.Elem()).Elem()
		workstreamAFillJSONValue(entry, filling)
		filled := reflect.MakeMapWithSize(typ, 1)
		filled.SetMapIndex(reflect.ValueOf("").Convert(typ.Key()), entry)
		value.Set(filled)
	case reflect.String:
		value.SetString("x")
	case reflect.Bool:
		value.SetBool(true)
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		value.SetInt(1)
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		value.SetUint(1)
	case reflect.Float32, reflect.Float64:
		value.SetFloat(1)
	}
}

// workstreamAJSONObjectKeyPaths records the path of every object key in a
// decoded JSON value, below prefix. The empty key, which only a map entry
// from workstreamAFillJSONValue has, is named "*". A key that holds ".", "[",
// "]" or "*" goes into ambiguous instead of a path.
func workstreamAJSONObjectKeyPaths(prefix string, value any, paths, ambiguous map[string]bool) {
	switch value := value.(type) {
	case map[string]any:
		for key, nested := range value {
			segment := key
			switch {
			case key == "":
				segment = "*"
			case strings.ContainsAny(key, ".[]*"):
				ambiguous[key] = true
				continue
			}
			path := segment
			if prefix != "" {
				path = prefix + "." + segment
			}
			paths[path] = true
			workstreamAJSONObjectKeyPaths(path, nested, paths, ambiguous)
		}
	case []any:
		for _, nested := range value {
			workstreamAJSONObjectKeyPaths(prefix+"[]", nested, paths, ambiguous)
		}
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
							line:     guardPosition(fileSet, n.Pos()).Line,
							term:     term,
							spelling: spelling,
							source:   workstreamASourceLine(lines, guardPosition(fileSet, n.Pos()).Line),
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
							line:     guardPosition(fileSet, n.Pos()).Line,
							term:     term,
							spelling: spelling,
							source:   workstreamASourceLine(lines, guardPosition(fileSet, n.Pos()).Line),
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
		if occurrence.file == "service.go" && field != nil &&
			(occurrence.node == field.Names[0] || occurrence.node == field.Tag) {
			return true
		}
		return workstreamAWorkloadGrantPublisherRead(occurrence)
	case "Invoker":
		return workstreamAWorkloadGrantPublisherRead(occurrence)
	case "Publisher", "publisher":
		return workstreamAWorkloadGrantPublisherField(occurrence)
	}
	return false
}

// Workload grants match on one AGS publication claim, the publisher
// principal claims.package.publication.invoker.principal, and on nothing
// else from claims.package.publication (.docs/execution_lifecycle/contracts.md,
// section 5B). ES reads it in one function of workload_grants.go, and keeps
// it in one field of one grant-facts type there. Nothing else is allowed:
// not another publication claim, not the same read elsewhere, and not a
// publisher field of any other type.
const (
	workstreamAWorkloadGrantFile          = "workload_grants.go"
	workstreamAWorkloadGrantReadFunction  = "workloadGrantEvidenceFactsFrom"
	workstreamAWorkloadGrantFactsType     = "workloadGrantEvidenceFacts"
	workstreamAWorkloadGrantPublisherName = "publisherPrincipal"
)

// workstreamAWorkloadGrantPublisherRead allows Publication and Invoker only
// as the selectors of the one read
// <parameter>.Claims.Package.Publication.Invoker.Principal in the top-level
// function workloadGrantEvidenceFactsFrom, whose only parameter is the
// verified evidencev1.ArtifactEvidence. The root of the read is compared by
// object, so a local or a closure parameter of the same name is another
// value and is refused.
func workstreamAWorkloadGrantPublisherRead(occurrence workstreamASourceOccurrence) bool {
	identifier, ok := occurrence.node.(*ast.Ident)
	if !ok || occurrence.file != workstreamAWorkloadGrantFile || occurrence.syntax == nil ||
		(identifier.Name != "Publication" && identifier.Name != "Invoker") {
		return false
	}
	function := workstreamATopLevelFunction(occurrence.syntax, workstreamAWorkloadGrantReadFunction)
	if function == nil || function.Body == nil || len(function.Type.Params.List) != 1 ||
		len(function.Type.Params.List[0].Names) != 1 {
		return false
	}
	parameter := function.Type.Params.List[0]
	if typeName, ok := parameter.Type.(*ast.SelectorExpr); !ok || typeName.Sel.Name != "ArtifactEvidence" ||
		!workstreamAIsIdent(typeName.X, "evidencev1") {
		return false
	}
	allowed := false
	ast.Inspect(function.Body, func(node ast.Node) bool {
		principal, ok := node.(*ast.SelectorExpr)
		if !ok || principal.Sel.Name != "Principal" {
			return true
		}
		chain := []string{"Invoker", "Publication", "Package", "Claims"}
		selectors := make([]*ast.SelectorExpr, 0, len(chain))
		next := principal.X
		for _, name := range chain {
			selector, ok := next.(*ast.SelectorExpr)
			if !ok || selector.Sel.Name != name {
				return true
			}
			selectors = append(selectors, selector)
			next = selector.X
		}
		// The root must be the parameter itself, the object the parser
		// resolves the identifier to, not another value of the same name.
		root, ok := next.(*ast.Ident)
		if !ok || root.Obj == nil || root.Obj != parameter.Names[0].Obj {
			return true
		}
		if occurrence.node == selectors[0].Sel || occurrence.node == selectors[1].Sel {
			allowed = true
		}
		return true
	})
	return allowed
}

// workstreamAWorkloadGrantPublisherField allows the identifier
// publisherPrincipal only as the field of the top-level type
// workloadGrantEvidenceFacts, as a key in a composite literal of that type,
// and as a selector, which can name only that field: a field of the same
// name declared anywhere else is refused.
func workstreamAWorkloadGrantPublisherField(occurrence workstreamASourceOccurrence) bool {
	identifier, ok := occurrence.node.(*ast.Ident)
	if !ok || occurrence.file != workstreamAWorkloadGrantFile || occurrence.syntax == nil ||
		identifier.Name != workstreamAWorkloadGrantPublisherName {
		return false
	}
	ancestors := workstreamAAncestors(occurrence.syntax, identifier)
	if len(ancestors) == 0 {
		return false
	}
	switch parent := ancestors[len(ancestors)-1].(type) {
	case *ast.SelectorExpr:
		return parent.Sel == identifier
	case *ast.KeyValueExpr:
		if parent.Key != identifier || len(ancestors) < 2 {
			return false
		}
		literal, ok := ancestors[len(ancestors)-2].(*ast.CompositeLit)
		return ok && workstreamAIsIdent(literal.Type, workstreamAWorkloadGrantFactsType)
	case *ast.Field:
		if len(parent.Names) != 1 || parent.Names[0] != identifier || len(ancestors) < 5 {
			return false
		}
		// File > GenDecl > TypeSpec > StructType > FieldList > Field.
		structType, isStruct := ancestors[len(ancestors)-3].(*ast.StructType)
		typeSpec, isSpec := ancestors[len(ancestors)-4].(*ast.TypeSpec)
		general, isDecl := ancestors[len(ancestors)-5].(*ast.GenDecl)
		return isStruct && isSpec && isDecl && len(ancestors) == 6 && general.Tok == token.TYPE &&
			typeSpec.Type == structType && typeSpec.Name.Name == workstreamAWorkloadGrantFactsType
	}
	return false
}

// workstreamATopLevelFunction returns the top-level function, not method, of
// that name, or nil.
func workstreamATopLevelFunction(syntax *ast.File, name string) *ast.FuncDecl {
	for _, declaration := range syntax.Decls {
		if function, ok := declaration.(*ast.FuncDecl); ok && function.Recv == nil && function.Name.Name == name {
			return function
		}
	}
	return nil
}

func workstreamAIsIdent(expression ast.Expr, name string) bool {
	identifier, ok := expression.(*ast.Ident)
	return ok && identifier.Name == name
}

// workstreamAAncestors returns the nodes that enclose target in syntax,
// outermost first, or nil when target is not in syntax.
func workstreamAAncestors(syntax *ast.File, target ast.Node) []ast.Node {
	var stack, found []ast.Node
	ast.Inspect(syntax, func(node ast.Node) bool {
		if found != nil {
			return false
		}
		if node == nil {
			stack = stack[:len(stack)-1]
			return false
		}
		if node == target {
			found = append([]ast.Node(nil), stack...)
			return false
		}
		stack = append(stack, node)
		return true
	})
	return found
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
