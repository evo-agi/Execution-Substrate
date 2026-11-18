package admission

import (
	"context"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"testing"
)

// This compact guard is deliberately local. Behavior tests own observable
// privacy and compatibility contracts; reflection owns the explicitly named
// field shapes below; and one narrow AST check owns the direct B2 golden
// declarations and comparisons. None of these checks is a general analyzer.
//
// A fresh source audit, not this file, owns expected-literal authorship,
// arbitrary aliases or deceptive helpers, secondary cause/log flows, custom
// logging sinks, generic/reflection/unsafe same-package flows, future route
// serializers, future provider types, general response-body consumption, and
// whole-runtime reliable-submit nonwiring. Provenance establishes bytes only.
//
// The assurance split is intentional. Owning behavior tests observe public
// serialization, fixed public messages, captured standard logs, response-body
// reads and closes, provider compatibility, submitted requests, opaque Logs
// bytes, and complete job/handoff equality. The reflection tables below ask
// only whether explicitly selected local types still have their directly
// authored fields, types, tags, omission behavior, and nesting. The AST test
// opens exactly one named test source and asks only whether the two B2 literals,
// their token ledgers, expected-only expansion, and direct DeepEqual failure
// branches retain the selected local form. Production itself owns the stronger
// cancellation fact: stopJob has no purge argument, mode, query bag, or generic
// DELETE helper, so the only constructed cancellation query is purge=false.
//
// These checks therefore do not turn current syntax into architecture. A
// harmless comment or line movement changes no expected record. Unknown Nomad
// fields remain compatible on input. Adding a future DTO or provider decode
// type requires an explicit contract decision rather than silent discovery.
// Existing reliable-submit guardrails remain regression alarms, not proof of
// whole-runtime absence, and Linux cross-compilation remains compile evidence
// rather than native runtime evidence.

type trancheB2FieldRecord struct {
	owner     string
	field     string
	goType    string
	jsonName  string
	jsonTag   string
	omitEmpty bool
	nested    string
}

// These 79 records are direct test-owned truth for current public execution
// request, Submit/lifecycle/cancel, and error JSON. PrepareResult's single
// success key remains owned by the existing endpoint behavior tests. Opaque
// Logs and result-bundle payload bytes are also intentionally absent: their
// contracts are headers plus byte-preserving behavior, not JSON fields.
var trancheB2PublicJSONFieldRecords = []trancheB2FieldRecord{
	{"PrepareRequest", "SchemaVersion", "string", "schema_version", "schema_version", false, ""},
	{"PrepareRequest", "Invocation", "admission.ArtifactInvocation", "invocation", "invocation", false, "ArtifactInvocation"},
	{"PrepareRequest", "Mode", "admission.ExecutionMode", "mode", "mode,omitempty", true, ""},
	{"PrepareRequest", "TimeoutSeconds", "int", "timeout_seconds", "timeout_seconds,omitempty", true, ""},
	{"PrepareRequest", "Resources", "*admission.ExecutionResources", "resources", "resources,omitempty", true, "ExecutionResources"},
	{"ArtifactInvocation", "SchemaVersion", "string", "schema_version", "schema_version", false, ""},
	{"ArtifactInvocation", "ArtifactDigest", "string", "artifact_digest", "artifact_digest", false, ""},
	{"ArtifactInvocation", "DerivationSpecDigest", "string", "derivation_spec_digest", "derivation_spec_digest", false, ""},
	{"ArtifactInvocation", "OutputID", "string", "output_id", "output_id", false, ""},
	{"ArtifactInvocation", "Argv", "[]string", "argv", "argv,omitempty", true, ""},
	{"ArtifactInvocation", "Env", "map[string]string", "env", "env,omitempty", true, ""},
	{"ArtifactInvocation", "Mounts", "[]admission.RuntimeMount", "mounts", "mounts,omitempty", true, "RuntimeMount"},
	{"ArtifactInvocation", "Annotations", "map[string]string", "annotations", "annotations,omitempty", true, ""},
	{"ExecutionResources", "CPU", "int", "cpu", "cpu", false, ""},
	{"ExecutionResources", "MemoryMB", "int", "memory_mb", "memory_mb", false, ""},
	{"RuntimeMount", "Source", "admission.MountSource", "source", "source", false, "MountSource"},
	{"RuntimeMount", "TargetPath", "string", "target_path", "target_path", false, ""},
	{"RuntimeMount", "ReadOnly", "bool", "read_only", "read_only", false, ""},
	{"MountSource", "ArtifactDigest", "string", "artifact_digest", "artifact_digest", false, ""},
	{"SubmitResult", "Success", "bool", "success", "success", false, ""},
	{"SubmitResult", "Submitted", "bool", "submitted", "submitted", false, ""},
	{"SubmitResult", "RunID", "string", "run_id", "run_id", false, ""},
	{"SubmitResult", "Status", "string", "status", "status", false, ""},
	{"SubmitResult", "AuthorityHandoff", "*admission.ExecutionAuthorityHandoff", "authority_handoff", "authority_handoff,omitempty", true, "ExecutionAuthorityHandoff"},
	{"ExecutionStatusResult", "Success", "bool", "success", "success", false, ""},
	{"ExecutionStatusResult", "RunID", "string", "run_id", "run_id", false, ""},
	{"ExecutionStatusResult", "Status", "string", "status", "status", false, ""},
	{"ExecutionStatusResult", "LifecycleProjection", "admission.LifecycleProjection", "lifecycle_projection", "lifecycle_projection", false, "LifecycleProjection"},
	{"ExecutionStatusResult", "OutcomeEvidence", "admission.ExecutionOutcomeEvidence", "outcome_evidence", "outcome_evidence", false, "ExecutionOutcomeEvidence"},
	{"ExecutionStatusResult", "AuthorityHandoff", "*admission.ExecutionAuthorityHandoff", "authority_handoff", "authority_handoff,omitempty", true, "ExecutionAuthorityHandoff"},
	{"ExecutionStatusResult", "ExitCode", "*int", "exit_code", "exit_code,omitempty", true, ""},
	{"ExecutionStatusResult", "Terminal", "bool", "terminal", "terminal", false, ""},
	{"LifecycleProjection", "Source", "string", "source", "source", false, ""},
	{"LifecycleProjection", "Revision", "string", "revision", "revision", false, ""},
	{"ExecutionOutcomeEvidence", "Source", "string", "source", "source", false, ""},
	{"ExecutionOutcomeEvidence", "Observation", "string", "observation", "observation", false, ""},
	{"ExecutionOutcomeEvidence", "AccessClass", "string", "access_class", "access_class,omitempty", true, ""},
	{"ExecutionOutcomeEvidence", "LifecycleProjection", "*admission.LifecycleProjection", "lifecycle_projection", "lifecycle_projection,omitempty", true, "LifecycleProjection"},
	{"ExecutionOutcomeEvidence", "ProviderTerminalObserved", "*bool", "provider_terminal_observed", "provider_terminal_observed,omitempty", true, ""},
	{"ExecutionAuthorityHandoff", "AuthorityPath", "string", "authority_path", "authority_path", false, ""},
	{"ExecutionAuthorityHandoff", "RuntimeProfile", "admission.ExecutionAuthorityRuntimeProfile", "runtime_profile", "runtime_profile", false, "ExecutionAuthorityRuntimeProfile"},
	{"ExecutionAuthorityHandoff", "IdentityHandoff", "admission.ExecutionAuthorityIdentityHandoff", "identity_handoff", "identity_handoff", false, "ExecutionAuthorityIdentityHandoff"},
	{"ExecutionAuthorityHandoff", "WorkloadVault", "admission.ExecutionAuthorityWorkloadVault", "workload_vault", "workload_vault", false, "ExecutionAuthorityWorkloadVault"},
	{"ExecutionAuthorityHandoff", "RuntimeConfigRefs", "admission.ExecutionAuthorityRuntimeConfigRefs", "runtime_config_refs", "runtime_config_refs", false, "ExecutionAuthorityRuntimeConfigRefs"},
	{"ExecutionAuthorityHandoff", "CodexCredentialLocation", "*admission.ExecutionAuthorityCodexCredential", "codex_credential_location", "codex_credential_location,omitempty", true, "ExecutionAuthorityCodexCredential"},
	{"ExecutionAuthorityHandoff", "Evidence", "admission.ExecutionAuthorityEvidence", "evidence", "evidence", false, "ExecutionAuthorityEvidence"},
	{"ExecutionAuthorityRuntimeProfile", "Name", "string", "name", "name", false, ""},
	{"ExecutionAuthorityIdentityHandoff", "Mode", "string", "mode", "mode", false, ""},
	{"ExecutionAuthorityIdentityHandoff", "EndpointEnv", "string", "endpoint_env", "endpoint_env", false, ""},
	{"ExecutionAuthorityIdentityHandoff", "EndpointURI", "string", "endpoint_uri", "endpoint_uri", false, ""},
	{"ExecutionAuthorityIdentityHandoff", "JWTSVIDTarget", "string", "jwt_svid_target", "jwt_svid_target", false, ""},
	{"ExecutionAuthorityWorkloadVault", "AuthMode", "string", "auth_mode", "auth_mode", false, ""},
	{"ExecutionAuthorityWorkloadVault", "Address", "string", "address", "address", false, ""},
	{"ExecutionAuthorityWorkloadVault", "AuthMount", "string", "auth_mount", "auth_mount", false, ""},
	{"ExecutionAuthorityWorkloadVault", "AuthRole", "string", "auth_role", "auth_role", false, ""},
	{"ExecutionAuthorityWorkloadVault", "JWTAudience", "string", "jwt_audience", "jwt_audience", false, ""},
	{"ExecutionAuthorityWorkloadVault", "CACertEnv", "string", "ca_cert_env", "ca_cert_env,omitempty", true, ""},
	{"ExecutionAuthorityWorkloadVault", "CACertPath", "string", "ca_cert_path", "ca_cert_path,omitempty", true, ""},
	{"ExecutionAuthorityWorkloadVault", "TLSBundleEnv", "string", "tls_bundle_env", "tls_bundle_env,omitempty", true, ""},
	{"ExecutionAuthorityWorkloadVault", "TLSBundlePath", "string", "tls_bundle_path", "tls_bundle_path,omitempty", true, ""},
	{"ExecutionAuthorityRuntimeConfigRefs", "WorkloadZoneVaultConfig", "admission.ExecutionAuthorityRuntimeConfigRef", "workload_zone_vault_config", "workload_zone_vault_config", false, "ExecutionAuthorityRuntimeConfigRef"},
	{"ExecutionAuthorityRuntimeConfigRef", "Digest", "string", "digest", "digest", false, ""},
	{"ExecutionAuthorityCodexCredential", "CLIPath", "string", "cli_path", "cli_path", false, ""},
	{"ExecutionAuthorityCodexCredential", "CredentialSource", "string", "credential_source", "credential_source", false, ""},
	{"ExecutionAuthorityCodexCredential", "VaultSecretPath", "string", "vault_secret_path", "vault_secret_path", false, ""},
	{"ExecutionAuthorityCodexCredential", "VaultSecretField", "string", "vault_secret_field", "vault_secret_field", false, ""},
	{"ExecutionAuthorityEvidence", "Source", "string", "source", "source", false, ""},
	{"ExecutionAuthorityEvidence", "RuntimeProfile", "string", "runtime_profile", "runtime_profile", false, ""},
	{"ExecutionAuthorityEvidence", "IdentityHandoff", "string", "identity_handoff", "identity_handoff", false, ""},
	{"ExecutionAuthorityEvidence", "WorkloadVault", "string", "workload_vault", "workload_vault", false, ""},
	{"ExecutionAuthorityEvidence", "RuntimeConfigRefs", "string", "runtime_config_refs", "runtime_config_refs", false, ""},
	{"ExecutionAuthorityEvidence", "CodexCredentialLocation", "string", "codex_credential_location", "codex_credential_location,omitempty", true, ""},
	{"ExecutionCancelResult", "Success", "bool", "success", "success", false, ""},
	{"ExecutionCancelResult", "RunID", "string", "run_id", "run_id", false, ""},
	{"ExecutionCancelResult", "Status", "string", "status", "status", false, ""},
	{"ExecutionCancelResult", "OutcomeEvidence", "admission.ExecutionOutcomeEvidence", "outcome_evidence", "outcome_evidence", false, "ExecutionOutcomeEvidence"},
	{"ErrorResponse", "Success", "bool", "success", "success", false, ""},
	{"ErrorResponse", "Error", "string", "error", "error", false, ""},
	{"ErrorResponse", "Code", "string", "code", "code,omitempty", true, ""},
}

var trancheB2PublicJSONOwners = map[string]reflect.Type{
	"PrepareRequest":                      reflect.TypeOf(PrepareRequest{}),
	"ArtifactInvocation":                  reflect.TypeOf(ArtifactInvocation{}),
	"ExecutionResources":                  reflect.TypeOf(ExecutionResources{}),
	"RuntimeMount":                        reflect.TypeOf(RuntimeMount{}),
	"MountSource":                         reflect.TypeOf(MountSource{}),
	"SubmitResult":                        reflect.TypeOf(SubmitResult{}),
	"ExecutionStatusResult":               reflect.TypeOf(ExecutionStatusResult{}),
	"LifecycleProjection":                 reflect.TypeOf(LifecycleProjection{}),
	"ExecutionOutcomeEvidence":            reflect.TypeOf(ExecutionOutcomeEvidence{}),
	"ExecutionAuthorityHandoff":           reflect.TypeOf(ExecutionAuthorityHandoff{}),
	"ExecutionAuthorityRuntimeProfile":    reflect.TypeOf(ExecutionAuthorityRuntimeProfile{}),
	"ExecutionAuthorityIdentityHandoff":   reflect.TypeOf(ExecutionAuthorityIdentityHandoff{}),
	"ExecutionAuthorityWorkloadVault":     reflect.TypeOf(ExecutionAuthorityWorkloadVault{}),
	"ExecutionAuthorityRuntimeConfigRefs": reflect.TypeOf(ExecutionAuthorityRuntimeConfigRefs{}),
	"ExecutionAuthorityRuntimeConfigRef":  reflect.TypeOf(ExecutionAuthorityRuntimeConfigRef{}),
	"ExecutionAuthorityCodexCredential":   reflect.TypeOf(ExecutionAuthorityCodexCredential{}),
	"ExecutionAuthorityEvidence":          reflect.TypeOf(ExecutionAuthorityEvidence{}),
	"ExecutionCancelResult":               reflect.TypeOf(ExecutionCancelResult{}),
	"ErrorResponse":                       reflect.TypeOf(ErrorResponse{}),
}

// These 20 records freeze only the eight Nomad response/decode structs and
// fields current production consumes. Compatible unknown provider fields are
// intentionally accepted by behavior below.
var trancheB2ProviderJSONFieldRecords = []trancheB2FieldRecord{
	{"nomadJobRegisterResponse", "EvalID", "string", "EvalID", "EvalID", false, ""},
	{"nomadJobSummary", "ID", "string", "ID", "ID", false, ""},
	{"nomadJobSummary", "Status", "string", "Status", "Status", false, ""},
	{"nomadJobSummary", "ModifyIndex", "uint64", "ModifyIndex", "ModifyIndex", false, ""},
	{"nomadJobSummary", "Meta", "map[string]string", "Meta", "Meta", false, ""},
	{"nomadJobSummary", "TaskGroups", "[]admission.nomadJobTaskGroup", "TaskGroups", "TaskGroups", false, "nomadJobTaskGroup"},
	{"nomadJobTaskGroup", "Tasks", "[]admission.nomadJobTask", "Tasks", "Tasks", false, "nomadJobTask"},
	{"nomadJobTask", "Name", "string", "Name", "Name", false, ""},
	{"nomadJobTask", "Env", "map[string]string", "Env", "Env", false, ""},
	{"nomadAllocationListEntry", "ID", "string", "ID", "ID", false, ""},
	{"nomadAllocationListEntry", "ModifyIndex", "uint64", "ModifyIndex", "ModifyIndex", false, ""},
	{"nomadAllocationDetail", "ID", "string", "ID", "ID", false, ""},
	{"nomadAllocationDetail", "ClientStatus", "string", "ClientStatus", "ClientStatus", false, ""},
	{"nomadAllocationDetail", "ModifyIndex", "uint64", "ModifyIndex", "ModifyIndex", false, ""},
	{"nomadAllocationDetail", "TaskStates", "map[string]admission.nomadTaskState", "TaskStates", "TaskStates", false, "nomadTaskState"},
	{"nomadTaskState", "State", "string", "State", "State", false, ""},
	{"nomadTaskState", "Failed", "bool", "Failed", "Failed", false, ""},
	{"nomadTaskState", "Events", "[]admission.nomadTaskEvent", "Events", "Events", false, "nomadTaskEvent"},
	{"nomadTaskEvent", "Type", "string", "Type", "Type", false, ""},
	{"nomadTaskEvent", "ExitCode", "int", "ExitCode", "ExitCode", false, ""},
}

var trancheB2ProviderJSONOwners = map[string]reflect.Type{
	"nomadJobRegisterResponse": reflect.TypeOf(nomadJobRegisterResponse{}),
	"nomadJobSummary":          reflect.TypeOf(nomadJobSummary{}),
	"nomadJobTaskGroup":        reflect.TypeOf(nomadJobTaskGroup{}),
	"nomadJobTask":             reflect.TypeOf(nomadJobTask{}),
	"nomadAllocationListEntry": reflect.TypeOf(nomadAllocationListEntry{}),
	"nomadAllocationDetail":    reflect.TypeOf(nomadAllocationDetail{}),
	"nomadTaskState":           reflect.TypeOf(nomadTaskState{}),
	"nomadTaskEvent":           reflect.TypeOf(nomadTaskEvent{}),
}

func TestTrancheB2CompactPublicJSONFieldInventory(t *testing.T) {
	if len(trancheB2PublicJSONFieldRecords) != 79 {
		t.Fatalf("public execution field record count = %d, want 79", len(trancheB2PublicJSONFieldRecords))
	}
	trancheB2AssertFieldInventory(t, trancheB2PublicJSONFieldRecords, trancheB2PublicJSONOwners)
}

func TestTrancheB2CompactProviderJSONFieldInventory(t *testing.T) {
	if len(trancheB2ProviderJSONFieldRecords) != 20 {
		t.Fatalf("Nomad provider field record count = %d, want 20", len(trancheB2ProviderJSONFieldRecords))
	}
	if got := len(trancheB2PublicJSONFieldRecords) + len(trancheB2ProviderJSONFieldRecords); got != 99 {
		t.Fatalf("direct semantic field record count = %d, want 99", got)
	}
	trancheB2AssertFieldInventory(t, trancheB2ProviderJSONFieldRecords, trancheB2ProviderJSONOwners)
}

func trancheB2AssertFieldInventory(t *testing.T, records []trancheB2FieldRecord, owners map[string]reflect.Type) {
	t.Helper()
	byOwner := make(map[string][]trancheB2FieldRecord, len(owners))
	for _, record := range records {
		if _, ok := owners[record.owner]; !ok {
			t.Fatalf("record names unknown owner %q", record.owner)
		}
		byOwner[record.owner] = append(byOwner[record.owner], record)
	}
	if len(byOwner) != len(owners) {
		t.Fatalf("field inventory covers %d owners, want %d", len(byOwner), len(owners))
	}

	for ownerName, ownerType := range owners {
		expected := byOwner[ownerName]
		if ownerType.Kind() != reflect.Struct || ownerType.NumField() != len(expected) {
			t.Fatalf("%s has %d fields, want %d", ownerName, ownerType.NumField(), len(expected))
		}
		encoded, err := json.Marshal(reflect.New(ownerType).Elem().Interface())
		if err != nil {
			t.Fatalf("marshal zero %s: %v", ownerName, err)
		}
		var zeroObject map[string]json.RawMessage
		if err := json.Unmarshal(encoded, &zeroObject); err != nil {
			t.Fatalf("decode zero %s: %v", ownerName, err)
		}

		for index, want := range expected {
			field := ownerType.Field(index)
			tag, ok := field.Tag.Lookup("json")
			if !ok {
				t.Fatalf("%s.%s has no JSON tag", ownerName, field.Name)
			}
			parts := strings.Split(tag, ",")
			omitEmpty := false
			for _, option := range parts[1:] {
				if option == "omitempty" {
					omitEmpty = true
				}
			}
			got := trancheB2FieldRecord{
				owner:     ownerName,
				field:     field.Name,
				goType:    field.Type.String(),
				jsonName:  parts[0],
				jsonTag:   tag,
				omitEmpty: omitEmpty,
				nested:    trancheB2NestedOwner(field.Type, owners),
			}
			if got != want {
				t.Fatalf("field record changed: got %+v want %+v", got, want)
			}
			_, presentAtZero := zeroObject[want.jsonName]
			if presentAtZero == want.omitEmpty {
				t.Fatalf("%s.%s zero-value omission = %v, want %v", ownerName, field.Name, !presentAtZero, want.omitEmpty)
			}
		}
	}
}

func trancheB2NestedOwner(fieldType reflect.Type, owners map[string]reflect.Type) string {
	for {
		switch fieldType.Kind() {
		case reflect.Pointer, reflect.Slice, reflect.Array, reflect.Map:
			fieldType = fieldType.Elem()
		default:
			for name, ownerType := range owners {
				if fieldType == ownerType {
					return name
				}
			}
			return ""
		}
	}
}

func TestTrancheB2PreparedAdmissionLocalStructure(t *testing.T) {
	wantDataFields := []string{
		"admittedRequest",
		"result",
		"artifact",
		"workloadVaultPlan",
		"workloadZoneVaultConfigRef",
		"trustModel",
		"policyPayloadBytes",
		"policyPayloadBytesAvailable",
	}
	preparedType := reflect.TypeOf(preparedAdmission{})
	markerType := reflect.TypeOf(privateExecutionValue{})
	if preparedType.NumField() != len(wantDataFields)+1 {
		t.Fatalf("preparedAdmission field count = %d, want %d", preparedType.NumField(), len(wantDataFields)+1)
	}
	marker := preparedType.Field(0)
	if !marker.Anonymous || marker.Name != "privateExecutionValue" || marker.Type != markerType || markerType.Size() != 0 || markerType.NumField() != 0 {
		t.Fatalf("preparedAdmission first field is not the anonymous zero-data privacy marker: %+v", marker)
	}
	for index, wantName := range wantDataFields {
		field := preparedType.Field(index + 1)
		if field.Name != wantName || field.Anonymous || field.PkgPath == "" {
			t.Fatalf("preparedAdmission data field %d changed visibility or shape: %+v", index, field)
		}
		if _, ok := field.Tag.Lookup("json"); ok {
			t.Fatalf("preparedAdmission.%s exposes a JSON tag", field.Name)
		}
	}
	for index := 0; index < preparedType.NumField(); index++ {
		if _, ok := preparedType.Field(index).Tag.Lookup("json"); ok {
			t.Fatalf("preparedAdmission field %s exposes a JSON tag", preparedType.Field(index).Name)
		}
	}

	formatterType := reflect.TypeOf((*fmt.Formatter)(nil)).Elem()
	if !preparedType.Implements(formatterType) || !reflect.PointerTo(preparedType).Implements(formatterType) {
		t.Fatal("preparedAdmission value and pointer must implement fmt.Formatter")
	}
	prepared := preparedAdmission{}
	if got := fmt.Sprintf("%v", prepared); got != privateExecutionValueRedaction {
		t.Fatalf("preparedAdmission value formatted as %q", got)
	}
	if got := fmt.Sprintf("%v", &prepared); got != privateExecutionValueRedaction {
		t.Fatalf("preparedAdmission pointer formatted as %q", got)
	}
	for _, value := range []any{prepared, &prepared} {
		encoded, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		if string(encoded) != "{}" {
			t.Fatalf("preparedAdmission ordinary JSON = %q, want {}", encoded)
		}
	}
}

func TestTrancheB2NomadRegistrationRequiresEvalIDAndIgnoresUnknownReceiptRef(t *testing.T) {
	baseURL, err := url.Parse("http://nomad.test")
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name     string
		response string
		wantID   string
		wantErr  string
	}{
		{name: "unknown receipt only", response: `{"ReceiptRef":"x"}`, wantErr: "missing eval id"},
		{name: "EvalID with compatible unknown receipt", response: `{"EvalID":"eval-b2","ReceiptRef":"x"}`, wantID: "eval-b2"},
	} {
		t.Run(test.name, func(t *testing.T) {
			responseBytes := []byte(test.response)
			client := &nomadClient{
				baseURL: baseURL,
				client: &http.Client{Transport: trancheB2RoundTripFunc(func(*http.Request) (*http.Response, error) {
					return &http.Response{
						StatusCode:    http.StatusOK,
						Header:        make(http.Header),
						Body:          io.NopCloser(strings.NewReader(test.response)),
						ContentLength: int64(len(responseBytes)),
					}, nil
				})},
			}
			gotID, submitErr := client.submitJob(context.Background(), map[string]any{"Job": map[string]any{"ID": "exec-test"}})
			if test.wantErr != "" {
				if submitErr == nil || !strings.Contains(submitErr.Error(), test.wantErr) {
					t.Fatalf("submit error = %v, want %q", submitErr, test.wantErr)
				}
				return
			}
			if submitErr != nil || gotID != test.wantID {
				t.Fatalf("submit returned id=%q err=%v, want id=%q", gotID, submitErr, test.wantID)
			}
		})
	}
}

type trancheB2RoundTripFunc func(*http.Request) (*http.Response, error)

func (transport trancheB2RoundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return transport(request)
}

func TestTrancheB2GoldenDeclarationsAndDirectEqualityAreLocal(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "resolved_execution_plan_test.go", nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatal(err)
	}

	wantValues := map[string]ast.Expr{
		"trancheB2ControlPlaneNormalShellNomadJobGolden":              nil,
		"trancheB2ControlPlaneNormalShellAuthorityHandoffGolden":      nil,
		"trancheB2ControlPlaneNormalShellNomadJobTokenLedger":         nil,
		"trancheB2ControlPlaneNormalShellAuthorityHandoffTokenLedger": nil,
	}
	var owningTest *ast.FuncDecl
	for _, declaration := range file.Decls {
		switch typed := declaration.(type) {
		case *ast.GenDecl:
			for _, rawSpec := range typed.Specs {
				spec, ok := rawSpec.(*ast.ValueSpec)
				if !ok {
					continue
				}
				for index, name := range spec.Names {
					if _, governed := wantValues[name.Name]; !governed {
						continue
					}
					if index >= len(spec.Values) || wantValues[name.Name] != nil {
						t.Fatalf("golden declaration %s is missing or duplicated", name.Name)
					}
					wantValues[name.Name] = spec.Values[index]
				}
			}
		case *ast.FuncDecl:
			if typed.Name.Name == "TestTrancheB2ControlPlaneNormalShellLiteralNomadJobAndAuthorityHandoff" {
				if owningTest != nil {
					t.Fatal("B2 golden owning test is duplicated")
				}
				owningTest = typed
			}
		}
	}

	for _, name := range []string{
		"trancheB2ControlPlaneNormalShellNomadJobGolden",
		"trancheB2ControlPlaneNormalShellAuthorityHandoffGolden",
	} {
		literal, ok := wantValues[name].(*ast.BasicLit)
		if !ok || literal.Kind != token.STRING {
			t.Fatalf("%s must be one direct string literal", name)
		}
	}
	trancheB2AssertDirectTokenLedger(t, wantValues["trancheB2ControlPlaneNormalShellNomadJobTokenLedger"], 14)
	trancheB2AssertDirectTokenLedger(t, wantValues["trancheB2ControlPlaneNormalShellAuthorityHandoffTokenLedger"], 1)
	if owningTest == nil || owningTest.Body == nil {
		t.Fatal("B2 golden owning test is missing")
	}

	foundJobEquality := false
	foundHandoffEquality := false
	expanderSources := map[string]int{}
	forbiddenComparisonHelperCalls := 0
	ast.Inspect(owningTest.Body, func(node ast.Node) bool {
		switch typed := node.(type) {
		case *ast.IfStmt:
			left, right, ok := trancheB2DirectDeepEqualInequality(typed.Cond)
			if !ok {
				break
			}
			if left == "actualJob" && right == "expandedJob" {
				foundJobEquality = true
			}
			if left == "actualHandoff" && right == "expandedHandoff" {
				foundHandoffEquality = true
			}
			if (left == "actualJob" && right == "expandedJob") || (left == "actualHandoff" && right == "expandedHandoff") {
				if !trancheB2BodyDirectlyFails(typed.Body) {
					t.Fatalf("direct %s/%s inequality does not unconditionally fail its branch", left, right)
				}
			}
		case *ast.CallExpr:
			name := trancheB2CalledName(typed.Fun)
			if name == "trancheB1CompareCompleteGolden" {
				forbiddenComparisonHelperCalls++
			}
			if name == "expandTrancheB1ExpectedGolden" {
				if len(typed.Args) == 0 {
					t.Fatal("B2 golden expander has no expected source")
				}
				source, ok := typed.Args[0].(*ast.Ident)
				if !ok || (source.Name != "expectedJob" && source.Name != "expectedHandoff") {
					t.Fatal("B2 golden expander source is not a direct expected literal variable")
				}
				expanderSources[source.Name]++
			}
		}
		return true
	})
	if !foundJobEquality || !foundHandoffEquality {
		t.Fatalf("direct B2 equality decisions missing: job=%v handoff=%v", foundJobEquality, foundHandoffEquality)
	}
	if forbiddenComparisonHelperCalls != 0 {
		t.Fatal("B2 owning test delegates acceptance to a comparison helper")
	}
	if expanderSources["expectedJob"] != 1 || expanderSources["expectedHandoff"] != 1 || len(expanderSources) != 2 {
		t.Fatalf("B2 expected-only expander sources changed: %v", expanderSources)
	}
}

func trancheB2AssertDirectTokenLedger(t *testing.T, expression ast.Expr, wantRows int) {
	t.Helper()
	ledger, ok := expression.(*ast.CompositeLit)
	if !ok {
		t.Fatal("B2 token ledger is not a direct composite literal")
	}
	arrayType, ok := ledger.Type.(*ast.ArrayType)
	if !ok || arrayType.Len != nil {
		t.Fatal("B2 token ledger must directly declare a slice")
	}
	elementType, ok := arrayType.Elt.(*ast.Ident)
	if !ok || elementType.Name != "trancheB1GoldenTokenOccurrence" || len(ledger.Elts) != wantRows {
		t.Fatal("B2 token ledger shape/row count changed")
	}
	for _, rawRow := range ledger.Elts {
		row, ok := rawRow.(*ast.CompositeLit)
		if !ok || row.Type != nil || len(row.Elts) != 3 {
			t.Fatal("B2 token-ledger row is not a direct three-field literal")
		}
		seen := map[string]bool{}
		for _, rawField := range row.Elts {
			field, ok := rawField.(*ast.KeyValueExpr)
			if !ok {
				t.Fatal("B2 token-ledger row contains a non-keyed value")
			}
			key, keyOK := field.Key.(*ast.Ident)
			value, valueOK := field.Value.(*ast.BasicLit)
			if !keyOK || !valueOK || value.Kind != token.STRING || (key.Name != "token" && key.Name != "pointer" && key.Name != "template") || seen[key.Name] {
				t.Fatal("B2 token-ledger fields must be unique direct string literals")
			}
			seen[key.Name] = true
		}
		if !seen["token"] || !seen["pointer"] || !seen["template"] {
			t.Fatal("B2 token-ledger row is incomplete")
		}
	}
}

func trancheB2DirectDeepEqualInequality(expression ast.Expr) (string, string, bool) {
	not, ok := expression.(*ast.UnaryExpr)
	if !ok || not.Op != token.NOT {
		return "", "", false
	}
	call, ok := not.X.(*ast.CallExpr)
	if !ok || len(call.Args) != 2 {
		return "", "", false
	}
	selector, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || selector.Sel.Name != "DeepEqual" {
		return "", "", false
	}
	owner, ownerOK := selector.X.(*ast.Ident)
	left, leftOK := call.Args[0].(*ast.Ident)
	right, rightOK := call.Args[1].(*ast.Ident)
	if !ownerOK || owner.Name != "reflect" || !leftOK || !rightOK {
		return "", "", false
	}
	return left.Name, right.Name, true
}

func trancheB2BodyDirectlyFails(body *ast.BlockStmt) bool {
	for _, statement := range body.List {
		expression, ok := statement.(*ast.ExprStmt)
		if !ok {
			continue
		}
		call, ok := expression.X.(*ast.CallExpr)
		if !ok {
			continue
		}
		selector, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || selector.Sel.Name != "Fatalf" {
			continue
		}
		owner, ok := selector.X.(*ast.Ident)
		if ok && owner.Name == "t" {
			return true
		}
	}
	return false
}

func trancheB2CalledName(expression ast.Expr) string {
	switch typed := expression.(type) {
	case *ast.Ident:
		return typed.Name
	case *ast.SelectorExpr:
		return typed.Sel.Name
	default:
		return ""
	}
}
