package executionsubstrate_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strconv"
	"strings"
	"testing"
)

const arsBlobVerificationContractHeading = "## 5A. ARS blob byte verification contract"

// arsBlobVerificationContractSection returns contracts.md section 5A, which
// must sit directly before the Submit contract.
func arsBlobVerificationContractSection(t *testing.T) string {
	t.Helper()
	contracts := mustRead(t, ".docs/execution_lifecycle/contracts.md")
	if strings.Count(contracts, arsBlobVerificationContractHeading+"\n") != 1 {
		t.Fatalf("contracts.md must contain exactly one %q heading", arsBlobVerificationContractHeading)
	}
	start := strings.Index(contracts, arsBlobVerificationContractHeading+"\n")
	rest := contracts[start+len(arsBlobVerificationContractHeading):]
	end := strings.Index(rest, "\n## ")
	if end < 0 {
		t.Fatal("contracts.md section 5A has no following section")
	}
	if !strings.HasPrefix(rest[end+1:], "## 6. Submit contract\n") {
		t.Fatal("contracts.md section 5A must come directly before the Submit contract")
	}
	return rest[:end]
}

// arsBlobMismatchMessages reads the public mismatch message constants from the
// ES source, so the contract text is checked against the code that emits it.
func arsBlobMismatchMessages(t *testing.T) map[string]string {
	t.Helper()
	path := "es/admission/ars_blob_fetch.go"
	parsed, err := parser.ParseFile(token.NewFileSet(), path, mustRead(t, path), parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	messages := map[string]string{}
	for _, decl := range parsed.Decls {
		general, ok := decl.(*ast.GenDecl)
		if !ok || general.Tok != token.CONST {
			continue
		}
		for _, spec := range general.Specs {
			value := spec.(*ast.ValueSpec)
			for index, name := range value.Names {
				if !strings.HasSuffix(name.Name, "DigestMismatchMessage") || index >= len(value.Values) {
					continue
				}
				literal, ok := value.Values[index].(*ast.BasicLit)
				if !ok || literal.Kind != token.STRING {
					t.Fatalf("%s is not a string literal", name.Name)
				}
				text, err := strconv.Unquote(literal.Value)
				if err != nil {
					t.Fatalf("unquote %s: %v", name.Name, err)
				}
				messages[name.Name] = text
			}
		}
	}
	return messages
}

func TestARSBlobVerificationContractNamesEveryCoveredReadAndRule(t *testing.T) {
	section := compactText(arsBlobVerificationContractSection(t))
	for _, required := range []string{
		"ES does not trust ARS for the integrity of the blobs it reads by digest.",
		"but ES does not rely on that check.",
		"ES still trusts ARS for one choice: which sealed evidence document applies to an artifact, through the discovery record (see \"Outside this contract\").",
		"These are all of ES's reads of `GET /v1/blobs/{digest}`. There is no other:",
		"| Aggregate artifact evidence | `:json` | evidence digest |",
		"| Workload-zone Vault runtime config | `:json` | configured reference digest |",
		"| Admission-policy payload input | `:bytes` | `payload_digest` |",
		"| Primary payload | `:bytes` | `payload_digest` |",
		"| Governed mount payload | `:bytes` | mount `payload_digest` |",
		"must be exactly `sha256:` followed by 64 lowercase hex digits. Any other value is refused before a request is sent.",
		"The string that is requested is the string that is verified; it is not trimmed or normalized in between.",
		"computes SHA-256 over exactly that buffer.",
		"A mismatched buffer is dropped.",
		"The verified buffer is the only copy ES uses.",
		"ES makes no second read of the same blob for use.",
		"When the admission policy already read the payload, Submit stages that same verified buffer as the primary payload.",
		"A mismatch fails closed. Every covered read happens before the Submit freeze point, so a mismatch leaves no run ID, staging directory, file write, ownership change, or Nomad registration behind.",
		"`HEAD /v1/blobs/{digest}`, the ARS `Content-Digest` header, and ARS read-path verification are not used as evidence of byte integrity.",
		"A mismatch keeps each read's existing HTTP status and code.",
		"No digest value, byte count, or received byte is exposed.",
		"| Admission-policy payload input | `403` | `admission_policy_input_unavailable` | the existing fixed admission-policy input message |",
		"Staged files after the Submit freeze point are protected by the Tranche A staging custody contract, not re-hashed.",
		"The ARS discovery record (`GET /v1/artifacts/{artifact_digest}/discovery`) is not read by digest. ES has no trusted digest for it and does not verify its bytes.",
		"its artifact digest must equal the requested one (the invocation's `artifact_digest`, or a governed mount's source `artifact_digest`), and its payload digest, artifact type and intent digest must equal the signature-verified evidence claims. Its evidence digest is used only to choose which evidence blob to read.",
		"claim the requested `artifact_digest`; for the primary artifact it must also claim the requested `derivation_spec_digest` and `output_id`.",
		"ES does not check that it is the only such document.",
		"When more than one exists, ARS chooses which of them ES admits.",
		"the provenance key can seal more than one evidence document that passes these checks, with different `network_access`, `target_platform` or runtime interface claims: for the primary artifact, with the same artifact digest, derivation spec digest and output ID; for a governed mount, with the same artifact digest.",
		"For a mount this changes no staged byte, because the artifact digest fixes the payload digest; for the primary artifact it decides which execution claims apply.",
		"ARS's index accepts one discovery record per artifact digest, so an ARS that follows its own registration contract always names the first registered document.",
	} {
		if !strings.Contains(section, compactText(required)) {
			t.Errorf("contracts.md section 5A is missing %q", required)
		}
	}
	// The contract must not claim that ES verifies everything it reads from
	// ARS: the discovery record is read unverified.
	if strings.Contains(section, compactText("ES does not trust ARS for the integrity of the bytes it reads.")) {
		t.Errorf("contracts.md section 5A claims ES verifies every ARS read, but the discovery record is not verified")
	}
	if rows := strings.Count(section, "| `:json` |") + strings.Count(section, "| `:bytes` |"); rows != 5 {
		t.Errorf("contracts.md section 5A must list exactly five covered reads, found %d", rows)
	}
}

func TestARSBlobVerificationContractMessagesMatchTheCode(t *testing.T) {
	section := compactText(arsBlobVerificationContractSection(t))
	messages := arsBlobMismatchMessages(t)
	want := map[string]string{
		"artifactEvidenceDigestMismatchMessage":      "| Aggregate artifact evidence | `503` | `artifact_evidence_unavailable` | `%s` |",
		"workloadZoneVaultBlobDigestMismatchMessage": "| Workload-zone Vault runtime config | `503` | `workload_zone_vault_unavailable` | `%s` |",
		"artifactPayloadDigestMismatchMessage":       "| Primary payload | `503` | `payload_unavailable` | `%s` |",
	}
	if len(messages) != len(want) {
		t.Fatalf("expected %d mismatch message constants in ES, found %v", len(want), messages)
	}
	for name, row := range want {
		message, ok := messages[name]
		if !ok {
			t.Fatalf("ES no longer defines %s", name)
		}
		if strings.Contains(message, "sha256") {
			t.Errorf("%s exposes a digest: %q", name, message)
		}
		if !strings.Contains(section, strings.Replace(row, "%s", message, 1)) {
			t.Errorf("contracts.md section 5A does not map %s to %q", name, message)
		}
	}
	mountRow := "| Governed mount payload | `503` | `payload_unavailable` | `" + messages["artifactPayloadDigestMismatchMessage"] + "` |"
	if !strings.Contains(section, mountRow) {
		t.Errorf("contracts.md section 5A does not map the governed mount payload mismatch")
	}
}

func TestARSBlobVerificationIsStatedWhereDocsDescribeARSReads(t *testing.T) {
	for _, check := range []struct {
		path     string
		required []string
		absent   []string
	}{
		{
			path: ".docs/execution_lifecycle/contracts.md",
			required: []string{
				"`:prepare` verifies every ARS blob it reads by digest, including the aggregate evidence, the workload-zone Vault config, and any policy payload input, against the requested digest before using it (section 5A). The discovery record is read by artifact digest and is not verified; section 5A states what binds it.",
				"Submit resolves payload bytes through the explicit payload digest carried in aggregate evidence, and uses only bytes that hash to that digest (section 5A).",
			},
		},
		{
			path: ".docs/system_overview/artifact_publication_storage.md",
			required: []string{
				"ES does not trust ARS for the integrity of the blobs it reads by digest. Every ES read of an ARS blob by digest hashes the exact bytes received and uses them only when they equal the requested digest; ARS's own read-path check is not relied on.",
				"The discovery record is read by artifact digest and is not verified: ES cross-checks it against the signed evidence, but ARS still chooses which sealed evidence document applies when more than one exists for the same artifact (and, for the primary artifact, the same derivation inputs).",
				"ES does not rely on the ARS check: it hashes the exact payload bytes it receives and inspects, stages, or runs them only when they equal the signed `payload_digest`.",
				"ES uses payload bytes only after it has itself verified that they hash to the signed `payload_digest`.",
			},
			absent: []string{"ES does not trust ARS for byte integrity."},
		},
		{
			path: ".docs/system_overview/runtime_config_ownership.md",
			required: []string{
				"ES does not rely on ARS integrity for this blob: it decodes the workload-zone Vault runtime-config blob only after the received bytes hash to the configured reference digest",
			},
			absent: []string{"ES does not rely on ARS integrity for the bytes it reads"},
		},
		{
			path: "PLANS.md",
			required: []string{
				"ES does not rely on ARS for their integrity: every ARS blob read by digest is hashed by ES and used only when it equals the requested digest",
			},
			absent: []string{"ARS remains their integrity authority"},
		},
		{
			path: ".docs/execution_lifecycle/design.md",
			required: []string{
				"ES verifies the bytes of every blob it reads by digest and does not verify the discovery record (contracts section 5A).",
			},
		},
		{
			path: ".docs/execution_lifecycle/implementation.md",
			required: []string{
				"whose bytes must hash to the discovery evidence digest before decoding (`fetchVerifiedARSBlob`, contracts section 5A).",
				"decode it only after its bytes hash to the reference digest.",
				"primary payload bytes (verified against the signed payload digest)",
				"fetches payload bytes, which must hash to the mount's signed payload digest,",
			},
		},
	} {
		text := compactText(mustRead(t, check.path))
		for _, required := range check.required {
			if !strings.Contains(text, compactText(required)) {
				t.Errorf("%s is missing %q", check.path, required)
			}
		}
		for _, absent := range check.absent {
			if strings.Contains(text, absent) {
				t.Errorf("%s still says %q", check.path, absent)
			}
		}
	}
}
