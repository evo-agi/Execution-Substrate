package evidencev1

import (
	"encoding/json"
	"strings"
	"testing"
)

// recordSignedBeforeMountTargetsCanonical is the canonical form of
// mountTargetsTestRecord as ES produced it at trunk_dev 39e19de, before
// mount_targets existed. A record that declares no mount target must keep
// these bytes, or every artifact published before the field landed would
// stop verifying.
const recordSignedBeforeMountTargetsCanonical = `{"schema_version":"v1","package":{"identity":{"artifact_digest":"sha256:7735524be4bd651a9422520067371e1c52e2a8d889d359c139c6b7ef86eaedb2","payload_digest":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","artifact_type":"static-script","intent_digest":"sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"},"publication":{"builder_service":"artifact-governance","invoker":{"service":"operator/local","principal":"spiffe://execution.internal/operator/local"},"policy_decisions":[{"rule":"allow","result":"applied"}],"build_log_digest":"sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"}},"admission":{"authorization":{"derivation":{"derivation_spec_digest":"sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee","output_id":"runtime"}},"execution":{"runtime":{"environment_variables":[],"required_capabilities":[]},"workload":{"target_platform":"docker"},"access":{"network_access":true}}}}`

func mountTargetsTestRecord(t *testing.T, mountTargets []string) ArtifactEvidence {
	t.Helper()
	identity, err := NewArtifactIdentity(
		"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		"static-script",
		"sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
	)
	if err != nil {
		t.Fatal(err)
	}
	return ArtifactEvidence{Claims: Claims{
		SchemaVersion: Version,
		Package: PackageClaims{
			Identity: identity,
			Publication: Publication{
				BuilderService:  "artifact-governance",
				Invoker:         Invoker{Service: "operator/local", Principal: "spiffe://execution.internal/operator/local"},
				PolicyDecisions: []PolicyDecision{{Rule: "allow", Result: "applied"}},
				BuildLogDigest:  "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
			},
		},
		Admission: AdmissionClaims{
			Authorization: AuthorizationClaims{Derivation: DerivationAuthorization{
				DerivationSpecDigest: "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
				OutputID:             "runtime",
			}},
			Execution: ExecutionClaims{
				Runtime: ExecutionRuntime{
					EnvironmentVariables: []string{},
					RequiredCapabilities: []string{},
					MountTargets:         mountTargets,
				},
				Workload: ExecutionWorkload{TargetPlatform: "docker"},
				Access:   ExecutionAccess{NetworkAccess: true},
			},
		},
	}}
}

func TestRecordWithoutMountTargetsKeepsItsCanonicalBytes(t *testing.T) {
	for name, targets := range map[string][]string{"absent": nil, "empty": {}} {
		canonical, err := mountTargetsTestRecord(t, targets).CanonicalBytes()
		if err != nil {
			t.Fatal(err)
		}
		if string(canonical) != recordSignedBeforeMountTargetsCanonical {
			t.Fatalf("%s mount_targets changed the canonical bytes of a record that declares none:\n got %s\nwant %s", name, canonical, recordSignedBeforeMountTargetsCanonical)
		}
	}
	// The served record of an artifact published before the field existed
	// has no mount_targets key; it must decode and canonicalize the same.
	var decoded ArtifactEvidence
	served, err := json.Marshal(mountTargetsTestRecord(t, nil))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(served), "mount_targets") {
		t.Fatalf("a record without mount targets serializes the key: %s", served)
	}
	if err := json.Unmarshal(served, &decoded); err != nil {
		t.Fatal(err)
	}
	canonical, err := decoded.CanonicalBytes()
	if err != nil || string(canonical) != recordSignedBeforeMountTargetsCanonical {
		t.Fatalf("decoded old-shape record canonicalizes differently: %s %v", canonical, err)
	}
}

func TestMountTargetsAreSignedAsATrimmedSortedSet(t *testing.T) {
	canonical, err := mountTargetsTestRecord(t, []string{" /execution/mounts/b", "/execution/mounts/a "}).CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	want := `"runtime":{"environment_variables":[],"required_capabilities":[],"mount_targets":["/execution/mounts/a","/execution/mounts/b"]}`
	if !strings.Contains(string(canonical), want) {
		t.Fatalf("canonical bytes lack %s: %s", want, canonical)
	}
	other, err := mountTargetsTestRecord(t, []string{"/execution/mounts/a"}).CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	if ContentDigest(other) == ContentDigest(canonical) || string(other) == recordSignedBeforeMountTargetsCanonical {
		t.Fatal("a change to the declared mount targets must change the signed content digest")
	}
}
