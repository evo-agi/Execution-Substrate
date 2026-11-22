package admission

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	egsmodel "execution-substrate/egs/model"

	"execution-substrate/es/admission/internal/reliablesubmit"
	evidencev1 "execution-substrate/internal/contracts/evidence/v1"
)

// These fixtures explicitly commission local proof Services. There is no
// production commissioning caller or installed policy-epoch agreement here.
func operationalV2Original(t *testing.T, f *operationalFixture) verifiedOperationalOriginal {
	t.Helper()
	caller, err := newSyntheticCallerFact(f.domain.caller.String())
	if err != nil {
		t.Fatal(err)
	}
	delivery, err := parsePrivateReplayDelivery(f.raw, caller)
	if err != nil {
		t.Fatal(err)
	}
	original, err := f.service.composeOperationalOriginal(context.Background(), delivery, f.domain.keys, f.domain.realm)
	if err != nil {
		t.Fatal(err)
	}
	return original
}

func operationalSeedIntent(t *testing.T, argv ...string) *operationalFixture {
	t.Helper()
	f := makeOperationalFixture(t, "", argv...)
	if err := f.domain.custody.ConfigureOperationalCommitFaultForProof(reliablesubmit.OperationalIntent, false); err != nil {
		t.Fatal(err)
	}
	first := f.submit()
	state := operationalPrestageStateAt(t, f)
	if first.operation != reliablesubmit.OperationalIntent || first.write != reliablesubmit.OperationalOwnCommitConfirmed ||
		first.run == "" || state.Revision != 3 || !state.Intent || state.StageEntries != 0 || state.Posts != 0 {
		t.Fatalf("invalid v2 retained-intent seed: result=%+v state=%+v", first, state)
	}
	return f
}

func operationalProofService(t *testing.T, f *operationalFixture, configure func(*Service)) *Service {
	t.Helper()
	trust := snapshotRuntimeTrustModel(*f.service.trustModel)
	old := f.service.provenanceVerifier
	service := &Service{cfg: f.service.cfg, trustModel: &trust, trustModelVerified: true,
		provenanceVerifier: &ed25519Verifier{algorithm: old.algorithm, keyID: old.keyID,
			publicKey: bytes.Clone(old.publicKey)}}
	service.trustModelOwner = service
	if configure != nil {
		configure(service)
	}
	if err := service.commissionOperationalAdmission(f.domain.realm); err != nil {
		t.Fatalf("commission selected synthetic policy: %v", err)
	}
	return service
}

func assertOperationalNoFurtherEffect(t *testing.T, f *operationalFixture, before operationalPrestageState, out operationalHandoffResult) {
	t.Helper()
	after := operationalPrestageStateAt(t, f)
	if out.kind != operationalUnavailable || out.run != "" || out.receipt.Valid() ||
		before.Revision != after.Revision || before.StageEntries != after.StageEntries || before.Posts != after.Posts {
		t.Fatalf("unaccepted effect/disclosure: result=%+v before=%+v after=%+v", out, before, after)
	}
}

func TestPR12RetainedAdmissionCuts(t *testing.T) {
	t.Run("allowed v2 retained policy", func(t *testing.T) {
		f := operationalSeedIntent(t)
		f.required.Store(0)
		f.evaluated.Store(0)
		out := f.service.handoffOperational(context.Background(), f.reopen(), f.domain.caller, f.raw)
		state := operationalPrestageStateAt(t, f)
		if out.kind != operationalAccepted || state.Revision != 6 || state.Posts != 1 ||
			f.required.Load() == 0 || f.evaluated.Load() == 0 {
			t.Fatalf("retained built-in policy/one POST: result=%+v state=%+v required=%d evaluated=%d", out, state, f.required.Load(), f.evaluated.Load())
		}
	})
	t.Run("missing local authority", func(t *testing.T) {
		f := operationalSeedIntent(t)
		before := operationalPrestageStateAt(t, f)
		out := (&Service{}).handoffOperational(context.Background(), f.reopen(), f.domain.caller, f.raw)
		assertOperationalNoFurtherEffect(t, f, before, out)
	})
	t.Run("current configured literal denial", func(t *testing.T) {
		f := operationalSeedIntent(t)
		var required, evaluated atomic.Int32
		service := operationalProofService(t, f, func(s *Service) {
			configureConfiguredStaticScriptLiteralDenyService(s, "policy-fixture-ok")
			s.operationalProof = &operationalAdmissionProofHooks{
				required:  func([]AdmissionPolicyInputClass) { required.Add(1) },
				evaluated: func(bool) { evaluated.Add(1) },
			}
		})
		before := operationalPrestageStateAt(t, f)
		out := service.handoffOperational(context.Background(), f.reopen(), f.domain.caller, f.raw)
		assertOperationalNoFurtherEffect(t, f, before, out)
		if required.Load() == 0 || evaluated.Load() == 0 {
			t.Fatal("retained denial bypassed selected built-in policy")
		}
	})
	t.Run("current configured positive", func(t *testing.T) {
		f := operationalSeedIntent(t)
		service := operationalProofService(t, f, func(s *Service) {
			configureConfiguredStaticScriptLiteralDenyService(s, "not-present-in-fixture")
		})
		out := service.handoffOperational(context.Background(), f.reopen(), f.domain.caller, f.raw)
		if state := operationalPrestageStateAt(t, f); out.kind != operationalAccepted || state.Posts != 1 {
			t.Fatalf("configured positive: result=%+v state=%+v", out, state)
		}
	})
	t.Run("current artifact revocation", func(t *testing.T) {
		f := operationalSeedIntent(t)
		original := operationalV2Original(t, f)
		service := operationalProofService(t, f, func(s *Service) {
			s.trustModel.ArtifactPolicy.RevokedArtifacts = append(s.trustModel.ArtifactPolicy.RevokedArtifacts,
				original.resolved.plan.artifactDigest)
		})
		before := operationalPrestageStateAt(t, f)
		out := service.handoffOperational(context.Background(), f.reopen(), f.domain.caller, f.raw)
		assertOperationalNoFurtherEffect(t, f, before, out)
	})
	t.Run("current signer revocation", func(t *testing.T) {
		f := operationalSeedIntent(t)
		var record evidencev1.ArtifactEvidence
		if err := json.Unmarshal([]byte(f.expectedEvidence), &record); err != nil {
			t.Fatal(err)
		}
		service := operationalProofService(t, f, func(s *Service) {
			s.trustModel.SignerPolicy.RevokedSigners = append(s.trustModel.SignerPolicy.RevokedSigners, record.Seal.KeyID)
		})
		if err := evidencev1.Verify(record, service.operationalAdmission.verifier.keyID,
			service.operationalAdmission.verifier.algorithm, service.operationalAdmission.verifier.publicKey); err != nil {
			t.Fatalf("revoked signer signature precondition: %v", err)
		}
		before := operationalPrestageStateAt(t, f)
		out := service.handoffOperational(context.Background(), f.reopen(), f.domain.caller, f.raw)
		assertOperationalNoFurtherEffect(t, f, before, out)
	})
	t.Run("fresh ordinary policy denial", func(t *testing.T) {
		f := makeOperationalFixture(t, "")
		configureConfiguredStaticScriptLiteralDenyService(f.service, "policy-fixture-ok")
		out := f.submit()
		state := operationalPrestageStateAt(t, f)
		if out.kind != operationalUnavailable || state.Claims != 0 || state.Posts != 0 {
			t.Fatalf("ordinary fresh denial: result=%+v state=%+v", out, state)
		}
	})
	t.Run("fresh ordinary revocation denial", func(t *testing.T) {
		f := makeOperationalFixture(t, "")
		caller, err := newSyntheticCallerFact(f.domain.caller.String())
		if err != nil {
			t.Fatal(err)
		}
		delivery, err := parsePrivateReplayDelivery(f.raw, caller)
		if err != nil {
			t.Fatal(err)
		}
		f.service.trustModel.ArtifactPolicy.RevokedArtifacts = append(f.service.trustModel.ArtifactPolicy.RevokedArtifacts,
			delivery.originalIntent.artifactDigest)
		out := f.submit()
		if state := operationalPrestageStateAt(t, f); out.kind != operationalUnavailable || state.Claims != 0 || state.Posts != 0 {
			t.Fatalf("fresh ordinary revocation: result=%+v state=%+v", out, state)
		}
	})
}

func TestPR12ReceiptAdmissionIndependence(t *testing.T) {
	t.Run("accepted retired key closed stage", func(t *testing.T) {
		f := makeOperationalFixture(t, "")
		first := f.submit()
		if first.kind != operationalAccepted || !first.receipt.Valid() {
			t.Fatal("accepted v2 setup")
		}
		if _, err := f.db.Exec("UPDATE reliable_submit_key_registry SET state=2"); err != nil {
			t.Fatal(err)
		}
		d := f.reopen()
		if err := d.stage.close(); err != nil {
			t.Fatal(err)
		}
		before := operationalPrestageStateAt(t, f)
		out := (&Service{}).recoverOperational(context.Background(), d, d.caller, f.raw)
		after := operationalPrestageStateAt(t, f)
		if out.kind != operationalAccepted || !out.receipt.Equal(first.receipt) || out.run != first.run ||
			after.Posts != before.Posts || after.Gets != before.Gets {
			t.Fatalf("receipt used current admission/effects: result=%+v before=%+v after=%+v", out, before, after)
		}
		if _, err := f.db.Exec("UPDATE reliable_submit_key_registry SET state=3 WHERE purpose=1"); err != nil {
			t.Fatal(err)
		}
		refused := (&Service{}).recoverOperational(context.Background(), d, d.caller, f.raw)
		if refused.kind != operationalUnavailable || refused.run != "" || refused.receipt.Valid() {
			t.Fatalf("revoked original key disclosed receipt: %+v", refused)
		}
	})
	t.Run("marked positive reconciliation", func(t *testing.T) {
		f := makeOperationalFixture(t, "")
		if err := f.domain.custody.ConfigureOperationalCommitFaultForProof(reliablesubmit.OperationalAccept, true); err != nil {
			t.Fatal(err)
		}
		first := f.submit()
		if first.kind != operationalAmbiguous {
			t.Fatalf("marked v2 seed: %+v", first)
		}
		before := operationalPrestageStateAt(t, f)
		out := (&Service{}).recoverOperational(context.Background(), f.reopen(), f.domain.caller, f.raw)
		after := operationalPrestageStateAt(t, f)
		if out.kind != operationalAccepted || !out.receipt.Valid() || after.Posts != before.Posts || after.Revision != 6 {
			t.Fatalf("marker-only reconciliation: result=%+v before=%+v after=%+v", out, before, after)
		}
	})
}

func TestOperationalRetainedAdmissionEvidenceV2(t *testing.T) {
	f := makeOperationalFixture(t, "")
	original := operationalV2Original(t, f)
	if original.variant != operationalOriginalV2 || original.resolved.provenanceRecord != f.expectedEvidence ||
		!bytes.Contains(original.wire, []byte("operational_local_v2")) ||
		!bytes.Contains(original.wire, []byte(f.expectedEvidence)) {
		t.Fatal("full signed evidence was not retained in v2 leaf")
	}
	verified, err := verifyOperationalOriginal(original.wire, f.domain.keys, f.domain.realm)
	if err != nil || verified.variant != operationalOriginalV2 || verified.resolved.provenanceRecord != f.expectedEvidence {
		t.Fatalf("v2 exact reader: %v", err)
	}
	if reason := f.service.qualifyOperationalRetained(context.Background(), verified, f.domain.realm); reason != reliablesubmit.OperationalReasonNone {
		t.Fatalf("valid retained input denied: %d", reason)
	}
	for name, record := range map[string]string{
		"claims only":         `{"claims":{}}`,
		"unknown member":      strings.TrimSuffix(f.expectedEvidence, "}") + `,"unknown":1}`,
		"trailing value":      f.expectedEvidence + ` {}`,
		"trailing whitespace": f.expectedEvidence + " ",
		"duplicate member":    strings.TrimSuffix(f.expectedEvidence, "}") + `,"seal":{}}`,
		"over cap":            strings.Repeat("x", maxOperationalEvidenceBytes+1),
		"invalid UTF8":        string([]byte{0xff}),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeOperationalEvidence(record); err == nil {
				t.Fatal("noncanonical evidence accepted")
			}
		})
	}
	var tampered evidencev1.ArtifactEvidence
	if err := json.Unmarshal([]byte(f.expectedEvidence), &tampered); err != nil {
		t.Fatal(err)
	}
	tampered.Seal.Signature = strings.Repeat("A", len(tampered.Seal.Signature))
	changed, err := json.Marshal(tampered)
	if err != nil {
		t.Fatal(err)
	}
	mutant := original
	mutant.resolved.provenanceRecord = string(changed)
	if reason := f.service.qualifyOperationalRetained(context.Background(), mutant, f.domain.realm); reason != reliablesubmit.OperationalIntegrity {
		t.Fatalf("signature mutant reason=%d", reason)
	}
	verifier := f.service.operationalAdmission.verifier
	resign := func(record *evidencev1.ArtifactEvidence) string {
		t.Helper()
		canonical, err := record.Claims.CanonicalBytes()
		if err != nil {
			t.Fatalf("synthetic contradiction claims: %v", err)
		}
		record.Seal = evidencev1.NewSeal(canonical, verifier.keyID, verifier.algorithm,
			base64.StdEncoding.EncodeToString(ed25519.Sign(ed25519.PrivateKey(f.signerPrivateKey), canonical)))
		if err := record.Validate(); err != nil {
			t.Fatalf("synthetic contradiction is not a valid record: %v", err)
		}
		if err := evidencev1.Verify(*record, verifier.keyID, verifier.algorithm, verifier.publicKey); err != nil {
			t.Fatalf("synthetic contradiction is not validly signed under retained verifier: %v", err)
		}
		encoded, err := json.Marshal(record)
		if err != nil {
			t.Fatal(err)
		}
		return string(encoded)
	}
	var positive evidencev1.ArtifactEvidence
	if err := json.Unmarshal([]byte(f.expectedEvidence), &positive); err != nil {
		t.Fatal(err)
	}
	if got := resign(&positive); got != f.expectedEvidence || !operationalEvidenceMatchesOriginal(positive, original, f.domain.realm) {
		t.Fatal("matching signed evidence did not meet the same retained association")
	}
	for name, alter := range map[string]func(*evidencev1.ArtifactEvidence){
		"artifact digest": func(e *evidencev1.ArtifactEvidence) {
			identity, _ := evidencev1.NewArtifactIdentity(e.Claims.Package.Identity.PayloadDigest,
				e.Claims.Package.Identity.ArtifactType, "sha256:"+strings.Repeat("0", 64))
			e.Claims.Package.Identity = identity
		},
		"payload digest": func(e *evidencev1.ArtifactEvidence) {
			identity, _ := evidencev1.NewArtifactIdentity("sha256:"+strings.Repeat("0", 64),
				e.Claims.Package.Identity.ArtifactType, e.Claims.Package.Identity.IntentDigest)
			e.Claims.Package.Identity = identity
		},
		"derivation": func(e *evidencev1.ArtifactEvidence) {
			e.Claims.Admission.Authorization.Derivation.DerivationSpecDigest = "sha256:" + strings.Repeat("0", 64)
		},
		"output": func(e *evidencev1.ArtifactEvidence) { e.Claims.Admission.Authorization.Derivation.OutputID = "other" },
		"artifact type": func(e *evidencev1.ArtifactEvidence) {
			identity, _ := evidencev1.NewArtifactIdentity(e.Claims.Package.Identity.PayloadDigest,
				"other", e.Claims.Package.Identity.IntentDigest)
			e.Claims.Package.Identity = identity
		},
		"network": func(e *evidencev1.ArtifactEvidence) { e.Claims.Admission.Execution.Access.NetworkAccess = true },
		"capability": func(e *evidencev1.ArtifactEvidence) {
			e.Claims.Admission.Execution.Runtime.RequiredCapabilities = []string{"NET_ADMIN"}
		},
	} {
		t.Run(name, func(t *testing.T) {
			var record evidencev1.ArtifactEvidence
			if err := json.Unmarshal([]byte(f.expectedEvidence), &record); err != nil {
				t.Fatal(err)
			}
			alter(&record)
			candidate := original
			candidate.resolved.provenanceRecord = resign(&record)
			if operationalEvidenceMatchesOriginal(record, candidate, f.domain.realm) {
				t.Fatal("contradiction did not isolate retained evidence/plan/material association")
			}
			if reason := f.service.qualifyOperationalRetained(context.Background(), candidate, f.domain.realm); reason != reliablesubmit.OperationalIntegrity {
				t.Fatalf("contradictory retained evidence reason=%d", reason)
			}
			wire := operationalVectorReplaceProvenance(t, original.wire, "operational_local_v2", []byte(candidate.resolved.provenanceRecord))
			if _, err := verifyOperationalOriginal(wire, f.domain.keys, f.domain.realm); err == nil {
				t.Fatal("structural reader accepted validly signed but mismatched evidence")
			}
		})
	}
	t.Run("target syntax refused before association", func(t *testing.T) {
		invalid := positive
		invalid.Claims.Admission.Execution.Workload.TargetPlatform = "linux"
		if _, err := invalid.Claims.CanonicalBytes(); err == nil {
			t.Fatal("unsupported target unexpectedly passed shared Claims syntax")
		}
	})
	for name, alter := range map[string]func(*verifiedOperationalOriginal){
		"material bytes": func(v *verifiedOperationalOriginal) {
			v.resolved.material.payloadBytes = bytes.Clone(v.resolved.material.payloadBytes)
			v.resolved.material.payloadBytes[0] ^= 1
		},
		"plan payload": func(v *verifiedOperationalOriginal) {
			v.resolved.plan.payloadDigest = "sha256:" + strings.Repeat("0", 64)
		},
		"profile": func(v *verifiedOperationalOriginal) { v.resolved.plan.runtimeProfile.name = "other" },
		"argv":    func(v *verifiedOperationalOriginal) { v.delivery.originalIntent.argv.value = []string{"other"} },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := original
			signed := positive
			candidate.resolved.provenanceRecord = resign(&signed)
			alter(&candidate)
			if err := evidencev1.Verify(signed, verifier.keyID, verifier.algorithm, verifier.publicKey); err != nil {
				t.Fatalf("unchanged retained signature precondition: %v", err)
			}
			if operationalEvidenceMatchesOriginal(signed, candidate, f.domain.realm) {
				t.Fatal("frozen contradiction did not isolate association")
			}
			if reason := f.service.qualifyOperationalRetained(context.Background(), candidate, f.domain.realm); reason != reliablesubmit.OperationalIntegrity {
				t.Fatalf("contradictory frozen input reason=%d", reason)
			}
		})
	}
	tampered.Claims.Package.Identity.PayloadDigest = strings.Repeat("0", len(tampered.Claims.Package.Identity.PayloadDigest))
	changed, _ = json.Marshal(tampered)
	mutant.resolved.provenanceRecord = string(changed)
	if _, err := encodeOperationalOriginal(mutant.delivery, mutant.resolved, mutant.assessment, f.domain.keys, f.domain.realm); err == nil {
		t.Fatal("contradictory evidence and frozen material encoded")
	}
	variantMutant := bytes.Replace(bytes.Clone(original.wire), []byte("operational_local_v2"), []byte("operational_local_v3"), 1)
	if _, err := verifyOperationalOriginal(variantMutant, f.domain.keys, f.domain.realm); err == nil {
		t.Fatal("unknown authenticated variant accepted")
	}
	var boundary evidencev1.ArtifactEvidence
	if err := json.Unmarshal([]byte(f.expectedEvidence), &boundary); err != nil {
		t.Fatal(err)
	}
	baseline, err := json.Marshal(boundary)
	if err != nil {
		t.Fatal(err)
	}
	boundary.Claims.Package.Publication.BuilderService += strings.Repeat("x", maxOperationalEvidenceBytes-len(baseline))
	exact, err := json.Marshal(boundary)
	if err != nil || len(exact) != maxOperationalEvidenceBytes {
		t.Fatalf("cap vector length=%d err=%v", len(exact), err)
	}
	if _, err := decodeOperationalEvidence(string(exact)); err != nil {
		t.Fatalf("exact cap rejected: %v", err)
	}
}

func TestOperationalAdmissionCommissioning(t *testing.T) {
	f := makeOperationalFixture(t, "")
	realm := f.domain.realm
	initialTrust := snapshotRuntimeTrustModel(f.service.operationalAdmission.trust)
	initialVerifier := bytes.Clone(f.service.operationalAdmission.verifier.publicKey)
	f.service.trustModel.ArtifactPolicy.RevokedArtifacts = append(f.service.trustModel.ArtifactPolicy.RevokedArtifacts,
		"sha256:"+strings.Repeat("a", 64))
	f.service.provenanceVerifier.publicKey[0] ^= 0xff
	if !reflect.DeepEqual(initialTrust, f.service.operationalAdmission.trust) ||
		!bytes.Equal(initialVerifier, f.service.operationalAdmission.verifier.publicKey) {
		t.Fatal("commissioned trust or verifier aliased caller input")
	}
	if err := f.service.commissionOperationalAdmission(realm); err == nil {
		t.Fatal("second commission accepted")
	}
	if _, ok := (&Service{operationalAdmission: f.service.operationalAdmission}).currentOperationalAdmission(realm); ok {
		t.Fatal("foreign Service borrowed authority")
	}
	copyTrust := snapshotRuntimeTrustModel(*f.service.trustModel)
	copyVerifier := *f.service.provenanceVerifier
	precommission := &Service{trustModel: &copyTrust, provenanceVerifier: &copyVerifier, trustModelVerified: true}
	precommission.trustModelOwner = precommission
	// An exact struct copy of the unlocked precommission Service. Reflection
	// keeps vet's copylocks check enabled for every ordinary assignment.
	copied := new(Service)
	reflect.ValueOf(copied).Elem().Set(reflect.ValueOf(precommission).Elem())
	if copied.trustModelOwner != precommission || copied.trustModel != precommission.trustModel ||
		!copied.trustModelVerified || copied.provenanceVerifier != precommission.provenanceVerifier {
		t.Fatal("copy fixture did not reproduce the precommission Service")
	}
	if err := copied.commissionOperationalAdmission(realm); err == nil {
		t.Fatal("copied precommission Service acquired authority")
	}
	tooLargeTrust := snapshotRuntimeTrustModel(*f.service.trustModel)
	for i := 0; i < 3600; i++ {
		tooLargeTrust.ArtifactPolicy.RevokedArtifacts = append(tooLargeTrust.ArtifactPolicy.RevokedArtifacts,
			fmt.Sprintf("sha256:%064x", i))
	}
	oversized := &Service{trustModel: &tooLargeTrust, provenanceVerifier: &copyVerifier, trustModelVerified: true}
	oversized.trustModelOwner = oversized
	if err := oversized.commissionOperationalAdmission(realm); err == nil {
		t.Fatal("oversized trust representation acquired writer authority")
	}
	other := realm
	other.epoch++
	if _, ok := f.service.currentOperationalAdmission(other); ok {
		t.Fatal("old authority crossed epoch")
	}
	if err := f.service.Initialize(context.Background()); err == nil {
		t.Fatal("Initialize replaced commissioned trust")
	}
	for name, configure := range map[string]func(*Service){
		"no trust":              func(s *Service) { s.trustModel = nil },
		"unverified trust":      func(s *Service) { s.trustModelVerified = false },
		"no verifier":           func(s *Service) { s.provenanceVerifier = nil },
		"unsupported evaluator": func(s *Service) { s.admissionPolicyEvaluator = &rejectAllPolicy{} },
		"nested evaluator": func(s *Service) {
			s.admissionPolicyEvaluator = admissionPolicySet{policies: []AdmissionPolicyEvaluator{admissionPolicySet{policies: []AdmissionPolicyEvaluator{selectedDestructiveShellCommandPolicy{}}}}}
		},
		"mismatched built-in": func(s *Service) {
			configureConfiguredStaticScriptLiteralDenyService(s, "policy-fixture-ok")
			s.admissionPolicyEvaluator = defaultAdmissionPolicyEvaluator()
		},
	} {
		t.Run(name, func(t *testing.T) {
			trust := snapshotRuntimeTrustModel(*f.service.trustModel)
			verifier := *f.service.provenanceVerifier
			s := &Service{trustModel: &trust, provenanceVerifier: &verifier, trustModelVerified: true}
			s.trustModelOwner = s
			configure(s)
			if err := s.commissionOperationalAdmission(realm); err == nil {
				t.Fatal("unsupported commission accepted")
			}
		})
	}
	configured := operationalProofService(t, f, func(s *Service) {
		configureConfiguredStaticScriptLiteralDenyService(s, "immutable-marker")
	})
	selected := configured.operationalAdmission.policy.policies[1].(configuredStaticScriptLiteralDenyPolicy)
	configured.cfg.AdmissionPolicy.ConfiguredStaticScriptLiteralDeny.Entries[0].Literal = "mutated-config"
	outer := configured.admissionPolicyEvaluator.(admissionPolicySet)
	aliased := outer.policies[1].(configuredStaticScriptLiteralDenyPolicy)
	aliased.entries[0].literal = "mutated-evaluator"
	if selected.entries[0].literal != "immutable-marker" ||
		configured.operationalAdmission.policy.policies[1].(configuredStaticScriptLiteralDenyPolicy).entries[0].literal != "immutable-marker" {
		t.Fatal("commissioned policy entries aliased config or ordinary evaluator")
	}
	if !f.service.withdrawOperationalEffects() || !f.service.withdrawOperationalEffects() {
		t.Fatal("withdrawal did not remain monotonic")
	}
	if _, ok := f.service.currentOperationalAdmission(realm); ok || f.service.commissionOperationalAdmission(realm) == nil {
		t.Fatal("withdrawn authority was reenabled")
	}
	t.Run("Initialize fetch cannot overwrite racing commission", func(t *testing.T) {
		trust := snapshotRuntimeTrustModel(initialTrust)
		verifier := *f.service.provenanceVerifier
		s := &Service{trustModel: &trust, provenanceVerifier: &verifier, trustModelVerified: true}
		s.trustModelOwner = s
		public, private, err := ed25519.GenerateKey(nil)
		if err != nil {
			t.Fatal(err)
		}
		s.trustModelVerifier = &ed25519Verifier{algorithm: "ed25519", keyID: "synthetic-egs", publicKey: public}
		remote := egsmodel.RuntimeTrustPolicy{SignerPolicy: egsmodel.SignerPolicy{AllowedSigners: []string{"other-signer"}}}
		canonical, err := remote.CanonicalBytes()
		if err != nil {
			t.Fatal(err)
		}
		envelope := signedRuntimeTrustResponse{RuntimeTrust: remote, Algorithm: "ed25519", KeyID: "synthetic-egs",
			PayloadDigest: digestBytes(canonical), Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(private, canonical))}
		entered, release := make(chan struct{}), make(chan struct{})
		s.egsClient = newResolvedPlanDependencyClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/v1/trust-model" {
				t.Errorf("unexpected path %s", r.URL.Path)
			}
			close(entered)
			<-release
			writeJSONResponse(t, w, http.StatusOK, envelope)
		}))
		s.egsClient.client.Timeout = 5 * time.Second
		result := make(chan error, 1)
		go func() { result <- s.Initialize(context.Background()) }()
		select {
		case <-entered:
		case <-time.After(5 * time.Second):
			t.Fatal("Initialize did not enter trust fetch")
		}
		if err := s.commissionOperationalAdmission(realm); err != nil {
			t.Fatalf("racing commission: %v", err)
		}
		close(release)
		select {
		case err := <-result:
			if err == nil || !strings.Contains(err.Error(), "commissioned during trust load") {
				t.Fatalf("Initialize overwrote commission: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("Initialize did not finish after release")
		}
		if !reflect.DeepEqual(*s.trustModel, trust) {
			t.Fatal("racing Initialize replaced commissioned trust")
		}
	})
}

type rejectAllPolicy struct{}

func (*rejectAllPolicy) RequiredInputClasses(AdmissionPolicyContext) []AdmissionPolicyInputClass {
	return nil
}
func (*rejectAllPolicy) Evaluate(context.Context, AdmissionPolicyContext) AdmissionPolicyDecision {
	return DenyAdmissionPolicyDecision("unsupported", "unsupported", "unsupported")
}

func TestOperationalRetainedAdmissionInputs(t *testing.T) {
	t.Run("observer argv isolation at evaluation cut", func(t *testing.T) {
		data, err := os.ReadFile("reliable_submit_operational_admission.go")
		if err != nil {
			t.Fatal(err)
		}
		const required = "observed := policyCtx\n\t\tobserved.InvocationArgv = slices.Clone(policyCtx.InvocationArgv)\n\t\tsnapshot.proof.contextObserved(observed)\n\t}\n\tdecision := snapshot.policy.Evaluate(ctx, policyCtx)"
		if !strings.Contains(string(data), required) {
			t.Fatal("observer argv copy is not immediately before built-in evaluation")
		}
		mutant := strings.Replace(string(data), "slices.Clone(policyCtx.InvocationArgv)", "policyCtx.InvocationArgv", 1)
		if strings.Contains(mutant, required) {
			t.Fatal("observer argv alias mutation escaped the isolation guard")
		}
	})
	f := makeOperationalFixture(t, "")
	original := operationalV2Original(t, f)
	all := []AdmissionPolicyInputClass{AdmissionPolicyInputInvocationArgv, AdmissionPolicyInputArtifactEvidenceMetadata,
		AdmissionPolicyInputRuntimeProfileMetadata, AdmissionPolicyInputPayloadDigestAndByteCount,
		AdmissionPolicyInputStaticScriptPayloadText}
	policyCtx := AdmissionPolicyContext{}
	if !completeOperationalPolicyInputs(&policyCtx, all, original.resolved.material.payloadBytes) ||
		policyCtx.PayloadByteCount != int64(len(original.resolved.material.payloadBytes)) ||
		!policyCtx.StaticScriptPayloadTextPresent || !strings.Contains(policyCtx.StaticScriptPayloadText, "policy-fixture-ok") {
		t.Fatal("all five retained input classes were not supplied from frozen material")
	}
	if completeOperationalPolicyInputs(&policyCtx, []AdmissionPolicyInputClass{"future_input"}, original.resolved.material.payloadBytes) ||
		completeOperationalPolicyInputs(&policyCtx, all, nil) {
		t.Fatal("unavailable retained input admitted")
	}
	if reason := f.service.qualifyOperationalRetained(context.Background(), original, f.domain.realm); reason != reliablesubmit.OperationalReasonNone {
		t.Fatalf("built-in retained input denied: %d", reason)
	}
	if f.required.Load() == 0 || f.evaluated.Load() == 0 {
		t.Fatal("actual built-in policy was not observed")
	}
	t.Run("populated retained context at built-in Evaluate", func(t *testing.T) {
		retained := operationalSeedIntent(t, "--audit-only")
		retainedOriginal := operationalV2Original(t, retained)
		retained.required.Store(0)
		retained.evaluated.Store(0)
		var observations []AdmissionPolicyContext
		retained.service.operationalAdmission.proof.contextObserved = func(value AdmissionPolicyContext) {
			copyOfValue := value
			copyOfValue.InvocationArgv = append([]string(nil), value.InvocationArgv...)
			observations = append(observations, copyOfValue)
			value.InvocationArgv[0] = "observer-mutated-copy"
		}
		// A retained continuation has no ARS, EGS or resolver dependency.
		retained.service.arsClient = nil
		retained.service.egsClient = nil
		before := operationalPrestageStateAt(t, retained)
		out := retained.service.handoffOperational(context.Background(), retained.reopen(), retained.domain.caller, retained.raw)
		if out.kind != operationalAccepted || len(observations) == 0 || retained.required.Load() != int32(len(observations)) || retained.evaluated.Load() != int32(len(observations)) {
			t.Fatalf("eligible retained built-in policy context not observed: kind=%d seen=%d required=%d evaluated=%d", out.kind, len(observations), retained.required.Load(), retained.evaluated.Load())
		}
		var signed evidencev1.ArtifactEvidence
		if err := json.Unmarshal([]byte(retained.expectedEvidence), &signed); err != nil {
			t.Fatal(err)
		}
		expected := AdmissionPolicyContext{
			InvocationArgv:   []string{"--audit-only"},
			ArtifactDigest:   signed.Claims.Package.Identity.ArtifactDigest,
			PayloadDigest:    signed.Claims.Package.Identity.PayloadDigest,
			PayloadByteCount: int64(len(retainedOriginal.resolved.material.payloadBytes)),
			ArtifactType:     "static-script", RuntimeProfileName: "static-script/default",
			TargetPlatform: "docker", NetworkAccess: false,
			StaticScriptPayloadText:        "#!/bin/sh\nprintf '%s\\n' policy-fixture-ok\n",
			StaticScriptPayloadTextPresent: true,
		}
		for _, observed := range observations {
			if !reflect.DeepEqual(observed, expected) {
				t.Fatalf("retained policy context: observed=%+v expected=%+v", observed, expected)
			}
		}
		if before.Posts != 0 || operationalPrestageStateAt(t, retained).Posts != 1 {
			t.Fatal("retained context flow had unexpected effect count")
		}
	})
}

func TestOperationalAdmissionWithdrawalCuts(t *testing.T) {
	for _, tc := range []struct {
		name, hook            string
		wantRevision          int
		wantStage, wantMarker bool
	}{
		{"before prestage", "prestage", 3, false, false},
		{"after stage create", "stamp", 3, true, false},
		{"before marker", "marker", 4, true, false},
		{"after marker before sender", "consume", 5, true, true},
		{"final protected sample", "entry", 5, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := operationalSeedIntent(t)
			d := f.reopen()
			var reached atomic.Bool
			withdraw := func() { reached.Store(true); f.service.withdrawOperationalEffects() }
			d.proof = &operationalHandoffProofHooks{}
			switch tc.hook {
			case "prestage":
				d.proof.beforePrestage = withdraw
			case "stamp":
				d.proof.beforeStamp = withdraw
			case "marker":
				d.proof.beforeMarker = withdraw
			case "consume":
				d.proof.beforeConsume = func(*liveSender, *handoffOwner) { withdraw() }
			case "entry":
				d.proof.beforeEntrySample = withdraw
			}
			out := f.service.handoffOperational(context.Background(), d, d.caller, f.raw)
			state := operationalPrestageStateAt(t, f)
			if !reached.Load() || out.kind != operationalUnavailable || out.run != "" || out.receipt.Valid() ||
				state.Revision != tc.wantRevision || (state.StageEntries != 0) != tc.wantStage ||
				state.Marker != tc.wantMarker || state.Posts != 0 {
				t.Fatalf("withdrawal cut result=%+v state=%+v", out, state)
			}
		})
	}
	t.Run("postcommit stage requalification withdrawal", func(t *testing.T) {
		f := operationalSeedIntent(t)
		d := f.reopen()
		reached := false
		beforeStagingHandoffValidationForTest = func(*stagingCustody) {
			var revision int
			if f.db.QueryRow("SELECT revision FROM reliable_submit_claims WHERE codec_version=5").Scan(&revision) == nil && revision == 5 {
				reached = true
				f.service.withdrawOperationalEffects()
			}
		}
		defer func() { beforeStagingHandoffValidationForTest = nil }()
		out := f.service.handoffOperational(context.Background(), d, d.caller, f.raw)
		state := operationalPrestageStateAt(t, f)
		if !reached || out.kind != operationalUnavailable || out.run != "" ||
			out.operation != reliablesubmit.OperationalMark || out.write != reliablesubmit.OperationalMarkerDirect ||
			state.Revision != 5 || !state.Marker || state.Posts != 0 {
			t.Fatalf("postcommit stage withdrawal: kind=%d run=%q op=%d write=%d reason=%d state=%+v reached=%t", out.kind, out.run, out.operation, out.write, out.reason, state, reached)
		}
	})
	t.Run("postcommit release qualifier", func(t *testing.T) {
		f := operationalSeedIntent(t)
		d := f.reopen()
		armed, calls := false, 0
		d.proof = &operationalHandoffProofHooks{beforeMarker: func() { armed = true }}
		f.service.operationalAdmission.proof.evaluated = func(bool) {
			if armed {
				calls++
				if calls == 2 {
					f.service.withdrawOperationalEffects()
				}
			}
		}
		out := f.service.handoffOperational(context.Background(), d, d.caller, f.raw)
		state := operationalPrestageStateAt(t, f)
		if calls != 2 || out.kind != operationalUnavailable || out.run != "" ||
			out.operation != reliablesubmit.OperationalMark || out.write != reliablesubmit.OperationalAppliedReleaseFailed ||
			state.Revision != 5 || !state.Marker || state.Posts != 0 {
			t.Fatalf("postcommit admission withdrawal: kind=%d run=%q op=%d write=%d reason=%d state=%+v calls=%d", out.kind, out.run, out.operation, out.write, out.reason, state, calls)
		}
	})
	t.Run("withdrawal after admitted POST entry", func(t *testing.T) {
		f := makeOperationalFixture(t, "")
		f.receiver.entered = make(chan struct{}, 1)
		f.receiver.release = make(chan struct{})
		defer func() {
			select {
			case <-f.receiver.release:
			default:
				close(f.receiver.release)
			}
		}()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		completed := make(chan operationalHandoffResult, 1)
		go func() { completed <- f.service.handoffOperational(ctx, f.domain, f.domain.caller, f.raw) }()
		select {
		case <-f.receiver.entered:
		case <-ctx.Done():
			t.Fatal("POST did not enter before withdrawal")
		}
		if !f.service.withdrawOperationalEffects() {
			t.Fatal("withdrawal unavailable")
		}
		close(f.receiver.release)
		select {
		case out := <-completed:
			if state := operationalPrestageStateAt(t, f); out.kind != operationalAccepted || state.Posts != 1 || !state.Marker {
				t.Fatalf("already entered POST was retracted: result=%+v state=%+v", out, state)
			}
		case <-ctx.Done():
			t.Fatal("entered POST did not complete")
		}
	})
}

func TestOperationalAdmissionV1Compatibility(t *testing.T) {
	t.Run("nonempty historical sequence is storage-shaped but admission-refused", func(t *testing.T) {
		f := makeOperationalFixture(t, "")
		legacy := operationalV2Original(t, f)
		legacy.resolved.provenanceRecord = ""
		wire, err := encodeOperationalOriginal(legacy.delivery, legacy.resolved, legacy.assessment, f.domain.keys, f.domain.realm)
		if err != nil {
			t.Fatal(err)
		}
		member := operationalVectorObject([]byte("synthetic"), []byte("record"), []byte("owner"))
		sequence := binary.BigEndian.AppendUint16(nil, 1)
		sequence = binary.BigEndian.AppendUint32(sequence, uint32(len(member)))
		sequence = append(sequence, member...)
		mutant := operationalVectorReplaceProvenance(t, wire, "operational_local_v1", sequence)
		if _, err := reliablesubmit.MatchOperationalOriginal(legacy.delivery.refs.claimID, legacy.assessment.boundPlan, mutant); err != nil {
			t.Fatalf("inherited custody shape refused structurally valid nonempty v1: %v", err)
		}
		if _, err := verifyOperationalOriginal(mutant, f.domain.keys, f.domain.realm); err == nil {
			t.Fatal("admission accepted nonempty historical v1 whole wire")
		}
		if got := f.domain.custody.EstablishOperational(context.Background(), legacy.delivery.refs.claimID,
			legacy.assessment.boundPlan, f.domain.keys.storage, mutant).Disposition(); got != reliablesubmit.OperationalApplied {
			t.Fatalf("custody refused structural nonempty v1 proof: %d", got)
		}
		before := operationalPrestageStateAt(t, f)
		assertOperationalNoFurtherEffect(t, f, before, f.submit())
	})
	f := makeOperationalFixture(t, "")
	original := operationalV2Original(t, f)
	legacy := original
	legacy.resolved.provenanceRecord = ""
	// The test-only full TLV/PB1 builder follows the published 8058561 v1
	// layout, including its empty provenance sequence and original commitments.
	historical := operationalVectorWire(t, f, original, "")
	wire, err := encodeOperationalOriginal(legacy.delivery, legacy.resolved, legacy.assessment, f.domain.keys, f.domain.realm)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(wire, historical) {
		t.Fatalf("historical v1 full-wire/PB1 oracle changed: expected=%d actual=%d", len(historical), len(wire))
	}
	wire = historical
	read, err := verifyOperationalOriginal(wire, f.domain.keys, f.domain.realm)
	if err != nil || read.variant != operationalOriginalV1 || !bytes.Contains(wire, []byte("operational_local_v1")) {
		t.Fatalf("historical exact reader: %v", err)
	}
	if !reflect.DeepEqual(wire, read.wire) {
		t.Fatal("historical bytes changed during read")
	}
	if reason := f.service.qualifyOperationalRetained(context.Background(), read, f.domain.realm); reason != reliablesubmit.OperationalUnavailable {
		t.Fatalf("unmarked v1 granted current first effect: %d", reason)
	}
	if got := f.domain.custody.EstablishOperational(context.Background(), legacy.delivery.refs.claimID,
		legacy.assessment.boundPlan, f.domain.keys.storage, wire).Disposition(); got != reliablesubmit.OperationalApplied {
		t.Fatalf("legacy proof establishment=%d", got)
	}
	before := operationalPrestageStateAt(t, f)
	out := f.submit()
	assertOperationalNoFurtherEffect(t, f, before, out)
	t.Run("stamped but unmarked", func(t *testing.T) {
		old, seed := operationalSeedHistoricalV1ForProof(t, false, true)
		atStamp := operationalPrestageStateAt(t, old)
		if seed.write != reliablesubmit.OperationalOwnCommitConfirmed || atStamp.Revision != 4 ||
			!atStamp.Stamp || atStamp.Marker || atStamp.StageEntries != 1 || atStamp.Posts != 0 {
			t.Fatalf("historical stamped seed: write=%d state=%+v", seed.write, atStamp)
		}
		refused := old.submit()
		assertOperationalNoFurtherEffect(t, old, atStamp, refused)
	})
	for _, rollback := range []bool{false, true} {
		name := "accepted"
		if rollback {
			name = "marked positive"
		}
		t.Run(name, func(t *testing.T) {
			old, seeded := operationalSeedHistoricalV1ForProof(t, rollback)
			if rollback && seeded.kind != operationalAmbiguous || !rollback && seeded.kind != operationalAccepted {
				t.Fatalf("historical v1 seed: %+v", seeded)
			}
			before := operationalPrestageStateAt(t, old)
			resumed := (&Service{}).recoverOperational(context.Background(), old.reopen(), old.domain.caller, old.raw)
			after := operationalPrestageStateAt(t, old)
			if resumed.kind != operationalAccepted || !resumed.receipt.Valid() ||
				after.Posts != before.Posts || after.Revision != 6 ||
				(!rollback && !resumed.receipt.Equal(seeded.receipt)) {
				t.Fatalf("historical v1 receipt/reconciliation: seed=%+v resumed=%+v before=%+v after=%+v", seeded, resumed, before, after)
			}
		})
	}
}

// A test-only historical writer makes a genuinely sealed v1 marker/receipt.
// The production handoff has no fresh-v1 writer path and refuses v1 first effects.
func operationalSeedHistoricalV1ForProof(t *testing.T, rollbackReceipt bool, stopAtStamp ...bool) (*operationalFixture, operationalHandoffResult) {
	t.Helper()
	f := makeOperationalFixture(t, "")
	base := operationalV2Original(t, f)
	legacy := base
	legacy.resolved.provenanceRecord = ""
	historical := operationalVectorWire(t, f, base, "")
	wire, err := encodeOperationalOriginal(legacy.delivery, legacy.resolved, legacy.assessment, f.domain.keys, f.domain.realm)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(wire, historical) {
		t.Fatal("historical v1 seed differs from independent complete byte/commitment oracle")
	}
	wire = historical
	legacy, err = verifyOperationalOriginal(wire, f.domain.keys, f.domain.realm)
	if err != nil || legacy.variant != operationalOriginalV1 {
		t.Fatalf("legacy test-only byte construction: %v", err)
	}
	if rollbackReceipt {
		if err := f.domain.custody.ConfigureOperationalCommitFaultForProof(reliablesubmit.OperationalAccept, true); err != nil {
			t.Fatal(err)
		}
	}
	if len(stopAtStamp) > 0 && stopAtStamp[0] {
		if err := f.domain.custody.ConfigureOperationalCommitFaultForProof(reliablesubmit.OperationalStamp, false); err != nil {
			t.Fatal(err)
		}
	}
	if got := f.domain.custody.EstablishOperational(context.Background(), legacy.delivery.refs.claimID,
		legacy.assessment.boundPlan, f.domain.keys.storage, wire).Disposition(); got != reliablesubmit.OperationalApplied {
		t.Fatalf("legacy original establishment=%d", got)
	}
	canonical, err := privateIncomingIntent(legacy.delivery)
	if err != nil {
		t.Fatal(err)
	}
	var result operationalHandoffResult
	read := f.domain.custody.WithOperationalOriginal(context.Background(), legacy.delivery.refs.claimID,
		f.domain.keys.storage, canonical, reliablesubmit.OperationalEstablishmentRead,
		func(*reliablesubmit.OperationalOriginalView) (reliablesubmit.OperationalOriginalMatch, error) {
			return reliablesubmit.MatchOperationalOriginal(legacy.delivery.refs.claimID, legacy.assessment.boundPlan, wire)
		}, func(access *reliablesubmit.OperationalAccess, projection reliablesubmit.OperationalProjection) {
			result = operationalAdvanceHistoricalV1ForProof(t, f.domain, access, projection, legacy, len(stopAtStamp) > 0 && stopAtStamp[0])
		})
	if read.Disposition() != reliablesubmit.OperationalCurrent {
		t.Fatalf("legacy authenticated borrow=%d reason=%d", read.Disposition(), read.Reason())
	}
	return f, result
}

func operationalAdvanceHistoricalV1ForProof(t *testing.T, d *operationalDomain, a *reliablesubmit.OperationalAccess,
	p reliablesubmit.OperationalProjection, original verifiedOperationalOriginal, stopAtStamp bool) operationalHandoffResult {
	t.Helper()
	ctx := context.Background()
	qualify := func() (reliablesubmit.OperationalOriginalMatch, error) {
		return reliablesubmit.MatchOperationalOriginal(original.delivery.refs.claimID, original.assessment.boundPlan, original.wire)
	}
	apply := func(current reliablesubmit.OperationalProjection, command reliablesubmit.OperationalCommand) reliablesubmit.OperationalProjection {
		t.Helper()
		mutation, err := reliablesubmit.NewOperationalMutation()
		if err != nil {
			t.Fatal(err)
		}
		status, next := a.Apply(ctx, current, mutation, command, qualify)
		if status != reliablesubmit.OperationalApplied {
			t.Fatalf("historical proof write status=%d", status)
		}
		return next
	}
	assign, err := reliablesubmit.NewAssignOperationalRun()
	if err != nil {
		t.Fatal(err)
	}
	p = apply(p, assign)
	runID, jobID, ok := p.Locator()
	if !ok {
		t.Fatal("legacy run assignment missing")
	}
	run := newResolvedRunProjection(original.resolved.plan, original.resolved.host, executionLocator{RunID: runID, jobID: jobID})
	job, err := d.provider.project(run, jobID)
	if err != nil {
		t.Fatal(err)
	}
	intent, err := a.BindOperationalIntent(p, job.locator)
	if err != nil {
		t.Fatal(err)
	}
	p = apply(p, intent)
	prestage := a.Prestage(ctx, p, qualify)
	if prestage.Disposition() != reliablesubmit.OperationalNoChange || prestage.Reason() != reliablesubmit.OperationalReasonNone {
		t.Fatalf("legacy pre-stage proof=%d/%d", prestage.Disposition(), prestage.Reason())
	}
	held, err := d.createOperationalStage(runID)
	if err != nil {
		t.Fatal(err)
	}
	defer held.close()
	if _, failure := materializeExecutionInputs(held, run, original.resolved.material); failure != nil {
		t.Fatal("legacy test-only materialization")
	}
	originalRef, intentRef, _, _, _ := p.Bindings()
	var parentLinks uint64
	first, err := measureOperationalStage(held, original.resolved.material, originalRef, runID, intentRef,
		job.project, &parentLinks, true)
	if err != nil {
		t.Fatal(err)
	}
	stage, err := a.BindOperationalStage(p, job.project, job.locator, first, func() ([]byte, error) {
		return measureOperationalStage(held, original.resolved.material, originalRef, runID, intentRef,
			job.project, &parentLinks, false)
	})
	if err != nil {
		t.Fatal(err)
	}
	if stopAtStamp {
		mutation, err := reliablesubmit.NewOperationalMutation()
		if err != nil {
			t.Fatal(err)
		}
		status, next := a.Apply(ctx, p, mutation, stage, qualify)
		if status != reliablesubmit.OperationalOwnCommitConfirmed {
			t.Fatalf("historical stamp uncertainty=%d", status)
		}
		return operationalReadProjection(next).withWrite(reliablesubmit.OperationalStamp, status)
	}
	p = apply(p, stage)
	mutation, err := reliablesubmit.NewOperationalMutation()
	if err != nil {
		t.Fatal(err)
	}
	marker, err := a.BindOperationalMarker(p, mutation, stage)
	if err != nil {
		t.Fatal(err)
	}
	body, err := job.request(job.carrierForMarker(d.keys.key.bytes, p, marker.Ref()))
	if err != nil {
		t.Fatal(err)
	}
	var ack operationalAck
	status, current := a.ApplyFirstMarker(ctx, p, mutation, marker, qualify, func(applied reliablesubmit.OperationalProjection) {
		if applied.Revision() != 5 {
			t.Fatal("historical marker callback lacked committed marker")
		}
		prepared, err := d.provider.prepareExchange(ctx, http.MethodPost, "/v1/jobs", body)
		if err != nil {
			t.Fatal(err)
		}
		defer prepared.cancel()
		ack = d.provider.register(prepared)
	})
	if status != reliablesubmit.OperationalMarkerDirect || ack.refused || ack.collision || ack.reason != reliablesubmit.OperationalReasonNone {
		t.Fatalf("historical direct marker/POST=%d ack=%+v", status, ack)
	}
	return d.reconcileOperational(ctx, a, current, job, ack)
}

func TestOperationalAdmissionCaptureIsSameResolution(t *testing.T) {
	f := makeOperationalFixture(t, "")
	var evidenceReads atomic.Int32
	client := f.service.arsClient.client
	base := client.Transport
	client.Transport = admissionCountTransport(func(r *http.Request) (*http.Response, error) {
		if strings.Contains(r.URL.Path, ":json") && !strings.Contains(r.URL.Path, "vault") {
			if strings.Contains(r.URL.Path, "/v1/blobs/") && !strings.Contains(r.URL.Path, testWorkloadZoneVaultConfigDigest) {
				evidenceReads.Add(1)
			}
		}
		return base.RoundTrip(r)
	})
	original := operationalV2Original(t, f)
	if original.resolved.provenanceRecord != f.expectedEvidence || evidenceReads.Load() != 1 {
		t.Fatalf("same-resolution full record capture: evidence reads=%d", evidenceReads.Load())
	}
	legacy := original.resolved
	legacy.provenanceRecord = ""
	if !reflect.DeepEqual(original.resolved.plan, legacy.plan) ||
		!reflect.DeepEqual(original.resolved.material, legacy.material) ||
		!reflect.DeepEqual(original.resolved.host, legacy.host) {
		t.Fatal("provenance carrier entered plan, PB1 material, or host")
	}
	if strings.Contains(reflect.TypeOf(original.resolved).String(), "ArtifactEvidence") {
		t.Fatal("resolved carrier aliases typed mutable evidence")
	}
	mutatedCopy := []byte(original.resolved.provenanceRecord)
	mutatedCopy[0] ^= 1
	if original.resolved.provenanceRecord != f.expectedEvidence {
		t.Fatal("retained immutable record aliased a caller byte slice")
	}
	if fmt.Sprintf("%+v", original) != privateExecutionValueRedaction ||
		fmt.Sprintf("%+v", preparedArtifact{provenanceRecord: original.resolved.provenanceRecord}) != privateExecutionValueRedaction {
		t.Fatal("full signed evidence escaped private formatting")
	}
}

type admissionCountTransport func(*http.Request) (*http.Response, error)

func (f admissionCountTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// A retry after the current admission inputs change is evaluated against the
// newly commissioned authority at the first remaining cut. Denial leaves the
// retained claim exactly where it was, and a later allowed retry still
// completes, so a denial neither advances nor poisons the claim.
func TestPR12RetryAfterPolicyChange(t *testing.T) {
	for _, seed := range []struct {
		name         string
		fault        reliablesubmit.OperationalOperation
		wantRevision int
		wantIntent   bool
	}{
		{"after run assignment", reliablesubmit.OperationalAssign, 2, false},
		{"after intent", reliablesubmit.OperationalIntent, 3, true},
	} {
		for _, change := range []struct {
			name      string
			configure func(*testing.T, *operationalFixture, *Service)
		}{
			{"configured literal denial", func(_ *testing.T, _ *operationalFixture, s *Service) {
				configureConfiguredStaticScriptLiteralDenyService(s, "policy-fixture-ok")
			}},
			{"artifact revocation", func(t *testing.T, f *operationalFixture, s *Service) {
				original := operationalV2Original(t, f)
				s.trustModel.ArtifactPolicy.RevokedArtifacts = append(s.trustModel.ArtifactPolicy.RevokedArtifacts,
					original.resolved.plan.artifactDigest)
			}},
			{"signer revocation", func(t *testing.T, f *operationalFixture, s *Service) {
				var record evidencev1.ArtifactEvidence
				if err := json.Unmarshal([]byte(f.expectedEvidence), &record); err != nil {
					t.Fatal(err)
				}
				s.trustModel.SignerPolicy.RevokedSigners = append(s.trustModel.SignerPolicy.RevokedSigners, record.Seal.KeyID)
			}},
		} {
			t.Run(seed.name+"/"+change.name, func(t *testing.T) {
				f := makeOperationalFixture(t, "")
				if err := f.domain.custody.ConfigureOperationalCommitFaultForProof(seed.fault, false); err != nil {
					t.Fatal(err)
				}
				first := f.submit()
				seeded := operationalPrestageStateAt(t, f)
				if first.operation != seed.fault || first.write != reliablesubmit.OperationalOwnCommitConfirmed ||
					seeded.Revision != seed.wantRevision || seeded.Intent != seed.wantIntent ||
					seeded.StageEntries != 0 || seeded.Stamp || seeded.Marker || seeded.Posts != 0 {
					t.Fatalf("seed: result=%+v state=%+v", first, seeded)
				}
				denying := operationalProofService(t, f, func(s *Service) { change.configure(t, f, s) })
				denied := denying.handoffOperational(context.Background(), f.reopen(), f.domain.caller, f.raw)
				assertOperationalNoFurtherEffect(t, f, seeded, denied)
				if after := operationalPrestageStateAt(t, f); denied.reason != reliablesubmit.OperationalUnavailable ||
					after != seeded {
					t.Fatalf("denied retry: result=%+v before=%+v after=%+v", denied, seeded, after)
				}
				allowed := f.service.handoffOperational(context.Background(), f.reopen(), f.domain.caller, f.raw)
				if state := operationalPrestageStateAt(t, f); allowed.kind != operationalAccepted || allowed.run == "" ||
					state.Revision != 6 || !state.Marker || state.Posts != 1 {
					t.Fatalf("allowed retry after denial: result=%+v state=%+v", allowed, state)
				}
			})
		}
	}
}
